package builtin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/x0c/agent-dbctl/internal/classify"
	"github.com/x0c/agent-dbctl/internal/driver"
	"github.com/x0c/agent-dbctl/internal/types"
)

// TDengineDriver implements TDengine HTTP/REST (taosAdapter /rest/sql) support in pure Go.
type TDengineDriver struct{}

func (d *TDengineDriver) Metadata() types.DriverMetadata {
	return types.DriverMetadata{
		ID:           "builtin-tdengine",
		Engine:       "tdengine",
		DisplayName:  "TDengine",
		Family:       types.FamilySQL,
		Tier:         "builtin",
		Version:      "1.0.0",
		Capabilities: []string{"ping", "list_databases", "schema", "preflight", "execute"},
		Verified:     true,
		Labels:       map[string]string{"en": "TDengine", "zh": "TDengine 时序数据库"},
	}
}

func (d *TDengineDriver) Classify(_ context.Context, raw string) (types.Classification, error) {
	return classify.Classify("tdengine", raw), nil
}

func (d *TDengineDriver) Open(ctx context.Context, cfg driver.ConnectionConfig) (driver.Conn, error) {
	tc := buildTDengineConn(cfg)
	if _, err := tc.Ping(ctx); err != nil {
		_ = tc.Close()
		return nil, err
	}
	return tc, nil
}

func buildTDengineConn(cfg driver.ConnectionConfig) *tdengineConn {
	port := cfg.Port
	if port <= 0 {
		port = 6041
	}
	host := strings.TrimSpace(cfg.Host)
	if host == "" {
		host = "127.0.0.1"
	}
	scheme := "http"
	if cfg.TLSConfig != nil ||
		strings.EqualFold(cfg.TLSMode, "require") ||
		strings.EqualFold(cfg.TLSMode, "verify-ca") ||
		strings.EqualFold(cfg.TLSMode, "verify-full") ||
		strings.EqualFold(strings.TrimSpace(cfg.Params["scheme"]), "https") {
		scheme = "https"
	}

	var baseURL string
	if strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
		baseURL = strings.TrimRight(host, "/")
	} else if _, _, err := net.SplitHostPort(host); err == nil {
		baseURL = fmt.Sprintf("%s://%s", scheme, host)
	} else {
		baseURL = fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(host, strconv.Itoa(port)))
	}

	tr := &http.Transport{
		TLSClientConfig:       cfg.TLSConfig,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
	}
	if cfg.DialContext != nil {
		tr.DialContext = cfg.DialContext
	}
	tc := &tdengineConn{
		baseURL:   baseURL,
		transport: tr,
		client:    &http.Client{Transport: tr},
		cfg:       cfg,
		closeHook: driver.CloseOnce(cfg.CloseHook),
	}
	if cfg.NegotiatedCapabilities != nil {
		cp := *cfg.NegotiatedCapabilities
		tc.caps.Store(&cp)
	}
	return tc
}

type tdengineConn struct {
	baseURL   string
	transport *http.Transport
	client    *http.Client
	cfg       driver.ConnectionConfig
	closeHook func() error
	closeOnce sync.Once
	closeErr  error
	caps      atomic.Pointer[types.ServerCapabilities]
}

type tdengineSQLResp struct {
	Code       int     `json:"code"`
	Desc       string  `json:"desc"`
	ColumnMeta [][]any `json:"column_meta"`
	Data       [][]any `json:"data"`
	Rows       int64   `json:"rows"`
}

func (c *tdengineConn) Capabilities() *types.ServerCapabilities {
	return c.caps.Load()
}

func (c *tdengineConn) ResetSession(ctx context.Context) error {
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, err := c.execSQL(pingCtx, "SELECT SERVER_VERSION()", false)
	return err
}

func (c *tdengineConn) execSQL(ctx context.Context, sqlText string, withDB bool) (*tdengineSQLResp, error) {
	endpoint := c.baseURL + "/rest/sql"
	if withDB && strings.TrimSpace(c.cfg.DatabaseName) != "" {
		endpoint += "/" + url.PathEscape(strings.TrimSpace(c.cfg.DatabaseName))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(sqlText))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	req.Header.Set("Accept", "application/json")
	applyTDengineAuth(req, c.cfg)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	rawBody, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	var parsed tdengineSQLResp
	if uErr := json.Unmarshal(rawBody, &parsed); uErr != nil {
		if resp.StatusCode >= 400 {
			return nil, fmt.Errorf("tdengine HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(rawBody)))
		}
		return nil, fmt.Errorf("tdengine invalid JSON response: %w", uErr)
	}
	if resp.StatusCode >= 400 || parsed.Code != 0 {
		msg := strings.TrimSpace(parsed.Desc)
		if msg == "" {
			msg = strings.TrimSpace(string(rawBody))
		}
		return nil, fmt.Errorf("tdengine error (%d): %s", parsed.Code, msg)
	}
	return &parsed, nil
}

func applyTDengineAuth(req *http.Request, cfg driver.ConnectionConfig) {
	authType := strings.ToLower(strings.TrimSpace(cfg.Params["auth_type"]))
	if authType == "taosd" || (cfg.Credential.Username == "" && cfg.Credential.Secret != "") {
		req.Header.Set("Authorization", "Taosd "+cfg.Credential.Secret)
		return
	}
	if cfg.Credential.Username != "" || cfg.Credential.Secret != "" {
		tok := base64.StdEncoding.EncodeToString([]byte(cfg.Credential.Username + ":" + cfg.Credential.Secret))
		req.Header.Set("Authorization", "Basic "+tok)
	}
}

func (c *tdengineConn) Ping(ctx context.Context) (types.PingResult, error) {
	start := time.Now()
	resp, err := c.execSQL(ctx, "SELECT SERVER_VERSION()", false)
	lat := time.Since(start).Milliseconds()
	if err != nil {
		return types.PingResult{Engine: "tdengine", Reachable: false, LatencyMs: lat, Error: err.Error()}, err
	}
	ver := "3.0"
	if len(resp.Data) > 0 && len(resp.Data[0]) > 0 {
		ver = fmt.Sprint(resp.Data[0][0])
	}
	caps := driver.DetectServerCapabilities("tdengine", ver, driver.DialectHints{})
	c.caps.Store(&caps)
	return types.PingResult{
		Engine:        "tdengine",
		Dialect:       caps.Dialect,
		Reachable:     true,
		ServerVersion: ver,
		Capabilities:  &caps,
		LatencyMs:     lat,
	}, nil
}

func (c *tdengineConn) ListDatabases(ctx context.Context) ([]string, error) {
	resp, err := c.execSQL(ctx, "SHOW DATABASES", false)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, row := range resp.Data {
		if len(row) > 0 {
			name := strings.TrimSpace(fmt.Sprint(row[0]))
			if name != "" {
				out = append(out, name)
			}
		}
	}
	return out, nil
}

func (c *tdengineConn) Preflight(ctx context.Context, raw string, _ driver.PreflightOpts) (*types.PreflightReport, error) {
	cls := classify.Classify("tdengine", raw)
	report := &types.PreflightReport{
		Supported: true,
		Executed:  false,
		Format:    "tdengine_explain",
	}
	if !driver.CanPreflightSQL(cls) {
		report.Warnings = append(report.Warnings, "EXPLAIN skipped for DDL/admin/multi-statement SQL")
		return report, nil
	}
	resp, err := c.execSQL(ctx, "EXPLAIN "+raw, true)
	if err != nil {
		report.Warnings = append(report.Warnings, "EXPLAIN failed: "+err.Error())
		return report, nil
	}
	var lines []string
	for _, row := range resp.Data {
		parts := make([]string, 0, len(row))
		for _, cell := range row {
			parts = append(parts, fmt.Sprint(cell))
		}
		line := strings.Join(parts, " | ")
		lines = append(lines, line)
		if strings.Contains(strings.ToUpper(line), "FULL") {
			report.FullScan = true
		}
	}
	report.PlanRaw = lines
	report.PlanSummary = strings.Join(lines, "\n")
	return report, nil
}

func (c *tdengineConn) Execute(ctx context.Context, raw string, opts driver.ExecOpts) (*types.ExecResult, error) {
	start := time.Now()
	cls := classify.Classify("tdengine", raw)
	if c.cfg.ReadOnly && !cls.IsReadOnly {
		return nil, fmt.Errorf("read-only mode blocks non-read TDengine statement (%s)", cls.RiskLevel)
	}
	resp, err := c.execSQL(ctx, raw, true)
	if err != nil {
		return nil, err
	}

	cols := make([]types.Column, 0, len(resp.ColumnMeta))
	for _, cm := range resp.ColumnMeta {
		name := ""
		tname := ""
		if len(cm) > 0 {
			name = fmt.Sprint(cm[0])
		}
		if len(cm) > 1 {
			tname = strings.ToUpper(fmt.Sprint(cm[1]))
		}
		cols = append(cols, types.Column{Name: name, TypeName: tname})
	}

	if len(cols) == 0 && !cls.IsReadOnly {
		aff := resp.Rows
		return &types.ExecResult{
			Family:       types.FamilySQL,
			AffectedRows: &aff,
			LatencyMs:    time.Since(start).Milliseconds(),
		}, nil
	}

	buf := driver.RowBuffer{MaxRows: opts.MaxRows, MaxBytes: opts.MaxBytes}
	var outRows [][]any
	for _, row := range resp.Data {
		if buf.TryAcceptRow(row) {
			outRows = append(outRows, row)
		} else if buf.ShouldStopLookahead() {
			break
		}
	}
	return &types.ExecResult{
		Family:        types.FamilySQL,
		Columns:       cols,
		Rows:          outRows,
		FetchedRows:   buf.FetchedRows,
		ReturnedRows:  len(outRows),
		ReturnedBytes: buf.ReturnedBytes,
		Truncated:     buf.Truncated,
		CutoffReason:  buf.CutoffReason,
		LatencyMs:     time.Since(start).Milliseconds(),
	}, nil
}

func (c *tdengineConn) ListTables(ctx context.Context, opts driver.SchemaListOpts) (*types.SchemaListResult, error) {
	var all []types.SchemaObjectSummary
	if stResp, err := c.execSQL(ctx, "SHOW STABLES", true); err == nil {
		for _, row := range stResp.Data {
			if len(row) > 0 {
				all = append(all, types.SchemaObjectSummary{
					Schema: c.cfg.DatabaseName,
					Name:   fmt.Sprint(row[0]),
					Type:   "stable",
				})
			}
		}
	}
	tResp, err := c.execSQL(ctx, "SHOW TABLES", true)
	if err != nil && len(all) == 0 {
		return nil, err
	}
	if tResp != nil {
		for _, row := range tResp.Data {
			if len(row) > 0 {
				all = append(all, types.SchemaObjectSummary{
					Schema: c.cfg.DatabaseName,
					Name:   fmt.Sprint(row[0]),
					Type:   "table",
				})
			}
		}
	}
	items, total, truncated := driver.FilterAndCapSchemaObjects(all, opts.Search, opts.Limit)
	return &types.SchemaListResult{
		Engine:        "tdengine",
		Dialect:       "tdengine",
		Database:      c.cfg.DatabaseName,
		Items:         items,
		TotalCount:    total,
		ReturnedCount: len(items),
		Truncated:     truncated,
	}, nil
}

func (c *tdengineConn) DescribeTable(ctx context.Context, name string) (*types.TableSchema, error) {
	sch, tbl := driver.SplitQualifiedObject(name)
	if tbl == "" {
		return nil, fmt.Errorf("table name is required")
	}
	if sch == "" {
		sch = c.cfg.DatabaseName
	}
	if !isSafeTDengineIdent(tbl) || (sch != "" && !isSafeTDengineIdent(sch)) {
		return nil, fmt.Errorf("invalid TDengine table identifier %q", name)
	}
	target := "`" + tbl + "`"
	if sch != "" {
		target = "`" + sch + "`.`" + tbl + "`"
	}
	resp, err := c.execSQL(ctx, "DESCRIBE "+target, true)
	if err != nil {
		return nil, err
	}
	var cols []types.SchemaColumn
	for _, row := range resp.Data {
		if len(row) < 2 {
			continue
		}
		extra := ""
		if len(row) >= 4 && row[3] != nil {
			extra = fmt.Sprint(row[3])
		}
		cols = append(cols, types.SchemaColumn{
			Name:     fmt.Sprint(row[0]),
			Type:     fmt.Sprint(row[1]),
			Nullable: true,
			Extra:    extra,
		})
	}
	if len(cols) == 0 {
		return nil, fmt.Errorf("table %s not found", name)
	}
	return &types.TableSchema{
		Engine:     "tdengine",
		Dialect:    "tdengine",
		Database:   c.cfg.DatabaseName,
		Schema:     sch,
		Name:       tbl,
		ObjectType: "table",
		Columns:    cols,
	}, nil
}

func isSafeTDengineIdent(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func (c *tdengineConn) CancelAndDiscard() error {
	return c.Close()
}

func (c *tdengineConn) Close() error {
	c.closeOnce.Do(func() {
		if c.closeHook != nil {
			_ = c.closeHook()
		}
		if c.transport != nil {
			c.transport.CloseIdleConnections()
		}
	})
	return c.closeErr
}
