package builtin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/x0c/agent-dbctl/internal/classify"
	"github.com/x0c/agent-dbctl/internal/driver"
	"github.com/x0c/agent-dbctl/internal/types"
)

// ElasticsearchDriver implements Elasticsearch & OpenSearch HTTP/REST support in pure Go.
type ElasticsearchDriver struct{}

func (d *ElasticsearchDriver) Metadata() types.DriverMetadata {
	return types.DriverMetadata{
		ID:           "builtin-elasticsearch",
		Engine:       "elasticsearch",
		DisplayName:  "Elasticsearch",
		Family:       types.FamilyDocument,
		Tier:         "builtin",
		Version:      "1.0.0",
		Capabilities: []string{"ping", "list_databases", "schema", "preflight", "execute"},
		Verified:     true,
		Labels:       map[string]string{"en": "Elasticsearch", "zh": "Elasticsearch"},
	}
}

func (d *ElasticsearchDriver) Classify(_ context.Context, raw string) (types.Classification, error) {
	return classify.Classify("elasticsearch", raw), nil
}

func (d *ElasticsearchDriver) Open(ctx context.Context, cfg driver.ConnectionConfig) (driver.Conn, error) {
	ec := buildESConn(cfg)
	if _, err := ec.Ping(ctx); err != nil {
		_ = ec.Close()
		return nil, err
	}
	return ec, nil
}

func buildESConn(cfg driver.ConnectionConfig) *esConn {
	port := cfg.Port
	if port <= 0 {
		port = 9200
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

	ec := &esConn{
		baseURL:   baseURL,
		transport: tr,
		client:    &http.Client{Transport: tr},
		cfg:       cfg,
		closeHook: driver.CloseOnce(cfg.CloseHook),
	}
	if cfg.NegotiatedCapabilities != nil {
		cp := *cfg.NegotiatedCapabilities
		ec.caps.Store(&cp)
	}
	return ec
}

type esConn struct {
	baseURL   string
	transport *http.Transport
	client    *http.Client
	cfg       driver.ConnectionConfig
	closeHook func() error
	closeOnce sync.Once
	closeErr  error
	caps      atomic.Pointer[types.ServerCapabilities]
}

func (c *esConn) Capabilities() *types.ServerCapabilities {
	return c.caps.Load()
}

func (c *esConn) ResetSession(ctx context.Context) error {
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, err := c.doJSON(pingCtx, http.MethodGet, "/", "")
	return err
}

func (c *esConn) doRaw(ctx context.Context, method, path, body string) (int, []byte, error) {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	targetURL := c.baseURL + path
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, targetURL, reader)
	if err != nil {
		return 0, nil, err
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	applyESAuth(req, c.cfg)

	resp, err := c.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	// Bound raw HTTP response read to 32 MiB to prevent unbounded memory consumption.
	data, err := io.ReadAll(io.LimitReader(resp.Body, 32*1024*1024))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	if resp.StatusCode >= 400 {
		return resp.StatusCode, data, fmt.Errorf("elasticsearch HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return resp.StatusCode, data, nil
}

func applyESAuth(req *http.Request, cfg driver.ConnectionConfig) {
	authType := strings.ToLower(strings.TrimSpace(cfg.Params["auth_type"]))
	switch authType {
	case "apikey", "api_key":
		if cfg.Credential.Secret != "" {
			req.Header.Set("Authorization", "ApiKey "+cfg.Credential.Secret)
		}
	case "bearer":
		if cfg.Credential.Secret != "" {
			req.Header.Set("Authorization", "Bearer "+cfg.Credential.Secret)
		}
	default:
		if cfg.Credential.Username != "" || cfg.Credential.Secret != "" {
			req.SetBasicAuth(cfg.Credential.Username, cfg.Credential.Secret)
		}
	}
}

func (c *esConn) doJSON(ctx context.Context, method, path, body string) (any, error) {
	_, data, err := c.doRaw(ctx, method, path, body)
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return map[string]any{}, nil
	}
	var out any
	if err := json.Unmarshal(trimmed, &out); err != nil {
		return string(trimmed), nil
	}
	return out, nil
}

func (c *esConn) Ping(ctx context.Context) (types.PingResult, error) {
	start := time.Now()
	val, err := c.doJSON(ctx, http.MethodGet, "/", "")
	lat := time.Since(start).Milliseconds()
	if err != nil {
		return types.PingResult{Engine: "elasticsearch", Reachable: false, LatencyMs: lat, Error: err.Error()}, err
	}
	var ver, dist string
	if m, ok := val.(map[string]any); ok {
		if vm, ok := m["version"].(map[string]any); ok {
			ver, _ = vm["number"].(string)
			dist, _ = vm["distribution"].(string)
		}
	}
	caps := driver.DetectServerCapabilities("elasticsearch", ver, driver.DialectHints{Distribution: dist})
	c.caps.Store(&caps)
	return types.PingResult{
		Engine:        "elasticsearch",
		Dialect:       caps.Dialect,
		Reachable:     true,
		ServerVersion: ver,
		Capabilities:  &caps,
		LatencyMs:     lat,
	}, nil
}

func (c *esConn) ListDatabases(ctx context.Context) ([]string, error) {
	val, err := c.doJSON(ctx, http.MethodGet, "/_cat/indices?format=json&h=index", "")
	if err != nil {
		return nil, err
	}
	arr, ok := val.([]any)
	if !ok {
		return nil, nil
	}
	seen := map[string]bool{}
	var out []string
	for _, item := range arr {
		if m, ok := item.(map[string]any); ok {
			if idx, ok := m["index"].(string); ok && idx != "" && !seen[idx] {
				seen[idx] = true
				out = append(out, idx)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

func (c *esConn) Preflight(ctx context.Context, raw string, _ driver.PreflightOpts) (*types.PreflightReport, error) {
	cls := classify.Classify("elasticsearch", raw)
	report := &types.PreflightReport{
		Supported: true,
		Executed:  false,
		Format:    "es_validate_query",
	}
	cmd, err := classify.ParseElasticsearchCommand(raw)
	if err != nil {
		report.Supported = false
		report.Warnings = append(report.Warnings, err.Error())
		return report, nil
	}
	if !cls.IsReadOnly {
		report.Warnings = append(report.Warnings, "Preflight validation skipped for write/DDL/admin request")
		return report, nil
	}

	u, _ := url.Parse(cmd.Path)
	cleanPath := cmd.Path
	if u != nil && u.Path != "" {
		cleanPath = u.Path
	}
	lowerPath := strings.ToLower(cleanPath)
	if !strings.HasSuffix(lowerPath, "/_search") && lowerPath != "/_search" {
		report.Supported = false
		return report, nil
	}

	prefix := ""
	if cmd.Index != "" {
		prefix = "/" + cmd.Index
	}
	if cmd.Index == "" || cmd.Index == "*" || cmd.Index == "_all" {
		report.FullScan = true
	}

	var queryPayload string
	if cmd.Doc != nil {
		if qObj, ok := cmd.Doc["query"]; ok {
			if b, err := json.Marshal(map[string]any{"query": qObj}); err == nil {
				queryPayload = string(b)
			}
			if m, ok := qObj.(map[string]any); ok {
				if _, isMatchAll := m["match_all"]; isMatchAll {
					if _, hasSize := cmd.Doc["size"]; !hasSize {
						report.FullScan = true
					}
				}
			}
		}
	}

	valOut, err := c.doJSON(ctx, http.MethodPost, prefix+"/_validate/query?explain=true", queryPayload)
	if err != nil {
		report.Warnings = append(report.Warnings, "_validate/query failed: "+err.Error())
	} else {
		report.PlanRaw = valOut
	}

	cntOut, err := c.doJSON(ctx, http.MethodPost, prefix+"/_count", queryPayload)
	if err == nil {
		if m, ok := cntOut.(map[string]any); ok {
			if n, ok := asInt64(m["count"]); ok {
				report.EstimatedRows = n
			}
		}
	}
	report.PlanSummary = fmt.Sprintf("Estimated hits: %d, full_scan: %v", report.EstimatedRows, report.FullScan)
	return report, nil
}

func (c *esConn) Execute(ctx context.Context, raw string, opts driver.ExecOpts) (*types.ExecResult, error) {
	start := time.Now()
	cls := classify.Classify("elasticsearch", raw)
	if c.cfg.ReadOnly && !cls.IsReadOnly {
		return nil, fmt.Errorf("read-only mode blocks non-read Elasticsearch command (%s)", cls.RiskLevel)
	}
	cmd, err := classify.ParseElasticsearchCommand(raw)
	if err != nil {
		return nil, err
	}
	if c.cfg.ReadOnly && cmd.Method != http.MethodGet && cmd.Method != http.MethodHead {
		lowerPath := strings.ToLower(cmd.Path)
		if !strings.Contains(lowerPath, "/_search") &&
			!strings.Contains(lowerPath, "/_msearch") &&
			!strings.Contains(lowerPath, "/_count") &&
			!strings.Contains(lowerPath, "/_validate/query") &&
			!strings.Contains(lowerPath, "/_sql") {
			return nil, fmt.Errorf("read-only mode blocks %s %s", cmd.Method, cmd.Path)
		}
	}

	path := cmd.Path
	if cmd.Index == "" && c.cfg.DatabaseName != "" && (strings.HasPrefix(path, "/_search") || strings.HasPrefix(path, "/_count") || strings.HasPrefix(path, "/_mapping")) {
		path = "/" + strings.TrimPrefix(c.cfg.DatabaseName, "/") + path
	}

	val, err := c.doJSON(ctx, cmd.Method, path, cmd.Body)
	if err != nil {
		return nil, err
	}

	buf := driver.RowBuffer{MaxRows: opts.MaxRows, MaxBytes: opts.MaxBytes}
	var docs []any
	switch x := val.(type) {
	case []any:
		for _, item := range x {
			if buf.TryAcceptRow(item) {
				docs = append(docs, item)
			} else if buf.ShouldStopLookahead() {
				break
			}
		}
	case map[string]any:
		if hitsWrap, ok := x["hits"].(map[string]any); ok {
			if hitList, ok := hitsWrap["hits"].([]any); ok {
				for _, hit := range hitList {
					if buf.TryAcceptRow(hit) {
						docs = append(docs, hit)
					} else if buf.ShouldStopLookahead() {
						break
					}
				}
				return &types.ExecResult{
					Family:        types.FamilyDocument,
					Documents:     docs,
					FetchedRows:   buf.FetchedRows,
					ReturnedRows:  len(docs),
					ReturnedBytes: buf.ReturnedBytes,
					Truncated:     buf.Truncated,
					CutoffReason:  buf.CutoffReason,
					LatencyMs:     time.Since(start).Milliseconds(),
				}, nil
			}
		}
		if buf.TryAcceptRow(x) {
			docs = append(docs, x)
		}
	default:
		if buf.TryAcceptRow(x) {
			docs = append(docs, x)
		}
	}

	return &types.ExecResult{
		Family:        types.FamilyDocument,
		Documents:     docs,
		FetchedRows:   buf.FetchedRows,
		ReturnedRows:  len(docs),
		ReturnedBytes: buf.ReturnedBytes,
		Truncated:     buf.Truncated,
		CutoffReason:  buf.CutoffReason,
		LatencyMs:     time.Since(start).Milliseconds(),
	}, nil
}

func (c *esConn) ListTables(ctx context.Context, opts driver.SchemaListOpts) (*types.SchemaListResult, error) {
	val, err := c.doJSON(ctx, http.MethodGet, "/_cat/indices?format=json&h=index,docs.count,health,status", "")
	if err != nil {
		return nil, err
	}
	arr, _ := val.([]any)
	var all []types.SchemaObjectSummary
	for _, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		idxName, _ := m["index"].(string)
		if idxName == "" {
			continue
		}
		sum := types.SchemaObjectSummary{
			Name: idxName,
			Type: "index",
		}
		if dc, ok := m["docs.count"]; ok {
			if n, ok := asInt64(dc); ok {
				v := n
				sum.EstimatedRows = &v
			}
		}
		all = append(all, sum)
	}
	items, total, truncated := driver.FilterAndCapSchemaObjects(all, opts.Search, opts.Limit)
	dialect := "elasticsearch"
	if caps := c.Capabilities(); caps != nil && caps.Dialect != "" {
		dialect = caps.Dialect
	}
	return &types.SchemaListResult{
		Engine:        "elasticsearch",
		Dialect:       dialect,
		Database:      c.cfg.DatabaseName,
		Items:         items,
		TotalCount:    total,
		ReturnedCount: len(items),
		Truncated:     truncated,
	}, nil
}

func (c *esConn) DescribeTable(ctx context.Context, name string) (*types.TableSchema, error) {
	idxName := strings.TrimSpace(name)
	if idxName == "" {
		idxName = strings.TrimSpace(c.cfg.DatabaseName)
	}
	if idxName == "" {
		return nil, fmt.Errorf("index name is required")
	}
	val, err := c.doJSON(ctx, http.MethodGet, "/"+url.PathEscape(idxName)+"/_mapping", "")
	if err != nil {
		return nil, err
	}
	root, ok := val.(map[string]any)
	if !ok || len(root) == 0 {
		return nil, fmt.Errorf("index %s mapping not found", idxName)
	}

	var cols []types.SchemaColumn
	for _, idxVal := range root {
		idxMap, ok := idxVal.(map[string]any)
		if !ok {
			continue
		}
		mappings, _ := idxMap["mappings"].(map[string]any)
		if mappings == nil {
			mappings = idxMap
		}
		if props, ok := mappings["properties"].(map[string]any); ok {
			flattenESProperties("", props, &cols)
		}
	}
	sort.Slice(cols, func(i, j int) bool { return cols[i].Name < cols[j].Name })

	dialect := "elasticsearch"
	if caps := c.Capabilities(); caps != nil && caps.Dialect != "" {
		dialect = caps.Dialect
	}
	return &types.TableSchema{
		Engine:     "elasticsearch",
		Dialect:    dialect,
		Database:   c.cfg.DatabaseName,
		Name:       idxName,
		ObjectType: "index",
		Columns:    cols,
	}, nil
}

func flattenESProperties(prefix string, props map[string]any, out *[]types.SchemaColumn) {
	for field, rawDef := range props {
		def, ok := rawDef.(map[string]any)
		if !ok {
			continue
		}
		fullName := field
		if prefix != "" {
			fullName = prefix + "." + field
		}
		ftype, _ := def["type"].(string)
		if ftype == "" {
			if _, hasSub := def["properties"]; hasSub {
				ftype = "object"
			}
		}
		if ftype != "" {
			*out = append(*out, types.SchemaColumn{
				Name:     fullName,
				Type:     ftype,
				Nullable: true,
			})
		}
		if subProps, ok := def["properties"].(map[string]any); ok {
			flattenESProperties(fullName, subProps, out)
		}
		if fields, ok := def["fields"].(map[string]any); ok {
			flattenESProperties(fullName, fields, out)
		}
	}
}

func (c *esConn) CancelAndDiscard() error {
	return c.Close()
}

func (c *esConn) Close() error {
	c.closeOnce.Do(func() {
		if c.transport != nil {
			c.transport.CloseIdleConnections()
		}
		if c.closeHook != nil {
			_ = c.closeHook()
		}
	})
	return c.closeErr
}
