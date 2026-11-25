package builtin

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"

	"github.com/x0c/agent-dbctl/internal/classify"
	"github.com/x0c/agent-dbctl/internal/driver"
	"github.com/x0c/agent-dbctl/internal/types"
)

var chPlanRowsRe = regexp.MustCompile(`(?i)\brows\s*[:=]\s*(\d+)`)

// ClickHouseDriver implements ClickHouse native TCP / HTTP support using pure-Go clickhouse-go/v2.
type ClickHouseDriver struct{}

func (d *ClickHouseDriver) Metadata() types.DriverMetadata {
	return types.DriverMetadata{
		ID:           "builtin-clickhouse",
		Engine:       "clickhouse",
		DisplayName:  "ClickHouse",
		Family:       types.FamilySQL,
		Tier:         "builtin",
		Version:      "1.0.0",
		Capabilities: []string{"ping", "list_databases", "schema", "preflight", "execute"},
		Verified:     true,
		Labels:       map[string]string{"en": "ClickHouse", "zh": "ClickHouse"},
	}
}

func (d *ClickHouseDriver) Classify(_ context.Context, raw string) (types.Classification, error) {
	return classify.Classify("clickhouse", raw), nil
}

func (d *ClickHouseDriver) Open(ctx context.Context, cfg driver.ConnectionConfig) (driver.Conn, error) {
	opts, err := buildClickHouseOptions(cfg)
	if err != nil {
		return nil, err
	}
	db := clickhouse.OpenDB(opts)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	var lockedProfile atomic.Bool
	probeQuery := func(qctx context.Context, handle *sql.DB) error {
		var one uint8
		return handle.QueryRowContext(qctx, "SELECT 1").Scan(&one)
	}
	if err := probeQuery(ctx, db); err != nil {
		// If the server user profile already locks readonly=1, it also forbids per-query
		// settings like readonly=1 or clickhouse-go's automatic max_execution_time from ctx.Deadline().
		if isCHReadOnlySettingLocked(err) {
			lockedProfile.Store(true)
			_ = db.Close()
			delete(opts.Settings, "readonly")
			db = clickhouse.OpenDB(opts)
			db.SetMaxOpenConns(1)
			db.SetMaxIdleConns(1)
			noDL, stop := withoutDeadlineContext(ctx)
			err = probeQuery(noDL, db)
			stop()
		}
		if err != nil {
			_ = db.Close()
			return nil, err
		}
	}

	cc := &clickhouseConn{
		db:                    db,
		opts:                  opts,
		cfg:                   cfg,
		readonlyProfileLocked: lockedProfile.Load(),
		closeHook:             driver.CloseOnce(cfg.CloseHook),
	}
	if cfg.NegotiatedCapabilities != nil {
		cp := *cfg.NegotiatedCapabilities
		cc.caps.Store(&cp)
	}
	return cc, nil
}

func isCHReadOnlySettingLocked(err error) bool {
	if err == nil {
		return false
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "readonly") &&
		(strings.Contains(lower, "cannot modify") || strings.Contains(lower, "locked") || strings.Contains(lower, "code: 164"))
}

// withoutDeadlineContext drops ctx.Deadline() so clickhouse-go does not inject
// max_execution_time into strict readonly=1 profiles, while preserving cancellation.
func withoutDeadlineContext(parent context.Context) (context.Context, func()) {
	if _, hasDeadline := parent.Deadline(); !hasDeadline {
		return parent, func() {}
	}
	ctx, cancel := context.WithCancel(context.WithoutCancel(parent))
	stop := context.AfterFunc(parent, cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}

func buildClickHouseOptions(cfg driver.ConnectionConfig) (*clickhouse.Options, error) {
	port := cfg.Port
	if port <= 0 {
		port = 9000
	}
	host := strings.TrimSpace(cfg.Host)
	if host == "" {
		host = "127.0.0.1"
	}
	var addrs []string
	for _, h := range strings.Split(host, ",") {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(h); err == nil {
			addrs = append(addrs, h)
		} else {
			addrs = append(addrs, net.JoinHostPort(h, strconv.Itoa(port)))
		}
	}

	dbName := strings.TrimSpace(cfg.DatabaseName)
	if dbName == "" {
		dbName = "default"
	}

	opts := &clickhouse.Options{
		Addr: addrs,
		Auth: clickhouse.Auth{
			Database: dbName,
			Username: cfg.Credential.Username,
			Password: cfg.Credential.Secret,
		},
		TLS:          cfg.TLSConfig,
		DialTimeout:  10 * time.Second,
		MaxOpenConns: 1,
		MaxIdleConns: 1,
		Settings:     clickhouse.Settings{},
	}
	if cfg.DialContext != nil {
		dialFn := cfg.DialContext
		opts.DialContext = func(dctx context.Context, addr string) (net.Conn, error) {
			return dialFn(dctx, "tcp", addr)
		}
	}

	for k, v := range cfg.Params {
		key := strings.ToLower(strings.TrimSpace(k))
		val := strings.TrimSpace(v)
		switch key {
		case "protocol":
			switch strings.ToLower(val) {
			case "", "native":
				opts.Protocol = clickhouse.Native
			case "http":
				opts.Protocol = clickhouse.HTTP
			default:
				return nil, fmt.Errorf("unsupported clickhouse protocol %q", val)
			}
		case "compress", "compression":
			switch strings.ToLower(val) {
			case "", "none":
				opts.Compression = &clickhouse.Compression{Method: clickhouse.CompressionNone}
			case "lz4":
				opts.Compression = &clickhouse.Compression{Method: clickhouse.CompressionLZ4}
			case "zstd":
				opts.Compression = &clickhouse.Compression{Method: clickhouse.CompressionZSTD}
			}
		case "dial_timeout", "connect_timeout":
			if d, err := parseDurationOrSeconds(val); err == nil && d > 0 {
				opts.DialTimeout = d
			}
		case "read_timeout":
			if d, err := parseDurationOrSeconds(val); err == nil && d > 0 {
				opts.ReadTimeout = d
			}
		case "readonly":
			// Controlled by cfg.ReadOnly so Params cannot disable read-only enforcement.
		default:
			opts.Settings[k] = v
		}
	}

	if cfg.ReadOnly {
		opts.Settings["readonly"] = 1
	}
	return opts, nil
}

type clickhouseConn struct {
	db                    *sql.DB
	opts                  *clickhouse.Options
	cfg                   driver.ConnectionConfig
	readonlyProfileLocked bool
	closeHook             func() error
	closeOnce             sync.Once
	closeErr              error
	caps                  atomic.Pointer[types.ServerCapabilities]
	activeQueryID         atomic.Value
}

func (c *clickhouseConn) queryCtx(ctx context.Context) (context.Context, func()) {
	if c.readonlyProfileLocked {
		return withoutDeadlineContext(ctx)
	}
	return ctx, func() {}
}

func (c *clickhouseConn) Capabilities() *types.ServerCapabilities {
	return c.caps.Load()
}

func (c *clickhouseConn) ResetSession(ctx context.Context) error {
	if c.db == nil {
		return fmt.Errorf("clickhouse db handle is closed")
	}
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	qctx, stop := c.queryCtx(pingCtx)
	defer stop()
	return c.db.PingContext(qctx)
}

func (c *clickhouseConn) Ping(ctx context.Context) (types.PingResult, error) {
	start := time.Now()
	qctx, stop := c.queryCtx(ctx)
	defer stop()
	var ver string
	err := c.db.QueryRowContext(qctx, "SELECT version()").Scan(&ver)
	lat := time.Since(start).Milliseconds()
	if err != nil {
		return types.PingResult{Engine: "clickhouse", Reachable: false, LatencyMs: lat, Error: err.Error()}, err
	}
	caps := driver.DetectServerCapabilities("clickhouse", ver, driver.DialectHints{})
	c.caps.Store(&caps)
	return types.PingResult{
		Engine:        "clickhouse",
		Dialect:       caps.Dialect,
		Reachable:     true,
		ServerVersion: ver,
		Capabilities:  &caps,
		LatencyMs:     lat,
	}, nil
}

func (c *clickhouseConn) ListDatabases(ctx context.Context) ([]string, error) {
	qctx, stop := c.queryCtx(ctx)
	defer stop()
	rows, err := c.db.QueryContext(qctx, "SELECT name FROM system.databases ORDER BY name")
	if err != nil {
		rows, err = c.db.QueryContext(qctx, "SHOW DATABASES")
		if err != nil {
			return nil, err
		}
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

func (c *clickhouseConn) Preflight(ctx context.Context, raw string, _ driver.PreflightOpts) (*types.PreflightReport, error) {
	cls := classify.Classify("clickhouse", raw)
	report := &types.PreflightReport{
		Supported: true,
		Executed:  false,
		Format:    "clickhouse_plan",
	}
	if !cls.IsReadOnly || cls.StatementCount != 1 {
		report.Warnings = append(report.Warnings, "EXPLAIN skipped for non-read or multi-statement SQL")
		return report, nil
	}

	qctx, stop := c.queryCtx(ctx)
	defer stop()

	// 1. Estimate rows/parts/marks via EXPLAIN ESTIMATE when available.
	estRows, estErr := c.db.QueryContext(qctx, "EXPLAIN ESTIMATE "+raw)
	if estErr == nil {
		defer func() { _ = estRows.Close() }()
		if estRes, err := collectSQLRows(estRows, driver.ExecOpts{MaxRows: 100}); err == nil {
			parseClickHouseEstimatePlan(estRes, report)
		}
	}

	// 2. Inspect physical plan steps via EXPLAIN PLAN indexes = 1 (fallback EXPLAIN PLAN).
	planRows, planErr := c.db.QueryContext(qctx, "EXPLAIN PLAN indexes = 1 "+raw)
	if planErr != nil {
		planRows, planErr = c.db.QueryContext(qctx, "EXPLAIN "+raw)
	}
	if planErr != nil {
		if estErr != nil {
			report.Warnings = append(report.Warnings, "EXPLAIN failed: "+planErr.Error())
		}
		return report, nil
	}
	defer func() { _ = planRows.Close() }()
	var lines []string
	for planRows.Next() {
		var line string
		if scanErr := planRows.Scan(&line); scanErr == nil {
			lines = append(lines, line)
		}
	}
	if len(lines) > 0 {
		parseClickHousePlanLines(lines, report)
	}
	return report, nil
}

func parseClickHouseEstimatePlan(res *types.ExecResult, report *types.PreflightReport) {
	if res == nil {
		return
	}
	rowsIdx, marksIdx, partsIdx := -1, -1, -1
	for i, c := range res.Columns {
		switch strings.ToLower(c.Name) {
		case "rows":
			rowsIdx = i
		case "marks":
			marksIdx = i
		case "parts":
			partsIdx = i
		}
	}
	var totalRows int64
	for _, r := range res.Rows {
		if rowsIdx >= 0 && rowsIdx < len(r) {
			if n, ok := asInt64(r[rowsIdx]); ok {
				totalRows += n
			}
		}
	}
	if totalRows > report.EstimatedRows {
		report.EstimatedRows = totalRows
	}
	_ = marksIdx
	_ = partsIdx
	report.PlanRaw = res.Rows
}

func parseClickHousePlanLines(lines []string, report *types.PreflightReport) {
	hasIndexPruning := false
	hasMergeTreeRead := false
	inIndexBlock := false
	for _, line := range lines {
		lower := strings.ToLower(line)
		trimmed := strings.TrimSpace(lower)
		if strings.Contains(lower, "readfrommergetree") || strings.Contains(lower, "readfromstorage") {
			hasMergeTreeRead = true
		}
		if trimmed == "primarykey" || trimmed == "minmax" || trimmed == "skip" ||
			strings.Contains(lower, "type: primarykey") || strings.Contains(lower, "type: minmax") ||
			strings.Contains(lower, "type: set") || strings.Contains(lower, "type: bloom_filter") {
			inIndexBlock = true
			if strings.Contains(lower, "type:") {
				hasIndexPruning = true
			}
		} else if inIndexBlock {
			if strings.HasPrefix(trimmed, "keys:") {
				hasIndexPruning = true
			} else if strings.HasPrefix(trimmed, "condition:") && trimmed != "condition: true" {
				hasIndexPruning = true
			}
		}
		if strings.Contains(lower, "readtype: default") && !strings.Contains(lower, "primarykey") {
			report.FullScan = true
		}
		if m := chPlanRowsRe.FindStringSubmatch(line); len(m) == 2 {
			if n, err := strconv.ParseInt(m[1], 10, 64); err == nil && n > report.EstimatedRows {
				report.EstimatedRows = n
			}
		}
	}
	if hasMergeTreeRead && !hasIndexPruning {
		report.FullScan = true
	}
	if report.PlanRaw == nil {
		report.PlanRaw = lines
	}
	report.PlanSummary = strings.Join(lines, "\n")
}

func (c *clickhouseConn) Execute(ctx context.Context, raw string, opts driver.ExecOpts) (*types.ExecResult, error) {
	start := time.Now()
	cls := classify.Classify("clickhouse", raw)
	if c.cfg.ReadOnly && !cls.IsReadOnly {
		return nil, fmt.Errorf("read-only mode blocks non-read ClickHouse statement (%s)", cls.RiskLevel)
	}

	qid := newCHQueryID()
	c.activeQueryID.Store(qid)
	defer c.activeQueryID.Store("")
	baseCtx, stop := c.queryCtx(ctx)
	defer stop()
	var qctx context.Context
	if c.readonlyProfileLocked {
		qctx = baseCtx
	} else {
		qctx = clickhouse.Context(baseCtx, clickhouse.WithQueryID(qid))
	}

	if cls.IsReadOnly && cls.StatementCount == 1 {
		rows, err := c.db.QueryContext(qctx, raw)
		if err != nil {
			return nil, err
		}
		defer func() { _ = rows.Close() }()
		res, err := collectSQLRows(rows, opts)
		if err != nil {
			return nil, err
		}
		res.LatencyMs = time.Since(start).Milliseconds()
		return res, nil
	}

	sqlRes, err := c.db.ExecContext(qctx, raw)
	if err != nil {
		return nil, err
	}
	affected, err := sqlRes.RowsAffected()
	var affPtr *int64
	if err == nil {
		affPtr = &affected
	}
	return &types.ExecResult{
		Family:       types.FamilySQL,
		AffectedRows: affPtr,
		LatencyMs:    time.Since(start).Milliseconds(),
	}, nil
}

func (c *clickhouseConn) ListTables(ctx context.Context, opts driver.SchemaListOpts) (*types.SchemaListResult, error) {
	dbName := strings.TrimSpace(c.cfg.DatabaseName)
	if dbName == "" {
		dbName = "default"
	}
	qctx, stop := c.queryCtx(ctx)
	defer stop()
	rows, err := c.db.QueryContext(qctx, `
		SELECT database, name, engine, total_rows
		FROM system.tables
		WHERE database = ?
		ORDER BY name`, dbName)
	if err != nil {
		rows, err = c.db.QueryContext(qctx, `
			SELECT database, name, engine, NULL
			FROM system.tables
			WHERE database = ?
			ORDER BY name`, dbName)
		if err != nil {
			return nil, err
		}
	}
	defer func() { _ = rows.Close() }()

	var all []types.SchemaObjectSummary
	for rows.Next() {
		var sch, name, eng string
		var estRows sql.NullInt64
		if err := rows.Scan(&sch, &name, &eng, &estRows); err != nil {
			return nil, err
		}
		objType := "table"
		if strings.Contains(strings.ToUpper(eng), "VIEW") {
			objType = "view"
		}
		item := types.SchemaObjectSummary{
			Schema: sch,
			Name:   name,
			Type:   objType,
			Engine: eng,
		}
		if estRows.Valid {
			v := estRows.Int64
			item.EstimatedRows = &v
		}
		all = append(all, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	items, total, truncated := driver.FilterAndCapSchemaObjects(all, opts.Search, opts.Limit)
	return &types.SchemaListResult{
		Engine:        "clickhouse",
		Dialect:       "clickhouse",
		Database:      dbName,
		Items:         items,
		TotalCount:    total,
		ReturnedCount: len(items),
		Truncated:     truncated,
	}, nil
}

func (c *clickhouseConn) DescribeTable(ctx context.Context, name string) (*types.TableSchema, error) {
	sch, tbl := driver.SplitQualifiedObject(name)
	if tbl == "" {
		return nil, fmt.Errorf("table name is required")
	}
	if sch == "" {
		sch = strings.TrimSpace(c.cfg.DatabaseName)
		if sch == "" {
			sch = "default"
		}
	}

	qctx, stop := c.queryCtx(ctx)
	defer stop()
	rows, err := c.db.QueryContext(qctx, `
		SELECT name, type, default_kind, default_expression, is_in_primary_key, is_in_sorting_key
		FROM system.columns
		WHERE database = ? AND table = ?
		ORDER BY position`, sch, tbl)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var cols []types.SchemaColumn
	var pkCols, sortCols []string
	for rows.Next() {
		var cname, dtype, defKind, defExpr string
		var inPK, inSort uint8
		if err := rows.Scan(&cname, &dtype, &defKind, &defExpr, &inPK, &inSort); err != nil {
			return nil, err
		}
		nullable := strings.HasPrefix(dtype, "Nullable(")
		extra := ""
		if defKind != "" {
			extra = defKind
		}
		if inPK > 0 {
			pkCols = append(pkCols, cname)
		}
		if inSort > 0 {
			sortCols = append(sortCols, cname)
		}
		cols = append(cols, types.SchemaColumn{
			Name:       cname,
			Type:       dtype,
			Nullable:   nullable,
			PrimaryKey: inPK > 0,
			Default:    defExpr,
			Extra:      extra,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(cols) == 0 {
		return nil, fmt.Errorf("table or view %s.%s not found", sch, tbl)
	}

	var idxs []types.SchemaIndex
	if len(pkCols) > 0 {
		idxs = append(idxs, types.SchemaIndex{Name: "PRIMARY KEY", Columns: pkCols, Primary: true})
	}
	if len(sortCols) > 0 {
		idxs = append(idxs, types.SchemaIndex{Name: "ORDER BY", Columns: sortCols})
	}
	return &types.TableSchema{
		Engine:     "clickhouse",
		Dialect:    "clickhouse",
		Database:   sch,
		Schema:     sch,
		Name:       tbl,
		ObjectType: "table",
		Columns:    cols,
		Indexes:    idxs,
	}, nil
}

func (c *clickhouseConn) CancelAndDiscard() error {
	if rawID, ok := c.activeQueryID.Load().(string); ok && rawID != "" && c.opts != nil {
		sideDB := clickhouse.OpenDB(c.opts)
		killCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, _ = sideDB.ExecContext(killCtx, fmt.Sprintf("KILL QUERY WHERE query_id = '%s' SYNC", strings.ReplaceAll(rawID, "'", "")))
		cancel()
		_ = sideDB.Close()
	}
	return c.Close()
}

func (c *clickhouseConn) Close() error {
	c.closeOnce.Do(func() {
		if c.closeHook != nil {
			_ = c.closeHook()
		}
		c.closeErr = c.db.Close()
	})
	return c.closeErr
}

func newCHQueryID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "adb_" + hex.EncodeToString(b[:])
}
