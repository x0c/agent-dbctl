package builtin

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/x0c/agent-dbctl/internal/classify"
	"github.com/x0c/agent-dbctl/internal/driver"
	"github.com/x0c/agent-dbctl/internal/types"
)

// RegisterAll registers all Tier-1 built-in pure Go drivers into a registry.
func RegisterAll(reg *driver.Registry) {
	reg.Register(&PostgresDriver{})
	reg.Register(&MySQLDriver{})
	reg.Register(&SQLiteDriver{})
	reg.Register(&MongoDriver{})
	reg.Register(&RedisDriver{})
}

// SQLiteDriver executes verbatim SQL against SQLite files via pure-Go modernc.org/sqlite.
type SQLiteDriver struct{}

func (d *SQLiteDriver) Metadata() types.DriverMetadata {
	return types.DriverMetadata{
		ID:           "builtin-sqlite",
		Engine:       "sqlite",
		DisplayName:  "SQLite",
		Family:       types.FamilySQL,
		Tier:         "builtin",
		Version:      "1.0.0",
		Capabilities: []string{"ping", "list_databases", "preflight", "execute"},
		Verified:     true,
		Labels:       map[string]string{"en": "SQLite", "zh": "SQLite"},
	}
}

func (d *SQLiteDriver) Classify(_ context.Context, raw string) (types.Classification, error) {
	return classify.Classify("sqlite", raw), nil
}

func (d *SQLiteDriver) Open(ctx context.Context, cfg driver.ConnectionConfig) (driver.Conn, error) {
	path := cfg.DatabaseName
	if path == "" {
		path = cfg.Host
	}
	if path == "" {
		return nil, fmt.Errorf("sqlite requires database_name or host file path")
	}
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)", path)
	if cfg.ReadOnly && path != ":memory:" {
		dsn += "&_pragma=query_only(1)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &sqliteConn{db: db, cfg: cfg}, nil
}

type sqliteConn struct {
	db  *sql.DB
	cfg driver.ConnectionConfig
}

func (c *sqliteConn) Ping(ctx context.Context) (types.PingResult, error) {
	start := time.Now()
	var ver string
	err := c.db.QueryRowContext(ctx, "SELECT sqlite_version()").Scan(&ver)
	lat := time.Since(start).Milliseconds()
	if err != nil {
		return types.PingResult{Engine: "sqlite", Reachable: false, LatencyMs: lat, Error: err.Error()}, err
	}
	return types.PingResult{Engine: "sqlite", Reachable: true, ServerVersion: ver, LatencyMs: lat}, nil
}

func (c *sqliteConn) ListDatabases(ctx context.Context) ([]string, error) {
	rows, err := c.db.QueryContext(ctx, "PRAGMA database_list")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var dbs []string
	for rows.Next() {
		var seq int
		var name, file string
		if err := rows.Scan(&seq, &name, &file); err != nil {
			return nil, err
		}
		if file != "" {
			dbs = append(dbs, file)
		} else {
			dbs = append(dbs, name)
		}
	}
	return dbs, rows.Err()
}

func (c *sqliteConn) Preflight(ctx context.Context, raw string, _ driver.PreflightOpts) (*types.PreflightReport, error) {
	cls := classify.Classify("sqlite", raw)
	report := &types.PreflightReport{
		Supported: true,
		Executed:  false,
		Format:    "sqlite_query_plan",
	}
	if !cls.IsReadOnly || cls.StatementCount != 1 {
		report.Warnings = append(report.Warnings, "EXPLAIN QUERY PLAN skipped for non-read or multi-statement SQL")
		return report, nil
	}
	rows, err := c.db.QueryContext(ctx, "EXPLAIN QUERY PLAN "+raw)
	if err != nil {
		report.Warnings = append(report.Warnings, "EXPLAIN QUERY PLAN failed: "+err.Error())
		return report, nil
	}
	defer func() { _ = rows.Close() }()

	var lines []string
	var rawPlan []map[string]any
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			return report, nil
		}
		lines = append(lines, detail)
		rawPlan = append(rawPlan, map[string]any{"id": id, "parent": parent, "detail": detail})
		upper := strings.ToUpper(detail)
		if strings.HasPrefix(upper, "SCAN ") && !strings.Contains(upper, "USING COVERING INDEX") && !strings.Contains(upper, "USING INDEX") {
			report.FullScan = true
		}
	}
	report.PlanSummary = strings.Join(lines, "\n")
	report.PlanRaw = rawPlan
	return report, nil
}

func (c *sqliteConn) Execute(ctx context.Context, raw string, opts driver.ExecOpts) (*types.ExecResult, error) {
	start := time.Now()
	cls := classify.Classify("sqlite", raw)
	// Use QueryContext when single read statement; ExecContext otherwise (or multi-statement fallback).
	if cls.IsReadOnly && cls.StatementCount == 1 {
		rows, err := c.db.QueryContext(ctx, raw)
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

	sqlRes, err := c.db.ExecContext(ctx, raw)
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

func (c *sqliteConn) CancelAndDiscard() error {
	return c.db.Close()
}

func (c *sqliteConn) Close() error {
	if c.cfg.CloseHook != nil {
		_ = c.cfg.CloseHook()
	}
	return c.db.Close()
}

func collectSQLRows(rows *sql.Rows, opts driver.ExecOpts) (*types.ExecResult, error) {
	colTypes, err := rows.ColumnTypes()
	if err != nil {
		return nil, err
	}
	cols := make([]types.Column, len(colTypes))
	for i, ct := range colTypes {
		cols[i] = types.Column{
			Name:     ct.Name(),
			TypeName: strings.ToUpper(ct.DatabaseTypeName()),
		}
	}

	buf := driver.RowBuffer{MaxRows: opts.MaxRows, MaxBytes: opts.MaxBytes}
	var outRows [][]any
	for rows.Next() {
		scanDest := make([]any, len(cols))
		scanPtrs := make([]any, len(cols))
		for i := range cols {
			scanPtrs[i] = &scanDest[i]
		}
		if err := rows.Scan(scanPtrs...); err != nil {
			return nil, err
		}
		norm := make([]any, len(cols))
		for i, v := range scanDest {
			norm[i] = normalizeSQLValue(v)
		}
		if buf.TryAcceptRow(norm) {
			outRows = append(outRows, norm)
		} else if buf.Truncated {
			// Continue counting remaining rows? Stop early after a bounded lookahead to avoid scanning millions of rows.
			if buf.FetchedRows >= opts.MaxRows+1000 {
				break
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
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
	}, nil
}

func normalizeSQLValue(v any) any {
	switch x := v.(type) {
	case nil:
		return nil
	case []byte:
		var js any
		if len(x) > 0 && (x[0] == '{' || x[0] == '[') && json.Unmarshal(x, &js) == nil {
			return js
		}
		return string(x)
	case time.Time:
		return x.UTC().Format(time.RFC3339Nano)
	default:
		return x
	}
}
