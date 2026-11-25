package builtin

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	_ "modernc.org/sqlite"

	"github.com/x0c/agent-dbctl/internal/classify"
	"github.com/x0c/agent-dbctl/internal/driver"
	"github.com/x0c/agent-dbctl/internal/types"
)

// RegisterAll registers all Tier-1 built-in pure Go drivers into a registry.
func RegisterAll(reg *driver.Registry) {
	reg.Register(&PostgresDriver{})
	reg.Register(&OpenGaussDriver{})
	reg.Register(&KingbaseDriver{})
	reg.Register(&DamengDriver{})
	reg.Register(&TDengineDriver{})
	reg.Register(&MySQLDriver{})
	reg.Register(&SQLiteDriver{})
	reg.Register(&MongoDriver{})
	reg.Register(&RedisDriver{})
	reg.Register(&ClickHouseDriver{})
	reg.Register(&MSSQLDriver{})
	reg.Register(&OracleDriver{})
	reg.Register(&ElasticsearchDriver{})
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
		Version:      "1.1.0",
		Capabilities: []string{"ping", "list_databases", "schema", "preflight", "execute"},
		Verified:     true,
		Labels:       map[string]string{"en": "SQLite", "zh": "SQLite"},
	}
}

func (d *SQLiteDriver) Classify(_ context.Context, raw string) (types.Classification, error) {
	return classify.Classify("sqlite", raw), nil
}

func (d *SQLiteDriver) Open(ctx context.Context, cfg driver.ConnectionConfig) (driver.Conn, error) {
	dsn, err := buildSQLiteDSN(cfg)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	sc := &sqliteConn{
		db:        db,
		cfg:       cfg,
		closeHook: driver.CloseOnce(cfg.CloseHook),
	}
	if cfg.NegotiatedCapabilities != nil {
		cp := *cfg.NegotiatedCapabilities
		sc.caps.Store(&cp)
	}
	return sc, nil
}

func buildSQLiteDSN(cfg driver.ConnectionConfig) (string, error) {
	path := strings.TrimSpace(cfg.DatabaseName)
	if path == "" {
		path = strings.TrimSpace(cfg.Host)
	}
	if path == "" {
		return "", fmt.Errorf("sqlite requires database_name or host file path")
	}
	if path != ":memory:" && !strings.HasPrefix(path, "file:") {
		path = expandHomePath(path)
	}

	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(1)")
	if cfg.ReadOnly && path != ":memory:" {
		// VFS mode=ro prevents accidentally creating empty files on read-only probes.
		q.Set("mode", "ro")
		q.Add("_pragma", "query_only(1)")
	}
	for k, v := range cfg.Params {
		key := strings.ToLower(strings.TrimSpace(k))
		val := strings.TrimSpace(v)
		switch key {
		case "journal_mode", "synchronous", "cache_size", "temp_store", "busy_timeout":
			if val != "" && !strings.ContainsAny(val, ";\r\n") {
				q.Add("_pragma", fmt.Sprintf("%s(%s)", key, val))
			}
		case "mode":
			if !cfg.ReadOnly && val != "" {
				q.Set("mode", val)
			}
		case "cache":
			if val != "" {
				q.Set("cache", val)
			}
		}
	}

	if path == ":memory:" {
		return "file::memory:?" + q.Encode(), nil
	}
	// If already a file: URI, preserve its path/authority cleanly.
	if strings.HasPrefix(path, "file:") {
		if u, err := url.Parse(path); err == nil {
			existing := u.Query()
			for k, vals := range q {
				if k == "_pragma" {
					for _, val := range vals {
						existing.Add(k, val)
					}
				} else if !existing.Has(k) {
					existing.Set(k, vals[0])
				}
			}
			u.RawQuery = existing.Encode()
			return u.String(), nil
		}
	}
	slashed := filepath.ToSlash(path)
	u := url.URL{
		Scheme:   "file",
		RawQuery: q.Encode(),
	}
	switch {
	case isWindowsDrivePath(slashed):
		// RFC 8089 / SQLite require three slashes before a Windows drive letter (file:///C:/...)
		// so SQLite does not parse the drive letter as an invalid URI authority.
		u.Path = "/" + strings.ReplaceAll(slashed, "\\", "/")
	case strings.HasPrefix(slashed, "/"):
		u.Path = slashed
	default:
		// OmitHost prevents url.URL.String from emitting file://rel/path (treating rel as host).
		u.OmitHost = true
		u.Path = slashed
	}
	return u.String(), nil
}

func isWindowsDrivePath(p string) bool {
	if len(p) < 3 {
		return false
	}
	c := p[0]
	isAlpha := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
	return isAlpha && p[1] == ':' && (p[2] == '/' || p[2] == '\\')
}

type sqliteConn struct {
	db        *sql.DB
	cfg       driver.ConnectionConfig
	closeHook func() error
	closeOnce sync.Once
	closeErr  error
	caps      atomic.Pointer[types.ServerCapabilities]
}

func (c *sqliteConn) Capabilities() *types.ServerCapabilities {
	return c.caps.Load()
}

func (c *sqliteConn) ResetSession(ctx context.Context) error {
	if c.db == nil {
		return fmt.Errorf("sqlite db handle is closed")
	}
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return c.db.PingContext(pingCtx)
}

func (c *sqliteConn) Ping(ctx context.Context) (types.PingResult, error) {
	start := time.Now()
	var ver string
	err := c.db.QueryRowContext(ctx, "SELECT sqlite_version()").Scan(&ver)
	lat := time.Since(start).Milliseconds()
	if err != nil {
		return types.PingResult{Engine: "sqlite", Reachable: false, LatencyMs: lat, Error: err.Error()}, err
	}
	caps := driver.DetectServerCapabilities("sqlite", ver, driver.DialectHints{})
	c.caps.Store(&caps)
	return types.PingResult{
		Engine:        "sqlite",
		Dialect:       caps.Dialect,
		Reachable:     true,
		ServerVersion: ver,
		Capabilities:  &caps,
		LatencyMs:     lat,
	}, nil
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
	if !driver.CanPreflightSQL(cls) {
		report.Warnings = append(report.Warnings, "EXPLAIN QUERY PLAN skipped for DDL/admin/multi-statement SQL")
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
		if strings.HasPrefix(upper, "SCAN ") && !strings.Contains(upper, "USING COVERING INDEX") && !strings.Contains(upper, "USING INDEX") && !isSQLiteCatalogScan(upper) {
			report.FullScan = true
		}
	}
	report.PlanSummary = strings.Join(lines, "\n")
	report.PlanRaw = rawPlan
	return report, nil
}

func isSQLiteCatalogScan(upperDetail string) bool {
	return strings.HasPrefix(upperDetail, "SCAN SQLITE_MASTER") ||
		strings.HasPrefix(upperDetail, "SCAN SQLITE_SCHEMA") ||
		strings.HasPrefix(upperDetail, "SCAN SQLITE_TEMP_MASTER") ||
		strings.HasPrefix(upperDetail, "SCAN SQLITE_TEMP_SCHEMA")
}

func (c *sqliteConn) Execute(ctx context.Context, raw string, opts driver.ExecOpts) (*types.ExecResult, error) {
	start := time.Now()
	cls := classify.Classify("sqlite", raw)
	// Use QueryContext for single-statement reads and DML ... RETURNING; ExecContext otherwise.
	if cls.StatementCount == 1 && (cls.IsReadOnly || classify.HasReturningClause(raw)) {
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

func (c *sqliteConn) ListTables(ctx context.Context, opts driver.SchemaListOpts) (*types.SchemaListResult, error) {
	rows, err := c.db.QueryContext(ctx, `
		SELECT name, type
		FROM sqlite_master
		WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%'
		ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var all []types.SchemaObjectSummary
	for rows.Next() {
		var name, objType string
		if err := rows.Scan(&name, &objType); err != nil {
			return nil, err
		}
		all = append(all, types.SchemaObjectSummary{
			Name: name,
			Type: strings.ToLower(objType),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	items, total, truncated := driver.FilterAndCapSchemaObjects(all, opts.Search, opts.Limit)
	return &types.SchemaListResult{
		Engine:        "sqlite",
		Dialect:       "sqlite",
		Database:      c.cfg.DatabaseName,
		Items:         items,
		TotalCount:    total,
		ReturnedCount: len(items),
		Truncated:     truncated,
	}, nil
}

func (c *sqliteConn) DescribeTable(ctx context.Context, name string) (*types.TableSchema, error) {
	_, tbl := driver.SplitQualifiedObject(name)
	if tbl == "" {
		return nil, fmt.Errorf("table name is required")
	}
	var resolvedName, objType string
	if err := c.db.QueryRowContext(ctx, `
		SELECT name, type
		FROM sqlite_master
		WHERE type IN ('table', 'view') AND LOWER(name) = LOWER(?)
		LIMIT 1`, tbl).Scan(&resolvedName, &objType); err != nil {
		return nil, fmt.Errorf("table or view %q not found", tbl)
	}
	quoted := driver.QuoteSQLiteIdent(resolvedName)

	colRows, err := c.db.QueryContext(ctx, "PRAGMA table_info("+quoted+")")
	if err != nil {
		return nil, err
	}
	defer func() { _ = colRows.Close() }()

	var cols []types.SchemaColumn
	for colRows.Next() {
		var cid, notnull, pk int
		var cname, ctype string
		var dflt sql.NullString
		if err := colRows.Scan(&cid, &cname, &ctype, &notnull, &dflt, &pk); err != nil {
			return nil, err
		}
		cols = append(cols, types.SchemaColumn{
			Name:       cname,
			Type:       ctype,
			Nullable:   notnull == 0 && pk == 0,
			PrimaryKey: pk > 0,
			Default:    dflt.String,
		})
	}
	if err := colRows.Err(); err != nil {
		return nil, err
	}

	var idxs []types.SchemaIndex
	idxListRows, err := c.db.QueryContext(ctx, "PRAGMA index_list("+quoted+")")
	if err == nil {
		type rawIdx struct {
			name   string
			unique bool
			origin string
		}
		var rawIdxs []rawIdx
		for idxListRows.Next() {
			var seq, unique, partial int
			var idxName, origin string
			if idxListRows.Scan(&seq, &idxName, &unique, &origin, &partial) == nil {
				rawIdxs = append(rawIdxs, rawIdx{name: idxName, unique: unique == 1, origin: origin})
			}
		}
		_ = idxListRows.Close()

		for _, ri := range rawIdxs {
			var idxCols []string
			infoRows, infoErr := c.db.QueryContext(ctx, "PRAGMA index_info("+driver.QuoteSQLiteIdent(ri.name)+")")
			if infoErr == nil {
				for infoRows.Next() {
					var seqno, cid int
					var colName sql.NullString
					if infoRows.Scan(&seqno, &cid, &colName) == nil && colName.Valid {
						idxCols = append(idxCols, colName.String)
					}
				}
				_ = infoRows.Close()
			}
			idxs = append(idxs, types.SchemaIndex{
				Name:    ri.name,
				Columns: idxCols,
				Unique:  ri.unique,
				Primary: ri.origin == "pk",
			})
		}
	}

	var fks []types.SchemaForeignKey
	fkRows, err := c.db.QueryContext(ctx, "PRAGMA foreign_key_list("+quoted+")")
	if err == nil {
		for fkRows.Next() {
			var id, seq int
			var refTable, fromCol, toCol, onUpd, onDel, match string
			if fkRows.Scan(&id, &seq, &refTable, &fromCol, &toCol, &onUpd, &onDel, &match) == nil {
				fks = append(fks, types.SchemaForeignKey{
					Column:           fromCol,
					ReferencedTable:  refTable,
					ReferencedColumn: toCol,
				})
			}
		}
		_ = fkRows.Close()
	}

	return &types.TableSchema{
		Engine:      "sqlite",
		Dialect:     "sqlite",
		Database:    c.cfg.DatabaseName,
		Name:        resolvedName,
		ObjectType:  strings.ToLower(objType),
		Columns:     cols,
		Indexes:     idxs,
		ForeignKeys: fks,
	}, nil
}

func (c *sqliteConn) CancelAndDiscard() error {
	return c.Close()
}

func (c *sqliteConn) Close() error {
	c.closeOnce.Do(func() {
		if c.closeHook != nil {
			_ = c.closeHook()
		}
		c.closeErr = c.db.Close()
	})
	return c.closeErr
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
			norm[i] = normalizeTypedSQLValue(v, cols[i].TypeName)
		}
		if buf.TryAcceptRow(norm) {
			outRows = append(outRows, norm)
		} else if buf.ShouldStopLookahead() {
			break
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

func expandHomePath(p string) string {
	trimmed := strings.TrimSpace(p)
	if trimmed == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return home
		}
		return trimmed
	}
	if strings.HasPrefix(trimmed, "~/") || strings.HasPrefix(trimmed, `~\`) {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, trimmed[2:])
		}
	}
	return trimmed
}

func normalizeTypedSQLValue(v any, typeName string) any {
	switch x := v.(type) {
	case nil:
		return nil
	case []byte:
		upperType := strings.ToUpper(typeName)
		isBinaryCol := strings.Contains(upperType, "BLOB") ||
			strings.Contains(upperType, "BYTEA") ||
			strings.Contains(upperType, "BINARY")
		if isBinaryCol && !utf8.Valid(x) {
			return base64.StdEncoding.EncodeToString(x)
		}
		if !isBinaryCol || strings.Contains(upperType, "JSON") {
			var js any
			if len(x) > 0 && (x[0] == '{' || x[0] == '[') && json.Unmarshal(x, &js) == nil {
				return js
			}
		}
		if !utf8.Valid(x) {
			return base64.StdEncoding.EncodeToString(x)
		}
		return string(x)
	case time.Time:
		return x.UTC().Format(time.RFC3339Nano)
	case float64:
		if math.IsNaN(x) {
			return "NaN"
		}
		if math.IsInf(x, 1) {
			return "Infinity"
		}
		if math.IsInf(x, -1) {
			return "-Infinity"
		}
		return x
	case float32:
		f := float64(x)
		if math.IsNaN(f) {
			return "NaN"
		}
		if math.IsInf(f, 1) {
			return "Infinity"
		}
		if math.IsInf(f, -1) {
			return "-Infinity"
		}
		return x
	default:
		return x
	}
}
