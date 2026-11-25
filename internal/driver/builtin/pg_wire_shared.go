package builtin

import (
	"context"
	"database/sql"
	sqldriver "database/sql/driver"
	"encoding/json"
	"fmt"
	"net"
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

// pgWireDialectConfig parameterizes a PostgreSQL-wire-compatible database/sql driver
// (such as openGauss or KingbaseES) without duplicating execution, preflight, or schema logic.
type pgWireDialectConfig struct {
	Engine               string
	DefaultPort          int
	DefaultDatabase      string
	ListDatabasesQueries []string
	IndexQueries         []string
	SetReadOnlySQLs      []string
}

// readOnlyExecConnector enforces session-level read-only constraints on every new physical connection.
type readOnlyExecConnector struct {
	inner     sqldriver.Connector
	stmts     []string
	errPrefix string
}

func (c *readOnlyExecConnector) Connect(ctx context.Context) (sqldriver.Conn, error) {
	conn, err := c.inner.Connect(ctx)
	if err != nil {
		return nil, err
	}
	execer, ok := conn.(sqldriver.ExecerContext)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("%s driver connection does not support ExecContext for read-only enforcement", c.errPrefix)
	}
	var lastErr error
	for _, stmt := range c.stmts {
		if _, err := execer.ExecContext(ctx, stmt, nil); err == nil {
			return conn, nil
		} else {
			lastErr = err
		}
	}
	_ = conn.Close()
	return nil, fmt.Errorf("enforce %s read-only session failed: %w", c.errPrefix, lastErr)
}

func (c *readOnlyExecConnector) Driver() sqldriver.Driver {
	return c.inner.Driver()
}

// pgWireConn provides unified Ping, ListDatabases, Preflight, Execute, and SchemaInspector
// over a database/sql handle backed by a PG-wire driver ($1, $2 placeholders).
type pgWireConn struct {
	db        *sql.DB
	cfg       driver.ConnectionConfig
	dialect   pgWireDialectConfig
	closeHook func() error
	closeOnce sync.Once
	closeErr  error
	caps      atomic.Pointer[types.ServerCapabilities]
}

func newPGWireConn(db *sql.DB, cfg driver.ConnectionConfig, dialect pgWireDialectConfig) *pgWireConn {
	c := &pgWireConn{
		db:        db,
		cfg:       cfg,
		dialect:   dialect,
		closeHook: driver.CloseOnce(cfg.CloseHook),
	}
	if cfg.NegotiatedCapabilities != nil {
		cp := *cfg.NegotiatedCapabilities
		c.caps.Store(&cp)
	}
	return c
}

func (c *pgWireConn) Capabilities() *types.ServerCapabilities {
	return c.caps.Load()
}

func (c *pgWireConn) ResetSession(ctx context.Context) error {
	if c.db == nil {
		return fmt.Errorf("%s db handle is closed", c.dialect.Engine)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return c.db.PingContext(pingCtx)
}

func (c *pgWireConn) Ping(ctx context.Context) (types.PingResult, error) {
	start := time.Now()
	var ver string
	err := c.db.QueryRowContext(ctx, "SELECT version()").Scan(&ver)
	if err != nil {
		if fbErr := c.db.QueryRowContext(ctx, "SHOW server_version").Scan(&ver); fbErr == nil {
			err = nil
		}
	}
	lat := time.Since(start).Milliseconds()
	if err != nil {
		return types.PingResult{Engine: c.dialect.Engine, Reachable: false, LatencyMs: lat, Error: err.Error()}, err
	}
	detectEngine := c.cfg.Engine
	if strings.TrimSpace(detectEngine) == "" {
		detectEngine = c.dialect.Engine
	}
	caps := driver.DetectServerCapabilities(detectEngine, ver, driver.DialectHints{})
	c.caps.Store(&caps)
	return types.PingResult{
		Engine:        c.dialect.Engine,
		Dialect:       caps.Dialect,
		Reachable:     true,
		ServerVersion: ver,
		Capabilities:  &caps,
		LatencyMs:     lat,
	}, nil
}

func (c *pgWireConn) ListDatabases(ctx context.Context) ([]string, error) {
	var lastErr error
	for _, q := range c.dialect.ListDatabasesQueries {
		rows, err := c.db.QueryContext(ctx, q)
		if err != nil {
			lastErr = err
			continue
		}
		var out []string
		for rows.Next() {
			var name string
			if scanErr := rows.Scan(&name); scanErr != nil {
				lastErr = scanErr
				out = nil
				break
			}
			if name != "" {
				out = append(out, name)
			}
		}
		if rowsErr := rows.Err(); rowsErr != nil {
			lastErr = rowsErr
			_ = rows.Close()
			continue
		}
		_ = rows.Close()
		if len(out) > 0 || lastErr == nil {
			return out, nil
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, nil
}

func (c *pgWireConn) Preflight(ctx context.Context, raw string, _ driver.PreflightOpts) (*types.PreflightReport, error) {
	cls := classify.Classify(c.dialect.Engine, raw)
	report := &types.PreflightReport{
		Supported: true,
		Executed:  false,
		Format:    "pg_json",
	}
	if !driver.CanPreflightSQL(cls) {
		report.Warnings = append(report.Warnings, "EXPLAIN skipped for DDL/admin/multi-statement SQL")
		return report, nil
	}
	if caps := c.Capabilities(); caps != nil && caps.SupportsExplain && !caps.SupportsExplainJSON {
		return c.preflightText(ctx, raw, report, nil)
	}

	var jsonStr string
	if err := c.db.QueryRowContext(ctx, "EXPLAIN (FORMAT JSON) "+raw).Scan(&jsonStr); err == nil {
		var nodes []map[string]any
		if uErr := json.Unmarshal([]byte(jsonStr), &nodes); uErr == nil && len(nodes) > 0 {
			report.PlanRaw = nodes[0]
			if plan, ok := nodes[0]["Plan"].(map[string]any); ok {
				walkPGPlan(plan, report)
				report.PlanSummary = fmt.Sprintf("Top node: %v, estimated rows: %d, full_scan: %v", plan["Node Type"], report.EstimatedRows, report.FullScan)
				return report, nil
			}
		}
		// Fallback to text EXPLAIN if JSON payload was non-standard.
		return c.preflightText(ctx, raw, report, nil)
	} else {
		return c.preflightText(ctx, raw, report, err)
	}
}

func (c *pgWireConn) preflightText(ctx context.Context, raw string, report *types.PreflightReport, jsonErr error) (*types.PreflightReport, error) {
	rows, textErr := c.db.QueryContext(ctx, "EXPLAIN "+raw)
	if textErr != nil {
		msgErr := textErr
		if jsonErr != nil {
			msgErr = jsonErr
		}
		report.Warnings = append(report.Warnings, "EXPLAIN failed: "+msgErr.Error())
		return report, nil
	}
	defer func() { _ = rows.Close() }()
	var lines []string
	for rows.Next() {
		var line string
		if rows.Scan(&line) == nil {
			lines = append(lines, line)
		}
	}
	if rows.Err() != nil || len(lines) == 0 {
		msgErr := rows.Err()
		if jsonErr != nil {
			msgErr = jsonErr
		}
		if msgErr != nil {
			report.Warnings = append(report.Warnings, "EXPLAIN failed: "+msgErr.Error())
		}
		return report, nil
	}
	report.Format = "pg_text"
	parsePGTextPlan(lines, report)
	return report, nil
}

func (c *pgWireConn) Execute(ctx context.Context, raw string, opts driver.ExecOpts) (*types.ExecResult, error) {
	start := time.Now()
	cls := classify.Classify(c.dialect.Engine, raw)
	if c.cfg.ReadOnly && !cls.IsReadOnly {
		return nil, fmt.Errorf("read-only mode blocks non-read %s statement (%s)", c.dialect.Engine, cls.RiskLevel)
	}
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

func (c *pgWireConn) ListTables(ctx context.Context, opts driver.SchemaListOpts) (*types.SchemaListResult, error) {
	rows, err := c.db.QueryContext(ctx, `
		SELECT table_schema, table_name, table_type
		FROM information_schema.tables
		WHERE table_schema NOT IN ('pg_catalog', 'information_schema', 'sys_catalog', 'dbe_perf', 'dbe_pldeveloper', 'dbe_pldebugger', 'snapshot', 'sqladvisor', 'cstore', 'db4ai', 'blockchain')
		ORDER BY (table_schema = current_schema()) DESC, table_schema, table_name`)
	if err != nil {
		rows, err = c.db.QueryContext(ctx, `
			SELECT table_schema, table_name, table_type
			FROM information_schema.tables
			WHERE table_schema NOT IN ('pg_catalog', 'information_schema', 'sys_catalog')
			ORDER BY table_schema, table_name`)
		if err != nil {
			return nil, err
		}
	}
	defer func() { _ = rows.Close() }()

	var all []types.SchemaObjectSummary
	for rows.Next() {
		var sch, name, ttype string
		if err := rows.Scan(&sch, &name, &ttype); err != nil {
			return nil, err
		}
		objType := "table"
		if strings.Contains(strings.ToUpper(ttype), "VIEW") {
			objType = "view"
		}
		all = append(all, types.SchemaObjectSummary{
			Schema: sch,
			Name:   name,
			Type:   objType,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	items, total, truncated := driver.FilterAndCapSchemaObjects(all, opts.Search, opts.Limit)
	return &types.SchemaListResult{
		Engine:        c.dialect.Engine,
		Dialect:       c.activeDialect(),
		Database:      c.cfg.DatabaseName,
		Items:         items,
		TotalCount:    total,
		ReturnedCount: len(items),
		Truncated:     truncated,
	}, nil
}

func (c *pgWireConn) DescribeTable(ctx context.Context, name string) (*types.TableSchema, error) {
	sch, tbl := driver.SplitQualifiedObject(name)
	if tbl == "" {
		return nil, fmt.Errorf("table name is required")
	}
	explicitSchema := sch != ""
	if !explicitSchema {
		_ = c.db.QueryRowContext(ctx, "SELECT current_schema()").Scan(&sch)
		if sch == "" {
			sch = "public"
		}
	}

	cols, pkSet, err := c.queryColumnsAndPK(ctx, sch, tbl)
	if err != nil {
		return nil, err
	}
	if len(cols) == 0 && !explicitSchema {
		// Engines like openGauss return "$user" from current_schema() even when no user schema exists
		// and tables live in "public" or another visible schema on search_path.
		var candidates []string
		if !strings.EqualFold(sch, "public") {
			candidates = append(candidates, "public")
		}
		var resolved string
		if rErr := c.db.QueryRowContext(ctx, `
			SELECT table_schema
			FROM information_schema.tables
			WHERE table_schema NOT IN ('pg_catalog', 'information_schema', 'sys_catalog')
			  AND table_name = $1
			ORDER BY table_schema
			LIMIT 1`, tbl).Scan(&resolved); rErr == nil && resolved != "" && resolved != sch {
			candidates = append(candidates, resolved)
		}
		for _, cand := range candidates {
			cCols, cPK, cErr := c.queryColumnsAndPK(ctx, cand, tbl)
			if cErr == nil && len(cCols) > 0 {
				sch, cols, pkSet = cand, cCols, cPK
				break
			}
		}
	}
	if len(cols) == 0 {
		return nil, fmt.Errorf("table or view %s.%s not found", sch, tbl)
	}
	_ = pkSet

	var fks []types.SchemaForeignKey
	fkRows, err := c.db.QueryContext(ctx, `
		SELECT kcu.column_name, ccu.table_name, ccu.column_name
		FROM information_schema.table_constraints tc
		JOIN information_schema.key_column_usage kcu
		  ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema
		JOIN information_schema.constraint_column_usage ccu
		  ON ccu.constraint_name = tc.constraint_name AND ccu.table_schema = tc.table_schema
		WHERE tc.constraint_type = 'FOREIGN KEY' AND tc.table_schema = $1 AND tc.table_name = $2`, sch, tbl)
	if err == nil {
		for fkRows.Next() {
			var fk types.SchemaForeignKey
			if fkRows.Scan(&fk.Column, &fk.ReferencedTable, &fk.ReferencedColumn) == nil {
				fks = append(fks, fk)
			}
		}
		_ = fkRows.Close()
	}

	var idxs []types.SchemaIndex
	for _, iq := range c.dialect.IndexQueries {
		idxRows, iqErr := c.db.QueryContext(ctx, iq, sch, tbl)
		if iqErr != nil {
			continue
		}
		for idxRows.Next() {
			var idxName, idxDef string
			if idxRows.Scan(&idxName, &idxDef) == nil {
				idxs = append(idxs, types.SchemaIndex{
					Name:    idxName,
					Columns: driver.ParsePGIndexColumns(idxDef),
					Unique:  strings.Contains(strings.ToUpper(idxDef), "CREATE UNIQUE INDEX"),
					Primary: strings.HasSuffix(strings.ToLower(idxName), "_pkey"),
				})
			}
		}
		_ = idxRows.Close()
		break
	}

	return &types.TableSchema{
		Engine:      c.dialect.Engine,
		Dialect:     c.activeDialect(),
		Database:    c.cfg.DatabaseName,
		Schema:      sch,
		Name:        tbl,
		ObjectType:  "table",
		Columns:     cols,
		Indexes:     idxs,
		ForeignKeys: fks,
	}, nil
}

func (c *pgWireConn) queryColumnsAndPK(ctx context.Context, sch, tbl string) ([]types.SchemaColumn, map[string]bool, error) {
	pkSet := map[string]bool{}
	pkRows, err := c.db.QueryContext(ctx, `
		SELECT kcu.column_name
		FROM information_schema.table_constraints tc
		JOIN information_schema.key_column_usage kcu
		  ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema
		WHERE tc.constraint_type = 'PRIMARY KEY' AND tc.table_schema = $1 AND tc.table_name = $2`, sch, tbl)
	if err == nil {
		for pkRows.Next() {
			var col string
			if pkRows.Scan(&col) == nil {
				pkSet[col] = true
			}
		}
		_ = pkRows.Close()
	}

	colRows, err := c.db.QueryContext(ctx, `
		SELECT column_name, data_type, is_nullable, COALESCE(column_default, '')
		FROM information_schema.columns
		WHERE table_schema = $1 AND table_name = $2
		ORDER BY ordinal_position`, sch, tbl)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = colRows.Close() }()

	var cols []types.SchemaColumn
	for colRows.Next() {
		var cname, dtype, nullable, defVal string
		if err := colRows.Scan(&cname, &dtype, &nullable, &defVal); err != nil {
			return nil, nil, err
		}
		cols = append(cols, types.SchemaColumn{
			Name:       cname,
			Type:       dtype,
			Nullable:   strings.EqualFold(nullable, "YES"),
			PrimaryKey: pkSet[cname],
			Default:    defVal,
		})
	}
	if err := colRows.Err(); err != nil {
		return nil, nil, err
	}
	return cols, pkSet, nil
}

func (c *pgWireConn) activeDialect() string {
	if caps := c.Capabilities(); caps != nil && caps.Dialect != "" {
		return caps.Dialect
	}
	return c.dialect.Engine
}

func (c *pgWireConn) CancelAndDiscard() error {
	return c.Close()
}

func (c *pgWireConn) Close() error {
	c.closeOnce.Do(func() {
		if c.closeHook != nil {
			_ = c.closeHook()
		}
		c.closeErr = c.db.Close()
	})
	return c.closeErr
}

// buildPGWireURI constructs a libpq-compatible connection URI safely escaping credentials and query parameters.
func buildPGWireURI(scheme string, cfg driver.ConnectionConfig, defaultPort int, defaultDB string) string {
	port := cfg.Port
	if port <= 0 {
		port = defaultPort
	}
	host := strings.TrimSpace(cfg.Host)
	if host == "" {
		host = "127.0.0.1"
	}
	dbName := strings.TrimSpace(cfg.DatabaseName)
	if dbName == "" {
		dbName = defaultDB
	}

	u := &url.URL{
		Scheme: scheme,
		Host:   net.JoinHostPort(host, strconv.Itoa(port)),
		Path:   "/" + dbName,
	}
	if cfg.Credential.Username != "" || cfg.Credential.Secret != "" {
		u.User = url.UserPassword(cfg.Credential.Username, cfg.Credential.Secret)
	}

	q := url.Values{}
	q.Set("connect_timeout", "10")
	q.Set("application_name", "agent-dbctl")
	q.Set("sslmode", mapLibpqSSLMode(cfg.TLSMode))

	for k, v := range cfg.Params {
		kl := strings.ToLower(strings.TrimSpace(k))
		switch kl {
		case "sslmode", "host", "port", "user", "password", "dbname":
			// Controlled by instance/credential/NetworkProfile fields.
		case "connect_timeout":
			if d, err := parseDurationOrSeconds(v); err == nil && d > 0 {
				secs := max(1, int(d.Seconds()))
				q.Set("connect_timeout", strconv.Itoa(secs))
			}
		default:
			q.Set(strings.TrimSpace(k), v)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func mapLibpqSSLMode(tlsMode string) string {
	switch strings.ToLower(strings.TrimSpace(tlsMode)) {
	case "disable":
		return "disable"
	case "require":
		return "require"
	case "verify-ca":
		return "verify-ca"
	case "verify-full":
		return "verify-full"
	default:
		return "prefer"
	}
}
