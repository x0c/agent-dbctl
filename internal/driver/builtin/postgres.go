package builtin

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/x0c/agent-dbctl/internal/classify"
	"github.com/x0c/agent-dbctl/internal/driver"
	"github.com/x0c/agent-dbctl/internal/types"
)

var pgExplainRowsRe = regexp.MustCompile(`rows=(\d+)`)

// PostgresDriver implements PostgreSQL (and PG-wire compatible engines) using pure-Go pgx/v5.
type PostgresDriver struct{}

func (d *PostgresDriver) Metadata() types.DriverMetadata {
	return types.DriverMetadata{
		ID:           "builtin-postgres",
		Engine:       "postgres",
		DisplayName:  "PostgreSQL",
		Family:       types.FamilySQL,
		Tier:         "builtin",
		Version:      "1.1.0",
		Capabilities: []string{"ping", "list_databases", "schema", "preflight", "execute"},
		Verified:     true,
		Labels:       map[string]string{"en": "PostgreSQL", "zh": "PostgreSQL"},
	}
}

func (d *PostgresDriver) Classify(_ context.Context, raw string) (types.Classification, error) {
	return classify.Classify("postgres", raw), nil
}

func (d *PostgresDriver) Open(ctx context.Context, cfg driver.ConnectionConfig) (driver.Conn, error) {
	pgCfg, err := buildPGConfig(cfg)
	if err != nil {
		return nil, err
	}
	conn, err := pgx.ConnectConfig(ctx, pgCfg)
	if err != nil {
		return nil, err
	}
	pc := &postgresConn{
		conn:      conn,
		cfg:       cfg,
		closeHook: driver.CloseOnce(cfg.CloseHook),
	}
	if cfg.NegotiatedCapabilities != nil {
		cp := *cfg.NegotiatedCapabilities
		pc.caps.Store(&cp)
	}
	return pc, nil
}

func buildPGConfig(cfg driver.ConnectionConfig) (*pgx.ConnConfig, error) {
	port := cfg.Port
	if port <= 0 {
		port = 5432
	}
	dbName := cfg.DatabaseName
	if dbName == "" {
		dbName = "postgres"
	}
	host := strings.TrimSpace(cfg.Host)
	if host == "" {
		host = "127.0.0.1"
	}

	// Build ConnConfig directly instead of URL interpolation so IPv6 hosts and
	// database names containing special characters do not break DSN parsing.
	pgCfg, err := pgx.ParseConfig("")
	if err != nil {
		return nil, err
	}
	pgCfg.Host = host
	pgCfg.Port = uint16(port)
	pgCfg.Database = dbName
	pgCfg.User = cfg.Credential.Username
	pgCfg.Password = cfg.Credential.Secret
	pgCfg.TLSConfig = cfg.TLSConfig
	pgCfg.ConnectTimeout = 10 * time.Second
	if cfg.DialContext != nil {
		pgCfg.DialFunc = func(dctx context.Context, network, addr string) (net.Conn, error) {
			return cfg.DialContext(dctx, network, addr)
		}
	}
	if pgCfg.RuntimeParams == nil {
		pgCfg.RuntimeParams = map[string]string{}
	}
	pgCfg.RuntimeParams["application_name"] = "agent-dbctl"

	for k, v := range cfg.Params {
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "exec_mode", "query_exec_mode":
			mode, err := parsePGExecMode(v)
			if err != nil {
				return nil, err
			}
			pgCfg.DefaultQueryExecMode = mode
		case "connect_timeout":
			if d, err := parseDurationOrSeconds(v); err == nil && d > 0 {
				pgCfg.ConnectTimeout = d
			}
		case "sslmode":
			// TLS is controlled by NetworkProfile / Instance.TLSMode; ignore raw sslmode param here.
		default:
			pgCfg.RuntimeParams[k] = v
		}
	}
	// Enforce read-only after applying Params so user params cannot disable read-only mode.
	if cfg.ReadOnly {
		pgCfg.RuntimeParams["default_transaction_read_only"] = "on"
	}
	return pgCfg, nil
}

func parsePGExecMode(raw string) (pgx.QueryExecMode, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "cache_statement":
		return pgx.QueryExecModeCacheStatement, nil
	case "cache_describe":
		return pgx.QueryExecModeCacheDescribe, nil
	case "describe_exec":
		return pgx.QueryExecModeDescribeExec, nil
	case "exec":
		return pgx.QueryExecModeExec, nil
	case "simple_protocol", "simple":
		return pgx.QueryExecModeSimpleProtocol, nil
	default:
		return 0, fmt.Errorf("unsupported postgres exec_mode %q", raw)
	}
}

func parseDurationOrSeconds(raw string) (time.Duration, error) {
	s := strings.TrimSpace(raw)
	if secs, err := strconv.Atoi(s); err == nil {
		return time.Duration(secs) * time.Second, nil
	}
	return time.ParseDuration(s)
}

type postgresConn struct {
	conn      *pgx.Conn
	cfg       driver.ConnectionConfig
	closeHook func() error
	closeOnce sync.Once
	closeErr  error
	caps      atomic.Pointer[types.ServerCapabilities]
}

func (c *postgresConn) Capabilities() *types.ServerCapabilities {
	return c.caps.Load()
}

func (c *postgresConn) ResetSession(ctx context.Context) error {
	if c.conn == nil || c.conn.IsClosed() {
		return fmt.Errorf("postgres connection is closed")
	}
	pgConn := c.conn.PgConn()
	if pgConn == nil {
		return fmt.Errorf("postgres underlying connection missing")
	}
	if txStatus := pgConn.TxStatus(); txStatus != 'I' {
		return fmt.Errorf("postgres connection has non-idle transaction status %q", txStatus)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return c.conn.Ping(pingCtx)
}

func (c *postgresConn) Ping(ctx context.Context) (types.PingResult, error) {
	start := time.Now()
	var ver string
	err := c.conn.QueryRow(ctx, "SELECT version()").Scan(&ver)
	if err != nil {
		if fallbackErr := c.conn.QueryRow(ctx, "SHOW server_version").Scan(&ver); fallbackErr == nil {
			err = nil
		}
	}
	lat := time.Since(start).Milliseconds()
	if err != nil {
		return types.PingResult{Engine: "postgres", Reachable: false, LatencyMs: lat, Error: err.Error()}, err
	}
	caps := driver.DetectServerCapabilities("postgres", ver, driver.DialectHints{})
	c.caps.Store(&caps)
	return types.PingResult{
		Engine:        "postgres",
		Dialect:       caps.Dialect,
		Reachable:     true,
		ServerVersion: ver,
		Capabilities:  &caps,
		LatencyMs:     lat,
	}, nil
}

func (c *postgresConn) ListDatabases(ctx context.Context) ([]string, error) {
	rows, err := c.conn.Query(ctx, "SELECT datname FROM pg_database WHERE datistemplate = false AND datallowconn = true ORDER BY datname")
	if err != nil {
		rows, err = c.conn.Query(ctx, "SELECT datname FROM pg_database WHERE datistemplate = false ORDER BY datname")
		if err != nil {
			return nil, err
		}
	}
	defer rows.Close()
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

func (c *postgresConn) Preflight(ctx context.Context, raw string, _ driver.PreflightOpts) (*types.PreflightReport, error) {
	cls := classify.Classify("postgres", raw)
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
		return c.preflightPGText(ctx, raw, report, nil)
	}

	var jsonStr string
	if err := c.conn.QueryRow(ctx, "EXPLAIN (FORMAT JSON) "+raw).Scan(&jsonStr); err == nil {
		var nodes []map[string]any
		if err := json.Unmarshal([]byte(jsonStr), &nodes); err == nil && len(nodes) > 0 {
			report.PlanRaw = nodes[0]
			if plan, ok := nodes[0]["Plan"].(map[string]any); ok {
				walkPGPlan(plan, report)
				report.PlanSummary = fmt.Sprintf("Top node: %v, estimated rows: %d, full_scan: %v", plan["Node Type"], report.EstimatedRows, report.FullScan)
			}
		}
		return report, nil
	} else {
		// Fallback for older PostgreSQL (<9.0) or PG-wire engines without FORMAT JSON.
		return c.preflightPGText(ctx, raw, report, err)
	}
}

func (c *postgresConn) preflightPGText(ctx context.Context, raw string, report *types.PreflightReport, jsonErr error) (*types.PreflightReport, error) {
	rows, textErr := c.conn.Query(ctx, "EXPLAIN "+raw)
	if textErr != nil {
		msgErr := textErr
		if jsonErr != nil {
			msgErr = jsonErr
		}
		report.Warnings = append(report.Warnings, "EXPLAIN failed: "+msgErr.Error())
		return report, nil
	}
	defer rows.Close()
	var lines []string
	for rows.Next() {
		var line string
		if scanErr := rows.Scan(&line); scanErr == nil {
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

func walkPGPlan(node map[string]any, report *types.PreflightReport) {
	if nt, ok := node["Node Type"].(string); ok {
		upper := strings.ToUpper(strings.TrimSpace(nt))
		if (upper == "SEQ SCAN" || upper == "PARALLEL SEQ SCAN" || upper == "FOREIGN SCAN") && !isPGCatalogNode(node) {
			report.FullScan = true
		}
	}
	if rows, ok := node["Plan Rows"].(float64); ok && int64(rows) > report.EstimatedRows {
		report.EstimatedRows = int64(rows)
	}
	if children, ok := node["Plans"].([]any); ok {
		for _, ch := range children {
			if m, ok := ch.(map[string]any); ok {
				walkPGPlan(m, report)
			}
		}
	}
}

func isPGCatalogNode(node map[string]any) bool {
	if schema, ok := node["Schema"].(string); ok {
		s := strings.ToLower(strings.TrimSpace(schema))
		if s == "pg_catalog" || s == "information_schema" {
			return true
		}
	}
	if rel, ok := node["Relation Name"].(string); ok {
		r := strings.ToLower(strings.TrimSpace(rel))
		if strings.HasPrefix(r, "pg_") {
			return true
		}
	}
	return false
}

func parsePGTextPlan(lines []string, report *types.PreflightReport) {
	for _, line := range lines {
		upper := strings.ToUpper(line)
		if strings.Contains(upper, "SEQ SCAN") || strings.Contains(upper, "SEQUENTIAL SCAN") || strings.Contains(upper, "FOREIGN SCAN") {
			report.FullScan = true
		}
		if m := pgExplainRowsRe.FindStringSubmatch(line); len(m) == 2 {
			if n, err := strconv.ParseInt(m[1], 10, 64); err == nil && n > report.EstimatedRows {
				report.EstimatedRows = n
			}
		}
	}
	report.PlanRaw = lines
	report.PlanSummary = strings.Join(lines, "\n")
}

func (c *postgresConn) Execute(ctx context.Context, raw string, opts driver.ExecOpts) (*types.ExecResult, error) {
	start := time.Now()
	cls := classify.Classify("postgres", raw)
	useQuery := cls.StatementCount == 1 && (cls.IsReadOnly || classify.HasReturningClause(raw))
	if useQuery {
		rows, err := c.conn.Query(ctx, raw)
		if err != nil {
			return nil, err
		}
		defer rows.Close()

		fds := rows.FieldDescriptions()
		cols := make([]types.Column, len(fds))
		tm := c.conn.TypeMap()
		for i, fd := range fds {
			typeName := fmt.Sprintf("OID_%d", fd.DataTypeOID)
			if tm != nil {
				if dt, ok := tm.TypeForOID(fd.DataTypeOID); ok && dt.Name != "" {
					typeName = strings.ToUpper(dt.Name)
				}
			}
			cols[i] = types.Column{
				Name:     fd.Name,
				TypeName: typeName,
			}
		}
		buf := driver.RowBuffer{MaxRows: opts.MaxRows, MaxBytes: opts.MaxBytes}
		var outRows [][]any
		for rows.Next() {
			if buf.Truncated {
				buf.RecordLookahead()
				if buf.ShouldStopLookahead() {
					break
				}
				continue
			}
			vals, err := rows.Values()
			if err != nil {
				return nil, err
			}
			for i, v := range vals {
				typeName := ""
				if i < len(cols) {
					typeName = cols[i].TypeName
				}
				vals[i] = normalizePGValue(v, typeName)
			}
			if buf.TryAcceptRow(vals) {
				outRows = append(outRows, vals)
			} else if buf.ShouldStopLookahead() {
				break
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		var affPtr *int64
		if !cls.IsReadOnly {
			aff := rows.CommandTag().RowsAffected()
			affPtr = &aff
		}
		return &types.ExecResult{
			Family:        types.FamilySQL,
			Columns:       cols,
			Rows:          outRows,
			AffectedRows:  affPtr,
			FetchedRows:   buf.FetchedRows,
			ReturnedRows:  len(outRows),
			ReturnedBytes: buf.ReturnedBytes,
			Truncated:     buf.Truncated,
			CutoffReason:  buf.CutoffReason,
			LatencyMs:     time.Since(start).Milliseconds(),
		}, nil
	}

	tag, err := c.conn.Exec(ctx, raw)
	if err != nil {
		return nil, err
	}
	aff := tag.RowsAffected()
	return &types.ExecResult{
		Family:       types.FamilySQL,
		AffectedRows: &aff,
		LatencyMs:    time.Since(start).Milliseconds(),
	}, nil
}

func (c *postgresConn) ListTables(ctx context.Context, opts driver.SchemaListOpts) (*types.SchemaListResult, error) {
	rows, err := c.conn.Query(ctx, `
		SELECT table_schema, table_name, table_type
		FROM information_schema.tables
		WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
		ORDER BY (table_schema = current_schema()) DESC, table_schema, table_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

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
	dialect := "postgres"
	if caps := c.Capabilities(); caps != nil && caps.Dialect != "" {
		dialect = caps.Dialect
	}
	return &types.SchemaListResult{
		Engine:        "postgres",
		Dialect:       dialect,
		Database:      c.cfg.DatabaseName,
		Items:         items,
		TotalCount:    total,
		ReturnedCount: len(items),
		Truncated:     truncated,
	}, nil
}

func (c *postgresConn) DescribeTable(ctx context.Context, name string) (*types.TableSchema, error) {
	sch, tbl := driver.SplitQualifiedObject(name)
	if tbl == "" {
		return nil, fmt.Errorf("table name is required")
	}
	if sch == "" {
		_ = c.conn.QueryRow(ctx, "SELECT current_schema()").Scan(&sch)
		if sch == "" {
			sch = "public"
		}
	}

	pkSet := map[string]bool{}
	pkRows, err := c.conn.Query(ctx, `
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
		pkRows.Close()
	}

	colRows, err := c.conn.Query(ctx, `
		SELECT column_name, data_type, is_nullable, COALESCE(column_default, '')
		FROM information_schema.columns
		WHERE table_schema = $1 AND table_name = $2
		ORDER BY ordinal_position`, sch, tbl)
	if err != nil {
		return nil, err
	}
	defer colRows.Close()

	var cols []types.SchemaColumn
	for colRows.Next() {
		var cname, dtype, nullable, defVal string
		if err := colRows.Scan(&cname, &dtype, &nullable, &defVal); err != nil {
			return nil, err
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
		return nil, err
	}
	if len(cols) == 0 {
		return nil, fmt.Errorf("table or view %s.%s not found", sch, tbl)
	}

	var fks []types.SchemaForeignKey
	fkRows, err := c.conn.Query(ctx, `
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
		fkRows.Close()
	}

	var idxs []types.SchemaIndex
	idxRows, err := c.conn.Query(ctx, `
		SELECT indexname, indexdef
		FROM pg_indexes
		WHERE schemaname = $1 AND tablename = $2
		ORDER BY indexname`, sch, tbl)
	if err == nil {
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
		idxRows.Close()
	}

	dialect := "postgres"
	if caps := c.Capabilities(); caps != nil && caps.Dialect != "" {
		dialect = caps.Dialect
	}
	return &types.TableSchema{
		Engine:      "postgres",
		Dialect:     dialect,
		Database:    c.cfg.DatabaseName,
		Schema:      sch,
		Name:        tbl,
		ObjectType:  "table",
		Columns:     cols,
		Indexes:     idxs,
		ForeignKeys: fks,
	}, nil
}

func normalizePGValue(v any, typeName string) any {
	switch x := v.(type) {
	case pgtype.Numeric:
		if !x.Valid {
			return nil
		}
		if x.NaN {
			return "NaN"
		}
		if x.InfinityModifier != pgtype.Finite {
			return x.InfinityModifier.String()
		}
		if b, err := x.MarshalJSON(); err == nil {
			return json.RawMessage(b)
		}
		return normalizeTypedSQLValue(v, typeName)
	case pgtype.Interval:
		if !x.Valid {
			return nil
		}
		return fmt.Sprintf("%d mons %d days %d us", x.Months, x.Days, x.Microseconds)
	case [16]byte:
		return fmt.Sprintf("%x-%x-%x-%x-%x", x[0:4], x[4:6], x[6:8], x[8:10], x[10:16])
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
		return normalizeTypedSQLValue(v, typeName)
	}
}

func (c *postgresConn) CancelAndDiscard() error {
	pgConn := c.conn.PgConn()
	if pgConn != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = pgConn.CancelRequest(ctx)
	}
	return c.Close()
}

func (c *postgresConn) Close() error {
	c.closeOnce.Do(func() {
		if c.closeHook != nil {
			_ = c.closeHook()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		c.closeErr = c.conn.Close(ctx)
	})
	return c.closeErr
}
