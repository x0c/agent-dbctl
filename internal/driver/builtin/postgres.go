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
		Capabilities: []string{"ping", "list_databases", "preflight", "execute"},
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
	return &postgresConn{
		conn:      conn,
		cfg:       cfg,
		closeHook: driver.CloseOnce(cfg.CloseHook),
	}, nil
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
}

func (c *postgresConn) Ping(ctx context.Context) (types.PingResult, error) {
	start := time.Now()
	var ver string
	err := c.conn.QueryRow(ctx, "SHOW server_version").Scan(&ver)
	if err != nil {
		// Some PG-wire compatible servers (e.g., Redshift or proxies) lack SHOW server_version.
		if fallbackErr := c.conn.QueryRow(ctx, "SELECT version()").Scan(&ver); fallbackErr == nil {
			err = nil
		}
	}
	lat := time.Since(start).Milliseconds()
	if err != nil {
		return types.PingResult{Engine: "postgres", Reachable: false, LatencyMs: lat, Error: err.Error()}, err
	}
	return types.PingResult{Engine: "postgres", Reachable: true, ServerVersion: ver, LatencyMs: lat}, nil
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
	if !cls.IsReadOnly || cls.StatementCount != 1 {
		report.Warnings = append(report.Warnings, "EXPLAIN skipped for non-read or multi-statement SQL")
		return report, nil
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
		rows, textErr := c.conn.Query(ctx, "EXPLAIN "+raw)
		if textErr != nil {
			report.Warnings = append(report.Warnings, "EXPLAIN failed: "+err.Error())
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
			report.Warnings = append(report.Warnings, "EXPLAIN failed: "+err.Error())
			return report, nil
		}
		report.Format = "pg_text"
		parsePGTextPlan(lines, report)
		return report, nil
	}
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
	useQuery := (cls.IsReadOnly && cls.StatementCount == 1) || (cls.StatementCount == 1 && hasReturningClause(raw))
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

func hasReturningClause(raw string) bool {
	return strings.Contains(strings.ToUpper(raw), " RETURNING ")
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
