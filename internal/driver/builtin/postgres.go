package builtin

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/x0c/agent-dbctl/internal/classify"
	"github.com/x0c/agent-dbctl/internal/driver"
	"github.com/x0c/agent-dbctl/internal/types"
)

// PostgresDriver implements PostgreSQL support using pure-Go pgx/v5.
type PostgresDriver struct{}

func (d *PostgresDriver) Metadata() types.DriverMetadata {
	return types.DriverMetadata{
		ID:           "builtin-postgres",
		Engine:       "postgres",
		DisplayName:  "PostgreSQL",
		Family:       types.FamilySQL,
		Tier:         "builtin",
		Version:      "1.0.0",
		Capabilities: []string{"ping", "list_databases", "preflight", "execute"},
		Verified:     true,
		Labels:       map[string]string{"en": "PostgreSQL", "zh": "PostgreSQL"},
	}
}

func (d *PostgresDriver) Classify(_ context.Context, raw string) (types.Classification, error) {
	return classify.Classify("postgres", raw), nil
}

func (d *PostgresDriver) Open(ctx context.Context, cfg driver.ConnectionConfig) (driver.Conn, error) {
	port := cfg.Port
	if port <= 0 {
		port = 5432
	}
	dbName := cfg.DatabaseName
	if dbName == "" {
		dbName = "postgres"
	}
	dsn := fmt.Sprintf("postgres://%s:%d/%s", cfg.Host, port, dbName)
	pgCfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	pgCfg.User = cfg.Credential.Username
	pgCfg.Password = cfg.Credential.Secret
	pgCfg.TLSConfig = cfg.TLSConfig
	if cfg.DialContext != nil {
		pgCfg.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return cfg.DialContext(ctx, network, addr)
		}
	}
	if pgCfg.RuntimeParams == nil {
		pgCfg.RuntimeParams = map[string]string{}
	}
	pgCfg.RuntimeParams["application_name"] = "agent-dbctl"
	if cfg.ReadOnly {
		pgCfg.RuntimeParams["default_transaction_read_only"] = "on"
	}
	for k, v := range cfg.Params {
		pgCfg.RuntimeParams[k] = v
	}

	conn, err := pgx.ConnectConfig(ctx, pgCfg)
	if err != nil {
		return nil, err
	}
	return &postgresConn{conn: conn, cfg: cfg}, nil
}

type postgresConn struct {
	conn *pgx.Conn
	cfg  driver.ConnectionConfig
}

func (c *postgresConn) Ping(ctx context.Context) (types.PingResult, error) {
	start := time.Now()
	var ver string
	err := c.conn.QueryRow(ctx, "SHOW server_version").Scan(&ver)
	lat := time.Since(start).Milliseconds()
	if err != nil {
		return types.PingResult{Engine: "postgres", Reachable: false, LatencyMs: lat, Error: err.Error()}, err
	}
	return types.PingResult{Engine: "postgres", Reachable: true, ServerVersion: ver, LatencyMs: lat}, nil
}

func (c *postgresConn) ListDatabases(ctx context.Context) ([]string, error) {
	rows, err := c.conn.Query(ctx, "SELECT datname FROM pg_database WHERE datistemplate = false ORDER BY datname")
	if err != nil {
		return nil, err
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
	if err := c.conn.QueryRow(ctx, "EXPLAIN (FORMAT JSON) "+raw).Scan(&jsonStr); err != nil {
		report.Warnings = append(report.Warnings, "EXPLAIN failed: "+err.Error())
		return report, nil
	}
	var nodes []map[string]any
	if err := json.Unmarshal([]byte(jsonStr), &nodes); err == nil && len(nodes) > 0 {
		report.PlanRaw = nodes[0]
		if plan, ok := nodes[0]["Plan"].(map[string]any); ok {
			walkPGPlan(plan, report)
			report.PlanSummary = fmt.Sprintf("Top node: %v, estimated rows: %d, full_scan: %v", plan["Node Type"], report.EstimatedRows, report.FullScan)
		}
	}
	return report, nil
}

func walkPGPlan(node map[string]any, report *types.PreflightReport) {
	if nt, ok := node["Node Type"].(string); ok && strings.EqualFold(nt, "Seq Scan") {
		report.FullScan = true
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

func (c *postgresConn) Execute(ctx context.Context, raw string, opts driver.ExecOpts) (*types.ExecResult, error) {
	start := time.Now()
	cls := classify.Classify("postgres", raw)
	if cls.IsReadOnly && cls.StatementCount == 1 {
		rows, err := c.conn.Query(ctx, raw)
		if err != nil {
			return nil, err
		}
		defer rows.Close()

		fds := rows.FieldDescriptions()
		cols := make([]types.Column, len(fds))
		for i, fd := range fds {
			cols[i] = types.Column{
				Name:     fd.Name,
				TypeName: fmt.Sprintf("OID_%d", fd.DataTypeOID),
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
				vals[i] = normalizePGValue(v)
			}
			if buf.TryAcceptRow(vals) {
				outRows = append(outRows, vals)
			} else if buf.Truncated && buf.FetchedRows >= opts.MaxRows+1000 {
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

func normalizePGValue(v any) any {
	switch x := v.(type) {
	case pgtype.Numeric:
		if !x.Valid {
			return nil
		}
		if b, err := x.MarshalJSON(); err == nil {
			return json.RawMessage(b)
		}
		return normalizeSQLValue(v)
	case [16]byte:
		return fmt.Sprintf("%x-%x-%x-%x-%x", x[0:4], x[4:6], x[6:8], x[8:10], x[10:16])
	default:
		return normalizeSQLValue(v)
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
	if c.cfg.CloseHook != nil {
		_ = c.cfg.CloseHook()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.conn.Close(ctx); err != nil {
		var pgErr *pgconn.PgError
		_ = pgErr
		return err
	}
	return nil
}
