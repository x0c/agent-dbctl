package builtin

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/x0c/agent-dbctl/internal/classify"
	"github.com/x0c/agent-dbctl/internal/driver"
	"github.com/x0c/agent-dbctl/internal/types"
)

var mysqlDialSeq atomic.Uint64

// MySQLDriver implements MySQL / MariaDB / TiDB protocol support using pure-Go go-sql-driver/mysql.
type MySQLDriver struct{}

func (d *MySQLDriver) Metadata() types.DriverMetadata {
	return types.DriverMetadata{
		ID:           "builtin-mysql",
		Engine:       "mysql",
		DisplayName:  "MySQL",
		Family:       types.FamilySQL,
		Tier:         "builtin",
		Version:      "1.0.0",
		Capabilities: []string{"ping", "list_databases", "preflight", "execute"},
		Verified:     true,
		Labels:       map[string]string{"en": "MySQL", "zh": "MySQL"},
	}
}

func (d *MySQLDriver) Classify(_ context.Context, raw string) (types.Classification, error) {
	return classify.Classify("mysql", raw), nil
}

func (d *MySQLDriver) Open(ctx context.Context, cfg driver.ConnectionConfig) (driver.Conn, error) {
	port := cfg.Port
	if port <= 0 {
		port = 3306
	}
	addr := net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", port))

	myCfg := mysql.NewConfig()
	myCfg.User = cfg.Credential.Username
	myCfg.Passwd = cfg.Credential.Secret
	myCfg.Net = "tcp"
	myCfg.Addr = addr
	myCfg.DBName = cfg.DatabaseName
	myCfg.ParseTime = true
	myCfg.MultiStatements = true
	myCfg.Timeout = 10 * time.Second
	if cfg.TLSConfig != nil {
		tlsKey := fmt.Sprintf("agentdbctl_%d", mysqlDialSeq.Add(1))
		_ = mysql.RegisterTLSConfig(tlsKey, cfg.TLSConfig)
		myCfg.TLSConfig = tlsKey
	}
	if cfg.DialContext != nil {
		dialKey := fmt.Sprintf("agentdbctl_dial_%d", mysqlDialSeq.Add(1))
		dialFn := cfg.DialContext
		mysql.RegisterDialContext(dialKey, func(ctx context.Context, addr string) (net.Conn, error) {
			return dialFn(ctx, "tcp", addr)
		})
		myCfg.Net = dialKey
	}
	if len(cfg.Params) > 0 {
		if myCfg.Params == nil {
			myCfg.Params = map[string]string{}
		}
		for k, v := range cfg.Params {
			myCfg.Params[k] = v
		}
	}

	db, err := sql.Open("mysql", myCfg.FormatDSN())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if cfg.ReadOnly {
		_, _ = db.ExecContext(ctx, "SET SESSION TRANSACTION READ ONLY")
	}
	return &mysqlConn{db: db, cfg: cfg}, nil
}

type mysqlConn struct {
	db  *sql.DB
	cfg driver.ConnectionConfig
}

func (c *mysqlConn) Ping(ctx context.Context) (types.PingResult, error) {
	start := time.Now()
	var ver string
	err := c.db.QueryRowContext(ctx, "SELECT VERSION()").Scan(&ver)
	lat := time.Since(start).Milliseconds()
	if err != nil {
		return types.PingResult{Engine: "mysql", Reachable: false, LatencyMs: lat, Error: err.Error()}, err
	}
	return types.PingResult{Engine: "mysql", Reachable: true, ServerVersion: ver, LatencyMs: lat}, nil
}

func (c *mysqlConn) ListDatabases(ctx context.Context) ([]string, error) {
	rows, err := c.db.QueryContext(ctx, "SHOW DATABASES")
	if err != nil {
		return nil, err
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

func (c *mysqlConn) Preflight(ctx context.Context, raw string, _ driver.PreflightOpts) (*types.PreflightReport, error) {
	cls := classify.Classify("mysql", raw)
	report := &types.PreflightReport{
		Supported: true,
		Executed:  false,
		Format:    "mysql_json",
	}
	if !cls.IsReadOnly || cls.StatementCount != 1 {
		report.Warnings = append(report.Warnings, "EXPLAIN skipped for non-read or multi-statement SQL")
		return report, nil
	}
	var jsonStr string
	if err := c.db.QueryRowContext(ctx, "EXPLAIN FORMAT=JSON "+raw).Scan(&jsonStr); err != nil {
		report.Warnings = append(report.Warnings, "EXPLAIN failed: "+err.Error())
		return report, nil
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err == nil {
		report.PlanRaw = parsed
		walkMySQLPlan(parsed, report)
		report.PlanSummary = fmt.Sprintf("Estimated rows: %d, full_scan: %v", report.EstimatedRows, report.FullScan)
	}
	return report, nil
}

func walkMySQLPlan(v any, report *types.PreflightReport) {
	switch x := v.(type) {
	case map[string]any:
		if acc, ok := x["access_type"].(string); ok && strings.EqualFold(acc, "ALL") {
			report.FullScan = true
		}
		if rows, ok := x["rows_examined_per_scan"].(float64); ok && int64(rows) > report.EstimatedRows {
			report.EstimatedRows = int64(rows)
		}
		for _, child := range x {
			walkMySQLPlan(child, report)
		}
	case []any:
		for _, item := range x {
			walkMySQLPlan(item, report)
		}
	}
}

func (c *mysqlConn) Execute(ctx context.Context, raw string, opts driver.ExecOpts) (*types.ExecResult, error) {
	start := time.Now()
	cls := classify.Classify("mysql", raw)
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

func (c *mysqlConn) CancelAndDiscard() error {
	return c.Close()
}

func (c *mysqlConn) Close() error {
	if c.cfg.CloseHook != nil {
		_ = c.cfg.CloseHook()
	}
	return c.db.Close()
}
