package builtin

import (
	"context"
	"database/sql"
	sqldriver "database/sql/driver"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/x0c/agent-dbctl/internal/classify"
	"github.com/x0c/agent-dbctl/internal/driver"
	"github.com/x0c/agent-dbctl/internal/types"
)

// MySQLDriver implements MySQL / MariaDB / TiDB protocol support using pure-Go go-sql-driver/mysql.
type MySQLDriver struct{}

func (d *MySQLDriver) Metadata() types.DriverMetadata {
	return types.DriverMetadata{
		ID:           "builtin-mysql",
		Engine:       "mysql",
		DisplayName:  "MySQL",
		Family:       types.FamilySQL,
		Tier:         "builtin",
		Version:      "1.1.0",
		Capabilities: []string{"ping", "list_databases", "preflight", "execute"},
		Verified:     true,
		Labels:       map[string]string{"en": "MySQL", "zh": "MySQL"},
	}
}

func (d *MySQLDriver) Classify(_ context.Context, raw string) (types.Classification, error) {
	return classify.Classify("mysql", raw), nil
}

func (d *MySQLDriver) Open(ctx context.Context, cfg driver.ConnectionConfig) (driver.Conn, error) {
	myCfg, err := buildMySQLConfig(cfg)
	if err != nil {
		return nil, err
	}

	// Use mysql.NewConnector + sql.OpenDB so TLSConfig and DialFunc are bound directly
	// per connection without leaking entries into global driver registries.
	baseConn, err := mysql.NewConnector(myCfg)
	if err != nil {
		return nil, err
	}
	connector := sqldriver.Connector(baseConn)
	if cfg.ReadOnly {
		connector = &readOnlyMySQLConnector{inner: baseConn}
	}

	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}

	var connID uint64
	_ = db.QueryRowContext(ctx, "SELECT CONNECTION_ID()").Scan(&connID)

	return &mysqlConn{
		db:        db,
		connector: baseConn,
		connID:    connID,
		cfg:       cfg,
		closeHook: driver.CloseOnce(cfg.CloseHook),
	}, nil
}

func buildMySQLConfig(cfg driver.ConnectionConfig) (*mysql.Config, error) {
	port := cfg.Port
	if port <= 0 {
		port = 3306
	}
	host := strings.TrimSpace(cfg.Host)
	if host == "" {
		host = "127.0.0.1"
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	myCfg := mysql.NewConfig()
	myCfg.User = cfg.Credential.Username
	myCfg.Passwd = cfg.Credential.Secret
	myCfg.Net = "tcp"
	myCfg.Addr = addr
	myCfg.DBName = cfg.DatabaseName
	myCfg.ParseTime = true
	myCfg.MultiStatements = !cfg.ReadOnly
	myCfg.AllowAllFiles = false
	myCfg.AllowCleartextPasswords = false
	myCfg.Timeout = 10 * time.Second
	myCfg.TLS = cfg.TLSConfig
	if cfg.DialContext != nil {
		myCfg.DialFunc = cfg.DialContext
	}

	for k, v := range cfg.Params {
		key := strings.TrimSpace(k)
		switch strings.ToLower(key) {
		case "collation":
			myCfg.Collation = v
		case "timeout", "connecttimeout":
			if d, err := parseDurationOrSeconds(v); err == nil && d > 0 {
				myCfg.Timeout = d
			}
		case "readtimeout":
			if d, err := parseDurationOrSeconds(v); err == nil && d > 0 {
				myCfg.ReadTimeout = d
			}
		case "writetimeout":
			if d, err := parseDurationOrSeconds(v); err == nil && d > 0 {
				myCfg.WriteTimeout = d
			}
		case "multistatements":
			if !cfg.ReadOnly {
				myCfg.MultiStatements = strings.EqualFold(strings.TrimSpace(v), "true") || strings.TrimSpace(v) == "1"
			}
		case "allowfallbacktoplaintext":
			myCfg.AllowFallbackToPlaintext = strings.EqualFold(strings.TrimSpace(v), "true") || strings.TrimSpace(v) == "1"
		case "allowallfiles", "allowcleartextpasswords", "tls":
			// Security-sensitive flags are controlled by NetworkProfile / policy, not raw Params.
		default:
			if myCfg.Params == nil {
				myCfg.Params = map[string]string{}
			}
			myCfg.Params[key] = v
		}
	}
	return myCfg, nil
}

// readOnlyMySQLConnector enforces read-only mode on every physical connection (including reconnects),
// adapting across MySQL 5.6/5.7/8.0/8.4 and MariaDB 10.x/11.x variable conventions.
type readOnlyMySQLConnector struct {
	inner sqldriver.Connector
}

func (c *readOnlyMySQLConnector) Connect(ctx context.Context) (sqldriver.Conn, error) {
	conn, err := c.inner.Connect(ctx)
	if err != nil {
		return nil, err
	}
	execer, ok := conn.(sqldriver.ExecerContext)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("mysql driver connection does not support ExecContext for read-only enforcement")
	}
	stmts := []string{
		"SET SESSION TRANSACTION READ ONLY",
		"SET SESSION tx_read_only = 1",
		"SET SESSION transaction_read_only = 1",
	}
	var lastErr error
	for _, stmt := range stmts {
		if _, err := execer.ExecContext(ctx, stmt, nil); err == nil {
			return conn, nil
		} else {
			lastErr = err
		}
	}
	_ = conn.Close()
	return nil, fmt.Errorf("enforce mysql read-only session failed: %w", lastErr)
}

func (c *readOnlyMySQLConnector) Driver() sqldriver.Driver {
	return c.inner.Driver()
}

type mysqlConn struct {
	db        *sql.DB
	connector sqldriver.Connector
	connID    uint64
	cfg       driver.ConnectionConfig
	closeHook func() error
	closeOnce sync.Once
	closeErr  error
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
	if err := c.db.QueryRowContext(ctx, "EXPLAIN FORMAT=JSON "+raw).Scan(&jsonStr); err == nil {
		var parsed map[string]any
		if err := json.Unmarshal([]byte(jsonStr), &parsed); err == nil {
			report.PlanRaw = parsed
			walkMySQLPlan(parsed, report)
			report.PlanSummary = fmt.Sprintf("Estimated rows: %d, full_scan: %v", report.EstimatedRows, report.FullScan)
			return report, nil
		}
	} else {
		// Fallback to classic tabular EXPLAIN for MySQL 5.5, older MariaDB, or TiDB.
		rows, tabErr := c.db.QueryContext(ctx, "EXPLAIN "+raw)
		if tabErr != nil {
			report.Warnings = append(report.Warnings, "EXPLAIN failed: "+err.Error())
			return report, nil
		}
		defer func() { _ = rows.Close() }()
		tabRes, collectErr := collectSQLRows(rows, driver.ExecOpts{MaxRows: 100})
		if collectErr != nil {
			report.Warnings = append(report.Warnings, "EXPLAIN failed: "+err.Error())
			return report, nil
		}
		report.Format = "mysql_tabular"
		parseMySQLTabularPlan(tabRes, report)
		return report, nil
	}
	return report, nil
}

func walkMySQLPlan(v any, report *types.PreflightReport) {
	switch x := v.(type) {
	case map[string]any:
		// MySQL 5.7/8.0/8.4 v1 & MariaDB JSON format.
		if acc, ok := x["access_type"].(string); ok {
			lower := strings.ToLower(strings.TrimSpace(acc))
			if lower == "all" || lower == "table_scan" {
				report.FullScan = true
			}
		}
		// MySQL 8.4+ explain_json_format_version = 2 uses "operation": "Table scan on ...".
		if op, ok := x["operation"].(string); ok {
			if strings.Contains(strings.ToLower(op), "table scan") {
				report.FullScan = true
			}
		}
		// Check MySQL v1 ("rows_examined_per_scan"), MySQL 8.4 v2 ("estimated_rows"), and MariaDB ("rows").
		for _, key := range []string{"rows_examined_per_scan", "estimated_rows", "rows"} {
			if rows, ok := asInt64(x[key]); ok && rows > report.EstimatedRows {
				report.EstimatedRows = rows
			}
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

func parseMySQLTabularPlan(res *types.ExecResult, report *types.PreflightReport) {
	if res == nil {
		return
	}
	typeIdx, rowsIdx, idIdx, estRowsIdx := -1, -1, -1, -1
	for i, c := range res.Columns {
		switch strings.ToLower(c.Name) {
		case "type":
			typeIdx = i
		case "rows":
			rowsIdx = i
		case "id":
			idIdx = i
		case "estrows":
			estRowsIdx = i
		}
	}
	for _, row := range res.Rows {
		if typeIdx >= 0 && typeIdx < len(row) {
			if s, ok := row[typeIdx].(string); ok && strings.EqualFold(strings.TrimSpace(s), "ALL") {
				report.FullScan = true
			}
		}
		if idIdx >= 0 && idIdx < len(row) {
			if s, ok := row[idIdx].(string); ok && strings.Contains(strings.ToLower(s), "tablefullscan") {
				report.FullScan = true
			}
		}
		for _, idx := range []int{rowsIdx, estRowsIdx} {
			if idx >= 0 && idx < len(row) {
				if n, ok := asInt64(row[idx]); ok && n > report.EstimatedRows {
					report.EstimatedRows = n
				}
			}
		}
	}
	report.PlanRaw = res.Rows
	report.PlanSummary = fmt.Sprintf("Tabular EXPLAIN rows: %d, full_scan: %v", report.EstimatedRows, report.FullScan)
}

func asInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	case string:
		if parsed, err := strconv.ParseFloat(strings.TrimSpace(n), 64); err == nil {
			return int64(parsed), true
		}
	}
	return 0, false
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
	if c.connID > 0 && c.connector != nil {
		killCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if sideConn, err := c.connector.Connect(killCtx); err == nil {
			if execer, ok := sideConn.(sqldriver.ExecerContext); ok {
				_, _ = execer.ExecContext(killCtx, fmt.Sprintf("KILL QUERY %d", c.connID), nil)
			}
			_ = sideConn.Close()
		}
	}
	return c.Close()
}

func (c *mysqlConn) Close() error {
	c.closeOnce.Do(func() {
		if c.closeHook != nil {
			_ = c.closeHook()
		}
		c.closeErr = c.db.Close()
	})
	return c.closeErr
}
