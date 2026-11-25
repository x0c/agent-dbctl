package builtin

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	go_ora "github.com/sijms/go-ora/v2"

	"github.com/x0c/agent-dbctl/internal/classify"
	"github.com/x0c/agent-dbctl/internal/driver"
	"github.com/x0c/agent-dbctl/internal/types"
)

var oracleXPlanRowsRe = regexp.MustCompile(`\|\s*\d+\s*\|[^|]+\|[^|]*\|\s*(\d+)\s*([KkMm]?)\s*\|`)

// OracleDriver implements Oracle Database thin-mode support using pure-Go go-ora/v2.
type OracleDriver struct{}

func (d *OracleDriver) Metadata() types.DriverMetadata {
	return types.DriverMetadata{
		ID:           "builtin-oracle",
		Engine:       "oracle",
		DisplayName:  "Oracle Database",
		Family:       types.FamilySQL,
		Tier:         "builtin",
		Version:      "1.0.0",
		Capabilities: []string{"ping", "list_databases", "schema", "preflight", "execute"},
		Verified:     true,
		Labels:       map[string]string{"en": "Oracle Database", "zh": "Oracle"},
	}
}

func (d *OracleDriver) Classify(_ context.Context, raw string) (types.Classification, error) {
	return classify.Classify("oracle", raw), nil
}

type oracleDialerFunc func(ctx context.Context, network, addr string) (net.Conn, error)

func (f oracleDialerFunc) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return f(ctx, network, addr)
}

func (d *OracleDriver) Open(ctx context.Context, cfg driver.ConnectionConfig) (driver.Conn, error) {
	dsn, err := buildOracleDSN(cfg)
	if err != nil {
		return nil, err
	}
	rawConn := go_ora.NewConnector(dsn)
	if oc, ok := rawConn.(*go_ora.OracleConnector); ok {
		if cfg.DialContext != nil {
			oc.Dialer(oracleDialerFunc(cfg.DialContext))
		}
		if cfg.TLSConfig != nil {
			oc.WithTLSConfig(cfg.TLSConfig)
		}
	}

	db := sql.OpenDB(rawConn)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}

	oc := &oracleConn{
		db:        db,
		cfg:       cfg,
		closeHook: driver.CloseOnce(cfg.CloseHook),
	}
	if cfg.NegotiatedCapabilities != nil {
		cp := *cfg.NegotiatedCapabilities
		oc.caps.Store(&cp)
	}
	return oc, nil
}

func buildOracleDSN(cfg driver.ConnectionConfig) (string, error) {
	port := cfg.Port
	if port <= 0 {
		port = 1521
	}
	host := strings.TrimSpace(cfg.Host)
	if host == "" {
		host = "127.0.0.1"
	}
	service := strings.TrimSpace(cfg.DatabaseName)
	urlParams := map[string]string{
		"TIMEOUT": "10",
	}
	if cfg.TLSConfig != nil || strings.EqualFold(cfg.TLSMode, "require") || strings.EqualFold(cfg.TLSMode, "verify-ca") || strings.EqualFold(cfg.TLSMode, "verify-full") {
		urlParams["SSL"] = "true"
		if strings.EqualFold(cfg.TLSMode, "require") {
			urlParams["SSL Verify"] = "false"
		} else {
			urlParams["SSL Verify"] = "true"
		}
	}

	for k, v := range cfg.Params {
		key := strings.ToLower(strings.TrimSpace(k))
		val := strings.TrimSpace(v)
		switch key {
		case "sid":
			if val != "" {
				urlParams["SID"] = val
				service = ""
			}
		case "service_name", "service":
			if val != "" {
				service = val
			}
		case "ssl", "ssl verify":
			// Controlled by NetworkProfile / TLSConfig.
		default:
			urlParams[k] = v
		}
	}
	if service == "" && urlParams["SID"] == "" {
		service = "ORCL"
	}
	return go_ora.BuildUrl(host, port, service, cfg.Credential.Username, cfg.Credential.Secret, urlParams), nil
}

type oracleConn struct {
	db        *sql.DB
	cfg       driver.ConnectionConfig
	closeHook func() error
	closeOnce sync.Once
	closeErr  error
	caps      atomic.Pointer[types.ServerCapabilities]
}

func (c *oracleConn) Capabilities() *types.ServerCapabilities {
	return c.caps.Load()
}

func (c *oracleConn) ResetSession(ctx context.Context) error {
	if c.db == nil {
		return fmt.Errorf("oracle db handle is closed")
	}
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return c.db.PingContext(pingCtx)
}

func (c *oracleConn) Ping(ctx context.Context) (types.PingResult, error) {
	start := time.Now()
	var ver string
	err := c.db.QueryRowContext(ctx, "SELECT banner_full FROM v$version WHERE ROWNUM = 1").Scan(&ver)
	if err != nil {
		if err2 := c.db.QueryRowContext(ctx, "SELECT banner FROM v$version WHERE ROWNUM = 1").Scan(&ver); err2 == nil {
			err = nil
		} else if err3 := c.db.QueryRowContext(ctx, "SELECT 'Oracle Database' FROM DUAL").Scan(&ver); err3 == nil {
			err = nil
		}
	}
	lat := time.Since(start).Milliseconds()
	if err != nil {
		return types.PingResult{Engine: "oracle", Reachable: false, LatencyMs: lat, Error: err.Error()}, err
	}
	caps := driver.DetectServerCapabilities("oracle", ver, driver.DialectHints{})
	c.caps.Store(&caps)
	return types.PingResult{
		Engine:        "oracle",
		Dialect:       caps.Dialect,
		Reachable:     true,
		ServerVersion: ver,
		Capabilities:  &caps,
		LatencyMs:     lat,
	}, nil
}

func (c *oracleConn) ListDatabases(ctx context.Context) ([]string, error) {
	rows, err := c.db.QueryContext(ctx, "SELECT name FROM v$pdbs ORDER BY name")
	if err != nil {
		rows, err = c.db.QueryContext(ctx, "SELECT sys_context('USERENV', 'CON_NAME') FROM DUAL")
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
		if name != "" {
			out = append(out, name)
		}
	}
	return out, rows.Err()
}

func (c *oracleConn) Preflight(ctx context.Context, raw string, _ driver.PreflightOpts) (*types.PreflightReport, error) {
	cls := classify.Classify("oracle", raw)
	report := &types.PreflightReport{
		Supported: true,
		Executed:  false,
		Format:    "oracle_xplan",
	}
	if !driver.CanPreflightSQL(cls) {
		report.Warnings = append(report.Warnings, "EXPLAIN PLAN skipped for DDL/admin/multi-statement SQL")
		return report, nil
	}

	if _, err := c.db.ExecContext(ctx, "EXPLAIN PLAN FOR "+raw); err != nil {
		report.Warnings = append(report.Warnings, "EXPLAIN PLAN failed: "+err.Error())
		return report, nil
	}
	defer func() {
		rbCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, _ = c.db.ExecContext(rbCtx, "ROLLBACK")
		cancel()
	}()

	rows, err := c.db.QueryContext(ctx, "SELECT plan_table_output FROM TABLE(DBMS_XPLAN.DISPLAY())")
	if err != nil {
		report.Warnings = append(report.Warnings, "DBMS_XPLAN.DISPLAY failed: "+err.Error())
		return report, nil
	}
	defer func() { _ = rows.Close() }()
	var lines []string
	for rows.Next() {
		var line string
		if scanErr := rows.Scan(&line); scanErr == nil {
			lines = append(lines, line)
		}
	}
	parseOracleXPlan(lines, report)
	return report, nil
}

func parseOracleXPlan(lines []string, report *types.PreflightReport) {
	for _, line := range lines {
		upper := strings.ToUpper(line)
		if strings.Contains(upper, "TABLE ACCESS FULL") || strings.Contains(upper, "INDEX FULL SCAN") {
			report.FullScan = true
		}
		if m := oracleXPlanRowsRe.FindStringSubmatch(line); len(m) == 3 {
			if n, err := strconv.ParseInt(m[1], 10, 64); err == nil {
				switch strings.ToUpper(m[2]) {
				case "K":
					n *= 1000
				case "M":
					n *= 1000000
				}
				if n > report.EstimatedRows {
					report.EstimatedRows = n
				}
			}
		}
	}
	report.PlanRaw = lines
	report.PlanSummary = strings.Join(lines, "\n")
}

func (c *oracleConn) Execute(ctx context.Context, raw string, opts driver.ExecOpts) (*types.ExecResult, error) {
	start := time.Now()
	cls := classify.Classify("oracle", raw)
	if c.cfg.ReadOnly && !cls.IsReadOnly {
		return nil, fmt.Errorf("read-only mode blocks non-read Oracle statement (%s)", cls.RiskLevel)
	}

	if cls.IsReadOnly && cls.StatementCount == 1 {
		// Enforce transaction-level read-only isolation in Oracle when ReadOnly is requested.
		if c.cfg.ReadOnly {
			tx, err := c.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
			if err == nil {
				defer func() { _ = tx.Rollback() }()
				rows, qErr := tx.QueryContext(ctx, raw)
				if qErr != nil {
					return nil, qErr
				}
				defer func() { _ = rows.Close() }()
				res, cErr := collectSQLRows(rows, opts)
				if cErr != nil {
					return nil, cErr
				}
				res.LatencyMs = time.Since(start).Milliseconds()
				return res, nil
			}
		}
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

func (c *oracleConn) ListTables(ctx context.Context, opts driver.SchemaListOpts) (*types.SchemaListResult, error) {
	rows, err := c.db.QueryContext(ctx, `
		SELECT owner, table_name, 'table' FROM all_tables WHERE owner = SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA')
		UNION ALL
		SELECT owner, view_name, 'view' FROM all_views WHERE owner = SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA')
		UNION ALL
		SELECT table_owner, synonym_name, 'synonym' FROM all_synonyms WHERE owner = SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA')
		ORDER BY 1, 2`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var all []types.SchemaObjectSummary
	for rows.Next() {
		var sch, name, ttype string
		if err := rows.Scan(&sch, &name, &ttype); err != nil {
			return nil, err
		}
		all = append(all, types.SchemaObjectSummary{
			Schema: sch,
			Name:   name,
			Type:   ttype,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	items, total, truncated := driver.FilterAndCapSchemaObjects(all, opts.Search, opts.Limit)
	return &types.SchemaListResult{
		Engine:        "oracle",
		Dialect:       "oracle",
		Database:      c.cfg.DatabaseName,
		Items:         items,
		TotalCount:    total,
		ReturnedCount: len(items),
		Truncated:     truncated,
	}, nil
}

func (c *oracleConn) DescribeTable(ctx context.Context, name string) (*types.TableSchema, error) {
	sch, tbl := driver.SplitQualifiedObject(name)
	if tbl == "" {
		return nil, fmt.Errorf("table name is required")
	}
	if sch == "" {
		_ = c.db.QueryRowContext(ctx, "SELECT SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA') FROM DUAL").Scan(&sch)
	}
	schUpper := strings.ToUpper(sch)
	tblUpper := strings.ToUpper(tbl)

	var colCount int
	if err := c.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM all_tab_columns WHERE owner = :1 AND table_name = :2`, schUpper, tblUpper).Scan(&colCount); err == nil && colCount == 0 {
		var synOwner, synTable string
		synErr := c.db.QueryRowContext(ctx, `
			SELECT table_owner, table_name
			FROM all_synonyms
			WHERE owner IN (:1, 'PUBLIC') AND synonym_name = :2
			ORDER BY CASE WHEN owner = :3 THEN 0 ELSE 1 END
			FETCH FIRST 1 ROWS ONLY`, schUpper, tblUpper, schUpper).Scan(&synOwner, &synTable)
		if synErr == nil && synOwner != "" && synTable != "" {
			schUpper = synOwner
			tblUpper = synTable
		}
	}

	pkSet := map[string]bool{}
	pkRows, err := c.db.QueryContext(ctx, `
		SELECT cols.column_name
		FROM all_constraints cons
		JOIN all_cons_columns cols
		  ON cons.owner = cols.owner AND cons.constraint_name = cols.constraint_name
		WHERE cons.constraint_type = 'P' AND cons.owner = :1 AND cons.table_name = :2`, schUpper, tblUpper)
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
		SELECT column_name, data_type, nullable, data_default
		FROM all_tab_columns
		WHERE owner = :1 AND table_name = :2
		ORDER BY column_id`, schUpper, tblUpper)
	if err != nil {
		return nil, err
	}
	defer func() { _ = colRows.Close() }()

	var cols []types.SchemaColumn
	for colRows.Next() {
		var cname, dtype, nullable string
		var defVal sql.NullString
		if err := colRows.Scan(&cname, &dtype, &nullable, &defVal); err != nil {
			return nil, err
		}
		cols = append(cols, types.SchemaColumn{
			Name:       cname,
			Type:       dtype,
			Nullable:   strings.EqualFold(nullable, "Y"),
			PrimaryKey: pkSet[cname],
			Default:    strings.TrimSpace(defVal.String),
		})
	}
	if err := colRows.Err(); err != nil {
		return nil, err
	}
	if len(cols) == 0 {
		return nil, fmt.Errorf("table or view %s.%s not found", schUpper, tblUpper)
	}

	var idxs []types.SchemaIndex
	idxRows, err := c.db.QueryContext(ctx, `
		SELECT ic.index_name, ic.column_name, i.uniqueness
		FROM all_ind_columns ic
		JOIN all_indexes i ON ic.index_owner = i.owner AND ic.index_name = i.index_name
		WHERE ic.table_owner = :1 AND ic.table_name = :2
		ORDER BY ic.index_name, ic.column_position`, schUpper, tblUpper)
	if err == nil {
		idxMap := map[string]*types.SchemaIndex{}
		var order []string
		for idxRows.Next() {
			var iname, cname, uniq string
			if idxRows.Scan(&iname, &cname, &uniq) == nil {
				entry, ok := idxMap[iname]
				if !ok {
					entry = &types.SchemaIndex{Name: iname, Unique: strings.EqualFold(uniq, "UNIQUE")}
					idxMap[iname] = entry
					order = append(order, iname)
				}
				entry.Columns = append(entry.Columns, cname)
			}
		}
		_ = idxRows.Close()
		for _, k := range order {
			idxs = append(idxs, *idxMap[k])
		}
	}

	return &types.TableSchema{
		Engine:     "oracle",
		Dialect:    "oracle",
		Database:   c.cfg.DatabaseName,
		Schema:     schUpper,
		Name:       tblUpper,
		ObjectType: "table",
		Columns:    cols,
		Indexes:    idxs,
	}, nil
}

func (c *oracleConn) CancelAndDiscard() error {
	return c.Close()
}

func (c *oracleConn) Close() error {
	c.closeOnce.Do(func() {
		if c.closeHook != nil {
			_ = c.closeHook()
		}
		c.closeErr = c.db.Close()
	})
	return c.closeErr
}
