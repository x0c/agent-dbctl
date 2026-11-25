package builtin

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	mssql "github.com/microsoft/go-mssqldb"
	"github.com/microsoft/go-mssqldb/msdsn"

	"github.com/x0c/agent-dbctl/internal/classify"
	"github.com/x0c/agent-dbctl/internal/driver"
	"github.com/x0c/agent-dbctl/internal/types"
)

// MSSQLDriver implements Microsoft SQL Server / Azure SQL support using pure-Go go-mssqldb.
type MSSQLDriver struct{}

func (d *MSSQLDriver) Metadata() types.DriverMetadata {
	return types.DriverMetadata{
		ID:           "builtin-mssql",
		Engine:       "mssql",
		DisplayName:  "SQL Server",
		Family:       types.FamilySQL,
		Tier:         "builtin",
		Version:      "1.0.0",
		Capabilities: []string{"ping", "list_databases", "schema", "preflight", "execute"},
		Verified:     true,
		Labels:       map[string]string{"en": "SQL Server", "zh": "SQL Server"},
	}
}

func (d *MSSQLDriver) Classify(_ context.Context, raw string) (types.Classification, error) {
	return classify.Classify("mssql", raw), nil
}

type mssqlDialerFunc func(ctx context.Context, network, addr string) (net.Conn, error)

func (f mssqlDialerFunc) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return f(ctx, network, addr)
}

func (d *MSSQLDriver) Open(ctx context.Context, cfg driver.ConnectionConfig) (driver.Conn, error) {
	msCfg, err := buildMSSQLConfig(cfg)
	if err != nil {
		return nil, err
	}
	connector := mssql.NewConnectorConfig(msCfg)
	if cfg.DialContext != nil {
		connector.Dialer = mssqlDialerFunc(cfg.DialContext)
	}

	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}

	var spid int64
	_ = db.QueryRowContext(ctx, "SELECT CAST(@@SPID AS BIGINT)").Scan(&spid)

	mc := &mssqlConn{
		db:        db,
		connector: connector,
		spid:      spid,
		cfg:       cfg,
		closeHook: driver.CloseOnce(cfg.CloseHook),
	}
	if cfg.NegotiatedCapabilities != nil {
		cp := *cfg.NegotiatedCapabilities
		mc.caps.Store(&cp)
	}
	return mc, nil
}

func buildMSSQLConfig(cfg driver.ConnectionConfig) (msdsn.Config, error) {
	port := cfg.Port
	if port <= 0 {
		port = 1433
	}
	host := strings.TrimSpace(cfg.Host)
	if host == "" {
		host = "127.0.0.1"
	}

	msCfg, err := msdsn.Parse("")
	if err != nil {
		return msdsn.Config{}, err
	}
	msCfg.Host = host
	msCfg.Port = uint64(port)
	msCfg.Database = strings.TrimSpace(cfg.DatabaseName)
	msCfg.User = cfg.Credential.Username
	msCfg.Password = cfg.Credential.Secret
	msCfg.AppName = "agent-dbctl"
	msCfg.DialTimeout = 10 * time.Second
	msCfg.ConnTimeout = 10 * time.Second
	msCfg.TLSConfig = cfg.TLSConfig
	if msCfg.Parameters == nil {
		msCfg.Parameters = map[string]string{}
	}
	if len(msCfg.Protocols) == 0 {
		msCfg.Protocols = []string{"tcp"}
	}

	switch strings.ToLower(strings.TrimSpace(cfg.TLSMode)) {
	case "disable":
		msCfg.Encryption = msdsn.EncryptionDisabled
	case "require":
		msCfg.Encryption = msdsn.EncryptionRequired
		msCfg.TrustServerCertificate = true
	case "verify-ca", "verify-full":
		msCfg.Encryption = msdsn.EncryptionRequired
		msCfg.TrustServerCertificate = false
	default:
		msCfg.Encryption = msdsn.EncryptionOff
		msCfg.TrustServerCertificate = true
		if msCfg.TLSConfig == nil {
			msCfg.TLSConfig = &tls.Config{InsecureSkipVerify: true}
		}
	}

	// go-mssqldb requires Database to be set when ReadOnlyIntent is enabled.
	if cfg.ReadOnly && msCfg.Database != "" {
		msCfg.ReadOnlyIntent = true
	}

	for k, v := range cfg.Params {
		key := strings.ToLower(strings.TrimSpace(k))
		val := strings.TrimSpace(v)
		switch key {
		case "instance":
			msCfg.Instance = val
		case "connect_timeout", "dial_timeout":
			if d, err := parseDurationOrSeconds(val); err == nil && d > 0 {
				msCfg.DialTimeout = d
				msCfg.ConnTimeout = d
			}
		case "encrypt", "trustservercertificate", "applicationintent":
			// Controlled by NetworkProfile / ReadOnly policy rather than raw Params.
		default:
			msCfg.Parameters[k] = v
		}
	}
	return msCfg, nil
}

type mssqlConn struct {
	db        *sql.DB
	connector *mssql.Connector
	spid      int64
	cfg       driver.ConnectionConfig
	closeHook func() error
	closeOnce sync.Once
	closeErr  error
	caps      atomic.Pointer[types.ServerCapabilities]
}

func (c *mssqlConn) Capabilities() *types.ServerCapabilities {
	return c.caps.Load()
}

func (c *mssqlConn) ResetSession(ctx context.Context) error {
	if c.db == nil {
		return fmt.Errorf("mssql db handle is closed")
	}
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return c.db.PingContext(pingCtx)
}

func (c *mssqlConn) Ping(ctx context.Context) (types.PingResult, error) {
	start := time.Now()
	var ver string
	err := c.db.QueryRowContext(ctx, "SELECT @@VERSION").Scan(&ver)
	lat := time.Since(start).Milliseconds()
	if err != nil {
		return types.PingResult{Engine: "mssql", Reachable: false, LatencyMs: lat, Error: err.Error()}, err
	}
	verLine := strings.TrimSpace(strings.Split(ver, "\n")[0])
	caps := driver.DetectServerCapabilities("mssql", verLine, driver.DialectHints{})
	c.caps.Store(&caps)
	return types.PingResult{
		Engine:        "mssql",
		Dialect:       caps.Dialect,
		Reachable:     true,
		ServerVersion: verLine,
		Capabilities:  &caps,
		LatencyMs:     lat,
	}, nil
}

func (c *mssqlConn) ListDatabases(ctx context.Context) ([]string, error) {
	rows, err := c.db.QueryContext(ctx, "SELECT name FROM sys.databases WHERE state = 0 ORDER BY name")
	if err != nil {
		rows, err = c.db.QueryContext(ctx, "SELECT name FROM master.dbo.sysdatabases ORDER BY name")
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

func (c *mssqlConn) Preflight(ctx context.Context, raw string, _ driver.PreflightOpts) (*types.PreflightReport, error) {
	cls := classify.Classify("mssql", raw)
	report := &types.PreflightReport{
		Supported: true,
		Executed:  false,
		Format:    "mssql_showplan",
	}
	if !driver.CanPreflightSQL(cls) {
		report.Warnings = append(report.Warnings, "SHOWPLAN skipped for DDL/admin/multi-statement SQL")
		return report, nil
	}

	// Isolate SHOWPLAN session setting to a single dedicated SQL connection.
	conn, err := c.db.Conn(ctx)
	if err != nil {
		report.Warnings = append(report.Warnings, "SHOWPLAN acquire connection failed: "+err.Error())
		return report, nil
	}
	defer func() { _ = conn.Close() }()

	showplanMode := "SHOWPLAN_ALL"
	if _, err := conn.ExecContext(ctx, "SET SHOWPLAN_ALL ON"); err != nil {
		showplanMode = "SHOWPLAN_TEXT"
		if _, err2 := conn.ExecContext(ctx, "SET SHOWPLAN_TEXT ON"); err2 != nil {
			report.Warnings = append(report.Warnings, "SHOWPLAN failed: "+err.Error())
			return report, nil
		}
	}
	defer func() {
		offCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, _ = conn.ExecContext(offCtx, "SET "+showplanMode+" OFF")
		cancel()
	}()

	rows, err := conn.QueryContext(ctx, raw)
	if err != nil {
		report.Warnings = append(report.Warnings, "SHOWPLAN failed: "+err.Error())
		return report, nil
	}
	defer func() { _ = rows.Close() }()
	res, err := collectSQLRows(rows, driver.ExecOpts{MaxRows: 200})
	if err != nil {
		report.Warnings = append(report.Warnings, "SHOWPLAN parse failed: "+err.Error())
		return report, nil
	}
	parseMSSQLShowplan(res, report)
	return report, nil
}

func parseMSSQLShowplan(res *types.ExecResult, report *types.PreflightReport) {
	if res == nil {
		return
	}
	stmtIdx, opIdx, estIdx := -1, -1, -1
	for i, c := range res.Columns {
		switch strings.ToLower(c.Name) {
		case "stmttext":
			stmtIdx = i
		case "physicalop":
			opIdx = i
		case "estimaterows":
			estIdx = i
		}
	}
	var lines []string
	for _, row := range res.Rows {
		if stmtIdx >= 0 && stmtIdx < len(row) {
			if s, ok := row[stmtIdx].(string); ok && strings.TrimSpace(s) != "" {
				lines = append(lines, strings.TrimSpace(s))
				upper := strings.ToUpper(s)
				if strings.Contains(upper, "TABLE SCAN") || strings.Contains(upper, "CLUSTERED INDEX SCAN") {
					report.FullScan = true
				}
			}
		} else if len(row) > 0 {
			if s, ok := row[0].(string); ok && strings.TrimSpace(s) != "" {
				lines = append(lines, strings.TrimSpace(s))
				upper := strings.ToUpper(s)
				if strings.Contains(upper, "TABLE SCAN") || strings.Contains(upper, "CLUSTERED INDEX SCAN") {
					report.FullScan = true
				}
			}
		}
		if opIdx >= 0 && opIdx < len(row) {
			if s, ok := row[opIdx].(string); ok {
				upper := strings.ToUpper(s)
				if strings.Contains(upper, "TABLE SCAN") || strings.Contains(upper, "CLUSTERED INDEX SCAN") {
					report.FullScan = true
				}
			}
		}
		if estIdx >= 0 && estIdx < len(row) {
			if n, ok := asInt64(row[estIdx]); ok && n > report.EstimatedRows {
				report.EstimatedRows = n
			}
		}
	}
	report.PlanRaw = res.Rows
	if len(lines) > 0 {
		report.PlanSummary = strings.Join(lines, "\n")
	} else {
		report.PlanSummary = fmt.Sprintf("Estimated rows: %d, full_scan: %v", report.EstimatedRows, report.FullScan)
	}
}

func (c *mssqlConn) Execute(ctx context.Context, raw string, opts driver.ExecOpts) (*types.ExecResult, error) {
	start := time.Now()
	cls := classify.Classify("mssql", raw)
	if c.cfg.ReadOnly && !cls.IsReadOnly {
		return nil, fmt.Errorf("read-only mode blocks non-read SQL Server statement (%s)", cls.RiskLevel)
	}

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

func (c *mssqlConn) ListTables(ctx context.Context, opts driver.SchemaListOpts) (*types.SchemaListResult, error) {
	rows, err := c.db.QueryContext(ctx, `
		SELECT TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE
		FROM INFORMATION_SCHEMA.TABLES
		ORDER BY CASE WHEN TABLE_SCHEMA = SCHEMA_NAME() THEN 0 ELSE 1 END, TABLE_SCHEMA, TABLE_NAME`)
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
	dialect := "mssql"
	if caps := c.Capabilities(); caps != nil && caps.Dialect != "" {
		dialect = caps.Dialect
	}
	return &types.SchemaListResult{
		Engine:        "mssql",
		Dialect:       dialect,
		Database:      c.cfg.DatabaseName,
		Items:         items,
		TotalCount:    total,
		ReturnedCount: len(items),
		Truncated:     truncated,
	}, nil
}

func (c *mssqlConn) DescribeTable(ctx context.Context, name string) (*types.TableSchema, error) {
	sch, tbl := driver.SplitQualifiedObject(name)
	if tbl == "" {
		return nil, fmt.Errorf("table name is required")
	}
	if sch == "" {
		_ = c.db.QueryRowContext(ctx, "SELECT SCHEMA_NAME()").Scan(&sch)
		if sch == "" {
			sch = "dbo"
		}
	}

	pkSet := map[string]bool{}
	pkRows, err := c.db.QueryContext(ctx, `
		SELECT kcu.COLUMN_NAME
		FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS tc
		JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE kcu
		  ON tc.CONSTRAINT_NAME = kcu.CONSTRAINT_NAME AND tc.TABLE_SCHEMA = kcu.TABLE_SCHEMA
		WHERE tc.CONSTRAINT_TYPE = 'PRIMARY KEY' AND tc.TABLE_SCHEMA = @p1 AND tc.TABLE_NAME = @p2`, sch, tbl)
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
		SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COALESCE(COLUMN_DEFAULT, '')
		FROM INFORMATION_SCHEMA.COLUMNS
		WHERE TABLE_SCHEMA = @p1 AND TABLE_NAME = @p2
		ORDER BY ORDINAL_POSITION`, sch, tbl)
	if err != nil {
		return nil, err
	}
	defer func() { _ = colRows.Close() }()

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

	var idxs []types.SchemaIndex
	idxRows, err := c.db.QueryContext(ctx, `
		SELECT i.name, c.name, i.is_unique, i.is_primary_key
		FROM sys.indexes i
		JOIN sys.index_columns ic ON i.object_id = ic.object_id AND i.index_id = ic.index_id
		JOIN sys.columns c ON ic.object_id = c.object_id AND ic.column_id = c.column_id
		JOIN sys.tables t ON i.object_id = t.object_id
		JOIN sys.schemas s ON t.schema_id = s.schema_id
		WHERE s.name = @p1 AND t.name = @p2 AND i.name IS NOT NULL
		ORDER BY i.name, ic.key_ordinal`, sch, tbl)
	if err == nil {
		idxMap := map[string]*types.SchemaIndex{}
		var idxOrder []string
		for idxRows.Next() {
			var idxName, colName string
			var isUnique, isPrimary bool
			if idxRows.Scan(&idxName, &colName, &isUnique, &isPrimary) == nil {
				entry, ok := idxMap[idxName]
				if !ok {
					entry = &types.SchemaIndex{Name: idxName, Unique: isUnique, Primary: isPrimary}
					idxMap[idxName] = entry
					idxOrder = append(idxOrder, idxName)
				}
				entry.Columns = append(entry.Columns, colName)
			}
		}
		_ = idxRows.Close()
		for _, k := range idxOrder {
			idxs = append(idxs, *idxMap[k])
		}
	}

	var fks []types.SchemaForeignKey
	fkRows, err := c.db.QueryContext(ctx, `
		SELECT pc.name, rt.name, rc.name
		FROM sys.foreign_key_columns fkc
		JOIN sys.tables pt ON fkc.parent_object_id = pt.object_id
		JOIN sys.schemas ps ON pt.schema_id = ps.schema_id
		JOIN sys.columns pc ON fkc.parent_object_id = pc.object_id AND fkc.parent_column_id = pc.column_id
		JOIN sys.tables rt ON fkc.referenced_object_id = rt.object_id
		JOIN sys.columns rc ON fkc.referenced_object_id = rc.object_id AND fkc.referenced_column_id = rc.column_id
		WHERE ps.name = @p1 AND pt.name = @p2
		ORDER BY fkc.constraint_object_id, fkc.constraint_column_id`, sch, tbl)
	if err == nil {
		for fkRows.Next() {
			var fk types.SchemaForeignKey
			if fkRows.Scan(&fk.Column, &fk.ReferencedTable, &fk.ReferencedColumn) == nil {
				fks = append(fks, fk)
			}
		}
		_ = fkRows.Close()
	}

	dialect := "mssql"
	if caps := c.Capabilities(); caps != nil && caps.Dialect != "" {
		dialect = caps.Dialect
	}
	return &types.TableSchema{
		Engine:      "mssql",
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

func (c *mssqlConn) CancelAndDiscard() error {
	if c.spid > 0 && c.connector != nil {
		killCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		sideDB := sql.OpenDB(c.connector)
		_, _ = sideDB.ExecContext(killCtx, fmt.Sprintf("KILL %d", c.spid))
		_ = sideDB.Close()
		cancel()
	}
	return c.Close()
}

func (c *mssqlConn) Close() error {
	c.closeOnce.Do(func() {
		if c.closeHook != nil {
			_ = c.closeHook()
		}
		c.closeErr = c.db.Close()
	})
	return c.closeErr
}
