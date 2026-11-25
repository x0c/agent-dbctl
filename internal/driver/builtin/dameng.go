package builtin

import (
	"context"
	"database/sql"
	sqldriver "database/sql/driver"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gitee.com/chunanyong/dm"

	"github.com/x0c/agent-dbctl/internal/classify"
	"github.com/x0c/agent-dbctl/internal/driver"
	"github.com/x0c/agent-dbctl/internal/types"
)

var dmExplainTripleRe = regexp.MustCompile(`\[\s*\d+\s*,\s*(\d+)\s*,\s*\d+\s*\]`)

// damengDialSlotPool bounds entries registered with dm.RegisterDialContext so repeated
// tunneled connections never grow the driver's global map unboundedly.
type damengDialSlotPool struct {
	mu      sync.Mutex
	free    []string
	nextID  uint64
	targets sync.Map // slotName -> func(context.Context, string) (net.Conn, error)
}

var dmDialSlots = &damengDialSlotPool{}

func (p *damengDialSlotPool) acquire(fn func(context.Context, string) (net.Conn, error)) string {
	p.mu.Lock()
	var slot string
	if n := len(p.free); n > 0 {
		slot = p.free[n-1]
		p.free = p.free[:n-1]
		p.mu.Unlock()
		p.targets.Store(slot, fn)
		return slot
	}
	p.nextID++
	slot = fmt.Sprintf("agentdbctl_%d", p.nextID)
	p.mu.Unlock()

	p.targets.Store(slot, fn)
	dm.RegisterDialContext(slot, func(ctx context.Context, addr string) (net.Conn, error) {
		v, ok := p.targets.Load(slot)
		if !ok || v == nil {
			return nil, fmt.Errorf("dameng dial slot %q is closed", slot)
		}
		targetFn := v.(func(context.Context, string) (net.Conn, error))
		return targetFn(ctx, addr)
	})
	return slot
}

func (p *damengDialSlotPool) release(slot string) {
	if slot == "" {
		return
	}
	p.targets.Delete(slot)
	p.mu.Lock()
	p.free = append(p.free, slot)
	p.mu.Unlock()
}

// DamengDriver implements Dameng DM8 (达梦) support using pure-Go gitee.com/chunanyong/dm.
type DamengDriver struct{}

func (d *DamengDriver) Metadata() types.DriverMetadata {
	return types.DriverMetadata{
		ID:           "builtin-dameng",
		Engine:       "dameng",
		DisplayName:  "Dameng DM8",
		Family:       types.FamilySQL,
		Tier:         "builtin",
		Version:      "1.0.0",
		Capabilities: []string{"ping", "list_databases", "schema", "preflight", "execute"},
		Verified:     true,
		Labels:       map[string]string{"en": "Dameng DM8", "zh": "达梦 DM8"},
	}
}

func (d *DamengDriver) Classify(_ context.Context, raw string) (types.Classification, error) {
	return classify.Classify("dameng", raw), nil
}

func buildDamengDSN(cfg driver.ConnectionConfig, dialSlot string) (string, error) {
	port := cfg.Port
	if port <= 0 {
		port = 5236
	}
	host := strings.TrimSpace(cfg.Host)
	if host == "" {
		host = "127.0.0.1"
	}

	user := cfg.Credential.Username
	if user == "" {
		user = "SYSDBA"
	}
	pass := cfg.Credential.Secret

	q := url.Values{}
	q.Set("connectTimeout", "10000")
	if db := strings.TrimSpace(cfg.DatabaseName); db != "" {
		q.Set("schema", db)
	}
	if dialSlot != "" {
		q.Set("dialName", dialSlot)
	}
	switch strings.ToLower(strings.TrimSpace(cfg.TLSMode)) {
	case "require", "verify-ca", "verify-full":
		q.Set("sslEncrypt", "1")
	}

	for k, v := range cfg.Params {
		kl := strings.ToLower(strings.TrimSpace(k))
		switch kl {
		case "dialname", "sslencrypt":
			// Controlled by NetworkProfile / dialer wiring.
		default:
			q.Set(strings.TrimSpace(k), v)
		}
	}

	// Note: dm driver's parseDSN splits at LastIndex("?") and LastIndex("@") without URL-unescaping
	// user/password; always keep a query string so raw special characters in pass remain intact.
	return fmt.Sprintf("dm://%s:%s@%s?%s", user, pass, net.JoinHostPort(host, strconv.Itoa(port)), q.Encode()), nil
}

func (d *DamengDriver) Open(ctx context.Context, cfg driver.ConnectionConfig) (driver.Conn, error) {
	var dialSlot string
	if cfg.DialContext != nil {
		dialSlot = dmDialSlots.acquire(func(dctx context.Context, addr string) (net.Conn, error) {
			return cfg.DialContext(dctx, "tcp", addr)
		})
	}
	releaseSlot := func() {
		if dialSlot != "" {
			dmDialSlots.release(dialSlot)
			dialSlot = ""
		}
	}

	dsn, err := buildDamengDSN(cfg, dialSlot)
	if err != nil {
		releaseSlot()
		return nil, err
	}

	baseDrv := &dm.DmDriver{}
	baseConn, err := baseDrv.OpenConnector(dsn)
	if err != nil {
		releaseSlot()
		return nil, err
	}

	connector := sqldriver.Connector(baseConn)
	if cfg.ReadOnly {
		connector = &readOnlyExecConnector{
			inner:     baseConn,
			stmts:     []string{"SP_SET_SESSION_READONLY(1)", "SET TRANSACTION READ ONLY"},
			errPrefix: "dameng",
		}
	}

	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		releaseSlot()
		return nil, err
	}

	dc := &damengConn{
		db:        db,
		cfg:       cfg,
		dialSlot:  dialSlot,
		closeHook: driver.CloseOnce(cfg.CloseHook),
	}
	if cfg.NegotiatedCapabilities != nil {
		cp := *cfg.NegotiatedCapabilities
		dc.caps.Store(&cp)
	}
	return dc, nil
}

type damengConn struct {
	db        *sql.DB
	cfg       driver.ConnectionConfig
	dialSlot  string
	closeHook func() error
	closeOnce sync.Once
	closeErr  error
	caps      atomic.Pointer[types.ServerCapabilities]
}

func (c *damengConn) Capabilities() *types.ServerCapabilities {
	return c.caps.Load()
}

func (c *damengConn) ResetSession(ctx context.Context) error {
	if c.db == nil {
		return fmt.Errorf("dameng db handle is closed")
	}
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return c.db.PingContext(pingCtx)
}

func (c *damengConn) Ping(ctx context.Context) (types.PingResult, error) {
	start := time.Now()
	var ver string
	err := c.db.QueryRowContext(ctx, "SELECT BANNER FROM V$VERSION WHERE ROWNUM = 1").Scan(&ver)
	if err != nil {
		if err2 := c.db.QueryRowContext(ctx, "SELECT TOP 1 * FROM V$VERSION").Scan(&ver); err2 == nil {
			err = nil
		} else if err3 := c.db.QueryRowContext(ctx, "SELECT ID_CODE() FROM DUAL").Scan(&ver); err3 == nil {
			err = nil
		} else if err4 := c.db.QueryRowContext(ctx, "SELECT 'DM8' FROM DUAL").Scan(&ver); err4 == nil {
			err = nil
		}
	}
	lat := time.Since(start).Milliseconds()
	if err != nil {
		return types.PingResult{Engine: "dameng", Reachable: false, LatencyMs: lat, Error: err.Error()}, err
	}
	caps := driver.DetectServerCapabilities("dameng", ver, driver.DialectHints{})
	c.caps.Store(&caps)
	return types.PingResult{
		Engine:        "dameng",
		Dialect:       caps.Dialect,
		Reachable:     true,
		ServerVersion: ver,
		Capabilities:  &caps,
		LatencyMs:     lat,
	}, nil
}

func (c *damengConn) ListDatabases(ctx context.Context) ([]string, error) {
	queries := []string{
		"SELECT NAME FROM SYS.SYSOBJECTS WHERE TYPE$ = 'SCH' ORDER BY NAME",
		"SELECT USERNAME FROM ALL_USERS ORDER BY USERNAME",
		"SELECT SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA') FROM DUAL",
	}
	var lastErr error
	for _, q := range queries {
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
	return nil, lastErr
}

func (c *damengConn) Preflight(ctx context.Context, raw string, _ driver.PreflightOpts) (*types.PreflightReport, error) {
	cls := classify.Classify("dameng", raw)
	report := &types.PreflightReport{
		Supported: true,
		Executed:  false,
		Format:    "dameng_explain",
	}
	if !driver.CanPreflightSQL(cls) {
		report.Warnings = append(report.Warnings, "EXPLAIN skipped for DDL/admin/multi-statement SQL")
		return report, nil
	}

	// DM8 EXPLAIN FOR populates session-local ##PLAN_TABLE with structured plan columns;
	// fall back to direct EXPLAIN <sql> if ##PLAN_TABLE is unavailable.
	if _, err := c.db.ExecContext(ctx, "EXPLAIN FOR "+raw); err == nil {
		rows, qErr := c.db.QueryContext(ctx, "SELECT OPERATION, COALESCE(OPTIONS, ''), COALESCE(OBJECT_NAME, ''), COALESCE(CARDINALITY, 0), COALESCE(COST, 0) FROM ##PLAN_TABLE ORDER BY ID")
		if qErr == nil {
			defer func() { _ = rows.Close() }()
			var lines []string
			for rows.Next() {
				var op, opts, obj string
				var card, cost int64
				if rows.Scan(&op, &opts, &obj, &card, &cost) == nil {
					lines = append(lines, fmt.Sprintf("%s %s %s [cost=%d, rows=%d]", op, opts, obj, cost, card))
					if card > report.EstimatedRows {
						report.EstimatedRows = card
					}
				}
			}
			if len(lines) > 0 {
				parseDamengExplainLines(lines, report)
				return report, nil
			}
		}
	}

	rows, err := c.db.QueryContext(ctx, "EXPLAIN "+raw)
	if err != nil {
		report.Warnings = append(report.Warnings, "EXPLAIN failed: "+err.Error())
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
	if len(lines) == 0 {
		report.Warnings = append(report.Warnings, "EXPLAIN returned no rows from DM8 driver")
		return report, nil
	}
	parseDamengExplainLines(lines, report)
	return report, nil
}

func parseDamengExplainLines(lines []string, report *types.PreflightReport) {
	for _, line := range lines {
		upper := strings.ToUpper(line)
		if strings.Contains(upper, "CSCN2") ||
			strings.Contains(upper, "CSCN") ||
			strings.Contains(upper, "SSCN") ||
			strings.Contains(upper, "TABLE ACCESS FULL") ||
			strings.Contains(upper, "INDEX FULL SCAN") {
			report.FullScan = true
		}
		if m := dmExplainTripleRe.FindStringSubmatch(line); len(m) == 2 {
			if n, err := strconv.ParseInt(m[1], 10, 64); err == nil && n > report.EstimatedRows {
				report.EstimatedRows = n
			}
		}
	}
	report.PlanRaw = lines
	report.PlanSummary = strings.Join(lines, "\n")
}

func (c *damengConn) Execute(ctx context.Context, raw string, opts driver.ExecOpts) (*types.ExecResult, error) {
	start := time.Now()
	cls := classify.Classify("dameng", raw)
	if c.cfg.ReadOnly && !cls.IsReadOnly {
		return nil, fmt.Errorf("read-only mode blocks non-read Dameng statement (%s)", cls.RiskLevel)
	}

	if cls.IsReadOnly && cls.StatementCount == 1 {
		if c.cfg.ReadOnly {
			if tx, err := c.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true}); err == nil {
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

func (c *damengConn) currentSchema(ctx context.Context) string {
	var sch string
	_ = c.db.QueryRowContext(ctx, "SELECT SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA') FROM DUAL").Scan(&sch)
	if strings.TrimSpace(sch) == "" {
		_ = c.db.QueryRowContext(ctx, "SELECT USER FROM DUAL").Scan(&sch)
	}
	if strings.TrimSpace(sch) == "" {
		sch = strings.TrimSpace(c.cfg.DatabaseName)
	}
	if sch == "" {
		sch = "SYSDBA"
	}
	return strings.ToUpper(sch)
}

func (c *damengConn) ListTables(ctx context.Context, opts driver.SchemaListOpts) (*types.SchemaListResult, error) {
	sch := c.currentSchema(ctx)
	rows, err := c.db.QueryContext(ctx, `
		SELECT owner, table_name, 'table' FROM all_tables WHERE owner = :1
		UNION ALL
		SELECT owner, view_name, 'view' FROM all_views WHERE owner = :2
		UNION ALL
		SELECT table_owner, synonym_name, 'synonym' FROM all_synonyms WHERE owner = :3
		ORDER BY 1, 2`, sch, sch, sch)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var all []types.SchemaObjectSummary
	for rows.Next() {
		var owner, name, ttype string
		if err := rows.Scan(&owner, &name, &ttype); err != nil {
			return nil, err
		}
		all = append(all, types.SchemaObjectSummary{
			Schema: owner,
			Name:   name,
			Type:   ttype,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	items, total, truncated := driver.FilterAndCapSchemaObjects(all, opts.Search, opts.Limit)
	return &types.SchemaListResult{
		Engine:        "dameng",
		Dialect:       "dameng",
		Database:      sch,
		Items:         items,
		TotalCount:    total,
		ReturnedCount: len(items),
		Truncated:     truncated,
	}, nil
}

func (c *damengConn) DescribeTable(ctx context.Context, name string) (*types.TableSchema, error) {
	sch, tbl := driver.SplitQualifiedObject(name)
	if tbl == "" {
		return nil, fmt.Errorf("table name is required")
	}
	if sch == "" {
		sch = c.currentSchema(ctx)
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
		Engine:     "dameng",
		Dialect:    "dameng",
		Database:   schUpper,
		Schema:     schUpper,
		Name:       tblUpper,
		ObjectType: "table",
		Columns:    cols,
		Indexes:    idxs,
	}, nil
}

func (c *damengConn) CancelAndDiscard() error {
	return c.Close()
}

func (c *damengConn) Close() error {
	c.closeOnce.Do(func() {
		if c.closeHook != nil {
			_ = c.closeHook()
		}
		c.closeErr = c.db.Close()
		if c.dialSlot != "" {
			dmDialSlots.release(c.dialSlot)
			c.dialSlot = ""
		}
	})
	return c.closeErr
}
