package builtin

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/microsoft/go-mssqldb/msdsn"

	"github.com/x0c/agent-dbctl/internal/driver"
	"github.com/x0c/agent-dbctl/internal/secrets"
	"github.com/x0c/agent-dbctl/internal/types"
)

func TestRegisterAllIncludesNewBuiltinsAndAliases(t *testing.T) {
	reg := driver.NewRegistry()
	RegisterAll(reg)

	for _, eng := range []string{"postgres", "opengauss", "kingbase", "dameng", "tdengine", "mysql", "sqlite", "mongodb", "redis", "clickhouse", "mssql", "oracle", "elasticsearch"} {
		d, ok := reg.Get(eng)
		if !ok {
			t.Fatalf("expected built-in driver %q to be registered", eng)
		}
		if d.Metadata().Engine != eng {
			t.Fatalf("unexpected metadata engine %q for %q", d.Metadata().Engine, eng)
		}
	}

	for alias, want := range map[string]string{
		"sqlserver":  "mssql",
		"opensearch": "elasticsearch",
		"easysearch": "elasticsearch",
		"mariadb":    "mysql",
		"tidb":       "mysql",
		"oceanbase":  "mysql",
		"polardb":    "mysql",
		"tdsql":      "mysql",
		"goldendb":   "mysql",
		"greatsql":   "mysql",
		"gbase8a":    "mysql",
		"selectdb":   "mysql",
		"valkey":     "redis",
		"gaussdb":    "opengauss",
		"vastbase":   "opengauss",
		"mogdb":      "opengauss",
		"gbase8c":    "opengauss",
		"kingbase8":  "kingbase",
		"kingbasees": "kingbase",
		"dm":         "dameng",
		"dm8":        "dameng",
		"taos":       "tdengine",
		"highgo":     "postgres",
		"uxdb":       "postgres",
		"opentenbase": "postgres",
		"kwdb":       "postgres",
	} {
		d, ok := reg.Get(alias)
		if !ok || d.Metadata().Engine != want {
			t.Fatalf("alias %q resolved to (%v, %v), want %q", alias, d, ok, want)
		}
	}
}

func TestClickHouseOptionsAndPlans(t *testing.T) {
	opts, err := buildClickHouseOptions(driver.ConnectionConfig{
		Engine:       "clickhouse",
		Host:         "ch1.internal,ch2.internal:9440",
		Port:         9000,
		DatabaseName: "analytics",
		ReadOnly:     true,
		Credential:   secrets.ResolvedSecret{Username: "ro_user", Secret: "pw"},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, nil
		},
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		Params: map[string]string{
			"readonly": "0", // must NOT bypass cfg.ReadOnly
			"compress": "lz4",
			"protocol": "native",
		},
	})
	if err != nil {
		t.Fatalf("buildClickHouseOptions: %v", err)
	}
	if len(opts.Addr) != 2 || opts.Addr[0] != "ch1.internal:9000" || opts.Addr[1] != "ch2.internal:9440" {
		t.Fatalf("unexpected clickhouse addrs: %v", opts.Addr)
	}
	if opts.Protocol != clickhouse.Native || opts.Compression == nil || opts.Compression.Method != clickhouse.CompressionLZ4 {
		t.Fatalf("unexpected protocol/compression: %+v", opts)
	}
	if opts.Settings["readonly"] != 1 {
		t.Fatalf("ReadOnly must not be bypassed by Params, got %v", opts.Settings["readonly"])
	}
	if opts.DialContext == nil || opts.TLS == nil {
		t.Fatal("expected DialContext and TLS to be wired")
	}

	// Plan without PrimaryKey pruning -> FullScan = true
	rep := &types.PreflightReport{}
	parseClickHouseEstimatePlan(&types.ExecResult{
		Columns: []types.Column{{Name: "database"}, {Name: "table"}, {Name: "parts"}, {Name: "rows"}, {Name: "marks"}},
		Rows:    [][]any{{"analytics", "events", int64(12), int64(250000), int64(31)}},
	}, rep)
	parseClickHousePlanLines([]string{
		"Expression (Projection)",
		"  ReadFromMergeTree (analytics.events)",
		"    ReadType: Default",
	}, rep)
	if !rep.FullScan || rep.EstimatedRows != 250000 {
		t.Fatalf("expected ClickHouse FullScan=true EstimatedRows=250000, got %+v", rep)
	}

	// Plan with PrimaryKey pruning -> FullScan = false
	repIdx := &types.PreflightReport{}
	parseClickHousePlanLines([]string{
		"Expression (Projection)",
		"  ReadFromMergeTree (analytics.events)",
		"    Indexes:",
		"      PrimaryKey",
		"        Type: PrimaryKey",
		"        Parts: 1/12",
	}, repIdx)
	if repIdx.FullScan {
		t.Fatalf("expected PrimaryKey-pruned ClickHouse plan not to mark FullScan, got %+v", repIdx)
	}

	// ClickHouse 24.8 PrimaryKey Condition: true -> FullScan = true; Keys + Condition != true -> FullScan = false
	rep24Full := &types.PreflightReport{}
	parseClickHousePlanLines([]string{
		"ReadFromMergeTree (orders_test.orders)",
		"Indexes:",
		"  PrimaryKey",
		"    Condition: true",
		"    Parts: 1/1",
	}, rep24Full)
	if !rep24Full.FullScan {
		t.Fatalf("expected ClickHouse 24.8 Condition: true to mark FullScan=true, got %+v", rep24Full)
	}
	rep24Pruned := &types.PreflightReport{}
	parseClickHousePlanLines([]string{
		"ReadFromMergeTree (orders_test.orders)",
		"Indexes:",
		"  PrimaryKey",
		"    Keys:",
		"      id",
		"    Condition: (id in [42, 42])",
	}, rep24Pruned)
	if rep24Pruned.FullScan {
		t.Fatalf("expected ClickHouse 24.8 Keys+Condition to mark FullScan=false, got %+v", rep24Pruned)
	}
}

func TestMSSQLConfigAndShowplanParsing(t *testing.T) {
	msCfg, err := buildMSSQLConfig(driver.ConnectionConfig{
		Engine:       "mssql",
		Host:         "sql.internal",
		DatabaseName: "orders",
		ReadOnly:     true,
		TLSMode:      "verify-full",
		Credential:   secrets.ResolvedSecret{Username: "ro", Secret: "pw"},
		Params: map[string]string{
			"applicationIntent": "ReadWrite", // ignored; governed by cfg.ReadOnly
			"encrypt":           "disable",   // ignored; governed by TLSMode
			"instance":          "SQLEXPRESS",
		},
	})
	if err != nil {
		t.Fatalf("buildMSSQLConfig: %v", err)
	}
	if msCfg.Port != 1433 || !msCfg.ReadOnlyIntent || msCfg.Encryption != msdsn.EncryptionRequired || msCfg.TrustServerCertificate {
		t.Fatalf("unexpected MSSQL config: %+v", msCfg)
	}
	if msCfg.Instance != "SQLEXPRESS" {
		t.Fatalf("expected instance SQLEXPRESS, got %q", msCfg.Instance)
	}

	// When DatabaseName is empty, ReadOnlyIntent must remain false per go-mssqldb constraint.
	msNoDB, err := buildMSSQLConfig(driver.ConnectionConfig{Engine: "mssql", Host: "127.0.0.1", ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if msNoDB.ReadOnlyIntent {
		t.Fatal("ReadOnlyIntent must stay false when DatabaseName is empty")
	}

	rep := &types.PreflightReport{}
	parseMSSQLShowplan(&types.ExecResult{
		Columns: []types.Column{{Name: "StmtText"}, {Name: "PhysicalOp"}, {Name: "EstimateRows"}},
		Rows: [][]any{
			{"SELECT * FROM orders", nil, float64(4200)},
			{"  |--Table Scan(OBJECT:([orders].[dbo].[orders]))", "Table Scan", float64(4200)},
		},
	}, rep)
	if !rep.FullScan || rep.EstimatedRows != 4200 {
		t.Fatalf("expected MSSQL Table Scan FullScan=true EstimatedRows=4200, got %+v", rep)
	}

	repSeek := &types.PreflightReport{}
	parseMSSQLShowplan(&types.ExecResult{
		Columns: []types.Column{{Name: "StmtText"}, {Name: "PhysicalOp"}, {Name: "EstimateRows"}},
		Rows: [][]any{
			{"  |--Clustered Index Seek(OBJECT:([orders].[dbo].[orders].[PK_orders]))", "Clustered Index Seek", float64(1)},
		},
	}, repSeek)
	if repSeek.FullScan || repSeek.EstimatedRows != 1 {
		t.Fatalf("expected MSSQL Clustered Index Seek FullScan=false EstimatedRows=1, got %+v", repSeek)
	}
}

func TestOracleDSNAndXPlanParsing(t *testing.T) {
	dsn, err := buildOracleDSN(driver.ConnectionConfig{
		Engine:       "oracle",
		Host:         "ora.internal",
		Port:         1522,
		DatabaseName: "FREEPDB1",
		TLSMode:      "verify-full",
		Credential:   secrets.ResolvedSecret{Username: "app_ro", Secret: "s3cret"},
	})
	if err != nil {
		t.Fatalf("buildOracleDSN: %v", err)
	}
	if !strings.Contains(dsn, "ora.internal:1522/FREEPDB1") || !strings.Contains(dsn, "SSL=true") {
		t.Fatalf("unexpected oracle DSN: %q", dsn)
	}

	dsnSID, err := buildOracleDSN(driver.ConnectionConfig{
		Engine:     "oracle",
		Host:       "ora.internal",
		Params:     map[string]string{"sid": "ORCLCDB"},
		Credential: secrets.ResolvedSecret{Username: "sys", Secret: "pw"},
	})
	if err != nil {
		t.Fatalf("buildOracleDSN SID: %v", err)
	}
	if !strings.Contains(dsnSID, "SID=ORCLCDB") {
		t.Fatalf("expected SID param in DSN, got %q", dsnSID)
	}

	rep := &types.PreflightReport{}
	parseOracleXPlan([]string{
		"----------------------------------------------------------------------------",
		"| Id  | Operation         | Name   | Rows  | Bytes | Cost (%CPU)| Time     |",
		"----------------------------------------------------------------------------",
		"|   0 | SELECT STATEMENT  |        | 15K   |  150K |    42   (0)| 00:00:01 |",
		"|*  1 |  TABLE ACCESS FULL| ORDERS | 15K   |  150K |    42   (0)| 00:00:01 |",
		"----------------------------------------------------------------------------",
	}, rep)
	if !rep.FullScan || rep.EstimatedRows != 15000 {
		t.Fatalf("expected Oracle TABLE ACCESS FULL FullScan=true EstimatedRows=15000, got %+v", rep)
	}
}

func TestElasticsearchEndToEndMockServer(t *testing.T) {
	var seenAuth atomic.Value
	var seenDialCalls atomic.Int32
	var seenWriteCalls atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth.Store(r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"cluster_name": "opensearch-prod",
				"version": map[string]any{
					"distribution": "opensearch",
					"number":       "2.17.1",
				},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/_cat/indices":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"index": "orders", "docs.count": "1234", "health": "green", "status": "open"},
				{"index": "audit_events", "docs.count": "50", "health": "green", "status": "open"},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/orders/_mapping":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"orders": map[string]any{
					"mappings": map[string]any{
						"properties": map[string]any{
							"order_id": map[string]any{"type": "long"},
							"customer": map[string]any{
								"properties": map[string]any{
									"email": map[string]any{"type": "keyword"},
								},
							},
						},
					},
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/orders/_validate/query":
			_ = json.NewEncoder(w).Encode(map[string]any{"valid": true, "_shards": map[string]any{"total": 1, "successful": 1}})
		case r.Method == http.MethodPost && r.URL.Path == "/orders/_count":
			_ = json.NewEncoder(w).Encode(map[string]any{"count": 1234})
		case r.Method == http.MethodPost && r.URL.Path == "/orders/_search":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"hits": map[string]any{
					"hits": []map[string]any{
						{"_id": "1", "_source": map[string]any{"order_id": 1, "status": "paid"}},
						{"_id": "2", "_source": map[string]any{"order_id": 2, "status": "pending"}},
						{"_id": "3", "_source": map[string]any{"order_id": 3, "status": "paid"}},
					},
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/orders/_doc":
			body, _ := io.ReadAll(r.Body)
			if len(body) > 0 {
				seenWriteCalls.Add(1)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"_id": "99", "result": "created"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, portStr, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portStr)

	var hookCalls atomic.Int32
	drv := &ElasticsearchDriver{}
	roConn, err := drv.Open(context.Background(), driver.ConnectionConfig{
		Engine:       "elasticsearch",
		Host:         host,
		Port:         port,
		DatabaseName: "orders",
		ReadOnly:     true,
		Credential:   secrets.ResolvedSecret{Secret: "tok_abc123"},
		Params:       map[string]string{"auth_type": "bearer"},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			seenDialCalls.Add(1)
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
		CloseHook: func() error {
			hookCalls.Add(1)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("Open elasticsearch: %v", err)
	}

	if gotAuth, _ := seenAuth.Load().(string); gotAuth != "Bearer tok_abc123" {
		t.Fatalf("expected Bearer auth header, got %q", gotAuth)
	}
	if seenDialCalls.Load() == 0 {
		t.Fatal("expected custom DialContext to be invoked")
	}

	ping, err := roConn.Ping(context.Background())
	if err != nil || !ping.Reachable || ping.Dialect != "opensearch" || ping.Capabilities == nil || ping.Capabilities.MajorVersion != 2 {
		t.Fatalf("unexpected Ping result: %+v err=%v", ping, err)
	}

	dbs, err := roConn.ListDatabases(context.Background())
	if err != nil || !slices.Equal(dbs, []string{"audit_events", "orders"}) {
		t.Fatalf("ListDatabases = (%v, %v), want [audit_events orders]", dbs, err)
	}

	inspector := roConn.(driver.SchemaInspector)
	listRes, err := inspector.ListTables(context.Background(), driver.SchemaListOpts{Search: "ord"})
	if err != nil || len(listRes.Items) != 1 || listRes.Items[0].Name != "orders" || *listRes.Items[0].EstimatedRows != 1234 {
		t.Fatalf("ListTables = (%+v, %v)", listRes, err)
	}

	tblSchema, err := inspector.DescribeTable(context.Background(), "orders")
	if err != nil || len(tblSchema.Columns) != 3 {
		t.Fatalf("DescribeTable = (%+v, %v)", tblSchema, err)
	}

	// Preflight match_all without size -> FullScan = true, EstimatedRows = 1234
	pf, err := roConn.Preflight(context.Background(), `{"index":"orders","query":{"match_all":{}}}`, driver.PreflightOpts{})
	if err != nil || !pf.FullScan || pf.EstimatedRows != 1234 {
		t.Fatalf("unexpected Preflight: %+v err=%v", pf, err)
	}

	// Execute search with MaxRows=2 truncation
	execRes, err := roConn.Execute(context.Background(), "POST /orders/_search\n{\"query\":{\"match_all\":{}},\"size\":10}", driver.ExecOpts{MaxRows: 2, MaxBytes: 65536})
	if err != nil || execRes.Family != types.FamilyDocument || !execRes.Truncated || execRes.ReturnedRows != 2 || execRes.FetchedRows != 3 {
		t.Fatalf("unexpected Execute result: %+v err=%v", execRes, err)
	}

	// ReadOnly mode must reject writes before sending HTTP request
	if _, err := roConn.Execute(context.Background(), "POST /orders/_doc\n{\"order_id\":99}", driver.ExecOpts{}); err == nil {
		t.Fatal("expected ReadOnly mode to block POST /orders/_doc")
	}
	if seenWriteCalls.Load() != 0 {
		t.Fatal("ReadOnly mode must not send blocked write to server")
	}

	_ = roConn.CancelAndDiscard()
	_ = roConn.Close()
	if hookCalls.Load() != 1 {
		t.Fatalf("expected CloseHook called once, got %d", hookCalls.Load())
	}

	// RW mode allows write execution
	rwConn, err := drv.Open(context.Background(), driver.ConnectionConfig{
		Engine:       "elasticsearch",
		Host:         host,
		Port:         port,
		DatabaseName: "orders",
		ReadOnly:     false,
		Credential:   secrets.ResolvedSecret{Username: "es_rw", Secret: "rw_secret"},
	})
	if err != nil {
		t.Fatalf("Open RW elasticsearch: %v", err)
	}
	defer func() { _ = rwConn.Close() }()
	wRes, err := rwConn.Execute(context.Background(), "POST /orders/_doc\n{\"order_id\":99}", driver.ExecOpts{})
	if err != nil || len(wRes.Documents) != 1 || seenWriteCalls.Load() != 1 {
		t.Fatalf("expected RW write to succeed: res=%+v err=%v writes=%d", wRes, err, seenWriteCalls.Load())
	}
}

func TestDamengOpenGaussKingbaseDSNAndPlans(t *testing.T) {
	// Dameng DSN preserves special characters in secret, wires dialName and sslEncrypt, and bounds dial slots.
	slot := dmDialSlots.acquire(func(context.Context, string) (net.Conn, error) { return nil, nil })
	if slot == "" {
		t.Fatal("expected non-empty dameng dial slot")
	}
	dmDSN, err := buildDamengDSN(driver.ConnectionConfig{
		Engine:       "dameng",
		Host:         "dm.internal",
		Port:         5236,
		DatabaseName: "ORDERS",
		TLSMode:      "require",
		Credential:   secrets.ResolvedSecret{Username: "SYSDBA", Secret: "p@ss:w?rd#1"},
	}, slot)
	dmDialSlots.release(slot)
	if err != nil {
		t.Fatalf("buildDamengDSN: %v", err)
	}
	if !strings.Contains(dmDSN, "dm://SYSDBA:p@ss:w?rd#1@dm.internal:5236?") ||
		!strings.Contains(dmDSN, "schema=ORDERS") ||
		!strings.Contains(dmDSN, "dialName="+slot) ||
		!strings.Contains(dmDSN, "sslEncrypt=1") {
		t.Fatalf("unexpected dameng DSN: %q", dmDSN)
	}

	// Slot reuse must keep slot count bounded.
	slot2 := dmDialSlots.acquire(func(context.Context, string) (net.Conn, error) { return nil, nil })
	dmDialSlots.release(slot2)
	if slot2 != slot {
		t.Fatalf("expected released slot %q to be reused, got %q", slot, slot2)
	}

	// Dameng EXPLAIN plan parsing detects CSCN2 full scans and row estimates.
	dmFull := &types.PreflightReport{}
	parseDamengExplainLines([]string{
		"1   #NSET2: [1, 42000, 128]",
		"2     #PRJT2: [1, 42000, 128]; exp_num(2)",
		"3       #CSCN2: [1, 42000, 128]; INDEX33555514(ORDERS)",
	}, dmFull)
	if !dmFull.FullScan || dmFull.EstimatedRows != 42000 {
		t.Fatalf("expected Dameng CSCN2 FullScan=true EstimatedRows=42000, got %+v", dmFull)
	}

	dmSeek := &types.PreflightReport{}
	parseDamengExplainLines([]string{
		"1   #NSET2: [1, 1, 64]",
		"2     #BLKUP2: [1, 1, 64]; IDX_ORDERS_ID(ORDERS)",
		"3       #SSEK2: [1, 1, 64]; scan_type(ASC), IDX_ORDERS_ID(ORDERS)",
	}, dmSeek)
	if dmSeek.FullScan || dmSeek.EstimatedRows != 1 {
		t.Fatalf("expected Dameng SSEK2 FullScan=false EstimatedRows=1, got %+v", dmSeek)
	}

	// openGauss & Kingbase DSN builders apply default ports and libpq sslmode mapping.
	ogDSN := buildOpenGaussDSN(driver.ConnectionConfig{
		Engine:       "opengauss",
		Host:         "og.internal",
		DatabaseName: "finance",
		TLSMode:      "verify-full",
		Credential:   secrets.ResolvedSecret{Username: "gaussdb", Secret: "s3cr@t"},
	})
	if !strings.HasPrefix(ogDSN, "opengauss://gaussdb:s3cr%40t@og.internal:5432/finance?") || !strings.Contains(ogDSN, "sslmode=verify-full") {
		t.Fatalf("unexpected opengauss DSN: %q", ogDSN)
	}
	kbDSN := buildKingbaseDSN(driver.ConnectionConfig{
		Engine:       "kingbase",
		Host:         "kb.internal",
		DatabaseName: "app",
		TLSMode:      "disable",
		Credential:   secrets.ResolvedSecret{Username: "system", Secret: "pw"},
	})
	if !strings.HasPrefix(kbDSN, "kingbase://system:pw@kb.internal:54321/app?") || !strings.Contains(kbDSN, "sslmode=disable") {
		t.Fatalf("unexpected kingbase DSN: %q", kbDSN)
	}
}

func TestTDengineEndToEndMockServer(t *testing.T) {
	var seenAuth atomic.Value
	var seenDialCalls atomic.Int32
	var seenWriteCalls atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth.Store(r.Header.Get("Authorization"))
		bodyBytes, _ := io.ReadAll(r.Body)
		sqlText := strings.TrimSpace(string(bodyBytes))
		upper := strings.ToUpper(sqlText)
		w.Header().Set("Content-Type", "application/json")

		switch {
		case upper == "SELECT SERVER_VERSION()":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code":        0,
				"column_meta": [][]any{{"server_version()", "VARCHAR", 16}},
				"data":        [][]any{{"3.3.2.0"}},
				"rows":        1,
			})
		case upper == "SHOW DATABASES":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code":        0,
				"column_meta": [][]any{{"name", "VARCHAR", 64}},
				"data":        [][]any{{"power"}, {"log"}},
				"rows":        2,
			})
		case upper == "SHOW STABLES":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code":        0,
				"column_meta": [][]any{{"stable_name", "VARCHAR", 64}},
				"data":        [][]any{{"meters"}},
				"rows":        1,
			})
		case upper == "SHOW TABLES":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code":        0,
				"column_meta": [][]any{{"table_name", "VARCHAR", 64}},
				"data":        [][]any{{"d1001"}},
				"rows":        1,
			})
		case strings.HasPrefix(upper, "DESCRIBE "):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code":        0,
				"column_meta": [][]any{{"field", "VARCHAR", 64}, {"type", "VARCHAR", 16}, {"length", "INT", 4}, {"note", "VARCHAR", 8}},
				"data":        [][]any{{"ts", "TIMESTAMP", 8, ""}, {"current", "FLOAT", 4, ""}, {"location", "NCHAR", 32, "TAG"}},
				"rows":        3,
			})
		case strings.HasPrefix(upper, "EXPLAIN "):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code":        0,
				"column_meta": [][]any{{"plan", "VARCHAR", 256}},
				"data":        [][]any{{"FULL TABLE SCAN on meters"}},
				"rows":        1,
			})
		case strings.HasPrefix(upper, "SELECT "):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code":        0,
				"column_meta": [][]any{{"ts", "TIMESTAMP", 8}, {"current", "FLOAT", 4}},
				"data": [][]any{
					{"2026-01-01T00:00:00Z", 10.2},
					{"2026-01-01T00:01:00Z", 10.5},
					{"2026-01-01T00:02:00Z", 10.8},
				},
				"rows": 3,
			})
		case strings.HasPrefix(upper, "INSERT "):
			seenWriteCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code":        0,
				"column_meta": [][]any{},
				"data":        [][]any{},
				"rows":        1,
			})
		default:
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 9728, "desc": "unexpected query: " + sqlText})
		}
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, portStr, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portStr)

	var hookCalls atomic.Int32
	drv := &TDengineDriver{}
	roConn, err := drv.Open(context.Background(), driver.ConnectionConfig{
		Engine:       "tdengine",
		Host:         host,
		Port:         port,
		DatabaseName: "power",
		ReadOnly:     true,
		Credential:   secrets.ResolvedSecret{Username: "root", Secret: "taosdata"},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			seenDialCalls.Add(1)
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
		CloseHook: func() error {
			hookCalls.Add(1)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("Open tdengine: %v", err)
	}

	if gotAuth, _ := seenAuth.Load().(string); !strings.HasPrefix(gotAuth, "Basic ") {
		t.Fatalf("expected Basic auth header, got %q", gotAuth)
	}
	if seenDialCalls.Load() == 0 {
		t.Fatal("expected custom DialContext to be invoked")
	}

	ping, err := roConn.Ping(context.Background())
	if err != nil || !ping.Reachable || ping.Dialect != "tdengine" || ping.Capabilities.MajorVersion != 3 {
		t.Fatalf("unexpected Ping result: %+v err=%v", ping, err)
	}
	dbs, err := roConn.ListDatabases(context.Background())
	if err != nil || !slices.Equal(dbs, []string{"power", "log"}) {
		t.Fatalf("ListDatabases = (%v, %v)", dbs, err)
	}

	inspector := roConn.(driver.SchemaInspector)
	tblList, err := inspector.ListTables(context.Background(), driver.SchemaListOpts{})
	if err != nil || len(tblList.Items) != 2 || tblList.Items[0].Type != "stable" {
		t.Fatalf("ListTables = (%+v, %v)", tblList, err)
	}
	tblDesc, err := inspector.DescribeTable(context.Background(), "meters")
	if err != nil || len(tblDesc.Columns) != 3 || tblDesc.Columns[2].Extra != "TAG" {
		t.Fatalf("DescribeTable = (%+v, %v)", tblDesc, err)
	}

	pf, err := roConn.Preflight(context.Background(), "SELECT * FROM meters WHERE location = 'hz' LIMIT 10", driver.PreflightOpts{})
	if err != nil || !pf.FullScan {
		t.Fatalf("expected TDengine EXPLAIN FullScan=true, got %+v err=%v", pf, err)
	}

	execRes, err := roConn.Execute(context.Background(), "SELECT ts, current FROM meters WHERE location = 'hz' LIMIT 10", driver.ExecOpts{MaxRows: 2, MaxBytes: 65536})
	if err != nil || !execRes.Truncated || execRes.ReturnedRows != 2 || execRes.FetchedRows != 3 {
		t.Fatalf("unexpected Execute result: %+v err=%v", execRes, err)
	}

	if _, err := roConn.Execute(context.Background(), "INSERT INTO d1001 VALUES (NOW, 12.3)", driver.ExecOpts{}); err == nil {
		t.Fatal("expected ReadOnly mode to block INSERT")
	}
	if seenWriteCalls.Load() != 0 {
		t.Fatal("ReadOnly mode must not send blocked INSERT to server")
	}

	_ = roConn.CancelAndDiscard()
	_ = roConn.Close()
	if hookCalls.Load() != 1 {
		t.Fatalf("expected CloseHook called once, got %d", hookCalls.Load())
	}
}
