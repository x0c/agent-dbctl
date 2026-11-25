package builtin

import (
	"context"
	"crypto/tls"
	"database/sql"
	sqldriver "database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
	ogU, ogParseErr := url.Parse(ogDSN)
	if ogParseErr != nil || ogU == nil {
		t.Fatalf("parse opengauss DSN %q: %v", ogDSN, ogParseErr)
	}
	ogPW, _ := ogU.User.Password()
	if ogU.Scheme != "postgres" ||
		ogU.User.Username() != "gaussdb" ||
		ogPW != "s3cr@t" ||
		ogU.Host != "og.internal:5432" ||
		ogU.Path != "/finance" ||
		ogU.Query().Get("sslmode") != "verify-full" {
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

	// Verify RW writes succeed, Taosd auth token header works, non-zero errors propagate, and ResetSession/Classify behave cleanly.
	rwConn, err := drv.Open(context.Background(), driver.ConnectionConfig{
		Engine:       "tdengine",
		Host:         host,
		Port:         port,
		DatabaseName: "power",
		ReadOnly:     false,
		Credential:   secrets.ResolvedSecret{Secret: "tok_abc123"},
		Params:       map[string]string{"auth_type": "taosd"},
	})
	if err != nil {
		t.Fatalf("Open tdengine taosd RW: %v", err)
	}
	defer func() { _ = rwConn.Close() }()
	if gotAuth, _ := seenAuth.Load().(string); gotAuth != "Taosd tok_abc123" {
		t.Fatalf("expected Taosd auth header, got %q", gotAuth)
	}
	if resetter, ok := rwConn.(interface{ ResetSession(context.Context) error }); !ok {
		t.Fatal("expected tdengine conn to implement ResetSession")
	} else if err := resetter.ResetSession(context.Background()); err != nil {
		t.Fatalf("tdengine ResetSession: %v", err)
	}
	if capRep, ok := rwConn.(interface{ Capabilities() *types.ServerCapabilities }); !ok {
		t.Fatal("expected tdengine conn to implement Capabilities")
	} else if caps := capRep.Capabilities(); caps == nil || caps.Dialect != "tdengine" {
		t.Fatalf("expected Open Ping to populate tdengine capabilities, got %+v", caps)
	}
	if cls, cErr := drv.Classify(context.Background(), "SELECT * FROM meters"); cErr != nil || !cls.IsReadOnly {
		t.Fatalf("tdengine Classify failed: cls=%+v err=%v", cls, cErr)
	}
	insRes, err := rwConn.Execute(context.Background(), "INSERT INTO d1001 VALUES (NOW, 12.3)", driver.ExecOpts{})
	if err != nil || insRes.AffectedRows == nil || *insRes.AffectedRows != 1 || seenWriteCalls.Load() != 1 {
		t.Fatalf("expected TDengine RW INSERT affected=1, got res=%+v err=%v writes=%d", insRes, err, seenWriteCalls.Load())
	}
	if _, err := rwConn.Execute(context.Background(), "SHOW INVALID_CMD", driver.ExecOpts{}); err == nil || !strings.Contains(err.Error(), "9728") {
		t.Fatalf("expected TDengine error code 9728, got %v", err)
	}
}

func TestEasysearchDialectPreservedOnPing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && r.URL.Path == "/" {
			// Intentionally omit version.distribution to ensure configured engine="easysearch" keeps dialect="easysearch".
			_ = json.NewEncoder(w).Encode(map[string]any{
				"cluster_name": "infini-test",
				"version":      map[string]any{"number": "1.10.2"},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	host, portStr, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portStr)

	conn, err := (&ElasticsearchDriver{}).Open(context.Background(), driver.ConnectionConfig{
		Engine: "easysearch",
		Host:   host,
		Port:   port,
	})
	if err != nil {
		t.Fatalf("Open easysearch: %v", err)
	}
	defer func() { _ = conn.Close() }()

	ping, err := conn.Ping(context.Background())
	if err != nil || !ping.Reachable || ping.Dialect != "easysearch" || ping.Capabilities == nil || ping.Capabilities.MajorVersion != 1 {
		t.Fatalf("unexpected easysearch Ping: %+v err=%v", ping, err)
	}
}

type stubSQLRows struct {
	cols []string
	rows [][]sqldriver.Value
	idx  int
}

func (r *stubSQLRows) Columns() []string { return r.cols }
func (r *stubSQLRows) Close() error      { return nil }
func (r *stubSQLRows) Next(dest []sqldriver.Value) error {
	if r.idx >= len(r.rows) {
		return io.EOF
	}
	copy(dest, r.rows[r.idx])
	r.idx++
	return nil
}

type stubSQLState struct {
	mu       sync.Mutex
	execs    []string
	queries  []string
	readOnly bool
	txCount  int
	closed   bool
	queryFn  func(q string, args []sqldriver.NamedValue) (sqldriver.Rows, error)
	execFn   func(q string, args []sqldriver.NamedValue) (sqldriver.Result, error)
}

type stubSQLConnector struct {
	state *stubSQLState
	drv   sqldriver.Driver
}

func (c *stubSQLConnector) Connect(context.Context) (sqldriver.Conn, error) {
	return &stubSQLConn{state: c.state}, nil
}
func (c *stubSQLConnector) Driver() sqldriver.Driver { return c.drv }

type stubSQLDriver struct{}

func (d stubSQLDriver) Open(string) (sqldriver.Conn, error) { return &stubSQLConn{}, nil }

type stubSQLConn struct{ state *stubSQLState }

func (c *stubSQLConn) Prepare(string) (sqldriver.Stmt, error) {
	return nil, errors.New("not implemented")
}
func (c *stubSQLConn) Close() error {
	if c.state != nil {
		c.state.mu.Lock()
		c.state.closed = true
		c.state.mu.Unlock()
	}
	return nil
}
func (c *stubSQLConn) Begin() (sqldriver.Tx, error) { return &stubSQLTx{}, nil }
func (c *stubSQLConn) BeginTx(_ context.Context, opts sqldriver.TxOptions) (sqldriver.Tx, error) {
	if c.state != nil {
		c.state.mu.Lock()
		c.state.readOnly = opts.ReadOnly
		c.state.txCount++
		c.state.mu.Unlock()
	}
	return &stubSQLTx{}, nil
}
func (c *stubSQLConn) Ping(context.Context) error { return nil }
func (c *stubSQLConn) ExecContext(_ context.Context, query string, args []sqldriver.NamedValue) (sqldriver.Result, error) {
	if c.state != nil {
		c.state.mu.Lock()
		c.state.execs = append(c.state.execs, query)
		fn := c.state.execFn
		c.state.mu.Unlock()
		if fn != nil {
			return fn(query, args)
		}
	}
	return sqldriver.RowsAffected(1), nil
}
func (c *stubSQLConn) QueryContext(_ context.Context, query string, args []sqldriver.NamedValue) (sqldriver.Rows, error) {
	if c.state != nil {
		c.state.mu.Lock()
		c.state.queries = append(c.state.queries, query)
		fn := c.state.queryFn
		c.state.mu.Unlock()
		if fn != nil {
			return fn(query, args)
		}
	}
	return &stubSQLRows{}, nil
}

type stubSQLTx struct{}

func (stubSQLTx) Commit() error   { return nil }
func (stubSQLTx) Rollback() error { return nil }

func TestPGWireConnRuntimeWithStubDriver(t *testing.T) {
	state := &stubSQLState{
		execFn: func(q string, _ []sqldriver.NamedValue) (sqldriver.Result, error) {
			if q == "SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY" {
				return nil, errors.New("unsupported primary stmt")
			}
			return sqldriver.RowsAffected(2), nil
		},
		queryFn: func(q string, _ []sqldriver.NamedValue) (sqldriver.Rows, error) {
			switch {
			case strings.Contains(q, "SELECT version()"):
				return nil, errors.New("version() disabled")
			case strings.Contains(q, "SHOW server_version"):
				return &stubSQLRows{
					cols: []string{"server_version"},
					rows: [][]sqldriver.Value{{"KingbaseES V008R006C008B0014 on x86_64"}},
				}, nil
			case strings.Contains(q, "sys_catalog.sys_database"):
				return nil, errors.New("sys_catalog permission denied")
			case strings.Contains(q, "pg_catalog.pg_database"):
				return &stubSQLRows{
					cols: []string{"datname"},
					rows: [][]sqldriver.Value{{"app"}, {"orders"}},
				}, nil
			case strings.Contains(q, "dbe_perf"):
				return nil, errors.New("fallback simple schema query")
			case strings.Contains(q, "FROM information_schema.tables"):
				return &stubSQLRows{
					cols: []string{"table_schema", "table_name", "table_type"},
					rows: [][]sqldriver.Value{{"public", "orders", "BASE TABLE"}, {"public", "orders_v", "VIEW"}},
				}, nil
			case strings.Contains(q, "SELECT current_schema()"):
				return &stubSQLRows{cols: []string{"current_schema"}, rows: [][]sqldriver.Value{{"public"}}}, nil
			case strings.Contains(q, "constraint_type = 'PRIMARY KEY'"):
				return &stubSQLRows{cols: []string{"column_name"}, rows: [][]sqldriver.Value{{"id"}}}, nil
			case strings.Contains(q, "FROM information_schema.columns"):
				return &stubSQLRows{
					cols: []string{"column_name", "data_type", "is_nullable", "default"},
					rows: [][]sqldriver.Value{{"id", "bigint", "NO", ""}, {"status", "text", "YES", "'pending'"}},
				}, nil
			case strings.Contains(q, "constraint_type = 'FOREIGN KEY'"):
				return &stubSQLRows{cols: []string{"col", "rtbl", "rcol"}, rows: [][]sqldriver.Value{{"user_id", "users", "id"}}}, nil
			case strings.Contains(q, "sys_catalog.sys_indexes"):
				return nil, errors.New("use pg_indexes")
			case strings.Contains(q, "pg_catalog.pg_indexes"):
				return &stubSQLRows{
					cols: []string{"indexname", "indexdef"},
					rows: [][]sqldriver.Value{{"orders_pkey", "CREATE UNIQUE INDEX orders_pkey ON public.orders USING btree (id)"}},
				}, nil
			case strings.HasPrefix(q, "EXPLAIN "):
				return &stubSQLRows{
					cols: []string{"QUERY PLAN"},
					rows: [][]sqldriver.Value{{"Seq Scan on orders  (cost=0.00..45.00 rows=1200 width=16)"}},
				}, nil
			case strings.HasPrefix(q, "SELECT id, status FROM orders"):
				return &stubSQLRows{
					cols: []string{"id", "status"},
					rows: [][]sqldriver.Value{{int64(1), "paid"}, {int64(2), "pending"}},
				}, nil
			default:
				return &stubSQLRows{}, nil
			}
		},
	}

	roConnector := &readOnlyExecConnector{
		inner:     &stubSQLConnector{state: state, drv: stubSQLDriver{}},
		stmts:     []string{"SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY", "SET default_transaction_read_only = on"},
		errPrefix: "kingbase",
	}
	db := sql.OpenDB(roConnector)
	var closedHook atomic.Int32
	conn := newPGWireConn(db, driver.ConnectionConfig{
		Engine:       "kingbase",
		DatabaseName: "app",
		ReadOnly:     true,
		CloseHook:    func() error { closedHook.Add(1); return nil },
	}, pgWireDialectConfig{
		Engine:               "kingbase",
		ListDatabasesQueries: []string{"SELECT datname FROM sys_catalog.sys_database", "SELECT datname FROM pg_catalog.pg_database"},
		IndexQueries:         []string{"SELECT indexname, indexdef FROM sys_catalog.sys_indexes WHERE schemaname = $1 AND tablename = $2", "SELECT indexname, indexdef FROM pg_catalog.pg_indexes WHERE schemaname = $1 AND tablename = $2"},
	})

	if err := conn.ResetSession(context.Background()); err != nil {
		t.Fatalf("ResetSession: %v", err)
	}
	ping, err := conn.Ping(context.Background())
	if err != nil || !ping.Reachable || ping.Dialect != "kingbase" || ping.Capabilities.MajorVersion != 8 || ping.Capabilities.MinorVersion != 6 {
		t.Fatalf("Ping = (%+v, %v)", ping, err)
	}
	dbs, err := conn.ListDatabases(context.Background())
	if err != nil || !slices.Equal(dbs, []string{"app", "orders"}) {
		t.Fatalf("ListDatabases = (%v, %v)", dbs, err)
	}
	tbls, err := conn.ListTables(context.Background(), driver.SchemaListOpts{Search: "orders", Limit: 1})
	if err != nil || tbls.TotalCount != 2 || len(tbls.Items) != 1 {
		t.Fatalf("ListTables = (%+v, %v)", tbls, err)
	}
	desc, err := conn.DescribeTable(context.Background(), "orders")
	if err != nil || len(desc.Columns) != 2 || !desc.Columns[0].PrimaryKey || len(desc.ForeignKeys) != 1 || len(desc.Indexes) != 1 || !desc.Indexes[0].Primary {
		t.Fatalf("DescribeTable = (%+v, %v)", desc, err)
	}
	pf, err := conn.Preflight(context.Background(), "SELECT id, status FROM orders", driver.PreflightOpts{})
	if err != nil || !pf.FullScan || pf.EstimatedRows != 1200 || pf.Format != "pg_text" {
		t.Fatalf("Preflight = (%+v, %v)", pf, err)
	}
	ddlPF, err := conn.Preflight(context.Background(), "CREATE TABLE t(id INT)", driver.PreflightOpts{})
	if err != nil || len(ddlPF.Warnings) == 0 {
		t.Fatalf("expected DDL preflight warning, got %+v err=%v", ddlPF, err)
	}
	res, err := conn.Execute(context.Background(), "SELECT id, status FROM orders", driver.ExecOpts{MaxRows: 1})
	if err != nil || !res.Truncated || res.ReturnedRows != 1 || res.FetchedRows != 2 {
		t.Fatalf("Execute read = (%+v, %v)", res, err)
	}
	if _, err := conn.Execute(context.Background(), "DELETE FROM orders", driver.ExecOpts{}); err == nil {
		t.Fatal("expected ReadOnly pgWireConn to block DELETE")
	}

	// Verify RW DML execution returns AffectedRows, then Close triggers CloseHook once.
	conn.cfg.ReadOnly = false
	wrRes, err := conn.Execute(context.Background(), "UPDATE orders SET status = 'done' WHERE id = 1", driver.ExecOpts{})
	if err != nil || wrRes.AffectedRows == nil || *wrRes.AffectedRows != 2 {
		t.Fatalf("Execute write = (%+v, %v)", wrRes, err)
	}
	_ = conn.CancelAndDiscard()
	_ = conn.Close()
	if closedHook.Load() != 1 {
		t.Fatalf("expected CloseHook once, got %d", closedHook.Load())
	}

	// Verify readOnlyExecConnector surfaces error if every read-only statement fails.
	failDB := sql.OpenDB(&readOnlyExecConnector{
		inner:     &stubSQLConnector{state: &stubSQLState{execFn: func(string, []sqldriver.NamedValue) (sqldriver.Result, error) { return nil, errors.New("ro rejected") }}},
		stmts:     []string{"SET TRANSACTION READ ONLY"},
		errPrefix: "opengauss",
	})
	defer func() { _ = failDB.Close() }()
	if err := failDB.PingContext(context.Background()); err == nil || !strings.Contains(err.Error(), "enforce opengauss read-only session failed") {
		t.Fatalf("expected read-only enforcement failure, got %v", err)
	}
}

func TestDamengConnRuntimeWithStubDriver(t *testing.T) {
	state := &stubSQLState{
		execFn: func(q string, _ []sqldriver.NamedValue) (sqldriver.Result, error) {
			if strings.HasPrefix(q, "EXPLAIN FOR ") {
				return sqldriver.RowsAffected(0), nil
			}
			return sqldriver.RowsAffected(3), nil
		},
		queryFn: func(q string, _ []sqldriver.NamedValue) (sqldriver.Rows, error) {
			switch {
			case strings.Contains(q, "V$VERSION WHERE ROWNUM"):
				return nil, errors.New("rownum error")
			case strings.Contains(q, "TOP 1 * FROM V$VERSION"):
				return &stubSQLRows{cols: []string{"BANNER"}, rows: [][]sqldriver.Value{{"DM Database Server 64 V8.1.3.140"}}}, nil
			case strings.Contains(q, "SYS.SYSOBJECTS"):
				return nil, errors.New("privilege denied")
			case strings.Contains(q, "ALL_USERS"):
				return &stubSQLRows{cols: []string{"USERNAME"}, rows: [][]sqldriver.Value{{"SYSDBA"}, {"ORDERS"}}}, nil
			case strings.Contains(q, "USERENV"):
				return &stubSQLRows{cols: []string{"SCHEMA"}, rows: [][]sqldriver.Value{{"orders"}}}, nil
			case strings.Contains(q, "FROM all_tables"):
				return &stubSQLRows{
					cols: []string{"OWNER", "NAME", "TTYPE"},
					rows: [][]sqldriver.Value{{"ORDERS", "T_ORD", "table"}, {"ORDERS", "SYN_ORD", "synonym"}},
				}, nil
			case strings.Contains(q, "SELECT COUNT(*) FROM all_tab_columns"):
				return &stubSQLRows{cols: []string{"CNT"}, rows: [][]sqldriver.Value{{int64(0)}}}, nil
			case strings.Contains(q, "FROM all_synonyms"):
				return &stubSQLRows{cols: []string{"OWNER", "TBL"}, rows: [][]sqldriver.Value{{"FIN", "ORDERS_BASE"}}}, nil
			case strings.Contains(q, "constraint_type = 'P'"):
				return &stubSQLRows{cols: []string{"COL"}, rows: [][]sqldriver.Value{{"ID"}}}, nil
			case strings.Contains(q, "FROM all_tab_columns"):
				return &stubSQLRows{
					cols: []string{"COLUMN_NAME", "DATA_TYPE", "NULLABLE", "DATA_DEFAULT"},
					rows: [][]sqldriver.Value{{"ID", "BIGINT", "N", nil}, {"NOTE", "VARCHAR", "Y", " 'ok' "}},
				}, nil
			case strings.Contains(q, "FROM all_ind_columns"):
				return &stubSQLRows{
					cols: []string{"INDEX_NAME", "COLUMN_NAME", "UNIQUENESS"},
					rows: [][]sqldriver.Value{{"PK_ORD", "ID", "UNIQUE"}},
				}, nil
			case strings.HasPrefix(q, "EXPLAIN FOR "):
				return &stubSQLRows{
					cols: []string{"OPERATION", "SCAN_TYPE", "TAB_NAME", "ROW_NUMS", "COST"},
					rows: [][]sqldriver.Value{{"CSCN2", nil, "ORDERS_BASE", "9800", "12"}},
				}, nil
			case strings.HasPrefix(q, "SELECT ID FROM ORDERS_BASE"):
				return &stubSQLRows{cols: []string{"ID"}, rows: [][]sqldriver.Value{{int64(10)}}}, nil
			default:
				return &stubSQLRows{}, nil
			}
		},
	}

	roSlot := dmDialSlots.acquire(func(context.Context, string) (net.Conn, error) { return nil, nil })
	var closedHook atomic.Int32
	dc := &damengConn{
		db:        sql.OpenDB(&stubSQLConnector{state: state, drv: stubSQLDriver{}}),
		cfg:       driver.ConnectionConfig{Engine: "dameng", ReadOnly: true},
		dialSlot:  roSlot,
		closeHook: driver.CloseOnce(func() error { closedHook.Add(1); return nil }),
	}

	if err := dc.ResetSession(context.Background()); err != nil {
		t.Fatalf("dameng ResetSession: %v", err)
	}
	ping, err := dc.Ping(context.Background())
	if err != nil || !ping.Reachable || ping.Capabilities == nil || ping.Capabilities.MajorVersion != 8 || ping.Capabilities.MinorVersion != 1 {
		t.Fatalf("dameng Ping = (%+v, %v)", ping, err)
	}
	dbs, err := dc.ListDatabases(context.Background())
	if err != nil || !slices.Equal(dbs, []string{"SYSDBA", "ORDERS"}) {
		t.Fatalf("dameng ListDatabases = (%v, %v)", dbs, err)
	}
	tbls, err := dc.ListTables(context.Background(), driver.SchemaListOpts{})
	if err != nil || tbls.Database != "ORDERS" || len(tbls.Items) != 2 {
		t.Fatalf("dameng ListTables = (%+v, %v)", tbls, err)
	}
	desc, err := dc.DescribeTable(context.Background(), "syn_ord")
	if err != nil || desc.Schema != "FIN" || desc.Name != "ORDERS_BASE" || !desc.Columns[0].PrimaryKey || len(desc.Indexes) != 1 || !desc.Indexes[0].Unique {
		t.Fatalf("dameng DescribeTable synonym resolution = (%+v, %v)", desc, err)
	}
	pf, err := dc.Preflight(context.Background(), "SELECT * FROM orders_base", driver.PreflightOpts{})
	if err != nil || !pf.FullScan || pf.EstimatedRows != 9800 {
		t.Fatalf("dameng Preflight ##PLAN_TABLE = (%+v, %v)", pf, err)
	}
	res, err := dc.Execute(context.Background(), "SELECT ID FROM ORDERS_BASE", driver.ExecOpts{MaxRows: 10})
	if err != nil || len(res.Rows) != 1 || !state.readOnly || state.txCount == 0 {
		t.Fatalf("dameng ReadOnly Tx Execute = (%+v, %v, ro=%v tx=%d)", res, err, state.readOnly, state.txCount)
	}
	if _, err := dc.Execute(context.Background(), "UPDATE ORDERS_BASE SET NOTE = 'x'", driver.ExecOpts{}); err == nil {
		t.Fatal("expected ReadOnly damengConn to block UPDATE")
	}

	dc.cfg.ReadOnly = false
	wrRes, err := dc.Execute(context.Background(), "UPDATE ORDERS_BASE SET NOTE = 'x' WHERE ID = 1", driver.ExecOpts{})
	if err != nil || wrRes.AffectedRows == nil || *wrRes.AffectedRows != 3 {
		t.Fatalf("dameng RW Execute = (%+v, %v)", wrRes, err)
	}
	_ = dc.CancelAndDiscard()
	_ = dc.Close()
	if closedHook.Load() != 1 || dc.dialSlot != "" {
		t.Fatalf("expected dameng Close to release slot and fire hook once, hook=%d slot=%q", closedHook.Load(), dc.dialSlot)
	}

	// extractDMConnectionExplain handles nil, missing fields, and populated unexported struct fields cleanly.
	if got := extractDMConnectionExplain(nil); got != "" {
		t.Fatalf("expected empty explain for nil, got %q", got)
	}
	if got := extractDMConnectionExplain(&stubSQLConn{}); got != "" {
		t.Fatalf("expected empty explain for stubSQLConn, got %q", got)
	}
	type mockExecInfo struct{ explain string }
	type mockDMConn struct{ lastExecInfo *mockExecInfo }
	if got := extractDMConnectionExplain(&mockDMConn{lastExecInfo: &mockExecInfo{explain: "1 #CSCN2: [1, 42, 8]"}}); !strings.Contains(got, "#CSCN2") {
		t.Fatalf("expected extracted explain plan, got %q", got)
	}
}

func TestOpenGaussKingbaseDamengCustomDialWiringAndCleanup(t *testing.T) {
	drivers := []struct {
		name string
		drv  driver.Driver
		eng  string
	}{
		{name: "opengauss", drv: &OpenGaussDriver{}, eng: "opengauss"},
		{name: "kingbase", drv: &KingbaseDriver{}, eng: "kingbase"},
		{name: "dameng", drv: &DamengDriver{}, eng: "dameng"},
	}
	for _, tc := range drivers {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = ln.Close() }()
			go func() {
				for {
					c, aErr := ln.Accept()
					if aErr != nil {
						return
					}
					_ = c.Close()
				}
			}()

			host, portStr, _ := net.SplitHostPort(ln.Addr().String())
			port, _ := strconv.Atoi(portStr)

			var dialCalls atomic.Int32
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_, openErr := tc.drv.Open(ctx, driver.ConnectionConfig{
				Engine:       tc.eng,
				Host:         host,
				Port:         port,
				DatabaseName: "testdb",
				TLSMode:      "disable",
				Credential:   secrets.ResolvedSecret{Username: "u", Secret: "p"},
				DialContext: func(dctx context.Context, network, addr string) (net.Conn, error) {
					dialCalls.Add(1)
					var d net.Dialer
					return d.DialContext(dctx, network, addr)
				},
			})
			if openErr == nil {
				t.Fatalf("expected handshake failure against immediate-close stub listener")
			}
			if dialCalls.Load() == 0 {
				t.Fatalf("expected custom DialContext to be invoked for %s", tc.name)
			}
		})
	}
}
