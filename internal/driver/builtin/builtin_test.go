package builtin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"math"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"

	"github.com/x0c/agent-dbctl/internal/driver"
	"github.com/x0c/agent-dbctl/internal/secrets"
	"github.com/x0c/agent-dbctl/internal/types"
)

func TestSQLiteReadOnlySpecialPathAndBinaryValues(t *testing.T) {
	ctx := context.Background()
	drv := &SQLiteDriver{}

	// 1. Read-only probe against non-existent file must NOT create an empty file on disk.
	missingPath := filepath.Join(t.TempDir(), "does not exist #1.sqlite")
	if _, err := drv.Open(ctx, driver.ConnectionConfig{
		Engine:       "sqlite",
		DatabaseName: missingPath,
		ReadOnly:     true,
	}); err == nil {
		t.Fatal("expected error opening missing sqlite file in read_only mode")
	}
	if _, statErr := os.Stat(missingPath); !os.IsNotExist(statErr) {
		t.Fatalf("read-only open should not create missing file, statErr=%v", statErr)
	}

	// 2. Special characters in path + Params + BLOB + JSON + CloseHook idempotency.
	dbPath := filepath.Join(t.TempDir(), "my db #1%test.sqlite")
	var hookCalls atomic.Int32
	rwConn, err := drv.Open(ctx, driver.ConnectionConfig{
		Engine:       "sqlite",
		DatabaseName: dbPath,
		Params:       map[string]string{"journal_mode": "WAL"},
		CloseHook:    func() error { hookCalls.Add(1); return nil },
	})
	if err != nil {
		t.Fatalf("open rw sqlite: %v", err)
	}

	if _, err := rwConn.Execute(ctx, "CREATE TABLE items(id INT PRIMARY KEY, payload TEXT, raw BLOB); INSERT INTO items VALUES (1, '{\"ok\":true}', X'FFFF00')", driver.ExecOpts{}); err != nil {
		t.Fatalf("seed sqlite: %v", err)
	}
	res, err := rwConn.Execute(ctx, "SELECT id, payload, raw FROM items", driver.ExecOpts{MaxRows: 10})
	if err != nil {
		t.Fatalf("select sqlite: %v", err)
	}
	if len(res.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(res.Rows))
	}
	if res.Rows[0][1] != `{"ok":true}` {
		t.Fatalf("expected verbatim TEXT string for SQLite TEXT column, got %T (%v)", res.Rows[0][1], res.Rows[0][1])
	}
	if m, ok := normalizeTypedSQLValue([]byte(`{"ok":true}`), "JSON").(map[string]any); !ok || m["ok"] != true {
		t.Fatalf("expected parsed JSON map for JSON column bytes, got %T", normalizeTypedSQLValue([]byte(`{"ok":true}`), "JSON"))
	}
	if s := normalizeTypedSQLValue([]byte("user@example.com"), "VARCHAR"); s != "user@example.com" {
		t.Fatalf("expected plain string for VARCHAR bytes, got %T (%v)", s, s)
	}
	wantB64 := base64.StdEncoding.EncodeToString([]byte{0xff, 0xff, 0x00})
	if res.Rows[0][2] != wantB64 {
		t.Fatalf("expected base64 %q for binary BLOB, got %v", wantB64, res.Rows[0][2])
	}

	_ = rwConn.CancelAndDiscard()
	_ = rwConn.Close()
	if hookCalls.Load() != 1 {
		t.Fatalf("expected CloseHook called exactly once across CancelAndDiscard+Close, got %d", hookCalls.Load())
	}

	// 3. Reopen read-only and verify writes fail.
	roConn, err := drv.Open(ctx, driver.ConnectionConfig{
		Engine:       "sqlite",
		DatabaseName: dbPath,
		ReadOnly:     true,
	})
	if err != nil {
		t.Fatalf("open ro sqlite: %v", err)
	}
	defer func() { _ = roConn.Close() }()
	if _, err := roConn.Execute(ctx, "INSERT INTO items VALUES (2, 'x', X'01')", driver.ExecOpts{}); err == nil {
		t.Fatal("expected write to fail on read-only sqlite connection")
	}
}

func TestPostgresMultiVersionConfigAndPlans(t *testing.T) {
	pgCfg, err := buildPGConfig(driver.ConnectionConfig{
		Engine:       "postgres",
		Host:         "::1",
		Port:         5432,
		DatabaseName: "orders/prod?v1",
		ReadOnly:     true,
		Credential:   secrets.ResolvedSecret{Username: "ro", Secret: "pw"},
		Params: map[string]string{
			"exec_mode":                     "simple_protocol",
			"default_transaction_read_only": "off", // must NOT bypass cfg.ReadOnly
			"statement_timeout":             "5000",
		},
	})
	if err != nil {
		t.Fatalf("buildPGConfig: %v", err)
	}
	if pgCfg.Host != "::1" || pgCfg.Database != "orders/prod?v1" {
		t.Fatalf("unexpected pg host/db: host=%q db=%q", pgCfg.Host, pgCfg.Database)
	}
	if pgCfg.DefaultQueryExecMode != pgx.QueryExecModeSimpleProtocol {
		t.Fatalf("expected simple_protocol exec mode, got %v", pgCfg.DefaultQueryExecMode)
	}
	if pgCfg.RuntimeParams["default_transaction_read_only"] != "on" {
		t.Fatalf("readOnly must not be bypassed by Params, got %q", pgCfg.RuntimeParams["default_transaction_read_only"])
	}
	if pgCfg.RuntimeParams["statement_timeout"] != "5000" {
		t.Fatalf("expected statement_timeout runtime param, got %v", pgCfg.RuntimeParams)
	}

	// Parallel Seq Scan detection (PG 9.6 - 17+).
	report := &types.PreflightReport{}
	walkPGPlan(map[string]any{
		"Node Type": "Gather",
		"Plan Rows": float64(100),
		"Plans": []any{
			map[string]any{
				"Node Type": "Parallel Seq Scan",
				"Plan Rows": float64(42000),
			},
		},
	}, report)
	if !report.FullScan || report.EstimatedRows != 42000 {
		t.Fatalf("expected Parallel Seq Scan FullScan=true EstimatedRows=42000, got %+v", report)
	}

	// Catalog-only Seq Scan (pg_catalog / pg_class) must not trigger false-positive FullScan.
	catReport := &types.PreflightReport{}
	walkPGPlan(map[string]any{
		"Node Type":     "Seq Scan",
		"Schema":        "pg_catalog",
		"Relation Name": "pg_class",
		"Plan Rows":     float64(90),
	}, catReport)
	if catReport.FullScan {
		t.Fatalf("expected pg_catalog Seq Scan not to flag FullScan, got %+v", catReport)
	}

	// Fallback text EXPLAIN parsing.
	textReport := &types.PreflightReport{}
	parsePGTextPlan([]string{"Seq Scan on orders  (cost=0.00..25.00 rows=1234 width=32)"}, textReport)
	if !textReport.FullScan || textReport.EstimatedRows != 1234 {
		t.Fatalf("expected text plan FullScan=true EstimatedRows=1234, got %+v", textReport)
	}

	// Non-finite floats and pgtype.Numeric.
	if normalizePGValue(math.NaN(), "FLOAT8") != "NaN" {
		t.Fatal("expected NaN stringification")
	}
	if normalizePGValue(pgtype.Numeric{NaN: true, Valid: true}, "NUMERIC") != "NaN" {
		t.Fatal("expected pgtype.Numeric NaN stringification")
	}
}

func TestMySQLMultiVersionConfigAndPlans(t *testing.T) {
	myCfg, err := buildMySQLConfig(driver.ConnectionConfig{
		Engine:       "mysql",
		Host:         "127.0.0.1",
		Port:         3306,
		DatabaseName: "orders",
		ReadOnly:     true,
		Credential:   secrets.ResolvedSecret{Username: "ro", Secret: "pw"},
		Params: map[string]string{
			"multiStatements":         "true", // blocked in ReadOnly
			"allowAllFiles":           "true", // blocked
			"allowCleartextPasswords": "true", // blocked
			"collation":               "utf8mb4_unicode_ci",
			"readTimeout":             "5s",
		},
	})
	if err != nil {
		t.Fatalf("buildMySQLConfig: %v", err)
	}
	if myCfg.MultiStatements || myCfg.AllowAllFiles || myCfg.AllowCleartextPasswords {
		t.Fatalf("security flags must be protected: %+v", myCfg)
	}
	if myCfg.Collation != "utf8mb4_unicode_ci" || myCfg.ReadTimeout.Seconds() != 5 {
		t.Fatalf("expected collation and readTimeout mapped, got %+v", myCfg)
	}

	// MySQL 8.4 explain_json_format_version=2
	r84 := &types.PreflightReport{}
	walkMySQLPlan(map[string]any{
		"query_plan": map[string]any{
			"operation":      "Table scan on orders",
			"access_type":    "table_scan",
			"estimated_rows": float64(9800),
		},
	}, r84)
	if !r84.FullScan || r84.EstimatedRows != 9800 {
		t.Fatalf("expected MySQL 8.4 v2 full scan 9800, got %+v", r84)
	}

	// MariaDB JSON EXPLAIN ("rows" instead of "rows_examined_per_scan")
	rMaria := &types.PreflightReport{}
	walkMySQLPlan(map[string]any{
		"query_block": map[string]any{
			"table": map[string]any{
				"access_type": "ALL",
				"rows":        float64(5432),
			},
		},
	}, rMaria)
	if !rMaria.FullScan || rMaria.EstimatedRows != 5432 {
		t.Fatalf("expected MariaDB full scan 5432, got %+v", rMaria)
	}

	// TiDB / MySQL 5.5 tabular EXPLAIN fallback
	rTab := &types.PreflightReport{}
	parseMySQLTabularPlan(&types.ExecResult{
		Columns: []types.Column{{Name: "id"}, {Name: "estRows"}},
		Rows:    [][]any{{"TableFullScan_5", "777.00"}},
	}, rTab)
	if !rTab.FullScan || rTab.EstimatedRows != 777 {
		t.Fatalf("expected TiDB tabular full scan 777, got %+v", rTab)
	}
}

func TestMongoOptionsAndBSONNormalization(t *testing.T) {
	opts, err := buildMongoClientOptions(driver.ConnectionConfig{
		Engine:   "mongodb",
		Host:     "127.0.0.1",
		Port:     27017,
		ReadOnly: true,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, nil
		},
		Params: map[string]string{"serverAPIVersion": "1"},
	})
	if err != nil {
		t.Fatalf("buildMongoClientOptions: %v", err)
	}
	if opts.Direct == nil || !*opts.Direct {
		t.Fatal("expected Direct=true when DialContext is set for single host")
	}
	if opts.ReadPreference == nil || opts.ReadPreference.Mode() != readpref.SecondaryPreferredMode {
		t.Fatalf("expected SecondaryPreferred read preference on ReadOnly, got %v", opts.ReadPreference)
	}
	if opts.ServerAPIOptions == nil {
		t.Fatal("expected ServerAPIOptions set for serverAPIVersion=1")
	}

	dec, err := bson.ParseDecimal128("1234.56")
	if err != nil {
		t.Fatal(err)
	}
	norm := normalizeBSON(bson.D{
		{Key: "amount", Value: dec},
		{Key: "ts", Value: bson.Timestamp{T: 100, I: 2}},
		{Key: "re", Value: bson.Regex{Pattern: "^ord", Options: "i"}},
		{Key: "bin", Value: bson.Binary{Data: []byte{0xff, 0x00}}},
		{Key: "nan", Value: math.NaN()},
	})
	raw, err := json.Marshal(norm)
	if err != nil {
		t.Fatalf("json.Marshal normalized BSON failed: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m["amount"] != "1234.56" || m["ts"] != "100:2" || m["nan"] != "NaN" {
		t.Fatalf("unexpected normalized BSON fields: %+v", m)
	}
	if collectionFromNS("orders_test.line_items") != "line_items" {
		t.Fatal("collectionFromNS failed")
	}
}

func TestRedisOptionsNormalizationAndCapping(t *testing.T) {
	uopts, isCluster, err := buildRedisOptions(driver.ConnectionConfig{
		Engine:       "redis",
		Host:         "127.0.0.1:6379,127.0.0.1:6380",
		ReadOnly:     true,
		DatabaseName: "0",
		Params:       map[string]string{"protocol": "2", "client_name": "agent-test"},
	})
	if err != nil {
		t.Fatalf("buildRedisOptions: %v", err)
	}
	if !isCluster || len(uopts.Addrs) != 2 || uopts.Protocol != 2 || !uopts.ReadOnly {
		t.Fatalf("unexpected redis cluster options: cluster=%v opts=%+v", isCluster, uopts)
	}

	// RESP3 map[any]any must normalize to JSON-safe map[string]any.
	resp3 := map[any]any{
		"field": "val",
		123:     []any{1, math.Inf(1)},
	}
	norm := normalizeRedisValue(resp3)
	if _, err := json.Marshal(norm); err != nil {
		t.Fatalf("normalized RESP3 value must be JSON-marshalable: %v", err)
	}

	buf := driver.RowBuffer{MaxRows: 2, MaxBytes: 1024}
	capped, returned := capRedisSingleResult([]any{"a", "b", "c", "d"}, &buf)
	if returned != 2 || !buf.Truncated || buf.CutoffReason != "max_rows" {
		t.Fatalf("expected slice capped at 2 rows, got returned=%d buf=%+v capped=%v", returned, buf, capped)
	}
}
