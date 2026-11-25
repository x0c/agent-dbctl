package classify_test

import (
	"slices"
	"testing"

	"github.com/x0c/agent-dbctl/internal/classify"
	"github.com/x0c/agent-dbctl/internal/types"
)

func TestClassifySQL(t *testing.T) {
	cases := []struct {
		name     string
		sql      string
		wantRisk types.RiskLevel
		wantRO   bool
		wantFlag string
	}{
		{"safe_select", "SELECT id, status FROM orders WHERE id = 42 LIMIT 1", types.RiskSafeRead, true, ""},
		{"safe_show", "SHOW TABLES", types.RiskSafeRead, true, ""},
		{"safe_explain", "EXPLAIN SELECT id FROM orders WHERE id = 1", types.RiskSafeRead, true, ""},
		{"explain_analyze", "EXPLAIN ANALYZE SELECT id FROM orders WHERE id = 1", types.RiskHighCostRead, true, "explain_analyze"},
		{"explain_analyze_delete", "EXPLAIN ANALYZE DELETE FROM orders WHERE id = 1", types.RiskWrite, false, "explain_analyze"},
		{"explain_analyze_paren_update", "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) UPDATE orders SET status = 'x' WHERE id = 1", types.RiskWrite, false, "explain_analyze"},
		{"explain_delete_no_analyze", "EXPLAIN DELETE FROM orders WHERE id = 1", types.RiskHighCostRead, true, "explain_dml"},
		{"explain_analyze_false_select", "EXPLAIN (ANALYZE FALSE) SELECT id FROM orders WHERE id = 1 LIMIT 1", types.RiskSafeRead, true, ""},
		{"select_star_no_where", "SELECT * FROM orders", types.RiskHighCostRead, true, "select_star_no_where"},
		{"select_star_bounded_limit", "SELECT * FROM orders LIMIT 10", types.RiskSafeRead, true, ""},
		{"select_star_huge_limit", "SELECT * FROM orders LIMIT 50000", types.RiskHighCostRead, true, "select_star_no_where"},
		{"cross_join", "SELECT a.id FROM a CROSS JOIN b WHERE a.id = 1 LIMIT 10", types.RiskHighCostRead, true, "cross_join"},
		{"implicit_comma_join", "SELECT a.id FROM a, b WHERE a.id = b.id LIMIT 10", types.RiskHighCostRead, true, "implicit_cross_join"},
		{"locking_read", "SELECT id FROM orders WHERE id = 1 FOR UPDATE", types.RiskHighCostRead, true, "locking_read"},
		{"locking_read_key_share", "SELECT id FROM orders WHERE id = 1 FOR KEY SHARE", types.RiskHighCostRead, true, "locking_read"},
		{"lock_in_share", "SELECT id FROM orders WHERE id = 1 LOCK IN SHARE MODE", types.RiskHighCostRead, true, "locking_read"},
		{"table_shorthand", "TABLE orders", types.RiskHighCostRead, true, "table_full_scan"},
		{"recursive_cte_count", "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM r WHERE n < 1000000) SELECT count(*) FROM r", types.RiskHighCostRead, true, "recursive_cte"},
		{"order_by_random", "SELECT id FROM orders WHERE status = 'ok' ORDER BY RANDOM() LIMIT 5", types.RiskHighCostRead, true, "order_by_random"},
		{"deep_offset", "SELECT id FROM orders WHERE status = 'ok' OFFSET 50000 LIMIT 10", types.RiskHighCostRead, true, "deep_offset"},
		{"sql_calc_found_rows", "SELECT SQL_CALC_FOUND_ROWS id FROM orders WHERE status = 'ok' LIMIT 10", types.RiskHighCostRead, true, "sql_calc_found_rows"},
		{"pg_sleep_no_from", "SELECT pg_sleep(5)", types.RiskHighCostRead, true, "high_cost_function"},
		{"sqlite_randomblob", "SELECT randomblob(200000000)", types.RiskHighCostRead, true, "high_cost_function"},
		{"pg_nextval", "SELECT nextval('orders_id_seq')", types.RiskWrite, false, "side_effect_function"},
		{"pg_advisory_lock", "SELECT pg_advisory_lock(42)", types.RiskWrite, false, "side_effect_function"},
		{"pg_read_file_schema", "SELECT pg_catalog.pg_read_file('/etc/passwd')", types.RiskAdmin, false, "dangerous_admin_function"},
		{"sqlite_pragma_table_info", "PRAGMA table_info('orders')", types.RiskSafeRead, true, ""},
		{"sqlite_pragma_query_only_zero", "PRAGMA query_only(0)", types.RiskAdmin, false, "pragma_mutate"},
		{"sqlite_pragma_wal_checkpoint", "PRAGMA wal_checkpoint(TRUNCATE)", types.RiskAdmin, false, "pragma_mutate"},
		{"sqlite_pragma_integrity_check", "PRAGMA integrity_check", types.RiskHighCostRead, true, "pragma_high_cost"},
		{"select_into_outfile", "SELECT * FROM orders INTO OUTFILE '/tmp/x.csv'", types.RiskWrite, false, "select_into"},
		{"insert", "INSERT INTO orders(id) VALUES (1)", types.RiskWrite, false, ""},
		{"update_no_where", "UPDATE orders SET status = 'paid'", types.RiskWrite, false, "missing_where"},
		{"delete_where", "DELETE FROM orders WHERE id = 1", types.RiskWrite, false, ""},
		{"pg_write_cte", "WITH del AS (DELETE FROM orders WHERE id = 1 RETURNING *) SELECT * FROM del", types.RiskWrite, false, "cte_write"},
		{"ddl_drop", "DROP TABLE orders", types.RiskDDL, false, ""},
		{"ddl_alter", "ALTER TABLE orders ADD COLUMN note TEXT", types.RiskDDL, false, ""},
		{"admin_copy_program", "COPY t FROM PROGRAM 'id'", types.RiskAdmin, false, "copy_program_rce"},
		{"multi_stmt_smuggle", "SELECT 1; DELETE FROM orders WHERE id = 1;", types.RiskWrite, false, "multi_statement"},
		{"dollar_quote_safe", "SELECT $tag$hello; DELETE FROM x;$tag$ AS txt", types.RiskSafeRead, true, ""},
		{"mysql_exec_comment", "/*!50000 DROP TABLE orders */", types.RiskDDL, false, ""},
		{"empty_fail_closed", "   ", types.RiskUnknown, false, "empty_query"},
		{"comments_only_fail_closed", "-- just a comment\n/* another */", types.RiskUnknown, false, "comments_only"},
		{"unclosed_quote_fail_closed", "SELECT 'unterminated", types.RiskUnknown, false, "unclosed_literal_or_comment"},
		{"unknown_verb_fail_closed", "FOOBAR SOMETHING", types.RiskUnknown, false, "unrecognized_statement"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classify.Classify("postgres", tc.sql)
			if got.RiskLevel != tc.wantRisk {
				t.Fatalf("risk=%s, want %s (summary=%s, flags=%v)", got.RiskLevel, tc.wantRisk, got.Summary, got.RiskFlags)
			}
			if got.IsReadOnly != tc.wantRO {
				t.Fatalf("is_read_only=%v, want %v (summary=%s, flags=%v)", got.IsReadOnly, tc.wantRO, got.Summary, got.RiskFlags)
			}
			if tc.wantFlag != "" {
				if !slices.Contains(got.RiskFlags, tc.wantFlag) {
					t.Fatalf("expected flag %q in %v", tc.wantFlag, got.RiskFlags)
				}
			}
		})
	}
}

func TestClassifyMongo(t *testing.T) {
	cases := []struct {
		name     string
		cmd      string
		wantRisk types.RiskLevel
		wantRO   bool
		wantFlag string
	}{
		{"safe_find_json", `{"find":"orders","filter":{"id":1},"limit":10}`, types.RiskSafeRead, true, ""},
		{"find_no_limit_json", `{"find":"orders","filter":{"status":"paid"}}`, types.RiskHighCostRead, true, "missing_limit"},
		{"empty_filter_json", `{"find":"orders","filter":{}}`, types.RiskHighCostRead, true, "empty_filter_no_limit"},
		{"agg_no_limit", `{"aggregate":"orders","pipeline":[{"$match":{"a":1}}]}`, types.RiskHighCostRead, true, "aggregate_missing_limit"},
		{"agg_allow_disk_use", `{"aggregate":"orders","pipeline":[{"$limit":10}],"allowDiskUse":true}`, types.RiskHighCostRead, true, "allow_disk_use"},
		{"agg_function_eval", `{"aggregate":"orders","pipeline":[{"$project":{"x":{"$function":{"body":"function(){return 1}","args":[],"lang":"js"}}}},{"$limit":5}]}`, types.RiskHighCostRead, true, "js_eval_operator"},
		{"agg_out", `{"aggregate":"orders","pipeline":[{"$out":"backup"}]}`, types.RiskWrite, false, "aggregate_write_stage"},
		{"explain_query_planner", `{"explain":{"find":"orders","filter":{"id":1},"limit":1},"verbosity":"queryPlanner"}`, types.RiskSafeRead, true, ""},
		{"explain_exec_stats_find", `{"explain":{"find":"orders","filter":{"id":1},"limit":1},"verbosity":"executionStats"}`, types.RiskHighCostRead, true, "explain_execution_stats"},
		{"explain_exec_stats_write", `{"explain":{"delete":"orders","deletes":[{"q":{},"limit":0}]},"verbosity":"executionStats"}`, types.RiskWrite, false, "explain_executes_write"},
		{"mongosh_find_where", `db.orders.find({"$where": "this.x > 1"})`, types.RiskHighCostRead, true, "where_js_eval"},
		{"mongosh_explain_exec_stats", `db.orders.find({"id": 1}).limit(5).explain("executionStats")`, types.RiskHighCostRead, true, "explain_execution_stats"},
		{"mongosh_update", `db.orders.updateMany({}, {"$set": {"a": 1}})`, types.RiskWrite, false, ""},
		{"mongosh_drop", `db.orders.drop()`, types.RiskDDL, false, ""},
		{"invalid_json", `{not json`, types.RiskUnknown, false, "invalid_json_command"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classify.Classify("mongodb", tc.cmd)
			if got.RiskLevel != tc.wantRisk || got.IsReadOnly != tc.wantRO {
				t.Fatalf("got=(%s, ro=%v), want=(%s, ro=%v) flags=%v", got.RiskLevel, got.IsReadOnly, tc.wantRisk, tc.wantRO, got.RiskFlags)
			}
			if tc.wantFlag != "" && !slices.Contains(got.RiskFlags, tc.wantFlag) {
				t.Fatalf("expected flag %q in %v", tc.wantFlag, got.RiskFlags)
			}
		})
	}
}

func TestClassifyRedis(t *testing.T) {
	cases := []struct {
		name     string
		cmd      string
		wantRisk types.RiskLevel
		wantRO   bool
	}{
		{"safe_get", `GET user:1`, types.RiskSafeRead, true},
		{"safe_lrange_small", `LRANGE queue 0 20`, types.RiskSafeRead, true},
		{"safe_client_id", `CLIENT ID`, types.RiskSafeRead, true},
		{"admin_client_pause", `CLIENT PAUSE 60000`, types.RiskAdmin, false},
		{"safe_memory_usage", `MEMORY USAGE user:1 SAMPLES 5`, types.RiskSafeRead, true},
		{"high_cost_memory_usage_samples_0", `MEMORY USAGE user:1 SAMPLES 0`, types.RiskHighCostRead, true},
		{"safe_scan_small", `SCAN 0 COUNT 100`, types.RiskSafeRead, true},
		{"high_cost_scan_large", `SCAN 0 COUNT 500000`, types.RiskHighCostRead, true},
		{"safe_zrangebyscore_limit", `ZRANGEBYSCORE z 0 100 LIMIT 0 20`, types.RiskSafeRead, true},
		{"high_cost_zrangebyscore_unbounded", `ZRANGEBYSCORE z -inf +inf`, types.RiskHighCostRead, true},
		{"high_cost_keys", `KEYS user:*`, types.RiskHighCostRead, true},
		{"high_cost_hgetall", `HGETALL session:1`, types.RiskHighCostRead, true},
		{"high_cost_lrange_all", `LRANGE queue 0 -1`, types.RiskHighCostRead, true},
		{"write_set", `SET foo "bar baz"`, types.RiskWrite, false},
		{"write_blpop", `BLPOP queue 0`, types.RiskWrite, false},
		{"admin_flushall", `FLUSHALL`, types.RiskAdmin, false},
		{"config_get_safe", `CONFIG GET maxmemory`, types.RiskSafeRead, true},
		{"config_set_admin", `CONFIG SET timeout 10`, types.RiskAdmin, false},
		{"unknown_cmd", `MYCUSTOMCMD x`, types.RiskUnknown, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classify.Classify("redis", tc.cmd)
			if got.RiskLevel != tc.wantRisk || got.IsReadOnly != tc.wantRO {
				t.Fatalf("got=(%s, ro=%v), want=(%s, ro=%v) flags=%v", got.RiskLevel, got.IsReadOnly, tc.wantRisk, tc.wantRO, got.RiskFlags)
			}
		})
	}
}

func TestExtractQueryContext(t *testing.T) {
	ctxPG := classify.ExtractQueryContext("postgres", "/* hint */ SELECT pg_catalog.pg_sleep(2) FROM public.orders WHERE id = 1 LIMIT 1")
	if !slices.Contains(ctxPG.Functions, "pg_sleep") || !slices.Contains(ctxPG.Functions, "pg_catalog.pg_sleep") {
		t.Fatalf("expected pg_sleep functions, got %v", ctxPG.Functions)
	}
	if !slices.Contains(ctxPG.Tables, "orders") || !slices.Contains(ctxPG.Tables, "public.orders") {
		t.Fatalf("expected orders tables, got %v", ctxPG.Tables)
	}
	if !ctxPG.HasLimit || !ctxPG.HasWhere {
		t.Fatalf("expected HasLimit and HasWhere true")
	}

	ctxSQLite := classify.ExtractQueryContext("sqlite", "PRAGMA query_only(0)")
	if !slices.Contains(ctxSQLite.Pragmas, "query_only") {
		t.Fatalf("expected query_only pragma, got %v", ctxSQLite.Pragmas)
	}

	ctxRedis := classify.ExtractQueryContext("redis", "MEMORY USAGE mykey SAMPLES 0")
	if len(ctxRedis.Commands) != 1 || len(ctxRedis.Commands[0]) != 5 {
		t.Fatalf("expected parsed redis args, got %v", ctxRedis.Commands)
	}
}

func TestHasReturningClause(t *testing.T) {
	if !classify.HasReturningClause("INSERT INTO items(name) VALUES ('a') RETURNING id, name") {
		t.Fatal("expected RETURNING to be detected")
	}
	if !classify.HasReturningClause("UPDATE items SET name = 'b'\nWHERE id = 1\nRETURNING *") {
		t.Fatal("expected multiline RETURNING to be detected")
	}
	if classify.HasReturningClause("INSERT INTO items(name) VALUES (' RETURNING id ')") {
		t.Fatal("string literal containing RETURNING must not trigger")
	}
	if classify.HasReturningClause("INSERT INTO items(name) VALUES ('a') /* RETURNING id */") {
		t.Fatal("comment containing RETURNING must not trigger")
	}
	if classify.HasReturningClause("SELECT 1; INSERT INTO items(name) VALUES ('a') RETURNING id") {
		t.Fatal("multi-statement input must return false")
	}
}

func TestClassifyNewDatabaseDialectsAndElasticsearch(t *testing.T) {
	sqlCases := []struct {
		name     string
		engine   string
		sql      string
		wantRisk types.RiskLevel
		wantRO   bool
		wantFlag string
	}{
		{"clickhouse_explain_plan", "clickhouse", "EXPLAIN PLAN indexes = 1 SELECT id FROM events WHERE day = '2026-11-25' LIMIT 10", types.RiskSafeRead, true, ""},
		{"clickhouse_explain_estimate_delete", "clickhouse", "EXPLAIN ESTIMATE DELETE FROM events WHERE day = '2026-11-25'", types.RiskHighCostRead, true, "explain_dml"},
		{"clickhouse_optimize_admin", "clickhouse", "OPTIMIZE TABLE events FINAL", types.RiskAdmin, false, ""},
		{"clickhouse_system_admin", "clickhouse", "SYSTEM FLUSH LOGS", types.RiskAdmin, false, ""},
		{"mssql_top_bounded", "sqlserver", "SELECT TOP 10 * FROM dbo.orders", types.RiskSafeRead, true, ""},
		{"mssql_top_huge_star", "mssql", "SELECT TOP 5000 * FROM dbo.orders", types.RiskHighCostRead, true, "select_star_no_where"},
		{"mssql_waitfor_admin", "mssql", "WAITFOR DELAY '00:00:05'", types.RiskAdmin, false, ""},
		{"mssql_dbcc_admin", "mssql", "DBCC FREEPROCCACHE", types.RiskAdmin, false, ""},
		{"mssql_xp_cmdshell", "mssql", "SELECT xp_cmdshell('whoami')", types.RiskAdmin, false, "dangerous_admin_function"},
		{"oracle_dual_safe", "oracle", "SELECT SYSDATE FROM DUAL", types.RiskSafeRead, true, ""},
		{"oracle_explain_plan_for_safe", "oracle", "EXPLAIN PLAN FOR SELECT id FROM orders WHERE id = 1", types.RiskSafeRead, true, ""},
		{"oracle_explain_plan_for_dml", "oracle", "EXPLAIN PLAN FOR DELETE FROM orders WHERE id = 1", types.RiskHighCostRead, true, "explain_dml"},
		{"oracle_utl_http_admin", "oracle", "SELECT UTL_HTTP.REQUEST('http://internal') FROM DUAL", types.RiskAdmin, false, "dangerous_admin_function"},
		{"oracle_dbms_lock_sleep", "oracle", "SELECT DBMS_LOCK.SLEEP(5) FROM DUAL", types.RiskHighCostRead, true, "high_cost_function"},
	}
	for _, tc := range sqlCases {
		t.Run(tc.name, func(t *testing.T) {
			got := classify.Classify(tc.engine, tc.sql)
			if got.RiskLevel != tc.wantRisk || got.IsReadOnly != tc.wantRO {
				t.Fatalf("Classify(%q, %q) = (%s, ro=%v), want (%s, ro=%v) flags=%v", tc.engine, tc.sql, got.RiskLevel, got.IsReadOnly, tc.wantRisk, tc.wantRO, got.RiskFlags)
			}
			if tc.wantFlag != "" && !slices.Contains(got.RiskFlags, tc.wantFlag) {
				t.Fatalf("expected flag %q in %v", tc.wantFlag, got.RiskFlags)
			}
		})
	}

	esCases := []struct {
		name     string
		cmd      string
		wantRisk types.RiskLevel
		wantRO   bool
		wantFlag string
	}{
		{"es_cat_indices", "GET /_cat/indices?format=json", types.RiskSafeRead, true, ""},
		{"es_search_bounded", "POST /orders/_search\n{\"query\":{\"term\":{\"status\":\"paid\"}},\"size\":20}", types.RiskSafeRead, true, ""},
		{"es_search_json_shorthand", `{"index":"orders","query":{"term":{"id":42}},"size":5}`, types.RiskSafeRead, true, ""},
		{"es_match_all_unbounded", "POST /orders/_search\n{\"query\":{\"match_all\":{}}}", types.RiskHighCostRead, true, "unbounded_match_all"},
		{"es_cross_index_scan", `GET /_search?q=status:error`, types.RiskHighCostRead, true, "cross_index_scan"},
		{"es_painless_script", `{"index":"orders","script_fields":{"x":{"script":"doc['a'].value * 2"}},"size":10}`, types.RiskHighCostRead, true, "script_eval"},
		{"es_large_size", `{"index":"orders","query":{"match_all":{}},"size":5000}`, types.RiskHighCostRead, true, "large_size"},
		{"es_sql_safe", `{"sql":"SELECT id FROM orders WHERE id = 1 LIMIT 5"}`, types.RiskSafeRead, true, ""},
		{"es_sql_delete", `{"sql":"DELETE FROM orders WHERE id = 1"}`, types.RiskWrite, false, ""},
		{"es_bulk_write", "POST /_bulk\n{\"index\":{\"_index\":\"orders\",\"_id\":\"1\"}}", types.RiskWrite, false, "es_write"},
		{"es_delete_by_query", "POST /orders/_delete_by_query\n{\"query\":{\"match_all\":{}}}", types.RiskWrite, false, "es_write"},
		{"es_delete_index_ddl", "DELETE /orders", types.RiskDDL, false, "es_ddl"},
		{"es_create_index_ddl", "PUT /orders_v2\n{\"settings\":{\"number_of_shards\":1}}", types.RiskDDL, false, "es_ddl"},
		{"es_cluster_settings_admin", "PUT /_cluster/settings\n{\"transient\":{}}", types.RiskAdmin, false, "es_admin_endpoint"},
		{"es_invalid_fail_closed", "FOOBAR /orders", types.RiskUnknown, false, "invalid_es_command"},
	}
	for _, tc := range esCases {
		t.Run(tc.name, func(t *testing.T) {
			got := classify.Classify("elasticsearch", tc.cmd)
			if got.RiskLevel != tc.wantRisk || got.IsReadOnly != tc.wantRO {
				t.Fatalf("Classify(elasticsearch, %q) = (%s, ro=%v), want (%s, ro=%v) flags=%v", tc.cmd, got.RiskLevel, got.IsReadOnly, tc.wantRisk, tc.wantRO, got.RiskFlags)
			}
			if tc.wantFlag != "" && !slices.Contains(got.RiskFlags, tc.wantFlag) {
				t.Fatalf("expected flag %q in %v", tc.wantFlag, got.RiskFlags)
			}
		})
	}

	ctxES := classify.ExtractQueryContext("opensearch", `{"index":"orders_prod","query":{"match_all":{}},"size":25}`)
	if !slices.Contains(ctxES.Tables, "orders_prod") || !ctxES.HasLimit {
		t.Fatalf("unexpected ExtractQueryContext for opensearch: %+v", ctxES)
	}
}
