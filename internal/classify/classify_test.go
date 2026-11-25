package classify_test

import (
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
		{"select_star_no_where", "SELECT * FROM orders", types.RiskHighCostRead, true, "select_star_no_where"},
		{"cross_join", "SELECT a.id FROM a CROSS JOIN b WHERE a.id = 1 LIMIT 10", types.RiskHighCostRead, true, "cross_join"},
		{"locking_read", "SELECT id FROM orders WHERE id = 1 FOR UPDATE", types.RiskHighCostRead, true, "locking_read"},
		{"lock_in_share", "SELECT id FROM orders WHERE id = 1 LOCK IN SHARE MODE", types.RiskHighCostRead, true, "locking_read"},
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
				t.Fatalf("is_read_only=%v, want %v", got.IsReadOnly, tc.wantRO)
			}
			if tc.wantFlag != "" {
				found := false
				for _, f := range got.RiskFlags {
					if f == tc.wantFlag {
						found = true
						break
					}
				}
				if !found {
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
	}{
		{"safe_find_json", `{"find":"orders","filter":{"id":1},"limit":10}`, types.RiskSafeRead, true},
		{"empty_filter_json", `{"find":"orders","filter":{}}`, types.RiskHighCostRead, true},
		{"agg_no_limit", `{"aggregate":"orders","pipeline":[{"$match":{"a":1}}]}`, types.RiskHighCostRead, true},
		{"agg_out", `{"aggregate":"orders","pipeline":[{"$out":"backup"}]}`, types.RiskWrite, false},
		{"mongosh_find_where", `db.orders.find({"$where": "this.x > 1"})`, types.RiskHighCostRead, true},
		{"mongosh_update", `db.orders.updateMany({}, {"$set": {"a": 1}})`, types.RiskWrite, false},
		{"mongosh_drop", `db.orders.drop()`, types.RiskDDL, false},
		{"invalid_json", `{not json`, types.RiskUnknown, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classify.Classify("mongodb", tc.cmd)
			if got.RiskLevel != tc.wantRisk || got.IsReadOnly != tc.wantRO {
				t.Fatalf("got=(%s, ro=%v), want=(%s, ro=%v) flags=%v", got.RiskLevel, got.IsReadOnly, tc.wantRisk, tc.wantRO, got.RiskFlags)
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
		{"high_cost_keys", `KEYS user:*`, types.RiskHighCostRead, true},
		{"high_cost_hgetall", `HGETALL session:1`, types.RiskHighCostRead, true},
		{"high_cost_lrange_all", `LRANGE queue 0 -1`, types.RiskHighCostRead, true},
		{"write_set", `SET foo "bar baz"`, types.RiskWrite, false},
		{"admin_flushall", `FLUSHALL`, types.RiskAdmin, false},
		{"config_get_safe", `CONFIG GET maxmemory`, types.RiskSafeRead, true},
		{"config_set_admin", `CONFIG SET timeout 10`, types.RiskAdmin, false},
		{"unknown_cmd", `MYCUSTOMCMD x`, types.RiskUnknown, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classify.Classify("redis", tc.cmd)
			if got.RiskLevel != tc.wantRisk || got.IsReadOnly != tc.wantRO {
				t.Fatalf("got=(%s, ro=%v), want=(%s, ro=%v)", got.RiskLevel, got.IsReadOnly, tc.wantRisk, tc.wantRO)
			}
		})
	}
}
