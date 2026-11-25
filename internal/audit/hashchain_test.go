package audit_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/x0c/agent-dbctl/internal/audit"
)

func TestComputeEntryHashDeterministic(t *testing.T) {
	h1 := audit.ComputeEntryHash(1, audit.GenesisPrevHash, "alice", "operation.submit", "tgt_1", "op_1", `{"a":1}`, "2026-11-25T00:00:00Z")
	h2 := audit.ComputeEntryHash(1, audit.GenesisPrevHash, "alice", "operation.submit", "tgt_1", "op_1", `{"a":1}`, "2026-11-25T00:00:00Z")
	if h1 != h2 || len(h1) != 64 {
		t.Fatalf("expected stable 64-char sha256 hex, got %q vs %q", h1, h2)
	}
	h3 := audit.ComputeEntryHash(2, audit.GenesisPrevHash, "alice", "operation.submit", "tgt_1", "op_1", `{"a":1}`, "2026-11-25T00:00:00Z")
	if h1 == h3 {
		t.Fatalf("expected seq change to alter hash")
	}
}

func TestRedactQueryAcrossEngines(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		mustHave  []string
		mustNot   []string
	}{
		{
			name:     "sql_single_and_double_escaped_quotes",
			input:    "SELECT * FROM users WHERE email = 'alice@example.com' AND bio = 'it''s secret' AND note = 'my\\'secret'",
			mustHave: []string{"SELECT * FROM users WHERE email = '***' AND bio = '***' AND note = '***'"},
			mustNot:  []string{"alice@example.com", "secret"},
		},
		{
			name:     "postgres_dollar_quotes",
			input:    "INSERT INTO secrets(body, tag) VALUES ($$top-secret-key$$, $pg_tag$another-secret$pg_tag$)",
			mustHave: []string{"$$***$$", "$pg_tag$***$pg_tag$"},
			mustNot:  []string{"top-secret-key", "another-secret"},
		},
		{
			name:     "sql_password_clauses",
			input:    `ALTER USER app IDENTIFIED BY "Sup3rS3cret!"; CREATE USER u WITH PASSWORD 'abc'; SET PASSWORD FOR u = unquotedPw`,
			mustHave: []string{"IDENTIFIED BY ***", "WITH PASSWORD ***", "SET PASSWORD FOR u = ***"},
			mustNot:  []string{"Sup3rS3cret", "abc", "unquotedPw"},
		},
		{
			name:     "uri_inline_password",
			input:    "postgres://dbadmin:myPass123@db.example.com:5432/prod",
			mustHave: []string{"postgres://dbadmin:***@db.example.com:5432/prod"},
			mustNot:  []string{"myPass123"},
		},
		{
			name:     "redis_auth_1arg_and_2arg_and_acl",
			input:    "AUTH legacySecret; AUTH admin aclSecret; ACL SETUSER alice on >newPass #hashVal; CONFIG SET requirepass cfgPass",
			mustHave: []string{"AUTH ***", "AUTH admin ***", ">***", "#***", "CONFIG SET requirepass ***"},
			mustNot:  []string{"legacySecret", "aclSecret", "newPass", "hashVal", "cfgPass"},
		},
		{
			name:     "double_quoted_identifier_with_apostrophe",
			input:    `SELECT "user's_col" FROM accounts WHERE token = 'tok_live_123'`,
			mustHave: []string{`"user's_col"`, "'***'"},
			mustNot:  []string{"tok_live_123"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := audit.RedactQuery(tc.input)
			for _, sub := range tc.mustHave {
				if !strings.Contains(got, sub) {
					t.Fatalf("expected %q to contain %q", got, sub)
				}
			}
			for _, bad := range tc.mustNot {
				if strings.Contains(got, bad) {
					t.Fatalf("expected %q NOT to contain %q", got, bad)
				}
			}
		})
	}
}

func TestRedactQueryMongoJSON(t *testing.T) {
	in := `{
		"find": "users",
		"filter": {"email": "bob@example.com", "status": {"$eq": "active"}, "ref": "$username"},
		"password": "rawPassword",
		"pipeline": [
			{"$match": {"org": "acme"}},
			{"$lookup": {"from": "orders", "localField": "_id", "foreignField": "user_id", "as": "user_orders"}}
		]
	}`
	got := audit.RedactQuery(in)
	var out map[string]any
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("expected valid redacted JSON, got %v (%s)", err, got)
	}
	if out["find"] != "users" {
		t.Fatalf("expected collection name 'users' preserved, got %v", out["find"])
	}
	if out["password"] != "***" {
		t.Fatalf("expected sensitive key 'password' redacted, got %v", out["password"])
	}
	filter := out["filter"].(map[string]any)
	if filter["email"] != "***" || filter["ref"] != "$username" {
		t.Fatalf("unexpected filter redaction: %+v", filter)
	}
	status := filter["status"].(map[string]any)
	if status["$eq"] != "***" {
		t.Fatalf("expected $eq literal redacted, got %+v", status)
	}
	if strings.Contains(got, "bob@example.com") || strings.Contains(got, "rawPassword") || strings.Contains(got, "acme") {
		t.Fatalf("found unredacted literal in %s", got)
	}
	if !strings.Contains(got, `"orders"`) || !strings.Contains(got, `"user_orders"`) {
		t.Fatalf("expected structural $lookup keys preserved in %s", got)
	}
}
