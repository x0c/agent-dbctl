package audit_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/x0c/agent-dbctl/internal/audit"
	"github.com/x0c/agent-dbctl/internal/types"
)

var (
	benchAuditStrSink  string
	benchAuditSlotSink *types.ExecResult
	benchAuditBoolSink bool
)

func BenchmarkComputeEntryHash(b *testing.B) {
	payload := `{"target_ref":"orders/prod/main","env":"prod","engine":"postgres","risk_level":"safe_read","decision":"allow","status":"succeeded","query":"SELECT id FROM orders WHERE user_id = '***' LIMIT 50"}`
	b.ReportAllocs()
	for b.Loop() {
		benchAuditStrSink = audit.ComputeEntryHash(42, audit.GenesisPrevHash, "agent-cli", "operation.succeeded", "tgt_1", "op_1", payload, "2026-11-25T00:00:00Z")
	}
}

func BenchmarkRedactQuerySQL(b *testing.B) {
	q := "SELECT id, email FROM users WHERE token = 'secret-abc-123' AND note = $$private payload$$ AND dsn = 'postgres://admin:supersecret@db.internal:5432/app' LIMIT 20"
	b.ReportAllocs()
	for b.Loop() {
		benchAuditStrSink = audit.RedactQuery(q)
	}
}

func BenchmarkRedactQueryMongoJSON(b *testing.B) {
	q := `{"find":"orders","filter":{"email":"alice@example.com","password":"p@ss","status":{"$in":["paid","shipped"]}},"limit":20}`
	b.ReportAllocs()
	for b.Loop() {
		benchAuditStrSink = audit.RedactQuery(q)
	}
}

func BenchmarkResultSlotPutGet(b *testing.B) {
	store := audit.NewResultSlotStore(5 * time.Minute)
	rows := make([][]any, 100)
	for i := range rows {
		rows[i] = []any{i, "order_status_paid", 1299}
	}
	res := &types.ExecResult{
		Family:        types.FamilySQL,
		Columns:       []types.Column{{Name: "id"}, {Name: "status"}, {Name: "amount"}},
		Rows:          rows,
		FetchedRows:   100,
		ReturnedRows:  100,
		ReturnedBytes: 4096,
	}
	keys := make([]string, 64)
	for i := range keys {
		keys[i] = fmt.Sprintf("op_%02d", i)
	}
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		k := keys[i&63]
		store.Put(k, res)
		benchAuditSlotSink, benchAuditBoolSink = store.Get(k)
		i++
	}
}
