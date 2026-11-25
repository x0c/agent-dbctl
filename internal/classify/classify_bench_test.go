package classify_test

import (
	"testing"

	"github.com/x0c/agent-dbctl/internal/classify"
	"github.com/x0c/agent-dbctl/internal/types"
)

var benchClassifySink types.Classification
var benchQueryCtxSink classify.QueryContext

func BenchmarkClassifySQLSimple(b *testing.B) {
	q := "SELECT id, user_id, status, total_cents FROM orders WHERE user_id = 42 AND status = 'paid' ORDER BY created_at DESC LIMIT 50"
	b.ReportAllocs()
	for b.Loop() {
		benchClassifySink = classify.Classify("postgres", q)
	}
}

func BenchmarkClassifySQLComplexMulti(b *testing.B) {
	q := `
-- audit report query
WITH recent_orders AS (
	SELECT o.id, o.user_id, o.total_cents
	FROM orders o
	JOIN users u ON u.id = o.user_id
	WHERE o.created_at >= '2026-01-01'
)
SELECT ro.user_id, COUNT(*), SUM(ro.total_cents)
FROM recent_orders ro
GROUP BY ro.user_id
ORDER BY 3 DESC
LIMIT 100;
SELECT pg_sleep(0.1);
`
	b.ReportAllocs()
	for b.Loop() {
		benchClassifySink = classify.Classify("postgres", q)
	}
}

func BenchmarkClassifyMongoJSON(b *testing.B) {
	q := `{"find":"orders","filter":{"status":"paid","tenant_id":1001},"sort":{"created_at":-1},"limit":50}`
	b.ReportAllocs()
	for b.Loop() {
		benchClassifySink = classify.Classify("mongodb", q)
	}
}

func BenchmarkClassifyRedis(b *testing.B) {
	q := "GET session:12345\nHGETALL user:profile:99\nSCAN 0 MATCH order:* COUNT 50"
	b.ReportAllocs()
	for b.Loop() {
		benchClassifySink = classify.Classify("redis", q)
	}
}

func BenchmarkExtractQueryContextSQL(b *testing.B) {
	q := "SELECT o.id, o.status, pg_sleep(1) FROM public.orders o WHERE o.created_at > '2026-01-01' AND o.note = $$secret$$ LIMIT 20"
	b.ReportAllocs()
	for b.Loop() {
		benchQueryCtxSink = classify.ExtractQueryContext("postgres", q)
	}
}
