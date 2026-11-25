package store_test

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/x0c/agent-dbctl/internal/store"
	"github.com/x0c/agent-dbctl/internal/types"
)

var (
	benchStoreOpSink    types.Operation
	benchStoreAuditSink []types.AuditEntry
	benchStoreVerify    types.AuditVerifyResult
)

func BenchmarkStoreOpenExisting(b *testing.B) {
	ctx := context.Background()
	dbPath := filepath.Join(b.TempDir(), "existing.db")
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		b.Fatal(err)
	}
	_ = st.Close()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		s, err := store.Open(ctx, dbPath)
		if err != nil {
			b.Fatal(err)
		}
		_ = s.Close()
	}
}

func BenchmarkStoreCreateAndUpdateOperation(b *testing.B) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(b.TempDir(), "ops.db"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = st.Close() })

	baseOp := types.Operation{
		TargetID:        "tgt_1",
		TargetRef:       "shop/dev/main",
		SystemID:        "sys_1",
		SystemSlug:      "shop",
		EnvironmentCode: "dev",
		Engine:          "sqlite",
		Actor:           "agent-cli",
		Reason:          "benchmark",
		QueryText:       "SELECT id FROM orders LIMIT 10",
		QueryRedacted:   "SELECT id FROM orders LIMIT 10",
		RiskLevel:       types.RiskSafeRead,
		Decision:        types.DecisionAllow,
		TriggerReasons:  []string{},
		Classification: types.Classification{
			Engine:         "sqlite",
			Family:         types.FamilySQL,
			RiskLevel:      types.RiskSafeRead,
			IsReadOnly:     true,
			StatementCount: 1,
		},
		Status:         types.OpPending,
		CredentialMode: types.AccessReadOnly,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		op, err := st.CreateOperation(ctx, baseOp)
		if err != nil {
			b.Fatal(err)
		}
		op.Status = types.OpSucceeded
		op.FetchedRows = 10
		op.ReturnedRows = 10
		op, err = st.UpdateOperation(ctx, "agent-cli", "operation.succeeded", op)
		if err != nil {
			b.Fatal(err)
		}
		benchStoreOpSink = op
	}
}

func BenchmarkStoreVerifyAuditChain500(b *testing.B) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(b.TempDir(), "audit.db"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = st.Close() })

	for i := 0; i < 500; i++ {
		if err := st.RecordAuditEvent(ctx, "agent-cli", "bench.event", fmt.Sprintf("tgt_%d", i%10), "", map[string]any{"i": i}); err != nil {
			b.Fatal(err)
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		res, err := st.VerifyAuditChain(ctx)
		if err != nil || !res.Valid {
			b.Fatalf("verify failed: %+v err=%v", res, err)
		}
		benchStoreVerify = res
	}
}

func BenchmarkStoreListAuditEntriesFiltered(b *testing.B) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(b.TempDir(), "auditlist.db"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = st.Close() })

	for i := 0; i < 500; i++ {
		if err := st.RecordAuditEvent(ctx, "agent-cli", "operation.succeeded", fmt.Sprintf("tgt_%d", i%10), "", map[string]any{"i": i}); err != nil {
			b.Fatal(err)
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		items, _, err := st.ListAuditEntriesFiltered(ctx, store.AuditFilter{
			Action: "operation",
			Limit:  50,
		})
		if err != nil {
			b.Fatal(err)
		}
		benchStoreAuditSink = items
	}
}
