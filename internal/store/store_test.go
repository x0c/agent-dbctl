package store_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/x0c/agent-dbctl/internal/store"
	"github.com/x0c/agent-dbctl/internal/types"
)

func TestStoreWALTransactionalAuditAndTopology(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "agent-dbctl.db")
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	mode, err := st.VerifyWAL(ctx)
	if err != nil || mode != "wal" {
		t.Fatalf("expected WAL mode, got %q (err=%v)", mode, err)
	}

	sys, err := st.UpsertSystem(ctx, "tester", types.System{
		Slug:           "order-core",
		Name:           "Order Core",
		Owner:          "platform",
		Tags:           []string{"core"},
		WorkspacePaths: []string{"~/Codes/order-core"},
	})
	if err != nil {
		t.Fatalf("upsert system: %v", err)
	}

	inst, err := st.UpsertInstance(ctx, "tester", types.Instance{
		Name:   "local-sqlite",
		Engine: "sqlite",
		Host:   ":memory:",
		Role:   types.RoleStandalone,
	})
	if err != nil {
		t.Fatalf("upsert instance: %v", err)
	}

	tgt, err := st.UpsertTarget(ctx, "tester", types.Target{
		Ref:             "order-core/dev/main",
		Alias:           "dev-orders",
		OwnerSystemID:   sys.ID,
		EnvironmentCode: "dev",
		InstanceID:      inst.ID,
		DatabaseName:    ":memory:",
		Status:          types.TargetActive,
	})
	if err != nil {
		t.Fatalf("upsert target: %v", err)
	}
	if tgt.Ref != "order-core/dev/main" {
		t.Fatalf("unexpected target ref: %s", tgt.Ref)
	}

	verifyRes, err := st.VerifyAuditChain(ctx)
	if err != nil {
		t.Fatalf("verify audit chain: %v", err)
	}
	if !verifyRes.Valid || verifyRes.CheckedCount < 7 {
		t.Fatalf("expected valid hash chain with >=7 entries, got %+v", verifyRes)
	}

	bundle, err := st.ExportTopology(ctx)
	if err != nil {
		t.Fatalf("export topology: %v", err)
	}
	if len(bundle.Systems) != 1 || len(bundle.Targets) != 1 {
		t.Fatalf("unexpected bundle counts: sys=%d tgt=%d", len(bundle.Systems), len(bundle.Targets))
	}
}
