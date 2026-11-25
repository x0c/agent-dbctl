package store_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"

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

func TestAtomicTopologyImportRollbackAndDeleteIntegrity(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "agent-dbctl.db")
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	// Unsupported schema version rejected.
	if err := st.ImportTopology(ctx, "admin", types.TopologyBundle{SchemaVersion: 99}); err == nil {
		t.Fatalf("expected unsupported schema_version error")
	}

	// Mid-bundle error (invalid target referencing nonexistent instance) must roll back earlier system & network inserts.
	badBundle := types.TopologyBundle{
		SchemaVersion: 1,
		Systems: []types.System{
			{ID: "sys_tmp", Slug: "tmp-sys", Name: "Tmp Sys"},
		},
		NetworkProfiles: []types.NetworkProfile{
			{ID: "net_tmp", Name: "tmp-net", Mode: types.NetworkDirect},
		},
		Targets: []types.Target{
			{ID: "tgt_bad", Ref: "tmp-sys/dev/db", OwnerSystemID: "sys_tmp", EnvironmentCode: "dev", InstanceID: "inst_missing"},
		},
	}
	if err := st.ImportTopology(ctx, "admin", badBundle); err == nil {
		t.Fatalf("expected foreign-key error on bad bundle")
	}
	syss, _ := st.ListSystems(ctx)
	nets, _ := st.ListNetworkProfiles(ctx)
	if len(syss) != 0 || len(nets) != 0 {
		t.Fatalf("expected atomic rollback leaving 0 systems/networks, got sys=%d net=%d", len(syss), len(nets))
	}
	verify, err := st.VerifyAuditChain(ctx)
	if err != nil || !verify.Valid {
		t.Fatalf("expected valid audit chain after rollback, got %+v err=%v", verify, err)
	}

	// Referential integrity on delete for NetworkProfile, CredentialProfile, and Policy.
	cpBastion, _ := st.UpsertCredentialProfile(ctx, "admin", types.CredentialProfile{Name: "bastion-cred", Kind: types.CredKeychain, AccessLevel: types.AccessReadOnly})
	cpRO, _ := st.UpsertCredentialProfile(ctx, "admin", types.CredentialProfile{Name: "ro-cred", Kind: types.CredKeychain, AccessLevel: types.AccessReadOnly})
	np, _ := st.UpsertNetworkProfile(ctx, "admin", types.NetworkProfile{Name: "bastion-net", Mode: types.NetworkSSHTunnel, BastionHost: "bastion.example.com", BastionCredentialID: cpBastion.ID})
	pol, _ := st.UpsertPolicy(ctx, "admin", types.PolicyRuleSet{Name: "strict-sys", ScopeType: "system", ScopeID: "sys_1"})
	sys, _ := st.UpsertSystem(ctx, "admin", types.System{ID: "sys_1", Slug: "payments", Name: "Payments", DefaultPolicyID: pol.ID})
	inst, _ := st.UpsertInstance(ctx, "admin", types.Instance{Name: "pg-main", Engine: "postgres", Host: "127.0.0.1", Port: 5432, NetworkProfileID: np.ID})
	tgt, _ := st.UpsertTarget(ctx, "admin", types.Target{Ref: "payments/prod/db", OwnerSystemID: sys.ID, EnvironmentCode: "prod", InstanceID: inst.ID, ROCredentialID: cpRO.ID})

	if err := st.DeleteNetworkProfile(ctx, "admin", np.ID); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected ErrConflict deleting referenced network profile, got %v", err)
	}
	if err := st.DeleteCredentialProfile(ctx, "admin", cpRO.ID); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected ErrConflict deleting target-referenced credential, got %v", err)
	}
	if err := st.DeleteCredentialProfile(ctx, "admin", cpBastion.ID); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected ErrConflict deleting bastion-referenced credential, got %v", err)
	}
	if err := st.DeletePolicy(ctx, "admin", pol.ID); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected ErrConflict deleting system-referenced policy, got %v", err)
	}

	// Clean up references and verify deletes succeed.
	_, _ = st.UpsertSystem(ctx, "admin", types.System{ID: sys.ID, Slug: sys.Slug, Name: sys.Name, DefaultPolicyID: ""})
	if err := st.DeletePolicy(ctx, "admin", pol.ID); err != nil {
		t.Fatalf("expected policy delete after unlinking, got %v", err)
	}
	_ = st.DeleteTarget(ctx, "admin", tgt.ID)
	_ = st.DeleteInstance(ctx, "admin", inst.ID)
	if err := st.DeleteNetworkProfile(ctx, "admin", np.ID); err != nil {
		t.Fatalf("expected network profile delete after unlinking, got %v", err)
	}
	if err := st.DeleteCredentialProfile(ctx, "admin", cpBastion.ID); err != nil {
		t.Fatalf("expected bastion credential delete after unlinking, got %v", err)
	}
	if err := st.DeleteCredentialProfile(ctx, "admin", cpRO.ID); err != nil {
		t.Fatalf("expected ro credential delete after unlinking, got %v", err)
	}
}

func TestApprovalExpiryTicketStartupRecoveryAndAuditFilters(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "agent-dbctl.db")
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	// Verify SQLite triggers block UPDATE and DELETE on audit_logs.
	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rawDB.Close() }()
	if _, err := rawDB.Exec(`UPDATE audit_logs SET actor = 'tamper' WHERE seq = 1`); err == nil {
		t.Fatalf("expected UPDATE trigger on audit_logs to abort")
	}
	if _, err := rawDB.Exec(`DELETE FROM audit_logs WHERE seq = 1`); err == nil {
		t.Fatalf("expected DELETE trigger on audit_logs to abort")
	}

	// Seed ops & approvals for startup recovery + expiry test.
	opReadRun, _ := st.CreateOperation(ctx, types.Operation{
		ID: "op_read_run", TargetID: "t1", TargetRef: "s/dev/db", SystemID: "s1", SystemSlug: "s",
		EnvironmentCode: "dev", Engine: "sqlite", Actor: "agent", QueryText: "SELECT 1", QueryRedacted: "SELECT 1",
		RiskLevel: types.RiskSafeRead, Decision: types.DecisionAllow,
		Classification: types.Classification{IsReadOnly: true, RiskLevel: types.RiskSafeRead},
		Status:         types.OpRunning, CredentialMode: types.AccessReadOnly,
	})
	opWriteRun, _ := st.CreateOperation(ctx, types.Operation{
		ID: "op_write_run", TargetID: "t1", TargetRef: "s/prod/db", SystemID: "s1", SystemSlug: "s",
		EnvironmentCode: "prod", Engine: "sqlite", Actor: "agent", QueryText: "DELETE FROM x", QueryRedacted: "DELETE FROM x",
		RiskLevel: types.RiskWrite, Decision: types.DecisionRequireApproval,
		Classification: types.Classification{IsReadOnly: false, RiskLevel: types.RiskWrite},
		Status:         types.OpRunning, CredentialMode: types.AccessReadWrite,
	})

	// Expired approval tested directly via ResolveApproval.
	opExpDirect, _ := st.CreateOperation(ctx, types.Operation{
		ID: "op_exp_direct", TargetID: "t1", TargetRef: "s/prod/db", SystemID: "s1", SystemSlug: "s",
		EnvironmentCode: "prod", Engine: "sqlite", Actor: "agent", QueryText: "UPDATE x SET a=1", QueryRedacted: "UPDATE x SET a=1",
		RiskLevel: types.RiskWrite, Decision: types.DecisionRequireApproval,
		Classification: types.Classification{IsReadOnly: false, RiskLevel: types.RiskWrite},
		Status:         types.OpWaitingApproval, CredentialMode: types.AccessReadWrite, ApprovalID: "apr_exp_direct",
	})
	_, _ = st.CreateApproval(ctx, "agent", types.ApprovalRequest{
		ID: "apr_exp_direct", OperationID: opExpDirect.ID, Provider: "local-web", Status: types.ApprovalPending,
		TargetRef: "s/prod/db", SystemSlug: "s", EnvironmentCode: "prod", Engine: "sqlite",
		Actor: "agent", QueryText: "UPDATE x SET a=1", RiskLevel: types.RiskWrite,
		ExpiresAtUTC: time.Now().UTC().Add(-2 * time.Minute).Format(time.RFC3339Nano),
	}, "hash1")
	if err := st.UpdateApprovalTicket(ctx, "apr_exp_direct", "ext_1", "http://127.0.0.1:8080/approvals/apr_exp_direct"); err != nil {
		t.Fatalf("update approval ticket: %v", err)
	}
	gotApp, _, err := st.GetApproval(ctx, "apr_exp_direct")
	if err != nil || gotApp.ExternalTicketID != "ext_1" {
		t.Fatalf("expected persisted ticket metadata, got %+v err=%v", gotApp, err)
	}
	expApp, err := st.ResolveApproval(ctx, "apr_exp_direct", types.ApprovalApproved, "reviewer", "late")
	if !errors.Is(err, store.ErrApprovalExpired) || expApp.Status != types.ApprovalExpired {
		t.Fatalf("expected ErrApprovalExpired and committed expired status, got status=%s err=%v", expApp.Status, err)
	}

	// Overdue pending approval + still-valid pending approval for RecoverOnStartup.
	opOverdue, _ := st.CreateOperation(ctx, types.Operation{
		ID: "op_overdue", TargetID: "t1", TargetRef: "s/prod/db", SystemID: "s1", SystemSlug: "s",
		EnvironmentCode: "prod", Engine: "sqlite", Actor: "agent", QueryText: "UPDATE x SET a=2", QueryRedacted: "UPDATE x SET a=2",
		RiskLevel: types.RiskWrite, Decision: types.DecisionRequireApproval,
		Classification: types.Classification{IsReadOnly: false, RiskLevel: types.RiskWrite},
		Status:         types.OpWaitingApproval, CredentialMode: types.AccessReadWrite, ApprovalID: "apr_overdue",
	})
	_, _ = st.CreateApproval(ctx, "agent", types.ApprovalRequest{
		ID: "apr_overdue", OperationID: opOverdue.ID, Provider: "local-web", Status: types.ApprovalPending,
		TargetRef: "s/prod/db", SystemSlug: "s", EnvironmentCode: "prod", Engine: "sqlite",
		Actor: "agent", QueryText: "UPDATE x SET a=2", RiskLevel: types.RiskWrite,
		ExpiresAtUTC: time.Now().UTC().Add(-1 * time.Minute).Format(time.RFC3339Nano),
	}, "hash2")

	opValid, _ := st.CreateOperation(ctx, types.Operation{
		ID: "op_valid", TargetID: "t1", TargetRef: "s/prod/db", SystemID: "s1", SystemSlug: "s",
		EnvironmentCode: "prod", Engine: "sqlite", Actor: "agent", QueryText: "UPDATE x SET a=3", QueryRedacted: "UPDATE x SET a=3",
		RiskLevel: types.RiskWrite, Decision: types.DecisionRequireApproval,
		Classification: types.Classification{IsReadOnly: false, RiskLevel: types.RiskWrite},
		Status:         types.OpWaitingApproval, CredentialMode: types.AccessReadWrite, ApprovalID: "apr_valid",
	})
	_, _ = st.CreateApproval(ctx, "agent", types.ApprovalRequest{
		ID: "apr_valid", OperationID: opValid.ID, Provider: "local-web", Status: types.ApprovalPending,
		TargetRef: "s/prod/db", SystemSlug: "s", EnvironmentCode: "prod", Engine: "sqlite",
		Actor: "agent", QueryText: "UPDATE x SET a=3", RiskLevel: types.RiskWrite,
		ExpiresAtUTC: time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339Nano),
	}, "hash3")

	rep, err := st.RecoverOnStartup(ctx, "system")
	if err != nil {
		t.Fatalf("recover on startup: %v", err)
	}
	if rep.InterruptedOps != 2 || rep.ExpiredApprovals != 1 || rep.ReconciledOps != 2 || len(rep.ActivePendingApprovals) != 1 {
		t.Fatalf("unexpected recovery report: %+v", rep)
	}
	if rep.ActivePendingApprovals[0].ID != "apr_valid" {
		t.Fatalf("expected apr_valid preserved, got %+v", rep.ActivePendingApprovals)
	}

	gotRead, _ := st.GetOperation(ctx, opReadRun.ID)
	gotWrite, _ := st.GetOperation(ctx, opWriteRun.ID)
	if gotRead.Status != types.OpFailed || gotRead.ErrorCode != types.ErrCodeDaemonRestarted || !gotRead.Retryable {
		t.Fatalf("expected interrupted read op retryable=true, got %+v", gotRead)
	}
	if gotWrite.Status != types.OpFailed || gotWrite.ErrorCode != types.ErrCodeDaemonRestarted || gotWrite.Retryable {
		t.Fatalf("expected interrupted write op retryable=false, got %+v", gotWrite)
	}

	// Filtered audit pagination.
	page1, total, err := st.ListAuditEntriesFiltered(ctx, store.AuditFilter{Actor: "agent", Limit: 2, Offset: 0})
	if err != nil || total < 4 || len(page1) != 2 {
		t.Fatalf("unexpected filtered audit page1: len=%d total=%d err=%v", len(page1), total, err)
	}
	page2, total2, err := st.ListAuditEntriesFiltered(ctx, store.AuditFilter{Actor: "agent", Limit: 2, Offset: 2})
	if err != nil || total2 != total || len(page2) == 0 || page2[0].Seq >= page1[len(page1)-1].Seq {
		t.Fatalf("unexpected filtered audit page2: %+v (page1=%+v) err=%v", page2, page1, err)
	}

	verify, err := st.VerifyAuditChain(ctx)
	if err != nil || !verify.Valid {
		t.Fatalf("expected intact audit hash chain after recovery, got %+v err=%v", verify, err)
	}
}
