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

func TestRiskPatternMigrationCRUDAndTopologyRoundtrip(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "v1-upgrade.db")

	// Seed a v1-shape database lacking matched_rules_json and risk_pattern_rules.
	rawDB, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	v1Schema := `
CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at_utc TEXT NOT NULL);
CREATE TABLE operations (
	id TEXT PRIMARY KEY, target_id TEXT NOT NULL, target_ref TEXT NOT NULL,
	system_id TEXT NOT NULL, system_slug TEXT NOT NULL, environment_code TEXT NOT NULL, engine TEXT NOT NULL,
	actor TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '', workspace_cwd TEXT NOT NULL DEFAULT '',
	query_text TEXT NOT NULL, query_redacted TEXT NOT NULL, risk_level TEXT NOT NULL,
	decision TEXT NOT NULL, trigger_reasons_json TEXT NOT NULL DEFAULT '[]',
	classification_json TEXT NOT NULL DEFAULT '{}', preflight_json TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL, credential_mode TEXT NOT NULL, approval_id TEXT NOT NULL DEFAULT '',
	fetched_rows INTEGER NOT NULL DEFAULT 0, returned_rows INTEGER NOT NULL DEFAULT 0,
	affected_rows INTEGER, truncated INTEGER NOT NULL DEFAULT 0, cutoff_reason TEXT NOT NULL DEFAULT '',
	latency_ms INTEGER NOT NULL DEFAULT 0, error_code TEXT NOT NULL DEFAULT '',
	error_message TEXT NOT NULL DEFAULT '', retryable INTEGER NOT NULL DEFAULT 0,
	created_at_utc TEXT NOT NULL, updated_at_utc TEXT NOT NULL, completed_at_utc TEXT NOT NULL DEFAULT ''
);
CREATE TABLE approvals (
	id TEXT PRIMARY KEY, operation_id TEXT NOT NULL, provider TEXT NOT NULL,
	external_ticket_id TEXT NOT NULL DEFAULT '', external_ticket_url TEXT NOT NULL DEFAULT '',
	token_hash TEXT NOT NULL DEFAULT '', status TEXT NOT NULL, target_ref TEXT NOT NULL,
	system_slug TEXT NOT NULL, environment_code TEXT NOT NULL, engine TEXT NOT NULL,
	actor TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '', workspace_cwd TEXT NOT NULL DEFAULT '',
	query_text TEXT NOT NULL, risk_level TEXT NOT NULL, trigger_reasons_json TEXT NOT NULL DEFAULT '[]',
	preflight_json TEXT NOT NULL DEFAULT '', reviewer TEXT NOT NULL DEFAULT '',
	reviewer_note TEXT NOT NULL DEFAULT '', created_at_utc TEXT NOT NULL,
	expires_at_utc TEXT NOT NULL, resolved_at_utc TEXT NOT NULL DEFAULT ''
);
INSERT INTO schema_migrations(version, applied_at_utc) VALUES (1, '2026-01-01T00:00:00Z');
`
	if _, err := rawDB.ExecContext(ctx, v1Schema); err != nil {
		_ = rawDB.Close()
		t.Fatalf("seed v1 schema: %v", err)
	}
	_ = rawDB.Close()

	// Re-open with store.Open to exercise automatic v1 -> v2 migration.
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("reopen v1 db with migration: %v", err)
	}
	defer func() { _ = st.Close() }()

	// Install a builtin pack + upsert custom rule + export/import topology.
	installed, err := st.InstallBuiltinRulePack(ctx, "web-admin", "sqlite-pragma-blob", "global", "global")
	if err != nil || len(installed) != 2 {
		t.Fatalf("install pack: count=%d err=%v", len(installed), err)
	}

	custom, err := st.UpsertRiskPatternRule(ctx, "web-admin", types.RiskPatternRule{
		Name:           "orders-table-confirm",
		ScopeType:      "env",
		ScopeID:        "dev",
		Enabled:        true,
		Engines:        []string{"sqlite"},
		Action:         types.PatternActionRequireApproval,
		ConfirmTitle:   "Confirm orders table access",
		ConfirmMessage: "Sensitive table orders requires human confirmation.",
		Condition: types.PatternCondition{
			Type:   types.MatcherTableRef,
			Values: []string{"orders"},
		},
		Priority: 50,
	})
	if err != nil || custom.ID == "" {
		t.Fatalf("upsert custom rule: %+v err=%v", custom, err)
	}

	bundle, err := st.ExportTopology(ctx)
	if err != nil || len(bundle.RiskPatternRules) != 3 {
		t.Fatalf("expected 3 rules in exported topology, got %d err=%v", len(bundle.RiskPatternRules), err)
	}

	// Re-import into fresh DB and confirm round-trip.
	db2 := filepath.Join(t.TempDir(), "reimport.db")
	st2, err := store.Open(ctx, db2)
	if err != nil {
		t.Fatalf("open st2: %v", err)
	}
	defer func() { _ = st2.Close() }()
	if err := st2.ImportTopology(ctx, "web-admin", bundle); err != nil {
		t.Fatalf("import topology: %v", err)
	}
	rules2, err := st2.ListRiskPatternRules(ctx)
	if err != nil || len(rules2) != 3 {
		t.Fatalf("expected 3 rules after import, got %d err=%v", len(rules2), err)
	}

	if err := st.DeleteRiskPatternRule(ctx, "web-admin", custom.ID); err != nil {
		t.Fatalf("delete rule: %v", err)
	}
	verify, err := st.VerifyAuditChain(ctx)
	if err != nil || !verify.Valid {
		t.Fatalf("expected valid audit hash chain after pattern mutations, got %+v err=%v", verify, err)
	}
}

func TestCrossMachineTopologyNaturalKeyMergeAndIntegrity(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "agent-dbctl.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	// Seed local machine state with local IDs and local workspace binding.
	localCred, err := st.UpsertCredentialProfile(ctx, "admin", types.CredentialProfile{
		ID: "cred_local", Name: "orders-ro", Kind: types.CredKeychain, AccessLevel: types.AccessReadOnly, Username: "ro",
	})
	if err != nil {
		t.Fatal(err)
	}
	localNet, err := st.UpsertNetworkProfile(ctx, "admin", types.NetworkProfile{
		ID: "net_local", Name: "corp-socks", Mode: types.NetworkSOCKS5, ProxyURL: "socks5://127.0.0.1:1080",
	})
	if err != nil {
		t.Fatal(err)
	}
	localSys, err := st.UpsertSystem(ctx, "admin", types.System{
		ID: "sys_local", Slug: "orders", Name: "Orders", WorkspacePaths: []string{"~/local/orders"},
	})
	if err != nil {
		t.Fatal(err)
	}
	localPrimary, err := st.UpsertInstance(ctx, "admin", types.Instance{
		ID: "inst_primary_local", Name: "pg-orders-primary", Engine: "postgres", Host: "192.0.2.1", Port: 5432, Role: types.RolePrimary, NetworkProfileID: localNet.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	localReplica, err := st.UpsertInstance(ctx, "admin", types.Instance{
		ID: "inst_replica_local", Name: "pg-orders-replica", Engine: "postgres", Host: "192.0.2.2", Port: 5432, Role: types.RoleReplica, PrimaryInstanceID: localPrimary.ID,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Referential integrity: missing network_profile / primary / credential / self-primary must fail; deleting primary with replica must fail.
	if _, err := st.UpsertInstance(ctx, "admin", types.Instance{
		Name: "bad-net-inst", Engine: "postgres", Host: "192.0.2.3", Port: 5432, NetworkProfileID: "net_missing",
	}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing network_profile_id, got %v", err)
	}
	if _, err := st.UpsertInstance(ctx, "admin", types.Instance{
		ID: "inst_self", Name: "self-inst", Engine: "postgres", Host: "192.0.2.4", Port: 5432, Role: types.RoleReplica, PrimaryInstanceID: "inst_self",
	}); err == nil {
		t.Fatalf("expected error for self-referencing primary_instance_id")
	}
	if _, err := st.UpsertTarget(ctx, "admin", types.Target{
		Ref: "orders/dev/badcred", OwnerSystemID: localSys.ID, EnvironmentCode: "dev", InstanceID: localPrimary.ID, ROCredentialID: "cred_missing",
	}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing ro_credential_id, got %v", err)
	}
	if err := st.DeleteInstance(ctx, "admin", localPrimary.ID); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected ErrConflict deleting primary instance referenced by replica, got %v", err)
	}
	_ = localReplica

	// Capabilities persistence & omission from TopologyBundle export.
	if err := st.UpdateInstanceCapabilities(ctx, localPrimary.ID, &types.ServerCapabilities{
		Engine: "postgres", Dialect: "postgres", ServerVersion: "16.4", SupportsExplain: true, SupportsExplainJSON: true,
	}); err != nil {
		t.Fatalf("update capabilities: %v", err)
	}
	gotPrimary, err := st.GetInstance(ctx, localPrimary.ID)
	if err != nil || gotPrimary.Capabilities == nil || gotPrimary.Capabilities.Dialect != "postgres" {
		t.Fatalf("expected persisted capabilities, got %+v err=%v", gotPrimary.Capabilities, err)
	}

	// Import bundle exported from another machine with different random IDs for the same natural keys.
	remoteBundle := types.TopologyBundle{
		SchemaVersion: 1,
		Systems: []types.System{
			{ID: "sys_remote", Slug: "orders", Name: "Orders Core", WorkspacePaths: nil},
		},
		CredentialProfiles: []types.CredentialProfile{
			{ID: "cred_remote", Name: "orders-ro", Kind: types.CredKeychain, AccessLevel: types.AccessReadOnly, Username: "ro_new"},
		},
		NetworkProfiles: []types.NetworkProfile{
			{ID: "net_remote", Name: "corp-socks", Mode: types.NetworkSOCKS5, ProxyURL: "socks5://127.0.0.1:1080"},
		},
		Instances: []types.Instance{
			// Put replica before primary to verify dependency ordering in ImportTopology.
			{ID: "inst_replica_remote", Name: "pg-orders-replica", Engine: "postgres", Host: "192.0.2.2", Port: 5432, Role: types.RoleReplica, PrimaryInstanceID: "inst_primary_remote"},
			{ID: "inst_primary_remote", Name: "pg-orders-primary", Engine: "postgres", Host: "192.0.2.1", Port: 5432, Role: types.RolePrimary, NetworkProfileID: "net_remote"},
		},
		Targets: []types.Target{
			{ID: "tgt_remote", Ref: "orders/prod/main", OwnerSystemID: "sys_remote", EnvironmentCode: "prod", InstanceID: "inst_primary_remote", DatabaseName: "orders", ROCredentialID: "cred_remote"},
		},
		Policies: []types.PolicyRuleSet{
			{ID: "pol_remote", Name: "orders-tight", ScopeType: "system", ScopeID: "sys_remote"},
		},
		RiskPatternRules: []types.RiskPatternRule{
			{
				ID: "pat_remote", Name: "block-secret-tbl", ScopeType: "target", ScopeID: "tgt_remote",
				Enabled: true, Action: types.PatternActionDeny,
				Condition: types.PatternCondition{Type: types.MatcherTableRef, Values: []string{"secrets"}},
			},
		},
	}
	if err := st.ImportTopology(ctx, "admin", remoteBundle); err != nil {
		t.Fatalf("cross-machine natural-key import failed: %v", err)
	}

	// Local IDs and local workspace_paths must survive!
	syss, _ := st.ListSystems(ctx)
	if len(syss) != 1 || syss[0].ID != localSys.ID || len(syss[0].WorkspacePaths) != 1 || syss[0].WorkspacePaths[0] != "~/local/orders" {
		t.Fatalf("expected preserved local system ID and workspace_paths, got %+v", syss)
	}
	creds, _ := st.ListCredentialProfiles(ctx)
	if len(creds) != 1 || creds[0].ID != localCred.ID || creds[0].Username != "ro_new" {
		t.Fatalf("expected preserved local credential ID with updated username, got %+v", creds)
	}
	tgts, _ := st.ListTargets(ctx)
	if len(tgts) != 1 || tgts[0].OwnerSystemID != localSys.ID || tgts[0].InstanceID != localPrimary.ID || tgts[0].ROCredentialID != localCred.ID {
		t.Fatalf("expected remapped target references, got %+v", tgts)
	}

	// Export must omit runtime Capabilities.
	exp, err := st.ExportTopology(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, inst := range exp.Instances {
		if inst.Capabilities != nil {
			t.Fatalf("expected ExportTopology to omit runtime capabilities, got %+v", inst.Capabilities)
		}
	}

	// Deleting target must clean up its target-scoped pattern rule in the same tx.
	if err := st.DeleteTarget(ctx, "admin", tgts[0].ID); err != nil {
		t.Fatalf("delete target: %v", err)
	}
	pats, _ := st.ListRiskPatternRules(ctx)
	if len(pats) != 0 {
		t.Fatalf("expected target-scoped pattern rule cleaned up on target delete, got %+v", pats)
	}
}

func TestNaturalKeyTopologyPlanAndPartialApply(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "topo-plan.db")
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = st.Close() }()

	// Pre-seed a system and credential outside the partial topology bundle.
	seededSys, err := st.UpsertSystem(ctx, "setup", types.System{Slug: "orders", Name: "Orders"})
	if err != nil {
		t.Fatal(err)
	}
	seededCred, err := st.UpsertCredentialProfile(ctx, "setup", types.CredentialProfile{
		Name: "orders-ro", Kind: types.CredKeychain, AccessLevel: types.AccessReadOnly, Username: "reader",
	})
	if err != nil {
		t.Fatal(err)
	}

	beforeAudits, _ := st.ListAuditEntries(ctx, "", "", "", 1000)
	beforeVerify, _ := st.VerifyAuditChain(ctx)

	// Partial bundle with zero IDs, using slug:, name:, and ref: natural references.
	partial := types.TopologyBundle{
		SchemaVersion: 1,
		Instances: []types.Instance{
			{Name: "orders-pg", Engine: "postgres", Host: "127.0.0.1", Port: 5432, Role: types.RolePrimary},
		},
		Targets: []types.Target{
			{
				Ref:             "orders/prod/main",
				Alias:           "orders-prod",
				OwnerSystemID:   "slug:orders",
				EnvironmentCode: "prod",
				InstanceID:      "name:orders-pg",
				DatabaseName:    "orders",
				ROCredentialID:  "name:orders-ro",
				Status:          types.TargetActive,
			},
		},
		Policies: []types.PolicyRuleSet{
			{Name: "orders-pol", ScopeType: "system", ScopeID: "slug:orders"},
		},
		RiskPatternRules: []types.RiskPatternRule{
			{
				Name:      "block-secrets-tbl",
				ScopeType: "target",
				ScopeID:   "ref:orders/prod/main",
				Enabled:   true,
				Action:    types.PatternActionDeny,
				Condition: types.PatternCondition{Type: types.MatcherTableRef, Values: []string{"secrets"}},
			},
		},
	}

	// Read-only plan must predict exact counts with zero DB/audit mutations.
	plan, err := st.PlanTopologyImport(ctx, partial)
	if err != nil {
		t.Fatalf("PlanTopologyImport failed: %v", err)
	}
	if !plan.DryRun || plan.Status != "planned" ||
		plan.Summary.Instances.Created != 1 ||
		plan.Summary.Targets.Created != 1 ||
		plan.Summary.Policies.Created != 1 ||
		plan.Summary.RiskPatternRules.Created != 1 {
		t.Fatalf("unexpected plan result: %+v", plan)
	}
	if insts, _ := st.ListInstances(ctx); len(insts) != 0 {
		t.Fatalf("expected PlanTopologyImport to make no writes, got %+v", insts)
	}
	afterPlanAudits, _ := st.ListAuditEntries(ctx, "", "", "", 1000)
	afterPlanVerify, _ := st.VerifyAuditChain(ctx)
	if len(afterPlanAudits) != len(beforeAudits) || afterPlanVerify.LastHash != beforeVerify.LastHash {
		t.Fatalf("expected PlanTopologyImport to write zero audit entries")
	}

	// Real apply creates and maps all natural keys to real IDs.
	res, err := st.ImportTopologyWithResult(ctx, "agent-cli", partial)
	if err != nil {
		t.Fatalf("ImportTopologyWithResult failed: %v", err)
	}
	if res.DryRun || res.Status != "applied" || res.Summary.Targets.Created != 1 {
		t.Fatalf("unexpected apply result: %+v", res)
	}
	tgts, _ := st.ListTargets(ctx)
	if len(tgts) != 1 || tgts[0].OwnerSystemID != seededSys.ID || tgts[0].ROCredentialID != seededCred.ID {
		t.Fatalf("expected natural keys mapped to seeded IDs, got %+v", tgts)
	}

	// Re-applying identical partial bundle is idempotent (status=unchanged).
	res2, err := st.ImportTopologyWithResult(ctx, "agent-cli", partial)
	if err != nil {
		t.Fatalf("second ImportTopologyWithResult failed: %v", err)
	}
	if res2.Status != "unchanged" || res2.Summary.Targets.Unchanged != 1 || res2.Summary.Policies.Unchanged != 1 {
		t.Fatalf("expected unchanged on idempotent re-apply, got %+v", res2)
	}
}

func TestSystemGitRemotesMigrationAndTopologySemantics(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "git-remotes-mig.db")

	// Seed legacy systems table without git_remotes_json column.
	rawDB, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = rawDB.ExecContext(ctx, `
CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at_utc TEXT NOT NULL);
CREATE TABLE systems (
	id TEXT PRIMARY KEY,
	slug TEXT NOT NULL UNIQUE,
	name TEXT NOT NULL,
	owner TEXT NOT NULL DEFAULT '',
	description TEXT NOT NULL DEFAULT '',
	tags_json TEXT NOT NULL DEFAULT '[]',
	workspace_paths_json TEXT NOT NULL DEFAULT '[]',
	default_policy_id TEXT NOT NULL DEFAULT '',
	created_at_utc TEXT NOT NULL,
	updated_at_utc TEXT NOT NULL
);
INSERT INTO systems(id, slug, name, created_at_utc, updated_at_utc) VALUES ('sys_legacy', 'legacy', 'Legacy', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');
`)
	_ = rawDB.Close()
	if err != nil {
		t.Fatalf("seed legacy systems: %v", err)
	}

	st, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open migrated store: %v", err)
	}
	defer func() { _ = st.Close() }()

	saved, err := st.UpsertSystem(ctx, "admin", types.System{
		ID:         "sys_legacy",
		Slug:       "legacy",
		Name:       "Legacy",
		GitRemotes: []string{"git@github.com:acme/legacy.git", "https://github.com/acme/legacy.git"},
	})
	if err != nil {
		t.Fatalf("upsert legacy system with git_remotes: %v", err)
	}
	if len(saved.GitRemotes) != 1 || saved.GitRemotes[0] != "github.com/acme/legacy" {
		t.Fatalf("expected normalized/deduped git_remotes, got %+v", saved.GitRemotes)
	}

	// Omitting GitRemotes (nil) in topology apply preserves existing GitRemotes.
	if err := st.ImportTopology(ctx, "admin", types.TopologyBundle{
		SchemaVersion: 1,
		Systems: []types.System{
			{Slug: "legacy", Name: "Legacy", GitRemotes: nil},
		},
	}); err != nil {
		t.Fatalf("import omitted git_remotes: %v", err)
	}
	syss, _ := st.ListSystems(ctx)
	if len(syss) != 1 || len(syss[0].GitRemotes) != 1 || syss[0].GitRemotes[0] != "github.com/acme/legacy" {
		t.Fatalf("expected omitted git_remotes to preserve existing binding, got %+v", syss)
	}

	// Explicit empty slice clears GitRemotes.
	if err := st.ImportTopology(ctx, "admin", types.TopologyBundle{
		SchemaVersion: 1,
		Systems: []types.System{
			{Slug: "legacy", Name: "Legacy", GitRemotes: []string{}},
		},
	}); err != nil {
		t.Fatalf("import explicit empty git_remotes: %v", err)
	}
	syss, _ = st.ListSystems(ctx)
	if len(syss) != 1 || len(syss[0].GitRemotes) != 0 {
		t.Fatalf("expected explicit empty git_remotes to clear binding, got %+v", syss)
	}

	// Policy ScanReadMode persists across UpsertPolicy, ListPolicies, and Topology export/apply.
	polSaved, err := st.UpsertPolicy(ctx, "admin", types.PolicyRuleSet{
		Name:         "prod-scan-reason",
		ScopeType:    "env",
		ScopeID:      "prod",
		ScanReadMode: types.ScanReadReasonOnly,
	})
	if err != nil {
		t.Fatalf("UpsertPolicy scan_read_mode: %v", err)
	}
	if polSaved.ScanReadMode != types.ScanReadReasonOnly {
		t.Fatalf("expected saved ScanReadMode=reason_only, got %q", polSaved.ScanReadMode)
	}
	exported, err := st.ExportTopology(ctx)
	if err != nil {
		t.Fatalf("ExportTopology: %v", err)
	}
	var found bool
	for _, p := range exported.Policies {
		if p.ID == polSaved.ID {
			found = true
			if p.ScanReadMode != types.ScanReadReasonOnly {
				t.Fatalf("expected exported ScanReadMode=reason_only, got %q", p.ScanReadMode)
			}
		}
	}
	if !found {
		t.Fatalf("expected saved policy %q in ExportTopology", polSaved.ID)
	}
	planRes, err := st.PlanTopologyImport(ctx, exported)
	if err != nil {
		t.Fatalf("PlanTopologyImport: %v", err)
	}
	if planRes.Summary.Policies.Unchanged == 0 {
		t.Fatalf("expected exported scan_read_mode policy to match unchanged in PlanTopologyImport, got %+v", planRes.Summary.Policies)
	}
}
