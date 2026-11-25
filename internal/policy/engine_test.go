package policy_test

import (
	"testing"

	"github.com/x0c/agent-dbctl/internal/policy"
	"github.com/x0c/agent-dbctl/internal/types"
)

func intPtr(v int) *int    { return &v }
func boolPtr(v bool) *bool { return &v }

func TestMonotonicInheritanceAndEvaluation(t *testing.T) {
	global := types.GlobalSecurityConfig{
		ExecTimeoutSec:            15,
		ApprovalTimeoutSec:        120,
		MaxRows:                   200,
		MaxBytes:                  262144,
		ExplainMaxRows:            1000,
		ProdReadOnlyFreeze:        false,
		BlockMultiStatementInProd: true,
		DefaultApprovalProvider:   "local-web",
	}
	prodEnv := &types.Environment{Code: "prod", SafetyTier: types.SafetyTierStrict}
	devEnv := &types.Environment{Code: "dev", SafetyTier: types.SafetyTierYOLO}
	sys := &types.System{ID: "sys1", Slug: "orders"}
	tgt := types.Target{
		ID:              "tgt1",
		Ref:             "orders/prod/main",
		OwnerSystemID:   "sys1",
		EnvironmentCode: "prod",
		ROCredentialID:  "cred_ro",
		RWCredentialID:  "cred_rw",
		Status:          types.TargetActive,
	}

	// Lower scope tries to loosen ExecTimeoutSec (30 > 15) and tighten MaxRows (50 < 200).
	policies := []types.PolicyRuleSet{
		{
			ID:                  "pol_sys",
			Name:                "sys-tighten",
			ScopeType:           "system",
			ScopeID:             "sys1",
			ExecTimeoutSec:      intPtr(30),
			MaxRows:             intPtr(50),
			AllowMultiStatement: boolPtr(true), // must not override BlockMultiStatementInProd in strict tier
		},
	}

	eff := policy.ResolveEffectivePolicy(global, prodEnv, sys, tgt, policies)
	if eff.ExecTimeoutSec != 15 {
		t.Fatalf("expected global ceiling 15s, got %d", eff.ExecTimeoutSec)
	}
	if eff.MaxRows != 50 || eff.Sources["max_rows"] != "system:orders" {
		t.Fatalf("expected tightened max_rows=50 from system:orders, got %d (%s)", eff.MaxRows, eff.Sources["max_rows"])
	}
	if eff.AllowMultiStatement {
		t.Fatalf("strict prod must keep AllowMultiStatement=false when global BlockMultiStatementInProd=true")
	}

	// Safe read with clean preflight -> allow with ro credential & replica preference.
	ev := policy.Evaluate(tgt, eff, types.Classification{RiskLevel: types.RiskSafeRead, IsReadOnly: true, StatementCount: 1}, &types.PreflightReport{FullScan: false, EstimatedRows: 10})
	if ev.Decision != types.DecisionAllow || ev.CredentialMode != types.AccessReadOnly || !ev.PreferReplica {
		t.Fatalf("unexpected safe read eval: %+v", ev)
	}

	// Safe read with full scan preflight -> escalates to require_approval.
	evScan := policy.Evaluate(tgt, eff, types.Classification{RiskLevel: types.RiskSafeRead, IsReadOnly: true, StatementCount: 1}, &types.PreflightReport{FullScan: true, EstimatedRows: 10})
	if evScan.Decision != types.DecisionRequireApproval {
		t.Fatalf("expected full scan escalation to require_approval, got %s", evScan.Decision)
	}

	// Write in prod -> require_approval + rw credential.
	evWrite := policy.Evaluate(tgt, eff, types.Classification{RiskLevel: types.RiskWrite, IsReadOnly: false, StatementCount: 1}, nil)
	if evWrite.Decision != types.DecisionRequireApproval || evWrite.CredentialMode != types.AccessReadWrite {
		t.Fatalf("unexpected write eval: %+v", evWrite)
	}

	// Prod freeze denies writes.
	global.ProdReadOnlyFreeze = true
	effFrozen := policy.ResolveEffectivePolicy(global, prodEnv, sys, tgt, policies)
	evFrozen := policy.Evaluate(tgt, effFrozen, types.Classification{RiskLevel: types.RiskWrite, IsReadOnly: false, StatementCount: 1}, nil)
	if evFrozen.Decision != types.DecisionDeny || evFrozen.DenyCode != types.ErrCodeProdFrozen {
		t.Fatalf("expected prod_frozen deny, got %+v", evFrozen)
	}

	// Dev YOLO allows writes freely.
	devTgt := tgt
	devTgt.EnvironmentCode = "dev"
	effDev := policy.ResolveEffectivePolicy(global, devEnv, sys, devTgt, nil)
	evDev := policy.Evaluate(devTgt, effDev, types.Classification{RiskLevel: types.RiskWrite, IsReadOnly: false, StatementCount: 1}, nil)
	if evDev.Decision != types.DecisionAllow {
		t.Fatalf("expected dev YOLO allow, got %+v", evDev)
	}

	// Single RW-only target must still enforce AccessReadOnly on read-only queries.
	singleCredTgt := tgt
	singleCredTgt.ROCredentialID = ""
	evSingleRO := policy.Evaluate(singleCredTgt, eff, types.Classification{RiskLevel: types.RiskSafeRead, IsReadOnly: true, StatementCount: 1}, nil)
	if evSingleRO.CredentialMode != types.AccessReadOnly || !evSingleRO.PreferReplica {
		t.Fatalf("expected AccessReadOnly even when only RWCredentialID is set, got %+v", evSingleRO)
	}
}

func TestStrictBooleanMonotonicityAcrossScopes(t *testing.T) {
	global := types.GlobalSecurityConfig{
		ExecTimeoutSec:            15,
		ApprovalTimeoutSec:        120,
		MaxRows:                   200,
		MaxBytes:                  262144,
		ExplainMaxRows:            1000,
		BlockMultiStatementInProd: true,
		DefaultApprovalProvider:   "local-web",
	}
	guardedEnv := &types.Environment{Code: "staging", SafetyTier: types.SafetyTierGuarded}
	yoloEnv := &types.Environment{Code: "dev", SafetyTier: types.SafetyTierYOLO}
	sys := &types.System{ID: "sys1", Slug: "orders"}
	tgt := types.Target{
		ID:              "tgt1",
		Ref:             "orders/staging/main",
		OwnerSystemID:   "sys1",
		EnvironmentCode: "staging",
		Status:          types.TargetActive,
	}

	// Lower scope attempts to loosen all boolean approvals and AllowMultiStatement in guarded tier -> must be ignored.
	loosen := []types.PolicyRuleSet{
		{
			ID:            "pol_env_safe",
			Name:          "env-require-safe-read",
			ScopeType:     "env",
			ScopeID:       "staging",
			AllowSafeRead: boolPtr(false),
		},
		{
			ID:                            "pol_loosen",
			Name:                          "try-loosen",
			ScopeType:                     "target",
			ScopeID:                       "tgt1",
			AllowSafeRead:                 boolPtr(true),
			RequireApprovalOnHighCostRead: boolPtr(false),
			RequireApprovalOnWrite:        boolPtr(false),
			RequireApprovalOnDDL:          boolPtr(false),
			RequireApprovalOnAdmin:        boolPtr(false),
			RequireApprovalOnUnknown:      boolPtr(false),
			AllowMultiStatement:           boolPtr(true),
		},
	}
	eff := policy.ResolveEffectivePolicy(global, guardedEnv, sys, tgt, loosen)
	if eff.AllowSafeRead {
		t.Fatalf("expected AllowSafeRead to remain tightened false")
	}
	if eff.Sources["allow_safe_read"] != "env:staging" {
		t.Fatalf("expected allow_safe_read source env:staging, got %q", eff.Sources["allow_safe_read"])
	}
	if !eff.RequireApprovalOnHighCostRead || !eff.RequireApprovalOnWrite || !eff.RequireApprovalOnDDL || !eff.RequireApprovalOnAdmin || !eff.RequireApprovalOnUnknown {
		t.Fatalf("lower scope must never disable approval requirements: %+v", eff)
	}
	if eff.AllowMultiStatement {
		t.Fatalf("lower scope must never enable AllowMultiStatement when guarded env disabled it")
	}
	if eff.Sources["require_approval_on_write"] != "env:staging" {
		t.Fatalf("expected source preserved as env:staging, got %q", eff.Sources["require_approval_on_write"])
	}

	// Lower scope CAN tighten a dev (YOLO) target.
	devTgt := types.Target{
		ID:              "tgt_dev",
		Ref:             "orders/dev/main",
		OwnerSystemID:   "sys1",
		EnvironmentCode: "dev",
		Status:          types.TargetActive,
	}
	tightenDev := []types.PolicyRuleSet{
		{
			ID:                     "pol_dev_tight",
			Name:                   "tighten-dev",
			ScopeType:              "target",
			ScopeID:                "tgt_dev",
			AllowSafeRead:          boolPtr(false),
			RequireApprovalOnWrite: boolPtr(true),
			AllowMultiStatement:    boolPtr(false),
		},
	}
	effDev := policy.ResolveEffectivePolicy(global, yoloEnv, sys, devTgt, tightenDev)
	if effDev.AllowSafeRead || !effDev.RequireApprovalOnWrite || effDev.AllowMultiStatement {
		t.Fatalf("expected dev target tightened by target policy, got %+v", effDev)
	}
	if effDev.Sources["require_approval_on_write"] != "target:orders/dev/main" {
		t.Fatalf("expected tightened source target:orders/dev/main, got %q", effDev.Sources["require_approval_on_write"])
	}
}

func TestLinkedSystemsMonotonicityAndReadOnlyTarget(t *testing.T) {
	global := types.GlobalSecurityConfig{
		ExecTimeoutSec:          15,
		ApprovalTimeoutSec:      120,
		MaxRows:                 200,
		MaxBytes:                262144,
		ExplainMaxRows:          1000,
		DefaultApprovalProvider: "local-web",
	}
	devEnv := &types.Environment{Code: "dev", SafetyTier: types.SafetyTierYOLO}
	ownerSys := &types.System{ID: "sys_owner", Slug: "analytics"}
	linkedStrict := types.System{ID: "sys_linked", Slug: "payments"}
	tgt := types.Target{
		ID:              "tgt_shared",
		Ref:             "analytics/dev/shared",
		OwnerSystemID:   ownerSys.ID,
		LinkedSystemIDs: []string{linkedStrict.ID},
		EnvironmentCode: "dev",
		ROCredentialID:  "cred_ro",
		Status:          types.TargetActive,
	}

	policies := []types.PolicyRuleSet{
		{
			ID:                     "pol_linked",
			Name:                   "payments-tight",
			ScopeType:              "system",
			ScopeID:                "payments", // slug matching
			MaxRows:                intPtr(25),
			RequireApprovalOnWrite: boolPtr(true),
		},
	}
	eff := policy.ResolveEffectivePolicyWithSystems(global, devEnv, ownerSys, []types.System{linkedStrict}, tgt, policies)
	if eff.MaxRows != 25 || !eff.RequireApprovalOnWrite || eff.Sources["max_rows"] != "system:payments" {
		t.Fatalf("expected linked system to tighten policy monotonically, got %+v", eff)
	}

	rules := []types.RiskPatternRule{
		{
			ID:        "pat_linked",
			Name:      "payments-audit-tbl",
			ScopeType: "system",
			ScopeID:   linkedStrict.ID,
			Enabled:   true,
			Action:    types.PatternActionRequireApproval,
			Condition: types.PatternCondition{Type: types.MatcherTableRef, Values: []string{"ledger"}},
		},
	}
	eff.PatternRules = policy.ResolveEffectivePatternRulesWithSystems(devEnv, ownerSys, []types.System{linkedStrict}, tgt, "sqlite", types.FamilySQL, rules)
	if len(eff.PatternRules) != 1 || eff.PatternRules[0].ScopeLabel != "system:payments" {
		t.Fatalf("expected linked system pattern rule included, got %+v", eff.PatternRules)
	}

	// Read-only target (ROCredentialID set, RWCredentialID empty) must deny mutating operations.
	evWrite := policy.EvaluateQuery(tgt, eff, types.Classification{RiskLevel: types.RiskWrite, IsReadOnly: false, StatementCount: 1}, nil, "DELETE FROM ledger")
	if evWrite.Decision != types.DecisionDeny || evWrite.DenyCode != types.ErrCodePolicyDenied {
		t.Fatalf("expected read-only target write denial, got %+v", evWrite)
	}
	// Safe read matching linked system pattern rule escalates to require_approval even in dev YOLO.
	evRead := policy.EvaluateQuery(tgt, eff, types.Classification{RiskLevel: types.RiskSafeRead, IsReadOnly: true, StatementCount: 1}, nil, "SELECT * FROM ledger LIMIT 5")
	if evRead.Decision != types.DecisionRequireApproval || len(evRead.MatchedRules) != 1 {
		t.Fatalf("expected linked system pattern escalation, got %+v", evRead)
	}
}

func TestScanReadModeModes(t *testing.T) {
	global := types.GlobalSecurityConfig{
		ExecTimeoutSec:          15,
		ApprovalTimeoutSec:      120,
		MaxRows:                 200,
		MaxBytes:                262144,
		ExplainMaxRows:          1000,
		ProdReadOnlyFreeze:      true,
		DefaultApprovalProvider: "local-web",
	}
	strictEnv := &types.Environment{Code: "prod", SafetyTier: types.SafetyTierStrict}
	sys := &types.System{ID: "sys1", Slug: "orders"}
	tgt := types.Target{
		ID:              "tgt_prod",
		Ref:             "orders/prod/main",
		OwnerSystemID:   "sys1",
		EnvironmentCode: "prod",
		ROCredentialID:  "cred_ro",
		RWCredentialID:  "cred_rw",
		Status:          types.TargetActive,
	}
	scanPF := &types.PreflightReport{Supported: true, Executed: true, FullScan: true, EstimatedRows: 50000}
	safeRead := types.Classification{RiskLevel: types.RiskSafeRead, IsReadOnly: true, StatementCount: 1}

	// Default strict requires human approval on full-scan read.
	effDefault := policy.ResolveEffectivePolicy(global, strictEnv, sys, tgt, nil)
	if effDefault.ScanReadMode != types.ScanReadRequireApproval {
		t.Fatalf("expected default strict scan_read_mode=require_approval, got %q", effDefault.ScanReadMode)
	}
	evDefault := policy.EvaluateQuery(tgt, effDefault, safeRead, scanPF, "SELECT COUNT(*) FROM orders")
	if evDefault.Decision != types.DecisionRequireApproval || evDefault.RequireReason {
		t.Fatalf("expected require_approval under default strict, got %+v", evDefault)
	}

	// Target override scan_read_mode=reason_only lets scan reads run immediately when --reason is supplied.
	effReasonOnly := policy.ResolveEffectivePolicy(global, strictEnv, sys, tgt, []types.PolicyRuleSet{{
		ID:           "pol_scan_reason",
		Name:         "orders-scan-reason",
		ScopeType:    "target",
		ScopeID:      tgt.ID,
		ScanReadMode: types.ScanReadReasonOnly,
	}})
	if effReasonOnly.ScanReadMode != types.ScanReadReasonOnly {
		t.Fatalf("expected scan_read_mode=reason_only, got %q", effReasonOnly.ScanReadMode)
	}
	evReasonOnly := policy.EvaluateQuery(tgt, effReasonOnly, safeRead, scanPF, "SELECT COUNT(*) FROM orders")
	if evReasonOnly.Decision != types.DecisionAllow || !evReasonOnly.RequireReason {
		t.Fatalf("expected DecisionAllow with RequireReason=true under reason_only, got %+v", evReasonOnly)
	}

	// Non-scan-only high-cost risk (e.g. RiskHighCostRead or matched custom pattern) still requires approval.
	evHighCost := policy.EvaluateQuery(tgt, effReasonOnly, types.Classification{RiskLevel: types.RiskHighCostRead, IsReadOnly: true, StatementCount: 1}, scanPF, "SELECT /*+ FULL(o) */ * FROM orders o")
	if evHighCost.Decision != types.DecisionRequireApproval {
		t.Fatalf("expected RiskHighCostRead to still require approval, got %+v", evHighCost)
	}

	// Target override scan_read_mode=allow permits scan reads directly without approval or --reason.
	effAllow := policy.ResolveEffectivePolicy(global, strictEnv, sys, tgt, []types.PolicyRuleSet{{
		ID:           "pol_scan_allow",
		Name:         "orders-scan-allow",
		ScopeType:    "target",
		ScopeID:      tgt.ID,
		ScanReadMode: types.ScanReadAllow,
	}})
	evAllow := policy.EvaluateQuery(tgt, effAllow, safeRead, scanPF, "SELECT COUNT(*) FROM orders")
	if evAllow.Decision != types.DecisionAllow || evAllow.RequireReason {
		t.Fatalf("expected direct DecisionAllow under scan_read_mode=allow, got %+v", evAllow)
	}
}
