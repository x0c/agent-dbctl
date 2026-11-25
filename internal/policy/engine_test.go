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
}
