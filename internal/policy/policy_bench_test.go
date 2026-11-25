package policy_test

import (
	"testing"

	"github.com/x0c/agent-dbctl/internal/classify"
	"github.com/x0c/agent-dbctl/internal/policy"
	"github.com/x0c/agent-dbctl/internal/types"
)

var (
	benchEffPolicySink  types.EffectivePolicy
	benchEffRulesSink   []types.RiskPatternRule
	benchEvalResultSink types.PolicyEvaluation
)

func benchPolicyFixtures() (
	types.GlobalSecurityConfig,
	*types.Environment,
	*types.System,
	[]types.System,
	types.Target,
	[]types.PolicyRuleSet,
	[]types.RiskPatternRule,
) {
	maxRows := 100
	execTimeout := 10
	global := types.GlobalSecurityConfig{
		ExecTimeoutSec:           15,
		ApprovalTimeoutSec:       120,
		MaxRows:                  200,
		MaxBytes:                 262144,
		ExplainMaxRows:           100000,
		ProdReadOnlyFreeze:       false,
		BlockMultiStatementInProd: true,
		DefaultApprovalProvider:  "local-web",
		RedactAuditLiterals:      true,
		RequireReasonForApproval: true,
	}
	env := &types.Environment{Code: "prod", SafetyTier: types.SafetyTierStrict, DefaultPolicyID: "pol-env"}
	sys := &types.System{ID: "sys-1", Slug: "orders", DefaultPolicyID: "pol-sys"}
	linked := []types.System{{ID: "sys-2", Slug: "billing", DefaultPolicyID: "pol-link"}}
	tgt := types.Target{
		ID:              "tgt-1",
		Ref:             "orders/prod/main",
		OwnerSystemID:   "sys-1",
		LinkedSystemIDs: []string{"sys-2"},
		EnvironmentCode: "prod",
		ROCredentialID:  "cred-ro",
		RWCredentialID:  "cred-rw",
	}
	policies := []types.PolicyRuleSet{
		{ID: "pol-env", ScopeType: "env", ScopeID: "prod", MaxRows: &maxRows},
		{ID: "pol-sys", ScopeType: "system", ScopeID: "orders", ExecTimeoutSec: &execTimeout},
		{ID: "pol-link", ScopeType: "system", ScopeID: "billing"},
	}
	var allRules []types.RiskPatternRule
	for _, pack := range policy.BuiltinRulePacks() {
		for _, r := range pack.Rules {
			r.ScopeType = "global"
			r.ScopeID = "global"
			allRules = append(allRules, r)
		}
	}
	return global, env, sys, linked, tgt, policies, allRules
}

func BenchmarkResolveEffectivePolicyWithSystems(b *testing.B) {
	global, env, sys, linked, tgt, policies, _ := benchPolicyFixtures()
	b.ReportAllocs()
	for b.Loop() {
		benchEffPolicySink = policy.ResolveEffectivePolicyWithSystems(global, env, sys, linked, tgt, policies)
	}
}

func BenchmarkResolveEffectivePatternRulesWithSystems(b *testing.B) {
	_, env, sys, linked, tgt, _, allRules := benchPolicyFixtures()
	b.ReportAllocs()
	for b.Loop() {
		benchEffRulesSink = policy.ResolveEffectivePatternRulesWithSystems(env, sys, linked, tgt, "postgres", types.FamilySQL, allRules)
	}
}

func BenchmarkEvaluateQueryWithPatternRules(b *testing.B) {
	global, env, sys, linked, tgt, policies, allRules := benchPolicyFixtures()
	eff := policy.ResolveEffectivePolicyWithSystems(global, env, sys, linked, tgt, policies)
	eff.PatternRules = policy.ResolveEffectivePatternRulesWithSystems(env, sys, linked, tgt, "postgres", types.FamilySQL, allRules)
	// Add a couple of regex rules to mirror real custom guardrails.
	eff.PatternRules = append(eff.PatternRules,
		types.RiskPatternRule{
			ID: "pat-re-1", Name: "no-select-star-users", ScopeType: "global", Enabled: true, Action: types.PatternActionRequireApproval,
			Condition: types.PatternCondition{Type: types.MatcherRegex, Pattern: `\bSELECT\s+\*\s+FROM\s+users\b`},
		},
		types.RiskPatternRule{
			ID: "pat-re-2", Name: "no-pg-catalog-regex", ScopeType: "global", Enabled: true, Action: types.PatternActionElevateHighCost,
			Condition: types.PatternCondition{Type: types.MatcherRegex, Pattern: `\bpg_stat_[a-z_]+\b`},
		},
	)
	q := "SELECT id, email, status FROM public.orders WHERE tenant_id = 7 AND status = 'open' ORDER BY id DESC LIMIT 50"
	cls := classify.Classify("postgres", q)
	pf := &types.PreflightReport{Supported: true, Executed: true, FullScan: false, EstimatedRows: 50, PlanSummary: "Index Scan using idx_orders_tenant on orders"}

	b.ReportAllocs()
	for b.Loop() {
		benchEvalResultSink = policy.EvaluateQuery(tgt, eff, cls, pf, q)
	}
}
