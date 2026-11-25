package policy_test

import (
	"strings"
	"testing"

	"github.com/x0c/agent-dbctl/internal/classify"
	"github.com/x0c/agent-dbctl/internal/policy"
	"github.com/x0c/agent-dbctl/internal/types"
)

func TestValidateRiskPatternRuleAndRegexSafety(t *testing.T) {
	valid := types.RiskPatternRule{
		Name:      "guard-orders",
		ScopeType: "global",
		ScopeID:   "global",
		Enabled:   true,
		Action:    types.PatternActionRequireApproval,
		Condition: types.PatternCondition{
			All: []types.PatternCondition{
				{Type: types.MatcherTableRef, Values: []string{"orders", "*_ledger"}},
				{Not: &types.PatternCondition{Type: types.MatcherRegex, Pattern: `\bLIMIT\s+\d+`}},
			},
		},
	}
	if err := policy.ValidateRiskPatternRule(valid); err != nil {
		t.Fatalf("expected valid rule, got: %v", err)
	}

	// Reject lookahead / non-RE2 syntax.
	lookahead := valid
	lookahead.Condition = types.PatternCondition{
		Type:    types.MatcherRegex,
		Pattern: `(?=orders)orders`,
	}
	if err := policy.ValidateRiskPatternRule(lookahead); err == nil {
		t.Fatalf("expected RE2 syntax rejection for lookahead")
	}

	// Reject excessive regex length.
	tooLong := valid
	tooLong.Condition = types.PatternCondition{
		Type:    types.MatcherRegex,
		Pattern: strings.Repeat("a", 600),
	}
	if err := policy.ValidateRiskPatternRule(tooLong); err == nil {
		t.Fatalf("expected regex length rejection")
	}

	// Reject excessive regex AST complexity (deeply nested repetitions/alternations).
	hugeAST := valid
	hugeAST.Condition = types.PatternCondition{
		Type:    types.MatcherRegex,
		Pattern: strings.Repeat("(a|bb)", 85),
	}
	if err := policy.ValidateRiskPatternRule(hugeAST); err == nil {
		t.Fatalf("expected regex AST node count limit rejection")
	}

	// Reject missing scope_id on non-global scope.
	badScope := valid
	badScope.ScopeType = "target"
	badScope.ScopeID = ""
	if err := policy.ValidateRiskPatternRule(badScope); err == nil {
		t.Fatalf("expected missing scope_id error")
	}
}

func TestMonotonicPatternRuleInheritanceAndYoloOverride(t *testing.T) {
	devEnv := &types.Environment{Code: "dev", SafetyTier: types.SafetyTierYOLO}
	sys := &types.System{ID: "sys1", Slug: "orders"}
	tgt := types.Target{
		ID:              "tgt1",
		Ref:             "orders/dev/main",
		OwnerSystemID:   "sys1",
		EnvironmentCode: "dev",
		Status:          types.TargetActive,
	}

	rules := []types.RiskPatternRule{
		{
			ID:        "r1_global",
			Name:      "orders-confirm",
			ScopeType: "global",
			ScopeID:   "global",
			Enabled:   true,
			Engines:   []string{"postgres", "sqlite"},
			Action:    types.PatternActionRequireApproval,
			Condition: types.PatternCondition{Type: types.MatcherTableRef, Values: []string{"orders"}},
		},
		{
			// Lower scope tries to disable global rule and downgrade action -> must stay enabled & tightened!
			ID:               "r1_target",
			Name:             "orders-confirm",
			ScopeType:        "target",
			ScopeID:          "tgt1",
			Enabled:          false,
			Engines:          []string{"postgres", "sqlite"},
			Action:           types.PatternActionElevateHighCost,
			ConfirmTitle:     "Orders table access",
			ConfirmMessage:   "Requires owner confirmation on dev too.",
			ApprovalProvider: "webhook",
			Condition:        types.PatternCondition{Type: types.MatcherTableRef, Values: []string{"orders"}},
		},
		{
			// Engine-mismatched rule should be filtered out for sqlite.
			ID:        "r_mysql_only",
			Name:      "mysql-only-rule",
			ScopeType: "global",
			ScopeID:   "global",
			Enabled:   true,
			Engines:   []string{"mysql"},
			Action:    types.PatternActionDeny,
			Condition: types.PatternCondition{Type: types.MatcherFunctionCall, Values: []string{"sleep"}},
		},
	}

	resolved := policy.ResolveEffectivePatternRules(devEnv, sys, tgt, "sqlite", types.FamilySQL, rules)
	if len(resolved) != 1 {
		t.Fatalf("expected 1 resolved rule, got %d (%+v)", len(resolved), resolved)
	}
	if !resolved[0].Enabled || resolved[0].Action != types.PatternActionRequireApproval {
		t.Fatalf("lower scope must not disable or weaken global rule: %+v", resolved[0])
	}

	eff := policy.ResolveEffectivePolicy(types.GlobalSecurityConfig{
		ExecTimeoutSec:          15,
		ApprovalTimeoutSec:      120,
		MaxRows:                 200,
		MaxBytes:                262144,
		ExplainMaxRows:          1000,
		DefaultApprovalProvider: "local-web",
	}, devEnv, sys, tgt, nil)
	eff.PatternRules = resolved

	q := "SELECT id FROM orders WHERE id = 1 LIMIT 1"
	cls := classify.Classify("sqlite", q)
	ev := policy.EvaluateQuery(tgt, eff, cls, nil, q)
	if ev.Decision != types.DecisionRequireApproval {
		t.Fatalf("expected require_approval even on dev/yolo when custom rule matches, got %s", ev.Decision)
	}
	if len(ev.MatchedRules) != 1 || ev.MatchedRules[0].MatchedFragment != "orders" || ev.MatchedRules[0].Scope != "target:orders/dev/main" {
		t.Fatalf("expected matched rule fragment 'orders' and human scope 'target:orders/dev/main', got %+v", ev.MatchedRules)
	}
	if ev.EffectivePolicy.ApprovalProvider != "webhook" {
		t.Fatalf("expected lower-scope provider override webhook, got %s", ev.EffectivePolicy.ApprovalProvider)
	}
}

func TestMultiModalPatternMatchersAndPreflight(t *testing.T) {
	rules := []types.RiskPatternRule{
		{
			ID:        "r_fn_no_comment_bypass",
			Name:      "sleep-check",
			ScopeType: "global",
			ScopeID:   "global",
			Enabled:   true,
			Action:    types.PatternActionRequireApproval,
			Condition: types.PatternCondition{
				Type:   types.MatcherRegex,
				Pattern: `pg_sleep\s*\(`,
			},
		},
		{
			ID:        "r_preflight_big",
			Name:      "big-scan",
			ScopeType: "global",
			ScopeID:   "global",
			Enabled:   true,
			Action:    types.PatternActionDeny,
			Condition: types.PatternCondition{
				All: []types.PatternCondition{
					{Type: types.MatcherPreflightMetric, Metric: "full_scan"},
					{Type: types.MatcherPreflightMetric, Metric: "estimated_rows", Operator: "gt", Threshold: int64Ptr(50000)},
				},
			},
		},
	}
	if !policy.HasPreflightPatternRule(rules) {
		t.Fatalf("expected HasPreflightPatternRule=true")
	}

	// Comments inside SQL must NOT bypass regex on NormalizedNoLit, and literals must NOT false-positive.
	safeLiteralSQL := "SELECT 'pg_sleep(10)' AS txt"
	matchedLit, _ := policy.MatchPatternRules(rules, classify.Classify("postgres", safeLiteralSQL), nil, safeLiteralSQL)
	if len(matchedLit) != 0 {
		t.Fatalf("string literal should not trigger normalized_no_literals regex, got %+v", matchedLit)
	}

	commentBypassSQL := "SELECT pg_sleep/*comment*/(5)"
	matchedBypass, _ := policy.MatchPatternRules(rules, classify.Classify("postgres", commentBypassSQL), &types.PreflightReport{
		FullScan:      true,
		EstimatedRows: 100000,
	}, commentBypassSQL)
	if len(matchedBypass) != 2 || matchedBypass[0].Action != types.PatternActionDeny {
		t.Fatalf("expected both deny preflight rule and sleep regex match, got %+v", matchedBypass)
	}

	// Verify all 5 builtin packs pass validation cleanly.
	for _, pack := range policy.BuiltinRulePacks() {
		for _, r := range pack.Rules {
			r.ScopeType = "global"
			r.ScopeID = "global"
			if err := policy.ValidateRiskPatternRule(r); err != nil {
				t.Fatalf("builtin pack %s rule %s invalid: %v", pack.ID, r.Name, err)
			}
		}
	}
}
