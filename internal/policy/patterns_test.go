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

	// Verify all builtin packs pass validation cleanly and Xinchuang rules trigger as expected.
	for _, pack := range policy.BuiltinRulePacks() {
		for _, r := range pack.Rules {
			r.ScopeType = "global"
			r.ScopeID = "global"
			if err := policy.ValidateRiskPatternRule(r); err != nil {
				t.Fatalf("builtin pack %s rule %s invalid: %v", pack.ID, r.Name, err)
			}
		}
	}

	var dmGuardRules, pgSideRules, tdGuardRules, esGuardRules []types.RiskPatternRule
	for _, pack := range policy.BuiltinRulePacks() {
		for _, r := range pack.Rules {
			r.ScopeType = "global"
			r.ScopeID = "global"
			switch pack.ID {
			case "dameng-sys-guard":
				dmGuardRules = append(dmGuardRules, r)
			case "pg-side-effect":
				pgSideRules = append(pgSideRules, r)
			case "tdengine-tsdb-guard":
				tdGuardRules = append(tdGuardRules, r)
			case "es-unbounded-scan":
				esGuardRules = append(esGuardRules, r)
			}
		}
	}
	if len(dmGuardRules) == 0 || len(tdGuardRules) == 0 {
		t.Fatal("expected dameng-sys-guard and tdengine-tsdb-guard builtin packs")
	}

	dmSys := &types.System{ID: "sys_dm", Slug: "erp"}
	prodEnv := &types.Environment{Code: "prod", SafetyTier: types.SafetyTierStrict}
	dmTgt := types.Target{ID: "tgt_dm", Ref: "erp/prod/dm", OwnerSystemID: "sys_dm", EnvironmentCode: "prod", Status: types.TargetActive}
	resolvedDM := policy.ResolveEffectivePatternRules(prodEnv, dmSys, dmTgt, "dameng", types.FamilySQL, dmGuardRules)
	if len(resolvedDM) == 0 {
		t.Fatal("expected dameng-sys-guard rule resolved for dameng engine")
	}
	for _, dmSQL := range []string{
		"CALL SP_SET_PARA_VALUE(1, 'ENABLE_MONITOR', 0)",
		"CALL SP_CREATE_JOB('nightly', 1, 0, '', 0, 0, '', 0, '')",
		"SELECT LEVEL FROM DUAL CONNECT BY LEVEL <= 1000000",
	} {
		if matches, _ := policy.MatchPatternRules(resolvedDM, classify.Classify("dameng", dmSQL), nil, dmSQL); len(matches) == 0 {
			t.Fatalf("expected dameng-sys-guard to match %q", dmSQL)
		}
	}

	for _, tc := range []struct {
		eng string
		sql string
	}{
		{"opengauss", "SELECT pg_sleep(5)"},
		{"opengauss", "SELECT gs_roach_stop_backup()"},
		{"kingbase", "SELECT sys_read_file('/etc/passwd')"},
		{"kingbase", "SELECT sys_sleep(5)"},
	} {
		resolvedPG := policy.ResolveEffectivePatternRules(prodEnv, dmSys, dmTgt, tc.eng, types.FamilySQL, pgSideRules)
		if matches, _ := policy.MatchPatternRules(resolvedPG, classify.Classify(tc.eng, tc.sql), nil, tc.sql); len(matches) == 0 {
			t.Fatalf("expected pg-side-effect to match %s query %q", tc.eng, tc.sql)
		}
	}

	tdTgt := types.Target{ID: "tgt_td", Ref: "erp/prod/td", OwnerSystemID: "sys_dm", EnvironmentCode: "prod", Status: types.TargetActive}
	resolvedTD := policy.ResolveEffectivePatternRules(prodEnv, dmSys, tdTgt, "tdengine", types.FamilySQL, tdGuardRules)
	for _, tdSQL := range []string{"COMPACT", "SELECT * FROM meters"} {
		if matches, _ := policy.MatchPatternRules(resolvedTD, classify.Classify("tdengine", tdSQL), nil, tdSQL); len(matches) == 0 {
			t.Fatalf("expected tdengine-tsdb-guard to match %q", tdSQL)
		}
	}

	esTgt := types.Target{ID: "tgt_es", Ref: "erp/prod/es", OwnerSystemID: "sys_dm", EnvironmentCode: "prod", Status: types.TargetActive}
	resolvedES := policy.ResolveEffectivePatternRules(prodEnv, dmSys, esTgt, "easysearch", types.FamilyDocument, esGuardRules)
	esQuery := "POST /orders/_search\n{\"knn\":{\"field\":\"vec\",\"k\":500,\"num_candidates\":2000}}"
	if matches, _ := policy.MatchPatternRules(resolvedES, classify.Classify("easysearch", esQuery), nil, esQuery); len(matches) == 0 {
		t.Fatalf("expected es-unbounded-scan to match heavy knn query on easysearch")
	}
}
