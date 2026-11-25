package policy

import (
	"fmt"
	"strings"

	"github.com/x0c/agent-dbctl/internal/types"
)

// ResolveEffectivePolicy computes the 4-level monotonic policy (global -> env -> system -> target).
// Lower layers can tighten ceilings and enable stricter approvals, but never bypass global ceilings.
func ResolveEffectivePolicy(
	global types.GlobalSecurityConfig,
	env *types.Environment,
	sys *types.System,
	tgt types.Target,
	policies []types.PolicyRuleSet,
) types.EffectivePolicy {
	return ResolveEffectivePolicyWithSystems(global, env, sys, nil, tgt, policies)
}

// ResolveEffectivePolicyWithSystems computes the 4-level monotonic policy including linked systems.
func ResolveEffectivePolicyWithSystems(
	global types.GlobalSecurityConfig,
	env *types.Environment,
	ownerSys *types.System,
	linkedSystems []types.System,
	tgt types.Target,
	policies []types.PolicyRuleSet,
) types.EffectivePolicy {
	tier := types.SafetyTierGuarded
	envLabel := "default"
	if env != nil {
		tier = env.SafetyTier
		envLabel = "env:" + env.Code
	}

	eff := types.EffectivePolicy{
		SafetyTier:         tier,
		AllowSafeRead:      true,
		ProdReadOnlyFreeze: global.ProdReadOnlyFreeze,
		ExecTimeoutSec:     global.ExecTimeoutSec,
		ApprovalTimeoutSec: global.ApprovalTimeoutSec,
		MaxRows:            global.MaxRows,
		MaxBytes:           global.MaxBytes,
		ExplainMaxRows:     global.ExplainMaxRows,
		ApprovalProvider:   global.DefaultApprovalProvider,
		Sources: map[string]string{
			"exec_timeout_sec":     "global",
			"approval_timeout_sec": "global",
			"max_rows":             "global",
			"max_bytes":            "global",
			"explain_max_rows":     "global",
			"approval_provider":    "global",
			"prod_read_only_freeze": "global",
		},
	}

	switch tier {
	case types.SafetyTierYOLO:
		eff.AllowMultiStatement = true
		eff.Sources["safety_tier"] = envLabel
	case types.SafetyTierGuarded:
		eff.RequireApprovalOnHighCostRead = true
		eff.RequireApprovalOnWrite = true
		eff.RequireApprovalOnDDL = true
		eff.RequireApprovalOnAdmin = true
		eff.RequireApprovalOnUnknown = true
		eff.AllowMultiStatement = false
		eff.Sources["safety_tier"] = envLabel
	case types.SafetyTierStrict:
		eff.RequireApprovalOnHighCostRead = true
		eff.RequireApprovalOnWrite = true
		eff.RequireApprovalOnDDL = true
		eff.RequireApprovalOnAdmin = true
		eff.RequireApprovalOnUnknown = true
		eff.AllowMultiStatement = !global.BlockMultiStatementInProd
		eff.Sources["safety_tier"] = envLabel
	}
	eff.Sources["allow_safe_read"] = envLabel
	eff.Sources["require_approval_on_high_cost_read"] = envLabel
	eff.Sources["require_approval_on_write"] = envLabel
	eff.Sources["require_approval_on_ddl"] = envLabel
	eff.Sources["require_approval_on_admin"] = envLabel
	eff.Sources["require_approval_on_unknown"] = envLabel
	if tier == types.SafetyTierStrict && global.BlockMultiStatementInProd {
		eff.Sources["allow_multi_statement"] = "global"
	} else {
		eff.Sources["allow_multi_statement"] = envLabel
	}

	byID := make(map[string]types.PolicyRuleSet, len(policies))
	for _, p := range policies {
		byID[p.ID] = p
	}

	// Lower levels can only tighten permissions and caps; loosening is never permitted.
	apply := func(p types.PolicyRuleSet, src string) {
		if p.AllowSafeRead != nil && !*p.AllowSafeRead && eff.AllowSafeRead {
			eff.AllowSafeRead = false
			eff.Sources["allow_safe_read"] = src
		}
		if p.RequireApprovalOnHighCostRead != nil && *p.RequireApprovalOnHighCostRead && !eff.RequireApprovalOnHighCostRead {
			eff.RequireApprovalOnHighCostRead = true
			eff.Sources["require_approval_on_high_cost_read"] = src
		}
		if p.RequireApprovalOnWrite != nil && *p.RequireApprovalOnWrite && !eff.RequireApprovalOnWrite {
			eff.RequireApprovalOnWrite = true
			eff.Sources["require_approval_on_write"] = src
		}
		if p.RequireApprovalOnDDL != nil && *p.RequireApprovalOnDDL && !eff.RequireApprovalOnDDL {
			eff.RequireApprovalOnDDL = true
			eff.Sources["require_approval_on_ddl"] = src
		}
		if p.RequireApprovalOnAdmin != nil && *p.RequireApprovalOnAdmin && !eff.RequireApprovalOnAdmin {
			eff.RequireApprovalOnAdmin = true
			eff.Sources["require_approval_on_admin"] = src
		}
		if p.RequireApprovalOnUnknown != nil && *p.RequireApprovalOnUnknown && !eff.RequireApprovalOnUnknown {
			eff.RequireApprovalOnUnknown = true
			eff.Sources["require_approval_on_unknown"] = src
		}
		if p.AllowMultiStatement != nil && !*p.AllowMultiStatement && eff.AllowMultiStatement {
			eff.AllowMultiStatement = false
			eff.Sources["allow_multi_statement"] = src
		}
		if p.ExecTimeoutSec != nil && *p.ExecTimeoutSec > 0 && (eff.ExecTimeoutSec <= 0 || *p.ExecTimeoutSec < eff.ExecTimeoutSec) {
			eff.ExecTimeoutSec = *p.ExecTimeoutSec
			eff.Sources["exec_timeout_sec"] = src
		}
		if p.ApprovalTimeoutSec != nil && *p.ApprovalTimeoutSec > 0 && (eff.ApprovalTimeoutSec <= 0 || *p.ApprovalTimeoutSec < eff.ApprovalTimeoutSec) {
			eff.ApprovalTimeoutSec = *p.ApprovalTimeoutSec
			eff.Sources["approval_timeout_sec"] = src
		}
		if p.MaxRows != nil && *p.MaxRows > 0 && (eff.MaxRows <= 0 || *p.MaxRows < eff.MaxRows) {
			eff.MaxRows = *p.MaxRows
			eff.Sources["max_rows"] = src
		}
		if p.MaxBytes != nil && *p.MaxBytes > 0 && (eff.MaxBytes <= 0 || *p.MaxBytes < eff.MaxBytes) {
			eff.MaxBytes = *p.MaxBytes
			eff.Sources["max_bytes"] = src
		}
		if p.ExplainMaxRows != nil && *p.ExplainMaxRows > 0 && (eff.ExplainMaxRows <= 0 || *p.ExplainMaxRows < eff.ExplainMaxRows) {
			eff.ExplainMaxRows = *p.ExplainMaxRows
			eff.Sources["explain_max_rows"] = src
		}
		if p.ApprovalProvider != "" {
			eff.ApprovalProvider = p.ApprovalProvider
			eff.Sources["approval_provider"] = src
		}
	}

	appliedIDs := make(map[string]bool, len(policies))
	applyOnce := func(p types.PolicyRuleSet, src string) {
		if p.ID != "" && appliedIDs[p.ID] {
			return
		}
		if p.ID != "" {
			appliedIDs[p.ID] = true
		}
		apply(p, src)
	}

	if env != nil {
		if env.DefaultPolicyID != "" {
			if p, ok := byID[env.DefaultPolicyID]; ok {
				applyOnce(p, "env:"+env.Code)
			}
		}
		for _, p := range policies {
			if p.ScopeType == "env" && strings.EqualFold(p.ScopeID, env.Code) {
				applyOnce(p, "env:"+env.Code)
			}
		}
	}

	applySystem := func(s types.System) {
		src := "system:" + s.Slug
		if s.Slug == "" {
			src = "system:" + s.ID
		}
		if s.DefaultPolicyID != "" {
			if p, ok := byID[s.DefaultPolicyID]; ok {
				applyOnce(p, src)
			}
		}
		for _, p := range policies {
			if p.ScopeType == "system" && (p.ScopeID == s.ID || (s.Slug != "" && strings.EqualFold(p.ScopeID, s.Slug))) {
				applyOnce(p, src)
			}
		}
	}
	if ownerSys != nil {
		applySystem(*ownerSys)
	}
	for _, ls := range linkedSystems {
		applySystem(ls)
	}

	tgtSrc := "target:" + tgt.Ref
	if tgt.Ref == "" {
		tgtSrc = "target:" + tgt.ID
	}
	if tgt.PolicyOverrideID != "" {
		if p, ok := byID[tgt.PolicyOverrideID]; ok {
			applyOnce(p, tgtSrc)
		}
	}
	for _, p := range policies {
		if p.ScopeType == "target" && (p.ScopeID == tgt.ID || (tgt.Ref != "" && strings.EqualFold(p.ScopeID, tgt.Ref))) {
			applyOnce(p, tgtSrc)
		}
	}

	return eff
}

// Evaluate decides allow vs require_approval vs deny plus credential routing.
func Evaluate(
	tgt types.Target,
	eff types.EffectivePolicy,
	cls types.Classification,
	preflight *types.PreflightReport,
) types.PolicyEvaluation {
	return EvaluateQuery(tgt, eff, cls, preflight, "")
}

// EvaluateQuery decides allow vs require_approval vs deny using both static classification,
// EXPLAIN preflight metrics, and configured custom high-risk pattern rules.
func EvaluateQuery(
	tgt types.Target,
	eff types.EffectivePolicy,
	cls types.Classification,
	preflight *types.PreflightReport,
	rawQuery string,
) types.PolicyEvaluation {
	eval := types.PolicyEvaluation{
		Decision:        types.DecisionAllow,
		CredentialMode:  types.AccessReadWrite,
		PreferReplica:   false,
		EffectivePolicy: eff,
	}

	if cls.IsReadOnly {
		eval.CredentialMode = types.AccessReadOnly
		eval.PreferReplica = true
	} else if tgt.RWCredentialID == "" && tgt.ROCredentialID != "" {
		eval.CredentialMode = types.AccessReadOnly
	}

	if tgt.Status == types.TargetDisabled || tgt.Status == types.TargetMaintenance {
		eval.Decision = types.DecisionDeny
		eval.DenyCode = types.ErrCodeTargetMaintenance
		eval.DenyMessage = fmt.Sprintf("Target %q is currently %s", tgt.Ref, tgt.Status)
		eval.TriggerReasons = append(eval.TriggerReasons, "target_"+string(tgt.Status))
		return eval
	}

	if len(eff.PatternRules) > 0 && rawQuery != "" {
		matched, _ := MatchPatternRules(eff.PatternRules, cls, preflight, rawQuery)
		eval.MatchedRules = matched
	}

	if eff.ProdReadOnlyFreeze && eff.SafetyTier == types.SafetyTierStrict && !cls.IsReadOnly {
		eval.Decision = types.DecisionDeny
		eval.DenyCode = types.ErrCodeProdFrozen
		eval.DenyMessage = "Global production read-only freeze is enabled; mutating or unknown production operations are blocked."
		eval.TriggerReasons = append(eval.TriggerReasons, "prod_read_only_freeze")
		return eval
	}

	if !cls.IsReadOnly && tgt.RWCredentialID == "" && tgt.ROCredentialID != "" {
		eval.Decision = types.DecisionDeny
		eval.DenyCode = types.ErrCodePolicyDenied
		eval.DenyMessage = fmt.Sprintf("Target %q is configured as read-only (only ro_credential_id is set); mutating or unknown operations require a read-write credential.", tgt.Ref)
		eval.TriggerReasons = append(eval.TriggerReasons, "read_only_target")
		return eval
	}

	var reasons []string
	if cls.StatementCount > 1 && !eff.AllowMultiStatement {
		reasons = append(reasons, "multi_statement_requires_approval")
	}

	switch cls.RiskLevel {
	case types.RiskSafeRead:
		if !eff.AllowSafeRead {
			reasons = append(reasons, "safe_read_requires_approval")
		}
		if eff.SafetyTier != types.SafetyTierYOLO && preflight != nil {
			if preflight.FullScan {
				reasons = append(reasons, "preflight_full_scan")
			}
			if preflight.EstimatedRows > 0 && eff.ExplainMaxRows > 0 && preflight.EstimatedRows > eff.ExplainMaxRows {
				reasons = append(reasons, fmt.Sprintf("preflight_estimated_rows_exceeded(%d>%d)", preflight.EstimatedRows, eff.ExplainMaxRows))
			}
		}
	case types.RiskHighCostRead:
		if eff.RequireApprovalOnHighCostRead {
			reasons = append(reasons, "high_cost_read")
			reasons = append(reasons, cls.RiskFlags...)
		}
	case types.RiskWrite:
		if eff.RequireApprovalOnWrite {
			reasons = append(reasons, "write_operation")
		}
	case types.RiskDDL:
		if eff.RequireApprovalOnDDL {
			reasons = append(reasons, "ddl_operation")
		}
	case types.RiskAdmin:
		if eff.RequireApprovalOnAdmin {
			reasons = append(reasons, "admin_operation")
		}
	default:
		if eff.RequireApprovalOnUnknown {
			reasons = append(reasons, "unknown_syntax_fail_closed")
		}
	}

	var patternDeny *types.MatchedRule
	var patternApprovalProvider string
	for i := range eval.MatchedRules {
		mr := &eval.MatchedRules[i]
		switch mr.Action {
		case types.PatternActionDeny:
			if patternDeny == nil {
				patternDeny = mr
			}
			reasons = append(reasons, "pattern_deny:"+mr.RuleName)
		case types.PatternActionRequireApproval:
			reasons = append(reasons, "pattern_rule:"+mr.RuleName)
			if patternApprovalProvider == "" && strings.TrimSpace(mr.ApprovalProvider) != "" {
				patternApprovalProvider = strings.TrimSpace(mr.ApprovalProvider)
			}
		case types.PatternActionElevateHighCost:
			if eff.RequireApprovalOnHighCostRead {
				reasons = append(reasons, "pattern_high_cost:"+mr.RuleName)
			}
		}
	}

	if patternDeny != nil {
		eval.Decision = types.DecisionDeny
		eval.DenyCode = types.ErrCodePolicyDenied
		title := strings.TrimSpace(patternDeny.ConfirmTitle)
		msg := strings.TrimSpace(patternDeny.ConfirmMessage)
		switch {
		case title != "" && msg != "":
			eval.DenyMessage = title + ": " + msg
		case msg != "":
			eval.DenyMessage = msg
		case title != "":
			eval.DenyMessage = title
		default:
			eval.DenyMessage = fmt.Sprintf("Blocked by custom risk pattern rule %q", patternDeny.RuleName)
		}
		eval.TriggerReasons = deduplicateStrings(reasons)
		return eval
	}

	if len(reasons) > 0 {
		eval.Decision = types.DecisionRequireApproval
		eval.TriggerReasons = deduplicateStrings(reasons)
		if patternApprovalProvider != "" {
			eval.EffectivePolicy.ApprovalProvider = patternApprovalProvider
		}
	}
	return eval
}

func deduplicateStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
