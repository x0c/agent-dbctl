package policy

import (
	"fmt"
	"path"
	"regexp"
	"regexp/syntax"
	"sort"
	"strconv"
	"strings"

	"github.com/x0c/agent-dbctl/internal/classify"
	"github.com/x0c/agent-dbctl/internal/types"
)

const (
	maxConditionDepth = 8
	maxConditionNodes = 64
	maxRegexLength    = 512
	maxRegexASTNodes  = 256
)

// ValidateRiskPatternRule checks field constraints, condition tree depth/size, and RE2 regex safety.
func ValidateRiskPatternRule(r types.RiskPatternRule) error {
	name := strings.TrimSpace(r.Name)
	if name == "" {
		return fmt.Errorf("pattern rule name is required")
	}
	if len(name) > 120 {
		return fmt.Errorf("pattern rule name exceeds 120 characters")
	}
	switch r.ScopeType {
	case "global", "env", "system", "target":
	default:
		return fmt.Errorf("invalid pattern rule scope_type %q: must be global, env, system, or target", r.ScopeType)
	}
	if r.ScopeType != "global" && strings.TrimSpace(r.ScopeID) == "" {
		return fmt.Errorf("pattern rule scope_id is required for scope_type %q", r.ScopeType)
	}
	switch r.Action {
	case types.PatternActionElevateHighCost, types.PatternActionRequireApproval, types.PatternActionDeny:
	default:
		return fmt.Errorf("invalid pattern rule action %q: must be elevate_high_cost, require_approval, or deny", r.Action)
	}
	nodeCount := 0
	if err := validateCondition(r.Condition, 1, &nodeCount); err != nil {
		return err
	}
	return nil
}

func validateCondition(c types.PatternCondition, depth int, count *int) error {
	if depth > maxConditionDepth {
		return fmt.Errorf("condition tree exceeds maximum depth %d", maxConditionDepth)
	}
	*count++
	if *count > maxConditionNodes {
		return fmt.Errorf("condition tree exceeds maximum %d nodes", maxConditionNodes)
	}

	hasComposite := len(c.All) > 0 || len(c.Any) > 0 || c.Not != nil
	if hasComposite && c.Type != "" {
		return fmt.Errorf("condition node cannot mix composite (all/any/not) and leaf matcher %q", c.Type)
	}
	if !hasComposite && c.Type == "" {
		return fmt.Errorf("condition node must specify all/any/not or a leaf type")
	}
	if hasComposite {
		branches := 0
		if len(c.All) > 0 {
			branches++
		}
		if len(c.Any) > 0 {
			branches++
		}
		if c.Not != nil {
			branches++
		}
		if branches > 1 {
			return fmt.Errorf("composite condition node may specify only one of all, any, or not")
		}
		for _, child := range c.All {
			if err := validateCondition(child, depth+1, count); err != nil {
				return err
			}
		}
		for _, child := range c.Any {
			if err := validateCondition(child, depth+1, count); err != nil {
				return err
			}
		}
		if c.Not != nil {
			if err := validateCondition(*c.Not, depth+1, count); err != nil {
				return err
			}
		}
		return nil
	}

	switch c.Type {
	case types.MatcherFunctionCall, types.MatcherTableRef, types.MatcherPragmaName, types.MatcherRiskFlag:
		if len(c.Values) == 0 {
			return fmt.Errorf("%s condition requires non-empty values", c.Type)
		}
	case types.MatcherRegex:
		if _, err := compileSafeRegex(c.Pattern, c.CaseSensitive); err != nil {
			return err
		}
		switch c.Target {
		case "", "normalized_no_literals", "normalized", "raw":
		default:
			return fmt.Errorf("invalid regex target %q", c.Target)
		}
	case types.MatcherCommandArg:
		if strings.TrimSpace(c.Command) == "" {
			return fmt.Errorf("command_arg condition requires command")
		}
	case types.MatcherJSONPath:
		if strings.TrimSpace(c.JSONPath) == "" {
			return fmt.Errorf("json_path condition requires json_path")
		}
	case types.MatcherPreflightMetric:
		switch c.Metric {
		case "full_scan":
			// BoolValue defaults to true if omitted.
		case "estimated_rows":
			if c.Threshold == nil || *c.Threshold < 0 {
				return fmt.Errorf("preflight_metric estimated_rows requires non-negative threshold")
			}
			switch c.Operator {
			case "", "gt", "gte", "eq":
			default:
				return fmt.Errorf("invalid preflight_metric operator %q", c.Operator)
			}
		case "plan_contains":
			if strings.TrimSpace(c.Pattern) == "" {
				return fmt.Errorf("preflight_metric plan_contains requires pattern")
			}
			if _, err := compileSafeRegex(c.Pattern, c.CaseSensitive); err != nil {
				return err
			}
		default:
			return fmt.Errorf("invalid preflight_metric %q: must be full_scan, estimated_rows, or plan_contains", c.Metric)
		}
	default:
		return fmt.Errorf("unsupported matcher type %q", c.Type)
	}
	return nil
}

func compileSafeRegex(pattern string, caseSensitive bool) (*regexp.Regexp, error) {
	if strings.TrimSpace(pattern) == "" {
		return nil, fmt.Errorf("regex pattern is required")
	}
	if len(pattern) > maxRegexLength {
		return nil, fmt.Errorf("regex pattern exceeds maximum length of %d bytes", maxRegexLength)
	}
	ast, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, fmt.Errorf("invalid regex syntax: %w", err)
	}
	if countRegexASTNodes(ast) > maxRegexASTNodes {
		return nil, fmt.Errorf("regex AST exceeds maximum %d nodes", maxRegexASTNodes)
	}
	expr := pattern
	if !caseSensitive {
		expr = "(?i)" + pattern
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return nil, fmt.Errorf("compile regex: %w", err)
	}
	return re, nil
}

func countRegexASTNodes(r *syntax.Regexp) int {
	if r == nil {
		return 0
	}
	stack := []*syntax.Regexp{r}
	count := 0
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		count++
		if count > maxRegexASTNodes {
			return count
		}
		stack = append(stack, cur.Sub...)
	}
	return count
}

// ResolveEffectivePatternRules resolves custom/preset rules monotonically across global -> env -> system -> target.
// Lower scopes can add rules or tighten actions/messages, but never disable or weaken an enabled ancestor rule.
func ResolveEffectivePatternRules(
	env *types.Environment,
	sys *types.System,
	tgt types.Target,
	engine string,
	family types.EngineFamily,
	allRules []types.RiskPatternRule,
) []types.RiskPatternRule {
	if len(allRules) == 0 {
		return nil
	}
	scopeRank := func(r types.RiskPatternRule) int {
		switch r.ScopeType {
		case "global":
			return 1
		case "env":
			if env != nil && strings.EqualFold(r.ScopeID, env.Code) {
				return 2
			}
		case "system":
			if sys != nil && (r.ScopeID == sys.ID || strings.EqualFold(r.ScopeID, sys.Slug)) {
				return 3
			}
		case "target":
			if r.ScopeID == tgt.ID || strings.EqualFold(r.ScopeID, tgt.Ref) {
				return 4
			}
		}
		return 0
	}

	scopeLabel := func(r types.RiskPatternRule) string {
		switch r.ScopeType {
		case "global":
			return "global"
		case "env":
			if env != nil {
				return "env:" + env.Code
			}
			return "env:" + r.ScopeID
		case "system":
			if sys != nil && sys.Slug != "" {
				return "system:" + sys.Slug
			}
			return "system:" + r.ScopeID
		case "target":
			if tgt.Ref != "" {
				return "target:" + tgt.Ref
			}
			return "target:" + r.ScopeID
		}
		return r.ScopeType
	}

	var applicable []types.RiskPatternRule
	for _, r := range allRules {
		rank := scopeRank(r)
		if rank == 0 {
			continue
		}
		if !ruleAppliesToTarget(r, engine, family) {
			continue
		}
		r.ScopeLabel = scopeLabel(r)
		applicable = append(applicable, r)
	}
	if len(applicable) == 0 {
		return nil
	}

	// Sort ancestor-first so monotonic merge preserves/tightens ancestor enforcement.
	sort.Slice(applicable, func(i, j int) bool {
		ri, rj := scopeRank(applicable[i]), scopeRank(applicable[j])
		if ri != rj {
			return ri < rj
		}
		return applicable[i].Name < applicable[j].Name
	})

	byKey := make(map[string]types.RiskPatternRule, len(applicable))
	for _, r := range applicable {
		key := strings.ToLower(strings.TrimSpace(r.Name))
		if key == "" {
			key = r.ID
		}
		existing, exists := byKey[key]
		if !exists {
			byKey[key] = r
			continue
		}
		merged := existing
		if !existing.Enabled && r.Enabled {
			merged = r
		} else if existing.Enabled {
			// Lower scope cannot disable an already enabled upper rule.
			merged.Enabled = true
			if actionSeverity(r.Action) > actionSeverity(existing.Action) {
				merged.Action = r.Action
			}
			if r.Priority > existing.Priority {
				merged.Priority = r.Priority
			}
			if r.ScopeLabel != "" {
				merged.ScopeLabel = r.ScopeLabel
			}
			if strings.TrimSpace(r.ConfirmTitle) != "" {
				merged.ConfirmTitle = r.ConfirmTitle
			}
			if strings.TrimSpace(r.ConfirmMessage) != "" {
				merged.ConfirmMessage = r.ConfirmMessage
			}
			if strings.TrimSpace(r.ApprovalProvider) != "" {
				merged.ApprovalProvider = r.ApprovalProvider
			}
		}
		byKey[key] = merged
	}

	var out []types.RiskPatternRule
	for _, r := range byKey {
		if r.Enabled {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority > out[j].Priority
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func ruleAppliesToTarget(r types.RiskPatternRule, engine string, family types.EngineFamily) bool {
	if len(r.Engines) > 0 {
		matched := false
		for _, e := range r.Engines {
			el := strings.ToLower(strings.TrimSpace(e))
			if el == "*" || el == "all" || el == strings.ToLower(engine) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if len(r.Families) > 0 && family != "" {
		matched := false
		for _, f := range r.Families {
			if f == family {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// MatchPatternRules evaluates enabled pattern rules against query context, classification, and preflight.
func MatchPatternRules(
	rules []types.RiskPatternRule,
	cls types.Classification,
	pf *types.PreflightReport,
	rawQuery string,
) ([]types.MatchedRule, classify.QueryContext) {
	qctx := classify.ExtractQueryContext(cls.Engine, rawQuery)
	if len(rules) == 0 {
		return nil, qctx
	}
	var matched []types.MatchedRule
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		if ok, frag := evalCondition(r.Condition, qctx, cls, pf); ok {
			scope := r.ScopeLabel
			if scope == "" {
				scope = r.ScopeType
				if r.ScopeID != "" && r.ScopeType != "global" {
					scope = r.ScopeType + ":" + r.ScopeID
				}
			}
			matched = append(matched, types.MatchedRule{
				RuleID:           r.ID,
				RuleName:         r.Name,
				Scope:            scope,
				Action:           r.Action,
				MatchedFragment:  truncateFragment(frag, 120),
				ConfirmTitle:     r.ConfirmTitle,
				ConfirmMessage:   r.ConfirmMessage,
				ApprovalProvider: r.ApprovalProvider,
			})
		}
	}
	sort.Slice(matched, func(i, j int) bool {
		si, sj := actionSeverity(matched[i].Action), actionSeverity(matched[j].Action)
		if si != sj {
			return si > sj
		}
		return matched[i].RuleName < matched[j].RuleName
	})
	return matched, qctx
}

// HasPreflightPatternRule returns true when any enabled rule requires EXPLAIN preflight metrics.
func HasPreflightPatternRule(rules []types.RiskPatternRule) bool {
	for _, r := range rules {
		if r.Enabled && conditionUsesPreflight(r.Condition) {
			return true
		}
	}
	return false
}

func conditionUsesPreflight(c types.PatternCondition) bool {
	if c.Type == types.MatcherPreflightMetric {
		return true
	}
	for _, ch := range c.All {
		if conditionUsesPreflight(ch) {
			return true
		}
	}
	for _, ch := range c.Any {
		if conditionUsesPreflight(ch) {
			return true
		}
	}
	if c.Not != nil {
		return conditionUsesPreflight(*c.Not)
	}
	return false
}

func evalCondition(c types.PatternCondition, qctx classify.QueryContext, cls types.Classification, pf *types.PreflightReport) (bool, string) {
	if len(c.All) > 0 {
		var frags []string
		for _, child := range c.All {
			ok, frag := evalCondition(child, qctx, cls, pf)
			if !ok {
				return false, ""
			}
			if frag != "" {
				frags = append(frags, frag)
			}
		}
		return true, strings.Join(frags, " & ")
	}
	if len(c.Any) > 0 {
		for _, child := range c.Any {
			if ok, frag := evalCondition(child, qctx, cls, pf); ok {
				return true, frag
			}
		}
		return false, ""
	}
	if c.Not != nil {
		ok, _ := evalCondition(*c.Not, qctx, cls, pf)
		if !ok {
			return true, "not matched"
		}
		return false, ""
	}

	switch c.Type {
	case types.MatcherFunctionCall:
		for _, val := range c.Values {
			for _, fn := range qctx.Functions {
				if matchGlobCI(val, fn) {
					return true, fn + "()"
				}
			}
		}
	case types.MatcherTableRef:
		for _, val := range c.Values {
			for _, tbl := range qctx.Tables {
				if matchGlobCI(val, tbl) {
					return true, tbl
				}
			}
		}
	case types.MatcherPragmaName:
		for _, val := range c.Values {
			for _, pr := range qctx.Pragmas {
				if matchGlobCI(val, pr) {
					return true, "PRAGMA " + pr
				}
			}
		}
	case types.MatcherRiskFlag:
		for _, val := range c.Values {
			for _, f := range cls.RiskFlags {
				if matchGlobCI(val, f) {
					return true, f
				}
			}
		}
	case types.MatcherCommandArg:
		return evalCommandArg(c, qctx.Commands)
	case types.MatcherJSONPath:
		return evalJSONPath(c, qctx)
	case types.MatcherRegex:
		re, err := compileSafeRegex(c.Pattern, c.CaseSensitive)
		if err != nil {
			return false, ""
		}
		haystack := qctx.NormalizedNoLit
		switch c.Target {
		case "normalized":
			haystack = qctx.Normalized
		case "raw":
			haystack = qctx.Raw
		}
		if m := re.FindString(haystack); m != "" {
			return true, m
		}
	case types.MatcherPreflightMetric:
		return evalPreflightMetric(c, pf)
	}
	return false, ""
}

func evalCommandArg(c types.PatternCondition, cmds [][]string) (bool, string) {
	for _, args := range cmds {
		if len(args) == 0 || !strings.EqualFold(args[0], c.Command) {
			continue
		}
		startIdx := 1
		if c.Subcommand != "" {
			if len(args) < 2 || !strings.EqualFold(args[1], c.Subcommand) {
				continue
			}
			startIdx = 2
		}
		if c.ArgKeyword == "" {
			if c.ArgEquals == "" && c.ArgGreaterThan == nil {
				return true, strings.Join(args, " ")
			}
			for _, a := range args[startIdx:] {
				if c.ArgEquals != "" && strings.EqualFold(a, c.ArgEquals) {
					return true, strings.Join(args, " ")
				}
				if c.ArgGreaterThan != nil {
					if n, err := strconv.ParseInt(a, 10, 64); err == nil && n > *c.ArgGreaterThan {
						return true, strings.Join(args, " ")
					}
				}
			}
			continue
		}
		for i := startIdx; i < len(args); i++ {
			if !strings.EqualFold(args[i], c.ArgKeyword) {
				continue
			}
			if c.ArgEquals == "" && c.ArgGreaterThan == nil {
				return true, c.ArgKeyword
			}
			if i+1 < len(args) {
				next := args[i+1]
				if c.ArgEquals != "" && strings.EqualFold(next, c.ArgEquals) {
					return true, c.ArgKeyword + " " + next
				}
				if c.ArgGreaterThan != nil {
					if n, err := strconv.ParseInt(next, 10, 64); err == nil && n > *c.ArgGreaterThan {
						return true, c.ArgKeyword + " " + next
					}
				}
			}
		}
	}
	return false, ""
}

func evalJSONPath(c types.PatternCondition, qctx classify.QueryContext) (bool, string) {
	jp := strings.TrimSpace(c.JSONPath)
	if strings.HasPrefix(jp, "$") {
		for _, op := range qctx.MongoOperators {
			if strings.EqualFold(op, jp) {
				return true, op
			}
		}
	}
	if qctx.MongoDoc != nil {
		parts := strings.Split(jp, ".")
		var cur any = qctx.MongoDoc
		found := true
		for _, p := range parts {
			m, ok := cur.(map[string]any)
			if !ok {
				found = false
				break
			}
			val, exists := m[p]
			if !exists {
				found = false
				break
			}
			cur = val
		}
		if found {
			strVal := fmt.Sprintf("%v", cur)
			if c.Equals == "" || strings.EqualFold(strVal, c.Equals) {
				if c.Equals != "" {
					return true, jp + "=" + strVal
				}
				return true, jp
			}
		}
	}
	// Fallback for mongosh string form (e.g. allowDiskUse / verbosity=executionStats).
	if qctx.Family == types.FamilyDocument && qctx.MongoDoc == nil {
		lowerRaw := strings.ToLower(qctx.Raw)
		if c.Equals != "" && strings.Contains(lowerRaw, strings.ToLower(c.Equals)) && (jp == "verbosity" || strings.Contains(lowerRaw, strings.ToLower(jp))) {
			return true, jp + "=" + c.Equals
		}
		if c.Equals == "" && strings.Contains(qctx.Raw, jp) {
			return true, jp
		}
	}
	return false, ""
}

func evalPreflightMetric(c types.PatternCondition, pf *types.PreflightReport) (bool, string) {
	if pf == nil {
		return false, ""
	}
	switch c.Metric {
	case "full_scan":
		want := true
		if c.BoolValue != nil {
			want = *c.BoolValue
		}
		if pf.FullScan == want {
			return true, fmt.Sprintf("full_scan=%v", pf.FullScan)
		}
	case "estimated_rows":
		if c.Threshold == nil {
			return false, ""
		}
		th := *c.Threshold
		op := c.Operator
		if op == "" {
			op = "gt"
		}
		switch op {
		case "gt":
			if pf.EstimatedRows > th {
				return true, fmt.Sprintf("estimated_rows=%d>%d", pf.EstimatedRows, th)
			}
		case "gte":
			if pf.EstimatedRows >= th {
				return true, fmt.Sprintf("estimated_rows=%d>=%d", pf.EstimatedRows, th)
			}
		case "eq":
			if pf.EstimatedRows == th {
				return true, fmt.Sprintf("estimated_rows=%d", pf.EstimatedRows)
			}
		}
	case "plan_contains":
		re, err := compileSafeRegex(c.Pattern, c.CaseSensitive)
		if err != nil {
			return false, ""
		}
		if m := re.FindString(pf.PlanSummary); m != "" {
			return true, m
		}
	}
	return false, ""
}

func matchGlobCI(pattern, val string) bool {
	p := strings.ToLower(strings.TrimSpace(pattern))
	v := strings.ToLower(strings.TrimSpace(val))
	if p == "" || v == "" {
		return false
	}
	if !strings.ContainsAny(p, "*?[") {
		return p == v
	}
	ok, err := path.Match(p, v)
	return err == nil && ok
}

func actionSeverity(a types.PatternAction) int {
	switch a {
	case types.PatternActionElevateHighCost:
		return 1
	case types.PatternActionRequireApproval:
		return 2
	case types.PatternActionDeny:
		return 3
	default:
		return 0
	}
}

func truncateFragment(s string, maxLen int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
