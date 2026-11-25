package types

// PatternAction defines what happens when a RiskPatternRule matches a query.
type PatternAction string

const (
	PatternActionElevateHighCost PatternAction = "elevate_high_cost"
	PatternActionRequireApproval PatternAction = "require_approval"
	PatternActionDeny            PatternAction = "deny"
)

// PatternMatcherType defines supported declarative matcher kinds.
type PatternMatcherType string

const (
	MatcherFunctionCall    PatternMatcherType = "function_call"
	MatcherTableRef        PatternMatcherType = "table_ref"
	MatcherPragmaName      PatternMatcherType = "pragma_name"
	MatcherCommandArg      PatternMatcherType = "command_arg"
	MatcherJSONPath        PatternMatcherType = "json_path"
	MatcherRegex           PatternMatcherType = "regex"
	MatcherRiskFlag        PatternMatcherType = "risk_flag"
	MatcherPreflightMetric PatternMatcherType = "preflight_metric"
)

// PatternCondition is a recursive boolean tree or leaf matcher over normalized query context and preflight data.
type PatternCondition struct {
	// Composite nodes (mutually exclusive with Type):
	All []PatternCondition `json:"all,omitempty" yaml:"all,omitempty"`
	Any []PatternCondition `json:"any,omitempty" yaml:"any,omitempty"`
	Not *PatternCondition  `json:"not,omitempty" yaml:"not,omitempty"`

	// Leaf matcher discriminator:
	Type PatternMatcherType `json:"type,omitempty" yaml:"type,omitempty"`

	// For function_call, table_ref, pragma_name, risk_flag:
	Values []string `json:"values,omitempty" yaml:"values,omitempty"`

	// For regex:
	Pattern       string `json:"pattern,omitempty" yaml:"pattern,omitempty"`
	Target        string `json:"target,omitempty" yaml:"target,omitempty"` // ""|"normalized_no_literals" | "normalized" | "raw"
	CaseSensitive bool   `json:"case_sensitive,omitempty" yaml:"case_sensitive,omitempty"`

	// For command_arg (Redis / CLI-style arguments):
	Command        string `json:"command,omitempty" yaml:"command,omitempty"`
	Subcommand     string `json:"subcommand,omitempty" yaml:"subcommand,omitempty"`
	ArgKeyword     string `json:"arg_keyword,omitempty" yaml:"arg_keyword,omitempty"`
	ArgEquals      string `json:"arg_equals,omitempty" yaml:"arg_equals,omitempty"`
	ArgGreaterThan *int64 `json:"arg_greater_than,omitempty" yaml:"arg_greater_than,omitempty"`

	// For json_path (MongoDB document / operators):
	JSONPath string `json:"json_path,omitempty" yaml:"json_path,omitempty"`
	Equals   string `json:"equals,omitempty" yaml:"equals,omitempty"`

	// For preflight_metric:
	Metric    string `json:"metric,omitempty" yaml:"metric,omitempty"`     // full_scan | estimated_rows | plan_contains
	Operator  string `json:"operator,omitempty" yaml:"operator,omitempty"` // eq | gt | gte | contains
	Threshold *int64 `json:"threshold,omitempty" yaml:"threshold,omitempty"`
	BoolValue *bool  `json:"bool_value,omitempty" yaml:"bool_value,omitempty"`
}

// RiskPatternRule represents a custom or preset high-risk detection rule across 4 monotonic scopes.
type RiskPatternRule struct {
	ID               string           `json:"id" yaml:"id"`
	Name             string           `json:"name" yaml:"name"`
	Description      string           `json:"description,omitempty" yaml:"description,omitempty"`
	ScopeType        string           `json:"scope_type" yaml:"scope_type"` // global | env | system | target
	ScopeID          string           `json:"scope_id" yaml:"scope_id"`     // "global" for global scope
	ScopeLabel       string           `json:"scope_label,omitempty" yaml:"-"`
	Enabled          bool             `json:"enabled" yaml:"enabled"`
	BuiltinPack      string           `json:"builtin_pack,omitempty" yaml:"builtin_pack,omitempty"`
	Engines          []string         `json:"engines,omitempty" yaml:"engines,omitempty"`   // empty or ["*"] means all
	Families         []EngineFamily   `json:"families,omitempty" yaml:"families,omitempty"` // empty means all
	Action           PatternAction    `json:"action" yaml:"action"`
	ConfirmTitle     string           `json:"confirm_title,omitempty" yaml:"confirm_title,omitempty"`
	ConfirmMessage   string           `json:"confirm_message,omitempty" yaml:"confirm_message,omitempty"`
	ApprovalProvider string           `json:"approval_provider,omitempty" yaml:"approval_provider,omitempty"`
	Condition        PatternCondition `json:"condition" yaml:"condition"`
	Priority         int              `json:"priority" yaml:"priority"`
	CreatedAtUTC     string           `json:"created_at_utc,omitempty" yaml:"created_at_utc,omitempty"`
	UpdatedAtUTC     string           `json:"updated_at_utc,omitempty" yaml:"updated_at_utc,omitempty"`
}

// MatchedRule records a custom or preset high-risk rule hit surfaced to CLI, Web UI, and audit logs.
type MatchedRule struct {
	RuleID           string        `json:"rule_id"`
	RuleName         string        `json:"rule_name"`
	Scope            string        `json:"scope"`
	Action           PatternAction `json:"action"`
	MatchedFragment  string        `json:"matched_fragment,omitempty"`
	ConfirmTitle     string        `json:"confirm_title,omitempty"`
	ConfirmMessage   string        `json:"confirm_message,omitempty"`
	ApprovalProvider string        `json:"approval_provider,omitempty"`
}

// BuiltinRulePack groups curated preset high-risk pattern rules installable via Web Console.
type BuiltinRulePack struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Engines     []string          `json:"engines"`
	Rules       []RiskPatternRule `json:"rules"`
}

// PatternTestRequest executes an offline dry-run evaluation for the Web UI sandbox.
type PatternTestRequest struct {
	TargetID           string           `json:"target_id,omitempty"`
	Engine             string           `json:"engine,omitempty"`
	SafetyTier         SafetyTier       `json:"safety_tier,omitempty"`
	Query              string           `json:"query"`
	DraftRule          *RiskPatternRule `json:"draft_rule,omitempty"`
	SimulatedPreflight *PreflightReport `json:"simulated_preflight,omitempty"`
}

// PatternTestExtracted holds normalized structural elements extracted from the test query.
type PatternTestExtracted struct {
	Functions      []string `json:"functions,omitempty"`
	Tables         []string `json:"tables,omitempty"`
	Pragmas        []string `json:"pragmas,omitempty"`
	MongoOperators []string `json:"mongo_operators,omitempty"`
}

// PatternTestResult returns structured dry-run pattern matching diagnostics.
type PatternTestResult struct {
	Classification  Classification       `json:"classification"`
	Evaluation      PolicyEvaluation     `json:"evaluation"`
	MatchedRules    []MatchedRule        `json:"matched_rules,omitempty"`
	DraftMatched    *MatchedRule         `json:"draft_matched,omitempty"`
	NormalizedQuery string               `json:"normalized_query"`
	Extracted       PatternTestExtracted `json:"extracted"`
}
