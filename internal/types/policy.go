package types

// RiskLevel classifies statement/command risk across heterogeneous engines.
type RiskLevel string

const (
	RiskSafeRead     RiskLevel = "safe_read"
	RiskHighCostRead RiskLevel = "high_cost_read"
	RiskWrite        RiskLevel = "write"
	RiskDDL          RiskLevel = "ddl"
	RiskAdmin        RiskLevel = "admin"
	RiskUnknown      RiskLevel = "unknown"
)

// Decision is the policy outcome for an evaluated operation.
type Decision string

const (
	DecisionAllow           Decision = "allow"
	DecisionRequireApproval Decision = "require_approval"
	DecisionDeny            Decision = "deny"
)

// ScanReadMode controls how non-yolo environments handle safe reads whose preflight shows a full/large scan.
type ScanReadMode string

const (
	ScanReadAllow           ScanReadMode = "allow"
	ScanReadReasonOnly      ScanReadMode = "reason_only"
	ScanReadRequireApproval ScanReadMode = "require_approval"
)

// GlobalSecurityConfig holds machine-wide security guardrails and hard ceilings.
type GlobalSecurityConfig struct {
	ExecTimeoutSec            int    `json:"exec_timeout_sec"`
	ApprovalTimeoutSec        int    `json:"approval_timeout_sec"`
	MaxRows                   int    `json:"max_rows"`
	MaxBytes                  int64  `json:"max_bytes"`
	ExplainMaxRows            int64  `json:"explain_max_rows"`
	ProdReadOnlyFreeze        bool   `json:"prod_read_only_freeze"`
	BlockMultiStatementInProd bool   `json:"block_multi_statement_in_prod"`
	DefaultApprovalProvider   string `json:"default_approval_provider"`
	RedactAuditLiterals       bool   `json:"redact_audit_literals"`
	RequireReasonForApproval  bool   `json:"require_reason_for_approval"`
	UpdatedAtUTC              string `json:"updated_at_utc"`
}

// PolicyRuleSet defines policy overrides scoped to env, system, or target.
type PolicyRuleSet struct {
	ID                            string `json:"id" yaml:"id"`
	Name                          string `json:"name" yaml:"name"`
	ScopeType                     string `json:"scope_type" yaml:"scope_type"` // env | system | target
	ScopeID                       string `json:"scope_id" yaml:"scope_id"`
	AllowSafeRead                 *bool  `json:"allow_safe_read,omitempty" yaml:"allow_safe_read,omitempty"`
	RequireApprovalOnHighCostRead *bool  `json:"require_approval_on_high_cost_read,omitempty" yaml:"require_approval_on_high_cost_read,omitempty"`
	RequireApprovalOnWrite        *bool  `json:"require_approval_on_write,omitempty" yaml:"require_approval_on_write,omitempty"`
	RequireApprovalOnDDL          *bool  `json:"require_approval_on_ddl,omitempty" yaml:"require_approval_on_ddl,omitempty"`
	RequireApprovalOnAdmin        *bool  `json:"require_approval_on_admin,omitempty" yaml:"require_approval_on_admin,omitempty"`
	RequireApprovalOnUnknown      *bool  `json:"require_approval_on_unknown,omitempty" yaml:"require_approval_on_unknown,omitempty"`
	AllowMultiStatement           *bool  `json:"allow_multi_statement,omitempty" yaml:"allow_multi_statement,omitempty"`
	ExecTimeoutSec                *int   `json:"exec_timeout_sec,omitempty" yaml:"exec_timeout_sec,omitempty"`
	ApprovalTimeoutSec            *int   `json:"approval_timeout_sec,omitempty" yaml:"approval_timeout_sec,omitempty"`
	MaxRows                       *int   `json:"max_rows,omitempty" yaml:"max_rows,omitempty"`
	MaxBytes                      *int64       `json:"max_bytes,omitempty" yaml:"max_bytes,omitempty"`
	ExplainMaxRows                *int64       `json:"explain_max_rows,omitempty" yaml:"explain_max_rows,omitempty"`
	ApprovalProvider              string       `json:"approval_provider,omitempty" yaml:"approval_provider,omitempty"`
	ScanReadMode                  ScanReadMode `json:"scan_read_mode,omitempty" yaml:"scan_read_mode,omitempty"`
	CreatedAtUTC                  string       `json:"created_at_utc,omitempty" yaml:"created_at_utc,omitempty"`
	UpdatedAtUTC                  string       `json:"updated_at_utc,omitempty" yaml:"updated_at_utc,omitempty"`
}

// EffectivePolicy is the resolved monotonic policy with per-field provenance.
type EffectivePolicy struct {
	SafetyTier                    SafetyTier        `json:"safety_tier"`
	AllowSafeRead                 bool              `json:"allow_safe_read"`
	RequireApprovalOnHighCostRead bool              `json:"require_approval_on_high_cost_read"`
	RequireApprovalOnWrite        bool              `json:"require_approval_on_write"`
	RequireApprovalOnDDL          bool              `json:"require_approval_on_ddl"`
	RequireApprovalOnAdmin        bool              `json:"require_approval_on_admin"`
	RequireApprovalOnUnknown      bool              `json:"require_approval_on_unknown"`
	AllowMultiStatement           bool              `json:"allow_multi_statement"`
	ProdReadOnlyFreeze            bool              `json:"prod_read_only_freeze"`
	ScanReadMode                  ScanReadMode      `json:"scan_read_mode,omitempty"`
	ExecTimeoutSec                int               `json:"exec_timeout_sec"`
	ApprovalTimeoutSec            int               `json:"approval_timeout_sec"`
	MaxRows                       int               `json:"max_rows"`
	MaxBytes                      int64             `json:"max_bytes"`
	ExplainMaxRows                int64             `json:"explain_max_rows"`
	ApprovalProvider              string            `json:"approval_provider"`
	PatternRules                  []RiskPatternRule `json:"pattern_rules,omitempty"`
	Sources                       map[string]string `json:"sources"`
}

// PolicyEvaluation describes the decision and exact reasons for an operation.
type PolicyEvaluation struct {
	Decision        Decision        `json:"decision"`
	RequireReason   bool            `json:"require_reason,omitempty"`
	TriggerReasons  []string        `json:"trigger_reasons,omitempty"`
	MatchedRules    []MatchedRule   `json:"matched_rules,omitempty"`
	CredentialMode  AccessLevel     `json:"credential_mode"`
	PreferReplica   bool            `json:"prefer_replica"`
	EffectivePolicy EffectivePolicy `json:"effective_policy"`
	DenyCode        string          `json:"deny_code,omitempty"`
	DenyMessage     string          `json:"deny_message,omitempty"`
}
