package types

// OS exit codes constrained to 0..125 (codes >=126 belong to shell/signals).
const (
	ExitSuccess         = 0
	ExitFailure         = 1
	ExitUsage           = 2
	ExitNotFound        = 3
	ExitDenied          = 4
	ExitConflict        = 5
	ExitTimeout         = 6
	ExitWaitingApproval = 7
)

// Semantic machine-readable error codes returned in JSON envelope error.code.
const (
	ErrCodeDBNotFound             = "db_not_found"
	ErrCodeSystemNotFound         = "system_not_found"
	ErrCodeOperationNotFound      = "operation_not_found"
	ErrCodeAmbiguousTarget        = "ambiguous_target"
	ErrCodeInvalidUsage           = "invalid_usage"
	ErrCodeInvalidInput           = "invalid_input"
	ErrCodeUnknownFlag            = "unknown_flag"
	ErrCodeMultiTargetWrite       = "multi_target_write_forbidden"
	ErrCodePolicyDenied           = "policy_denied"
	ErrCodeApprovalRejected       = "approval_rejected"
	ErrCodeApprovalTimeout        = "approval_timeout"
	ErrCodeWaitingApproval        = "waiting_approval"
	ErrCodeProdFrozen             = "prod_frozen"
	ErrCodeQueryTimeout           = "query_timeout"
	ErrCodeHighCostReadBlocked    = "high_cost_read_blocked"
	ErrCodeDriverError            = "driver_error"
	ErrCodeDaemonUnavailable      = "daemon_unavailable"
	ErrCodeDaemonRestarted        = "daemon_restarted"
	ErrCodeDaemonVersionMismatch  = "daemon_version_mismatch"
	ErrCodePluginInvalid          = "plugin_invalid"
	ErrCodeAuditTampered          = "audit_tampered"
	ErrCodeOutputExists           = "output_exists"
	ErrCodeCredentialMissing      = "credential_missing"
	ErrCodeTargetMaintenance      = "target_maintenance"
	ErrCodeInternalError          = "internal_error"
)

// Envelope is the uniform JSON output contract for both success and error responses.
type Envelope struct {
	OK    bool       `json:"ok"`
	Data  any        `json:"data"`
	Error *ErrorBody `json:"error"`
	Meta  Meta       `json:"meta"`
}

// ErrorBody conveys identity, reason, and concrete recovery guidance.
type ErrorBody struct {
	Code         string         `json:"code"`
	Retryable    bool           `json:"retryable"`
	Message      string         `json:"message"`
	Hint         string         `json:"hint,omitempty"`
	Context      map[string]any `json:"context,omitempty"`
	NextCommands []string       `json:"next_commands,omitempty"`
}

// Meta holds non-body response metadata.
type Meta struct {
	Version    string `json:"version"`
	Session    string `json:"session"`
	DurationMs int64  `json:"duration_ms,omitempty"`
	DryRun     bool   `json:"dry_run,omitempty"`
	Preflight  bool   `json:"preflight,omitempty"`
	Partial    bool   `json:"partial,omitempty"`
}

// ExitCodeForError maps semantic error codes to CLI exit codes.
func ExitCodeForError(code string) int {
	switch code {
	case "":
		return ExitSuccess
	case ErrCodeInvalidUsage, ErrCodeInvalidInput, ErrCodeUnknownFlag, ErrCodeMultiTargetWrite:
		return ExitUsage
	case ErrCodeDBNotFound, ErrCodeSystemNotFound, ErrCodeOperationNotFound:
		return ExitNotFound
	case ErrCodePolicyDenied, ErrCodeApprovalRejected, ErrCodeProdFrozen, ErrCodeHighCostReadBlocked, ErrCodeTargetMaintenance:
		return ExitDenied
	case ErrCodeAmbiguousTarget, ErrCodeDaemonVersionMismatch, ErrCodeOutputExists:
		return ExitConflict
	case ErrCodeQueryTimeout, ErrCodeApprovalTimeout:
		return ExitTimeout
	case ErrCodeWaitingApproval:
		return ExitWaitingApproval
	default:
		return ExitFailure
	}
}
