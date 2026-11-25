package policy

import (
	"fmt"
	"strings"

	"github.com/x0c/agent-dbctl/internal/types"
)

// ValidateRuleSet checks required fields and rejects negative limits on a PolicyRuleSet.
func ValidateRuleSet(p types.PolicyRuleSet) error {
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("policy name is required")
	}
	switch p.ScopeType {
	case "env", "system", "target":
	default:
		return fmt.Errorf("invalid policy scope_type %q: must be env, system, or target", p.ScopeType)
	}
	if strings.TrimSpace(p.ScopeID) == "" {
		return fmt.Errorf("policy scope_id is required")
	}
	if p.ExecTimeoutSec != nil && *p.ExecTimeoutSec < 0 {
		return fmt.Errorf("exec_timeout_sec cannot be negative")
	}
	if p.ApprovalTimeoutSec != nil && *p.ApprovalTimeoutSec < 0 {
		return fmt.Errorf("approval_timeout_sec cannot be negative")
	}
	if p.MaxRows != nil && *p.MaxRows < 0 {
		return fmt.Errorf("max_rows cannot be negative")
	}
	if p.MaxBytes != nil && *p.MaxBytes < 0 {
		return fmt.Errorf("max_bytes cannot be negative")
	}
	if p.ExplainMaxRows != nil && *p.ExplainMaxRows < 0 {
		return fmt.Errorf("explain_max_rows cannot be negative")
	}
	return nil
}

// ValidateGlobalConfig checks that global security timeouts and caps are strictly positive.
func ValidateGlobalConfig(cfg types.GlobalSecurityConfig) error {
	if cfg.ExecTimeoutSec <= 0 || cfg.ApprovalTimeoutSec <= 0 || cfg.MaxRows <= 0 || cfg.MaxBytes <= 0 || cfg.ExplainMaxRows <= 0 {
		return fmt.Errorf("timeouts and caps must be positive integers")
	}
	return nil
}
