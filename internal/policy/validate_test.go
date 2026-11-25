package policy_test

import (
	"testing"

	"github.com/x0c/agent-dbctl/internal/policy"
	"github.com/x0c/agent-dbctl/internal/types"
)

func int64Ptr(v int64) *int64 { return &v }

func TestValidateRuleSet(t *testing.T) {
	valid := types.PolicyRuleSet{
		Name:           "prod-tight",
		ScopeType:      "env",
		ScopeID:        "prod",
		ExecTimeoutSec: intPtr(10),
		MaxRows:        intPtr(100),
		MaxBytes:       int64Ptr(65536),
		ExplainMaxRows: int64Ptr(5000),
	}
	if err := policy.ValidateRuleSet(valid); err != nil {
		t.Fatalf("expected valid rule set, got %v", err)
	}

	cases := []struct {
		name string
		mod  func(p *types.PolicyRuleSet)
	}{
		{"empty_name", func(p *types.PolicyRuleSet) { p.Name = "  " }},
		{"bad_scope_type", func(p *types.PolicyRuleSet) { p.ScopeType = "global" }},
		{"empty_scope_id", func(p *types.PolicyRuleSet) { p.ScopeID = "" }},
		{"neg_exec_timeout", func(p *types.PolicyRuleSet) { p.ExecTimeoutSec = intPtr(-1) }},
		{"neg_approval_timeout", func(p *types.PolicyRuleSet) { p.ApprovalTimeoutSec = intPtr(-5) }},
		{"neg_max_rows", func(p *types.PolicyRuleSet) { p.MaxRows = intPtr(-10) }},
		{"neg_max_bytes", func(p *types.PolicyRuleSet) { p.MaxBytes = int64Ptr(-1) }},
		{"neg_explain_rows", func(p *types.PolicyRuleSet) { p.ExplainMaxRows = int64Ptr(-2) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cp := valid
			tc.mod(&cp)
			if err := policy.ValidateRuleSet(cp); err == nil {
				t.Fatalf("expected validation error for %s", tc.name)
			}
		})
	}
}

func TestValidateGlobalConfig(t *testing.T) {
	valid := types.GlobalSecurityConfig{
		ExecTimeoutSec:     15,
		ApprovalTimeoutSec: 120,
		MaxRows:            200,
		MaxBytes:           262144,
		ExplainMaxRows:     100000,
	}
	if err := policy.ValidateGlobalConfig(valid); err != nil {
		t.Fatalf("expected valid global config, got %v", err)
	}
	bad := valid
	bad.MaxRows = 0
	if err := policy.ValidateGlobalConfig(bad); err == nil {
		t.Fatalf("expected error for non-positive max_rows")
	}
	bad2 := valid
	bad2.ExplainMaxRows = -1
	if err := policy.ValidateGlobalConfig(bad2); err == nil {
		t.Fatalf("expected error for negative explain_max_rows")
	}
}
