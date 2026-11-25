package rbac

import (
	"testing"

	"github.com/x0c/agent-dbctl/internal/types"
)

func TestRBACRolesAndHumanOnlyApprovalBoundary(t *testing.T) {
	devUser := types.Principal{
		Kind:    types.PrincipalHuman,
		ID:      "usr_dev",
		Subject: "user:dev@corp.com",
		Roles: []types.RoleBinding{
			{Role: types.RoleDeveloper, ScopeType: types.ScopeSystem, ScopeID: "sys_orders"},
		},
	}

	ordersDev := ResourceScope{SystemID: "sys_orders", SystemSlug: "order-core", EnvironmentCode: "dev"}
	billingDev := ResourceScope{SystemID: "sys_billing", SystemSlug: "billing", EnvironmentCode: "dev"}

	if err := Authorize(devUser, ActionDBExecute, ordersDev); err != nil {
		t.Fatalf("developer should execute on assigned system: %v", err)
	}
	if err := Authorize(devUser, ActionDBExecute, billingDev); err == nil {
		t.Fatalf("developer must not access unassigned system")
	}
	if err := Authorize(devUser, ActionTargetWrite, ordersDev); err == nil {
		t.Fatalf("developer must not mutate catalog targets")
	}
	if err := Authorize(devUser, ActionApprovalResolve, ordersDev); err == nil {
		t.Fatalf("developer must not resolve approvals")
	}

	agentTok := types.Principal{
		Kind:           types.PrincipalAgentToken,
		ID:             "tok_1",
		OwnerUserID:    "usr_approver",
		Subject:        "agent:approver@corp.com:ci",
		RoleCeiling:    types.RoleSystemAdmin,
		AllowedSystems: []string{"order-core"},
		AllowedEnvs:    []string{"staging"},
		Roles: []types.RoleBinding{
			{Role: types.RolePlatformAdmin, ScopeType: types.ScopeGlobal},
		},
	}

	// AgentToken must NEVER resolve approvals even if owner is platform_admin.
	app := types.ApprovalRequest{
		ID:              "apr_1",
		SystemSlug:      "order-core",
		EnvironmentCode: "staging",
		PrincipalID:     "tok_other",
	}
	if err := AuthorizeApprovalDecision(agentTok, app, "sys_orders", true); err == nil {
		t.Fatalf("agent token must never approve requests")
	}
	// AgentToken ceiling caps platform_admin down to system_admin and scopes to order-core/staging.
	if err := Authorize(agentTok, ActionGlobalSecurityWrite, ordersDev); err == nil {
		t.Fatalf("agent token capped below platform_admin must not mutate global security")
	}
	if err := Authorize(agentTok, ActionDBExecute, ResourceScope{SystemID: "sys_orders", SystemSlug: "order-core", EnvironmentCode: "prod"}); err == nil {
		t.Fatalf("agent token allowed_envs must block prod")
	}

	// Human approver with four-eyes check.
	approver := types.Principal{
		Kind:    types.PrincipalHuman,
		ID:      "usr_approver",
		Subject: "user:approver@corp.com",
		Roles: []types.RoleBinding{
			{Role: types.RoleApprover, ScopeType: types.ScopeSystem, ScopeID: "order-core"},
		},
	}
	if err := AuthorizeApprovalDecision(approver, app, "sys_orders", true); err != nil {
		t.Fatalf("human approver should approve other requester's ticket: %v", err)
	}
	selfApp := app
	selfApp.PrincipalID = "usr_approver"
	if err := AuthorizeApprovalDecision(approver, selfApp, "sys_orders", true); err == nil {
		t.Fatalf("four-eyes policy must block self-approval")
	}
}
