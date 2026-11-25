package rbac

import (
	"context"
	"fmt"
	"strings"

	"github.com/x0c/agent-dbctl/internal/types"
)

type principalCtxKey struct{}

// Action enumerates RBAC-controlled operations.
type Action string

const (
	ActionCatalogRead         Action = "catalog:read"
	ActionSystemWrite         Action = "system:write"
	ActionEnvWrite            Action = "env:write"
	ActionNetworkWrite        Action = "network:write"
	ActionCredentialWrite     Action = "credential:write"
	ActionCredentialExecWrite Action = "credential:exec_write"
	ActionInstanceWrite       Action = "instance:write"
	ActionInstanceDiscover    Action = "instance:discover"
	ActionTargetWrite         Action = "target:write"
	ActionPolicyWrite         Action = "policy:write"
	ActionPatternWrite        Action = "pattern:write"
	ActionGlobalSecurityWrite Action = "security:write"
	ActionDBExecute           Action = "db:execute"
	ActionDBSchema            Action = "db:schema"
	ActionDBTest              Action = "db:test"
	ActionOperationRead       Action = "operation:read"
	ActionOperationCancel     Action = "operation:cancel"
	ActionApprovalRead        Action = "approval:read"
	ActionApprovalResolve     Action = "approval:resolve"
	ActionAuditRead           Action = "audit:read"
	ActionAuditVerify         Action = "audit:verify"
	ActionTokenManage         Action = "token:manage"
	ActionUserManage          Action = "user:manage"
	ActionPluginManage        Action = "plugin:manage"
	ActionTopologyRead        Action = "topology:read"
	ActionTopologyWrite       Action = "topology:write"
)

// ResourceScope carries optional system and environment boundaries for an action check.
type ResourceScope struct {
	SystemID        string
	SystemSlug      string
	LinkedSystemIDs []string
	EnvironmentCode string
	OwnerUserID     string
}

// WithPrincipal attaches the authenticated Principal to ctx.
func WithPrincipal(ctx context.Context, p types.Principal) context.Context {
	return context.WithValue(ctx, principalCtxKey{}, p)
}

// PrincipalFromContext retrieves the Principal from ctx, falling back to LocalOwnerPrincipal.
func PrincipalFromContext(ctx context.Context) types.Principal {
	if ctx != nil {
		if p, ok := ctx.Value(principalCtxKey{}).(types.Principal); ok && p.Kind != "" {
			return p
		}
	}
	return LocalOwnerPrincipal()
}

// LocalOwnerPrincipal returns the implicit single-user local daemon principal.
func LocalOwnerPrincipal() types.Principal {
	return types.Principal{
		Kind:        types.PrincipalLocalOwner,
		ID:          "local-owner",
		Subject:     "local-owner",
		DisplayName: "Local Owner",
		Roles: []types.RoleBinding{
			{
				ID:        "local-global-admin",
				UserID:    "local-owner",
				Role:      types.RolePlatformAdmin,
				ScopeType: types.ScopeGlobal,
			},
		},
	}
}

func roleRank(r types.Role) int {
	switch r {
	case types.RolePlatformAdmin:
		return 5
	case types.RoleSystemAdmin:
		return 4
	case types.RoleApprover:
		return 3
	case types.RoleDeveloper:
		return 2
	case types.RoleViewer:
		return 1
	default:
		return 0
	}
}

// IsPlatformAdmin reports whether the principal has an active global platform_admin binding (not capped by token).
func IsPlatformAdmin(p types.Principal) bool {
	if p.Kind == types.PrincipalLocalOwner {
		return true
	}
	if p.Kind == types.PrincipalAgentToken && p.RoleCeiling != "" && roleRank(p.RoleCeiling) < roleRank(types.RolePlatformAdmin) {
		return false
	}
	for _, b := range p.Roles {
		if b.ScopeType == types.ScopeGlobal && b.Role == types.RolePlatformAdmin {
			return true
		}
	}
	return false
}

// EffectiveRoleForScope computes the highest authorized role across the principal's bindings
// constrained by any AgentToken ceiling and allowed system/env filters.
func EffectiveRoleForScope(p types.Principal, res ResourceScope) types.Role {
	if p.Kind == types.PrincipalLocalOwner {
		return types.RolePlatformAdmin
	}
	if p.Kind == types.PrincipalAgentToken {
		if len(p.AllowedSystems) > 0 && (res.SystemID != "" || res.SystemSlug != "") {
			if !matchesAnySystem(p.AllowedSystems, res) {
				return ""
			}
		}
		if len(p.AllowedEnvs) > 0 && res.EnvironmentCode != "" {
			if !containsFold(p.AllowedEnvs, res.EnvironmentCode) {
				return ""
			}
		}
	}

	best := types.Role("")
	for _, b := range p.Roles {
		if !bindingApplies(b, res) {
			continue
		}
		r := b.Role
		if p.Kind == types.PrincipalAgentToken && p.RoleCeiling != "" && roleRank(r) > roleRank(p.RoleCeiling) {
			r = p.RoleCeiling
		}
		if p.Kind == types.PrincipalAgentToken && p.ReadOnlyForced && roleRank(r) > roleRank(types.RoleViewer) {
			r = types.RoleViewer
		}
		if roleRank(r) > roleRank(best) {
			best = r
		}
	}
	return best
}

func bindingApplies(b types.RoleBinding, res ResourceScope) bool {
	switch b.ScopeType {
	case types.ScopeGlobal:
		return true
	case types.ScopeSystem:
		if res.SystemID != "" && b.ScopeID == res.SystemID {
			return true
		}
		if res.SystemSlug != "" && strings.EqualFold(b.ScopeID, res.SystemSlug) {
			return true
		}
		for _, lid := range res.LinkedSystemIDs {
			if lid != "" && b.ScopeID == lid {
				return true
			}
		}
		return res.SystemID == "" && res.SystemSlug == "" && len(res.LinkedSystemIDs) == 0
	case types.ScopeEnv:
		if res.EnvironmentCode == "" {
			return true
		}
		return strings.EqualFold(b.ScopeID, res.EnvironmentCode)
	default:
		return false
	}
}

func matchesAnySystem(allowed []string, res ResourceScope) bool {
	if containsFold(allowed, res.SystemID) || containsFold(allowed, res.SystemSlug) {
		return true
	}
	for _, lid := range res.LinkedSystemIDs {
		if containsFold(allowed, lid) {
			return true
		}
	}
	return false
}

func containsFold(items []string, needle string) bool {
	if needle == "" {
		return false
	}
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item), strings.TrimSpace(needle)) {
			return true
		}
	}
	return false
}

// Authorize validates whether p can perform action on res, returning a descriptive error on denial.
func Authorize(p types.Principal, action Action, res ResourceScope) error {
	if p.Kind == types.PrincipalLocalOwner {
		return nil
	}

	// Human-only boundary: AgentTokens can never resolve human approvals or mutate platform security/envs/topology/plugins/users.
	if p.Kind == types.PrincipalAgentToken {
		switch action {
		case ActionApprovalResolve, ActionUserManage, ActionGlobalSecurityWrite, ActionEnvWrite, ActionPluginManage, ActionCredentialExecWrite, ActionTopologyWrite:
			return fmt.Errorf("forbidden: action %s is restricted to human principals", action)
		}
	}

	role := EffectiveRoleForScope(p, res)
	if role == "" {
		return fmt.Errorf("forbidden: principal %q has no role on target scope", p.Subject)
	}
	if role == types.RolePlatformAdmin {
		return nil
	}

	switch action {
	case ActionGlobalSecurityWrite, ActionEnvWrite, ActionUserManage, ActionPluginManage, ActionCredentialExecWrite, ActionAuditVerify, ActionTopologyWrite:
		return fmt.Errorf("forbidden: action %s requires platform_admin", action)

	case ActionSystemWrite, ActionNetworkWrite, ActionCredentialWrite, ActionInstanceWrite, ActionInstanceDiscover, ActionTargetWrite, ActionPolicyWrite, ActionPatternWrite:
		if role == types.RoleSystemAdmin && res.SystemID != "" {
			return nil
		}
		return fmt.Errorf("forbidden: action %s requires system_admin on owning system or platform_admin", action)

	case ActionApprovalResolve:
		if role == types.RoleApprover || role == types.RoleSystemAdmin {
			return nil
		}
		return fmt.Errorf("forbidden: action %s requires approver role", action)

	case ActionDBExecute, ActionDBSchema, ActionDBTest:
		if roleRank(role) >= roleRank(types.RoleViewer) {
			return nil
		}

	case ActionCatalogRead, ActionOperationRead, ActionApprovalRead, ActionAuditRead, ActionTopologyRead:
		if roleRank(role) >= roleRank(types.RoleViewer) {
			return nil
		}

	case ActionOperationCancel:
		if roleRank(role) >= roleRank(types.RoleSystemAdmin) {
			return nil
		}
		if res.OwnerUserID != "" && (res.OwnerUserID == p.ID || res.OwnerUserID == p.OwnerUserID) {
			return nil
		}
		return fmt.Errorf("forbidden: only owner or system_admin may cancel operation")

	case ActionTokenManage:
		if p.Kind == types.PrincipalHuman {
			return nil
		}
		return fmt.Errorf("forbidden: token management requires human authentication")
	}

	return fmt.Errorf("forbidden: role %q cannot perform %s", role, action)
}

// AuthorizeApprovalDecision enforces human-only approval, approver RBAC, and optional four-eyes separation.
func AuthorizeApprovalDecision(p types.Principal, app types.ApprovalRequest, systemID, opOwnerUserID string, forbidSelf bool) error {
	if p.Kind == types.PrincipalLocalOwner {
		return nil
	}
	if p.Kind != types.PrincipalHuman {
		return fmt.Errorf("forbidden: approvals require a human principal")
	}
	if err := Authorize(p, ActionApprovalResolve, ResourceScope{
		SystemID:        systemID,
		SystemSlug:      app.SystemSlug,
		EnvironmentCode: app.EnvironmentCode,
	}); err != nil {
		return err
	}
	if forbidSelf {
		// Compare requester user ID, linked operation owner, and requester subject.
		if (app.PrincipalID != "" && app.PrincipalID == p.ID) ||
			(opOwnerUserID != "" && opOwnerUserID == p.ID) ||
			(app.Actor != "" && strings.EqualFold(app.Actor, p.Subject)) {
			return fmt.Errorf("forbidden: four-eyes policy forbids self-approval")
		}
	}
	return nil
}

// ShouldForceReadOnly reports whether the principal is restricted to read-only DB access for res.
func ShouldForceReadOnly(p types.Principal, res ResourceScope) bool {
	if p.Kind == types.PrincipalLocalOwner {
		return false
	}
	if p.Kind == types.PrincipalAgentToken && p.ReadOnlyForced {
		return true
	}
	return EffectiveRoleForScope(p, res) == types.RoleViewer
}

// CanViewTarget reports whether p can view a target detail record.
func CanViewTarget(p types.Principal, d types.TargetDetail) bool {
	if IsPlatformAdmin(p) {
		return true
	}
	linked := make([]string, 0, len(d.Target.LinkedSystemIDs))
	linked = append(linked, d.Target.LinkedSystemIDs...)
	sysSlug := ""
	if d.OwnerSystem != nil {
		sysSlug = d.OwnerSystem.Slug
	}
	return EffectiveRoleForScope(p, ResourceScope{
		SystemID:        d.Target.OwnerSystemID,
		SystemSlug:      sysSlug,
		LinkedSystemIDs: linked,
		EnvironmentCode: d.Target.EnvironmentCode,
	}) != ""
}

// CanViewOperation reports whether p can read op (requester or scoped member).
func CanViewOperation(p types.Principal, op types.Operation) bool {
	if IsPlatformAdmin(p) {
		return true
	}
	if op.OwnerUserID != "" && (op.OwnerUserID == p.ID || (p.OwnerUserID != "" && op.OwnerUserID == p.OwnerUserID)) {
		return true
	}
	if op.PrincipalID != "" && op.PrincipalID == p.ID {
		return true
	}
	return EffectiveRoleForScope(p, ResourceScope{
		SystemID:        op.SystemID,
		SystemSlug:      op.SystemSlug,
		EnvironmentCode: op.EnvironmentCode,
	}) != ""
}
