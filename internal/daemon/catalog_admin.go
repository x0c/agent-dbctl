package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/x0c/agent-dbctl/internal/classify"
	"github.com/x0c/agent-dbctl/internal/config"
	"github.com/x0c/agent-dbctl/internal/policy"
	"github.com/x0c/agent-dbctl/internal/rbac"
	"github.com/x0c/agent-dbctl/internal/secrets"
	"github.com/x0c/agent-dbctl/internal/store"
	"github.com/x0c/agent-dbctl/internal/types"
)

// AdminMutationResult wraps an idempotent catalog or policy mutation outcome.
type AdminMutationResult[T any] struct {
	DryRun         bool                      `json:"dry_run"`
	Status         string                    `json:"status"` // planned | created | updated | unchanged
	Action         string                    `json:"action,omitempty"`
	Item           T                         `json:"item"`
	MissingSecrets []types.MissingSecretInfo `json:"missing_secrets,omitempty"`
	Warnings       []string                  `json:"warnings,omitempty"`
}

// CredentialUpsertRequest carries metadata and optional write-only secret instructions.
type CredentialUpsertRequest struct {
	types.CredentialProfile
	SecretValue    string `json:"secret_value,omitempty"`
	SecretProvided bool   `json:"secret_provided,omitempty"`
	ClearSecret    bool   `json:"clear_secret,omitempty"`
	DryRun         bool   `json:"dry_run,omitempty"`
}

// DBAddRequest configures one-shot database onboarding via DSN and/or explicit fields.
type DBAddRequest struct {
	DSN                   string            `json:"dsn,omitempty"`
	InlinePasswordWarning bool              `json:"inline_password_warning,omitempty"`
	Engine                string            `json:"engine,omitempty"`
	Host                  string            `json:"host,omitempty"`
	Port                  int               `json:"port,omitempty"`
	Database              string            `json:"database,omitempty"`
	TLSMode               string            `json:"tls_mode,omitempty"`
	Params                map[string]string `json:"params,omitempty"`
	Ref                   string            `json:"ref,omitempty"`
	Alias                 string            `json:"alias,omitempty"`
	System                string            `json:"system,omitempty"`
	SystemName            string            `json:"system_name,omitempty"`
	WorkspaceCWD          string            `json:"workspace_cwd,omitempty"`
	WorkspacePaths        []string          `json:"workspace_paths,omitempty"`
	WorkspaceGitRemotes   []string          `json:"workspace_git_remotes,omitempty"`
	GitRemotes            []string          `json:"git_remotes,omitempty"`
	NoWorkspace           bool              `json:"no_workspace,omitempty"`
	Env                   string            `json:"env,omitempty"`
	SafetyTier            types.SafetyTier  `json:"safety_tier,omitempty"`
	Instance              string            `json:"instance,omitempty"`
	Role                  types.InstanceRole `json:"role,omitempty"`
	Network               string            `json:"network,omitempty"`
	User                  string            `json:"user,omitempty"`
	CredName              string            `json:"cred_name,omitempty"`
	CredKind              types.CredentialKind `json:"cred_kind,omitempty"`
	AccessLevel           types.AccessLevel `json:"access_level,omitempty"`
	ROCred                string            `json:"ro_cred,omitempty"`
	RWCred                string            `json:"rw_cred,omitempty"`
	EnvVarName            string            `json:"env_var_name,omitempty"`
	ExecCommand           string            `json:"exec_command,omitempty"`
	SecretValue           string            `json:"secret_value,omitempty"`
	SecretProvided        bool              `json:"secret_provided,omitempty"`
	Status                types.TargetStatus `json:"status,omitempty"`
	ScanReadMode          types.ScanReadMode `json:"scan_read_mode,omitempty"`
	Description           string            `json:"description,omitempty"`
	DryRun                bool              `json:"dry_run,omitempty"`
	Test                  bool              `json:"test,omitempty"`
}

// DBAddResponse summarizes the created/updated/reused catalog entities for `db add`.
type DBAddResponse struct {
	DryRun         bool                      `json:"dry_run"`
	Status         string                    `json:"status"` // planned | created | updated | unchanged
	AccessLevel    string                    `json:"access_level,omitempty"`
	Target         types.TargetSummary       `json:"target"`
	Actions        map[string]string         `json:"actions"`
	MissingSecrets []types.MissingSecretInfo `json:"missing_secrets,omitempty"`
	Ping           *types.PingResult         `json:"ping,omitempty"`
	Warnings       []string                  `json:"warnings,omitempty"`
	NextCommands   []string                  `json:"next_commands,omitempty"`
}

// OrphanResource identifies an unreferenced instance, credential, or custom environment left after deletion.
type OrphanResource struct {
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	Name    string `json:"name"`
	Command string `json:"command"`
}

// TargetDeleteResult summarizes a deleted target and any newly orphaned catalog assets.
type TargetDeleteResult struct {
	Deleted      bool             `json:"deleted"`
	Target       string           `json:"target"`
	Orphans      []OrphanResource `json:"orphans,omitempty"`
	Hint         string           `json:"hint,omitempty"`
	NextCommands []string         `json:"next_commands,omitempty"`
}

// BuildMissingSecrets lists keychain credentials from the provided IDs (or all credentials if empty) missing a secret.
func (s *Service) BuildMissingSecrets(ctx context.Context, filterIDs []string) []types.MissingSecretInfo {
	creds, err := s.store.ListCredentialProfiles(ctx)
	if err != nil {
		return nil
	}
	var allowed map[string]bool
	if len(filterIDs) > 0 {
		allowed = make(map[string]bool, len(filterIDs))
		for _, id := range filterIDs {
			if id != "" {
				allowed[id] = true
			}
		}
	}
	var out []types.MissingSecretInfo
	for _, cp := range creds {
		if allowed != nil && !allowed[cp.ID] {
			continue
		}
		if cp.Kind != types.CredKeychain {
			continue
		}
		if s.hasCredentialSecret(ctx, cp) {
			continue
		}
		out = append(out, types.MissingSecretInfo{
			ID:          cp.ID,
			Name:        cp.Name,
			Username:    cp.Username,
			AccessLevel: cp.AccessLevel,
			SetupURL:    s.CredentialSetupURL(cp.ID),
		})
	}
	return out
}

func (s *Service) scopeForScopedResource(ctx context.Context, scopeType, scopeID string) rbac.ResourceScope {
	switch strings.ToLower(strings.TrimSpace(scopeType)) {
	case "system":
		if scopeID == "" {
			return rbac.ResourceScope{}
		}
		if sys, err := s.store.ResolveSystem(ctx, scopeID); err == nil {
			return rbac.ResourceScope{SystemID: sys.ID, SystemSlug: sys.Slug}
		}
		return rbac.ResourceScope{SystemID: scopeID, SystemSlug: scopeID}
	case "env":
		return rbac.ResourceScope{EnvironmentCode: scopeID}
	case "target":
		if tgt, err := s.store.ResolveTargetRecord(ctx, scopeID); err == nil {
			return rbac.ResourceScope{
				SystemID:        tgt.OwnerSystemID,
				LinkedSystemIDs: tgt.LinkedSystemIDs,
				EnvironmentCode: tgt.EnvironmentCode,
			}
		}
		return rbac.ResourceScope{}
	default:
		return rbac.ResourceScope{}
	}
}

func (s *Service) authorizeScopedWrite(ctx context.Context, action rbac.Action, scopeType, scopeID string) error {
	if !s.IsServerMode() {
		return nil
	}
	return rbac.Authorize(rbac.PrincipalFromContext(ctx), action, s.scopeForScopedResource(ctx, scopeType, scopeID))
}

func validateProxyURL(raw string, serverMode bool) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return fmt.Errorf("invalid proxy_url %q: %w", raw, err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "socks5", "socks5h":
	default:
		return fmt.Errorf("invalid proxy_url scheme %q (expected http, https, socks5, or socks5h)", u.Scheme)
	}
	if serverMode && u.User != nil {
		return fmt.Errorf("forbidden: inline credentials in proxy_url are disallowed in server mode; bind a credential profile instead")
	}
	return nil
}

func (s *Service) validateServerCred(ctx context.Context, cp types.CredentialProfile) error {
	if !s.IsServerMode() {
		return nil
	}
	if err := s.authorizeScopedWrite(ctx, rbac.ActionCredentialWrite, cp.ScopeType, cp.ScopeID); err != nil {
		return err
	}
	switch cp.Kind {
	case types.CredEnvRef:
		if err := rbac.Authorize(rbac.PrincipalFromContext(ctx), rbac.ActionCredentialExecWrite, rbac.ResourceScope{}); err != nil {
			return err
		}
		if err := secrets.ValidateServerEnvVar(cp.EnvVarName, s.secretPolicy); err != nil {
			return err
		}
	case types.CredExecProvider:
		if err := rbac.Authorize(rbac.PrincipalFromContext(ctx), rbac.ActionCredentialExecWrite, rbac.ResourceScope{}); err != nil {
			return err
		}
		if err := secrets.ValidateServerExecCommand(cp.ExecCommand, s.secretPolicy); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) validateServerTargetBindings(ctx context.Context, tgt types.Target) error {
	if !s.IsServerMode() {
		return nil
	}
	p := rbac.PrincipalFromContext(ctx)
	if rbac.IsPlatformAdmin(p) {
		return nil
	}
	if tgt.InstanceID != "" {
		inst, err := s.store.GetInstance(ctx, tgt.InstanceID)
		if err == nil && inst.ScopeType == "system" && inst.ScopeID != tgt.OwnerSystemID {
			return fmt.Errorf("forbidden: cannot bind instance %q belonging to another system", inst.Name)
		}
	}
	for _, credID := range []string{tgt.ROCredentialID, tgt.RWCredentialID} {
		if credID == "" {
			continue
		}
		cp, err := s.store.ResolveCredentialProfile(ctx, credID)
		if err == nil && cp.ScopeType == "system" && cp.ScopeID != tgt.OwnerSystemID {
			return fmt.Errorf("forbidden: cannot bind credential %q belonging to another system", cp.Name)
		}
	}
	if tgt.EnvironmentCode != "" && (tgt.ROCredentialID != "" || tgt.RWCredentialID != "") {
		if env, err := s.store.ResolveEnvironment(ctx, tgt.EnvironmentCode); err == nil && env.SafetyTier == types.SafetyTierYOLO {
			allTargets, _ := s.store.ListTargets(ctx)
			allEnvs, _ := s.store.ListEnvironments(ctx)
			envTiers := make(map[string]types.SafetyTier, len(allEnvs))
			for _, e := range allEnvs {
				envTiers[e.Code] = e.SafetyTier
			}
			for _, other := range allTargets {
				if other.ID == tgt.ID || envTiers[other.EnvironmentCode] != types.SafetyTierStrict {
					continue
				}
				if (tgt.ROCredentialID != "" && (other.ROCredentialID == tgt.ROCredentialID || other.RWCredentialID == tgt.ROCredentialID)) ||
					(tgt.RWCredentialID != "" && (other.ROCredentialID == tgt.RWCredentialID || other.RWCredentialID == tgt.RWCredentialID)) {
					return fmt.Errorf("forbidden: credential is bound to a strict target %q and cannot be reused on a yolo target without platform_admin", other.Ref)
				}
			}
		}
	}
	return nil
}

// AdminUpsertSystem creates or updates a System idempotently with optional dry-run.
func (s *Service) AdminUpsertSystem(ctx context.Context, actor string, sys types.System, dryRun bool) (AdminMutationResult[types.System], error) {
	actor = s.effectiveActor(ctx, actor)
	if strings.TrimSpace(sys.Slug) == "" {
		return AdminMutationResult[types.System]{}, fmt.Errorf("system slug is required")
	}
	if strings.TrimSpace(sys.Name) == "" {
		sys.Name = titleSlug(sys.Slug)
	}
	if sys.DefaultPolicyID != "" {
		pol, err := s.store.ResolvePolicy(ctx, sys.DefaultPolicyID)
		if err != nil {
			return AdminMutationResult[types.System]{}, err
		}
		sys.DefaultPolicyID = pol.ID
	}

	var existing *types.System
	if sys.ID != "" {
		if cur, err := s.store.ResolveSystem(ctx, sys.ID); err == nil {
			existing = &cur
		}
	} else if cur, err := s.store.ResolveSystem(ctx, sys.Slug); err == nil {
		existing = &cur
		sys.ID = cur.ID
	}
	if s.IsServerMode() {
		scope := rbac.ResourceScope{}
		if existing != nil {
			scope = rbac.ResourceScope{SystemID: existing.ID, SystemSlug: existing.Slug}
		}
		if err := rbac.Authorize(rbac.PrincipalFromContext(ctx), rbac.ActionSystemWrite, scope); err != nil {
			return AdminMutationResult[types.System]{}, err
		}
	}

	if sys.Tags == nil {
		if existing != nil {
			sys.Tags = existing.Tags
		} else {
			sys.Tags = []string{}
		}
	}
	if sys.WorkspacePaths == nil {
		if existing != nil {
			sys.WorkspacePaths = existing.WorkspacePaths
		} else {
			sys.WorkspacePaths = []string{}
		}
	}
	if sys.GitRemotes == nil {
		if existing != nil {
			sys.GitRemotes = config.NormalizeGitRemotes(existing.GitRemotes)
		} else {
			sys.GitRemotes = []string{}
		}
	} else {
		sys.GitRemotes = config.NormalizeGitRemotes(sys.GitRemotes)
	}

	action := "created"
	if existing != nil {
		if systemsEqual(*existing, sys) {
			action = "unchanged"
		} else {
			action = "updated"
		}
	}
	if dryRun {
		return AdminMutationResult[types.System]{
			DryRun: true,
			Status: planOrUnchanged(action),
			Action: action,
			Item:   sys,
		}, nil
	}
	if action == "unchanged" && existing != nil {
		return AdminMutationResult[types.System]{
			DryRun: false,
			Status: "unchanged",
			Action: "unchanged",
			Item:   *existing,
		}, nil
	}
	saved, err := s.store.UpsertSystem(ctx, actor, sys)
	if err != nil {
		return AdminMutationResult[types.System]{}, err
	}
	s.broadcast(Event{Type: "catalog_updated", Data: map[string]string{"kind": "system", "id": saved.ID}})
	return AdminMutationResult[types.System]{
		DryRun: false,
		Status: action,
		Action: action,
		Item:   saved,
	}, nil
}

// AdminDeleteSystem removes a System by ID or slug.
func (s *Service) AdminDeleteSystem(ctx context.Context, actor, idOrSlug string) error {
	cur, err := s.store.ResolveSystem(ctx, idOrSlug)
	if err != nil {
		return err
	}
	if s.IsServerMode() {
		if err := rbac.Authorize(rbac.PrincipalFromContext(ctx), rbac.ActionSystemWrite, rbac.ResourceScope{SystemID: cur.ID, SystemSlug: cur.Slug}); err != nil {
			return err
		}
	}
	if err := s.store.DeleteSystem(ctx, s.effectiveActor(ctx, actor), cur.ID); err != nil {
		return err
	}
	s.broadcast(Event{Type: "catalog_updated", Data: map[string]string{"kind": "system", "id": cur.ID}})
	return nil
}

// AdminUpsertEnvironment creates or updates an Environment idempotently with optional dry-run.
func (s *Service) AdminUpsertEnvironment(ctx context.Context, actor string, env types.Environment, dryRun bool) (AdminMutationResult[types.Environment], error) {
	actor = s.effectiveActor(ctx, actor)
	if s.IsServerMode() {
		if err := rbac.Authorize(rbac.PrincipalFromContext(ctx), rbac.ActionEnvWrite, rbac.ResourceScope{}); err != nil {
			return AdminMutationResult[types.Environment]{}, err
		}
	}
	if strings.TrimSpace(env.Code) == "" {
		return AdminMutationResult[types.Environment]{}, fmt.Errorf("environment code is required")
	}
	if env.DefaultPolicyID != "" {
		pol, err := s.store.ResolvePolicy(ctx, env.DefaultPolicyID)
		if err != nil {
			return AdminMutationResult[types.Environment]{}, err
		}
		env.DefaultPolicyID = pol.ID
	}

	var existing *types.Environment
	if cur, err := s.store.ResolveEnvironment(ctx, env.Code); err == nil {
		existing = &cur
		env.Code = cur.Code
	}
	if env.SafetyTier == "" {
		if existing != nil {
			env.SafetyTier = existing.SafetyTier
		} else {
			env.SafetyTier = types.SafetyTierGuarded
		}
	}
	switch env.SafetyTier {
	case types.SafetyTierYOLO, types.SafetyTierGuarded, types.SafetyTierStrict:
	default:
		return AdminMutationResult[types.Environment]{}, fmt.Errorf("invalid safety_tier %q (expected yolo, guarded, or strict)", env.SafetyTier)
	}
	if len(env.Labels) == 0 {
		if existing != nil && len(existing.Labels) > 0 {
			env.Labels = existing.Labels
		} else {
			env.Labels = map[string]string{"en": env.Code}
		}
	}
	if env.Color == "" {
		if existing != nil && existing.Color != "" {
			env.Color = existing.Color
		} else {
			env.Color = "#6B7280"
		}
	}

	action := "created"
	if existing != nil {
		if envsEqual(*existing, env) {
			action = "unchanged"
		} else {
			action = "updated"
		}
	}
	if dryRun {
		return AdminMutationResult[types.Environment]{
			DryRun: true,
			Status: planOrUnchanged(action),
			Action: action,
			Item:   env,
		}, nil
	}
	if action == "unchanged" && existing != nil {
		return AdminMutationResult[types.Environment]{
			DryRun: false,
			Status: "unchanged",
			Action: "unchanged",
			Item:   *existing,
		}, nil
	}
	saved, err := s.store.UpsertEnvironment(ctx, actor, env)
	if err != nil {
		return AdminMutationResult[types.Environment]{}, err
	}
	s.broadcast(Event{Type: "catalog_updated", Data: map[string]string{"kind": "environment", "code": saved.Code}})
	return AdminMutationResult[types.Environment]{
		DryRun: false,
		Status: action,
		Action: action,
		Item:   saved,
	}, nil
}

// AdminDeleteEnvironment removes an unreferenced Environment tier by code.
func (s *Service) AdminDeleteEnvironment(ctx context.Context, actor, code string) error {
	cur, err := s.store.ResolveEnvironment(ctx, code)
	if err != nil {
		return err
	}
	if s.IsServerMode() {
		if err := rbac.Authorize(rbac.PrincipalFromContext(ctx), rbac.ActionEnvWrite, rbac.ResourceScope{}); err != nil {
			return err
		}
	}
	if err := s.store.DeleteEnvironment(ctx, s.effectiveActor(ctx, actor), cur.Code); err != nil {
		return err
	}
	s.broadcast(Event{Type: "catalog_updated", Data: map[string]string{"kind": "environment", "code": cur.Code}})
	return nil
}

// AdminUpsertNetworkProfile creates or updates a NetworkProfile idempotently with optional dry-run.
func (s *Service) AdminUpsertNetworkProfile(ctx context.Context, actor string, np types.NetworkProfile, dryRun bool) (AdminMutationResult[types.NetworkProfile], error) {
	actor = s.effectiveActor(ctx, actor)
	if strings.TrimSpace(np.Name) == "" {
		return AdminMutationResult[types.NetworkProfile]{}, fmt.Errorf("network profile name is required")
	}
	if np.BastionCredentialID != "" {
		cp, err := s.store.ResolveCredentialProfile(ctx, np.BastionCredentialID)
		if err != nil {
			return AdminMutationResult[types.NetworkProfile]{}, err
		}
		np.BastionCredentialID = cp.ID
	}

	var existing *types.NetworkProfile
	if np.ID != "" {
		if cur, err := s.store.ResolveNetworkProfile(ctx, np.ID); err == nil {
			existing = &cur
		}
	} else if cur, err := s.store.ResolveNetworkProfile(ctx, np.Name); err == nil {
		existing = &cur
		np.ID = cur.ID
	}
	if np.ScopeType == "" && existing != nil {
		np.ScopeType = existing.ScopeType
		np.ScopeID = existing.ScopeID
	}
	if np.ScopeType == "" {
		np.ScopeType = "global"
	}
	if np.ScopeType == "global" && np.ScopeID == "" {
		np.ScopeID = "global"
	}
	if err := s.authorizeScopedWrite(ctx, rbac.ActionNetworkWrite, np.ScopeType, np.ScopeID); err != nil {
		return AdminMutationResult[types.NetworkProfile]{}, err
	}
	if existing != nil && s.IsServerMode() {
		if err := s.authorizeScopedWrite(ctx, rbac.ActionNetworkWrite, existing.ScopeType, existing.ScopeID); err != nil {
			return AdminMutationResult[types.NetworkProfile]{}, err
		}
	}

	if np.Mode == "" {
		if existing != nil {
			np.Mode = existing.Mode
		} else {
			np.Mode = types.NetworkDirect
		}
	}
	switch np.Mode {
	case types.NetworkDirect, types.NetworkSSHTunnel, types.NetworkSOCKS5, types.NetworkHTTPProxy:
	default:
		return AdminMutationResult[types.NetworkProfile]{}, fmt.Errorf("invalid network mode %q (expected direct, ssh_tunnel, socks5, or http_proxy)", np.Mode)
	}
	if err := validateProxyURL(np.ProxyURL, s.IsServerMode()); err != nil {
		return AdminMutationResult[types.NetworkProfile]{}, err
	}
	if np.BastionPort == 0 && np.Mode == types.NetworkSSHTunnel {
		np.BastionPort = 22
	}

	action := "created"
	if existing != nil {
		if netsEqual(*existing, np) {
			action = "unchanged"
		} else {
			action = "updated"
		}
	}
	if dryRun {
		return AdminMutationResult[types.NetworkProfile]{
			DryRun: true,
			Status: planOrUnchanged(action),
			Action: action,
			Item:   np,
		}, nil
	}
	if action == "unchanged" && existing != nil {
		return AdminMutationResult[types.NetworkProfile]{
			DryRun: false,
			Status: "unchanged",
			Action: "unchanged",
			Item:   *existing,
		}, nil
	}
	saved, err := s.store.UpsertNetworkProfile(ctx, actor, np)
	if err != nil {
		return AdminMutationResult[types.NetworkProfile]{}, err
	}
	s.InvalidateCatalogPools("network_profile", saved.ID)
	s.broadcast(Event{Type: "catalog_updated", Data: map[string]string{"kind": "network_profile", "id": saved.ID}})
	return AdminMutationResult[types.NetworkProfile]{
		DryRun: false,
		Status: action,
		Action: action,
		Item:   saved,
	}, nil
}

// AdminDeleteNetworkProfile removes a NetworkProfile by ID or name.
func (s *Service) AdminDeleteNetworkProfile(ctx context.Context, actor, idOrName string) error {
	cur, err := s.store.ResolveNetworkProfile(ctx, idOrName)
	if err != nil {
		return err
	}
	if err := s.authorizeScopedWrite(ctx, rbac.ActionNetworkWrite, cur.ScopeType, cur.ScopeID); err != nil {
		return err
	}
	if err := s.store.DeleteNetworkProfile(ctx, s.effectiveActor(ctx, actor), cur.ID); err != nil {
		return err
	}
	s.InvalidateCatalogPools("network_profile", cur.ID)
	s.broadcast(Event{Type: "catalog_updated", Data: map[string]string{"kind": "network_profile", "id": cur.ID}})
	return nil
}

// AdminUpsertCredentialProfile creates/updates credential metadata and optionally writes/clears the OS secret.
func (s *Service) AdminUpsertCredentialProfile(ctx context.Context, actor string, req CredentialUpsertRequest) (AdminMutationResult[types.CredentialProfile], error) {
	actor = s.effectiveActor(ctx, actor)
	cp := req.CredentialProfile
	if strings.TrimSpace(cp.Name) == "" {
		return AdminMutationResult[types.CredentialProfile]{}, fmt.Errorf("credential name is required")
	}

	var existing *types.CredentialProfile
	if cp.ID != "" {
		if cur, err := s.store.ResolveCredentialProfile(ctx, cp.ID); err == nil {
			existing = &cur
		}
	} else if cur, err := s.store.ResolveCredentialProfile(ctx, cp.Name); err == nil {
		existing = &cur
		cp.ID = cur.ID
	}
	if cp.ScopeType == "" && existing != nil {
		cp.ScopeType = existing.ScopeType
		cp.ScopeID = existing.ScopeID
	}
	if cp.ScopeType == "" {
		cp.ScopeType = "global"
	}
	if cp.ScopeType == "global" && cp.ScopeID == "" {
		cp.ScopeID = "global"
	}

	if cp.Kind == "" {
		if existing != nil {
			cp.Kind = existing.Kind
		} else {
			cp.Kind = types.CredKeychain
		}
	}
	switch cp.Kind {
	case types.CredKeychain, types.CredEnvRef, types.CredExecProvider:
	default:
		return AdminMutationResult[types.CredentialProfile]{}, fmt.Errorf("invalid credential kind %q (expected keychain, env_ref, or exec_provider)", cp.Kind)
	}
	if cp.AccessLevel == "" {
		if existing != nil {
			cp.AccessLevel = existing.AccessLevel
		} else {
			cp.AccessLevel = types.AccessReadOnly
		}
	}
	switch cp.AccessLevel {
	case types.AccessReadOnly, types.AccessReadWrite:
	default:
		return AdminMutationResult[types.CredentialProfile]{}, fmt.Errorf("invalid access_level %q (expected read_only or read_write)", cp.AccessLevel)
	}
	if cp.Kind == types.CredEnvRef && strings.TrimSpace(cp.EnvVarName) == "" {
		return AdminMutationResult[types.CredentialProfile]{}, fmt.Errorf("env_var_name is required for env_ref credential")
	}
	if cp.Kind == types.CredExecProvider && strings.TrimSpace(cp.ExecCommand) == "" {
		return AdminMutationResult[types.CredentialProfile]{}, fmt.Errorf("exec_command is required for exec_provider credential")
	}
	if err := s.validateServerCred(ctx, cp); err != nil {
		return AdminMutationResult[types.CredentialProfile]{}, err
	}
	if existing != nil && s.IsServerMode() {
		if err := s.authorizeScopedWrite(ctx, rbac.ActionCredentialWrite, existing.ScopeType, existing.ScopeID); err != nil {
			return AdminMutationResult[types.CredentialProfile]{}, err
		}
	}

	metaAction := "created"
	if existing != nil {
		if credsEqual(*existing, cp) {
			metaAction = "unchanged"
		} else {
			metaAction = "updated"
		}
	}
	secretChange := (cp.Kind == types.CredKeychain) && ((req.SecretProvided && req.SecretValue != "") || req.ClearSecret)
	overallAction := metaAction
	if overallAction == "unchanged" && secretChange {
		overallAction = "updated"
	}

	if req.DryRun {
		if existing != nil {
			cp.HasSecret = s.hasCredentialSecret(ctx, *existing)
		}
		if cp.Kind == types.CredKeychain {
			if req.ClearSecret {
				cp.HasSecret = false
			} else if req.SecretProvided && req.SecretValue != "" {
				cp.HasSecret = true
			}
		} else {
			cp.HasSecret = s.hasCredentialSecret(ctx, cp)
		}
		res := AdminMutationResult[types.CredentialProfile]{
			DryRun: true,
			Status: planOrUnchanged(overallAction),
			Action: overallAction,
			Item:   cp,
		}
		if cp.Kind == types.CredKeychain && !cp.HasSecret {
			res.MissingSecrets = []types.MissingSecretInfo{{
				ID:          cp.ID,
				Name:        cp.Name,
				Username:    cp.Username,
				AccessLevel: cp.AccessLevel,
				SetupURL:    s.CredentialSetupURL(cp.ID),
			}}
		}
		return res, nil
	}

	var saved types.CredentialProfile
	if metaAction == "unchanged" && existing != nil {
		saved = *existing
	} else {
		var err error
		saved, err = s.store.UpsertCredentialProfile(ctx, actor, cp)
		if err != nil {
			return AdminMutationResult[types.CredentialProfile]{}, err
		}
	}

	if cp.Kind == types.CredKeychain {
		if req.ClearSecret {
			if err := s.secrets.Delete(ctx, "cred:"+saved.ID); err != nil {
				return AdminMutationResult[types.CredentialProfile]{}, fmt.Errorf("delete secret failed: %w", err)
			}
			_ = s.store.RecordAuditEvent(ctx, actor, "credential_secret.clear", saved.ID, "", map[string]any{"name": saved.Name})
		} else if req.SecretProvided && req.SecretValue != "" {
			if err := s.secrets.Put(ctx, "cred:"+saved.ID, req.SecretValue); err != nil {
				return AdminMutationResult[types.CredentialProfile]{}, fmt.Errorf("save secret failed: %w", err)
			}
			_ = s.store.RecordAuditEvent(ctx, actor, "credential_secret.set", saved.ID, "", map[string]any{"name": saved.Name})
		}
	}

	saved.HasSecret = s.hasCredentialSecret(ctx, saved)
	if overallAction != "unchanged" {
		s.InvalidateCatalogPools("credential", saved.ID)
		s.broadcast(Event{Type: "catalog_updated", Data: map[string]string{"kind": "credential", "id": saved.ID}})
	}
	res := AdminMutationResult[types.CredentialProfile]{
		DryRun: false,
		Status: overallAction,
		Action: overallAction,
		Item:   saved,
	}
	if saved.Kind == types.CredKeychain && !saved.HasSecret {
		res.MissingSecrets = []types.MissingSecretInfo{{
			ID:          saved.ID,
			Name:        saved.Name,
			Username:    saved.Username,
			AccessLevel: saved.AccessLevel,
			SetupURL:    s.CredentialSetupURL(saved.ID),
		}}
	}
	return res, nil
}

// AdminDeleteCredentialProfile removes a CredentialProfile and its stored secret if unreferenced.
func (s *Service) AdminDeleteCredentialProfile(ctx context.Context, actor, idOrName string) error {
	cur, err := s.store.ResolveCredentialProfile(ctx, idOrName)
	if err != nil {
		return err
	}
	if s.IsServerMode() {
		if err := s.authorizeScopedWrite(ctx, rbac.ActionCredentialWrite, cur.ScopeType, cur.ScopeID); err != nil {
			return err
		}
		if cur.Kind == types.CredExecProvider || cur.Kind == types.CredEnvRef {
			if err := rbac.Authorize(rbac.PrincipalFromContext(ctx), rbac.ActionCredentialExecWrite, rbac.ResourceScope{}); err != nil {
				return err
			}
		}
	}
	if err := s.store.DeleteCredentialProfile(ctx, s.effectiveActor(ctx, actor), cur.ID); err != nil {
		return err
	}
	_ = s.secrets.Delete(ctx, "cred:"+cur.ID)
	s.InvalidateCatalogPools("credential", cur.ID)
	s.broadcast(Event{Type: "catalog_updated", Data: map[string]string{"kind": "credential", "id": cur.ID}})
	return nil
}

// AdminUpsertInstance creates or updates an Instance idempotently with optional dry-run.
func (s *Service) AdminUpsertInstance(ctx context.Context, actor string, inst types.Instance, dryRun bool) (AdminMutationResult[types.Instance], error) {
	actor = s.effectiveActor(ctx, actor)
	if strings.TrimSpace(inst.Name) == "" {
		return AdminMutationResult[types.Instance]{}, fmt.Errorf("instance name is required")
	}
	if inst.NetworkProfileID != "" {
		np, err := s.store.ResolveNetworkProfile(ctx, inst.NetworkProfileID)
		if err != nil {
			return AdminMutationResult[types.Instance]{}, err
		}
		inst.NetworkProfileID = np.ID
	}
	if inst.PrimaryInstanceID != "" {
		prim, err := s.store.ResolveInstance(ctx, inst.PrimaryInstanceID)
		if err != nil {
			return AdminMutationResult[types.Instance]{}, err
		}
		inst.PrimaryInstanceID = prim.ID
	}

	var existing *types.Instance
	if inst.ID != "" {
		if cur, err := s.store.ResolveInstance(ctx, inst.ID); err == nil {
			existing = &cur
		}
	} else if cur, err := s.store.ResolveInstance(ctx, inst.Name); err == nil {
		existing = &cur
		inst.ID = cur.ID
	}
	if inst.ScopeType == "" && existing != nil {
		inst.ScopeType = existing.ScopeType
		inst.ScopeID = existing.ScopeID
	}
	if inst.ScopeType == "" {
		inst.ScopeType = "global"
	}
	if inst.ScopeType == "global" && inst.ScopeID == "" {
		inst.ScopeID = "global"
	}
	if err := s.authorizeScopedWrite(ctx, rbac.ActionInstanceWrite, inst.ScopeType, inst.ScopeID); err != nil {
		return AdminMutationResult[types.Instance]{}, err
	}
	if existing != nil && s.IsServerMode() {
		if err := s.authorizeScopedWrite(ctx, rbac.ActionInstanceWrite, existing.ScopeType, existing.ScopeID); err != nil {
			return AdminMutationResult[types.Instance]{}, err
		}
	}

	if inst.Engine == "" && existing != nil {
		inst.Engine = existing.Engine
	}
	if strings.TrimSpace(inst.Engine) == "" {
		return AdminMutationResult[types.Instance]{}, fmt.Errorf("instance engine is required")
	}
	if _, ok := s.drivers.Get(inst.Engine); !ok {
		return AdminMutationResult[types.Instance]{}, fmt.Errorf("unsupported engine %q (run `driver list` to inspect registered engines)", inst.Engine)
	}
	if s.IsServerMode() && classify.CanonicalEngine(inst.Engine) == "sqlite" && !s.ServerConfig().AllowSQLiteTargets {
		return AdminMutationResult[types.Instance]{}, fmt.Errorf("forbidden: sqlite targets are disabled in server mode")
	}
	if s.IsServerMode() && inst.NetworkProfileID != "" && !rbac.IsPlatformAdmin(rbac.PrincipalFromContext(ctx)) {
		if np, err := s.store.ResolveNetworkProfile(ctx, inst.NetworkProfileID); err == nil {
			if np.ScopeType == "system" && (inst.ScopeType != "system" || inst.ScopeID != np.ScopeID) {
				return AdminMutationResult[types.Instance]{}, fmt.Errorf("forbidden: cannot bind network profile %q across systems", np.Name)
			}
		}
	}
	if inst.Role == "" {
		if existing != nil {
			inst.Role = existing.Role
		} else {
			inst.Role = types.RoleStandalone
		}
	}
	switch inst.Role {
	case types.RoleStandalone, types.RolePrimary, types.RoleReplica:
	default:
		return AdminMutationResult[types.Instance]{}, fmt.Errorf("invalid role %q (expected standalone, primary, or replica)", inst.Role)
	}
	if inst.Port == 0 && classify.CanonicalEngine(inst.Engine) != "sqlite" {
		if existing != nil && existing.Port > 0 {
			inst.Port = existing.Port
		} else {
			inst.Port = DefaultPortForEngine(inst.Engine)
		}
	}
	if inst.Params == nil {
		if existing != nil && existing.Params != nil {
			inst.Params = existing.Params
		} else {
			inst.Params = map[string]string{}
		}
	}

	action := "created"
	if existing != nil {
		if instsEqual(*existing, inst) {
			action = "unchanged"
		} else {
			action = "updated"
		}
	}
	if dryRun {
		return AdminMutationResult[types.Instance]{
			DryRun: true,
			Status: planOrUnchanged(action),
			Action: action,
			Item:   inst,
		}, nil
	}
	if action == "unchanged" && existing != nil {
		return AdminMutationResult[types.Instance]{
			DryRun: false,
			Status: "unchanged",
			Action: "unchanged",
			Item:   *existing,
		}, nil
	}
	saved, err := s.store.UpsertInstance(ctx, actor, inst)
	if err != nil {
		return AdminMutationResult[types.Instance]{}, err
	}
	s.InvalidateCatalogPools("instance", saved.ID)
	s.broadcast(Event{Type: "catalog_updated", Data: map[string]string{"kind": "instance", "id": saved.ID}})
	return AdminMutationResult[types.Instance]{
		DryRun: false,
		Status: action,
		Action: action,
		Item:   saved,
	}, nil
}

// AdminDeleteInstance removes an Instance by ID or name.
func (s *Service) AdminDeleteInstance(ctx context.Context, actor, idOrName string) error {
	cur, err := s.store.ResolveInstance(ctx, idOrName)
	if err != nil {
		return err
	}
	if err := s.authorizeScopedWrite(ctx, rbac.ActionInstanceWrite, cur.ScopeType, cur.ScopeID); err != nil {
		return err
	}
	if err := s.store.DeleteInstance(ctx, s.effectiveActor(ctx, actor), cur.ID); err != nil {
		return err
	}
	s.InvalidateCatalogPools("instance", cur.ID)
	s.broadcast(Event{Type: "catalog_updated", Data: map[string]string{"kind": "instance", "id": cur.ID}})
	return nil
}

// AdminTestInstance probes an instance resolved by ID or name and credential ID or name.
func (s *Service) AdminTestInstance(ctx context.Context, instanceRef, credRef, dbName string) (types.PingResult, error) {
	inst, err := s.store.ResolveInstance(ctx, instanceRef)
	if err != nil {
		return types.PingResult{}, err
	}
	credID := ""
	if strings.TrimSpace(credRef) != "" {
		cp, err := s.store.ResolveCredentialProfile(ctx, credRef)
		if err != nil {
			return types.PingResult{}, err
		}
		credID = cp.ID
	}
	return s.PingInstance(ctx, inst.ID, credID, dbName)
}

// AdminDiscoverInstance discovers databases on an instance resolved by ID or name.
func (s *Service) AdminDiscoverInstance(ctx context.Context, instanceRef, credRef, dbName string) (types.Instance, []string, error) {
	inst, err := s.store.ResolveInstance(ctx, instanceRef)
	if err != nil {
		return types.Instance{}, nil, err
	}
	credID := ""
	if strings.TrimSpace(credRef) != "" {
		cp, err := s.store.ResolveCredentialProfile(ctx, credRef)
		if err != nil {
			return types.Instance{}, nil, err
		}
		credID = cp.ID
	}
	dbs, err := s.DiscoverInstance(ctx, inst.ID, credID, dbName)
	return inst, dbs, err
}

// AdminUpsertTarget creates or updates a Target idempotently, accepting IDs or natural keys.
func (s *Service) AdminUpsertTarget(ctx context.Context, actor string, tgt types.Target, dryRun bool) (AdminMutationResult[types.Target], error) {
	actor = s.effectiveActor(ctx, actor)
	var existing *types.Target
	if tgt.ID != "" {
		if cur, err := s.store.ResolveTargetRecord(ctx, tgt.ID); err == nil {
			existing = &cur
		}
	} else if tgt.Ref != "" {
		if cur, err := s.store.ResolveTargetRecord(ctx, tgt.Ref); err == nil {
			existing = &cur
			tgt.ID = cur.ID
		}
	}

	if tgt.OwnerSystemID != "" {
		sys, err := s.store.ResolveSystem(ctx, tgt.OwnerSystemID)
		if err != nil {
			return AdminMutationResult[types.Target]{}, err
		}
		tgt.OwnerSystemID = sys.ID
	} else if existing != nil {
		tgt.OwnerSystemID = existing.OwnerSystemID
	}

	if tgt.LinkedSystemIDs != nil {
		var linked []string
		for _, lid := range tgt.LinkedSystemIDs {
			if strings.TrimSpace(lid) == "" {
				continue
			}
			sys, err := s.store.ResolveSystem(ctx, lid)
			if err != nil {
				return AdminMutationResult[types.Target]{}, err
			}
			linked = append(linked, sys.ID)
		}
		tgt.LinkedSystemIDs = linked
	} else if existing != nil {
		tgt.LinkedSystemIDs = existing.LinkedSystemIDs
	}

	if tgt.EnvironmentCode != "" {
		env, err := s.store.ResolveEnvironment(ctx, tgt.EnvironmentCode)
		if err != nil {
			return AdminMutationResult[types.Target]{}, err
		}
		tgt.EnvironmentCode = env.Code
	} else if existing != nil {
		tgt.EnvironmentCode = existing.EnvironmentCode
	}

	if tgt.InstanceID != "" {
		inst, err := s.store.ResolveInstance(ctx, tgt.InstanceID)
		if err != nil {
			return AdminMutationResult[types.Target]{}, err
		}
		tgt.InstanceID = inst.ID
	} else if existing != nil {
		tgt.InstanceID = existing.InstanceID
	}

	if tgt.ROCredentialID != "" {
		cp, err := s.store.ResolveCredentialProfile(ctx, tgt.ROCredentialID)
		if err != nil {
			return AdminMutationResult[types.Target]{}, err
		}
		tgt.ROCredentialID = cp.ID
	}
	if tgt.RWCredentialID != "" {
		cp, err := s.store.ResolveCredentialProfile(ctx, tgt.RWCredentialID)
		if err != nil {
			return AdminMutationResult[types.Target]{}, err
		}
		tgt.RWCredentialID = cp.ID
	}
	if tgt.PolicyOverrideID != "" {
		pol, err := s.store.ResolvePolicy(ctx, tgt.PolicyOverrideID)
		if err != nil {
			return AdminMutationResult[types.Target]{}, err
		}
		tgt.PolicyOverrideID = pol.ID
	}
	if tgt.Status == "" {
		if existing != nil {
			tgt.Status = existing.Status
		} else {
			tgt.Status = types.TargetActive
		}
	}
	switch tgt.Status {
	case types.TargetActive, types.TargetMaintenance, types.TargetDisabled:
	default:
		return AdminMutationResult[types.Target]{}, fmt.Errorf("invalid target status %q (expected active, maintenance, or disabled)", tgt.Status)
	}
	if s.IsServerMode() {
		if err := rbac.Authorize(rbac.PrincipalFromContext(ctx), rbac.ActionTargetWrite, rbac.ResourceScope{
			SystemID:        tgt.OwnerSystemID,
			LinkedSystemIDs: tgt.LinkedSystemIDs,
			EnvironmentCode: tgt.EnvironmentCode,
		}); err != nil {
			return AdminMutationResult[types.Target]{}, err
		}
		if existing != nil && existing.OwnerSystemID != "" && existing.OwnerSystemID != tgt.OwnerSystemID {
			if err := rbac.Authorize(rbac.PrincipalFromContext(ctx), rbac.ActionTargetWrite, rbac.ResourceScope{
				SystemID:        existing.OwnerSystemID,
				EnvironmentCode: existing.EnvironmentCode,
			}); err != nil {
				return AdminMutationResult[types.Target]{}, err
			}
		}
		if err := s.validateServerTargetBindings(ctx, tgt); err != nil {
			return AdminMutationResult[types.Target]{}, err
		}
	}

	action := "created"
	if existing != nil {
		if targetsEqual(*existing, tgt) {
			action = "unchanged"
		} else {
			action = "updated"
		}
	}
	if dryRun {
		return AdminMutationResult[types.Target]{
			DryRun: true,
			Status: planOrUnchanged(action),
			Action: action,
			Item:   tgt,
		}, nil
	}
	if action == "unchanged" && existing != nil {
		return AdminMutationResult[types.Target]{
			DryRun: false,
			Status: "unchanged",
			Action: "unchanged",
			Item:   *existing,
		}, nil
	}
	saved, err := s.store.UpsertTarget(ctx, actor, tgt)
	if err != nil {
		return AdminMutationResult[types.Target]{}, err
	}
	s.InvalidateCatalogPools("target", saved.ID)
	s.broadcast(Event{Type: "catalog_updated", Data: map[string]string{"kind": "target", "id": saved.ID}})
	return AdminMutationResult[types.Target]{
		DryRun: false,
		Status: action,
		Action: action,
		Item:   saved,
	}, nil
}

// AdminDeleteTarget removes a Target by ID, ref, or alias and reports any newly orphaned instances, credentials, or custom environments.
func (s *Service) AdminDeleteTarget(ctx context.Context, actor, idOrRefOrAlias string) (TargetDeleteResult, error) {
	cur, err := s.store.ResolveTargetRecord(ctx, idOrRefOrAlias)
	if err != nil {
		return TargetDeleteResult{}, err
	}
	if s.IsServerMode() {
		if err := rbac.Authorize(rbac.PrincipalFromContext(ctx), rbac.ActionTargetWrite, rbac.ResourceScope{
			SystemID:        cur.OwnerSystemID,
			LinkedSystemIDs: cur.LinkedSystemIDs,
			EnvironmentCode: cur.EnvironmentCode,
		}); err != nil {
			return TargetDeleteResult{}, err
		}
	}
	if err := s.store.DeleteTarget(ctx, s.effectiveActor(ctx, actor), cur.ID); err != nil {
		return TargetDeleteResult{}, err
	}
	s.InvalidateCatalogPools("target", cur.ID)
	s.broadcast(Event{Type: "catalog_updated", Data: map[string]string{"kind": "target", "id": cur.ID}})

	orphans := s.findOrphansAfterTargetDelete(ctx, cur)
	res := TargetDeleteResult{
		Deleted: true,
		Target:  firstNonEmpty(cur.Ref, cur.ID),
		Orphans: orphans,
	}
	if len(orphans) > 0 {
		res.Hint = "Target deleted; unreferenced instance, credential, or custom environment assets remain. Run the suggested commands if you want to clean them up."
		for _, o := range orphans {
			res.NextCommands = append(res.NextCommands, o.Command)
		}
	}
	return res, nil
}

func (s *Service) findOrphansAfterTargetDelete(ctx context.Context, deleted types.Target) []OrphanResource {
	targets, err := s.store.ListTargets(ctx)
	if err != nil {
		return nil
	}
	instances, _ := s.store.ListInstances(ctx)
	nets, _ := s.store.ListNetworkProfiles(ctx)

	var orphans []OrphanResource
	if deleted.InstanceID != "" {
		inUse := false
		for _, t := range targets {
			if t.InstanceID == deleted.InstanceID {
				inUse = true
				break
			}
		}
		if !inUse {
			for _, inst := range instances {
				if inst.PrimaryInstanceID == deleted.InstanceID {
					inUse = true
					break
				}
			}
		}
		if !inUse {
			for _, inst := range instances {
				if inst.ID == deleted.InstanceID {
					orphans = append(orphans, OrphanResource{
						Kind:    "instance",
						ID:      inst.ID,
						Name:    inst.Name,
						Command: fmt.Sprintf("agent-dbctl instance delete %s --yes --json", inst.Name),
					})
					break
				}
			}
		}
	}

	seenCred := map[string]bool{}
	for _, cid := range []string{deleted.ROCredentialID, deleted.RWCredentialID} {
		if cid == "" || seenCred[cid] {
			continue
		}
		seenCred[cid] = true
		inUse := false
		for _, t := range targets {
			if t.ROCredentialID == cid || t.RWCredentialID == cid {
				inUse = true
				break
			}
		}
		if !inUse {
			for _, np := range nets {
				if np.BastionCredentialID == cid {
					inUse = true
					break
				}
			}
		}
		if !inUse {
			if cp, cErr := s.store.ResolveCredentialProfile(ctx, cid); cErr == nil {
				orphans = append(orphans, OrphanResource{
					Kind:    "credential",
					ID:      cp.ID,
					Name:    cp.Name,
					Command: fmt.Sprintf("agent-dbctl cred delete %s --yes --json", cp.Name),
				})
			}
		}
	}

	envCode := strings.TrimSpace(deleted.EnvironmentCode)
	if envCode != "" && envCode != "dev" && envCode != "staging" && envCode != "prod" {
		inUse := false
		for _, t := range targets {
			if strings.EqualFold(t.EnvironmentCode, envCode) {
				inUse = true
				break
			}
		}
		if !inUse {
			if envObj, eErr := s.store.ResolveEnvironment(ctx, envCode); eErr == nil {
				orphans = append(orphans, OrphanResource{
					Kind:    "environment",
					ID:      envObj.Code,
					Name:    envObj.Code,
					Command: fmt.Sprintf("agent-dbctl env delete %s --yes --json", envObj.Code),
				})
			}
		}
	}
	return orphans
}

// AdminAddDatabase performs declarative one-shot onboarding (System + Credential + Instance + Target).
func (s *Service) AdminAddDatabase(ctx context.Context, actor string, req DBAddRequest) (DBAddResponse, error) {
	actor = s.effectiveActor(ctx, actor)
	var warnings []string

	switch req.ScanReadMode {
	case "", types.ScanReadAllow, types.ScanReadReasonOnly, types.ScanReadRequireApproval:
	default:
		return DBAddResponse{}, fmt.Errorf("invalid scan_read_mode %q (expected allow, reason_only, or require_approval)", req.ScanReadMode)
	}
	switch req.SafetyTier {
	case "", types.SafetyTierYOLO, types.SafetyTierGuarded, types.SafetyTierStrict:
	default:
		return DBAddResponse{}, fmt.Errorf("invalid safety_tier %q (expected yolo, guarded, or strict)", req.SafetyTier)
	}
	switch req.AccessLevel {
	case "", types.AccessReadOnly, types.AccessReadWrite:
	default:
		return DBAddResponse{}, fmt.Errorf("invalid access_level %q (expected read_only or read_write)", req.AccessLevel)
	}

	var parsed ParsedDSN
	if strings.TrimSpace(req.DSN) != "" {
		var err error
		parsed, err = ParseDSN(req.DSN, req.Engine)
		if err != nil {
			return DBAddResponse{}, err
		}
		if req.InlinePasswordWarning && parsed.HasPassword {
			warnings = append(warnings, "Inline DSN password detected; prefer leaving password blank with --open-secret or using --dsn-env / --secret-env / --secret-stdin.")
		}
	}

	engine := firstNonEmpty(strings.TrimSpace(req.Engine), parsed.Engine)
	if engine == "" {
		return DBAddResponse{}, fmt.Errorf("engine is required (pass --engine or --dsn)")
	}
	if _, ok := s.drivers.Get(engine); !ok {
		return DBAddResponse{}, fmt.Errorf("unsupported engine %q (run `driver list` to inspect registered engines)", engine)
	}
	canonEngine := classify.CanonicalEngine(engine)
	if s.IsServerMode() && canonEngine == "sqlite" && !s.ServerConfig().AllowSQLiteTargets {
		return DBAddResponse{}, fmt.Errorf("forbidden: sqlite targets are disabled in server mode")
	}

	host := firstNonEmpty(strings.TrimSpace(req.Host), parsed.Host)
	dbName := firstNonEmpty(strings.TrimSpace(req.Database), parsed.DatabaseName)
	if canonEngine == "sqlite" {
		if host == "" && dbName != "" {
			host = dbName
		}
		if dbName == "" && host != "" {
			dbName = host
		}
		if host == "" {
			return DBAddResponse{}, fmt.Errorf("sqlite target requires --host <path>, --database <path>, or --dsn")
		}
	} else if host == "" {
		return DBAddResponse{}, fmt.Errorf("host is required for engine %q (pass --host or --dsn)", engine)
	}

	port := req.Port
	if port <= 0 {
		port = parsed.Port
	}
	if port <= 0 && canonEngine != "sqlite" {
		port = DefaultPortForEngine(engine)
	}

	tlsMode := firstNonEmpty(strings.TrimSpace(req.TLSMode), parsed.TLSMode)
	params := map[string]string{}
	for k, v := range parsed.Params {
		params[k] = v
	}
	for k, v := range req.Params {
		params[k] = v
	}

	// 1. System resolution / auto-creation.
	sysGitRemotes := config.NormalizeGitRemotes(req.GitRemotes)
	if len(sysGitRemotes) == 0 && !req.NoWorkspace && len(req.WorkspaceGitRemotes) > 0 {
		sysGitRemotes = config.NormalizeGitRemotes(req.WorkspaceGitRemotes)
	}

	sysSlug := strings.TrimSpace(req.System)
	if sysSlug == "" && !req.NoWorkspace {
		wsCWD := req.WorkspaceCWD
		if s.IsServerMode() {
			wsCWD = ""
		}
		if matched := s.resolveSystemByWorkspace(ctx, wsCWD, sysGitRemotes); matched != nil {
			sysSlug = matched.Slug
		}
	}
	if sysSlug == "" && !req.NoWorkspace {
		if len(sysGitRemotes) > 0 {
			if repoSlug := sanitizeSlug(config.RepoNameFromGitRemote(sysGitRemotes[0])); repoSlug != "" {
				sysSlug = repoSlug
			}
		}
		if !s.IsServerMode() && sysSlug == "" && strings.TrimSpace(req.WorkspaceCWD) != "" {
			base := sanitizeSlug(filepath.Base(filepath.Clean(req.WorkspaceCWD)))
			if base != "" && base != "." {
				sysSlug = base
			}
		}
	}
	if sysSlug == "" {
		sysSlug = "default"
	}

	var sysWS []string
	if !s.IsServerMode() {
		for _, ws := range req.WorkspacePaths {
			if trimmed := strings.TrimSpace(ws); trimmed != "" {
				sysWS = append(sysWS, trimmed)
			}
		}
		if len(sysWS) == 0 && !req.NoWorkspace && strings.TrimSpace(req.WorkspaceCWD) != "" {
			sysWS = []string{req.WorkspaceCWD}
		}
	}

	var sysObj types.System
	sysAction := "created"
	if existingSys, err := s.store.ResolveSystem(ctx, sysSlug); err == nil {
		sysObj = existingSys
		if s.IsServerMode() {
			if err := rbac.Authorize(rbac.PrincipalFromContext(ctx), rbac.ActionTargetWrite, rbac.ResourceScope{
				SystemID:   existingSys.ID,
				SystemSlug: existingSys.Slug,
			}); err != nil {
				return DBAddResponse{}, err
			}
		}
		mergedWS := mergeUniqueStrings(existingSys.WorkspacePaths, sysWS)
		existingRemotes := config.NormalizeGitRemotes(existingSys.GitRemotes)
		mergedRemotes := config.NormalizeGitRemotes(append(append([]string(nil), existingRemotes...), sysGitRemotes...))
		nameChanged := req.SystemName != "" && req.SystemName != existingSys.Name
		if nameChanged {
			sysObj.Name = req.SystemName
		}
		wsChanged := len(mergedWS) != len(existingSys.WorkspacePaths)
		if wsChanged {
			sysObj.WorkspacePaths = mergedWS
		}
		gitChanged := !reflect.DeepEqual(mergedRemotes, existingRemotes)
		if gitChanged {
			sysObj.GitRemotes = mergedRemotes
		}
		if nameChanged || wsChanged || gitChanged {
			sysAction = "updated"
			if s.IsServerMode() {
				if err := rbac.Authorize(rbac.PrincipalFromContext(ctx), rbac.ActionSystemWrite, rbac.ResourceScope{
					SystemID:   existingSys.ID,
					SystemSlug: existingSys.Slug,
				}); err != nil {
					return DBAddResponse{}, err
				}
			}
		} else {
			sysAction = "unchanged"
		}
	} else {
		if s.IsServerMode() {
			if err := rbac.Authorize(rbac.PrincipalFromContext(ctx), rbac.ActionSystemWrite, rbac.ResourceScope{}); err != nil {
				return DBAddResponse{}, err
			}
		}
		sysName := firstNonEmpty(strings.TrimSpace(req.SystemName), titleSlug(sysSlug))
		sysObj = types.System{
			Slug:           sysSlug,
			Name:           sysName,
			WorkspacePaths: sysWS,
			GitRemotes:     sysGitRemotes,
			Tags:           []string{},
		}
	}

	// 2. Environment verification (or inline creation when --safety-tier is provided).
	envCode := firstNonEmpty(strings.TrimSpace(req.Env), "dev")
	var envObj types.Environment
	envAction := "unchanged"
	if curEnv, err := s.store.ResolveEnvironment(ctx, envCode); err == nil {
		envObj = curEnv
		if req.SafetyTier != "" && envObj.SafetyTier != req.SafetyTier {
			return DBAddResponse{}, fmt.Errorf("environment %q already exists with safety_tier %q (requested %q); run `agent-dbctl env set %s --safety-tier %s --json` to change it", envObj.Code, envObj.SafetyTier, req.SafetyTier, envObj.Code, req.SafetyTier)
		}
	} else if req.SafetyTier != "" {
		envRes, err := s.AdminUpsertEnvironment(ctx, actor, types.Environment{
			Code:       envCode,
			SafetyTier: req.SafetyTier,
		}, req.DryRun)
		if err != nil {
			return DBAddResponse{}, err
		}
		envObj = envRes.Item
		envAction = envRes.Action
	} else {
		envs, _ := s.store.ListEnvironments(ctx)
		var codes []string
		for _, e := range envs {
			codes = append(codes, e.Code)
		}
		return DBAddResponse{}, &TargetLookupError{
			Code:         types.ErrCodeNotFound,
			Message:      fmt.Sprintf("environment %q not found (available environments: %s)", envCode, strings.Join(codes, ", ")),
			SimilarNames: codes,
			Hint:         fmt.Sprintf("Create %q first with `env set`, or create it inline by passing `--safety-tier <yolo|guarded|strict>` to `db add`.", envCode),
			NextCommands: []string{
				fmt.Sprintf("agent-dbctl env set --code %s --safety-tier guarded --json", envCode),
				fmt.Sprintf("agent-dbctl db add --env %s --safety-tier guarded --json", envCode),
				"agent-dbctl env list --json",
			},
		}
	}

	// 3. NetworkProfile resolution (optional).
	netID := ""
	if strings.TrimSpace(req.Network) != "" {
		np, err := s.store.ResolveNetworkProfile(ctx, req.Network)
		if err != nil {
			nets, _ := s.store.ListNetworkProfiles(ctx)
			names := make([]string, 0, len(nets))
			for _, n := range nets {
				names = append(names, n.Name)
			}
			return DBAddResponse{}, &TargetLookupError{
				Code:         types.ErrCodeNotFound,
				Message:      fmt.Sprintf("network profile %q not found", req.Network),
				SimilarNames: names,
				Hint:         "Inspect configured network profiles with `network list` or omit --network for direct connections.",
				NextCommands: []string{"agent-dbctl network list --json"},
			}
		}
		netID = np.ID
	}

	// 4. Target ref derivation.
	dbSlug := deriveDBLabel(canonEngine, host, dbName)
	ref := strings.TrimSpace(req.Ref)
	if ref == "" {
		ref = fmt.Sprintf("%s/%s/%s", sysObj.Slug, envObj.Code, dbSlug)
	}

	// 5. Credential resolution or implicit CredentialProfile creation/reuse.
	roCredID := ""
	rwCredID := ""
	if strings.TrimSpace(req.ROCred) != "" {
		cp, err := s.store.ResolveCredentialProfile(ctx, req.ROCred)
		if err != nil {
			creds, _ := s.store.ListCredentialProfiles(ctx)
			names := make([]string, 0, len(creds))
			for _, c := range creds {
				names = append(names, c.Name)
			}
			return DBAddResponse{}, &TargetLookupError{
				Code:         types.ErrCodeNotFound,
				Message:      fmt.Sprintf("read-only credential %q not found", req.ROCred),
				SimilarNames: names,
				Hint:         "Inspect available credentials with `cred list` or let `db add` create an implicit profile via --user / --access-level.",
				NextCommands: []string{"agent-dbctl cred list --json"},
			}
		}
		roCredID = cp.ID
	}
	if strings.TrimSpace(req.RWCred) != "" {
		cp, err := s.store.ResolveCredentialProfile(ctx, req.RWCred)
		if err != nil {
			creds, _ := s.store.ListCredentialProfiles(ctx)
			names := make([]string, 0, len(creds))
			for _, c := range creds {
				names = append(names, c.Name)
			}
			return DBAddResponse{}, &TargetLookupError{
				Code:         types.ErrCodeNotFound,
				Message:      fmt.Sprintf("read-write credential %q not found", req.RWCred),
				SimilarNames: names,
				Hint:         "Inspect available credentials with `cred list` or let `db add` create an implicit profile via --user / --access-level read_write.",
				NextCommands: []string{"agent-dbctl cred list --json"},
			}
		}
		rwCredID = cp.ID
	}

	user := firstNonEmpty(strings.TrimSpace(req.User), parsed.Username)
	secretVal := req.SecretValue
	secretProvided := req.SecretProvided
	if !secretProvided && parsed.HasPassword && parsed.Password != "" {
		secretVal = parsed.Password
		secretProvided = true
	}

	var managedCredReq *CredentialUpsertRequest
	needImplicitCred := roCredID == "" && rwCredID == "" && (user != "" ||
		strings.TrimSpace(req.CredName) != "" ||
		secretProvided ||
		strings.TrimSpace(req.EnvVarName) != "" ||
		strings.TrimSpace(req.ExecCommand) != "" ||
		req.CredKind != "" ||
		canonEngine != "sqlite")
	if needImplicitCred {
		credKind := req.CredKind
		if credKind == "" {
			credKind = types.CredKeychain
		}
		accLevel := req.AccessLevel
		if accLevel == "" {
			if envObj.SafetyTier == types.SafetyTierYOLO {
				accLevel = types.AccessReadWrite
			} else {
				accLevel = types.AccessReadOnly
			}
		}
		credName := strings.TrimSpace(req.CredName)
		if credName == "" {
			credName = sanitizeSlug(ref) + "-" + string(accLevel)
		}
		managedCredReq = &CredentialUpsertRequest{
			CredentialProfile: types.CredentialProfile{
				Name:        credName,
				Kind:        credKind,
				AccessLevel: accLevel,
				Username:    user,
				EnvVarName:  strings.TrimSpace(req.EnvVarName),
				ExecCommand: strings.TrimSpace(req.ExecCommand),
				ScopeType:   func() string {
					if s.IsServerMode() && sysObj.ID != "" {
						return "system"
					}
					return "global"
				}(),
				ScopeID:     func() string {
					if s.IsServerMode() && sysObj.ID != "" {
						return sysObj.ID
					}
					return "global"
				}(),
			},
			SecretValue:    secretVal,
			SecretProvided: secretProvided,
			DryRun:         req.DryRun,
		}
	}

	// 6. Instance resolution / matching.
	instName := strings.TrimSpace(req.Instance)
	var existingInst *types.Instance
	if instName != "" {
		if cur, err := s.store.ResolveInstance(ctx, instName); err == nil {
			existingInst = &cur
		}
	} else {
		allInsts, _ := s.store.ListInstances(ctx)
		for _, cand := range allInsts {
			if strings.EqualFold(cand.Engine, engine) &&
				cand.Host == host &&
				cand.Port == port &&
				cand.NetworkProfileID == netID {
				candCopy := cand
				existingInst = &candCopy
				instName = cand.Name
				break
			}
		}
		if instName == "" {
			if canonEngine == "sqlite" {
				instName = "sqlite-" + sanitizeSlug(filepath.Base(host))
			} else {
				instName = fmt.Sprintf("%s-%s-%d", sanitizeSlug(engine), sanitizeSlug(host), port)
			}
		}
	}

	role := req.Role
	if role == "" {
		if existingInst != nil {
			role = existingInst.Role
		} else {
			role = types.RoleStandalone
		}
	}
	instInput := types.Instance{
		Name:             instName,
		Engine:           engine,
		Host:             host,
		Port:             port,
		Role:             role,
		NetworkProfileID: netID,
		TLSMode:          tlsMode,
		Params:           params,
	}
	if existingInst != nil {
		instInput.ID = existingInst.ID
		instInput.ScopeType = existingInst.ScopeType
		instInput.ScopeID = existingInst.ScopeID
		if len(instInput.Params) == 0 && len(existingInst.Params) > 0 {
			instInput.Params = existingInst.Params
		}
		if instInput.TLSMode == "" {
			instInput.TLSMode = existingInst.TLSMode
		}
	} else if s.IsServerMode() && sysObj.ID != "" && !rbac.IsPlatformAdmin(rbac.PrincipalFromContext(ctx)) {
		instInput.ScopeType = "system"
		instInput.ScopeID = sysObj.ID
	}
	if s.IsServerMode() {
		if err := s.authorizeScopedWrite(ctx, rbac.ActionInstanceWrite, instInput.ScopeType, instInput.ScopeID); err != nil {
			return DBAddResponse{}, err
		}
		if managedCredReq != nil {
			if err := s.validateServerCred(ctx, managedCredReq.CredentialProfile); err != nil {
				return DBAddResponse{}, err
			}
		}
	}

	// Plan or apply step by step.
	actions := map[string]string{
		"system":     sysAction,
		"credential": "unchanged",
		"instance":   "unchanged",
		"target":     "unchanged",
	}
	if req.SafetyTier != "" || envAction != "unchanged" {
		actions["environment"] = envAction
	}

	var missingSecrets []types.MissingSecretInfo
	if req.DryRun {
		if managedCredReq != nil {
			cRes, err := s.AdminUpsertCredentialProfile(ctx, actor, *managedCredReq)
			if err != nil {
				return DBAddResponse{}, err
			}
			actions["credential"] = cRes.Action
			missingSecrets = append(missingSecrets, cRes.MissingSecrets...)
			if managedCredReq.AccessLevel == types.AccessReadWrite {
				rwCredID = cRes.Item.ID
			} else {
				roCredID = cRes.Item.ID
			}
		} else {
			missingSecrets = append(missingSecrets, s.BuildMissingSecrets(ctx, []string{roCredID, rwCredID})...)
		}

		instAction := "created"
		if existingInst != nil {
			if instsEqual(*existingInst, instInput) {
				instAction = "unchanged"
			} else {
				instAction = "updated"
			}
		}
		actions["instance"] = instAction

		tgtInput := buildDBAddTargetInput(ref, req, sysObj.ID, envObj.Code, instInput.ID, dbName, roCredID, rwCredID)
		tgtAction := "created"
		if existingTgt, err := s.store.ResolveTargetRecord(ctx, ref); err == nil {
			tgtInput.ID = existingTgt.ID
			if existingTgt.Alias != "" && req.Alias == "" {
				tgtInput.Alias = existingTgt.Alias
			}
			if existingTgt.Description != "" && req.Description == "" {
				tgtInput.Description = existingTgt.Description
			}
			if existingTgt.ROCredentialID != "" && tgtInput.ROCredentialID == "" {
				tgtInput.ROCredentialID = existingTgt.ROCredentialID
			}
			if existingTgt.RWCredentialID != "" && tgtInput.RWCredentialID == "" {
				tgtInput.RWCredentialID = existingTgt.RWCredentialID
			}
			if existingTgt.OwnerSystemID == sysObj.ID &&
				existingTgt.EnvironmentCode == envObj.Code &&
				(existingInst != nil && existingTgt.InstanceID == existingInst.ID) &&
				existingTgt.DatabaseName == tgtInput.DatabaseName &&
				existingTgt.Alias == tgtInput.Alias &&
				existingTgt.Description == tgtInput.Description &&
				existingTgt.ROCredentialID == tgtInput.ROCredentialID &&
				existingTgt.RWCredentialID == tgtInput.RWCredentialID &&
				existingTgt.Status == tgtInput.Status {
				tgtAction = "unchanged"
			} else {
				tgtAction = "updated"
			}
		}
		actions["target"] = tgtAction

		if req.ScanReadMode != "" {
			polRes, err := s.AdminSetTargetScanReadMode(ctx, actor, tgtInput.ID, req.ScanReadMode, true)
			if err != nil {
				return DBAddResponse{}, err
			}
			actions["policy"] = polRes.Action
		}

		summary := s.dryRunTargetSummary(ctx, sysObj, envObj, tgtInput, engine, roCredID, rwCredID, req.ScanReadMode)
		overall := "planned"
		if envAction == "unchanged" && actions["system"] == "unchanged" && actions["credential"] == "unchanged" && actions["instance"] == "unchanged" && actions["target"] == "unchanged" && (actions["policy"] == "" || actions["policy"] == "unchanged") {
			overall = "unchanged"
		}
		return DBAddResponse{
			DryRun:         true,
			Status:         overall,
			AccessLevel:    summarizeTargetAccessLevel(tgtInput.ROCredentialID, tgtInput.RWCredentialID, summary.Writable),
			Target:         summary,
			Actions:        actions,
			MissingSecrets: missingSecrets,
			Warnings:       warnings,
		}, nil
	}

	// Real execution (non-dry-run): persist system, credential, instance, target.
	sysRes, err := s.AdminUpsertSystem(ctx, actor, sysObj, false)
	if err != nil {
		return DBAddResponse{}, err
	}
	sysObj = sysRes.Item
	actions["system"] = sysRes.Action

	if managedCredReq != nil {
		if s.IsServerMode() && sysObj.ID != "" {
			managedCredReq.ScopeType = "system"
			managedCredReq.ScopeID = sysObj.ID
		}
		cRes, err := s.AdminUpsertCredentialProfile(ctx, actor, *managedCredReq)
		if err != nil {
			return DBAddResponse{}, err
		}
		actions["credential"] = cRes.Action
		missingSecrets = append(missingSecrets, cRes.MissingSecrets...)
		if cRes.Item.AccessLevel == types.AccessReadWrite {
			rwCredID = cRes.Item.ID
		} else {
			roCredID = cRes.Item.ID
		}
	} else {
		missingSecrets = append(missingSecrets, s.BuildMissingSecrets(ctx, []string{roCredID, rwCredID})...)
	}

	if existingInst == nil && s.IsServerMode() && sysObj.ID != "" && !rbac.IsPlatformAdmin(rbac.PrincipalFromContext(ctx)) {
		instInput.ScopeType = "system"
		instInput.ScopeID = sysObj.ID
	}
	instRes, err := s.AdminUpsertInstance(ctx, actor, instInput, false)
	if err != nil {
		return DBAddResponse{}, err
	}
	instObj := instRes.Item
	actions["instance"] = instRes.Action

	tgtInput := buildDBAddTargetInput(ref, req, sysObj.ID, envObj.Code, instObj.ID, dbName, roCredID, rwCredID)
	if existingTgt, err := s.store.ResolveTargetRecord(ctx, ref); err == nil {
		tgtInput.ID = existingTgt.ID
		if req.Alias == "" {
			tgtInput.Alias = existingTgt.Alias
		}
		if req.Description == "" {
			tgtInput.Description = existingTgt.Description
		}
		if tgtInput.ROCredentialID == "" {
			tgtInput.ROCredentialID = existingTgt.ROCredentialID
		}
		if tgtInput.RWCredentialID == "" {
			tgtInput.RWCredentialID = existingTgt.RWCredentialID
		}
		tgtInput.PolicyOverrideID = existingTgt.PolicyOverrideID
		tgtInput.LinkedSystemIDs = existingTgt.LinkedSystemIDs
	}

	tgtRes, err := s.AdminUpsertTarget(ctx, actor, tgtInput, false)
	if err != nil {
		return DBAddResponse{}, err
	}
	actions["target"] = tgtRes.Action

	if req.ScanReadMode != "" {
		polRes, err := s.AdminSetTargetScanReadMode(ctx, actor, tgtRes.Item.ID, req.ScanReadMode, false)
		if err != nil {
			return DBAddResponse{}, err
		}
		actions["policy"] = polRes.Action
	}

	detail, err := s.ResolveTarget(ctx, tgtRes.Item.Ref, req.WorkspaceCWD, req.WorkspaceGitRemotes...)
	if err != nil {
		return DBAddResponse{}, err
	}

	overall := tgtRes.Action
	if overall == "unchanged" && (envAction != "unchanged" || actions["system"] != "unchanged" || actions["credential"] != "unchanged" || actions["instance"] != "unchanged" || (actions["policy"] != "" && actions["policy"] != "unchanged")) {
		overall = "updated"
	}

	summary := SummarizeTarget(detail)
	resp := DBAddResponse{
		DryRun:         false,
		Status:         overall,
		AccessLevel:    summarizeTargetAccessLevel(detail.Target.ROCredentialID, detail.Target.RWCredentialID, summary.Writable),
		Target:         summary,
		Actions:        actions,
		MissingSecrets: missingSecrets,
		Warnings:       warnings,
	}

	if len(missingSecrets) > 0 {
		resp.NextCommands = append(resp.NextCommands, fmt.Sprintf("agent-dbctl ui open --credential %s", missingSecrets[0].ID))
		if req.Test {
			resp.Warnings = append(resp.Warnings, fmt.Sprintf("Live connectivity test skipped because credential %q has no secret stored yet; open setup_url to enter it and run `db test`.", missingSecrets[0].Name))
		}
	} else if req.Test {
		ping := s.PingTarget(ctx, detail)
		resp.Ping = &ping
		if !ping.Reachable {
			resp.Warnings = append(resp.Warnings, fmt.Sprintf("Target saved, but connectivity probe failed: %s", ping.Error))
			resp.NextCommands = append(resp.NextCommands,
				fmt.Sprintf("agent-dbctl db show %s --json", resp.Target.Ref),
				fmt.Sprintf("agent-dbctl db test %s --json", resp.Target.Ref),
			)
		}
	}

	return resp, nil
}

// AdminApplyTopology previews (--dry-run) or atomically imports a TopologyBundle and flags missing Keychain secrets.
func (s *Service) AdminApplyTopology(ctx context.Context, actor string, bundle types.TopologyBundle, dryRun bool) (types.TopologyImportResult, error) {
	actor = s.effectiveActor(ctx, actor)
	if s.IsServerMode() {
		p := rbac.PrincipalFromContext(ctx)
		if err := rbac.Authorize(p, rbac.ActionTopologyWrite, rbac.ResourceScope{}); err != nil {
			return types.TopologyImportResult{}, err
		}
		if bundle.GlobalSecurity != nil {
			if err := rbac.Authorize(p, rbac.ActionGlobalSecurityWrite, rbac.ResourceScope{}); err != nil {
				return types.TopologyImportResult{}, err
			}
		}
		if len(bundle.Environments) > 0 {
			if err := rbac.Authorize(p, rbac.ActionEnvWrite, rbac.ResourceScope{}); err != nil {
				return types.TopologyImportResult{}, err
			}
		}
		for _, np := range bundle.NetworkProfiles {
			if err := validateProxyURL(np.ProxyURL, true); err != nil {
				return types.TopologyImportResult{}, err
			}
		}
		for _, cp := range bundle.CredentialProfiles {
			if err := s.validateServerCred(ctx, cp); err != nil {
				return types.TopologyImportResult{}, err
			}
		}
		for _, inst := range bundle.Instances {
			if classify.CanonicalEngine(inst.Engine) == "sqlite" && !s.ServerConfig().AllowSQLiteTargets {
				return types.TopologyImportResult{}, fmt.Errorf("forbidden: sqlite targets are disabled in server mode")
			}
		}
	}
	if dryRun {
		res, err := s.store.PlanTopologyImport(ctx, bundle)
		if err != nil {
			return res, err
		}
		res.MissingSecrets = s.missingSecretsForTopologyPlan(ctx, bundle)
		return res, nil
	}
	res, err := s.store.ImportTopologyWithResult(ctx, actor, bundle)
	if err != nil {
		return res, err
	}
	var credIDs []string
	for _, cp := range bundle.CredentialProfiles {
		if resolved, rErr := s.store.ResolveCredentialProfile(ctx, firstNonEmpty(cp.ID, cp.Name)); rErr == nil {
			credIDs = append(credIDs, resolved.ID)
		}
	}
	if len(credIDs) > 0 {
		res.MissingSecrets = s.BuildMissingSecrets(ctx, credIDs)
	}
	if res.Status == "applied" {
		s.InvalidateCatalogPools("topology", "")
		s.broadcast(Event{Type: "catalog_updated", Data: map[string]string{"kind": "topology"}})
	}
	return res, nil
}

func (s *Service) missingSecretsForTopologyPlan(ctx context.Context, b types.TopologyBundle) []types.MissingSecretInfo {
	var out []types.MissingSecretInfo
	for _, cp := range b.CredentialProfiles {
		kind := cp.Kind
		if kind == "" {
			kind = types.CredKeychain
		}
		if kind != types.CredKeychain {
			continue
		}
		acc := cp.AccessLevel
		if acc == "" {
			acc = types.AccessReadOnly
		}
		if existing, err := s.store.ResolveCredentialProfile(ctx, firstNonEmpty(cp.ID, cp.Name)); err == nil {
			if s.hasCredentialSecret(ctx, existing) {
				continue
			}
			out = append(out, types.MissingSecretInfo{
				ID:          existing.ID,
				Name:        existing.Name,
				Username:    firstNonEmpty(cp.Username, existing.Username),
				AccessLevel: acc,
				SetupURL:    s.CredentialSetupURL(existing.ID),
			})
			continue
		}
		out = append(out, types.MissingSecretInfo{
			ID:          cp.ID,
			Name:        cp.Name,
			Username:    cp.Username,
			AccessLevel: acc,
		})
	}
	return out
}

// AdminUpdateGlobalSecurity updates GlobalSecurityConfig idempotently with optional dry-run.
func (s *Service) AdminUpdateGlobalSecurity(ctx context.Context, actor string, cfg types.GlobalSecurityConfig, dryRun bool) (AdminMutationResult[types.GlobalSecurityConfig], error) {
	actor = s.effectiveActor(ctx, actor)
	if s.IsServerMode() {
		if err := rbac.Authorize(rbac.PrincipalFromContext(ctx), rbac.ActionGlobalSecurityWrite, rbac.ResourceScope{}); err != nil {
			return AdminMutationResult[types.GlobalSecurityConfig]{}, err
		}
	}
	if err := policy.ValidateGlobalConfig(cfg); err != nil {
		return AdminMutationResult[types.GlobalSecurityConfig]{}, err
	}
	if cfg.DefaultApprovalProvider == "" {
		cfg.DefaultApprovalProvider = "local-web"
	}
	cur, err := s.store.GetGlobalSecurityConfig(ctx)
	if err != nil {
		return AdminMutationResult[types.GlobalSecurityConfig]{}, err
	}
	curNorm := cur
	curNorm.UpdatedAtUTC = ""
	nextNorm := cfg
	nextNorm.UpdatedAtUTC = ""
	action := "updated"
	if curNorm == nextNorm {
		action = "unchanged"
	}
	if dryRun {
		return AdminMutationResult[types.GlobalSecurityConfig]{
			DryRun: true,
			Status: planOrUnchanged(action),
			Action: action,
			Item:   cfg,
		}, nil
	}
	if action == "unchanged" {
		return AdminMutationResult[types.GlobalSecurityConfig]{
			DryRun: false,
			Status: "unchanged",
			Action: "unchanged",
			Item:   cur,
		}, nil
	}
	saved, err := s.store.UpdateGlobalSecurityConfig(ctx, actor, cfg)
	if err != nil {
		return AdminMutationResult[types.GlobalSecurityConfig]{}, err
	}
	s.broadcast(Event{Type: "security_updated", Data: saved})
	return AdminMutationResult[types.GlobalSecurityConfig]{
		DryRun: false,
		Status: "updated",
		Action: "updated",
		Item:   saved,
	}, nil
}

// AdminUpsertPolicy creates or updates a PolicyRuleSet idempotently with natural-key scope resolution.
func (s *Service) AdminUpsertPolicy(ctx context.Context, actor string, p types.PolicyRuleSet, dryRun bool) (AdminMutationResult[types.PolicyRuleSet], error) {
	actor = s.effectiveActor(ctx, actor)
	if strings.TrimSpace(p.Name) == "" {
		return AdminMutationResult[types.PolicyRuleSet]{}, fmt.Errorf("policy name is required")
	}
	var existing *types.PolicyRuleSet
	if p.ID != "" {
		if cur, err := s.store.ResolvePolicy(ctx, p.ID); err == nil {
			existing = &cur
		}
	} else if cur, err := s.store.ResolvePolicy(ctx, p.Name); err == nil {
		existing = &cur
		p.ID = cur.ID
	}

	if p.ScopeType == "" && existing != nil {
		p.ScopeType = existing.ScopeType
	}
	if p.ScopeID == "" && existing != nil {
		p.ScopeID = existing.ScopeID
	}
	resolvedScope, err := s.resolveScopeTarget(ctx, p.ScopeType, p.ScopeID)
	if err != nil {
		return AdminMutationResult[types.PolicyRuleSet]{}, err
	}
	p.ScopeID = resolvedScope
	if err := s.authorizeScopedWrite(ctx, rbac.ActionPolicyWrite, p.ScopeType, p.ScopeID); err != nil {
		return AdminMutationResult[types.PolicyRuleSet]{}, err
	}
	if err := policy.ValidateRuleSet(p); err != nil {
		return AdminMutationResult[types.PolicyRuleSet]{}, err
	}

	action := "created"
	if existing != nil {
		if policiesEqual(*existing, p) {
			action = "unchanged"
		} else {
			action = "updated"
		}
	}
	if dryRun {
		return AdminMutationResult[types.PolicyRuleSet]{
			DryRun: true,
			Status: planOrUnchanged(action),
			Action: action,
			Item:   p,
		}, nil
	}
	if action == "unchanged" && existing != nil {
		return AdminMutationResult[types.PolicyRuleSet]{
			DryRun: false,
			Status: "unchanged",
			Action: "unchanged",
			Item:   *existing,
		}, nil
	}
	saved, err := s.store.UpsertPolicy(ctx, actor, p)
	if err != nil {
		return AdminMutationResult[types.PolicyRuleSet]{}, err
	}
	s.broadcast(Event{Type: "catalog_updated", Data: map[string]string{"kind": "policy", "id": saved.ID}})
	return AdminMutationResult[types.PolicyRuleSet]{
		DryRun: false,
		Status: action,
		Action: action,
		Item:   saved,
	}, nil
}

// AdminSetTargetScanReadMode creates or updates a target-scoped policy's ScanReadMode without disturbing other overrides.
func (s *Service) AdminSetTargetScanReadMode(ctx context.Context, actor, targetIDOrRef string, mode types.ScanReadMode, dryRun bool) (AdminMutationResult[types.PolicyRuleSet], error) {
	actor = s.effectiveActor(ctx, actor)
	switch mode {
	case types.ScanReadAllow, types.ScanReadReasonOnly, types.ScanReadRequireApproval:
	default:
		return AdminMutationResult[types.PolicyRuleSet]{}, fmt.Errorf("invalid scan_read_mode %q (expected allow, reason_only, or require_approval)", mode)
	}
	if strings.TrimSpace(targetIDOrRef) == "" && dryRun {
		return AdminMutationResult[types.PolicyRuleSet]{
			DryRun: true,
			Status: "planned",
			Action: "created",
			Item: types.PolicyRuleSet{
				ScopeType:    "target",
				ScanReadMode: mode,
			},
		}, nil
	}
	tgt, err := s.store.ResolveTargetRecord(ctx, targetIDOrRef)
	if err != nil {
		return AdminMutationResult[types.PolicyRuleSet]{}, err
	}
	policies, err := s.store.ListPolicies(ctx)
	if err != nil {
		return AdminMutationResult[types.PolicyRuleSet]{}, err
	}
	var existing *types.PolicyRuleSet
	for _, p := range policies {
		if (tgt.PolicyOverrideID != "" && p.ID == tgt.PolicyOverrideID) ||
			(p.ScopeType == "target" && p.ScopeID == tgt.ID) {
			cp := p
			existing = &cp
			break
		}
	}
	if existing != nil {
		existing.ScanReadMode = mode
		return s.AdminUpsertPolicy(ctx, actor, *existing, dryRun)
	}
	return s.AdminUpsertPolicy(ctx, actor, types.PolicyRuleSet{
		Name:         sanitizeSlug(tgt.Ref) + "-policy",
		ScopeType:    "target",
		ScopeID:      tgt.ID,
		ScanReadMode: mode,
	}, dryRun)
}

func summarizeTargetAccessLevel(roCredID, rwCredID string, writable bool) string {
	if rwCredID != "" {
		return string(types.AccessReadWrite)
	}
	if roCredID != "" {
		return string(types.AccessReadOnly)
	}
	if writable {
		return string(types.AccessReadWrite)
	}
	return string(types.AccessReadOnly)
}

func (s *Service) dryRunTargetSummary(ctx context.Context, sysObj types.System, envObj types.Environment, tgtInput types.Target, engine, roCredID, rwCredID string, overrideScanMode types.ScanReadMode) types.TargetSummary {
	global, _ := s.store.GetGlobalSecurityConfig(ctx)
	policies, _ := s.store.ListPolicies(ctx)
	var linked []types.System
	if len(tgtInput.LinkedSystemIDs) > 0 {
		if allSys, err := s.store.ListSystems(ctx); err == nil {
			byID := make(map[string]types.System, len(allSys))
			for _, sys := range allSys {
				byID[sys.ID] = sys
			}
			for _, id := range tgtInput.LinkedSystemIDs {
				if sys, ok := byID[id]; ok {
					linked = append(linked, sys)
				}
			}
		}
	}
	eff := policy.ResolveEffectivePolicyWithSystems(global, &envObj, &sysObj, linked, tgtInput, policies)
	if overrideScanMode != "" {
		eff.ScanReadMode = overrideScanMode
	}
	hasRWPath := rwCredID != "" || (roCredID == "" && rwCredID == "")
	frozen := eff.ProdReadOnlyFreeze && eff.SafetyTier == types.SafetyTierStrict
	writable := tgtInput.Status == types.TargetActive && hasRWPath && !frozen

	return types.TargetSummary{
		Ref:             tgtInput.Ref,
		Alias:           tgtInput.Alias,
		System:          sysObj.Slug,
		Env:             envObj.Code,
		SafetyTier:      eff.SafetyTier,
		Engine:          engine,
		Database:        tgtInput.DatabaseName,
		Status:          tgtInput.Status,
		Writable:        writable,
		ScanReadMode:    eff.ScanReadMode,
		MaxRows:         eff.MaxRows,
		ExecTimeoutSec:  eff.ExecTimeoutSec,
		QuerySyntaxHint: engineQuerySyntaxHint(engine),
		Description:     tgtInput.Description,
	}
}

// AdminDeletePolicy removes a PolicyRuleSet by ID or name.
func (s *Service) AdminDeletePolicy(ctx context.Context, actor, idOrName string) error {
	cur, err := s.store.ResolvePolicy(ctx, idOrName)
	if err != nil {
		return err
	}
	if err := s.authorizeScopedWrite(ctx, rbac.ActionPolicyWrite, cur.ScopeType, cur.ScopeID); err != nil {
		return err
	}
	if err := s.store.DeletePolicy(ctx, s.effectiveActor(ctx, actor), cur.ID); err != nil {
		return err
	}
	s.broadcast(Event{Type: "catalog_updated", Data: map[string]string{"kind": "policy", "id": cur.ID}})
	return nil
}

// AdminUpsertRiskPattern creates or updates a RiskPatternRule idempotently with optional dry-run.
func (s *Service) AdminUpsertRiskPattern(ctx context.Context, actor string, r types.RiskPatternRule, dryRun bool) (AdminMutationResult[types.RiskPatternRule], error) {
	actor = s.effectiveActor(ctx, actor)
	r.Name = strings.TrimSpace(r.Name)
	if r.ScopeType == "" {
		r.ScopeType = "global"
	}
	resolvedScope, err := s.resolveScopeTarget(ctx, r.ScopeType, r.ScopeID)
	if err != nil {
		return AdminMutationResult[types.RiskPatternRule]{}, err
	}
	r.ScopeID = resolvedScope
	if err := s.authorizeScopedWrite(ctx, rbac.ActionPatternWrite, r.ScopeType, r.ScopeID); err != nil {
		return AdminMutationResult[types.RiskPatternRule]{}, err
	}
	if err := policy.ValidateRiskPatternRule(r); err != nil {
		return AdminMutationResult[types.RiskPatternRule]{}, err
	}
	if r.Engines == nil {
		r.Engines = []string{}
	}
	if r.Families == nil {
		r.Families = []types.EngineFamily{}
	}

	var existing *types.RiskPatternRule
	if r.ID != "" {
		if cur, err := s.store.ResolveRiskPatternRule(ctx, r.ID, "", ""); err == nil {
			existing = &cur
		}
	} else if cur, err := s.store.ResolveRiskPatternRule(ctx, r.Name, r.ScopeType, r.ScopeID); err == nil {
		existing = &cur
		r.ID = cur.ID
	}

	action := "created"
	if existing != nil {
		if patternsEqual(*existing, r) {
			action = "unchanged"
		} else {
			action = "updated"
		}
	}
	if dryRun {
		return AdminMutationResult[types.RiskPatternRule]{
			DryRun: true,
			Status: planOrUnchanged(action),
			Action: action,
			Item:   r,
		}, nil
	}
	if action == "unchanged" && existing != nil {
		return AdminMutationResult[types.RiskPatternRule]{
			DryRun: false,
			Status: "unchanged",
			Action: "unchanged",
			Item:   *existing,
		}, nil
	}
	saved, err := s.store.UpsertRiskPatternRule(ctx, actor, r)
	if err != nil {
		return AdminMutationResult[types.RiskPatternRule]{}, err
	}
	s.broadcast(Event{Type: "patterns_updated", Data: saved})
	return AdminMutationResult[types.RiskPatternRule]{
		DryRun: false,
		Status: action,
		Action: action,
		Item:   saved,
	}, nil
}

// AdminDeleteRiskPattern removes a RiskPatternRule by ID or name+scope.
func (s *Service) AdminDeleteRiskPattern(ctx context.Context, actor, idOrName, scopeType, scopeID string) error {
	cur, err := s.store.ResolveRiskPatternRule(ctx, idOrName, scopeType, scopeID)
	if err != nil {
		return err
	}
	if err := s.authorizeScopedWrite(ctx, rbac.ActionPatternWrite, cur.ScopeType, cur.ScopeID); err != nil {
		return err
	}
	if err := s.store.DeleteRiskPatternRule(ctx, s.effectiveActor(ctx, actor), cur.ID); err != nil {
		return err
	}
	s.broadcast(Event{Type: "patterns_updated", Data: map[string]string{"id": cur.ID}})
	return nil
}

// AdminInstallRulePack installs a builtin risk pattern pack for a scope (supporting dry-run).
func (s *Service) AdminInstallRulePack(ctx context.Context, actor, packID, scopeType, scopeID string, dryRun bool) (map[string]any, error) {
	actor = s.effectiveActor(ctx, actor)
	pack, ok := policy.GetBuiltinRulePack(packID)
	if !ok {
		return nil, fmt.Errorf("%w: unknown builtin rule pack %q", store.ErrNotFound, packID)
	}
	if scopeType == "" {
		scopeType = "global"
	}
	resolvedScope, err := s.resolveScopeTarget(ctx, scopeType, scopeID)
	if err != nil {
		return nil, err
	}
	if err := s.authorizeScopedWrite(ctx, rbac.ActionPatternWrite, scopeType, resolvedScope); err != nil {
		return nil, err
	}
	if dryRun {
		items := make([]types.RiskPatternRule, 0, len(pack.Rules))
		for _, r := range pack.Rules {
			r.ScopeType = scopeType
			r.ScopeID = resolvedScope
			items = append(items, r)
		}
		return map[string]any{
			"dry_run":    true,
			"status":     "planned",
			"pack_id":    packID,
			"scope_type": scopeType,
			"scope_id":   resolvedScope,
			"items":      items,
		}, nil
	}
	installed, err := s.store.InstallBuiltinRulePack(ctx, actor, packID, scopeType, resolvedScope)
	if err != nil {
		return nil, err
	}
	s.broadcast(Event{Type: "patterns_updated", Data: map[string]any{"pack_id": packID, "count": len(installed)}})
	return map[string]any{
		"dry_run":    false,
		"status":     "applied",
		"pack_id":    packID,
		"scope_type": scopeType,
		"scope_id":   resolvedScope,
		"items":      installed,
	}, nil
}

func (s *Service) resolveScopeTarget(ctx context.Context, scopeType, scopeID string) (string, error) {
	switch scopeType {
	case "global":
		return "global", nil
	case "env":
		env, err := s.store.ResolveEnvironment(ctx, scopeID)
		if err != nil {
			return "", err
		}
		return env.Code, nil
	case "system":
		sys, err := s.store.ResolveSystem(ctx, scopeID)
		if err != nil {
			return "", err
		}
		return sys.ID, nil
	case "target":
		tgt, err := s.store.ResolveTargetRecord(ctx, scopeID)
		if err != nil {
			return "", err
		}
		return tgt.ID, nil
	default:
		return strings.TrimSpace(scopeID), nil
	}
}

func buildDBAddTargetInput(ref string, req DBAddRequest, sysID, envCode, instID, dbName, roCredID, rwCredID string) types.Target {
	status := req.Status
	if status == "" {
		status = types.TargetActive
	}
	return types.Target{
		Ref:             ref,
		Alias:           strings.TrimSpace(req.Alias),
		OwnerSystemID:   sysID,
		EnvironmentCode: envCode,
		InstanceID:      instID,
		DatabaseName:    dbName,
		ROCredentialID:  roCredID,
		RWCredentialID:  rwCredID,
		Status:          status,
		Description:     strings.TrimSpace(req.Description),
	}
}

func deriveDBLabel(canonEngine, host, dbName string) string {
	if canonEngine == "sqlite" {
		if dbName == ":memory:" || host == ":memory:" {
			return "memory"
		}
		base := filepath.Base(firstNonEmpty(dbName, host))
		ext := filepath.Ext(base)
		if ext != "" {
			base = strings.TrimSuffix(base, ext)
		}
		if s := sanitizeSlug(base); s != "" {
			return s
		}
		return "sqlite"
	}
	if dbName != "" {
		if s := sanitizeSlug(dbName); s != "" {
			return s
		}
	}
	if canonEngine == "redis" {
		return "db0"
	}
	if s := sanitizeSlug(host); s != "" {
		return s
	}
	return canonEngine
}

func sanitizeSlug(raw string) string {
	var b strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(strings.TrimSpace(raw)) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
		} else if !lastDash && b.Len() > 0 {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func titleSlug(slug string) string {
	parts := strings.FieldsFunc(slug, func(r rune) bool {
		return r == '-' || r == '_' || r == ' '
	})
	for i, p := range parts {
		if p != "" {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	if len(parts) == 0 {
		return slug
	}
	return strings.Join(parts, " ")
}

func mergeUniqueStrings(base, add []string) []string {
	out := append([]string(nil), base...)
	seen := make(map[string]bool, len(base))
	for _, b := range base {
		seen[b] = true
	}
	for _, a := range add {
		if a != "" && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func planOrUnchanged(action string) string {
	if action == "unchanged" {
		return "unchanged"
	}
	return "planned"
}

func (s *Service) resolveSystemByWorkspace(ctx context.Context, cwd string, gitRemotes []string) *types.System {
	systems, err := s.store.ListSystems(ctx)
	if err != nil {
		return nil
	}
	var pathMatches []types.System
	for _, sys := range systems {
		if matchesWorkspace(cwd, sys.WorkspacePaths) {
			pathMatches = append(pathMatches, sys)
		}
	}
	if len(pathMatches) == 1 {
		match := pathMatches[0]
		return &match
	}
	if len(pathMatches) > 1 {
		return nil
	}
	normRemotes := config.NormalizeGitRemotes(gitRemotes)
	var remoteMatches []types.System
	for _, sys := range systems {
		if matchesGitRemotes(normRemotes, sys.GitRemotes) {
			remoteMatches = append(remoteMatches, sys)
		}
	}
	if len(remoteMatches) == 1 {
		match := remoteMatches[0]
		return &match
	}
	return nil
}

func systemsEqual(a, b types.System) bool {
	a.CreatedAtUTC, a.UpdatedAtUTC = "", ""
	b.CreatedAtUTC, b.UpdatedAtUTC = "", ""
	if a.Tags == nil {
		a.Tags = []string{}
	}
	if b.Tags == nil {
		b.Tags = []string{}
	}
	if a.WorkspacePaths == nil {
		a.WorkspacePaths = []string{}
	}
	if b.WorkspacePaths == nil {
		b.WorkspacePaths = []string{}
	}
	a.GitRemotes = config.NormalizeGitRemotes(a.GitRemotes)
	b.GitRemotes = config.NormalizeGitRemotes(b.GitRemotes)
	return reflect.DeepEqual(a, b)
}

func envsEqual(a, b types.Environment) bool {
	a.CreatedAtUTC, a.UpdatedAtUTC = "", ""
	b.CreatedAtUTC, b.UpdatedAtUTC = "", ""
	return reflect.DeepEqual(a, b)
}

func netsEqual(a, b types.NetworkProfile) bool {
	a.CreatedAtUTC, a.UpdatedAtUTC = "", ""
	b.CreatedAtUTC, b.UpdatedAtUTC = "", ""
	return a == b
}

func credsEqual(a, b types.CredentialProfile) bool {
	a.CreatedAtUTC, a.UpdatedAtUTC, a.HasSecret = "", "", false
	b.CreatedAtUTC, b.UpdatedAtUTC, b.HasSecret = "", "", false
	return a == b
}

func instsEqual(a, b types.Instance) bool {
	a.CreatedAtUTC, a.UpdatedAtUTC, a.Capabilities, a.CapabilitiesDetectedAt = "", "", nil, ""
	b.CreatedAtUTC, b.UpdatedAtUTC, b.Capabilities, b.CapabilitiesDetectedAt = "", "", nil, ""
	if a.Params == nil {
		a.Params = map[string]string{}
	}
	if b.Params == nil {
		b.Params = map[string]string{}
	}
	return reflect.DeepEqual(a, b)
}

func targetsEqual(a, b types.Target) bool {
	a.CreatedAtUTC, a.UpdatedAtUTC = "", ""
	b.CreatedAtUTC, b.UpdatedAtUTC = "", ""
	al := append([]string(nil), a.LinkedSystemIDs...)
	bl := append([]string(nil), b.LinkedSystemIDs...)
	sort.Strings(al)
	sort.Strings(bl)
	a.LinkedSystemIDs = al
	b.LinkedSystemIDs = bl
	return reflect.DeepEqual(a, b)
}

func policiesEqual(a, b types.PolicyRuleSet) bool {
	a.CreatedAtUTC, a.UpdatedAtUTC = "", ""
	b.CreatedAtUTC, b.UpdatedAtUTC = "", ""
	return reflect.DeepEqual(a, b)
}

func patternsEqual(a, b types.RiskPatternRule) bool {
	a.CreatedAtUTC, a.UpdatedAtUTC, a.ScopeLabel = "", "", ""
	b.CreatedAtUTC, b.UpdatedAtUTC, b.ScopeLabel = "", "", ""
	if a.Engines == nil {
		a.Engines = []string{}
	}
	if b.Engines == nil {
		b.Engines = []string{}
	}
	if a.Families == nil {
		a.Families = []types.EngineFamily{}
	}
	if b.Families == nil {
		b.Families = []types.EngineFamily{}
	}
	return reflect.DeepEqual(a, b)
}

var _ = errors.Is
