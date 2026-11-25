package daemon

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/x0c/agent-dbctl/internal/classify"
	"github.com/x0c/agent-dbctl/internal/policy"
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
	NoWorkspace           bool              `json:"no_workspace,omitempty"`
	Env                   string            `json:"env,omitempty"`
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
	Description           string            `json:"description,omitempty"`
	DryRun                bool              `json:"dry_run,omitempty"`
	Test                  bool              `json:"test,omitempty"`
}

// DBAddResponse summarizes the created/updated/reused catalog entities for `db add`.
type DBAddResponse struct {
	DryRun         bool                      `json:"dry_run"`
	Status         string                    `json:"status"` // planned | created | updated | unchanged
	Target         types.TargetSummary       `json:"target"`
	Actions        map[string]string         `json:"actions"`
	MissingSecrets []types.MissingSecretInfo `json:"missing_secrets,omitempty"`
	Ping           *types.PingResult         `json:"ping,omitempty"`
	Warnings       []string                  `json:"warnings,omitempty"`
	NextCommands   []string                  `json:"next_commands,omitempty"`
}

func defaultActor(actor string) string {
	if strings.TrimSpace(actor) == "" {
		return "agent-cli"
	}
	return strings.TrimSpace(actor)
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

// AdminUpsertSystem creates or updates a System idempotently with optional dry-run.
func (s *Service) AdminUpsertSystem(ctx context.Context, actor string, sys types.System, dryRun bool) (AdminMutationResult[types.System], error) {
	actor = defaultActor(actor)
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
	if err := s.store.DeleteSystem(ctx, defaultActor(actor), cur.ID); err != nil {
		return err
	}
	s.broadcast(Event{Type: "catalog_updated", Data: map[string]string{"kind": "system", "id": cur.ID}})
	return nil
}

// AdminUpsertEnvironment creates or updates an Environment idempotently with optional dry-run.
func (s *Service) AdminUpsertEnvironment(ctx context.Context, actor string, env types.Environment, dryRun bool) (AdminMutationResult[types.Environment], error) {
	actor = defaultActor(actor)
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

// AdminUpsertNetworkProfile creates or updates a NetworkProfile idempotently with optional dry-run.
func (s *Service) AdminUpsertNetworkProfile(ctx context.Context, actor string, np types.NetworkProfile, dryRun bool) (AdminMutationResult[types.NetworkProfile], error) {
	actor = defaultActor(actor)
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
	if err := s.store.DeleteNetworkProfile(ctx, defaultActor(actor), cur.ID); err != nil {
		return err
	}
	s.broadcast(Event{Type: "catalog_updated", Data: map[string]string{"kind": "network_profile", "id": cur.ID}})
	return nil
}

// AdminUpsertCredentialProfile creates/updates credential metadata and optionally writes/clears the OS secret.
func (s *Service) AdminUpsertCredentialProfile(ctx context.Context, actor string, req CredentialUpsertRequest) (AdminMutationResult[types.CredentialProfile], error) {
	actor = defaultActor(actor)
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
	if err := s.store.DeleteCredentialProfile(ctx, defaultActor(actor), cur.ID); err != nil {
		return err
	}
	_ = s.secrets.Delete(ctx, "cred:"+cur.ID)
	s.broadcast(Event{Type: "catalog_updated", Data: map[string]string{"kind": "credential", "id": cur.ID}})
	return nil
}

// AdminUpsertInstance creates or updates an Instance idempotently with optional dry-run.
func (s *Service) AdminUpsertInstance(ctx context.Context, actor string, inst types.Instance, dryRun bool) (AdminMutationResult[types.Instance], error) {
	actor = defaultActor(actor)
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

	if inst.Engine == "" && existing != nil {
		inst.Engine = existing.Engine
	}
	if strings.TrimSpace(inst.Engine) == "" {
		return AdminMutationResult[types.Instance]{}, fmt.Errorf("instance engine is required")
	}
	if _, ok := s.drivers.Get(inst.Engine); !ok {
		return AdminMutationResult[types.Instance]{}, fmt.Errorf("unsupported engine %q (run `driver list` to inspect registered engines)", inst.Engine)
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
	if err := s.store.DeleteInstance(ctx, defaultActor(actor), cur.ID); err != nil {
		return err
	}
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
	actor = defaultActor(actor)
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
	s.broadcast(Event{Type: "catalog_updated", Data: map[string]string{"kind": "target", "id": saved.ID}})
	return AdminMutationResult[types.Target]{
		DryRun: false,
		Status: action,
		Action: action,
		Item:   saved,
	}, nil
}

// AdminDeleteTarget removes a Target by ID, ref, or alias.
func (s *Service) AdminDeleteTarget(ctx context.Context, actor, idOrRefOrAlias string) error {
	cur, err := s.store.ResolveTargetRecord(ctx, idOrRefOrAlias)
	if err != nil {
		return err
	}
	if err := s.store.DeleteTarget(ctx, defaultActor(actor), cur.ID); err != nil {
		return err
	}
	s.broadcast(Event{Type: "catalog_updated", Data: map[string]string{"kind": "target", "id": cur.ID}})
	return nil
}

// AdminAddDatabase performs declarative one-shot onboarding (System + Credential + Instance + Target).
func (s *Service) AdminAddDatabase(ctx context.Context, actor string, req DBAddRequest) (DBAddResponse, error) {
	actor = defaultActor(actor)
	var warnings []string

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
	sysSlug := strings.TrimSpace(req.System)
	if sysSlug == "" && !req.NoWorkspace && strings.TrimSpace(req.WorkspaceCWD) != "" {
		base := sanitizeSlug(filepath.Base(filepath.Clean(req.WorkspaceCWD)))
		if base != "" && base != "." {
			sysSlug = base
		}
	}
	if sysSlug == "" {
		sysSlug = "default"
	}

	var sysWS []string
	for _, ws := range req.WorkspacePaths {
		if trimmed := strings.TrimSpace(ws); trimmed != "" {
			sysWS = append(sysWS, trimmed)
		}
	}
	if len(sysWS) == 0 && !req.NoWorkspace && strings.TrimSpace(req.WorkspaceCWD) != "" {
		sysWS = []string{req.WorkspaceCWD}
	}

	var sysObj types.System
	sysAction := "created"
	if existingSys, err := s.store.ResolveSystem(ctx, sysSlug); err == nil {
		sysObj = existingSys
		mergedWS := mergeUniqueStrings(existingSys.WorkspacePaths, sysWS)
		nameChanged := req.SystemName != "" && req.SystemName != existingSys.Name
		if nameChanged {
			sysObj.Name = req.SystemName
		}
		wsChanged := len(mergedWS) != len(existingSys.WorkspacePaths)
		if wsChanged {
			sysObj.WorkspacePaths = mergedWS
		}
		if nameChanged || wsChanged {
			sysAction = "updated"
		} else {
			sysAction = "unchanged"
		}
	} else {
		sysName := firstNonEmpty(strings.TrimSpace(req.SystemName), titleSlug(sysSlug))
		sysObj = types.System{
			Slug:           sysSlug,
			Name:           sysName,
			WorkspacePaths: sysWS,
			Tags:           []string{},
		}
	}

	// 2. Environment verification.
	envCode := firstNonEmpty(strings.TrimSpace(req.Env), "dev")
	envObj, err := s.store.ResolveEnvironment(ctx, envCode)
	if err != nil {
		envs, _ := s.store.ListEnvironments(ctx)
		var codes []string
		for _, e := range envs {
			codes = append(codes, e.Code)
		}
		return DBAddResponse{}, fmt.Errorf("%w (available environments: %s)", err, strings.Join(codes, ", "))
	}

	// 3. NetworkProfile resolution (optional).
	netID := ""
	if strings.TrimSpace(req.Network) != "" {
		np, err := s.store.ResolveNetworkProfile(ctx, req.Network)
		if err != nil {
			return DBAddResponse{}, err
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
			return DBAddResponse{}, err
		}
		roCredID = cp.ID
	}
	if strings.TrimSpace(req.RWCred) != "" {
		cp, err := s.store.ResolveCredentialProfile(ctx, req.RWCred)
		if err != nil {
			return DBAddResponse{}, err
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
			accLevel = types.AccessReadOnly
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
		if len(instInput.Params) == 0 && len(existingInst.Params) > 0 {
			instInput.Params = existingInst.Params
		}
		if instInput.TLSMode == "" {
			instInput.TLSMode = existingInst.TLSMode
		}
	}

	// Plan or apply step by step.
	actions := map[string]string{
		"system":     sysAction,
		"credential": "unchanged",
		"instance":   "unchanged",
		"target":     "unchanged",
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

		overall := "planned"
		if actions["system"] == "unchanged" && actions["credential"] == "unchanged" && actions["instance"] == "unchanged" && actions["target"] == "unchanged" {
			overall = "unchanged"
		}
		return DBAddResponse{
			DryRun: true,
			Status: overall,
			Target: types.TargetSummary{
				Ref:      ref,
				Alias:    tgtInput.Alias,
				System:   sysObj.Slug,
				Env:      envObj.Code,
				Engine:   engine,
				Database: dbName,
				Status:   tgtInput.Status,
			},
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

	detail, err := s.ResolveTarget(ctx, tgtRes.Item.Ref, req.WorkspaceCWD)
	if err != nil {
		return DBAddResponse{}, err
	}

	overall := tgtRes.Action
	if overall == "unchanged" && (actions["system"] != "unchanged" || actions["credential"] != "unchanged" || actions["instance"] != "unchanged") {
		overall = "updated"
	}

	resp := DBAddResponse{
		DryRun:         false,
		Status:         overall,
		Target:         SummarizeTarget(detail),
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
		}
	}

	return resp, nil
}

// AdminApplyTopology previews (--dry-run) or atomically imports a TopologyBundle and flags missing Keychain secrets.
func (s *Service) AdminApplyTopology(ctx context.Context, actor string, bundle types.TopologyBundle, dryRun bool) (types.TopologyImportResult, error) {
	actor = defaultActor(actor)
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
	actor = defaultActor(actor)
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
	actor = defaultActor(actor)
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

// AdminDeletePolicy removes a PolicyRuleSet by ID or name.
func (s *Service) AdminDeletePolicy(ctx context.Context, actor, idOrName string) error {
	cur, err := s.store.ResolvePolicy(ctx, idOrName)
	if err != nil {
		return err
	}
	if err := s.store.DeletePolicy(ctx, defaultActor(actor), cur.ID); err != nil {
		return err
	}
	s.broadcast(Event{Type: "catalog_updated", Data: map[string]string{"kind": "policy", "id": cur.ID}})
	return nil
}

// AdminUpsertRiskPattern creates or updates a RiskPatternRule idempotently with optional dry-run.
func (s *Service) AdminUpsertRiskPattern(ctx context.Context, actor string, r types.RiskPatternRule, dryRun bool) (AdminMutationResult[types.RiskPatternRule], error) {
	actor = defaultActor(actor)
	r.Name = strings.TrimSpace(r.Name)
	if r.ScopeType == "" {
		r.ScopeType = "global"
	}
	resolvedScope, err := s.resolveScopeTarget(ctx, r.ScopeType, r.ScopeID)
	if err != nil {
		return AdminMutationResult[types.RiskPatternRule]{}, err
	}
	r.ScopeID = resolvedScope
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
	if err := s.store.DeleteRiskPatternRule(ctx, defaultActor(actor), cur.ID); err != nil {
		return err
	}
	s.broadcast(Event{Type: "patterns_updated", Data: map[string]string{"id": cur.ID}})
	return nil
}

// AdminInstallRulePack installs a builtin risk pattern pack for a scope (supporting dry-run).
func (s *Service) AdminInstallRulePack(ctx context.Context, actor, packID, scopeType, scopeID string, dryRun bool) (map[string]any, error) {
	actor = defaultActor(actor)
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
