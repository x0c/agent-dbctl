package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/x0c/agent-dbctl/internal/config"
	"github.com/x0c/agent-dbctl/internal/policy"
	"github.com/x0c/agent-dbctl/internal/types"
)

// ResolveSystem looks up a System by ID or case-insensitive slug.
func (s *Store) ResolveSystem(ctx context.Context, idOrSlug string) (types.System, error) {
	q := strings.TrimSpace(idOrSlug)
	if q == "" {
		return types.System{}, fmt.Errorf("%w: system identifier is required", ErrNotFound)
	}
	items, err := s.ListSystems(ctx)
	if err != nil {
		return types.System{}, err
	}
	for _, it := range items {
		if it.ID == q || strings.EqualFold(it.Slug, q) {
			return it, nil
		}
	}
	return types.System{}, fmt.Errorf("%w: system %q not found", ErrNotFound, q)
}

// ResolveEnvironment looks up an Environment by case-insensitive code.
func (s *Store) ResolveEnvironment(ctx context.Context, code string) (types.Environment, error) {
	q := strings.TrimSpace(code)
	if q == "" {
		return types.Environment{}, fmt.Errorf("%w: environment code is required", ErrNotFound)
	}
	items, err := s.ListEnvironments(ctx)
	if err != nil {
		return types.Environment{}, err
	}
	for _, it := range items {
		if strings.EqualFold(it.Code, q) {
			return it, nil
		}
	}
	return types.Environment{}, fmt.Errorf("%w: environment %q not found", ErrNotFound, q)
}

// ResolveNetworkProfile looks up a NetworkProfile by ID or case-insensitive name.
func (s *Store) ResolveNetworkProfile(ctx context.Context, idOrName string) (types.NetworkProfile, error) {
	q := strings.TrimSpace(idOrName)
	if q == "" {
		return types.NetworkProfile{}, fmt.Errorf("%w: network profile identifier is required", ErrNotFound)
	}
	items, err := s.ListNetworkProfiles(ctx)
	if err != nil {
		return types.NetworkProfile{}, err
	}
	for _, it := range items {
		if it.ID == q || strings.EqualFold(it.Name, q) {
			return it, nil
		}
	}
	return types.NetworkProfile{}, fmt.Errorf("%w: network profile %q not found", ErrNotFound, q)
}

// ResolveCredentialProfile looks up a CredentialProfile by ID or case-insensitive name.
func (s *Store) ResolveCredentialProfile(ctx context.Context, idOrName string) (types.CredentialProfile, error) {
	q := strings.TrimSpace(idOrName)
	if q == "" {
		return types.CredentialProfile{}, fmt.Errorf("%w: credential identifier is required", ErrNotFound)
	}
	items, err := s.ListCredentialProfiles(ctx)
	if err != nil {
		return types.CredentialProfile{}, err
	}
	for _, it := range items {
		if it.ID == q || strings.EqualFold(it.Name, q) {
			return it, nil
		}
	}
	return types.CredentialProfile{}, fmt.Errorf("%w: credential profile %q not found", ErrNotFound, q)
}

// ResolveInstance looks up an Instance by ID or case-insensitive name.
func (s *Store) ResolveInstance(ctx context.Context, idOrName string) (types.Instance, error) {
	q := strings.TrimSpace(idOrName)
	if q == "" {
		return types.Instance{}, fmt.Errorf("%w: instance identifier is required", ErrNotFound)
	}
	items, err := s.ListInstances(ctx)
	if err != nil {
		return types.Instance{}, err
	}
	for _, it := range items {
		if it.ID == q || strings.EqualFold(it.Name, q) {
			return it, nil
		}
	}
	return types.Instance{}, fmt.Errorf("%w: instance %q not found", ErrNotFound, q)
}

// ResolveTargetRecord looks up a Target by ID, ref, or alias.
func (s *Store) ResolveTargetRecord(ctx context.Context, idOrRefOrAlias string) (types.Target, error) {
	q := strings.TrimSpace(idOrRefOrAlias)
	if q == "" {
		return types.Target{}, fmt.Errorf("%w: target identifier is required", ErrNotFound)
	}
	items, err := s.ListTargets(ctx)
	if err != nil {
		return types.Target{}, err
	}
	var aliasMatches []types.Target
	for _, it := range items {
		if it.ID == q || strings.EqualFold(it.Ref, q) {
			return it, nil
		}
		if it.Alias != "" && strings.EqualFold(it.Alias, q) {
			aliasMatches = append(aliasMatches, it)
		}
	}
	if len(aliasMatches) == 1 {
		return aliasMatches[0], nil
	}
	if len(aliasMatches) > 1 {
		return types.Target{}, fmt.Errorf("%w: alias %q matches %d targets; use target ref or ID", ErrConflict, q, len(aliasMatches))
	}
	return types.Target{}, fmt.Errorf("%w: target %q not found", ErrNotFound, q)
}

// ResolvePolicy looks up a PolicyRuleSet by ID or case-insensitive name.
func (s *Store) ResolvePolicy(ctx context.Context, idOrName string) (types.PolicyRuleSet, error) {
	q := strings.TrimSpace(idOrName)
	if q == "" {
		return types.PolicyRuleSet{}, fmt.Errorf("%w: policy identifier is required", ErrNotFound)
	}
	items, err := s.ListPolicies(ctx)
	if err != nil {
		return types.PolicyRuleSet{}, err
	}
	for _, it := range items {
		if it.ID == q || strings.EqualFold(it.Name, q) {
			return it, nil
		}
	}
	return types.PolicyRuleSet{}, fmt.Errorf("%w: policy %q not found", ErrNotFound, q)
}

// ResolveRiskPatternRule looks up a RiskPatternRule by ID or name (optionally narrowed by scopeType/scopeID).
func (s *Store) ResolveRiskPatternRule(ctx context.Context, idOrName, scopeType, scopeID string) (types.RiskPatternRule, error) {
	q := strings.TrimSpace(idOrName)
	if q == "" {
		return types.RiskPatternRule{}, fmt.Errorf("%w: risk pattern identifier is required", ErrNotFound)
	}
	items, err := s.ListRiskPatternRules(ctx)
	if err != nil {
		return types.RiskPatternRule{}, err
	}
	for _, it := range items {
		if it.ID == q {
			return it, nil
		}
	}

	resolvedScopeID := strings.TrimSpace(scopeID)
	if scopeType == "global" {
		resolvedScopeID = "global"
	} else if scopeType != "" && resolvedScopeID != "" {
		switch scopeType {
		case "env":
			if env, eErr := s.ResolveEnvironment(ctx, resolvedScopeID); eErr == nil {
				resolvedScopeID = env.Code
			}
		case "system":
			if sys, sErr := s.ResolveSystem(ctx, resolvedScopeID); sErr == nil {
				resolvedScopeID = sys.ID
			}
		case "target":
			if tgt, tErr := s.ResolveTargetRecord(ctx, resolvedScopeID); tErr == nil {
				resolvedScopeID = tgt.ID
			}
		}
	}

	var matches []types.RiskPatternRule
	for _, it := range items {
		if !strings.EqualFold(it.Name, q) {
			continue
		}
		if scopeType != "" && !strings.EqualFold(it.ScopeType, scopeType) {
			continue
		}
		if resolvedScopeID != "" && !strings.EqualFold(it.ScopeID, resolvedScopeID) && !strings.EqualFold(it.ScopeID, scopeID) {
			continue
		}
		matches = append(matches, it)
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	if len(matches) > 1 {
		return types.RiskPatternRule{}, fmt.Errorf("%w: multiple pattern rules named %q; specify --scope-type/--scope-id or rule id", ErrConflict, q)
	}
	return types.RiskPatternRule{}, fmt.Errorf("%w: risk pattern rule %q not found", ErrNotFound, q)
}

type topologySnapshot struct {
	global types.GlobalSecurityConfig
	envs   map[string]types.Environment
	syss   map[string]types.System
	sysByS map[string]types.System
	creds  map[string]types.CredentialProfile
	credN  map[string]types.CredentialProfile
	nets   map[string]types.NetworkProfile
	netN   map[string]types.NetworkProfile
	insts  map[string]types.Instance
	instN  map[string]types.Instance
	tgts   map[string]types.Target
	tgtR   map[string]types.Target
	pols   map[string]types.PolicyRuleSet
	polN   map[string]types.PolicyRuleSet
	pats   map[string]types.RiskPatternRule
	patKey map[string]types.RiskPatternRule
}

func loadTopologySnapshot(ctx context.Context, q interface {
	GetGlobalSecurityConfig(context.Context) (types.GlobalSecurityConfig, error)
	ListEnvironments(context.Context) ([]types.Environment, error)
	ListSystems(context.Context) ([]types.System, error)
	ListCredentialProfiles(context.Context) ([]types.CredentialProfile, error)
	ListNetworkProfiles(context.Context) ([]types.NetworkProfile, error)
	ListInstances(context.Context) ([]types.Instance, error)
	ListTargets(context.Context) ([]types.Target, error)
	ListPolicies(context.Context) ([]types.PolicyRuleSet, error)
	ListRiskPatternRules(context.Context) ([]types.RiskPatternRule, error)
}) (*topologySnapshot, error) {
	snap := &topologySnapshot{
		envs:   map[string]types.Environment{},
		syss:   map[string]types.System{},
		sysByS: map[string]types.System{},
		creds:  map[string]types.CredentialProfile{},
		credN:  map[string]types.CredentialProfile{},
		nets:   map[string]types.NetworkProfile{},
		netN:   map[string]types.NetworkProfile{},
		insts:  map[string]types.Instance{},
		instN:  map[string]types.Instance{},
		tgts:   map[string]types.Target{},
		tgtR:   map[string]types.Target{},
		pols:   map[string]types.PolicyRuleSet{},
		polN:   map[string]types.PolicyRuleSet{},
		pats:   map[string]types.RiskPatternRule{},
		patKey: map[string]types.RiskPatternRule{},
	}
	var err error
	if snap.global, err = q.GetGlobalSecurityConfig(ctx); err != nil {
		return nil, err
	}
	envs, err := q.ListEnvironments(ctx)
	if err != nil {
		return nil, err
	}
	for _, e := range envs {
		snap.envs[strings.ToLower(e.Code)] = e
	}
	syss, err := q.ListSystems(ctx)
	if err != nil {
		return nil, err
	}
	for _, s := range syss {
		snap.syss[s.ID] = s
		snap.sysByS[strings.ToLower(s.Slug)] = s
	}
	creds, err := q.ListCredentialProfiles(ctx)
	if err != nil {
		return nil, err
	}
	for _, c := range creds {
		snap.creds[c.ID] = c
		snap.credN[strings.ToLower(c.Name)] = c
	}
	nets, err := q.ListNetworkProfiles(ctx)
	if err != nil {
		return nil, err
	}
	for _, n := range nets {
		snap.nets[n.ID] = n
		snap.netN[strings.ToLower(n.Name)] = n
	}
	insts, err := q.ListInstances(ctx)
	if err != nil {
		return nil, err
	}
	for _, i := range insts {
		snap.insts[i.ID] = i
		snap.instN[strings.ToLower(i.Name)] = i
	}
	tgts, err := q.ListTargets(ctx)
	if err != nil {
		return nil, err
	}
	for _, t := range tgts {
		snap.tgts[t.ID] = t
		snap.tgtR[strings.ToLower(t.Ref)] = t
	}
	pols, err := q.ListPolicies(ctx)
	if err != nil {
		return nil, err
	}
	for _, p := range pols {
		snap.pols[p.ID] = p
		snap.polN[strings.ToLower(p.Name)] = p
	}
	pats, err := q.ListRiskPatternRules(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range pats {
		snap.pats[r.ID] = r
		snap.patKey[patternNaturalKey(r.ScopeType, r.ScopeID, r.Name)] = r
	}
	return snap, nil
}

func patternNaturalKey(scopeType, scopeID, name string) string {
	return strings.ToLower(strings.TrimSpace(scopeType)) + "|" + strings.ToLower(strings.TrimSpace(scopeID)) + "|" + strings.ToLower(strings.TrimSpace(name))
}

type preparedTopology struct {
	globalSec        *types.GlobalSecurityConfig
	globalChanged    bool
	envs             []plannedEnv
	syss             []plannedSys
	creds            []plannedCred
	nets             []plannedNet
	insts            []plannedInst
	tgts             []plannedTarget
	pols             []plannedPolicy
	pats             []plannedPattern
	summary          types.TopologyImportSummary
	changedCount     int
	bundleCredIDs    []string
}

type plannedEnv struct {
	item   types.Environment
	action string // created | updated | unchanged
}
type plannedSys struct {
	item   types.System
	action string
}
type plannedCred struct {
	item   types.CredentialProfile
	action string
}
type plannedNet struct {
	item   types.NetworkProfile
	action string
}
type plannedInst struct {
	item   types.Instance
	action string
}
type plannedTarget struct {
	item   types.Target
	action string
}
type plannedPolicy struct {
	item   types.PolicyRuleSet
	action string
}
type plannedPattern struct {
	item   types.RiskPatternRule
	action string
}

func prepareTopologyBundle(b types.TopologyBundle, snap *topologySnapshot, assignRealIDs bool) (*preparedTopology, error) {
	if b.SchemaVersion < 0 || b.SchemaVersion > 1 {
		return nil, fmt.Errorf("unsupported topology schema_version %d (supported: 1)", b.SchemaVersion)
	}
	if b.GlobalSecurity != nil {
		if err := policy.ValidateGlobalConfig(*b.GlobalSecurity); err != nil {
			return nil, fmt.Errorf("invalid global_security in topology: %w", err)
		}
	}

	prep := &preparedTopology{}
	if b.GlobalSecurity != nil {
		cfg := *b.GlobalSecurity
		if cfg.DefaultApprovalProvider == "" {
			cfg.DefaultApprovalProvider = "local-web"
		}
		prep.globalSec = &cfg
		if globalSecurityEqual(snap.global, cfg) {
			prep.summary.GlobalSecurityAction = "unchanged"
		} else {
			prep.summary.GlobalSecurityAction = "updated"
			prep.globalChanged = true
			prep.changedCount++
		}
	}

	makeID := func(prefix, natural string, seq int) string {
		if assignRealIDs {
			return newID(prefix)
		}
		return fmt.Sprintf("__planned_%s_%d_%s", prefix, seq, strings.ToLower(strings.TrimSpace(natural)))
	}

	// 1. Pre-assign canonical IDs and build lookup maps (bundle ID/natural key + existing DB).
	envCodeMap := map[string]string{}
	envSet := map[string]bool{}
	for code := range snap.envs {
		envSet[code] = true
	}
	envs := make([]types.Environment, len(b.Environments))
	for i, env := range b.Environments {
		if strings.TrimSpace(env.Code) == "" {
			return nil, fmt.Errorf("environment code is required")
		}
		if existing, ok := snap.envs[strings.ToLower(env.Code)]; ok {
			env.Code = existing.Code
		}
		if env.SafetyTier == "" {
			env.SafetyTier = types.SafetyTierGuarded
		}
		switch env.SafetyTier {
		case types.SafetyTierYOLO, types.SafetyTierGuarded, types.SafetyTierStrict:
		default:
			return nil, fmt.Errorf("invalid safety_tier %q for environment %q", env.SafetyTier, env.Code)
		}
		if len(env.Labels) == 0 {
			env.Labels = map[string]string{"en": env.Code}
		}
		if env.Color == "" {
			env.Color = "#6B7280"
		}
		envCodeMap[strings.ToLower(env.Code)] = env.Code
		envSet[strings.ToLower(env.Code)] = true
		envs[i] = env
	}

	sysMap := map[string]string{}
	sysSet := map[string]bool{}
	for id, s := range snap.syss {
		sysSet[id] = true
		sysMap["slug:"+strings.ToLower(s.Slug)] = id
	}
	syss := make([]types.System, len(b.Systems))
	for i, sys := range b.Systems {
		if strings.TrimSpace(sys.Slug) == "" || strings.TrimSpace(sys.Name) == "" {
			return nil, fmt.Errorf("system slug and name are required")
		}
		origID := sys.ID
		if existing, ok := snap.syss[sys.ID]; ok {
			sys.ID = existing.ID
			if len(sys.WorkspacePaths) == 0 && len(existing.WorkspacePaths) > 0 {
				sys.WorkspacePaths = append([]string(nil), existing.WorkspacePaths...)
			}
			if sys.GitRemotes == nil && len(existing.GitRemotes) > 0 {
				sys.GitRemotes = append([]string(nil), existing.GitRemotes...)
			}
		} else if existing, ok := snap.sysByS[strings.ToLower(sys.Slug)]; ok {
			sys.ID = existing.ID
			if len(sys.WorkspacePaths) == 0 && len(existing.WorkspacePaths) > 0 {
				sys.WorkspacePaths = append([]string(nil), existing.WorkspacePaths...)
			}
			if sys.GitRemotes == nil && len(existing.GitRemotes) > 0 {
				sys.GitRemotes = append([]string(nil), existing.GitRemotes...)
			}
		} else if sys.ID == "" {
			sys.ID = makeID("sys", sys.Slug, i)
		}
		if sys.Tags == nil {
			sys.Tags = []string{}
		}
		if sys.WorkspacePaths == nil {
			sys.WorkspacePaths = []string{}
		}
		sys.GitRemotes = config.NormalizeGitRemotes(sys.GitRemotes)
		if origID != "" {
			sysMap[origID] = sys.ID
		}
		sysMap["slug:"+strings.ToLower(sys.Slug)] = sys.ID
		sysSet[sys.ID] = true
		syss[i] = sys
	}

	credMap := map[string]string{}
	credSet := map[string]bool{}
	for id, c := range snap.creds {
		credSet[id] = true
		credMap["name:"+strings.ToLower(c.Name)] = id
	}
	creds := make([]types.CredentialProfile, len(b.CredentialProfiles))
	for i, cp := range b.CredentialProfiles {
		if strings.TrimSpace(cp.Name) == "" {
			return nil, fmt.Errorf("credential name is required")
		}
		origID := cp.ID
		if existing, ok := snap.creds[cp.ID]; ok {
			cp.ID = existing.ID
		} else if existing, ok := snap.credN[strings.ToLower(cp.Name)]; ok {
			cp.ID = existing.ID
		} else if cp.ID == "" {
			cp.ID = makeID("cred", cp.Name, i)
		}
		if cp.Kind == "" {
			cp.Kind = types.CredKeychain
		}
		switch cp.Kind {
		case types.CredKeychain, types.CredEnvRef, types.CredExecProvider:
		default:
			return nil, fmt.Errorf("invalid credential kind %q for %q", cp.Kind, cp.Name)
		}
		if cp.AccessLevel == "" {
			cp.AccessLevel = types.AccessReadOnly
		}
		switch cp.AccessLevel {
		case types.AccessReadOnly, types.AccessReadWrite:
		default:
			return nil, fmt.Errorf("invalid access_level %q for credential %q", cp.AccessLevel, cp.Name)
		}
		if origID != "" {
			credMap[origID] = cp.ID
		}
		credMap["name:"+strings.ToLower(cp.Name)] = cp.ID
		credSet[cp.ID] = true
		creds[i] = cp
		prep.bundleCredIDs = append(prep.bundleCredIDs, cp.ID)
	}

	netMap := map[string]string{}
	netSet := map[string]bool{}
	for id, n := range snap.nets {
		netSet[id] = true
		netMap["name:"+strings.ToLower(n.Name)] = id
	}
	nets := make([]types.NetworkProfile, len(b.NetworkProfiles))
	for i, np := range b.NetworkProfiles {
		if strings.TrimSpace(np.Name) == "" {
			return nil, fmt.Errorf("network profile name is required")
		}
		origID := np.ID
		if existing, ok := snap.nets[np.ID]; ok {
			np.ID = existing.ID
		} else if existing, ok := snap.netN[strings.ToLower(np.Name)]; ok {
			np.ID = existing.ID
		} else if np.ID == "" {
			np.ID = makeID("net", np.Name, i)
		}
		if np.Mode == "" {
			np.Mode = types.NetworkDirect
		}
		switch np.Mode {
		case types.NetworkDirect, types.NetworkSSHTunnel, types.NetworkSOCKS5, types.NetworkHTTPProxy:
		default:
			return nil, fmt.Errorf("invalid network mode %q for %q", np.Mode, np.Name)
		}
		if np.BastionPort == 0 && np.Mode == types.NetworkSSHTunnel {
			np.BastionPort = 22
		}
		if origID != "" {
			netMap[origID] = np.ID
		}
		netMap["name:"+strings.ToLower(np.Name)] = np.ID
		netSet[np.ID] = true
		nets[i] = np
	}

	instMap := map[string]string{}
	instSet := map[string]bool{}
	for id, i := range snap.insts {
		instSet[id] = true
		instMap["name:"+strings.ToLower(i.Name)] = id
	}
	insts := make([]types.Instance, len(b.Instances))
	for i, inst := range b.Instances {
		if strings.TrimSpace(inst.Name) == "" || strings.TrimSpace(inst.Engine) == "" {
			return nil, fmt.Errorf("instance name and engine are required")
		}
		origID := inst.ID
		if existing, ok := snap.insts[inst.ID]; ok {
			inst.ID = existing.ID
		} else if existing, ok := snap.instN[strings.ToLower(inst.Name)]; ok {
			inst.ID = existing.ID
		} else if inst.ID == "" {
			inst.ID = makeID("inst", inst.Name, i)
		}
		if inst.Role == "" {
			inst.Role = types.RoleStandalone
		}
		switch inst.Role {
		case types.RolePrimary, types.RoleReplica, types.RoleStandalone:
		default:
			return nil, fmt.Errorf("invalid instance role %q for %q", inst.Role, inst.Name)
		}
		if inst.Params == nil {
			inst.Params = map[string]string{}
		}
		if origID != "" {
			instMap[origID] = inst.ID
		}
		instMap["name:"+strings.ToLower(inst.Name)] = inst.ID
		instSet[inst.ID] = true
		insts[i] = inst
	}

	tgtMap := map[string]string{}
	tgtSet := map[string]bool{}
	for id, t := range snap.tgts {
		tgtSet[id] = true
		tgtMap["ref:"+strings.ToLower(t.Ref)] = id
	}
	tgts := make([]types.Target, len(b.Targets))
	for i, tgt := range b.Targets {
		if strings.TrimSpace(tgt.Ref) == "" {
			return nil, fmt.Errorf("target ref is required")
		}
		origID := tgt.ID
		if existing, ok := snap.tgts[tgt.ID]; ok {
			tgt.ID = existing.ID
		} else if existing, ok := snap.tgtR[strings.ToLower(tgt.Ref)]; ok {
			tgt.ID = existing.ID
		} else if tgt.ID == "" {
			tgt.ID = makeID("tgt", tgt.Ref, i)
		}
		if tgt.Status == "" {
			tgt.Status = types.TargetActive
		}
		switch tgt.Status {
		case types.TargetActive, types.TargetMaintenance, types.TargetDisabled:
		default:
			return nil, fmt.Errorf("invalid target status %q for %q", tgt.Status, tgt.Ref)
		}
		if tgt.LinkedSystemIDs == nil {
			tgt.LinkedSystemIDs = []string{}
		}
		if origID != "" {
			tgtMap[origID] = tgt.ID
		}
		tgtMap["ref:"+strings.ToLower(tgt.Ref)] = tgt.ID
		tgtSet[tgt.ID] = true
		tgts[i] = tgt
	}

	polMap := map[string]string{}
	polSet := map[string]bool{}
	for id, p := range snap.pols {
		polSet[id] = true
		polMap["name:"+strings.ToLower(p.Name)] = id
	}
	pols := make([]types.PolicyRuleSet, len(b.Policies))
	for i, pol := range b.Policies {
		origID := pol.ID
		if existing, ok := snap.pols[pol.ID]; ok {
			pol.ID = existing.ID
		} else if existing, ok := snap.polN[strings.ToLower(pol.Name)]; ok {
			pol.ID = existing.ID
		} else if pol.ID == "" {
			pol.ID = makeID("pol", pol.Name, i)
		}
		if origID != "" {
			polMap[origID] = pol.ID
		}
		polMap["name:"+strings.ToLower(pol.Name)] = pol.ID
		polSet[pol.ID] = true
		pols[i] = pol
	}

	// Reference resolvers checking in-bundle IDs, in-bundle natural keys, and existing DB snapshot.
	resolveEnv := func(raw string) string {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			return ""
		}
		if mapped, ok := envCodeMap[strings.ToLower(trimmed)]; ok {
			return mapped
		}
		if existing, ok := snap.envs[strings.ToLower(trimmed)]; ok {
			return existing.Code
		}
		return trimmed
	}
	resolveSys := func(raw string) string {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			return ""
		}
		if mapped, ok := sysMap[trimmed]; ok {
			return mapped
		}
		if mapped, ok := sysMap["slug:"+strings.ToLower(trimmed)]; ok {
			return mapped
		}
		if existing, ok := snap.syss[trimmed]; ok {
			return existing.ID
		}
		if existing, ok := snap.sysByS[strings.ToLower(trimmed)]; ok {
			return existing.ID
		}
		return trimmed
	}
	resolveCred := func(raw string) string {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			return ""
		}
		if mapped, ok := credMap[trimmed]; ok {
			return mapped
		}
		if mapped, ok := credMap["name:"+strings.ToLower(trimmed)]; ok {
			return mapped
		}
		if existing, ok := snap.creds[trimmed]; ok {
			return existing.ID
		}
		if existing, ok := snap.credN[strings.ToLower(trimmed)]; ok {
			return existing.ID
		}
		return trimmed
	}
	resolveNet := func(raw string) string {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			return ""
		}
		if mapped, ok := netMap[trimmed]; ok {
			return mapped
		}
		if mapped, ok := netMap["name:"+strings.ToLower(trimmed)]; ok {
			return mapped
		}
		if existing, ok := snap.nets[trimmed]; ok {
			return existing.ID
		}
		if existing, ok := snap.netN[strings.ToLower(trimmed)]; ok {
			return existing.ID
		}
		return trimmed
	}
	resolveInst := func(raw string) string {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			return ""
		}
		if mapped, ok := instMap[trimmed]; ok {
			return mapped
		}
		if mapped, ok := instMap["name:"+strings.ToLower(trimmed)]; ok {
			return mapped
		}
		if existing, ok := snap.insts[trimmed]; ok {
			return existing.ID
		}
		if existing, ok := snap.instN[strings.ToLower(trimmed)]; ok {
			return existing.ID
		}
		return trimmed
	}
	resolveTgt := func(raw string) string {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			return ""
		}
		if mapped, ok := tgtMap[trimmed]; ok {
			return mapped
		}
		if mapped, ok := tgtMap["ref:"+strings.ToLower(trimmed)]; ok {
			return mapped
		}
		if existing, ok := snap.tgts[trimmed]; ok {
			return existing.ID
		}
		if existing, ok := snap.tgtR[strings.ToLower(trimmed)]; ok {
			return existing.ID
		}
		return trimmed
	}
	resolvePol := func(raw string) string {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			return ""
		}
		if mapped, ok := polMap[trimmed]; ok {
			return mapped
		}
		if mapped, ok := polMap["name:"+strings.ToLower(trimmed)]; ok {
			return mapped
		}
		if existing, ok := snap.pols[trimmed]; ok {
			return existing.ID
		}
		if existing, ok := snap.polN[strings.ToLower(trimmed)]; ok {
			return existing.ID
		}
		return trimmed
	}
	resolveScope := func(scopeType, scopeID string) string {
		switch scopeType {
		case "global":
			return "global"
		case "env":
			return resolveEnv(scopeID)
		case "system":
			return resolveSys(scopeID)
		case "target":
			return resolveTgt(scopeID)
		default:
			return strings.TrimSpace(scopeID)
		}
	}

	// 2. Remap all references, validate all constraints, and compute diff counts.
	for _, pol := range pols {
		pol.ScopeID = resolveScope(pol.ScopeType, pol.ScopeID)
		if err := policy.ValidateRuleSet(pol); err != nil {
			return nil, err
		}
		action := "created"
		if existing, ok := snap.pols[pol.ID]; ok {
			if policyEqual(existing, pol) {
				action = "unchanged"
			} else {
				action = "updated"
			}
		}
		recordPlanCount(&prep.summary.Policies, action)
		if action != "unchanged" {
			prep.changedCount++
		}
		prep.pols = append(prep.pols, plannedPolicy{item: pol, action: action})
	}

	for _, env := range envs {
		env.DefaultPolicyID = resolvePol(env.DefaultPolicyID)
		if env.DefaultPolicyID != "" && !polSet[env.DefaultPolicyID] {
			return nil, fmt.Errorf("%w: policy %q referenced by environment %q does not exist", ErrNotFound, env.DefaultPolicyID, env.Code)
		}
		action := "created"
		if existing, ok := snap.envs[strings.ToLower(env.Code)]; ok {
			if envEqual(existing, env) {
				action = "unchanged"
			} else {
				action = "updated"
			}
		}
		recordPlanCount(&prep.summary.Environments, action)
		if action != "unchanged" {
			prep.changedCount++
		}
		prep.envs = append(prep.envs, plannedEnv{item: env, action: action})
	}

	for _, sys := range syss {
		sys.DefaultPolicyID = resolvePol(sys.DefaultPolicyID)
		if sys.DefaultPolicyID != "" && !polSet[sys.DefaultPolicyID] {
			return nil, fmt.Errorf("%w: policy %q referenced by system %q does not exist", ErrNotFound, sys.DefaultPolicyID, sys.Slug)
		}
		action := "created"
		if existing, ok := snap.syss[sys.ID]; ok {
			if systemEqual(existing, sys) {
				action = "unchanged"
			} else {
				action = "updated"
			}
		}
		recordPlanCount(&prep.summary.Systems, action)
		if action != "unchanged" {
			prep.changedCount++
		}
		prep.syss = append(prep.syss, plannedSys{item: sys, action: action})
	}

	for _, cp := range creds {
		action := "created"
		if existing, ok := snap.creds[cp.ID]; ok {
			if credEqual(existing, cp) {
				action = "unchanged"
			} else {
				action = "updated"
			}
		}
		recordPlanCount(&prep.summary.CredentialProfiles, action)
		if action != "unchanged" {
			prep.changedCount++
		}
		prep.creds = append(prep.creds, plannedCred{item: cp, action: action})
	}

	for _, np := range nets {
		np.BastionCredentialID = resolveCred(np.BastionCredentialID)
		if np.BastionCredentialID != "" && !credSet[np.BastionCredentialID] {
			return nil, fmt.Errorf("%w: credential profile %q referenced by network %q does not exist", ErrNotFound, np.BastionCredentialID, np.Name)
		}
		action := "created"
		if existing, ok := snap.nets[np.ID]; ok {
			if netEqual(existing, np) {
				action = "unchanged"
			} else {
				action = "updated"
			}
		}
		recordPlanCount(&prep.summary.NetworkProfiles, action)
		if action != "unchanged" {
			prep.changedCount++
		}
		prep.nets = append(prep.nets, plannedNet{item: np, action: action})
	}

	// Sort instances root-first so primary_instance_id checks succeed regardless of bundle order.
	for pass := 0; pass < 2; pass++ {
		for _, inst := range insts {
			inst.NetworkProfileID = resolveNet(inst.NetworkProfileID)
			inst.PrimaryInstanceID = resolveInst(inst.PrimaryInstanceID)
			isDep := inst.PrimaryInstanceID != ""
			if (pass == 0 && isDep) || (pass == 1 && !isDep) {
				continue
			}
			if inst.NetworkProfileID != "" && !netSet[inst.NetworkProfileID] {
				return nil, fmt.Errorf("%w: network_profile_id %q referenced by instance %q does not exist", ErrNotFound, inst.NetworkProfileID, inst.Name)
			}
			if inst.PrimaryInstanceID != "" {
				if inst.PrimaryInstanceID == inst.ID {
					return nil, fmt.Errorf("instance %q cannot set primary_instance_id to itself", inst.Name)
				}
				if !instSet[inst.PrimaryInstanceID] {
					return nil, fmt.Errorf("%w: primary_instance_id %q referenced by instance %q does not exist", ErrNotFound, inst.PrimaryInstanceID, inst.Name)
				}
			}
			action := "created"
			if existing, ok := snap.insts[inst.ID]; ok {
				if instEqual(existing, inst) {
					action = "unchanged"
				} else {
					action = "updated"
				}
			}
			recordPlanCount(&prep.summary.Instances, action)
			if action != "unchanged" {
				prep.changedCount++
			}
			prep.insts = append(prep.insts, plannedInst{item: inst, action: action})
		}
	}

	for _, tgt := range tgts {
		tgt.OwnerSystemID = resolveSys(tgt.OwnerSystemID)
		if strings.TrimSpace(tgt.OwnerSystemID) == "" || !sysSet[tgt.OwnerSystemID] {
			return nil, fmt.Errorf("%w: owner_system_id %q referenced by target %q does not exist", ErrNotFound, tgt.OwnerSystemID, tgt.Ref)
		}
		var resolvedLinked []string
		for _, lid := range tgt.LinkedSystemIDs {
			rl := resolveSys(lid)
			if rl == "" || rl == tgt.OwnerSystemID {
				continue
			}
			if !sysSet[rl] {
				return nil, fmt.Errorf("%w: linked_system_id %q referenced by target %q does not exist", ErrNotFound, lid, tgt.Ref)
			}
			resolvedLinked = append(resolvedLinked, rl)
		}
		tgt.LinkedSystemIDs = resolvedLinked
		tgt.EnvironmentCode = resolveEnv(tgt.EnvironmentCode)
		if strings.TrimSpace(tgt.EnvironmentCode) == "" || !envSet[strings.ToLower(tgt.EnvironmentCode)] {
			return nil, fmt.Errorf("%w: environment_code %q referenced by target %q does not exist", ErrNotFound, tgt.EnvironmentCode, tgt.Ref)
		}
		tgt.InstanceID = resolveInst(tgt.InstanceID)
		if strings.TrimSpace(tgt.InstanceID) == "" || !instSet[tgt.InstanceID] {
			return nil, fmt.Errorf("%w: instance_id %q referenced by target %q does not exist", ErrNotFound, tgt.InstanceID, tgt.Ref)
		}
		tgt.ROCredentialID = resolveCred(tgt.ROCredentialID)
		if tgt.ROCredentialID != "" && !credSet[tgt.ROCredentialID] {
			return nil, fmt.Errorf("%w: ro_credential_id %q referenced by target %q does not exist", ErrNotFound, tgt.ROCredentialID, tgt.Ref)
		}
		tgt.RWCredentialID = resolveCred(tgt.RWCredentialID)
		if tgt.RWCredentialID != "" && !credSet[tgt.RWCredentialID] {
			return nil, fmt.Errorf("%w: rw_credential_id %q referenced by target %q does not exist", ErrNotFound, tgt.RWCredentialID, tgt.Ref)
		}
		tgt.PolicyOverrideID = resolvePol(tgt.PolicyOverrideID)
		if tgt.PolicyOverrideID != "" && !polSet[tgt.PolicyOverrideID] {
			return nil, fmt.Errorf("%w: policy_override_id %q referenced by target %q does not exist", ErrNotFound, tgt.PolicyOverrideID, tgt.Ref)
		}
		action := "created"
		if existing, ok := snap.tgts[tgt.ID]; ok {
			if targetEqual(existing, tgt) {
				action = "unchanged"
			} else {
				action = "updated"
			}
		}
		recordPlanCount(&prep.summary.Targets, action)
		if action != "unchanged" {
			prep.changedCount++
		}
		prep.tgts = append(prep.tgts, plannedTarget{item: tgt, action: action})
	}

	for i, pat := range b.RiskPatternRules {
		pat.Name = strings.TrimSpace(pat.Name)
		pat.ScopeID = resolveScope(pat.ScopeType, pat.ScopeID)
		if err := policy.ValidateRiskPatternRule(pat); err != nil {
			return nil, err
		}
		if existing, ok := snap.pats[pat.ID]; ok {
			pat.ID = existing.ID
		} else if existing, ok := snap.patKey[patternNaturalKey(pat.ScopeType, pat.ScopeID, pat.Name)]; ok {
			pat.ID = existing.ID
		} else if pat.ID == "" {
			pat.ID = makeID("pat", pat.Name, i)
		}
		if pat.Engines == nil {
			pat.Engines = []string{}
		}
		if pat.Families == nil {
			pat.Families = []types.EngineFamily{}
		}
		action := "created"
		if existing, ok := snap.pats[pat.ID]; ok {
			if patternEqual(existing, pat) {
				action = "unchanged"
			} else {
				action = "updated"
			}
		}
		recordPlanCount(&prep.summary.RiskPatternRules, action)
		if action != "unchanged" {
			prep.changedCount++
		}
		prep.pats = append(prep.pats, plannedPattern{item: pat, action: action})
	}

	return prep, nil
}

// PlanTopologyImport validates a TopologyBundle and computes a read-only diff without mutating SQLite.
func (s *Store) PlanTopologyImport(ctx context.Context, b types.TopologyBundle) (types.TopologyImportResult, error) {
	snap, err := loadTopologySnapshot(ctx, s)
	if err != nil {
		return types.TopologyImportResult{}, err
	}
	prep, err := prepareTopologyBundle(b, snap, false)
	if err != nil {
		return types.TopologyImportResult{}, err
	}
	status := "planned"
	if prep.changedCount == 0 {
		status = "unchanged"
	}
	return types.TopologyImportResult{
		DryRun:  true,
		Status:  status,
		Summary: prep.summary,
	}, nil
}

// ImportTopologyWithResult imports a TopologyBundle atomically, resolving IDs & natural keys, and returns the applied summary.
func (s *Store) ImportTopologyWithResult(ctx context.Context, actor string, b types.TopologyBundle) (types.TopologyImportResult, error) {
	var result types.TopologyImportResult
	now := nowUTC()
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		snap, err := loadTopologySnapshot(ctx, &txSnapshotQuerier{tx: tx})
		if err != nil {
			return err
		}
		prep, err := prepareTopologyBundle(b, snap, true)
		if err != nil {
			return err
		}
		if prep.changedCount == 0 {
			result = types.TopologyImportResult{
				DryRun:  false,
				Status:  "unchanged",
				Summary: prep.summary,
			}
			return nil
		}

		if prep.globalChanged && prep.globalSec != nil {
			cfg := *prep.globalSec
			cfg.UpdatedAtUTC = now
			if _, err := tx.ExecContext(ctx, `
				UPDATE global_security_config SET
					exec_timeout_sec = ?,
					approval_timeout_sec = ?,
					max_rows = ?,
					max_bytes = ?,
					explain_max_rows = ?,
					prod_read_only_freeze = ?,
					block_multi_statement_in_prod = ?,
					default_approval_provider = ?,
					redact_audit_literals = ?,
					require_reason_for_approval = ?,
					updated_at_utc = ?
				WHERE id = 1`,
				cfg.ExecTimeoutSec, cfg.ApprovalTimeoutSec, cfg.MaxRows, cfg.MaxBytes, cfg.ExplainMaxRows,
				boolToInt(cfg.ProdReadOnlyFreeze), boolToInt(cfg.BlockMultiStatementInProd),
				cfg.DefaultApprovalProvider, boolToInt(cfg.RedactAuditLiterals), boolToInt(cfg.RequireReasonForApproval), now); err != nil {
				return err
			}
			if err := s.appendAuditTx(ctx, tx, actor, "global_security.update", "global", "", cfg, now); err != nil {
				return err
			}
		}

		for _, it := range prep.pols {
			if it.action == "unchanged" {
				continue
			}
			if _, err := s.upsertPolicyTx(ctx, tx, actor, it.item, now); err != nil {
				return err
			}
		}
		for _, it := range prep.envs {
			if it.action == "unchanged" {
				continue
			}
			if _, err := s.upsertEnvironmentTx(ctx, tx, actor, it.item, now); err != nil {
				return err
			}
		}
		for _, it := range prep.syss {
			if it.action == "unchanged" {
				continue
			}
			if _, err := s.upsertSystemTx(ctx, tx, actor, it.item, now); err != nil {
				return err
			}
		}
		for _, it := range prep.creds {
			if it.action == "unchanged" {
				continue
			}
			if _, err := s.upsertCredentialProfileTx(ctx, tx, actor, it.item, now); err != nil {
				return err
			}
		}
		for _, it := range prep.nets {
			if it.action == "unchanged" {
				continue
			}
			if _, err := s.upsertNetworkProfileTx(ctx, tx, actor, it.item, now); err != nil {
				return err
			}
		}
		for _, it := range prep.insts {
			if it.action == "unchanged" {
				continue
			}
			if _, err := s.upsertInstanceTx(ctx, tx, actor, it.item, now); err != nil {
				return err
			}
		}
		for _, it := range prep.tgts {
			if it.action == "unchanged" {
				continue
			}
			if _, err := s.upsertTargetTx(ctx, tx, actor, it.item, now); err != nil {
				return err
			}
		}
		for _, it := range prep.pats {
			if it.action == "unchanged" {
				continue
			}
			if _, err := s.upsertRiskPatternRuleTx(ctx, tx, actor, it.item, now); err != nil {
				return err
			}
		}

		if err := s.appendAuditTx(ctx, tx, actor, "topology.import", "catalog", "", map[string]any{
			"schema_version":      b.SchemaVersion,
			"environments":        len(prep.envs),
			"systems":             len(prep.syss),
			"credential_profiles": len(prep.creds),
			"network_profiles":    len(prep.nets),
			"instances":           len(prep.insts),
			"targets":             len(prep.tgts),
			"policies":            len(prep.pols),
			"risk_pattern_rules":  len(prep.pats),
		}, now); err != nil {
			return err
		}

		result = types.TopologyImportResult{
			DryRun:  false,
			Status:  "applied",
			Summary: prep.summary,
		}
		return nil
	})
	return result, err
}

type txSnapshotQuerier struct {
	tx *sql.Tx
}

func (q *txSnapshotQuerier) GetGlobalSecurityConfig(ctx context.Context) (types.GlobalSecurityConfig, error) {
	var cfg types.GlobalSecurityConfig
	var freeze, blockMulti, redact, reqReason int
	err := q.tx.QueryRowContext(ctx, `
		SELECT exec_timeout_sec, approval_timeout_sec, max_rows, max_bytes, explain_max_rows,
			prod_read_only_freeze, block_multi_statement_in_prod, default_approval_provider, redact_audit_literals,
			require_reason_for_approval, updated_at_utc
		FROM global_security_config WHERE id = 1`).
		Scan(&cfg.ExecTimeoutSec, &cfg.ApprovalTimeoutSec, &cfg.MaxRows, &cfg.MaxBytes, &cfg.ExplainMaxRows,
			&freeze, &blockMulti, &cfg.DefaultApprovalProvider, &redact, &reqReason, &cfg.UpdatedAtUTC)
	if err != nil {
		return cfg, err
	}
	cfg.ProdReadOnlyFreeze = freeze == 1
	cfg.BlockMultiStatementInProd = blockMulti == 1
	cfg.RedactAuditLiterals = redact == 1
	cfg.RequireReasonForApproval = reqReason == 1
	return cfg, nil
}

func (q *txSnapshotQuerier) ListEnvironments(ctx context.Context) ([]types.Environment, error) {
	rows, err := q.tx.QueryContext(ctx, `SELECT code, safety_tier, labels_json, color, sort_order, default_policy_id, created_at_utc, updated_at_utc FROM environments ORDER BY sort_order ASC, code ASC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []types.Environment
	for rows.Next() {
		var env types.Environment
		var labelsJSON string
		if err := rows.Scan(&env.Code, &env.SafetyTier, &labelsJSON, &env.Color, &env.SortOrder, &env.DefaultPolicyID, &env.CreatedAtUTC, &env.UpdatedAtUTC); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(labelsJSON), &env.Labels)
		if env.Labels == nil {
			env.Labels = map[string]string{"en": env.Code}
		}
		out = append(out, env)
	}
	return out, rows.Err()
}

func (q *txSnapshotQuerier) ListSystems(ctx context.Context) ([]types.System, error) {
	rows, err := q.tx.QueryContext(ctx, `SELECT id, slug, name, owner, description, tags_json, workspace_paths_json, git_remotes_json, default_policy_id, created_at_utc, updated_at_utc FROM systems ORDER BY slug ASC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []types.System
	for rows.Next() {
		var sys types.System
		var tagsJSON, wsJSON, gitJSON string
		if err := rows.Scan(&sys.ID, &sys.Slug, &sys.Name, &sys.Owner, &sys.Description, &tagsJSON, &wsJSON, &gitJSON, &sys.DefaultPolicyID, &sys.CreatedAtUTC, &sys.UpdatedAtUTC); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(tagsJSON), &sys.Tags)
		_ = json.Unmarshal([]byte(wsJSON), &sys.WorkspacePaths)
		_ = json.Unmarshal([]byte(gitJSON), &sys.GitRemotes)
		if sys.Tags == nil {
			sys.Tags = []string{}
		}
		if sys.WorkspacePaths == nil {
			sys.WorkspacePaths = []string{}
		}
		if sys.GitRemotes == nil {
			sys.GitRemotes = []string{}
		}
		out = append(out, sys)
	}
	return out, rows.Err()
}

func (q *txSnapshotQuerier) ListCredentialProfiles(ctx context.Context) ([]types.CredentialProfile, error) {
	rows, err := q.tx.QueryContext(ctx, `SELECT id, name, kind, access_level, username, env_var_name, exec_command, created_at_utc, updated_at_utc FROM credential_profiles ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []types.CredentialProfile
	for rows.Next() {
		var cp types.CredentialProfile
		if err := rows.Scan(&cp.ID, &cp.Name, &cp.Kind, &cp.AccessLevel, &cp.Username, &cp.EnvVarName, &cp.ExecCommand, &cp.CreatedAtUTC, &cp.UpdatedAtUTC); err != nil {
			return nil, err
		}
		out = append(out, cp)
	}
	return out, rows.Err()
}

func (q *txSnapshotQuerier) ListNetworkProfiles(ctx context.Context) ([]types.NetworkProfile, error) {
	rows, err := q.tx.QueryContext(ctx, `SELECT id, name, mode, proxy_url, bastion_host, bastion_port, bastion_user, bastion_credential_id, ssh_strict_host_key, tls_mode, created_at_utc, updated_at_utc FROM network_profiles ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []types.NetworkProfile
	for rows.Next() {
		var np types.NetworkProfile
		var strict int
		if err := rows.Scan(&np.ID, &np.Name, &np.Mode, &np.ProxyURL, &np.BastionHost, &np.BastionPort, &np.BastionUser, &np.BastionCredentialID, &strict, &np.TLSMode, &np.CreatedAtUTC, &np.UpdatedAtUTC); err != nil {
			return nil, err
		}
		np.SSHStrictHostKey = strict == 1
		out = append(out, np)
	}
	return out, rows.Err()
}

func (q *txSnapshotQuerier) ListInstances(ctx context.Context) ([]types.Instance, error) {
	rows, err := q.tx.QueryContext(ctx, `SELECT id, name, engine, host, port, role, primary_instance_id, network_profile_id, tls_mode, params_json, capabilities_json, capabilities_detected_at_utc, created_at_utc, updated_at_utc FROM instances ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []types.Instance
	for rows.Next() {
		var inst types.Instance
		var paramsJSON, capsJSON string
		if err := rows.Scan(&inst.ID, &inst.Name, &inst.Engine, &inst.Host, &inst.Port, &inst.Role, &inst.PrimaryInstanceID, &inst.NetworkProfileID, &inst.TLSMode, &paramsJSON, &capsJSON, &inst.CapabilitiesDetectedAt, &inst.CreatedAtUTC, &inst.UpdatedAtUTC); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(paramsJSON), &inst.Params)
		if inst.Params == nil {
			inst.Params = map[string]string{}
		}
		out = append(out, inst)
	}
	return out, rows.Err()
}

func (q *txSnapshotQuerier) ListTargets(ctx context.Context) ([]types.Target, error) {
	rows, err := q.tx.QueryContext(ctx, `SELECT id, ref, alias, owner_system_id, environment_code, instance_id, database_name, ro_credential_id, rw_credential_id, policy_override_id, status, description, created_at_utc, updated_at_utc FROM targets ORDER BY ref ASC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []types.Target
	for rows.Next() {
		var t types.Target
		if err := rows.Scan(&t.ID, &t.Ref, &t.Alias, &t.OwnerSystemID, &t.EnvironmentCode, &t.InstanceID, &t.DatabaseName, &t.ROCredentialID, &t.RWCredentialID, &t.PolicyOverrideID, &t.Status, &t.Description, &t.CreatedAtUTC, &t.UpdatedAtUTC); err != nil {
			return nil, err
		}
		t.LinkedSystemIDs = []string{}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	linkRows, err := q.tx.QueryContext(ctx, `SELECT target_id, system_id FROM target_linked_systems ORDER BY system_id ASC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = linkRows.Close() }()
	links := map[string][]string{}
	for linkRows.Next() {
		var tid, sid string
		if err := linkRows.Scan(&tid, &sid); err != nil {
			return nil, err
		}
		links[tid] = append(links[tid], sid)
	}
	for i := range out {
		if l, ok := links[out[i].ID]; ok {
			out[i].LinkedSystemIDs = l
		}
	}
	return out, linkRows.Err()
}

func (q *txSnapshotQuerier) ListPolicies(ctx context.Context) ([]types.PolicyRuleSet, error) {
	rows, err := q.tx.QueryContext(ctx, `
		SELECT id, name, scope_type, scope_id,
			allow_safe_read, require_approval_on_high_cost_read, require_approval_on_write,
			require_approval_on_ddl, require_approval_on_admin, require_approval_on_unknown,
			allow_multi_statement, exec_timeout_sec, approval_timeout_sec, max_rows, max_bytes, explain_max_rows,
			scan_read_mode, approval_provider, created_at_utc, updated_at_utc
		FROM policies ORDER BY scope_type ASC, name ASC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []types.PolicyRuleSet
	for rows.Next() {
		var p types.PolicyRuleSet
		var aSafe, rHigh, rWrite, rDDL, rAdmin, rUnk, aMulti, execT, appT, maxR, maxB, expR sql.NullInt64
		if err := rows.Scan(&p.ID, &p.Name, &p.ScopeType, &p.ScopeID,
			&aSafe, &rHigh, &rWrite, &rDDL, &rAdmin, &rUnk, &aMulti,
			&execT, &appT, &maxR, &maxB, &expR,
			&p.ScanReadMode, &p.ApprovalProvider, &p.CreatedAtUTC, &p.UpdatedAtUTC); err != nil {
			return nil, err
		}
		p.AllowSafeRead = nullIntToBoolPtr(aSafe)
		p.RequireApprovalOnHighCostRead = nullIntToBoolPtr(rHigh)
		p.RequireApprovalOnWrite = nullIntToBoolPtr(rWrite)
		p.RequireApprovalOnDDL = nullIntToBoolPtr(rDDL)
		p.RequireApprovalOnAdmin = nullIntToBoolPtr(rAdmin)
		p.RequireApprovalOnUnknown = nullIntToBoolPtr(rUnk)
		p.AllowMultiStatement = nullIntToBoolPtr(aMulti)
		p.ExecTimeoutSec = nullIntToIntPtr(execT)
		p.ApprovalTimeoutSec = nullIntToIntPtr(appT)
		p.MaxRows = nullIntToIntPtr(maxR)
		p.MaxBytes = nullIntToInt64Ptr(maxB)
		p.ExplainMaxRows = nullIntToInt64Ptr(expR)
		out = append(out, p)
	}
	return out, rows.Err()
}

func (q *txSnapshotQuerier) ListRiskPatternRules(ctx context.Context) ([]types.RiskPatternRule, error) {
	rows, err := q.tx.QueryContext(ctx, `
		SELECT id, name, description, scope_type, scope_id, enabled, builtin_pack,
			engines_json, families_json, action, confirm_title, confirm_message,
			approval_provider, condition_json, priority, created_at_utc, updated_at_utc
		FROM risk_pattern_rules ORDER BY priority DESC, name ASC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []types.RiskPatternRule
	for rows.Next() {
		var r types.RiskPatternRule
		var enabledInt int
		var enginesJSON, familiesJSON, condJSON string
		if err := rows.Scan(
			&r.ID, &r.Name, &r.Description, &r.ScopeType, &r.ScopeID, &enabledInt, &r.BuiltinPack,
			&enginesJSON, &familiesJSON, &r.Action, &r.ConfirmTitle, &r.ConfirmMessage,
			&r.ApprovalProvider, &condJSON, &r.Priority, &r.CreatedAtUTC, &r.UpdatedAtUTC,
		); err != nil {
			return nil, err
		}
		r.Enabled = enabledInt == 1
		_ = json.Unmarshal([]byte(enginesJSON), &r.Engines)
		_ = json.Unmarshal([]byte(familiesJSON), &r.Families)
		_ = json.Unmarshal([]byte(condJSON), &r.Condition)
		if r.Engines == nil {
			r.Engines = []string{}
		}
		if r.Families == nil {
			r.Families = []types.EngineFamily{}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func recordPlanCount(c *types.ResourcePlanCounts, action string) {
	switch action {
	case "created":
		c.Created++
	case "updated":
		c.Updated++
	case "unchanged":
		c.Unchanged++
	}
}

func globalSecurityEqual(a, b types.GlobalSecurityConfig) bool {
	a.UpdatedAtUTC = ""
	b.UpdatedAtUTC = ""
	if a.DefaultApprovalProvider == "" {
		a.DefaultApprovalProvider = "local-web"
	}
	if b.DefaultApprovalProvider == "" {
		b.DefaultApprovalProvider = "local-web"
	}
	return a == b
}

func envEqual(a, b types.Environment) bool {
	a.CreatedAtUTC, a.UpdatedAtUTC = "", ""
	b.CreatedAtUTC, b.UpdatedAtUTC = "", ""
	return reflect.DeepEqual(a, b)
}

func systemEqual(a, b types.System) bool {
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

func credEqual(a, b types.CredentialProfile) bool {
	a.CreatedAtUTC, a.UpdatedAtUTC, a.HasSecret = "", "", false
	b.CreatedAtUTC, b.UpdatedAtUTC, b.HasSecret = "", "", false
	return a == b
}

func netEqual(a, b types.NetworkProfile) bool {
	a.CreatedAtUTC, a.UpdatedAtUTC = "", ""
	b.CreatedAtUTC, b.UpdatedAtUTC = "", ""
	return a == b
}

func instEqual(a, b types.Instance) bool {
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

func targetEqual(a, b types.Target) bool {
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

func policyEqual(a, b types.PolicyRuleSet) bool {
	a.CreatedAtUTC, a.UpdatedAtUTC = "", ""
	b.CreatedAtUTC, b.UpdatedAtUTC = "", ""
	return reflect.DeepEqual(a, b)
}

func patternEqual(a, b types.RiskPatternRule) bool {
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

// Keep unused error reference clean when callers check errors.Is(..., ErrNotFound).
var _ = errors.Is
