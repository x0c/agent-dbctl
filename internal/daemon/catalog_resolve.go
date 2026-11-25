package daemon

import (
	"context"
	"path/filepath"
	"sort"
	"strings"

	"github.com/x0c/agent-dbctl/internal/classify"
	"github.com/x0c/agent-dbctl/internal/config"
	"github.com/x0c/agent-dbctl/internal/policy"
	"github.com/x0c/agent-dbctl/internal/types"
)

// ListFilter narrows db list results.
type ListFilter struct {
	System       string `json:"system,omitempty"`
	Env          string `json:"env,omitempty"`
	Engine       string `json:"engine,omitempty"`
	Tag          string `json:"tag,omitempty"`
	Search       string `json:"search,omitempty"`
	WorkspaceCWD string `json:"workspace_cwd,omitempty"`
}

// TargetLookupError provides structured ambiguity or zero-hit recovery metadata.
type TargetLookupError struct {
	Code              string
	Message           string
	Candidates        []types.TargetDetail
	SimilarNames      []string
	UnsearchedSources []string
}

func (e *TargetLookupError) Error() string {
	return e.Message
}

// BuildTargetDetails enriches all targets with system, env, instance, network, credentials (secret-free), and effective policy.
func (s *Service) BuildTargetDetails(ctx context.Context, workspaceCWD string) ([]types.TargetDetail, error) {
	global, err := s.store.GetGlobalSecurityConfig(ctx)
	if err != nil {
		return nil, err
	}
	systems, err := s.store.ListSystems(ctx)
	if err != nil {
		return nil, err
	}
	envs, err := s.store.ListEnvironments(ctx)
	if err != nil {
		return nil, err
	}
	nets, err := s.store.ListNetworkProfiles(ctx)
	if err != nil {
		return nil, err
	}
	creds, err := s.store.ListCredentialProfiles(ctx)
	if err != nil {
		return nil, err
	}
	insts, err := s.store.ListInstances(ctx)
	if err != nil {
		return nil, err
	}
	targets, err := s.store.ListTargets(ctx)
	if err != nil {
		return nil, err
	}
	policies, err := s.store.ListPolicies(ctx)
	if err != nil {
		return nil, err
	}
	patternRules, err := s.store.ListRiskPatternRules(ctx)
	if err != nil {
		return nil, err
	}

	sysMap := make(map[string]types.System, len(systems))
	for _, item := range systems {
		sysMap[item.ID] = item
	}
	envMap := make(map[string]types.Environment, len(envs))
	for _, item := range envs {
		envMap[item.Code] = item
	}
	netMap := make(map[string]types.NetworkProfile, len(nets))
	for _, item := range nets {
		netMap[item.ID] = item
	}
	credMap := make(map[string]types.CredentialProfile, len(creds))
	for _, item := range creds {
		item.HasSecret = s.hasCredentialSecret(ctx, item)
		credMap[item.ID] = item
	}
	instMap := make(map[string]types.Instance, len(insts))
	for _, item := range insts {
		instMap[item.ID] = item
	}

	out := make([]types.TargetDetail, 0, len(targets))
	for _, t := range targets {
		d := types.TargetDetail{Target: t}
		var ownerPtr *types.System
		if sys, ok := sysMap[t.OwnerSystemID]; ok {
			sysCopy := sys
			ownerPtr = &sysCopy
			d.OwnerSystem = ownerPtr
			if matchesWorkspace(workspaceCWD, sys.WorkspacePaths) {
				d.WorkspaceMatch = true
			}
		}
		for _, lid := range t.LinkedSystemIDs {
			if lsys, ok := sysMap[lid]; ok {
				d.LinkedSystems = append(d.LinkedSystems, lsys)
				if matchesWorkspace(workspaceCWD, lsys.WorkspacePaths) {
					d.WorkspaceMatch = true
				}
			}
		}
		var envPtr *types.Environment
		if env, ok := envMap[t.EnvironmentCode]; ok {
			envCopy := env
			envPtr = &envCopy
			d.Environment = envPtr
		}
		if inst, ok := instMap[t.InstanceID]; ok {
			instCopy := inst
			d.Instance = &instCopy
			if inst.NetworkProfileID != "" {
				if np, ok := netMap[inst.NetworkProfileID]; ok {
					npCopy := np
					d.NetworkProfile = &npCopy
				}
			}
		}
		if t.ROCredentialID != "" {
			if cp, ok := credMap[t.ROCredentialID]; ok {
				cpCopy := cp
				d.ROCredential = &cpCopy
			}
		}
		if t.RWCredentialID != "" {
			if cp, ok := credMap[t.RWCredentialID]; ok {
				cpCopy := cp
				d.RWCredential = &cpCopy
			}
		}
		d.EffectivePolicy = policy.ResolveEffectivePolicyWithSystems(global, envPtr, ownerPtr, d.LinkedSystems, t, policies)
		if d.Instance != nil {
			eng := d.Instance.Engine
			fam := classify.EngineFamily(eng)
			if drv, ok := s.drivers.Get(eng); ok {
				fam = drv.Metadata().Family
			}
			d.EffectivePolicy.PatternRules = policy.ResolveEffectivePatternRulesWithSystems(envPtr, ownerPtr, d.LinkedSystems, t, eng, fam, patternRules)
		}
		out = append(out, d)
	}

	// Prioritize workspace-matched targets, then environment sort order, then ref.
	sort.Slice(out, func(i, j int) bool {
		if out[i].WorkspaceMatch != out[j].WorkspaceMatch {
			return out[i].WorkspaceMatch
		}
		oi, oj := 999, 999
		if out[i].Environment != nil {
			oi = out[i].Environment.SortOrder
		}
		if out[j].Environment != nil {
			oj = out[j].Environment.SortOrder
		}
		if oi != oj {
			return oi < oj
		}
		return out[i].Target.Ref < out[j].Target.Ref
	})
	return out, nil
}

// ListTargetsFiltered filters targets and populates recovery hints when zero hits occur.
func (s *Service) ListTargetsFiltered(ctx context.Context, f ListFilter) ([]types.TargetDetail, []string, []string, error) {
	all, err := s.BuildTargetDetails(ctx, f.WorkspaceCWD)
	if err != nil {
		return nil, nil, nil, err
	}

	envSet := map[string]bool{}
	for _, part := range strings.Split(f.Env, ",") {
		p := strings.ToLower(strings.TrimSpace(part))
		if p != "" {
			envSet[p] = true
		}
	}
	sysFilter := strings.ToLower(strings.TrimSpace(f.System))
	engFilter := strings.ToLower(strings.TrimSpace(f.Engine))
	tagFilter := strings.ToLower(strings.TrimSpace(f.Tag))
	kw := strings.ToLower(strings.TrimSpace(f.Search))

	var matched []types.TargetDetail
	for _, d := range all {
		if sysFilter != "" {
			ok := d.OwnerSystem != nil && (strings.EqualFold(d.OwnerSystem.Slug, sysFilter) || strings.EqualFold(d.OwnerSystem.ID, sysFilter))
			if !ok {
				for _, ls := range d.LinkedSystems {
					if strings.EqualFold(ls.Slug, sysFilter) || strings.EqualFold(ls.ID, sysFilter) {
						ok = true
						break
					}
				}
			}
			if !ok {
				continue
			}
		}
		if len(envSet) > 0 && !envSet[strings.ToLower(d.Target.EnvironmentCode)] {
			continue
		}
		if engFilter != "" && (d.Instance == nil || !strings.EqualFold(d.Instance.Engine, engFilter)) {
			continue
		}
		if tagFilter != "" {
			hasTag := false
			if d.OwnerSystem != nil {
				for _, tg := range d.OwnerSystem.Tags {
					if strings.EqualFold(tg, tagFilter) {
						hasTag = true
						break
					}
				}
			}
			if !hasTag {
				continue
			}
		}
		if kw != "" {
			hay := strings.ToLower(d.Target.Ref + " " + d.Target.Alias + " " + d.Target.DatabaseName + " " + d.Target.Description)
			if d.OwnerSystem != nil {
				hay += " " + strings.ToLower(d.OwnerSystem.Slug+" "+d.OwnerSystem.Name)
			}
			if !strings.Contains(hay, kw) {
				continue
			}
		}
		matched = append(matched, d)
	}

	if len(matched) > 0 {
		return matched, nil, nil, nil
	}

	var unsearched []string
	if sysFilter != "" {
		unsearched = append(unsearched, "systems outside --system="+f.System)
	}
	if len(envSet) > 0 {
		unsearched = append(unsearched, "environments outside --env="+f.Env)
	}
	if engFilter != "" {
		unsearched = append(unsearched, "engines outside --engine="+f.Engine)
	}
	similar := suggestSimilarTargets(all, kw, 5)
	return nil, similar, unsearched, nil
}

// ResolveTarget resolves ref/alias using tiered matching: exact > prefix > substring.
func (s *Service) ResolveTarget(ctx context.Context, query, workspaceCWD string) (types.TargetDetail, error) {
	all, err := s.BuildTargetDetails(ctx, workspaceCWD)
	if err != nil {
		return types.TargetDetail{}, err
	}
	q := strings.TrimSpace(query)
	if q == "" {
		return types.TargetDetail{}, &TargetLookupError{
			Code:         types.ErrCodeInvalidUsage,
			Message:      "Target database identifier is required.",
			SimilarNames: topTargetNames(all, 8),
		}
	}
	ql := strings.ToLower(q)

	// Tier 1: exact match on ref, alias, or id.
	var exact []types.TargetDetail
	for _, d := range all {
		if strings.EqualFold(d.Target.Ref, q) || (d.Target.Alias != "" && strings.EqualFold(d.Target.Alias, q)) || strings.EqualFold(d.Target.ID, q) {
			exact = append(exact, d)
		}
	}
	if len(exact) == 1 {
		return exact[0], nil
	}
	if len(exact) > 1 {
		return types.TargetDetail{}, &TargetLookupError{
			Code:       types.ErrCodeAmbiguousTarget,
			Message:    fmtAmbiguousMsg(q, exact),
			Candidates: exact,
		}
	}

	// Tier 2: prefix match on ref or alias.
	var prefix []types.TargetDetail
	for _, d := range all {
		if strings.HasPrefix(strings.ToLower(d.Target.Ref), ql) || (d.Target.Alias != "" && strings.HasPrefix(strings.ToLower(d.Target.Alias), ql)) {
			prefix = append(prefix, d)
		}
	}
	if len(prefix) == 1 {
		return prefix[0], nil
	}
	if len(prefix) > 1 {
		return types.TargetDetail{}, &TargetLookupError{
			Code:       types.ErrCodeAmbiguousTarget,
			Message:    fmtAmbiguousMsg(q, prefix),
			Candidates: prefix,
		}
	}

	// Tier 3: substring match on ref, alias, or database_name.
	var sub []types.TargetDetail
	for _, d := range all {
		if strings.Contains(strings.ToLower(d.Target.Ref), ql) ||
			(d.Target.Alias != "" && strings.Contains(strings.ToLower(d.Target.Alias), ql)) ||
			strings.Contains(strings.ToLower(d.Target.DatabaseName), ql) {
			sub = append(sub, d)
		}
	}
	if len(sub) == 1 {
		return sub[0], nil
	}
	if len(sub) > 1 {
		return types.TargetDetail{}, &TargetLookupError{
			Code:       types.ErrCodeAmbiguousTarget,
			Message:    fmtAmbiguousMsg(q, sub),
			Candidates: sub,
		}
	}

	return types.TargetDetail{}, &TargetLookupError{
		Code:         types.ErrCodeDBNotFound,
		Message:      "Database target " + q + " was not found.",
		SimilarNames: suggestSimilarTargets(all, ql, 5),
	}
}

func fmtAmbiguousMsg(q string, cands []types.TargetDetail) string {
	names := make([]string, 0, len(cands))
	for _, c := range cands {
		names = append(names, c.Target.Ref)
	}
	return "Target " + q + " matched multiple databases: " + strings.Join(names, ", ")
}

func matchesWorkspace(cwd string, paths []string) bool {
	if cwd == "" || len(paths) == 0 {
		return false
	}
	cleanCWD := filepath.Clean(cwd)
	for _, p := range paths {
		p = config.ExpandHomePath(p)
		if p == "" {
			continue
		}
		cleanP := filepath.Clean(p)
		if cleanCWD == cleanP || strings.HasPrefix(cleanCWD, cleanP+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func topTargetNames(all []types.TargetDetail, max int) []string {
	out := make([]string, 0, minInt(max, len(all)))
	for _, d := range all {
		if len(out) >= max {
			break
		}
		out = append(out, d.Target.Ref)
	}
	return out
}

func suggestSimilarTargets(all []types.TargetDetail, kw string, max int) []string {
	if kw == "" {
		return topTargetNames(all, max)
	}
	type scored struct {
		ref   string
		score int
	}
	var list []scored
	for _, d := range all {
		refL := strings.ToLower(d.Target.Ref)
		aliasL := strings.ToLower(d.Target.Alias)
		s := tokenOverlapScore(kw, refL+" "+aliasL)
		if s > 0 {
			list = append(list, scored{ref: d.Target.Ref, score: s})
		}
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].score != list[j].score {
			return list[i].score > list[j].score
		}
		return list[i].ref < list[j].ref
	})
	if len(list) == 0 {
		return topTargetNames(all, max)
	}
	out := make([]string, 0, minInt(max, len(list)))
	for _, item := range list {
		if len(out) >= max {
			break
		}
		out = append(out, item.ref)
	}
	return out
}

func tokenOverlapScore(a, b string) int {
	parts := strings.FieldsFunc(a, func(r rune) bool {
		return r == '-' || r == '_' || r == '/' || r == '.' || r == ' '
	})
	score := 0
	for _, p := range parts {
		if p != "" && strings.Contains(b, p) {
			score += len(p) + 2
		}
	}
	if strings.Contains(b, a) {
		score += 10
	}
	return score
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
