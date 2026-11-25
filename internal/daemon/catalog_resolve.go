package daemon

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/x0c/agent-dbctl/internal/classify"
	"github.com/x0c/agent-dbctl/internal/config"
	"github.com/x0c/agent-dbctl/internal/policy"
	"github.com/x0c/agent-dbctl/internal/rbac"
	"github.com/x0c/agent-dbctl/internal/types"
)

// ListFilter narrows db list results.
type ListFilter struct {
	System              string   `json:"system,omitempty"`
	Env                 string   `json:"env,omitempty"`
	Engine              string   `json:"engine,omitempty"`
	Tag                 string   `json:"tag,omitempty"`
	Search              string   `json:"search,omitempty"`
	WorkspaceCWD        string   `json:"workspace_cwd,omitempty"`
	WorkspaceGitRemotes []string `json:"workspace_git_remotes,omitempty"`
}

// TargetLookupError provides structured ambiguity or zero-hit recovery metadata.
type TargetLookupError struct {
	Code              string
	Message           string
	Candidates        []types.TargetDetail
	SimilarNames      []string
	UnsearchedSources []string
	Hint              string
	NextCommands      []string
}

func (e *TargetLookupError) Error() string {
	return e.Message
}

// BuildTargetDetails enriches all targets with system, env, instance, network, credentials (secret-free), and effective policy.
func (s *Service) BuildTargetDetails(ctx context.Context, workspaceCWD string, gitRemotes ...string) ([]types.TargetDetail, error) {
	return s.buildTargetDetails(ctx, workspaceCWD, true, gitRemotes...)
}

func (s *Service) buildTargetDetails(ctx context.Context, workspaceCWD string, includeHasSecret bool, gitRemotes ...string) ([]types.TargetDetail, error) {
	targets, err := s.store.ListTargets(ctx)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, nil
	}
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
		if includeHasSecret {
			item.HasSecret = s.hasCredentialSecret(ctx, item)
		}
		credMap[item.ID] = item
	}
	instMap := make(map[string]types.Instance, len(insts))
	for _, item := range insts {
		instMap[item.ID] = item
	}

	normRemotes := config.NormalizeGitRemotes(gitRemotes)
	allowLocalPathMatch := !s.IsServerMode()
	sysRankCache := make(map[string]int, len(systems))
	getSysRank := func(sys types.System) int {
		if r, ok := sysRankCache[sys.ID]; ok {
			return r
		}
		r := 0
		if allowLocalPathMatch && matchesWorkspace(workspaceCWD, sys.WorkspacePaths) {
			r = 2
		} else if matchesGitRemotes(normRemotes, sys.GitRemotes) {
			r = 1
		}
		sysRankCache[sys.ID] = r
		return r
	}

	p := rbac.PrincipalFromContext(ctx)
	type rankedTarget struct {
		detail types.TargetDetail
		rank   int
	}
	ranked := make([]rankedTarget, 0, len(targets))
	for _, t := range targets {
		d := types.TargetDetail{Target: t}
		rank := 0
		var ownerPtr *types.System
		if sys, ok := sysMap[t.OwnerSystemID]; ok {
			sysCopy := sys
			ownerPtr = &sysCopy
			d.OwnerSystem = ownerPtr
			if sr := getSysRank(sys); sr > 0 {
				d.WorkspaceMatch = true
				rank = sr
			}
		}
		for _, lid := range t.LinkedSystemIDs {
			if lsys, ok := sysMap[lid]; ok {
				d.LinkedSystems = append(d.LinkedSystems, lsys)
				if sr := getSysRank(lsys); sr > 0 {
					d.WorkspaceMatch = true
					if sr > rank {
						rank = sr
					}
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
		if s.IsServerMode() && !rbac.CanViewTarget(p, d) {
			continue
		}
		ranked = append(ranked, rankedTarget{detail: d, rank: rank})
	}

	// Prioritize workspace-matched targets (local path match ahead of git remote match), then environment sort order, then ref.
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].rank != ranked[j].rank {
			return ranked[i].rank > ranked[j].rank
		}
		oi, oj := 999, 999
		if ranked[i].detail.Environment != nil {
			oi = ranked[i].detail.Environment.SortOrder
		}
		if ranked[j].detail.Environment != nil {
			oj = ranked[j].detail.Environment.SortOrder
		}
		if oi != oj {
			return oi < oj
		}
		return ranked[i].detail.Target.Ref < ranked[j].detail.Target.Ref
	})
	out := make([]types.TargetDetail, len(ranked))
	for i := range ranked {
		out[i] = ranked[i].detail
	}
	return out, nil
}

// SummarizeTarget projects TargetDetail into a compact agent-facing TargetSummary.
func SummarizeTarget(d types.TargetDetail) types.TargetSummary {
	sysSlug := ""
	if d.OwnerSystem != nil {
		sysSlug = d.OwnerSystem.Slug
	}
	eng := ""
	if d.Instance != nil {
		eng = d.Instance.Engine
	}
	hasRWPath := d.RWCredential != nil || (d.ROCredential == nil && d.RWCredential == nil)
	frozen := d.EffectivePolicy.ProdReadOnlyFreeze && d.EffectivePolicy.SafetyTier == types.SafetyTierStrict
	writable := d.Target.Status == types.TargetActive && hasRWPath && !frozen

	return types.TargetSummary{
		Ref:             d.Target.Ref,
		Alias:           d.Target.Alias,
		System:          sysSlug,
		Env:             d.Target.EnvironmentCode,
		SafetyTier:      d.EffectivePolicy.SafetyTier,
		Engine:          eng,
		Database:        d.Target.DatabaseName,
		Status:          d.Target.Status,
		Writable:        writable,
		ScanReadMode:    d.EffectivePolicy.ScanReadMode,
		MaxRows:         d.EffectivePolicy.MaxRows,
		ExecTimeoutSec:  d.EffectivePolicy.ExecTimeoutSec,
		WorkspaceMatch:  d.WorkspaceMatch,
		QuerySyntaxHint: engineQuerySyntaxHint(eng),
		Description:     d.Target.Description,
	}
}

// SummarizeTargetShow builds the concise default payload for `db show <ref>`.
func SummarizeTargetShow(d types.TargetDetail) types.TargetShowSummary {
	sum := SummarizeTarget(d)
	endpoint := ""
	tlsMode := ""
	if d.Instance != nil {
		tlsMode = d.Instance.TLSMode
		if d.Instance.Engine == "sqlite" {
			endpoint = d.Instance.Host
		} else if d.Instance.Host != "" {
			endpoint = fmt.Sprintf("%s:%d", d.Instance.Host, d.Instance.Port)
		}
	}
	netMode := "direct"
	if d.NetworkProfile != nil {
		if d.NetworkProfile.Mode != "" {
			netMode = string(d.NetworkProfile.Mode)
		}
		if tlsMode == "" {
			tlsMode = d.NetworkProfile.TLSMode
		}
	}
	ref := d.Target.Ref
	if d.Target.Alias != "" {
		ref = d.Target.Alias
	}
	return types.TargetShowSummary{
		TargetSummary:       sum,
		Endpoint:            endpoint,
		NetworkMode:         netMode,
		TLSMode:             tlsMode,
		HasROCredential:     d.ROCredential != nil,
		HasRWCredential:     d.RWCredential != nil,
		AllowMultiStatement: d.EffectivePolicy.AllowMultiStatement,
		ExplainMaxRows:      d.EffectivePolicy.ExplainMaxRows,
		PatternRulesCount:   len(d.EffectivePolicy.PatternRules),
		Examples:            buildTargetExamples(ref, sum.Engine),
	}
}

func engineQuerySyntaxHint(engine string) string {
	switch classify.CanonicalEngine(engine) {
	case "mongodb":
		return `JSON RunCommand (e.g. {"find":"coll","filter":{},"limit":20}) or show collections`
	case "redis":
		return "Redis commands (e.g. GET key, SCAN 0 COUNT 50)"
	case "elasticsearch":
		return `HTTP+JSON (e.g. GET /idx/_search) or JSON search ({"index":"idx","query":{"match_all":{}},"size":10})`
	case "mssql":
		return "T-SQL (e.g. SELECT TOP 10 * FROM dbo.orders)"
	case "oracle":
		return "Oracle SQL (e.g. SELECT * FROM orders FETCH FIRST 10 ROWS ONLY)"
	case "dameng":
		return "Dameng DM8 SQL (e.g. SELECT * FROM orders FETCH FIRST 10 ROWS ONLY)"
	case "tdengine":
		return "TDengine SQL over /rest/sql (e.g. SELECT * FROM meters LIMIT 10)"
	default:
		return ""
	}
}

func buildTargetExamples(targetRef, engine string) []string {
	out := []string{
		fmt.Sprintf("agent-dbctl db schema %s --json", targetRef),
	}
	switch classify.CanonicalEngine(engine) {
	case "mongodb":
		out = append(out, fmt.Sprintf(`agent-dbctl exec --db %s '{"find":"orders","filter":{},"limit":10}' --json`, targetRef))
	case "redis":
		out = append(out, fmt.Sprintf(`agent-dbctl exec --db %s "SCAN 0 COUNT 20" --json`, targetRef))
	case "elasticsearch":
		out = append(out, fmt.Sprintf(`agent-dbctl exec --db %s '{"index":"logs","query":{"match_all":{}},"size":10}' --json`, targetRef))
	case "mssql":
		out = append(out, fmt.Sprintf(`agent-dbctl exec --db %s "SELECT TOP 10 * FROM orders" --json`, targetRef))
	case "oracle", "dameng":
		out = append(out, fmt.Sprintf(`agent-dbctl exec --db %s "SELECT * FROM orders FETCH FIRST 10 ROWS ONLY" --json`, targetRef))
	default:
		out = append(out, fmt.Sprintf(`agent-dbctl exec --db %s "SELECT * FROM orders LIMIT 10" --json`, targetRef))
	}
	return out
}

// EngineGuide documents connection defaults, aliases, and query syntax for one registered driver.
type EngineGuide struct {
	Engine       string   `json:"engine"`
	DisplayName  string   `json:"display_name"`
	Family       string   `json:"family"`
	Tier         string   `json:"tier"`
	DefaultPort  int      `json:"default_port"`
	Aliases      []string `json:"aliases,omitempty"`
	KeyParams    []string `json:"key_params,omitempty"`
	SyntaxHint   string   `json:"syntax_hint,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	Verified     bool     `json:"verified"`
}

// BuildEngineGuides enriches driver metadata with onboarding defaults and syntax guidance.
func BuildEngineGuides(drivers []types.DriverMetadata) []EngineGuide {
	out := make([]EngineGuide, 0, len(drivers))
	for _, d := range drivers {
		g := EngineGuide{
			Engine:       d.Engine,
			DisplayName:  d.DisplayName,
			Family:       string(d.Family),
			Tier:         d.Tier,
			DefaultPort:  DefaultPortForEngine(d.Engine),
			Capabilities: d.Capabilities,
			Verified:     d.Verified,
			SyntaxHint:   engineQuerySyntaxHint(d.Engine),
		}
		switch classify.CanonicalEngine(d.Engine) {
		case "postgres":
			g.Aliases = []string{"postgresql", "cockroachdb", "redshift", "yugabytedb", "greenplum", "alloydb", "highgo", "uxdb", "opentenbase", "kwdb", "polardb_pg", "tdsql_pg"}
			g.KeyParams = []string{"exec_mode=simple_protocol (for PgBouncer)"}
		case "opengauss":
			g.Aliases = []string{"gaussdb", "gaussdb_dws", "vastbase", "mogdb", "gbase8c"}
			g.KeyParams = []string{"connect_timeout=10", "search_path=public"}
		case "kingbase":
			g.Aliases = []string{"kingbase8", "kingbasees", "kes"}
			g.KeyParams = []string{"connect_timeout=10", "search_path=public"}
		case "dameng":
			g.Aliases = []string{"dm", "dm8"}
			g.KeyParams = []string{"schema=<SCHEMA> (defaults to database_name)", "connectTimeout=10000"}
		case "tdengine":
			g.Aliases = []string{"taos", "taosdata"}
			g.KeyParams = []string{"scheme=http|https", "auth_type=basic|taosd"}
		case "mysql":
			g.Aliases = []string{"mariadb", "tidb", "oceanbase", "oceanbase_mysql", "polardb", "polardb_mysql", "tdsql", "tdsql_mysql", "goldendb", "greatsql", "gbase", "gbase8a", "starrocks", "doris", "selectdb"}
			g.KeyParams = []string{"charset", "parseTime"}
		case "sqlite":
			g.Aliases = []string{"sqlite3"}
			g.KeyParams = []string{"SQLite file path goes in instance.host (port=0)"}
		case "mongodb":
			g.Aliases = []string{"documentdb", "ferretdb", "cosmosdb_mongo"}
			g.KeyParams = []string{"authSource", "replicaSet", "directConnection=true|false"}
		case "redis":
			g.Aliases = []string{"valkey", "dragonfly", "keydb"}
			g.KeyParams = []string{"cluster=true", "protocol=2|3", "username"}
		case "clickhouse":
			g.Aliases = []string{"ch"}
			g.KeyParams = []string{"protocol=native|http"}
		case "mssql":
			g.Aliases = []string{"sqlserver", "azuresql"}
			g.KeyParams = []string{"encrypt", "TrustServerCertificate"}
		case "oracle":
			g.Aliases = []string{"oracledb"}
			g.KeyParams = []string{"sid=<SID> (defaults to service name in database_name)"}
		case "elasticsearch":
			g.Aliases = []string{"opensearch", "easysearch", "es"}
			g.KeyParams = []string{"scheme=http|https", "auth_type=basic|api_key|bearer"}
		}
		if g.SyntaxHint == "" {
			g.SyntaxHint = "Standard SQL via --sql / --file / --stdin"
		}
		out = append(out, g)
	}
	return out
}

// ListTargetsFiltered filters targets and populates recovery hints when zero hits occur.
func (s *Service) ListTargetsFiltered(ctx context.Context, f ListFilter) ([]types.TargetDetail, []string, []string, error) {
	all, err := s.buildTargetDetails(ctx, f.WorkspaceCWD, false, f.WorkspaceGitRemotes...)
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
func (s *Service) ResolveTarget(ctx context.Context, query, workspaceCWD string, gitRemotes ...string) (types.TargetDetail, error) {
	q := strings.TrimSpace(query)
	if q == "" {
		all, err := s.buildTargetDetails(ctx, workspaceCWD, false, gitRemotes...)
		if err != nil {
			return types.TargetDetail{}, err
		}
		return types.TargetDetail{}, &TargetLookupError{
			Code:         types.ErrCodeInvalidUsage,
			Message:      "Target database identifier is required.",
			SimilarNames: topTargetNames(all, 8),
		}
	}

	targets, err := s.store.ListTargets(ctx)
	if err != nil {
		return types.TargetDetail{}, err
	}
	if !s.IsServerMode() {
		if matched, singleOK := matchSingleTargetRecord(targets, q); singleOK {
			return s.enrichSingleTargetDetail(ctx, matched, workspaceCWD, gitRemotes...)
		}
	}

	all, err := s.buildTargetDetails(ctx, workspaceCWD, false, gitRemotes...)
	if err != nil {
		return types.TargetDetail{}, err
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

func matchSingleTargetRecord(targets []types.Target, q string) (types.Target, bool) {
	ql := strings.ToLower(q)

	var exactIdx = -1
	for i := range targets {
		t := &targets[i]
		if strings.EqualFold(t.Ref, q) || (t.Alias != "" && strings.EqualFold(t.Alias, q)) || strings.EqualFold(t.ID, q) {
			if exactIdx >= 0 {
				return types.Target{}, false
			}
			exactIdx = i
		}
	}
	if exactIdx >= 0 {
		return targets[exactIdx], true
	}

	var prefixIdx = -1
	for i := range targets {
		t := &targets[i]
		if strings.HasPrefix(strings.ToLower(t.Ref), ql) || (t.Alias != "" && strings.HasPrefix(strings.ToLower(t.Alias), ql)) {
			if prefixIdx >= 0 {
				return types.Target{}, false
			}
			prefixIdx = i
		}
	}
	if prefixIdx >= 0 {
		return targets[prefixIdx], true
	}

	var subIdx = -1
	for i := range targets {
		t := &targets[i]
		if strings.Contains(strings.ToLower(t.Ref), ql) ||
			(t.Alias != "" && strings.Contains(strings.ToLower(t.Alias), ql)) ||
			strings.Contains(strings.ToLower(t.DatabaseName), ql) {
			if subIdx >= 0 {
				return types.Target{}, false
			}
			subIdx = i
		}
	}
	if subIdx >= 0 {
		return targets[subIdx], true
	}
	return types.Target{}, false
}

func (s *Service) enrichSingleTargetDetail(ctx context.Context, t types.Target, workspaceCWD string, gitRemotes ...string) (types.TargetDetail, error) {
	global, err := s.store.GetGlobalSecurityConfig(ctx)
	if err != nil {
		return types.TargetDetail{}, err
	}
	systems, err := s.store.ListSystems(ctx)
	if err != nil {
		return types.TargetDetail{}, err
	}
	envs, err := s.store.ListEnvironments(ctx)
	if err != nil {
		return types.TargetDetail{}, err
	}
	policies, err := s.store.ListPolicies(ctx)
	if err != nil {
		return types.TargetDetail{}, err
	}
	patternRules, err := s.store.ListRiskPatternRules(ctx)
	if err != nil {
		return types.TargetDetail{}, err
	}

	d := types.TargetDetail{Target: t}
	normRemotes := config.NormalizeGitRemotes(gitRemotes)
	allowLocalPathMatch := !s.IsServerMode()

	var ownerPtr *types.System
	var linkedNeed map[string]struct{}
	if len(t.LinkedSystemIDs) > 0 {
		linkedNeed = make(map[string]struct{}, len(t.LinkedSystemIDs))
		for _, lid := range t.LinkedSystemIDs {
			linkedNeed[lid] = struct{}{}
		}
	}
	for i := range systems {
		sys := systems[i]
		if sys.ID == t.OwnerSystemID {
			sysCopy := sys
			ownerPtr = &sysCopy
			d.OwnerSystem = ownerPtr
			if (allowLocalPathMatch && matchesWorkspace(workspaceCWD, sys.WorkspacePaths)) || matchesGitRemotes(normRemotes, sys.GitRemotes) {
				d.WorkspaceMatch = true
			}
		}
		if _, ok := linkedNeed[sys.ID]; ok {
			d.LinkedSystems = append(d.LinkedSystems, sys)
			if !d.WorkspaceMatch && ((allowLocalPathMatch && matchesWorkspace(workspaceCWD, sys.WorkspacePaths)) || matchesGitRemotes(normRemotes, sys.GitRemotes)) {
				d.WorkspaceMatch = true
			}
		}
	}

	var envPtr *types.Environment
	for i := range envs {
		if envs[i].Code == t.EnvironmentCode {
			envCopy := envs[i]
			envPtr = &envCopy
			d.Environment = envPtr
			break
		}
	}

	if inst, err := s.store.GetInstance(ctx, t.InstanceID); err == nil {
		instCopy := inst
		d.Instance = &instCopy
		if inst.NetworkProfileID != "" {
			d.NetworkProfile = s.resolveNetworkProfile(ctx, inst.NetworkProfileID)
		}
	}

	if t.ROCredentialID != "" || t.RWCredentialID != "" {
		if creds, err := s.store.ListCredentialProfiles(ctx); err == nil {
			for i := range creds {
				cp := creds[i]
				if cp.ID == t.ROCredentialID {
					cpCopy := cp
					d.ROCredential = &cpCopy
				}
				if cp.ID == t.RWCredentialID {
					cpCopy := cp
					d.RWCredential = &cpCopy
				}
			}
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
	return d, nil
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

func matchesGitRemotes(detectedNorm, configured []string) bool {
	if len(detectedNorm) == 0 || len(configured) == 0 {
		return false
	}
	normConfigured := config.NormalizeGitRemotes(configured)
	for _, d := range detectedNorm {
		for _, c := range normConfigured {
			if strings.EqualFold(d, c) {
				return true
			}
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
