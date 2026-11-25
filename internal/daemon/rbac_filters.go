package daemon

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/x0c/agent-dbctl/internal/config"
	"github.com/x0c/agent-dbctl/internal/rbac"
	"github.com/x0c/agent-dbctl/internal/store"
	"github.com/x0c/agent-dbctl/internal/types"
)

// NewRemoteClient constructs an HTTPS/Bearer/mTLS RPC client from a ClientContext and bearer token.
func NewRemoteClient(ctxCfg config.ClientContext, bearerToken string) (*Client, error) {
	if err := config.ValidateContext(ctxCfg); err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: ctxCfg.InsecureSkipTLS, //nolint:gosec // Explicit user opt-in in context config.
	}
	if strings.TrimSpace(ctxCfg.CACertFile) != "" {
		caPath := config.ExpandHomePath(ctxCfg.CACertFile)
		caPEM, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("read ca_cert_file %s: %w", caPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("parse ca_cert_file %s: no certificates found", caPath)
		}
		tlsCfg.RootCAs = pool
	}
	if ctxCfg.ClientCertFile != "" && ctxCfg.ClientKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(
			config.ExpandHomePath(ctxCfg.ClientCertFile),
			config.ExpandHomePath(ctxCfg.ClientKeyFile),
		)
		if err != nil {
			return nil, fmt.Errorf("load mTLS client keypair: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	tr := &http.Transport{
		TLSClientConfig: tlsCfg,
	}
	return &Client{
		httpClient:  &http.Client{Transport: tr, Timeout: 0},
		baseURL:     strings.TrimRight(ctxCfg.Endpoint, "/"),
		bearerToken: strings.TrimSpace(bearerToken),
		remote:      true,
	}, nil
}

func filterSystemsForPrincipal(p types.Principal, items []types.System) []types.System {
	if rbac.IsPlatformAdmin(p) {
		return items
	}
	out := make([]types.System, 0, len(items))
	for _, sys := range items {
		if rbac.EffectiveRoleForScope(p, rbac.ResourceScope{SystemID: sys.ID, SystemSlug: sys.Slug}) != "" {
			out = append(out, sys)
		}
	}
	return out
}

func filterScopedProfiles[T any](p types.Principal, items []T, scopeFn func(T) (string, string)) []T {
	if rbac.IsPlatformAdmin(p) {
		return items
	}
	out := make([]T, 0, len(items))
	for _, it := range items {
		st, sid := scopeFn(it)
		if st == "" || st == "global" {
			out = append(out, it)
			continue
		}
		if st == "system" && rbac.EffectiveRoleForScope(p, rbac.ResourceScope{SystemID: sid, SystemSlug: sid}) != "" {
			out = append(out, it)
		}
	}
	return out
}

func filterApprovalsForPrincipal(ctx context.Context, svc *Service, p types.Principal, items []types.ApprovalRequest) []types.ApprovalRequest {
	if rbac.IsPlatformAdmin(p) {
		return items
	}
	sysIDBySlug := map[string]string{}
	if syss, err := svc.Store().ListSystems(ctx); err == nil {
		for _, s := range syss {
			sysIDBySlug[strings.ToLower(s.Slug)] = s.ID
		}
	}
	out := make([]types.ApprovalRequest, 0, len(items))
	for _, app := range items {
		sysID := sysIDBySlug[strings.ToLower(app.SystemSlug)]
		if app.PrincipalID == p.ID || rbac.EffectiveRoleForScope(p, rbac.ResourceScope{
			SystemID:        sysID,
			SystemSlug:      app.SystemSlug,
			EnvironmentCode: app.EnvironmentCode,
		}) != "" {
			app.QueryText = ""
			out = append(out, app)
		}
	}
	return out
}

func filterOperationsForPrincipal(p types.Principal, items []types.Operation) []types.Operation {
	if rbac.IsPlatformAdmin(p) {
		return items
	}
	out := make([]types.Operation, 0, len(items))
	for _, op := range items {
		if rbac.CanViewOperation(p, op) {
			op.QueryText = ""
			out = append(out, op)
		}
	}
	return out
}

func isAuthorizedAuditEntry(p types.Principal, allowedTargets map[string]bool, e types.AuditEntry) bool {
	return strings.EqualFold(e.Actor, p.Subject) || allowedTargets[e.TargetID] || allowedTargets[strings.ToLower(e.TargetID)]
}

func (s *Service) listAuthorizedAuditEntries(ctx context.Context, f store.AuditFilter) ([]types.AuditEntry, int, bool, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 200
	} else if limit > 1000 {
		limit = 1000
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}
	f.Limit = limit
	f.Offset = offset

	p := rbac.PrincipalFromContext(ctx)
	if !s.IsServerMode() || rbac.IsPlatformAdmin(p) {
		items, total, err := s.store.ListAuditEntriesFiltered(ctx, f)
		if err != nil {
			return nil, 0, false, err
		}
		if items == nil {
			items = []types.AuditEntry{}
		}
		return items, total, offset+len(items) < total, nil
	}

	allowedTargets := map[string]bool{}
	if details, err := s.BuildTargetDetails(ctx, ""); err == nil {
		for _, d := range details {
			allowedTargets[d.Target.ID] = true
			allowedTargets[strings.ToLower(d.Target.Ref)] = true
		}
	}

	const batchSize = 500
	var beforeSeq int64
	totalAuthorized := 0
	page := make([]types.AuditEntry, 0, limit)
	for {
		chunkFilter := f
		chunkFilter.Limit = batchSize
		chunkFilter.Offset = 0
		chunkFilter.BeforeSeq = beforeSeq
		chunkFilter.SkipCount = true
		chunk, _, err := s.store.ListAuditEntriesFiltered(ctx, chunkFilter)
		if err != nil {
			return nil, 0, false, err
		}
		if len(chunk) == 0 {
			break
		}
		for _, e := range chunk {
			if isAuthorizedAuditEntry(p, allowedTargets, e) {
				if totalAuthorized >= offset && len(page) < limit {
					page = append(page, e)
				}
				totalAuthorized++
			}
			beforeSeq = e.Seq
		}
		if len(chunk) < batchSize || beforeSeq <= 1 {
			break
		}
	}
	return page, totalAuthorized, offset+len(page) < totalAuthorized, nil
}

// ExportTopologyForPrincipal exports a TopologyBundle filtered to the caller's authorized systems in server mode.
func (s *Service) ExportTopologyForPrincipal(ctx context.Context) (types.TopologyBundle, error) {
	b, err := s.store.ExportTopology(ctx)
	if err != nil || !s.IsServerMode() {
		return b, err
	}
	p := rbac.PrincipalFromContext(ctx)
	if rbac.IsPlatformAdmin(p) {
		return b, nil
	}
	b.GlobalSecurity = nil
	b.Systems = filterSystemsForPrincipal(p, b.Systems)
	allowedSys := map[string]bool{}
	for _, sys := range b.Systems {
		allowedSys[sys.ID] = true
		allowedSys[strings.ToLower(sys.Slug)] = true
	}
	var tgts []types.Target
	allowedInst := map[string]bool{}
	allowedCred := map[string]bool{}
	for _, t := range b.Targets {
		if allowedSys[t.OwnerSystemID] && rbac.EffectiveRoleForScope(p, rbac.ResourceScope{
			SystemID:        t.OwnerSystemID,
			EnvironmentCode: t.EnvironmentCode,
		}) != "" {
			tgts = append(tgts, t)
			allowedInst[t.InstanceID] = true
			if t.ROCredentialID != "" {
				allowedCred[t.ROCredentialID] = true
			}
			if t.RWCredentialID != "" {
				allowedCred[t.RWCredentialID] = true
			}
		}
	}
	b.Targets = tgts
	var insts []types.Instance
	allowedNet := map[string]bool{}
	for _, inst := range b.Instances {
		if allowedInst[inst.ID] || (inst.ScopeType == "system" && allowedSys[inst.ScopeID]) {
			insts = append(insts, inst)
			if inst.NetworkProfileID != "" {
				allowedNet[inst.NetworkProfileID] = true
			}
		}
	}
	b.Instances = insts
	var nets []types.NetworkProfile
	for _, np := range b.NetworkProfiles {
		if allowedNet[np.ID] || (np.ScopeType == "system" && allowedSys[np.ScopeID]) {
			nets = append(nets, np)
			if np.BastionCredentialID != "" {
				allowedCred[np.BastionCredentialID] = true
			}
		}
	}
	b.NetworkProfiles = nets
	var creds []types.CredentialProfile
	for _, cp := range b.CredentialProfiles {
		if allowedCred[cp.ID] || (cp.ScopeType == "system" && allowedSys[cp.ScopeID]) {
			creds = append(creds, cp)
		}
	}
	b.CredentialProfiles = creds
	return b, nil
}

func filterPoliciesForPrincipal(ctx context.Context, svc *Service, p types.Principal, items []types.PolicyRuleSet) []types.PolicyRuleSet {
	if rbac.IsPlatformAdmin(p) {
		return items
	}
	allowedTargets := map[string]bool{}
	if details, err := svc.BuildTargetDetails(ctx, ""); err == nil {
		for _, d := range details {
			allowedTargets[d.Target.ID] = true
		}
	}
	out := make([]types.PolicyRuleSet, 0, len(items))
	for _, pol := range items {
		switch pol.ScopeType {
		case "", "global", "env":
			out = append(out, pol)
		case "system":
			if rbac.EffectiveRoleForScope(p, rbac.ResourceScope{SystemID: pol.ScopeID, SystemSlug: pol.ScopeID}) != "" {
				out = append(out, pol)
			}
		case "target":
			if allowedTargets[pol.ScopeID] {
				out = append(out, pol)
			}
		}
	}
	return out
}

func filterRiskPatternsForPrincipal(ctx context.Context, svc *Service, p types.Principal, items []types.RiskPatternRule) []types.RiskPatternRule {
	if rbac.IsPlatformAdmin(p) {
		return items
	}
	allowedTargets := map[string]bool{}
	if details, err := svc.BuildTargetDetails(ctx, ""); err == nil {
		for _, d := range details {
			allowedTargets[d.Target.ID] = true
		}
	}
	out := make([]types.RiskPatternRule, 0, len(items))
	for _, r := range items {
		switch r.ScopeType {
		case "", "global", "env":
			out = append(out, r)
		case "system":
			if rbac.EffectiveRoleForScope(p, rbac.ResourceScope{SystemID: r.ScopeID, SystemSlug: r.ScopeID}) != "" {
				out = append(out, r)
			}
		case "target":
			if allowedTargets[r.ScopeID] {
				out = append(out, r)
			}
		}
	}
	return out
}
