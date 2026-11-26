package daemon

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/x0c/agent-dbctl/internal/auth"
	"github.com/x0c/agent-dbctl/internal/policy"
	"github.com/x0c/agent-dbctl/internal/rbac"
	"github.com/x0c/agent-dbctl/internal/store"
	"github.com/x0c/agent-dbctl/internal/types"
	"github.com/x0c/agent-dbctl/internal/webui"
)

const (
	uiSessionCookieName = "agent_dbctl_session"
	uiCSRFHeaderName    = "X-Agent-DBCTL-CSRF"
)

// NewWebHandler builds the local HTTP + SSE router for the embedded Web Console.
func NewWebHandler(svc *Service) http.Handler {
	mux := http.NewServeMux()
	registerWebAPIRoutes(mux, svc)
	return WebSecurityMiddleware(svc, mux)
}

func registerWebAPIRoutes(mux *http.ServeMux, svc *Service) {
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResp(w, http.StatusOK, map[string]string{"status": "running"})
	})

	// Bootstrap & server-driven display catalogs.
	mux.HandleFunc("GET /api/v1/bootstrap", func(w http.ResponseWriter, r *http.Request) {
		if !svc.IsServerMode() && !isSafeBootstrapRequest(r) {
			writeHTTPErr(w, http.StatusForbidden, "cross-origin bootstrap blocked")
			return
		}
		cat, err := svc.BuildDisplayCatalog(r.Context())
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		sec, err := svc.Store().GetGlobalSecurityConfig(r.Context())
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		pending, _ := svc.Store().ListApprovals(r.Context(), string(types.ApprovalPending), 200)
		p := rbac.PrincipalFromContext(r.Context())
		if svc.IsServerMode() {
			pending = filterApprovalsForPrincipal(r.Context(), svc, p, pending)
			csrf := ""
			if c, err := r.Cookie(uiSessionCookieName); err == nil && c != nil && c.Value != "" {
				csrf = serverCSRFForSession(svc, auth.HashToken(c.Value))
			}
			isAdmin := rbac.IsPlatformAdmin(p)
			authInfo := publicAuthInfo(svc, true)
			writeJSONResp(w, http.StatusOK, map[string]any{
				"mode":                   types.ModeServer,
				"authenticated":          true,
				"auth_methods":           authInfo.AuthMethods,
				"oidc_enabled":           authInfo.OIDCEnabled,
				"local_enabled":          authInfo.LocalEnabled,
				"identity":               svc.Identity(),
				"display_catalog":        cat,
				"global_security":        sec,
				"pending_approval_count": len(pending),
				"secret_backend":         svc.Secrets().Name(),
				"ui_csrf_token":          csrf,
				"current_user": types.AuthBootstrapUser{
					ID:              p.ID,
					Email:           p.Email,
					DisplayName:     p.DisplayName,
					Roles:           p.Roles,
					IsPlatformAdmin: isAdmin,
					CanManageUsers:  isAdmin,
					CanEditSecurity: isAdmin,
				},
			})
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     uiSessionCookieName,
			Value:    svc.UISessionToken(),
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
		writeJSONResp(w, http.StatusOK, map[string]any{
			"mode":                   types.ModeLocal,
			"authenticated":          true,
			"identity":               svc.Identity(),
			"display_catalog":        cat,
			"global_security":        sec,
			"pending_approval_count": len(pending),
			"secret_backend":         svc.Secrets().Name(),
			"ui_csrf_token":          svc.UICSRFToken(),
		})
	})

	// Live SSE stream for approvals and execution updates.
	mux.HandleFunc("GET /api/v1/events", func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Connection", "keep-alive")
		sub := svc.subscribeSSE(rbac.PrincipalFromContext(r.Context()))
		defer svc.unsubscribeSSE(sub)

		_, _ = fmt.Fprintf(w, "event: ready\ndata: {}\n\n")
		flusher.Flush()

		keepAlive := time.NewTicker(20 * time.Second)
		defer keepAlive.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case <-svc.Done():
				return
			case <-keepAlive.C:
				_, _ = fmt.Fprintf(w, ": ping\n\n")
				flusher.Flush()
			case ev, open := <-sub.ch:
				if !open {
					return
				}
				payload, _ := json.Marshal(ev.Data)
				_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, payload)
				flusher.Flush()
			}
		}
	})

	// Systems
	mux.HandleFunc("GET /api/v1/systems", func(w http.ResponseWriter, r *http.Request) {
		items, err := svc.Store().ListSystems(r.Context())
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if svc.IsServerMode() {
			items = filterSystemsForPrincipal(rbac.PrincipalFromContext(r.Context()), items)
		}
		writeJSONResp(w, http.StatusOK, map[string]any{"items": items})
	})
	mux.HandleFunc("POST /api/v1/systems", func(w http.ResponseWriter, r *http.Request) {
		var body types.System
		if err := decodeJSONBody(r, &body); err != nil {
			writeHTTPErr(w, http.StatusBadRequest, err.Error())
			return
		}
		res, err := svc.AdminUpsertSystem(r.Context(), svc.effectiveActor(r.Context(), ""), body, false)
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, res.Item)
	})
	mux.HandleFunc("DELETE /api/v1/systems/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := svc.AdminDeleteSystem(r.Context(), svc.effectiveActor(r.Context(), ""), r.PathValue("id")); err != nil {
			writeStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, map[string]bool{"deleted": true})
	})

	// Environments
	mux.HandleFunc("GET /api/v1/environments", func(w http.ResponseWriter, r *http.Request) {
		items, err := svc.Store().ListEnvironments(r.Context())
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSONResp(w, http.StatusOK, map[string]any{"items": items})
	})
	mux.HandleFunc("POST /api/v1/environments", func(w http.ResponseWriter, r *http.Request) {
		var body types.Environment
		if err := decodeJSONBody(r, &body); err != nil {
			writeHTTPErr(w, http.StatusBadRequest, err.Error())
			return
		}
		res, err := svc.AdminUpsertEnvironment(r.Context(), svc.effectiveActor(r.Context(), ""), body, false)
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, res.Item)
	})
	mux.HandleFunc("DELETE /api/v1/environments/{code...}", func(w http.ResponseWriter, r *http.Request) {
		if err := svc.AdminDeleteEnvironment(r.Context(), svc.effectiveActor(r.Context(), ""), r.PathValue("code")); err != nil {
			writeStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, map[string]bool{"deleted": true})
	})

	// Network Profiles
	mux.HandleFunc("GET /api/v1/network-profiles", func(w http.ResponseWriter, r *http.Request) {
		items, err := svc.Store().ListNetworkProfiles(r.Context())
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if svc.IsServerMode() {
			items = filterScopedProfiles(rbac.PrincipalFromContext(r.Context()), items, func(x types.NetworkProfile) (string, string) { return x.ScopeType, x.ScopeID })
		}
		writeJSONResp(w, http.StatusOK, map[string]any{"items": items})
	})
	mux.HandleFunc("POST /api/v1/network-profiles", func(w http.ResponseWriter, r *http.Request) {
		var body types.NetworkProfile
		if err := decodeJSONBody(r, &body); err != nil {
			writeHTTPErr(w, http.StatusBadRequest, err.Error())
			return
		}
		res, err := svc.AdminUpsertNetworkProfile(r.Context(), svc.effectiveActor(r.Context(), ""), body, false)
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, res.Item)
	})
	mux.HandleFunc("DELETE /api/v1/network-profiles/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := svc.AdminDeleteNetworkProfile(r.Context(), svc.effectiveActor(r.Context(), ""), r.PathValue("id")); err != nil {
			writeStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, map[string]bool{"deleted": true})
	})

	// Credential Profiles (write-only secret input, never returned in GET)
	mux.HandleFunc("GET /api/v1/credentials", func(w http.ResponseWriter, r *http.Request) {
		items, err := svc.Store().ListCredentialProfiles(r.Context())
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if svc.IsServerMode() {
			items = filterScopedProfiles(rbac.PrincipalFromContext(r.Context()), items, func(x types.CredentialProfile) (string, string) { return x.ScopeType, x.ScopeID })
		}
		for i := range items {
			items[i].HasSecret = svc.hasCredentialSecret(r.Context(), items[i])
		}
		writeJSONResp(w, http.StatusOK, map[string]any{"items": items})
	})
	mux.HandleFunc("POST /api/v1/credentials", func(w http.ResponseWriter, r *http.Request) {
		var body CredentialUpsertRequest
		if err := decodeJSONBody(r, &body); err != nil {
			writeHTTPErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if body.SecretValue != "" {
			body.SecretProvided = true
		}
		res, err := svc.AdminUpsertCredentialProfile(r.Context(), svc.effectiveActor(r.Context(), ""), body)
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		svc.InvalidateCatalogPools("credential", res.Item.ID)
		writeJSONResp(w, http.StatusOK, res.Item)
	})
	mux.HandleFunc("DELETE /api/v1/credentials/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := svc.AdminDeleteCredentialProfile(r.Context(), svc.effectiveActor(r.Context(), ""), id); err != nil {
			writeStoreErr(w, err)
			return
		}
		svc.InvalidateCatalogPools("credential", id)
		writeJSONResp(w, http.StatusOK, map[string]bool{"deleted": true})
	})

	// Instances + Live Test & Discover
	mux.HandleFunc("GET /api/v1/instances", func(w http.ResponseWriter, r *http.Request) {
		items, err := svc.Store().ListInstances(r.Context())
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if svc.IsServerMode() {
			items = filterScopedProfiles(rbac.PrincipalFromContext(r.Context()), items, func(x types.Instance) (string, string) { return x.ScopeType, x.ScopeID })
		}
		writeJSONResp(w, http.StatusOK, map[string]any{"items": items})
	})
	mux.HandleFunc("POST /api/v1/instances", func(w http.ResponseWriter, r *http.Request) {
		var body types.Instance
		if err := decodeJSONBody(r, &body); err != nil {
			writeHTTPErr(w, http.StatusBadRequest, err.Error())
			return
		}
		res, err := svc.AdminUpsertInstance(r.Context(), svc.effectiveActor(r.Context(), ""), body, false)
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		svc.InvalidateCatalogPools("instance", res.Item.ID)
		writeJSONResp(w, http.StatusOK, res.Item)
	})
	mux.HandleFunc("DELETE /api/v1/instances/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := svc.AdminDeleteInstance(r.Context(), svc.effectiveActor(r.Context(), ""), id); err != nil {
			writeStoreErr(w, err)
			return
		}
		svc.InvalidateCatalogPools("instance", id)
		writeJSONResp(w, http.StatusOK, map[string]bool{"deleted": true})
	})
	mux.HandleFunc("POST /api/v1/instances/{id}/test", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			CredentialID string `json:"credential_id"`
			DatabaseName string `json:"database_name"`
		}
		_ = decodeJSONBody(r, &body)
		res, err := svc.PingInstance(r.Context(), r.PathValue("id"), body.CredentialID, body.DatabaseName)
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, res)
	})
	mux.HandleFunc("POST /api/v1/instances/{id}/discover", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			CredentialID string `json:"credential_id"`
			DatabaseName string `json:"database_name"`
		}
		_ = decodeJSONBody(r, &body)
		dbs, err := svc.DiscoverInstance(r.Context(), r.PathValue("id"), body.CredentialID, body.DatabaseName)
		if err != nil {
			writeHTTPErr(w, http.StatusBadGateway, err.Error())
			return
		}
		writeJSONResp(w, http.StatusOK, map[string]any{"databases": dbs})
	})

	// Targets & One-Shot DB Add
	mux.HandleFunc("POST /api/v1/db/add", func(w http.ResponseWriter, r *http.Request) {
		var req DBAddRequest
		if err := decodeJSONBody(r, &req); err != nil {
			writeHTTPErr(w, http.StatusBadRequest, err.Error())
			return
		}
		req.NoWorkspace = true
		req.WorkspaceCWD = ""
		req.WorkspaceGitRemotes = nil
		res, err := svc.AdminAddDatabase(r.Context(), svc.effectiveActor(r.Context(), ""), req)
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, res)
	})
	mux.HandleFunc("GET /api/v1/targets", func(w http.ResponseWriter, r *http.Request) {
		items, err := svc.BuildTargetDetails(r.Context(), "")
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSONResp(w, http.StatusOK, map[string]any{"items": items})
	})
	mux.HandleFunc("POST /api/v1/targets", func(w http.ResponseWriter, r *http.Request) {
		var body types.Target
		if err := decodeJSONBody(r, &body); err != nil {
			writeHTTPErr(w, http.StatusBadRequest, err.Error())
			return
		}
		res, err := svc.AdminUpsertTarget(r.Context(), svc.effectiveActor(r.Context(), ""), body, false)
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		svc.InvalidateCatalogPools("target", res.Item.ID)
		writeJSONResp(w, http.StatusOK, res.Item)
	})
	mux.HandleFunc("DELETE /api/v1/targets/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if _, err := svc.AdminDeleteTarget(r.Context(), svc.effectiveActor(r.Context(), ""), id); err != nil {
			writeStoreErr(w, err)
			return
		}
		svc.InvalidateCatalogPools("target", id)
		writeJSONResp(w, http.StatusOK, map[string]bool{"deleted": true})
	})
	mux.HandleFunc("POST /api/v1/targets/{id}/test", func(w http.ResponseWriter, r *http.Request) {
		details, err := svc.BuildTargetDetails(r.Context(), "")
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		id := r.PathValue("id")
		for _, d := range details {
			if d.Target.ID == id || d.Target.Ref == id {
				if svc.IsServerMode() {
					if !requireHTTPAction(w, r, rbac.ActionDBTest, scopeForTarget(d)) {
						return
					}
				}
				writeJSONResp(w, http.StatusOK, svc.PingTarget(r.Context(), d))
				return
			}
		}
		writeHTTPErr(w, http.StatusNotFound, "target not found")
	})
	mux.HandleFunc("POST /api/v1/targets/test-all", func(w http.ResponseWriter, r *http.Request) {
		details, err := svc.BuildTargetDetails(r.Context(), "")
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if svc.IsServerMode() {
			p := rbac.PrincipalFromContext(r.Context())
			filtered := make([]types.TargetDetail, 0, len(details))
			for _, d := range details {
				if rbac.Authorize(p, rbac.ActionDBTest, scopeForTarget(d)) == nil {
					filtered = append(filtered, d)
				}
			}
			details = filtered
		}
		results := svc.PingTargets(r.Context(), details)
		writeJSONResp(w, http.StatusOK, map[string]any{"results": results})
	})

	// Topology Export / Import (YAML or JSON, secret-free)
	mux.HandleFunc("GET /api/v1/topology", func(w http.ResponseWriter, r *http.Request) {
		if svc.IsServerMode() && !requireHTTPAction(w, r, rbac.ActionTopologyRead, rbac.ResourceScope{}) {
			return
		}
		b, err := svc.ExportTopologyForPrincipal(r.Context())
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if r.URL.Query().Get("format") == "yaml" {
			raw, err := yaml.Marshal(b)
			if err != nil {
				writeHTTPErr(w, http.StatusInternalServerError, err.Error())
				return
			}
			w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(raw)
			return
		}
		writeJSONResp(w, http.StatusOK, b)
	})
	mux.HandleFunc("POST /api/v1/topology", func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		if err != nil {
			writeHTTPErr(w, http.StatusBadRequest, err.Error())
			return
		}
		var bundle types.TopologyBundle
		if strings.HasPrefix(strings.TrimSpace(string(raw)), "{") {
			if err := json.Unmarshal(raw, &bundle); err != nil {
				writeHTTPErr(w, http.StatusBadRequest, "invalid topology JSON: "+err.Error())
				return
			}
		} else {
			if err := yaml.Unmarshal(raw, &bundle); err != nil {
				writeHTTPErr(w, http.StatusBadRequest, "invalid topology YAML: "+err.Error())
				return
			}
		}
		if _, err := svc.AdminApplyTopology(r.Context(), svc.effectiveActor(r.Context(), ""), bundle, false); err != nil {
			writeStoreErr(w, err)
			return
		}
		svc.InvalidateCatalogPools("topology", "")
		writeJSONResp(w, http.StatusOK, map[string]bool{"imported": true})
	})

	// Policies & Global Security
	mux.HandleFunc("GET /api/v1/policies", func(w http.ResponseWriter, r *http.Request) {
		items, err := svc.Store().ListPolicies(r.Context())
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if svc.IsServerMode() {
			items = filterPoliciesForPrincipal(r.Context(), svc, rbac.PrincipalFromContext(r.Context()), items)
		}
		writeJSONResp(w, http.StatusOK, map[string]any{"items": items})
	})
	mux.HandleFunc("POST /api/v1/policies", func(w http.ResponseWriter, r *http.Request) {
		var body types.PolicyRuleSet
		if err := decodeJSONBody(r, &body); err != nil {
			writeHTTPErr(w, http.StatusBadRequest, err.Error())
			return
		}
		res, err := svc.AdminUpsertPolicy(r.Context(), svc.effectiveActor(r.Context(), ""), body, false)
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, res.Item)
	})
	mux.HandleFunc("DELETE /api/v1/policies/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := svc.AdminDeletePolicy(r.Context(), svc.effectiveActor(r.Context(), ""), r.PathValue("id")); err != nil {
			writeStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, map[string]bool{"deleted": true})
	})
	mux.HandleFunc("GET /api/v1/security/global", func(w http.ResponseWriter, r *http.Request) {
		cfg, err := svc.Store().GetGlobalSecurityConfig(r.Context())
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSONResp(w, http.StatusOK, cfg)
	})
	mux.HandleFunc("PUT /api/v1/security/global", func(w http.ResponseWriter, r *http.Request) {
		var body types.GlobalSecurityConfig
		if err := decodeJSONBody(r, &body); err != nil {
			writeHTTPErr(w, http.StatusBadRequest, err.Error())
			return
		}
		res, err := svc.AdminUpdateGlobalSecurity(r.Context(), svc.effectiveActor(r.Context(), ""), body, false)
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		svc.broadcast(Event{Type: "security_updated", Data: res.Item})
		writeJSONResp(w, http.StatusOK, res.Item)
	})

	// Custom High-Risk Pattern Rules & Dry-Run Sandbox
	mux.HandleFunc("GET /api/v1/risk-patterns", func(w http.ResponseWriter, r *http.Request) {
		items, err := svc.Store().ListRiskPatternRules(r.Context())
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if svc.IsServerMode() {
			items = filterRiskPatternsForPrincipal(r.Context(), svc, rbac.PrincipalFromContext(r.Context()), items)
		}
		writeJSONResp(w, http.StatusOK, map[string]any{
			"items":         items,
			"builtin_packs": policy.BuiltinRulePacks(),
		})
	})
	mux.HandleFunc("POST /api/v1/risk-patterns", func(w http.ResponseWriter, r *http.Request) {
		var body types.RiskPatternRule
		if err := decodeJSONBody(r, &body); err != nil {
			writeHTTPErr(w, http.StatusBadRequest, err.Error())
			return
		}
		res, err := svc.AdminUpsertRiskPattern(r.Context(), svc.effectiveActor(r.Context(), ""), body, false)
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		svc.broadcast(Event{Type: "patterns_updated", Data: res.Item})
		writeJSONResp(w, http.StatusOK, res.Item)
	})
	mux.HandleFunc("DELETE /api/v1/risk-patterns/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := svc.AdminDeleteRiskPattern(r.Context(), svc.effectiveActor(r.Context(), ""), id, "", ""); err != nil {
			writeStoreErr(w, err)
			return
		}
		svc.broadcast(Event{Type: "patterns_updated", Data: map[string]string{"id": id}})
		writeJSONResp(w, http.StatusOK, map[string]bool{"deleted": true})
	})
	mux.HandleFunc("POST /api/v1/risk-patterns/packs/{id}/install", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ScopeType string `json:"scope_type"`
			ScopeID   string `json:"scope_id"`
		}
		_ = decodeJSONBody(r, &body)
		res, err := svc.AdminInstallRulePack(r.Context(), svc.effectiveActor(r.Context(), ""), r.PathValue("id"), body.ScopeType, body.ScopeID, false)
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, res)
	})
	mux.HandleFunc("POST /api/v1/risk-patterns/test", func(w http.ResponseWriter, r *http.Request) {
		var body types.PatternTestRequest
		if err := decodeJSONBody(r, &body); err != nil {
			writeHTTPErr(w, http.StatusBadRequest, err.Error())
			return
		}
		res, err := svc.TestRiskPattern(r.Context(), body)
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, res)
	})

	// Approvals
	mux.HandleFunc("GET /api/v1/approvals", func(w http.ResponseWriter, r *http.Request) {
		status := r.URL.Query().Get("status")
		items, err := svc.Store().ListApprovals(r.Context(), status, 200)
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if svc.IsServerMode() {
			items = filterApprovalsForPrincipal(r.Context(), svc, rbac.PrincipalFromContext(r.Context()), items)
		}
		writeJSONResp(w, http.StatusOK, map[string]any{"items": items})
	})
	mux.HandleFunc("GET /api/v1/approvals/{id}", func(w http.ResponseWriter, r *http.Request) {
		app, _, err := svc.Store().GetApproval(r.Context(), r.PathValue("id"))
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		if svc.IsServerMode() {
			p := rbac.PrincipalFromContext(r.Context())
			if len(filterApprovalsForPrincipal(r.Context(), svc, p, []types.ApprovalRequest{app})) == 0 {
				writeHTTPErr(w, http.StatusForbidden, "forbidden: approval is outside your authorized scope")
				return
			}
		}
		writeJSONResp(w, http.StatusOK, app)
	})
	mux.HandleFunc("POST /api/v1/approvals/{id}/approve", func(w http.ResponseWriter, r *http.Request) {
		handleApprovalDecision(w, r, svc, true)
	})
	mux.HandleFunc("POST /api/v1/approvals/{id}/reject", func(w http.ResponseWriter, r *http.Request) {
		handleApprovalDecision(w, r, svc, false)
	})

	// Operations & Audit Logs
	mux.HandleFunc("GET /api/v1/operations", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		limit, _ := strconv.Atoi(q.Get("limit"))
		items, err := svc.Store().ListOperations(r.Context(), q.Get("target"), q.Get("env"), q.Get("system"), q.Get("status"), q.Get("search"), limit)
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if svc.IsServerMode() {
			items = filterOperationsForPrincipal(rbac.PrincipalFromContext(r.Context()), items)
		}
		writeJSONResp(w, http.StatusOK, map[string]any{"items": items})
	})
	mux.HandleFunc("GET /api/v1/audit", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		limit, _ := strconv.Atoi(q.Get("limit"))
		offset, _ := strconv.Atoi(q.Get("offset"))
		items, total, truncated, err := svc.listAuthorizedAuditEntries(r.Context(), store.AuditFilter{
			Action:      q.Get("action"),
			TargetID:    q.Get("target"),
			OperationID: q.Get("operation_id"),
			Actor:       q.Get("actor"),
			SinceUTC:    q.Get("since"),
			UntilUTC:    q.Get("until"),
			Limit:       limit,
			Offset:      offset,
		})
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSONResp(w, http.StatusOK, map[string]any{
			"items":         items,
			"total_matched": total,
			"returned":      len(items),
			"truncated":     truncated,
		})
	})
	mux.HandleFunc("POST /api/v1/audit/verify", func(w http.ResponseWriter, r *http.Request) {
		if svc.IsServerMode() && !requireHTTPAction(w, r, rbac.ActionAuditVerify, rbac.ResourceScope{}) {
			return
		}
		res, err := svc.Store().VerifyAuditChain(r.Context())
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSONResp(w, http.StatusOK, res)
	})

	// Drivers & External Plugins
	mux.HandleFunc("GET /api/v1/drivers", func(w http.ResponseWriter, r *http.Request) {
		builtins := svc.Drivers().List()
		discovered := svc.Plugins().ListDiscovered()
		writeJSONResp(w, http.StatusOK, map[string]any{
			"drivers": builtins,
			"plugins": discovered,
		})
	})
	mux.HandleFunc("POST /api/v1/plugins/reload", func(w http.ResponseWriter, r *http.Request) {
		if svc.IsServerMode() && !requireHTTPAction(w, r, rbac.ActionPluginManage, rbac.ResourceScope{}) {
			return
		}
		items, err := svc.Plugins().Reload()
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSONResp(w, http.StatusOK, map[string]any{"plugins": items})
	})

	// Embedded TypeScript Web Console SPA fallback.
	mux.Handle("/", webui.Handler())
}

func handleApprovalDecision(w http.ResponseWriter, r *http.Request, svc *Service, approve bool) {
	var body struct {
		Reviewer string `json:"reviewer"`
		Note     string `json:"note"`
		Token    string `json:"token"`
	}
	_ = decodeJSONBody(r, &body)
	// In local mode, accept either validated UI session+CSRF or one-time approval_token;
	// in server mode, ServerSecurityMiddleware always enforces authenticated human session+CSRF.
	trustedUI := svc.IsServerMode() || hasValidUISession(r, svc)
	app, err := svc.ResolveApproval(r.Context(), r.PathValue("id"), approve, body.Reviewer, body.Note, body.Token, trustedUI)
	if err != nil {
		if strings.Contains(err.Error(), "forbidden") {
			writeHTTPErr(w, http.StatusForbidden, err.Error())
			return
		}
		if strings.Contains(err.Error(), "token") {
			writeHTTPErr(w, http.StatusForbidden, err.Error())
			return
		}
		writeStoreErr(w, err)
		return
	}
	writeJSONResp(w, http.StatusOK, app)
}

// WebSecurityMiddleware protects the local Web Console against DNS rebinding, cross-site CSRF,
// and unauthenticated loopback mutations:
//   - Every request must target a loopback Host header (127.0.0.1, localhost, or [::1]).
//   - Every mutating request must satisfy strict browser same-origin checks (Origin, Sec-Fetch-Site, or Referer;
//     headerless loopback requests are rejected).
//   - Mutating /api/v1/* endpoints require a valid per-daemon HttpOnly session cookie + X-Agent-DBCTL-CSRF header
//     (except approval decision endpoints, which also accept a valid one-time approval_token).
func WebSecurityMiddleware(svc *Service, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isLoopbackHostHeader(r.Host) {
			writeHTTPErr(w, http.StatusForbidden, "non-loopback host forbidden")
			return
		}
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		if !isSameOriginRequest(r) {
			writeHTTPErr(w, http.StatusForbidden, "cross-origin mutation blocked")
			return
		}
		if !isApprovalDecisionPath(r.URL.Path) && !hasValidUISession(r, svc) {
			writeHTTPErr(w, http.StatusForbidden, "missing or invalid UI session token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// SameOriginMiddleware enforces loopback Host and strict same-origin validation on mutating HTTP requests.
func SameOriginMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isLoopbackHostHeader(r.Host) {
			writeHTTPErr(w, http.StatusForbidden, "non-loopback host forbidden")
			return
		}
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		if !isSameOriginRequest(r) {
			writeHTTPErr(w, http.StatusForbidden, "cross-origin mutation blocked")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isApprovalDecisionPath(path string) bool {
	return strings.HasPrefix(path, "/api/v1/approvals/") &&
		(strings.HasSuffix(path, "/approve") || strings.HasSuffix(path, "/reject"))
}

func hasValidUISession(r *http.Request, svc *Service) bool {
	if svc == nil {
		return false
	}
	cookie, err := r.Cookie(uiSessionCookieName)
	if err != nil || cookie == nil || cookie.Value == "" {
		return false
	}
	csrf := strings.TrimSpace(r.Header.Get(uiCSRFHeaderName))
	if csrf == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(svc.UISessionToken())) == 1 &&
		subtle.ConstantTimeCompare([]byte(csrf), []byte(svc.UICSRFToken())) == 1
}

func isLoopbackHostHeader(hostHeader string) bool {
	trimmed := strings.TrimSpace(hostHeader)
	if trimmed == "" {
		return false
	}
	var host string
	if h, _, err := net.SplitHostPort(trimmed); err == nil {
		host = h
	} else {
		host = strings.Trim(trimmed, "[]")
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isSafeBootstrapRequest(r *http.Request) bool {
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
		if origin == "null" {
			return strings.EqualFold(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")), "same-origin")
		}
		u, err := url.Parse(origin)
		if err != nil || !strings.EqualFold(u.Host, r.Host) {
			return false
		}
	}
	if sfs := strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")); sfs != "" {
		if !strings.EqualFold(sfs, "same-origin") && !strings.EqualFold(sfs, "none") {
			return false
		}
	}
	return true
}

func isSameOriginRequest(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin != "" && origin != "null" {
		u, err := url.Parse(origin)
		if err != nil {
			return false
		}
		return strings.EqualFold(u.Host, r.Host)
	}

	sfs := strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))
	if sfs != "" {
		return strings.EqualFold(sfs, "same-origin")
	}

	ref := strings.TrimSpace(r.Header.Get("Referer"))
	if ref != "" {
		u, err := url.Parse(ref)
		if err != nil {
			return false
		}
		return strings.EqualFold(u.Host, r.Host)
	}

	return false
}

func decodeJSONBody(r *http.Request, dst any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 2<<20))
	return dec.Decode(dst)
}

func writeJSONResp(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeHTTPErr(w http.ResponseWriter, status int, msg string) {
	writeJSONResp(w, status, map[string]string{"error": msg})
}

func writeStoreErr(w http.ResponseWriter, err error) {
	switch {
	case strings.Contains(err.Error(), "forbidden"):
		writeHTTPErr(w, http.StatusForbidden, err.Error())
	case errors.Is(err, store.ErrNotFound):
		writeHTTPErr(w, http.StatusNotFound, err.Error())
	case errors.Is(err, store.ErrConflict):
		writeHTTPErr(w, http.StatusConflict, err.Error())
	default:
		writeHTTPErr(w, http.StatusBadRequest, err.Error())
	}
}
