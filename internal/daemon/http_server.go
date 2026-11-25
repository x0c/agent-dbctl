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

	"github.com/x0c/agent-dbctl/internal/policy"
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
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResp(w, http.StatusOK, map[string]string{"status": "running"})
	})

	// Bootstrap & server-driven display catalogs (also issues per-daemon HttpOnly session cookie + CSRF token).
	mux.HandleFunc("GET /api/v1/bootstrap", func(w http.ResponseWriter, r *http.Request) {
		if !isSafeBootstrapRequest(r) {
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
		http.SetCookie(w, &http.Cookie{
			Name:     uiSessionCookieName,
			Value:    svc.UISessionToken(),
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
		writeJSONResp(w, http.StatusOK, map[string]any{
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
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		ch := svc.subscribeSSE()
		defer svc.unsubscribeSSE(ch)

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
			case ev, open := <-ch:
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
		writeJSONResp(w, http.StatusOK, map[string]any{"items": items})
	})
	mux.HandleFunc("POST /api/v1/systems", func(w http.ResponseWriter, r *http.Request) {
		var body types.System
		if err := decodeJSONBody(r, &body); err != nil {
			writeHTTPErr(w, http.StatusBadRequest, err.Error())
			return
		}
		saved, err := svc.Store().UpsertSystem(r.Context(), "web-admin", body)
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, saved)
	})
	mux.HandleFunc("DELETE /api/v1/systems/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := svc.Store().DeleteSystem(r.Context(), "web-admin", r.PathValue("id")); err != nil {
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
		saved, err := svc.Store().UpsertEnvironment(r.Context(), "web-admin", body)
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, saved)
	})
	mux.HandleFunc("DELETE /api/v1/environments/{code...}", func(w http.ResponseWriter, r *http.Request) {
		if err := svc.AdminDeleteEnvironment(r.Context(), "web-admin", r.PathValue("code")); err != nil {
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
		writeJSONResp(w, http.StatusOK, map[string]any{"items": items})
	})
	mux.HandleFunc("POST /api/v1/network-profiles", func(w http.ResponseWriter, r *http.Request) {
		var body types.NetworkProfile
		if err := decodeJSONBody(r, &body); err != nil {
			writeHTTPErr(w, http.StatusBadRequest, err.Error())
			return
		}
		saved, err := svc.Store().UpsertNetworkProfile(r.Context(), "web-admin", body)
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, saved)
	})
	mux.HandleFunc("DELETE /api/v1/network-profiles/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := svc.Store().DeleteNetworkProfile(r.Context(), "web-admin", r.PathValue("id")); err != nil {
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
		for i := range items {
			items[i].HasSecret = svc.hasCredentialSecret(r.Context(), items[i])
		}
		writeJSONResp(w, http.StatusOK, map[string]any{"items": items})
	})
	mux.HandleFunc("POST /api/v1/credentials", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			types.CredentialProfile
			SecretValue string `json:"secret_value"`
		}
		if err := decodeJSONBody(r, &body); err != nil {
			writeHTTPErr(w, http.StatusBadRequest, err.Error())
			return
		}
		saved, err := svc.Store().UpsertCredentialProfile(r.Context(), "web-admin", body.CredentialProfile)
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		if body.Kind == types.CredKeychain && body.SecretValue != "" {
			if err := svc.Secrets().Put(r.Context(), "cred:"+saved.ID, body.SecretValue); err != nil {
				writeHTTPErr(w, http.StatusInternalServerError, "save secret failed: "+err.Error())
				return
			}
		}
		saved.HasSecret = svc.hasCredentialSecret(r.Context(), saved)
		svc.broadcast(Event{Type: "catalog_updated", Data: map[string]string{"kind": "credential", "id": saved.ID}})
		writeJSONResp(w, http.StatusOK, saved)
	})
	mux.HandleFunc("DELETE /api/v1/credentials/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := svc.Store().DeleteCredentialProfile(r.Context(), "web-admin", id); err != nil {
			writeStoreErr(w, err)
			return
		}
		_ = svc.Secrets().Delete(r.Context(), "cred:"+id)
		writeJSONResp(w, http.StatusOK, map[string]bool{"deleted": true})
	})

	// Instances + Live Test & Discover
	mux.HandleFunc("GET /api/v1/instances", func(w http.ResponseWriter, r *http.Request) {
		items, err := svc.Store().ListInstances(r.Context())
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSONResp(w, http.StatusOK, map[string]any{"items": items})
	})
	mux.HandleFunc("POST /api/v1/instances", func(w http.ResponseWriter, r *http.Request) {
		var body types.Instance
		if err := decodeJSONBody(r, &body); err != nil {
			writeHTTPErr(w, http.StatusBadRequest, err.Error())
			return
		}
		saved, err := svc.Store().UpsertInstance(r.Context(), "web-admin", body)
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, saved)
	})
	mux.HandleFunc("DELETE /api/v1/instances/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := svc.Store().DeleteInstance(r.Context(), "web-admin", r.PathValue("id")); err != nil {
			writeStoreErr(w, err)
			return
		}
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
		res, err := svc.AdminAddDatabase(r.Context(), "web-admin", req)
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
		saved, err := svc.Store().UpsertTarget(r.Context(), "web-admin", body)
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, saved)
	})
	mux.HandleFunc("DELETE /api/v1/targets/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := svc.Store().DeleteTarget(r.Context(), "web-admin", r.PathValue("id")); err != nil {
			writeStoreErr(w, err)
			return
		}
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
		results := svc.PingTargets(r.Context(), details)
		writeJSONResp(w, http.StatusOK, map[string]any{"results": results})
	})

	// Topology Export / Import (YAML or JSON, secret-free)
	mux.HandleFunc("GET /api/v1/topology", func(w http.ResponseWriter, r *http.Request) {
		b, err := svc.Store().ExportTopology(r.Context())
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
		if err := svc.Store().ImportTopology(r.Context(), "web-admin", bundle); err != nil {
			writeStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, map[string]bool{"imported": true})
	})

	// Policies & Global Security
	mux.HandleFunc("GET /api/v1/policies", func(w http.ResponseWriter, r *http.Request) {
		items, err := svc.Store().ListPolicies(r.Context())
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSONResp(w, http.StatusOK, map[string]any{"items": items})
	})
	mux.HandleFunc("POST /api/v1/policies", func(w http.ResponseWriter, r *http.Request) {
		var body types.PolicyRuleSet
		if err := decodeJSONBody(r, &body); err != nil {
			writeHTTPErr(w, http.StatusBadRequest, err.Error())
			return
		}
		saved, err := svc.Store().UpsertPolicy(r.Context(), "web-admin", body)
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, saved)
	})
	mux.HandleFunc("DELETE /api/v1/policies/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := svc.Store().DeletePolicy(r.Context(), "web-admin", r.PathValue("id")); err != nil {
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
		saved, err := svc.Store().UpdateGlobalSecurityConfig(r.Context(), "web-admin", body)
		if err != nil {
			writeHTTPErr(w, http.StatusBadRequest, err.Error())
			return
		}
		svc.broadcast(Event{Type: "security_updated", Data: saved})
		writeJSONResp(w, http.StatusOK, saved)
	})

	// Custom High-Risk Pattern Rules & Dry-Run Sandbox
	mux.HandleFunc("GET /api/v1/risk-patterns", func(w http.ResponseWriter, r *http.Request) {
		items, err := svc.Store().ListRiskPatternRules(r.Context())
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
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
		saved, err := svc.Store().UpsertRiskPatternRule(r.Context(), "web-admin", body)
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		svc.broadcast(Event{Type: "patterns_updated", Data: saved})
		writeJSONResp(w, http.StatusOK, saved)
	})
	mux.HandleFunc("DELETE /api/v1/risk-patterns/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := svc.Store().DeleteRiskPatternRule(r.Context(), "web-admin", id); err != nil {
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
		installed, err := svc.Store().InstallBuiltinRulePack(r.Context(), "web-admin", r.PathValue("id"), body.ScopeType, body.ScopeID)
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		svc.broadcast(Event{Type: "patterns_updated", Data: map[string]any{"pack_id": r.PathValue("id"), "count": len(installed)}})
		writeJSONResp(w, http.StatusOK, map[string]any{"items": installed})
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
		writeJSONResp(w, http.StatusOK, map[string]any{"items": items})
	})
	mux.HandleFunc("GET /api/v1/approvals/{id}", func(w http.ResponseWriter, r *http.Request) {
		app, _, err := svc.Store().GetApproval(r.Context(), r.PathValue("id"))
		if err != nil {
			writeStoreErr(w, err)
			return
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
		writeJSONResp(w, http.StatusOK, map[string]any{"items": items})
	})
	mux.HandleFunc("GET /api/v1/audit", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		limit, _ := strconv.Atoi(q.Get("limit"))
		items, err := svc.Store().ListAuditEntries(r.Context(), q.Get("action"), q.Get("target"), q.Get("operation_id"), limit)
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSONResp(w, http.StatusOK, map[string]any{"items": items})
	})
	mux.HandleFunc("POST /api/v1/audit/verify", func(w http.ResponseWriter, r *http.Request) {
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
		items, err := svc.Plugins().Reload()
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSONResp(w, http.StatusOK, map[string]any{"plugins": items})
	})

	// Embedded TypeScript Web Console SPA fallback.
	mux.Handle("/", webui.Handler())

	return WebSecurityMiddleware(svc, mux)
}

func handleApprovalDecision(w http.ResponseWriter, r *http.Request, svc *Service, approve bool) {
	var body struct {
		Reviewer string `json:"reviewer"`
		Note     string `json:"note"`
		Token    string `json:"token"`
	}
	_ = decodeJSONBody(r, &body)
	// Require a validated per-daemon session cookie + CSRF token for session-based approval;
	// otherwise ResolveApproval validates the one-time approval_token from the deep link.
	trustedUI := hasValidUISession(r, svc)
	app, err := svc.ResolveApproval(r.Context(), r.PathValue("id"), approve, body.Reviewer, body.Note, body.Token, trustedUI)
	if err != nil {
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
// - Every request must target a loopback Host header (127.0.0.1, localhost, or [::1]).
// - Every mutating request must satisfy strict browser same-origin checks (Origin, Sec-Fetch-Site, or Referer;
//   headerless loopback requests are rejected).
// - Mutating /api/v1/* endpoints require a valid per-daemon HttpOnly session cookie + X-Agent-DBCTL-CSRF header
//   (except approval decision endpoints, which also accept a valid one-time approval_token).
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
	case errors.Is(err, store.ErrNotFound):
		writeHTTPErr(w, http.StatusNotFound, err.Error())
	case errors.Is(err, store.ErrConflict):
		writeHTTPErr(w, http.StatusConflict, err.Error())
	default:
		writeHTTPErr(w, http.StatusBadRequest, err.Error())
	}
}
