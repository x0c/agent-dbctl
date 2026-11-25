package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/x0c/agent-dbctl/internal/config"
	"github.com/x0c/agent-dbctl/internal/policy"
	"github.com/x0c/agent-dbctl/internal/store"
	"github.com/x0c/agent-dbctl/internal/types"
	"gopkg.in/yaml.v3"
)

// DaemonMeta persists active listener endpoints for a session.
type DaemonMeta struct {
	Version    string `json:"version"`
	Commit     string `json:"commit"`
	PID        int    `json:"pid"`
	Session    string `json:"session"`
	RPCAddr    string `json:"rpc_addr"`
	RPCToken   string `json:"rpc_token,omitempty"`
	WebURL     string `json:"web_url"`
	StartedAt  string `json:"started_at_utc"`
}

// NewRPCHandler creates the CLI-facing control RPC handler (full catalog/policy automation, human-only approvals).
func NewRPCHandler(svc *Service, shutdownFn func()) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /rpc/v1/identity", func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResp(w, http.StatusOK, svc.Identity())
	})

	mux.HandleFunc("POST /rpc/v1/shutdown", func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResp(w, http.StatusOK, map[string]bool{"stopping": true})
		if shutdownFn != nil {
			go shutdownFn()
		}
	})

	mux.HandleFunc("POST /rpc/v1/db/list", func(w http.ResponseWriter, r *http.Request) {
		var f ListFilter
		_ = decodeJSONBody(r, &f)
		items, similar, unsearched, err := svc.ListTargetsFiltered(r.Context(), f)
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSONResp(w, http.StatusOK, map[string]any{
			"items":              items,
			"similar_names":      similar,
			"unsearched_sources": unsearched,
		})
	})

	mux.HandleFunc("POST /rpc/v1/db/show", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Target       string `json:"target"`
			WorkspaceCWD string `json:"workspace_cwd"`
		}
		if err := decodeJSONBody(r, &req); err != nil {
			writeHTTPErr(w, http.StatusBadRequest, err.Error())
			return
		}
		d, err := svc.ResolveTarget(r.Context(), req.Target, req.WorkspaceCWD)
		if err != nil {
			writeLookupErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, d)
	})

	mux.HandleFunc("POST /rpc/v1/db/schema", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Target       string `json:"target"`
			Table        string `json:"table"`
			Search       string `json:"search"`
			Limit        int    `json:"limit"`
			WorkspaceCWD string `json:"workspace_cwd"`
		}
		if err := decodeJSONBody(r, &req); err != nil {
			writeHTTPErr(w, http.StatusBadRequest, err.Error())
			return
		}
		res, err := svc.InspectSchema(r.Context(), req.Target, req.WorkspaceCWD, req.Table, req.Search, req.Limit)
		if err != nil {
			writeLookupErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, res)
	})

	mux.HandleFunc("POST /rpc/v1/db/test", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Target       string     `json:"target"`
			All          bool       `json:"all"`
			Filter       ListFilter `json:"filter"`
		}
		if err := decodeJSONBody(r, &req); err != nil {
			writeHTTPErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if req.All {
			items, _, _, err := svc.ListTargetsFiltered(r.Context(), req.Filter)
			if err != nil {
				writeHTTPErr(w, http.StatusInternalServerError, err.Error())
				return
			}
			results := svc.PingTargets(r.Context(), items)
			writeJSONResp(w, http.StatusOK, map[string]any{"results": results})
			return
		}
		d, err := svc.ResolveTarget(r.Context(), req.Target, req.Filter.WorkspaceCWD)
		if err != nil {
			writeLookupErr(w, err)
			return
		}
		res := svc.PingTarget(r.Context(), d)
		writeJSONResp(w, http.StatusOK, map[string]any{"results": []types.PingResult{res}})
	})

	mux.HandleFunc("POST /rpc/v1/exec", func(w http.ResponseWriter, r *http.Request) {
		var req types.ExecRequest
		if err := decodeJSONBody(r, &req); err != nil {
			writeHTTPErr(w, http.StatusBadRequest, err.Error())
			return
		}
		resp, err := svc.Execute(r.Context(), req)
		if err != nil {
			writeLookupErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, resp)
	})

	mux.HandleFunc("GET /rpc/v1/ops/{id}", func(w http.ResponseWriter, r *http.Request) {
		resp, err := svc.GetOperationStatus(r.Context(), r.PathValue("id"))
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, resp)
	})

	mux.HandleFunc("GET /rpc/v1/ops", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		limit := 50
		if raw := strings.TrimSpace(q.Get("limit")); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil && n > 0 {
				limit = n
				if limit > 500 {
					limit = 500
				}
			}
		}
		target := strings.TrimSpace(q.Get("target"))
		if target != "" {
			if d, err := svc.ResolveTarget(r.Context(), target, ""); err == nil {
				target = d.Target.Ref
			}
		}
		items, err := svc.Store().ListOperations(r.Context(), target, q.Get("env"), q.Get("system"), q.Get("status"), q.Get("search"), limit)
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSONResp(w, http.StatusOK, map[string]any{"items": items})
	})

	mux.HandleFunc("GET /rpc/v1/ops/{id}/wait", func(w http.ResponseWriter, r *http.Request) {
		timeoutSec := 120
		if raw := strings.TrimSpace(r.URL.Query().Get("timeout_sec")); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil && n > 0 {
				timeoutSec = n
				if timeoutSec > 600 {
					timeoutSec = 600
				}
			}
		}
		resp, err := svc.WaitForOperation(r.Context(), r.PathValue("id"), time.Duration(timeoutSec)*time.Second)
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, resp)
	})

	mux.HandleFunc("POST /rpc/v1/ops/{id}/cancel", func(w http.ResponseWriter, r *http.Request) {
		resp, err := svc.CancelOperationAndWait(r.Context(), r.PathValue("id"), "agent-cli")
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, resp)
	})

	mux.HandleFunc("GET /rpc/v1/audit", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		limit := 50
		if raw := strings.TrimSpace(q.Get("limit")); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil && n > 0 {
				limit = n
				if limit > 1000 {
					limit = 1000
				}
			}
		}
		offset := 0
		if raw := strings.TrimSpace(q.Get("offset")); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil && n > 0 {
				offset = n
			}
		}
		items, total, err := svc.Store().ListAuditEntriesFiltered(r.Context(), store.AuditFilter{
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
			"truncated":     offset+len(items) < total,
			"limit":         limit,
			"offset":        offset,
		})
	})

	mux.HandleFunc("GET /rpc/v1/plugins", func(w http.ResponseWriter, _ *http.Request) {
		builtins := svc.Drivers().List()
		writeJSONResp(w, http.StatusOK, map[string]any{
			"drivers": builtins,
			"plugins": svc.Plugins().ListDiscovered(),
		})
	})

	mux.HandleFunc("GET /rpc/v1/drivers", func(w http.ResponseWriter, _ *http.Request) {
		builtins := svc.Drivers().List()
		writeJSONResp(w, http.StatusOK, map[string]any{
			"drivers": builtins,
			"guides":  BuildEngineGuides(builtins),
			"plugins": svc.Plugins().ListDiscovered(),
		})
	})

	mux.HandleFunc("POST /rpc/v1/plugins/reload", func(w http.ResponseWriter, _ *http.Request) {
		items, err := svc.Plugins().Reload()
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSONResp(w, http.StatusOK, map[string]any{"plugins": items})
	})

	mux.HandleFunc("POST /rpc/v1/audit/verify", func(w http.ResponseWriter, r *http.Request) {
		res, err := svc.Store().VerifyAuditChain(r.Context())
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSONResp(w, http.StatusOK, res)
	})

	// Systems
	mux.HandleFunc("GET /rpc/v1/systems", func(w http.ResponseWriter, r *http.Request) {
		items, err := svc.Store().ListSystems(r.Context())
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if items == nil {
			items = []types.System{}
		}
		writeJSONResp(w, http.StatusOK, map[string]any{"items": items})
	})
	mux.HandleFunc("POST /rpc/v1/systems", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			System types.System `json:"system"`
			DryRun bool         `json:"dry_run"`
			Actor  string       `json:"actor"`
		}
		if err := decodeJSONBody(r, &req); err != nil {
			writeRPCInvalidErr(w, err.Error())
			return
		}
		res, err := svc.AdminUpsertSystem(r.Context(), req.Actor, req.System, req.DryRun)
		if err != nil {
			writeRPCStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, res)
	})
	mux.HandleFunc("DELETE /rpc/v1/systems/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := svc.AdminDeleteSystem(r.Context(), "agent-cli", r.PathValue("id")); err != nil {
			writeRPCStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, map[string]bool{"deleted": true})
	})

	// Environments
	mux.HandleFunc("GET /rpc/v1/environments", func(w http.ResponseWriter, r *http.Request) {
		items, err := svc.Store().ListEnvironments(r.Context())
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if items == nil {
			items = []types.Environment{}
		}
		writeJSONResp(w, http.StatusOK, map[string]any{"items": items})
	})
	mux.HandleFunc("POST /rpc/v1/environments", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Environment types.Environment `json:"environment"`
			DryRun      bool              `json:"dry_run"`
			Actor       string            `json:"actor"`
		}
		if err := decodeJSONBody(r, &req); err != nil {
			writeRPCInvalidErr(w, err.Error())
			return
		}
		res, err := svc.AdminUpsertEnvironment(r.Context(), req.Actor, req.Environment, req.DryRun)
		if err != nil {
			writeRPCStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, res)
	})

	// Network Profiles
	mux.HandleFunc("GET /rpc/v1/network-profiles", func(w http.ResponseWriter, r *http.Request) {
		items, err := svc.Store().ListNetworkProfiles(r.Context())
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if items == nil {
			items = []types.NetworkProfile{}
		}
		writeJSONResp(w, http.StatusOK, map[string]any{"items": items})
	})
	mux.HandleFunc("POST /rpc/v1/network-profiles", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			NetworkProfile types.NetworkProfile `json:"network_profile"`
			DryRun         bool                 `json:"dry_run"`
			Actor          string               `json:"actor"`
		}
		if err := decodeJSONBody(r, &req); err != nil {
			writeRPCInvalidErr(w, err.Error())
			return
		}
		res, err := svc.AdminUpsertNetworkProfile(r.Context(), req.Actor, req.NetworkProfile, req.DryRun)
		if err != nil {
			writeRPCStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, res)
	})
	mux.HandleFunc("DELETE /rpc/v1/network-profiles/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := svc.AdminDeleteNetworkProfile(r.Context(), "agent-cli", r.PathValue("id")); err != nil {
			writeRPCStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, map[string]bool{"deleted": true})
	})

	// Credential Profiles (secret-free GET, write-only secret input)
	mux.HandleFunc("GET /rpc/v1/credentials", func(w http.ResponseWriter, r *http.Request) {
		items, err := svc.Store().ListCredentialProfiles(r.Context())
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if items == nil {
			items = []types.CredentialProfile{}
		}
		for i := range items {
			items[i].HasSecret = svc.hasCredentialSecret(r.Context(), items[i])
		}
		writeJSONResp(w, http.StatusOK, map[string]any{"items": items})
	})
	mux.HandleFunc("POST /rpc/v1/credentials", func(w http.ResponseWriter, r *http.Request) {
		var req CredentialUpsertRequest
		if err := decodeJSONBody(r, &req); err != nil {
			writeRPCInvalidErr(w, err.Error())
			return
		}
		res, err := svc.AdminUpsertCredentialProfile(r.Context(), "agent-cli", req)
		if err != nil {
			writeRPCStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, res)
	})
	mux.HandleFunc("DELETE /rpc/v1/credentials/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := svc.AdminDeleteCredentialProfile(r.Context(), "agent-cli", r.PathValue("id")); err != nil {
			writeRPCStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, map[string]bool{"deleted": true})
	})

	// Instances + Test + Discover
	mux.HandleFunc("GET /rpc/v1/instances", func(w http.ResponseWriter, r *http.Request) {
		items, err := svc.Store().ListInstances(r.Context())
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if items == nil {
			items = []types.Instance{}
		}
		writeJSONResp(w, http.StatusOK, map[string]any{"items": items})
	})
	mux.HandleFunc("POST /rpc/v1/instances", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Instance types.Instance `json:"instance"`
			DryRun   bool           `json:"dry_run"`
			Actor    string         `json:"actor"`
		}
		if err := decodeJSONBody(r, &req); err != nil {
			writeRPCInvalidErr(w, err.Error())
			return
		}
		res, err := svc.AdminUpsertInstance(r.Context(), req.Actor, req.Instance, req.DryRun)
		if err != nil {
			writeRPCStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, res)
	})
	mux.HandleFunc("DELETE /rpc/v1/instances/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := svc.AdminDeleteInstance(r.Context(), "agent-cli", r.PathValue("id")); err != nil {
			writeRPCStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, map[string]bool{"deleted": true})
	})
	mux.HandleFunc("POST /rpc/v1/instances/{id}/test", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			CredentialID string `json:"credential_id"`
			DatabaseName string `json:"database_name"`
		}
		_ = decodeJSONBody(r, &body)
		res, err := svc.AdminTestInstance(r.Context(), r.PathValue("id"), body.CredentialID, body.DatabaseName)
		if err != nil {
			writeRPCStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, res)
	})
	mux.HandleFunc("POST /rpc/v1/instances/{id}/discover", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			CredentialID string `json:"credential_id"`
			DatabaseName string `json:"database_name"`
		}
		_ = decodeJSONBody(r, &body)
		inst, dbs, err := svc.AdminDiscoverInstance(r.Context(), r.PathValue("id"), body.CredentialID, body.DatabaseName)
		if err != nil {
			writeRPCStoreErr(w, err)
			return
		}
		if dbs == nil {
			dbs = []string{}
		}
		writeJSONResp(w, http.StatusOK, map[string]any{
			"instance":  inst.Name,
			"engine":    inst.Engine,
			"databases": dbs,
		})
	})

	// One-shot DB Add & Target CRUD
	mux.HandleFunc("POST /rpc/v1/db/add", func(w http.ResponseWriter, r *http.Request) {
		var req DBAddRequest
		if err := decodeJSONBody(r, &req); err != nil {
			writeRPCInvalidErr(w, err.Error())
			return
		}
		res, err := svc.AdminAddDatabase(r.Context(), "agent-cli", req)
		if err != nil {
			writeRPCStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, res)
	})
	mux.HandleFunc("POST /rpc/v1/targets", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Target types.Target `json:"target"`
			DryRun bool         `json:"dry_run"`
			Actor  string       `json:"actor"`
		}
		if err := decodeJSONBody(r, &req); err != nil {
			writeRPCInvalidErr(w, err.Error())
			return
		}
		res, err := svc.AdminUpsertTarget(r.Context(), req.Actor, req.Target, req.DryRun)
		if err != nil {
			writeRPCStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, res)
	})
	mux.HandleFunc("DELETE /rpc/v1/targets/{id...}", func(w http.ResponseWriter, r *http.Request) {
		if err := svc.AdminDeleteTarget(r.Context(), "agent-cli", r.PathValue("id")); err != nil {
			writeRPCStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, map[string]bool{"deleted": true})
	})

	// Topology Export / Apply
	mux.HandleFunc("GET /rpc/v1/topology", func(w http.ResponseWriter, r *http.Request) {
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
	mux.HandleFunc("POST /rpc/v1/topology", func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		if err != nil {
			writeRPCInvalidErr(w, err.Error())
			return
		}
		var bundle types.TopologyBundle
		trimmed := strings.TrimSpace(string(raw))
		if strings.HasPrefix(trimmed, "{") {
			if err := json.Unmarshal(raw, &bundle); err != nil {
				writeRPCInvalidErr(w, "invalid topology JSON: "+err.Error())
				return
			}
		} else {
			if err := yaml.Unmarshal(raw, &bundle); err != nil {
				writeRPCInvalidErr(w, "invalid topology YAML: "+err.Error())
				return
			}
		}
		dryRun := r.URL.Query().Get("dry_run") == "1" || strings.EqualFold(r.URL.Query().Get("dry_run"), "true")
		res, err := svc.AdminApplyTopology(r.Context(), "agent-cli", bundle, dryRun)
		if err != nil {
			writeRPCStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, res)
	})

	// Global Security, Policies & Risk Patterns
	mux.HandleFunc("GET /rpc/v1/security/global", func(w http.ResponseWriter, r *http.Request) {
		cfg, err := svc.Store().GetGlobalSecurityConfig(r.Context())
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSONResp(w, http.StatusOK, cfg)
	})
	mux.HandleFunc("PUT /rpc/v1/security/global", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Config types.GlobalSecurityConfig `json:"config"`
			DryRun bool                       `json:"dry_run"`
			Actor  string                     `json:"actor"`
		}
		if err := decodeJSONBody(r, &req); err != nil {
			writeRPCInvalidErr(w, err.Error())
			return
		}
		res, err := svc.AdminUpdateGlobalSecurity(r.Context(), req.Actor, req.Config, req.DryRun)
		if err != nil {
			writeRPCStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, res)
	})
	mux.HandleFunc("GET /rpc/v1/policies", func(w http.ResponseWriter, r *http.Request) {
		items, err := svc.Store().ListPolicies(r.Context())
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if items == nil {
			items = []types.PolicyRuleSet{}
		}
		writeJSONResp(w, http.StatusOK, map[string]any{"items": items})
	})
	mux.HandleFunc("POST /rpc/v1/policies", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Policy types.PolicyRuleSet `json:"policy"`
			DryRun bool                `json:"dry_run"`
			Actor  string              `json:"actor"`
		}
		if err := decodeJSONBody(r, &req); err != nil {
			writeRPCInvalidErr(w, err.Error())
			return
		}
		res, err := svc.AdminUpsertPolicy(r.Context(), req.Actor, req.Policy, req.DryRun)
		if err != nil {
			writeRPCStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, res)
	})
	mux.HandleFunc("DELETE /rpc/v1/policies/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := svc.AdminDeletePolicy(r.Context(), "agent-cli", r.PathValue("id")); err != nil {
			writeRPCStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, map[string]bool{"deleted": true})
	})

	mux.HandleFunc("GET /rpc/v1/risk-patterns", func(w http.ResponseWriter, r *http.Request) {
		items, err := svc.Store().ListRiskPatternRules(r.Context())
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if items == nil {
			items = []types.RiskPatternRule{}
		}
		writeJSONResp(w, http.StatusOK, map[string]any{
			"items":         items,
			"builtin_packs": policy.BuiltinRulePacks(),
		})
	})
	mux.HandleFunc("POST /rpc/v1/risk-patterns", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Rule   types.RiskPatternRule `json:"rule"`
			DryRun bool                  `json:"dry_run"`
			Actor  string                `json:"actor"`
		}
		if err := decodeJSONBody(r, &req); err != nil {
			writeRPCInvalidErr(w, err.Error())
			return
		}
		res, err := svc.AdminUpsertRiskPattern(r.Context(), req.Actor, req.Rule, req.DryRun)
		if err != nil {
			writeRPCStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, res)
	})
	mux.HandleFunc("DELETE /rpc/v1/risk-patterns/{id}", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if err := svc.AdminDeleteRiskPattern(r.Context(), "agent-cli", r.PathValue("id"), q.Get("scope_type"), q.Get("scope_id")); err != nil {
			writeRPCStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, map[string]bool{"deleted": true})
	})
	mux.HandleFunc("POST /rpc/v1/risk-patterns/packs/{id}/install", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ScopeType string `json:"scope_type"`
			ScopeID   string `json:"scope_id"`
			DryRun    bool   `json:"dry_run"`
			Actor     string `json:"actor"`
		}
		_ = decodeJSONBody(r, &req)
		res, err := svc.AdminInstallRulePack(r.Context(), req.Actor, r.PathValue("id"), req.ScopeType, req.ScopeID, req.DryRun)
		if err != nil {
			writeRPCStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, res)
	})
	mux.HandleFunc("POST /rpc/v1/risk-patterns/test", func(w http.ResponseWriter, r *http.Request) {
		var req types.PatternTestRequest
		if err := decodeJSONBody(r, &req); err != nil {
			writeRPCInvalidErr(w, err.Error())
			return
		}
		res, err := svc.TestRiskPattern(r.Context(), req)
		if err != nil {
			writeRPCStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, res)
	})

	// Read-only Approval Queue Inspection (resolution remains strictly human-only)
	mux.HandleFunc("GET /rpc/v1/approvals", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		status := q.Get("status")
		limit, _ := strconv.Atoi(q.Get("limit"))
		items, err := svc.Store().ListApprovals(r.Context(), status, limit)
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if items == nil {
			items = []types.ApprovalRequest{}
		}
		writeJSONResp(w, http.StatusOK, map[string]any{"items": items})
	})
	mux.HandleFunc("GET /rpc/v1/approvals/{id}", func(w http.ResponseWriter, r *http.Request) {
		app, _, err := svc.Store().GetApproval(r.Context(), r.PathValue("id"))
		if err != nil {
			writeRPCStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, app)
	})

	return mux
}

func writeRPCInvalidErr(w http.ResponseWriter, msg string) {
	writeJSONResp(w, http.StatusBadRequest, map[string]any{
		"code":  types.ErrCodeInvalidInput,
		"error": msg,
	})
}

func writeRPCStoreErr(w http.ResponseWriter, err error) {
	switch {
	case storeErrIsNotFound(err):
		writeJSONResp(w, http.StatusNotFound, map[string]any{
			"code":  types.ErrCodeNotFound,
			"error": err.Error(),
		})
	case storeErrIsConflict(err):
		writeJSONResp(w, http.StatusConflict, map[string]any{
			"code":  types.ErrCodeConflict,
			"error": err.Error(),
		})
	default:
		writeJSONResp(w, http.StatusBadRequest, map[string]any{
			"code":  types.ErrCodeInvalidInput,
			"error": err.Error(),
		})
	}
}

func storeErrIsNotFound(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), store.ErrNotFound.Error())
}

func storeErrIsConflict(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), store.ErrConflict.Error())
}

func writeLookupErr(w http.ResponseWriter, err error) {
	if le, ok := err.(*TargetLookupError); ok {
		status := http.StatusBadRequest
		switch le.Code {
		case types.ErrCodeDBNotFound:
			status = http.StatusNotFound
		case types.ErrCodeAmbiguousTarget:
			status = http.StatusConflict
		case types.ErrCodePolicyDenied, types.ErrCodeTargetMaintenance:
			status = http.StatusForbidden
		case types.ErrCodeDriverError:
			status = http.StatusBadGateway
		}
		writeJSONResp(w, status, map[string]any{
			"code":               le.Code,
			"error":              le.Message,
			"candidates":         le.Candidates,
			"similar_names":      le.SimilarNames,
			"unsearched_sources": le.UnsearchedSources,
		})
		return
	}
	writeHTTPErr(w, http.StatusBadRequest, err.Error())
}

// Client talks to the local daemon over Unix Socket (Unix) or loopback token TCP (Windows).
type Client struct {
	httpClient *http.Client
	baseURL    string
	token      string
}

// LookupError mirrors TargetLookupError across the RPC boundary.
type LookupError struct {
	Code              string               `json:"code"`
	Message           string               `json:"error"`
	Candidates        []types.TargetDetail `json:"candidates"`
	SimilarNames      []string             `json:"similar_names"`
	UnsearchedSources []string             `json:"unsearched_sources"`
}

func (e *LookupError) Error() string { return e.Message }

// ReadDaemonMeta reads and validates the session's daemon metadata file.
func ReadDaemonMeta(paths config.Paths) (DaemonMeta, error) {
	if err := config.ValidateRegularFile(paths.DaemonMeta); err != nil {
		return DaemonMeta{}, err
	}
	raw, err := os.ReadFile(paths.DaemonMeta)
	if err != nil {
		return DaemonMeta{}, err
	}
	var m DaemonMeta
	if err := json.Unmarshal(raw, &m); err != nil {
		return DaemonMeta{}, err
	}
	return m, nil
}

// WriteDaemonMeta writes daemon metadata atomically at 0600.
func WriteDaemonMeta(paths config.Paths, m DaemonMeta) error {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(paths.RunDir, ".daemon-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(name)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, paths.DaemonMeta); err != nil {
		return err
	}
	cleanup = false
	return nil
}

// DoJSON sends an RPC request with bounded context timeout (Client.Timeout=0 per go.md).
func (c *Client) DoJSON(ctx context.Context, method, path string, body any, out any) error {
	var rawBody []byte
	contentType := ""
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rawBody = b
		contentType = "application/json"
	}
	raw, err := c.DoRaw(ctx, method, path, contentType, rawBody)
	if err != nil {
		return err
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// DoRaw sends a raw RPC payload and returns the raw response bytes, mapping structured RPC errors to *LookupError.
func (c *Client) DoRaw(ctx context.Context, method, path, contentType string, rawBody []byte) ([]byte, error) {
	var rdr io.Reader
	if len(rawBody) > 0 {
		rdr = bytes.NewReader(rawBody)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, rdr)
	if err != nil {
		return nil, err
	}
	if contentType != "" && len(rawBody) > 0 {
		req.Header.Set("Content-Type", contentType)
	}
	if c.token != "" {
		req.Header.Set("X-Agent-DBCTL-Token", c.token)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		var le LookupError
		if json.Unmarshal(raw, &le) == nil && le.Code != "" {
			return nil, &le
		}
		var errMap map[string]string
		if json.Unmarshal(raw, &errMap) == nil && errMap["error"] != "" {
			return nil, fmt.Errorf("%s", errMap["error"])
		}
		return nil, fmt.Errorf("daemon RPC HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return raw, nil
}

// GetIdentity queries the running daemon's identity with a short timeout.
func (c *Client) GetIdentity(ctx context.Context) (Identity, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var id Identity
	err := c.DoJSON(ctx, http.MethodGet, "/rpc/v1/identity", nil, &id)
	return id, err
}

// Shutdown requests clean daemon termination.
func (c *Client) Shutdown(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return c.DoJSON(ctx, http.MethodPost, "/rpc/v1/shutdown", map[string]any{}, nil)
}
