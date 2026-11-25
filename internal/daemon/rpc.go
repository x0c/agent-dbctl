package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/x0c/agent-dbctl/internal/config"
	"github.com/x0c/agent-dbctl/internal/types"
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

// NewRPCHandler creates the CLI-facing control RPC handler (config read-only for agents).
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
			results := make([]types.PingResult, 0, len(items))
			for _, d := range items {
				results = append(results, svc.PingTarget(r.Context(), d))
			}
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
		items, err := svc.Store().ListOperations(r.Context(), q.Get("target"), q.Get("env"), q.Get("system"), q.Get("status"), q.Get("search"), 50)
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSONResp(w, http.StatusOK, map[string]any{"items": items})
	})

	mux.HandleFunc("POST /rpc/v1/ops/{id}/cancel", func(w http.ResponseWriter, r *http.Request) {
		resp, err := svc.CancelOperation(r.Context(), r.PathValue("id"), "agent-cli")
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, resp)
	})

	mux.HandleFunc("GET /rpc/v1/plugins", func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResp(w, http.StatusOK, map[string]any{
			"drivers": svc.Drivers().List(),
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

	return mux
}

func writeLookupErr(w http.ResponseWriter, err error) {
	if le, ok := err.(*TargetLookupError); ok {
		status := http.StatusBadRequest
		switch le.Code {
		case types.ErrCodeDBNotFound:
			status = http.StatusNotFound
		case types.ErrCodeAmbiguousTarget:
			status = http.StatusConflict
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
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("X-Agent-DBCTL-Token", c.token)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		var le LookupError
		if json.Unmarshal(raw, &le) == nil && le.Code != "" {
			return &le
		}
		var errMap map[string]string
		if json.Unmarshal(raw, &errMap) == nil && errMap["error"] != "" {
			return fmt.Errorf("%s", errMap["error"])
		}
		return fmt.Errorf("daemon RPC HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
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
