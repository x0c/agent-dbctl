package daemon_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/x0c/agent-dbctl/internal/config"
	"github.com/x0c/agent-dbctl/internal/daemon"
	"github.com/x0c/agent-dbctl/internal/store"
	"github.com/x0c/agent-dbctl/internal/types"
)

func setupIsolatedServer(t *testing.T) (*daemon.Server, config.Paths) {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv(config.EnvConfigHome, tmp)
	t.Setenv(config.EnvSecretBackend, "file")
	t.Setenv(config.EnvNoBrowser, "1")
	t.Setenv(config.EnvSession, "test-sess")

	paths, err := config.ResolvePaths("test-sess")
	if err != nil {
		t.Fatalf("resolve paths: %v", err)
	}
	srv, err := daemon.StartServer(context.Background(), paths, "v0.1.0-test", "abc123", "")
	if err != nil {
		t.Fatalf("start server: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		done <- srv.Run(context.Background())
	}()
	t.Cleanup(func() {
		srv.TriggerShutdown()
		if runErr := <-done; runErr != nil {
			t.Errorf("server shutdown error: %v", runErr)
		}
	})
	return srv, paths
}

func issueTestWebSession(t *testing.T, handler http.Handler) (*http.Cookie, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/bootstrap", nil)
	req.Host = "127.0.0.1:8080"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("bootstrap HTTP %d: %s", rec.Code, rec.Body.String())
	}
	var sessionCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "agent_dbctl_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatalf("expected agent_dbctl_session cookie from bootstrap")
	}
	var boot struct {
		UICSRFToken string `json:"ui_csrf_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &boot); err != nil || boot.UICSRFToken == "" {
		t.Fatalf("expected ui_csrf_token in bootstrap, got %q err=%v", rec.Body.String(), err)
	}
	return sessionCookie, boot.UICSRFToken
}

func newAuthedWebPOST(path string, body io.Reader, cookie *http.Cookie, csrf string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, path, body)
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	req.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if csrf != "" {
		req.Header.Set("X-Agent-DBCTL-CSRF", csrf)
	}
	return req
}

func TestE2EExecApprovalRejectTruncationAndSameOrigin(t *testing.T) {
	srv, _ := setupIsolatedServer(t)
	svc := srv.Service()
	ctx := context.Background()

	// Seed real SQLite dev & prod databases on disk.
	devDB := filepath.Join(t.TempDir(), "dev.sqlite")
	prodDB := filepath.Join(t.TempDir(), "prod.sqlite")

	sys, err := svc.Store().UpsertSystem(ctx, "test", types.System{
		Slug:           "orders",
		Name:           "Order Core",
		WorkspacePaths: []string{t.TempDir()},
	})
	if err != nil {
		t.Fatalf("upsert sys: %v", err)
	}

	devInst, err := svc.Store().UpsertInstance(ctx, "test", types.Instance{
		Name:   "sqlite-dev",
		Engine: "sqlite",
		Host:   devDB,
	})
	if err != nil {
		t.Fatalf("upsert dev inst: %v", err)
	}
	prodInst, err := svc.Store().UpsertInstance(ctx, "test", types.Instance{
		Name:   "sqlite-prod",
		Engine: "sqlite",
		Host:   prodDB,
	})
	if err != nil {
		t.Fatalf("upsert prod inst: %v", err)
	}

	devTgt, err := svc.Store().UpsertTarget(ctx, "test", types.Target{
		Ref:             "orders/dev/main",
		Alias:           "dev-orders",
		OwnerSystemID:   sys.ID,
		EnvironmentCode: "dev",
		InstanceID:      devInst.ID,
		DatabaseName:    devDB,
	})
	if err != nil {
		t.Fatalf("upsert dev target: %v", err)
	}
	prodTgt, err := svc.Store().UpsertTarget(ctx, "test", types.Target{
		Ref:             "orders/prod/main",
		Alias:           "prod-orders",
		OwnerSystemID:   sys.ID,
		EnvironmentCode: "prod",
		InstanceID:      prodInst.ID,
		DatabaseName:    prodDB,
	})
	if err != nil {
		t.Fatalf("upsert prod target: %v", err)
	}

	// 1. Dev YOLO: create table, insert rows, query with max_rows truncation.
	for _, q := range []string{
		"CREATE TABLE items(id INTEGER PRIMARY KEY, name TEXT)",
		"INSERT INTO items(id, name) VALUES (1,'a'),(2,'b'),(3,'c'),(4,'d'),(5,'e')",
	} {
		resp, err := svc.Execute(ctx, types.ExecRequest{TargetRefOrAlias: devTgt.Alias, Query: q, Wait: true})
		if err != nil || resp.Status != types.OpSucceeded {
			t.Fatalf("dev YOLO exec %q failed: resp=%+v err=%v", q, resp, err)
		}
	}

	truncResp, err := svc.Execute(ctx, types.ExecRequest{
		TargetRefOrAlias: "dev-orders",
		Query:            "SELECT id, name FROM items ORDER BY id",
		MaxRows:          3,
		Wait:             true,
	})
	if err != nil || !truncResp.Result.Truncated || truncResp.Result.ReturnedRows != 3 || truncResp.Result.CutoffReason != "max_rows" {
		t.Fatalf("expected clean max_rows=3 truncation, got %+v (err=%v)", truncResp, err)
	}

	// Seed prodDB directly with schema + index so safe indexed query passes EXPLAIN without full scan.
	if _, err := svc.Execute(ctx, types.ExecRequest{TargetRefOrAlias: devTgt.Ref, Query: "SELECT 1", Wait: true}); err != nil {
		t.Fatal(err)
	}
	// Pre-populate prod via temporary YOLO env on a setup step? Even better: approve DDL in prod via real approval flow!
	missingReasonResp, err := svc.Execute(ctx, types.ExecRequest{
		TargetRefOrAlias: prodTgt.Alias,
		Query:            "CREATE TABLE items(id INTEGER PRIMARY KEY, name TEXT)",
		Wait:             false,
	})
	if err != nil || missingReasonResp.ErrorCode != types.ErrCodeReasonRequired || missingReasonResp.ApprovalID != "" {
		t.Fatalf("expected reason_required without creating approval when Reason is empty, got %+v err=%v", missingReasonResp, err)
	}
	ddlAsync, err := svc.Execute(ctx, types.ExecRequest{
		TargetRefOrAlias: prodTgt.Alias,
		Query:            "CREATE TABLE items(id INTEGER PRIMARY KEY, name TEXT)",
		Reason:           "Init prod schema for verification",
		Wait:             false,
	})
	if err != nil || ddlAsync.Status != types.OpWaitingApproval || ddlAsync.ApprovalURL == "" {
		t.Fatalf("expected waiting_approval for prod DDL, got %+v err=%v", ddlAsync, err)
	}

	// Dry-run must NOT mutate prod.
	dryResp, err := svc.Execute(ctx, types.ExecRequest{
		TargetRefOrAlias: prodTgt.Alias,
		Query:            "DROP TABLE items",
		DryRun:           true,
	})
	if err != nil || dryResp.Evaluation.Decision != types.DecisionRequireApproval {
		t.Fatalf("unexpected dry-run result: %+v err=%v", dryResp, err)
	}

	// Approve DDL using the one-time token from ApprovalURL via HTTP (verifying same-origin too!).
	parsedURL, _ := url.Parse(ddlAsync.ApprovalURL)
	oneTimeToken := parsedURL.Query().Get("token")
	approveBody, _ := json.Marshal(map[string]string{"reviewer": "tester", "note": "approved ddl", "token": oneTimeToken})
	req, _ := http.NewRequest(http.MethodPost, srv.WebURL()+"/api/v1/approvals/"+ddlAsync.ApprovalID+"/approve", bytes.NewReader(approveBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", srv.WebURL())
	httpResp, err := http.DefaultClient.Do(req)
	if err != nil || httpResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP approve failed: status=%v err=%v", httpResp, err)
	}
	_ = httpResp.Body.Close()

	// Poll op status until succeeded.
	var finalStatus types.ExecResponse
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		finalStatus, err = svc.GetOperationStatus(ctx, ddlAsync.OperationID)
		if err == nil && finalStatus.Status == types.OpSucceeded {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	if finalStatus.Status != types.OpSucceeded {
		t.Fatalf("expected approved prod DDL to succeed, got %+v", finalStatus)
	}

	// Rejection flow preserves reviewer_note.
	rejAsync, err := svc.Execute(ctx, types.ExecRequest{
		TargetRefOrAlias: prodTgt.Alias,
		Query:            "DELETE FROM items",
		Reason:           "Bad unbounded delete",
		Wait:             false,
	})
	if err != nil || rejAsync.Status != types.OpWaitingApproval {
		t.Fatalf("expected waiting_approval, got %+v err=%v", rejAsync, err)
	}
	rejURL, _ := url.Parse(rejAsync.ApprovalURL)
	rejToken := rejURL.Query().Get("token")
	rejBody, _ := json.Marshal(map[string]string{"reviewer": "dba", "note": "Add WHERE id = ?", "token": rejToken})
	rejReq, _ := http.NewRequest(http.MethodPost, srv.WebURL()+"/api/v1/approvals/"+rejAsync.ApprovalID+"/reject", bytes.NewReader(rejBody))
	rejReq.Header.Set("Content-Type", "application/json")
	rejReq.Header.Set("Origin", "null")
	rejReq.Header.Set("Sec-Fetch-Site", "same-origin")
	rejResp, err := http.DefaultClient.Do(rejReq)
	if err != nil || rejResp.StatusCode != http.StatusOK {
		t.Fatalf("Safari null-origin same-origin reject should succeed, got %v err=%v", rejResp, err)
	}
	_ = rejResp.Body.Close()

	time.Sleep(50 * time.Millisecond)
	rejStatus, err := svc.GetOperationStatus(ctx, rejAsync.OperationID)
	if err != nil || rejStatus.Status != types.OpRejected || rejStatus.ReviewerNote != "Add WHERE id = ?" {
		t.Fatalf("expected rejected with reviewer_note, got %+v err=%v", rejStatus, err)
	}

	// Hardened WebSecurityMiddleware unit tests (Host, Origin/Sec-Fetch-Site, HttpOnly cookie + CSRF header).
	handler := daemon.NewWebHandler(svc)
	cookie, csrf := issueTestWebSession(t, handler)
	for _, tc := range []struct {
		name     string
		host     string
		origin   string
		sfs      string
		useAuth  bool
		badCSRF  bool
		wantCode int
	}{
		{"external_origin_blocked", "127.0.0.1:8080", "https://evil.example", "", true, false, http.StatusForbidden},
		{"non_loopback_host_blocked", "evil.example:8080", "http://127.0.0.1:8080", "", true, false, http.StatusForbidden},
		{"headerless_post_blocked", "127.0.0.1:8080", "", "", true, false, http.StatusForbidden},
		{"null_cross_site_blocked", "127.0.0.1:8080", "null", "cross-site", true, false, http.StatusForbidden},
		{"null_without_sfs_blocked", "127.0.0.1:8080", "null", "", true, false, http.StatusForbidden},
		{"missing_session_cookie_blocked", "127.0.0.1:8080", "http://127.0.0.1:8080", "", false, false, http.StatusForbidden},
		{"invalid_csrf_header_blocked", "127.0.0.1:8080", "http://127.0.0.1:8080", "", true, true, http.StatusForbidden},
		{"null_same_origin_with_session_allowed", "127.0.0.1:8080", "null", "same-origin", true, false, http.StatusOK},
		{"same_origin_with_session_allowed", "127.0.0.1:8080", "http://127.0.0.1:8080", "", true, false, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/api/v1/audit/verify", bytes.NewReader([]byte("{}")))
			r.Host = tc.host
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			if tc.sfs != "" {
				r.Header.Set("Sec-Fetch-Site", tc.sfs)
			}
			if tc.useAuth {
				r.AddCookie(cookie)
				if tc.badCSRF {
					r.Header.Set("X-Agent-DBCTL-CSRF", "wrong-token")
				} else {
					r.Header.Set("X-Agent-DBCTL-CSRF", csrf)
				}
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != tc.wantCode {
				t.Fatalf("got HTTP %d, want %d (body=%s)", w.Code, tc.wantCode, w.Body.String())
			}
		})
	}

	// Audit hash chain remains valid across all operations.
	verify, err := svc.Store().VerifyAuditChain(ctx)
	if err != nil || !verify.Valid {
		t.Fatalf("expected intact audit hash chain, got %+v err=%v", verify, err)
	}

	// Workspace tilde expansion & synchronous CancelOperation status.
	home, err := os.UserHomeDir()
	if err == nil {
		subDir := filepath.Join(home, ".config")
		tildeSys, err := svc.Store().UpsertSystem(ctx, "test", types.System{
			Slug:           "tilde-sys",
			Name:           "Tilde Sys",
			WorkspacePaths: []string{"~/.config"},
		})
		if err != nil {
			t.Fatalf("upsert tilde sys: %v", err)
		}
		_, err = svc.Store().UpsertTarget(ctx, "test", types.Target{
			Ref:             "tilde-sys/dev/main",
			OwnerSystemID:   tildeSys.ID,
			EnvironmentCode: "dev",
			InstanceID:      devInst.ID,
			DatabaseName:    devDB,
		})
		if err != nil {
			t.Fatalf("upsert tilde target: %v", err)
		}
		details, err := svc.BuildTargetDetails(ctx, subDir)
		if err != nil {
			t.Fatalf("build target details: %v", err)
		}
		matched := false
		for _, d := range details {
			if d.Target.Ref == "tilde-sys/dev/main" && d.WorkspaceMatch {
				matched = true
			}
		}
		if !matched {
			t.Fatalf("expected ~/ workspace path to match %s", subDir)
		}
	}

	cancelAsync, err := svc.Execute(ctx, types.ExecRequest{
		TargetRefOrAlias: prodTgt.Alias,
		Query:            "DELETE FROM items WHERE id = 999",
		Reason:           "Test cancel status",
		Wait:             false,
	})
	if err != nil || cancelAsync.Status != types.OpWaitingApproval {
		t.Fatalf("expected waiting_approval, got %+v err=%v", cancelAsync, err)
	}
	cancelled, err := svc.CancelOperation(ctx, cancelAsync.OperationID, "tester")
	if err != nil || cancelled.Status != types.OpCancelled {
		t.Fatalf("expected immediate cancelled status, got %+v err=%v", cancelled, err)
	}
}

func TestTier3ExternalGRPCPluginAndChecksumGuard(t *testing.T) {
	srv, paths := setupIsolatedServer(t)
	svc := srv.Service()
	ctx := context.Background()

	// Build real external plugin binary into isolated plugins/<id>/.
	pluginDir := filepath.Join(paths.PluginsDir, "custom-sqlite")
	if err := os.MkdirAll(pluginDir, 0o700); err != nil {
		t.Fatal(err)
	}
	binName := "agent-dbctl-plugin-sqlite"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	binPath := filepath.Join(pluginDir, binName)
	buildCmd := exec.Command("go", "build", "-o", binPath, "../../cmd/agent-dbctl-plugin-sqlite")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build plugin binary: %v\n%s", err, string(out))
	}

	rawBin, err := os.ReadFile(binPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(rawBin)
	hexSum := hex.EncodeToString(sum[:])

	manifest := fmt.Sprintf(`{
  "id": "custom-sqlite",
  "engine": "sqlite-ext",
  "display_name": "External SQLite Plugin",
  "family": "sql",
  "version": "0.1.0",
  "host_api_version": 1,
  "binary": %q,
  "sha256": %q,
  "capabilities": ["ping", "list_databases", "preflight", "execute_stream"]
}`, binName, hexSum)
	manifestPath := filepath.Join(pluginDir, "manifest.json")
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}

	items, err := svc.Plugins().Reload()
	if err != nil || len(items) != 1 || !items[0].Verified {
		t.Fatalf("expected 1 verified plugin, got %+v err=%v", items, err)
	}

	// Configure target using external engine "sqlite-ext" and execute streaming query!
	extDB := filepath.Join(t.TempDir(), "ext.sqlite")
	sys, _ := svc.Store().UpsertSystem(ctx, "test", types.System{Slug: "extsys", Name: "Ext Sys"})
	inst, _ := svc.Store().UpsertInstance(ctx, "test", types.Instance{Name: "ext-inst", Engine: "sqlite-ext", Host: extDB})
	tgt, _ := svc.Store().UpsertTarget(ctx, "test", types.Target{Ref: "extsys/dev/db", OwnerSystemID: sys.ID, EnvironmentCode: "dev", InstanceID: inst.ID, DatabaseName: extDB})

	if _, err := svc.Execute(ctx, types.ExecRequest{TargetRefOrAlias: tgt.Ref, Query: "CREATE TABLE t(id INT); INSERT INTO t VALUES (10),(20);", Wait: true}); err != nil {
		t.Fatalf("plugin write failed: %v", err)
	}
	res, err := svc.Execute(ctx, types.ExecRequest{TargetRefOrAlias: tgt.Ref, Query: "SELECT id FROM t ORDER BY id", Wait: true})
	if err != nil || res.Status != types.OpSucceeded || res.Result == nil || len(res.Result.Rows) != 2 {
		t.Fatalf("expected 2 streamed rows from gRPC plugin, got %+v err=%v", res, err)
	}

	// Tamper SHA-256 in manifest -> reload must refuse plugin.
	badManifest := strings.ReplaceAll(manifest, hexSum, strings.Repeat("0", 64))
	if err := os.WriteFile(manifestPath, []byte(badManifest), 0o600); err != nil {
		t.Fatal(err)
	}
	itemsBad, err := svc.Plugins().Reload()
	if err != nil || len(itemsBad) != 1 || itemsBad[0].Verified {
		t.Fatalf("expected tampered plugin to fail verification, got %+v err=%v", itemsBad, err)
	}
}

func TestCustomRiskPatternApprovalDenyAndSandboxAPI(t *testing.T) {
	srv, _ := setupIsolatedServer(t)
	svc := srv.Service()
	ctx := context.Background()

	devDB := filepath.Join(t.TempDir(), "pat-dev.sqlite")
	sys, err := svc.Store().UpsertSystem(ctx, "test", types.System{Slug: "ledger", Name: "Ledger"})
	if err != nil {
		t.Fatal(err)
	}
	inst, err := svc.Store().UpsertInstance(ctx, "test", types.Instance{Name: "pat-sqlite", Engine: "sqlite", Host: devDB})
	if err != nil {
		t.Fatal(err)
	}
	tgt, err := svc.Store().UpsertTarget(ctx, "test", types.Target{
		Ref:             "ledger/dev/main",
		Alias:           "dev-ledger",
		OwnerSystemID:   sys.ID,
		EnvironmentCode: "dev",
		InstanceID:      inst.ID,
		DatabaseName:    devDB,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Seed table in dev/yolo before installing table-scoped confirmation rule.
	if _, err := svc.Execute(ctx, types.ExecRequest{
		TargetRefOrAlias: tgt.Ref,
		Query:            "CREATE TABLE secret_ledger(id INTEGER PRIMARY KEY, amount INTEGER); INSERT INTO secret_ledger VALUES (1, 999);",
		Wait:             true,
	}); err != nil {
		t.Fatalf("seed sqlite table: %v", err)
	}

	handler := daemon.NewWebHandler(svc)
	cookie, csrf := issueTestWebSession(t, handler)
	// Install builtin sqlite-pragma-blob pack via HTTP API.
	packBody := bytes.NewBufferString(`{"scope_type":"global","scope_id":"global"}`)
	packReq := newAuthedWebPOST("/api/v1/risk-patterns/packs/sqlite-pragma-blob/install", packBody, cookie, csrf)
	packRec := httptest.NewRecorder()
	handler.ServeHTTP(packRec, packReq)
	if packRec.Code != http.StatusOK {
		t.Fatalf("install pack HTTP %d: %s", packRec.Code, packRec.Body.String())
	}

	// Add custom require_approval rule on secret_ledger AND custom deny rule on zeroblob(999999999).
	rulePayload, _ := json.Marshal(types.RiskPatternRule{
		Name:           "confirm-secret-ledger",
		ScopeType:      "target",
		ScopeID:        tgt.ID,
		Enabled:        true,
		Engines:        []string{"sqlite"},
		Action:         types.PatternActionRequireApproval,
		ConfirmTitle:   "Sensitive Ledger Access",
		ConfirmMessage: "Reading secret_ledger requires secondary confirmation even in dev.",
		Condition:      types.PatternCondition{Type: types.MatcherTableRef, Values: []string{"secret_ledger"}},
		Priority:       100,
	})
	saveReq := newAuthedWebPOST("/api/v1/risk-patterns", bytes.NewReader(rulePayload), cookie, csrf)
	saveRec := httptest.NewRecorder()
	handler.ServeHTTP(saveRec, saveReq)
	if saveRec.Code != http.StatusOK {
		t.Fatalf("save pattern HTTP %d: %s", saveRec.Code, saveRec.Body.String())
	}

	// Sandbox test endpoint with inline draft deny rule.
	testPayload, _ := json.Marshal(types.PatternTestRequest{
		TargetID: tgt.Ref,
		Query:    "SELECT id, amount FROM secret_ledger WHERE id = 1 LIMIT 1",
	})
	testReq := newAuthedWebPOST("/api/v1/risk-patterns/test", bytes.NewReader(testPayload), cookie, csrf)
	testRec := httptest.NewRecorder()
	handler.ServeHTTP(testRec, testReq)
	if testRec.Code != http.StatusOK {
		t.Fatalf("test pattern HTTP %d: %s", testRec.Code, testRec.Body.String())
	}
	var testRes types.PatternTestResult
	if err := json.Unmarshal(testRec.Body.Bytes(), &testRes); err != nil {
		t.Fatal(err)
	}
	if testRes.Evaluation.Decision != types.DecisionRequireApproval || len(testRes.MatchedRules) != 1 || testRes.MatchedRules[0].MatchedFragment != "secret_ledger" {
		t.Fatalf("unexpected sandbox test result: %+v", testRes)
	}

	// Real execution on dev/yolo target must pause for human approval with matched_rules attached.
	asyncResp, err := svc.Execute(ctx, types.ExecRequest{
		TargetRefOrAlias: tgt.Alias,
		Query:            "SELECT id, amount FROM secret_ledger WHERE id = 1 LIMIT 1",
		Reason:           "Inspect ledger row",
		Wait:             false,
	})
	if err != nil {
		t.Fatalf("execute async: %v", err)
	}
	if asyncResp.Status != types.OpWaitingApproval || len(asyncResp.Evaluation.MatchedRules) != 1 {
		t.Fatalf("expected waiting_approval with 1 matched rule, got %+v", asyncResp)
	}
	app, _, err := svc.Store().GetApproval(ctx, asyncResp.ApprovalID)
	if err != nil || len(app.MatchedRules) != 1 || app.MatchedRules[0].ConfirmTitle != "Sensitive Ledger Access" {
		t.Fatalf("expected persisted approval MatchedRules, got %+v err=%v", app, err)
	}

	// Approve via hardened Web API (session cookie + CSRF) -> query runs and returns row!
	aprReq := newAuthedWebPOST("/api/v1/approvals/"+asyncResp.ApprovalID+"/approve", bytes.NewBufferString(`{"reviewer":"owner","note":"confirmed"}`), cookie, csrf)
	aprRec := httptest.NewRecorder()
	handler.ServeHTTP(aprRec, aprReq)
	if aprRec.Code != http.StatusOK {
		t.Fatalf("approve HTTP %d: %s", aprRec.Code, aprRec.Body.String())
	}

	deadline := time.Now().Add(3 * time.Second)
	var finalResp types.ExecResponse
	for time.Now().Before(deadline) {
		finalResp, err = svc.GetOperationStatus(ctx, asyncResp.OperationID)
		if err == nil && finalResp.Status == types.OpSucceeded {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if finalResp.Status != types.OpSucceeded || finalResp.Result == nil || len(finalResp.Result.Rows) != 1 {
		t.Fatalf("expected succeeded execution after confirmation, got %+v", finalResp)
	}

	// Custom deny rule blocks immediately without approval ticket.
	_, err = svc.Store().UpsertRiskPatternRule(ctx, "web-admin", types.RiskPatternRule{
		Name:           "deny-big-blob",
		ScopeType:      "global",
		ScopeID:        "global",
		Enabled:        true,
		Engines:        []string{"sqlite"},
		Action:         types.PatternActionDeny,
		ConfirmTitle:   "Large Blob Blocked",
		ConfirmMessage: "randomblob exceeds policy.",
		Condition:      types.PatternCondition{Type: types.MatcherFunctionCall, Values: []string{"randomblob"}},
		Priority:       100,
	})
	if err != nil {
		t.Fatal(err)
	}
	denyResp, err := svc.Execute(ctx, types.ExecRequest{
		TargetRefOrAlias: tgt.Alias,
		Query:            "SELECT randomblob(1000000)",
		Wait:             false,
	})
	if err != nil || denyResp.Status != types.OpDenied || denyResp.ErrorCode != types.ErrCodePolicyDenied {
		t.Fatalf("expected custom pattern deny, got %+v err=%v", denyResp, err)
	}

	// Schema introspection + audit event recording.
	if _, err := svc.Execute(ctx, types.ExecRequest{
		TargetRefOrAlias: tgt.Alias,
		Query:            "CREATE TABLE audit_demo(id INTEGER PRIMARY KEY, label TEXT)",
		Wait:             true,
	}); err != nil {
		t.Fatalf("create audit_demo: %v", err)
	}
	schemaListAny, err := svc.InspectSchema(ctx, tgt.Alias, "", "", "", 50)
	if err != nil {
		t.Fatalf("InspectSchema list: %v", err)
	}
	schemaList := schemaListAny.(*types.SchemaListResult)
	if schemaList.TargetRef != tgt.Ref || len(schemaList.Items) < 2 {
		t.Fatalf("unexpected InspectSchema list result: %+v", schemaList)
	}
	tblAny, err := svc.InspectSchema(ctx, tgt.Alias, "", "audit_demo", "", 0)
	if err != nil {
		t.Fatalf("InspectSchema describe: %v", err)
	}
	tbl := tblAny.(*types.TableSchema)
	if tbl.Name != "audit_demo" || len(tbl.Columns) != 2 {
		t.Fatalf("unexpected InspectSchema table result: %+v", tbl)
	}

	entries, _, err := svc.Store().ListAuditEntriesFiltered(ctx, store.AuditFilter{Action: "schema.", Limit: 10})
	if err != nil || len(entries) < 2 {
		t.Fatalf("expected schema.list & schema.describe audit entries, got %+v err=%v", entries, err)
	}
}

func TestReplicaNetworkIsolationAndCapabilitiesPersistence(t *testing.T) {
	t.Setenv("AGENT_DBCTL_WEBHOOK_URL", "https://127.0.0.1:9443/approve")
	srv, _ := setupIsolatedServer(t)
	svc := srv.Service()
	svc.RegisterWebhookProviderFromEnv()
	ctx := context.Background()

	// 1. DisplayCatalog dynamically includes registered webhook approval provider.
	cat, err := svc.BuildDisplayCatalog(ctx)
	if err != nil {
		t.Fatal(err)
	}
	foundWebhook := false
	for _, ap := range cat.ApprovalProviders {
		if ap.Code == "webhook" {
			foundWebhook = true
		}
	}
	if !foundWebhook {
		t.Fatalf("expected webhook in DisplayCatalog.ApprovalProviders, got %+v", cat.ApprovalProviders)
	}

	// 2. PingTarget persists Dialect and ServerCapabilities on the SQLite instance.
	dbPath := filepath.Join(t.TempDir(), "caps.sqlite")
	sys, err := svc.Store().UpsertSystem(ctx, "test", types.System{Slug: "caps-sys", Name: "Caps Sys"})
	if err != nil {
		t.Fatal(err)
	}
	sqliteInst, err := svc.Store().UpsertInstance(ctx, "test", types.Instance{
		Name: "sqlite-caps", Engine: "sqlite", Host: dbPath, Role: types.RoleStandalone,
	})
	if err != nil {
		t.Fatal(err)
	}
	sqliteTgt, err := svc.Store().UpsertTarget(ctx, "test", types.Target{
		Ref: "caps-sys/dev/sqlite", OwnerSystemID: sys.ID, EnvironmentCode: "dev", InstanceID: sqliteInst.ID, DatabaseName: dbPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Execute(ctx, types.ExecRequest{
		TargetRefOrAlias: sqliteTgt.Ref, Query: "CREATE TABLE t(id INTEGER)", Wait: true,
	}); err != nil {
		t.Fatal(err)
	}
	det, err := svc.ResolveTarget(ctx, sqliteTgt.Ref, "")
	if err != nil {
		t.Fatal(err)
	}
	ping := svc.PingTarget(ctx, det)
	if !ping.Reachable || ping.Dialect != "sqlite" || ping.Capabilities == nil {
		t.Fatalf("expected reachable SQLite ping with dialect & capabilities, got %+v", ping)
	}
	storedInst, err := svc.Store().GetInstance(ctx, sqliteInst.ID)
	if err != nil || storedInst.Capabilities == nil || storedInst.Capabilities.Dialect != "sqlite" {
		t.Fatalf("expected persisted capabilities on instance, got %+v err=%v", storedInst.Capabilities, err)
	}

	// 3. Replica routing must resolve the replica's own NetworkProfile rather than primary's direct profile.
	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = socksLn.Close() }()
	var replicaProxyDialed atomic.Int32
	go func() {
		for {
			c, acceptErr := socksLn.Accept()
			if acceptErr != nil {
				return
			}
			replicaProxyDialed.Add(1)
			_ = c.Close()
		}
	}()

	replicaNet, err := svc.Store().UpsertNetworkProfile(ctx, "test", types.NetworkProfile{
		Name: "replica-socks", Mode: types.NetworkSOCKS5, ProxyURL: "socks5://" + socksLn.Addr().String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	pgPrimary, err := svc.Store().UpsertInstance(ctx, "test", types.Instance{
		Name: "pg-primary-direct", Engine: "postgres", Host: "127.0.0.1", Port: 1, Role: types.RolePrimary,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Store().UpsertInstance(ctx, "test", types.Instance{
		Name: "pg-replica-socks", Engine: "postgres", Host: "127.0.0.1", Port: 5432, Role: types.RoleReplica,
		PrimaryInstanceID: pgPrimary.ID, NetworkProfileID: replicaNet.ID,
	}); err != nil {
		t.Fatal(err)
	}
	pgTgt, err := svc.Store().UpsertTarget(ctx, "test", types.Target{
		Ref: "caps-sys/dev/pg", OwnerSystemID: sys.ID, EnvironmentCode: "dev", InstanceID: pgPrimary.ID, DatabaseName: "app",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = svc.Execute(ctx, types.ExecRequest{
		TargetRefOrAlias: pgTgt.Ref,
		Query:            "SELECT 1",
		Preflight:        true,
	})
	if replicaProxyDialed.Load() == 0 {
		t.Fatalf("expected read-only replica routing to dial replica's SOCKS5 NetworkProfile")
	}
}

func TestNewBuiltinEnginesCatalogAndOpenSearchE2E(t *testing.T) {
	srv, _ := setupIsolatedServer(t)
	svc := srv.Service()
	ctx := context.Background()

	cat, err := svc.BuildDisplayCatalog(ctx)
	if err != nil {
		t.Fatal(err)
	}
	seenEngines := map[string]bool{}
	for _, item := range cat.Engines {
		seenEngines[item.Code] = true
	}
	for _, want := range []string{"postgres", "opengauss", "kingbase", "dameng", "tdengine", "mysql", "sqlite", "mongodb", "redis", "clickhouse", "mssql", "oracle", "elasticsearch"} {
		if !seenEngines[want] {
			t.Fatalf("DisplayCatalog missing built-in engine %q (got %+v)", want, cat.Engines)
		}
	}

	// Mock OpenSearch HTTP endpoint exercising opensearch alias -> elasticsearch driver end-to-end.
	var writeCount atomic.Int32
	esMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"version": map[string]any{"distribution": "opensearch", "number": "2.17.0"},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/_cat/indices":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"index": "logs", "docs.count": "500"},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/logs/_mapping":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"logs": map[string]any{
					"mappings": map[string]any{
						"properties": map[string]any{
							"level": map[string]any{"type": "keyword"},
						},
					},
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/logs/_validate/query":
			_ = json.NewEncoder(w).Encode(map[string]any{"valid": true})
		case r.Method == http.MethodPost && r.URL.Path == "/logs/_count":
			_ = json.NewEncoder(w).Encode(map[string]any{"count": 500})
		case r.Method == http.MethodPost && r.URL.Path == "/logs/_search":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"hits": map[string]any{
					"hits": []map[string]any{
						{"_id": "doc1", "_source": map[string]any{"level": "error"}},
					},
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/logs/_doc":
			writeCount.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"_id": "doc2", "result": "created"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer esMock.Close()

	u, err := url.Parse(esMock.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, portStr, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portStr)

	sys, err := svc.Store().UpsertSystem(ctx, "test", types.System{Slug: "search-core", Name: "Search Core"})
	if err != nil {
		t.Fatal(err)
	}
	inst, err := svc.Store().UpsertInstance(ctx, "test", types.Instance{
		Name:   "os-prod",
		Engine: "opensearch", // alias resolved via Registry.Get -> elasticsearch
		Host:   host,
		Port:   port,
		Role:   types.RoleStandalone,
	})
	if err != nil {
		t.Fatal(err)
	}
	prodTgt, err := svc.Store().UpsertTarget(ctx, "test", types.Target{
		Ref:             "search-core/prod/logs",
		Alias:           "prod-logs",
		OwnerSystemID:   sys.ID,
		EnvironmentCode: "prod",
		InstanceID:      inst.ID,
		DatabaseName:    "logs",
	})
	if err != nil {
		t.Fatal(err)
	}

	det, err := svc.ResolveTarget(ctx, prodTgt.Ref, "")
	if err != nil {
		t.Fatal(err)
	}
	ping := svc.PingTarget(ctx, det)
	if !ping.Reachable || ping.Dialect != "opensearch" {
		t.Fatalf("expected reachable opensearch ping, got %+v", ping)
	}

	schemaAny, err := svc.InspectSchema(ctx, prodTgt.Alias, "", "logs", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	tbl := schemaAny.(*types.TableSchema)
	if tbl.Dialect != "opensearch" || len(tbl.Columns) != 1 || tbl.Columns[0].Name != "level" {
		t.Fatalf("unexpected OpenSearch schema inspection: %+v", tbl)
	}

	// Bounded search executes immediately on prod
	readRes, err := svc.Execute(ctx, types.ExecRequest{
		TargetRefOrAlias: prodTgt.Alias,
		Query:            `{"index":"logs","query":{"term":{"level":"error"}},"size":10}`,
		Wait:             true,
	})
	if err != nil || readRes.Status != types.OpSucceeded || len(readRes.Result.Documents) != 1 {
		t.Fatalf("expected bounded OpenSearch read to succeed, got %+v err=%v", readRes, err)
	}

	// Unbounded match_all escalates via preflight to waiting_approval
	pfRes, err := svc.Execute(ctx, types.ExecRequest{
		TargetRefOrAlias: prodTgt.Alias,
		Query:            `{"index":"logs","query":{"match_all":{}}}`,
		Preflight:        true,
	})
	if err != nil || pfRes.Preflight == nil || !pfRes.Preflight.FullScan || pfRes.Evaluation.Decision != types.DecisionRequireApproval {
		t.Fatalf("expected match_all preflight escalation, got %+v err=%v", pfRes, err)
	}

	// Write in prod requires approval -> approve -> executes
	wAsync, err := svc.Execute(ctx, types.ExecRequest{
		TargetRefOrAlias: prodTgt.Alias,
		Query:            "POST /logs/_doc\n{\"level\":\"info\"}",
		Reason:           "Insert probe log",
		Wait:             false,
	})
	if err != nil || wAsync.Status != types.OpWaitingApproval {
		t.Fatalf("expected waiting_approval for ES write, got %+v err=%v", wAsync, err)
	}
	_, err = svc.ResolveApproval(ctx, wAsync.ApprovalID, true, "reviewer", "ok", "", true)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	var finalResp types.ExecResponse
	for time.Now().Before(deadline) {
		finalResp, err = svc.GetOperationStatus(ctx, wAsync.OperationID)
		if err == nil && finalResp.Status == types.OpSucceeded {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if finalResp.Status != types.OpSucceeded || writeCount.Load() != 1 {
		t.Fatalf("expected approved ES write to succeed, got %+v writes=%d", finalResp, writeCount.Load())
	}
}

func TestParseAndRedactDSNAllNineEngines(t *testing.T) {
	cases := []struct {
		name       string
		dsn        string
		hintEngine string
		wantEngine string
		wantHost   string
		wantPort   int
		wantDB     string
		wantUser   string
		wantPass   bool
		wantTLS    string
	}{
		{
			name:       "postgres_url",
			dsn:        "postgres://alice:s3cr3t@127.0.0.1:5432/orders?sslmode=require",
			wantEngine: "postgres", wantHost: "127.0.0.1", wantPort: 5432, wantDB: "orders", wantUser: "alice", wantPass: true, wantTLS: "require",
		},
		{
			name:       "mysql_url",
			dsn:        "mysql://bob@127.0.0.1:3307/billing",
			wantEngine: "mysql", wantHost: "127.0.0.1", wantPort: 3307, wantDB: "billing", wantUser: "bob",
		},
		{
			name:       "mysql_go_dsn",
			dsn:        "bob:pw123@tcp(127.0.0.1:3306)/billing?tls=true",
			wantEngine: "mysql", wantHost: "127.0.0.1", wantPort: 3306, wantDB: "billing", wantUser: "bob", wantPass: true, wantTLS: "require",
		},
		{
			name:       "sqlite_file",
			dsn:        "sqlite:///tmp/local.db",
			wantEngine: "sqlite", wantHost: "/tmp/local.db", wantPort: 0, wantDB: "/tmp/local.db",
		},
		{
			name:       "sqlite_memory",
			dsn:        ":memory:",
			wantEngine: "sqlite", wantHost: ":memory:", wantPort: 0, wantDB: ":memory:",
		},
		{
			name:       "mongodb",
			dsn:        "mongodb://reader:pw@127.0.0.1:27017/events?authSource=admin",
			wantEngine: "mongodb", wantHost: "127.0.0.1", wantPort: 27017, wantDB: "events", wantUser: "reader", wantPass: true,
		},
		{
			name:       "rediss",
			dsn:        "rediss://default:tok@127.0.0.1:6380/2",
			wantEngine: "redis", wantHost: "127.0.0.1", wantPort: 6380, wantDB: "2", wantUser: "default", wantPass: true, wantTLS: "require",
		},
		{
			name:       "clickhouse",
			dsn:        "clickhouse://ch_ro:pw@127.0.0.1:9000/analytics",
			wantEngine: "clickhouse", wantHost: "127.0.0.1", wantPort: 9000, wantDB: "analytics", wantUser: "ch_ro", wantPass: true,
		},
		{
			name:       "mssql",
			dsn:        "sqlserver://sa:pw@127.0.0.1:1433?database=sales&encrypt=true",
			wantEngine: "mssql", wantHost: "127.0.0.1", wantPort: 1433, wantDB: "sales", wantUser: "sa", wantPass: true, wantTLS: "require",
		},
		{
			name:       "oracle",
			dsn:        "oracle://hr:pw@127.0.0.1:1521/ORCLPDB1",
			wantEngine: "oracle", wantHost: "127.0.0.1", wantPort: 1521, wantDB: "ORCLPDB1", wantUser: "hr", wantPass: true,
		},
		{
			name:       "elasticsearch_https",
			dsn:        "https://elastic:pw@127.0.0.1:9200/logs",
			hintEngine: "elasticsearch",
			wantEngine: "elasticsearch", wantHost: "127.0.0.1", wantPort: 9200, wantDB: "logs", wantUser: "elastic", wantPass: true, wantTLS: "require",
		},
		{
			name:       "dameng_dm8",
			dsn:        "dm8://SYSDBA:pw@127.0.0.1:5236/ORDERS",
			wantEngine: "dm8", wantHost: "127.0.0.1", wantPort: 5236, wantDB: "ORDERS", wantUser: "SYSDBA", wantPass: true,
		},
		{
			name:       "kingbase_default_port",
			dsn:        "kingbase://system:pw@127.0.0.1/app",
			wantEngine: "kingbase", wantHost: "127.0.0.1", wantPort: 54321, wantDB: "app", wantUser: "system", wantPass: true,
		},
		{
			name:       "opengauss_default_port",
			dsn:        "opengauss://gaussdb:pw@127.0.0.1/finance",
			wantEngine: "opengauss", wantHost: "127.0.0.1", wantPort: 5432, wantDB: "finance", wantUser: "gaussdb", wantPass: true,
		},
		{
			name:       "gaussdb_dws_default_port",
			dsn:        "gaussdb_dws://dbadmin:pw@127.0.0.1/dw",
			wantEngine: "gaussdb_dws", wantHost: "127.0.0.1", wantPort: 8000, wantDB: "dw", wantUser: "dbadmin", wantPass: true,
		},
		{
			name:       "tidb_default_port",
			dsn:        "tidb://root:pw@127.0.0.1/shop",
			wantEngine: "tidb", wantHost: "127.0.0.1", wantPort: 4000, wantDB: "shop", wantUser: "root", wantPass: true,
		},
		{
			name:       "oceanbase_default_port",
			dsn:        "oceanbase://root@127.0.0.1/ob",
			wantEngine: "oceanbase", wantHost: "127.0.0.1", wantPort: 2883, wantDB: "ob", wantUser: "root",
		},
		{
			name:       "gbase8a_default_port",
			dsn:        "gbase8a://gbasedbt:pw@127.0.0.1/bi",
			wantEngine: "gbase8a", wantHost: "127.0.0.1", wantPort: 5258, wantDB: "bi", wantUser: "gbasedbt", wantPass: true,
		},
		{
			name:       "tdengine_default_port",
			dsn:        "tdengine://root:pw@127.0.0.1/power",
			wantEngine: "tdengine", wantHost: "127.0.0.1", wantPort: 6041, wantDB: "power", wantUser: "root", wantPass: true,
		},
		{
			name:       "easysearch_https",
			dsn:        "https://admin:pw@127.0.0.1:9200/logs",
			hintEngine: "easysearch",
			wantEngine: "easysearch", wantHost: "127.0.0.1", wantPort: 9200, wantDB: "logs", wantUser: "admin", wantPass: true, wantTLS: "require",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := daemon.ParseDSN(tc.dsn, tc.hintEngine)
			if err != nil {
				t.Fatalf("ParseDSN(%q) err=%v", tc.dsn, err)
			}
			if got.Engine != tc.wantEngine || got.Host != tc.wantHost || got.Port != tc.wantPort ||
				got.DatabaseName != tc.wantDB || got.Username != tc.wantUser || got.HasPassword != tc.wantPass {
				t.Fatalf("ParseDSN(%q) = %+v, want engine=%s host=%s port=%d db=%s user=%s pass=%v",
					tc.dsn, got, tc.wantEngine, tc.wantHost, tc.wantPort, tc.wantDB, tc.wantUser, tc.wantPass)
			}
			if tc.wantTLS != "" && got.TLSMode != tc.wantTLS {
				t.Fatalf("expected tls_mode=%q, got %q", tc.wantTLS, got.TLSMode)
			}
			if tc.wantPass {
				redacted := daemon.RedactDSN(tc.dsn)
				if strings.Contains(redacted, "s3cr3t") || strings.Contains(redacted, "pw123") || strings.Contains(redacted, ":pw@") || strings.Contains(redacted, ":tok@") {
					t.Fatalf("RedactDSN leaked secret in %q -> %q", tc.dsn, redacted)
				}
			}
		})
	}
}

func TestRPCDisallowsApprovalResolutionRoutes(t *testing.T) {
	_, paths := setupIsolatedServer(t)
	cl, err := daemon.NewClient(paths)
	if err != nil {
		t.Fatalf("new RPC client: %v", err)
	}
	err = cl.DoJSON(context.Background(), http.MethodPost, "/rpc/v1/approvals/apr_test/approve", map[string]string{"reviewer": "bot"}, nil)
	if err == nil {
		t.Fatalf("expected RPC approval route to be rejected, but succeeded")
	}
}

func TestSystemGitRemoteMatchingPriorityAndDBAddConvergence(t *testing.T) {
	srv, _ := setupIsolatedServer(t)
	svc := srv.Service()
	ctx := context.Background()

	// Create two systems: one bound via workspace_paths + git_remotes, another bound only via git_remotes (same monorepo), plus an unrelated system.
	sysRepo, err := svc.Store().UpsertSystem(ctx, "test", types.System{
		Slug:           "orders-api",
		Name:           "Orders API",
		WorkspacePaths: []string{"/repos/mono/orders-api"},
		GitRemotes:     []string{"git@github.com:acme/mono.git"},
	})
	if err != nil {
		t.Fatal(err)
	}
	sysSub, err := svc.Store().UpsertSystem(ctx, "test", types.System{
		Slug:       "billing-api",
		Name:       "Billing API",
		GitRemotes: []string{"https://github.com/acme/mono.git"},
	})
	if err != nil {
		t.Fatal(err)
	}
	sysOther, err := svc.Store().UpsertSystem(ctx, "test", types.System{
		Slug:       "analytics",
		Name:       "Analytics",
		GitRemotes: []string{"github.com/acme/analytics"},
	})
	if err != nil {
		t.Fatal(err)
	}

	inst, err := svc.Store().UpsertInstance(ctx, "test", types.Instance{
		Name:   "shared-sqlite",
		Engine: "sqlite",
		Host:   filepath.Join(t.TempDir(), "shared.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		ref string
		sys string
	}{
		{"orders-api/dev/db", sysRepo.ID},
		{"billing-api/dev/db", sysSub.ID},
		{"analytics/dev/db", sysOther.ID},
	} {
		if _, err := svc.Store().UpsertTarget(ctx, "test", types.Target{
			Ref: item.ref, OwnerSystemID: item.sys, EnvironmentCode: "dev", InstanceID: inst.ID, DatabaseName: inst.Host,
		}); err != nil {
			t.Fatal(err)
		}
	}

	// From a git worktree outside /repos/mono/orders-api, both mono systems match via git_remotes.
	details, _, _, err := svc.ListTargetsFiltered(ctx, daemon.ListFilter{
		WorkspaceCWD:        "/tmp/wt-123",
		WorkspaceGitRemotes: []string{"https://oauth2:tok@github.com/acme/mono.git"},
	})
	if err != nil || len(details) != 3 {
		t.Fatalf("ListTargetsFiltered failed: len=%d err=%v", len(details), err)
	}
	if !details[0].WorkspaceMatch || !details[1].WorkspaceMatch || details[2].WorkspaceMatch {
		t.Fatalf("expected first two targets to match via git_remotes and analytics not to match: %+v", details)
	}

	// Inside /repos/mono/orders-api/sub, local workspace_paths match ranks strictly ahead of git_remotes-only match.
	details, _, _, err = svc.ListTargetsFiltered(ctx, daemon.ListFilter{
		WorkspaceCWD:        "/repos/mono/orders-api/sub",
		WorkspaceGitRemotes: []string{"git@github.com:acme/mono.git"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if details[0].Target.Ref != "orders-api/dev/db" {
		t.Fatalf("expected workspace_paths match orders-api/dev/db first, got %s", details[0].Target.Ref)
	}

	// db add without --system from a worktree matches unique existing git_remote system and merges workspace_path.
	addResp, err := svc.AdminAddDatabase(ctx, "agent-cli", daemon.DBAddRequest{
		Engine:              "sqlite",
		Host:                filepath.Join(t.TempDir(), "ana.db"),
		WorkspaceCWD:        "/tmp/wt-analytics-fix",
		WorkspaceGitRemotes: []string{"git@github.com:acme/analytics.git"},
		Env:                 "dev",
	})
	if err != nil {
		t.Fatalf("AdminAddDatabase from worktree failed: %v", err)
	}
	if addResp.Target.System != "analytics" || addResp.Actions["system"] != "updated" {
		t.Fatalf("expected db add to reuse analytics system and merge worktree path, got target=%+v actions=%+v", addResp.Target, addResp.Actions)
	}

	// db add without --system in a brand-new git repo derives slug from git repo name rather than worktree folder name.
	newResp, err := svc.AdminAddDatabase(ctx, "agent-cli", daemon.DBAddRequest{
		Engine:              "sqlite",
		Host:                filepath.Join(t.TempDir(), "pay.db"),
		WorkspaceCWD:        "/tmp/wt-999",
		WorkspaceGitRemotes: []string{"ssh://git@github.com/acme/payment-gateway.git"},
		Env:                 "dev",
	})
	if err != nil {
		t.Fatalf("AdminAddDatabase new git repo failed: %v", err)
	}
	if newResp.Target.System != "payment-gateway" {
		t.Fatalf("expected repo-derived slug payment-gateway, got %q", newResp.Target.System)
	}
	gotPaySys, err := svc.Store().ResolveSystem(ctx, "payment-gateway")
	if err != nil || !reflect.DeepEqual(gotPaySys.GitRemotes, []string{"github.com/acme/payment-gateway"}) {
		t.Fatalf("expected normalized git_remote persisted on payment-gateway, got %+v err=%v", gotPaySys, err)
	}
}

func TestTDengineFullApprovalAndAuditLifecycleE2E(t *testing.T) {
	var insertCalls atomic.Int32
	tdSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		sqlText := strings.TrimSpace(string(bodyBytes))
		upper := strings.ToUpper(sqlText)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case upper == "SELECT SERVER_VERSION()":
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 0, "column_meta": [][]any{{"server_version()", "VARCHAR", 16}}, "data": [][]any{{"3.3.2.0"}}, "rows": 1})
		case upper == "SHOW DATABASES":
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 0, "column_meta": [][]any{{"name", "VARCHAR", 64}}, "data": [][]any{{"power"}}, "rows": 1})
		case upper == "SHOW STABLES":
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 0, "column_meta": [][]any{{"stable_name", "VARCHAR", 64}}, "data": [][]any{{"meters"}}, "rows": 1})
		case upper == "SHOW TABLES":
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 0, "column_meta": [][]any{{"table_name", "VARCHAR", 64}}, "data": [][]any{{"d1001"}}, "rows": 1})
		case strings.HasPrefix(upper, "DESCRIBE "):
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 0, "column_meta": [][]any{{"field", "VARCHAR", 64}, {"type", "VARCHAR", 16}, {"length", "INT", 4}, {"note", "VARCHAR", 8}}, "data": [][]any{{"ts", "TIMESTAMP", 8, ""}, {"current", "FLOAT", 4, ""}}, "rows": 2})
		case strings.HasPrefix(upper, "EXPLAIN "):
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 0, "column_meta": [][]any{{"plan", "VARCHAR", 128}}, "data": [][]any{{"FULL TABLE SCAN on meters"}}, "rows": 1})
		case strings.HasPrefix(upper, "SELECT "):
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 0, "column_meta": [][]any{{"ts", "TIMESTAMP", 8}, {"current", "FLOAT", 4}}, "data": [][]any{{"2026-11-25T10:00:00Z", 12.5}}, "rows": 1})
		case strings.HasPrefix(upper, "INSERT "):
			insertCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 0, "column_meta": [][]any{}, "data": [][]any{}, "rows": 1})
		default:
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 9728, "desc": "unexpected SQL"})
		}
	}))
	defer tdSrv.Close()

	u, _ := url.Parse(tdSrv.URL)
	host, portStr, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portStr)

	srv, _ := setupIsolatedServer(t)
	svc := srv.Service()
	ctx := context.Background()

	addRes, err := svc.AdminAddDatabase(ctx, "qa", daemon.DBAddRequest{
		Engine:         "tdengine",
		Host:           host,
		Port:           port,
		Database:       "power",
		System:         "grid-telemetry",
		Env:            "prod",
		Alias:          "prod-tsdb",
		AccessLevel:    types.AccessReadWrite,
		User:           "root",
		SecretValue:    "taosdata",
		SecretProvided: true,
	})
	if err != nil {
		t.Fatalf("AdminAddDatabase tdengine: %v", err)
	}

	det, err := svc.ResolveTarget(ctx, addRes.Target.Ref, "")
	if err != nil {
		t.Fatalf("ResolveTarget: %v", err)
	}
	if ping := svc.PingTarget(ctx, det); !ping.Reachable || ping.Dialect != "tdengine" {
		t.Fatalf("PingTarget = %+v", ping)
	}
	schemaRes, err := svc.InspectSchema(ctx, "prod-tsdb", "", "meters", "", 0)
	ts, ok := schemaRes.(*types.TableSchema)
	if err != nil || !ok || len(ts.Columns) != 2 {
		t.Fatalf("InspectSchema = (%+v, %v)", schemaRes, err)
	}

	// Read with preflight surfaces FullScan escalation on prod strict environment.
	pfRes, err := svc.Execute(ctx, types.ExecRequest{
		TargetRefOrAlias: "prod-tsdb",
		Query:            "SELECT ts, current FROM meters LIMIT 1",
		Preflight:        true,
	})
	if err != nil || pfRes.Preflight == nil || !pfRes.Preflight.FullScan || pfRes.Evaluation.Decision != types.DecisionRequireApproval {
		t.Fatalf("expected TDengine preflight full scan escalation, got %+v err=%v", pfRes, err)
	}

	// Write triggers approval queue -> HTTP approve -> executes against mock TDengine -> valid hash-chain audit.
	wrRes, err := svc.Execute(ctx, types.ExecRequest{
		TargetRefOrAlias: "prod-tsdb",
		Query:            "INSERT INTO d1001 VALUES (NOW, 12.5)",
		Reason:           "Seed telemetry sample",
		Wait:             false,
	})
	if err != nil || wrRes.Status != types.OpWaitingApproval {
		t.Fatalf("expected waiting_approval, got %+v err=%v", wrRes, err)
	}
	approvePendingHTTP(t, srv.WebURL(), wrRes.ApprovalID, wrRes.ApprovalURL, "approved telemetry insert")
	done := waitOpTerminal(t, ctx, svc, wrRes.OperationID)
	if done.Status != types.OpSucceeded || insertCalls.Load() != 1 {
		t.Fatalf("expected approved TDengine insert to succeed, status=%s inserts=%d err=%s", done.Status, insertCalls.Load(), done.ErrorMessage)
	}
	verify, err := svc.Store().VerifyAuditChain(ctx)
	if err != nil || !verify.Valid {
		t.Fatalf("VerifyAuditChain failed: %+v err=%v", verify, err)
	}
}

func TestOnboardingDefaultsInlineEnvAndScanReadMode(t *testing.T) {
	srv, _ := setupIsolatedServer(t)
	svc := srv.Service()
	ctx := context.Background()

	// 1. Unknown --env without --safety-tier returns structured TargetLookupError with actionable NextCommands.
	_, err := svc.AdminAddDatabase(ctx, "qa", daemon.DBAddRequest{
		Engine: "sqlite",
		Host:   filepath.Join(t.TempDir(), "missing-env.db"),
		System: "friction-sys",
		Env:    "uat",
	})
	le, ok := err.(*daemon.TargetLookupError)
	if !ok || le.Code != types.ErrCodeNotFound || le.Hint == "" || len(le.NextCommands) == 0 {
		t.Fatalf("expected structured TargetLookupError for missing env, got %T (%v)", err, err)
	}

	// 2. Inline --safety-tier creates new environment in --dry-run (without persisting) and real execution.
	uatDBPath := filepath.Join(t.TempDir(), "uat.db")
	dryPlan, err := svc.AdminAddDatabase(ctx, "qa", daemon.DBAddRequest{
		Engine:       "sqlite",
		Host:         uatDBPath,
		System:       "friction-sys",
		Env:          "uat",
		SafetyTier:   types.SafetyTierStrict,
		ScanReadMode: types.ScanReadReasonOnly,
		DryRun:       true,
	})
	if err != nil {
		t.Fatalf("AdminAddDatabase inline env dry-run: %v", err)
	}
	if dryPlan.Actions["environment"] != "created" || dryPlan.Actions["policy"] != "created" ||
		dryPlan.Target.SafetyTier != types.SafetyTierStrict || dryPlan.Target.ScanReadMode != types.ScanReadReasonOnly || !dryPlan.Target.Writable {
		t.Fatalf("unexpected dry-run TargetSummary/Actions: %+v", dryPlan)
	}
	if _, err := svc.Store().ResolveEnvironment(ctx, "uat"); err == nil {
		t.Fatalf("expected dry-run not to persist environment uat")
	}

	// 3. Real non-sqlite DB add in yolo (dev) defaults AccessLevel to read_write; strict (prod) defaults to read_only.
	devPG, err := svc.AdminAddDatabase(ctx, "qa", daemon.DBAddRequest{
		Engine:   "postgres",
		Host:     "127.0.0.1",
		Port:     5432,
		Database: "orders",
		System:   "shop",
		Env:      "dev",
		User:     "devuser",
	})
	if err != nil {
		t.Fatalf("AdminAddDatabase dev postgres: %v", err)
	}
	if devPG.AccessLevel != string(types.AccessReadWrite) || !devPG.Target.Writable {
		t.Fatalf("expected yolo env to default AccessLevel=read_write and Writable=true, got %+v", devPG)
	}

	prodPG, err := svc.AdminAddDatabase(ctx, "qa", daemon.DBAddRequest{
		Engine:   "postgres",
		Host:     "127.0.0.1",
		Port:     5432,
		Database: "orders",
		System:   "shop",
		Env:      "prod",
		User:     "prodreader",
	})
	if err != nil {
		t.Fatalf("AdminAddDatabase prod postgres: %v", err)
	}
	if prodPG.AccessLevel != string(types.AccessReadOnly) || prodPG.Target.Writable {
		t.Fatalf("expected strict env to default AccessLevel=read_only and Writable=false, got %+v", prodPG)
	}

	// 4. SQLite file diagnostics when --test runs before DB file exists, followed by full-scan read policy test.
	prodSQLitePath := filepath.Join(t.TempDir(), "prod-orders.db")
	missingPingRes, err := svc.AdminAddDatabase(ctx, "qa", daemon.DBAddRequest{
		Engine:       "sqlite",
		Host:         prodSQLitePath,
		System:       "shop",
		Env:          "prod",
		Alias:        "prod-sqlite",
		ScanReadMode: types.ScanReadRequireApproval,
		Test:         true,
	})
	if err != nil {
		t.Fatalf("AdminAddDatabase prod sqlite with --test: %v", err)
	}
	if missingPingRes.Ping == nil || missingPingRes.Ping.Reachable || !strings.Contains(missingPingRes.Ping.Error, "does not exist yet") {
		t.Fatalf("expected explanatory non-existent sqlite ping error, got %+v", missingPingRes.Ping)
	}

	// Seed a dev alias pointing to the same SQLite file to populate schema/rows (also verifies sqlite writes work).
	if _, err := svc.AdminAddDatabase(ctx, "qa", daemon.DBAddRequest{
		Engine: "sqlite",
		Host:   prodSQLitePath,
		System: "shop",
		Env:    "dev",
		Alias:  "dev-sqlite",
	}); err != nil {
		t.Fatalf("AdminAddDatabase dev sqlite: %v", err)
	}
	for _, stmt := range []string{
		`CREATE TABLE orders (id INTEGER PRIMARY KEY, status TEXT)`,
		`INSERT INTO orders (status) VALUES ('open'), ('closed')`,
	} {
		wr, err := svc.Execute(ctx, types.ExecRequest{TargetRefOrAlias: "dev-sqlite", Query: stmt, Wait: true})
		if err != nil || wr.Status != types.OpSucceeded {
			t.Fatalf("seed dev sqlite %q failed: %+v err=%v", stmt, wr, err)
		}
	}

	// Default prod SQLite full-scan SELECT COUNT(*) triggers waiting_approval.
	scanReqWait, err := svc.Execute(ctx, types.ExecRequest{
		TargetRefOrAlias: "prod-sqlite",
		Query:            "SELECT COUNT(*) FROM orders",
		Reason:           "check row count",
		Wait:             false,
	})
	if err != nil || scanReqWait.Status != types.OpWaitingApproval {
		t.Fatalf("expected SELECT COUNT(*) on prod sqlite to wait for approval, got %+v err=%v", scanReqWait, err)
	}
	_, _ = svc.CancelOperation(ctx, "qa", scanReqWait.OperationID)

	// Switch prod-sqlite scan_read_mode=reason_only -> without --reason rejected with reason_required; with --reason executes immediately.
	if _, err := svc.AdminSetTargetScanReadMode(ctx, "qa", "prod-sqlite", types.ScanReadReasonOnly, false); err != nil {
		t.Fatalf("AdminSetTargetScanReadMode: %v", err)
	}
	noReasonRes, err := svc.Execute(ctx, types.ExecRequest{
		TargetRefOrAlias: "prod-sqlite",
		Query:            "SELECT COUNT(*) FROM orders",
		Wait:             true,
	})
	if err != nil || noReasonRes.Status != types.OpDenied || noReasonRes.ErrorCode != types.ErrCodeReasonRequired {
		t.Fatalf("expected reason_required without --reason, got %+v err=%v", noReasonRes, err)
	}
	withReasonRes, err := svc.Execute(ctx, types.ExecRequest{
		TargetRefOrAlias: "prod-sqlite",
		Query:            "SELECT * FROM orders WHERE status = 'open' LIMIT 1",
		Reason:           "troubleshoot open orders",
		Wait:             true,
	})
	if err != nil || withReasonRes.Status != types.OpSucceeded || withReasonRes.ApprovalID != "" {
		t.Fatalf("expected scan read with --reason to succeed without approval, got %+v err=%v", withReasonRes, err)
	}

	// Writes in prod still require human approval despite scan_read_mode=reason_only, and RO-only target denies writes.
	writeProd, err := svc.Execute(ctx, types.ExecRequest{
		TargetRefOrAlias: "prod-sqlite",
		Query:            "INSERT INTO orders (status) VALUES ('hack')",
		Reason:           "write attempt",
		Wait:             false,
	})
	if err != nil || writeProd.Status != types.OpWaitingApproval {
		t.Fatalf("expected prod write to still require approval, got %+v err=%v", writeProd, err)
	}
	_, _ = svc.CancelOperation(ctx, "qa", writeProd.OperationID)

	writeROTarget, err := svc.Execute(ctx, types.ExecRequest{
		TargetRefOrAlias: prodPG.Target.Ref,
		Query:            "DELETE FROM orders WHERE id = 1",
		Reason:           "write attempt on ro target",
		Wait:             true,
	})
	if err != nil || writeROTarget.Status != types.OpDenied || writeROTarget.ErrorCode != types.ErrCodePolicyDenied {
		t.Fatalf("expected ro-only target write denial, got %+v err=%v", writeROTarget, err)
	}

	// Domestic engines with zero-value default TLSMode must probe cleanly without pre-dial sslmode errors
	// and always return an explicit non-empty driver error on unreachable endpoints.
	ln, lnErr := net.Listen("tcp", "127.0.0.1:0")
	if lnErr != nil {
		t.Fatal(lnErr)
	}
	closedPort := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	for _, dom := range []struct {
		engine string
		db     string
		alias  string
		user   string
	}{
		{engine: "opengauss", db: "og_db", alias: "og-legacy", user: "gaussdb"},
		{engine: "kingbase", db: "kb_db", alias: "kb-legacy", user: "system"},
		{engine: "dameng", db: "dm_db", alias: "dm-legacy", user: "SYSDBA"},
		{engine: "tdengine", db: "td_db", alias: "td-legacy", user: "root"},
		{engine: "easysearch", db: "es_db", alias: "es-legacy", user: "admin"},
	} {
		probeRes, addErr := svc.AdminAddDatabase(ctx, "qa", daemon.DBAddRequest{
			Engine:         dom.engine,
			Host:           "127.0.0.1",
			Port:           closedPort,
			Database:       dom.db,
			System:         "dom-sys",
			Env:            "shared/base-legacy",
			SafetyTier:     types.SafetyTierGuarded,
			Alias:          dom.alias,
			User:           dom.user,
			SecretValue:    "pw",
			SecretProvided: true,
			Test:           true,
		})
		if addErr != nil {
			t.Fatalf("AdminAddDatabase %s: %v", dom.engine, addErr)
		}
		if probeRes.Ping == nil || probeRes.Ping.Reachable || strings.TrimSpace(probeRes.Ping.Error) == "" {
			t.Fatalf("expected Ping with explicit error on unreachable %s, got %+v", dom.engine, probeRes.Ping)
		}
		if strings.Contains(probeRes.Ping.Error, "unsupported sslmode") {
			t.Fatalf("expected %s default tls_mode to avoid unsupported sslmode error, got %q", dom.engine, probeRes.Ping.Error)
		}
	}

	// Deleting target reports newly orphaned instance, credential, and custom environment; env delete removes it cleanly.
	if err := svc.AdminDeleteEnvironment(ctx, "qa", "shared/base-legacy"); err == nil {
		t.Fatalf("expected deleting in-use env shared/base-legacy to fail")
	}
	aliases := []string{"og-legacy", "kb-legacy", "dm-legacy", "td-legacy", "es-legacy"}
	for i, alias := range aliases {
		delRes, err := svc.AdminDeleteTarget(ctx, "qa", alias)
		if err != nil {
			t.Fatalf("AdminDeleteTarget(%s): %v", alias, err)
		}
		minOrphans := 2
		if i == len(aliases)-1 {
			minOrphans = 3
		}
		if !delRes.Deleted || len(delRes.Orphans) < minOrphans || len(delRes.NextCommands) < minOrphans {
			t.Fatalf("expected >= %d orphans after db delete %s, got %+v", minOrphans, alias, delRes)
		}
	}
	if err := svc.AdminDeleteEnvironment(ctx, "qa", "shared/base-legacy"); err != nil {
		t.Fatalf("expected env delete after target removal to succeed, got %v", err)
	}
}
