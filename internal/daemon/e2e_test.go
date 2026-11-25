package daemon_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/x0c/agent-dbctl/internal/config"
	"github.com/x0c/agent-dbctl/internal/daemon"
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

	// Same-origin middleware unit tests (external origin & cross-site null must be 403).
	handler := daemon.NewWebHandler(svc)
	for _, tc := range []struct {
		name   string
		origin string
		sfs    string
		want   int
	}{
		{"external_origin_blocked", "https://evil.example", "", http.StatusForbidden},
		{"null_cross_site_blocked", "null", "cross-site", http.StatusForbidden},
		{"null_without_sfs_blocked", "null", "", http.StatusForbidden},
		{"null_same_origin_allowed", "null", "same-origin", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/api/v1/audit/verify", bytes.NewReader([]byte("{}")))
			r.Host = "127.0.0.1:8080"
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			if tc.sfs != "" {
				r.Header.Set("Sec-Fetch-Site", tc.sfs)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("got HTTP %d, want %d (body=%s)", w.Code, tc.want, w.Body.String())
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
