package daemon_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/x0c/agent-dbctl/internal/config"
	"github.com/x0c/agent-dbctl/internal/daemon"
	"github.com/x0c/agent-dbctl/internal/types"
)

func TestDaemonStartupRecoveryAndRehydratedApproval(t *testing.T) {
	cfgHome := t.TempDir()
	dbFile := filepath.Join(t.TempDir(), "prod.sqlite")

	t.Setenv(config.EnvConfigHome, cfgHome)
	t.Setenv(config.EnvSecretBackend, "file")
	t.Setenv(config.EnvNoBrowser, "1")
	t.Setenv(config.EnvSession, "recover-sess")

	paths, err := config.ResolvePaths("recover-sess")
	if err != nil {
		t.Fatalf("resolve paths: %v", err)
	}
	ctx := context.Background()

	// Boot #1: seed target, create an interrupted running op, an expired pending approval, and a valid pending approval.
	srv1, err := daemon.StartServer(ctx, paths, "v0.1.0-test", "abc", "")
	if err != nil {
		t.Fatalf("start server 1: %v", err)
	}
	done1 := make(chan error, 1)
	go func() { done1 <- srv1.Run(ctx) }()

	svc1 := srv1.Service()
	sys, _ := svc1.Store().UpsertSystem(ctx, "test", types.System{Slug: "billing", Name: "Billing"})
	inst, _ := svc1.Store().UpsertInstance(ctx, "test", types.Instance{Name: "sqlite-prod", Engine: "sqlite", Host: dbFile})
	tgt, _ := svc1.Store().UpsertTarget(ctx, "test", types.Target{
		Ref: "billing/prod/main", Alias: "prod-billing", OwnerSystemID: sys.ID, EnvironmentCode: "prod", InstanceID: inst.ID, DatabaseName: dbFile,
	})

	// Interrupted running write op.
	_, _ = svc1.Store().CreateOperation(ctx, types.Operation{
		ID: "op_stuck_write", TargetID: tgt.ID, TargetRef: tgt.Ref, SystemID: sys.ID, SystemSlug: sys.Slug,
		EnvironmentCode: "prod", Engine: "sqlite", Actor: "agent", QueryText: "INSERT INTO x VALUES (1)", QueryRedacted: "INSERT INTO x VALUES (1)",
		RiskLevel: types.RiskWrite, Decision: types.DecisionRequireApproval,
		Classification: types.Classification{IsReadOnly: false, RiskLevel: types.RiskWrite},
		Status:         types.OpRunning, CredentialMode: types.AccessReadWrite,
	})

	// Submit a real pending prod DDL before stopping srv1.
	pendingResp, err := svc1.Execute(ctx, types.ExecRequest{
		TargetRefOrAlias: tgt.Alias,
		Query:            "CREATE TABLE ledger(id INTEGER PRIMARY KEY, amount INTEGER)",
		Reason:           "Init ledger across restart",
		Wait:             false,
	})
	if err != nil || pendingResp.Status != types.OpWaitingApproval {
		t.Fatalf("expected waiting_approval before restart, got %+v err=%v", pendingResp, err)
	}

	// Verify op status persists sanitized URL (no ?token=).
	stBefore, err := svc1.GetOperationStatus(ctx, pendingResp.OperationID)
	if err != nil || stBefore.ApprovalURL == "" || strings.Contains(stBefore.ApprovalURL, "token=") {
		t.Fatalf("expected sanitized ApprovalURL in status, got %+v err=%v", stBefore, err)
	}

	parsedRawURL, _ := url.Parse(pendingResp.ApprovalURL)
	oneTimeToken := parsedRawURL.Query().Get("token")

	// Shut down srv1 before approval arrives.
	srv1.TriggerShutdown()
	if err := <-done1; err != nil {
		t.Fatalf("srv1 shutdown: %v", err)
	}

	// Boot #2 on the exact same cfgHome / SQLite DB.
	srv2, err := daemon.StartServer(ctx, paths, "v0.1.0-test", "abc", "")
	if err != nil {
		t.Fatalf("start server 2: %v", err)
	}
	done2 := make(chan error, 1)
	go func() { done2 <- srv2.Run(ctx) }()
	t.Cleanup(func() {
		srv2.TriggerShutdown()
		if err := <-done2; err != nil {
			t.Errorf("srv2 shutdown: %v", err)
		}
	})
	svc2 := srv2.Service()

	// Stuck running write op must be marked failed + daemon_restarted + retryable=false.
	stuckStatus, err := svc2.GetOperationStatus(ctx, "op_stuck_write")
	if err != nil || stuckStatus.Status != types.OpFailed || stuckStatus.ErrorCode != types.ErrCodeDaemonRestarted || stuckStatus.Retryable {
		t.Fatalf("expected interrupted write op reconciled to failed/daemon_restarted/non-retryable, got %+v err=%v", stuckStatus, err)
	}

	// Approve the pre-restart pending DDL on srv2 via HTTP POST using the original one-time token.
	body, _ := json.Marshal(map[string]string{"reviewer": "dba", "note": "post-restart approve", "token": oneTimeToken})
	req, _ := http.NewRequest(http.MethodPost, srv2.WebURL()+"/api/v1/approvals/"+pendingResp.ApprovalID+"/approve", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", srv2.WebURL())
	httpResp, err := http.DefaultClient.Do(req)
	if err != nil || httpResp.StatusCode != http.StatusOK {
		t.Fatalf("post-restart approve failed: resp=%v err=%v", httpResp, err)
	}
	_ = httpResp.Body.Close()

	// WaitForOperation should observe the rehydrated lifecycle execute the DDL to OpSucceeded!
	finalResp, err := svc2.WaitForOperation(ctx, pendingResp.OperationID, 5*time.Second)
	if err != nil || finalResp.Status != types.OpSucceeded {
		t.Fatalf("expected rehydrated DDL op to succeed after restart, got %+v err=%v", finalResp, err)
	}
}

func TestCancelOperationAndWaitAndWaitForOperationTimeout(t *testing.T) {
	srv, _ := setupIsolatedServer(t)
	svc := srv.Service()
	ctx := context.Background()

	dbFile := filepath.Join(t.TempDir(), "prod.sqlite")
	sys, _ := svc.Store().UpsertSystem(ctx, "test", types.System{Slug: "cancel-sys", Name: "Cancel Sys"})
	inst, _ := svc.Store().UpsertInstance(ctx, "test", types.Instance{Name: "sqlite-cancel", Engine: "sqlite", Host: dbFile})
	tgt, _ := svc.Store().UpsertTarget(ctx, "test", types.Target{
		Ref: "cancel-sys/prod/db", Alias: "prod-cancel", OwnerSystemID: sys.ID, EnvironmentCode: "prod", InstanceID: inst.ID, DatabaseName: dbFile,
	})

	pending, err := svc.Execute(ctx, types.ExecRequest{
		TargetRefOrAlias: tgt.Alias,
		Query:            "CREATE TABLE z(id INT)",
		Reason:           "test wait timeout & cancel",
		Wait:             false,
	})
	if err != nil || pending.Status != types.OpWaitingApproval {
		t.Fatalf("expected waiting_approval, got %+v err=%v", pending, err)
	}

	// WaitForOperation with short timeout returns waiting_approval cleanly.
	timed, err := svc.WaitForOperation(ctx, pending.OperationID, 120*time.Millisecond)
	if err != nil || timed.Status != types.OpWaitingApproval || timed.ErrorCode != types.ErrCodeWaitingApproval {
		t.Fatalf("expected waiting_approval timeout status, got %+v err=%v", timed, err)
	}

	// CancelOperationAndWait settles deterministically to OpCancelled on return.
	cancelled, err := svc.CancelOperationAndWait(ctx, pending.OperationID, "agent-cli")
	if err != nil || cancelled.Status != types.OpCancelled {
		t.Fatalf("expected settled cancelled status, got %+v err=%v", cancelled, err)
	}
}

func TestServerSessionLockPreventsDuplicateAndSSEShutdownIsFast(t *testing.T) {
	cfgHome := t.TempDir()
	t.Setenv(config.EnvConfigHome, cfgHome)
	t.Setenv(config.EnvSecretBackend, "file")
	t.Setenv(config.EnvNoBrowser, "1")
	t.Setenv(config.EnvSession, "lock-sse-test")

	paths, err := config.ResolvePaths("lock-sse-test")
	if err != nil {
		t.Fatalf("resolve paths: %v", err)
	}

	srv1, err := daemon.StartServer(context.Background(), paths, "v0.2.0-test", "abc", "")
	if err != nil {
		t.Fatalf("start server 1: %v", err)
	}
	done1 := make(chan error, 1)
	go func() { done1 <- srv1.Run(context.Background()) }()

	// Second StartServer for the same session must fail immediately while lock is held.
	if srv2, dupErr := daemon.StartServer(context.Background(), paths, "v0.2.0-test", "def", ""); dupErr == nil {
		srv2.TriggerShutdown()
		t.Fatalf("expected second StartServer on same session to fail with session lock")
	}

	// Open an active SSE connection and verify TriggerShutdown completes promptly (<1.5s, not 5s).
	sseReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv1.WebURL()+"/api/v1/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	sseResp, err := http.DefaultClient.Do(sseReq)
	if err != nil {
		t.Fatalf("connect SSE: %v", err)
	}
	defer func() { _ = sseResp.Body.Close() }()
	line, err := bufio.NewReader(sseResp.Body).ReadString('\n')
	if err != nil || !strings.Contains(line, "ready") {
		t.Fatalf("expected initial SSE ready event, got %q err=%v", line, err)
	}

	startStop := time.Now()
	srv1.TriggerShutdown()
	select {
	case runErr := <-done1:
		if runErr != nil {
			t.Fatalf("srv1 shutdown error: %v", runErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("daemon shutdown with active SSE connection hung past 2s")
	}
	if elapsed := time.Since(startStop); elapsed > 1500*time.Millisecond {
		t.Fatalf("expected fast SSE shutdown, took %v", elapsed)
	}

	// Lock is released once Run exits, allowing a subsequent StartServer to succeed.
	srv3, err := daemon.StartServer(context.Background(), paths, "v0.2.0-test", "def", "")
	if err != nil {
		t.Fatalf("expected StartServer after shutdown to succeed, got: %v", err)
	}
	done3 := make(chan error, 1)
	go func() { done3 <- srv3.Run(context.Background()) }()
	srv3.TriggerShutdown()
	if runErr := <-done3; runErr != nil {
		t.Fatalf("srv3 shutdown error: %v", runErr)
	}
}
