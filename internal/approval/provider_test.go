package approval_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/x0c/agent-dbctl/internal/approval"
	"github.com/x0c/agent-dbctl/internal/store"
	"github.com/x0c/agent-dbctl/internal/types"
)

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func seedTestOp(t *testing.T, st *store.Store, id string) types.Operation {
	t.Helper()
	op, err := st.CreateOperation(context.Background(), types.Operation{
		ID: id, TargetID: "t1", TargetRef: "orders/prod/db", SystemID: "s1", SystemSlug: "orders",
		EnvironmentCode: "prod", Engine: "postgres", Actor: "agent",
		QueryText: "UPDATE users SET note = 'sample-literal-value' WHERE id = 1",
		QueryRedacted: "UPDATE users SET note = '***' WHERE id = 1",
		RiskLevel: types.RiskWrite, Decision: types.DecisionRequireApproval,
		Classification: types.Classification{IsReadOnly: false, RiskLevel: types.RiskWrite},
		Status:         types.OpWaitingApproval, CredentialMode: types.AccessReadWrite,
	})
	if err != nil {
		t.Fatalf("create operation: %v", err)
	}
	return op
}

func TestManagerInstantShutdownTokenValidationTicketSanitizationAndRehydrate(t *testing.T) {
	t.Setenv("AGENT_DBCTL_NO_BROWSER", "1")
	ctx := context.Background()
	st := openTestStore(t)
	mgr := approval.NewManager(st)
	lw := approval.NewLocalWebProvider(nil)
	lw.SetBaseURL("http://127.0.0.1:18888")
	mgr.RegisterProvider(lw)

	op1 := seedTestOp(t, st, "op_shut")
	app1, rawURL, err := mgr.Submit(ctx, "local-web", op1, types.TargetDetail{}, 120)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if !strings.Contains(rawURL, "?token=") {
		t.Fatalf("expected rawURL to contain token, got %q", rawURL)
	}

	// Verify persisted external_ticket_url stripped ?token=.
	persisted, _, err := st.GetApproval(ctx, app1.ID)
	if err != nil {
		t.Fatalf("get approval: %v", err)
	}
	if persisted.ExternalTicketURL == "" || strings.Contains(persisted.ExternalTicketURL, "token=") {
		t.Fatalf("expected sanitized ticket URL in DB, got %q", persisted.ExternalTicketURL)
	}

	// Wrong token rejected; valid token succeeds; replay fails with conflict.
	if _, err := mgr.Resolve(ctx, app1.ID, true, "human", "bad", "wrong-token", false); err == nil {
		t.Fatalf("expected wrong token rejection")
	}
	parsed, _ := url.Parse(rawURL)
	tok := parsed.Query().Get("token")
	resApp, err := mgr.Resolve(ctx, app1.ID, true, "human", "ok", tok, false)
	if err != nil || resApp.Status != types.ApprovalApproved {
		t.Fatalf("expected approval with valid token, got status=%s err=%v", resApp.Status, err)
	}
	if _, err := mgr.Resolve(ctx, app1.ID, true, "human", "replay", tok, false); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected replay conflict, got %v", err)
	}

	// Submit another long-timeout approval (120s) and verify Shutdown() finishes < 300ms.
	op2 := seedTestOp(t, st, "op_fast_stop")
	if _, _, err := mgr.Submit(ctx, "local-web", op2, types.TargetDetail{}, 120); err != nil {
		t.Fatalf("submit op2: %v", err)
	}
	start := time.Now()
	mgr.Shutdown()
	if elapsed := time.Since(start); elapsed > 300*time.Millisecond {
		t.Fatalf("Shutdown blocked for %v (want <300ms)", elapsed)
	}

	// Rehydrate a pending approval with short deadline and confirm watchDeadline expires it.
	mgr2 := approval.NewManager(st)
	defer mgr2.Shutdown()
	op3 := seedTestOp(t, st, "op_rehydrate")
	app3, err := st.CreateApproval(ctx, "agent", types.ApprovalRequest{
		ID: "apr_rehydrate", OperationID: op3.ID, Provider: "local-web", Status: types.ApprovalPending,
		TargetRef: "orders/prod/db", SystemSlug: "orders", EnvironmentCode: "prod", Engine: "postgres",
		Actor: "agent", QueryText: op3.QueryText, RiskLevel: types.RiskWrite,
		ExpiresAtUTC: time.Now().UTC().Add(80 * time.Millisecond).Format(time.RFC3339Nano),
	}, approval.HashToken("tok3"))
	if err != nil {
		t.Fatal(err)
	}
	ch, ok := mgr2.Rehydrate(app3)
	if !ok {
		t.Fatalf("expected Rehydrate to accept pending approval")
	}
	select {
	case res := <-ch:
		if res.Approval.Status != types.ApprovalExpired {
			t.Fatalf("expected rehydrated approval to expire, got %s", res.Approval.Status)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for rehydrated expiration")
	}
}

func TestWebhookProviderSecuritySigningAndLifecycle(t *testing.T) {
	if _, err := approval.ValidateWebhookURL("http://hooks.example.com/approve"); err == nil {
		t.Fatalf("expected non-loopback http webhook URL to be rejected")
	}
	if _, err := approval.ValidateWebhookURL("https://hooks.example.com/approve"); err != nil {
		t.Fatalf("expected https webhook URL accepted, got %v", err)
	}

	var mu sync.Mutex
	var events []map[string]any
	const secret = "whsec_test_123"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ts := r.Header.Get("X-Agent-DBCTL-Timestamp")
		sig := r.Header.Get("X-Agent-DBCTL-Signature")
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(ts + "."))
		mac.Write(body)
		wantSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if !hmac.Equal([]byte(sig), []byte(wantSig)) {
			http.Error(w, "bad signature", http.StatusUnauthorized)
			return
		}
		var payload map[string]any
		_ = json.Unmarshal(body, &payload)
		mu.Lock()
		events = append(events, payload)
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ticket_id":"TICKET-42","ticket_url":"https://tickets.example.com/42"}`))
	}))
	defer srv.Close()

	ctx := context.Background()
	st := openTestStore(t)
	mgr := approval.NewManager(st)
	defer mgr.Shutdown()

	lw := approval.NewLocalWebProvider(nil)
	lw.SetBaseURL("http://127.0.0.1:19999")

	t.Setenv(approval.EnvWebhookURL, srv.URL)
	t.Setenv(approval.EnvWebhookSecret, secret)
	t.Setenv(approval.EnvWebhookTimeout, "3s")
	wh, err := approval.NewWebhookProviderFromEnv(lw)
	if err != nil || wh == nil {
		t.Fatalf("NewWebhookProviderFromEnv failed: %v", err)
	}
	mgr.RegisterProvider(lw)
	mgr.RegisterProvider(wh)

	op := seedTestOp(t, st, "op_wh")
	app, ticketURL, err := mgr.Submit(ctx, "webhook", op, types.TargetDetail{}, 60)
	if err != nil {
		t.Fatalf("webhook submit: %v", err)
	}
	if app.ExternalTicketID != "TICKET-42" || ticketURL != "https://tickets.example.com/42" {
		t.Fatalf("unexpected external ticket: id=%q url=%q", app.ExternalTicketID, ticketURL)
	}

	if _, err := mgr.Cancel(ctx, app.ID, "agent-cli"); err != nil {
		t.Fatalf("webhook cancel: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 2 {
		t.Fatalf("expected 2 webhook events (requested + cancelled), got %d", len(events))
	}
	if events[0]["event"] != "approval.requested" || events[1]["event"] != "approval.cancelled" {
		t.Fatalf("unexpected event sequence: %+v", events)
	}
	qRedacted, _ := events[0]["query_redacted"].(string)
	if strings.Contains(qRedacted, "sample-literal-value") || !strings.Contains(qRedacted, "'***'") {
		t.Fatalf("expected redacted query in webhook payload, got %q", qRedacted)
	}
}
