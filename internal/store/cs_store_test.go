package store

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/x0c/agent-dbctl/internal/types"
)

func TestRebindPostgresAndCSStoreLifecycle(t *testing.T) {
	q := `SELECT * FROM users WHERE email = ? AND status = '?' AND id = ?`
	got := rebindPostgres(q)
	want := `SELECT * FROM users WHERE email = $1 AND status = '?' AND id = $2`
	if got != want {
		t.Fatalf("rebindPostgres mismatch:\ngot:  %s\nwant: %s", got, want)
	}

	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "cs.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = st.Close() }()

	u, err := st.CreateUser(ctx, "system", types.User{
		Email:        "Alice@Corp.com",
		DisplayName:  "Alice",
		PasswordHash: "$argon2id$dummy",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.Email != "alice@corp.com" {
		t.Fatalf("expected lowercased email, got %q", u.Email)
	}

	rb, err := st.UpsertRoleBinding(ctx, "system", types.RoleBinding{
		UserID:    u.ID,
		Role:      types.RoleSystemAdmin,
		ScopeType: types.ScopeSystem,
		ScopeID:   "order-core",
	})
	if err != nil || rb.ID == "" {
		t.Fatalf("UpsertRoleBinding: %+v err=%v", rb, err)
	}

	tok, err := st.CreateAPIToken(ctx, "user:"+u.Email, types.APIToken{
		UserID:         u.ID,
		Name:           "ci-agent",
		TokenPrefix:    "abcd1234",
		TokenHash:      "hash_abc",
		RoleCeiling:    types.RoleDeveloper,
		AllowedSystems: []string{"order-core"},
		AllowedEnvs:    []string{"dev", "staging"},
	})
	if err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}
	foundTok, foundUser, err := st.LookupAPITokenByHash(ctx, "hash_abc")
	if err != nil || foundTok.ID != tok.ID || foundUser.ID != u.ID {
		t.Fatalf("LookupAPITokenByHash failed: tok=%+v user=%+v err=%v", foundTok, foundUser, err)
	}
	if err := st.RevokeAPIToken(ctx, "user:"+u.Email, tok.ID, u.ID); err != nil {
		t.Fatalf("RevokeAPIToken: %v", err)
	}

	exp := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	if err := st.CreateWebSession(ctx, types.WebSession{
		IDHash:        "sess_h1",
		UserID:        u.ID,
		CSRFTokenHash: "csrf_h1",
		ExpiresAtUTC:  exp,
	}); err != nil {
		t.Fatalf("CreateWebSession: %v", err)
	}
	sess, sessUser, err := st.GetWebSessionByHash(ctx, "sess_h1")
	if err != nil || sess.UserID != u.ID || sessUser.Email != u.Email {
		t.Fatalf("GetWebSessionByHash: sess=%+v user=%+v err=%v", sess, sessUser, err)
	}

	if err := st.CheckAndStoreWebhookNonce(ctx, "feishu", "evt_1", exp); err != nil {
		t.Fatalf("CheckAndStoreWebhookNonce first: %v", err)
	}
	if err := st.CheckAndStoreWebhookNonce(ctx, "feishu", "evt_1", exp); err == nil {
		t.Fatalf("expected replayed webhook nonce to fail")
	}

	// Verify PrincipalKind persistence for human CLI tokens vs agent tokens.
	humanTok, err := st.CreateAPIToken(ctx, "user:"+u.Email, types.APIToken{
		UserID:        u.ID,
		Name:          "cli-sso-session",
		TokenPrefix:   "humn1234",
		TokenHash:     "hash_human",
		PrincipalKind: types.PrincipalHuman,
	})
	if err != nil {
		t.Fatalf("CreateAPIToken human: %v", err)
	}
	gotHuman, _, err := st.LookupAPITokenByHash(ctx, "hash_human")
	if err != nil || gotHuman.ID != humanTok.ID || gotHuman.PrincipalKind != types.PrincipalHuman {
		t.Fatalf("LookupAPITokenByHash human mismatch: tok=%+v err=%v", gotHuman, err)
	}
	toks, err := st.ListAPITokens(ctx, u.ID)
	if err != nil || len(toks) < 2 {
		t.Fatalf("ListAPITokens mismatch: toks=%+v err=%v", toks, err)
	}

	// Verify concurrent audit writes remain strictly serialized and hash-chain valid.
	var auditWG sync.WaitGroup
	errs := make(chan error, 12)
	for i := 0; i < 12; i++ {
		i := i
		auditWG.Add(1)
		go func() {
			defer auditWG.Done()
			if err := st.RecordAuditEvent(ctx, "user:alice@corp.com", "audit.concurrent", fmt.Sprintf("tgt_%d", i), "", map[string]any{"i": i}); err != nil {
				errs <- err
			}
		}()
	}
	auditWG.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent RecordAuditEvent failed: %v", err)
	}

	// Verify audit chain after all C/S mutations.
	vr, err := st.VerifyAuditChain(ctx)
	if err != nil || !vr.Valid || vr.CheckedCount == 0 {
		t.Fatalf("VerifyAuditChain failed: %+v err=%v", vr, err)
	}
}
