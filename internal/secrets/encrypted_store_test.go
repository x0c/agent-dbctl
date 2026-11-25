package secrets

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/x0c/agent-dbctl/internal/types"
)

func testKEK(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return b
}

func TestEnvelopeCipherAndFileStore(t *testing.T) {
	kek := testKEK(t)
	parsed, err := ParseMasterKey(hex.EncodeToString(kek))
	if err != nil || len(parsed) != 32 {
		t.Fatalf("ParseMasterKey hex failed: %v", err)
	}

	path := filepath.Join(t.TempDir(), "secrets.enc")
	st, err := NewEncryptedFileStore(path, kek)
	if err != nil {
		t.Fatalf("NewEncryptedFileStore: %v", err)
	}

	ctx := context.Background()
	if err := st.Put(ctx, "cred:c1", "s3cr3t-pass"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if ok, err := st.Has(ctx, "cred:c1"); err != nil || !ok {
		t.Fatalf("Has expected true, got ok=%v err=%v", ok, err)
	}
	got, err := st.Get(ctx, "cred:c1")
	if err != nil || got != "s3cr3t-pass" {
		t.Fatalf("Get mismatch: got=%q err=%v", got, err)
	}

	// Verify AAD prevents swapping ciphertext across credential keys.
	c, _ := NewEnvelopeCipher(kek, 1)
	rec, err := c.Encrypt("cred:dev", "dev-pass")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	rec.Key = "cred:prod"
	if _, err := c.Decrypt(rec); err == nil {
		t.Fatalf("expected AAD mismatch error when swapping key")
	}

	if err := st.Delete(ctx, "cred:c1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if ok, _ := st.Has(ctx, "cred:c1"); ok {
		t.Fatalf("expected deleted secret to be absent")
	}
}

func TestServerEnvAndExecGuards(t *testing.T) {
	pol := ServerPolicy{
		Enabled:             true,
		AllowExecForAdmin:   true,
		AllowedExecPrefixes: []string{"/nonexistent/vault-helper"},
		AllowedEnvPrefixes:  []string{"CORP_DB_"},
	}

	if err := ValidateServerEnvVar("AGENT_DBCTL_MASTER_KEY", pol); err == nil {
		t.Fatalf("expected AGENT_DBCTL_* env_ref to be blocked")
	}
	if err := ValidateServerEnvVar("OTHER_PASS", pol); err == nil {
		t.Fatalf("expected non-allowlisted env_ref to be blocked")
	}
	if err := ValidateServerEnvVar("CORP_DB_RO_PASS", pol); err != nil {
		t.Fatalf("expected allowlisted env_ref to pass: %v", err)
	}

	if err := ValidateServerExecCommand("/bin/sh -c 'env'", pol); err == nil {
		t.Fatalf("expected shell exec_provider to be blocked")
	}

	p := &types.CredentialProfile{
		ID:         "c1",
		Name:       "c1",
		Kind:       types.CredEnvRef,
		EnvVarName: "CORP_DB_RO_PASS",
	}
	t.Setenv("CORP_DB_RO_PASS", "vault-token-123")
	res, err := ResolveCredentialWithOptions(context.Background(), nil, p, pol)
	if err != nil || res.Secret != "vault-token-123" {
		t.Fatalf("ResolveCredentialWithOptions env_ref failed: res=%+v err=%v", res, err)
	}
}
