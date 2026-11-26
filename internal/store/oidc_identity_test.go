package store

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/x0c/agent-dbctl/internal/types"
)

func TestOIDCIdentityAndManagedAdminReconciliation(t *testing.T) {
	ctx := t.Context()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "oidc.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	baseline, err := st.VerifyAuditChain(ctx)
	if err != nil || !baseline.Valid {
		t.Fatalf("invalid seeded audit chain: %+v, %v", baseline, err)
	}
	const issuer = "https://id.example.com"
	local, err := st.CreateUser(ctx, "test", types.User{Email: "local@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.UpsertOIDCUser(ctx, issuer, "local-subject", local.Email, ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("unbound local account must require explicit linking: %v", err)
	}
	admin, created, err := st.UpsertOIDCUser(ctx, issuer, "configured-subject", "oidc@example.com", "Test Admin")
	if err != nil || !created {
		t.Fatalf("unable to provision verified identity: %v", err)
	}
	if _, _, err := st.UpsertOIDCUser(ctx, issuer, "other-subject", admin.Email, ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("email collision did not report conflict: %v", err)
	}
	got, created, err := st.UpsertOIDCUser(ctx, issuer, admin.OIDCSubject, "updated@example.com", "")
	if err != nil || created || got.ID != admin.ID {
		t.Fatalf("existing identity should remain stable when contact claim changes: %v", err)
	}
	for user, actor := range map[string]string{local.ID: "manual-admin", admin.ID: "oidc-sync"} {
		if _, err := st.UpsertRoleBinding(ctx, actor, types.RoleBinding{UserID: user, Role: types.RolePlatformAdmin, ScopeType: types.ScopeGlobal}); err != nil {
			t.Fatal(err)
		}
	}
	for _, subjects := range [][]string{{admin.OIDCSubject}, nil} {
		if err := st.ReconcileOIDCAdminBindings(ctx, issuer, subjects); err != nil {
			t.Fatal(err)
		}
		if got, err := st.ListRoleBindings(ctx, admin.ID); err != nil || len(got) != len(subjects) {
			t.Fatalf("incorrect configured grants after reconciliation: %v, %v", got, err)
		}
	}
	if got, err := st.ListRoleBindings(ctx, local.ID); err != nil || len(got) != 1 || got[0].CreatedBy != "manual-admin" {
		t.Fatalf("explicit grant not retained: %v, %v", got, err)
	}
	if got, err := st.VerifyAuditChain(ctx); err != nil || !got.Valid || got.CheckedCount != baseline.CheckedCount+5 {
		t.Fatalf("unexpected audited actions: %+v, %v", got, err)
	}
}
