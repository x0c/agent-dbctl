package secrets_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"testing"

	"github.com/x0c/agent-dbctl/internal/secrets"
	"github.com/x0c/agent-dbctl/internal/types"
)

func TestFileStoreCRUDPermissionsSymlinkAndRace(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")
	fs := secrets.NewFileStore(path)

	if has, err := fs.Has(ctx, "k1"); err != nil || has {
		t.Fatalf("expected missing key, got has=%v err=%v", has, err)
	}
	if _, err := fs.Get(ctx, "k1"); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	if err := fs.Put(ctx, "k1", "s3cr3t"); err != nil {
		t.Fatalf("put: %v", err)
	}
	if got, err := fs.Get(ctx, "k1"); err != nil || got != "s3cr3t" {
		t.Fatalf("get mismatch: got=%q err=%v", got, err)
	}

	// Loosen mode on disk and ensure FileStore tightens it back to 0600 on read.
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := fs.Get(ctx, "k1"); err != nil {
			t.Fatalf("get after chmod: %v", err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("expected permissions tightened to 0600, got %o", info.Mode().Perm())
		}
	}

	if err := fs.Delete(ctx, "k1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if has, err := fs.Has(ctx, "k1"); err != nil || has {
		t.Fatalf("expected deleted key, got has=%v err=%v", has, err)
	}

	// Symlink refusal.
	realFile := filepath.Join(dir, "real.json")
	if err := os.WriteFile(realFile, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	symPath := filepath.Join(dir, "sym.json")
	if err := os.Symlink(realFile, symPath); err != nil {
		t.Fatal(err)
	}
	symStore := secrets.NewFileStore(symPath)
	if err := symStore.Put(ctx, "x", "y"); err == nil {
		t.Fatalf("expected symlink secret store refusal")
	}

	// Concurrent reads/writes under -race.
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			k := fmt.Sprintf("k_%d", idx)
			if err := fs.Put(ctx, k, "val"); err != nil {
				t.Errorf("concurrent put %s: %v", k, err)
			}
			_, _ = fs.Get(ctx, k)
			_ = fs.Delete(ctx, k)
		}(i)
	}
	wg.Wait()
}

func TestSplitExecArgs(t *testing.T) {
	got, err := secrets.SplitExecArgs(`vault kv get -field="api key" 'secret/prod app' --flag\ 1`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"vault", "kv", "get", "-field=api key", "secret/prod app", "--flag 1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SplitExecArgs got %#v, want %#v", got, want)
	}

	for _, bad := range []string{"", "   ", `echo "unclosed`, `echo 'unclosed`, `echo trailing\`} {
		if _, err := secrets.SplitExecArgs(bad); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
}

func TestResolveCredentialBackends(t *testing.T) {
	ctx := context.Background()
	fs := secrets.NewFileStore(filepath.Join(t.TempDir(), "s.json"))
	if err := fs.Put(ctx, "cred:c1", "db-pass"); err != nil {
		t.Fatal(err)
	}

	r1, err := secrets.ResolveCredential(ctx, fs, &types.CredentialProfile{
		ID:       "c1",
		Name:     "ro",
		Kind:     types.CredKeychain,
		Username: "reader",
	})
	if err != nil || r1.Username != "reader" || r1.Secret != "db-pass" {
		t.Fatalf("unexpected keychain/file resolution: %+v err=%v", r1, err)
	}

	t.Setenv("TEST_ADB_PASS", "env-secret")
	r2, err := secrets.ResolveCredential(ctx, fs, &types.CredentialProfile{
		ID:         "c2",
		Name:       "env",
		Kind:       types.CredEnvRef,
		Username:   "envuser",
		EnvVarName: "TEST_ADB_PASS",
	})
	if err != nil || r2.Secret != "env-secret" {
		t.Fatalf("unexpected env_ref resolution: %+v err=%v", r2, err)
	}

	if runtime.GOOS != "windows" {
		r3, err := secrets.ResolveCredential(ctx, fs, &types.CredentialProfile{
			ID:          "c3",
			Name:        "exec",
			Kind:        types.CredExecProvider,
			Username:    "exuser",
			ExecCommand: `printf '%s\n' "spaced secret value"`,
		})
		if err != nil || r3.Secret != "spaced secret value" {
			t.Fatalf("unexpected exec_provider resolution: %+v err=%v", r3, err)
		}
	}
}
