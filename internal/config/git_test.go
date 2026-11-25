package config_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/x0c/agent-dbctl/internal/config"
)

func TestNormalizeGitRemote(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"", ""},
		{"   ", ""},
		{"https://github.com/Org/Order-Core.git", "github.com/Org/Order-Core"},
		{"https://oauth2:secret-token@github.com/org/order-core.git/", "github.com/org/order-core"},
		{"https://GitHub.com:443/org/order-core.GIT", "github.com/org/order-core"},
		{"git@github.com:org/order-core.git", "github.com/org/order-core"},
		{"ssh://git@github.com/org/order-core.git", "github.com/org/order-core"},
		{"ssh://git@github.com:22/org/order-core.git", "github.com/org/order-core"},
		{"ssh://git@git.example.com:2222/org/order-core.git", "git.example.com:2222/org/order-core"},
		{"git.example.com:2222/org/order-core.git", "git.example.com:2222/org/order-core"},
		{"git://github.com/org/order-core.git", "github.com/org/order-core"},
		{"github.com/org/order-core", "github.com/org/order-core"},
		{"github.com/org/order-core.git", "github.com/org/order-core"},
		{"C:\\work\\repo", "C:\\work\\repo"},
	}
	for _, tc := range cases {
		got := config.NormalizeGitRemote(tc.raw)
		if got != tc.want {
			t.Errorf("NormalizeGitRemote(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}

	deduped := config.NormalizeGitRemotes([]string{
		"git@github.com:org/order-core.git",
		"https://github.com/ORG/order-core.git",
		"ssh://git@git.example.com:2222/org/billing.git",
		"",
	})
	wantDeduped := []string{"github.com/org/order-core", "git.example.com:2222/org/billing"}
	if !reflect.DeepEqual(deduped, wantDeduped) {
		t.Fatalf("NormalizeGitRemotes = %v, want %v", deduped, wantDeduped)
	}

	if slug := config.RepoNameFromGitRemote("git@github.com:org/order-core.git"); slug != "order-core" {
		t.Fatalf("RepoNameFromGitRemote = %q, want order-core", slug)
	}
}

func TestDetectGitRemotesWithWorktree(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not available")
	}
	ctx := context.Background()
	tmp := t.TempDir()
	mainRepo := filepath.Join(tmp, "order-core")
	wtDir := filepath.Join(tmp, "wt-feature-123")
	subDir := filepath.Join(wtDir, "cmd", "api")

	runGit := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Test",
			"GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=Test",
			"GIT_COMMITTER_EMAIL=test@example.com",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, out)
		}
	}

	if err := os.MkdirAll(mainRepo, 0o755); err != nil {
		t.Fatal(err)
	}
	runGit(mainRepo, "init")
	runGit(mainRepo, "remote", "add", "upstream", "https://github.com/upstream-org/order-core.git")
	runGit(mainRepo, "remote", "add", "origin", "git@github.com:acme/order-core.git")
	if err := os.WriteFile(filepath.Join(mainRepo, "README.md"), []byte("hi\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(mainRepo, "add", "README.md")
	runGit(mainRepo, "commit", "-m", "init")
	runGit(mainRepo, "worktree", "add", "-b", "feat/wt", wtDir)
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatal(err)
	}

	got := config.DetectGitRemotes(ctx, subDir)
	want := []string{"github.com/acme/order-core", "github.com/upstream-org/order-core"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DetectGitRemotes(%q) = %v, want %v", subDir, got, want)
	}

	nonRepo := t.TempDir()
	if none := config.DetectGitRemotes(ctx, nonRepo); len(none) != 0 {
		t.Fatalf("expected empty remotes for non-git dir, got %v", none)
	}
}
