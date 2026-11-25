package skillinstall_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/x0c/agent-dbctl/internal/config"
	"github.com/x0c/agent-dbctl/internal/skillinstall"
)

func TestInstallUpdateConflictAndUninstall(t *testing.T) {
	cfgHome := filepath.Join(t.TempDir(), "cfg")
	skillRoot := filepath.Join(t.TempDir(), "agent-skills")
	t.Setenv(config.EnvConfigHome, cfgHome)
	t.Setenv(config.EnvSkillHome, skillRoot)

	const v1 = "# skill v1\nhello\n"
	const v2 = "# skill v2\nupdated\n"

	res, err := skillinstall.Install(skillinstall.InstallOpts{
		Version:       "v0.1.0",
		SkillMarkdown: v1,
	})
	if err != nil {
		t.Fatalf("Install v1: %v", err)
	}
	if res.Status != "applied" || len(res.Actions) != 1 || res.Actions[0].Action != "create" {
		t.Fatalf("unexpected v1 install result: %+v", res)
	}
	dest := filepath.Join(skillRoot, skillinstall.SkillName, "SKILL.md")
	got, err := os.ReadFile(dest)
	if err != nil || string(got) != v1 {
		t.Fatalf("skill file mismatch: got %q, err %v", string(got), err)
	}

	// Idempotent second run should report unchanged.
	res2, err := skillinstall.Install(skillinstall.InstallOpts{
		Version:       "v0.1.0",
		SkillMarkdown: v1,
	})
	if err != nil {
		t.Fatalf("Install idempotent: %v", err)
	}
	if res2.Status != "unchanged" || res2.Actions[0].Action != "unchanged" {
		t.Fatalf("expected unchanged, got %+v", res2)
	}

	// Update when bundled content changes.
	res3, err := skillinstall.Install(skillinstall.InstallOpts{
		Version:       "v0.2.0",
		SkillMarkdown: v2,
	})
	if err != nil {
		t.Fatalf("Install v2: %v", err)
	}
	if res3.Status != "applied" || res3.Actions[0].Action != "update" {
		t.Fatalf("expected update, got %+v", res3)
	}

	// Simulate local user edit -> install without --force preserves modified file.
	if err := os.WriteFile(dest, []byte("# user customized\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	resMod, err := skillinstall.Install(skillinstall.InstallOpts{
		Version:       "v0.3.0",
		SkillMarkdown: v2,
	})
	if err != nil {
		t.Fatalf("Install on modified: %v", err)
	}
	if len(resMod.Conflicts) != 1 || resMod.Conflicts[0].State != "modified" {
		t.Fatalf("expected modified conflict, got %+v", resMod)
	}
	if data, _ := os.ReadFile(dest); string(data) != "# user customized\n" {
		t.Fatalf("user edit was overwritten: %q", string(data))
	}

	// Uninstall must keep user-modified file intact.
	unRes, err := skillinstall.Uninstall(false, "", v2)
	if err != nil {
		t.Fatalf("Uninstall while modified: %v", err)
	}
	if len(unRes.Actions) != 1 || unRes.Actions[0].Action != "keep_modified" {
		t.Fatalf("expected keep_modified, got %+v", unRes)
	}

	// Force install reclaims ownership, then uninstall removes cleanly.
	resForce, err := skillinstall.Install(skillinstall.InstallOpts{
		Force:         true,
		Version:       "v0.3.0",
		SkillMarkdown: v2,
	})
	if err != nil || resForce.Actions[0].Action != "overwrite" {
		t.Fatalf("expected force overwrite, got %+v (err=%v)", resForce, err)
	}
	unClean, err := skillinstall.Uninstall(false, "", v2)
	if err != nil {
		t.Fatalf("Uninstall clean: %v", err)
	}
	if unClean.Actions[0].Action != "remove" {
		t.Fatalf("expected remove, got %+v", unClean)
	}
	if _, err := os.Stat(filepath.Join(skillRoot, skillinstall.SkillName)); !os.IsNotExist(err) {
		t.Fatalf("expected skill dir removed cleanly, err=%v", err)
	}
}

func TestAutoSyncAndKillSwitches(t *testing.T) {
	cfgHome := filepath.Join(t.TempDir(), "cfg")
	skillRoot := filepath.Join(t.TempDir(), "skills")
	t.Setenv(config.EnvConfigHome, cfgHome)
	t.Setenv(config.EnvSkillHome, skillRoot)
	t.Setenv(config.EnvNoSkillSync, "1")
	t.Setenv(config.EnvSkillsAuto, "")

	const content = "# embedded skill\n"
	skillinstall.AutoSync("v0.1.0", content)
	dest := filepath.Join(skillRoot, skillinstall.SkillName, "SKILL.md")
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatalf("AutoSync should not install when %s=1", config.EnvNoSkillSync)
	}

	t.Setenv(config.EnvNoSkillSync, "")
	skillinstall.AutoSync("v0.1.0", content)
	got, err := os.ReadFile(dest)
	if err != nil || string(got) != content {
		t.Fatalf("AutoSync failed to write skill: got %q, err=%v", string(got), err)
	}

	// Fast-path second AutoSync should leave file intact and report current via Status.
	skillinstall.AutoSync("v0.1.0", content)
	st, err := skillinstall.Status("v0.1.0", content, "")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if len(st.Targets) != 1 || st.Targets[0].State != "current" {
		t.Fatalf("expected current status, got %+v", st)
	}
}

func TestEmbeddedSkillMatchesCanonical(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := os.ReadFile(filepath.Join(repoRoot, "skills", "agent-dbctl", "SKILL.md"))
	if err != nil {
		t.Fatalf("read canonical skill: %v", err)
	}
	embedded, err := os.ReadFile(filepath.Join(repoRoot, "cmd", "agent-dbctl", "skill.md"))
	if err != nil {
		t.Fatalf("read embedded skill: %v", err)
	}
	if strings.TrimSpace(string(canonical)) != strings.TrimSpace(string(embedded)) {
		t.Fatalf("cmd/agent-dbctl/skill.md is out of sync with skills/agent-dbctl/SKILL.md; run make sync-skill")
	}
}
