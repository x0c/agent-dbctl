package cli_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/x0c/agent-dbctl/internal/cli"
	"github.com/x0c/agent-dbctl/internal/config"
	"github.com/x0c/agent-dbctl/internal/types"
)

func buildTestCLI(t *testing.T) string {
	t.Helper()
	name := "agent-dbctl"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	bin := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-ldflags", "-X main.version=v0.9.9 -X main.buildCommit=deadbeef", "-o", bin, "../../cmd/agent-dbctl")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build test CLI: %v\n%s", err, string(out))
	}
	return bin
}

func runCLI(t *testing.T, bin, cfgHome string, args ...string) (int, types.Envelope, string) {
	return runCLIWithExtraEnv(t, bin, cfgHome, []string{config.EnvNoSkillSync + "=1"}, args...)
}

func runCLIWithExtraEnv(t *testing.T, bin, cfgHome string, extraEnv []string, args ...string) (int, types.Envelope, string) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	envVars := append(os.Environ(),
		config.EnvConfigHome+"="+cfgHome,
		config.EnvSecretBackend+"=file",
		config.EnvNoBrowser+"=1",
		config.EnvSession+"=cli-test",
	)
	envVars = append(envVars, extraEnv...)
	cmd.Env = envVars
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("run cli: %v", err)
		}
	}
	var env types.Envelope
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("expected valid JSON envelope on stdout, got parse error %v\nstdout=%s\nstderr=%s", err, stdout.String(), stderr.String())
	}
	return code, env, stderr.String()
}

func TestCLIDualAudienceDescribeAndErrors(t *testing.T) {
	bin := buildTestCLI(t)
	cfgHome := t.TempDir()

	// 1. version --json (even without TTY, non-TTY auto-emits JSON).
	code, env, _ := runCLI(t, bin, cfgHome, "version")
	if code != 0 || !env.OK {
		t.Fatalf("version failed: code=%d env=%+v", code, env)
	}
	dataMap := env.Data.(map[string]any)
	if dataMap["version"] != "v0.9.9" || dataMap["commit"] != "deadbeef" {
		t.Fatalf("ldflags injection check failed: %+v", dataMap)
	}

	// 2. describe exec --json (single-source flag schema).
	code, env, _ = runCLI(t, bin, cfgHome, "describe", "exec", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("describe exec failed: %+v", env)
	}

	// 3. Unknown flag must fail with exit 2 and valid JSON envelope on stdout.
	code, env, _ = runCLI(t, bin, cfgHome, "exec", "--nonexistent-flag")
	if code != types.ExitUsage || env.OK || env.Error == nil || env.Error.Code != types.ErrCodeUnknownFlag {
		t.Fatalf("expected exit 2 unknown_flag envelope, got code=%d env=%+v", code, env)
	}

	// 4. Multi-target write forbidden on exec.
	code, env, _ = runCLI(t, bin, cfgHome, "exec", "--db", "a,b", "--sql", "SELECT 1")
	if code != types.ExitUsage || env.Error == nil || env.Error.Code != types.ErrCodeMultiTargetWrite {
		t.Fatalf("expected multi_target_write_forbidden exit 2, got code=%d env=%+v", code, env)
	}

	// 5. Mutually exclusive --dry-run and --preflight.
	code, env, _ = runCLI(t, bin, cfgHome, "exec", "--db", "x", "--sql", "SELECT 1", "--dry-run", "--preflight")
	if code != types.ExitUsage || env.OK {
		t.Fatalf("expected usage error for mixed --dry-run/--preflight, got code=%d env=%+v", code, env)
	}

	// 6. doctor --json isolated inside cfgHome.
	code, env, _ = runCLI(t, bin, cfgHome, "doctor", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("doctor failed: code=%d env=%+v", code, env)
	}
}

func TestWriteAtomicOutputRefusesSymlinkAndOverwriteWithoutForce(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.txt")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	sym := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, sym); err != nil {
		t.Fatal(err)
	}
	if _, err := cli.WriteAtomicOutput(sym, []byte("{}"), true); err == nil {
		t.Fatalf("expected symlink rejection")
	}

	out := filepath.Join(dir, "result.json")
	if _, err := cli.WriteAtomicOutput(out, []byte(`{"a":1}`), false); err != nil {
		t.Fatalf("initial write failed: %v", err)
	}
	if _, err := cli.WriteAtomicOutput(out, []byte(`{"a":2}`), false); err == nil {
		t.Fatalf("expected refusal to overwrite without --force")
	}
	if _, err := cli.WriteAtomicOutput(out, []byte(`{"a":2}`), true); err != nil {
		t.Fatalf("overwrite with --force failed: %v", err)
	}
}

func TestCLISilentSkillSync(t *testing.T) {
	bin := buildTestCLI(t)
	cfgHome := t.TempDir()
	skillHome := filepath.Join(t.TempDir(), "skills-root")

	extra := []string{
		config.EnvSkillHome + "=" + skillHome,
		config.EnvNoSkillSync + "=",
		config.EnvSkillsAuto + "=",
	}

	// Normal CLI execution should silently install companion SKILL.md with zero stderr noise.
	code, env, stderr := runCLIWithExtraEnv(t, bin, cfgHome, extra, "version", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("version failed: code=%d env=%+v", code, env)
	}
	if stderr != "" {
		t.Fatalf("expected silent auto-sync without stderr output, got: %q", stderr)
	}

	dest := filepath.Join(skillHome, "agent-dbctl", "SKILL.md")
	if _, err := os.Stat(dest); err != nil {
		t.Fatalf("expected auto-installed SKILL.md at %s: %v", dest, err)
	}

	// skill status --json reports current.
	code, env, stderr = runCLIWithExtraEnv(t, bin, cfgHome, extra, "skill", "status", "--json")
	if code != 0 || !env.OK || stderr != "" {
		t.Fatalf("skill status failed: code=%d env=%+v stderr=%q", code, env, stderr)
	}
	data := env.Data.(map[string]any)
	targets := data["targets"].([]any)
	if len(targets) != 1 || targets[0].(map[string]any)["state"] != "current" {
		t.Fatalf("expected target state=current, got %+v", targets)
	}

	// skill uninstall --json removes it cleanly without PersistentPreRun re-installing it.
	code, env, _ = runCLIWithExtraEnv(t, bin, cfgHome, extra, "skill", "uninstall", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("skill uninstall failed: code=%d env=%+v", code, env)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatalf("expected skill uninstalled, err=%v", err)
	}
}

func TestCLIDescribeAuditListExportDoctorLiveAndOps(t *testing.T) {
	bin := buildTestCLI(t)
	cfgHome := t.TempDir()

	// 1. Multi-word unquoted describe + exit_codes + capabilities.
	code, env, _ := runCLI(t, bin, cfgHome, "describe", "db", "list", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("describe db list failed: code=%d env=%+v", code, env)
	}
	data := env.Data.(map[string]any)
	cmds := data["commands"].([]any)
	if len(cmds) != 1 || cmds[0].(map[string]any)["path"] != "agent-dbctl db list" {
		t.Fatalf("unexpected describe db list commands: %+v", cmds)
	}
	if _, ok := data["exit_codes"]; !ok {
		t.Fatalf("expected exit_codes map in describe output")
	}

	code, env, _ = runCLI(t, bin, cfgHome, "capabilities", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("capabilities failed: %+v", env)
	}
	capBytes, _ := json.Marshal(env.Data)
	if !strings.Contains(string(capBytes), `"webhook"`) || !strings.Contains(string(capBytes), `"op_wait"`) {
		t.Fatalf("expected webhook & op_wait in capabilities, got %s", string(capBytes))
	}

	// 2. doctor --json + doctor --live --json (start isolated daemon and clean up).
	t.Cleanup(func() {
		_, _, _ = runCLI(t, bin, cfgHome, "daemon", "stop", "--json")
	})
	code, env, _ = runCLI(t, bin, cfgHome, "doctor", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("doctor failed: code=%d env=%+v", code, env)
	}
	docMap := env.Data.(map[string]any)
	if permOK, _ := docMap["permissions_ok"].(bool); !permOK {
		t.Fatalf("expected permissions_ok=true, got %+v", docMap)
	}

	code, env, _ = runCLI(t, bin, cfgHome, "doctor", "--live", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("doctor --live failed: code=%d env=%+v", code, env)
	}
	liveMap := env.Data.(map[string]any)
	if checked, _ := liveMap["live_checked"].(bool); !checked {
		t.Fatalf("expected live_checked=true, got %+v", liveMap)
	}

	// 3. audit list --json & audit export --format jsonl/csv --out + bad format rejection.
	code, env, _ = runCLI(t, bin, cfgHome, "audit", "list", "--limit", "2", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("audit list failed: code=%d env=%+v", code, env)
	}
	audMap := env.Data.(map[string]any)
	if int(audMap["returned"].(float64)) != 2 || int(audMap["total_matched"].(float64)) < 4 {
		t.Fatalf("unexpected audit list counts: %+v", audMap)
	}

	outCSV := filepath.Join(t.TempDir(), "audit.csv")
	code, env, _ = runCLI(t, bin, cfgHome, "audit", "export", "--format", "csv", "--out", outCSV, "--json")
	if code != 0 || !env.OK {
		t.Fatalf("audit export csv failed: code=%d env=%+v", code, env)
	}
	csvRaw, err := os.ReadFile(outCSV)
	if err != nil || !strings.HasPrefix(string(csvRaw), "seq,id,created_at_utc,") {
		t.Fatalf("unexpected exported CSV: err=%v content=%q", err, string(csvRaw))
	}

	code, env, _ = runCLI(t, bin, cfgHome, "audit", "export", "--format", "xml", "--json")
	if code != types.ExitUsage || env.OK || env.Error == nil || env.Error.Code != types.ErrCodeInvalidUsage {
		t.Fatalf("expected invalid_usage exit 2 for bad export format, got code=%d env=%+v", code, env)
	}

	// 4. op list --limit & op status missing -> ExitNotFound (3) or ExitFailure.
	code, env, _ = runCLI(t, bin, cfgHome, "op", "list", "--limit", "5", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("op list failed: code=%d env=%+v", code, env)
	}
	opMap := env.Data.(map[string]any)
	if int(opMap["limit"].(float64)) != 5 {
		t.Fatalf("expected limit=5 echoed, got %+v", opMap)
	}
}
