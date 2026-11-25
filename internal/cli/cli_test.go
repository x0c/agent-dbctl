package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/x0c/agent-dbctl/internal/cli"
	"github.com/x0c/agent-dbctl/internal/config"
	"github.com/x0c/agent-dbctl/internal/daemon"
	"github.com/x0c/agent-dbctl/internal/store"
	"github.com/x0c/agent-dbctl/internal/types"
)

func buildTestCLIWithVersion(t *testing.T, ver, commit string) string {
	t.Helper()
	name := "agent-dbctl"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	bin := filepath.Join(t.TempDir(), name)
	ldflags := "-X main.version=" + ver + " -X main.buildCommit=" + commit
	cmd := exec.Command("go", "build", "-ldflags", ldflags, "-o", bin, "../../cmd/agent-dbctl")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build test CLI (%s %s): %v\n%s", ver, commit, err, string(out))
	}
	return bin
}

func buildTestCLI(t *testing.T) string {
	t.Helper()
	return buildTestCLIWithVersion(t, "v0.9.9", "deadbeef")
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

func TestCLIAgentErgonomicsSchemaCompactFormatAndWaitDefault(t *testing.T) {
	bin := buildTestCLI(t)
	cfgHome := t.TempDir()
	dbFile := filepath.Join(t.TempDir(), "agent-ergo.sqlite")

	// Seed catalog targets in isolated cfgHome store before launching CLI/daemon.
	st, err := store.Open(context.Background(), filepath.Join(cfgHome, "agent-dbctl.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	sys, err := st.UpsertSystem(context.Background(), "test", types.System{Slug: "shop", Name: "Shop"})
	if err != nil {
		t.Fatal(err)
	}
	inst, err := st.UpsertInstance(context.Background(), "test", types.Instance{Name: "shop-sqlite", Engine: "sqlite", Host: dbFile})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertTarget(context.Background(), "test", types.Target{
		Ref:             "shop/dev/main",
		Alias:           "dev-shop",
		OwnerSystemID:   sys.ID,
		EnvironmentCode: "dev",
		InstanceID:      inst.ID,
		DatabaseName:    dbFile,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertTarget(context.Background(), "test", types.Target{
		Ref:             "shop/prod/main",
		Alias:           "prod-shop",
		OwnerSystemID:   sys.ID,
		EnvironmentCode: "prod",
		InstanceID:      inst.ID,
		DatabaseName:    dbFile,
	}); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()

	t.Cleanup(func() {
		_, _, _ = runCLI(t, bin, cfgHome, "daemon", "stop", "--json")
	})

	// 1. db list defaults to compact TargetSummary, while --detail returns TargetDetail.
	code, env, _ := runCLI(t, bin, cfgHome, "db", "list", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("db list failed: code=%d env=%+v", code, env)
	}
	items := env.Data.(map[string]any)["items"].([]any)
	if len(items) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(items))
	}
	firstCompact := items[0].(map[string]any)
	if _, hasPolicy := firstCompact["effective_policy"]; hasPolicy {
		t.Fatalf("compact db list must omit effective_policy, got %+v", firstCompact)
	}
	if firstCompact["ref"] == nil || firstCompact["safety_tier"] == nil {
		t.Fatalf("compact db list missing core fields: %+v", firstCompact)
	}

	code, env, _ = runCLI(t, bin, cfgHome, "db", "list", "--detail", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("db list --detail failed: code=%d env=%+v", code, env)
	}
	firstDetail := env.Data.(map[string]any)["items"].([]any)[0].(map[string]any)
	if _, hasPolicy := firstDetail["effective_policy"]; !hasPolicy {
		t.Fatalf("db list --detail must include effective_policy, got %+v", firstDetail)
	}

	// 2. db show defaults to TargetShowSummary with examples.
	code, env, _ = runCLI(t, bin, cfgHome, "db", "show", "dev-shop", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("db show failed: code=%d env=%+v", code, env)
	}
	showMap := env.Data.(map[string]any)
	if _, hasExamples := showMap["examples"]; !hasExamples {
		t.Fatalf("expected examples in compact db show, got %+v", showMap)
	}
	if _, hasSources := showMap["effective_policy"]; hasSources {
		t.Fatalf("compact db show must omit effective_policy, got %+v", showMap)
	}

	// 3. Seed table via exec, then inspect via db schema.
	code, env, _ = runCLI(t, bin, cfgHome, "exec", "--db", "dev-shop", "CREATE TABLE items(id INTEGER PRIMARY KEY, title TEXT NOT NULL); INSERT INTO items(id, title) VALUES (1, 'alpha'), (2, 'beta');", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("seed exec failed: code=%d env=%+v", code, env)
	}

	code, env, _ = runCLI(t, bin, cfgHome, "describe", "db", "schema", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("describe db schema failed: code=%d env=%+v", code, env)
	}

	code, env, _ = runCLI(t, bin, cfgHome, "db", "schema", "dev-shop", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("db schema list failed: code=%d env=%+v", code, env)
	}
	schemaItems := env.Data.(map[string]any)["items"].([]any)
	if len(schemaItems) != 1 || schemaItems[0].(map[string]any)["name"] != "items" {
		t.Fatalf("unexpected db schema items: %+v", schemaItems)
	}

	code, env, _ = runCLI(t, bin, cfgHome, "db", "schema", "dev-shop", "items", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("db schema items failed: code=%d env=%+v", code, env)
	}
	cols := env.Data.(map[string]any)["columns"].([]any)
	if len(cols) != 2 {
		t.Fatalf("expected 2 columns in db schema items, got %+v", cols)
	}

	// 4. exec compact JSON vs --format objects vs --verbose.
	code, env, _ = runCLI(t, bin, cfgHome, "exec", "--db", "dev-shop", "SELECT * FROM items LIMIT 2", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("compact exec failed: code=%d env=%+v", code, env)
	}
	execMap := env.Data.(map[string]any)
	if _, hasEval := execMap["evaluation"]; hasEval {
		t.Fatalf("default compact exec must omit evaluation, got %+v", execMap)
	}
	if len(execMap["rows"].([]any)) != 2 || execMap["truncated"] != false {
		t.Fatalf("unexpected compact exec rows/truncated: %+v", execMap)
	}

	code, env, _ = runCLI(t, bin, cfgHome, "exec", "--db", "dev-shop", "--format", "objects", "SELECT id, title FROM items ORDER BY id", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("format objects exec failed: code=%d env=%+v", code, env)
	}
	objMap := env.Data.(map[string]any)
	recs := objMap["records"].([]any)
	if len(recs) != 2 || recs[0].(map[string]any)["title"] != "alpha" {
		t.Fatalf("unexpected --format objects records: %+v", objMap)
	}

	code, env, _ = runCLI(t, bin, cfgHome, "exec", "--db", "dev-shop", "--verbose", "SELECT id FROM items LIMIT 1", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("verbose exec failed: code=%d env=%+v", code, env)
	}
	if _, hasEval := env.Data.(map[string]any)["evaluation"]; !hasEval {
		t.Fatalf("verbose exec must include evaluation, got %+v", env.Data)
	}

	// 5. Bounded indexed prod SELECT passes without approval; prod UPDATE defaults to --wait=false in non-TTY (exit 7).
	code, env, _ = runCLI(t, bin, cfgHome, "exec", "--db", "prod-shop", "SELECT * FROM items WHERE id = 1 LIMIT 2", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("bounded indexed prod SELECT should succeed without approval, got code=%d env=%+v", code, env)
	}

	code, env, _ = runCLI(t, bin, cfgHome, "exec", "--db", "prod-shop", "--reason", "Update row", "UPDATE items SET title = 'gamma' WHERE id = 1", "--json")
	if code != types.ExitWaitingApproval || env.OK || env.Error == nil || env.Error.Code != types.ErrCodeWaitingApproval {
		t.Fatalf("expected non-TTY exec on prod write to default --wait=false and exit 7, got code=%d env=%+v", code, env)
	}
	if len(env.Error.NextCommands) == 0 || !strings.Contains(env.Error.NextCommands[0], "op wait") {
		t.Fatalf("expected op wait in next_commands, got %+v", env.Error.NextCommands)
	}

	// 6. driver_error returns actionable hint + db schema recovery command without blank approval fields.
	code, env, _ = runCLI(t, bin, cfgHome, "exec", "--db", "dev-shop", "SELECT missing_col FROM items LIMIT 1", "--json")
	if code != types.ExitFailure || env.OK || env.Error == nil || env.Error.Code != types.ErrCodeDriverError {
		t.Fatalf("expected driver_error exit 1, got code=%d env=%+v", code, env)
	}
	if env.Error.Hint == "" || len(env.Error.NextCommands) == 0 || !strings.Contains(env.Error.NextCommands[0], "db schema") {
		t.Fatalf("expected actionable db schema hint/next_commands on missing column, got %+v", env.Error)
	}
	if _, hasBlankApproval := env.Error.Context["approval_id"]; hasBlankApproval {
		t.Fatalf("driver_error context should omit blank approval_id, got %+v", env.Error.Context)
	}
}

func TestCLIRequireReasonForApprovalAndDisableToggle(t *testing.T) {
	bin := buildTestCLI(t)
	cfgHome := t.TempDir()
	dbFile := filepath.Join(t.TempDir(), "reason.sqlite")

	st, err := store.Open(context.Background(), filepath.Join(cfgHome, "agent-dbctl.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	sys, err := st.UpsertSystem(context.Background(), "test", types.System{Slug: "core", Name: "Core"})
	if err != nil {
		t.Fatal(err)
	}
	inst, err := st.UpsertInstance(context.Background(), "test", types.Instance{Name: "core-sqlite", Engine: "sqlite", Host: dbFile})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertTarget(context.Background(), "test", types.Target{
		Ref:             "core/prod/main",
		Alias:           "prod-core",
		OwnerSystemID:   sys.ID,
		EnvironmentCode: "prod",
		InstanceID:      inst.ID,
		DatabaseName:    dbFile,
	}); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()

	t.Cleanup(func() {
		_, _, _ = runCLI(t, bin, cfgHome, "daemon", "stop", "--json")
	})

	// Approval-requiring write without --reason must fail fast with exit 2 (reason_required) and recovery command.
	code, env, _ := runCLI(t, bin, cfgHome, "exec", "--db", "prod-core", "CREATE TABLE t(id INTEGER PRIMARY KEY)", "--json")
	if code != types.ExitUsage || env.OK || env.Error == nil || env.Error.Code != types.ErrCodeReasonRequired {
		t.Fatalf("expected reason_required exit 2 when --reason is omitted, got code=%d env=%+v", code, env)
	}
	if env.Error.Hint == "" || len(env.Error.NextCommands) == 0 || !strings.Contains(env.Error.NextCommands[0], "--reason") {
		t.Fatalf("expected actionable --reason hint and next_commands, got %+v", env.Error)
	}

	// Dry-run still works without --reason.
	code, env, _ = runCLI(t, bin, cfgHome, "exec", "--db", "prod-core", "--dry-run", "CREATE TABLE t(id INTEGER PRIMARY KEY)", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("dry-run without --reason should succeed, got code=%d env=%+v", code, env)
	}

	// With --reason, approval submission succeeds and returns exit 7 (waiting_approval).
	code, env, _ = runCLI(t, bin, cfgHome, "exec", "--db", "prod-core", "--reason", "Bootstrap table t", "CREATE TABLE t(id INTEGER PRIMARY KEY)", "--json")
	if code != types.ExitWaitingApproval || env.OK || env.Error == nil || env.Error.Code != types.ErrCodeWaitingApproval {
		t.Fatalf("expected waiting_approval exit 7 when --reason is provided, got code=%d env=%+v", code, env)
	}
}

func TestDaemonVersionUpgradeAutoRestartAndDowngradeProtection(t *testing.T) {
	binV1 := buildTestCLIWithVersion(t, "v0.1.0", "c85d5fe")
	binV2 := buildTestCLIWithVersion(t, "v0.2.0", "6961753")
	binV2New := buildTestCLIWithVersion(t, "v0.2.0", "7777777")
	cfgHome := t.TempDir()
	sessEnv := []string{
		config.EnvNoSkillSync + "=1",
		config.EnvSession + "=upgrade-test",
	}

	t.Cleanup(func() {
		_, _, _ = runCLIWithExtraEnv(t, binV2New, cfgHome, sessEnv, "daemon", "stop", "--json")
	})

	// 1. Start v0.1.0 daemon.
	code, env, _ := runCLIWithExtraEnv(t, binV1, cfgHome, sessEnv, "daemon", "start", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("v0.1.0 daemon start failed: code=%d env=%+v", code, env)
	}
	pid1 := int(env.Data.(map[string]any)["pid"].(float64))
	if pid1 <= 0 {
		t.Fatalf("expected positive pid1, got %v", pid1)
	}

	// 2. Running v0.2.0 ui open --no-open auto-restarts stale v0.1.0 daemon and succeeds.
	code, env, _ = runCLIWithExtraEnv(t, binV2, cfgHome, sessEnv, "ui", "open", "--no-open", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("v0.2.0 ui open failed: code=%d env=%+v", code, env)
	}
	uiData := env.Data.(map[string]any)
	if webURL, _ := uiData["web_url"].(string); !strings.HasPrefix(webURL, "http://127.0.0.1:") {
		t.Fatalf("expected local web_url, got %+v", uiData)
	}

	code, env, _ = runCLIWithExtraEnv(t, binV2, cfgHome, sessEnv, "daemon", "status", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("daemon status failed: code=%d env=%+v", code, env)
	}
	st := env.Data.(map[string]any)
	pid2 := int(st["pid"].(float64))
	if st["version"] != "v0.2.0" || st["commit"] != "6961753" || pid2 == pid1 {
		t.Fatalf("expected daemon upgraded to v0.2.0 with new pid, got %+v (pid1=%d)", st, pid1)
	}
	for range 20 {
		if !daemon.IsProcessAlive(pid1) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if daemon.IsProcessAlive(pid1) {
		t.Fatalf("expected old daemon pid1=%d to exit cleanly", pid1)
	}

	// 3. Invoking older v0.1.0 binary against newer v0.2.0 daemon refuses silent downgrade (exit 5).
	code, env, _ = runCLIWithExtraEnv(t, binV1, cfgHome, sessEnv, "ui", "open", "--no-open", "--json")
	if code != types.ExitConflict || env.OK || env.Error == nil || env.Error.Code != types.ErrCodeDaemonVersionMismatch {
		t.Fatalf("expected daemon_version_mismatch (exit 5) when downgrading, got code=%d env=%+v", code, env)
	}

	// 4. AGENT_DBCTL_NO_DAEMON_SPAWN=1 prevents auto-restart on commit mismatch.
	noSpawnEnv := append(append([]string(nil), sessEnv...), config.EnvNoDaemonSpawn+"=1")
	code, env, _ = runCLIWithExtraEnv(t, binV2New, cfgHome, noSpawnEnv, "ui", "open", "--no-open", "--json")
	if code != types.ExitConflict || env.OK || env.Error == nil || env.Error.Code != types.ErrCodeDaemonVersionMismatch {
		t.Fatalf("expected daemon_version_mismatch with NO_DAEMON_SPAWN=1, got code=%d env=%+v", code, env)
	}

	// 5. Same base version with different commit auto-restarts when auto-spawn is enabled.
	code, env, _ = runCLIWithExtraEnv(t, binV2New, cfgHome, sessEnv, "ui", "open", "--no-open", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("v0.2.0 commit-upgrade ui open failed: code=%d env=%+v", code, env)
	}
	code, env, _ = runCLIWithExtraEnv(t, binV2New, cfgHome, sessEnv, "daemon", "status", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("daemon status after commit upgrade failed: code=%d env=%+v", code, env)
	}
	if env.Data.(map[string]any)["commit"] != "7777777" {
		t.Fatalf("expected commit updated to 7777777, got %+v", env.Data)
	}
}

func TestCLIOnboardingCatalogPolicyAndAuditActor(t *testing.T) {
	bin := buildTestCLI(t)
	cfgHome := t.TempDir()
	dbFile := filepath.Join(t.TempDir(), "onboarding.sqlite")
	if err := os.WriteFile(dbFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	topoFile := filepath.Join(t.TempDir(), "exported.yaml")

	t.Cleanup(func() {
		_, _, _ = runCLI(t, bin, cfgHome, "daemon", "stop", "--json")
	})

	// 1. Offline discovery: topology schema, capabilities, describe.
	code, env, _ := runCLI(t, bin, cfgHome, "capabilities", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("capabilities failed: code=%d env=%+v", code, env)
	}
	caps := env.Data.(map[string]any)
	engines := caps["builtin_engines"].([]any)
	if len(engines) < 9 {
		t.Fatalf("expected >=9 builtin engines in capabilities, got %+v", engines)
	}

	code, env, _ = runCLI(t, bin, cfgHome, "topology", "schema", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("topology schema failed: code=%d env=%+v", code, env)
	}

	code, env, _ = runCLI(t, bin, cfgHome, "describe", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("describe failed: code=%d env=%+v", code, env)
	}
	rawDesc, _ := json.Marshal(env.Data)
	for _, wantCmd := range []string{"db add", "topology apply", "cred set", "policy set", "pattern set", "security set", "driver list"} {
		if !strings.Contains(string(rawDesc), wantCmd) {
			t.Fatalf("expected describe --json to include %q", wantCmd)
		}
	}

	// 2. Empty `db list` provides onboarding guidance; `driver list` shows guides.
	code, env, _ = runCLI(t, bin, cfgHome, "db", "list", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("empty db list failed: code=%d env=%+v", code, env)
	}
	emptyList := env.Data.(map[string]any)
	if int(emptyList["count"].(float64)) != 0 || emptyList["hint"] == "" {
		t.Fatalf("expected onboarding hint on empty db list, got %+v", emptyList)
	}

	code, env, _ = runCLI(t, bin, cfgHome, "driver", "list", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("driver list failed: code=%d env=%+v", code, env)
	}

	// 3. `db add --dry-run` plans without writing catalog or audit rows.
	code, env, _ = runCLI(t, bin, cfgHome, "db", "add",
		"--dsn", "postgres://reader@127.0.0.1:5432/app",
		"--system", "billing", "--env", "dev", "--alias", "billing-pg-dev", "--dry-run", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("db add --dry-run failed: code=%d env=%+v", code, env)
	}
	code, env, _ = runCLI(t, bin, cfgHome, "db", "list", "--json")
	if code != 0 || int(env.Data.(map[string]any)["count"].(float64)) != 0 {
		t.Fatalf("expected zero targets after --dry-run, got %+v", env.Data)
	}

	// 4. `db add` with blank keychain password emits MissingSecrets + setup_url and converges on re-run.
	code, env, _ = runCLI(t, bin, cfgHome, "db", "add",
		"--dsn", "postgres://reader@127.0.0.1:5432/app",
		"--system", "billing", "--env", "dev", "--alias", "billing-pg-dev", "--cred-name", "billing-pg-ro", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("db add failed: code=%d env=%+v", code, env)
	}
	addMap := env.Data.(map[string]any)
	if addMap["status"] != "created" {
		t.Fatalf("expected created status, got %+v", addMap)
	}
	msList, ok := addMap["missing_secrets"].([]any)
	if !ok || len(msList) != 1 {
		t.Fatalf("expected 1 missing secret info, got %+v", addMap)
	}
	setupURL, _ := msList[0].(map[string]any)["setup_url"].(string)
	if !strings.Contains(setupURL, "/catalog?subtab=credentials&credential=") {
		t.Fatalf("unexpected credential setup_url: %q", setupURL)
	}

	// Idempotent second `db add` converges cleanly to unchanged.
	code, env, _ = runCLI(t, bin, cfgHome, "db", "add",
		"--dsn", "postgres://reader@127.0.0.1:5432/app",
		"--system", "billing", "--env", "dev", "--alias", "billing-pg-dev", "--cred-name", "billing-pg-ro", "--json")
	if code != 0 || !env.OK || env.Data.(map[string]any)["status"] != "unchanged" {
		t.Fatalf("expected unchanged on idempotent db add, got code=%d env=%+v", code, env)
	}

	// 5. `ui open --credential` builds matching URL; `cred set --secret-env` stores secret without leaking it.
	code, env, _ = runCLI(t, bin, cfgHome, "ui", "open", "--credential", "billing-pg-ro", "--no-open", "--json")
	if code != 0 || !env.OK || env.Data.(map[string]any)["web_url"] != setupURL {
		t.Fatalf("ui open --credential mismatch: got %+v vs %q", env, setupURL)
	}
	const superSecret = "sUp3r-Secr3t-CLI-Token"
	code, env, stderrStr := runCLIWithExtraEnv(t, bin, cfgHome,
		[]string{config.EnvNoSkillSync + "=1", "TEST_CLI_DB_SECRET=" + superSecret},
		"cred", "set", "billing-pg-ro", "--secret-env", "TEST_CLI_DB_SECRET", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("cred set --secret-env failed: code=%d env=%+v stderr=%s", code, env, stderrStr)
	}
	credRaw, _ := json.Marshal(env)
	if strings.Contains(string(credRaw), superSecret) || strings.Contains(stderrStr, superSecret) {
		t.Fatalf("secret leaked in cred set output!")
	}
	if !env.Data.(map[string]any)["item"].(map[string]any)["has_secret"].(bool) {
		t.Fatalf("expected has_secret=true after cred set, got %+v", env.Data)
	}

	// 6. Onboard SQLite target with `--test`, execute SQL, mutate via `db set`, delete via ref containing `/`.
	code, env, _ = runCLI(t, bin, cfgHome, "db", "add",
		"--engine", "sqlite", "--host", dbFile, "--system", "billing", "--env", "dev", "--alias", "billing-sqlite", "--test", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("sqlite db add --test failed: code=%d env=%+v", code, env)
	}
	sqliteRes := env.Data.(map[string]any)
	sqliteRef := sqliteRes["target"].(map[string]any)["ref"].(string)
	if !sqliteRes["ping"].(map[string]any)["reachable"].(bool) {
		t.Fatalf("expected reachable sqlite ping, got %+v", sqliteRes)
	}
	code, env, _ = runCLI(t, bin, cfgHome, "exec", "--db", "billing-sqlite", "SELECT 42 AS answer", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("sqlite exec failed: code=%d env=%+v", code, env)
	}
	code, env, _ = runCLI(t, bin, cfgHome, "db", "set", "billing-sqlite", "--description", "updated by cli", "--json")
	if code != 0 || !env.OK || env.Data.(map[string]any)["status"] != "updated" {
		t.Fatalf("db set failed: code=%d env=%+v", code, env)
	}

	// 7. System / Env / Network / Instance / Security / Policy / Pattern / Approval inspection.
	for _, cmdArgs := range [][]string{
		{"system", "set", "billing", "--owner", "fintech", "--json"},
		{"env", "set", "uat", "--safety-tier", "guarded", "--json"},
		{"network", "set", "direct-corp", "--mode", "direct", "--tls-mode", "require", "--json"},
		{"instance", "list", "--json"},
		{"security", "get", "--json"},
		{"security", "set", "--max-rows", "400", "--json"},
		{"policy", "set", "billing-guard", "--scope-type", "system", "--scope-id", "billing", "--max-rows", "250", "--json"},
		{"pattern", "set", "deny-drop-uat", "--scope-type", "env", "--scope-id", "uat", "--action", "deny", "--regex", `\bDROP\b`, "--json"},
		{"pattern", "test", "--db", "billing-sqlite", "SELECT 1", "--json"},
		{"approval", "list", "--json"},
	} {
		code, env, stderrStr = runCLI(t, bin, cfgHome, cmdArgs...)
		if code != 0 || !env.OK {
			t.Fatalf("command %v failed: code=%d env=%+v stderr=%s", cmdArgs, code, env, stderrStr)
		}
	}

	// 8. Export YAML topology, dry-run apply, real apply, then delete slash ref target.
	code, env, _ = runCLI(t, bin, cfgHome, "topology", "export", "--format", "yaml", "--out", topoFile, "--json")
	if code != 0 || !env.OK {
		t.Fatalf("topology export failed: code=%d env=%+v", code, env)
	}
	code, env, _ = runCLI(t, bin, cfgHome, "topology", "apply", "-f", topoFile, "--dry-run", "--json")
	if code != 0 || !env.OK || env.Data.(map[string]any)["status"] != "unchanged" {
		t.Fatalf("topology apply --dry-run failed: code=%d env=%+v", code, env)
	}
	code, env, _ = runCLI(t, bin, cfgHome, "db", "delete", sqliteRef, "--yes", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("db delete %q failed: code=%d env=%+v", sqliteRef, code, env)
	}

	// 9. Verify audit actor attribution (`agent-cli`), zero secret leaks, and intact hash chain.
	code, env, _ = runCLI(t, bin, cfgHome, "audit", "list", "--actor", "agent-cli", "--limit", "50", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("audit list failed: code=%d env=%+v", code, env)
	}
	audItems := env.Data.(map[string]any)["items"].([]any)
	if len(audItems) < 5 {
		t.Fatalf("expected >=5 agent-cli audit entries, got %d", len(audItems))
	}
	audRaw, _ := json.Marshal(audItems)
	if strings.Contains(string(audRaw), superSecret) {
		t.Fatalf("secret leaked in audit logs!")
	}
	code, env, _ = runCLI(t, bin, cfgHome, "audit", "verify", "--json")
	if code != 0 || !env.OK || !env.Data.(map[string]any)["valid"].(bool) {
		t.Fatalf("audit verify failed: code=%d env=%+v", code, env)
	}
}

func TestCLISystemGitRemoteAndWorktreeResolution(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not available")
	}
	bin := buildTestCLI(t)
	cfgHome := t.TempDir()
	t.Cleanup(func() {
		_, _, _ = runCLI(t, bin, cfgHome, "daemon", "stop", "--json")
	})

	repoBase := t.TempDir()
	mainRepo := filepath.Join(repoBase, "orders-repo")
	wtRepo := filepath.Join(repoBase, "wt-hotfix-77")
	runGit := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Test",
			"GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=Test",
			"GIT_COMMITTER_EMAIL=test@example.com",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, out)
		}
	}
	if err := os.MkdirAll(mainRepo, 0o755); err != nil {
		t.Fatal(err)
	}
	runGit(mainRepo, "init")
	runGit(mainRepo, "remote", "add", "origin", "git@github.com:acme/orders-service.git")
	if err := os.WriteFile(filepath.Join(mainRepo, "README.md"), []byte("orders\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(mainRepo, "add", "README.md")
	runGit(mainRepo, "commit", "-m", "init")
	runGit(mainRepo, "worktree", "add", "-b", "hotfix-77", wtRepo)

	dbFile := filepath.Join(t.TempDir(), "orders.sqlite")
	if err := os.WriteFile(dbFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	// Run `db add` inside mainRepo without --system: should derive slug from git repo and bind normalized remote.
	runInDir := func(dir string, args ...string) (int, types.Envelope) {
		t.Helper()
		cmd := exec.Command(bin, args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			config.EnvConfigHome+"="+cfgHome,
			config.EnvSecretBackend+"=file",
			config.EnvNoBrowser+"=1",
			config.EnvSession+"=cli-test",
			config.EnvNoSkillSync+"=1",
		)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		code := 0
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else {
				t.Fatalf("run cli in %s: %v", dir, err)
			}
		}
		var env types.Envelope
		if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
			t.Fatalf("invalid json in %s: %v\nstdout=%s\nstderr=%s", dir, err, stdout.String(), stderr.String())
		}
		return code, env
	}

	code, env := runInDir(mainRepo, "db", "add", "--engine", "sqlite", "--host", dbFile, "--env", "dev", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("db add in git repo failed: code=%d env=%+v", code, env)
	}
	targetMap := env.Data.(map[string]any)["target"].(map[string]any)
	if targetMap["system"] != "orders-service" {
		t.Fatalf("expected system=orders-service, got %+v", targetMap)
	}

	// Run `db list` inside the separate git worktree: workspace_match must be true!
	code, env = runInDir(wtRepo, "db", "list", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("db list in worktree failed: code=%d env=%+v", code, env)
	}
	items := env.Data.(map[string]any)["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["workspace_match"] != true {
		t.Fatalf("expected workspace_match=true in git worktree, got %+v", items)
	}

	// Verify `system set --git-remote` normalizes and persists remotes cleanly.
	code, env = runInDir(wtRepo, "system", "set", "orders-service", "--git-remote", "https://github.com/acme/orders-service.git", "--git-remote", "ssh://git@git.example.com:2222/acme/orders-alt.git", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("system set --git-remote failed: code=%d env=%+v", code, env)
	}
	sysItem := env.Data.(map[string]any)["item"].(map[string]any)
	remotes := sysItem["git_remotes"].([]any)
	if len(remotes) != 2 || remotes[0] != "github.com/acme/orders-service" || remotes[1] != "git.example.com:2222/acme/orders-alt" {
		t.Fatalf("unexpected normalized git_remotes: %+v", remotes)
	}
}

func TestCLIFrictionFixesAndPatternPartialUpdate(t *testing.T) {
	bin := buildTestCLI(t)
	cfgHome := t.TempDir()

	runCLI := func(args ...string) (int, types.Envelope) {
		t.Helper()
		cmd := exec.Command(bin, args...)
		cmd.Env = append(os.Environ(),
			config.EnvConfigHome+"="+cfgHome,
			config.EnvSecretBackend+"=file",
			config.EnvNoBrowser+"=1",
			config.EnvSession+"=cli-friction-test",
			config.EnvNoSkillSync+"=1",
		)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		code := 0
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else {
				t.Fatalf("run %v: %v", args, err)
			}
		}
		var env types.Envelope
		if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
			t.Fatalf("invalid json for %v: %v\nstdout=%s\nstderr=%s", args, err, stdout.String(), stderr.String())
		}
		return code, env
	}

	dbFile := filepath.Join(t.TempDir(), "friction.db")
	// 1. Missing env without --safety-tier includes actionable hint and next_commands.
	code, env := runCLI("db", "add", "--engine", "sqlite", "--host", dbFile, "--env", "staging-missing", "--no-workspace", "--json")
	if code == 0 || env.OK || env.Error == nil || len(env.Error.NextCommands) == 0 || !strings.Contains(env.Error.Hint, "--safety-tier") {
		t.Fatalf("expected missing env hint and next_commands, got code=%d env=%+v", code, env)
	}

	// 2. Inline --safety-tier creates environment + sets --scan-read-mode in one `db add` call.
	code, env = runCLI("db", "add", "--engine", "sqlite", "--host", dbFile, "--system", "orders", "--env", "uat", "--safety-tier", "guarded", "--scan-read-mode", "reason_only", "--alias", "uat-orders", "--no-workspace", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("inline env db add failed: code=%d env=%+v", code, env)
	}
	tgtSummary := env.Data.(map[string]any)["target"].(map[string]any)
	if tgtSummary["safety_tier"] != "guarded" || tgtSummary["scan_read_mode"] != "reason_only" {
		t.Fatalf("unexpected inline env target summary: %+v", tgtSummary)
	}

	// 3. `db set --scan-read-mode allow` updates scan_read_mode cleanly.
	code, env = runCLI("db", "set", "uat-orders", "--scan-read-mode", "allow", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("db set --scan-read-mode failed: code=%d env=%+v", code, env)
	}
	code, env = runCLI("db", "show", "uat-orders", "--json")
	if code != 0 || !env.OK || env.Data.(map[string]any)["scan_read_mode"] != "allow" {
		t.Fatalf("expected db show scan_read_mode=allow, got code=%d env=%+v", code, env)
	}

	// 4. `pattern set` partial flag update (`--enabled=false`) preserves existing Condition & Action.
	code, env = runCLI("pattern", "set", "block-full-update", "--scope-type", "env", "--scope-id", "uat", "--action", "deny", "--regex", `\bUPDATE\b`, "--json")
	if code != 0 || !env.OK {
		t.Fatalf("pattern set create failed: code=%d env=%+v", code, env)
	}
	code, env = runCLI("pattern", "set", "block-full-update", "--enabled=false", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("pattern set partial disable failed: code=%d env=%+v", code, env)
	}
	item := env.Data.(map[string]any)["item"].(map[string]any)
	cond := item["condition"].(map[string]any)
	if item["enabled"] != false || item["action"] != "deny" || item["scope_type"] != "env" || cond["pattern"] != `\bUPDATE\b` {
		t.Fatalf("expected partial pattern set to preserve condition/action/scope, got %+v", item)
	}

	// 5. `db test` surfaces concrete driver error in error.message, and `db delete` reports orphans including custom `env delete`.
	t.Setenv("AGENT_DBCTL_TEST_KB_PASS", "pw")
	code, env = runCLI("db", "add", "--engine", "kingbase", "--host", "127.0.0.1", "--port", "59999", "--database", "kb", "--system", "kbcli", "--env", "legacy/qa", "--safety-tier", "guarded", "--user", "system", "--secret-env", "AGENT_DBCTL_TEST_KB_PASS", "--alias", "kb-qa", "--no-workspace", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("kingbase db add failed: code=%d env=%+v", code, env)
	}
	code, env = runCLI("db", "test", "kb-qa", "--json")
	if code == 0 || env.OK || env.Error == nil || !strings.Contains(env.Error.Message, "kbcli/legacy/qa/kb") || strings.Contains(env.Error.Message, "unsupported sslmode") {
		t.Fatalf("expected db test error.message to include concrete target ref and driver error (and not sslmode=prefer), got code=%d env=%+v err=%+v", code, env, env.Error)
	}
	code, env = runCLI("db", "delete", "kb-qa", "--yes", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("db delete failed: code=%d env=%+v", code, env)
	}
	orphans, _ := env.Data.(map[string]any)["orphans"].([]any)
	if len(orphans) < 2 {
		t.Fatalf("expected orphaned assets reported on db delete, got %+v", env.Data)
	}
	code, env = runCLI("env", "delete", "legacy/qa", "--yes", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("env delete legacy/qa failed: code=%d env=%+v", code, env)
	}
}
