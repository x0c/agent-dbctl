package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/x0c/agent-dbctl/internal/config"
	"github.com/x0c/agent-dbctl/internal/types"
)

func TestRenderExecOutcomeHumanTTYConcise(t *testing.T) {
	t.Run("dry_run_with_patterns_omits_raw_json", func(t *testing.T) {
		var out, errBuf bytes.Buffer
		ic := IOContext{
			Stdout:   &out,
			Stderr:   &errBuf,
			JSONMode: false,
			BinPath:  "agent-dbctl",
		}
		resp := types.ExecResponse{
			Status:          types.OpPending,
			TargetRef:       "orders/dev/main",
			EnvironmentCode: "dev",
			Engine:          "sqlite",
			CredentialMode:  types.AccessReadOnly,
			Classification: types.Classification{
				RiskLevel:  types.RiskHighCostRead,
				IsReadOnly: true,
				RiskFlags:  []string{"missing_where"},
			},
			Evaluation: types.PolicyEvaluation{
				Decision:       types.DecisionRequireApproval,
				TriggerReasons: []string{"pattern_rule:confirm-secret-ledger"},
				MatchedRules: []types.MatchedRule{
					{
						RuleName:        "confirm-secret-ledger",
						ConfirmTitle:    "Sensitive Ledger",
						Action:          types.PatternActionRequireApproval,
						Scope:           "target:orders/dev/main",
						MatchedFragment: "secret_ledger",
					},
				},
			},
		}
		code := renderExecOutcome(ic, resp, "", false, types.Meta{DryRun: true})
		if code != types.ExitSuccess {
			t.Fatalf("expected ExitSuccess, got %d", code)
		}
		got := out.String()
		for _, want := range []string{
			"Target:    orders/dev/main (dev, sqlite)",
			"Mode:      dry-run",
			"Risk:      high_cost_read (read_only=true)",
			"Flags:     missing_where",
			"Decision:  require_approval (credential=read_only)",
			"Reasons:   pattern_rule:confirm-secret-ledger",
			"confirm-secret-ledger (Sensitive Ledger) [require_approval, target:orders/dev/main]: secret_ledger",
		} {
			if !strings.Contains(got, want) {
				t.Fatalf("expected %q in output:\n%s", want, got)
			}
		}
		if strings.Contains(got, "effective_policy") || strings.Contains(got, "plan_raw") {
			t.Fatalf("human TTY output must not dump raw policy/plan JSON:\n%s", got)
		}
	})

	t.Run("preflight_suppresses_plan_raw_and_shows_summary_and_warnings", func(t *testing.T) {
		var out, errBuf bytes.Buffer
		ic := IOContext{
			Stdout:   &out,
			Stderr:   &errBuf,
			JSONMode: false,
		}
		resp := types.ExecResponse{
			Status:          types.OpPending,
			TargetRef:       "alphaforge/prod/mongo",
			EnvironmentCode: "prod",
			Engine:          "mongodb",
			CredentialMode:  types.AccessReadOnly,
			Classification: types.Classification{
				RiskLevel:  types.RiskHighCostRead,
				IsReadOnly: true,
				RiskFlags:  []string{"empty_filter_no_limit"},
			},
			Preflight: &types.PreflightReport{
				Supported:     true,
				FullScan:      true,
				EstimatedRows: 50000,
				PlanSummary:   "COLLSCAN on users",
				Warnings:      []string{"Full collection scan detected"},
				PlanRaw: map[string]any{
					"very_large_nested_explain": "SHOULD_NOT_APPEAR_IN_TTY",
				},
			},
			Evaluation: types.PolicyEvaluation{
				Decision:       types.DecisionRequireApproval,
				TriggerReasons: []string{"preflight_full_scan"},
			},
		}
		code := renderExecOutcome(ic, resp, "", false, types.Meta{Preflight: true})
		if code != types.ExitSuccess {
			t.Fatalf("expected ExitSuccess, got %d", code)
		}
		got := out.String()
		for _, want := range []string{
			"Mode:      preflight",
			"Preflight: supported=true full_scan=true est_rows=50000",
			"Plan:      COLLSCAN on users",
			"Warnings:  Full collection scan detected",
		} {
			if !strings.Contains(got, want) {
				t.Fatalf("expected %q in output:\n%s", want, got)
			}
		}
		if strings.Contains(got, "SHOULD_NOT_APPEAR_IN_TTY") || strings.Contains(got, "plan_raw") {
			t.Fatalf("preflight TTY output leaked raw plan JSON:\n%s", got)
		}
	})

	t.Run("preflight_unsupported_mongosh_warning_and_empty_exec_result", func(t *testing.T) {
		var out bytes.Buffer
		ic := IOContext{Stdout: &out, Stderr: &out, JSONMode: false}
		resp := types.ExecResponse{
			Status:          types.OpPending,
			TargetRef:       "alphaforge/prod/mongo",
			EnvironmentCode: "prod",
			Engine:          "mongodb",
			CredentialMode:  types.AccessReadOnly,
			Classification:  types.Classification{RiskLevel: types.RiskSafeRead, IsReadOnly: true},
			Preflight: &types.PreflightReport{
				Supported: false,
				Warnings:  []string{`MongoDB preflight requires JSON RunCommand syntax (e.g. {"find": "coll", "filter": {}, "limit": 20}).`},
			},
			Evaluation: types.PolicyEvaluation{Decision: types.DecisionAllow},
		}
		renderExecOutcome(ic, resp, "", false, types.Meta{Preflight: true})
		if !strings.Contains(out.String(), "Preflight: supported=false full_scan=false est_rows=0") ||
			!strings.Contains(out.String(), "Warnings:  MongoDB preflight requires JSON RunCommand syntax") {
			t.Fatalf("unexpected unsupported preflight output:\n%s", out.String())
		}

		out.Reset()
		renderExecOutcome(ic, types.ExecResponse{
			Status: types.OpSucceeded,
			Result: &types.ExecResult{ReturnedRows: 0, LatencyMs: 4},
		}, "", false, types.Meta{})
		if strings.TrimSpace(out.String()) != "OK (0 row(s), 4ms)" {
			t.Fatalf("unexpected empty result summary: %q", out.String())
		}
	})
}

func TestExecPositionalQueryConflictAndFallback(t *testing.T) {
	name := "agent-dbctl"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	bin := filepath.Join(t.TempDir(), name)
	build := exec.Command("go", "build", "-o", bin, "../../cmd/agent-dbctl")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, string(out))
	}

	cfgHome := t.TempDir()
	run := func(args ...string) (int, types.Envelope) {
		t.Helper()
		cmd := exec.Command(bin, args...)
		cmd.Env = append(os.Environ(),
			config.EnvConfigHome+"="+cfgHome,
			config.EnvSecretBackend+"=file",
			config.EnvNoBrowser+"=1",
			config.EnvNoSkillSync+"=1",
			config.EnvSession+"=cli-pos-test",
		)
		var stdout bytes.Buffer
		cmd.Stdout = &stdout
		err := cmd.Run()
		code := 0
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else {
				t.Fatal(err)
			}
		}
		var env types.Envelope
		if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
			t.Fatalf("unmarshal stdout %q: %v", stdout.String(), err)
		}
		return code, env
	}

	// Combining positional query + --sql rejects cleanly with usage error.
	code, env := run("exec", "--db", "orders/dev/main", "--sql", "SELECT 1", "SELECT 2")
	if code != types.ExitUsage || env.Error == nil || env.Error.Code != types.ErrCodeInvalidUsage {
		t.Fatalf("expected invalid_usage on conflicting --sql + positional arg, got code=%d env=%+v", code, env)
	}

	// Positional query reaches target resolution (db_not_found rather than missing query input).
	code, env = run("exec", "--db", "nonexistent-db", "--dry-run", "SELECT 1")
	if code != types.ExitNotFound || env.Error == nil || env.Error.Code != types.ErrCodeDBNotFound {
		t.Fatalf("expected positional query to reach target lookup (db_not_found), got code=%d env=%+v", code, env)
	}
}
