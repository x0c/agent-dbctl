package daemon_test

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/x0c/agent-dbctl/internal/config"
	"github.com/x0c/agent-dbctl/internal/daemon"
	"github.com/x0c/agent-dbctl/internal/policy"
	"github.com/x0c/agent-dbctl/internal/types"
)

var (
	benchTargetDetailsSink []types.TargetDetail
	benchTargetDetailSink  types.TargetDetail
	benchExecRespSink      types.ExecResponse
)

func setupBenchService(b *testing.B, numTargets int) (*daemon.Service, string) {
	b.Helper()
	tmp := b.TempDir()
	b.Setenv(config.EnvConfigHome, tmp)
	b.Setenv(config.EnvSecretBackend, "file")
	b.Setenv(config.EnvNoBrowser, "1")
	b.Setenv(config.EnvSession, "bench-sess")

	paths, err := config.ResolvePaths("bench-sess")
	if err != nil {
		b.Fatal(err)
	}
	svc, err := daemon.NewService(context.Background(), paths, "v0.1.0-bench", "abc")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(svc.Shutdown)

	ctx := context.Background()
	sqlitePath := filepath.Join(tmp, "sample.sqlite")
	rawDB, err := sql.Open("sqlite", "file:"+sqlitePath)
	if err != nil {
		b.Fatal(err)
	}
	if _, err := rawDB.Exec(`CREATE TABLE orders(id INTEGER PRIMARY KEY, status TEXT, total INTEGER); INSERT INTO orders VALUES (1, 'paid', 100), (2, 'open', 200);`); err != nil {
		b.Fatal(err)
	}
	_ = rawDB.Close()

	// Install a couple of builtin rule packs to represent realistic pattern rules.
	for _, packID := range []string{"pg-side-effect", "sqlite-pragma-blob", "mysql-dos-guard"} {
		if _, err := svc.Store().InstallBuiltinRulePack(ctx, "bench", packID, "global", "global"); err != nil {
			b.Fatal(err)
		}
	}

	for i := 0; i < numTargets; i++ {
		sys, err := svc.Store().UpsertSystem(ctx, "bench", types.System{
			Slug:           fmt.Sprintf("sys-%02d", i),
			Name:           fmt.Sprintf("System %02d", i),
			WorkspacePaths: []string{fmt.Sprintf("/tmp/ws-%02d", i)},
			GitRemotes:     []string{fmt.Sprintf("https://github.com/org/repo-%02d.git", i)},
		})
		if err != nil {
			b.Fatal(err)
		}
		roCred, err := svc.Store().UpsertCredentialProfile(ctx, "bench", types.CredentialProfile{
			Name:        fmt.Sprintf("cred-ro-%02d", i),
			Kind:        types.CredKeychain,
			AccessLevel: types.AccessReadOnly,
			Username:    "ro",
		})
		if err != nil {
			b.Fatal(err)
		}
		_ = svc.Secrets().Put(ctx, "cred:"+roCred.ID, "secret-val")

		inst, err := svc.Store().UpsertInstance(ctx, "bench", types.Instance{
			Name:   fmt.Sprintf("inst-%02d", i),
			Engine: "sqlite",
			Host:   sqlitePath,
		})
		if err != nil {
			b.Fatal(err)
		}
		if _, err := svc.Store().UpsertTarget(ctx, "bench", types.Target{
			Ref:             fmt.Sprintf("sys-%02d/dev/main", i),
			Alias:           fmt.Sprintf("alias-%02d", i),
			OwnerSystemID:   sys.ID,
			EnvironmentCode: "dev",
			InstanceID:      inst.ID,
			DatabaseName:    sqlitePath,
			ROCredentialID:  roCred.ID,
			Status:          types.TargetActive,
		}); err != nil {
			b.Fatal(err)
		}
	}
	_ = policy.BuiltinRulePacks()
	return svc, sqlitePath
}

func BenchmarkBuildTargetDetails20(b *testing.B) {
	svc, _ := setupBenchService(b, 20)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		details, err := svc.BuildTargetDetails(ctx, "/tmp/ws-05", "https://github.com/org/repo-05.git")
		if err != nil {
			b.Fatal(err)
		}
		benchTargetDetailsSink = details
	}
}

func BenchmarkResolveTarget20(b *testing.B) {
	svc, _ := setupBenchService(b, 20)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		d, err := svc.ResolveTarget(ctx, "alias-10", "/tmp/ws-10")
		if err != nil {
			b.Fatal(err)
		}
		benchTargetDetailSink = d
	}
}

func BenchmarkExecuteSQLiteDryRun(b *testing.B) {
	svc, _ := setupBenchService(b, 10)
	ctx := context.Background()
	req := types.ExecRequest{
		TargetRefOrAlias: "alias-03",
		Query:            "SELECT id, status, total FROM orders WHERE id = 1 LIMIT 10",
		DryRun:           true,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		resp, err := svc.Execute(ctx, req)
		if err != nil {
			b.Fatal(err)
		}
		benchExecRespSink = resp
	}
}

func BenchmarkExecuteSQLiteLiveRead(b *testing.B) {
	svc, _ := setupBenchService(b, 10)
	ctx := context.Background()
	req := types.ExecRequest{
		TargetRefOrAlias: "alias-03",
		Query:            "SELECT id, status, total FROM orders WHERE id = 1 LIMIT 10",
	}
	// Warm up connection pool.
	if _, err := svc.Execute(ctx, req); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		resp, err := svc.Execute(ctx, req)
		if err != nil {
			b.Fatal(err)
		}
		benchExecRespSink = resp
	}
}
