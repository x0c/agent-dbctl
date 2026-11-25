package skillinstall_test

import (
	"path/filepath"
	"testing"

	"github.com/x0c/agent-dbctl/internal/config"
	"github.com/x0c/agent-dbctl/internal/skillinstall"
)

func BenchmarkAutoSyncSteadyState(b *testing.B) {
	cfgHome := filepath.Join(b.TempDir(), "cfg")
	skillRoot := filepath.Join(b.TempDir(), "skills")
	b.Setenv(config.EnvConfigHome, cfgHome)
	b.Setenv(config.EnvSkillHome, skillRoot)
	b.Setenv(config.EnvNoSkillSync, "")
	b.Setenv(config.EnvSkillsAuto, "")

	const md = "# agent-dbctl\nskill body\n"
	skillinstall.AutoSync("v0.1.0", md)

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		skillinstall.AutoSync("v0.1.0", md)
	}
}

func BenchmarkDetectRuntimeRootsDefault(b *testing.B) {
	b.Setenv(config.EnvSkillHome, "")
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, err := skillinstall.DetectRuntimeRoots()
		if err != nil {
			b.Fatal(err)
		}
	}
}
