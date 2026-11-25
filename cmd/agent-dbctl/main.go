package main

import (
	_ "embed"
	"os"

	"github.com/x0c/agent-dbctl/internal/cli"
)

var (
	version     = "dev"
	buildCommit = "dev"
)

//go:embed skill.md
var embeddedSkill string

func main() {
	cli.SkillMarkdown = embeddedSkill
	os.Exit(cli.Execute(version, buildCommit))
}
