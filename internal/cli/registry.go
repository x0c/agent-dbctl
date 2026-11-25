package cli

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/x0c/agent-dbctl/internal/types"
)

// DefaultExitCodes returns the documented OS exit code map exposed by `describe --json`.
func DefaultExitCodes() map[int]string {
	return map[int]string{
		types.ExitSuccess:         "success",
		types.ExitFailure:         "execution_or_internal_error",
		types.ExitUsage:           "usage_or_validation_error",
		types.ExitNotFound:        "not_found",
		types.ExitDenied:          "policy_or_approval_denied",
		types.ExitConflict:        "conflict_or_ambiguity",
		types.ExitTimeout:         "timeout",
		types.ExitWaitingApproval: "waiting_approval",
	}
}

// CommandRisk labels each command's external effect for `describe`.
type CommandRisk string

const (
	RiskRead          CommandRisk = "read"
	RiskWriteLocal    CommandRisk = "write_local"
	RiskExecuteRemote CommandRisk = "execute_remote"
)

// FlagSpec is generated straight from Cobra's FlagSet so describe and parser share one source of truth.
type FlagSpec struct {
	Name      string `json:"name"`
	Shorthand string `json:"shorthand,omitempty"`
	Type      string `json:"type"`
	Default   string `json:"default,omitempty"`
	Usage     string `json:"usage"`
	Hidden    bool   `json:"hidden,omitempty"`
}

// CommandSpec describes a runnable command for `agent-dbctl describe [cmd] --json`.
type CommandSpec struct {
	Path     string      `json:"path"`
	Summary  string      `json:"summary"`
	Risk     CommandRisk `json:"risk"`
	Examples []string    `json:"examples,omitempty"`
	Flags    []FlagSpec  `json:"flags,omitempty"`
}

const riskAnnotationKey = "agent_dbctl_risk"
const exampleAnnotationKey = "agent_dbctl_examples"

func annotateCommand(cmd *cobra.Command, risk CommandRisk, examples string) {
	if cmd.Annotations == nil {
		cmd.Annotations = map[string]string{}
	}
	cmd.Annotations[riskAnnotationKey] = string(risk)
	if examples != "" {
		cmd.Annotations[exampleAnnotationKey] = examples
	}
}

// BuildDescribeSpecs traverses the live Cobra command tree as the single source of truth.
func BuildDescribeSpecs(root *cobra.Command, filterPath string) []CommandSpec {
	filterPath = strings.TrimSpace(filterPath)
	var specs []CommandSpec
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if c.Hidden {
			return
		}
		if c != root && c.Runnable() {
			p := c.CommandPath()
			if filterPath == "" || p == filterPath || c.Name() == filterPath || p == root.Name()+" "+filterPath {
				risk := CommandRisk(c.Annotations[riskAnnotationKey])
				if risk == "" {
					risk = RiskRead
				}
				var flags []FlagSpec
				collectFlags := func(fs *pflag.FlagSet) {
					fs.VisitAll(func(f *pflag.Flag) {
						if f.Hidden {
							return
						}
						flags = append(flags, FlagSpec{
							Name:      "--" + f.Name,
							Shorthand: f.Shorthand,
							Type:      f.Value.Type(),
							Default:   f.DefValue,
							Usage:     f.Usage,
						})
					})
				}
				collectFlags(c.NonInheritedFlags())
				collectFlags(c.InheritedFlags())
				var examples []string
				if ex := c.Annotations[exampleAnnotationKey]; ex != "" {
					for _, line := range strings.Split(ex, "\n") {
						line = strings.TrimSpace(line)
						if line != "" {
							examples = append(examples, line)
						}
					}
				}
				specs = append(specs, CommandSpec{
					Path:     p,
					Summary:  c.Short,
					Risk:     risk,
					Examples: examples,
					Flags:    flags,
				})
			}
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
	return specs
}
