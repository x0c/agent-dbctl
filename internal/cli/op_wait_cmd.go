package cli

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/x0c/agent-dbctl/internal/types"
)

func newOpWaitCmd(ioCtx func() IOContext, version, commit string, exitCode *int) *cobra.Command {
	var opts struct {
		timeout time.Duration
		outPath string
		force   bool
		format  string
		verbose bool
	}
	cmd := &cobra.Command{
		Use:   "wait <operation_id>",
		Short: "Wait until an operation finishes approval/execution or timeout elapses",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			format, err := normalizeExecFormat(opts.format)
			if err != nil {
				*exitCode = ic.WriteError(types.ErrCodeInvalidUsage, false, err.Error(), "Use --format auto, rows, or objects.", nil, nil, types.Meta{})
				return nil
			}
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				*exitCode = writeClientInitErr(ic, err)
				return nil
			}
			timeout := opts.timeout
			if timeout <= 0 {
				timeout = 120 * time.Second
			}
			resp, err := waitForOperationLoop(cmd.Context(), client, args[0], timeout)
			if err != nil {
				*exitCode = writeRPCErr(ic, err)
				return nil
			}
			*exitCode = renderExecOutcomeWithOpts(ic, resp, execRenderOpts{
				outPath:  opts.outPath,
				forceOut: opts.force,
				format:   format,
				verbose:  opts.verbose,
			}, types.Meta{})
			return nil
		},
	}
	cmd.Flags().DurationVar(&opts.timeout, "timeout", 120*time.Second, "Maximum wait duration (1s..10m)")
	cmd.Flags().StringVar(&opts.format, "format", "auto", "Result row format: auto, rows, or objects")
	cmd.Flags().BoolVar(&opts.verbose, "verbose", false, "Include full policy evaluation and preflight plan_raw metadata")
	cmd.Flags().StringVar(&opts.outPath, "out", "", "Write result JSON atomically to file path")
	cmd.Flags().BoolVar(&opts.force, "force", false, "Overwrite existing --out file")
	annotateCommand(cmd, RiskRead, "agent-dbctl op wait op_012345 --timeout 60s --json")
	return cmd
}
