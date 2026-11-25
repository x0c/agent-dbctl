package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/x0c/agent-dbctl/internal/approval"
	"github.com/x0c/agent-dbctl/internal/config"
	"github.com/x0c/agent-dbctl/internal/daemon"
	drvplugin "github.com/x0c/agent-dbctl/internal/driver/plugin"
	"github.com/x0c/agent-dbctl/internal/secrets"
	"github.com/x0c/agent-dbctl/internal/skillinstall"
	"github.com/x0c/agent-dbctl/internal/store"
	"github.com/x0c/agent-dbctl/internal/types"
)

// SkillMarkdown holds the embedded companion SKILL.md template printed by `skill print`.
var SkillMarkdown string

type globalOpts struct {
	jsonOut bool
	noColor bool
	noInput bool
	session string
}

// Execute builds the root CLI command, executes it, and returns the OS exit code.
func Execute(version, commit string) int {
	var g globalOpts
	var exitCode int

	root := &cobra.Command{
		Use:           "agent-dbctl",
		Short:         "Database execution gate, enterprise catalog, and audit CLI for coding agents",
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRun: func(cmd *cobra.Command, _ []string) {
			switch cmd.CommandPath() {
			case "agent-dbctl skill install", "agent-dbctl skill status", "agent-dbctl skill uninstall", "agent-dbctl skill print":
				return
			}
			if cmd.Parent() != nil && cmd.Parent().Name() == "completion" {
				return
			}
			skillinstall.AutoSync(version, SkillMarkdown)
		},
	}
	root.PersistentFlags().BoolVar(&g.jsonOut, "json", false, "Output structured JSON envelope")
	root.PersistentFlags().BoolVar(&g.noColor, "no-color", false, "Disable ANSI colors")
	root.PersistentFlags().BoolVar(&g.noInput, "no-input", false, "Disable interactive prompts")
	root.PersistentFlags().BoolVar(&g.noInput, "non-interactive", false, "Alias for --no-input")
	root.PersistentFlags().StringVar(&g.session, "session", "", "Daemon session name (or AGENT_DBCTL_SESSION)")
	_ = root.PersistentFlags().MarkHidden("non-interactive")

	ioCtx := func() IOContext {
		sess := g.session
		if sess == "" {
			sess = os.Getenv(config.EnvSession)
		}
		if sess == "" {
			sess = "default"
		}
		return DetectIO(g.jsonOut, g.noColor, g.noInput, version, sess)
	}

	// ---- db ----
	dbCmd := &cobra.Command{Use: "db", Short: "Discover and inspect configured databases (read-only)"}
	var dbListOpts struct {
		system string
		env    string
		engine string
		tag    string
		search string
	}
	dbListCmd := &cobra.Command{
		Use:   "list",
		Short: "List databases (prioritizes systems matching current workspace)",
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				exitCode = writeClientInitErr(ic, err)
				return nil
			}
			cwd, _ := os.Getwd()
			var res struct {
				Items             []types.TargetDetail `json:"items"`
				SimilarNames      []string             `json:"similar_names"`
				UnsearchedSources []string             `json:"unsearched_sources"`
			}
			err = client.DoJSON(cmd.Context(), http.MethodPost, "/rpc/v1/db/list", daemon.ListFilter{
				System:       dbListOpts.system,
				Env:          dbListOpts.env,
				Engine:       dbListOpts.engine,
				Tag:          dbListOpts.tag,
				Search:       dbListOpts.search,
				WorkspaceCWD: cwd,
			}, &res)
			if err != nil {
				exitCode = writeRPCErr(ic, err)
				return nil
			}
			if ic.JSONMode {
				exitCode = ic.WriteSuccess(map[string]any{
					"items":              res.Items,
					"count":              len(res.Items),
					"similar_names":      res.SimilarNames,
					"unsearched_sources": res.UnsearchedSources,
				}, types.Meta{})
				return nil
			}
			if len(res.Items) == 0 {
				_, _ = fmt.Fprintln(ic.Stdout, "No matching databases found.")
				if len(res.SimilarNames) > 0 {
					_, _ = fmt.Fprintf(ic.Stdout, "Similar: %s\n", strings.Join(res.SimilarNames, ", "))
				}
				return nil
			}
			rows := make([][]string, 0, len(res.Items))
			for _, d := range res.Items {
				wsMark := ""
				if d.WorkspaceMatch {
					wsMark = "*"
				}
				sysSlug := ""
				if d.OwnerSystem != nil {
					sysSlug = d.OwnerSystem.Slug
				}
				eng := ""
				if d.Instance != nil {
					eng = d.Instance.Engine
				}
				rows = append(rows, []string{wsMark + d.Target.Ref, d.Target.Alias, sysSlug, d.Target.EnvironmentCode, eng, string(d.EffectivePolicy.SafetyTier)})
			}
			renderTable(ic.Stdout, []string{"REF", "ALIAS", "SYSTEM", "ENV", "ENGINE", "TIER"}, rows)
			return nil
		},
	}
	dbListCmd.Flags().StringVar(&dbListOpts.system, "system", "", "Filter by system slug or ID")
	dbListCmd.Flags().StringVar(&dbListOpts.env, "env", "", "Filter by comma-separated environments")
	dbListCmd.Flags().StringVar(&dbListOpts.engine, "engine", "", "Filter by database engine")
	dbListCmd.Flags().StringVar(&dbListOpts.tag, "tag", "", "Filter by system tag")
	dbListCmd.Flags().StringVar(&dbListOpts.search, "search", "", "Substring search across ref/alias/description")
	dbListCmd.Flags().StringVar(&dbListOpts.search, "grep", "", "Alias for --search")
	_ = dbListCmd.Flags().MarkHidden("grep")
	annotateCommand(dbListCmd, RiskRead, "agent-dbctl db list --env prod --json")

	dbShowCmd := &cobra.Command{
		Use:   "show <ref-or-alias>",
		Short: "Show target metadata and effective policy provenance",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				exitCode = writeClientInitErr(ic, err)
				return nil
			}
			cwd, _ := os.Getwd()
			var detail types.TargetDetail
			err = client.DoJSON(cmd.Context(), http.MethodPost, "/rpc/v1/db/show", map[string]string{
				"target":        args[0],
				"workspace_cwd": cwd,
			}, &detail)
			if err != nil {
				exitCode = writeRPCErr(ic, err)
				return nil
			}
			if ic.JSONMode {
				exitCode = ic.WriteSuccess(detail, types.Meta{})
				return nil
			}
			eng, endpoint, netLabel := "—", "—", "direct"
			if detail.Instance != nil {
				eng = detail.Instance.Engine
				if eng == "sqlite" {
					endpoint = detail.Instance.Host
				} else {
					endpoint = fmt.Sprintf("%s:%d", detail.Instance.Host, detail.Instance.Port)
				}
			}
			if detail.NetworkProfile != nil {
				netLabel = fmt.Sprintf("%s (%s)", detail.NetworkProfile.Name, detail.NetworkProfile.Mode)
			}
			roName, rwName := "—", "—"
			if detail.ROCredential != nil {
				roName = detail.ROCredential.Name
			}
			if detail.RWCredential != nil {
				rwName = detail.RWCredential.Name
			}
			_, _ = fmt.Fprintf(ic.Stdout,
				"Ref:       %s (alias: %s)\nStatus:    %s\nEnv:       %s (%s)\nEngine:    %s\nEndpoint:  %s\nDatabase:  %s\nNetwork:   %s\nCreds:     ro=%s, rw=%s\nTimeout:   %ds (%s)\nMaxRows:   %d (%s)\nMaxBytes:  %d (%s)\nExplain:   max_rows=%d (%s)\nMultiStmt: %v\n",
				detail.Target.Ref, detail.Target.Alias, detail.Target.Status,
				detail.Target.EnvironmentCode, detail.EffectivePolicy.SafetyTier,
				eng, endpoint, detail.Target.DatabaseName, netLabel, roName, rwName,
				detail.EffectivePolicy.ExecTimeoutSec, detail.EffectivePolicy.Sources["exec_timeout_sec"],
				detail.EffectivePolicy.MaxRows, detail.EffectivePolicy.Sources["max_rows"],
				detail.EffectivePolicy.MaxBytes, detail.EffectivePolicy.Sources["max_bytes"],
				detail.EffectivePolicy.ExplainMaxRows, detail.EffectivePolicy.Sources["explain_max_rows"],
				detail.EffectivePolicy.AllowMultiStatement)
			if len(detail.EffectivePolicy.PatternRules) > 0 {
				_, _ = fmt.Fprintf(ic.Stdout, "Patterns:  %d active rule(s)\n", len(detail.EffectivePolicy.PatternRules))
			}
			return nil
		},
	}
	annotateCommand(dbShowCmd, RiskRead, "agent-dbctl db show prod-orders --json")

	var dbTestAll bool
	var dbTestEnv, dbTestSys string
	dbTestCmd := &cobra.Command{
		Use:   "test [ref-or-alias]",
		Short: "Probe live database connectivity",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			if !dbTestAll && len(args) == 0 {
				exitCode = ic.WriteError(types.ErrCodeInvalidUsage, false, "Target ref/alias or --all is required.", "", nil, []string{ic.BinPath + " db list --json"}, types.Meta{})
				return nil
			}
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				exitCode = writeClientInitErr(ic, err)
				return nil
			}
			cwd, _ := os.Getwd()
			target := ""
			if len(args) == 1 {
				target = args[0]
			}
			var res struct {
				Results []types.PingResult `json:"results"`
			}
			err = client.DoJSON(cmd.Context(), http.MethodPost, "/rpc/v1/db/test", map[string]any{
				"target": target,
				"all":    dbTestAll,
				"filter": daemon.ListFilter{System: dbTestSys, Env: dbTestEnv, WorkspaceCWD: cwd},
			}, &res)
			if err != nil {
				exitCode = writeRPCErr(ic, err)
				return nil
			}
			reachableCount := 0
			for _, r := range res.Results {
				if r.Reachable {
					reachableCount++
				}
			}
			partial := len(res.Results) > 1 && reachableCount > 0 && reachableCount < len(res.Results)
			if ic.JSONMode {
				if reachableCount == 0 && len(res.Results) > 0 {
					exitCode = ic.WriteError(types.ErrCodeDriverError, true, "All tested database targets are unreachable.", "Inspect per-target errors in context and verify network/credentials.", map[string]any{"results": res.Results}, []string{ic.BinPath + " doctor --live --json"}, types.Meta{Partial: partial})
					return nil
				}
				exitCode = ic.WriteSuccess(map[string]any{"results": res.Results}, types.Meta{Partial: partial})
				return nil
			}
			rows := make([][]string, 0, len(res.Results))
			for _, r := range res.Results {
				rows = append(rows, []string{r.TargetRef, r.Engine, fmt.Sprintf("%v", r.Reachable), fmt.Sprintf("%dms", r.LatencyMs), r.ServerVersion, r.Error})
			}
			renderTable(ic.Stdout, []string{"TARGET", "ENGINE", "REACHABLE", "LATENCY", "VERSION", "ERROR"}, rows)
			if reachableCount == 0 && len(res.Results) > 0 {
				exitCode = types.ExitFailure
			}
			return nil
		},
	}
	dbTestCmd.Flags().BoolVar(&dbTestAll, "all", false, "Test all matching databases")
	dbTestCmd.Flags().StringVar(&dbTestSys, "system", "", "Filter --all by system")
	dbTestCmd.Flags().StringVar(&dbTestEnv, "env", "", "Filter --all by environment")
	annotateCommand(dbTestCmd, RiskExecuteRemote, "agent-dbctl db test --all --json")

	dbCmd.AddCommand(dbListCmd, dbShowCmd, dbTestCmd)

	// ---- exec ----
	var execOpts struct {
		db       string
		sql      string
		file     string
		stdin    bool
		reason   string
		dryRun   bool
		preflight bool
		maxRows  int
		maxBytes int64
		timeout  time.Duration
		out      string
		force    bool
		wait     bool
	}
	execCmd := &cobra.Command{
		Use:   "exec [query]",
		Short: "Execute verbatim SQL, MongoDB, or Redis commands through environment guardrails",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			if strings.TrimSpace(execOpts.db) == "" {
				exitCode = ic.WriteError(types.ErrCodeInvalidUsage, false, "--db is required.", "Run db list first to pick a target ref or alias.", nil, []string{ic.BinPath + " db list --json"}, types.Meta{})
				return nil
			}
			if strings.Contains(execOpts.db, ",") || strings.EqualFold(strings.TrimSpace(execOpts.db), "all") {
				exitCode = ic.WriteError(types.ErrCodeMultiTargetWrite, false, "exec targets exactly one database at a time.", "Pass a single target ref or alias to --db.", nil, []string{ic.BinPath + " db list --json"}, types.Meta{})
				return nil
			}
			if execOpts.dryRun && execOpts.preflight {
				exitCode = ic.WriteError(types.ErrCodeInvalidUsage, false, "--dry-run and --preflight are mutually exclusive.", "Use --dry-run for offline checks or --preflight for live EXPLAIN.", nil, nil, types.Meta{})
				return nil
			}

			inlineQuery := execOpts.sql
			if len(args) == 1 {
				if execOpts.sql != "" || execOpts.file != "" || execOpts.stdin {
					exitCode = ic.WriteError(types.ErrCodeInvalidUsage, false, "Specify query via --sql, --file, --stdin, or a single positional argument, not multiple.", "", nil, nil, types.Meta{})
					return nil
				}
				inlineQuery = args[0]
			}

			query, err := readQueryInput(inlineQuery, execOpts.file, execOpts.stdin, ic.StdinIsTTY)
			if err != nil {
				exitCode = ic.WriteError(types.ErrCodeInvalidInput, false, err.Error(), "Pass --sql, --file, positional query, or pipe query to stdin.", nil, nil, types.Meta{})
				return nil
			}

			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				exitCode = writeClientInitErr(ic, err)
				return nil
			}
			cwd, _ := os.Getwd()
			tSec := int(execOpts.timeout.Seconds())
			start := time.Now()

			var resp types.ExecResponse
			err = client.DoJSON(cmd.Context(), http.MethodPost, "/rpc/v1/exec", types.ExecRequest{
				TargetRefOrAlias: execOpts.db,
				Query:            query,
				Reason:           execOpts.reason,
				Actor:            "agent-cli",
				WorkspaceCWD:     cwd,
				DryRun:           execOpts.dryRun,
				Preflight:        execOpts.preflight,
				MaxRows:          execOpts.maxRows,
				MaxBytes:         execOpts.maxBytes,
				TimeoutSec:       tSec,
				Wait:             execOpts.wait,
			}, &resp)
			if err != nil {
				exitCode = writeRPCErr(ic, err)
				return nil
			}
			meta := types.Meta{
				DurationMs: time.Since(start).Milliseconds(),
				DryRun:     execOpts.dryRun,
				Preflight:  execOpts.preflight,
			}

			exitCode = renderExecOutcome(ic, resp, execOpts.out, execOpts.force, meta)
			return nil
		},
	}
	execCmd.Flags().StringVar(&execOpts.db, "db", "", "Target database ref or alias (aliases: --target/--source)")
	execCmd.Flags().StringVar(&execOpts.db, "target", "", "Alias for --db")
	execCmd.Flags().StringVar(&execOpts.db, "source", "", "Alias for --db")
	_ = execCmd.Flags().MarkHidden("target")
	_ = execCmd.Flags().MarkHidden("source")

	execCmd.Flags().StringVar(&execOpts.sql, "sql", "", "Verbatim SQL/command text (aliases: --query/--cmd)")
	execCmd.Flags().StringVar(&execOpts.sql, "query", "", "Alias for --sql")
	execCmd.Flags().StringVar(&execOpts.sql, "cmd", "", "Alias for --sql")
	_ = execCmd.Flags().MarkHidden("query")
	_ = execCmd.Flags().MarkHidden("cmd")

	execCmd.Flags().StringVar(&execOpts.file, "file", "", "Read verbatim query from file")
	execCmd.Flags().BoolVar(&execOpts.stdin, "stdin", false, "Read verbatim query from stdin")
	execCmd.Flags().StringVar(&execOpts.reason, "reason", "", "Business reason shown on Web approval and audit log")
	execCmd.Flags().BoolVar(&execOpts.dryRun, "dry-run", false, "Offline risk & policy analysis only (never dials DB)")
	execCmd.Flags().BoolVar(&execOpts.preflight, "preflight", false, "Remote read-only EXPLAIN check without execution")
	execCmd.Flags().IntVar(&execOpts.maxRows, "max-rows", 0, "Cap returned rows (alias: --limit)")
	execCmd.Flags().IntVar(&execOpts.maxRows, "limit", 0, "Alias for --max-rows")
	_ = execCmd.Flags().MarkHidden("limit")
	execCmd.Flags().Int64Var(&execOpts.maxBytes, "max-bytes", 0, "Cap returned bytes")
	execCmd.Flags().DurationVar(&execOpts.timeout, "timeout", 0, "Execution timeout override (capped by policy)")
	execCmd.Flags().StringVar(&execOpts.out, "out", "", "Write result JSON atomically to file path")
	execCmd.Flags().BoolVar(&execOpts.force, "force", false, "Overwrite existing --out file")
	execCmd.Flags().BoolVar(&execOpts.wait, "wait", true, "Wait for human approval (false returns operation_id immediately)")
	annotateCommand(execCmd, RiskExecuteRemote, "agent-dbctl exec --db prod-orders --preflight --sql \"SELECT id FROM orders LIMIT 20\" --json")

	// ---- op ----
	opCmd := &cobra.Command{Use: "op", Short: "Inspect or cancel execution operations"}
	var opStatusOut string
	var opStatusForce bool
	opStatusCmd := &cobra.Command{
		Use:   "status <operation_id>",
		Short: "Check status and retrieve result of an operation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				exitCode = writeClientInitErr(ic, err)
				return nil
			}
			var resp types.ExecResponse
			if err := client.DoJSON(cmd.Context(), http.MethodGet, "/rpc/v1/ops/"+url.PathEscape(args[0]), nil, &resp); err != nil {
				exitCode = writeRPCErr(ic, err)
				return nil
			}
			exitCode = renderExecOutcome(ic, resp, opStatusOut, opStatusForce, types.Meta{})
			return nil
		},
	}
	opStatusCmd.Flags().StringVar(&opStatusOut, "out", "", "Write result JSON atomically to file path")
	opStatusCmd.Flags().BoolVar(&opStatusForce, "force", false, "Overwrite existing --out file")
	annotateCommand(opStatusCmd, RiskRead, "agent-dbctl op status op_012345 --json")

	var opListTarget, opListEnv, opListSystem, opListStatus string
	var opListLimit int
	opListCmd := &cobra.Command{
		Use:   "list",
		Short: "List recent operations",
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				exitCode = writeClientInitErr(ic, err)
				return nil
			}
			limit := opListLimit
			if limit <= 0 {
				limit = 50
			} else if limit > 500 {
				limit = 500
			}
			q := url.Values{}
			if opListTarget != "" {
				q.Set("target", opListTarget)
			}
			if opListEnv != "" {
				q.Set("env", opListEnv)
			}
			if opListSystem != "" {
				q.Set("system", opListSystem)
			}
			if opListStatus != "" {
				q.Set("status", opListStatus)
			}
			q.Set("limit", fmt.Sprintf("%d", limit))

			var res struct {
				Items []types.Operation `json:"items"`
			}
			path := "/rpc/v1/ops?" + q.Encode()
			if err := client.DoJSON(cmd.Context(), http.MethodGet, path, nil, &res); err != nil {
				exitCode = writeRPCErr(ic, err)
				return nil
			}
			if ic.JSONMode {
				exitCode = ic.WriteSuccess(map[string]any{
					"items":     res.Items,
					"count":     len(res.Items),
					"limit":     limit,
					"truncated": len(res.Items) >= limit,
				}, types.Meta{})
				return nil
			}
			rows := make([][]string, 0, len(res.Items))
			for _, op := range res.Items {
				rows = append(rows, []string{op.ID, op.TargetRef, op.EnvironmentCode, string(op.RiskLevel), string(op.Status), fmt.Sprintf("%dms", op.LatencyMs)})
			}
			renderTable(ic.Stdout, []string{"OP_ID", "TARGET", "ENV", "RISK", "STATUS", "LATENCY"}, rows)
			return nil
		},
	}
	opListCmd.Flags().StringVar(&opListTarget, "db", "", "Filter by target ref or alias")
	opListCmd.Flags().StringVar(&opListEnv, "env", "", "Filter by environment code")
	opListCmd.Flags().StringVar(&opListSystem, "system", "", "Filter by system slug")
	opListCmd.Flags().StringVar(&opListStatus, "status", "", "Filter by status")
	opListCmd.Flags().IntVar(&opListLimit, "limit", 50, "Maximum operations to return (1..500)")
	annotateCommand(opListCmd, RiskRead, "agent-dbctl op list --json")

	opCancelCmd := &cobra.Command{
		Use:   "cancel <operation_id>",
		Short: "Cancel a waiting approval or running operation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				exitCode = writeClientInitErr(ic, err)
				return nil
			}
			var resp types.ExecResponse
			if err := client.DoJSON(cmd.Context(), http.MethodPost, "/rpc/v1/ops/"+url.PathEscape(args[0])+"/cancel", map[string]any{}, &resp); err != nil {
				exitCode = writeRPCErr(ic, err)
				return nil
			}
			exitCode = ic.WriteSuccess(resp, types.Meta{})
			if !ic.JSONMode {
				_, _ = fmt.Fprintf(ic.Stdout, "Cancelled %s (%s)\n", resp.OperationID, resp.Status)
			}
			return nil
		},
	}
	annotateCommand(opCancelCmd, RiskExecuteRemote, "agent-dbctl op cancel op_012345 --json")
	opWaitCmd := newOpWaitCmd(ioCtx, version, commit, &exitCode)
	opCmd.AddCommand(opStatusCmd, opListCmd, opCancelCmd, opWaitCmd)

	// ---- ui ----
	uiCmd := &cobra.Command{Use: "ui", Short: "Open the local human Web Console"}
	var uiNoOpen bool
	uiOpenCmd := &cobra.Command{
		Use:   "open",
		Short: "Start daemon if needed and open the local Web Console",
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				exitCode = writeClientInitErr(ic, err)
				return nil
			}
			id, err := client.GetIdentity(cmd.Context())
			if err != nil {
				exitCode = writeRPCErr(ic, err)
				return nil
			}
			if !uiNoOpen && os.Getenv(config.EnvNoBrowser) != "1" {
				_ = approval.OpenBrowser(id.WebURL)
			}
			if ic.JSONMode {
				exitCode = ic.WriteSuccess(map[string]any{"web_url": id.WebURL, "session": id.Session}, types.Meta{})
				return nil
			}
			_, _ = fmt.Fprintf(ic.Stdout, "Web Console: %s\n", id.WebURL)
			return nil
		},
	}
	uiOpenCmd.Flags().BoolVar(&uiNoOpen, "no-open", false, "Print URL without opening browser")
	annotateCommand(uiOpenCmd, RiskWriteLocal, "agent-dbctl ui open")
	uiCmd.AddCommand(uiOpenCmd)

	// ---- daemon ----
	daemonCmd := &cobra.Command{Use: "daemon", Short: "Manage the local agent-dbctl daemon"}
	var servePort string
	daemonServeCmd := &cobra.Command{
		Use:    "serve",
		Short:  "Run daemon in foreground",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			paths, err := config.ResolvePaths(ic.Session)
			if err != nil {
				return err
			}
			srv, err := daemon.StartServer(cmd.Context(), paths, version, commit, servePort)
			if err != nil {
				return err
			}
			return srv.Run(cmd.Context())
		},
	}
	daemonServeCmd.Flags().StringVar(&servePort, "web-port", "", "Pin local web port")

	daemonStartCmd := &cobra.Command{
		Use:   "start",
		Short: "Start background daemon for current session",
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				exitCode = writeClientInitErr(ic, err)
				return nil
			}
			id, err := client.GetIdentity(cmd.Context())
			if err != nil {
				exitCode = writeRPCErr(ic, err)
				return nil
			}
			if ic.JSONMode {
				exitCode = ic.WriteSuccess(id, types.Meta{})
				return nil
			}
			_, _ = fmt.Fprintf(ic.Stdout, "Daemon running (pid=%d, version=%s, web=%s)\n", id.PID, id.Version, id.WebURL)
			return nil
		},
	}
	annotateCommand(daemonStartCmd, RiskWriteLocal, "agent-dbctl daemon start --json")

	daemonStatusCmd := &cobra.Command{
		Use:   "status",
		Short: "Check running daemon identity and version",
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			paths, err := config.ResolvePaths(ic.Session)
			if err != nil {
				exitCode = ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{})
				return nil
			}
			client, err := daemon.NewClient(paths)
			if err != nil {
				exitCode = ic.WriteError(types.ErrCodeDaemonUnavailable, true, "Daemon is not running for session "+ic.Session, "Start it with daemon start.", nil, []string{ic.BinPath + " daemon start --json"}, types.Meta{})
				return nil
			}
			id, err := client.GetIdentity(cmd.Context())
			if err != nil {
				exitCode = ic.WriteError(types.ErrCodeDaemonUnavailable, true, "Daemon socket unresponsive: "+err.Error(), "", nil, []string{ic.BinPath + " daemon restart --json"}, types.Meta{})
				return nil
			}
			if ic.JSONMode {
				exitCode = ic.WriteSuccess(id, types.Meta{})
				return nil
			}
			_, _ = fmt.Fprintf(ic.Stdout, "PID: %d\nVersion: %s (%s)\nSession: %s\nWeb: %s\n", id.PID, id.Version, id.Commit, id.Session, id.WebURL)
			return nil
		},
	}
	annotateCommand(daemonStatusCmd, RiskRead, "agent-dbctl daemon status --json")

	daemonStopCmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop the running session daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			paths, err := config.ResolvePaths(ic.Session)
			if err != nil {
				exitCode = ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{})
				return nil
			}
			if err := stopDaemon(cmd.Context(), paths); err != nil {
				exitCode = ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{})
				return nil
			}
			if ic.JSONMode {
				exitCode = ic.WriteSuccess(map[string]bool{"stopped": true}, types.Meta{})
				return nil
			}
			_, _ = fmt.Fprintln(ic.Stdout, "Daemon stopped.")
			return nil
		},
	}
	annotateCommand(daemonStopCmd, RiskWriteLocal, "agent-dbctl daemon stop --json")

	daemonRestartCmd := &cobra.Command{
		Use:   "restart",
		Short: "Restart the session daemon with the current binary version",
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			paths, err := config.ResolvePaths(ic.Session)
			if err != nil {
				exitCode = ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{})
				return nil
			}
			_ = stopDaemon(cmd.Context(), paths)
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				exitCode = writeClientInitErr(ic, err)
				return nil
			}
			id, err := client.GetIdentity(cmd.Context())
			if err != nil {
				exitCode = writeRPCErr(ic, err)
				return nil
			}
			if ic.JSONMode {
				exitCode = ic.WriteSuccess(id, types.Meta{})
				return nil
			}
			_, _ = fmt.Fprintf(ic.Stdout, "Daemon restarted (pid=%d, version=%s, web=%s)\n", id.PID, id.Version, id.WebURL)
			return nil
		},
	}
	annotateCommand(daemonRestartCmd, RiskWriteLocal, "agent-dbctl daemon restart --json")

	daemonCmd.AddCommand(daemonServeCmd, daemonStartCmd, daemonStatusCmd, daemonStopCmd, daemonRestartCmd)

	// ---- plugin ----
	pluginCmd := &cobra.Command{Use: "plugin", Short: "Inspect and verify Tier-3 external driver plugins"}
	pluginListCmd := &cobra.Command{
		Use:   "list",
		Short: "List built-in drivers and discovered external plugins",
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			paths, err := config.ResolvePaths(ic.Session)
			if err != nil {
				exitCode = ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{})
				return nil
			}
			plugins, err := drvplugin.ScanPlugins(paths.PluginsDir)
			if err != nil {
				exitCode = ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{})
				return nil
			}
			if ic.JSONMode {
				exitCode = ic.WriteSuccess(map[string]any{"plugins_dir": paths.PluginsDir, "plugins": plugins}, types.Meta{})
				return nil
			}
			rows := make([][]string, 0, len(plugins))
			for _, p := range plugins {
				rows = append(rows, []string{p.Manifest.ID, p.Manifest.Engine, p.Manifest.Version, fmt.Sprintf("%v", p.Verified), p.VerificationErr})
			}
			renderTable(ic.Stdout, []string{"ID", "ENGINE", "VERSION", "VERIFIED", "ERROR"}, rows)
			return nil
		},
	}
	annotateCommand(pluginListCmd, RiskRead, "agent-dbctl plugin list --json")

	pluginVerifyCmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify manifest.json and SHA-256 checksums for all plugins",
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			paths, err := config.ResolvePaths(ic.Session)
			if err != nil {
				exitCode = ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{})
				return nil
			}
			plugins, err := drvplugin.ScanPlugins(paths.PluginsDir)
			if err != nil {
				exitCode = ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{})
				return nil
			}
			allOK := true
			for _, p := range plugins {
				if !p.Verified {
					allOK = false
				}
			}
			if !allOK {
				exitCode = ic.WriteError(types.ErrCodePluginInvalid, false, "One or more external plugins failed SHA-256 or API compatibility verification.", "Inspect plugins in context and fix manifest.json checksums.", map[string]any{"plugins": plugins}, nil, types.Meta{})
				return nil
			}
			if ic.JSONMode {
				exitCode = ic.WriteSuccess(map[string]any{"verified": true, "count": len(plugins), "plugins": plugins}, types.Meta{})
				return nil
			}
			_, _ = fmt.Fprintf(ic.Stdout, "All %d plugin(s) verified.\n", len(plugins))
			return nil
		},
	}
	annotateCommand(pluginVerifyCmd, RiskRead, "agent-dbctl plugin verify --json")

	pluginReloadCmd := &cobra.Command{
		Use:   "reload",
		Short: "Reload external plugins inside the running daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				exitCode = writeClientInitErr(ic, err)
				return nil
			}
			var res map[string]any
			if err := client.DoJSON(cmd.Context(), http.MethodPost, "/rpc/v1/plugins/reload", map[string]any{}, &res); err != nil {
				exitCode = writeRPCErr(ic, err)
				return nil
			}
			if ic.JSONMode {
				exitCode = ic.WriteSuccess(res, types.Meta{})
				return nil
			}
			_, _ = fmt.Fprintln(ic.Stdout, "Reloaded external plugins.")
			return nil
		},
	}
	annotateCommand(pluginReloadCmd, RiskWriteLocal, "agent-dbctl plugin reload --json")
	pluginCmd.AddCommand(pluginListCmd, pluginVerifyCmd, pluginReloadCmd)

	// ---- audit ----
	auditCmd := newAuditCmd(ioCtx, version, commit, &exitCode)

	// ---- doctor / describe / version / capabilities / skill ----
	var doctorLive bool
	doctorCmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check config permissions, SQLite WAL, secret backend, daemon identity, and plugins",
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			paths, err := config.ResolvePaths(ic.Session)
			if err != nil {
				exitCode = ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{})
				return nil
			}
			st, err := store.Open(cmd.Context(), paths.DBPath)
			if err != nil {
				exitCode = ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{})
				return nil
			}
			defer func() { _ = st.Close() }()
			walMode, _ := st.VerifyWAL(cmd.Context())
			chainRes, _ := st.VerifyAuditChain(cmd.Context())
			sec := secrets.NewStore(paths)
			plugins, _ := drvplugin.ScanPlugins(paths.PluginsDir)

			dirMode, dbMode, permOK := inspectFilePermissions(paths)
			webhookConfigured := strings.TrimSpace(os.Getenv(approval.EnvWebhookURL)) != ""

			var daemonID *daemon.Identity
			if cl, err := daemon.NewClient(paths); err == nil {
				if id, err := cl.GetIdentity(cmd.Context()); err == nil {
					daemonID = &id
				}
			}

			report := map[string]any{
				"binary_path":        ic.BinPath,
				"version":            version,
				"commit":             commit,
				"config_home":        paths.ConfigHome,
				"session":            paths.Session,
				"config_dir_mode":    dirMode,
				"db_file_mode":       dbMode,
				"permissions_ok":     permOK,
				"sqlite_wal":         walMode,
				"audit_valid":        chainRes.Valid,
				"audit_entries":      chainRes.CheckedCount,
				"secret_backend":     sec.Name(),
				"webhook_configured": webhookConfigured,
				"daemon":             daemonID,
				"plugins_count":      len(plugins),
			}

			if doctorLive {
				cl, clErr := ensureDaemon(ic, version, commit)
				if clErr != nil {
					exitCode = writeClientInitErr(ic, clErr)
					return nil
				}
				if id, err := cl.GetIdentity(cmd.Context()); err == nil {
					daemonID = &id
					report["daemon"] = daemonID
				}
				cwd, _ := os.Getwd()
				var testRes struct {
					Results []types.PingResult `json:"results"`
				}
				if err := cl.DoJSON(cmd.Context(), http.MethodPost, "/rpc/v1/db/test", map[string]any{
					"all":    true,
					"filter": daemon.ListFilter{WorkspaceCWD: cwd},
				}, &testRes); err != nil {
					exitCode = writeRPCErr(ic, err)
					return nil
				}
				reachable, failed := 0, 0
				for _, r := range testRes.Results {
					if r.Reachable {
						reachable++
					} else {
						failed++
					}
				}
				report["live_checked"] = true
				report["live_targets_total"] = len(testRes.Results)
				report["live_targets_reachable"] = reachable
				report["live_targets_failed"] = failed
				report["live_results"] = testRes.Results
			}

			if ic.JSONMode {
				exitCode = ic.WriteSuccess(report, types.Meta{})
				return nil
			}
			_, _ = fmt.Fprintf(ic.Stdout, "Version: %s (%s)\nConfig: %s (dir=%s, db=%s, ok=%v)\nSQLite WAL: %s\nAudit Chain: valid=%v (%d entries)\nSecret Backend: %s\nWebhook Configured: %v\n",
				version, commit, paths.ConfigHome, dirMode, dbMode, permOK, walMode, chainRes.Valid, chainRes.CheckedCount, sec.Name(), webhookConfigured)
			if doctorLive {
				_, _ = fmt.Fprintf(ic.Stdout, "Live Targets: %v reachable / %v total\n", report["live_targets_reachable"], report["live_targets_total"])
			}
			return nil
		},
	}
	doctorCmd.Flags().BoolVar(&doctorLive, "live", false, "Include live database connectivity checks")
	annotateCommand(doctorCmd, RiskRead, "agent-dbctl doctor --json")

	describeCmd := &cobra.Command{
		Use:   "describe [command...]",
		Short: "Machine-readable command & flag schema generated directly from parser",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			target := strings.TrimSpace(strings.Join(args, " "))
			specs := BuildDescribeSpecs(root, target)
			if target != "" && len(specs) == 0 {
				exitCode = ic.WriteError(types.ErrCodeInvalidUsage, false, fmt.Sprintf("Unknown command %q", target), "", nil, []string{ic.BinPath + " describe --json"}, types.Meta{})
				return nil
			}
			if ic.JSONMode {
				exitCode = ic.WriteSuccess(map[string]any{
					"commands":   specs,
					"exit_codes": DefaultExitCodes(),
				}, types.Meta{})
				return nil
			}
			for _, s := range specs {
				_, _ = fmt.Fprintf(ic.Stdout, "%s [%s] - %s\n", s.Path, s.Risk, s.Summary)
			}
			return nil
		},
	}
	annotateCommand(describeCmd, RiskRead, "agent-dbctl describe exec --json")

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print CLI version and commit offline",
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			payload := map[string]any{"version": version, "commit": commit, "binary": ic.BinPath}
			if ic.JSONMode {
				exitCode = ic.WriteSuccess(payload, types.Meta{})
				return nil
			}
			_, _ = fmt.Fprintf(ic.Stdout, "agent-dbctl %s (%s)\n", version, commit)
			return nil
		},
	}
	annotateCommand(versionCmd, RiskRead, "agent-dbctl version --json")

	capabilitiesCmd := &cobra.Command{
		Use:   "capabilities",
		Short: "Report supported built-in drivers, approval providers, and contract features offline",
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			caps := map[string]any{
				"version":            version,
				"builtin_engines":    []string{"postgres", "mysql", "sqlite", "mongodb", "redis"},
				"plugin_protocol":    "grpc-v1",
				"host_api_version":   drvplugin.SupportedHostAPIVersion,
				"approval_providers": []string{"local-web", "webhook"},
				"features":           []string{"dry_run", "preflight", "async_wait_false", "op_wait", "hash_chain_audit", "audit_list_export", "crash_recovery", "system_workspace_match"},
			}
			if ic.JSONMode {
				exitCode = ic.WriteSuccess(caps, types.Meta{})
				return nil
			}
			b, _ := json.MarshalIndent(caps, "", "  ")
			_, _ = fmt.Fprintln(ic.Stdout, string(b))
			return nil
		},
	}
	annotateCommand(capabilitiesCmd, RiskRead, "agent-dbctl capabilities --json")

	skillCmd := &cobra.Command{Use: "skill", Short: "Manage companion SKILL.md integration for coding agents"}
	var skillOpts struct {
		dryRun  bool
		force   bool
		runtime string
	}
	skillInstallCmd := &cobra.Command{
		Use:   "install",
		Short: "Install or update the companion SKILL.md in detected agent skill directories",
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			res, err := skillinstall.Install(skillinstall.InstallOpts{
				DryRun:        skillOpts.dryRun,
				Force:         skillOpts.force,
				Runtime:       skillOpts.runtime,
				Version:       version,
				SkillMarkdown: SkillMarkdown,
			})
			if err != nil {
				exitCode = ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{})
				return nil
			}
			if ic.JSONMode {
				exitCode = ic.WriteSuccess(res, types.Meta{})
				return nil
			}
			for _, a := range res.Actions {
				_, _ = fmt.Fprintf(ic.Stdout, "%s\t%s\t(%s)\t%s\n", a.Action, a.Path, strings.Join(a.Runtimes, ","), a.State)
			}
			if len(res.Actions) == 0 {
				_, _ = fmt.Fprintln(ic.Stdout, "No coding-agent skill directories detected.")
			}
			return nil
		},
	}
	skillInstallCmd.Flags().BoolVar(&skillOpts.dryRun, "dry-run", false, "Preview skill changes without writing files")
	skillInstallCmd.Flags().BoolVar(&skillOpts.force, "force", false, "Overwrite existing non-symlink SKILL.md conflicts")
	skillInstallCmd.Flags().StringVar(&skillOpts.runtime, "runtime", "", "Filter to a specific runtime (claude, codex, cursor, opencode, pi, antigravity, agents)")
	annotateCommand(skillInstallCmd, RiskWriteLocal, "agent-dbctl skill install --json")

	skillStatusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show companion SKILL.md installation status across coding agents",
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			res, err := skillinstall.Status(version, SkillMarkdown, skillOpts.runtime)
			if err != nil {
				exitCode = ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{})
				return nil
			}
			if ic.JSONMode {
				exitCode = ic.WriteSuccess(res, types.Meta{})
				return nil
			}
			for _, t := range res.Targets {
				_, _ = fmt.Fprintf(ic.Stdout, "%s\t%s\t[%s]\n", t.State, t.Path, strings.Join(t.Runtimes, ","))
			}
			return nil
		},
	}
	skillStatusCmd.Flags().StringVar(&skillOpts.runtime, "runtime", "", "Filter to a specific runtime")
	annotateCommand(skillStatusCmd, RiskRead, "agent-dbctl skill status --json")

	skillUninstallCmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove unmodified agent-dbctl SKILL.md copies managed by this tool",
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			res, err := skillinstall.Uninstall(skillOpts.dryRun, skillOpts.runtime, SkillMarkdown)
			if err != nil {
				exitCode = ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{})
				return nil
			}
			if ic.JSONMode {
				exitCode = ic.WriteSuccess(res, types.Meta{})
				return nil
			}
			for _, a := range res.Actions {
				_, _ = fmt.Fprintf(ic.Stdout, "%s\t%s\t(%s)\n", a.Action, a.Path, a.State)
			}
			return nil
		},
	}
	skillUninstallCmd.Flags().BoolVar(&skillOpts.dryRun, "dry-run", false, "Preview removal without deleting files")
	skillUninstallCmd.Flags().StringVar(&skillOpts.runtime, "runtime", "", "Filter to a specific runtime")
	annotateCommand(skillUninstallCmd, RiskWriteLocal, "agent-dbctl skill uninstall --json")

	skillPrintCmd := &cobra.Command{
		Use:   "print",
		Short: "Print companion SKILL.md instructions",
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			if ic.JSONMode {
				exitCode = ic.WriteSuccess(map[string]string{"skill_markdown": SkillMarkdown}, types.Meta{})
				return nil
			}
			_, _ = fmt.Fprint(ic.Stdout, SkillMarkdown)
			return nil
		},
	}
	annotateCommand(skillPrintCmd, RiskRead, "agent-dbctl skill print")
	skillCmd.AddCommand(skillInstallCmd, skillStatusCmd, skillUninstallCmd, skillPrintCmd)

	root.AddCommand(dbCmd, execCmd, opCmd, uiCmd, daemonCmd, pluginCmd, auditCmd, doctorCmd, describeCmd, versionCmd, capabilitiesCmd, skillCmd)

	if err := root.Execute(); err != nil {
		ic := ioCtx()
		code := types.ErrCodeInvalidUsage
		if strings.Contains(err.Error(), "unknown flag") || strings.Contains(err.Error(), "unknown shorthand") {
			code = types.ErrCodeUnknownFlag
		}
		return ic.WriteError(code, false, err.Error(), "Check command syntax with --help or describe.", nil, []string{ic.BinPath + " describe --json"}, types.Meta{})
	}
	return exitCode
}

func renderExecOutcome(ic IOContext, resp types.ExecResponse, outPath string, forceOut bool, meta types.Meta) int {
	if outPath != "" && resp.Result != nil {
		raw, _ := json.MarshalIndent(resp, "", "  ")
		absPath, err := WriteAtomicOutput(outPath, raw, forceOut)
		if err != nil {
			code := types.ErrCodeInvalidInput
			if errors.Is(err, errOutputExists) {
				code = types.ErrCodeOutputExists
			}
			return ic.WriteError(code, false, err.Error(), "", nil, nil, meta)
		}
		// Return path + bounded summary rather than duplicating megabytes on stdout.
		resp.Result.Rows = nil
		resp.Result.Documents = nil
		resp.Result.KVResult = nil
		resp.Result.RawText = ""
		if ic.JSONMode {
			return ic.WriteSuccess(map[string]any{
				"operation":   resp,
				"output_file": absPath,
			}, meta)
		}
		_, _ = fmt.Fprintf(ic.Stdout, "Wrote result (%d rows, truncated=%v) to %s\n", resp.Result.ReturnedRows, resp.Result.Truncated, absPath)
		return types.ExitSuccess
	}

	if resp.ErrorCode != "" && resp.Status != types.OpSucceeded {
		hint := ""
		if resp.ReviewerNote != "" {
			hint = "Reviewer note: " + resp.ReviewerNote
		} else if resp.Status == types.OpTimedOut && !resp.Classification.IsReadOnly {
			hint = "Write/mutating query timed out; verify state via read-only query before retrying."
		} else if resp.Status == types.OpWaitingApproval {
			hint = "Human confirmation requested. Poll op status or review in browser."
			if len(resp.Evaluation.MatchedRules) > 0 {
				top := resp.Evaluation.MatchedRules[0]
				label := top.ConfirmTitle
				if label == "" {
					label = top.RuleName
				}
				hint = fmt.Sprintf("High-risk pattern matched (%s). Poll op status or confirm in browser.", label)
			}
		}
		ctxMap := map[string]any{
			"operation_id":     resp.OperationID,
			"target_ref":       resp.TargetRef,
			"status":           resp.Status,
			"approval_id":      resp.ApprovalID,
			"approval_url":     resp.ApprovalURL,
			"expires_at_utc":   resp.ApprovalExpires,
			"reviewer_note":    resp.ReviewerNote,
			"trigger_reasons":  resp.Evaluation.TriggerReasons,
			"matched_rules":    resp.Evaluation.MatchedRules,
			"classification":   resp.Classification,
			"preflight":        resp.Preflight,
		}
		var next []string
		if resp.OperationID != "" && resp.Status == types.OpWaitingApproval {
			next = append(next, fmt.Sprintf("%s op status %s --json", ic.BinPath, resp.OperationID))
		}
		return ic.WriteError(resp.ErrorCode, resp.Retryable, resp.ErrorMessage, hint, ctxMap, next, meta)
	}

	if ic.JSONMode {
		return ic.WriteSuccess(resp, meta)
	}

	if resp.Result != nil && len(resp.Result.Columns) > 0 {
		headers := make([]string, len(resp.Result.Columns))
		for i, c := range resp.Result.Columns {
			headers[i] = c.Name
		}
		rows := make([][]string, 0, len(resp.Result.Rows))
		for _, r := range resp.Result.Rows {
			line := make([]string, len(r))
			for i, v := range r {
				line[i] = fmt.Sprintf("%v", v)
			}
			rows = append(rows, line)
		}
		renderTable(ic.Stdout, headers, rows)
		if resp.Result.Truncated {
			_, _ = fmt.Fprintf(ic.Stderr, "(truncated at %s: returned %d of %d fetched rows)\n", resp.Result.CutoffReason, resp.Result.ReturnedRows, resp.Result.FetchedRows)
		}
		return types.ExitSuccess
	}

	if resp.Result != nil && len(resp.Result.Documents) > 0 {
		b, _ := json.MarshalIndent(resp.Result.Documents, "", "  ")
		_, _ = fmt.Fprintln(ic.Stdout, string(b))
		if resp.Result.Truncated {
			_, _ = fmt.Fprintf(ic.Stderr, "(truncated at %s: returned %d of %d fetched docs)\n", resp.Result.CutoffReason, resp.Result.ReturnedRows, resp.Result.FetchedRows)
		}
		return types.ExitSuccess
	}

	if resp.Result != nil && resp.Result.Family == types.FamilyKV {
		b, _ := json.MarshalIndent(resp.Result.KVResult, "", "  ")
		_, _ = fmt.Fprintln(ic.Stdout, string(b))
		if resp.Result.Truncated {
			_, _ = fmt.Fprintf(ic.Stderr, "(truncated at %s: returned %d of %d fetched items)\n", resp.Result.CutoffReason, resp.Result.ReturnedRows, resp.Result.FetchedRows)
		}
		return types.ExitSuccess
	}

	if resp.Result != nil && resp.Result.AffectedRows != nil {
		_, _ = fmt.Fprintf(ic.Stdout, "OK (%d row(s) affected, %dms)\n", *resp.Result.AffectedRows, resp.Result.LatencyMs)
		return types.ExitSuccess
	}

	if resp.Result != nil {
		if strings.TrimSpace(resp.Result.RawText) != "" {
			_, _ = fmt.Fprintln(ic.Stdout, resp.Result.RawText)
		} else {
			_, _ = fmt.Fprintf(ic.Stdout, "OK (%d row(s), %dms)\n", resp.Result.ReturnedRows, resp.Result.LatencyMs)
		}
		return types.ExitSuccess
	}

	renderExecSummary(ic.Stdout, resp, meta)
	return types.ExitSuccess
}

func renderExecSummary(w io.Writer, resp types.ExecResponse, meta types.Meta) {
	_, _ = fmt.Fprintf(w, "Target:    %s (%s, %s)\n", resp.TargetRef, resp.EnvironmentCode, resp.Engine)
	switch {
	case meta.DryRun:
		_, _ = fmt.Fprintln(w, "Mode:      dry-run")
	case meta.Preflight:
		_, _ = fmt.Fprintln(w, "Mode:      preflight")
	default:
		_, _ = fmt.Fprintf(w, "Status:    %s\n", resp.Status)
	}
	_, _ = fmt.Fprintf(w, "Risk:      %s (read_only=%v)\n", resp.Classification.RiskLevel, resp.Classification.IsReadOnly)
	if len(resp.Classification.RiskFlags) > 0 {
		_, _ = fmt.Fprintf(w, "Flags:     %s\n", strings.Join(resp.Classification.RiskFlags, ", "))
	}
	_, _ = fmt.Fprintf(w, "Decision:  %s (credential=%s)\n", resp.Evaluation.Decision, resp.CredentialMode)
	if len(resp.Evaluation.TriggerReasons) > 0 {
		_, _ = fmt.Fprintf(w, "Reasons:   %s\n", strings.Join(resp.Evaluation.TriggerReasons, ", "))
	}
	if len(resp.Evaluation.MatchedRules) > 0 {
		_, _ = fmt.Fprintln(w, "Patterns:")
		for _, mr := range resp.Evaluation.MatchedRules {
			title := mr.RuleName
			if mr.ConfirmTitle != "" {
				title = fmt.Sprintf("%s (%s)", mr.RuleName, mr.ConfirmTitle)
			}
			if mr.MatchedFragment != "" {
				_, _ = fmt.Fprintf(w, "  - %s [%s, %s]: %s\n", title, mr.Action, mr.Scope, mr.MatchedFragment)
			} else {
				_, _ = fmt.Fprintf(w, "  - %s [%s, %s]\n", title, mr.Action, mr.Scope)
			}
		}
	}
	if resp.Preflight != nil {
		_, _ = fmt.Fprintf(w, "Preflight: supported=%v full_scan=%v est_rows=%d\n",
			resp.Preflight.Supported, resp.Preflight.FullScan, resp.Preflight.EstimatedRows)
		if strings.TrimSpace(resp.Preflight.PlanSummary) != "" {
			_, _ = fmt.Fprintf(w, "Plan:      %s\n", strings.TrimSpace(resp.Preflight.PlanSummary))
		}
		if len(resp.Preflight.Warnings) > 0 {
			_, _ = fmt.Fprintf(w, "Warnings:  %s\n", strings.Join(resp.Preflight.Warnings, "; "))
		}
	}
	if resp.Evaluation.DenyMessage != "" {
		_, _ = fmt.Fprintf(w, "Deny:      %s\n", resp.Evaluation.DenyMessage)
	}
}

func readQueryInput(inline, filePath string, useStdin, stdinTTY bool) (string, error) {
	if inline != "" {
		return inline, nil
	}
	if filePath != "" {
		abs, err := filepath.Abs(filePath)
		if err != nil {
			return "", err
		}
		if err := config.ValidateRegularFile(abs); err != nil {
			return "", err
		}
		b, err := os.ReadFile(abs)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	if useStdin || !stdinTTY {
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 2<<20))
		if err != nil {
			return "", err
		}
		if strings.TrimSpace(string(b)) != "" {
			return string(b), nil
		}
	}
	return "", fmt.Errorf("missing query input")
}

func ensureDaemon(ic IOContext, version, commit string) (*daemon.Client, error) {
	paths, err := config.ResolvePaths(ic.Session)
	if err != nil {
		return nil, err
	}
	if cl, err := daemon.NewClient(paths); err == nil {
		if id, idErr := cl.GetIdentity(context.Background()); idErr == nil {
			if id.Version != version || (commit != "dev" && id.Commit != commit) {
				return nil, fmt.Errorf("%s: daemon version %s (%s) does not match CLI %s (%s)", types.ErrCodeDaemonVersionMismatch, id.Version, id.Commit, version, commit)
			}
			return cl, nil
		}
	}
	if os.Getenv(config.EnvNoDaemonSpawn) == "1" {
		return nil, fmt.Errorf("%s: daemon not running and auto-spawn disabled", types.ErrCodeDaemonUnavailable)
	}
	if err := daemon.SpawnDetached(ic.BinPath, []string{"daemon", "serve", "--session", ic.Session}); err != nil {
		return nil, fmt.Errorf("spawn daemon: %w", err)
	}

	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if cl, err := daemon.NewClient(paths); err == nil {
			if id, idErr := cl.GetIdentity(context.Background()); idErr == nil && id.PID > 0 {
				return cl, nil
			}
		}
		time.Sleep(80 * time.Millisecond)
	}
	return nil, fmt.Errorf("%s: timed out waiting for daemon startup", types.ErrCodeDaemonUnavailable)
}

func stopDaemon(ctx context.Context, paths config.Paths) error {
	if cl, err := daemon.NewClient(paths); err == nil {
		_ = cl.Shutdown(ctx)
		time.Sleep(150 * time.Millisecond)
	}
	if meta, err := daemon.ReadDaemonMeta(paths); err == nil && meta.PID > 0 {
		_ = daemon.KillPID(meta.PID)
	}
	_ = os.Remove(paths.SocketPath)
	_ = os.Remove(paths.DaemonMeta)
	return nil
}

func writeClientInitErr(ic IOContext, err error) int {
	msg := err.Error()
	if strings.Contains(msg, types.ErrCodeDaemonVersionMismatch) {
		return ic.WriteError(types.ErrCodeDaemonVersionMismatch, false, msg, "Restart the daemon to match the current CLI binary.", nil, []string{ic.BinPath + " daemon restart --session " + ic.Session + " --json"}, types.Meta{})
	}
	return ic.WriteError(types.ErrCodeDaemonUnavailable, true, msg, "Run doctor or daemon start to inspect local daemon state.", nil, []string{ic.BinPath + " doctor --json"}, types.Meta{})
}

func writeRPCErr(ic IOContext, err error) int {
	var le *daemon.LookupError
	if errors.As(err, &le) {
		ctxMap := map[string]any{
			"similar_names":      le.SimilarNames,
			"unsearched_sources": le.UnsearchedSources,
		}
		var next []string
		if len(le.Candidates) > 0 {
			cands := make([]map[string]string, 0, len(le.Candidates))
			for _, c := range le.Candidates {
				eng := ""
				if c.Instance != nil {
					eng = c.Instance.Engine
				}
				cands = append(cands, map[string]string{
					"ref":    c.Target.Ref,
					"alias":  c.Target.Alias,
					"env":    c.Target.EnvironmentCode,
					"engine": eng,
				})
				next = append(next, fmt.Sprintf("%s db show %s --json", ic.BinPath, c.Target.Ref))
			}
			ctxMap["candidates"] = cands
		} else {
			next = append(next, ic.BinPath+" db list --json")
		}
		return ic.WriteError(le.Code, false, le.Message, "Pick an exact target ref or alias from context.", ctxMap, next, types.Meta{})
	}
	return ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{})
}

func inspectFilePermissions(paths config.Paths) (dirMode string, dbMode string, ok bool) {
	ok = true
	if info, err := os.Stat(paths.ConfigHome); err == nil {
		perm := info.Mode().Perm()
		dirMode = fmt.Sprintf("%04o", perm)
		if runtime.GOOS != "windows" && perm&0o077 != 0 {
			ok = false
		}
	}
	if info, err := os.Stat(paths.DBPath); err == nil {
		perm := info.Mode().Perm()
		dbMode = fmt.Sprintf("%04o", perm)
		if runtime.GOOS != "windows" && perm&0o077 != 0 {
			ok = false
		}
	}
	return dirMode, dbMode, ok
}
