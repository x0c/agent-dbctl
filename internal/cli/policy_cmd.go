package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/x0c/agent-dbctl/internal/config"
	"github.com/x0c/agent-dbctl/internal/daemon"
	"github.com/x0c/agent-dbctl/internal/types"
)

func registerPolicyCommands(
	root *cobra.Command,
	ioCtx func() IOContext,
	ensureDaemon daemonEnsurer,
	writeClientInitErr func(IOContext, error) int,
	writeRPCErr func(IOContext, error) int,
	setExitCode func(int),
	version, commit string,
) {
	// ---- security ----
	secCmd := &cobra.Command{Use: "security", Short: "Inspect or update machine-wide GlobalSecurityConfig guardrails"}
	secGetCmd := &cobra.Command{
		Use:   "get",
		Short: "Show current GlobalSecurityConfig guardrails",
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				setExitCode(writeClientInitErr(ic, err))
				return nil
			}
			var cfg types.GlobalSecurityConfig
			if err := client.DoJSON(cmd.Context(), http.MethodGet, "/rpc/v1/security/global", nil, &cfg); err != nil {
				setExitCode(writeRPCErr(ic, err))
				return nil
			}
			if ic.JSONMode {
				setExitCode(ic.WriteSuccess(cfg, types.Meta{}))
				return nil
			}
			renderTable(ic.Stdout, []string{"SETTING", "VALUE"}, [][]string{
				{"exec_timeout_sec", strconv.Itoa(cfg.ExecTimeoutSec)},
				{"approval_timeout_sec", strconv.Itoa(cfg.ApprovalTimeoutSec)},
				{"max_rows", strconv.Itoa(cfg.MaxRows)},
				{"max_bytes", strconv.FormatInt(cfg.MaxBytes, 10)},
				{"explain_max_rows", strconv.FormatInt(cfg.ExplainMaxRows, 10)},
				{"prod_read_only_freeze", fmt.Sprintf("%v", cfg.ProdReadOnlyFreeze)},
				{"block_multi_statement_in_prod", fmt.Sprintf("%v", cfg.BlockMultiStatementInProd)},
				{"default_approval_provider", cfg.DefaultApprovalProvider},
				{"redact_audit_literals", fmt.Sprintf("%v", cfg.RedactAuditLiterals)},
				{"require_reason_for_approval", fmt.Sprintf("%v", cfg.RequireReasonForApproval)},
			})
			return nil
		},
	}
	annotateCommand(secGetCmd, RiskRead, "agent-dbctl security get --json")

	var secSet struct {
		execTimeout     int
		approvalTimeout int
		maxRows         int
		maxBytes        int64
		explainMaxRows  int64
		prodROFreeze    bool
		blockMultiProd  bool
		provider        string
		redactLiterals  bool
		requireReason   bool
		dryRun          bool
	}
	secSetCmd := &cobra.Command{
		Use:   "set",
		Short: "Update GlobalSecurityConfig guardrails",
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				setExitCode(writeClientInitErr(ic, err))
				return nil
			}
			var cur types.GlobalSecurityConfig
			if err := client.DoJSON(cmd.Context(), http.MethodGet, "/rpc/v1/security/global", nil, &cur); err != nil {
				setExitCode(writeRPCErr(ic, err))
				return nil
			}
			if cmd.Flags().Changed("exec-timeout-sec") {
				cur.ExecTimeoutSec = secSet.execTimeout
			}
			if cmd.Flags().Changed("approval-timeout-sec") {
				cur.ApprovalTimeoutSec = secSet.approvalTimeout
			}
			if cmd.Flags().Changed("max-rows") {
				cur.MaxRows = secSet.maxRows
			}
			if cmd.Flags().Changed("max-bytes") {
				cur.MaxBytes = secSet.maxBytes
			}
			if cmd.Flags().Changed("explain-max-rows") {
				cur.ExplainMaxRows = secSet.explainMaxRows
			}
			if cmd.Flags().Changed("prod-read-only-freeze") {
				cur.ProdReadOnlyFreeze = secSet.prodROFreeze
			}
			if cmd.Flags().Changed("block-multi-statement-in-prod") {
				cur.BlockMultiStatementInProd = secSet.blockMultiProd
			}
			if cmd.Flags().Changed("default-approval-provider") {
				cur.DefaultApprovalProvider = secSet.provider
			}
			if cmd.Flags().Changed("redact-audit-literals") {
				cur.RedactAuditLiterals = secSet.redactLiterals
			}
			if cmd.Flags().Changed("require-reason-for-approval") {
				cur.RequireReasonForApproval = secSet.requireReason
			}
			var res daemon.AdminMutationResult[types.GlobalSecurityConfig]
			if err := client.DoJSON(cmd.Context(), http.MethodPut, "/rpc/v1/security/global", map[string]any{
				"config":  cur,
				"dry_run": secSet.dryRun,
			}, &res); err != nil {
				setExitCode(writeRPCErr(ic, err))
				return nil
			}
			if ic.JSONMode {
				setExitCode(ic.WriteSuccess(res, types.Meta{}))
				return nil
			}
			_, _ = fmt.Fprintf(ic.Stdout, "Global security config: %s\n", res.Status)
			return nil
		},
	}
	secSetCmd.Flags().IntVar(&secSet.execTimeout, "exec-timeout-sec", 0, "Hard ceiling execution timeout in seconds")
	secSetCmd.Flags().IntVar(&secSet.approvalTimeout, "approval-timeout-sec", 0, "Default approval timeout in seconds")
	secSetCmd.Flags().IntVar(&secSet.maxRows, "max-rows", 0, "Maximum rows returned per query")
	secSetCmd.Flags().Int64Var(&secSet.maxBytes, "max-bytes", 0, "Maximum bytes returned per query")
	secSetCmd.Flags().Int64Var(&secSet.explainMaxRows, "explain-max-rows", 0, "Preflight EXPLAIN estimated-rows ceiling")
	secSetCmd.Flags().BoolVar(&secSet.prodROFreeze, "prod-read-only-freeze", false, "Freeze production environments to read-only")
	secSetCmd.Flags().BoolVar(&secSet.blockMultiProd, "block-multi-statement-in-prod", true, "Block multi-statement queries in prod")
	secSetCmd.Flags().StringVar(&secSet.provider, "default-approval-provider", "", "Default approval provider (local-web|webhook)")
	secSetCmd.Flags().BoolVar(&secSet.redactLiterals, "redact-audit-literals", true, "Redact string/number literals in audit logs")
	secSetCmd.Flags().BoolVar(&secSet.requireReason, "require-reason-for-approval", true, "Require --reason when an operation triggers human approval")
	secSetCmd.Flags().BoolVar(&secSet.dryRun, "dry-run", false, "Preview change without saving")
	annotateCommand(secSetCmd, RiskWriteLocal, "agent-dbctl security set --max-rows 500 --explain-max-rows 100000 --json")
	secCmd.AddCommand(secGetCmd, secSetCmd)

	// ---- policy ----
	policyCmd := &cobra.Command{Use: "policy", Short: "Manage monotonic scoped PolicyRuleSet overrides (env, system, target)"}
	policyListCmd := &cobra.Command{
		Use:   "list",
		Short: "List scoped policy rule sets",
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				setExitCode(writeClientInitErr(ic, err))
				return nil
			}
			var res struct {
				Items []types.PolicyRuleSet `json:"items"`
			}
			if err := client.DoJSON(cmd.Context(), http.MethodGet, "/rpc/v1/policies", nil, &res); err != nil {
				setExitCode(writeRPCErr(ic, err))
				return nil
			}
			if ic.JSONMode {
				setExitCode(ic.WriteSuccess(map[string]any{"items": res.Items, "count": len(res.Items)}, types.Meta{}))
				return nil
			}
			rows := make([][]string, 0, len(res.Items))
			for _, p := range res.Items {
				rows = append(rows, []string{p.ID, p.Name, p.ScopeType, p.ScopeID, p.ApprovalProvider})
			}
			renderTable(ic.Stdout, []string{"ID", "NAME", "SCOPE_TYPE", "SCOPE_ID", "PROVIDER"}, rows)
			return nil
		},
	}
	annotateCommand(policyListCmd, RiskRead, "agent-dbctl policy list --json")

	var polSet struct {
		file                string
		scopeType           string
		scopeID             string
		allowSafeRead       bool
		reqApprovalHighCost bool
		reqApprovalWrite    bool
		reqApprovalDDL      bool
		reqApprovalAdmin    bool
		reqApprovalUnknown  bool
		allowMultiStatement bool
		execTimeout         int
		approvalTimeout     int
		maxRows             int
		maxBytes            int64
		explainMaxRows      int64
		approvalProvider    string
		dryRun              bool
	}
	policySetCmd := &cobra.Command{
		Use:   "set [name-or-id]",
		Short: "Create or update a scoped PolicyRuleSet",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				setExitCode(writeClientInitErr(ic, err))
				return nil
			}
			var cur types.PolicyRuleSet
			if polSet.file != "" {
				raw, err := readSpecFile(polSet.file)
				if err != nil {
					setExitCode(ic.WriteError(types.ErrCodeInvalidUsage, false, err.Error(), "", nil, nil, types.Meta{}))
					return nil
				}
				if err := yamlOrJSONDecode(raw, &cur); err != nil {
					setExitCode(ic.WriteError(types.ErrCodeInvalidUsage, false, err.Error(), "", nil, nil, types.Meta{}))
					return nil
				}
			}
			nameOrID := strings.TrimSpace(cur.Name)
			if len(args) == 1 {
				nameOrID = strings.TrimSpace(args[0])
			}
			if nameOrID != "" {
				var existing struct {
					Items []types.PolicyRuleSet `json:"items"`
				}
				_ = client.DoJSON(cmd.Context(), http.MethodGet, "/rpc/v1/policies", nil, &existing)
				for _, p := range existing.Items {
					if p.ID == nameOrID || strings.EqualFold(p.Name, nameOrID) {
						if polSet.file == "" {
							cur = p
						} else if cur.ID == "" {
							cur.ID = p.ID
						}
						break
					}
				}
				if cur.Name == "" {
					cur.Name = nameOrID
				}
			}
			if cur.Name == "" {
				setExitCode(ic.WriteError(types.ErrCodeInvalidUsage, false, "Policy name is required.", "Pass <name> or -f <policy.yaml>.", nil, nil, types.Meta{}))
				return nil
			}
			if cmd.Flags().Changed("scope-type") {
				cur.ScopeType = polSet.scopeType
			}
			if cmd.Flags().Changed("scope-id") {
				cur.ScopeID = polSet.scopeID
			}
			if cmd.Flags().Changed("allow-safe-read") {
				cur.AllowSafeRead = boolPtr(polSet.allowSafeRead)
			}
			if cmd.Flags().Changed("require-approval-high-cost") {
				cur.RequireApprovalOnHighCostRead = boolPtr(polSet.reqApprovalHighCost)
			}
			if cmd.Flags().Changed("require-approval-write") {
				cur.RequireApprovalOnWrite = boolPtr(polSet.reqApprovalWrite)
			}
			if cmd.Flags().Changed("require-approval-ddl") {
				cur.RequireApprovalOnDDL = boolPtr(polSet.reqApprovalDDL)
			}
			if cmd.Flags().Changed("require-approval-admin") {
				cur.RequireApprovalOnAdmin = boolPtr(polSet.reqApprovalAdmin)
			}
			if cmd.Flags().Changed("require-approval-unknown") {
				cur.RequireApprovalOnUnknown = boolPtr(polSet.reqApprovalUnknown)
			}
			if cmd.Flags().Changed("allow-multi-statement") {
				cur.AllowMultiStatement = boolPtr(polSet.allowMultiStatement)
			}
			if cmd.Flags().Changed("exec-timeout-sec") {
				v := polSet.execTimeout
				cur.ExecTimeoutSec = &v
			}
			if cmd.Flags().Changed("approval-timeout-sec") {
				v := polSet.approvalTimeout
				cur.ApprovalTimeoutSec = &v
			}
			if cmd.Flags().Changed("max-rows") {
				v := polSet.maxRows
				cur.MaxRows = &v
			}
			if cmd.Flags().Changed("max-bytes") {
				v := polSet.maxBytes
				cur.MaxBytes = &v
			}
			if cmd.Flags().Changed("explain-max-rows") {
				v := polSet.explainMaxRows
				cur.ExplainMaxRows = &v
			}
			if cmd.Flags().Changed("approval-provider") {
				cur.ApprovalProvider = polSet.approvalProvider
			}
			var res daemon.AdminMutationResult[types.PolicyRuleSet]
			if err := client.DoJSON(cmd.Context(), http.MethodPost, "/rpc/v1/policies", map[string]any{
				"policy":  cur,
				"dry_run": polSet.dryRun,
			}, &res); err != nil {
				setExitCode(writeRPCErr(ic, err))
				return nil
			}
			if ic.JSONMode {
				setExitCode(ic.WriteSuccess(res, types.Meta{}))
				return nil
			}
			_, _ = fmt.Fprintf(ic.Stdout, "Policy %s (%s:%s): %s\n", res.Item.Name, res.Item.ScopeType, res.Item.ScopeID, res.Status)
			return nil
		},
	}
	policySetCmd.Flags().StringVarP(&polSet.file, "file", "f", "", "YAML or JSON PolicyRuleSet file")
	policySetCmd.Flags().StringVar(&polSet.scopeType, "scope-type", "", "Scope type (env|system|target)")
	policySetCmd.Flags().StringVar(&polSet.scopeID, "scope-id", "", "Scope reference (env code, system slug, target ref/alias, or ID)")
	policySetCmd.Flags().BoolVar(&polSet.allowSafeRead, "allow-safe-read", true, "Allow safe reads")
	policySetCmd.Flags().BoolVar(&polSet.reqApprovalHighCost, "require-approval-high-cost", true, "Require approval on high-cost reads")
	policySetCmd.Flags().BoolVar(&polSet.reqApprovalWrite, "require-approval-write", true, "Require approval on DML writes")
	policySetCmd.Flags().BoolVar(&polSet.reqApprovalDDL, "require-approval-ddl", true, "Require approval on DDL statements")
	policySetCmd.Flags().BoolVar(&polSet.reqApprovalAdmin, "require-approval-admin", true, "Require approval on admin statements")
	policySetCmd.Flags().BoolVar(&polSet.reqApprovalUnknown, "require-approval-unknown", true, "Require approval on unknown statements")
	policySetCmd.Flags().BoolVar(&polSet.allowMultiStatement, "allow-multi-statement", false, "Allow multi-statement execution")
	policySetCmd.Flags().IntVar(&polSet.execTimeout, "exec-timeout-sec", 0, "Scoped execution timeout seconds")
	policySetCmd.Flags().IntVar(&polSet.approvalTimeout, "approval-timeout-sec", 0, "Scoped approval timeout seconds")
	policySetCmd.Flags().IntVar(&polSet.maxRows, "max-rows", 0, "Scoped max rows ceiling")
	policySetCmd.Flags().Int64Var(&polSet.maxBytes, "max-bytes", 0, "Scoped max bytes ceiling")
	policySetCmd.Flags().Int64Var(&polSet.explainMaxRows, "explain-max-rows", 0, "Scoped preflight row limit")
	policySetCmd.Flags().StringVar(&polSet.approvalProvider, "approval-provider", "", "Approval provider (local-web|webhook)")
	policySetCmd.Flags().BoolVar(&polSet.dryRun, "dry-run", false, "Preview change without saving")
	annotateCommand(policySetCmd, RiskWriteLocal, "agent-dbctl policy set prod-strict --scope-type env --scope-id prod --max-rows 200 --json")

	var polDelYes bool
	policyDeleteCmd := &cobra.Command{
		Use:   "delete <name-or-id>",
		Short: "Delete a PolicyRuleSet",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				setExitCode(writeClientInitErr(ic, err))
				return nil
			}
			var out map[string]bool
			if err := client.DoJSON(cmd.Context(), http.MethodDelete, "/rpc/v1/policies/"+url.PathEscape(args[0]), nil, &out); err != nil {
				setExitCode(writeRPCErr(ic, err))
				return nil
			}
			if ic.JSONMode {
				setExitCode(ic.WriteSuccess(map[string]any{"deleted": true, "policy": args[0]}, types.Meta{}))
				return nil
			}
			_, _ = fmt.Fprintf(ic.Stdout, "Deleted policy %s\n", args[0])
			return nil
		},
	}
	policyDeleteCmd.Flags().BoolVarP(&polDelYes, "yes", "y", false, "Confirm deletion non-interactively")
	annotateCommand(policyDeleteCmd, RiskWriteLocal, "agent-dbctl policy delete prod-strict --yes --json")
	policyCmd.AddCommand(policyListCmd, policySetCmd, policyDeleteCmd)

	// ---- pattern ----
	patternCmd := &cobra.Command{Use: "pattern", Short: "Manage custom RiskPatternRule rules, built-in packs, and offline sandbox tests"}
	patternListCmd := &cobra.Command{
		Use:   "list",
		Short: "List custom risk patterns and available built-in rule packs",
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				setExitCode(writeClientInitErr(ic, err))
				return nil
			}
			var res struct {
				Items        []types.RiskPatternRule `json:"items"`
				BuiltinPacks []types.BuiltinRulePack `json:"builtin_packs"`
			}
			if err := client.DoJSON(cmd.Context(), http.MethodGet, "/rpc/v1/risk-patterns", nil, &res); err != nil {
				setExitCode(writeRPCErr(ic, err))
				return nil
			}
			if ic.JSONMode {
				setExitCode(ic.WriteSuccess(res, types.Meta{}))
				return nil
			}
			rows := make([][]string, 0, len(res.Items))
			for _, r := range res.Items {
				rows = append(rows, []string{r.ID, r.Name, r.ScopeType + ":" + r.ScopeID, string(r.Action), fmt.Sprintf("%v", r.Enabled), strings.Join(r.Engines, ",")})
			}
			renderTable(ic.Stdout, []string{"ID", "NAME", "SCOPE", "ACTION", "ENABLED", "ENGINES"}, rows)
			return nil
		},
	}
	annotateCommand(patternListCmd, RiskRead, "agent-dbctl pattern list --json")

	var patSet struct {
		file             string
		stdin            bool
		scopeType        string
		scopeID          string
		action           string
		regex            string
		regexTarget      string
		caseSensitive    bool
		engines          []string
		enabled          bool
		priority         int
		confirmTitle     string
		confirmMessage   string
		approvalProvider string
		description      string
		dryRun           bool
	}
	patternSetCmd := &cobra.Command{
		Use:   "set [name-or-id]",
		Short: "Create or update a RiskPatternRule via flags or YAML/JSON spec",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			if patSet.file != "" && patSet.stdin {
				setExitCode(ic.WriteError(types.ErrCodeInvalidUsage, false, "--file and --stdin are mutually exclusive.", "", nil, nil, types.Meta{}))
				return nil
			}
			var rule types.RiskPatternRule
			if patSet.file != "" || patSet.stdin {
				var raw []byte
				var err error
				if patSet.file != "" {
					raw, err = readSpecFile(patSet.file)
				} else {
					raw, err = io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
				}
				if err != nil {
					setExitCode(ic.WriteError(types.ErrCodeInvalidUsage, false, err.Error(), "", nil, nil, types.Meta{}))
					return nil
				}
				if err := yamlOrJSONDecode(raw, &rule); err != nil {
					setExitCode(ic.WriteError(types.ErrCodeInvalidUsage, false, err.Error(), "", nil, nil, types.Meta{}))
					return nil
				}
			}
			if len(args) == 1 && rule.Name == "" {
				rule.Name = strings.TrimSpace(args[0])
			}
			if cmd.Flags().Changed("scope-type") {
				rule.ScopeType = patSet.scopeType
			}
			if rule.ScopeType == "" {
				rule.ScopeType = "global"
			}
			if cmd.Flags().Changed("scope-id") {
				rule.ScopeID = patSet.scopeID
			}
			if rule.ScopeType == "global" && rule.ScopeID == "" {
				rule.ScopeID = "global"
			}
			if cmd.Flags().Changed("action") {
				rule.Action = types.PatternAction(patSet.action)
			}
			if cmd.Flags().Changed("regex") {
				rule.Condition = types.PatternCondition{
					Type:          types.MatcherRegex,
					Pattern:       patSet.regex,
					Target:        patSet.regexTarget,
					CaseSensitive: patSet.caseSensitive,
				}
			}
			if cmd.Flags().Changed("engine") {
				rule.Engines = patSet.engines
			}
			if cmd.Flags().Changed("enabled") {
				rule.Enabled = patSet.enabled
			} else if patSet.file == "" && !patSet.stdin {
				rule.Enabled = true
			}
			if cmd.Flags().Changed("priority") {
				rule.Priority = patSet.priority
			}
			if cmd.Flags().Changed("confirm-title") {
				rule.ConfirmTitle = patSet.confirmTitle
			}
			if cmd.Flags().Changed("confirm-message") {
				rule.ConfirmMessage = patSet.confirmMessage
			}
			if cmd.Flags().Changed("approval-provider") {
				rule.ApprovalProvider = patSet.approvalProvider
			}
			if cmd.Flags().Changed("description") {
				rule.Description = patSet.description
			}
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				setExitCode(writeClientInitErr(ic, err))
				return nil
			}
			var res daemon.AdminMutationResult[types.RiskPatternRule]
			if err := client.DoJSON(cmd.Context(), http.MethodPost, "/rpc/v1/risk-patterns", map[string]any{
				"rule":    rule,
				"dry_run": patSet.dryRun,
			}, &res); err != nil {
				setExitCode(writeRPCErr(ic, err))
				return nil
			}
			if ic.JSONMode {
				setExitCode(ic.WriteSuccess(res, types.Meta{}))
				return nil
			}
			_, _ = fmt.Fprintf(ic.Stdout, "Risk pattern %s (%s:%s): %s\n", res.Item.Name, res.Item.ScopeType, res.Item.ScopeID, res.Status)
			return nil
		},
	}
	patternSetCmd.Flags().StringVarP(&patSet.file, "file", "f", "", "YAML or JSON RiskPatternRule spec file")
	patternSetCmd.Flags().BoolVar(&patSet.stdin, "stdin", false, "Read YAML or JSON RiskPatternRule spec from stdin")
	patternSetCmd.Flags().StringVar(&patSet.scopeType, "scope-type", "global", "Scope type (global|env|system|target)")
	patternSetCmd.Flags().StringVar(&patSet.scopeID, "scope-id", "global", "Scope reference")
	patternSetCmd.Flags().StringVar(&patSet.action, "action", string(types.PatternActionRequireApproval), "Action (elevate_high_cost|require_approval|deny)")
	patternSetCmd.Flags().StringVar(&patSet.regex, "regex", "", "Regex condition pattern")
	patternSetCmd.Flags().StringVar(&patSet.regexTarget, "target", "normalized_no_literals", "Regex target (normalized_no_literals|normalized|raw)")
	patternSetCmd.Flags().BoolVar(&patSet.caseSensitive, "case-sensitive", false, "Case-sensitive regex match")
	patternSetCmd.Flags().StringArrayVar(&patSet.engines, "engine", nil, "Restrict to engine (repeatable)")
	patternSetCmd.Flags().BoolVar(&patSet.enabled, "enabled", true, "Enable or disable rule")
	patternSetCmd.Flags().IntVar(&patSet.priority, "priority", 0, "Rule priority")
	patternSetCmd.Flags().StringVar(&patSet.confirmTitle, "confirm-title", "", "Custom approval title")
	patternSetCmd.Flags().StringVar(&patSet.confirmMessage, "confirm-message", "", "Custom approval message")
	patternSetCmd.Flags().StringVar(&patSet.approvalProvider, "approval-provider", "", "Approval provider override")
	patternSetCmd.Flags().StringVar(&patSet.description, "description", "", "Rule description")
	patternSetCmd.Flags().BoolVar(&patSet.dryRun, "dry-run", false, "Preview change without saving")
	annotateCommand(patternSetCmd, RiskWriteLocal, `agent-dbctl pattern set block-drop-prod --scope-type env --scope-id prod --action deny --regex '\bTRUNCATE\b' --json`)

	var patDelScopeType, patDelScopeID string
	var patDelYes bool
	patternDeleteCmd := &cobra.Command{
		Use:   "delete <name-or-id>",
		Short: "Delete a RiskPatternRule",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				setExitCode(writeClientInitErr(ic, err))
				return nil
			}
			path := "/rpc/v1/risk-patterns/" + url.PathEscape(args[0])
			q := url.Values{}
			if patDelScopeType != "" {
				q.Set("scope_type", patDelScopeType)
			}
			if patDelScopeID != "" {
				q.Set("scope_id", patDelScopeID)
			}
			if encoded := q.Encode(); encoded != "" {
				path += "?" + encoded
			}
			var out map[string]bool
			if err := client.DoJSON(cmd.Context(), http.MethodDelete, path, nil, &out); err != nil {
				setExitCode(writeRPCErr(ic, err))
				return nil
			}
			if ic.JSONMode {
				setExitCode(ic.WriteSuccess(map[string]any{"deleted": true, "pattern": args[0]}, types.Meta{}))
				return nil
			}
			_, _ = fmt.Fprintf(ic.Stdout, "Deleted risk pattern %s\n", args[0])
			return nil
		},
	}
	patternDeleteCmd.Flags().StringVar(&patDelScopeType, "scope-type", "", "Scope type hint if disambiguating by name")
	patternDeleteCmd.Flags().StringVar(&patDelScopeID, "scope-id", "", "Scope ID hint if disambiguating by name")
	patternDeleteCmd.Flags().BoolVarP(&patDelYes, "yes", "y", false, "Confirm deletion non-interactively")
	annotateCommand(patternDeleteCmd, RiskWriteLocal, "agent-dbctl pattern delete block-drop-prod --yes --json")

	var packScopeType, packScopeID string
	var packDryRun bool
	patternPackCmd := &cobra.Command{
		Use:   "install-pack <pack-id>",
		Short: "Install a curated built-in high-risk pattern pack",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				setExitCode(writeClientInitErr(ic, err))
				return nil
			}
			var res daemon.AdminMutationResult[[]types.RiskPatternRule]
			if err := client.DoJSON(cmd.Context(), http.MethodPost, "/rpc/v1/risk-patterns/packs/"+url.PathEscape(args[0])+"/install", map[string]any{
				"scope_type": packScopeType,
				"scope_id":   packScopeID,
				"dry_run":    packDryRun,
			}, &res); err != nil {
				setExitCode(writeRPCErr(ic, err))
				return nil
			}
			if ic.JSONMode {
				setExitCode(ic.WriteSuccess(res, types.Meta{}))
				return nil
			}
			_, _ = fmt.Fprintf(ic.Stdout, "Pack %s (%s): %d rule(s)\n", args[0], res.Status, len(res.Item))
			return nil
		},
	}
	patternPackCmd.Flags().StringVar(&packScopeType, "scope-type", "global", "Scope type (global|env|system|target)")
	patternPackCmd.Flags().StringVar(&packScopeID, "scope-id", "global", "Scope reference")
	patternPackCmd.Flags().BoolVar(&packDryRun, "dry-run", false, "Preview pack installation without saving")
	annotateCommand(patternPackCmd, RiskWriteLocal, "agent-dbctl pattern install-pack dangerous-reads --scope-type env --scope-id prod --json")

	var patTest struct {
		db     string
		engine string
		tier   string
		query  string
	}
	patternTestCmd := &cobra.Command{
		Use:   "test [query]",
		Short: "Evaluate a query against active policy & risk patterns without executing",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			q := strings.TrimSpace(patTest.query)
			if q == "" && len(args) == 1 {
				q = strings.TrimSpace(args[0])
			}
			if q == "" {
				setExitCode(ic.WriteError(types.ErrCodeInvalidUsage, false, "Query is required.", "Pass --query or positional query string.", nil, nil, types.Meta{}))
				return nil
			}
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				setExitCode(writeClientInitErr(ic, err))
				return nil
			}
			var res types.PatternTestResult
			if err := client.DoJSON(cmd.Context(), http.MethodPost, "/rpc/v1/risk-patterns/test", types.PatternTestRequest{
				TargetID:   patTest.db,
				Engine:     patTest.engine,
				SafetyTier: types.SafetyTier(patTest.tier),
				Query:      q,
			}, &res); err != nil {
				setExitCode(writeRPCErr(ic, err))
				return nil
			}
			if ic.JSONMode {
				setExitCode(ic.WriteSuccess(res, types.Meta{}))
				return nil
			}
			_, _ = fmt.Fprintf(ic.Stdout, "Risk=%s Decision=%s MatchedRules=%d\n", res.Classification.RiskLevel, res.Evaluation.Decision, len(res.MatchedRules))
			return nil
		},
	}
	patternTestCmd.Flags().StringVar(&patTest.db, "db", "", "Target ref, alias, or ID")
	patternTestCmd.Flags().StringVar(&patTest.engine, "engine", "postgres", "Engine if --db is omitted")
	patternTestCmd.Flags().StringVar(&patTest.tier, "safety-tier", "guarded", "Safety tier if --db is omitted")
	patternTestCmd.Flags().StringVar(&patTest.query, "query", "", "Query string to evaluate")
	annotateCommand(patternTestCmd, RiskRead, `agent-dbctl pattern test --db prod-orders "SELECT pg_sleep(10)" --json`)
	patternCmd.AddCommand(patternListCmd, patternSetCmd, patternDeleteCmd, patternPackCmd, patternTestCmd)

	// ---- approval (strictly read-only inspection) ----
	appCmd := &cobra.Command{Use: "approval", Short: "Inspect human approval requests (approving/rejecting stays human-only)"}
	var appStatus string
	var appLimit int
	appListCmd := &cobra.Command{
		Use:   "list",
		Short: "List pending or historical approval requests (read-only)",
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				setExitCode(writeClientInitErr(ic, err))
				return nil
			}
			q := url.Values{}
			q.Set("limit", strconv.Itoa(appLimit))
			if appStatus != "" {
				q.Set("status", appStatus)
			}
			path := "/rpc/v1/approvals?" + q.Encode()
			var res struct {
				Items []types.ApprovalRequest `json:"items"`
			}
			if err := client.DoJSON(cmd.Context(), http.MethodGet, path, nil, &res); err != nil {
				setExitCode(writeRPCErr(ic, err))
				return nil
			}
			if ic.JSONMode {
				setExitCode(ic.WriteSuccess(map[string]any{"items": res.Items, "count": len(res.Items)}, types.Meta{}))
				return nil
			}
			rows := make([][]string, 0, len(res.Items))
			for _, a := range res.Items {
				rows = append(rows, []string{a.ID, string(a.Status), a.TargetRef, a.EnvironmentCode, string(a.RiskLevel), a.Reason})
			}
			renderTable(ic.Stdout, []string{"ID", "STATUS", "TARGET", "ENV", "RISK", "REASON"}, rows)
			return nil
		},
	}
	appListCmd.Flags().StringVar(&appStatus, "status", "", "Filter by status (pending|approved|rejected|expired|cancelled)")
	appListCmd.Flags().IntVar(&appLimit, "limit", 50, "Maximum approval rows to list")
	annotateCommand(appListCmd, RiskRead, "agent-dbctl approval list --status pending --json")

	appShowCmd := &cobra.Command{
		Use:   "show <approval-id>",
		Short: "Inspect one approval request (read-only)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				setExitCode(writeClientInitErr(ic, err))
				return nil
			}
			var app types.ApprovalRequest
			if err := client.DoJSON(cmd.Context(), http.MethodGet, "/rpc/v1/approvals/"+url.PathEscape(args[0]), nil, &app); err != nil {
				setExitCode(writeRPCErr(ic, err))
				return nil
			}
			if ic.JSONMode {
				setExitCode(ic.WriteSuccess(app, types.Meta{}))
				return nil
			}
			_, _ = fmt.Fprintf(ic.Stdout, "Approval %s (%s)\nTarget: %s (%s)\nOperation: %s\nReason: %s\n", app.ID, app.Status, app.TargetRef, app.EnvironmentCode, app.OperationID, app.Reason)
			return nil
		},
	}
	annotateCommand(appShowCmd, RiskRead, "agent-dbctl approval show app_123 --json")
	appCmd.AddCommand(appListCmd, appShowCmd)

	root.AddCommand(secCmd, policyCmd, patternCmd, appCmd)
}

func readSpecFile(filePath string) ([]byte, error) {
	p := config.ExpandHomePath(filePath)
	if err := config.ValidateRegularFile(p); err != nil {
		return nil, fmt.Errorf("validate spec file: %w", err)
	}
	return os.ReadFile(p)
}

func yamlOrJSONDecode(raw []byte, dst any) error {
	trimmed := strings.TrimSpace(string(raw))
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return json.Unmarshal(raw, dst)
	}
	return yaml.Unmarshal(raw, dst)
}

func jsonMarshalPretty(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func writeOutputPathErr(ic IOContext, err error) int {
	code := types.ErrCodeInvalidInput
	if strings.Contains(err.Error(), "already exists") {
		code = types.ErrCodeOutputExists
	}
	return ic.WriteError(code, false, err.Error(), "", nil, nil, types.Meta{})
}

func boolPtr(b bool) *bool {
	v := b
	return &v
}
