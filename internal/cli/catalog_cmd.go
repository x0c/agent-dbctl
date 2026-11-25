package cli

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/x0c/agent-dbctl/internal/approval"
	"github.com/x0c/agent-dbctl/internal/config"
	"github.com/x0c/agent-dbctl/internal/daemon"
	drvplugin "github.com/x0c/agent-dbctl/internal/driver/plugin"
	"github.com/x0c/agent-dbctl/internal/types"
)

type daemonEnsurer func(ic IOContext, version, commit string) (*daemon.Client, error)

func registerDBWriteCommands(
	dbCmd *cobra.Command,
	ioCtx func() IOContext,
	ensureDaemon daemonEnsurer,
	writeClientInitErr func(IOContext, error) int,
	writeRPCErr func(IOContext, error) int,
	setExitCode func(int),
	version, commit string,
) {
	var addOpts struct {
		dsn         string
		dsnEnv      string
		dsnStdin    bool
		engine      string
		host        string
		port        int
		database    string
		tlsMode     string
		params      []string
		ref         string
		alias       string
		system      string
		systemName  string
		workspaces  []string
		gitRemotes  []string
		noWorkspace bool
		env         string
		instance    string
		role        string
		network     string
		user        string
		credName    string
		credKind    string
		accessLevel string
		roCred      string
		rwCred      string
		envVarName  string
		execCommand string
		secretEnv   string
		secretFile  string
		secretStdin bool
		status      string
		description string
		test        bool
		dryRun      bool
		openSecret  bool
	}
	dbAddCmd := &cobra.Command{
		Use:   "add",
		Short: "Declaratively onboard a database target via DSN or flags",
		Long: `Create or idempotently converge System, CredentialProfile, Instance, and Target in one command.

Secrets can be provided via --secret-env, --secret-file, --secret-stdin, --dsn-env, --dsn-stdin,
or omitted entirely (Keychain with blank password) and filled interactively by the user in Web UI
with --open-secret or 'agent-dbctl ui open --credential <name>'.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			dsnVal, inlineDSNUsed, err := readDSNInput(addOpts.dsn, addOpts.dsnEnv, addOpts.dsnStdin)
			if err != nil {
				setExitCode(ic.WriteError(types.ErrCodeInvalidUsage, false, err.Error(), "Provide at most one of --dsn, --dsn-env, or --dsn-stdin.", nil, nil, types.Meta{}))
				return nil
			}
			secVal, secProvided, err := readSecretInput(addOpts.secretEnv, addOpts.secretFile, addOpts.secretStdin)
			if err != nil {
				setExitCode(ic.WriteError(types.ErrCodeInvalidUsage, false, err.Error(), "Provide at most one of --secret-env, --secret-file, or --secret-stdin.", nil, nil, types.Meta{}))
				return nil
			}
			paramsMap, err := parseKeyValuePairs(addOpts.params)
			if err != nil {
				setExitCode(ic.WriteError(types.ErrCodeInvalidUsage, false, err.Error(), "Use --param key=value.", nil, nil, types.Meta{}))
				return nil
			}
			cwd, detectedRemotes := detectWorkspaceContext(cmd.Context(), addOpts.noWorkspace)
			req := daemon.DBAddRequest{
				DSN:                   dsnVal,
				InlinePasswordWarning: inlineDSNUsed,
				Engine:                addOpts.engine,
				Host:                  addOpts.host,
				Port:                  addOpts.port,
				Database:              addOpts.database,
				TLSMode:               addOpts.tlsMode,
				Params:                paramsMap,
				Ref:                   addOpts.ref,
				Alias:                 addOpts.alias,
				System:                addOpts.system,
				SystemName:            addOpts.systemName,
				WorkspaceCWD:          cwd,
				WorkspacePaths:        addOpts.workspaces,
				WorkspaceGitRemotes:   detectedRemotes,
				GitRemotes:            addOpts.gitRemotes,
				NoWorkspace:           addOpts.noWorkspace,
				Env:                   addOpts.env,
				Instance:              addOpts.instance,
				Role:                  types.InstanceRole(addOpts.role),
				Network:               addOpts.network,
				User:                  addOpts.user,
				CredName:              addOpts.credName,
				CredKind:              types.CredentialKind(addOpts.credKind),
				AccessLevel:           types.AccessLevel(addOpts.accessLevel),
				ROCred:                addOpts.roCred,
				RWCred:                addOpts.rwCred,
				EnvVarName:            addOpts.envVarName,
				ExecCommand:           addOpts.execCommand,
				SecretValue:           secVal,
				SecretProvided:        secProvided,
				Status:                types.TargetStatus(addOpts.status),
				Description:           addOpts.description,
				DryRun:                addOpts.dryRun,
				Test:                  addOpts.test,
			}

			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				setExitCode(writeClientInitErr(ic, err))
				return nil
			}
			var res daemon.DBAddResponse
			if err := client.DoJSON(cmd.Context(), http.MethodPost, "/rpc/v1/db/add", req, &res); err != nil {
				setExitCode(writeRPCErr(ic, err))
				return nil
			}
			if !addOpts.dryRun && addOpts.openSecret && len(res.MissingSecrets) > 0 && os.Getenv(config.EnvNoBrowser) != "1" {
				if res.MissingSecrets[0].SetupURL != "" {
					_ = approval.OpenBrowser(res.MissingSecrets[0].SetupURL)
				}
			}
			if ic.JSONMode {
				setExitCode(ic.WriteSuccess(res, types.Meta{}))
				return nil
			}
			_, _ = fmt.Fprintf(ic.Stdout, "Target: %s (%s, env=%s, engine=%s)\n", res.Target.Ref, res.Status, res.Target.Env, res.Target.Engine)
			if len(res.MissingSecrets) > 0 {
				for _, ms := range res.MissingSecrets {
					_, _ = fmt.Fprintf(ic.Stdout, "Missing secret for credential %q (%s): %s\n", ms.Name, ms.ID, ms.SetupURL)
				}
			}
			if res.Ping != nil {
				_, _ = fmt.Fprintf(ic.Stdout, "Live test: reachable=%v latency=%dms version=%s err=%s\n", res.Ping.Reachable, res.Ping.LatencyMs, res.Ping.ServerVersion, res.Ping.Error)
			}
			for _, w := range res.Warnings {
				_, _ = fmt.Fprintf(ic.Stderr, "Warning: %s\n", w)
			}
			for _, n := range res.NextCommands {
				_, _ = fmt.Fprintf(ic.Stdout, "Next: %s\n", n)
			}
			return nil
		},
	}
	dbAddCmd.Flags().StringVar(&addOpts.dsn, "dsn", "", "Database connection URI/DSN (avoid inline passwords; prefer --dsn-env or --open-secret)")
	dbAddCmd.Flags().StringVar(&addOpts.dsnEnv, "dsn-env", "", "Environment variable name containing the DSN")
	dbAddCmd.Flags().BoolVar(&addOpts.dsnStdin, "dsn-stdin", false, "Read DSN from stdin")
	dbAddCmd.Flags().StringVar(&addOpts.engine, "engine", "", "Database engine (postgres, mysql, sqlite, mongodb, redis, clickhouse, mssql, oracle, elasticsearch, or alias)")
	dbAddCmd.Flags().StringVar(&addOpts.host, "host", "", "Database host or SQLite file path")
	dbAddCmd.Flags().IntVar(&addOpts.port, "port", 0, "Database port (defaults by engine)")
	dbAddCmd.Flags().StringVar(&addOpts.database, "database", "", "Logical database/schema/DB index")
	dbAddCmd.Flags().StringVar(&addOpts.tlsMode, "tls-mode", "", "TLS mode (disable|prefer|require|verify-full)")
	dbAddCmd.Flags().StringArrayVar(&addOpts.params, "param", nil, "Extra driver parameter as key=value (repeatable)")
	dbAddCmd.Flags().StringVar(&addOpts.ref, "ref", "", "Target ref (default: <system>/<env>/<db>)")
	dbAddCmd.Flags().StringVar(&addOpts.alias, "alias", "", "Short alias for the target")
	dbAddCmd.Flags().StringVar(&addOpts.system, "system", "", "System slug or ID (default: matched workspace/Git repo or directory name)")
	dbAddCmd.Flags().StringVar(&addOpts.systemName, "system-name", "", "Display name if creating a new system")
	dbAddCmd.Flags().StringArrayVar(&addOpts.workspaces, "workspace-path", nil, "Workspace path to bind to the system (repeatable)")
	dbAddCmd.Flags().StringArrayVar(&addOpts.gitRemotes, "git-remote", nil, "Git remote URL or host/org/repo to bind to the system (repeatable)")
	dbAddCmd.Flags().BoolVar(&addOpts.noWorkspace, "no-workspace", false, "Do not bind current working directory or Git remotes to system")
	dbAddCmd.Flags().StringVar(&addOpts.env, "env", "dev", "Environment code (default: dev)")
	dbAddCmd.Flags().StringVar(&addOpts.instance, "instance", "", "Existing or custom Instance name/ID")
	dbAddCmd.Flags().StringVar(&addOpts.role, "role", "", "Instance role (primary|replica|standalone)")
	dbAddCmd.Flags().StringVar(&addOpts.network, "network", "", "Existing NetworkProfile name or ID")
	dbAddCmd.Flags().StringVar(&addOpts.user, "user", "", "Database username")
	dbAddCmd.Flags().StringVar(&addOpts.credName, "cred-name", "", "CredentialProfile name when creating/reusing")
	dbAddCmd.Flags().StringVar(&addOpts.credKind, "cred-kind", "", "Credential kind (keychain|env_ref|exec_provider)")
	dbAddCmd.Flags().StringVar(&addOpts.accessLevel, "access-level", "", "Credential access level (read_only|read_write)")
	dbAddCmd.Flags().StringVar(&addOpts.roCred, "ro-cred", "", "Existing read-only CredentialProfile name or ID")
	dbAddCmd.Flags().StringVar(&addOpts.rwCred, "rw-cred", "", "Existing read-write CredentialProfile name or ID")
	dbAddCmd.Flags().StringVar(&addOpts.envVarName, "env-var-name", "", "Environment variable name when using env_ref")
	dbAddCmd.Flags().StringVar(&addOpts.execCommand, "exec-command", "", "Shell command when using exec_provider")
	dbAddCmd.Flags().StringVar(&addOpts.secretEnv, "secret-env", "", "Environment variable name holding the password/secret")
	dbAddCmd.Flags().StringVar(&addOpts.secretFile, "secret-file", "", "File path holding the password/secret")
	dbAddCmd.Flags().BoolVar(&addOpts.secretStdin, "secret-stdin", false, "Read password/secret from stdin")
	dbAddCmd.Flags().StringVar(&addOpts.status, "status", "", "Target status (active|maintenance|disabled)")
	dbAddCmd.Flags().StringVar(&addOpts.description, "description", "", "Target description")
	dbAddCmd.Flags().BoolVar(&addOpts.test, "test", false, "Run live Ping test after configuring target")
	dbAddCmd.Flags().BoolVar(&addOpts.dryRun, "dry-run", false, "Preview planned catalog/credential changes without writing")
	dbAddCmd.Flags().BoolVar(&addOpts.openSecret, "open-secret", false, "Open Web Console password-entry modal if keychain secret is missing")
	annotateCommand(dbAddCmd, RiskWriteLocal, "agent-dbctl db add --dsn postgres://reader@localhost:5432/app --env dev --open-secret --json\nagent-dbctl db add --engine sqlite --host ./app.db --env dev --test --json")

	var setOpts struct {
		ref         string
		alias       string
		system      string
		env         string
		instance    string
		database    string
		roCred      string
		rwCred      string
		policy      string
		status      string
		description string
		clearRWCred bool
		clearPolicy bool
		dryRun      bool
	}
	dbSetCmd := &cobra.Command{
		Use:   "set <ref-or-alias>",
		Short: "Update metadata or bindings on an existing database target",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				setExitCode(writeClientInitErr(ic, err))
				return nil
			}
			cwd, gitRemotes := detectWorkspaceContext(cmd.Context(), false)
			var detail types.TargetDetail
			if err := client.DoJSON(cmd.Context(), http.MethodPost, "/rpc/v1/db/show", map[string]any{
				"target":                args[0],
				"workspace_cwd":         cwd,
				"workspace_git_remotes": gitRemotes,
			}, &detail); err != nil {
				setExitCode(writeRPCErr(ic, err))
				return nil
			}
			tgt := detail.Target
			if cmd.Flags().Changed("ref") {
				tgt.Ref = setOpts.ref
			}
			if cmd.Flags().Changed("alias") {
				tgt.Alias = setOpts.alias
			}
			if cmd.Flags().Changed("system") {
				tgt.OwnerSystemID = setOpts.system
			}
			if cmd.Flags().Changed("env") {
				tgt.EnvironmentCode = setOpts.env
			}
			if cmd.Flags().Changed("instance") {
				tgt.InstanceID = setOpts.instance
			}
			if cmd.Flags().Changed("database") {
				tgt.DatabaseName = setOpts.database
			}
			if cmd.Flags().Changed("ro-cred") {
				tgt.ROCredentialID = setOpts.roCred
			}
			if setOpts.clearRWCred {
				tgt.RWCredentialID = ""
			} else if cmd.Flags().Changed("rw-cred") {
				tgt.RWCredentialID = setOpts.rwCred
			}
			if setOpts.clearPolicy {
				tgt.PolicyOverrideID = ""
			} else if cmd.Flags().Changed("policy") {
				tgt.PolicyOverrideID = setOpts.policy
			}
			if cmd.Flags().Changed("status") {
				tgt.Status = types.TargetStatus(setOpts.status)
			}
			if cmd.Flags().Changed("description") {
				tgt.Description = setOpts.description
			}
			var res daemon.AdminMutationResult[types.Target]
			if err := client.DoJSON(cmd.Context(), http.MethodPost, "/rpc/v1/targets", map[string]any{
				"target":  tgt,
				"dry_run": setOpts.dryRun,
			}, &res); err != nil {
				setExitCode(writeRPCErr(ic, err))
				return nil
			}
			if ic.JSONMode {
				setExitCode(ic.WriteSuccess(res, types.Meta{}))
				return nil
			}
			_, _ = fmt.Fprintf(ic.Stdout, "Target %s: %s\n", res.Item.Ref, res.Status)
			return nil
		},
	}
	dbSetCmd.Flags().StringVar(&setOpts.ref, "ref", "", "New target ref")
	dbSetCmd.Flags().StringVar(&setOpts.alias, "alias", "", "Target alias")
	dbSetCmd.Flags().StringVar(&setOpts.system, "system", "", "Owner system slug or ID")
	dbSetCmd.Flags().StringVar(&setOpts.env, "env", "", "Environment code")
	dbSetCmd.Flags().StringVar(&setOpts.instance, "instance", "", "Instance name or ID")
	dbSetCmd.Flags().StringVar(&setOpts.database, "database", "", "Logical database name")
	dbSetCmd.Flags().StringVar(&setOpts.roCred, "ro-cred", "", "Read-only credential name or ID")
	dbSetCmd.Flags().StringVar(&setOpts.rwCred, "rw-cred", "", "Read-write credential name or ID")
	dbSetCmd.Flags().StringVar(&setOpts.policy, "policy", "", "Target policy override name or ID")
	dbSetCmd.Flags().StringVar(&setOpts.status, "status", "", "Status (active|maintenance|disabled)")
	dbSetCmd.Flags().StringVar(&setOpts.description, "description", "", "Description")
	dbSetCmd.Flags().BoolVar(&setOpts.clearRWCred, "clear-rw-cred", false, "Detach read-write credential")
	dbSetCmd.Flags().BoolVar(&setOpts.clearPolicy, "clear-policy", false, "Detach policy override")
	dbSetCmd.Flags().BoolVar(&setOpts.dryRun, "dry-run", false, "Preview change without saving")
	annotateCommand(dbSetCmd, RiskWriteLocal, "agent-dbctl db set myapp/dev/app --alias app-dev --json")

	var deleteYes bool
	dbDeleteCmd := &cobra.Command{
		Use:   "delete <ref-or-alias-or-id>",
		Short: "Delete a database target from the catalog",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				setExitCode(writeClientInitErr(ic, err))
				return nil
			}
			var out map[string]bool
			if err := client.DoJSON(cmd.Context(), http.MethodDelete, "/rpc/v1/targets/"+url.PathEscape(args[0]), nil, &out); err != nil {
				setExitCode(writeRPCErr(ic, err))
				return nil
			}
			if ic.JSONMode {
				setExitCode(ic.WriteSuccess(map[string]any{"deleted": true, "target": args[0]}, types.Meta{}))
				return nil
			}
			_, _ = fmt.Fprintf(ic.Stdout, "Deleted target %s\n", args[0])
			return nil
		},
	}
	dbDeleteCmd.Flags().BoolVarP(&deleteYes, "yes", "y", false, "Confirm deletion non-interactively")
	annotateCommand(dbDeleteCmd, RiskWriteLocal, "agent-dbctl db delete myapp/dev/app --yes --json")

	dbCmd.AddCommand(dbAddCmd, dbSetCmd, dbDeleteCmd)
}

func registerCatalogCommands(
	root *cobra.Command,
	ioCtx func() IOContext,
	ensureDaemon daemonEnsurer,
	writeClientInitErr func(IOContext, error) int,
	writeRPCErr func(IOContext, error) int,
	setExitCode func(int),
	version, commit string,
) {
	// ---- system ----
	systemCmd := &cobra.Command{Use: "system", Short: "Manage logical business systems and workspace bindings"}
	systemListCmd := &cobra.Command{
		Use:   "list",
		Short: "List configured systems",
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				setExitCode(writeClientInitErr(ic, err))
				return nil
			}
			var res struct {
				Items []types.System `json:"items"`
			}
			if err := client.DoJSON(cmd.Context(), http.MethodGet, "/rpc/v1/systems", nil, &res); err != nil {
				setExitCode(writeRPCErr(ic, err))
				return nil
			}
			if ic.JSONMode {
				setExitCode(ic.WriteSuccess(map[string]any{"items": res.Items, "count": len(res.Items)}, types.Meta{}))
				return nil
			}
			rows := make([][]string, 0, len(res.Items))
			for _, s := range res.Items {
				rows = append(rows, []string{s.Slug, s.Name, s.Owner, strings.Join(s.Tags, ","), strings.Join(s.WorkspacePaths, ","), strings.Join(s.GitRemotes, ",")})
			}
			renderTable(ic.Stdout, []string{"SLUG", "NAME", "OWNER", "TAGS", "WORKSPACES", "GIT_REMOTES"}, rows)
			return nil
		},
	}
	annotateCommand(systemListCmd, RiskRead, "agent-dbctl system list --json")

	var sysSet struct {
		slug          string
		name          string
		owner         string
		desc          string
		tags          []string
		workspaces    []string
		gitRemotes    []string
		defaultPolicy string
		dryRun        bool
	}
	systemSetCmd := &cobra.Command{
		Use:   "set [slug]",
		Short: "Create or update a system idempotently",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			slug := strings.TrimSpace(sysSet.slug)
			if len(args) == 1 && slug == "" {
				slug = strings.TrimSpace(args[0])
			}
			if slug == "" {
				setExitCode(ic.WriteError(types.ErrCodeInvalidUsage, false, "System slug is required.", "Pass <slug> or --slug <slug>.", nil, nil, types.Meta{}))
				return nil
			}
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				setExitCode(writeClientInitErr(ic, err))
				return nil
			}
			var existing struct {
				Items []types.System `json:"items"`
			}
			_ = client.DoJSON(cmd.Context(), http.MethodGet, "/rpc/v1/systems", nil, &existing)
			var cur types.System
			for _, s := range existing.Items {
				if strings.EqualFold(s.Slug, slug) || s.ID == slug {
					cur = s
					break
				}
			}
			if cur.Slug == "" {
				cur.Slug = slug
			}
			if cmd.Flags().Changed("name") || cur.Name == "" {
				cur.Name = firstNonEmpty(sysSet.name, slug)
			}
			if cmd.Flags().Changed("owner") {
				cur.Owner = sysSet.owner
			}
			if cmd.Flags().Changed("description") {
				cur.Description = sysSet.desc
			}
			if cmd.Flags().Changed("tag") {
				cur.Tags = sysSet.tags
			}
			if cmd.Flags().Changed("workspace-path") {
				cur.WorkspacePaths = sysSet.workspaces
			}
			if cmd.Flags().Changed("git-remote") {
				cur.GitRemotes = config.NormalizeGitRemotes(sysSet.gitRemotes)
			}
			if cmd.Flags().Changed("default-policy") {
				cur.DefaultPolicyID = sysSet.defaultPolicy
			}
			var res daemon.AdminMutationResult[types.System]
			if err := client.DoJSON(cmd.Context(), http.MethodPost, "/rpc/v1/systems", map[string]any{
				"system":  cur,
				"dry_run": sysSet.dryRun,
			}, &res); err != nil {
				setExitCode(writeRPCErr(ic, err))
				return nil
			}
			if ic.JSONMode {
				setExitCode(ic.WriteSuccess(res, types.Meta{}))
				return nil
			}
			_, _ = fmt.Fprintf(ic.Stdout, "System %s: %s\n", res.Item.Slug, res.Status)
			return nil
		},
	}
	systemSetCmd.Flags().StringVar(&sysSet.slug, "slug", "", "System slug")
	systemSetCmd.Flags().StringVar(&sysSet.name, "name", "", "Display name")
	systemSetCmd.Flags().StringVar(&sysSet.owner, "owner", "", "Owning team or person")
	systemSetCmd.Flags().StringVar(&sysSet.desc, "description", "", "Description")
	systemSetCmd.Flags().StringArrayVar(&sysSet.tags, "tag", nil, "System tag (repeatable)")
	systemSetCmd.Flags().StringArrayVar(&sysSet.workspaces, "workspace-path", nil, "Bound workspace directory path (repeatable)")
	systemSetCmd.Flags().StringArrayVar(&sysSet.gitRemotes, "git-remote", nil, "Bound Git remote URL or host/org/repo (repeatable)")
	systemSetCmd.Flags().StringVar(&sysSet.defaultPolicy, "default-policy", "", "Default PolicyRuleSet name or ID")
	systemSetCmd.Flags().BoolVar(&sysSet.dryRun, "dry-run", false, "Preview change without saving")
	annotateCommand(systemSetCmd, RiskWriteLocal, "agent-dbctl system set orders --name Orders --workspace-path . --json")

	var sysDelYes bool
	systemDeleteCmd := &cobra.Command{
		Use:   "delete <slug-or-id>",
		Short: "Delete a system",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				setExitCode(writeClientInitErr(ic, err))
				return nil
			}
			var out map[string]bool
			if err := client.DoJSON(cmd.Context(), http.MethodDelete, "/rpc/v1/systems/"+url.PathEscape(args[0]), nil, &out); err != nil {
				setExitCode(writeRPCErr(ic, err))
				return nil
			}
			if ic.JSONMode {
				setExitCode(ic.WriteSuccess(map[string]any{"deleted": true, "system": args[0]}, types.Meta{}))
				return nil
			}
			_, _ = fmt.Fprintf(ic.Stdout, "Deleted system %s\n", args[0])
			return nil
		},
	}
	systemDeleteCmd.Flags().BoolVarP(&sysDelYes, "yes", "y", false, "Confirm deletion non-interactively")
	annotateCommand(systemDeleteCmd, RiskWriteLocal, "agent-dbctl system delete orders --yes --json")
	systemCmd.AddCommand(systemListCmd, systemSetCmd, systemDeleteCmd)

	// ---- env ----
	envCmd := &cobra.Command{Use: "env", Short: "Manage environment tiers (dev, test, stage, prod)"}
	envListCmd := &cobra.Command{
		Use:   "list",
		Short: "List configured environments",
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				setExitCode(writeClientInitErr(ic, err))
				return nil
			}
			var res struct {
				Items []types.Environment `json:"items"`
			}
			if err := client.DoJSON(cmd.Context(), http.MethodGet, "/rpc/v1/environments", nil, &res); err != nil {
				setExitCode(writeRPCErr(ic, err))
				return nil
			}
			if ic.JSONMode {
				setExitCode(ic.WriteSuccess(map[string]any{"items": res.Items, "count": len(res.Items)}, types.Meta{}))
				return nil
			}
			rows := make([][]string, 0, len(res.Items))
			for _, e := range res.Items {
				rows = append(rows, []string{e.Code, string(e.SafetyTier), e.Color, strconv.Itoa(e.SortOrder), e.DefaultPolicyID})
			}
			renderTable(ic.Stdout, []string{"CODE", "SAFETY_TIER", "COLOR", "SORT", "DEFAULT_POLICY"}, rows)
			return nil
		},
	}
	annotateCommand(envListCmd, RiskRead, "agent-dbctl env list --json")

	var envSet struct {
		safetyTier    string
		color         string
		sortOrder     int
		defaultPolicy string
		labels        []string
		dryRun        bool
	}
	envSetCmd := &cobra.Command{
		Use:   "set <code>",
		Short: "Create or update an environment tier",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			code := strings.TrimSpace(args[0])
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				setExitCode(writeClientInitErr(ic, err))
				return nil
			}
			var existing struct {
				Items []types.Environment `json:"items"`
			}
			_ = client.DoJSON(cmd.Context(), http.MethodGet, "/rpc/v1/environments", nil, &existing)
			var cur types.Environment
			for _, e := range existing.Items {
				if strings.EqualFold(e.Code, code) {
					cur = e
					break
				}
			}
			cur.Code = code
			if cmd.Flags().Changed("safety-tier") || cur.SafetyTier == "" {
				cur.SafetyTier = types.SafetyTier(firstNonEmpty(envSet.safetyTier, string(types.SafetyTierGuarded)))
			}
			if cmd.Flags().Changed("color") {
				cur.Color = envSet.color
			}
			if cmd.Flags().Changed("sort-order") {
				cur.SortOrder = envSet.sortOrder
			}
			if cmd.Flags().Changed("default-policy") {
				cur.DefaultPolicyID = envSet.defaultPolicy
			}
			if cmd.Flags().Changed("label") {
				m, err := parseKeyValuePairs(envSet.labels)
				if err != nil {
					setExitCode(ic.WriteError(types.ErrCodeInvalidUsage, false, err.Error(), "Use --label lang=label.", nil, nil, types.Meta{}))
					return nil
				}
				cur.Labels = m
			}
			var res daemon.AdminMutationResult[types.Environment]
			if err := client.DoJSON(cmd.Context(), http.MethodPost, "/rpc/v1/environments", map[string]any{
				"environment": cur,
				"dry_run":     envSet.dryRun,
			}, &res); err != nil {
				setExitCode(writeRPCErr(ic, err))
				return nil
			}
			if ic.JSONMode {
				setExitCode(ic.WriteSuccess(res, types.Meta{}))
				return nil
			}
			_, _ = fmt.Fprintf(ic.Stdout, "Environment %s: %s (tier=%s)\n", res.Item.Code, res.Status, res.Item.SafetyTier)
			return nil
		},
	}
	envSetCmd.Flags().StringVar(&envSet.safetyTier, "safety-tier", "", "Safety tier (yolo|guarded|strict)")
	envSetCmd.Flags().StringVar(&envSet.color, "color", "", "Hex badge color")
	envSetCmd.Flags().IntVar(&envSet.sortOrder, "sort-order", 0, "Display sort order")
	envSetCmd.Flags().StringVar(&envSet.defaultPolicy, "default-policy", "", "Default PolicyRuleSet name or ID")
	envSetCmd.Flags().StringArrayVar(&envSet.labels, "label", nil, "Localized label as key=value (repeatable)")
	envSetCmd.Flags().BoolVar(&envSet.dryRun, "dry-run", false, "Preview change without saving")
	annotateCommand(envSetCmd, RiskWriteLocal, "agent-dbctl env set staging --safety-tier guarded --json")
	envCmd.AddCommand(envListCmd, envSetCmd)

	// ---- network ----
	netCmd := &cobra.Command{Use: "network", Short: "Manage network/tunnel profiles (direct, ssh_tunnel, socks5, http_proxy)"}
	netListCmd := &cobra.Command{
		Use:   "list",
		Short: "List network profiles",
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				setExitCode(writeClientInitErr(ic, err))
				return nil
			}
			var res struct {
				Items []types.NetworkProfile `json:"items"`
			}
			if err := client.DoJSON(cmd.Context(), http.MethodGet, "/rpc/v1/network-profiles", nil, &res); err != nil {
				setExitCode(writeRPCErr(ic, err))
				return nil
			}
			if ic.JSONMode {
				setExitCode(ic.WriteSuccess(map[string]any{"items": res.Items, "count": len(res.Items)}, types.Meta{}))
				return nil
			}
			rows := make([][]string, 0, len(res.Items))
			for _, n := range res.Items {
				rows = append(rows, []string{n.ID, n.Name, string(n.Mode), firstNonEmpty(n.BastionHost, n.ProxyURL), n.TLSMode})
			}
			renderTable(ic.Stdout, []string{"ID", "NAME", "MODE", "ENDPOINT", "TLS"}, rows)
			return nil
		},
	}
	annotateCommand(netListCmd, RiskRead, "agent-dbctl network list --json")

	var netSet struct {
		mode          string
		proxyURL      string
		bastionHost   string
		bastionPort   int
		bastionUser   string
		bastionCred   string
		strictHostKey bool
		tlsMode       string
		dryRun        bool
	}
	netSetCmd := &cobra.Command{
		Use:   "set <name-or-id>",
		Short: "Create or update a network profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			nameOrID := strings.TrimSpace(args[0])
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				setExitCode(writeClientInitErr(ic, err))
				return nil
			}
			var existing struct {
				Items []types.NetworkProfile `json:"items"`
			}
			_ = client.DoJSON(cmd.Context(), http.MethodGet, "/rpc/v1/network-profiles", nil, &existing)
			var cur types.NetworkProfile
			for _, n := range existing.Items {
				if n.ID == nameOrID || strings.EqualFold(n.Name, nameOrID) {
					cur = n
					break
				}
			}
			if cur.Name == "" {
				cur.Name = nameOrID
			}
			if cmd.Flags().Changed("mode") || cur.Mode == "" {
				cur.Mode = types.NetworkMode(firstNonEmpty(netSet.mode, string(types.NetworkDirect)))
			}
			if cmd.Flags().Changed("proxy-url") {
				cur.ProxyURL = netSet.proxyURL
			}
			if cmd.Flags().Changed("bastion-host") {
				cur.BastionHost = netSet.bastionHost
			}
			if cmd.Flags().Changed("bastion-port") {
				cur.BastionPort = netSet.bastionPort
			}
			if cmd.Flags().Changed("bastion-user") {
				cur.BastionUser = netSet.bastionUser
			}
			if cmd.Flags().Changed("bastion-cred") {
				cur.BastionCredentialID = netSet.bastionCred
			}
			if cmd.Flags().Changed("strict-host-key") {
				cur.SSHStrictHostKey = netSet.strictHostKey
			}
			if cmd.Flags().Changed("tls-mode") {
				cur.TLSMode = netSet.tlsMode
			}
			var res daemon.AdminMutationResult[types.NetworkProfile]
			if err := client.DoJSON(cmd.Context(), http.MethodPost, "/rpc/v1/network-profiles", map[string]any{
				"network_profile": cur,
				"dry_run":         netSet.dryRun,
			}, &res); err != nil {
				setExitCode(writeRPCErr(ic, err))
				return nil
			}
			if ic.JSONMode {
				setExitCode(ic.WriteSuccess(res, types.Meta{}))
				return nil
			}
			_, _ = fmt.Fprintf(ic.Stdout, "Network profile %s: %s\n", res.Item.Name, res.Status)
			return nil
		},
	}
	netSetCmd.Flags().StringVar(&netSet.mode, "mode", "", "Network mode (direct|ssh_tunnel|socks5|http_proxy)")
	netSetCmd.Flags().StringVar(&netSet.proxyURL, "proxy-url", "", "SOCKS5 or HTTP proxy URL")
	netSetCmd.Flags().StringVar(&netSet.bastionHost, "bastion-host", "", "SSH bastion host")
	netSetCmd.Flags().IntVar(&netSet.bastionPort, "bastion-port", 22, "SSH bastion port")
	netSetCmd.Flags().StringVar(&netSet.bastionUser, "bastion-user", "", "SSH bastion username")
	netSetCmd.Flags().StringVar(&netSet.bastionCred, "bastion-cred", "", "SSH bastion credential name or ID")
	netSetCmd.Flags().BoolVar(&netSet.strictHostKey, "strict-host-key", true, "Enforce SSH strict host key verification")
	netSetCmd.Flags().StringVar(&netSet.tlsMode, "tls-mode", "", "TLS mode")
	netSetCmd.Flags().BoolVar(&netSet.dryRun, "dry-run", false, "Preview change without saving")
	annotateCommand(netSetCmd, RiskWriteLocal, "agent-dbctl network set corp-socks --mode socks5 --proxy-url socks5://127.0.0.1:1080 --json")

	var netDelYes bool
	netDeleteCmd := &cobra.Command{
		Use:   "delete <name-or-id>",
		Short: "Delete a network profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				setExitCode(writeClientInitErr(ic, err))
				return nil
			}
			var out map[string]bool
			if err := client.DoJSON(cmd.Context(), http.MethodDelete, "/rpc/v1/network-profiles/"+url.PathEscape(args[0]), nil, &out); err != nil {
				setExitCode(writeRPCErr(ic, err))
				return nil
			}
			if ic.JSONMode {
				setExitCode(ic.WriteSuccess(map[string]any{"deleted": true, "network": args[0]}, types.Meta{}))
				return nil
			}
			_, _ = fmt.Fprintf(ic.Stdout, "Deleted network profile %s\n", args[0])
			return nil
		},
	}
	netDeleteCmd.Flags().BoolVarP(&netDelYes, "yes", "y", false, "Confirm deletion non-interactively")
	annotateCommand(netDeleteCmd, RiskWriteLocal, "agent-dbctl network delete corp-socks --yes --json")
	netCmd.AddCommand(netListCmd, netSetCmd, netDeleteCmd)

	// ---- cred ----
	credCmd := &cobra.Command{Use: "cred", Short: "Manage credential profiles (secret-free metadata; Web handoff supported)"}
	credListCmd := &cobra.Command{
		Use:   "list",
		Short: "List credential profiles (never outputs secret values)",
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				setExitCode(writeClientInitErr(ic, err))
				return nil
			}
			var res struct {
				Items []types.CredentialProfile `json:"items"`
			}
			if err := client.DoJSON(cmd.Context(), http.MethodGet, "/rpc/v1/credentials", nil, &res); err != nil {
				setExitCode(writeRPCErr(ic, err))
				return nil
			}
			if ic.JSONMode {
				setExitCode(ic.WriteSuccess(map[string]any{"items": res.Items, "count": len(res.Items)}, types.Meta{}))
				return nil
			}
			rows := make([][]string, 0, len(res.Items))
			for _, c := range res.Items {
				rows = append(rows, []string{c.ID, c.Name, string(c.Kind), string(c.AccessLevel), c.Username, fmt.Sprintf("%v", c.HasSecret)})
			}
			renderTable(ic.Stdout, []string{"ID", "NAME", "KIND", "ACCESS", "USERNAME", "HAS_SECRET"}, rows)
			return nil
		},
	}
	annotateCommand(credListCmd, RiskRead, "agent-dbctl cred list --json")

	var credSet struct {
		kind        string
		access      string
		username    string
		envVarName  string
		execCommand string
		secretEnv   string
		secretFile  string
		secretStdin bool
		clearSecret bool
		openSecret  bool
		dryRun      bool
	}
	credSetCmd := &cobra.Command{
		Use:   "set <name-or-id>",
		Short: "Create or update a credential profile (password may remain blank for Web entry)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			nameOrID := strings.TrimSpace(args[0])
			if credSet.clearSecret && (credSet.secretEnv != "" || credSet.secretFile != "" || credSet.secretStdin) {
				setExitCode(ic.WriteError(types.ErrCodeInvalidUsage, false, "--clear-secret cannot be combined with secret input flags.", "", nil, nil, types.Meta{}))
				return nil
			}
			secVal, secProvided, err := readSecretInput(credSet.secretEnv, credSet.secretFile, credSet.secretStdin)
			if err != nil {
				setExitCode(ic.WriteError(types.ErrCodeInvalidUsage, false, err.Error(), "Provide at most one of --secret-env, --secret-file, or --secret-stdin.", nil, nil, types.Meta{}))
				return nil
			}
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				setExitCode(writeClientInitErr(ic, err))
				return nil
			}
			var existing struct {
				Items []types.CredentialProfile `json:"items"`
			}
			_ = client.DoJSON(cmd.Context(), http.MethodGet, "/rpc/v1/credentials", nil, &existing)
			var cur types.CredentialProfile
			for _, c := range existing.Items {
				if c.ID == nameOrID || strings.EqualFold(c.Name, nameOrID) {
					cur = c
					break
				}
			}
			if cur.Name == "" {
				cur.Name = nameOrID
			}
			if cmd.Flags().Changed("kind") || cur.Kind == "" {
				cur.Kind = types.CredentialKind(firstNonEmpty(credSet.kind, string(types.CredKeychain)))
			}
			if cmd.Flags().Changed("access-level") || cur.AccessLevel == "" {
				cur.AccessLevel = types.AccessLevel(firstNonEmpty(credSet.access, string(types.AccessReadOnly)))
			}
			if cmd.Flags().Changed("user") {
				cur.Username = credSet.username
			}
			if cmd.Flags().Changed("env-var-name") {
				cur.EnvVarName = credSet.envVarName
			}
			if cmd.Flags().Changed("exec-command") {
				cur.ExecCommand = credSet.execCommand
			}
			var res daemon.AdminMutationResult[types.CredentialProfile]
			if err := client.DoJSON(cmd.Context(), http.MethodPost, "/rpc/v1/credentials", daemon.CredentialUpsertRequest{
				CredentialProfile: cur,
				SecretValue:       secVal,
				SecretProvided:    secProvided,
				ClearSecret:       credSet.clearSecret,
				DryRun:            credSet.dryRun,
			}, &res); err != nil {
				setExitCode(writeRPCErr(ic, err))
				return nil
			}
			if !credSet.dryRun && credSet.openSecret && len(res.MissingSecrets) > 0 && os.Getenv(config.EnvNoBrowser) != "1" {
				if res.MissingSecrets[0].SetupURL != "" {
					_ = approval.OpenBrowser(res.MissingSecrets[0].SetupURL)
				}
			}
			if ic.JSONMode {
				setExitCode(ic.WriteSuccess(res, types.Meta{}))
				return nil
			}
			_, _ = fmt.Fprintf(ic.Stdout, "Credential %s (%s): %s (has_secret=%v)\n", res.Item.Name, res.Item.ID, res.Status, res.Item.HasSecret)
			for _, ms := range res.MissingSecrets {
				_, _ = fmt.Fprintf(ic.Stdout, "Enter secret in Web UI: %s\n", ms.SetupURL)
			}
			return nil
		},
	}
	credSetCmd.Flags().StringVar(&credSet.kind, "kind", "", "Credential kind (keychain|env_ref|exec_provider)")
	credSetCmd.Flags().StringVar(&credSet.access, "access-level", "", "Access level (read_only|read_write)")
	credSetCmd.Flags().StringVar(&credSet.username, "user", "", "Database username")
	credSetCmd.Flags().StringVar(&credSet.envVarName, "env-var-name", "", "Env var name for env_ref")
	credSetCmd.Flags().StringVar(&credSet.execCommand, "exec-command", "", "Command for exec_provider")
	credSetCmd.Flags().StringVar(&credSet.secretEnv, "secret-env", "", "Env var name holding password/secret")
	credSetCmd.Flags().StringVar(&credSet.secretFile, "secret-file", "", "File path holding password/secret")
	credSetCmd.Flags().BoolVar(&credSet.secretStdin, "secret-stdin", false, "Read password/secret from stdin")
	credSetCmd.Flags().BoolVar(&credSet.clearSecret, "clear-secret", false, "Clear stored keychain secret")
	credSetCmd.Flags().BoolVar(&credSet.openSecret, "open-secret", false, "Open Web Console password-entry modal if keychain secret is missing")
	credSetCmd.Flags().BoolVar(&credSet.dryRun, "dry-run", false, "Preview change without saving")
	annotateCommand(credSetCmd, RiskWriteLocal, "agent-dbctl cred set orders-ro --kind keychain --access-level read_only --user reader --open-secret --json")

	var credDelYes bool
	credDeleteCmd := &cobra.Command{
		Use:   "delete <name-or-id>",
		Short: "Delete a credential profile and its stored keychain secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				setExitCode(writeClientInitErr(ic, err))
				return nil
			}
			var out map[string]bool
			if err := client.DoJSON(cmd.Context(), http.MethodDelete, "/rpc/v1/credentials/"+url.PathEscape(args[0]), nil, &out); err != nil {
				setExitCode(writeRPCErr(ic, err))
				return nil
			}
			if ic.JSONMode {
				setExitCode(ic.WriteSuccess(map[string]any{"deleted": true, "credential": args[0]}, types.Meta{}))
				return nil
			}
			_, _ = fmt.Fprintf(ic.Stdout, "Deleted credential %s\n", args[0])
			return nil
		},
	}
	credDeleteCmd.Flags().BoolVarP(&credDelYes, "yes", "y", false, "Confirm deletion non-interactively")
	annotateCommand(credDeleteCmd, RiskWriteLocal, "agent-dbctl cred delete orders-ro --yes --json")
	credCmd.AddCommand(credListCmd, credSetCmd, credDeleteCmd)

	// ---- instance ----
	instCmd := &cobra.Command{Use: "instance", Short: "Manage database instances, connectivity tests, and database discovery"}
	instListCmd := &cobra.Command{
		Use:   "list",
		Short: "List database instances",
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				setExitCode(writeClientInitErr(ic, err))
				return nil
			}
			var res struct {
				Items []types.Instance `json:"items"`
			}
			if err := client.DoJSON(cmd.Context(), http.MethodGet, "/rpc/v1/instances", nil, &res); err != nil {
				setExitCode(writeRPCErr(ic, err))
				return nil
			}
			if ic.JSONMode {
				setExitCode(ic.WriteSuccess(map[string]any{"items": res.Items, "count": len(res.Items)}, types.Meta{}))
				return nil
			}
			rows := make([][]string, 0, len(res.Items))
			for _, inst := range res.Items {
				rows = append(rows, []string{inst.ID, inst.Name, inst.Engine, fmt.Sprintf("%s:%d", inst.Host, inst.Port), string(inst.Role), inst.TLSMode})
			}
			renderTable(ic.Stdout, []string{"ID", "NAME", "ENGINE", "ENDPOINT", "ROLE", "TLS"}, rows)
			return nil
		},
	}
	annotateCommand(instListCmd, RiskRead, "agent-dbctl instance list --json")

	var instSet struct {
		engine    string
		host      string
		port      int
		role      string
		primaryID string
		network   string
		tlsMode   string
		params    []string
		dryRun    bool
	}
	instSetCmd := &cobra.Command{
		Use:   "set <name-or-id>",
		Short: "Create or update a database instance",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			nameOrID := strings.TrimSpace(args[0])
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				setExitCode(writeClientInitErr(ic, err))
				return nil
			}
			var existing struct {
				Items []types.Instance `json:"items"`
			}
			_ = client.DoJSON(cmd.Context(), http.MethodGet, "/rpc/v1/instances", nil, &existing)
			var cur types.Instance
			for _, i := range existing.Items {
				if i.ID == nameOrID || strings.EqualFold(i.Name, nameOrID) {
					cur = i
					break
				}
			}
			if cur.Name == "" {
				cur.Name = nameOrID
			}
			if cmd.Flags().Changed("engine") {
				cur.Engine = instSet.engine
			}
			if cmd.Flags().Changed("host") {
				cur.Host = instSet.host
			}
			if cmd.Flags().Changed("port") {
				cur.Port = instSet.port
			}
			if cmd.Flags().Changed("role") || cur.Role == "" {
				cur.Role = types.InstanceRole(firstNonEmpty(instSet.role, string(types.RolePrimary)))
			}
			if cmd.Flags().Changed("primary") {
				cur.PrimaryInstanceID = instSet.primaryID
			}
			if cmd.Flags().Changed("network") {
				cur.NetworkProfileID = instSet.network
			}
			if cmd.Flags().Changed("tls-mode") {
				cur.TLSMode = instSet.tlsMode
			}
			if cmd.Flags().Changed("param") {
				m, err := parseKeyValuePairs(instSet.params)
				if err != nil {
					setExitCode(ic.WriteError(types.ErrCodeInvalidUsage, false, err.Error(), "Use --param key=value.", nil, nil, types.Meta{}))
					return nil
				}
				cur.Params = m
			}
			var res daemon.AdminMutationResult[types.Instance]
			if err := client.DoJSON(cmd.Context(), http.MethodPost, "/rpc/v1/instances", map[string]any{
				"instance": cur,
				"dry_run":  instSet.dryRun,
			}, &res); err != nil {
				setExitCode(writeRPCErr(ic, err))
				return nil
			}
			if ic.JSONMode {
				setExitCode(ic.WriteSuccess(res, types.Meta{}))
				return nil
			}
			_, _ = fmt.Fprintf(ic.Stdout, "Instance %s (%s:%d): %s\n", res.Item.Name, res.Item.Host, res.Item.Port, res.Status)
			return nil
		},
	}
	instSetCmd.Flags().StringVar(&instSet.engine, "engine", "", "Database engine")
	instSetCmd.Flags().StringVar(&instSet.host, "host", "", "Host or SQLite path")
	instSetCmd.Flags().IntVar(&instSet.port, "port", 0, "TCP port (0 for default / SQLite)")
	instSetCmd.Flags().StringVar(&instSet.role, "role", "", "Role (primary|replica|standalone)")
	instSetCmd.Flags().StringVar(&instSet.primaryID, "primary", "", "Primary instance name or ID (for replicas)")
	instSetCmd.Flags().StringVar(&instSet.network, "network", "", "NetworkProfile name or ID")
	instSetCmd.Flags().StringVar(&instSet.tlsMode, "tls-mode", "", "TLS mode")
	instSetCmd.Flags().StringArrayVar(&instSet.params, "param", nil, "Extra driver param key=value (repeatable)")
	instSetCmd.Flags().BoolVar(&instSet.dryRun, "dry-run", false, "Preview change without saving")
	annotateCommand(instSetCmd, RiskWriteLocal, "agent-dbctl instance set pg-local --engine postgres --host 127.0.0.1 --port 5432 --json")

	var instDelYes bool
	instDeleteCmd := &cobra.Command{
		Use:   "delete <name-or-id>",
		Short: "Delete an instance",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				setExitCode(writeClientInitErr(ic, err))
				return nil
			}
			var out map[string]bool
			if err := client.DoJSON(cmd.Context(), http.MethodDelete, "/rpc/v1/instances/"+url.PathEscape(args[0]), nil, &out); err != nil {
				setExitCode(writeRPCErr(ic, err))
				return nil
			}
			if ic.JSONMode {
				setExitCode(ic.WriteSuccess(map[string]any{"deleted": true, "instance": args[0]}, types.Meta{}))
				return nil
			}
			_, _ = fmt.Fprintf(ic.Stdout, "Deleted instance %s\n", args[0])
			return nil
		},
	}
	instDeleteCmd.Flags().BoolVarP(&instDelYes, "yes", "y", false, "Confirm deletion non-interactively")
	annotateCommand(instDeleteCmd, RiskWriteLocal, "agent-dbctl instance delete pg-local --yes --json")

	var instProbeCred, instProbeDB string
	instTestCmd := &cobra.Command{
		Use:   "test <name-or-id>",
		Short: "Probe live connectivity to a configured instance",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				setExitCode(writeClientInitErr(ic, err))
				return nil
			}
			var res types.PingResult
			if err := client.DoJSON(cmd.Context(), http.MethodPost, "/rpc/v1/instances/"+url.PathEscape(args[0])+"/test", map[string]string{
				"credential_id": instProbeCred,
				"database_name": instProbeDB,
			}, &res); err != nil {
				setExitCode(writeRPCErr(ic, err))
				return nil
			}
			if ic.JSONMode {
				if !res.Reachable {
					setExitCode(ic.WriteError(types.ErrCodeDriverError, true, res.Error, "Verify endpoint, network profile, and credential.", map[string]any{"result": res}, nil, types.Meta{}))
					return nil
				}
				setExitCode(ic.WriteSuccess(res, types.Meta{}))
				return nil
			}
			_, _ = fmt.Fprintf(ic.Stdout, "Instance %s: reachable=%v latency=%dms version=%s err=%s\n", args[0], res.Reachable, res.LatencyMs, res.ServerVersion, res.Error)
			if !res.Reachable {
				setExitCode(types.ExitFailure)
			}
			return nil
		},
	}
	instTestCmd.Flags().StringVar(&instProbeCred, "cred", "", "Credential name or ID")
	instTestCmd.Flags().StringVar(&instProbeDB, "database", "", "Override database name for handshake")
	annotateCommand(instTestCmd, RiskExecuteRemote, "agent-dbctl instance test pg-local --cred orders-ro --json")

	var instDiscCred, instDiscDB string
	instDiscoverCmd := &cobra.Command{
		Use:   "discover <name-or-id>",
		Short: "List databases/schemas/indices hosted on an instance",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				setExitCode(writeClientInitErr(ic, err))
				return nil
			}
			var res struct {
				Instance  string   `json:"instance"`
				Engine    string   `json:"engine"`
				Databases []string `json:"databases"`
			}
			if err := client.DoJSON(cmd.Context(), http.MethodPost, "/rpc/v1/instances/"+url.PathEscape(args[0])+"/discover", map[string]string{
				"credential_id": instDiscCred,
				"database_name": instDiscDB,
			}, &res); err != nil {
				setExitCode(writeRPCErr(ic, err))
				return nil
			}
			if ic.JSONMode {
				setExitCode(ic.WriteSuccess(res, types.Meta{}))
				return nil
			}
			for _, db := range res.Databases {
				_, _ = fmt.Fprintln(ic.Stdout, db)
			}
			return nil
		},
	}
	instDiscoverCmd.Flags().StringVar(&instDiscCred, "cred", "", "Credential name or ID")
	instDiscoverCmd.Flags().StringVar(&instDiscDB, "database", "", "Seed database for connection handshake")
	annotateCommand(instDiscoverCmd, RiskExecuteRemote, "agent-dbctl instance discover pg-local --cred orders-ro --json")
	instCmd.AddCommand(instListCmd, instSetCmd, instDeleteCmd, instTestCmd, instDiscoverCmd)

	// ---- topology ----
	topoCmd := &cobra.Command{Use: "topology", Short: "Inspect schema, export, and declaratively apply secret-free catalog topology"}
	var topoSchemaOpts struct {
		format  string
		outPath string
		force   bool
	}
	topoSchemaCmd := &cobra.Command{
		Use:   "schema",
		Short: "Print documented TopologyBundle template and natural-key reference rules (offline)",
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			tpl := buildTopologyTemplate()
			fmtChoice := strings.ToLower(strings.TrimSpace(topoSchemaOpts.format))
			if fmtChoice == "" {
				if ic.JSONMode {
					fmtChoice = "json"
				} else {
					fmtChoice = "yaml"
				}
			}
			var rawOut []byte
			if fmtChoice == "yaml" || fmtChoice == "yml" {
				rawYAML, err := yaml.Marshal(tpl)
				if err != nil {
					setExitCode(ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{}))
					return nil
				}
				rawOut = append([]byte(topologySchemaHeaderComment()), rawYAML...)
			} else {
				fmtChoice = "json"
			}
			if topoSchemaOpts.outPath != "" {
				if fmtChoice == "json" {
					rawOut, _ = jsonMarshalPretty(tpl)
				}
				absPath, err := WriteAtomicOutput(topoSchemaOpts.outPath, rawOut, topoSchemaOpts.force)
				if err != nil {
					setExitCode(writeOutputPathErr(ic, err))
					return nil
				}
				if ic.JSONMode {
					setExitCode(ic.WriteSuccess(map[string]any{"output_file": absPath, "format": fmtChoice}, types.Meta{}))
					return nil
				}
				_, _ = fmt.Fprintf(ic.Stdout, "Wrote topology schema template to %s\n", absPath)
				return nil
			}
			if ic.JSONMode && fmtChoice == "json" {
				setExitCode(ic.WriteSuccess(tpl, types.Meta{}))
				return nil
			}
			if ic.JSONMode {
				setExitCode(ic.WriteSuccess(map[string]any{"format": fmtChoice, "yaml": string(rawOut)}, types.Meta{}))
				return nil
			}
			_, _ = ic.Stdout.Write(rawOut)
			return nil
		},
	}
	topoSchemaCmd.Flags().StringVar(&topoSchemaOpts.format, "format", "", "Output format (yaml|json)")
	topoSchemaCmd.Flags().StringVar(&topoSchemaOpts.outPath, "out", "", "Write template atomically to file path")
	topoSchemaCmd.Flags().BoolVar(&topoSchemaOpts.force, "force", false, "Overwrite existing --out file")
	annotateCommand(topoSchemaCmd, RiskRead, "agent-dbctl topology schema --format yaml\nagent-dbctl topology schema --json")

	var topoExportOpts struct {
		format  string
		outPath string
		force   bool
	}
	topoExportCmd := &cobra.Command{
		Use:   "export",
		Short: "Export current catalog, policies, and risk patterns (secret-free)",
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				setExitCode(writeClientInitErr(ic, err))
				return nil
			}
			fmtChoice := strings.ToLower(strings.TrimSpace(topoExportOpts.format))
			if fmtChoice == "" {
				if ic.JSONMode && topoExportOpts.outPath == "" {
					fmtChoice = "json"
				} else {
					fmtChoice = "yaml"
				}
			}
			rpcPath := "/rpc/v1/topology"
			if fmtChoice == "yaml" || fmtChoice == "yml" {
				fmtChoice = "yaml"
				rpcPath += "?format=yaml"
			} else {
				fmtChoice = "json"
			}
			raw, err := client.DoRaw(cmd.Context(), http.MethodGet, rpcPath, "", nil)
			if err != nil {
				setExitCode(writeRPCErr(ic, err))
				return nil
			}
			if topoExportOpts.outPath != "" {
				absPath, err := WriteAtomicOutput(topoExportOpts.outPath, raw, topoExportOpts.force)
				if err != nil {
					setExitCode(writeOutputPathErr(ic, err))
					return nil
				}
				if ic.JSONMode {
					setExitCode(ic.WriteSuccess(map[string]any{"output_file": absPath, "format": fmtChoice}, types.Meta{}))
					return nil
				}
				_, _ = fmt.Fprintf(ic.Stdout, "Exported topology (%s) to %s\n", fmtChoice, absPath)
				return nil
			}
			if fmtChoice == "json" {
				var bundle types.TopologyBundle
				if err := yamlOrJSONDecode(raw, &bundle); err != nil {
					setExitCode(ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{}))
					return nil
				}
				if ic.JSONMode {
					setExitCode(ic.WriteSuccess(bundle, types.Meta{}))
					return nil
				}
				pretty, _ := jsonMarshalPretty(bundle)
				_, _ = fmt.Fprintln(ic.Stdout, string(pretty))
				return nil
			}
			if ic.JSONMode {
				setExitCode(ic.WriteSuccess(map[string]any{"format": "yaml", "yaml": string(raw)}, types.Meta{}))
				return nil
			}
			_, _ = ic.Stdout.Write(raw)
			return nil
		},
	}
	topoExportCmd.Flags().StringVar(&topoExportOpts.format, "format", "", "Export format (yaml|json)")
	topoExportCmd.Flags().StringVar(&topoExportOpts.outPath, "out", "", "Write topology atomically to file path")
	topoExportCmd.Flags().BoolVar(&topoExportOpts.force, "force", false, "Overwrite existing --out file")
	annotateCommand(topoExportCmd, RiskRead, "agent-dbctl topology export --format yaml --out topology.yaml")

	var topoApplyOpts struct {
		file       string
		stdin      bool
		dryRun     bool
		openSecret bool
	}
	topoApplyCmd := &cobra.Command{
		Use:   "apply",
		Short: "Apply a YAML or JSON topology bundle idempotently",
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			raw, err := readTopologyBytes(topoApplyOpts.file, topoApplyOpts.stdin)
			if err != nil {
				setExitCode(ic.WriteError(types.ErrCodeInvalidUsage, false, err.Error(), "Pass -f <topology.yaml|json> or --stdin.", nil, []string{ic.BinPath + " topology schema"}, types.Meta{}))
				return nil
			}
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				setExitCode(writeClientInitErr(ic, err))
				return nil
			}
			rpcPath := "/rpc/v1/topology"
			if topoApplyOpts.dryRun {
				rpcPath += "?dry_run=1"
			}
			ct := "application/yaml"
			if strings.HasPrefix(strings.TrimSpace(string(raw)), "{") {
				ct = "application/json"
			}
			respRaw, err := client.DoRaw(cmd.Context(), http.MethodPost, rpcPath, ct, raw)
			if err != nil {
				setExitCode(writeRPCErr(ic, err))
				return nil
			}
			var res types.TopologyImportResult
			if err := yamlOrJSONDecode(respRaw, &res); err != nil {
				setExitCode(ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{}))
				return nil
			}
			if !topoApplyOpts.dryRun && topoApplyOpts.openSecret && len(res.MissingSecrets) > 0 && os.Getenv(config.EnvNoBrowser) != "1" {
				if res.MissingSecrets[0].SetupURL != "" {
					_ = approval.OpenBrowser(res.MissingSecrets[0].SetupURL)
				}
			}
			if ic.JSONMode {
				setExitCode(ic.WriteSuccess(res, types.Meta{}))
				return nil
			}
			_, _ = fmt.Fprintf(ic.Stdout, "Topology %s (dry_run=%v): systems(+%d/~%d) creds(+%d/~%d) instances(+%d/~%d) targets(+%d/~%d)\n",
				res.Status, res.DryRun,
				res.Summary.Systems.Created, res.Summary.Systems.Updated,
				res.Summary.CredentialProfiles.Created, res.Summary.CredentialProfiles.Updated,
				res.Summary.Instances.Created, res.Summary.Instances.Updated,
				res.Summary.Targets.Created, res.Summary.Targets.Updated)
			for _, ms := range res.MissingSecrets {
				_, _ = fmt.Fprintf(ic.Stdout, "Missing secret for credential %q (%s): %s\n", ms.Name, ms.ID, ms.SetupURL)
			}
			return nil
		},
	}
	topoApplyCmd.Flags().StringVarP(&topoApplyOpts.file, "file", "f", "", "YAML or JSON topology file path")
	topoApplyCmd.Flags().BoolVar(&topoApplyOpts.stdin, "stdin", false, "Read YAML or JSON topology from stdin")
	topoApplyCmd.Flags().BoolVar(&topoApplyOpts.dryRun, "dry-run", false, "Plan changes without mutating catalog or writing audit entries")
	topoApplyCmd.Flags().BoolVar(&topoApplyOpts.openSecret, "open-secret", false, "Open Web Console password modal for first keychain credential missing a secret")
	annotateCommand(topoApplyCmd, RiskWriteLocal, "agent-dbctl topology apply -f topology.yaml --dry-run --json\nagent-dbctl topology apply -f topology.yaml --open-secret --json")
	topoCmd.AddCommand(topoSchemaCmd, topoExportCmd, topoApplyCmd)

	// ---- driver ----
	var driverEngineFilter string
	driverCmd := &cobra.Command{Use: "driver", Short: "Inspect built-in drivers, dialect aliases, default ports, and external plugins"}
	driverListCmd := &cobra.Command{
		Use:   "list",
		Short: "List supported database drivers, dialect aliases, query syntax, and plugins",
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				setExitCode(writeClientInitErr(ic, err))
				return nil
			}
			var res struct {
				Drivers []types.DriverMetadata     `json:"drivers"`
				Guides  []daemon.EngineGuide       `json:"guides"`
				Plugins []drvplugin.DiscoveredPlugin `json:"plugins"`
			}
			if err := client.DoJSON(cmd.Context(), http.MethodGet, "/rpc/v1/drivers", nil, &res); err != nil {
				setExitCode(writeRPCErr(ic, err))
				return nil
			}
			if f := strings.ToLower(strings.TrimSpace(driverEngineFilter)); f != "" {
				var filtered []daemon.EngineGuide
				for _, g := range res.Guides {
					matched := strings.EqualFold(g.Engine, f)
					for _, al := range g.Aliases {
						if strings.EqualFold(al, f) {
							matched = true
							break
						}
					}
					if matched {
						filtered = append(filtered, g)
					}
				}
				res.Guides = filtered
			}
			if ic.JSONMode {
				setExitCode(ic.WriteSuccess(res, types.Meta{}))
				return nil
			}
			rows := make([][]string, 0, len(res.Guides))
			for _, g := range res.Guides {
				rows = append(rows, []string{g.Engine, g.Family, strconv.Itoa(g.DefaultPort), g.Tier, strings.Join(g.Aliases, ","), g.SyntaxHint})
			}
			renderTable(ic.Stdout, []string{"ENGINE", "FAMILY", "PORT", "TIER", "ALIASES", "SYNTAX"}, rows)
			return nil
		},
	}
	driverListCmd.Flags().StringVar(&driverEngineFilter, "engine", "", "Filter to a specific engine or alias")
	annotateCommand(driverListCmd, RiskRead, "agent-dbctl driver list --json")
	driverCmd.AddCommand(driverListCmd)

	root.AddCommand(systemCmd, envCmd, netCmd, credCmd, instCmd, topoCmd, driverCmd)
}

func readDSNInput(dsnFlag, dsnEnv string, dsnStdin bool) (val string, inline bool, err error) {
	count := 0
	if dsnFlag != "" {
		count++
	}
	if dsnEnv != "" {
		count++
	}
	if dsnStdin {
		count++
	}
	if count > 1 {
		return "", false, fmt.Errorf("--dsn, --dsn-env, and --dsn-stdin are mutually exclusive")
	}
	switch {
	case dsnFlag != "":
		return strings.TrimSpace(dsnFlag), true, nil
	case dsnEnv != "":
		v := strings.TrimSpace(os.Getenv(dsnEnv))
		if v == "" {
			return "", false, fmt.Errorf("environment variable %q is empty or unset", dsnEnv)
		}
		return v, false, nil
	case dsnStdin:
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 64*1024))
		if err != nil {
			return "", false, err
		}
		v := strings.TrimSpace(string(b))
		if v == "" {
			return "", false, fmt.Errorf("--dsn-stdin read empty input")
		}
		return v, false, nil
	default:
		return "", false, nil
	}
}

func readSecretInput(secretEnv, secretFile string, secretStdin bool) (val string, provided bool, err error) {
	count := 0
	if secretEnv != "" {
		count++
	}
	if secretFile != "" {
		count++
	}
	if secretStdin {
		count++
	}
	if count > 1 {
		return "", false, fmt.Errorf("--secret-env, --secret-file, and --secret-stdin are mutually exclusive")
	}
	switch {
	case secretEnv != "":
		v, ok := os.LookupEnv(secretEnv)
		if !ok {
			return "", false, fmt.Errorf("environment variable %q is not set", secretEnv)
		}
		return v, true, nil
	case secretFile != "":
		p := config.ExpandHomePath(secretFile)
		if err := config.ValidateRegularFile(p); err != nil {
			return "", false, fmt.Errorf("validate --secret-file: %w", err)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return "", false, err
		}
		return strings.TrimRight(string(b), "\r\n"), true, nil
	case secretStdin:
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 64*1024))
		if err != nil {
			return "", false, err
		}
		return strings.TrimRight(string(b), "\r\n"), true, nil
	default:
		return "", false, nil
	}
}

func readTopologyBytes(filePath string, fromStdin bool) ([]byte, error) {
	if filePath != "" && fromStdin {
		return nil, fmt.Errorf("--file and --stdin are mutually exclusive")
	}
	if filePath != "" {
		p := config.ExpandHomePath(filePath)
		if err := config.ValidateRegularFile(p); err != nil {
			return nil, fmt.Errorf("validate topology file: %w", err)
		}
		return os.ReadFile(p)
	}
	if fromStdin {
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 4<<20))
		if err != nil {
			return nil, err
		}
		if len(strings.TrimSpace(string(b))) == 0 {
			return nil, fmt.Errorf("stdin topology payload is empty")
		}
		return b, nil
	}
	return nil, fmt.Errorf("topology input file (-f/--file) or --stdin is required")
}

func parseKeyValuePairs(pairs []string) (map[string]string, error) {
	if len(pairs) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(pairs))
	for _, item := range pairs {
		k, v, ok := strings.Cut(item, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			return nil, fmt.Errorf("invalid key=value pair %q", item)
		}
		out[k] = strings.TrimSpace(v)
	}
	return out, nil
}

func buildTopologyTemplate() types.TopologyBundle {
	return types.TopologyBundle{
		SchemaVersion: 1,
		Environments: []types.Environment{
			{Code: "dev", SafetyTier: types.SafetyTierYOLO, SortOrder: 10},
			{Code: "prod", SafetyTier: types.SafetyTierStrict, SortOrder: 40},
		},
		Systems: []types.System{
			{
				Slug:           "orders",
				Name:           "Orders Service",
				Owner:          "platform",
				Tags:           []string{"core"},
				WorkspacePaths: []string{filepath.Join("~", "Codes", "orders")},
				GitRemotes:     []string{"github.com/org/orders"},
			},
		},
		NetworkProfiles: []types.NetworkProfile{
			{ID: "net_direct", Name: "direct-tls", Mode: types.NetworkDirect, TLSMode: "require"},
		},
		CredentialProfiles: []types.CredentialProfile{
			{Name: "orders-ro", Kind: types.CredKeychain, AccessLevel: types.AccessReadOnly, Username: "reader"},
			{Name: "orders-rw-env", Kind: types.CredEnvRef, AccessLevel: types.AccessReadWrite, Username: "writer", EnvVarName: "ORDERS_DB_PASS"},
		},
		Instances: []types.Instance{
			{
				Name:             "orders-pg-primary",
				Engine:           "postgres",
				Host:             "127.0.0.1",
				Port:             5432,
				Role:             types.RolePrimary,
				NetworkProfileID: "name:direct-tls",
				TLSMode:          "require",
			},
		},
		Targets: []types.Target{
			{
				Ref:             "orders/dev/main",
				Alias:           "orders-dev",
				OwnerSystemID:   "slug:orders",
				EnvironmentCode: "dev",
				InstanceID:      "name:orders-pg-primary",
				DatabaseName:    "orders",
				ROCredentialID:  "name:orders-ro",
				RWCredentialID:  "name:orders-rw-env",
				Status:          types.TargetActive,
			},
		},
	}
}

func topologySchemaHeaderComment() string {
	return `# agent-dbctl TopologyBundle (secret-free YAML or JSON)
# Natural-key references avoid hardcoding internal UUIDs:
#   owner_system_id / scope_id (system):  "slug:<slug>" or system slug/ID
#   instance_id / primary_instance_id:    "name:<name>" or instance name/ID
#   network_profile_id:                   "name:<name>" or network name/ID
#   ro_credential_id / rw_credential_id:  "name:<name>" or credential name/ID (secrets NEVER belong in topology files)
#   policy_override_id / default_policy_id: "name:<name>" or policy name/ID
#   scope_id (target):                    "ref:<target_ref>" or target ref/alias/ID
# Apply with: agent-dbctl topology apply -f topology.yaml --dry-run --json
#             agent-dbctl topology apply -f topology.yaml --open-secret --json
`
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
