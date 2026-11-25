package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/x0c/agent-dbctl/internal/approval"
	"github.com/x0c/agent-dbctl/internal/auth"
	"github.com/x0c/agent-dbctl/internal/config"
	"github.com/x0c/agent-dbctl/internal/daemon"
	"github.com/x0c/agent-dbctl/internal/secrets"
	"github.com/x0c/agent-dbctl/internal/types"
)

func isRemoteIO(ic IOContext) bool {
	return ic.Mode == string(config.ContextModeRemote)
}

func detectWorkspaceContextForIO(ctx context.Context, ic IOContext, noWorkspace bool) (string, []string) {
	cwd, remotes := detectWorkspaceContext(ctx, noWorkspace)
	if isRemoteIO(ic) {
		cwd = ""
	}
	return cwd, remotes
}

func resolveRemoteToken(paths config.Paths, ctxCfg config.ClientContext) string {
	if strings.TrimSpace(ctxCfg.TokenEnv) != "" {
		if v := strings.TrimSpace(os.Getenv(ctxCfg.TokenEnv)); v != "" {
			return v
		}
	}
	if v := strings.TrimSpace(os.Getenv(config.EnvToken)); v != "" {
		return v
	}
	sec := secrets.NewStore(paths)
	if v, err := sec.Get(context.Background(), "ctx-token:"+ctxCfg.Name); err == nil {
		return strings.TrimSpace(v)
	}
	return ""
}

func waitForOperationLoop(ctx context.Context, client *daemon.Client, opID string, totalTimeout time.Duration) (types.ExecResponse, error) {
	if totalTimeout <= 0 {
		totalTimeout = 120 * time.Second
	}
	if !client.IsRemote() {
		tSec := int(totalTimeout.Seconds())
		if tSec <= 0 {
			tSec = 1
		}
		var resp types.ExecResponse
		err := client.DoJSON(ctx, http.MethodGet, fmt.Sprintf("/rpc/v1/ops/%s/wait?timeout_sec=%d", url.PathEscape(opID), tSec), nil, &resp)
		return resp, err
	}

	deadline := time.Now().Add(totalTimeout)
	var last types.ExecResponse
	for {
		if err := ctx.Err(); err != nil {
			return last, err
		}
		rem := time.Until(deadline)
		if rem <= 0 {
			return last, nil
		}
		chunk := rem
		if chunk > 25*time.Second {
			chunk = 25 * time.Second
		}
		chunkSec := int(chunk.Seconds())
		if chunkSec <= 0 {
			chunkSec = 1
		}
		var resp types.ExecResponse
		if err := client.DoJSON(ctx, http.MethodGet, fmt.Sprintf("/rpc/v1/ops/%s/wait?timeout_sec=%d", url.PathEscape(opID), chunkSec), nil, &resp); err != nil {
			return last, err
		}
		last = resp
		switch resp.Status {
		case types.OpSucceeded, types.OpFailed, types.OpDenied, types.OpRejected, types.OpExpired, types.OpCancelled, types.OpTimedOut:
			return resp, nil
		}
	}
}

func newServeCmd(ioCtx func() IOContext, version, commit string, exitCode *int) *cobra.Command {
	var cfgPath, listenAddr, publicURL string
	var allowSQLite bool
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run multi-user centralized agent-dbctl server (Web Console + HTTPS/RPC)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ic := ioCtx()
			paths, err := config.ResolvePaths(ic.Session)
			if err != nil {
				*exitCode = ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{})
				return nil
			}
			cfg, err := config.LoadServerConfig(cfgPath, paths)
			if err != nil {
				*exitCode = ic.WriteError(types.ErrCodeInvalidUsage, false, err.Error(), "Provide --config server.yaml and set AGENT_DBCTL_MASTER_KEY.", nil, nil, types.Meta{})
				return nil
			}
			if strings.TrimSpace(listenAddr) != "" {
				cfg.ListenAddr = strings.TrimSpace(listenAddr)
			}
			if strings.TrimSpace(publicURL) != "" {
				cfg.PublicURL = strings.TrimRight(strings.TrimSpace(publicURL), "/")
			}
			if cmd.Flags().Changed("allow-sqlite") {
				cfg.AllowSQLiteTargets = allowSQLite
			}
			if err := cfg.Validate(); err != nil {
				*exitCode = ic.WriteError(types.ErrCodeInvalidUsage, false, err.Error(), "", nil, nil, types.Meta{})
				return nil
			}
			srv, err := daemon.StartRemoteServer(cmd.Context(), paths, cfg, version, commit)
			if err != nil {
				*exitCode = ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{})
				return nil
			}
			if !ic.JSONMode {
				_, _ = fmt.Fprintf(ic.Stderr, "agent-dbctl server listening on %s (public_url=%s, mode=server)\n", srv.Addr(), cfg.PublicURL)
			}
			if err := srv.Run(cmd.Context()); err != nil {
				*exitCode = ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{})
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "", "Path to server YAML configuration (or AGENT_DBCTL_SERVER_CONFIG)")
	cmd.Flags().StringVar(&listenAddr, "listen", "", "Override HTTP listen address (e.g. 127.0.0.1:8443)")
	cmd.Flags().StringVar(&publicURL, "public-url", "", "Override canonical external base URL (e.g. https://db.example.com)")
	cmd.Flags().BoolVar(&allowSQLite, "allow-sqlite", false, "Allow SQLite database targets in server mode")
	annotateCommand(cmd, RiskWriteLocal, "agent-dbctl serve --config /etc/agent-dbctl/server.yaml")
	return cmd
}

func newContextCmd(ioCtx func() IOContext, exitCode *int) *cobra.Command {
	ctxCmd := &cobra.Command{Use: "context", Short: "Manage local and remote server contexts"}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List configured client contexts",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ic := ioCtx()
			paths, err := config.ResolvePaths(ic.Session)
			if err != nil {
				*exitCode = ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{})
				return nil
			}
			cf, err := config.LoadContexts(paths)
			if err != nil {
				*exitCode = ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{})
				return nil
			}
			type ctxRow struct {
				Name     string             `json:"name"`
				Mode     config.ContextMode `json:"mode"`
				Endpoint string             `json:"endpoint,omitempty"`
				AuthMode config.AuthMode    `json:"auth_mode,omitempty"`
				Current  bool               `json:"current"`
			}
			var rowsOut []ctxRow
			var tableRows [][]string
			for name, c := range cf.Contexts {
				cur := name == cf.CurrentContext
				rowsOut = append(rowsOut, ctxRow{
					Name:     name,
					Mode:     c.Mode,
					Endpoint: c.Endpoint,
					AuthMode: c.AuthMode,
					Current:  cur,
				})
				mark := ""
				if cur {
					mark = "*"
				}
				tableRows = append(tableRows, []string{mark, name, string(c.Mode), c.Endpoint, string(c.AuthMode)})
			}
			if ic.JSONMode {
				*exitCode = ic.WriteSuccess(map[string]any{
					"current_context": cf.CurrentContext,
					"items":           rowsOut,
				}, types.Meta{})
				return nil
			}
			renderTable(ic.Stdout, []string{"CURRENT", "NAME", "MODE", "ENDPOINT", "AUTH"}, tableRows)
			return nil
		},
	}
	annotateCommand(listCmd, RiskRead, "agent-dbctl context list --json")

	showCmd := &cobra.Command{
		Use:   "show [name]",
		Short: "Inspect active or named client context",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			paths, err := config.ResolvePaths(ic.Session)
			if err != nil {
				*exitCode = ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{})
				return nil
			}
			targetName := ic.Context
			if len(args) == 1 {
				targetName = args[0]
			}
			cfg, _, err := config.ResolveActiveContext(paths, targetName)
			if err != nil {
				*exitCode = ic.WriteError(types.ErrCodeNotFound, false, err.Error(), "Run `agent-dbctl context list`.", nil, nil, types.Meta{})
				return nil
			}
			if ic.JSONMode {
				*exitCode = ic.WriteSuccess(cfg, types.Meta{})
				return nil
			}
			_, _ = fmt.Fprintf(ic.Stdout, "Name: %s\nMode: %s\nEndpoint: %s\nAuth: %s\n", cfg.Name, cfg.Mode, cfg.Endpoint, cfg.AuthMode)
			return nil
		},
	}
	annotateCommand(showCmd, RiskRead, "agent-dbctl context show --json")

	var addOpts struct {
		endpoint        string
		caCert          string
		clientCert      string
		clientKey       string
		authMode        string
		tokenEnv        string
		insecureSkipTLS bool
		use             bool
	}
	addCmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Add or update a remote server context",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			name := strings.TrimSpace(args[0])
			if name == "local" {
				*exitCode = ic.WriteError(types.ErrCodeInvalidUsage, false, "context name 'local' is reserved", "", nil, nil, types.Meta{})
				return nil
			}
			paths, err := config.ResolvePaths(ic.Session)
			if err != nil {
				*exitCode = ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{})
				return nil
			}
			cf, err := config.LoadContexts(paths)
			if err != nil {
				*exitCode = ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{})
				return nil
			}
			authMode := config.AuthMode(strings.TrimSpace(addOpts.authMode))
			if authMode == "" {
				authMode = config.AuthModeBearerToken
			}
			entry := config.ClientContext{
				Name:            name,
				Mode:            config.ContextModeRemote,
				Endpoint:        strings.TrimRight(strings.TrimSpace(addOpts.endpoint), "/"),
				CACertFile:      addOpts.caCert,
				ClientCertFile:  addOpts.clientCert,
				ClientKeyFile:   addOpts.clientKey,
				AuthMode:        authMode,
				TokenEnv:        addOpts.tokenEnv,
				InsecureSkipTLS: addOpts.insecureSkipTLS,
			}
			if err := config.ValidateContextName(name); err != nil {
				*exitCode = ic.WriteError(types.ErrCodeInvalidUsage, false, err.Error(), "", nil, nil, types.Meta{})
				return nil
			}
			if err := config.ValidateContext(entry); err != nil {
				*exitCode = ic.WriteError(types.ErrCodeInvalidUsage, false, err.Error(), "", nil, nil, types.Meta{})
				return nil
			}
			cf.Contexts[name] = entry
			if addOpts.use {
				cf.CurrentContext = name
			}
			if err := config.SaveContexts(paths, cf); err != nil {
				*exitCode = ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{})
				return nil
			}
			if ic.JSONMode {
				*exitCode = ic.WriteSuccess(map[string]any{"context": entry, "current_context": cf.CurrentContext}, types.Meta{})
				return nil
			}
			_, _ = fmt.Fprintf(ic.Stdout, "Saved context %q (%s)\n", name, entry.Endpoint)
			return nil
		},
	}
	addCmd.Flags().StringVar(&addOpts.endpoint, "endpoint", "", "Remote HTTPS endpoint URL (e.g. https://db.example.com)")
	addCmd.Flags().StringVar(&addOpts.caCert, "ca-cert", "", "Optional PEM CA certificate path")
	addCmd.Flags().StringVar(&addOpts.clientCert, "client-cert", "", "Optional mTLS client certificate path")
	addCmd.Flags().StringVar(&addOpts.clientKey, "client-key", "", "Optional mTLS client private key path")
	addCmd.Flags().StringVar(&addOpts.authMode, "auth", "bearer_token", "Authentication mode: oidc_device or bearer_token")
	addCmd.Flags().StringVar(&addOpts.tokenEnv, "token-env", "", "Optional environment variable carrying bearer token")
	addCmd.Flags().BoolVar(&addOpts.insecureSkipTLS, "insecure-skip-tls", false, "Skip TLS verification (testing only)")
	addCmd.Flags().BoolVar(&addOpts.use, "use", false, "Switch current_context to this context")
	_ = addCmd.MarkFlagRequired("endpoint")
	annotateCommand(addCmd, RiskWriteLocal, "agent-dbctl context add corp --endpoint https://db.example.com --auth oidc_device --use")

	useCmd := &cobra.Command{
		Use:   "use <name>",
		Short: "Switch current active client context",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			name := strings.TrimSpace(args[0])
			paths, err := config.ResolvePaths(ic.Session)
			if err != nil {
				*exitCode = ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{})
				return nil
			}
			cf, err := config.LoadContexts(paths)
			if err != nil {
				*exitCode = ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{})
				return nil
			}
			if _, ok := cf.Contexts[name]; !ok {
				*exitCode = ic.WriteError(types.ErrCodeNotFound, false, fmt.Sprintf("context %q not found", name), "List available contexts with `agent-dbctl context list`.", nil, nil, types.Meta{})
				return nil
			}
			cf.CurrentContext = name
			if err := config.SaveContexts(paths, cf); err != nil {
				*exitCode = ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{})
				return nil
			}
			if ic.JSONMode {
				*exitCode = ic.WriteSuccess(map[string]string{"current_context": name}, types.Meta{})
				return nil
			}
			_, _ = fmt.Fprintf(ic.Stdout, "Switched active context to %q\n", name)
			return nil
		},
	}
	annotateCommand(useCmd, RiskWriteLocal, "agent-dbctl context use corp")

	removeCmd := &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove a remote client context",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			name := strings.TrimSpace(args[0])
			if name == "local" {
				*exitCode = ic.WriteError(types.ErrCodeInvalidUsage, false, "cannot remove built-in 'local' context", "", nil, nil, types.Meta{})
				return nil
			}
			paths, err := config.ResolvePaths(ic.Session)
			if err != nil {
				*exitCode = ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{})
				return nil
			}
			cf, err := config.LoadContexts(paths)
			if err != nil {
				*exitCode = ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{})
				return nil
			}
			if _, ok := cf.Contexts[name]; !ok {
				*exitCode = ic.WriteError(types.ErrCodeNotFound, false, fmt.Sprintf("context %q not found", name), "", nil, nil, types.Meta{})
				return nil
			}
			delete(cf.Contexts, name)
			if cf.CurrentContext == name {
				cf.CurrentContext = "local"
			}
			if err := config.SaveContexts(paths, cf); err != nil {
				*exitCode = ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{})
				return nil
			}
			_ = secrets.NewStore(paths).Delete(cmd.Context(), "ctx-token:"+name)
			if ic.JSONMode {
				*exitCode = ic.WriteSuccess(map[string]any{"removed": name, "current_context": cf.CurrentContext}, types.Meta{})
				return nil
			}
			_, _ = fmt.Fprintf(ic.Stdout, "Removed context %q (current=%s)\n", name, cf.CurrentContext)
			return nil
		},
	}
	annotateCommand(removeCmd, RiskWriteLocal, "agent-dbctl context remove corp")

	ctxCmd.AddCommand(listCmd, showCmd, addCmd, useCmd, removeCmd)
	return ctxCmd
}

func newLoginCmd(ioCtx func() IOContext, version, commit string, exitCode *int) *cobra.Command {
	var tokenStdin bool
	var tokenEnv string
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate against a remote agent-dbctl server (OIDC Device Flow or Bearer token)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ic := ioCtx()
			paths, err := config.ResolvePaths(ic.Session)
			if err != nil {
				*exitCode = ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{})
				return nil
			}
			ctxCfg, _, err := config.ResolveActiveContext(paths, ic.Context)
			if err != nil {
				*exitCode = writeClientInitErr(ic, err)
				return nil
			}
			if ctxCfg.Mode != config.ContextModeRemote {
				*exitCode = ic.WriteError(types.ErrCodeInvalidUsage, false, "login applies only to remote server contexts", "Add and select a remote context first via `agent-dbctl context add`.", nil, nil, types.Meta{})
				return nil
			}

			var tok string
			switch {
			case tokenStdin:
				raw, rErr := io.ReadAll(io.LimitReader(os.Stdin, 32*1024))
				if rErr != nil {
					*exitCode = ic.WriteError(types.ErrCodeInvalidInput, false, rErr.Error(), "", nil, nil, types.Meta{})
					return nil
				}
				tok = strings.TrimSpace(string(bytes.TrimSpace(raw)))
			case strings.TrimSpace(tokenEnv) != "":
				tok = strings.TrimSpace(os.Getenv(strings.TrimSpace(tokenEnv)))
			default:
				unauthClient, cErr := daemon.NewRemoteClient(ctxCfg, "")
				if cErr != nil {
					*exitCode = writeClientInitErr(ic, cErr)
					return nil
				}
				var oidcInfo struct {
					IssuerURL string   `json:"issuer_url"`
					ClientID  string   `json:"client_id"`
					Scopes    []string `json:"scopes"`
				}
				if err := unauthClient.DoJSON(cmd.Context(), http.MethodGet, "/rpc/v1/auth/oidc", nil, &oidcInfo); err != nil {
					*exitCode = writeRPCErr(ic, err)
					return nil
				}
				oidcCl := auth.NewOIDCClient(oidcInfo.IssuerURL, oidcInfo.ClientID, "", oidcInfo.Scopes)
				dev, err := oidcCl.StartDeviceAuth(cmd.Context())
				if err != nil {
					*exitCode = ic.WriteError(types.ErrCodeAuthRequired, false, err.Error(), "Or authenticate non-interactively with `--token-stdin` / `--token-env`.", nil, nil, types.Meta{})
					return nil
				}
				_, _ = fmt.Fprintf(ic.Stderr, "Open %s and enter code: %s\n", dev.VerificationURI, dev.UserCode)
				if dev.VerificationURIComplete != "" && !ic.NoInput && os.Getenv(config.EnvNoBrowser) != "1" {
					_ = approval.OpenBrowser(dev.VerificationURIComplete)
				}
				deadline := time.Now().Add(time.Duration(dev.ExpiresIn) * time.Second)
				interval := time.Duration(dev.Interval) * time.Second
				if interval <= 0 {
					interval = 5 * time.Second
				}
				for time.Now().Before(deadline) {
					select {
					case <-cmd.Context().Done():
						return nil
					case <-time.After(interval):
					}
					tr, pErr := oidcCl.PollDeviceToken(cmd.Context(), dev.DeviceCode)
					if pErr != nil {
						continue
					}
					switch tr.Error {
					case "":
						tok = strings.TrimSpace(tr.IDToken)
						if tok == "" {
							tok = strings.TrimSpace(tr.AccessToken)
						}
					case "authorization_pending":
						continue
					case "slow_down":
						interval += 5 * time.Second
						continue
					default:
						*exitCode = ic.WriteError(types.ErrCodeAuthRequired, false, fmt.Sprintf("OIDC device login error: %s %s", tr.Error, tr.ErrorDesc), "", nil, nil, types.Meta{})
						return nil
					}
					if tok != "" {
						break
					}
				}
			}
			if tok == "" {
				*exitCode = ic.WriteError(types.ErrCodeAuthRequired, false, "no bearer token received", "Pass `--token-stdin` / `--token-env <VAR>` or complete OIDC device approval.", nil, nil, types.Meta{})
				return nil
			}
			client, err := daemon.NewRemoteClient(ctxCfg, tok)
			if err != nil {
				*exitCode = writeClientInitErr(ic, err)
				return nil
			}
			var whoami types.Principal
			if err := client.DoJSON(cmd.Context(), http.MethodGet, "/rpc/v1/whoami", nil, &whoami); err != nil {
				*exitCode = writeRPCErr(ic, err)
				return nil
			}
			if err := secrets.NewStore(paths).Put(cmd.Context(), "ctx-token:"+ctxCfg.Name, tok); err != nil {
				*exitCode = ic.WriteError(types.ErrCodeInternalError, false, "save context credential: "+err.Error(), "", nil, nil, types.Meta{})
				return nil
			}
			if ic.JSONMode {
				*exitCode = ic.WriteSuccess(map[string]any{"context": ctxCfg.Name, "principal": whoami}, types.Meta{})
				return nil
			}
			_, _ = fmt.Fprintf(ic.Stdout, "Authenticated as %s (%s) on context %q\n", whoami.Subject, whoami.Kind, ctxCfg.Name)
			return nil
		},
	}
	cmd.Flags().BoolVar(&tokenStdin, "token-stdin", false, "Read bearer/agent token from stdin")
	cmd.Flags().StringVar(&tokenEnv, "token-env", "", "Read bearer/agent token from an environment variable")
	annotateCommand(cmd, RiskWriteLocal, "agent-dbctl login --context corp\nagent-dbctl login --context corp --token-stdin")
	return cmd
}

func newLogoutCmd(ioCtx func() IOContext, exitCode *int) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "logout",
		Short: "Remove stored authentication token for the active remote context",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ic := ioCtx()
			paths, err := config.ResolvePaths(ic.Session)
			if err != nil {
				*exitCode = ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{})
				return nil
			}
			ctxCfg, _, err := config.ResolveActiveContext(paths, ic.Context)
			if err != nil {
				*exitCode = writeClientInitErr(ic, err)
				return nil
			}
			if ctxCfg.Mode != config.ContextModeRemote {
				*exitCode = ic.WriteError(types.ErrCodeInvalidUsage, false, "logout applies only to remote server contexts", "", nil, nil, types.Meta{})
				return nil
			}
			if err := secrets.NewStore(paths).Delete(cmd.Context(), "ctx-token:"+ctxCfg.Name); err != nil && !errors.Is(err, secrets.ErrNotFound) {
				*exitCode = ic.WriteError(types.ErrCodeInternalError, false, err.Error(), "", nil, nil, types.Meta{})
				return nil
			}
			if ic.JSONMode {
				*exitCode = ic.WriteSuccess(map[string]any{"logged_out": true, "context": ctxCfg.Name}, types.Meta{})
				return nil
			}
			_, _ = fmt.Fprintf(ic.Stdout, "Cleared saved credentials for context %q\n", ctxCfg.Name)
			return nil
		},
	}
	annotateCommand(cmd, RiskWriteLocal, "agent-dbctl logout --context corp")
	return cmd
}

func newWhoamiCmd(ioCtx func() IOContext, version, commit string, exitCode *int) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "whoami",
		Short: "Show authenticated principal and effective RBAC bindings",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ic := ioCtx()
			if !isRemoteIO(ic) {
				out := map[string]any{
					"kind":    types.PrincipalLocalOwner,
					"subject": "local-owner",
					"mode":    types.ModeLocal,
				}
				if ic.JSONMode {
					*exitCode = ic.WriteSuccess(out, types.Meta{})
					return nil
				}
				_, _ = fmt.Fprintln(ic.Stdout, "Principal: local-owner (mode=local, full local access)")
				return nil
			}
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				*exitCode = writeClientInitErr(ic, err)
				return nil
			}
			var whoami types.Principal
			if err := client.DoJSON(cmd.Context(), http.MethodGet, "/rpc/v1/whoami", nil, &whoami); err != nil {
				*exitCode = writeRPCErr(ic, err)
				return nil
			}
			if ic.JSONMode {
				*exitCode = ic.WriteSuccess(whoami, types.Meta{})
				return nil
			}
			_, _ = fmt.Fprintf(ic.Stdout, "Subject: %s\nKind: %s\nEmail: %s\nAllowed Systems: %v\nAllowed Envs: %v\nReadOnlyForced: %v\n",
				whoami.Subject, whoami.Kind, whoami.Email, whoami.AllowedSystems, whoami.AllowedEnvs, whoami.ReadOnlyForced)
			return nil
		},
	}
	annotateCommand(cmd, RiskRead, "agent-dbctl whoami --json")
	return cmd
}

func newTokenCmd(ioCtx func() IOContext, version, commit string, exitCode *int) *cobra.Command {
	tokenCmd := &cobra.Command{Use: "token", Short: "Create, list, and revoke scoped agent API tokens"}

	var listAll bool
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List agent API tokens",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ic := ioCtx()
			if !isRemoteIO(ic) {
				*exitCode = ic.WriteError(types.ErrCodeRemoteUnsupported, false, "token management requires a remote server context", "Select or specify `--context <name>`.", nil, nil, types.Meta{})
				return nil
			}
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				*exitCode = writeClientInitErr(ic, err)
				return nil
			}
			path := "/rpc/v1/tokens"
			if listAll {
				path += "?all=1"
			}
			var res struct {
				Items []types.APIToken `json:"items"`
			}
			if err := client.DoJSON(cmd.Context(), http.MethodGet, path, nil, &res); err != nil {
				*exitCode = writeRPCErr(ic, err)
				return nil
			}
			if ic.JSONMode {
				*exitCode = ic.WriteSuccess(res, types.Meta{})
				return nil
			}
			rows := make([][]string, 0, len(res.Items))
			for _, t := range res.Items {
				rows = append(rows, []string{t.ID, t.Name, t.TokenPrefix, string(t.RoleCeiling), strings.Join(t.AllowedSystems, ","), t.ExpiresAtUTC, t.RevokedAtUTC})
			}
			renderTable(ic.Stdout, []string{"ID", "NAME", "PREFIX", "ROLE_CEILING", "SYSTEMS", "EXPIRES", "REVOKED"}, rows)
			return nil
		},
	}
	listCmd.Flags().BoolVar(&listAll, "all", false, "List tokens across all users (platform_admin only)")
	annotateCommand(listCmd, RiskRead, "agent-dbctl token list --json")

	var createOpts struct {
		name     string
		role     string
		systems  []string
		envs     []string
		readOnly bool
		ttl      time.Duration
	}
	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Mint a scoped agent API token",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ic := ioCtx()
			if !isRemoteIO(ic) {
				*exitCode = ic.WriteError(types.ErrCodeRemoteUnsupported, false, "token creation requires a remote server context", "Select or specify `--context <name>`.", nil, nil, types.Meta{})
				return nil
			}
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				*exitCode = writeClientInitErr(ic, err)
				return nil
			}
			ttlSec := int(createOpts.ttl.Seconds())
			if ttlSec <= 0 {
				ttlSec = 30 * 24 * 3600
			}
			var res types.APITokenCreateResponse
			if err := client.DoJSON(cmd.Context(), http.MethodPost, "/rpc/v1/tokens", map[string]any{
				"name":             strings.TrimSpace(createOpts.name),
				"role_ceiling":     types.Role(strings.TrimSpace(createOpts.role)),
				"allowed_systems":  splitCommaSlice(createOpts.systems),
				"allowed_envs":     splitCommaSlice(createOpts.envs),
				"read_only_forced": createOpts.readOnly,
				"ttl_seconds":      ttlSec,
			}, &res); err != nil {
				*exitCode = writeRPCErr(ic, err)
				return nil
			}
			if ic.JSONMode {
				*exitCode = ic.WriteSuccess(res, types.Meta{})
				return nil
			}
			_, _ = fmt.Fprintf(ic.Stdout, "Token created (id=%s, prefix=%s). Store this secret securely:\n%s\n", res.Token.ID, res.Token.TokenPrefix, res.SecretToken)
			return nil
		},
	}
	createCmd.Flags().StringVar(&createOpts.name, "name", "", "Token display name")
	createCmd.Flags().StringVar(&createOpts.role, "role", string(types.RoleDeveloper), "Role ceiling (viewer|developer|system_admin|approver)")
	createCmd.Flags().StringSliceVar(&createOpts.systems, "system", nil, "Restrict token to system slug/ID(s)")
	createCmd.Flags().StringSliceVar(&createOpts.envs, "env", nil, "Restrict token to environment code(s)")
	createCmd.Flags().BoolVar(&createOpts.readOnly, "read-only", false, "Force read-only database access")
	createCmd.Flags().DurationVar(&createOpts.ttl, "ttl", 30*24*time.Hour, "Token time-to-live")
	_ = createCmd.MarkFlagRequired("name")
	annotateCommand(createCmd, RiskExecuteRemote, "agent-dbctl token create --name ci-bot --role developer --system orders --json")

	revokeCmd := &cobra.Command{
		Use:   "revoke <token_id>",
		Short: "Revoke an existing agent API token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ic := ioCtx()
			if !isRemoteIO(ic) {
				*exitCode = ic.WriteError(types.ErrCodeRemoteUnsupported, false, "token revocation requires a remote server context", "", nil, nil, types.Meta{})
				return nil
			}
			client, err := ensureDaemon(ic, version, commit)
			if err != nil {
				*exitCode = writeClientInitErr(ic, err)
				return nil
			}
			var res map[string]any
			if err := client.DoJSON(cmd.Context(), http.MethodDelete, "/rpc/v1/tokens/"+url.PathEscape(args[0]), nil, &res); err != nil {
				*exitCode = writeRPCErr(ic, err)
				return nil
			}
			if ic.JSONMode {
				*exitCode = ic.WriteSuccess(res, types.Meta{})
				return nil
			}
			_, _ = fmt.Fprintf(ic.Stdout, "Revoked token %s\n", args[0])
			return nil
		},
	}
	annotateCommand(revokeCmd, RiskExecuteRemote, "agent-dbctl token revoke tok_123 --json")

	tokenCmd.AddCommand(listCmd, createCmd, revokeCmd)
	return tokenCmd
}

func splitCommaSlice(in []string) []string {
	var out []string
	for _, s := range in {
		for _, part := range strings.Split(s, ",") {
			if tr := strings.TrimSpace(part); tr != "" {
				out = append(out, tr)
			}
		}
	}
	return out
}
