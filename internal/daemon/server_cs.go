package daemon

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/x0c/agent-dbctl/internal/approval"
	"github.com/x0c/agent-dbctl/internal/audit"
	"github.com/x0c/agent-dbctl/internal/auth"
	"github.com/x0c/agent-dbctl/internal/config"
	"github.com/x0c/agent-dbctl/internal/driver"
	"github.com/x0c/agent-dbctl/internal/driver/builtin"
	drvplugin "github.com/x0c/agent-dbctl/internal/driver/plugin"
	"github.com/x0c/agent-dbctl/internal/netdial"
	"github.com/x0c/agent-dbctl/internal/rbac"
	"github.com/x0c/agent-dbctl/internal/secrets"
	"github.com/x0c/agent-dbctl/internal/store"
	"github.com/x0c/agent-dbctl/internal/types"
)

// NewServerService constructs a multi-user enterprise Service configured by ServerConfig.
func NewServerService(ctx context.Context, paths config.Paths, srvCfg config.ServerConfig, version, commit string) (*Service, error) {
	if err := srvCfg.Validate(); err != nil {
		return nil, err
	}

	var st *store.Store
	var err error
	if srvCfg.Storage.PostgresSkipMigrations {
		st, err = store.OpenPreparedPostgres(ctx, srvCfg.Storage.DSN)
	} else if strings.EqualFold(srvCfg.Storage.Driver, "postgres") {
		st, err = store.OpenPostgres(ctx, srvCfg.Storage.DSN)
	} else {
		st, err = store.Open(ctx, srvCfg.Storage.DBPath)
	}
	if err != nil {
		return nil, err
	}

	kek, err := secrets.ParseMasterKey(srvCfg.Secrets.MasterKey)
	if err != nil {
		_ = st.Close()
		return nil, fmt.Errorf("parse server master key: %w", err)
	}

	var secStore secrets.Store
	if strings.EqualFold(srvCfg.Secrets.Driver, "encrypted_file") {
		secStore, err = secrets.NewEncryptedFileStore(paths.ConfigHome+"/secrets.enc", kek)
	} else {
		secStore, err = secrets.NewEncryptedDBStore(st, kek)
	}
	if err != nil {
		_ = st.Close()
		return nil, err
	}

	var slots audit.ResultRelay
	switch strings.ToLower(srvCfg.ResultSlot.Driver) {
	case "redis":
		slots, err = audit.NewRedisResultRelay(srvCfg.ResultSlot.RedisURL, 10*time.Minute, 32<<20)
		if err != nil {
			_ = st.Close()
			return nil, err
		}
	case "postgres":
		slots = audit.NewDBResultRelay(st, 10*time.Minute, 32<<20)
	default:
		slots = audit.NewMemoryResultRelay(10 * time.Minute)
	}

	nodeID := "srv-" + randomHexToken(6)
	var bus EventBus
	switch strings.ToLower(srvCfg.PubSub.Driver) {
	case "postgres":
		bus, err = NewPostgresEventBus(srvCfg.Storage.DSN, nodeID)
		if err != nil {
			_ = slots.Close()
			_ = st.Close()
			return nil, err
		}
	case "redis":
		bus, err = NewRedisEventBus(srvCfg.ResultSlot.RedisURL, nodeID)
		if err != nil {
			_ = slots.Close()
			_ = st.Close()
			return nil, err
		}
	default:
		bus = NewMemoryEventBus()
	}

	dialPol, err := netdial.ParseDialPolicy(true, srvCfg.DisableSSHAuthSock, true, srvCfg.BlockedEgressCIDRs, srvCfg.AllowedEgressCIDRs)
	if err != nil {
		_ = bus.Close()
		_ = slots.Close()
		_ = st.Close()
		return nil, err
	}

	reg := driver.NewRegistry()
	builtin.RegisterAll(reg)
	pm := drvplugin.NewManager(paths.PluginsDir, reg)
	_, _ = pm.Reload()

	appMgr := approval.NewManager(st)
	tunnels := netdial.NewTunnelPool(netdial.TunnelPoolConfig{})
	connPool := driver.NewConnPool(driver.ConnPoolConfig{})

	var oidcClient *auth.OIDCClient
	if srvCfg.Auth.OIDC.Enabled {
		oidcClient = auth.NewOIDCClient(srvCfg.Auth.OIDC.IssuerURL, srvCfg.Auth.OIDC.ClientID, srvCfg.Auth.OIDC.ClientSecret, srvCfg.Auth.OIDC.Scopes)
	}

	cfgCopy := srvCfg
	rootCtx, cancelRoot := context.WithCancel(context.Background())
	svc := &Service{
		mode:       types.ModeServer,
		nodeID:     nodeID,
		serverCfg:  &cfgCopy,
		paths:      paths,
		store:      st,
		secrets:    secStore,
		drivers:    reg,
		plugins:    pm,
		approvals:  appMgr,
		slots:      slots,
		bus:        bus,
		tunnels:    tunnels,
		connPool:   connPool,
		dialPolicy: dialPol,
		secretPolicy: secrets.ServerPolicy{
			Enabled:             true,
			AllowExecForAdmin:   srvCfg.Secrets.AllowExecProviderForAdmin,
			AllowedExecPrefixes: srvCfg.Secrets.AllowedExecPrefixes,
			AllowedEnvPrefixes:  srvCfg.Secrets.AllowedEnvPrefixes,
		},
		oidcClient: oidcClient,
		identity: Identity{
			Version:       version,
			Commit:        commit,
			WebURL:        srvCfg.PublicURL,
			StartedAt:     time.Now().UTC().Format(time.RFC3339),
			Mode:          types.ModeServer,
			APIVersion:    1,
			MinCLIVersion: srvCfg.MinCLIVersion,
			NodeID:        nodeID,
		},
		rootCtx:        rootCtx,
		cancelRoot:     cancelRoot,
		opWaiters:      make(map[string]chan types.ExecResponse),
		opActive:       make(map[string]context.CancelFunc),
		sseSubs:        make(map[*sseSubscriber]struct{}),
		uiSessionToken: randomHexToken(32),
		uiCSRFToken:    randomHexToken(32),
	}

	lw := approval.NewLocalWebProvider(func(approvalID string) {
		svc.broadcast(Event{Type: "approval_created", Data: map[string]string{"approval_id": approvalID}})
	})
	lw.SetHeadless(true)
	lw.SetBaseURL(srvCfg.PublicURL)
	svc.localWeb = lw
	appMgr.RegisterProvider(lw)
	_ = svc.RegisterWebhookProviderFromEnv()

	var issuer string
	var adminSubjects []string
	if oidcClient != nil {
		issuer = oidcClient.IssuerURL
		adminSubjects = srvCfg.Auth.OIDC.AdminSubjects
	}
	if err := st.ReconcileOIDCAdminBindings(ctx, issuer, adminSubjects); err != nil {
		svc.Shutdown()
		return nil, fmt.Errorf("reconcile OIDC admin bindings: %w", err)
	}
	if err := seedBootstrapAdminIfEmpty(ctx, st, srvCfg); err != nil {
		svc.Shutdown()
		return nil, err
	}
	if err := bus.Start(rootCtx, svc.handleBusEvent); err != nil {
		svc.Shutdown()
		return nil, err
	}
	slots.Start(rootCtx)
	return svc, nil
}

func seedBootstrapAdminIfEmpty(ctx context.Context, st *store.Store, cfg config.ServerConfig) error {
	if !cfg.Auth.LocalLoginEnabled || (cfg.Auth.OIDC.Enabled && len(cfg.Auth.OIDC.AdminSubjects) != 0 && cfg.Auth.BootstrapAdminEmail == "") {
		return nil
	}
	cnt, err := st.CountUsers(ctx)
	if err != nil || cnt > 0 {
		return err
	}
	email := strings.TrimSpace(cfg.Auth.BootstrapAdminEmail)
	if email == "" {
		email = "admin@localhost"
	}
	pass := ""
	if cfg.Auth.BootstrapAdminPassEnv != "" {
		pass = strings.TrimSpace(os.Getenv(cfg.Auth.BootstrapAdminPassEnv))
	}
	if pass == "" {
		return fmt.Errorf("first local administrator requires a password via auth.bootstrap_admin_password_env")
	}
	hash, err := auth.HashPassword(pass)
	if err != nil {
		return err
	}
	u, err := st.CreateUser(ctx, "system", types.User{
		Email:        email,
		DisplayName:  "Platform Admin",
		PasswordHash: hash,
		Status:       "active",
	})
	if err != nil {
		return err
	}
	if _, err := st.UpsertRoleBinding(ctx, "system", types.RoleBinding{
		UserID:    u.ID,
		Role:      types.RolePlatformAdmin,
		ScopeType: types.ScopeGlobal,
		CreatedBy: "system",
	}); err != nil {
		return err
	}
	return nil
}

// RemoteServer hosts the unified HTTPS-ready Web Console + RPC API for `agent-dbctl serve`.
type RemoteServer struct {
	svc        *Service
	ln         net.Listener
	httpSrv    *http.Server
	shutdownCh chan struct{}
}

// StartRemoteServer binds the server listener, recovers stale node operations, and starts lease reaping.
func StartRemoteServer(ctx context.Context, paths config.Paths, srvCfg config.ServerConfig, version, commit string) (*RemoteServer, error) {
	svc, err := NewServerService(ctx, paths, srvCfg, version, commit)
	if err != nil {
		return nil, err
	}
	if _, err := svc.store.RecoverNodeOperations(ctx, svc.nodeID, "system"); err != nil {
		svc.Shutdown()
		return nil, fmt.Errorf("recover server operations: %w", err)
	}
	ln, err := net.Listen("tcp", srvCfg.ListenAddr)
	if err != nil {
		svc.Shutdown()
		return nil, fmt.Errorf("listen %s: %w", srvCfg.ListenAddr, err)
	}
	rs := &RemoteServer{
		svc:        svc,
		ln:         ln,
		shutdownCh: make(chan struct{}),
	}
	rs.httpSrv = &http.Server{
		Handler:           NewRemoteServerHandler(svc),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return rs, nil
}

func (s *RemoteServer) Addr() string      { return s.ln.Addr().String() }
func (s *RemoteServer) Service() *Service { return s.svc }

func (s *RemoteServer) Run(ctx context.Context) error {
	// Periodic lease reaper for multi-replica stale operation cleanup.
	s.svc.wg.Add(1)
	go func() {
		defer s.svc.wg.Done()
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-s.svc.rootCtx.Done():
				return
			case <-ticker.C:
				_, _ = s.svc.store.RecoverNodeOperations(s.svc.rootCtx, s.svc.nodeID, "system")
			}
		}
	}()

	errCh := make(chan error, 1)
	go func() {
		if err := s.httpSrv.Serve(s.ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	var runErr error
	select {
	case <-ctx.Done():
	case <-sigCh:
	case <-s.shutdownCh:
	case e := <-errCh:
		runErr = e
	}

	s.svc.CancelBackground()
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.httpSrv.Shutdown(shutCtx); err != nil {
		_ = s.httpSrv.Close()
	}
	s.svc.Shutdown()
	return runErr
}

// NewRemoteServerHandler mounts /api/v1/*, /rpc/v1/*, /hooks/v1/*, and the embedded SPA behind ServerSecurityMiddleware.
func NewRemoteServerHandler(svc *Service) http.Handler {
	mux := http.NewServeMux()
	registerWebAPIRoutes(mux, svc)
	registerServerAuthAndAdminRoutes(mux, svc)
	registerRPCRoutes(mux, svc, nil)
	return ServerSecurityMiddleware(svc, mux)
}

func registerServerAuthAndAdminRoutes(mux *http.ServeMux, svc *Service) {
	passwordGuard := newPasswordLoginGuard()
	mux.HandleFunc("GET /api/v1/auth/config", func(w http.ResponseWriter, r *http.Request) {
		p, ok := resolveRequestPrincipal(r, svc)
		info := publicAuthInfo(svc, ok && p.Kind == types.PrincipalHuman)
		writeJSONResp(w, http.StatusOK, info)
	})

	mux.HandleFunc("POST /api/v1/auth/login", func(w http.ResponseWriter, r *http.Request) {
		cfg := svc.ServerConfig()
		if cfg == nil || !cfg.Auth.LocalLoginEnabled {
			writeHTTPErr(w, http.StatusForbidden, "local password login is disabled")
			return
		}
		if !passwordGuard.allow(loginPeerIP(r, cfg), time.Now()) {
			w.Header().Set("Retry-After", "60")
			writeHTTPErr(w, http.StatusTooManyRequests, "too many sign-in attempts; retry in one minute")
			return
		}
		var body struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
		if err := decodeJSONBody(r, &body); err != nil {
			writeHTTPErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if !passwordGuard.tryVerify() {
			w.Header().Set("Retry-After", "1")
			writeHTTPErr(w, http.StatusTooManyRequests, "sign-in is busy; try again shortly")
			return
		}
		defer passwordGuard.endVerify()
		u, err := svc.Store().GetUserByEmail(r.Context(), body.Email)
		eligible := err == nil && u.Status == "active" && u.PasswordHash != ""
		hash := dummyLoginPasswordHash
		if eligible {
			hash = u.PasswordHash
		}
		if !auth.VerifyPassword(hash, body.Password) || !eligible {
			writeHTTPErr(w, http.StatusUnauthorized, "invalid email or password")
			return
		}
		csrf, err := issueWebSessionCookie(w, r, svc, u)
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		_ = svc.Store().RecordAuditEvent(r.Context(), "user:"+u.Email, "auth.login", u.ID, "", map[string]any{"method": "local_password"})
		writeJSONResp(w, http.StatusOK, map[string]any{
			"authenticated": true,
			"ui_csrf_token": csrf,
		})
	})

	mux.HandleFunc("POST /api/v1/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie(uiSessionCookieName); err == nil && cookie != nil && cookie.Value != "" {
			_ = svc.Store().DeleteWebSession(r.Context(), auth.HashToken(cookie.Value))
		}
		clearWebSessionCookie(w, svc)
		writeJSONResp(w, http.StatusOK, map[string]bool{"logged_out": true})
	})

	mux.HandleFunc("GET /api/v1/auth/oidc/login", func(w http.ResponseWriter, r *http.Request) {
		if svc.oidcClient == nil {
			writeHTTPErr(w, http.StatusNotFound, "OIDC is not enabled")
			return
		}
		returnTo := sanitizeReturnTo(r.URL.Query().Get("return_to"))
		stateRaw, err := auth.RandomHex(24)
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		nonce, err := auth.RandomHex(16)
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, "could not start sign-in")
			return
		}
		browserKey := readOIDCBrowserKey(r, svc.ServerConfig())
		if browserKey == "" {
			browserKey, err = auth.RandomHex(32)
			if err != nil {
				writeHTTPErr(w, http.StatusInternalServerError, "could not start sign-in")
				return
			}
		}
		verifier, challenge, err := auth.GeneratePKCE()
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		exp := time.Now().UTC().Add(oidcBrowserTTL).Format(time.RFC3339Nano)
		if err := svc.Store().CreateOIDCAuthState(r.Context(), types.OIDCAuthState{
			StateHash:    oidcBrowserStateHash(stateRaw, browserKey),
			Nonce:        nonce,
			PKCEVerifier: verifier,
			ReturnTo:     returnTo,
			ExpiresAtUTC: exp,
		}); err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		redirectURI := strings.TrimRight(svc.ServerConfig().PublicURL, "/") + "/api/v1/auth/oidc/callback"
		authURL, err := svc.oidcClient.AuthCodeURL(r.Context(), redirectURI, stateRaw, nonce, challenge)
		if err != nil {
			writeHTTPErr(w, http.StatusBadGateway, "oidc discovery failed: "+err.Error())
			return
		}
		setOIDCBrowserKey(w, svc.ServerConfig(), browserKey)
		http.Redirect(w, r, authURL, http.StatusFound)
	})

	mux.HandleFunc("GET /api/v1/auth/oidc/callback", func(w http.ResponseWriter, r *http.Request) {
		if svc.oidcClient == nil {
			writeHTTPErr(w, http.StatusNotFound, "OIDC is not enabled")
			return
		}
		q := r.URL.Query()
		stateRaw, code, oidcErr := q.Get("state"), q.Get("code"), q.Get("error")
		browserKey := readOIDCBrowserKey(r, svc.ServerConfig())
		if browserKey == "" || !isHexToken(stateRaw, 24) || (code == "" && oidcErr == "") {
			writeHTTPErr(w, http.StatusForbidden, "invalid or expired OIDC sign-in; start sign-in again")
			return
		}
		if iss := q.Get("iss"); iss != "" && iss != svc.oidcClient.IssuerURL {
			writeHTTPErr(w, http.StatusForbidden, "unexpected OIDC issuer")
			return
		}
		st, err := svc.Store().ConsumeOIDCAuthState(r.Context(), oidcBrowserStateHash(stateRaw, browserKey))
		if err != nil {
			writeHTTPErr(w, http.StatusForbidden, "invalid or expired OIDC sign-in; start sign-in again")
			return
		}
		if oidcErr != "" {
			http.Redirect(w, r, appendQueryParam(sanitizeReturnTo(st.ReturnTo), "error", "Sign-in was not completed."), http.StatusFound)
			return
		}
		redirectURI := strings.TrimRight(svc.ServerConfig().PublicURL, "/") + "/api/v1/auth/oidc/callback"
		tokResp, err := svc.oidcClient.ExchangeCode(r.Context(), code, redirectURI, st.PKCEVerifier)
		if err != nil || tokResp.Error != "" {
			writeHTTPErr(w, http.StatusBadGateway, "OIDC token exchange failed")
			return
		}
		claims, u, err := verifyAndProvisionOIDCUser(r.Context(), svc, tokResp.IDToken, st.Nonce)
		if err != nil {
			writeHTTPErr(w, http.StatusUnauthorized, err.Error())
			return
		}
		_ = claims
		if _, err := issueWebSessionCookie(w, r, svc, u); err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		http.Redirect(w, r, sanitizeReturnTo(st.ReturnTo), http.StatusFound)
	})

	// CLI Device Flow info + server-mediated browser confirmation endpoints
	mux.HandleFunc("GET /rpc/v1/auth/oidc", func(w http.ResponseWriter, r *http.Request) {
		cfg := svc.ServerConfig()
		if cfg == nil || !cfg.Auth.OIDC.Enabled || !cfg.Auth.OIDC.DeviceFlowEnabled {
			writeHTTPErr(w, http.StatusNotFound, "OIDC device flow is not enabled on this server")
			return
		}
		writeJSONResp(w, http.StatusOK, map[string]any{
			"issuer_url": cfg.Auth.OIDC.IssuerURL,
			"client_id":  cfg.Auth.OIDC.ClientID,
			"scopes":     cfg.Auth.OIDC.Scopes,
		})
	})

	mux.HandleFunc("POST /rpc/v1/auth/device/start", func(w http.ResponseWriter, r *http.Request) {
		cfg := svc.ServerConfig()
		if cfg == nil {
			writeHTTPErr(w, http.StatusNotFound, "server auth is not configured")
			return
		}
		if svc.oidcClient != nil && cfg.Auth.OIDC.DeviceFlowEnabled {
			dev, err := svc.oidcClient.StartDeviceAuth(r.Context())
			if err != nil {
				writeHTTPErr(w, http.StatusBadGateway, "oidc device authorization failed: "+err.Error())
				return
			}
			completeURI := strings.TrimSpace(dev.VerificationURIComplete)
			if completeURI == "" && dev.VerificationURI != "" && dev.UserCode != "" {
				sep := "?"
				if strings.Contains(dev.VerificationURI, "?") {
					sep = "&"
				}
				completeURI = dev.VerificationURI + sep + "user_code=" + url.QueryEscape(dev.UserCode)
			}
			writeJSONResp(w, http.StatusOK, types.DeviceCodeStartResponse{
				Mode:                    "oidc",
				DeviceCode:              dev.DeviceCode,
				UserCode:                dev.UserCode,
				VerificationURI:         dev.VerificationURI,
				VerificationURIComplete: completeURI,
				ExpiresIn:               dev.ExpiresIn,
				Interval:                dev.Interval,
			})
			return
		}

		devCode, err := auth.RandomHex(32)
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		userCode, err := auth.GenerateDeviceUserCode()
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		exp := time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339Nano)
		if err := svc.Store().CreateCLIDeviceCode(r.Context(), types.CLIDeviceCode{
			DeviceCodeHash: auth.HashToken(devCode),
			UserCode:       userCode,
			Status:         "pending",
			ExpiresAtUTC:   exp,
		}); err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		pub := strings.TrimRight(cfg.PublicURL, "/")
		verifyURI := pub + "/device"
		writeJSONResp(w, http.StatusOK, types.DeviceCodeStartResponse{
			Mode:                    "local",
			DeviceCode:              devCode,
			UserCode:                userCode,
			VerificationURI:         verifyURI,
			VerificationURIComplete: verifyURI + "?user_code=" + url.QueryEscape(userCode),
			ExpiresIn:               600,
			Interval:                2,
		})
	})

	mux.HandleFunc("POST /rpc/v1/auth/device/poll", func(w http.ResponseWriter, r *http.Request) {
		cfg := svc.ServerConfig()
		if cfg == nil {
			writeHTTPErr(w, http.StatusNotFound, "server auth is not configured")
			return
		}
		var body struct {
			DeviceCode string `json:"device_code"`
		}
		if err := decodeJSONBody(r, &body); err != nil || strings.TrimSpace(body.DeviceCode) == "" {
			writeHTTPErr(w, http.StatusBadRequest, "device_code is required")
			return
		}
		if svc.oidcClient != nil && cfg.Auth.OIDC.DeviceFlowEnabled {
			tr, pErr := svc.oidcClient.PollDeviceToken(r.Context(), strings.TrimSpace(body.DeviceCode))
			if pErr != nil {
				writeJSONResp(w, http.StatusOK, types.DeviceCodePollResponse{
					Status:    "error",
					Error:     "token_poll_failed",
					ErrorDesc: pErr.Error(),
				})
				return
			}
			switch tr.Error {
			case "":
			case "authorization_pending":
				writeJSONResp(w, http.StatusOK, types.DeviceCodePollResponse{Status: "pending"})
				return
			case "slow_down":
				writeJSONResp(w, http.StatusOK, types.DeviceCodePollResponse{Status: "slow_down"})
				return
			case "access_denied":
				writeJSONResp(w, http.StatusOK, types.DeviceCodePollResponse{Status: "denied", Error: tr.Error, ErrorDesc: tr.ErrorDesc})
				return
			case "expired_token":
				writeJSONResp(w, http.StatusOK, types.DeviceCodePollResponse{Status: "expired", Error: tr.Error, ErrorDesc: tr.ErrorDesc})
				return
			default:
				writeJSONResp(w, http.StatusOK, types.DeviceCodePollResponse{Status: "error", Error: tr.Error, ErrorDesc: tr.ErrorDesc})
				return
			}
			rawJWT := strings.TrimSpace(tr.IDToken)
			if rawJWT == "" {
				writeJSONResp(w, http.StatusOK, types.DeviceCodePollResponse{
					Status:    "error",
					Error:     "missing_id_token",
					ErrorDesc: "OIDC device token response omitted id_token",
				})
				return
			}
			_, u, vErr := verifyAndProvisionOIDCUser(r.Context(), svc, rawJWT, "")
			if vErr != nil {
				writeJSONResp(w, http.StatusOK, types.DeviceCodePollResponse{Status: "error", Error: "oidc_verify_failed", ErrorDesc: vErr.Error()})
				return
			}
			tok, mErr := mintCLISessionToken(r.Context(), svc, u, "cli-sso")
			if mErr != nil {
				writeHTTPErr(w, http.StatusInternalServerError, mErr.Error())
				return
			}
			writeJSONResp(w, http.StatusOK, types.DeviceCodePollResponse{Status: "approved", AccessToken: tok, Email: u.Email})
			return
		}

		status, userID, err := svc.Store().PollCLIDeviceCode(r.Context(), auth.HashToken(strings.TrimSpace(body.DeviceCode)))
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if status != "approved" {
			writeJSONResp(w, http.StatusOK, types.DeviceCodePollResponse{Status: status})
			return
		}
		u, uErr := svc.Store().GetUserByID(r.Context(), userID)
		if uErr != nil || u.Status != "active" {
			writeJSONResp(w, http.StatusOK, types.DeviceCodePollResponse{Status: "denied", Error: "user_inactive"})
			return
		}
		tok, mErr := mintCLISessionToken(r.Context(), svc, u, "cli-web")
		if mErr != nil {
			writeHTTPErr(w, http.StatusInternalServerError, mErr.Error())
			return
		}
		writeJSONResp(w, http.StatusOK, types.DeviceCodePollResponse{Status: "approved", AccessToken: tok, Email: u.Email})
	})

	mux.HandleFunc("POST /api/v1/auth/device/decide", func(w http.ResponseWriter, r *http.Request) {
		p := rbac.PrincipalFromContext(r.Context())
		if p.Kind != types.PrincipalHuman || p.ID == "" {
			writeHTTPErr(w, http.StatusForbidden, "human web session is required to confirm CLI login")
			return
		}
		var body struct {
			UserCode string `json:"user_code"`
			Decision string `json:"decision"` // approve | reject
		}
		if err := decodeJSONBody(r, &body); err != nil {
			writeHTTPErr(w, http.StatusBadRequest, err.Error())
			return
		}
		approve := strings.EqualFold(strings.TrimSpace(body.Decision), "approve")
		if !approve && !strings.EqualFold(strings.TrimSpace(body.Decision), "reject") {
			writeHTTPErr(w, http.StatusBadRequest, "decision must be approve or reject")
			return
		}
		dc, err := svc.Store().DecideCLIDeviceCode(r.Context(), p.Subject, body.UserCode, p.ID, approve)
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, map[string]any{
			"user_code": dc.UserCode,
			"status":    dc.Status,
		})
	})

	mux.HandleFunc("GET /rpc/v1/whoami", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResp(w, http.StatusOK, rbac.PrincipalFromContext(r.Context()))
	})

	// User & Role management (platform_admin)
	mux.HandleFunc("GET /api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		if !requireHTTPAction(w, r, rbac.ActionUserManage, rbac.ResourceScope{}) {
			return
		}
		users, err := svc.Store().ListUsers(r.Context())
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		bindings, _ := svc.Store().ListRoleBindings(r.Context(), "")
		writeJSONResp(w, http.StatusOK, map[string]any{"users": users, "role_bindings": bindings})
	})
	mux.HandleFunc("POST /api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		if !requireHTTPAction(w, r, rbac.ActionUserManage, rbac.ResourceScope{}) {
			return
		}
		var body struct {
			Email       string `json:"email"`
			DisplayName string `json:"display_name"`
			Password    string `json:"password"`
		}
		if err := decodeJSONBody(r, &body); err != nil {
			writeHTTPErr(w, http.StatusBadRequest, err.Error())
			return
		}
		hash, err := auth.HashPassword(body.Password)
		if err != nil {
			writeHTTPErr(w, http.StatusBadRequest, err.Error())
			return
		}
		p := rbac.PrincipalFromContext(r.Context())
		saved, err := svc.Store().CreateUser(r.Context(), p.Subject, types.User{
			Email:        body.Email,
			DisplayName:  body.DisplayName,
			PasswordHash: hash,
			Status:       "active",
		})
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, saved)
	})
	mux.HandleFunc("POST /api/v1/users/{id}/status", func(w http.ResponseWriter, r *http.Request) {
		if !requireHTTPAction(w, r, rbac.ActionUserManage, rbac.ResourceScope{}) {
			return
		}
		var body struct {
			Status string `json:"status"`
		}
		if err := decodeJSONBody(r, &body); err != nil {
			writeHTTPErr(w, http.StatusBadRequest, err.Error())
			return
		}
		p := rbac.PrincipalFromContext(r.Context())
		if err := svc.Store().UpdateUserStatus(r.Context(), p.Subject, r.PathValue("id"), body.Status); err != nil {
			writeStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, map[string]bool{"updated": true})
	})

	mux.HandleFunc("POST /api/v1/roles", func(w http.ResponseWriter, r *http.Request) {
		if !requireHTTPAction(w, r, rbac.ActionUserManage, rbac.ResourceScope{}) {
			return
		}
		var body types.RoleBinding
		if err := decodeJSONBody(r, &body); err != nil {
			writeHTTPErr(w, http.StatusBadRequest, err.Error())
			return
		}
		p := rbac.PrincipalFromContext(r.Context())
		saved, err := svc.Store().UpsertRoleBinding(r.Context(), p.Subject, body)
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, saved)
	})
	mux.HandleFunc("DELETE /api/v1/roles/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !requireHTTPAction(w, r, rbac.ActionUserManage, rbac.ResourceScope{}) {
			return
		}
		p := rbac.PrincipalFromContext(r.Context())
		if err := svc.Store().DeleteRoleBinding(r.Context(), p.Subject, r.PathValue("id")); err != nil {
			writeStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, map[string]bool{"deleted": true})
	})

	// Scoped Agent API Token management (Web + authenticated Human CLI)
	handleTokenList := func(w http.ResponseWriter, r *http.Request) {
		p := rbac.PrincipalFromContext(r.Context())
		if err := rbac.Authorize(p, rbac.ActionTokenManage, rbac.ResourceScope{}); err != nil {
			writeHTTPErr(w, http.StatusForbidden, err.Error())
			return
		}
		filterUser := p.ID
		if rbac.IsPlatformAdmin(p) && r.URL.Query().Get("all") == "1" {
			filterUser = ""
		}
		items, err := svc.Store().ListAPITokens(r.Context(), filterUser)
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSONResp(w, http.StatusOK, map[string]any{"items": items})
	}
	handleTokenCreate := func(w http.ResponseWriter, r *http.Request) {
		p := rbac.PrincipalFromContext(r.Context())
		if err := rbac.Authorize(p, rbac.ActionTokenManage, rbac.ResourceScope{}); err != nil {
			writeHTTPErr(w, http.StatusForbidden, err.Error())
			return
		}
		var body struct {
			Name           string     `json:"name"`
			RoleCeiling    types.Role `json:"role_ceiling"`
			AllowedSystems []string   `json:"allowed_systems"`
			AllowedEnvs    []string   `json:"allowed_envs"`
			ReadOnlyForced bool       `json:"read_only_forced"`
			TTLSeconds     int        `json:"ttl_seconds"`
		}
		if err := decodeJSONBody(r, &body); err != nil {
			writeHTTPErr(w, http.StatusBadRequest, err.Error())
			return
		}
		plain, prefix, hash, err := auth.GenerateAPIToken()
		if err != nil {
			writeHTTPErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		ttlSec := body.TTLSeconds
		if ttlSec <= 0 {
			ttlSec = 30 * 24 * 3600
		}
		exp := time.Now().UTC().Add(time.Duration(ttlSec) * time.Second).Format(time.RFC3339Nano)
		roleCeil := body.RoleCeiling
		if roleCeil == "" {
			roleCeil = types.RoleDeveloper
		}
		saved, err := svc.Store().CreateAPIToken(r.Context(), p.Subject, types.APIToken{
			UserID:         p.ID,
			OwnerEmail:     p.Email,
			Name:           strings.TrimSpace(body.Name),
			TokenPrefix:    prefix,
			TokenHash:      hash,
			PrincipalKind:  types.PrincipalAgentToken,
			RoleCeiling:    roleCeil,
			AllowedSystems: body.AllowedSystems,
			AllowedEnvs:    body.AllowedEnvs,
			ReadOnlyForced: body.ReadOnlyForced,
			ExpiresAtUTC:   exp,
		})
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, types.APITokenCreateResponse{Token: saved, SecretToken: plain})
	}
	handleTokenDelete := func(w http.ResponseWriter, r *http.Request) {
		p := rbac.PrincipalFromContext(r.Context())
		if err := rbac.Authorize(p, rbac.ActionTokenManage, rbac.ResourceScope{}); err != nil {
			writeHTTPErr(w, http.StatusForbidden, err.Error())
			return
		}
		ownerFilter := p.ID
		if rbac.IsPlatformAdmin(p) {
			ownerFilter = ""
		}
		if err := svc.Store().RevokeAPIToken(r.Context(), p.Subject, r.PathValue("id"), ownerFilter); err != nil {
			writeStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, map[string]bool{"revoked": true})
	}
	mux.HandleFunc("GET /api/v1/tokens", handleTokenList)
	mux.HandleFunc("POST /api/v1/tokens", handleTokenCreate)
	mux.HandleFunc("DELETE /api/v1/tokens/{id}", handleTokenDelete)
	mux.HandleFunc("GET /rpc/v1/tokens", handleTokenList)
	mux.HandleFunc("POST /rpc/v1/tokens", handleTokenCreate)
	mux.HandleFunc("DELETE /rpc/v1/tokens/{id}", handleTokenDelete)
	mux.HandleFunc("POST /rpc/v1/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		p := rbac.PrincipalFromContext(r.Context())
		rawTok := extractBearerToken(r)
		if rawTok == "" {
			writeJSONResp(w, http.StatusOK, map[string]bool{"revoked": false})
			return
		}
		tok, _, err := svc.Store().LookupAPITokenByHash(r.Context(), auth.HashToken(rawTok))
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeJSONResp(w, http.StatusOK, map[string]bool{"revoked": false})
				return
			}
			writeStoreErr(w, err)
			return
		}
		if err := svc.Store().RevokeAPIToken(r.Context(), p.Subject, tok.ID, ""); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeJSONResp(w, http.StatusOK, map[string]bool{"revoked": false})
				return
			}
			writeStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, map[string]bool{"revoked": true})
	})

	// External IM / Ticket Webhook Interactive Callback (HMAC-SHA256 + anti-replay nonce)
	mux.HandleFunc("POST /hooks/v1/approvals/{provider}/callback", func(w http.ResponseWriter, r *http.Request) {
		secret := strings.TrimSpace(os.Getenv(approval.EnvWebhookSecret))
		if secret == "" {
			writeHTTPErr(w, http.StatusForbidden, "webhook callback secret is not configured")
			return
		}
		tsRaw := strings.TrimSpace(r.Header.Get("X-Agent-DBCTL-Timestamp"))
		sigRaw := strings.TrimSpace(r.Header.Get("X-Agent-DBCTL-Signature"))
		tsVal, err := time.Parse(time.RFC3339, tsRaw)
		if err != nil || time.Since(tsVal).Abs() > 5*time.Minute {
			writeHTTPErr(w, http.StatusUnauthorized, "missing or expired callback timestamp")
			return
		}
		var bodyBytes []byte
		bodyBytes, err = ioReadLimited(r.Body, 1<<20)
		if err != nil {
			writeHTTPErr(w, http.StatusBadRequest, err.Error())
			return
		}
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write([]byte(tsRaw + "." + string(bodyBytes)))
		expectedSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if !auth.ConstantTimeEqual(sigRaw, expectedSig) {
			writeHTTPErr(w, http.StatusUnauthorized, "invalid callback signature")
			return
		}
		var payload struct {
			EventID       string `json:"event_id"`
			ApprovalID    string `json:"approval_id"`
			Decision      string `json:"decision"` // approve | reject
			ReviewerEmail string `json:"reviewer_email"`
			Note          string `json:"note"`
		}
		if err := json.Unmarshal(bodyBytes, &payload); err != nil {
			writeHTTPErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if payload.EventID == "" || payload.ApprovalID == "" {
			writeHTTPErr(w, http.StatusBadRequest, "event_id and approval_id are required")
			return
		}
		exp := time.Now().UTC().Add(15 * time.Minute).Format(time.RFC3339Nano)
		if err := svc.Store().CheckAndStoreWebhookNonce(r.Context(), r.PathValue("provider"), payload.EventID, exp); err != nil {
			writeHTTPErr(w, http.StatusConflict, err.Error())
			return
		}
		u, err := svc.Store().GetUserByEmail(r.Context(), payload.ReviewerEmail)
		if err != nil || u.Status != "active" {
			writeHTTPErr(w, http.StatusForbidden, "reviewer_email is not an active internal user")
			return
		}
		bindings, _ := svc.Store().ListRoleBindings(r.Context(), u.ID)
		revPrincipal := types.Principal{
			Kind:        types.PrincipalHuman,
			ID:          u.ID,
			Subject:     "user:" + u.Email,
			Email:       u.Email,
			DisplayName: u.DisplayName,
			Roles:       bindings,
		}
		approve := strings.EqualFold(payload.Decision, "approve") || strings.EqualFold(payload.Decision, "approved")
		app, err := svc.ResolveApproval(rbac.WithPrincipal(r.Context(), revPrincipal), payload.ApprovalID, approve, revPrincipal.Subject, payload.Note, "", true)
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, app)
	})
}

func publicAuthInfo(svc *Service, authenticated bool) types.PublicAuthInfo {
	cfg := svc.ServerConfig()
	if cfg == nil {
		return types.PublicAuthInfo{
			Mode:          types.ModeLocal,
			Authenticated: true,
			Version:       svc.Identity().Version,
		}
	}
	var methods []string
	if cfg.Auth.OIDC.Enabled {
		methods = append(methods, "oidc")
	}
	if cfg.Auth.LocalLoginEnabled {
		methods = append(methods, "local_password")
	}
	return types.PublicAuthInfo{
		Mode:          types.ModeServer,
		Authenticated: authenticated,
		AuthMethods:   methods,
		OIDCEnabled:   cfg.Auth.OIDC.Enabled,
		LocalEnabled:  cfg.Auth.LocalLoginEnabled,
		Version:       svc.Identity().Version,
	}
}

func serverCSRFForSession(svc *Service, sessIDHash string) string {
	key := svc.uiSessionToken
	if cfg := svc.ServerConfig(); cfg != nil && cfg.Secrets.MasterKey != "" {
		key = cfg.Secrets.MasterKey
	}
	mac := hmac.New(sha256.New, []byte("agent-dbctl-csrf:"+key))
	_, _ = mac.Write([]byte(sessIDHash))
	return hex.EncodeToString(mac.Sum(nil))
}

func issueWebSessionCookie(w http.ResponseWriter, r *http.Request, svc *Service, u types.User) (string, error) {
	sessTok, err := auth.RandomHex(32)
	if err != nil {
		return "", err
	}
	idHash := auth.HashToken(sessTok)
	csrfTok := serverCSRFForSession(svc, idHash)
	ttl := 24 * time.Hour
	if cfg := svc.ServerConfig(); cfg != nil && cfg.Auth.SessionTTLHours > 0 {
		ttl = time.Duration(cfg.Auth.SessionTTLHours) * time.Hour
	}
	exp := time.Now().UTC().Add(ttl).Format(time.RFC3339Nano)
	if err := svc.Store().CreateWebSession(r.Context(), types.WebSession{
		IDHash:        idHash,
		UserID:        u.ID,
		CSRFTokenHash: auth.HashToken(csrfTok),
		ExpiresAtUTC:  exp,
	}); err != nil {
		return "", err
	}
	isHTTPS := false
	if cfg := svc.ServerConfig(); cfg != nil && strings.HasPrefix(strings.ToLower(cfg.PublicURL), "https://") {
		isHTTPS = true
	}
	http.SetCookie(w, &http.Cookie{
		Name:     uiSessionCookieName,
		Value:    sessTok,
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPS,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().UTC().Add(ttl),
	})
	return csrfTok, nil
}

func clearWebSessionCookie(w http.ResponseWriter, svc *Service) {
	isHTTPS := false
	if cfg := svc.ServerConfig(); cfg != nil && strings.HasPrefix(strings.ToLower(cfg.PublicURL), "https://") {
		isHTTPS = true
	}
	http.SetCookie(w, &http.Cookie{
		Name:     uiSessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPS,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func grantConfiguredOIDCAdmin(ctx context.Context, svc *Service, user types.User) error {
	cfg := svc.ServerConfig()
	if cfg == nil || !slices.Contains(cfg.Auth.OIDC.AdminSubjects, user.OIDCSubject) {
		return nil
	}
	_, err := svc.Store().UpsertRoleBinding(ctx, "oidc-sync", types.RoleBinding{
		UserID:    user.ID,
		Role:      types.RolePlatformAdmin,
		ScopeType: types.ScopeGlobal,
		CreatedBy: "oidc-sync",
	})
	return err
}

func verifyAndProvisionOIDCUser(ctx context.Context, svc *Service, rawIDToken, expectedNonce string) (auth.IDTokenClaims, types.User, error) {
	if svc == nil || svc.oidcClient == nil {
		return auth.IDTokenClaims{}, types.User{}, fmt.Errorf("OIDC is not enabled")
	}
	claims, err := svc.oidcClient.VerifyJWT(ctx, rawIDToken, expectedNonce)
	if err != nil {
		return auth.IDTokenClaims{}, types.User{}, fmt.Errorf("verify oidc id_token: %w", err)
	}
	if strings.TrimSpace(claims.Email) == "" {
		return auth.IDTokenClaims{}, types.User{}, fmt.Errorf("oidc token missing email claim")
	}
	if claims.EmailVerified == nil || !*claims.EmailVerified {
		return auth.IDTokenClaims{}, types.User{}, fmt.Errorf("OIDC email address must be verified")
	}
	u, _, err := svc.Store().UpsertOIDCUser(ctx, svc.oidcClient.IssuerURL, claims.Subject, claims.Email, claims.Name)
	if err != nil {
		return auth.IDTokenClaims{}, types.User{}, err
	}
	if u.Status != "active" {
		return auth.IDTokenClaims{}, types.User{}, fmt.Errorf("user account is disabled")
	}
	if err := grantConfiguredOIDCAdmin(ctx, svc, u); err != nil {
		return auth.IDTokenClaims{}, types.User{}, fmt.Errorf("assign configured OIDC roles: %w", err)
	}
	return claims, u, nil
}

func mintCLISessionToken(ctx context.Context, svc *Service, u types.User, prefixLabel string) (string, error) {
	plain, prefix, hash, err := auth.GenerateAPIToken()
	if err != nil {
		return "", err
	}
	suffix, _ := auth.RandomHex(3)
	exp := time.Now().UTC().Add(30 * 24 * time.Hour).Format(time.RFC3339Nano)
	_, err = svc.Store().CreateAPIToken(ctx, "user:"+u.Email, types.APIToken{
		UserID:        u.ID,
		OwnerEmail:    u.Email,
		Name:          fmt.Sprintf("%s-%s-%s", prefixLabel, time.Now().UTC().Format("20060102"), suffix),
		TokenPrefix:   prefix,
		TokenHash:     hash,
		PrincipalKind: types.PrincipalHuman,
		ExpiresAtUTC:  exp,
	})
	if err != nil {
		return "", err
	}
	return plain, nil
}

func sanitizeReturnTo(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || !strings.HasPrefix(trimmed, "/") || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/\\") {
		return "/"
	}
	if strings.HasPrefix(trimmed, "/api/") || strings.HasPrefix(trimmed, "/rpc/") {
		return "/"
	}
	return trimmed
}

func appendQueryParam(rawPath, key, val string) string {
	u, err := url.Parse(rawPath)
	if err != nil {
		return "/?" + url.QueryEscape(key) + "=" + url.QueryEscape(val)
	}
	q := u.Query()
	q.Set(key, val)
	u.RawQuery = q.Encode()
	return u.String()
}

func extractBearerToken(r *http.Request) string {
	hdr := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(strings.ToLower(hdr), "bearer ") {
		return ""
	}
	return strings.TrimSpace(hdr[7:])
}

// ServerSecurityMiddleware enforces Host allowlists, AuthN (Bearer token or DB Web session), and CSRF for server mode.
func ServerSecurityMiddleware(svc *Service, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := svc.ServerConfig()
		setServerSecurityHeaders(w.Header(), r.URL.Path, cfg)
		effectiveHost := effectiveRequestHost(r, cfg)
		if !isAllowedServerHost(effectiveHost, cfg) {
			writeHTTPErr(w, http.StatusForbidden, "host not in server allowed_hosts")
			return
		}

		path := r.URL.Path
		if path == "/healthz" || strings.HasPrefix(path, "/hooks/v1/") {
			next.ServeHTTP(w, r)
			return
		}
		if path == "/api/v1/auth/config" || path == "/api/v1/auth/login" || path == "/api/v1/auth/logout" ||
			path == "/api/v1/auth/oidc/login" || path == "/api/v1/auth/oidc/callback" ||
			path == "/rpc/v1/auth/oidc" || path == "/rpc/v1/auth/device/start" || path == "/rpc/v1/auth/device/poll" {
			if path == "/api/v1/auth/login" || path == "/api/v1/auth/logout" {
				if !isSameOriginServerRequest(r, cfg) {
					writeHTTPErr(w, http.StatusForbidden, "cross-origin auth mutation blocked")
					return
				}
			}
			next.ServeHTTP(w, r)
			return
		}

		if strings.HasPrefix(path, "/rpc/v1/") {
			p, ok := resolveBearerPrincipal(r, svc)
			if !ok {
				writeJSONResp(w, http.StatusUnauthorized, LookupError{
					Code:    types.ErrCodeAuthRequired,
					Message: "authentication required; run agent-dbctl login or supply AGENT_DBCTL_TOKEN",
				})
				return
			}
			next.ServeHTTP(w, r.WithContext(rbac.WithPrincipal(r.Context(), p)))
			return
		}

		if strings.HasPrefix(path, "/api/v1/") {
			p, sess, ok := resolveWebPrincipalAndSession(r, svc)
			if path == "/api/v1/bootstrap" {
				if !ok {
					writeJSONResp(w, http.StatusUnauthorized, map[string]any{
						"error":     "authentication required",
						"auth_info": publicAuthInfo(svc, false),
					})
					return
				}
				next.ServeHTTP(w, r.WithContext(rbac.WithPrincipal(r.Context(), p)))
				return
			}
			if !ok {
				writeHTTPErr(w, http.StatusUnauthorized, "authentication required")
				return
			}
			if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
				if !isSameOriginServerRequest(r, cfg) {
					writeHTTPErr(w, http.StatusForbidden, "cross-origin mutation blocked")
					return
				}
				csrf := strings.TrimSpace(r.Header.Get(uiCSRFHeaderName))
				expected := serverCSRFForSession(svc, sess.IDHash)
				if csrf == "" || !auth.ConstantTimeEqual(csrf, expected) {
					writeHTTPErr(w, http.StatusForbidden, "missing or invalid CSRF token")
					return
				}
			}
			next.ServeHTTP(w, r.WithContext(rbac.WithPrincipal(r.Context(), p)))
			return
		}

		// Static SPA fallback
		next.ServeHTTP(w, r)
	})
}

func resolveRequestPrincipal(r *http.Request, svc *Service) (types.Principal, bool) {
	if p, ok := resolveBearerPrincipal(r, svc); ok {
		return p, true
	}
	p, _, ok := resolveWebPrincipalAndSession(r, svc)
	return p, ok
}

func (s *Service) touchAPITokenLastUsedAsync(tokenID string) {
	s.goBackground(func(rootCtx context.Context) {
		ctx, cancel := context.WithTimeout(rootCtx, 5*time.Second)
		defer cancel()
		s.store.TouchAPITokenLastUsed(ctx, tokenID)
	})
}

func resolveBearerPrincipal(r *http.Request, svc *Service) (types.Principal, bool) {
	hdr := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(strings.ToLower(hdr), "bearer ") {
		return types.Principal{}, false
	}
	rawTok := strings.TrimSpace(hdr[7:])
	if rawTok == "" {
		return types.Principal{}, false
	}

	// 1. Check scoped API Token (adb_live_...)
	tok, u, err := svc.Store().LookupAPITokenByHash(r.Context(), auth.HashToken(rawTok))
	if err == nil {
		if u.Status != "active" || tok.RevokedAtUTC != "" {
			return types.Principal{}, false
		}
		if tok.ExpiresAtUTC != "" {
			if exp, ok := parseISO8601(tok.ExpiresAtUTC); ok && time.Now().UTC().After(exp) {
				return types.Principal{}, false
			}
		}
		bindings, _ := svc.Store().ListRoleBindings(r.Context(), u.ID)
		svc.touchAPITokenLastUsedAsync(tok.ID)
		if tok.PrincipalKind == types.PrincipalHuman {
			return types.Principal{
				Kind:        types.PrincipalHuman,
				ID:          u.ID,
				Subject:     "user:" + u.Email,
				OwnerUserID: u.ID,
				Email:       u.Email,
				DisplayName: u.DisplayName,
				Roles:       bindings,
			}, true
		}
		return types.Principal{
			Kind:           types.PrincipalAgentToken,
			ID:             tok.ID,
			Subject:        fmt.Sprintf("agent:%s:%s", u.Email, tok.Name),
			OwnerUserID:    u.ID,
			Email:          u.Email,
			DisplayName:    tok.Name,
			Roles:          bindings,
			RoleCeiling:    tok.RoleCeiling,
			AllowedSystems: tok.AllowedSystems,
			AllowedEnvs:    tok.AllowedEnvs,
			ReadOnlyForced: tok.ReadOnlyForced,
		}, true
	}

	// 2. Check OIDC JWT from Device Flow / SSO client
	if svc.oidcClient != nil && strings.Count(rawTok, ".") == 2 {
		_, u, vErr := verifyAndProvisionOIDCUser(r.Context(), svc, rawTok, "")
		if vErr != nil {
			return types.Principal{}, false
		}
		bindings, _ := svc.Store().ListRoleBindings(r.Context(), u.ID)
		return types.Principal{
			Kind:        types.PrincipalHuman,
			ID:          u.ID,
			Subject:     "user:" + u.Email,
			Email:       u.Email,
			DisplayName: u.DisplayName,
			Roles:       bindings,
		}, true
	}

	return types.Principal{}, false
}

func resolveWebPrincipalAndSession(r *http.Request, svc *Service) (types.Principal, types.WebSession, bool) {
	cookie, err := r.Cookie(uiSessionCookieName)
	if err != nil || cookie == nil || cookie.Value == "" {
		return types.Principal{}, types.WebSession{}, false
	}
	sess, u, err := svc.Store().GetWebSessionByHash(r.Context(), auth.HashToken(cookie.Value))
	if err != nil || u.Status != "active" {
		return types.Principal{}, types.WebSession{}, false
	}
	bindings, _ := svc.Store().ListRoleBindings(r.Context(), u.ID)
	return types.Principal{
		Kind:        types.PrincipalHuman,
		ID:          u.ID,
		Subject:     "user:" + u.Email,
		Email:       u.Email,
		DisplayName: u.DisplayName,
		Roles:       bindings,
	}, sess, true
}

func effectiveRequestHost(r *http.Request, cfg *config.ServerConfig) string {
	if cfg != nil && cfg.TrustProxyHeaders && isTrustedProxyAddr(r.RemoteAddr, cfg.TrustedProxyCIDRs) {
		if xfh := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); xfh != "" {
			if idx := strings.IndexByte(xfh, ','); idx >= 0 {
				xfh = strings.TrimSpace(xfh[:idx])
			}
			return xfh
		}
	}
	return strings.TrimSpace(r.Host)
}

func isTrustedProxyAddr(remoteAddr string, cidrs []string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return false
	}
	if len(cidrs) == 0 {
		return ip.IsLoopback()
	}
	for _, raw := range cidrs {
		if _, n, err := net.ParseCIDR(raw); err == nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

func isAllowedServerHost(host string, cfg *config.ServerConfig) bool {
	if cfg == nil {
		return isLoopbackHostHeader(host)
	}
	trimmed := strings.ToLower(strings.TrimSpace(host))
	if trimmed == "" {
		return false
	}
	bareHost := trimmed
	if h, _, err := net.SplitHostPort(trimmed); err == nil {
		bareHost = h
	}
	for _, allowed := range cfg.EffectiveAllowedHosts() {
		if trimmed == allowed || bareHost == allowed {
			return true
		}
	}
	return false
}

func isSameOriginServerRequest(r *http.Request, cfg *config.ServerConfig) bool {
	if cfg == nil {
		return isSameOriginRequest(r)
	}
	pubURL, err := url.Parse(cfg.PublicURL)
	if err != nil || pubURL.Host == "" {
		return isSameOriginRequest(r)
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin != "" && origin != "null" {
		u, err := url.Parse(origin)
		if err != nil {
			return false
		}
		return strings.EqualFold(u.Scheme, pubURL.Scheme) && strings.EqualFold(u.Host, pubURL.Host)
	}
	if sfs := strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")); sfs != "" {
		return strings.EqualFold(sfs, "same-origin")
	}
	if ref := strings.TrimSpace(r.Header.Get("Referer")); ref != "" {
		u, err := url.Parse(ref)
		if err != nil {
			return false
		}
		return strings.EqualFold(u.Scheme, pubURL.Scheme) && strings.EqualFold(u.Host, pubURL.Host)
	}
	return false
}

func requireHTTPAction(w http.ResponseWriter, r *http.Request, action rbac.Action, scope rbac.ResourceScope) bool {
	p := rbac.PrincipalFromContext(r.Context())
	if err := rbac.Authorize(p, action, scope); err != nil {
		writeHTTPErr(w, http.StatusForbidden, err.Error())
		return false
	}
	return true
}

func parseISO8601(raw string) (time.Time, bool) {
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t.UTC(), true
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t.UTC(), true
	}
	return time.Time{}, false
}

func ioReadLimited(r interface{ Read([]byte) (int, error) }, max int64) ([]byte, error) {
	buf := make([]byte, 0, 1024)
	tmp := make([]byte, 1024)
	var total int64
	for {
		n, err := r.Read(tmp)
		if n > 0 {
			total += int64(n)
			if total > max {
				return nil, fmt.Errorf("request body exceeded %d bytes", max)
			}
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return buf, err
		}
	}
	return buf, nil
}
