package daemon

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/x0c/agent-dbctl/internal/config"
	"github.com/x0c/agent-dbctl/internal/types"
)

func TestRemoteServerEnterpriseCS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmpDir := t.TempDir()
	ordersDB := filepath.Join(tmpDir, "orders.db")
	billingDB := filepath.Join(tmpDir, "billing.db")
	for _, dbPath := range []string{ordersDB, billingDB} {
		db, err := sql.Open("sqlite", dbPath)
		if err != nil {
			t.Fatalf("open sqlite %s: %v", dbPath, err)
		}
		if _, err := db.Exec(`CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT); INSERT INTO items (id, name) VALUES (1, 'seed');`); err != nil {
			_ = db.Close()
			t.Fatalf("seed sqlite %s: %v", dbPath, err)
		}
		_ = db.Close()
	}

	// Start TLS listener first so PublicURL and AllowedHosts match its ephemeral port.
	tlsSrv := httptest.NewUnstartedServer(http.NotFoundHandler())
	tlsSrv.StartTLS()
	defer tlsSrv.Close()

	u, err := url.Parse(tlsSrv.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	caPath := filepath.Join(tmpDir, "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsSrv.Certificate().Raw})
	if err := os.WriteFile(caPath, caPEM, 0600); err != nil {
		t.Fatalf("write CA cert: %v", err)
	}

	adminPass := "BootstrapAdmin#2026!"
	t.Setenv("TEST_BOOTSTRAP_PASS", adminPass)

	forbidSelf := true
	masterKey := strings.Repeat("a", 64)
	paths := config.Paths{
		ConfigHome: filepath.Join(tmpDir, "cfg"),
		PluginsDir: filepath.Join(tmpDir, "plugins"),
		DBPath:     filepath.Join(tmpDir, "controlplane.db"),
	}
	if err := os.MkdirAll(paths.ConfigHome, 0700); err != nil {
		t.Fatalf("mkdir config home: %v", err)
	}
	srvCfg := config.DefaultServerConfig(paths)
	srvCfg.ListenAddr = u.Host
	srvCfg.PublicURL = tlsSrv.URL
	srvCfg.AllowedHosts = []string{"127.0.0.1", "localhost", u.Host}
	srvCfg.AllowSQLiteTargets = true
	srvCfg.Storage = config.ServerStorageConfig{
		Driver: "sqlite",
		DBPath: paths.DBPath,
	}
	srvCfg.Secrets = config.ServerSecretsConfig{
		Driver:       "encrypted_db",
		MasterKey:    masterKey,
		MasterKeyEnv: "",
	}
	srvCfg.Auth = config.ServerAuthConfig{
		LocalLoginEnabled:     true,
		BootstrapAdminEmail:   "admin@corp.example",
		BootstrapAdminPassEnv: "TEST_BOOTSTRAP_PASS",
		SessionTTLHours:       24,
		ForbidSelfApproval:    &forbidSelf,
	}

	svc, err := NewServerService(ctx, paths, srvCfg, "2.0.0-test", "deadbeef")
	if err != nil {
		t.Fatalf("NewServerService: %v", err)
	}
	defer svc.Shutdown()

	tlsSrv.Config.Handler = NewRemoteServerHandler(svc)

	// Helper to build a Web browser client (with cookie jar + CA cert)
	newWebClient := func() *http.Client {
		jar, _ := cookiejar.New(nil)
		baseClient := tlsSrv.Client()
		return &http.Client{
			Transport: baseClient.Transport,
			Jar:       jar,
			Timeout:   10 * time.Second,
		}
	}

	webDo := func(c *http.Client, method, path, csrf string, body any, extraHeaders map[string]string) (*http.Response, []byte) {
		var rdr io.Reader
		if body != nil {
			b, mErr := json.Marshal(body)
			if mErr != nil {
				t.Fatalf("marshal %s: %v", path, mErr)
			}
			rdr = bytes.NewReader(b)
		}
		req, rErr := http.NewRequestWithContext(ctx, method, tlsSrv.URL+path, rdr)
		if rErr != nil {
			t.Fatalf("new req %s: %v", path, rErr)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("Origin", tlsSrv.URL)
		if csrf != "" {
			req.Header.Set(uiCSRFHeaderName, csrf)
		}
		for k, v := range extraHeaders {
			req.Header.Set(k, v)
		}
		resp, dErr := c.Do(req)
		if dErr != nil {
			t.Fatalf("http %s %s: %v", method, path, dErr)
		}
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp, raw
	}

	// 1. Unauthenticated requests must fail without leaking catalog or global security.
	anonWeb := newWebClient()
	resp, raw := webDo(anonWeb, http.MethodGet, "/api/v1/bootstrap", "", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /api/v1/bootstrap status=%d body=%s, want 401", resp.StatusCode, string(raw))
	}
	if strings.Contains(string(raw), "global_security") || strings.Contains(string(raw), "display_catalog") {
		t.Fatalf("unauthenticated bootstrap leaked internal config: %s", string(raw))
	}

	// Host allowlist guard must reject unknown Host headers.
	hostReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, tlsSrv.URL+"/healthz", nil)
	hostReq.Host = "evil.invalid"
	hostResp, err := tlsSrv.Client().Do(hostReq)
	if err != nil {
		t.Fatalf("evil Host request failed unexpectedly: %v", err)
	}
	_ = hostResp.Body.Close()
	if hostResp.StatusCode != http.StatusForbidden {
		t.Fatalf("disallowed Host returned status=%d, want 403", hostResp.StatusCode)
	}

	// Unauthenticated RPC client gets ErrCodeAuthRequired.
	unauthRPC, err := NewRemoteClient(config.ClientContext{
		Name:       "srv",
		Endpoint:   tlsSrv.URL,
		CACertFile: caPath,
	}, "")
	if err != nil {
		t.Fatalf("NewRemoteClient unauth: %v", err)
	}
	var dummy any
	if err := unauthRPC.DoJSON(ctx, http.MethodPost, "/rpc/v1/db/list", ListFilter{}, &dummy); err == nil {
		t.Fatalf("expected unauthenticated RPC call to fail")
	} else {
		var le *LookupError
		if !errors.As(err, &le) || le.Code != types.ErrCodeAuthRequired {
			t.Fatalf("expected LookupError ErrCodeAuthRequired, got %v", err)
		}
	}

	// 2. Admin login + CSRF enforcement + user/role/token setup.
	adminWeb := newWebClient()
	// Cross-origin login must be rejected.
	resp, _ = webDo(adminWeb, http.MethodPost, "/api/v1/auth/login", "", map[string]string{
		"email":    "admin@corp.example",
		"password": adminPass,
	}, map[string]string{"Origin": "https://evil.example"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin login status=%d, want 403", resp.StatusCode)
	}

	resp, raw = webDo(adminWeb, http.MethodPost, "/api/v1/auth/login", "", map[string]string{
		"email":    "admin@corp.example",
		"password": adminPass,
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin login failed status=%d body=%s", resp.StatusCode, string(raw))
	}
	var loginOut struct {
		Authenticated bool   `json:"authenticated"`
		CSRFToken     string `json:"ui_csrf_token"`
	}
	_ = json.Unmarshal(raw, &loginOut)
	if !loginOut.Authenticated || loginOut.CSRFToken == "" {
		t.Fatalf("unexpected login response: %s", string(raw))
	}

	// Missing CSRF header must return 403.
	resp, _ = webDo(adminWeb, http.MethodPost, "/api/v1/users", "", map[string]string{
		"email":        "alice@corp.example",
		"display_name": "Alice",
		"password":     "AlicePass#2026!",
	}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("mutation without CSRF status=%d, want 403", resp.StatusCode)
	}

	// Create Alice (developer + approver on orders) & Carol (approver on orders).
	resp, raw = webDo(adminWeb, http.MethodPost, "/api/v1/users", loginOut.CSRFToken, map[string]string{
		"email":        "alice@corp.example",
		"display_name": "Alice",
		"password":     "AlicePass#2026!",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create alice status=%d body=%s", resp.StatusCode, string(raw))
	}
	var aliceUser types.User
	_ = json.Unmarshal(raw, &aliceUser)

	resp, raw = webDo(adminWeb, http.MethodPost, "/api/v1/users", loginOut.CSRFToken, map[string]string{
		"email":        "carol@corp.example",
		"display_name": "Carol",
		"password":     "CarolPass#2026!",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create carol status=%d body=%s", resp.StatusCode, string(raw))
	}
	var carolUser types.User
	_ = json.Unmarshal(raw, &carolUser)

	// Onboard orders & billing systems via admin Web Console.
	for _, addReq := range []DBAddRequest{
		{
			Engine:   "sqlite",
			Host:     ordersDB,
			Database: ordersDB,
			System:   "orders",
			Env:      "staging",
			SafetyTier:     types.SafetyTierGuarded,
			AccessLevel:    types.AccessReadWrite,
			User:           "orders_user",
			SecretValue:    "orders-test-pw",
			SecretProvided: true,
		},
		{
			Engine:         "sqlite",
			Host:           billingDB,
			Database:       billingDB,
			System:         "billing",
			Env:            "prod",
			SafetyTier:     types.SafetyTierStrict,
			User:           "billing_user",
			SecretValue:    "billing-test-pw",
			SecretProvided: true,
		},
	} {
		// Ensure safety tier env exists before db/add in guarded/strict
		_, _ = webDo(adminWeb, http.MethodPost, "/api/v1/environments", loginOut.CSRFToken, types.Environment{
			Code:       addReq.Env,
			SafetyTier: addReq.SafetyTier,
		}, nil)
		resp, raw = webDo(adminWeb, http.MethodPost, "/api/v1/db/add", loginOut.CSRFToken, addReq, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("db/add %s failed status=%d body=%s", addReq.System, resp.StatusCode, string(raw))
		}
	}

	// Verify EncryptedDBStore persisted ciphertext rather than plaintext in SQLite!
	rawDB, err := sql.Open("sqlite", srvCfg.Storage.DBPath)
	if err != nil {
		t.Fatalf("open controlplane db: %v", err)
	}
	var encCipher string
	if err := rawDB.QueryRow(`SELECT ciphertext FROM encrypted_secrets LIMIT 1`).Scan(&encCipher); err != nil {
		_ = rawDB.Close()
		t.Fatalf("read encrypted_secrets: %v", err)
	}
	_ = rawDB.Close()
	if encCipher == "" || strings.Contains(encCipher, "orders-test-pw") || strings.Contains(encCipher, "billing-test-pw") {
		t.Fatalf("encrypted_secrets leaked plaintext or was empty: %q", encCipher)
	}

	// Bind Alice -> system_admin + approver on orders; Carol -> approver on orders.
	sysListResp, sysRaw := webDo(adminWeb, http.MethodGet, "/api/v1/systems", "", nil, nil)
	if sysListResp.StatusCode != http.StatusOK {
		t.Fatalf("list systems status=%d body=%s", sysListResp.StatusCode, string(sysRaw))
	}
	var sysOut struct {
		Items []types.System `json:"items"`
	}
	_ = json.Unmarshal(sysRaw, &sysOut)
	ordersSysID := ""
	for _, s := range sysOut.Items {
		if s.Slug == "orders" {
			ordersSysID = s.ID
			break
		}
	}
	if ordersSysID == "" {
		t.Fatalf("orders system not found in %+v", sysOut.Items)
	}

	for _, rb := range []types.RoleBinding{
		{UserID: aliceUser.ID, Role: types.RoleApprover, ScopeType: types.ScopeSystem, ScopeID: ordersSysID},
		{UserID: carolUser.ID, Role: types.RoleApprover, ScopeType: types.ScopeSystem, ScopeID: ordersSysID},
	} {
		resp, raw = webDo(adminWeb, http.MethodPost, "/api/v1/roles", loginOut.CSRFToken, rb, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("bind role failed status=%d body=%s", resp.StatusCode, string(raw))
		}
	}

	// 3. Alice logs in to mint her scoped Agent Token.
	aliceWeb := newWebClient()
	resp, raw = webDo(aliceWeb, http.MethodPost, "/api/v1/auth/login", "", map[string]string{
		"email":    "alice@corp.example",
		"password": "AlicePass#2026!",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("alice login status=%d body=%s", resp.StatusCode, string(raw))
	}
	var aliceLogin struct {
		CSRFToken string `json:"ui_csrf_token"`
	}
	_ = json.Unmarshal(raw, &aliceLogin)

	resp, raw = webDo(aliceWeb, http.MethodPost, "/api/v1/tokens", aliceLogin.CSRFToken, map[string]any{
		"name":            "alice-ci",
		"role_ceiling":    types.RoleDeveloper,
		"allowed_systems": []string{"orders"},
		"ttl_seconds":     3600,
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create alice token status=%d body=%s", resp.StatusCode, string(raw))
	}
	var tokCreated types.APITokenCreateResponse
	_ = json.Unmarshal(raw, &tokCreated)
	if !strings.HasPrefix(tokCreated.SecretToken, "adb_live_") {
		t.Fatalf("unexpected token format: %q", tokCreated.SecretToken)
	}

	aliceClient, err := NewRemoteClient(config.ClientContext{
		Name:       "corp",
		Endpoint:   tlsSrv.URL,
		CACertFile: caPath,
	}, tokCreated.SecretToken)
	if err != nil {
		t.Fatalf("NewRemoteClient alice: %v", err)
	}

	// Verify /rpc/v1/whoami
	var whoami types.Principal
	if err := aliceClient.DoJSON(ctx, http.MethodGet, "/rpc/v1/whoami", nil, &whoami); err != nil {
		t.Fatalf("whoami: %v", err)
	}
	if whoami.Kind != types.PrincipalAgentToken || whoami.OwnerUserID != aliceUser.ID {
		t.Fatalf("unexpected whoami principal: %+v", whoami)
	}

	// Verify scoped db list sees only orders, never billing!
	var dbListRes struct {
		Items []types.TargetDetail `json:"items"`
	}
	if err := aliceClient.DoJSON(ctx, http.MethodPost, "/rpc/v1/db/list", ListFilter{}, &dbListRes); err != nil {
		t.Fatalf("alice db/list: %v", err)
	}
	if len(dbListRes.Items) != 1 || dbListRes.Items[0].OwnerSystem == nil || dbListRes.Items[0].OwnerSystem.Slug != "orders" {
		t.Fatalf("expected only orders target for alice token, got %+v", dbListRes.Items)
	}

	// Verify agent token cannot mutate systems (token ceiling is developer) or call shutdown or send workspace_cwd.
	err = aliceClient.DoJSON(ctx, http.MethodPost, "/rpc/v1/systems", map[string]any{
		"system": types.System{Slug: "evil-sys", Name: "Evil"},
	}, nil)
	if err == nil {
		t.Fatalf("developer token must not create system")
	}
	err = aliceClient.Shutdown(ctx)
	if err == nil {
		t.Fatalf("remote /rpc/v1/shutdown must be disabled in server mode")
	}
	err = aliceClient.DoJSON(ctx, http.MethodPost, "/rpc/v1/db/add", DBAddRequest{
		Engine:       "sqlite",
		Host:         ordersDB,
		WorkspaceCWD: "/some/client/path",
	}, nil)
	if err == nil {
		t.Fatalf("workspace_cwd on /rpc/v1/db/add must be rejected in server mode")
	}

	// Verify read query execution over remote HTTPS works.
	var readResp types.ExecResponse
	if err := aliceClient.DoJSON(ctx, http.MethodPost, "/rpc/v1/exec", types.ExecRequest{
		TargetRefOrAlias: dbListRes.Items[0].Target.Ref,
		Query:            "SELECT id, name FROM items WHERE id = 1 LIMIT 10",
		Wait:             true,
	}, &readResp); err != nil {
		t.Fatalf("alice SELECT exec: %v", err)
	}
	if readResp.Status != types.OpSucceeded || len(readResp.Result.Rows) != 1 {
		t.Fatalf("unexpected read exec result: %+v", readResp)
	}

	// 4. Server RCE guardrails: exec_provider & sensitive env_ref must fail even for platform_admin!
	resp, raw = webDo(adminWeb, http.MethodPost, "/api/v1/credentials", loginOut.CSRFToken, CredentialUpsertRequest{
		CredentialProfile: types.CredentialProfile{
			Name:        "bad-shell-exec",
			Kind:        types.CredExecProvider,
			ExecCommand: "/bin/sh -c env",
		},
	}, nil)
	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("blocked exec_provider returned status=%d body=%s", resp.StatusCode, string(raw))
	}

	// 5. Four-eyes approval enforcement:
	// Alice's agent token requests DDL -> triggers approval.
	var writeAsync types.ExecResponse
	if err := aliceClient.DoJSON(ctx, http.MethodPost, "/rpc/v1/exec", types.ExecRequest{
		TargetRefOrAlias: dbListRes.Items[0].Target.Ref,
		Query:            "INSERT INTO items (id, name) VALUES (2, 'second')",
		Reason:           "add test row via remote client",
		Wait:             false,
	}, &writeAsync); err != nil {
		t.Fatalf("alice write exec: %v", err)
	}
	if writeAsync.Status != types.OpWaitingApproval || writeAsync.ApprovalID == "" {
		t.Fatalf("expected waiting_approval, got %+v", writeAsync)
	}

	// Agent token must NOT approve via /api/v1/approvals/{id}/approve.
	agentApproveReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, tlsSrv.URL+"/api/v1/approvals/"+writeAsync.ApprovalID+"/approve", strings.NewReader(`{"note":"self"}`))
	agentApproveReq.Header.Set("Authorization", "Bearer "+tokCreated.SecretToken)
	agentApproveReq.Header.Set("Origin", tlsSrv.URL)
	agentApproveResp, err := tlsSrv.Client().Do(agentApproveReq)
	if err != nil {
		t.Fatalf("agent approve request error: %v", err)
	}
	_ = agentApproveResp.Body.Close()
	if agentApproveResp.StatusCode == http.StatusOK {
		t.Fatalf("agent token must never resolve human approvals")
	}

	// Alice's own human web session must also be blocked from approving her own token's request (four-eyes)!
	resp, raw = webDo(aliceWeb, http.MethodPost, "/api/v1/approvals/"+writeAsync.ApprovalID+"/approve", aliceLogin.CSRFToken, map[string]string{
		"note": "self-approve attempt",
	}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("four-eyes self-approval returned status=%d body=%s, want 403", resp.StatusCode, string(raw))
	}

	// Carol (a different human approver on orders) approves!
	carolWeb := newWebClient()
	resp, raw = webDo(carolWeb, http.MethodPost, "/api/v1/auth/login", "", map[string]string{
		"email":    "carol@corp.example",
		"password": "CarolPass#2026!",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("carol login status=%d body=%s", resp.StatusCode, string(raw))
	}
	var carolLogin struct {
		CSRFToken string `json:"ui_csrf_token"`
	}
	_ = json.Unmarshal(raw, &carolLogin)

	resp, raw = webDo(carolWeb, http.MethodPost, "/api/v1/approvals/"+writeAsync.ApprovalID+"/approve", carolLogin.CSRFToken, map[string]string{
		"note": "verified by carol",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("carol approve status=%d body=%s", resp.StatusCode, string(raw))
	}

	// Wait via remote /rpc/v1/ops/{id}/wait for completion.
	var finalResp types.ExecResponse
	if err := aliceClient.DoJSON(ctx, http.MethodGet, "/rpc/v1/ops/"+writeAsync.OperationID+"/wait?timeout_sec=10", nil, &finalResp); err != nil {
		t.Fatalf("wait operation: %v", err)
	}
	if finalResp.Status != types.OpSucceeded {
		t.Fatalf("expected operation succeeded after carol approval, got %+v", finalResp)
	}

	// Verify audit chain integrity after full C/S lifecycle.
	resp, raw = webDo(adminWeb, http.MethodPost, "/api/v1/audit/verify", loginOut.CSRFToken, map[string]any{}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("audit verify status=%d body=%s", resp.StatusCode, string(raw))
	}
	var auditRes struct {
		Valid        bool `json:"valid"`
		CheckedCount int  `json:"checked_count"`
	}
	_ = json.Unmarshal(raw, &auditRes)
	if !auditRes.Valid || auditRes.CheckedCount < 5 {
		t.Fatalf("expected valid audit chain with entries, got %+v", auditRes)
	}

	// 4. Built-in CLI Device Confirmation Flow (local server mode without OIDC).
	var devStart types.DeviceCodeStartResponse
	if err := unauthRPC.DoJSON(ctx, http.MethodPost, "/rpc/v1/auth/device/start", map[string]any{}, &devStart); err != nil {
		t.Fatalf("device start: %v", err)
	}
	if devStart.Mode != "local" || devStart.DeviceCode == "" || len(devStart.UserCode) != 9 {
		t.Fatalf("unexpected device start response: %+v", devStart)
	}
	var pollPending types.DeviceCodePollResponse
	if err := unauthRPC.DoJSON(ctx, http.MethodPost, "/rpc/v1/auth/device/poll", map[string]string{"device_code": devStart.DeviceCode}, &pollPending); err != nil {
		t.Fatalf("device poll pending: %v", err)
	}
	if pollPending.Status != "pending" {
		t.Fatalf("expected pending before decision, got %+v", pollPending)
	}
	// Missing CSRF on device decide must be 403.
	resp, _ = webDo(carolWeb, http.MethodPost, "/api/v1/auth/device/decide", "", map[string]string{
		"user_code": devStart.UserCode,
		"decision":  "approve",
	}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("device decide without CSRF status=%d, want 403", resp.StatusCode)
	}
	resp, raw = webDo(carolWeb, http.MethodPost, "/api/v1/auth/device/decide", carolLogin.CSRFToken, map[string]string{
		"user_code": devStart.UserCode,
		"decision":  "approve",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("device decide approve status=%d body=%s", resp.StatusCode, string(raw))
	}
	var pollApproved types.DeviceCodePollResponse
	if err := unauthRPC.DoJSON(ctx, http.MethodPost, "/rpc/v1/auth/device/poll", map[string]string{"device_code": devStart.DeviceCode}, &pollApproved); err != nil {
		t.Fatalf("device poll approved: %v", err)
	}
	if pollApproved.Status != "approved" || pollApproved.AccessToken == "" || pollApproved.Email != "carol@corp.example" {
		t.Fatalf("unexpected approved device poll: %+v", pollApproved)
	}
	carolCLI, err := NewRemoteClient(config.ClientContext{
		Name:       "srv",
		Endpoint:   tlsSrv.URL,
		CACertFile: caPath,
	}, pollApproved.AccessToken)
	if err != nil {
		t.Fatalf("carolCLI NewRemoteClient: %v", err)
	}
	var carolWho types.Principal
	if err := carolCLI.DoJSON(ctx, http.MethodGet, "/rpc/v1/whoami", nil, &carolWho); err != nil {
		t.Fatalf("carolCLI whoami: %v", err)
	}
	if carolWho.Email != "carol@corp.example" {
		t.Fatalf("expected carol@corp.example principal, got %+v", carolWho)
	}

	// 5. Platform admin Device Flow session mints PrincipalHuman (can mutate envs/security via CLI),
	// whereas scoped AgentToken stays blocked by ActionEnvWrite.
	if err := aliceClient.DoJSON(ctx, http.MethodPost, "/rpc/v1/environments", map[string]any{
		"environment": types.Environment{
			Code:       "qa-blocked",
			SafetyTier: types.SafetyTierGuarded,
		},
	}, nil); err == nil {
		t.Fatalf("agent token must not mutate environments via CLI")
	}

	var adminDevStart types.DeviceCodeStartResponse
	if err := unauthRPC.DoJSON(ctx, http.MethodPost, "/rpc/v1/auth/device/start", map[string]any{}, &adminDevStart); err != nil {
		t.Fatalf("admin device start: %v", err)
	}
	resp, raw = webDo(adminWeb, http.MethodPost, "/api/v1/auth/device/decide", loginOut.CSRFToken, map[string]string{
		"user_code": adminDevStart.UserCode,
		"decision":  "approve",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin device decide status=%d body=%s", resp.StatusCode, string(raw))
	}
	var adminPoll types.DeviceCodePollResponse
	if err := unauthRPC.DoJSON(ctx, http.MethodPost, "/rpc/v1/auth/device/poll", map[string]string{"device_code": adminDevStart.DeviceCode}, &adminPoll); err != nil {
		t.Fatalf("admin device poll: %v", err)
	}
	if adminPoll.Status != "approved" || adminPoll.AccessToken == "" {
		t.Fatalf("unexpected admin device poll: %+v", adminPoll)
	}
	adminCLI, err := NewRemoteClient(config.ClientContext{
		Name:       "srv",
		Endpoint:   tlsSrv.URL,
		CACertFile: caPath,
	}, adminPoll.AccessToken)
	if err != nil {
		t.Fatalf("adminCLI NewRemoteClient: %v", err)
	}
	var adminWho types.Principal
	if err := adminCLI.DoJSON(ctx, http.MethodGet, "/rpc/v1/whoami", nil, &adminWho); err != nil {
		t.Fatalf("adminCLI whoami: %v", err)
	}
	if adminWho.Kind != types.PrincipalHuman {
		t.Fatalf("interactive CLI login should mint PrincipalHuman, got %+v", adminWho)
	}
	var envCreated types.Environment
	if err := adminCLI.DoJSON(ctx, http.MethodPost, "/rpc/v1/environments", map[string]any{
		"environment": types.Environment{
			Code:       "qa-human",
			SafetyTier: types.SafetyTierGuarded,
		},
	}, &envCreated); err != nil {
		t.Fatalf("platform_admin human CLI token should be allowed ActionEnvWrite: %v", err)
	}

	// 6. Non-admin audit pagination must filter BEFORE LIMIT/OFFSET and report accurate totals/truncated.
	// Note that several platform_admin events were just recorded after Alice's executions.
	var rpcAudit struct {
		Items        []types.AuditEntry `json:"items"`
		TotalMatched int                `json:"total_matched"`
		Returned     int                `json:"returned"`
		Truncated    bool               `json:"truncated"`
	}
	if err := aliceClient.DoJSON(ctx, http.MethodGet, "/rpc/v1/audit?limit=1&offset=0", nil, &rpcAudit); err != nil {
		t.Fatalf("alice rpc audit page 1: %v", err)
	}
	if len(rpcAudit.Items) != 1 || rpcAudit.TotalMatched < 2 || !rpcAudit.Truncated {
		t.Fatalf("expected non-empty paginated audit slice after unauthorized newer rows, got items=%d total=%d truncated=%v",
			len(rpcAudit.Items), rpcAudit.TotalMatched, rpcAudit.Truncated)
	}
	resp, raw = webDo(aliceWeb, http.MethodGet, "/api/v1/audit?limit=1&offset=0", "", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("alice web audit status=%d body=%s", resp.StatusCode, string(raw))
	}
	var webAudit struct {
		Items        []types.AuditEntry `json:"items"`
		TotalMatched int                `json:"total_matched"`
		Truncated    bool               `json:"truncated"`
	}
	_ = json.Unmarshal(raw, &webAudit)
	if len(webAudit.Items) != 1 || webAudit.TotalMatched < 2 || !webAudit.Truncated {
		t.Fatalf("expected non-empty web audit page, got items=%d total=%d truncated=%v",
			len(webAudit.Items), webAudit.TotalMatched, webAudit.Truncated)
	}

	// 7. Explicit target test RBAC enforcement: Alice can test orders target, cannot test billing target.
	resp, raw = webDo(aliceWeb, http.MethodPost, "/api/v1/targets/"+dbListRes.Items[0].Target.ID+"/test", aliceLogin.CSRFToken, map[string]any{}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("alice target test orders status=%d body=%s", resp.StatusCode, string(raw))
	}
	resp, raw = webDo(adminWeb, http.MethodGet, "/api/v1/targets", "", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin targets status=%d body=%s", resp.StatusCode, string(raw))
	}
	var adminTargets struct {
		Items []types.TargetDetail `json:"items"`
	}
	_ = json.Unmarshal(raw, &adminTargets)
	billingID := ""
	for _, td := range adminTargets.Items {
		if td.OwnerSystem != nil && td.OwnerSystem.Slug == "billing" {
			billingID = td.Target.ID
			break
		}
	}
	if billingID == "" {
		t.Fatalf("billing target not found")
	}
	resp, _ = webDo(aliceWeb, http.MethodPost, "/api/v1/targets/"+billingID+"/test", aliceLogin.CSRFToken, map[string]any{}, nil)
	if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusForbidden {
		t.Fatalf("alice must not test unauthorized billing target, got %d", resp.StatusCode)
	}
}
