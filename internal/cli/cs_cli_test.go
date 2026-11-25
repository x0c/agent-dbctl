package cli_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/x0c/agent-dbctl/internal/config"
	"github.com/x0c/agent-dbctl/internal/daemon"
	"github.com/x0c/agent-dbctl/internal/types"
)

func TestRemoteContextAndCLIWorkflow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	bin := buildTestCLI(t)
	tmpDir := t.TempDir()
	clientHome := filepath.Join(tmpDir, "client-home")
	serverHome := filepath.Join(tmpDir, "server-home")
	if err := os.MkdirAll(serverHome, 0o700); err != nil {
		t.Fatalf("mkdir serverHome: %v", err)
	}

	targetDB := filepath.Join(tmpDir, "app.db")
	db, err := sql.Open("sqlite", targetDB)
	if err != nil {
		t.Fatalf("open target sqlite: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE widgets (id INTEGER PRIMARY KEY, label TEXT); INSERT INTO widgets (id, label) VALUES (1, 'alpha');`); err != nil {
		_ = db.Close()
		t.Fatalf("seed target sqlite: %v", err)
	}
	_ = db.Close()

	tlsSrv := httptest.NewUnstartedServer(http.NotFoundHandler())
	tlsSrv.StartTLS()
	defer tlsSrv.Close()

	u, err := url.Parse(tlsSrv.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	caPath := filepath.Join(tmpDir, "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsSrv.Certificate().Raw})
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatalf("write CA cert: %v", err)
	}

	adminPass := "AdminCliPass#2026!"
	t.Setenv("CLI_TEST_ADMIN_PASS", adminPass)
	paths := config.Paths{
		ConfigHome: serverHome,
		PluginsDir: filepath.Join(serverHome, "plugins"),
		DBPath:     filepath.Join(serverHome, "server.db"),
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
		Driver:    "encrypted_db",
		MasterKey: strings.Repeat("b", 64),
	}
	srvCfg.Auth = config.ServerAuthConfig{
		LocalLoginEnabled:     true,
		BootstrapAdminEmail:   "admin@corp.example",
		BootstrapAdminPassEnv: "CLI_TEST_ADMIN_PASS",
		SessionTTLHours:       24,
	}
	svc, err := daemon.NewServerService(ctx, paths, srvCfg, "v0.9.9", "deadbeef")
	if err != nil {
		t.Fatalf("NewServerService: %v", err)
	}
	defer svc.Shutdown()
	tlsSrv.Config.Handler = daemon.NewRemoteServerHandler(svc)

	// Bootstrap admin login via Web session to seed one DB target + mint an API token.
	jar, _ := cookiejar.New(nil)
	webClient := &http.Client{Transport: tlsSrv.Client().Transport, Jar: jar, Timeout: 10 * time.Second}
	loginReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, tlsSrv.URL+"/api/v1/auth/login", strings.NewReader(`{"email":"admin@corp.example","password":"`+adminPass+`"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	loginReq.Header.Set("Origin", tlsSrv.URL)
	loginResp, err := webClient.Do(loginReq)
	if err != nil {
		t.Fatalf("web login: %v", err)
	}
	loginRaw, _ := io.ReadAll(loginResp.Body)
	_ = loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("web login status=%d body=%s", loginResp.StatusCode, string(loginRaw))
	}
	var loginData struct {
		CSRFToken string `json:"ui_csrf_token"`
	}
	_ = json.Unmarshal(loginRaw, &loginData)

	webPost := func(path, body string) []byte {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, tlsSrv.URL+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", tlsSrv.URL)
		req.Header.Set("X-Agent-DBCTL-CSRF", loginData.CSRFToken)
		resp, err := webClient.Do(req)
		if err != nil {
			t.Fatalf("post %s: %v", path, err)
		}
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("post %s status=%d body=%s", path, resp.StatusCode, string(raw))
		}
		return raw
	}

	_ = webPost("/api/v1/db/add", `{"engine":"sqlite","host":"`+filepath.ToSlash(targetDB)+`","database":"`+filepath.ToSlash(targetDB)+`","system":"shop","env":"dev"}`)
	tokRaw := webPost("/api/v1/tokens", `{"name":"cli-test-bot","role_ceiling":"developer","allowed_systems":["shop"],"ttl_seconds":3600}`)
	var tokCreated types.APITokenCreateResponse
	_ = json.Unmarshal(tokRaw, &tokCreated)

	// 1. Non-loopback http:// context must be rejected.
	code, env, rawOut := runCLI(t, bin, clientHome, "context", "add", "bad", "--endpoint", "http://db.corp.example:8443", "--json")
	if code == 0 || env.OK {
		t.Fatalf("expected non-loopback http context add to fail, got code=%d out=%s", code, rawOut)
	}

	// 2. Add & activate HTTPS remote context.
	code, env, rawOut = runCLI(t, bin, clientHome, "context", "add", "corp", "--endpoint", tlsSrv.URL, "--ca-cert", caPath, "--use", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("context add failed code=%d out=%s", code, rawOut)
	}

	// 3. Reject conflicting --session + --context.
	code, env, rawOut = runCLI(t, bin, clientHome, "--session", "alt", "--context", "corp", "whoami", "--json")
	if code == 0 || env.OK {
		t.Fatalf("expected --session + --context conflict, got code=%d out=%s", code, rawOut)
	}

	// 4. Login non-interactively via --token-stdin.
	loginCmd := exec.Command(bin, "--context", "corp", "login", "--token-stdin", "--json")
	loginCmd.Env = append(os.Environ(),
		config.EnvConfigHome+"="+clientHome,
		config.EnvSecretBackend+"=file",
		config.EnvNoBrowser+"=1",
		config.EnvNoSkillSync+"=1",
	)
	loginCmd.Stdin = strings.NewReader(tokCreated.SecretToken + "\n")
	var stdout, stderr bytes.Buffer
	loginCmd.Stdout = &stdout
	loginCmd.Stderr = &stderr
	if err := loginCmd.Run(); err != nil {
		t.Fatalf("cli login --token-stdin failed: %v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
	}

	// 5. Verify remote whoami, db list, exec, audit list, doctor, and unsupported daemon stop.
	code, env, rawOut = runCLI(t, bin, clientHome, "--context", "corp", "whoami", "--json")
	if code != 0 || !env.OK || env.Meta.Context != "corp" || env.Meta.Mode != "remote" {
		t.Fatalf("whoami failed code=%d meta=%+v out=%s", code, env.Meta, rawOut)
	}

	dataStr := func(e types.Envelope) string {
		b, _ := json.Marshal(e.Data)
		return string(b)
	}

	code, env, rawOut = runCLI(t, bin, clientHome, "--context", "corp", "db", "list", "--json")
	if code != 0 || !env.OK || !strings.Contains(dataStr(env), "shop/dev/") {
		t.Fatalf("remote db list failed code=%d data=%s err=%s", code, dataStr(env), rawOut)
	}

	code, env, rawOut = runCLI(t, bin, clientHome, "--context", "corp", "exec", "--db", "shop/dev/app", "--sql", "SELECT id, label FROM widgets WHERE id = 1 LIMIT 5", "--json")
	if code != 0 || !env.OK || !strings.Contains(dataStr(env), "alpha") {
		t.Fatalf("remote exec failed code=%d data=%s err=%s", code, dataStr(env), rawOut)
	}

	code, env, rawOut = runCLI(t, bin, clientHome, "--context", "corp", "audit", "list", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("remote audit list failed code=%d out=%s", code, rawOut)
	}

	code, env, rawOut = runCLI(t, bin, clientHome, "--context", "corp", "doctor", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("remote doctor failed code=%d out=%s", code, rawOut)
	}

	code, env, rawOut = runCLI(t, bin, clientHome, "--context", "corp", "daemon", "stop", "--json")
	if code != types.ExitUsage || env.Error == nil || env.Error.Code != types.ErrCodeRemoteUnsupported {
		t.Fatalf("expected remote_mode_unsupported on daemon stop, got code=%d env=%+v out=%s", code, env, rawOut)
	}

	// 6. Switch back to local context and remove remote context cleanly.
	code, env, rawOut = runCLI(t, bin, clientHome, "context", "use", "local", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("context use local failed code=%d out=%s", code, rawOut)
	}
	code, env, rawOut = runCLI(t, bin, clientHome, "context", "remove", "corp", "--json")
	if code != 0 || !env.OK {
		t.Fatalf("context remove failed code=%d out=%s", code, rawOut)
	}
}
