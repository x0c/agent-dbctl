package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestContextsRoundTripAndValidation(t *testing.T) {
	t.Setenv(EnvConfigHome, t.TempDir())
	t.Setenv(EnvContext, "")
	t.Setenv(EnvEndpoint, "")

	paths, err := ResolvePaths("default")
	if err != nil {
		t.Fatalf("ResolvePaths: %v", err)
	}

	// Default context resolves to local.
	active, explicit, err := ResolveActiveContext(paths, "")
	if err != nil || explicit || active.Mode != ContextModeLocal || active.Name != "local" {
		t.Fatalf("unexpected default context: active=%+v explicit=%v err=%v", active, explicit, err)
	}

	// Reject non-loopback http:// remote endpoint.
	if err := ValidateContext(ClientContext{
		Name:     "bad",
		Mode:     ContextModeRemote,
		Endpoint: "http://dbctl.example.com",
	}); err == nil {
		t.Fatalf("expected non-loopback http:// remote context to be rejected")
	}

	// Allow https:// remote endpoint and loopback http://.
	cf, err := LoadContexts(paths)
	if err != nil {
		t.Fatalf("LoadContexts: %v", err)
	}
	cf.Contexts["corp"] = ClientContext{
		Name:     "corp",
		Mode:     ContextModeRemote,
		Endpoint: "https://dbctl.example.com",
		AuthMode: AuthModeOIDCDevice,
	}
	cf.CurrentContext = "corp"
	if err := SaveContexts(paths, cf); err != nil {
		t.Fatalf("SaveContexts: %v", err)
	}

	info, err := os.Stat(ContextsPath(paths))
	if err != nil {
		t.Fatalf("stat contexts.yaml: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600 mode on contexts.yaml, got %o", info.Mode().Perm())
	}

	active, explicit, err = ResolveActiveContext(paths, "")
	if err != nil || explicit || active.Mode != ContextModeRemote || active.Endpoint != "https://dbctl.example.com" {
		t.Fatalf("unexpected active corp context: active=%+v explicit=%v err=%v", active, explicit, err)
	}

	// Explicit --context local overrides current_context=corp.
	active, explicit, err = ResolveActiveContext(paths, "local")
	if err != nil || !explicit || active.Mode != ContextModeLocal {
		t.Fatalf("expected explicit local override, got active=%+v explicit=%v err=%v", active, explicit, err)
	}

	// Env endpoint override when no explicit --context.
	t.Setenv(EnvEndpoint, "http://127.0.0.1:8443")
	cf.CurrentContext = "local"
	_ = SaveContexts(paths, cf)
	active, explicit, err = ResolveActiveContext(paths, "")
	if err != nil || !explicit || active.Mode != ContextModeRemote || active.Endpoint != "http://127.0.0.1:8443" {
		t.Fatalf("expected AGENT_DBCTL_ENDPOINT override, got active=%+v explicit=%v err=%v", active, explicit, err)
	}
}

func TestServerConfigValidation(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv(EnvConfigHome, tmp)
	paths, err := ResolvePaths("default")
	if err != nil {
		t.Fatalf("ResolvePaths: %v", err)
	}

	keyHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cfgPath := filepath.Join(tmp, "server.yaml")
	yamlBody := `
listen_addr: "127.0.0.1:8080"
public_url: "https://dbctl.example.com"
trust_proxy_headers: true
trusted_proxy_cidrs: ["198.51.100.0/24"]
replicas: 2
storage:
  driver: "postgres"
  dsn: "postgres://user:pass@localhost:5432/dbctl"
pubsub:
  driver: "postgres"
result_slot:
  driver: "redis"
  redis_url: "redis://localhost:6379/0"
secrets:
  driver: "encrypted_db"
auth:
  local_login_enabled: true
`
	if err := os.WriteFile(cfgPath, []byte(yamlBody), 0o600); err != nil {
		t.Fatalf("write server.yaml: %v", err)
	}
	t.Setenv(EnvMasterKey, keyHex)

	cfg, err := LoadServerConfig(cfgPath, paths)
	if err != nil {
		t.Fatalf("LoadServerConfig valid: %v", err)
	}
	hosts := cfg.EffectiveAllowedHosts()
	if len(hosts) == 0 || hosts[0] != "dbctl.example.com" {
		t.Fatalf("unexpected effective allowed hosts: %v", hosts)
	}

	// Replicas > 1 with sqlite must fail.
	bad := cfg
	bad.Storage.Driver = "sqlite"
	if err := bad.Validate(); err == nil {
		t.Fatalf("expected replicas > 1 with sqlite to fail validation")
	}

	// Non-loopback http:// public_url must fail.
	bad = cfg
	bad.PublicURL = "http://dbctl.example.com"
	if err := bad.Validate(); err == nil {
		t.Fatalf("expected non-loopback http public_url to fail validation")
	}
}
