package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	EnvServerConfig = "AGENT_DBCTL_SERVER_CONFIG"
	EnvStoreDSN     = "AGENT_DBCTL_STORE_DSN"
	EnvMasterKey    = "AGENT_DBCTL_MASTER_KEY"
	EnvRedisURL     = "AGENT_DBCTL_REDIS_URL"
	EnvOIDCSecret   = "AGENT_DBCTL_OIDC_SECRET"
	EnvPublicURL    = "AGENT_DBCTL_PUBLIC_URL"
	EnvListenAddr   = "AGENT_DBCTL_LISTEN_ADDR"
)

// ServerConfig configures `agent-dbctl serve` for centralized C/S deployments.
type ServerConfig struct {
	Mode               string   `yaml:"mode" json:"mode"`
	ListenAddr         string   `yaml:"listen_addr" json:"listen_addr"`
	PublicURL          string   `yaml:"public_url" json:"public_url"`
	AllowedHosts       []string `yaml:"allowed_hosts" json:"allowed_hosts"`
	TrustProxyHeaders  bool     `yaml:"trust_proxy_headers" json:"trust_proxy_headers"`
	TrustedProxyCIDRs  []string `yaml:"trusted_proxy_cidrs" json:"trusted_proxy_cidrs"`
	AllowSQLiteTargets bool     `yaml:"allow_sqlite_targets" json:"allow_sqlite_targets"`
	DisableSSHAuthSock bool     `yaml:"disable_ssh_auth_sock" json:"disable_ssh_auth_sock"`
	BlockedEgressCIDRs []string `yaml:"blocked_egress_cidrs" json:"blocked_egress_cidrs"`
	AllowedEgressCIDRs []string `yaml:"allowed_egress_cidrs" json:"allowed_egress_cidrs"`
	MinCLIVersion      string   `yaml:"min_cli_version" json:"min_cli_version"`
	Replicas           int      `yaml:"replicas" json:"replicas"`

	Storage    ServerStorageConfig    `yaml:"storage" json:"storage"`
	PubSub     ServerPubSubConfig     `yaml:"pubsub" json:"pubsub"`
	ResultSlot ServerResultSlotConfig `yaml:"result_slot" json:"result_slot"`
	Secrets    ServerSecretsConfig    `yaml:"secrets" json:"secrets"`
	Auth       ServerAuthConfig       `yaml:"auth" json:"auth"`
}

// ServerStorageConfig configures SQLite WAL or PostgreSQL repository storage.
type ServerStorageConfig struct {
	Driver string `yaml:"driver" json:"driver"` // sqlite | postgres
	DBPath string `yaml:"db_path" json:"db_path"`
	DSN    string `yaml:"dsn" json:"dsn"`
	DSNEnv string `yaml:"dsn_env" json:"dsn_env"`
}

// ServerPubSubConfig configures cross-node event distribution.
type ServerPubSubConfig struct {
	Driver string `yaml:"driver" json:"driver"` // memory | postgres | redis
}

// ServerResultSlotConfig configures query result relay caching.
type ServerResultSlotConfig struct {
	Driver      string `yaml:"driver" json:"driver"` // memory | redis | postgres
	RedisURL    string `yaml:"redis_url" json:"redis_url"`
	RedisURLEnv string `yaml:"redis_url_env" json:"redis_url_env"`
}

// ServerSecretsConfig configures server-side credential encryption and RCE/env-leak guards.
type ServerSecretsConfig struct {
	Driver                    string   `yaml:"driver" json:"driver"` // encrypted_db | encrypted_file
	MasterKey                 string   `yaml:"master_key" json:"-"`
	MasterKeyEnv              string   `yaml:"master_key_env" json:"master_key_env"`
	MasterKeyFile             string   `yaml:"master_key_file" json:"master_key_file"`
	AllowExecProviderForAdmin bool     `yaml:"allow_exec_provider_for_admin" json:"allow_exec_provider_for_admin"`
	AllowedExecPrefixes       []string `yaml:"allowed_exec_prefixes" json:"allowed_exec_prefixes"`
	AllowedEnvPrefixes        []string `yaml:"allowed_env_prefixes" json:"allowed_env_prefixes"`
}

// ServerAuthConfig configures Web/CLI authentication and four-eyes approval policy.
type ServerAuthConfig struct {
	LocalLoginEnabled     bool             `yaml:"local_login_enabled" json:"local_login_enabled"`
	BootstrapAdminEmail   string           `yaml:"bootstrap_admin_email" json:"bootstrap_admin_email"`
	BootstrapAdminPassEnv string           `yaml:"bootstrap_admin_password_env" json:"bootstrap_admin_password_env"`
	SessionTTLHours       int              `yaml:"session_ttl_hours" json:"session_ttl_hours"`
	ForbidSelfApproval    *bool            `yaml:"forbid_self_approval" json:"forbid_self_approval"`
	OIDC                  ServerOIDCConfig `yaml:"oidc" json:"oidc"`
}

// ServerOIDCConfig configures external OpenID Connect SSO + CLI Device Flow.
type ServerOIDCConfig struct {
	Enabled           bool     `yaml:"enabled" json:"enabled"`
	IssuerURL         string   `yaml:"issuer_url" json:"issuer_url"`
	ClientID          string   `yaml:"client_id" json:"client_id"`
	ClientSecret      string   `yaml:"client_secret" json:"-"`
	ClientSecretEnv   string   `yaml:"client_secret_env" json:"client_secret_env"`
	DeviceFlowEnabled bool     `yaml:"device_flow_enabled" json:"device_flow_enabled"`
	AdminGroups       []string `yaml:"admin_groups" json:"admin_groups"`
	AdminEmails       []string `yaml:"admin_emails" json:"admin_emails"`
	Scopes            []string `yaml:"scopes" json:"scopes"`
}

// DefaultServerConfig returns secure defaults for centralized server deployment.
func DefaultServerConfig(paths Paths) ServerConfig {
	forbidSelf := true
	return ServerConfig{
		Mode:               "server",
		ListenAddr:         "127.0.0.1:8080",
		PublicURL:          "http://127.0.0.1:8080",
		AllowSQLiteTargets: false,
		DisableSSHAuthSock: true,
		Replicas:           1,
		Storage: ServerStorageConfig{
			Driver: "sqlite",
			DBPath: paths.DBPath,
			DSNEnv: EnvStoreDSN,
		},
		PubSub: ServerPubSubConfig{
			Driver: "memory",
		},
		ResultSlot: ServerResultSlotConfig{
			Driver:      "memory",
			RedisURLEnv: EnvRedisURL,
		},
		Secrets: ServerSecretsConfig{
			Driver:       "encrypted_db",
			MasterKeyEnv: EnvMasterKey,
		},
		Auth: ServerAuthConfig{
			LocalLoginEnabled:  true,
			SessionTTLHours:    24,
			ForbidSelfApproval: &forbidSelf,
			OIDC: ServerOIDCConfig{
				ClientSecretEnv: EnvOIDCSecret,
				Scopes:          []string{"openid", "profile", "email"},
			},
		},
	}
}

// LoadServerConfig loads a server YAML config (if non-empty) and applies env overrides + validation.
func LoadServerConfig(path string, paths Paths) (ServerConfig, error) {
	cfg := DefaultServerConfig(paths)
	resolvedPath := strings.TrimSpace(path)
	if resolvedPath == "" {
		resolvedPath = strings.TrimSpace(os.Getenv(EnvServerConfig))
	}
	if resolvedPath != "" {
		if err := ValidateRegularFile(resolvedPath); err != nil {
			return ServerConfig{}, fmt.Errorf("server config %s: %w", resolvedPath, err)
		}
		raw, err := os.ReadFile(resolvedPath)
		if err != nil {
			return ServerConfig{}, fmt.Errorf("read server config: %w", err)
		}
		if err := yaml.Unmarshal(raw, &cfg); err != nil {
			return ServerConfig{}, fmt.Errorf("parse server config: %w", err)
		}
	}

	if v := strings.TrimSpace(os.Getenv(EnvListenAddr)); v != "" {
		cfg.ListenAddr = v
	}
	if v := strings.TrimSpace(os.Getenv(EnvPublicURL)); v != "" {
		cfg.PublicURL = v
	}
	cfg.PublicURL = strings.TrimRight(strings.TrimSpace(cfg.PublicURL), "/")
	if cfg.PublicURL == "" {
		cfg.PublicURL = "http://" + cfg.ListenAddr
	}
	if cfg.Storage.DSN == "" && cfg.Storage.DSNEnv != "" {
		cfg.Storage.DSN = strings.TrimSpace(os.Getenv(cfg.Storage.DSNEnv))
	}
	if cfg.ResultSlot.RedisURL == "" && cfg.ResultSlot.RedisURLEnv != "" {
		cfg.ResultSlot.RedisURL = strings.TrimSpace(os.Getenv(cfg.ResultSlot.RedisURLEnv))
	}
	if cfg.Secrets.MasterKey == "" && cfg.Secrets.MasterKeyEnv != "" {
		cfg.Secrets.MasterKey = strings.TrimSpace(os.Getenv(cfg.Secrets.MasterKeyEnv))
	}
	if cfg.Secrets.MasterKey == "" && strings.TrimSpace(cfg.Secrets.MasterKeyFile) != "" {
		keyPath := ExpandHomePath(cfg.Secrets.MasterKeyFile)
		if err := ValidateRegularFile(keyPath); err != nil {
			return ServerConfig{}, fmt.Errorf("master_key_file: %w", err)
		}
		b, err := os.ReadFile(keyPath)
		if err != nil {
			return ServerConfig{}, fmt.Errorf("read master_key_file: %w", err)
		}
		cfg.Secrets.MasterKey = strings.TrimSpace(string(b))
	}
	if cfg.Auth.OIDC.ClientSecret == "" && cfg.Auth.OIDC.ClientSecretEnv != "" {
		cfg.Auth.OIDC.ClientSecret = strings.TrimSpace(os.Getenv(cfg.Auth.OIDC.ClientSecretEnv))
	}
	if cfg.Storage.DBPath == "" {
		cfg.Storage.DBPath = paths.DBPath
	} else {
		cfg.Storage.DBPath = filepath.Clean(ExpandHomePath(cfg.Storage.DBPath))
	}
	if cfg.Replicas <= 0 {
		cfg.Replicas = 1
	}
	if cfg.Auth.SessionTTLHours <= 0 {
		cfg.Auth.SessionTTLHours = 24
	}
	if cfg.Auth.ForbidSelfApproval == nil {
		t := true
		cfg.Auth.ForbidSelfApproval = &t
	}

	if err := cfg.Validate(); err != nil {
		return ServerConfig{}, err
	}
	return cfg, nil
}

// Validate checks ServerConfig consistency and enforces multi-replica & security invariants.
func (c ServerConfig) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("listen_addr must not be empty")
	}
	u, err := url.Parse(c.PublicURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("invalid public_url %q", c.PublicURL)
	}
	if u.Scheme != "https" && (u.Scheme != "http" || !IsLoopbackURL(c.PublicURL)) {
		return fmt.Errorf("public_url %q must use https:// for non-loopback hosts", c.PublicURL)
	}
	for _, cidr := range c.TrustedProxyCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("invalid trusted_proxy_cidr %q: %w", cidr, err)
		}
	}
	for _, cidr := range append(append([]string{}, c.BlockedEgressCIDRs...), c.AllowedEgressCIDRs...) {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("invalid egress CIDR %q: %w", cidr, err)
		}
	}
	switch strings.ToLower(c.Storage.Driver) {
	case "sqlite":
		if c.Replicas > 1 {
			return fmt.Errorf("replicas > 1 requires storage.driver=postgres")
		}
	case "postgres":
		if strings.TrimSpace(c.Storage.DSN) == "" {
			return fmt.Errorf("storage.driver=postgres requires storage.dsn or %s", c.Storage.DSNEnv)
		}
	default:
		return fmt.Errorf("unsupported storage.driver %q", c.Storage.Driver)
	}
	switch strings.ToLower(c.PubSub.Driver) {
	case "memory", "postgres", "redis":
	default:
		return fmt.Errorf("unsupported pubsub.driver %q", c.PubSub.Driver)
	}
	switch strings.ToLower(c.ResultSlot.Driver) {
	case "memory", "redis", "postgres":
	default:
		return fmt.Errorf("unsupported result_slot.driver %q", c.ResultSlot.Driver)
	}
	if c.Replicas > 1 && strings.EqualFold(c.ResultSlot.Driver, "memory") {
		return fmt.Errorf("replicas > 1 requires shared result_slot.driver (redis or postgres)")
	}
	if c.Replicas > 1 && strings.EqualFold(c.PubSub.Driver, "memory") {
		return fmt.Errorf("replicas > 1 requires shared pubsub.driver (postgres or redis)")
	}
	if (strings.EqualFold(c.PubSub.Driver, "redis") || strings.EqualFold(c.ResultSlot.Driver, "redis")) && strings.TrimSpace(c.ResultSlot.RedisURL) == "" {
		return fmt.Errorf("redis pubsub/result_slot requires redis_url or %s", c.ResultSlot.RedisURLEnv)
	}
	switch strings.ToLower(c.Secrets.Driver) {
	case "encrypted_db", "encrypted_file":
		if strings.TrimSpace(c.Secrets.MasterKey) == "" {
			return fmt.Errorf("secrets.driver=%s requires master_key, master_key_file, or %s", c.Secrets.Driver, c.Secrets.MasterKeyEnv)
		}
	default:
		return fmt.Errorf("server secrets.driver %q must be encrypted_db or encrypted_file", c.Secrets.Driver)
	}
	if !c.Auth.LocalLoginEnabled && !c.Auth.OIDC.Enabled {
		return fmt.Errorf("at least one authentication method (local_login_enabled or auth.oidc.enabled) must be enabled")
	}
	if c.Auth.OIDC.Enabled {
		if strings.TrimSpace(c.Auth.OIDC.IssuerURL) == "" || strings.TrimSpace(c.Auth.OIDC.ClientID) == "" {
			return fmt.Errorf("auth.oidc.enabled requires issuer_url and client_id")
		}
	}
	return nil
}

// EffectiveAllowedHosts returns normalized host[:port] entries allowed on incoming Host headers.
func (c ServerConfig) EffectiveAllowedHosts() []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(h string) {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			return
		}
		if _, ok := seen[h]; ok {
			return
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	if u, err := url.Parse(c.PublicURL); err == nil {
		add(u.Host)
		add(u.Hostname())
	}
	for _, h := range c.AllowedHosts {
		add(h)
	}
	return out
}
