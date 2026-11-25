package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	EnvContext  = "AGENT_DBCTL_CONTEXT"
	EnvEndpoint = "AGENT_DBCTL_ENDPOINT"
	EnvToken    = "AGENT_DBCTL_TOKEN"
)

// ContextMode selects local daemon mode or remote server client mode.
type ContextMode string

const (
	ContextModeLocal  ContextMode = "local"
	ContextModeRemote ContextMode = "remote"
)

// AuthMode configures how a remote CLI context authenticates.
type AuthMode string

const (
	AuthModeOIDCDevice  AuthMode = "oidc_device"
	AuthModeBearerToken AuthMode = "bearer_token"
)

var validContextNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// ClientContext defines one named local or remote CLI target profile.
type ClientContext struct {
	Name            string      `yaml:"name,omitempty" json:"name"`
	Mode            ContextMode `yaml:"mode" json:"mode"`
	Endpoint        string      `yaml:"endpoint,omitempty" json:"endpoint,omitempty"`
	CACertFile      string      `yaml:"ca_cert_file,omitempty" json:"ca_cert_file,omitempty"`
	ClientCertFile  string      `yaml:"client_cert_file,omitempty" json:"client_cert_file,omitempty"`
	ClientKeyFile   string      `yaml:"client_key_file,omitempty" json:"client_key_file,omitempty"`
	AuthMode        AuthMode    `yaml:"auth_mode,omitempty" json:"auth_mode,omitempty"`
	TokenEnv        string      `yaml:"token_env,omitempty" json:"token_env,omitempty"`
	InsecureSkipTLS bool        `yaml:"insecure_skip_tls_verify,omitempty" json:"insecure_skip_tls_verify,omitempty"`
}

// ContextsFile persists named contexts under <config_home>/contexts.yaml at mode 0600.
type ContextsFile struct {
	CurrentContext string                   `yaml:"current_context" json:"current_context"`
	Contexts       map[string]ClientContext `yaml:"contexts" json:"contexts"`
}

// ContextsPath returns the canonical contexts.yaml path under ConfigHome.
func ContextsPath(paths Paths) string {
	return filepath.Join(paths.ConfigHome, "contexts.yaml")
}

// ValidateContextName validates a context identifier.
func ValidateContextName(name string) error {
	trimmed := strings.TrimSpace(name)
	if !validContextNameRe.MatchString(trimmed) {
		return fmt.Errorf("invalid context name %q: must match %s", name, validContextNameRe.String())
	}
	return nil
}

// IsLoopbackURL reports whether rawURL targets a loopback IP or localhost.
func IsLoopbackURL(rawURL string) bool {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return false
	}
	host := strings.TrimSpace(u.Hostname())
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ValidateContext validates context fields and enforces HTTPS for non-loopback remote endpoints.
func ValidateContext(c ClientContext) error {
	if c.Mode == "" || c.Mode == ContextModeLocal {
		return nil
	}
	if c.Mode != ContextModeRemote {
		return fmt.Errorf("invalid context mode %q: expected local or remote", c.Mode)
	}
	ep := strings.TrimSpace(c.Endpoint)
	if ep == "" {
		return fmt.Errorf("remote context requires endpoint URL")
	}
	u, err := url.Parse(ep)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("invalid remote endpoint URL %q", ep)
	}
	if u.User != nil {
		return fmt.Errorf("remote endpoint URL must not embed credentials")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && (scheme != "http" || !IsLoopbackURL(ep)) {
		return fmt.Errorf("remote endpoint %q must use https:// (http:// is allowed only for loopback)", ep)
	}
	if c.AuthMode != "" && c.AuthMode != AuthModeOIDCDevice && c.AuthMode != AuthModeBearerToken {
		return fmt.Errorf("invalid auth_mode %q: expected oidc_device or bearer_token", c.AuthMode)
	}
	if (c.ClientCertFile != "") != (c.ClientKeyFile != "") {
		return fmt.Errorf("client_cert_file and client_key_file must both be set for mTLS")
	}
	return nil
}

// DefaultContextsFile returns a baseline contexts structure with the implicit local context.
func DefaultContextsFile() ContextsFile {
	return ContextsFile{
		CurrentContext: "local",
		Contexts: map[string]ClientContext{
			"local": {Name: "local", Mode: ContextModeLocal},
		},
	}
}

// LoadContexts reads contexts.yaml if present, refusing symlinks and normalizing defaults.
func LoadContexts(paths Paths) (ContextsFile, error) {
	p := ContextsPath(paths)
	if err := ValidateRegularFile(p); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return DefaultContextsFile(), nil
		}
		return ContextsFile{}, err
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return ContextsFile{}, err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return DefaultContextsFile(), nil
	}
	var cf ContextsFile
	if err := yaml.Unmarshal(raw, &cf); err != nil {
		return ContextsFile{}, fmt.Errorf("parse %s: %w", p, err)
	}
	if cf.Contexts == nil {
		cf.Contexts = map[string]ClientContext{}
	}
	if _, ok := cf.Contexts["local"]; !ok {
		cf.Contexts["local"] = ClientContext{Name: "local", Mode: ContextModeLocal}
	}
	for k, v := range cf.Contexts {
		v.Name = k
		if v.Mode == "" {
			if v.Endpoint != "" {
				v.Mode = ContextModeRemote
			} else {
				v.Mode = ContextModeLocal
			}
		}
		cf.Contexts[k] = v
	}
	if strings.TrimSpace(cf.CurrentContext) == "" {
		cf.CurrentContext = "local"
	}
	return cf, nil
}

// SaveContexts atomically persists contexts.yaml with mode 0600 inside a 0700 ConfigHome.
func SaveContexts(paths Paths, cf ContextsFile) error {
	if err := EnsurePrivateDir(paths.ConfigHome); err != nil {
		return err
	}
	p := ContextsPath(paths)
	if err := ValidateRegularFile(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if cf.Contexts == nil {
		cf.Contexts = map[string]ClientContext{}
	}
	if _, ok := cf.Contexts["local"]; !ok {
		cf.Contexts["local"] = ClientContext{Name: "local", Mode: ContextModeLocal}
	}
	if strings.TrimSpace(cf.CurrentContext) == "" {
		cf.CurrentContext = "local"
	}
	if _, ok := cf.Contexts[cf.CurrentContext]; !ok {
		return fmt.Errorf("current_context %q does not exist in contexts", cf.CurrentContext)
	}
	for name, ctxCfg := range cf.Contexts {
		if err := ValidateContextName(name); err != nil {
			return err
		}
		ctxCfg.Name = name
		if err := ValidateContext(ctxCfg); err != nil {
			return fmt.Errorf("context %q: %w", name, err)
		}
		cf.Contexts[name] = ctxCfg
	}

	raw, err := yaml.Marshal(cf)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(paths.ConfigHome, ".contexts-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, p); err != nil {
		return err
	}
	cleanup = false
	return nil
}

// ResolveActiveContext selects the active client context from flags, env vars, and contexts.yaml.
// Precedence: explicit --context > AGENT_DBCTL_CONTEXT > AGENT_DBCTL_ENDPOINT > contexts.yaml current_context > local.
func ResolveActiveContext(paths Paths, flagContext string) (ClientContext, bool, error) {
	selected := strings.TrimSpace(flagContext)
	explicit := selected != ""
	if selected == "" {
		selected = strings.TrimSpace(os.Getenv(EnvContext))
		if selected != "" {
			explicit = true
		}
	}

	envEndpoint := strings.TrimSpace(os.Getenv(EnvEndpoint))
	if !explicit && envEndpoint != "" {
		ctxCfg := ClientContext{
			Name:     "env",
			Mode:     ContextModeRemote,
			Endpoint: strings.TrimRight(envEndpoint, "/"),
			AuthMode: AuthModeBearerToken,
		}
		if err := ValidateContext(ctxCfg); err != nil {
			return ClientContext{}, false, err
		}
		return ctxCfg, true, nil
	}

	cf, err := LoadContexts(paths)
	if err != nil {
		return ClientContext{}, explicit, err
	}
	if selected == "" {
		selected = cf.CurrentContext
	}
	if selected == "" || selected == "local" {
		return ClientContext{Name: "local", Mode: ContextModeLocal}, explicit, nil
	}
	ctxCfg, ok := cf.Contexts[selected]
	if !ok {
		return ClientContext{}, explicit, fmt.Errorf("context %q not found in %s", selected, ContextsPath(paths))
	}
	ctxCfg.Name = selected
	if ctxCfg.Mode == ContextModeRemote {
		ctxCfg.Endpoint = strings.TrimRight(ctxCfg.Endpoint, "/")
	}
	if err := ValidateContext(ctxCfg); err != nil {
		return ClientContext{}, explicit, err
	}
	return ctxCfg, explicit, nil
}
