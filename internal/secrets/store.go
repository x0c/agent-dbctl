package secrets

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/x0c/agent-dbctl/internal/config"
	"github.com/x0c/agent-dbctl/internal/types"
)

// ErrNotFound indicates no secret is stored for the requested profile.
var ErrNotFound = errors.New("secret not found")

// ResolvedSecret holds ephemeral runtime authentication values (never serialized to logs/audit).
type ResolvedSecret struct {
	Username string
	Secret   string // Password, private key, or token
}

// Store persists and retrieves profile secrets outside SQLite.
type Store interface {
	Name() string
	Get(ctx context.Context, key string) (string, error)
	Put(ctx context.Context, key, value string) error
	Delete(ctx context.Context, key string) error
	Has(ctx context.Context, key string) (bool, error)
}

// NewStore selects the configured secret backend (keychain on macOS, or isolated 0600 file store).
func NewStore(paths config.Paths) Store {
	backend := strings.ToLower(strings.TrimSpace(os.Getenv(config.EnvSecretBackend)))
	if backend == "file" {
		return NewFileStore(paths.SecretFile)
	}
	return newPlatformStore(paths)
}

// ResolveCredential resolves runtime credentials for a CredentialProfile without leaking secrets.
func ResolveCredential(ctx context.Context, store Store, prof *types.CredentialProfile) (ResolvedSecret, error) {
	if prof == nil {
		return ResolvedSecret{}, nil
	}
	out := ResolvedSecret{Username: prof.Username}
	switch prof.Kind {
	case types.CredKeychain:
		val, err := store.Get(ctx, "cred:"+prof.ID)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return out, fmt.Errorf("credential %q (%s): %w", prof.Name, prof.ID, ErrNotFound)
			}
			return out, err
		}
		out.Secret = val
		return out, nil
	case types.CredEnvRef:
		if strings.TrimSpace(prof.EnvVarName) == "" {
			return out, fmt.Errorf("credential %q has empty env_var_name", prof.ID)
		}
		val, ok := os.LookupEnv(prof.EnvVarName)
		if !ok || val == "" {
			return out, fmt.Errorf("credential %q requires environment variable %s: %w", prof.Name, prof.EnvVarName, ErrNotFound)
		}
		out.Secret = val
		return out, nil
	case types.CredExecProvider:
		cmdLine := strings.TrimSpace(prof.ExecCommand)
		if cmdLine == "" {
			return out, fmt.Errorf("credential %q has empty exec_command", prof.ID)
		}
		parts := strings.Fields(cmdLine)
		execCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		// Execute directly without shell interpolation to block command injection.
		cmd := exec.CommandContext(execCtx, parts[0], parts[1:]...) //nolint:gosec // Explicit user-configured credential command without shell.
		raw, err := cmd.Output()
		if err != nil {
			return out, fmt.Errorf("credential %q exec_provider failed: %w", prof.Name, err)
		}
		out.Secret = strings.TrimRight(string(raw), "\r\n")
		return out, nil
	default:
		return out, fmt.Errorf("unsupported credential kind %q", prof.Kind)
	}
}
