package secrets

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
	"unicode"

	"github.com/x0c/agent-dbctl/internal/config"
	"github.com/x0c/agent-dbctl/internal/types"
)

const maxExecSecretBytes = 64 << 10 // 64 KiB

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

// SplitExecArgs splits a command line into executable and arguments with support for
// single quotes, double quotes, and backslash escapes, without invoking a shell.
func SplitExecArgs(cmdLine string) ([]string, error) {
	trimmed := strings.TrimSpace(cmdLine)
	if trimmed == "" {
		return nil, fmt.Errorf("empty exec_command")
	}

	var args []string
	var cur strings.Builder
	inToken := false
	var quote rune

	runes := []rune(trimmed)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if quote != 0 {
			if quote == '\'' {
				if r == '\'' {
					quote = 0
					continue
				}
				cur.WriteRune(r)
				continue
			}
			// Double-quoted segment: supports \", \\, \$, \` escapes.
			if r == '\\' && i+1 < len(runes) {
				next := runes[i+1]
				if next == '"' || next == '\\' || next == '$' || next == '`' {
					cur.WriteRune(next)
					i++
					continue
				}
			}
			if r == '"' {
				quote = 0
				continue
			}
			cur.WriteRune(r)
			continue
		}

		if unicode.IsSpace(r) {
			if inToken {
				args = append(args, cur.String())
				cur.Reset()
				inToken = false
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			inToken = true
			continue
		}
		if r == '\\' {
			if i+1 >= len(runes) {
				return nil, fmt.Errorf("dangling escape in exec_command")
			}
			cur.WriteRune(runes[i+1])
			inToken = true
			i++
			continue
		}
		cur.WriteRune(r)
		inToken = true
	}

	if quote != 0 {
		return nil, fmt.Errorf("unclosed quote in exec_command")
	}
	if inToken {
		args = append(args, cur.String())
	}
	if len(args) == 0 || strings.TrimSpace(args[0]) == "" {
		return nil, fmt.Errorf("empty executable in exec_command")
	}
	return args, nil
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
		parts, err := SplitExecArgs(prof.ExecCommand)
		if err != nil {
			return out, fmt.Errorf("credential %q invalid exec_command: %w", prof.Name, err)
		}
		execCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		// Execute directly without shell interpolation to block command injection.
		cmd := exec.CommandContext(execCtx, parts[0], parts[1:]...) //nolint:gosec // Explicit user-configured credential command without shell.
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return out, fmt.Errorf("credential %q exec_provider pipe failed: %w", prof.Name, err)
		}
		if err := cmd.Start(); err != nil {
			return out, fmt.Errorf("credential %q exec_provider start failed: %w", prof.Name, err)
		}
		raw, readErr := io.ReadAll(io.LimitReader(stdout, maxExecSecretBytes+1))
		waitErr := cmd.Wait()
		if readErr != nil {
			return out, fmt.Errorf("credential %q exec_provider read failed: %w", prof.Name, readErr)
		}
		if len(raw) > maxExecSecretBytes {
			return out, fmt.Errorf("credential %q exec_provider output exceeded %d bytes", prof.Name, maxExecSecretBytes)
		}
		if waitErr != nil {
			// Never include stdout bytes in error messages.
			return out, fmt.Errorf("credential %q exec_provider failed: %w", prof.Name, waitErr)
		}
		out.Secret = strings.TrimRight(string(raw), "\r\n")
		return out, nil
	default:
		return out, fmt.Errorf("unsupported credential kind %q", prof.Kind)
	}
}
