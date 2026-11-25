package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	EnvConfigHome    = "AGENT_DBCTL_CONFIG_HOME"
	EnvSession       = "AGENT_DBCTL_SESSION"
	EnvSecretBackend = "AGENT_DBCTL_SECRET_BACKEND"
	EnvWebPort       = "AGENT_DBCTL_WEB_PORT"
	EnvNoBrowser     = "AGENT_DBCTL_NO_BROWSER"
	EnvNoDaemonSpawn = "AGENT_DBCTL_NO_DAEMON_SPAWN"
	EnvNoSkillSync   = "AGENT_DBCTL_NO_SKILL_SYNC"
	EnvSkillsAuto    = "AGENT_DBCTL_SKILLS_AUTO"
	EnvSkillHome     = "AGENT_DBCTL_SKILL_HOME"
)

var validSessionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Paths holds resolved, permission-checked filesystem locations for one session.
type Paths struct {
	ConfigHome string
	RunDir     string
	PluginsDir string
	DBPath     string
	SocketPath string
	DaemonMeta string
	SecretFile string
	Session    string
}

// ResolveConfigHome returns the absolute root config directory without creating subdirectories.
func ResolveConfigHome() (string, error) {
	root := strings.TrimSpace(os.Getenv(EnvConfigHome))
	if root == "" {
		xdg := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME"))
		if xdg != "" {
			root = filepath.Join(xdg, "agent-dbctl")
		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", fmt.Errorf("resolve home directory: %w", err)
			}
			root = filepath.Join(home, ".config", "agent-dbctl")
		}
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve absolute config path: %w", err)
	}
	return absRoot, nil
}

// ResolvePaths computes isolated config and runtime paths for the active session.
func ResolvePaths(sessionOverride string) (Paths, error) {
	session := strings.TrimSpace(sessionOverride)
	if session == "" {
		session = strings.TrimSpace(os.Getenv(EnvSession))
	}
	if session == "" {
		session = "default"
	}
	if !validSessionRe.MatchString(session) {
		return Paths{}, fmt.Errorf("invalid session name %q: must match %s", session, validSessionRe.String())
	}

	absRoot, err := ResolveConfigHome()
	if err != nil {
		return Paths{}, err
	}

	runDir := filepath.Join(absRoot, "run")
	pluginsDir := filepath.Join(absRoot, "plugins")

	for _, dir := range []string{absRoot, runDir, pluginsDir} {
		if err := EnsurePrivateDir(dir); err != nil {
			return Paths{}, err
		}
	}

	sockPath := filepath.Join(runDir, session+".sock")
	// Unix domain socket sun_path is capped at 104 bytes on macOS (108 on Linux).
	// If ConfigHome is deep (e.g. long test temp dirs), hash into os.TempDir() to stay well below the limit.
	if len(sockPath) > 95 {
		sum := sha256.Sum256([]byte(absRoot + "\x00" + session))
		sockPath = filepath.Join(os.TempDir(), "adb-"+hex.EncodeToString(sum[:6])+".sock")
	}

	return Paths{
		ConfigHome: absRoot,
		RunDir:     runDir,
		PluginsDir: pluginsDir,
		DBPath:     filepath.Join(absRoot, "agent-dbctl.db"),
		SocketPath: sockPath,
		DaemonMeta: filepath.Join(runDir, session+".daemon.json"),
		SecretFile: filepath.Join(absRoot, "secrets.json"),
		Session:    session,
	}, nil
}

// EnsurePrivateDir creates a directory at mode 0700 and refuses symlinked directories.
func EnsurePrivateDir(dir string) error {
	info, err := os.Lstat(dir)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlinked config directory: %s", dir)
		}
		if !info.IsDir() {
			return fmt.Errorf("expected directory at %s", dir)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("chmod 0700 %s: %w", dir, err)
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", dir, err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("chmod 0700 %s: %w", dir, err)
	}
	return nil
}

// ValidateRegularFile rejects symlinks and non-regular files.
func ValidateRegularFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlinked file: %s", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("refusing non-regular file: %s", path)
	}
	return nil
}

// ExpandHomePath expands a leading "~" or "~/" to the current user's home directory.
func ExpandHomePath(p string) string {
	trimmed := strings.TrimSpace(p)
	if trimmed == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return home
		}
		return trimmed
	}
	if strings.HasPrefix(trimmed, "~/") || strings.HasPrefix(trimmed, `~\`) {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, trimmed[2:])
		}
	}
	return trimmed
}
