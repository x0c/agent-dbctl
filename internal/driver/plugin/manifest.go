package plugin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/x0c/agent-dbctl/internal/config"
	"github.com/x0c/agent-dbctl/internal/types"
)

const (
	// MinHostAPIVersion is the minimum external plugin host API version supported.
	MinHostAPIVersion = 1
	// MaxHostAPIVersion is the latest external plugin host API version supported.
	MaxHostAPIVersion = 2
	// SupportedHostAPIVersion is the current default plugin host API version.
	SupportedHostAPIVersion = MaxHostAPIVersion
)

// Manifest describes an external Tier-3 driver plugin on disk.
type Manifest struct {
	ID             string             `json:"id"`
	Engine         string             `json:"engine"`
	DisplayName    string             `json:"display_name"`
	Family         types.EngineFamily `json:"family"`
	Version        string             `json:"version"`
	HostAPIVersion int                `json:"host_api_version"`
	Binary         string             `json:"binary"`
	SHA256         string             `json:"sha256"`
	Capabilities   []string           `json:"capabilities"`
}

// DiscoveredPlugin represents a scanned manifest with verification status.
type DiscoveredPlugin struct {
	Manifest        Manifest
	Dir             string
	BinaryPath      string
	ActualSHA256    string
	Verified        bool
	VerificationErr string
}

// ScanPlugins discovers and cryptographically verifies all manifests under pluginsDir.
func ScanPlugins(pluginsDir string) ([]DiscoveredPlugin, error) {
	entries, err := os.ReadDir(pluginsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []DiscoveredPlugin
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(pluginsDir, entry.Name())
		manifestPath := filepath.Join(dir, "manifest.json")
		if _, err := os.Lstat(manifestPath); os.IsNotExist(err) {
			continue
		}
		dp := verifyOnePlugin(dir, manifestPath)
		out = append(out, dp)
	}
	return out, nil
}

func verifyOnePlugin(dir, manifestPath string) DiscoveredPlugin {
	dp := DiscoveredPlugin{Dir: dir}
	if err := config.ValidateRegularFile(manifestPath); err != nil {
		dp.VerificationErr = fmt.Sprintf("invalid manifest file: %v", err)
		return dp
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		dp.VerificationErr = fmt.Sprintf("read manifest: %v", err)
		return dp
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		dp.VerificationErr = fmt.Sprintf("parse manifest.json: %v", err)
		return dp
	}
	dp.Manifest = m

	if strings.TrimSpace(m.ID) == "" || strings.TrimSpace(m.Engine) == "" || strings.TrimSpace(m.Binary) == "" {
		dp.VerificationErr = "manifest missing required id, engine, or binary field"
		return dp
	}
	if m.HostAPIVersion < MinHostAPIVersion || m.HostAPIVersion > MaxHostAPIVersion {
		dp.VerificationErr = fmt.Sprintf("incompatible host_api_version %d (supported: %d..%d)", m.HostAPIVersion, MinHostAPIVersion, MaxHostAPIVersion)
		return dp
	}

	// Prevent path traversal out of plugin directory.
	cleanBin := filepath.Clean(m.Binary)
	if filepath.IsAbs(cleanBin) || strings.HasPrefix(cleanBin, "..") || strings.Contains(cleanBin, string(filepath.Separator)+"..") {
		dp.VerificationErr = fmt.Sprintf("binary path %q escapes plugin directory", m.Binary)
		return dp
	}
	binPath := filepath.Join(dir, cleanBin)
	absDir, _ := filepath.Abs(dir)
	absBin, _ := filepath.Abs(binPath)
	if !strings.HasPrefix(absBin, absDir+string(filepath.Separator)) {
		dp.VerificationErr = fmt.Sprintf("binary path %q outside plugin directory", m.Binary)
		return dp
	}
	dp.BinaryPath = absBin

	if err := config.ValidateRegularFile(absBin); err != nil {
		dp.VerificationErr = fmt.Sprintf("invalid plugin binary: %v", err)
		return dp
	}
	sum, err := fileSHA256(absBin)
	if err != nil {
		dp.VerificationErr = fmt.Sprintf("hash plugin binary: %v", err)
		return dp
	}
	dp.ActualSHA256 = sum
	expected := strings.ToLower(strings.TrimSpace(m.SHA256))
	if expected == "" || sum != expected {
		dp.VerificationErr = fmt.Sprintf("sha256 mismatch: expected %q, got %q", expected, sum)
		return dp
	}
	dp.Verified = true
	return dp
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
