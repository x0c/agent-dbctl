package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/x0c/agent-dbctl/internal/config"
	"github.com/x0c/agent-dbctl/internal/types"
)

// EnvelopeRecordStore persists AES-256-GCM wrapped DEK + ciphertext rows (DB-backed in server mode).
type EnvelopeRecordStore interface {
	GetEncryptedSecret(ctx context.Context, key string) (types.EncryptedSecretRecord, error)
	PutEncryptedSecret(ctx context.Context, rec types.EncryptedSecretRecord) error
	DeleteEncryptedSecret(ctx context.Context, key string) error
	HasEncryptedSecret(ctx context.Context, key string) (bool, error)
}

// ParseMasterKey parses a 32-byte key encoded as 64-char hex or base64 (std/raw/url).
func ParseMasterKey(raw string) ([]byte, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("master key is empty")
	}
	if len(trimmed) == 64 {
		if b, err := hex.DecodeString(trimmed); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(trimmed); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	return nil, fmt.Errorf("master key must decode to 32 bytes (64 hex chars or base64)")
}

// EnvelopeCipher encrypts and authenticates secrets using AES-256-GCM with per-record DEKs and bound AAD.
type EnvelopeCipher struct {
	kek        []byte
	keyVersion int
}

// NewEnvelopeCipher builds an AES-256-GCM envelope cipher from a 32-byte KEK.
func NewEnvelopeCipher(kek []byte, keyVersion int) (*EnvelopeCipher, error) {
	if len(kek) != 32 {
		return nil, fmt.Errorf("kek must be 32 bytes, got %d", len(kek))
	}
	if keyVersion <= 0 {
		keyVersion = 1
	}
	cp := make([]byte, 32)
	copy(cp, kek)
	return &EnvelopeCipher{kek: cp, keyVersion: keyVersion}, nil
}

type encryptedEnvelopePayload struct {
	WrappedDEK []byte `json:"wrapped_dek"`
	DEKNonce   []byte `json:"dek_nonce"`
	Data       []byte `json:"data"`
}

func secretAAD(key string, keyVersion int) []byte {
	return []byte(fmt.Sprintf("agent-dbctl:secret:v%d:%s", keyVersion, key))
}

// Encrypt generates a fresh 256-bit DEK, wraps it with KEK, and encrypts plaintext with key-bound AAD.
func (c *EnvelopeCipher) Encrypt(key, plaintext string) (types.EncryptedSecretRecord, error) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return types.EncryptedSecretRecord{}, err
	}
	aad := secretAAD(key, c.keyVersion)

	dataBlock, err := aes.NewCipher(dek)
	if err != nil {
		return types.EncryptedSecretRecord{}, err
	}
	dataGCM, err := cipher.NewGCM(dataBlock)
	if err != nil {
		return types.EncryptedSecretRecord{}, err
	}
	dataNonce := make([]byte, dataGCM.NonceSize())
	if _, err := rand.Read(dataNonce); err != nil {
		return types.EncryptedSecretRecord{}, err
	}
	ciphertext := dataGCM.Seal(nil, dataNonce, []byte(plaintext), aad)

	kekBlock, err := aes.NewCipher(c.kek)
	if err != nil {
		return types.EncryptedSecretRecord{}, err
	}
	kekGCM, err := cipher.NewGCM(kekBlock)
	if err != nil {
		return types.EncryptedSecretRecord{}, err
	}
	dekNonce := make([]byte, kekGCM.NonceSize())
	if _, err := rand.Read(dekNonce); err != nil {
		return types.EncryptedSecretRecord{}, err
	}
	wrappedDEK := kekGCM.Seal(nil, dekNonce, dek, aad)

	payload, err := json.Marshal(encryptedEnvelopePayload{
		WrappedDEK: wrappedDEK,
		DEKNonce:   dekNonce,
		Data:       ciphertext,
	})
	if err != nil {
		return types.EncryptedSecretRecord{}, err
	}
	return types.EncryptedSecretRecord{
		Key:          key,
		KeyVersion:   c.keyVersion,
		Nonce:        dataNonce,
		Ciphertext:   payload,
		UpdatedAtUTC: time.Now().UTC().Format(time.RFC3339Nano),
	}, nil
}

// Decrypt unwraps the DEK and decrypts the secret while validating key-bound AAD.
func (c *EnvelopeCipher) Decrypt(rec types.EncryptedSecretRecord) (string, error) {
	var payload encryptedEnvelopePayload
	if err := json.Unmarshal(rec.Ciphertext, &payload); err != nil {
		return "", fmt.Errorf("decode encrypted secret payload: %w", err)
	}
	aad := secretAAD(rec.Key, rec.KeyVersion)

	kekBlock, err := aes.NewCipher(c.kek)
	if err != nil {
		return "", err
	}
	kekGCM, err := cipher.NewGCM(kekBlock)
	if err != nil {
		return "", err
	}
	dek, err := kekGCM.Open(nil, payload.DEKNonce, payload.WrappedDEK, aad)
	if err != nil {
		return "", fmt.Errorf("unwrap DEK for %q: %w", rec.Key, err)
	}

	dataBlock, err := aes.NewCipher(dek)
	if err != nil {
		return "", err
	}
	dataGCM, err := cipher.NewGCM(dataBlock)
	if err != nil {
		return "", err
	}
	plain, err := dataGCM.Open(nil, rec.Nonce, payload.Data, aad)
	if err != nil {
		return "", fmt.Errorf("decrypt secret for %q: %w", rec.Key, err)
	}
	return string(plain), nil
}

// EncryptedDBStore implements secrets.Store backed by EnvelopeRecordStore.
type EncryptedDBStore struct {
	repo   EnvelopeRecordStore
	cipher *EnvelopeCipher
}

// NewEncryptedDBStore creates a DB-backed envelope-encrypted secret store.
func NewEncryptedDBStore(repo EnvelopeRecordStore, kek []byte) (*EncryptedDBStore, error) {
	c, err := NewEnvelopeCipher(kek, 1)
	if err != nil {
		return nil, err
	}
	return &EncryptedDBStore{repo: repo, cipher: c}, nil
}

func (s *EncryptedDBStore) Name() string { return "encrypted_db" }

func (s *EncryptedDBStore) Get(ctx context.Context, key string) (string, error) {
	rec, err := s.repo.GetEncryptedSecret(ctx, key)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not found") {
			return "", ErrNotFound
		}
		return "", err
	}
	return s.cipher.Decrypt(rec)
}

func (s *EncryptedDBStore) Put(ctx context.Context, key, value string) error {
	rec, err := s.cipher.Encrypt(key, value)
	if err != nil {
		return err
	}
	return s.repo.PutEncryptedSecret(ctx, rec)
}

func (s *EncryptedDBStore) Delete(ctx context.Context, key string) error {
	return s.repo.DeleteEncryptedSecret(ctx, key)
}

func (s *EncryptedDBStore) Has(ctx context.Context, key string) (bool, error) {
	return s.repo.HasEncryptedSecret(ctx, key)
}

// EncryptedFileStore implements secrets.Store using a 0600 envelope-encrypted JSON file.
type EncryptedFileStore struct {
	path   string
	cipher *EnvelopeCipher
	mu     sync.Mutex
}

// NewEncryptedFileStore creates an encrypted local/server file secret store.
func NewEncryptedFileStore(path string, kek []byte) (*EncryptedFileStore, error) {
	c, err := NewEnvelopeCipher(kek, 1)
	if err != nil {
		return nil, err
	}
	return &EncryptedFileStore{path: path, cipher: c}, nil
}

func (f *EncryptedFileStore) Name() string { return "encrypted_file" }

func (f *EncryptedFileStore) loadLocked() (map[string]types.EncryptedSecretRecord, error) {
	if err := config.EnsurePrivateDir(filepath.Dir(f.path)); err != nil {
		return nil, err
	}
	err := config.ValidateRegularFile(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]types.EncryptedSecretRecord{}, nil
	}
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(f.path)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return map[string]types.EncryptedSecretRecord{}, nil
	}
	m := map[string]types.EncryptedSecretRecord{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("parse encrypted secret file: %w", err)
	}
	return m, nil
}

func (f *EncryptedFileStore) saveLocked(m map[string]types.EncryptedSecretRecord) error {
	dir := filepath.Dir(f.path)
	if err := config.EnsurePrivateDir(dir); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".secrets-enc-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(name)
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
	if err := os.Rename(name, f.path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func (f *EncryptedFileStore) Get(_ context.Context, key string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, err := f.loadLocked()
	if err != nil {
		return "", err
	}
	rec, ok := m[key]
	if !ok {
		return "", ErrNotFound
	}
	return f.cipher.Decrypt(rec)
}

func (f *EncryptedFileStore) Put(_ context.Context, key, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, err := f.loadLocked()
	if err != nil {
		return err
	}
	rec, err := f.cipher.Encrypt(key, value)
	if err != nil {
		return err
	}
	m[key] = rec
	return f.saveLocked(m)
}

func (f *EncryptedFileStore) Delete(_ context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, err := f.loadLocked()
	if err != nil {
		return err
	}
	delete(m, key)
	return f.saveLocked(m)
}

func (f *EncryptedFileStore) Has(_ context.Context, key string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, err := f.loadLocked()
	if err != nil {
		return false, err
	}
	_, ok := m[key]
	return ok, nil
}

var blockedServerEnvPrefixes = []string{
	"AGENT_DBCTL_",
	"OIDC_",
	"AWS_",
	"GCP_",
	"AZURE_",
	"KUBERNETES_",
	"TLS_",
	"SSL_",
	"LD_",
	"DYLD_",
	"PATH",
	"HOME",
}

// ServerPolicy enforces server-mode allowlists for env_ref and exec_provider credentials.
type ServerPolicy struct {
	Enabled             bool
	AllowExecForAdmin   bool
	AllowedExecPrefixes []string
	AllowedEnvPrefixes  []string
}

// ValidateServerEnvVar rejects sensitive server environment variable names and enforces prefixes.
func ValidateServerEnvVar(name string, pol ServerPolicy) error {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return fmt.Errorf("env_var_name is required")
	}
	upper := strings.ToUpper(trimmed)
	for _, blocked := range blockedServerEnvPrefixes {
		if upper == blocked || strings.HasPrefix(upper, blocked) {
			return fmt.Errorf("environment variable %q is blocked in server mode", trimmed)
		}
	}
	if len(pol.AllowedEnvPrefixes) == 0 {
		return fmt.Errorf("env_ref credentials are disabled in server mode (no allowed_env_prefixes configured)")
	}
	for _, prefix := range pol.AllowedEnvPrefixes {
		if strings.HasPrefix(trimmed, prefix) {
			return nil
		}
	}
	return fmt.Errorf("environment variable %q does not match server allowed_env_prefixes", trimmed)
}

// ValidateServerExecCommand resolves symlinks and ensures exec_provider binaries match configured allowlists.
func ValidateServerExecCommand(cmdLine string, pol ServerPolicy) error {
	if !pol.AllowExecForAdmin || len(pol.AllowedExecPrefixes) == 0 {
		return fmt.Errorf("exec_provider credentials are disabled in server mode")
	}
	parts, err := SplitExecArgs(cmdLine)
	if err != nil {
		return err
	}
	exe := parts[0]
	resolved, err := exec.LookPath(exe)
	if err != nil {
		return fmt.Errorf("exec_provider executable %q not found: %w", exe, err)
	}
	realPath, err := filepath.EvalSymlinks(resolved)
	if err != nil {
		return fmt.Errorf("resolve exec_provider symlinks: %w", err)
	}
	realPath = filepath.Clean(realPath)
	base := strings.ToLower(filepath.Base(realPath))
	switch base {
	case "sh", "bash", "zsh", "dash", "ksh", "env", "python", "python3", "perl", "ruby", "node", "cmd", "cmd.exe", "powershell", "pwsh":
		return fmt.Errorf("exec_provider executable %q cannot be a shell or generic interpreter in server mode", base)
	}
	for _, rawPrefix := range pol.AllowedExecPrefixes {
		prefix := filepath.Clean(rawPrefix)
		if realPrefix, rErr := filepath.EvalSymlinks(prefix); rErr == nil {
			prefix = filepath.Clean(realPrefix)
		}
		if realPath == prefix || (strings.HasSuffix(rawPrefix, string(os.PathSeparator)) && strings.HasPrefix(realPath, prefix+string(os.PathSeparator))) {
			return nil
		}
	}
	return fmt.Errorf("exec_provider executable %q is not in server allowed_exec_prefixes", realPath)
}

// ResolveCredentialWithOptions resolves credentials while enforcing server-mode env scrubbing and allowlists.
func ResolveCredentialWithOptions(ctx context.Context, store Store, prof *types.CredentialProfile, srvPol ServerPolicy) (ResolvedSecret, error) {
	if prof == nil {
		return ResolvedSecret{}, nil
	}
	if !srvPol.Enabled {
		return ResolveCredential(ctx, store, prof)
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
		if err := ValidateServerEnvVar(prof.EnvVarName, srvPol); err != nil {
			return out, err
		}
		val, ok := os.LookupEnv(prof.EnvVarName)
		if !ok || val == "" {
			return out, fmt.Errorf("credential %q requires environment variable %s: %w", prof.Name, prof.EnvVarName, ErrNotFound)
		}
		out.Secret = val
		return out, nil
	case types.CredExecProvider:
		if err := ValidateServerExecCommand(prof.ExecCommand, srvPol); err != nil {
			return out, err
		}
		parts, err := SplitExecArgs(prof.ExecCommand)
		if err != nil {
			return out, err
		}
		execCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(execCtx, parts[0], parts[1:]...) //nolint:gosec // Validated via ValidateServerExecCommand.
		// Scrub server environment so KEK/OIDC/webhook secrets never pass to child processes.
		cmd.Env = []string{
			"PATH=" + os.Getenv("PATH"),
			"HOME=" + os.Getenv("HOME"),
		}
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
			return out, fmt.Errorf("credential %q exec_provider failed: %w", prof.Name, waitErr)
		}
		out.Secret = strings.TrimRight(string(raw), "\r\n")
		return out, nil
	default:
		return out, fmt.Errorf("unsupported credential kind %q", prof.Kind)
	}
}

// FingerprintKEK returns a non-secret short digest for diagnostics.
func FingerprintKEK(kek []byte) string {
	sum := sha256.Sum256(kek)
	return hex.EncodeToString(sum[:6])
}
