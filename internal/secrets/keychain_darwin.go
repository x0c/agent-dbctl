//go:build darwin

package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/x0c/agent-dbctl/internal/config"
)

const keychainService = "io.github.x0c.agent-dbctl"

// KeychainStore accesses macOS Keychain via `security -i` reading commands over stdin
// so secrets never appear in process arguments.
type KeychainStore struct {
	session string
}

func newPlatformStore(paths config.Paths) Store {
	return &KeychainStore{session: paths.Session}
}

func (k *KeychainStore) Name() string {
	return "keychain"
}

func (k *KeychainStore) accountName(key string) string {
	return k.session + ":" + key
}

func (k *KeychainStore) Get(ctx context.Context, key string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "security", "-i")
	// Account/service are non-secret identifiers; password is read from stdout.
	line := fmt.Sprintf("find-generic-password -s %s -a %s -w\n", keychainService, k.accountName(key))
	cmd.Stdin = strings.NewReader(line)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := stderr.String()
		if strings.Contains(msg, "could not be found") || strings.Contains(msg, "SecKeychainSearchCopyNext") {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("keychain lookup failed: %w (%s)", err, strings.TrimSpace(msg))
	}
	val := strings.TrimRight(stdout.String(), "\r\n")
	if strings.HasPrefix(val, "b64:") {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(val, "b64:"))
		if err != nil {
			return "", fmt.Errorf("decode keychain payload: %w", err)
		}
		return string(decoded), nil
	}
	return val, nil
}

func (k *KeychainStore) Put(ctx context.Context, key, value string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// Encode as base64 so multiline keys or quotes never break `security -i` line parsing or touch argv.
	encoded := "b64:" + base64.StdEncoding.EncodeToString([]byte(value))
	cmd := exec.CommandContext(ctx, "security", "-i")
	line := fmt.Sprintf("add-generic-password -U -s %s -a %s -w %s\n", keychainService, k.accountName(key), encoded)
	cmd.Stdin = strings.NewReader(line)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("keychain store failed: %w (%s)", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func (k *KeychainStore) Delete(ctx context.Context, key string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "security", "-i")
	line := fmt.Sprintf("delete-generic-password -s %s -a %s\n", keychainService, k.accountName(key))
	cmd.Stdin = strings.NewReader(line)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := stderr.String()
		if strings.Contains(msg, "could not be found") {
			return nil
		}
		return fmt.Errorf("keychain delete failed: %w (%s)", err, strings.TrimSpace(msg))
	}
	return nil
}

func (k *KeychainStore) Has(ctx context.Context, key string) (bool, error) {
	_, err := k.Get(ctx, key)
	if err == nil {
		return true, nil
	}
	if err == ErrNotFound {
		return false, nil
	}
	return false, err
}
