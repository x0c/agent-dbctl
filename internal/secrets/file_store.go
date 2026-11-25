package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/x0c/agent-dbctl/internal/config"
)

// FileStore stores secrets in a 0600 JSON file inside a 0700 directory using atomic renames.
type FileStore struct {
	path string
	mu   sync.Mutex
}

// NewFileStore creates an isolated 0600 file-backed secret store.
func NewFileStore(path string) *FileStore {
	return &FileStore{path: path}
}

func (f *FileStore) Name() string {
	return "file"
}

func (f *FileStore) loadLocked() (map[string]string, error) {
	if err := config.EnsurePrivateDir(filepath.Dir(f.path)); err != nil {
		return nil, err
	}
	err := config.ValidateRegularFile(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(f.path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(f.path, 0o600); err != nil {
			return nil, fmt.Errorf("tighten secret file permissions: %w", err)
		}
	}
	raw, err := os.ReadFile(f.path)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return map[string]string{}, nil
	}
	m := map[string]string{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("parse secret file: %w", err)
	}
	return m, nil
}

func (f *FileStore) saveLocked(m map[string]string) error {
	dir := filepath.Dir(f.path)
	if err := config.EnsurePrivateDir(dir); err != nil {
		return err
	}
	if err := config.ValidateRegularFile(f.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".secrets-*.tmp")
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
	if err := os.Rename(tmpName, f.path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func (f *FileStore) Get(_ context.Context, key string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, err := f.loadLocked()
	if err != nil {
		return "", err
	}
	v, ok := m[key]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}

func (f *FileStore) Put(_ context.Context, key, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, err := f.loadLocked()
	if err != nil {
		return err
	}
	m[key] = value
	return f.saveLocked(m)
}

func (f *FileStore) Delete(_ context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, err := f.loadLocked()
	if err != nil {
		return err
	}
	delete(m, key)
	return f.saveLocked(m)
}

func (f *FileStore) Has(_ context.Context, key string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, err := f.loadLocked()
	if err != nil {
		return false, err
	}
	_, ok := m[key]
	return ok, nil
}
