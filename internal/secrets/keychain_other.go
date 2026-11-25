//go:build !darwin

package secrets

import "github.com/x0c/agent-dbctl/internal/config"

func newPlatformStore(paths config.Paths) Store {
	return NewFileStore(paths.SecretFile)
}
