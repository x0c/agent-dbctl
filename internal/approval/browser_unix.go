//go:build !windows

package approval

import (
	"os/exec"
	"runtime"
)

// OpenBrowser launches the OS default browser asynchronously for an explicit URL.
func OpenBrowser(url string) error {
	bin := "xdg-open"
	if runtime.GOOS == "darwin" {
		bin = "open"
	}
	cmd := exec.Command(bin, url) //nolint:gosec // Loopback local Web Console URL constructed by daemon.
	return cmd.Start()
}
