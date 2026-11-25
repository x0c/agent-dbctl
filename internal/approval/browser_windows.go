//go:build windows

package approval

import "os/exec"

// OpenBrowser launches the Windows default browser asynchronously for an explicit URL.
func OpenBrowser(url string) error {
	cmd := exec.Command("rundll32", "url.dll,FileProtocolHandler", url) //nolint:gosec // Loopback local Web Console URL constructed by daemon.
	return cmd.Start()
}
