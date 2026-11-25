//go:build !windows

package daemon

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/x0c/agent-dbctl/internal/config"
)

// ListenRPC creates the 0600 Unix domain socket listener for CLI -> Daemon RPC.
func ListenRPC(paths config.Paths) (net.Listener, string, string, error) {
	_ = os.Remove(paths.SocketPath)
	ln, err := net.Listen("unix", paths.SocketPath)
	if err != nil {
		return nil, "", "", err
	}
	if err := os.Chmod(paths.SocketPath, 0o600); err != nil {
		_ = ln.Close()
		return nil, "", "", err
	}
	return ln, paths.SocketPath, "", nil
}

// NewClient dials the session's Unix domain socket.
func NewClient(paths config.Paths) (*Client, error) {
	if _, err := os.Stat(paths.SocketPath); err != nil {
		return nil, err
	}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", paths.SocketPath)
		},
	}
	return &Client{
		httpClient: &http.Client{Transport: tr, Timeout: 0},
		baseURL:    "http://unix",
	}, nil
}

// SpawnDetached starts the daemon subprocess in its own session on Unix.
func SpawnDetached(binPath string, args []string) error {
	cmd := exec.Command(binPath, args...) //nolint:gosec // Verified executable path.
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err == nil {
		cmd.Stdin = devNull
		cmd.Stdout = devNull
		cmd.Stderr = devNull
		defer func() { _ = devNull.Close() }()
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd.Start()
}

// KillPID terminates an orphaned or mismatched daemon PID safely.
func KillPID(pid int) error {
	if pid <= 1 {
		return nil
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	_ = p.Signal(syscall.SIGTERM)
	time.Sleep(200 * time.Millisecond)
	return nil
}
