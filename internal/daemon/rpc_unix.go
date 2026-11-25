//go:build !windows

package daemon

import (
	"context"
	"errors"
	"fmt"
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
	return WaitOrTerminatePID(pid, 0, 1500*time.Millisecond)
}

// AcquireFileLock acquires an exclusive advisory lock on path.
func AcquireFileLock(path string, blocking bool) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	how := syscall.LOCK_EX
	if !blocking {
		how |= syscall.LOCK_NB
	}
	for {
		err = syscall.Flock(int(f.Fd()), how)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			_ = f.Close()
			return nil, err
		}
		return f, nil
	}
}

// ReleaseFileLock releases and closes a file lock acquired via AcquireFileLock.
func ReleaseFileLock(f *os.File) {
	if f == nil {
		return
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	_ = f.Close()
}

// IsProcessAlive reports whether pid currently exists on this host.
func IsProcessAlive(pid int) bool {
	if pid <= 1 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// WaitOrTerminatePID waits for pid to exit gracefully, escalating to SIGTERM and SIGKILL if needed.
func WaitOrTerminatePID(pid int, gracefulWait, termWait time.Duration) error {
	if pid <= 1 || !IsProcessAlive(pid) {
		return nil
	}
	if waitForProcessExit(pid, gracefulWait) {
		return nil
	}
	_ = syscall.Kill(pid, syscall.SIGTERM)
	if waitForProcessExit(pid, termWait) {
		return nil
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
	if waitForProcessExit(pid, 500*time.Millisecond) {
		return nil
	}
	return fmt.Errorf("process %d did not exit after SIGKILL", pid)
}

func waitForProcessExit(pid int, timeout time.Duration) bool {
	if timeout <= 0 {
		return !IsProcessAlive(pid)
	}
	deadline := time.Now().Add(timeout)
	for {
		if !IsProcessAlive(pid) {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(25 * time.Millisecond)
	}
}
