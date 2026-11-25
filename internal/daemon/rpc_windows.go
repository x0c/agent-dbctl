//go:build windows

package daemon

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"syscall"
	"time"
	"unsafe"

	"github.com/x0c/agent-dbctl/internal/config"
)

var (
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx         = kernel32.NewProc("LockFileEx")
	procUnlockFileEx       = kernel32.NewProc("UnlockFileEx")
	procGetExitCodeProcess = kernel32.NewProc("GetExitCodeProcess")
)

const (
	winLockfileExclusiveLock   = 0x00000002
	winLockfileFailImmediately = 0x00000001
	winProcessQueryLimitedInfo = 0x1000
	winStillActive             = 259
)

// ListenRPC creates a loopback TCP listener guarded by an ephemeral 0600 token on Windows.
func ListenRPC(_ config.Paths) (net.Listener, string, string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", "", err
	}
	var b [24]byte
	_, _ = rand.Read(b[:])
	tok := hex.EncodeToString(b[:])
	return ln, ln.Addr().String(), tok, nil
}

// WrapRPCTokenMiddleware enforces the Windows loopback RPC token.
func WrapRPCTokenMiddleware(token string, next http.Handler) http.Handler {
	if token == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("X-Agent-DBCTL-Token")
		if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// NewClient connects to the Windows daemon loopback address using the stored token.
func NewClient(paths config.Paths) (*Client, error) {
	meta, err := ReadDaemonMeta(paths)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{Proxy: nil}
	return &Client{
		httpClient: &http.Client{Transport: tr, Timeout: 0},
		baseURL:    "http://" + meta.RPCAddr,
		token:      meta.RPCToken,
	}, nil
}

// SpawnDetached starts the daemon subprocess detached on Windows.
func SpawnDetached(binPath string, args []string) error {
	cmd := exec.Command(binPath, args...) //nolint:gosec // Verified executable path.
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err == nil {
		cmd.Stdin = devNull
		cmd.Stdout = devNull
		cmd.Stderr = devNull
		defer func() { _ = devNull.Close() }()
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x00000008 | 0x00000200} // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
	return cmd.Start()
}

// KillPID terminates an orphaned or mismatched daemon PID on Windows.
func KillPID(pid int) error {
	return WaitOrTerminatePID(pid, 0, 1500*time.Millisecond)
}

// AcquireFileLock acquires an exclusive advisory lock on path.
func AcquireFileLock(path string, blocking bool) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	flags := uint32(winLockfileExclusiveLock)
	if !blocking {
		flags |= winLockfileFailImmediately
	}
	var ol syscall.Overlapped
	r1, _, callErr := procLockFileEx.Call(f.Fd(), uintptr(flags), 0, 1, 0, uintptr(unsafe.Pointer(&ol)))
	if r1 == 0 {
		_ = f.Close()
		return nil, callErr
	}
	return f, nil
}

// ReleaseFileLock releases and closes a file lock acquired via AcquireFileLock.
func ReleaseFileLock(f *os.File) {
	if f == nil {
		return
	}
	var ol syscall.Overlapped
	_, _, _ = procUnlockFileEx.Call(f.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&ol)))
	_ = f.Close()
}

// IsProcessAlive reports whether pid currently exists on Windows.
func IsProcessAlive(pid int) bool {
	if pid <= 1 {
		return false
	}
	h, err := syscall.OpenProcess(winProcessQueryLimitedInfo, false, uint32(pid))
	if err != nil {
		return false
	}
	defer func() { _ = syscall.CloseHandle(h) }()
	var code uint32
	r1, _, _ := procGetExitCodeProcess.Call(uintptr(h), uintptr(unsafe.Pointer(&code)))
	return r1 != 0 && code == winStillActive
}

// WaitOrTerminatePID waits for pid to exit gracefully, killing it if still alive.
func WaitOrTerminatePID(pid int, gracefulWait, termWait time.Duration) error {
	if pid <= 1 || !IsProcessAlive(pid) {
		return nil
	}
	if waitForProcessExit(pid, gracefulWait) {
		return nil
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	_ = p.Kill()
	if waitForProcessExit(pid, termWait) {
		return nil
	}
	return fmt.Errorf("process %d did not exit after Kill", pid)
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
