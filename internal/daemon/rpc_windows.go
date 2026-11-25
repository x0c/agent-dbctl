//go:build windows

package daemon

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"net/http"
	"os"
	"os/exec"
	"syscall"

	"github.com/x0c/agent-dbctl/internal/config"
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
	if pid <= 1 {
		return nil
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Kill()
}
