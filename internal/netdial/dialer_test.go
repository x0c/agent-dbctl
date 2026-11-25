package netdial_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/x0c/agent-dbctl/internal/netdial"
	"github.com/x0c/agent-dbctl/internal/secrets"
	"github.com/x0c/agent-dbctl/internal/types"
)

func TestBuildContextTLSModes(t *testing.T) {
	for _, tc := range []struct {
		mode      string
		wantNil   bool
		wantErr   bool
		wantInsec bool
		wantHost  string
	}{
		{mode: "", wantNil: true},
		{mode: "disable", wantNil: true},
		{mode: "prefer", wantNil: true},
		{mode: "require", wantNil: false, wantInsec: true},
		{mode: "verify-ca", wantNil: false, wantInsec: true},
		{mode: "verify-full", wantNil: false, wantInsec: false, wantHost: "db.example.internal"},
		{mode: "invalid-mode", wantErr: true},
	} {
		t.Run("mode_"+tc.mode, func(t *testing.T) {
			res, err := netdial.BuildContext(context.Background(), nil, secrets.ResolvedSecret{}, tc.mode, "db.example.internal")
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for invalid tls_mode %q", tc.mode)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantNil {
				if res.TLSConfig != nil {
					t.Fatalf("expected nil TLSConfig, got %+v", res.TLSConfig)
				}
				return
			}
			if res.TLSConfig == nil {
				t.Fatal("expected non-nil TLSConfig")
			}
			if res.TLSConfig.MinVersion != tls.VersionTLS12 {
				t.Fatalf("expected MinVersion TLS 1.2, got %v", res.TLSConfig.MinVersion)
			}
			if res.TLSConfig.InsecureSkipVerify != tc.wantInsec {
				t.Fatalf("InsecureSkipVerify=%v, want %v", res.TLSConfig.InsecureSkipVerify, tc.wantInsec)
			}
			if tc.mode == "verify-ca" && res.TLSConfig.VerifyConnection == nil {
				t.Fatal("expected custom VerifyConnection for verify-ca")
			}
			if tc.wantHost != "" && res.TLSConfig.ServerName != tc.wantHost {
				t.Fatalf("ServerName=%q, want %q", res.TLSConfig.ServerName, tc.wantHost)
			}
		})
	}
}

func TestBuildContextHTTPProxyConnectAndCancellation(t *testing.T) {
	// Echo backend server.
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = backendLn.Close() }()
	go func() {
		for {
			c, err := backendLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	// Minimal HTTP CONNECT proxy server.
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = proxyLn.Close() }()
	go func() {
		for {
			c, err := proxyLn.Accept()
			if err != nil {
				return
			}
			go func(client net.Conn) {
				br := bufio.NewReader(client)
				req, err := http.ReadRequest(br)
				if err != nil || req.Method != http.MethodConnect {
					_ = client.Close()
					return
				}
				if req.Header.Get("Proxy-Authorization") != "Basic dXNlcjpwYXNz" {
					_, _ = io.WriteString(client, "HTTP/1.1 407 Proxy Auth Required\r\n\r\n")
					_ = client.Close()
					return
				}
				up, err := net.Dial("tcp", req.Host)
				if err != nil {
					_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
					_ = client.Close()
					return
				}
				_, _ = io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
				go func() { _, _ = io.Copy(up, br); _ = up.Close() }()
				_, _ = io.Copy(client, up)
				_ = client.Close()
			}(c)
		}
	}()

	np := &types.NetworkProfile{
		Mode:     types.NetworkHTTPProxy,
		ProxyURL: "http://user:pass@" + proxyLn.Addr().String(),
	}
	dialRes, err := netdial.BuildContext(context.Background(), np, secrets.ResolvedSecret{}, "disable", "127.0.0.1")
	if err != nil {
		t.Fatalf("build http_proxy dialer: %v", err)
	}
	defer func() { _ = dialRes.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := dialRes.DialContext(ctx, "tcp", backendLn.Addr().String())
	if err != nil {
		t.Fatalf("dial via http_proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := io.WriteString(conn, "ping"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("expected ping echo, got %q", string(buf))
	}

	// Verify hanging proxy respects context deadline.
	stallLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stallLn.Close() }()
	go func() {
		for {
			c, err := stallLn.Accept()
			if err != nil {
				return
			}
			// Never reply to CONNECT.
			go func(cn net.Conn) {
				time.Sleep(2 * time.Second)
				_ = cn.Close()
			}(c)
		}
	}()
	stallRes, err := netdial.BuildContext(context.Background(), &types.NetworkProfile{
		Mode:     types.NetworkHTTPProxy,
		ProxyURL: "http://" + stallLn.Addr().String(),
	}, secrets.ResolvedSecret{}, "", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	shortCtx, shortCancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer shortCancel()
	_, err = stallRes.DialContext(shortCtx, "tcp", backendLn.Addr().String())
	if err == nil || (!strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "closed")) {
		t.Fatalf("expected timeout/closed error on stalled CONNECT, got %v", err)
	}
}

type stubNoDeadlineConn struct {
	net.Conn
}

func (stubNoDeadlineConn) SetDeadline(time.Time) error {
	return io.ErrUnexpectedEOF
}

func (stubNoDeadlineConn) SetReadDeadline(time.Time) error {
	return &net.OpError{Op: "set", Err: errDeadlineUnsupported}
}

func (stubNoDeadlineConn) SetWriteDeadline(time.Time) error {
	return &net.OpError{Op: "set", Err: errDeadlineUnsupported}
}

var errDeadlineUnsupported = errString("ssh: tcpChan: deadline not supported")

type errString string

func (e errString) Error() string { return string(e) }

func TestWrapSSHConnIgnoresUnsupportedDeadlines(t *testing.T) {
	wrapped := netdial.WrapSSHConn(stubNoDeadlineConn{})
	if err := wrapped.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("expected deadline-not-supported error to be ignored, got %v", err)
	}
	if err := wrapped.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("expected write deadline-not-supported error to be ignored, got %v", err)
	}
	if err := wrapped.SetDeadline(time.Now()); err == nil {
		t.Fatal("expected unrelated deadline error to be preserved")
	}
}
