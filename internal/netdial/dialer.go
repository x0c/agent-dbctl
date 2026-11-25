package netdial

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/net/proxy"

	"github.com/x0c/agent-dbctl/internal/secrets"
	"github.com/x0c/agent-dbctl/internal/types"
)

// DialResult wraps a DialFunc, optional TLS config, and cleanup hook for tunnel resources.
type DialResult struct {
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	TLSMode     string
	TLSConfig   *tls.Config
	Close       func() error
}

// Build constructs a DialFunc and TLSConfig from a NetworkProfile and optional bastion credential.
func Build(np *types.NetworkProfile, bastionCred secrets.ResolvedSecret, instanceTLSMode, targetHost string) (DialResult, error) {
	return BuildContext(context.Background(), np, bastionCred, instanceTLSMode, targetHost)
}

// BuildContext constructs a context-aware DialFunc and TLSConfig from a NetworkProfile.
func BuildContext(ctx context.Context, np *types.NetworkProfile, bastionCred secrets.ResolvedSecret, instanceTLSMode, targetHost string) (DialResult, error) {
	tlsMode := strings.ToLower(strings.TrimSpace(instanceTLSMode))
	if np != nil && strings.TrimSpace(np.TLSMode) != "" && tlsMode == "" {
		tlsMode = strings.ToLower(strings.TrimSpace(np.TLSMode))
	}
	tlsCfg, err := buildTLSConfig(tlsMode, targetHost)
	if err != nil {
		return DialResult{}, err
	}

	if np == nil || np.Mode == "" || np.Mode == types.NetworkDirect {
		d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
		return DialResult{
			DialContext: d.DialContext,
			TLSMode:     tlsMode,
			TLSConfig:   tlsCfg,
			Close:       func() error { return nil },
		}, nil
	}

	switch np.Mode {
	case types.NetworkSOCKS5:
		u, err := url.Parse(np.ProxyURL)
		if err != nil || u.Host == "" {
			return DialResult{}, fmt.Errorf("invalid socks5 proxy_url %q", np.ProxyURL)
		}
		var auth *proxy.Auth
		if u.User != nil {
			pw, _ := u.User.Password()
			auth = &proxy.Auth{User: u.User.Username(), Password: pw}
		}
		d, err := proxy.SOCKS5("tcp", u.Host, auth, &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second})
		if err != nil {
			return DialResult{}, fmt.Errorf("create socks5 dialer: %w", err)
		}
		return DialResult{
			DialContext: func(dctx context.Context, network, addr string) (net.Conn, error) {
				if cd, ok := d.(proxy.ContextDialer); ok {
					return cd.DialContext(dctx, network, addr)
				}
				return d.Dial(network, addr)
			},
			TLSMode:   tlsMode,
			TLSConfig: tlsCfg,
			Close:     func() error { return nil },
		}, nil

	case types.NetworkHTTPProxy:
		u, err := url.Parse(np.ProxyURL)
		if err != nil || u.Host == "" {
			return DialResult{}, fmt.Errorf("invalid http_proxy url %q", np.ProxyURL)
		}
		return DialResult{
			DialContext: func(dctx context.Context, network, addr string) (net.Conn, error) {
				return dialHTTPConnect(dctx, u, addr)
			},
			TLSMode:   tlsMode,
			TLSConfig: tlsCfg,
			Close:     func() error { return nil },
		}, nil

	case types.NetworkSSHTunnel:
		return buildSSHTunnel(ctx, np, bastionCred, tlsMode, tlsCfg)

	default:
		return DialResult{}, fmt.Errorf("unsupported network mode %q", np.Mode)
	}
}

func buildTLSConfig(mode, host string) (*tls.Config, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "disable", "prefer":
		return nil, nil
	case "require":
		return &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // Explicit user-selected TLS "require" without CA verification.
			MinVersion:         tls.VersionTLS12,
		}, nil
	case "verify-ca":
		return &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // Custom VerifyConnection validates CA chain without hostname check.
			MinVersion:         tls.VersionTLS12,
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return fmt.Errorf("tls verify-ca: server presented no certificates")
				}
				opts := x509.VerifyOptions{
					Intermediates: x509.NewCertPool(),
				}
				for _, cert := range cs.PeerCertificates[1:] {
					opts.Intermediates.AddCert(cert)
				}
				_, err := cs.PeerCertificates[0].Verify(opts)
				return err
			},
		}, nil
	case "verify-full":
		return &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS12,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported tls_mode %q (expected disable, prefer, require, verify-ca, or verify-full)", mode)
	}
}

func defaultDialer() *net.Dialer {
	return &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
}

func dialHTTPConnect(ctx context.Context, proxyURL *url.URL, targetAddr string) (net.Conn, error) {
	return dialHTTPConnectWithDialer(ctx, proxyURL, targetAddr, defaultDialer())
}

func dialHTTPConnectWithDialer(ctx context.Context, proxyURL *url.URL, targetAddr string, d *net.Dialer) (net.Conn, error) {
	if d == nil {
		d = defaultDialer()
	}
	conn, err := d.DialContext(ctx, "tcp", proxyURL.Host)
	if err != nil {
		return nil, err
	}

	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	}

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()

	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: targetAddr},
		Host:   targetAddr,
		Header: make(http.Header),
	}
	if proxyURL.User != nil {
		pw, _ := proxyURL.User.Password()
		cred := base64.StdEncoding.EncodeToString([]byte(proxyURL.User.Username() + ":" + pw))
		req.Header.Set("Proxy-Authorization", "Basic "+cred)
	}
	if err := req.Write(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, fmt.Errorf("http proxy CONNECT failed: %s", resp.Status)
	}
	_ = conn.SetDeadline(time.Time{})
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: io.MultiReader(br, conn)}, nil
	}
	return conn, nil
}

type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

func dialSSHClientWithDialer(ctx context.Context, np *types.NetworkProfile, cred secrets.ResolvedSecret, dialer *net.Dialer) (*ssh.Client, error) {
	if dialer == nil {
		dialer = defaultDialer()
	}
	if np == nil {
		return nil, fmt.Errorf("ssh_tunnel requires network profile")
	}
	if np.BastionHost == "" {
		return nil, fmt.Errorf("ssh_tunnel requires bastion_host")
	}
	port := np.BastionPort
	if port <= 0 {
		port = 22
	}
	user := np.BastionUser
	if user == "" {
		user = cred.Username
	}
	if user == "" {
		return nil, fmt.Errorf("ssh_tunnel requires bastion_user")
	}

	var authMethods []ssh.AuthMethod
	var agentConn net.Conn
	if cred.Secret != "" {
		if strings.Contains(cred.Secret, "PRIVATE KEY") {
			signer, err := ssh.ParsePrivateKey([]byte(cred.Secret))
			if err != nil {
				return nil, fmt.Errorf("parse bastion private key: %w", err)
			}
			authMethods = append(authMethods, ssh.PublicKeys(signer))
		} else {
			authMethods = append(authMethods, ssh.Password(cred.Secret))
		}
	} else if sock := strings.TrimSpace(os.Getenv("SSH_AUTH_SOCK")); sock != "" {
		if conn, err := net.DialTimeout("unix", sock, 2*time.Second); err == nil {
			agentConn = conn
			authMethods = append(authMethods, ssh.PublicKeysCallback(agent.NewClient(conn).Signers))
		}
	}
	if len(authMethods) == 0 {
		return nil, fmt.Errorf("ssh_tunnel requires bastion credential secret (password, private key, or SSH_AUTH_SOCK)")
	}

	var hostKeyCallback ssh.HostKeyCallback
	if np.SSHStrictHostKey {
		home, err := os.UserHomeDir()
		if err != nil {
			if agentConn != nil {
				_ = agentConn.Close()
			}
			return nil, err
		}
		khPath := filepath.Join(home, ".ssh", "known_hosts")
		cb, err := knownhosts.New(khPath)
		if err != nil {
			if agentConn != nil {
				_ = agentConn.Close()
			}
			return nil, fmt.Errorf("load known_hosts %s: %w", khPath, err)
		}
		hostKeyCallback = cb
	} else {
		hostKeyCallback = ssh.InsecureIgnoreHostKey() //nolint:gosec // Explicit user opt-out in NetworkProfile.
	}

	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         10 * time.Second,
	}
	bastionAddr := net.JoinHostPort(np.BastionHost, fmt.Sprintf("%d", port))
	rawConn, err := dialer.DialContext(ctx, "tcp", bastionAddr)
	if err != nil {
		if agentConn != nil {
			_ = agentConn.Close()
		}
		return nil, fmt.Errorf("dial ssh bastion %s: %w", bastionAddr, err)
	}
	c, chans, reqs, err := ssh.NewClientConn(rawConn, bastionAddr, cfg)
	if err != nil {
		_ = rawConn.Close()
		if agentConn != nil {
			_ = agentConn.Close()
		}
		return nil, fmt.Errorf("ssh handshake %s: %w", bastionAddr, err)
	}
	if agentConn != nil {
		_ = agentConn.Close()
	}
	return ssh.NewClient(c, chans, reqs), nil
}

func buildSSHTunnel(ctx context.Context, np *types.NetworkProfile, cred secrets.ResolvedSecret, tlsMode string, tlsCfg *tls.Config) (DialResult, error) {
	return buildSSHTunnelWithDialer(ctx, np, cred, tlsMode, tlsCfg, defaultDialer())
}

func buildSSHTunnelWithDialer(ctx context.Context, np *types.NetworkProfile, cred secrets.ResolvedSecret, tlsMode string, tlsCfg *tls.Config, dialer *net.Dialer) (DialResult, error) {
	client, err := dialSSHClientWithDialer(ctx, np, cred, dialer)
	if err != nil {
		return DialResult{}, err
	}

	var closeOnce sync.Once
	var closeErr error
	closeFn := func() error {
		closeOnce.Do(func() {
			closeErr = client.Close()
		})
		return closeErr
	}

	return DialResult{
		DialContext: func(dctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := client.DialContext(dctx, network, addr)
			if err != nil {
				return nil, err
			}
			return WrapSSHConn(conn), nil
		},
		TLSMode:   tlsMode,
		TLSConfig: tlsCfg,
		Close:     closeFn,
	}, nil
}

// WrapSSHConn adapts ssh.tcpChan (whose Set*Deadline methods return "deadline not supported")
// so drivers like go-redis/v9 can operate over SSH tunnels without failing on socket deadlines.
func WrapSSHConn(c net.Conn) net.Conn {
	return &sshDeadlineCompatConn{Conn: c}
}

type sshDeadlineCompatConn struct {
	net.Conn
}

func (s *sshDeadlineCompatConn) SetDeadline(t time.Time) error {
	err := s.Conn.SetDeadline(t)
	if isDeadlineUnsupported(err) {
		return nil
	}
	return err
}

func (s *sshDeadlineCompatConn) SetReadDeadline(t time.Time) error {
	err := s.Conn.SetReadDeadline(t)
	if isDeadlineUnsupported(err) {
		return nil
	}
	return err
}

func (s *sshDeadlineCompatConn) SetWriteDeadline(t time.Time) error {
	err := s.Conn.SetWriteDeadline(t)
	if isDeadlineUnsupported(err) {
		return nil
	}
	return err
}

func isDeadlineUnsupported(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "deadline not supported")
}
