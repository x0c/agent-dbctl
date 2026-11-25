package netdial

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/net/proxy"

	"github.com/x0c/agent-dbctl/internal/secrets"
	"github.com/x0c/agent-dbctl/internal/types"
)

// DialResult wraps a DialFunc, optional TLS config, and cleanup hook for tunnel resources.
type DialResult struct {
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	TLSConfig   *tls.Config
	Close       func() error
}

// Build constructs a DialFunc and TLSConfig from a NetworkProfile and optional bastion credential.
func Build(np *types.NetworkProfile, bastionCred secrets.ResolvedSecret, instanceTLSMode, targetHost string) (DialResult, error) {
	tlsMode := instanceTLSMode
	if np != nil && np.TLSMode != "" && tlsMode == "" {
		tlsMode = np.TLSMode
	}
	tlsCfg := buildTLSConfig(tlsMode, targetHost)

	if np == nil || np.Mode == "" || np.Mode == types.NetworkDirect {
		d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
		return DialResult{
			DialContext: d.DialContext,
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
		d, err := proxy.SOCKS5("tcp", u.Host, auth, &net.Dialer{Timeout: 10 * time.Second})
		if err != nil {
			return DialResult{}, fmt.Errorf("create socks5 dialer: %w", err)
		}
		return DialResult{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if cd, ok := d.(proxy.ContextDialer); ok {
					return cd.DialContext(ctx, network, addr)
				}
				return d.Dial(network, addr)
			},
			TLSConfig: tlsCfg,
			Close:     func() error { return nil },
		}, nil

	case types.NetworkHTTPProxy:
		u, err := url.Parse(np.ProxyURL)
		if err != nil || u.Host == "" {
			return DialResult{}, fmt.Errorf("invalid http_proxy url %q", np.ProxyURL)
		}
		return DialResult{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialHTTPConnect(ctx, u, addr)
			},
			TLSConfig: tlsCfg,
			Close:     func() error { return nil },
		}, nil

	case types.NetworkSSHTunnel:
		return buildSSHTunnel(np, bastionCred, tlsCfg)

	default:
		return DialResult{}, fmt.Errorf("unsupported network mode %q", np.Mode)
	}
}

func buildTLSConfig(mode, host string) *tls.Config {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "disable", "prefer":
		return nil
	case "require":
		return &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // Explicit user-selected TLS "require" without CA verification.
			MinVersion:         tls.VersionTLS12,
		}
	case "verify-ca", "verify-full":
		return &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS12,
		}
	default:
		return nil
	}
}

func dialHTTPConnect(ctx context.Context, proxyURL *url.URL, targetAddr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", proxyURL.Host)
	if err != nil {
		return nil, err
	}
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

func buildSSHTunnel(np *types.NetworkProfile, cred secrets.ResolvedSecret, tlsCfg *tls.Config) (DialResult, error) {
	if np.BastionHost == "" {
		return DialResult{}, fmt.Errorf("ssh_tunnel requires bastion_host")
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
		return DialResult{}, fmt.Errorf("ssh_tunnel requires bastion_user")
	}

	var authMethods []ssh.AuthMethod
	if cred.Secret != "" {
		if strings.Contains(cred.Secret, "PRIVATE KEY") {
			signer, err := ssh.ParsePrivateKey([]byte(cred.Secret))
			if err != nil {
				return DialResult{}, fmt.Errorf("parse bastion private key: %w", err)
			}
			authMethods = append(authMethods, ssh.PublicKeys(signer))
		} else {
			authMethods = append(authMethods, ssh.Password(cred.Secret))
		}
	}
	if len(authMethods) == 0 {
		return DialResult{}, fmt.Errorf("ssh_tunnel requires bastion credential secret (password or private key)")
	}

	var hostKeyCallback ssh.HostKeyCallback
	if np.SSHStrictHostKey {
		home, err := os.UserHomeDir()
		if err != nil {
			return DialResult{}, err
		}
		khPath := filepath.Join(home, ".ssh", "known_hosts")
		cb, err := knownhosts.New(khPath)
		if err != nil {
			return DialResult{}, fmt.Errorf("load known_hosts %s: %w", khPath, err)
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
	client, err := ssh.Dial("tcp", bastionAddr, cfg)
	if err != nil {
		return DialResult{}, fmt.Errorf("dial ssh bastion %s: %w", bastionAddr, err)
	}
	return DialResult{
		DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
			return client.Dial(network, addr)
		},
		TLSConfig: tlsCfg,
		Close:     client.Close,
	}, nil
}
