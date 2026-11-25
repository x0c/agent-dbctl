package netdial

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/proxy"

	"github.com/x0c/agent-dbctl/internal/secrets"
	"github.com/x0c/agent-dbctl/internal/types"
)

// DialPolicy restricts outbound network dials in multi-tenant server mode.
type DialPolicy struct {
	EnforceEgressGuard bool
	DisableSSHAuthSock bool
	RejectProxyAuth    bool
	BlockedCIDRs       []*net.IPNet
	AllowedCIDRs       []*net.IPNet
}

var defaultBlockedNets = mustParseCIDRs([]string{
	"127.0.0.0/8",
	"::1/128",
	"169.254.0.0/16",
	"fe80::/10",
	"0.0.0.0/8",
	"224.0.0.0/4",
	"ff00::/8",
})

func mustParseCIDRs(cidrs []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err == nil {
			out = append(out, n)
		}
	}
	return out
}

// ParseDialPolicy compiles string CIDRs into a DialPolicy.
func ParseDialPolicy(enforceEgress, disableSSHAgent, rejectProxyAuth bool, blocked, allowed []string) (DialPolicy, error) {
	pol := DialPolicy{
		EnforceEgressGuard: enforceEgress,
		DisableSSHAuthSock: disableSSHAgent,
		RejectProxyAuth:    rejectProxyAuth,
	}
	for _, raw := range blocked {
		_, n, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err != nil {
			return DialPolicy{}, fmt.Errorf("invalid blocked_egress_cidr %q: %w", raw, err)
		}
		pol.BlockedCIDRs = append(pol.BlockedCIDRs, n)
	}
	for _, raw := range allowed {
		_, n, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err != nil {
			return DialPolicy{}, fmt.Errorf("invalid allowed_egress_cidr %q: %w", raw, err)
		}
		pol.AllowedCIDRs = append(pol.AllowedCIDRs, n)
	}
	return pol, nil
}

// CheckIP validates a resolved target IP against AllowedCIDRs / BlockedCIDRs.
func (p DialPolicy) CheckIP(ip net.IP) error {
	if !p.EnforceEgressGuard || ip == nil {
		return nil
	}
	if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() {
		if !ipInAny(ip, p.AllowedCIDRs) {
			return fmt.Errorf("egress blocked to special/link-local address %s", ip.String())
		}
	}
	if ip.IsLoopback() && !ipInAny(ip, p.AllowedCIDRs) {
		return fmt.Errorf("egress blocked to loopback address %s", ip.String())
	}
	if ipInAny(ip, p.BlockedCIDRs) && !ipInAny(ip, p.AllowedCIDRs) {
		return fmt.Errorf("egress blocked by CIDR policy for %s", ip.String())
	}
	if len(p.AllowedCIDRs) > 0 && !ipInAny(ip, p.AllowedCIDRs) {
		return fmt.Errorf("egress address %s is outside allowed_egress_cidrs", ip.String())
	}
	if ipInAny(ip, defaultBlockedNets) && !ipInAny(ip, p.AllowedCIDRs) {
		return fmt.Errorf("egress blocked to restricted address %s", ip.String())
	}
	return nil
}

func ipInAny(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n != nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

// NewDialer constructs a net.Dialer enforcing post-DNS IP checks before TCP connect.
func (p DialPolicy) NewDialer() *net.Dialer {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	if !p.EnforceEgressGuard {
		return d
	}
	d.Control = func(network, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			host = address
		}
		ip := net.ParseIP(strings.Trim(host, "[]"))
		if ip == nil {
			return nil
		}
		return p.CheckIP(ip)
	}
	return d
}

// BuildContextWithPolicy constructs a DialResult enforcing DialPolicy for server deployments.
func BuildContextWithPolicy(ctx context.Context, np *types.NetworkProfile, bastionCred secrets.ResolvedSecret, instanceTLSMode, targetHost string, pol DialPolicy) (DialResult, error) {
	if !pol.EnforceEgressGuard && !pol.DisableSSHAuthSock && !pol.RejectProxyAuth {
		return BuildContext(ctx, np, bastionCred, instanceTLSMode, targetHost)
	}

	tlsMode := strings.ToLower(strings.TrimSpace(instanceTLSMode))
	if np != nil && strings.TrimSpace(np.TLSMode) != "" && tlsMode == "" {
		tlsMode = strings.ToLower(strings.TrimSpace(np.TLSMode))
	}
	tlsCfg, err := buildTLSConfig(tlsMode, targetHost)
	if err != nil {
		return DialResult{}, err
	}

	d := pol.NewDialer()
	if np == nil || np.Mode == "" || np.Mode == types.NetworkDirect {
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
		if pol.RejectProxyAuth && u.User != nil {
			return DialResult{}, fmt.Errorf("proxy_url must not embed credentials in server mode")
		}
		var auth *proxy.Auth
		if u.User != nil {
			pw, _ := u.User.Password()
			auth = &proxy.Auth{User: u.User.Username(), Password: pw}
		}
		pd, err := proxy.SOCKS5("tcp", u.Host, auth, d)
		if err != nil {
			return DialResult{}, fmt.Errorf("create socks5 dialer: %w", err)
		}
		return DialResult{
			DialContext: func(dctx context.Context, network, addr string) (net.Conn, error) {
				if cd, ok := pd.(proxy.ContextDialer); ok {
					return cd.DialContext(dctx, network, addr)
				}
				return pd.Dial(network, addr)
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
		if pol.RejectProxyAuth && u.User != nil {
			return DialResult{}, fmt.Errorf("proxy_url must not embed credentials in server mode")
		}
		if err := checkDialHostPolicy(ctx, u.Hostname(), pol); err != nil {
			return DialResult{}, err
		}
		return DialResult{
			DialContext: func(dctx context.Context, network, addr string) (net.Conn, error) {
				return dialHTTPConnectWithDialer(dctx, u, addr, d)
			},
			TLSMode:   tlsMode,
			TLSConfig: tlsCfg,
			Close:     func() error { return nil },
		}, nil

	case types.NetworkSSHTunnel:
		if pol.DisableSSHAuthSock && bastionCred.Secret == "" {
			return DialResult{}, fmt.Errorf("ssh_tunnel requires explicit bastion credential secret in server mode")
		}
		if err := checkDialHostPolicy(ctx, np.BastionHost, pol); err != nil {
			return DialResult{}, err
		}
		return buildSSHTunnelWithDialer(ctx, np, bastionCred, tlsMode, tlsCfg, d)

	default:
		return DialResult{}, fmt.Errorf("unsupported network mode %q", np.Mode)
	}
}

func checkDialHostPolicy(ctx context.Context, host string, pol DialPolicy) error {
	if !pol.EnforceEgressGuard || strings.TrimSpace(host) == "" {
		return nil
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return pol.CheckIP(ip)
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("resolve egress host %q: %w", host, err)
	}
	for _, ip := range ips {
		if err := pol.CheckIP(ip.IP); err != nil {
			return err
		}
	}
	return nil
}

// BuildContextWithPolicy forwards to TunnelPool when mode is ssh_tunnel after enforcing DialPolicy.
func (p *TunnelPool) BuildContextWithPolicy(ctx context.Context, np *types.NetworkProfile, bastionCred secrets.ResolvedSecret, instanceTLSMode, targetHost string, pol DialPolicy) (DialResult, error) {
	if p == nil || np == nil || np.Mode != types.NetworkSSHTunnel {
		return BuildContextWithPolicy(ctx, np, bastionCred, instanceTLSMode, targetHost, pol)
	}
	if pol.DisableSSHAuthSock && bastionCred.Secret == "" {
		return DialResult{}, fmt.Errorf("ssh_tunnel requires explicit bastion credential secret in server mode")
	}
	if err := checkDialHostPolicy(ctx, np.BastionHost, pol); err != nil {
		return DialResult{}, err
	}
	return p.buildContextWithDialer(ctx, np, bastionCred, instanceTLSMode, targetHost, pol.NewDialer())
}
