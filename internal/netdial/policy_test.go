package netdial

import (
	"context"
	"net"
	"net/url"
	"testing"

	"github.com/x0c/agent-dbctl/internal/secrets"
	"github.com/x0c/agent-dbctl/internal/types"
)

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u
}

func TestDialPolicyEgressAndSSHGuards(t *testing.T) {
	pol, err := ParseDialPolicy(true, true, true, nil, []string{"198.51.100.0/24"})
	if err != nil {
		t.Fatalf("ParseDialPolicy: %v", err)
	}
	if err := pol.CheckIP(net.ParseIP("127.0.0.1")); err == nil {
		t.Fatalf("expected loopback IP to be blocked")
	}
	if err := pol.CheckIP(net.ParseIP("169.254.169.254")); err == nil {
		t.Fatalf("expected link-local metadata IP to be blocked")
	}
	if err := pol.CheckIP(net.ParseIP("203.0.113.10")); err == nil {
		t.Fatalf("expected IP outside allowed_egress_cidrs to be blocked")
	}
	if err := pol.CheckIP(net.ParseIP("198.51.100.40")); err != nil {
		t.Fatalf("expected IP inside allowed_egress_cidrs to pass: %v", err)
	}

	// Reject embedded proxy credentials in server mode.
	if _, err := BuildContextWithPolicy(context.Background(), &types.NetworkProfile{
		Mode:     types.NetworkSOCKS5,
		ProxyURL: "socks5://user:pass@198.51.100.2:1080",
	}, secrets.ResolvedSecret{}, "", "198.51.100.5", pol); err == nil {
		t.Fatalf("expected embedded proxy credentials to be rejected")
	}

	// Reject SSH tunnel without explicit secret when DisableSSHAuthSock=true.
	if _, err := BuildContextWithPolicy(context.Background(), &types.NetworkProfile{
		Mode:        types.NetworkSSHTunnel,
		BastionHost: "198.51.100.2",
		BastionUser: "ops",
	}, secrets.ResolvedSecret{}, "", "198.51.100.5", pol); err == nil {
		t.Fatalf("expected ssh_tunnel without explicit credential secret to fail in server mode")
	}

	// Custom BlockedCIDRs must not disable defaultBlockedNets (loopback / metadata / link-local).
	customPol, err := ParseDialPolicy(true, true, true, []string{"203.0.113.0/24"}, nil)
	if err != nil {
		t.Fatalf("ParseDialPolicy custom: %v", err)
	}
	for _, blocked := range []string{"127.0.0.1", "169.254.169.254", "203.0.113.7"} {
		if err := customPol.CheckIP(net.ParseIP(blocked)); err == nil {
			t.Fatalf("expected %s to remain blocked with custom blocked_egress_cidrs", blocked)
		}
	}

	// HTTP proxy and SSH tunnel must block loopback targets and unresolvable hosts (fail closed),
	// and TunnelPool must also enforce DialPolicy + dialer Control hook.
	defaultServerPol, err := ParseDialPolicy(true, true, true, nil, nil)
	if err != nil {
		t.Fatalf("ParseDialPolicy server default: %v", err)
	}
	if _, err := BuildContextWithPolicy(context.Background(), &types.NetworkProfile{
		Mode:     types.NetworkHTTPProxy,
		ProxyURL: "http://127.0.0.1:3128",
	}, secrets.ResolvedSecret{}, "", "198.51.100.5", defaultServerPol); err == nil {
		t.Fatalf("expected http_proxy loopback address to be blocked")
	}
	if _, err := BuildContextWithPolicy(context.Background(), &types.NetworkProfile{
		Mode:     types.NetworkHTTPProxy,
		ProxyURL: "http://nonexistent.invalid:3128",
	}, secrets.ResolvedSecret{}, "", "198.51.100.5", defaultServerPol); err == nil {
		t.Fatalf("expected unresolvable http_proxy host to fail closed")
	}
	if _, err := dialHTTPConnectWithDialer(context.Background(), mustParseURL(t, "http://127.0.0.1:3128"), "198.51.100.5:5432", defaultServerPol.NewDialer()); err == nil {
		t.Fatalf("expected dialHTTPConnectWithDialer Control hook to block loopback")
	}
	pool := NewTunnelPool(TunnelPoolConfig{})
	defer func() { _ = pool.Close() }()
	if _, err := pool.BuildContextWithPolicy(context.Background(), &types.NetworkProfile{
		Mode:        types.NetworkSSHTunnel,
		BastionHost: "127.0.0.1",
		BastionUser: "ops",
	}, secrets.ResolvedSecret{Secret: "pass"}, "", "198.51.100.5", defaultServerPol); err == nil {
		t.Fatalf("expected pooled ssh_tunnel loopback bastion to be blocked")
	}
	if _, err := dialSSHClientWithDialer(context.Background(), &types.NetworkProfile{
		Mode:        types.NetworkSSHTunnel,
		BastionHost: "127.0.0.1",
		BastionUser: "ops",
	}, secrets.ResolvedSecret{Secret: "pass"}, defaultServerPol.NewDialer()); err == nil {
		t.Fatalf("expected dialSSHClientWithDialer Control hook to block loopback")
	}

	// Control hook must strip IPv6 zones, unmap IPv4-mapped IPv6, block CGNAT/broadcast/NAT64, and fail closed on non-IPs.
	ctrl := defaultServerPol.NewDialer().Control
	if ctrl == nil {
		t.Fatalf("expected Control hook when EnforceEgressGuard=true")
	}
	for _, addr := range []string{
		"[::1%lo0]:5432",
		"[fe80::1%en0]:80",
		"[::ffff:127.0.0.1]:5432",
		"[::ffff:169.254.169.254]:80",
		"100.100.100.200:80",
		"255.255.255.255:5432",
		"[64:ff9b::127.0.0.1]:5432",
		"not-an-ip-literal:5432",
	} {
		if err := ctrl("tcp", addr, nil); err == nil {
			t.Fatalf("expected Control to reject %s", addr)
		}
	}
	// Proxy and tunnel paths must reject literal restricted target hosts (e.g. cloud metadata).
	for _, prof := range []*types.NetworkProfile{
		{Mode: types.NetworkHTTPProxy, ProxyURL: "http://198.51.100.2:3128"},
		{Mode: types.NetworkSOCKS5, ProxyURL: "socks5://198.51.100.2:1080"},
		{Mode: types.NetworkSSHTunnel, BastionHost: "198.51.100.2", BastionUser: "ops"},
	} {
		if _, err := BuildContextWithPolicy(context.Background(), prof, secrets.ResolvedSecret{Secret: "pass"}, "", "169.254.169.254", pol); err == nil {
			t.Fatalf("expected %s to reject metadata target 169.254.169.254", prof.Mode)
		}
	}
}
