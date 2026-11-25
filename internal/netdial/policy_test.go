package netdial

import (
	"context"
	"net"
	"testing"

	"github.com/x0c/agent-dbctl/internal/secrets"
	"github.com/x0c/agent-dbctl/internal/types"
)

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
}
