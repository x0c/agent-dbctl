package netdial

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/x0c/agent-dbctl/internal/secrets"
	"github.com/x0c/agent-dbctl/internal/types"
)

type testSSHBastion struct {
	addr           string
	password       atomic.Value // string
	handshakes     atomic.Int64
	keepalives     atomic.Int64
	dropConnsNext  atomic.Bool
	ln             net.Listener
	mu             sync.Mutex
	activeConns    []net.Conn
}

func startTestBastion(t *testing.T, initialPassword string) *testSSHBastion {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	b := &testSSHBastion{}
	b.password.Store(initialPassword)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b.ln = ln
	b.addr = ln.Addr().String()

	cfg := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			want, _ := b.password.Load().(string)
			if string(pass) == want {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("invalid password")
		},
	}
	cfg.AddHostKey(signer)

	go func() {
		for {
			rawConn, err := ln.Accept()
			if err != nil {
				return
			}
			go b.serveConn(rawConn, cfg)
		}
	}()

	t.Cleanup(func() {
		b.closeAll()
	})
	return b
}

func (b *testSSHBastion) serveConn(rawConn net.Conn, cfg *ssh.ServerConfig) {
	b.mu.Lock()
	b.activeConns = append(b.activeConns, rawConn)
	b.mu.Unlock()

	sconn, chans, reqs, err := ssh.NewServerConn(rawConn, cfg)
	if err != nil {
		_ = rawConn.Close()
		return
	}
	b.handshakes.Add(1)
	defer func() { _ = sconn.Close() }()

	go func() {
		for req := range reqs {
			if req.Type == "keepalive@openssh.com" {
				b.keepalives.Add(1)
			}
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		}
	}()

	for newChan := range chans {
		if newChan.ChannelType() != "direct-tcpip" {
			_ = newChan.Reject(ssh.UnknownChannelType, "unsupported channel")
			continue
		}
		if b.dropConnsNext.Swap(false) {
			_ = newChan.Reject(ssh.ConnectionFailed, "simulated drop")
			_ = rawConn.Close()
			return
		}
		var payload struct {
			DestAddr string
			DestPort uint32
			OrigAddr string
			OrigPort uint32
		}
		if err := ssh.Unmarshal(newChan.ExtraData(), &payload); err != nil {
			_ = newChan.Reject(ssh.ConnectionFailed, err.Error())
			continue
		}
		target := net.JoinHostPort(payload.DestAddr, strconv.Itoa(int(payload.DestPort)))
		remote, err := net.DialTimeout("tcp", target, 2*time.Second)
		if err != nil {
			_ = newChan.Reject(ssh.ConnectionFailed, err.Error())
			continue
		}
		ch, chReqs, err := newChan.Accept()
		if err != nil {
			_ = remote.Close()
			continue
		}
		go ssh.DiscardRequests(chReqs)
		go func() {
			defer func() {
				_ = ch.Close()
				_ = remote.Close()
			}()
			go func() {
				_, _ = io.Copy(remote, ch)
				_ = remote.Close()
			}()
			_, _ = io.Copy(ch, remote)
		}()
	}
}

func (b *testSSHBastion) dropActiveConns() {
	b.mu.Lock()
	conns := append([]net.Conn(nil), b.activeConns...)
	b.activeConns = nil
	b.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

func (b *testSSHBastion) closeAll() {
	if b.ln != nil {
		_ = b.ln.Close()
	}
	b.dropActiveConns()
}

func startEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(cn net.Conn) {
				defer func() { _ = cn.Close() }()
				_, _ = io.Copy(cn, cn)
			}(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

func echoOverDialer(t *testing.T, res DialResult, targetAddr string, msg string) {
	t.Helper()
	conn, err := res.DialContext(context.Background(), "tcp", targetAddr)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := io.WriteString(conn, msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("echo mismatch: got %q, want %q", string(buf), msg)
	}
}

func bastionHostPort(addr string) (string, int) {
	h, pStr, _ := net.SplitHostPort(addr)
	p, _ := strconv.Atoi(pStr)
	return h, p
}

func TestTunnelPoolReuseRotationInvalidationAndReconnect(t *testing.T) {
	bastion := startTestBastion(t, "pass-v1")
	echoAddr := startEchoServer(t)
	bHost, bPort := bastionHostPort(bastion.addr)

	pool := NewTunnelPool(TunnelPoolConfig{
		IdleTTL:           2 * time.Second,
		KeepaliveInterval: 100 * time.Millisecond,
		KeepaliveTimeout:  500 * time.Millisecond,
		ReapInterval:      2 * time.Second,
	})
	defer func() { _ = pool.Close() }()

	np := &types.NetworkProfile{
		ID:          "np-ssh-1",
		Name:        "bastion-1",
		Mode:        types.NetworkSSHTunnel,
		BastionHost: bHost,
		BastionPort: bPort,
		BastionUser: "ops",
	}
	cred1 := secrets.ResolvedSecret{Username: "ops", Secret: "pass-v1"}

	// 1. Concurrent callers targeting same bastion share 1 SSH handshake.
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			res, err := pool.BuildContext(context.Background(), np, cred1, "disable", "127.0.0.1")
			if err != nil {
				t.Errorf("BuildContext %d: %v", idx, err)
				return
			}
			echoOverDialer(t, res, echoAddr, fmt.Sprintf("ping-%d", idx))
			_ = res.Close()
		}(i)
	}
	wg.Wait()

	if hs := bastion.handshakes.Load(); hs != 1 {
		t.Fatalf("expected 1 SSH handshake for concurrent callers, got %d", hs)
	}
	st := pool.Stats()
	if st.Misses != 1 || st.Hits < 3 || st.ActiveTunnels != 1 {
		t.Fatalf("unexpected pool stats after concurrent reuse: %+v", st)
	}

	// Verify keepalives run on cached tunnel.
	deadline := time.Now().Add(1 * time.Second)
	for bastion.keepalives.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if bastion.keepalives.Load() == 0 {
		t.Fatalf("expected SSH keepalive@openssh.com requests to fire")
	}

	// 2. Rotated password creates distinct cache entry & new handshake.
	bastion.password.Store("pass-v2")
	cred2 := secrets.ResolvedSecret{Username: "ops", Secret: "pass-v2"}
	res2, err := pool.BuildContext(context.Background(), np, cred2, "disable", "127.0.0.1")
	if err != nil {
		t.Fatalf("BuildContext rotated secret: %v", err)
	}
	echoOverDialer(t, res2, echoAddr, "rotated")
	if hs := bastion.handshakes.Load(); hs != 2 {
		t.Fatalf("expected 2 handshakes after secret rotation, got %d", hs)
	}

	// 3. Drop active SSH connections -> next dial evicts & transparently reconnects.
	bastion.dropActiveConns()
	time.Sleep(30 * time.Millisecond)
	echoOverDialer(t, res2, echoAddr, "reconnected")
	if st := pool.Stats(); st.Reconnects < 1 {
		t.Fatalf("expected Reconnects >= 1 after bastion connection drop, got %+v", st)
	}

	// 4. InvalidateProfile clears all cached entries for np.ID.
	pool.InvalidateProfile(np.ID)
	if st := pool.Stats(); st.ActiveTunnels != 0 {
		t.Fatalf("expected ActiveTunnels=0 after InvalidateProfile, got %+v", st)
	}
}

func TestTunnelPoolIdleEviction(t *testing.T) {
	bastion := startTestBastion(t, "pass-idle")
	echoAddr := startEchoServer(t)
	bHost, bPort := bastionHostPort(bastion.addr)

	pool := NewTunnelPool(TunnelPoolConfig{
		IdleTTL:           120 * time.Millisecond,
		KeepaliveInterval: 5 * time.Second,
		KeepaliveTimeout:  500 * time.Millisecond,
		ReapInterval:      40 * time.Millisecond,
	})
	defer func() { _ = pool.Close() }()

	np := &types.NetworkProfile{
		ID:          "np-idle",
		Mode:        types.NetworkSSHTunnel,
		BastionHost: bHost,
		BastionPort: bPort,
		BastionUser: "ops",
	}
	cred := secrets.ResolvedSecret{Username: "ops", Secret: "pass-idle"}
	res, err := pool.BuildContext(context.Background(), np, cred, "", "127.0.0.1")
	if err != nil {
		t.Fatalf("BuildContext: %v", err)
	}
	echoOverDialer(t, res, echoAddr, "idle-check")

	deadline := time.Now().Add(2 * time.Second)
	for pool.Stats().ActiveTunnels > 0 && time.Now().Before(deadline) {
		time.Sleep(25 * time.Millisecond)
	}
	if st := pool.Stats(); st.ActiveTunnels != 0 || st.Evictions == 0 {
		t.Fatalf("expected idle tunnel eviction, got %+v", st)
	}
}
