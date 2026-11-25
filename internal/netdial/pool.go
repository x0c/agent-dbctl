package netdial

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/x0c/agent-dbctl/internal/secrets"
	"github.com/x0c/agent-dbctl/internal/types"
)

// TunnelPoolConfig tunes SSH bastion connection pooling and keepalive monitoring.
type TunnelPoolConfig struct {
	IdleTTL           time.Duration
	KeepaliveInterval time.Duration
	KeepaliveTimeout  time.Duration
	ReapInterval      time.Duration
	MaxTunnels        int
}

// TunnelPoolStats summarizes pooled SSH tunnel utilization and lifecycle counters.
type TunnelPoolStats struct {
	ActiveTunnels int   `json:"active_tunnels"`
	Hits          int64 `json:"hits"`
	Misses        int64 `json:"misses"`
	Evictions     int64 `json:"evictions"`
	Reconnects    int64 `json:"reconnects"`
}

type pooledTunnel struct {
	key       string
	profileID string
	client    *ssh.Client
	createdAt time.Time
	lastUsed  atomic.Int64 // UnixNano
	stopCh    chan struct{}
	closeOnce sync.Once
}

func (e *pooledTunnel) touch() {
	e.lastUsed.Store(time.Now().UnixNano())
}

func (e *pooledTunnel) close() error {
	var err error
	e.closeOnce.Do(func() {
		close(e.stopCh)
		if e.client != nil {
			err = e.client.Close()
		}
	})
	return err
}

// TunnelPool caches keepalive-monitored *ssh.Client connections keyed by network profile and bastion credential hash.
type TunnelPool struct {
	cfg TunnelPoolConfig

	mu        sync.Mutex
	closed    bool
	entries   map[string]*pooledTunnel
	dialLocks map[string]*sync.Mutex

	stopReaper chan struct{}
	closeOnce  sync.Once
	wg         sync.WaitGroup

	hits       atomic.Int64
	misses     atomic.Int64
	evictions  atomic.Int64
	reconnects atomic.Int64
}

// NewTunnelPool creates an SSH tunnel pool with background keepalive and idle reaper loops.
func NewTunnelPool(cfg TunnelPoolConfig) *TunnelPool {
	if cfg.IdleTTL <= 0 {
		cfg.IdleTTL = 5 * time.Minute
	}
	if cfg.KeepaliveInterval <= 0 {
		cfg.KeepaliveInterval = 30 * time.Second
	}
	if cfg.KeepaliveTimeout <= 0 {
		cfg.KeepaliveTimeout = 5 * time.Second
	}
	if cfg.ReapInterval <= 0 {
		cfg.ReapInterval = 30 * time.Second
	}
	if cfg.MaxTunnels <= 0 {
		cfg.MaxTunnels = 32
	}

	p := &TunnelPool{
		cfg:        cfg,
		entries:    make(map[string]*pooledTunnel),
		dialLocks:  make(map[string]*sync.Mutex),
		stopReaper: make(chan struct{}),
	}
	p.wg.Add(1)
	go p.reapLoop()
	return p
}

// BuildContext returns a DialResult backed by a pooled SSH bastion tunnel when np.Mode is NetworkSSHTunnel,
// or delegates to stateless BuildContext for direct, SOCKS5, and HTTP proxy connections.
func (p *TunnelPool) BuildContext(ctx context.Context, np *types.NetworkProfile, bastionCred secrets.ResolvedSecret, instanceTLSMode, targetHost string) (DialResult, error) {
	if p == nil || np == nil || np.Mode != types.NetworkSSHTunnel {
		return BuildContext(ctx, np, bastionCred, instanceTLSMode, targetHost)
	}

	tlsMode := strings.ToLower(strings.TrimSpace(instanceTLSMode))
	if strings.TrimSpace(np.TLSMode) != "" && tlsMode == "" {
		tlsMode = strings.ToLower(strings.TrimSpace(np.TLSMode))
	}
	tlsCfg, err := buildTLSConfig(tlsMode, targetHost)
	if err != nil {
		return DialResult{}, err
	}

	key := buildTunnelKey(np, bastionCred)
	entry, err := p.getOrDial(ctx, key, np, bastionCred)
	if err != nil {
		return DialResult{}, err
	}

	return DialResult{
		DialContext: func(dctx context.Context, network, addr string) (net.Conn, error) {
			return p.dialThroughPool(dctx, key, np, bastionCred, entry, network, addr)
		},
		TLSMode:   tlsMode,
		TLSConfig: tlsCfg,
		// Pooled SSH clients remain open across operations; pool invalidation/TTL closes them.
		Close: func() error { return nil },
	}, nil
}

func (p *TunnelPool) dialThroughPool(dctx context.Context, key string, np *types.NetworkProfile, cred secrets.ResolvedSecret, initial *pooledTunnel, network, addr string) (net.Conn, error) {
	entry := initial
	if entry == nil {
		var err error
		entry, err = p.getOrDial(dctx, key, np, cred)
		if err != nil {
			return nil, err
		}
	}
	entry.touch()
	conn, err := entry.client.DialContext(dctx, network, addr)
	if err == nil {
		entry.touch()
		return WrapSSHConn(conn), nil
	}
	if dctx.Err() != nil {
		return nil, err
	}

	// Evict stale transport and transparently reconnect once.
	p.evictIfSame(key, entry)
	p.reconnects.Add(1)

	fresh, dialErr := p.getOrDial(dctx, key, np, cred)
	if dialErr != nil {
		return nil, err
	}
	fresh.touch()
	conn2, err2 := fresh.client.DialContext(dctx, network, addr)
	if err2 != nil {
		return nil, err2
	}
	fresh.touch()
	return WrapSSHConn(conn2), nil
}

func (p *TunnelPool) dialLockForKey(key string) *sync.Mutex {
	p.mu.Lock()
	defer p.mu.Unlock()
	lk, ok := p.dialLocks[key]
	if !ok {
		lk = &sync.Mutex{}
		p.dialLocks[key] = lk
	}
	return lk
}

func (p *TunnelPool) getOrDial(ctx context.Context, key string, np *types.NetworkProfile, cred secrets.ResolvedSecret) (*pooledTunnel, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, fmt.Errorf("ssh tunnel pool is closed")
	}
	if e, ok := p.entries[key]; ok {
		e.touch()
		p.hits.Add(1)
		p.mu.Unlock()
		return e, nil
	}
	p.mu.Unlock()

	lk := p.dialLockForKey(key)
	lk.Lock()
	defer lk.Unlock()

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, fmt.Errorf("ssh tunnel pool is closed")
	}
	if e, ok := p.entries[key]; ok {
		e.touch()
		p.hits.Add(1)
		p.mu.Unlock()
		return e, nil
	}
	p.mu.Unlock()

	client, err := dialSSHClient(ctx, np, cred)
	if err != nil {
		return nil, err
	}

	entry := &pooledTunnel{
		key:       key,
		profileID: np.ID,
		client:    client,
		createdAt: time.Now(),
		stopCh:    make(chan struct{}),
	}
	entry.touch()

	var evicted []*pooledTunnel
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		_ = client.Close()
		return nil, fmt.Errorf("ssh tunnel pool is closed")
	}
	for len(p.entries) >= p.cfg.MaxTunnels {
		if oldest := p.popOldestLocked(); oldest != nil {
			evicted = append(evicted, oldest)
			p.evictions.Add(1)
		} else {
			break
		}
	}
	p.entries[key] = entry
	p.misses.Add(1)
	p.mu.Unlock()

	for _, old := range evicted {
		_ = old.close()
	}

	p.wg.Add(1)
	go p.keepaliveLoop(entry)
	return entry, nil
}

func (p *TunnelPool) popOldestLocked() *pooledTunnel {
	var oldest *pooledTunnel
	for _, e := range p.entries {
		if oldest == nil || e.lastUsed.Load() < oldest.lastUsed.Load() {
			oldest = e
		}
	}
	if oldest != nil {
		delete(p.entries, oldest.key)
	}
	return oldest
}

func (p *TunnelPool) evictIfSame(key string, target *pooledTunnel) {
	p.mu.Lock()
	cur, ok := p.entries[key]
	if ok && cur == target {
		delete(p.entries, key)
		p.evictions.Add(1)
	} else {
		ok = false
	}
	p.mu.Unlock()
	if ok {
		_ = target.close()
	}
}

func (p *TunnelPool) keepaliveLoop(entry *pooledTunnel) {
	defer p.wg.Done()
	ticker := time.NewTicker(p.cfg.KeepaliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-entry.stopCh:
			return
		case <-p.stopReaper:
			return
		case <-ticker.C:
			if err := probeSSHKeepalive(entry.client, p.cfg.KeepaliveTimeout); err != nil {
				p.evictIfSame(entry.key, entry)
				return
			}
		}
	}
}

func probeSSHKeepalive(client *ssh.Client, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() {
		_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
		done <- err
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		// OpenSSH replies with failure packet ("request failed") when keepalive extension is ignored,
		// which still proves the SSH transport socket is alive.
		if err != nil && err.Error() == "request failed" {
			return nil
		}
		return err
	case <-timer.C:
		_ = client.Close()
		return fmt.Errorf("ssh keepalive timed out after %s", timeout)
	}
}

func (p *TunnelPool) reapLoop() {
	defer p.wg.Done()
	ticker := time.NewTicker(p.cfg.ReapInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopReaper:
			return
		case <-ticker.C:
			p.reapIdle()
		}
	}
}

func (p *TunnelPool) reapIdle() {
	cutoff := time.Now().Add(-p.cfg.IdleTTL).UnixNano()
	var evicted []*pooledTunnel

	p.mu.Lock()
	for k, e := range p.entries {
		if e.lastUsed.Load() < cutoff {
			delete(p.entries, k)
			evicted = append(evicted, e)
			p.evictions.Add(1)
		}
	}
	p.mu.Unlock()

	for _, e := range evicted {
		_ = e.close()
	}
}

// InvalidateProfile closes and removes all cached SSH tunnels associated with networkProfileID.
func (p *TunnelPool) InvalidateProfile(networkProfileID string) {
	if p == nil || networkProfileID == "" {
		return
	}
	var evicted []*pooledTunnel
	p.mu.Lock()
	for k, e := range p.entries {
		if e.profileID == networkProfileID {
			delete(p.entries, k)
			evicted = append(evicted, e)
			p.evictions.Add(1)
		}
	}
	p.mu.Unlock()
	for _, e := range evicted {
		_ = e.close()
	}
}

// InvalidateAll closes and removes all cached SSH tunnels without closing the pool itself.
func (p *TunnelPool) InvalidateAll() {
	if p == nil {
		return
	}
	var evicted []*pooledTunnel
	p.mu.Lock()
	for k, e := range p.entries {
		delete(p.entries, k)
		evicted = append(evicted, e)
		p.evictions.Add(1)
	}
	p.mu.Unlock()
	for _, e := range evicted {
		_ = e.close()
	}
}

// Stats returns current tunnel pool occupancy and cumulative hit/miss/eviction/reconnect counters.
func (p *TunnelPool) Stats() TunnelPoolStats {
	if p == nil {
		return TunnelPoolStats{}
	}
	p.mu.Lock()
	active := len(p.entries)
	p.mu.Unlock()
	return TunnelPoolStats{
		ActiveTunnels: active,
		Hits:          p.hits.Load(),
		Misses:        p.misses.Load(),
		Evictions:     p.evictions.Load(),
		Reconnects:    p.reconnects.Load(),
	}
}

// Close shuts down the reaper and keepalive goroutines and closes all pooled SSH clients.
func (p *TunnelPool) Close() error {
	if p == nil {
		return nil
	}
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.closed = true
		all := make([]*pooledTunnel, 0, len(p.entries))
		for k, e := range p.entries {
			all = append(all, e)
			delete(p.entries, k)
		}
		p.mu.Unlock()

		close(p.stopReaper)
		for _, e := range all {
			_ = e.close()
		}
		p.wg.Wait()
	})
	return nil
}

// FingerprintProfile returns a redacted deterministic hash identifying a NetworkProfile and optional bastion secret.
func FingerprintProfile(np *types.NetworkProfile, bastionCred secrets.ResolvedSecret) string {
	if np == nil {
		return "direct"
	}
	if np.Mode == types.NetworkSSHTunnel {
		return buildTunnelKey(np, bastionCred)
	}
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s|%s|%s|%s", np.ID, np.Mode, np.ProxyURL, np.TLSMode)
	return hex.EncodeToString(h.Sum(nil))
}

func buildTunnelKey(np *types.NetworkProfile, cred secrets.ResolvedSecret) string {
	port := np.BastionPort
	if port <= 0 {
		port = 22
	}
	user := np.BastionUser
	if user == "" {
		user = cred.Username
	}
	secretSum := sha256.Sum256([]byte(cred.Secret))
	sock := ""
	if cred.Secret == "" {
		sock = strings.TrimSpace(os.Getenv("SSH_AUTH_SOCK"))
	}
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "ssh|%s|%s|%d|%s|%t|%s|%s",
		np.ID,
		np.BastionHost,
		port,
		user,
		np.SSHStrictHostKey,
		hex.EncodeToString(secretSum[:]),
		sock,
	)
	return hex.EncodeToString(h.Sum(nil))
}
