package driver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/x0c/agent-dbctl/internal/types"
)

// ConnPoolConfig configures idle pooling for short-lived read-only database connections.
type ConnPoolConfig struct {
	MaxIdlePerKey      int
	MaxTotalIdle       int
	IdleTTL            time.Duration
	MaxAge             time.Duration
	ExecProviderMaxAge time.Duration // < 0 disables pooling for exec_provider credentials
	HealthCheckAfter   time.Duration
	ReapInterval       time.Duration
}

// ConnPoolMeta identifies pool ownership and invalidation axes without storing raw credentials.
type ConnPoolMeta struct {
	TargetID         string
	InstanceID       string
	NetworkProfileID string
	CredentialID     string
	CredKind         types.CredentialKind
	ReadOnly         bool
	Key              string
	DisablePool      bool
}

// ConnPoolStats summarizes idle connection pool utilization and lifecycle counters.
type ConnPoolStats struct {
	IdleConns int   `json:"idle_conns"`
	Hits      int64 `json:"hits"`
	Misses    int64 `json:"misses"`
	Discards  int64 `json:"discards"`
	Evictions int64 `json:"evictions"`
}

// BuildConnPoolKey computes a deterministic, secret-free SHA-256 key for pooling compatible read-only handles.
func BuildConnPoolKey(meta ConnPoolMeta, cfg ConnectionConfig, networkHash string) string {
	h := sha256.New()
	secretSum := sha256.Sum256([]byte(cfg.Credential.Secret))
	_, _ = fmt.Fprintf(h, "%s|%s|%d|%s|%t|%s|%s|%s|%s",
		cfg.Engine,
		cfg.Host,
		cfg.Port,
		cfg.DatabaseName,
		meta.ReadOnly,
		cfg.TLSMode,
		cfg.Credential.Username,
		hex.EncodeToString(secretSum[:]),
		networkHash,
	)
	if len(cfg.Params) > 0 {
		keys := make([]string, 0, len(cfg.Params))
		for k := range cfg.Params {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			_, _ = fmt.Fprintf(h, "|%s=%s", k, cfg.Params[k])
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

type idleConn struct {
	conn      Conn
	meta      ConnPoolMeta
	createdAt time.Time
	lastUsed  time.Time
}

// ConnPool caches verified, clean read-only driver.Conn handles across operations (e.g. Preflight -> Execute).
type ConnPool struct {
	cfg ConnPoolConfig

	mu     sync.Mutex
	closed bool
	idle   map[string][]*idleConn

	stopReaper chan struct{}
	closeOnce  sync.Once
	wg         sync.WaitGroup

	hits      atomic.Int64
	misses    atomic.Int64
	discards  atomic.Int64
	evictions atomic.Int64
}

// NewConnPool creates a read-only connection pool with idle TTL and max-age reaping.
func NewConnPool(cfg ConnPoolConfig) *ConnPool {
	if cfg.MaxIdlePerKey <= 0 {
		cfg.MaxIdlePerKey = 2
	}
	if cfg.MaxTotalIdle <= 0 {
		cfg.MaxTotalIdle = 32
	}
	if cfg.IdleTTL <= 0 {
		cfg.IdleTTL = 90 * time.Second
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = 10 * time.Minute
	}
	if cfg.ExecProviderMaxAge == 0 {
		cfg.ExecProviderMaxAge = 2 * time.Minute
	}
	if cfg.HealthCheckAfter <= 0 {
		cfg.HealthCheckAfter = 15 * time.Second
	}
	if cfg.ReapInterval <= 0 {
		cfg.ReapInterval = 30 * time.Second
	}

	p := &ConnPool{
		cfg:        cfg,
		idle:       make(map[string][]*idleConn),
		stopReaper: make(chan struct{}),
	}
	p.wg.Add(1)
	go p.reapLoop()
	return p
}

func (p *ConnPool) isPoolable(meta ConnPoolMeta) bool {
	if p == nil || meta.DisablePool || !meta.ReadOnly || meta.Key == "" {
		return false
	}
	if meta.CredKind == types.CredExecProvider && p.cfg.ExecProviderMaxAge <= 0 {
		return false
	}
	return true
}

func (p *ConnPool) maxAgeFor(kind types.CredentialKind) time.Duration {
	if kind == types.CredExecProvider {
		return p.cfg.ExecProviderMaxAge
	}
	return p.cfg.MaxAge
}

// ShouldBypassPool reports whether a connection target (e.g., SQLite :memory:) must remain unpooled.
func ShouldBypassPool(cfg ConnectionConfig) bool {
	return strings.EqualFold(cfg.Engine, "sqlite") && strings.TrimSpace(cfg.DatabaseName) == ":memory:"
}

// Acquire returns a reusable read-only connection or opens a new one via openFn.
// Write connections (ReadOnly == false) and non-poolable targets always bypass pooling.
func (p *ConnPool) Acquire(ctx context.Context, meta ConnPoolMeta, openFn func(context.Context) (Conn, error)) (Conn, error) {
	if !p.isPoolable(meta) {
		if p != nil {
			p.misses.Add(1)
		}
		return openFn(ctx)
	}

	for {
		entry := p.popLatest(meta.Key)
		if entry == nil {
			break
		}
		if p.isExpired(entry) {
			_ = entry.conn.Close()
			p.evictions.Add(1)
			continue
		}
		if time.Since(entry.lastUsed) >= p.cfg.HealthCheckAfter {
			pingCtx, cancel := boundedSubContext(ctx, 2*time.Second)
			res, err := entry.conn.Ping(pingCtx)
			cancel()
			if err != nil || !res.Reachable {
				_ = entry.conn.Close()
				p.discards.Add(1)
				continue
			}
		}
		p.hits.Add(1)
		return wrapPooledConn(p, entry.conn, meta, entry.createdAt), nil
	}

	p.misses.Add(1)
	conn, err := openFn(ctx)
	if err != nil {
		return nil, err
	}
	return wrapPooledConn(p, conn, meta, time.Now()), nil
}

func wrapPooledConn(p *ConnPool, inner Conn, meta ConnPoolMeta, createdAt time.Time) Conn {
	pc := &pooledConn{
		pool:      p,
		inner:     inner,
		meta:      meta,
		createdAt: createdAt,
	}
	if si, ok := inner.(SchemaInspector); ok {
		return &pooledSchemaConn{pooledConn: pc, si: si}
	}
	return pc
}

func (p *ConnPool) popLatest(key string) *idleConn {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	list := p.idle[key]
	if len(list) == 0 {
		return nil
	}
	entry := list[len(list)-1]
	if len(list) == 1 {
		delete(p.idle, key)
	} else {
		p.idle[key] = list[:len(list)-1]
	}
	return entry
}

func (p *ConnPool) isExpired(entry *idleConn) bool {
	now := time.Now()
	if now.Sub(entry.lastUsed) > p.cfg.IdleTTL {
		return true
	}
	maxAge := p.maxAgeFor(entry.meta.CredKind)
	return maxAge <= 0 || now.Sub(entry.createdAt) > maxAge
}

func (p *ConnPool) put(entry *idleConn) bool {
	var toClose []*idleConn

	p.mu.Lock()
	if p.closed || p.isExpired(entry) {
		p.mu.Unlock()
		return false
	}

	list := p.idle[entry.meta.Key]
	if len(list) >= p.cfg.MaxIdlePerKey {
		toClose = append(toClose, list[0])
		list = list[1:]
		p.evictions.Add(1)
	}
	list = append(list, entry)
	p.idle[entry.meta.Key] = list

	for p.totalIdleLocked() > p.cfg.MaxTotalIdle {
		if evicted := p.evictOldestGlobalLocked(); evicted != nil {
			toClose = append(toClose, evicted)
			p.evictions.Add(1)
		} else {
			break
		}
	}
	p.mu.Unlock()

	for _, old := range toClose {
		_ = old.conn.Close()
	}
	return true
}

func (p *ConnPool) totalIdleLocked() int {
	total := 0
	for _, list := range p.idle {
		total += len(list)
	}
	return total
}

func (p *ConnPool) evictOldestGlobalLocked() *idleConn {
	var oldestKey string
	var oldestIdx int
	var oldest *idleConn
	for k, list := range p.idle {
		for i, e := range list {
			if oldest == nil || e.lastUsed.Before(oldest.lastUsed) {
				oldestKey = k
				oldestIdx = i
				oldest = e
			}
		}
	}
	if oldest == nil {
		return nil
	}
	list := p.idle[oldestKey]
	list = append(list[:oldestIdx], list[oldestIdx+1:]...)
	if len(list) == 0 {
		delete(p.idle, oldestKey)
	} else {
		p.idle[oldestKey] = list
	}
	return oldest
}

func (p *ConnPool) reapLoop() {
	defer p.wg.Done()
	ticker := time.NewTicker(p.cfg.ReapInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopReaper:
			return
		case <-ticker.C:
			p.reapExpired()
		}
	}
}

func (p *ConnPool) reapExpired() {
	var expired []*idleConn
	p.mu.Lock()
	for k, list := range p.idle {
		kept := list[:0]
		for _, e := range list {
			if p.isExpired(e) {
				expired = append(expired, e)
				p.evictions.Add(1)
			} else {
				kept = append(kept, e)
			}
		}
		if len(kept) == 0 {
			delete(p.idle, k)
		} else {
			p.idle[k] = kept
		}
	}
	p.mu.Unlock()

	for _, e := range expired {
		_ = e.conn.Close()
	}
}

func (p *ConnPool) invalidateWhere(pred func(ConnPoolMeta) bool) {
	if p == nil {
		return
	}
	var removed []*idleConn
	p.mu.Lock()
	for k, list := range p.idle {
		kept := list[:0]
		for _, e := range list {
			if pred(e.meta) {
				removed = append(removed, e)
				p.evictions.Add(1)
			} else {
				kept = append(kept, e)
			}
		}
		if len(kept) == 0 {
			delete(p.idle, k)
		} else {
			p.idle[k] = kept
		}
	}
	p.mu.Unlock()

	for _, e := range removed {
		_ = e.conn.Close()
	}
}

// InvalidateTarget closes and removes all idle connections owned by targetID.
func (p *ConnPool) InvalidateTarget(targetID string) {
	if targetID != "" {
		p.invalidateWhere(func(m ConnPoolMeta) bool { return m.TargetID == targetID })
	}
}

// InvalidateInstance closes and removes all idle connections targeting instanceID.
func (p *ConnPool) InvalidateInstance(instanceID string) {
	if instanceID != "" {
		p.invalidateWhere(func(m ConnPoolMeta) bool { return m.InstanceID == instanceID })
	}
}

// InvalidateNetwork closes and removes all idle connections using networkProfileID.
func (p *ConnPool) InvalidateNetwork(networkProfileID string) {
	if networkProfileID != "" {
		p.invalidateWhere(func(m ConnPoolMeta) bool { return m.NetworkProfileID == networkProfileID })
	}
}

// InvalidateCredential closes and removes all idle connections using credentialID.
func (p *ConnPool) InvalidateCredential(credentialID string) {
	if credentialID != "" {
		p.invalidateWhere(func(m ConnPoolMeta) bool { return m.CredentialID == credentialID })
	}
}

// InvalidateAll closes and removes all idle pooled connections.
func (p *ConnPool) InvalidateAll() {
	p.invalidateWhere(func(ConnPoolMeta) bool { return true })
}

// Stats returns current idle count and cumulative hit/miss/discard/eviction counters.
func (p *ConnPool) Stats() ConnPoolStats {
	if p == nil {
		return ConnPoolStats{}
	}
	p.mu.Lock()
	idleCount := p.totalIdleLocked()
	p.mu.Unlock()
	return ConnPoolStats{
		IdleConns: idleCount,
		Hits:      p.hits.Load(),
		Misses:    p.misses.Load(),
		Discards:  p.discards.Load(),
		Evictions: p.evictions.Load(),
	}
}

// Close stops background reaping and closes every idle pooled connection.
func (p *ConnPool) Close() error {
	if p == nil {
		return nil
	}
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.closed = true
		var all []*idleConn
		for k, list := range p.idle {
			all = append(all, list...)
			delete(p.idle, k)
		}
		p.mu.Unlock()

		close(p.stopReaper)
		for _, e := range all {
			_ = e.conn.Close()
		}
		p.wg.Wait()
	})
	return nil
}

type pooledConn struct {
	pool      *ConnPool
	inner     Conn
	meta      ConnPoolMeta
	createdAt time.Time

	poisoned atomic.Bool
	mu       sync.Mutex
	finished bool
	closeErr error
}

func (c *pooledConn) Capabilities() *types.ServerCapabilities {
	if da, ok := c.inner.(DialectAwareConn); ok {
		return da.Capabilities()
	}
	return nil
}

type pooledSchemaConn struct {
	*pooledConn
	si SchemaInspector
}

func (c *pooledSchemaConn) ListTables(ctx context.Context, opts SchemaListOpts) (*types.SchemaListResult, error) {
	res, err := c.si.ListTables(ctx, opts)
	if err != nil && ctx.Err() != nil {
		c.poisoned.Store(true)
	}
	return res, err
}

func (c *pooledSchemaConn) DescribeTable(ctx context.Context, name string) (*types.TableSchema, error) {
	res, err := c.si.DescribeTable(ctx, name)
	if err != nil && ctx.Err() != nil {
		c.poisoned.Store(true)
	}
	return res, err
}

func (c *pooledConn) Ping(ctx context.Context) (types.PingResult, error) {
	res, err := c.inner.Ping(ctx)
	if err != nil || !res.Reachable {
		c.poisoned.Store(true)
	}
	return res, err
}

func (c *pooledConn) ListDatabases(ctx context.Context) ([]string, error) {
	dbs, err := c.inner.ListDatabases(ctx)
	if err != nil && ctx.Err() != nil {
		c.poisoned.Store(true)
	}
	return dbs, err
}

func (c *pooledConn) Preflight(ctx context.Context, raw string, opts PreflightOpts) (*types.PreflightReport, error) {
	rep, err := c.inner.Preflight(ctx, raw, opts)
	if err != nil && ctx.Err() != nil {
		c.poisoned.Store(true)
	}
	return rep, err
}

func (c *pooledConn) Execute(ctx context.Context, raw string, opts ExecOpts) (*types.ExecResult, error) {
	res, err := c.inner.Execute(ctx, raw, opts)
	if err != nil && ctx.Err() != nil {
		c.poisoned.Store(true)
	}
	return res, err
}

func (c *pooledConn) CancelAndDiscard() error {
	c.poisoned.Store(true)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.finished {
		return c.closeErr
	}
	c.finished = true
	c.pool.discards.Add(1)
	c.closeErr = c.inner.CancelAndDiscard()
	return c.closeErr
}

func (c *pooledConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.finished {
		return c.closeErr
	}
	c.finished = true

	if c.poisoned.Load() || time.Since(c.createdAt) >= c.pool.maxAgeFor(c.meta.CredKind) {
		c.pool.discards.Add(1)
		c.closeErr = c.inner.Close()
		return c.closeErr
	}

	if resetter, ok := c.inner.(SessionResetter); ok {
		resetCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		err := resetter.ResetSession(resetCtx)
		cancel()
		if err != nil {
			c.pool.discards.Add(1)
			c.closeErr = c.inner.Close()
			return c.closeErr
		}
	}

	entry := &idleConn{
		conn:      c.inner,
		meta:      c.meta,
		createdAt: c.createdAt,
		lastUsed:  time.Now(),
	}
	if !c.pool.put(entry) {
		c.pool.discards.Add(1)
		c.closeErr = c.inner.Close()
		return c.closeErr
	}
	return nil
}

func boundedSubContext(parent context.Context, maxDur time.Duration) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	if dl, ok := parent.Deadline(); ok {
		if rem := time.Until(dl); rem > 0 && rem < maxDur {
			return context.WithTimeout(parent, rem)
		}
	}
	return context.WithTimeout(parent, maxDur)
}
