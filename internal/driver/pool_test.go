package driver

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/x0c/agent-dbctl/internal/secrets"
	"github.com/x0c/agent-dbctl/internal/types"
)

type fakePoolConn struct {
	id          int
	pingErr     atomic.Pointer[error]
	resetErr    atomic.Pointer[error]
	caps        *types.ServerCapabilities
	closed      atomic.Bool
	cancelled   atomic.Bool
	pingCalls   atomic.Int64
	resetCalls  atomic.Int64
	closeCalls  atomic.Int64
}

func (f *fakePoolConn) Capabilities() *types.ServerCapabilities {
	return f.caps
}

func (f *fakePoolConn) ResetSession(context.Context) error {
	f.resetCalls.Add(1)
	if ep := f.resetErr.Load(); ep != nil {
		return *ep
	}
	return nil
}

func (f *fakePoolConn) Ping(context.Context) (types.PingResult, error) {
	f.pingCalls.Add(1)
	if ep := f.pingErr.Load(); ep != nil {
		return types.PingResult{Reachable: false, Error: (*ep).Error()}, *ep
	}
	return types.PingResult{Engine: "postgres", Dialect: "postgres", Reachable: true}, nil
}

func (f *fakePoolConn) ListDatabases(context.Context) ([]string, error) {
	return []string{"app"}, nil
}

func (f *fakePoolConn) Preflight(context.Context, string, PreflightOpts) (*types.PreflightReport, error) {
	return &types.PreflightReport{Supported: true}, nil
}

func (f *fakePoolConn) Execute(context.Context, string, ExecOpts) (*types.ExecResult, error) {
	return &types.ExecResult{Family: types.FamilySQL}, nil
}

func (f *fakePoolConn) CancelAndDiscard() error {
	f.cancelled.Store(true)
	return f.Close()
}

func (f *fakePoolConn) Close() error {
	f.closed.Store(true)
	f.closeCalls.Add(1)
	return nil
}

func TestConnPoolReuseWriteBypassAndDiscard(t *testing.T) {
	pool := NewConnPool(ConnPoolConfig{
		IdleTTL:          5 * time.Second,
		MaxAge:           30 * time.Second,
		HealthCheckAfter: 10 * time.Second,
		ReapInterval:     5 * time.Second,
	})
	defer func() { _ = pool.Close() }()

	var nextID atomic.Int64
	var opened []*fakePoolConn
	var mu sync.Mutex

	openFn := func() (*fakePoolConn, func(context.Context) (Conn, error)) {
		return nil, func(context.Context) (Conn, error) {
			id := int(nextID.Add(1))
			fc := &fakePoolConn{
				id:   id,
				caps: &types.ServerCapabilities{Engine: "postgres", Dialect: "cockroachdb"},
			}
			mu.Lock()
			opened = append(opened, fc)
			mu.Unlock()
			return fc, nil
		}
	}

	roMeta := ConnPoolMeta{
		TargetID:         "tgt-1",
		InstanceID:       "inst-1",
		NetworkProfileID: "np-1",
		CredentialID:     "cred-1",
		CredKind:         types.CredKeychain,
		ReadOnly:         true,
	}
	roMeta.Key = BuildConnPoolKey(roMeta, ConnectionConfig{
		Engine:       "postgres",
		Host:         "db.internal",
		Port:         5432,
		DatabaseName: "app",
		Credential:   secrets.ResolvedSecret{Username: "ro", Secret: "pw"},
	}, "net-hash-1")

	_, open := openFn()
	// 1. Read-only acquire + close returns handle cleanly; second acquire reuses it.
	c1, err := pool.Acquire(context.Background(), roMeta, open)
	if err != nil {
		t.Fatalf("Acquire 1: %v", err)
	}
	if da, ok := c1.(DialectAwareConn); !ok || da.Capabilities().Dialect != "cockroachdb" {
		t.Fatalf("expected pooledConn to delegate DialectAwareConn")
	}
	if err := c1.Close(); err != nil {
		t.Fatalf("Close 1: %v", err)
	}
	c2, err := pool.Acquire(context.Background(), roMeta, open)
	if err != nil {
		t.Fatalf("Acquire 2: %v", err)
	}
	if st := pool.Stats(); st.Hits != 1 || st.Misses != 1 {
		t.Fatalf("expected Hits=1 Misses=1, got %+v", st)
	}
	if opened[0].resetCalls.Load() != 1 || opened[0].closed.Load() {
		t.Fatalf("expected ResetSession called once and conn kept open, got reset=%d closed=%v",
			opened[0].resetCalls.Load(), opened[0].closed.Load())
	}

	// 2. CancelAndDiscard discards physical conn permanently (even if Close runs afterwards).
	if err := c2.CancelAndDiscard(); err != nil {
		t.Fatalf("CancelAndDiscard: %v", err)
	}
	_ = c2.Close()
	if !opened[0].cancelled.Load() || !opened[0].closed.Load() {
		t.Fatalf("expected CancelAndDiscard to poison & close underlying conn")
	}
	if pool.Stats().Discards != 1 {
		t.Fatalf("expected Discards=1, got %+v", pool.Stats())
	}

	// 3. Failed ResetSession discards connection on Close.
	c3, err := pool.Acquire(context.Background(), roMeta, open)
	if err != nil {
		t.Fatalf("Acquire 3: %v", err)
	}
	resetErr := fmt.Errorf("dirty tx")
	opened[1].resetErr.Store(&resetErr)
	_ = c3.Close()
	if !opened[1].closed.Load() || pool.Stats().IdleConns != 0 {
		t.Fatalf("expected failed ResetSession to close & discard conn")
	}

	// 4. Write connections never pool.
	rwMeta := roMeta
	rwMeta.ReadOnly = false
	rwMeta.Key = BuildConnPoolKey(rwMeta, ConnectionConfig{Engine: "postgres", Host: "db.internal", Port: 5432}, "net-hash-1")
	w1, _ := pool.Acquire(context.Background(), rwMeta, open)
	_ = w1.Close()
	w2, _ := pool.Acquire(context.Background(), rwMeta, open)
	_ = w2.Close()
	if !opened[2].closed.Load() || !opened[3].closed.Load() {
		t.Fatalf("expected write connections to bypass pool and close immediately")
	}
}

func TestConnPoolHealthCheckExecProviderAndInvalidation(t *testing.T) {
	pool := NewConnPool(ConnPoolConfig{
		IdleTTL:            5 * time.Second,
		MaxAge:             5 * time.Second,
		ExecProviderMaxAge: 80 * time.Millisecond,
		HealthCheckAfter:   30 * time.Millisecond,
		ReapInterval:       5 * time.Second,
	})
	defer func() { _ = pool.Close() }()

	var nextID atomic.Int64
	var conns []*fakePoolConn
	openFn := func(context.Context) (Conn, error) {
		fc := &fakePoolConn{id: int(nextID.Add(1))}
		conns = append(conns, fc)
		return fc, nil
	}

	execMeta := ConnPoolMeta{
		TargetID:         "tgt-exec",
		InstanceID:       "inst-exec",
		NetworkProfileID: "np-exec",
		CredentialID:     "cred-exec",
		CredKind:         types.CredExecProvider,
		ReadOnly:         true,
		Key:              "exec-key",
	}

	c1, _ := pool.Acquire(context.Background(), execMeta, openFn)
	_ = c1.Close()

	// Wait past HealthCheckAfter; fail Ping -> should discard and open conn #2.
	time.Sleep(45 * time.Millisecond)
	badPing := fmt.Errorf("broken pipe")
	conns[0].pingErr.Store(&badPing)

	c2, _ := pool.Acquire(context.Background(), execMeta, openFn)
	if len(conns) != 2 || conns[0].pingCalls.Load() != 1 || !conns[0].closed.Load() {
		t.Fatalf("expected failed HealthCheckAfter ping to discard conn 0 and open conn 1")
	}

	// Wait past ExecProviderMaxAge -> Close discards instead of re-pooling expired token.
	time.Sleep(90 * time.Millisecond)
	_ = c2.Close()
	if !conns[1].closed.Load() || pool.Stats().IdleConns != 0 {
		t.Fatalf("expected expired exec_provider conn to be discarded on Close")
	}

	// Verify axis invalidation closes idle entries immediately.
	keychainMeta := execMeta
	keychainMeta.CredKind = types.CredKeychain
	keychainMeta.Key = "kc-key"
	c3, _ := pool.Acquire(context.Background(), keychainMeta, openFn)
	_ = c3.Close()
	if pool.Stats().IdleConns != 1 {
		t.Fatalf("expected IdleConns=1 before invalidation")
	}
	pool.InvalidateNetwork("np-exec")
	if pool.Stats().IdleConns != 0 || !conns[2].closed.Load() {
		t.Fatalf("expected InvalidateNetwork to close idle conn")
	}
}

func TestConnPoolConcurrentAcquireCloseInvalidateRace(t *testing.T) {
	pool := NewConnPool(ConnPoolConfig{
		MaxIdlePerKey:    4,
		MaxTotalIdle:     8,
		IdleTTL:          500 * time.Millisecond,
		HealthCheckAfter: 5 * time.Millisecond,
		ReapInterval:     20 * time.Millisecond,
	})
	defer func() { _ = pool.Close() }()

	meta := ConnPoolMeta{
		TargetID:         "tgt-race",
		InstanceID:       "inst-race",
		NetworkProfileID: "np-race",
		CredentialID:     "cred-race",
		CredKind:         types.CredKeychain,
		ReadOnly:         true,
		Key:              "race-key",
	}

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				conn, err := pool.Acquire(context.Background(), meta, func(context.Context) (Conn, error) {
					return &fakePoolConn{}, nil
				})
				if err != nil {
					return
				}
				_, _ = conn.Execute(context.Background(), "SELECT 1", ExecOpts{})
				if (worker+i)%7 == 0 {
					_ = conn.CancelAndDiscard()
				}
				_ = conn.Close()
				if i%5 == 0 {
					pool.InvalidateTarget("tgt-race")
				}
			}
		}(g)
	}
	wg.Wait()
}
