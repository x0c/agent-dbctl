package driver

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"sync"

	"github.com/x0c/agent-dbctl/internal/secrets"
	"github.com/x0c/agent-dbctl/internal/types"
)

// ConnectionConfig carries resolved endpoint, dialer, TLS, and credential info into a Driver.
type ConnectionConfig struct {
	Engine       string
	Host         string
	Port         int
	DatabaseName string
	Params       map[string]string
	ReadOnly     bool
	Credential      secrets.ResolvedSecret
	DialContext     func(ctx context.Context, network, addr string) (net.Conn, error)
	NeedsDialBridge bool
	TLSMode         string
	TLSConfig       *tls.Config
	CloseHook       func() error
}

// CloseOnce wraps fn so repeated Close/CancelAndDiscard calls invoke it at most once.
func CloseOnce(fn func() error) func() error {
	if fn == nil {
		return nil
	}
	var once sync.Once
	var closeErr error
	return func() error {
		once.Do(func() {
			closeErr = fn()
		})
		return closeErr
	}
}

// PreflightOpts governs non-mutating execution-plan checks.
type PreflightOpts struct {
	ExplainFormat string
}

// ExecOpts bounds execution rows, bytes, and timeout.
type ExecOpts struct {
	MaxRows  int
	MaxBytes int64
}

// Driver defines the engine-level contract (zero cross-dialect rewriting).
type Driver interface {
	Metadata() types.DriverMetadata
	Open(ctx context.Context, cfg ConnectionConfig) (Conn, error)
	Classify(ctx context.Context, raw string) (types.Classification, error)
}

// Conn represents an opened engine connection with explicit cancellation discard.
type Conn interface {
	Ping(ctx context.Context) (types.PingResult, error)
	ListDatabases(ctx context.Context) ([]string, error)
	Preflight(ctx context.Context, raw string, opts PreflightOpts) (*types.PreflightReport, error)
	Execute(ctx context.Context, raw string, opts ExecOpts) (*types.ExecResult, error)
	// CancelAndDiscard aborts any active operation and discards the underlying physical connection.
	CancelAndDiscard() error
	Close() error
}

// Registry stores built-in and dynamically loaded external plugin drivers.
type Registry struct {
	mu      sync.RWMutex
	drivers map[string]Driver
}

// NewRegistry creates a thread-safe driver registry.
func NewRegistry() *Registry {
	return &Registry{drivers: make(map[string]Driver)}
}

// Register adds or replaces a driver keyed by lowercase engine identifier.
func (r *Registry) Register(d Driver) {
	meta := d.Metadata()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.drivers[meta.Engine] = d
}

// ClearTier removes all drivers matching a tier (e.g. "plugin") prior to reload.
func (r *Registry) ClearTier(tier string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, d := range r.drivers {
		if d.Metadata().Tier == tier {
			delete(r.drivers, k)
		}
	}
}

// Get retrieves a registered driver by engine name.
func (r *Registry) Get(engine string) (Driver, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	d, ok := r.drivers[engine]
	return d, ok
}

// List returns metadata for all registered drivers sorted by tier and engine.
func (r *Registry) List() []types.DriverMetadata {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]types.DriverMetadata, 0, len(r.drivers))
	for _, d := range r.drivers {
		out = append(out, d.Metadata())
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Tier != out[j].Tier {
			return out[i].Tier < out[j].Tier
		}
		return out[i].Engine < out[j].Engine
	})
	return out
}

// RowBuffer enforces max_rows and max_bytes strictly on complete row/document boundaries.
type RowBuffer struct {
	MaxRows  int
	MaxBytes int64

	FetchedRows   int
	LookaheadRows int
	ReturnedBytes int64
	Truncated     bool
	CutoffReason  string
}

// TryAcceptRow checks whether adding one whole row fits within MaxRows and MaxBytes.
func (b *RowBuffer) TryAcceptRow(row any) bool {
	b.FetchedRows++
	if b.Truncated {
		b.LookaheadRows++
		return false
	}
	if b.MaxRows > 0 && b.FetchedRows > b.MaxRows {
		b.Truncated = true
		b.CutoffReason = "max_rows"
		b.LookaheadRows++
		return false
	}
	encoded, err := json.Marshal(row)
	if err != nil {
		encoded = []byte(fmt.Sprint(row))
	}
	size := int64(len(encoded))
	// Always allow at least 1 row if FetchedRows == 1 unless caller budget is 0, or check byte limit strictly after 1st row.
	if b.MaxBytes > 0 && b.ReturnedBytes+size > b.MaxBytes && b.FetchedRows > 1 {
		b.Truncated = true
		b.CutoffReason = "max_bytes"
		b.LookaheadRows++
		return false
	}
	b.ReturnedBytes += size
	return true
}

// ShouldStopLookahead returns true once bounded post-truncation row counting has been reached.
func (b *RowBuffer) ShouldStopLookahead() bool {
	return b.Truncated && b.LookaheadRows >= 1000
}

// ExecuteWithCancelGuard runs fn with ctx cancellation watching; on ctx cancel/timeout it invokes
// CancelAndDiscard so dirty physical connections are never reused.
func ExecuteWithCancelGuard[T any](ctx context.Context, conn Conn, fn func(context.Context) (T, error)) (T, error) {
	type outcome struct {
		val T
		err error
	}
	ch := make(chan outcome, 1)
	go func() {
		v, err := fn(ctx)
		ch <- outcome{val: v, err: err}
	}()

	select {
	case res := <-ch:
		if ctx.Err() != nil {
			_ = conn.CancelAndDiscard()
		}
		return res.val, res.err
	case <-ctx.Done():
		_ = conn.CancelAndDiscard()
		var zero T
		return zero, fmt.Errorf("execution aborted: %w", ctx.Err())
	}
}
