package driver

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/x0c/agent-dbctl/internal/classify"
	"github.com/x0c/agent-dbctl/internal/secrets"
	"github.com/x0c/agent-dbctl/internal/types"
)

// ConnectionConfig carries resolved endpoint, dialer, TLS, and credential info into a Driver.
type ConnectionConfig struct {
	Engine                 string
	Host                   string
	Port                   int
	DatabaseName           string
	Params                 map[string]string
	ReadOnly               bool
	Credential             secrets.ResolvedSecret
	DialContext            func(ctx context.Context, network, addr string) (net.Conn, error)
	NeedsDialBridge        bool
	TLSMode                string
	TLSConfig              *tls.Config
	CloseHook              func() error
	NegotiatedCapabilities *types.ServerCapabilities
}

// DialectAwareConn is optionally implemented by connections that cache negotiated server capabilities.
type DialectAwareConn interface {
	Capabilities() *types.ServerCapabilities
}

// SessionResetter is optionally implemented by connections to validate and reset session state before pool reuse.
type SessionResetter interface {
	ResetSession(ctx context.Context) error
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

// SchemaListOpts filters and bounds schema object enumeration.
type SchemaListOpts struct {
	Search string
	Limit  int
}

// SchemaInspector is optionally implemented by drivers supporting read-only schema introspection.
type SchemaInspector interface {
	ListTables(ctx context.Context, opts SchemaListOpts) (*types.SchemaListResult, error)
	DescribeTable(ctx context.Context, name string) (*types.TableSchema, error)
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
	r.drivers[strings.ToLower(strings.TrimSpace(meta.Engine))] = d
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

// Get retrieves a registered driver by exact engine name, falling back to compatible dialect aliases
// when no explicit plugin overrides the requested engine name.
func (r *Registry) Get(engine string) (Driver, bool) {
	key := strings.ToLower(strings.TrimSpace(engine))
	r.mu.RLock()
	defer r.mu.RUnlock()
	if d, ok := r.drivers[key]; ok {
		return d, true
	}
	if canonical := classify.CanonicalEngine(key); canonical != "" && canonical != key {
		if d, ok := r.drivers[canonical]; ok {
			return d, true
		}
	}
	return nil, false
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

var rowSizeBufPool = sync.Pool{
	New: func() any {
		return bytes.NewBuffer(make([]byte, 0, 512))
	},
}

// RecordLookahead advances FetchedRows and LookaheadRows for an already-truncated RowBuffer
// without marshaling or normalizing skipped rows.
func (b *RowBuffer) RecordLookahead() {
	b.FetchedRows++
	b.LookaheadRows++
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
	var size int64
	if b.MaxBytes > 0 {
		size = encodedRowByteSize(row)
		// Always allow at least 1 row if FetchedRows == 1 unless caller budget is 0, or check byte limit strictly after 1st row.
		if b.ReturnedBytes+size > b.MaxBytes && b.FetchedRows > 1 {
			b.Truncated = true
			b.CutoffReason = "max_bytes"
			b.LookaheadRows++
			return false
		}
	} else {
		size = encodedRowByteSize(row)
	}
	b.ReturnedBytes += size
	return true
}

func encodedRowByteSize(row any) int64 {
	if slice, ok := row.([]any); ok {
		if n, fastOK := fastJSONRowSliceSize(slice); fastOK {
			return n
		}
	}
	buf := rowSizeBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	enc := json.NewEncoder(buf)
	if err := enc.Encode(row); err == nil && buf.Len() > 0 {
		// json.Encoder.Encode appends '\n' after the exact json.Marshal output.
		n := int64(buf.Len() - 1)
		if buf.Cap() <= 64*1024 {
			rowSizeBufPool.Put(buf)
		}
		return n
	}
	if buf.Cap() <= 64*1024 {
		rowSizeBufPool.Put(buf)
	}
	return int64(len(fmt.Sprint(row)))
}

// fastJSONRowSliceSize computes the exact len(json.Marshal(slice)) with zero allocations
// for common SQL row slices containing nil, bool, integers, finite float64, and plain ASCII strings.
func fastJSONRowSliceSize(row []any) (int64, bool) {
	if row == nil {
		return 4, true // "null"
	}
	if len(row) == 0 {
		return 2, true // "[]"
	}
	var numScratch [32]byte
	total := int64(2 + len(row) - 1) // '[' + ']' + commas
	for _, v := range row {
		switch x := v.(type) {
		case nil:
			total += 4
		case bool:
			if x {
				total += 4
			} else {
				total += 5
			}
		case int:
			total += int64(len(strconv.AppendInt(numScratch[:0], int64(x), 10)))
		case int64:
			total += int64(len(strconv.AppendInt(numScratch[:0], x, 10)))
		case int32:
			total += int64(len(strconv.AppendInt(numScratch[:0], int64(x), 10)))
		case uint64:
			total += int64(len(strconv.AppendUint(numScratch[:0], x, 10)))
		case string:
			for i := 0; i < len(x); i++ {
				c := x[i]
				if c < 0x20 || c >= 0x80 || c == '"' || c == '\\' || c == '<' || c == '>' || c == '&' {
					return 0, false
				}
			}
			total += int64(2 + len(x))
		default:
			return 0, false
		}
	}
	return total, true
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
