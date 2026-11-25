package driver_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/x0c/agent-dbctl/internal/driver"
	"github.com/x0c/agent-dbctl/internal/types"
)

func TestRowBufferMaxRowsAndLookahead(t *testing.T) {
	buf := driver.RowBuffer{MaxRows: 2, MaxBytes: 1024}
	if !buf.TryAcceptRow([]any{1, "a"}) {
		t.Fatal("row 1 should be accepted")
	}
	if !buf.TryAcceptRow([]any{2, "b"}) {
		t.Fatal("row 2 should be accepted")
	}
	if buf.TryAcceptRow([]any{3, "c"}) {
		t.Fatal("row 3 should trigger max_rows truncation")
	}
	if !buf.Truncated || buf.CutoffReason != "max_rows" {
		t.Fatalf("unexpected truncation state: %+v", buf)
	}
	for i := 0; i < 999; i++ {
		if buf.TryAcceptRow([]any{i}) {
			t.Fatal("truncated buffer must reject further rows")
		}
	}
	if !buf.ShouldStopLookahead() {
		t.Fatalf("expected ShouldStopLookahead after 1000 post-truncation rows (lookahead=%d)", buf.LookaheadRows)
	}
}

func TestRowBufferMaxBytesWithUnlimitedRows(t *testing.T) {
	buf := driver.RowBuffer{MaxRows: 0, MaxBytes: 25}
	if !buf.TryAcceptRow([]any{"01234567890123456789"}) {
		t.Fatal("first row should always be accepted")
	}
	if buf.TryAcceptRow([]any{"0123456789"}) {
		t.Fatal("second row should exceed MaxBytes")
	}
	if !buf.Truncated || buf.CutoffReason != "max_bytes" {
		t.Fatalf("expected max_bytes cutoff, got %+v", buf)
	}
	if buf.LookaheadRows != 1 {
		t.Fatalf("expected LookaheadRows=1, got %d", buf.LookaheadRows)
	}
}

func TestCloseOnceIdempotent(t *testing.T) {
	var calls atomic.Int32
	fn := driver.CloseOnce(func() error {
		calls.Add(1)
		return errors.New("boom")
	})
	for i := 0; i < 5; i++ {
		if err := fn(); err == nil || err.Error() != "boom" {
			t.Fatalf("expected boom error, got %v", err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("expected 1 underlying close call, got %d", calls.Load())
	}
}

type fakeConn struct {
	discarded atomic.Int32
}

func (f *fakeConn) Ping(context.Context) (types.PingResult, error) { return types.PingResult{}, nil }
func (f *fakeConn) ListDatabases(context.Context) ([]string, error) { return nil, nil }
func (f *fakeConn) Preflight(context.Context, string, driver.PreflightOpts) (*types.PreflightReport, error) {
	return nil, nil
}
func (f *fakeConn) Execute(context.Context, string, driver.ExecOpts) (*types.ExecResult, error) {
	return nil, nil
}
func (f *fakeConn) CancelAndDiscard() error {
	f.discarded.Add(1)
	return nil
}
func (f *fakeConn) Close() error { return nil }

func TestExecuteWithCancelGuardDiscardsOnCancel(t *testing.T) {
	conn := &fakeConn{}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, err := driver.ExecuteWithCancelGuard(ctx, conn, func(cctx context.Context) (int, error) {
		<-cctx.Done()
		time.Sleep(50 * time.Millisecond)
		return 0, cctx.Err()
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded, got %v", err)
	}
	if conn.discarded.Load() == 0 {
		t.Fatal("expected CancelAndDiscard to be called on timeout")
	}

	// Even if fn returns immediately on ctx error, CancelAndDiscard must still fire.
	conn2 := &fakeConn{}
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	_, _ = driver.ExecuteWithCancelGuard(ctx2, conn2, func(cctx context.Context) (int, error) {
		return 0, cctx.Err()
	})
	if conn2.discarded.Load() == 0 {
		t.Fatal("expected CancelAndDiscard when ctx is already cancelled")
	}
}
