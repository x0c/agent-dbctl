package audit_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/x0c/agent-dbctl/internal/audit"
	"github.com/x0c/agent-dbctl/internal/types"
)

func TestResultSlotEvictionAndDelete(t *testing.T) {
	store := audit.NewResultSlotStoreWithLimits(time.Minute, 2, 250)

	store.Put("op1", &types.ExecResult{ReturnedBytes: 100, ReturnedRows: 1})
	time.Sleep(5 * time.Millisecond)
	store.Put("op2", &types.ExecResult{ReturnedBytes: 100, ReturnedRows: 2})
	if st := store.Stats(); st.Count != 2 || st.TotalBytes != 200 {
		t.Fatalf("expected 2 slots / 200 bytes, got %+v", st)
	}

	// Inserting op3 should evict oldest (op1) due to both slot cap (2) and byte cap (250).
	time.Sleep(5 * time.Millisecond)
	store.Put("op3", &types.ExecResult{ReturnedBytes: 100, ReturnedRows: 3})
	if _, ok := store.Get("op1"); ok {
		t.Fatalf("expected op1 to be evicted")
	}
	if _, ok := store.Get("op2"); !ok {
		t.Fatalf("expected op2 to remain")
	}
	if _, ok := store.Get("op3"); !ok {
		t.Fatalf("expected op3 to be present")
	}

	// Byte-only eviction when maxSlots is generous.
	byteStore := audit.NewResultSlotStoreWithLimits(time.Minute, 10, 150)
	byteStore.Put("a", &types.ExecResult{ReturnedBytes: 80})
	time.Sleep(5 * time.Millisecond)
	byteStore.Put("b", &types.ExecResult{ReturnedBytes: 80})
	if _, ok := byteStore.Get("a"); ok {
		t.Fatalf("expected 'a' evicted by byte budget")
	}
	if st := byteStore.Stats(); st.Count != 1 || st.TotalBytes != 80 {
		t.Fatalf("unexpected byteStore stats: %+v", st)
	}

	// Single item exceeding total budget is skipped cleanly.
	byteStore.Put("huge", &types.ExecResult{ReturnedBytes: 999})
	if _, ok := byteStore.Get("huge"); ok {
		t.Fatalf("expected oversized result not to be cached")
	}

	byteStore.Delete("b")
	if st := byteStore.Stats(); st.Count != 0 || st.TotalBytes != 0 {
		t.Fatalf("expected empty stats after Delete, got %+v", st)
	}
}

func TestResultSlotTTLExpiryAndConcurrency(t *testing.T) {
	store := audit.NewResultSlotStoreWithLimits(25*time.Millisecond, 32, 1<<20)
	store.Put("ttl_op", &types.ExecResult{ReturnedBytes: 64})
	if _, ok := store.Get("ttl_op"); !ok {
		t.Fatalf("expected immediate Get hit")
	}
	time.Sleep(40 * time.Millisecond)
	if _, ok := store.Get("ttl_op"); ok {
		t.Fatalf("expected TTL expiry miss")
	}
	if st := store.Stats(); st.Count != 0 || st.TotalBytes != 0 {
		t.Fatalf("expected expired entry purged from stats, got %+v", st)
	}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			id := fmt.Sprintf("op_%d", idx)
			store.Put(id, &types.ExecResult{ReturnedBytes: 128})
			_, _ = store.Get(id)
			_ = store.Stats()
			store.Delete(id)
		}(i)
	}
	wg.Wait()
}
