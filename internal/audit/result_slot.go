package audit

import (
	"context"
	"sync"
	"time"

	"github.com/x0c/agent-dbctl/internal/types"
)

// ResultSlotStore holds query result payloads in memory with wall-clock TTL so large
// data rows never bloat or linger in the SQLite audit database.
type ResultSlotStore struct {
	ttl   time.Duration
	mu    sync.RWMutex
	slots map[string]resultEntry
	wg    sync.WaitGroup
}

type resultEntry struct {
	result    *types.ExecResult
	expiresAt time.Time // stripped monotonic clock via Round(0)
}

// NewResultSlotStore creates a TTL-bounded in-memory result relay.
func NewResultSlotStore(ttl time.Duration) *ResultSlotStore {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &ResultSlotStore{
		ttl:   ttl,
		slots: make(map[string]resultEntry),
	}
}

// Start launches background cleanup tracked by WaitGroup.
func (s *ResultSlotStore) Start(ctx context.Context) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.PurgeExpired()
			}
		}
	}()
}

// Wait blocks until background cleanup exits.
func (s *ResultSlotStore) Wait() {
	s.wg.Wait()
}

// Put stores a result slot using wall-clock TTL.
func (s *ResultSlotStore) Put(opID string, res *types.ExecResult) {
	if res == nil {
		return
	}
	now := time.Now().Round(0)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.slots[opID] = resultEntry{
		result:    res,
		expiresAt: now.Add(s.ttl),
	}
}

// Get retrieves a non-expired result slot.
func (s *ResultSlotStore) Get(opID string) (*types.ExecResult, bool) {
	now := time.Now().Round(0)
	s.mu.RLock()
	entry, ok := s.slots[opID]
	s.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if now.After(entry.expiresAt) {
		s.mu.Lock()
		if cur, exists := s.slots[opID]; exists && now.After(cur.expiresAt) {
			delete(s.slots, opID)
		}
		s.mu.Unlock()
		return nil, false
	}
	return entry.result, true
}

// PurgeExpired removes all expired slots.
func (s *ResultSlotStore) PurgeExpired() {
	now := time.Now().Round(0)
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.slots {
		if now.After(v.expiresAt) {
			delete(s.slots, k)
		}
	}
}
