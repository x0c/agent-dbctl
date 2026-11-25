package audit

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/x0c/agent-dbctl/internal/types"
)

const (
	defaultMaxSlots      = 64
	defaultMaxTotalBytes = 32 << 20 // 32 MiB
)

// ResultSlotStats summarizes current in-memory ResultSlot occupancy and configured caps.
type ResultSlotStats struct {
	Count         int   `json:"count"`
	TotalBytes    int64 `json:"total_bytes"`
	MaxSlots      int   `json:"max_slots"`
	MaxTotalBytes int64 `json:"max_total_bytes"`
}

// ResultSlotStore holds query result payloads in memory with wall-clock TTL and bounded
// slot/byte eviction so large data rows never bloat SQLite or exhaust daemon memory.
type ResultSlotStore struct {
	ttl           time.Duration
	maxSlots      int
	maxTotalBytes int64

	mu         sync.RWMutex
	slots      map[string]resultEntry
	totalBytes int64
	wg         sync.WaitGroup
}

type resultEntry struct {
	result     *types.ExecResult
	insertedAt time.Time
	expiresAt  time.Time // stripped monotonic clock via Round(0)
	byteSize   int64
}

// NewResultSlotStore creates a TTL-bounded in-memory result relay with default capacity limits.
func NewResultSlotStore(ttl time.Duration) *ResultSlotStore {
	return NewResultSlotStoreWithLimits(ttl, defaultMaxSlots, defaultMaxTotalBytes)
}

// NewResultSlotStoreWithLimits creates a bounded in-memory result relay with explicit slot and byte caps.
func NewResultSlotStoreWithLimits(ttl time.Duration, maxSlots int, maxTotalBytes int64) *ResultSlotStore {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	if maxSlots < 0 {
		maxSlots = 0
	}
	if maxTotalBytes < 0 {
		maxTotalBytes = 0
	}
	return &ResultSlotStore{
		ttl:           ttl,
		maxSlots:      maxSlots,
		maxTotalBytes: maxTotalBytes,
		slots:         make(map[string]resultEntry),
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

// Put stores a result slot using wall-clock TTL and evicts oldest entries when capacity caps are reached.
func (s *ResultSlotStore) Put(opID string, res *types.ExecResult) {
	if res == nil || opID == "" {
		return
	}
	size := res.ReturnedBytes
	if size <= 0 {
		size = estimateResultBytes(res)
	}
	now := time.Now().Round(0)

	s.mu.Lock()
	defer s.mu.Unlock()

	s.purgeExpiredLocked(now)

	if prev, exists := s.slots[opID]; exists {
		s.totalBytes -= prev.byteSize
		delete(s.slots, opID)
	}

	if s.maxTotalBytes > 0 && size > s.maxTotalBytes {
		// Single payload exceeds entire cache budget; skip caching in memory.
		return
	}

	for (s.maxSlots > 0 && len(s.slots) >= s.maxSlots) ||
		(s.maxTotalBytes > 0 && len(s.slots) > 0 && s.totalBytes+size > s.maxTotalBytes) {
		if !s.evictOldestLocked() {
			break
		}
	}

	s.slots[opID] = resultEntry{
		result:     res,
		insertedAt: now,
		expiresAt:  now.Add(s.ttl),
		byteSize:   size,
	}
	s.totalBytes += size
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
			s.totalBytes -= cur.byteSize
			delete(s.slots, opID)
		}
		s.mu.Unlock()
		return nil, false
	}
	return entry.result, true
}

// Delete removes a cached result slot if present.
func (s *ResultSlotStore) Delete(opID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, exists := s.slots[opID]; exists {
		s.totalBytes -= cur.byteSize
		delete(s.slots, opID)
	}
}

// Stats returns current slot occupancy and configured limits after purging expired entries.
func (s *ResultSlotStore) Stats() ResultSlotStats {
	now := time.Now().Round(0)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeExpiredLocked(now)
	return ResultSlotStats{
		Count:         len(s.slots),
		TotalBytes:    s.totalBytes,
		MaxSlots:      s.maxSlots,
		MaxTotalBytes: s.maxTotalBytes,
	}
}

// PurgeExpired removes all expired slots.
func (s *ResultSlotStore) PurgeExpired() {
	now := time.Now().Round(0)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeExpiredLocked(now)
}

func (s *ResultSlotStore) purgeExpiredLocked(now time.Time) {
	for k, v := range s.slots {
		if now.After(v.expiresAt) {
			s.totalBytes -= v.byteSize
			delete(s.slots, k)
		}
	}
	if s.totalBytes < 0 {
		s.totalBytes = 0
	}
}

func (s *ResultSlotStore) evictOldestLocked() bool {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for k, v := range s.slots {
		if first || v.insertedAt.Before(oldestTime) {
			oldestKey = k
			oldestTime = v.insertedAt
			first = false
		}
	}
	if first {
		return false
	}
	s.totalBytes -= s.slots[oldestKey].byteSize
	if s.totalBytes < 0 {
		s.totalBytes = 0
	}
	delete(s.slots, oldestKey)
	return true
}

func estimateResultBytes(res *types.ExecResult) int64 {
	b, err := json.Marshal(res)
	if err != nil {
		return 64
	}
	if len(b) == 0 {
		return 64
	}
	return int64(len(b))
}
