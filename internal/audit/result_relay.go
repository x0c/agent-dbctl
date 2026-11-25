package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/x0c/agent-dbctl/internal/types"
)

// ResultRelay abstracts ephemeral operation result caching (in-memory, Redis, or shared DB table).
type ResultRelay interface {
	PutResult(ctx context.Context, opID string, res *types.ExecResult) error
	GetResult(ctx context.Context, opID string) (*types.ExecResult, bool, error)
	DeleteResult(ctx context.Context, opID string) error
	Start(ctx context.Context)
	Wait()
	Close() error
}

// MemoryResultRelay wraps the bounded in-memory ResultSlotStore.
type MemoryResultRelay struct {
	Store *ResultSlotStore
}

// NewMemoryResultRelay constructs an in-memory ResultRelay.
func NewMemoryResultRelay(ttl time.Duration) *MemoryResultRelay {
	return &MemoryResultRelay{Store: NewResultSlotStore(ttl)}
}

func (m *MemoryResultRelay) PutResult(_ context.Context, opID string, res *types.ExecResult) error {
	m.Store.Put(opID, res)
	return nil
}

func (m *MemoryResultRelay) GetResult(_ context.Context, opID string) (*types.ExecResult, bool, error) {
	res, ok := m.Store.Get(opID)
	return res, ok, nil
}

func (m *MemoryResultRelay) DeleteResult(_ context.Context, opID string) error {
	m.Store.Delete(opID)
	return nil
}

func (m *MemoryResultRelay) Start(ctx context.Context) { m.Store.Start(ctx) }
func (m *MemoryResultRelay) Wait()                   { m.Store.Wait() }
func (m *MemoryResultRelay) Close() error            { return nil }

// DBResultStore defines the minimal DB persistence contract for shared operation_results caching.
type DBResultStore interface {
	PutOperationResult(ctx context.Context, opID string, raw []byte, expiresAtUTC string) error
	GetOperationResult(ctx context.Context, opID string) ([]byte, bool, error)
	PurgeExpiredOperationResults(ctx context.Context) error
}

// DBResultRelay stores ephemeral ExecResults in operation_results (outside audit_logs) for multi-replica deployments without Redis.
type DBResultRelay struct {
	db       DBResultStore
	ttl      time.Duration
	maxBytes int64
	wg       sync.WaitGroup
}

// NewDBResultRelay creates a DB-backed ResultRelay with wall-clock TTL cleanup.
func NewDBResultRelay(db DBResultStore, ttl time.Duration, maxBytes int64) *DBResultRelay {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	if maxBytes <= 0 {
		maxBytes = defaultMaxTotalBytes
	}
	return &DBResultRelay{db: db, ttl: ttl, maxBytes: maxBytes}
}

func (r *DBResultRelay) PutResult(ctx context.Context, opID string, res *types.ExecResult) error {
	if res == nil || opID == "" {
		return nil
	}
	raw, err := json.Marshal(res)
	if err != nil {
		return err
	}
	if int64(len(raw)) > r.maxBytes {
		return nil
	}
	exp := time.Now().UTC().Add(r.ttl).Format(time.RFC3339Nano)
	return r.db.PutOperationResult(ctx, opID, raw, exp)
}

func (r *DBResultRelay) GetResult(ctx context.Context, opID string) (*types.ExecResult, bool, error) {
	raw, ok, err := r.db.GetOperationResult(ctx, opID)
	if err != nil || !ok {
		return nil, false, err
	}
	var res types.ExecResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, false, err
	}
	return &res, true, nil
}

func (r *DBResultRelay) DeleteResult(_ context.Context, _ string) error { return nil }

func (r *DBResultRelay) Start(ctx context.Context) {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = r.db.PurgeExpiredOperationResults(ctx)
			}
		}
	}()
}

func (r *DBResultRelay) Wait()        { r.wg.Wait() }
func (r *DBResultRelay) Close() error { return nil }

// RedisResultRelay stores ephemeral ExecResults in Redis with TTL for multi-replica deployments.
type RedisResultRelay struct {
	client   *redis.Client
	ttl      time.Duration
	maxBytes int64
}

// NewRedisResultRelay parses redisURL and constructs a RedisResultRelay.
func NewRedisResultRelay(redisURL string, ttl time.Duration, maxBytes int64) (*RedisResultRelay, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("parse redis url: %w", err)
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	if maxBytes <= 0 {
		maxBytes = defaultMaxTotalBytes
	}
	return &RedisResultRelay{
		client:   redis.NewClient(opts),
		ttl:      ttl,
		maxBytes: maxBytes,
	}, nil
}

func redisResultKey(opID string) string {
	return "adbctl:result:" + opID
}

func (r *RedisResultRelay) PutResult(ctx context.Context, opID string, res *types.ExecResult) error {
	if res == nil || opID == "" {
		return nil
	}
	raw, err := json.Marshal(res)
	if err != nil {
		return err
	}
	if int64(len(raw)) > r.maxBytes {
		return nil
	}
	return r.client.Set(ctx, redisResultKey(opID), raw, r.ttl).Err()
}

func (r *RedisResultRelay) GetResult(ctx context.Context, opID string) (*types.ExecResult, bool, error) {
	raw, err := r.client.Get(ctx, redisResultKey(opID)).Bytes()
	if err == redis.Nil {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var res types.ExecResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, false, err
	}
	return &res, true, nil
}

func (r *RedisResultRelay) DeleteResult(ctx context.Context, opID string) error {
	return r.client.Del(ctx, redisResultKey(opID)).Err()
}

func (r *RedisResultRelay) Start(context.Context) {}
func (r *RedisResultRelay) Wait()               {}
func (r *RedisResultRelay) Close() error        { return r.client.Close() }
