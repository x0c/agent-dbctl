package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

const (
	pgEventChannel    = "agent_dbctl_events"
	redisEventChannel = "adbctl:events"
)

// EventBus fans out daemon events locally or across replicas.
type EventBus interface {
	Publish(ctx context.Context, ev Event) error
	Start(ctx context.Context, onEvent func(Event)) error
	Close() error
}

// MemoryEventBus delivers events strictly inside the current process.
type MemoryEventBus struct {
	mu      sync.RWMutex
	handler func(Event)
}

func NewMemoryEventBus() *MemoryEventBus {
	return &MemoryEventBus{}
}

func (b *MemoryEventBus) Start(_ context.Context, onEvent func(Event)) error {
	b.mu.Lock()
	b.handler = onEvent
	b.mu.Unlock()
	return nil
}

func (b *MemoryEventBus) Publish(_ context.Context, ev Event) error {
	b.mu.RLock()
	h := b.handler
	b.mu.RUnlock()
	if h != nil {
		h(ev)
	}
	return nil
}

func (b *MemoryEventBus) Close() error { return nil }

// PostgresEventBus broadcasts events across server replicas via PostgreSQL LISTEN/NOTIFY.
type PostgresEventBus struct {
	pool   *pgxpool.Pool
	nodeID string
	wg     sync.WaitGroup
}

type busEnvelope struct {
	OriginNodeID string          `json:"origin_node_id"`
	Type         string          `json:"type"`
	Data         json.RawMessage `json:"data,omitempty"`
}

func NewPostgresEventBus(dsn, nodeID string) (*PostgresEventBus, error) {
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		return nil, fmt.Errorf("connect postgres event bus: %w", err)
	}
	return &PostgresEventBus{pool: pool, nodeID: nodeID}, nil
}

func (b *PostgresEventBus) Start(ctx context.Context, onEvent func(Event)) error {
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		for {
			if ctx.Err() != nil {
				return
			}
			_ = b.listenLoop(ctx, onEvent)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
		}
	}()
	return nil
}

func (b *PostgresEventBus) listenLoop(ctx context.Context, onEvent func(Event)) error {
	conn, err := b.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "LISTEN "+pgEventChannel); err != nil {
		return err
	}
	for {
		n, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			return err
		}
		var env busEnvelope
		if err := json.Unmarshal([]byte(n.Payload), &env); err != nil {
			continue
		}
		if env.OriginNodeID == b.nodeID {
			continue
		}
		var data any
		if len(env.Data) > 0 {
			_ = json.Unmarshal(env.Data, &data)
		}
		onEvent(Event{Type: env.Type, Data: data, RawData: env.Data})
	}
}

func (b *PostgresEventBus) Publish(ctx context.Context, ev Event) error {
	dataBytes, _ := json.Marshal(ev.Data)
	raw, err := json.Marshal(busEnvelope{
		OriginNodeID: b.nodeID,
		Type:         ev.Type,
		Data:         dataBytes,
	})
	if err != nil {
		return err
	}
	_, err = b.pool.Exec(ctx, `SELECT pg_notify($1, $2)`, pgEventChannel, string(raw))
	return err
}

func (b *PostgresEventBus) Close() error {
	b.wg.Wait()
	b.pool.Close()
	return nil
}

// RedisEventBus broadcasts events across server replicas via Redis Pub/Sub.
type RedisEventBus struct {
	client *redis.Client
	nodeID string
	wg     sync.WaitGroup
}

func NewRedisEventBus(redisURL, nodeID string) (*RedisEventBus, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("parse redis event bus url: %w", err)
	}
	return &RedisEventBus{client: redis.NewClient(opts), nodeID: nodeID}, nil
}

func (b *RedisEventBus) Start(ctx context.Context, onEvent func(Event)) error {
	sub := b.client.Subscribe(ctx, redisEventChannel)
	if _, err := sub.Receive(ctx); err != nil {
		_ = sub.Close()
		return err
	}
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		defer func() { _ = sub.Close() }()
		ch := sub.Channel()
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-ch:
				if !ok {
					return
				}
				var env busEnvelope
				if err := json.Unmarshal([]byte(msg.Payload), &env); err != nil {
					continue
				}
				if env.OriginNodeID == b.nodeID {
					continue
				}
				var data any
				if len(env.Data) > 0 {
					_ = json.Unmarshal(env.Data, &data)
				}
				onEvent(Event{Type: env.Type, Data: data, RawData: env.Data})
			}
		}
	}()
	return nil
}

func (b *RedisEventBus) Publish(ctx context.Context, ev Event) error {
	dataBytes, _ := json.Marshal(ev.Data)
	raw, err := json.Marshal(busEnvelope{
		OriginNodeID: b.nodeID,
		Type:         ev.Type,
		Data:         dataBytes,
	})
	if err != nil {
		return err
	}
	return b.client.Publish(ctx, redisEventChannel, raw).Err()
}

func (b *RedisEventBus) Close() error {
	b.wg.Wait()
	return b.client.Close()
}
