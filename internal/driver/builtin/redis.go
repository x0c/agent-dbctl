package builtin

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/x0c/agent-dbctl/internal/classify"
	"github.com/x0c/agent-dbctl/internal/driver"
	"github.com/x0c/agent-dbctl/internal/types"
)

// RedisDriver implements Redis / Valkey support using official go-redis/v9.
type RedisDriver struct{}

func (d *RedisDriver) Metadata() types.DriverMetadata {
	return types.DriverMetadata{
		ID:           "builtin-redis",
		Engine:       "redis",
		DisplayName:  "Redis",
		Family:       types.FamilyKV,
		Tier:         "builtin",
		Version:      "1.0.0",
		Capabilities: []string{"ping", "list_databases", "preflight", "execute"},
		Verified:     true,
		Labels:       map[string]string{"en": "Redis", "zh": "Redis"},
	}
}

func (d *RedisDriver) Classify(_ context.Context, raw string) (types.Classification, error) {
	return classify.Classify("redis", raw), nil
}

func (d *RedisDriver) Open(ctx context.Context, cfg driver.ConnectionConfig) (driver.Conn, error) {
	port := cfg.Port
	if port <= 0 {
		port = 6379
	}
	dbIdx := 0
	if cfg.DatabaseName != "" {
		if n, err := strconv.Atoi(cfg.DatabaseName); err == nil && n >= 0 {
			dbIdx = n
		}
	}
	ropts := &redis.Options{
		Addr:        net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", port)),
		Username:    cfg.Credential.Username,
		Password:    cfg.Credential.Secret,
		DB:          dbIdx,
		TLSConfig:   cfg.TLSConfig,
		DialTimeout: 10 * time.Second,
		ReadTimeout: 15 * time.Second,
	}
	if cfg.DialContext != nil {
		ropts.Dialer = cfg.DialContext
	}
	client := redis.NewClient(ropts)
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, err
	}
	return &redisConn{client: client, cfg: cfg}, nil
}

type redisConn struct {
	client *redis.Client
	cfg    driver.ConnectionConfig
}

func (c *redisConn) Ping(ctx context.Context) (types.PingResult, error) {
	start := time.Now()
	info, err := c.client.Info(ctx, "server").Result()
	lat := time.Since(start).Milliseconds()
	if err != nil {
		return types.PingResult{Engine: "redis", Reachable: false, LatencyMs: lat, Error: err.Error()}, err
	}
	ver := ""
	for _, line := range strings.Split(info, "\n") {
		if strings.HasPrefix(line, "redis_version:") {
			ver = strings.TrimSpace(strings.TrimPrefix(line, "redis_version:"))
			break
		}
	}
	return types.PingResult{Engine: "redis", Reachable: true, ServerVersion: ver, LatencyMs: lat}, nil
}

func (c *redisConn) ListDatabases(ctx context.Context) ([]string, error) {
	count := 16
	res, err := c.client.ConfigGet(ctx, "databases").Result()
	if err == nil {
		if v, ok := res["databases"]; ok {
			if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 64 {
				count = n
			}
		}
	}
	out := make([]string, count)
	for i := 0; i < count; i++ {
		out[i] = strconv.Itoa(i)
	}
	return out, nil
}

func (c *redisConn) Preflight(_ context.Context, raw string, _ driver.PreflightOpts) (*types.PreflightReport, error) {
	cls := classify.Classify("redis", raw)
	return &types.PreflightReport{
		Supported:   false,
		Executed:    false,
		Format:      "redis_classification",
		PlanSummary: cls.Summary,
		Warnings:    cls.RiskFlags,
	}, nil
}

func (c *redisConn) Execute(ctx context.Context, raw string, opts driver.ExecOpts) (*types.ExecResult, error) {
	start := time.Now()
	cmds, err := classify.ParseRedisLines(raw)
	if err != nil {
		return nil, err
	}
	if len(cmds) == 0 {
		return nil, fmt.Errorf("no redis commands provided")
	}
	var results []any
	buf := driver.RowBuffer{MaxRows: opts.MaxRows, MaxBytes: opts.MaxBytes}

	for _, args := range cmds {
		ifaces := make([]any, len(args))
		for i, a := range args {
			ifaces[i] = a
		}
		val, err := c.client.Do(ctx, ifaces...).Result()
		if err != nil && err != redis.Nil {
			return nil, err
		}
		if err == redis.Nil {
			val = nil
		}
		if buf.TryAcceptRow(val) {
			results = append(results, val)
		} else if buf.Truncated {
			break
		}
	}

	var kv any
	if len(results) == 1 {
		kv = results[0]
	} else {
		kv = results
	}
	b, _ := json.Marshal(kv)
	return &types.ExecResult{
		Family:        types.FamilyKV,
		KVResult:      kv,
		FetchedRows:   buf.FetchedRows,
		ReturnedRows:  len(results),
		ReturnedBytes: int64(len(b)),
		Truncated:     buf.Truncated,
		CutoffReason:  buf.CutoffReason,
		LatencyMs:     time.Since(start).Milliseconds(),
	}, nil
}

func (c *redisConn) CancelAndDiscard() error {
	return c.Close()
}

func (c *redisConn) Close() error {
	if c.cfg.CloseHook != nil {
		_ = c.cfg.CloseHook()
	}
	return c.client.Close()
}
