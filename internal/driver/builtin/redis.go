package builtin

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/x0c/agent-dbctl/internal/classify"
	"github.com/x0c/agent-dbctl/internal/driver"
	"github.com/x0c/agent-dbctl/internal/types"
)

// RedisDriver implements Redis (5/6/7) and Valkey support (standalone & cluster) using go-redis/v9.
type RedisDriver struct{}

func (d *RedisDriver) Metadata() types.DriverMetadata {
	return types.DriverMetadata{
		ID:           "builtin-redis",
		Engine:       "redis",
		DisplayName:  "Redis",
		Family:       types.FamilyKV,
		Tier:         "builtin",
		Version:      "1.1.0",
		Capabilities: []string{"ping", "list_databases", "preflight", "execute"},
		Verified:     true,
		Labels:       map[string]string{"en": "Redis", "zh": "Redis"},
	}
}

func (d *RedisDriver) Classify(_ context.Context, raw string) (types.Classification, error) {
	return classify.Classify("redis", raw), nil
}

func (d *RedisDriver) Open(ctx context.Context, cfg driver.ConnectionConfig) (driver.Conn, error) {
	uopts, isCluster, err := buildRedisOptions(cfg)
	if err != nil {
		return nil, err
	}
	client := redis.NewUniversalClient(uopts)
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, err
	}
	return &redisConn{
		client:    client,
		cluster:   isCluster,
		cfg:       cfg,
		closeHook: driver.CloseOnce(cfg.CloseHook),
	}, nil
}

func buildRedisOptions(cfg driver.ConnectionConfig) (*redis.UniversalOptions, bool, error) {
	port := cfg.Port
	if port <= 0 {
		port = 6379
	}
	host := strings.TrimSpace(cfg.Host)
	if host == "" {
		host = "127.0.0.1"
	}
	var addrs []string
	for _, h := range strings.Split(host, ",") {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(h); err == nil {
			addrs = append(addrs, h)
		} else {
			addrs = append(addrs, net.JoinHostPort(h, strconv.Itoa(port)))
		}
	}

	dbIdx := 0
	if cfg.DatabaseName != "" {
		if n, err := strconv.Atoi(cfg.DatabaseName); err == nil && n >= 0 {
			dbIdx = n
		}
	}

	protocol := 3
	if p := strings.TrimSpace(cfg.Params["protocol"]); p != "" {
		switch p {
		case "2", "resp2", "RESP2":
			protocol = 2
		case "3", "resp3", "RESP3":
			protocol = 3
		default:
			return nil, false, fmt.Errorf("unsupported redis protocol %q (expected 2 or 3)", p)
		}
	}

	dialTimeout := 10 * time.Second
	if dt := strings.TrimSpace(cfg.Params["dial_timeout"]); dt != "" {
		if d, err := parseDurationOrSeconds(dt); err == nil && d > 0 {
			dialTimeout = d
		}
	}
	readTimeout := 15 * time.Second
	if rt := strings.TrimSpace(cfg.Params["read_timeout"]); rt != "" {
		if d, err := parseDurationOrSeconds(rt); err == nil && d > 0 {
			readTimeout = d
		}
	}

	isCluster := len(addrs) > 1 || strings.EqualFold(strings.TrimSpace(cfg.Params["cluster"]), "true") || strings.TrimSpace(cfg.Params["cluster"]) == "1"
	readOnlyReplica := cfg.ReadOnly && isCluster
	if ro := strings.TrimSpace(cfg.Params["read_only"]); ro != "" {
		readOnlyReplica = strings.EqualFold(ro, "true") || ro == "1"
	}

	uopts := &redis.UniversalOptions{
		Addrs:       addrs,
		ClientName:  strings.TrimSpace(cfg.Params["client_name"]),
		Username:    cfg.Credential.Username,
		Password:    cfg.Credential.Secret,
		DB:          dbIdx,
		Protocol:    protocol,
		ReadOnly:    readOnlyReplica,
		TLSConfig:   cfg.TLSConfig,
		DialTimeout: dialTimeout,
		ReadTimeout: readTimeout,
	}
	if cfg.DialContext != nil {
		uopts.Dialer = cfg.DialContext
	}
	return uopts, isCluster, nil
}

type redisConn struct {
	client    redis.UniversalClient
	cluster   bool
	cfg       driver.ConnectionConfig
	closeHook func() error
	closeOnce sync.Once
	closeErr  error
}

func (c *redisConn) Ping(ctx context.Context) (types.PingResult, error) {
	start := time.Now()
	if err := c.client.Ping(ctx).Err(); err != nil {
		return types.PingResult{Engine: "redis", Reachable: false, LatencyMs: time.Since(start).Milliseconds(), Error: err.Error()}, err
	}
	lat := time.Since(start).Milliseconds()

	// Best-effort INFO server; ACL-restricted or serverless Redis/Valkey may deny INFO while allowing PING.
	ver := ""
	if info, err := c.client.Info(ctx, "server").Result(); err == nil {
		for _, line := range strings.Split(info, "\n") {
			if strings.HasPrefix(line, "redis_version:") {
				ver = strings.TrimSpace(strings.TrimPrefix(line, "redis_version:"))
				break
			}
		}
	}
	return types.PingResult{Engine: "redis", Reachable: true, ServerVersion: ver, LatencyMs: lat}, nil
}

func (c *redisConn) ListDatabases(ctx context.Context) ([]string, error) {
	if c.cluster {
		return []string{"0"}, nil
	}
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

	if len(cmds) == 1 {
		ifaces := make([]any, len(cmds[0]))
		for i, a := range cmds[0] {
			ifaces[i] = a
		}
		val, err := c.client.Do(ctx, ifaces...).Result()
		if err != nil && err != redis.Nil {
			return nil, err
		}
		if err == redis.Nil {
			val = nil
		}
		norm := normalizeRedisValue(val)
		kv, returnedRows := capRedisSingleResult(norm, &buf)
		b, _ := json.Marshal(kv)
		return &types.ExecResult{
			Family:        types.FamilyKV,
			KVResult:      kv,
			FetchedRows:   buf.FetchedRows,
			ReturnedRows:  returnedRows,
			ReturnedBytes: int64(len(b)),
			Truncated:     buf.Truncated,
			CutoffReason:  buf.CutoffReason,
			LatencyMs:     time.Since(start).Milliseconds(),
		}, nil
	}

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
		norm := normalizeRedisValue(val)
		if buf.TryAcceptRow(norm) {
			results = append(results, norm)
		} else if buf.Truncated {
			break
		}
	}

	b, _ := json.Marshal(results)
	return &types.ExecResult{
		Family:        types.FamilyKV,
		KVResult:      results,
		FetchedRows:   buf.FetchedRows,
		ReturnedRows:  len(results),
		ReturnedBytes: int64(len(b)),
		Truncated:     buf.Truncated,
		CutoffReason:  buf.CutoffReason,
		LatencyMs:     time.Since(start).Milliseconds(),
	}, nil
}

// capRedisSingleResult bounds large single-command slices/maps (e.g. LRANGE/HGETALL/KEYS)
// by RowBuffer so --max-rows and --max-bytes apply consistently to collection replies.
func capRedisSingleResult(norm any, buf *driver.RowBuffer) (any, int) {
	switch x := norm.(type) {
	case []any:
		out := make([]any, 0, len(x))
		for _, item := range x {
			if buf.TryAcceptRow(item) {
				out = append(out, item)
			} else if buf.Truncated {
				break
			}
		}
		return out, len(out)
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, v := range x {
			entry := map[string]any{k: v}
			if buf.TryAcceptRow(entry) {
				out[k] = v
			} else if buf.Truncated {
				break
			}
		}
		return out, len(out)
	default:
		if buf.TryAcceptRow(norm) {
			return norm, 1
		}
		return nil, 0
	}
}

// normalizeRedisValue converts RESP3 map[any]any and non-finite floats into JSON-safe values.
func normalizeRedisValue(v any) any {
	switch x := v.(type) {
	case nil:
		return nil
	case map[any]any:
		m := make(map[string]any, len(x))
		for k, val := range x {
			m[fmt.Sprint(k)] = normalizeRedisValue(val)
		}
		return m
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, val := range x {
			m[k] = normalizeRedisValue(val)
		}
		return m
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = normalizeRedisValue(item)
		}
		return out
	case float64:
		if math.IsNaN(x) {
			return "NaN"
		}
		if math.IsInf(x, 1) {
			return "Infinity"
		}
		if math.IsInf(x, -1) {
			return "-Infinity"
		}
		return x
	default:
		return x
	}
}

func (c *redisConn) CancelAndDiscard() error {
	return c.Close()
}

func (c *redisConn) Close() error {
	c.closeOnce.Do(func() {
		if c.closeHook != nil {
			_ = c.closeHook()
		}
		c.closeErr = c.client.Close()
	})
	return c.closeErr
}
