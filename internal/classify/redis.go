package classify

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"github.com/x0c/agent-dbctl/internal/types"
)

var redisSafeReadCmds = map[string]bool{
	"PING": true, "ECHO": true, "INFO": true, "DBSIZE": true,
	"GET": true, "MGET": true, "STRLEN": true, "GETRANGE": true, "GETBIT": true, "BITCOUNT": true, "BITPOS": true,
	"EXISTS": true, "TYPE": true, "TTL": true, "PTTL": true, "EXPIRETIME": true, "PEXPIRETIME": true,
	"LLEN": true, "LINDEX": true, "LPOS": true,
	"SCARD": true, "SISMEMBER": true, "SMISMEMBER": true, "SRANDMEMBER": true,
	"ZCARD": true, "ZSCORE": true, "ZMSCORE": true, "ZCOUNT": true, "ZLEXCOUNT": true, "ZRANK": true, "ZREVRANK": true,
	"HGET": true, "HMGET": true, "HEXISTS": true, "HLEN": true, "HSTRLEN": true, "HRANDFIELD": true,
	"PFCOUNT": true, "XLEN": true,
	"SCAN": true, "HSCAN": true, "SSCAN": true, "ZSCAN": true,
	"COMMAND": true, "CLIENT": true, "MEMORY": true,
}

var redisHighCostReadCmds = map[string]bool{
	"KEYS": true, "HGETALL": true, "HKEYS": true, "HVALS": true,
	"SMEMBERS": true, "SINTER": true, "SUNION": true, "SDIFF": true, "SINTERCARD": true,
	"ZINTER": true, "ZUNION": true, "ZDIFF": true, "ZINTERCARD": true,
	"SORT_RO": true, "MONITOR": true, "SLOWLOG": true, "DUMP": true, "RANDOMKEY": true,
	"XRANGE": true, "XREVRANGE": true, "XPENDING": true, "XREAD": true,
}

var redisWriteCmds = map[string]bool{
	"SET": true, "SETEX": true, "PSETEX": true, "SETNX": true, "MSET": true, "MSETNX": true, "GETSET": true, "GETDEL": true, "GETEX": true,
	"INCR": true, "INCRBY": true, "INCRBYFLOAT": true, "DECR": true, "DECRBY": true, "APPEND": true, "SETRANGE": true, "SETBIT": true,
	"DEL": true, "UNLINK": true, "EXPIRE": true, "PEXPIRE": true, "EXPIREAT": true, "PEXPIREAT": true, "PERSIST": true,
	"RENAME": true, "RENAMENX": true, "COPY": true, "MOVE": true, "TOUCH": true,
	"HSET": true, "HSETNX": true, "HMSET": true, "HDEL": true, "HINCRBY": true, "HINCRBYFLOAT": true,
	"LPUSH": true, "RPUSH": true, "LPOP": true, "RPOP": true, "LSET": true, "LREM": true, "LTRIM": true, "LMOVE": true, "RPOPLPUSH": true,
	"SADD": true, "SREM": true, "SPOP": true, "SMOVE": true, "SINTERSTORE": true, "SUNIONSTORE": true, "SDIFFSTORE": true,
	"ZADD": true, "ZREM": true, "ZINCRBY": true, "ZPOPMIN": true, "ZPOPMAX": true, "ZREMRANGEBYRANK": true, "ZREMRANGEBYSCORE": true,
	"XADD": true, "XDEL": true, "XTRIM": true, "XACK": true, "XGROUP": true, "PFADD": true, "PFMERGE": true, "PUBLISH": true,
}

var redisAdminCmds = map[string]bool{
	"FLUSHDB": true, "FLUSHALL": true, "EVAL": true, "EVALSHA": true, "EVAL_RO": true, "EVALSHA_RO": true,
	"FCALL": true, "FCALL_RO": true, "FUNCTION": true, "SCRIPT": true,
	"CONFIG": true, "SHUTDOWN": true, "ACL": true, "MIGRATE": true, "RESTORE": true,
	"BGSAVE": true, "BGREWRITEAOF": true, "SAVE": true, "SLAVEOF": true, "REPLICAOF": true,
	"SWAPDB": true, "SELECT": true, "AUTH": true, "DEBUG": true, "MODULE": true, "LATENCY": true,
	"MULTI": true, "EXEC": true, "DISCARD": true,
}

// ParseRedisLines splits multi-line Redis input into argument vectors respecting quotes.
func ParseRedisLines(raw string) ([][]string, error) {
	var cmds [][]string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		args, err := splitShellArgs(line)
		if err != nil {
			return nil, err
		}
		if len(args) > 0 {
			cmds = append(cmds, args)
		}
	}
	return cmds, nil
}

func classifyRedis(engine, raw string) types.Classification {
	cmds, err := ParseRedisLines(raw)
	if err != nil || len(cmds) == 0 {
		flag := "empty_command"
		if err != nil {
			flag = "malformed_quoting"
		}
		return types.Classification{
			Engine:         engine,
			Family:         types.FamilyKV,
			RiskLevel:      types.RiskUnknown,
			IsReadOnly:     false,
			StatementCount: 0,
			RiskFlags:      []string{flag},
			Summary:        "Empty or malformed Redis command (fail-closed)",
		}
	}

	out := types.Classification{
		Engine:         engine,
		Family:         types.FamilyKV,
		RiskLevel:      types.RiskSafeRead,
		IsReadOnly:     true,
		StatementCount: len(cmds),
	}
	flagSet := map[string]bool{}
	if len(cmds) > 1 {
		flagSet["multi_statement"] = true
	}

	for _, args := range cmds {
		sum := classifySingleRedis(args)
		out.Statements = append(out.Statements, sum)
		for _, f := range sum.Flags {
			flagSet[f] = true
		}
		if riskRank(sum.RiskLevel) > riskRank(out.RiskLevel) {
			out.RiskLevel = sum.RiskLevel
		}
		if sum.RiskLevel != types.RiskSafeRead && sum.RiskLevel != types.RiskHighCostRead {
			out.IsReadOnly = false
		}
	}
	for f := range flagSet {
		out.RiskFlags = append(out.RiskFlags, f)
	}
	sortStrings(out.RiskFlags)
	out.Summary = fmt.Sprintf("%d Redis command(s), highest risk: %s", out.StatementCount, out.RiskLevel)
	return out
}

func classifySingleRedis(args []string) types.StatementSummary {
	cmd := strings.ToUpper(args[0])
	snippet := truncateSnippet(strings.Join(args, " "), 120)

	// Subcommand overrides.
	if cmd == "CONFIG" && len(args) > 1 && strings.EqualFold(args[1], "GET") {
		return types.StatementSummary{StatementType: "CONFIG_GET", RiskLevel: types.RiskSafeRead, Snippet: snippet}
	}
	if cmd == "CLIENT" && len(args) > 1 && strings.EqualFold(args[1], "KILL") {
		return types.StatementSummary{StatementType: "CLIENT_KILL", RiskLevel: types.RiskAdmin, Snippet: snippet}
	}
	if cmd == "LRANGE" || cmd == "ZRANGE" || cmd == "ZREVRANGE" {
		if isBoundedRange(args) {
			return types.StatementSummary{StatementType: cmd, RiskLevel: types.RiskSafeRead, Snippet: snippet}
		}
		return types.StatementSummary{
			StatementType: cmd,
			RiskLevel:     types.RiskHighCostRead,
			Flags:         []string{"unbounded_range_read"},
			Snippet:       snippet,
		}
	}

	switch {
	case redisSafeReadCmds[cmd]:
		return types.StatementSummary{StatementType: cmd, RiskLevel: types.RiskSafeRead, Snippet: snippet}
	case redisHighCostReadCmds[cmd]:
		return types.StatementSummary{
			StatementType: cmd,
			RiskLevel:     types.RiskHighCostRead,
			Flags:         []string{"redis_high_cost_read"},
			Snippet:       snippet,
		}
	case redisWriteCmds[cmd]:
		return types.StatementSummary{StatementType: cmd, RiskLevel: types.RiskWrite, Snippet: snippet}
	case redisAdminCmds[cmd]:
		return types.StatementSummary{StatementType: cmd, RiskLevel: types.RiskAdmin, Snippet: snippet}
	default:
		return types.StatementSummary{
			StatementType: "UNKNOWN_" + cmd,
			RiskLevel:     types.RiskUnknown,
			Flags:         []string{"unrecognized_redis_command"},
			Snippet:       snippet,
		}
	}
}

func isBoundedRange(args []string) bool {
	if len(args) < 4 {
		return false
	}
	start, err1 := strconv.Atoi(args[2])
	stop, err2 := strconv.Atoi(args[3])
	if err1 != nil || err2 != nil {
		return false
	}
	if stop < 0 || start < 0 {
		return false
	}
	return (stop - start) <= 500
}

func splitShellArgs(line string) ([]string, error) {
	var args []string
	var cur strings.Builder
	inToken := false
	var quote byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		if quote != 0 {
			if c == '\\' && quote == '"' && i+1 < len(line) {
				i++
				cur.WriteByte(line[i])
				continue
			}
			if c == quote {
				quote = 0
				continue
			}
			cur.WriteByte(c)
			continue
		}
		if unicode.IsSpace(rune(c)) {
			if inToken {
				args = append(args, cur.String())
				cur.Reset()
				inToken = false
			}
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
			inToken = true
			continue
		}
		inToken = true
		cur.WriteByte(c)
	}
	if quote != 0 {
		return nil, fmt.Errorf("unclosed quote in redis command")
	}
	if inToken {
		args = append(args, cur.String())
	}
	return args, nil
}
