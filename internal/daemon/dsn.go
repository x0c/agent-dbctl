package daemon

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/x0c/agent-dbctl/internal/classify"
)

// ParsedDSN holds non-secret and ephemeral secret fields parsed from a connection string.
type ParsedDSN struct {
	Engine       string
	Host         string
	Port         int
	DatabaseName string
	Username     string
	Password     string
	HasPassword  bool
	TLSMode      string
	Params       map[string]string
}

// DefaultPortForEngine returns the canonical default TCP port for built-in engines (0 for SQLite).
func DefaultPortForEngine(engine string) int {
	switch classify.CanonicalEngine(engine) {
	case "postgres":
		return 5432
	case "mysql":
		return 3306
	case "mongodb":
		return 27017
	case "redis":
		return 6379
	case "clickhouse":
		return 9000
	case "mssql":
		return 1433
	case "oracle":
		return 1521
	case "elasticsearch":
		return 9200
	case "sqlite":
		return 0
	default:
		return 0
	}
}

// ParseDSN parses standard database URIs, Go MySQL DSNs, and SQLite file paths without logging credentials.
func ParseDSN(raw, engineHint string) (ParsedDSN, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ParsedDSN{}, fmt.Errorf("dsn cannot be empty")
	}

	hint := strings.ToLower(strings.TrimSpace(engineHint))
	out := ParsedDSN{Params: map[string]string{}}

	// 1. SQLite paths / file: URIs / :memory:
	if trimmed == ":memory:" ||
		strings.HasPrefix(strings.ToLower(trimmed), "file:") ||
		strings.HasPrefix(strings.ToLower(trimmed), "sqlite:") ||
		strings.HasPrefix(strings.ToLower(trimmed), "sqlite3:") ||
		(!strings.Contains(trimmed, "://") && (classify.CanonicalEngine(hint) == "sqlite" || looksLikeSQLitePath(trimmed))) {
		return parseSQLiteDSN(trimmed, hint)
	}

	// 2. Go MySQL DSN: [user[:pass]@][tcp(host[:port])]/dbname[?params]
	if !strings.Contains(trimmed, "://") && (strings.Contains(trimmed, "@tcp(") || strings.HasPrefix(trimmed, "tcp(")) {
		return parseGoMySQLDSN(trimmed, hint)
	}

	// 3. Standard URL-based DSNs.
	u, err := url.Parse(trimmed)
	if err != nil {
		return ParsedDSN{}, fmt.Errorf("invalid DSN: %w", err)
	}
	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
	if scheme == "" {
		return ParsedDSN{}, fmt.Errorf("DSN must include a scheme (e.g. postgres://, mysql://, sqlite://, mongodb://, redis://)")
	}

	eng, tlsMode, extraParams, err := resolveDSNScheme(scheme, hint)
	if err != nil {
		return ParsedDSN{}, err
	}
	out.Engine = eng
	out.TLSMode = tlsMode
	for k, v := range extraParams {
		out.Params[k] = v
	}

	if u.User != nil {
		out.Username = u.User.Username()
		if pw, ok := u.User.Password(); ok {
			out.Password = pw
			out.HasPassword = true
		}
	}

	out.Host = u.Hostname()
	if out.Host == "" && out.Engine != "sqlite" {
		return ParsedDSN{}, fmt.Errorf("DSN is missing host")
	}
	if portStr := u.Port(); portStr != "" {
		p, err := strconv.Atoi(portStr)
		if err != nil || p <= 0 || p > 65535 {
			return ParsedDSN{}, fmt.Errorf("invalid DSN port %q", portStr)
		}
		out.Port = p
	} else {
		out.Port = defaultPortForURLScheme(scheme, out.Engine)
	}

	dbPath := strings.TrimPrefix(u.Path, "/")
	if dbPath != "" {
		if classify.CanonicalEngine(out.Engine) == "redis" {
			if _, convErr := strconv.Atoi(dbPath); convErr != nil {
				return ParsedDSN{}, fmt.Errorf("redis DSN database index must be an integer, got %q", dbPath)
			}
		}
		out.DatabaseName = dbPath
	}

	for key, vals := range u.Query() {
		if len(vals) == 0 {
			continue
		}
		val := vals[0]
		kl := strings.ToLower(strings.TrimSpace(key))
		switch kl {
		case "sslmode", "tls", "ssl":
			if norm := normalizeDSTLSMode(val); norm != "" {
				out.TLSMode = norm
			}
		case "encrypt":
			if strings.EqualFold(val, "disable") || strings.EqualFold(val, "false") {
				out.TLSMode = "disable"
			} else if strings.EqualFold(val, "true") && out.TLSMode == "" {
				out.TLSMode = "require"
			}
		case "database":
			if out.DatabaseName == "" && classify.CanonicalEngine(out.Engine) == "mssql" {
				out.DatabaseName = val
			} else {
				out.Params[key] = val
			}
		default:
			out.Params[key] = val
		}
	}
	return out, nil
}

func parseSQLiteDSN(raw, hint string) (ParsedDSN, error) {
	out := ParsedDSN{
		Engine: "sqlite",
		Params: map[string]string{},
	}
	if hint != "" && classify.CanonicalEngine(hint) == "sqlite" {
		out.Engine = hint
	}
	if raw == ":memory:" {
		out.Host = ":memory:"
		out.DatabaseName = ":memory:"
		return out, nil
	}
	pathPart := raw
	if strings.HasPrefix(strings.ToLower(raw), "sqlite3://") {
		pathPart = raw[len("sqlite3://"):]
	} else if strings.HasPrefix(strings.ToLower(raw), "sqlite://") {
		pathPart = raw[len("sqlite://"):]
	} else if strings.HasPrefix(strings.ToLower(raw), "file:") {
		pathPart = raw[len("file:"):]
	}
	if idx := strings.IndexByte(pathPart, '?'); idx >= 0 {
		qStr := pathPart[idx+1:]
		pathPart = pathPart[:idx]
		if q, err := url.ParseQuery(qStr); err == nil {
			for k, vals := range q {
				if len(vals) > 0 {
					out.Params[k] = vals[0]
				}
			}
		}
	}
	pathPart = strings.TrimSpace(pathPart)
	if pathPart == "" {
		return ParsedDSN{}, fmt.Errorf("sqlite DSN requires a file path or memory database")
	}
	out.Host = pathPart
	out.DatabaseName = pathPart
	return out, nil
}

func parseGoMySQLDSN(raw, hint string) (ParsedDSN, error) {
	out := ParsedDSN{
		Engine: "mysql",
		Port:   3306,
		Params: map[string]string{},
	}
	if hint != "" && classify.CanonicalEngine(hint) == "mysql" {
		out.Engine = hint
	}
	rest := raw
	if at := strings.LastIndexByte(rest, '@'); at >= 0 {
		creds := rest[:at]
		rest = rest[at+1:]
		if colon := strings.IndexByte(creds, ':'); colon >= 0 {
			out.Username = creds[:colon]
			out.Password = creds[colon+1:]
			out.HasPassword = true
		} else {
			out.Username = creds
		}
	}
	if !strings.HasPrefix(rest, "tcp(") {
		return ParsedDSN{}, fmt.Errorf("unsupported Go MySQL DSN transport (expected tcp(host:port))")
	}
	endParen := strings.IndexByte(rest, ')')
	if endParen < 0 {
		return ParsedDSN{}, fmt.Errorf("malformed Go MySQL DSN tcp(...) block")
	}
	addr := rest[len("tcp("):endParen]
	afterAddr := rest[endParen+1:]

	if colon := strings.LastIndexByte(addr, ':'); colon >= 0 && !strings.Contains(addr[colon:], "]") {
		hostPart := strings.Trim(addr[:colon], "[]")
		portStr := addr[colon+1:]
		p, err := strconv.Atoi(portStr)
		if err != nil || p <= 0 || p > 65535 {
			return ParsedDSN{}, fmt.Errorf("invalid MySQL DSN port %q", portStr)
		}
		out.Host = hostPart
		out.Port = p
	} else {
		out.Host = strings.Trim(addr, "[]")
	}
	if out.Host == "" {
		return ParsedDSN{}, fmt.Errorf("mysql DSN missing host")
	}

	afterAddr = strings.TrimPrefix(afterAddr, "/")
	if qIdx := strings.IndexByte(afterAddr, '?'); qIdx >= 0 {
		out.DatabaseName = afterAddr[:qIdx]
		if q, err := url.ParseQuery(afterAddr[qIdx+1:]); err == nil {
			for k, vals := range q {
				if len(vals) == 0 {
					continue
				}
				if strings.EqualFold(k, "tls") {
					if norm := normalizeDSTLSMode(vals[0]); norm != "" {
						out.TLSMode = norm
					}
				} else {
					out.Params[k] = vals[0]
				}
			}
		}
	} else {
		out.DatabaseName = afterAddr
	}
	return out, nil
}

func resolveDSNScheme(scheme, hint string) (engine, tlsMode string, params map[string]string, err error) {
	params = map[string]string{}
	switch scheme {
	case "postgres", "postgresql", "pg":
		engine = "postgres"
	case "cockroachdb", "cockroach", "redshift", "yugabytedb", "yugabyte", "greenplum", "alloydb":
		engine = scheme
	case "mysql":
		engine = "mysql"
	case "mariadb", "tidb", "oceanbase_mysql", "starrocks", "doris":
		engine = scheme
	case "mongodb", "mongo":
		engine = "mongodb"
	case "mongodb+srv":
		engine = "mongodb"
		params["srv"] = "true"
		tlsMode = "require"
	case "redis":
		engine = "redis"
	case "rediss":
		engine = "redis"
		tlsMode = "require"
	case "valkey", "dragonfly", "keydb":
		engine = scheme
	case "clickhouse":
		engine = "clickhouse"
	case "clickhouses":
		engine = "clickhouse"
		tlsMode = "require"
	case "sqlserver", "mssql":
		engine = "mssql"
	case "oracle", "oracledb":
		engine = "oracle"
	case "elasticsearch", "es":
		engine = "elasticsearch"
	case "opensearch":
		engine = "opensearch"
	case "http", "https":
		canonHint := classify.CanonicalEngine(hint)
		switch canonHint {
		case "elasticsearch":
			engine = hint
			params["scheme"] = scheme
		case "clickhouse":
			engine = hint
			params["protocol"] = "http"
		default:
			return "", "", nil, fmt.Errorf("scheme %q is ambiguous; pass --engine elasticsearch, opensearch, or clickhouse", scheme)
		}
		if scheme == "https" {
			tlsMode = "require"
		}
	default:
		return "", "", nil, fmt.Errorf("unsupported DSN scheme %q", scheme)
	}

	if hint != "" && classify.CanonicalEngine(hint) == classify.CanonicalEngine(engine) {
		engine = hint
	}
	return engine, tlsMode, params, nil
}

func defaultPortForURLScheme(scheme, engine string) int {
	if classify.CanonicalEngine(engine) == "clickhouse" {
		if scheme == "http" {
			return 8123
		}
		if scheme == "https" {
			return 8443
		}
	}
	if classify.CanonicalEngine(engine) == "elasticsearch" && scheme == "https" {
		return 443
	}
	return DefaultPortForEngine(engine)
}

func normalizeDSTLSMode(val string) string {
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "disable", "false", "0", "off":
		return "disable"
	case "prefer", "allow", "preferred":
		return "prefer"
	case "require", "true", "1", "on", "skip-verify":
		return "require"
	case "verify-ca":
		return "verify-ca"
	case "verify-full":
		return "verify-full"
	default:
		return ""
	}
}

func looksLikeSQLitePath(s string) bool {
	ext := strings.ToLower(filepath.Ext(s))
	return ext == ".db" || ext == ".sqlite" || ext == ".sqlite3"
}

// RedactDSN masks embedded passwords in a connection string for safe diagnostic display.
func RedactDSN(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	if strings.Contains(trimmed, "://") {
		if u, err := url.Parse(trimmed); err == nil && u.User != nil {
			if _, hasPW := u.User.Password(); hasPW {
				u.User = url.UserPassword(u.User.Username(), "***")
				return u.String()
			}
		}
	}
	if at := strings.IndexByte(trimmed, '@'); at > 0 && strings.Contains(trimmed[at:], "tcp(") {
		creds := trimmed[:at]
		if colon := strings.IndexByte(creds, ':'); colon >= 0 {
			return creds[:colon+1] + "***" + trimmed[at:]
		}
	}
	return trimmed
}
