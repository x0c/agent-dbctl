package driver

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/x0c/agent-dbctl/internal/types"
)

// DialectHints carries optional transport/metadata signals for capability detection.
type DialectHints struct {
	ClusterMode      bool
	InfoServer       string
	BuildInfoModules []string
	MaxWireVersion   int
	VersionComment   string
}

var semverMajorMinorRe = regexp.MustCompile(`v?(\d+)\.(\d+)`)
var wireVersionRe = regexp.MustCompile(`(?i)^wire_v(\d+)$`)

// DetectServerCapabilities resolves engine dialect, major/minor version, and feature flags from a live probe.
func DetectServerCapabilities(engine, serverVersion string, hints DialectHints) types.ServerCapabilities {
	eng := strings.ToLower(strings.TrimSpace(engine))
	ver := strings.TrimSpace(serverVersion)
	caps := types.ServerCapabilities{
		Engine:        eng,
		Dialect:       eng,
		ServerVersion: ver,
		ClusterMode:   hints.ClusterMode,
		DetectedAtUTC: time.Now().UTC().Format(time.RFC3339),
	}

	switch eng {
	case "postgres", "postgresql":
		caps.Engine = "postgres"
		return detectPostgresCapabilities(caps, ver)
	case "mysql":
		return detectMySQLCapabilities(caps, ver, hints.VersionComment)
	case "sqlite", "sqlite-ext":
		return detectSQLiteCapabilities(caps, ver)
	case "mongodb":
		return detectMongoCapabilities(caps, ver, hints)
	case "redis":
		return detectRedisCapabilities(caps, ver, hints)
	default:
		caps.MajorVersion, caps.MinorVersion = parseMajorMinor(ver)
		return caps
	}
}

func detectPostgresCapabilities(caps types.ServerCapabilities, ver string) types.ServerCapabilities {
	lower := strings.ToLower(ver)
	caps.Dialect = "postgres"
	caps.SupportsExplain = true
	caps.SupportsReadOnlySession = true
	caps.SupportsCancelQuery = true
	caps.SupportsReturning = true

	switch {
	case strings.Contains(lower, "cockroach"):
		caps.Dialect = "cockroachdb"
		caps.MajorVersion, caps.MinorVersion = parseDialectMajorMinor(ver, "cockroach")
		caps.ExplainFormat = "pg_text"
		caps.SupportsExplainJSON = false
		return caps
	case strings.Contains(lower, "redshift"):
		caps.Dialect = "redshift"
		caps.MajorVersion, caps.MinorVersion = parseMajorMinor(ver)
		caps.ExplainFormat = "pg_text"
		caps.SupportsExplainJSON = false
		caps.SupportsReturning = false
		return caps
	case strings.Contains(lower, "yugabyte") || strings.Contains(lower, "-yb-"):
		caps.Dialect = "yugabytedb"
		caps.MajorVersion, caps.MinorVersion = parseMajorMinor(ver)
		caps.ExplainFormat = "pg_json"
		caps.SupportsExplainJSON = true
		return caps
	case strings.Contains(lower, "greenplum"):
		caps.Dialect = "greenplum"
		caps.MajorVersion, caps.MinorVersion = parseDialectMajorMinor(ver, "greenplum")
		caps.ExplainFormat = "pg_text"
		caps.SupportsExplainJSON = false
		return caps
	case strings.Contains(lower, "alloydb"):
		caps.Dialect = "alloydb"
		caps.MajorVersion, caps.MinorVersion = parseMajorMinor(ver)
		caps.ExplainFormat = "pg_json"
		caps.SupportsExplainJSON = true
		return caps
	}

	caps.MajorVersion, caps.MinorVersion = parseMajorMinor(ver)
	if caps.MajorVersion == 0 || caps.MajorVersion >= 9 {
		caps.ExplainFormat = "pg_json"
		caps.SupportsExplainJSON = true
	} else {
		caps.ExplainFormat = "pg_text"
		caps.SupportsExplainJSON = false
	}
	return caps
}

func detectMySQLCapabilities(caps types.ServerCapabilities, ver, comment string) types.ServerCapabilities {
	lower := strings.ToLower(ver + " " + comment)
	caps.Dialect = "mysql"
	caps.SupportsExplain = true
	caps.SupportsReadOnlySession = true
	caps.SupportsCancelQuery = true

	switch {
	case strings.Contains(lower, "tidb"):
		caps.Dialect = "tidb"
		caps.MajorVersion, caps.MinorVersion = parseDialectMajorMinor(ver, "tidb")
		caps.ExplainFormat = "mysql_tabular"
		caps.SupportsExplainJSON = false
		return caps
	case strings.Contains(lower, "mariadb"):
		caps.Dialect = "mariadb"
		caps.MajorVersion, caps.MinorVersion = parseMajorMinor(ver)
		if caps.MajorVersion == 0 || caps.MajorVersion > 10 || (caps.MajorVersion == 10 && caps.MinorVersion >= 1) {
			caps.ExplainFormat = "mariadb_json"
			caps.SupportsExplainJSON = true
		} else {
			caps.ExplainFormat = "mysql_tabular"
			caps.SupportsExplainJSON = false
		}
		caps.SupportsReturning = caps.MajorVersion > 10 || (caps.MajorVersion == 10 && caps.MinorVersion >= 5)
		return caps
	case strings.Contains(lower, "oceanbase"):
		caps.Dialect = "oceanbase_mysql"
		caps.MajorVersion, caps.MinorVersion = parseDialectMajorMinor(ver, "oceanbase")
		caps.ExplainFormat = "mysql_tabular"
		caps.SupportsExplainJSON = false
		return caps
	case strings.Contains(lower, "starrocks"):
		caps.Dialect = "starrocks"
		caps.MajorVersion, caps.MinorVersion = parseDialectMajorMinor(ver, "starrocks")
		caps.ExplainFormat = "mysql_tabular"
		caps.SupportsExplainJSON = false
		return caps
	case strings.Contains(lower, "doris"):
		caps.Dialect = "doris"
		caps.MajorVersion, caps.MinorVersion = parseDialectMajorMinor(ver, "doris")
		caps.ExplainFormat = "mysql_tabular"
		caps.SupportsExplainJSON = false
		return caps
	}

	caps.MajorVersion, caps.MinorVersion = parseMajorMinor(ver)
	switch {
	case caps.MajorVersion > 8 || (caps.MajorVersion == 8 && caps.MinorVersion >= 4):
		caps.ExplainFormat = "mysql_json_v2"
		caps.SupportsExplainJSON = true
	case caps.MajorVersion == 0 || caps.MajorVersion > 5 || (caps.MajorVersion == 5 && caps.MinorVersion >= 6):
		caps.ExplainFormat = "mysql_json_v1"
		caps.SupportsExplainJSON = true
	default:
		caps.ExplainFormat = "mysql_tabular"
		caps.SupportsExplainJSON = false
	}
	return caps
}

func detectSQLiteCapabilities(caps types.ServerCapabilities, ver string) types.ServerCapabilities {
	caps.Dialect = "sqlite"
	caps.MajorVersion, caps.MinorVersion = parseMajorMinor(ver)
	caps.ExplainFormat = "sqlite_eqp"
	caps.SupportsExplain = true
	caps.SupportsReadOnlySession = true
	caps.SupportsCancelQuery = true
	caps.SupportsReturning = caps.MajorVersion > 3 || (caps.MajorVersion == 3 && caps.MinorVersion >= 35)
	return caps
}

func detectMongoCapabilities(caps types.ServerCapabilities, ver string, hints DialectHints) types.ServerCapabilities {
	lower := strings.ToLower(ver + " " + strings.Join(hints.BuildInfoModules, " "))
	caps.Dialect = "mongodb"
	caps.ExplainFormat = "mongo_queryPlanner"
	caps.SupportsExplain = true
	caps.SupportsExplainJSON = true
	caps.SupportsReadOnlySession = true
	caps.SupportsCancelQuery = true

	switch {
	case strings.Contains(lower, "documentdb"):
		caps.Dialect = "documentdb"
	case strings.Contains(lower, "ferretdb"):
		caps.Dialect = "ferretdb"
	case strings.Contains(lower, "cosmos"):
		caps.Dialect = "cosmosdb_mongo"
	}

	if m := wireVersionRe.FindStringSubmatch(strings.TrimSpace(ver)); len(m) == 2 {
		if wire, err := strconv.Atoi(m[1]); err == nil {
			hints.MaxWireVersion = wire
		}
	}
	caps.MajorVersion, caps.MinorVersion = parseMajorMinor(ver)
	if caps.MajorVersion == 0 && hints.MaxWireVersion > 0 {
		switch {
		case hints.MaxWireVersion >= 25:
			caps.MajorVersion, caps.MinorVersion = 8, 0
		case hints.MaxWireVersion >= 21:
			caps.MajorVersion, caps.MinorVersion = 7, 0
		case hints.MaxWireVersion >= 17:
			caps.MajorVersion, caps.MinorVersion = 6, 0
		case hints.MaxWireVersion >= 13:
			caps.MajorVersion, caps.MinorVersion = 5, 0
		case hints.MaxWireVersion >= 9:
			caps.MajorVersion, caps.MinorVersion = 4, 4
		case hints.MaxWireVersion >= 8:
			caps.MajorVersion, caps.MinorVersion = 4, 2
		default:
			caps.MajorVersion, caps.MinorVersion = 4, 0
		}
	}
	caps.SupportsAuthorizedDBList = caps.MajorVersion == 0 || caps.MajorVersion >= 4
	return caps
}

func detectRedisCapabilities(caps types.ServerCapabilities, ver string, hints DialectHints) types.ServerCapabilities {
	lower := strings.ToLower(hints.InfoServer + "\n" + ver)
	caps.Dialect = "redis"
	caps.ExplainFormat = "none"
	caps.SupportsExplain = false
	caps.SupportsReadOnlySession = hints.ClusterMode
	caps.SupportsCancelQuery = false

	switch {
	case strings.Contains(lower, "valkey_version:") || strings.Contains(lower, "valkey"):
		caps.Dialect = "valkey"
		if v := extractInfoField(hints.InfoServer, "valkey_version:"); v != "" {
			caps.ServerVersion = v
		}
	case strings.Contains(lower, "dragonfly_version:") || strings.Contains(lower, "dragonfly"):
		caps.Dialect = "dragonfly"
		if v := extractInfoField(hints.InfoServer, "dragonfly_version:"); v != "" {
			caps.ServerVersion = v
		}
	case strings.Contains(lower, "keydb_version:") || strings.Contains(lower, "keydb"):
		caps.Dialect = "keydb"
		if v := extractInfoField(hints.InfoServer, "keydb_version:"); v != "" {
			caps.ServerVersion = v
		}
	}

	caps.MajorVersion, caps.MinorVersion = parseMajorMinor(caps.ServerVersion)
	caps.SupportsRESP3 = caps.Dialect == "valkey" || caps.Dialect == "dragonfly" || caps.MajorVersion == 0 || caps.MajorVersion >= 6
	return caps
}

func extractInfoField(info, key string) string {
	for _, line := range strings.Split(info, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, key) {
			return strings.TrimSpace(strings.TrimPrefix(line, key))
		}
	}
	return ""
}

func parseDialectMajorMinor(raw, marker string) (int, int) {
	lower := strings.ToLower(raw)
	if idx := strings.Index(lower, strings.ToLower(marker)); idx >= 0 {
		if maj, min := parseMajorMinor(raw[idx:]); maj > 0 || min > 0 {
			return maj, min
		}
	}
	return parseMajorMinor(raw)
}

func parseMajorMinor(raw string) (int, int) {
	m := semverMajorMinorRe.FindStringSubmatch(raw)
	if len(m) != 3 {
		return 0, 0
	}
	maj, _ := strconv.Atoi(m[1])
	min, _ := strconv.Atoi(m[2])
	return maj, min
}
