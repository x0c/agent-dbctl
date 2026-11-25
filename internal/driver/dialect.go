package driver

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/x0c/agent-dbctl/internal/classify"
	"github.com/x0c/agent-dbctl/internal/types"
)

// DialectHints carries optional transport/metadata signals for capability detection.
type DialectHints struct {
	ClusterMode      bool
	InfoServer       string
	BuildInfoModules []string
	MaxWireVersion   int
	VersionComment   string
	Distribution     string
}

var semverMajorMinorRe = regexp.MustCompile(`v?(\d+)\.(\d+)`)
var kingbaseVersionRe = regexp.MustCompile(`(?i)V(\d+)R(\d+)`)
var wireVersionRe = regexp.MustCompile(`(?i)^wire_v(\d+)$`)

// DetectServerCapabilities resolves engine dialect, major/minor version, and feature flags from a live probe.
func DetectServerCapabilities(engine, serverVersion string, hints DialectHints) types.ServerCapabilities {
	rawEng := strings.ToLower(strings.TrimSpace(engine))
	eng := classify.CanonicalEngine(rawEng)
	ver := strings.TrimSpace(serverVersion)
	caps := types.ServerCapabilities{
		Engine:        eng,
		Dialect:       eng,
		ServerVersion: ver,
		ClusterMode:   hints.ClusterMode,
		DetectedAtUTC: time.Now().UTC().Format(time.RFC3339),
	}

	switch eng {
	case "postgres":
		return detectPostgresCapabilities(caps, rawEng, ver)
	case "opengauss":
		return detectOpenGaussCapabilities(caps, rawEng, ver)
	case "kingbase":
		return detectKingbaseCapabilities(caps, ver)
	case "dameng":
		return detectDamengCapabilities(caps, ver)
	case "tdengine":
		return detectTDengineCapabilities(caps, ver)
	case "mysql":
		return detectMySQLCapabilities(caps, rawEng, ver, hints.VersionComment)
	case "sqlite":
		return detectSQLiteCapabilities(caps, ver)
	case "mongodb":
		return detectMongoCapabilities(caps, ver, hints)
	case "redis":
		return detectRedisCapabilities(caps, ver, hints)
	case "clickhouse":
		return detectClickHouseCapabilities(caps, ver)
	case "mssql":
		return detectMSSQLCapabilities(caps, ver)
	case "oracle":
		return detectOracleCapabilities(caps, ver)
	case "elasticsearch":
		return detectElasticsearchCapabilities(caps, rawEng, ver, hints)
	default:
		caps.MajorVersion, caps.MinorVersion = parseMajorMinor(ver)
		return caps
	}
}

func detectPostgresCapabilities(caps types.ServerCapabilities, rawEng, ver string) types.ServerCapabilities {
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
	case strings.Contains(lower, "highgo") || rawEng == "highgo":
		caps.Dialect = "highgo"
		caps.MajorVersion, caps.MinorVersion = parseDialectMajorMinor(ver, "highgo")
		caps.ExplainFormat = "pg_json"
		caps.SupportsExplainJSON = true
		return caps
	case strings.Contains(lower, "uxdb") || rawEng == "uxdb":
		caps.Dialect = "uxdb"
		caps.MajorVersion, caps.MinorVersion = parseMajorMinor(ver)
		caps.ExplainFormat = "pg_json"
		caps.SupportsExplainJSON = true
		return caps
	case strings.Contains(lower, "opentenbase") || rawEng == "opentenbase":
		caps.Dialect = "opentenbase"
		caps.MajorVersion, caps.MinorVersion = parseMajorMinor(ver)
		caps.ExplainFormat = "pg_text"
		caps.SupportsExplainJSON = false
		return caps
	case strings.Contains(lower, "kwdb") || strings.Contains(lower, "kaiwudb") || rawEng == "kwdb" || rawEng == "kaiwudb":
		caps.Dialect = "kwdb"
		caps.MajorVersion, caps.MinorVersion = parseMajorMinor(ver)
		caps.ExplainFormat = "pg_text"
		caps.SupportsExplainJSON = false
		return caps
	case strings.Contains(lower, "polardb") || rawEng == "polardb_pg" || rawEng == "polardb-pg":
		caps.Dialect = "polardb_pg"
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

func detectOpenGaussCapabilities(caps types.ServerCapabilities, rawEng, ver string) types.ServerCapabilities {
	lower := strings.ToLower(ver)
	caps.Dialect = "opengauss"
	caps.SupportsExplain = true
	caps.SupportsExplainJSON = false
	caps.ExplainFormat = "pg_text"
	caps.SupportsReadOnlySession = true
	caps.SupportsCancelQuery = true
	caps.SupportsReturning = true

	switch {
	case strings.Contains(lower, "gbase8c") || rawEng == "gbase8c" || rawEng == "gbase-8c":
		caps.Dialect = "gbase8c"
		caps.MajorVersion, caps.MinorVersion = parseDialectMajorMinor(ver, "gbase8c")
	case strings.Contains(lower, "vastbase") || rawEng == "vastbase":
		caps.Dialect = "vastbase"
		caps.MajorVersion, caps.MinorVersion = parseDialectMajorMinor(ver, "vastbase")
	case strings.Contains(lower, "mogdb") || rawEng == "mogdb":
		caps.Dialect = "mogdb"
		caps.MajorVersion, caps.MinorVersion = parseDialectMajorMinor(ver, "mogdb")
	case strings.Contains(lower, "gaussdb") || rawEng == "gaussdb" || rawEng == "gaussdb_dws" || rawEng == "gaussdb-dws":
		caps.Dialect = "gaussdb"
		caps.MajorVersion, caps.MinorVersion = parseDialectMajorMinor(ver, "gaussdb")
	default:
		caps.MajorVersion, caps.MinorVersion = parseDialectMajorMinor(ver, "opengauss")
	}
	return caps
}

func detectKingbaseCapabilities(caps types.ServerCapabilities, ver string) types.ServerCapabilities {
	caps.Dialect = "kingbase"
	caps.SupportsExplain = true
	caps.SupportsExplainJSON = false
	caps.ExplainFormat = "pg_text"
	caps.SupportsReadOnlySession = true
	caps.SupportsCancelQuery = true
	caps.SupportsReturning = true
	caps.MajorVersion, caps.MinorVersion = parseDialectMajorMinor(ver, "kingbase")
	if caps.MajorVersion == 0 {
		caps.MajorVersion, caps.MinorVersion = parseDialectMajorMinor(ver, "v")
	}
	if caps.MajorVersion == 0 {
		if m := kingbaseVersionRe.FindStringSubmatch(ver); len(m) == 3 {
			caps.MajorVersion, _ = strconv.Atoi(m[1])
			caps.MinorVersion, _ = strconv.Atoi(m[2])
		}
	}
	return caps
}

func detectDamengCapabilities(caps types.ServerCapabilities, ver string) types.ServerCapabilities {
	caps.Dialect = "dameng"
	caps.SupportsExplain = true
	caps.SupportsExplainJSON = false
	caps.ExplainFormat = "dameng_explain"
	caps.SupportsReadOnlySession = true
	caps.SupportsCancelQuery = true
	caps.SupportsReturning = false
	caps.MajorVersion, caps.MinorVersion = parseDialectMajorMinor(ver, "dm")
	if caps.MajorVersion == 0 {
		caps.MajorVersion, caps.MinorVersion = parseMajorMinor(ver)
	}
	return caps
}

func detectTDengineCapabilities(caps types.ServerCapabilities, ver string) types.ServerCapabilities {
	caps.Dialect = "tdengine"
	caps.SupportsExplain = true
	caps.SupportsExplainJSON = false
	caps.ExplainFormat = "tdengine_explain"
	caps.SupportsReadOnlySession = false
	caps.SupportsCancelQuery = true
	caps.MajorVersion, caps.MinorVersion = parseMajorMinor(ver)
	return caps
}

func detectMySQLCapabilities(caps types.ServerCapabilities, rawEng, ver, comment string) types.ServerCapabilities {
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
	case strings.Contains(lower, "oceanbase") || rawEng == "oceanbase" || rawEng == "oceanbase_mysql":
		caps.Dialect = "oceanbase_mysql"
		caps.MajorVersion, caps.MinorVersion = parseDialectMajorMinor(ver, "oceanbase")
		caps.ExplainFormat = "mysql_tabular"
		caps.SupportsExplainJSON = false
		return caps
	case strings.Contains(lower, "starrocks") || rawEng == "starrocks":
		caps.Dialect = "starrocks"
		caps.MajorVersion, caps.MinorVersion = parseDialectMajorMinor(ver, "starrocks")
		caps.ExplainFormat = "mysql_tabular"
		caps.SupportsExplainJSON = false
		return caps
	case strings.Contains(lower, "selectdb") || rawEng == "selectdb":
		caps.Dialect = "selectdb"
		caps.MajorVersion, caps.MinorVersion = parseDialectMajorMinor(ver, "selectdb")
		caps.ExplainFormat = "mysql_tabular"
		caps.SupportsExplainJSON = false
		return caps
	case strings.Contains(lower, "doris") || rawEng == "doris":
		caps.Dialect = "doris"
		caps.MajorVersion, caps.MinorVersion = parseDialectMajorMinor(ver, "doris")
		caps.ExplainFormat = "mysql_tabular"
		caps.SupportsExplainJSON = false
		return caps
	case strings.Contains(lower, "gbase") || rawEng == "gbase" || rawEng == "gbase8a" || rawEng == "gbase-8a":
		caps.Dialect = "gbase8a"
		caps.MajorVersion, caps.MinorVersion = parseDialectMajorMinor(ver, "gbase")
		caps.ExplainFormat = "mysql_tabular"
		caps.SupportsExplainJSON = false
		return caps
	case strings.Contains(lower, "goldendb") || rawEng == "goldendb":
		caps.Dialect = "goldendb"
		caps.MajorVersion, caps.MinorVersion = parseDialectMajorMinor(ver, "goldendb")
		caps.ExplainFormat = "mysql_tabular"
		caps.SupportsExplainJSON = false
		return caps
	case strings.Contains(lower, "tdsql") || rawEng == "tdsql" || rawEng == "tdsql_mysql" || rawEng == "tdsql-mysql":
		caps.Dialect = "tdsql"
		caps.MajorVersion, caps.MinorVersion = parseMajorMinor(ver)
		caps.ExplainFormat = "mysql_json_v1"
		caps.SupportsExplainJSON = true
		return caps
	case strings.Contains(lower, "polardb") || rawEng == "polardb" || rawEng == "polardb_mysql" || rawEng == "polardb-mysql":
		caps.Dialect = "polardb"
		caps.MajorVersion, caps.MinorVersion = parseMajorMinor(ver)
		caps.ExplainFormat = "mysql_json_v1"
		caps.SupportsExplainJSON = true
		return caps
	case strings.Contains(lower, "greatsql") || rawEng == "greatsql":
		caps.Dialect = "greatsql"
		caps.MajorVersion, caps.MinorVersion = parseMajorMinor(ver)
		caps.ExplainFormat = "mysql_json_v1"
		caps.SupportsExplainJSON = true
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

func detectClickHouseCapabilities(caps types.ServerCapabilities, ver string) types.ServerCapabilities {
	caps.Dialect = "clickhouse"
	caps.MajorVersion, caps.MinorVersion = parseMajorMinor(ver)
	caps.SupportsExplain = caps.MajorVersion == 0 || caps.MajorVersion >= 20
	if caps.SupportsExplain {
		caps.ExplainFormat = "clickhouse_plan"
	} else {
		caps.ExplainFormat = "none"
	}
	caps.SupportsExplainJSON = caps.MajorVersion >= 22
	caps.SupportsReadOnlySession = true
	caps.SupportsCancelQuery = true
	return caps
}

func detectMSSQLCapabilities(caps types.ServerCapabilities, ver string) types.ServerCapabilities {
	lower := strings.ToLower(ver)
	caps.Dialect = "mssql"
	caps.ExplainFormat = "mssql_showplan"
	caps.SupportsExplain = true
	caps.SupportsExplainJSON = false
	caps.SupportsReadOnlySession = false // MSSQL lacks native session-level transaction READ ONLY; enforced via ApplicationIntent + driver gate.
	caps.SupportsCancelQuery = true
	if strings.Contains(lower, "azure") {
		caps.Dialect = "azure_sql"
	}
	caps.MajorVersion, caps.MinorVersion = parseMajorMinor(ver)
	return caps
}

func detectOracleCapabilities(caps types.ServerCapabilities, ver string) types.ServerCapabilities {
	caps.Dialect = "oracle"
	caps.ExplainFormat = "oracle_xplan"
	caps.SupportsExplain = true
	caps.SupportsExplainJSON = false
	caps.SupportsReadOnlySession = true
	caps.SupportsCancelQuery = true
	caps.SupportsReturning = true
	caps.MajorVersion, caps.MinorVersion = parseDialectMajorMinor(ver, "release")
	if caps.MajorVersion == 0 {
		caps.MajorVersion, caps.MinorVersion = parseMajorMinor(ver)
	}
	return caps
}

func detectElasticsearchCapabilities(caps types.ServerCapabilities, rawEng, ver string, hints DialectHints) types.ServerCapabilities {
	dist := strings.ToLower(strings.TrimSpace(hints.Distribution + " " + ver))
	caps.Dialect = "elasticsearch"
	switch {
	case strings.Contains(dist, "opensearch"):
		caps.Dialect = "opensearch"
	case strings.Contains(dist, "easysearch") || rawEng == "easysearch":
		caps.Dialect = "easysearch"
	}
	caps.ExplainFormat = "es_validate_query"
	caps.SupportsExplain = true
	caps.SupportsExplainJSON = true
	caps.SupportsReadOnlySession = true
	caps.SupportsCancelQuery = true
	caps.MajorVersion, caps.MinorVersion = parseMajorMinor(ver)
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
