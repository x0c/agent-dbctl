package classify

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"github.com/x0c/agent-dbctl/internal/types"
)

var sqlAdminFunctions = map[string]bool{
	"pg_read_file":            true,
	"pg_read_binary_file":     true,
	"pg_ls_dir":               true,
	"pg_ls_logdir":            true,
	"pg_ls_waldir":            true,
	"pg_ls_tmpdir":            true,
	"pg_stat_file":            true,
	"lo_import":               true,
	"lo_export":               true,
	"lo_from_bytea":           true,
	"lo_put":                  true,
	"lo_unlink":               true,
	"dblink":                  true,
	"dblink_connect":          true,
	"dblink_connect_u":        true,
	"dblink_exec":             true,
	"dblink_send_query":       true,
	"load_file":               true,
	"load_extension":          true,
	"pg_terminate_backend":    true,
	"pg_cancel_backend":       true,
	"pg_reload_conf":          true,
	"pg_rotate_logfile":       true,
	"set_config":              true,
	"pg_switch_wal":           true,
	"pg_create_restore_point": true,
	"pg_backup_start":         true,
	"pg_backup_stop":          true,
	"xp_cmdshell":             true,
	"sp_oacreate":             true,
	"sp_oamethod":             true,
	"openrowset":              true,
	"opendatasource":          true,
	"utl_file":                true,
	"utl_file.fopen":          true,
	"utl_http":                true,
	"utl_http.request":        true,
	"utl_tcp":                 true,
	"utl_tcp.open_connection": true,
	"dbms_sql":                  true,
	"dbms_sql.execute":          true,
	"dbms_pipe":                 true,
	"sf_set_session_para_value": true,
	"sf_set_system_para_value":  true,
	"sp_set_para_value":         true,
	"sp_set_para_double_value":  true,
	"sp_create_system_packages": true,
	"sp_set_session_readonly":   true,
	"pg_switch_xlog":            true,
	"gs_password_notify":        true,
	"gs_wlm_readjust_user_space": true,
}

var sqlWriteFunctions = map[string]bool{
	"nextval":                     true,
	"setval":                      true,
	"pg_advisory_lock":            true,
	"pg_advisory_lock_shared":     true,
	"pg_try_advisory_lock":        true,
	"pg_try_advisory_lock_shared": true,
	"pg_advisory_xact_lock":       true,
	"pg_advisory_xact_lock_shared": true,
	"pg_advisory_unlock":          true,
	"pg_advisory_unlock_all":      true,
	"get_lock":                    true,
	"release_lock":                true,
	"release_all_locks":           true,
}

var sqlHighCostFunctions = map[string]bool{
	"pg_sleep":        true,
	"pg_sleep_for":    true,
	"pg_sleep_until":  true,
	"sleep":           true,
	"benchmark":       true,
	"randomblob":      true,
	"zeroblob":        true,
	"generate_series": true,
	"xmlparse":        true,
	"dbms_lock.sleep": true,
}

var sqliteSafeParenPragmas = map[string]bool{
	"table_info":       true,
	"table_xinfo":      true,
	"index_list":       true,
	"index_info":       true,
	"index_xinfo":      true,
	"foreign_key_list": true,
}

var sqliteHighCostPragmas = map[string]bool{
	"integrity_check":   true,
	"quick_check":       true,
	"foreign_key_check": true,
	"freelist_count":    true,
}

var sqliteMutateBarePragmas = map[string]bool{
	"wal_checkpoint":     true,
	"shrink_memory":      true,
	"optimize":           true,
	"incremental_vacuum": true,
}

var sqlNonFunctionKeywords = map[string]bool{
	"SELECT": true, "FROM": true, "WHERE": true, "AND": true, "OR": true, "NOT": true,
	"IN": true, "EXISTS": true, "ANY": true, "ALL": true, "SOME": true, "VALUES": true,
	"SET": true, "AS": true, "ON": true, "USING": true, "JOIN": true, "CASE": true,
	"WHEN": true, "THEN": true, "ELSE": true, "OVER": true, "FILTER": true, "WITHIN": true,
	"GROUP": true, "PARTITION": true, "ORDER": true, "BY": true, "HAVING": true,
	"LIMIT": true, "OFFSET": true, "INTO": true, "TABLE": true, "EXPLAIN": true,
	"UNION": true, "INTERSECT": true, "EXCEPT": true, "CAST": true, "CHECK": true,
	"UNIQUE": true, "PRIMARY": true, "FOREIGN": true, "KEY": true, "REFERENCES": true,
	"RETURNING": true, "LATERAL": true, "ONLY": true, "WITH": true, "RECURSIVE": true,
}

var sqlExplainModifiers = map[string]bool{
	"ANALYZE": true, "ANALYSE": true, "VERBOSE": true, "COSTS": true, "SETTINGS": true,
	"BUFFERS": true, "WAL": true, "TIMING": true, "SUMMARY": true, "MEMORY": true,
	"SERIALIZE": true, "GENERIC_PLAN": true, "FORMAT": true, "JSON": true, "TEXT": true,
	"XML": true, "YAML": true, "EXTENDED": true, "PARTITIONS": true, "TREE": true,
	"QUERY": true, "PLAN": true, "ESTIMATE": true, "SYNTAX": true, "AST": true,
	"PIPELINE": true, "ON": true, "OFF": true, "TRUE": true, "FALSE": true,
}

// CanonicalEngine normalizes engine names and compatible dialect aliases to their primary built-in engine key.
func CanonicalEngine(engine string) string {
	e := strings.ToLower(strings.TrimSpace(engine))
	switch e {
	case "postgres", "postgresql", "pg", "cockroachdb", "cockroach", "redshift", "yugabytedb", "yugabyte", "greenplum", "alloydb",
		"highgo", "uxdb", "opentenbase", "kwdb", "kaiwudb", "polardb_pg", "polardb-pg", "tdsql_pg", "tdsql-pg":
		return "postgres"
	case "opengauss", "gaussdb", "gaussdb_dws", "gaussdb-dws", "vastbase", "mogdb", "gbase8c", "gbase-8c":
		return "opengauss"
	case "kingbase", "kingbase8", "kingbasees", "kes":
		return "kingbase"
	case "dameng", "dm", "dm8":
		return "dameng"
	case "tdengine", "taos", "taosdata":
		return "tdengine"
	case "mysql", "mariadb", "tidb", "oceanbase", "oceanbase_mysql", "starrocks", "doris", "selectdb",
		"polardb", "polardb_mysql", "polardb-mysql", "tdsql", "tdsql_mysql", "tdsql-mysql", "goldendb", "greatsql", "gbase", "gbase8a", "gbase-8a":
		return "mysql"
	case "sqlite", "sqlite3", "sqlite-ext":
		return "sqlite"
	case "mongodb", "mongo", "documentdb", "ferretdb", "cosmosdb_mongo":
		return "mongodb"
	case "redis", "valkey", "dragonfly", "keydb":
		return "redis"
	case "clickhouse", "ch":
		return "clickhouse"
	case "mssql", "sqlserver", "sql-server", "azuresql":
		return "mssql"
	case "oracle", "oracledb":
		return "oracle"
	case "elasticsearch", "es", "opensearch", "easysearch":
		return "elasticsearch"
	default:
		if strings.Contains(e, "mongo") {
			return "mongodb"
		}
		if strings.Contains(e, "redis") || strings.Contains(e, "valkey") {
			return "redis"
		}
		if strings.Contains(e, "elastic") || strings.Contains(e, "opensearch") || strings.Contains(e, "easysearch") {
			return "elasticsearch"
		}
		return e
	}
}

// Classify evaluates raw statements/commands for an engine and returns fail-closed risk classification.
func Classify(engine, raw string) types.Classification {
	eng := normalizeEngine(engine)
	switch eng {
	case "mongodb":
		return classifyMongo(engine, raw)
	case "redis":
		return classifyRedis(engine, raw)
	case "elasticsearch":
		return classifyElasticsearch(engine, raw)
	default:
		return classifySQL(engine, raw)
	}
}

// EngineFamily returns the EngineFamily matching an engine name.
func EngineFamily(engine string) types.EngineFamily {
	switch normalizeEngine(engine) {
	case "mongodb", "elasticsearch":
		return types.FamilyDocument
	case "redis":
		return types.FamilyKV
	default:
		return types.FamilySQL
	}
}

func normalizeEngine(engine string) string {
	return CanonicalEngine(engine)
}

func classifySQL(engine, raw string) types.Classification {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return types.Classification{
			Engine:         engine,
			Family:         types.FamilySQL,
			RiskLevel:      types.RiskUnknown,
			IsReadOnly:     false,
			StatementCount: 0,
			RiskFlags:      []string{"empty_query"},
			Summary:        "Empty SQL input (fail-closed)",
		}
	}

	stmts, unclosed := splitSQLStatements(trimmed)
	if unclosed {
		return types.Classification{
			Engine:         engine,
			Family:         types.FamilySQL,
			RiskLevel:      types.RiskUnknown,
			IsReadOnly:     false,
			StatementCount: maxInt(1, len(stmts)),
			RiskFlags:      []string{"unclosed_literal_or_comment"},
			Summary:        "Malformed or unclosed SQL literal/comment (fail-closed)",
		}
	}
	if len(stmts) == 0 {
		return types.Classification{
			Engine:         engine,
			Family:         types.FamilySQL,
			RiskLevel:      types.RiskUnknown,
			IsReadOnly:     false,
			StatementCount: 0,
			RiskFlags:      []string{"comments_only"},
			Summary:        "Comments-only SQL input (fail-closed)",
		}
	}

	out := types.Classification{
		Engine:         engine,
		Family:         types.FamilySQL,
		RiskLevel:      types.RiskSafeRead,
		IsReadOnly:     true,
		StatementCount: len(stmts),
	}
	flagSet := map[string]bool{}
	if len(stmts) > 1 {
		flagSet["multi_statement"] = true
	}

	for _, stmt := range stmts {
		sum := classifySingleSQL(stmt)
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
	out.Summary = fmt.Sprintf("%d SQL statement(s), highest risk: %s", out.StatementCount, out.RiskLevel)
	return out
}

func classifySingleSQL(stmt string) types.StatementSummary {
	rawTokens := tokenizeSQLWithPunctuation(stmt)
	snippet := truncateSnippet(stmt, 120)
	return classifySQLTokens(rawTokens, snippet)
}

func classifySQLTokens(rawTokens []string, snippet string) types.StatementSummary {
	if len(rawTokens) == 0 {
		return types.StatementSummary{
			StatementType: "UNKNOWN",
			RiskLevel:     types.RiskUnknown,
			Flags:         []string{"empty_statement"},
			Snippet:       snippet,
		}
	}

	upper := make([]string, len(rawTokens))
	for i, t := range rawTokens {
		upper[i] = strings.ToUpper(t)
	}
	// Keyword-only view (without "," or ".") for sequence checks like FOR UPDATE / CROSS JOIN.
	kwUpper := filterPunctuation(upper)
	if len(kwUpper) == 0 {
		return types.StatementSummary{
			StatementType: "UNKNOWN",
			RiskLevel:     types.RiskUnknown,
			Flags:         []string{"empty_statement"},
			Snippet:       snippet,
		}
	}
	first := kwUpper[0]

	var flags []string
	if containsSequence(kwUpper, "FOR", "UPDATE") ||
		containsSequence(kwUpper, "FOR", "SHARE") ||
		containsSequence(kwUpper, "FOR", "NO", "KEY", "UPDATE") ||
		containsSequence(kwUpper, "FOR", "KEY", "SHARE") ||
		containsSequence(kwUpper, "LOCK", "IN", "SHARE", "MODE") {
		flags = append(flags, "locking_read")
	}

	if containsToken(kwUpper, "INTO") && (first == "SELECT" || first == "WITH") &&
		(containsSequence(kwUpper, "INTO", "OUTFILE") || containsSequence(kwUpper, "INTO", "DUMPFILE") || !containsToken(kwUpper, "INSERT")) {
		// SELECT ... INTO creates a table or writes a file in PG/MySQL.
		if containsSequence(kwUpper, "INTO", "OUTFILE") || containsSequence(kwUpper, "INTO", "DUMPFILE") || selectIntoTable(kwUpper) {
			flags = append(flags, "select_into")
			return types.StatementSummary{
				StatementType: "SELECT_INTO",
				RiskLevel:     types.RiskWrite,
				Flags:         flags,
				Snippet:       snippet,
			}
		}
	}

	switch first {
	case "EXPLAIN":
		isAnalyze, innerRaw := parseExplainInner(rawTokens)
		if len(innerRaw) == 0 {
			return types.StatementSummary{
				StatementType: "UNKNOWN_EXPLAIN",
				RiskLevel:     types.RiskUnknown,
				Flags:         append(flags, "explain_empty"),
				Snippet:       snippet,
			}
		}
		innerSum := classifySQLTokens(innerRaw, snippet)
		mergedFlags := append(flags, innerSum.Flags...)
		if isAnalyze {
			mergedFlags = append(mergedFlags, "explain_analyze")
			// EXPLAIN ANALYZE actually executes the wrapped statement. Preserve mutating/admin/unknown risk!
			if riskRank(innerSum.RiskLevel) >= riskRank(types.RiskWrite) {
				return types.StatementSummary{
					StatementType: "EXPLAIN_ANALYZE_" + innerSum.StatementType,
					RiskLevel:     innerSum.RiskLevel,
					Flags:         mergedFlags,
					Snippet:       snippet,
				}
			}
			return types.StatementSummary{
				StatementType: "EXPLAIN_ANALYZE",
				RiskLevel:     types.RiskHighCostRead,
				Flags:         mergedFlags,
				Snippet:       snippet,
			}
		}
		if riskRank(innerSum.RiskLevel) >= riskRank(types.RiskWrite) {
			return types.StatementSummary{
				StatementType: "EXPLAIN_" + innerSum.StatementType,
				RiskLevel:     types.RiskHighCostRead,
				Flags:         append(mergedFlags, "explain_dml"),
				Snippet:       snippet,
			}
		}
		return types.StatementSummary{
			StatementType: "EXPLAIN",
			RiskLevel:     types.RiskSafeRead,
			Flags:         mergedFlags,
			Snippet:       snippet,
		}

	case "WITH":
		isRecursive := containsToken(kwUpper, "RECURSIVE")
		if isRecursive {
			flags = append(flags, "recursive_cte")
		}
		// Detect data-modifying CTEs (e.g. WITH del AS (DELETE FROM t RETURNING *) SELECT * FROM del).
		for _, kw := range kwUpper[1:] {
			switch kw {
			case "INSERT", "UPDATE", "DELETE", "MERGE":
				return types.StatementSummary{
					StatementType: "CTE_" + kw,
					RiskLevel:     types.RiskWrite,
					Flags:         append(flags, "cte_write"),
					Snippet:       snippet,
				}
			case "CREATE", "ALTER", "DROP", "TRUNCATE":
				return types.StatementSummary{
					StatementType: "CTE_" + kw,
					RiskLevel:     types.RiskDDL,
					Flags:         append(flags, "cte_ddl"),
					Snippet:       snippet,
				}
			}
		}
		return analyzeSelectQuery("WITH_SELECT", rawTokens, upper, kwUpper, flags, snippet)

	case "SELECT", "VALUES", "TABLE":
		return analyzeSelectQuery(first, rawTokens, upper, kwUpper, flags, snippet)

	case "SHOW", "DESCRIBE", "DESC":
		return types.StatementSummary{
			StatementType: first,
			RiskLevel:     types.RiskSafeRead,
			Flags:         flags,
			Snippet:       snippet,
		}

	case "PRAGMA":
		return classifyPragma(rawTokens, kwUpper, flags, snippet)

	case "INSERT", "REPLACE":
		return types.StatementSummary{
			StatementType: first,
			RiskLevel:     types.RiskWrite,
			Flags:         flags,
			Snippet:       snippet,
		}

	case "UPDATE", "DELETE", "MERGE":
		if !containsToken(kwUpper, "WHERE") && first != "MERGE" {
			flags = append(flags, "missing_where")
		}
		return types.StatementSummary{
			StatementType: first,
			RiskLevel:     types.RiskWrite,
			Flags:         flags,
			Snippet:       snippet,
		}

	case "CREATE", "ALTER", "DROP", "TRUNCATE", "RENAME", "COMMENT":
		return types.StatementSummary{
			StatementType: first,
			RiskLevel:     types.RiskDDL,
			Flags:         flags,
			Snippet:       snippet,
		}

	case "GRANT", "REVOKE", "COPY", "LOAD", "CALL", "EXEC", "EXECUTE", "VACUUM", "ANALYZE", "REINDEX", "CLUSTER", "KILL", "FLUSH", "LOCK", "UNLOCK", "SET", "USE", "ATTACH", "DETACH",
		"OPTIMIZE", "SYSTEM", "EXCHANGE", "BACKUP", "RESTORE", "DBCC", "SHUTDOWN", "RECONFIGURE", "BULK", "WAITFOR":
		if first == "COPY" && containsToken(kwUpper, "PROGRAM") {
			flags = append(flags, "copy_program_rce")
		}
		return types.StatementSummary{
			StatementType: first,
			RiskLevel:     types.RiskAdmin,
			Flags:         flags,
			Snippet:       snippet,
		}

	default:
		return types.StatementSummary{
			StatementType: "UNKNOWN_" + first,
			RiskLevel:     types.RiskUnknown,
			Flags:         append(flags, "unrecognized_statement"),
			Snippet:       snippet,
		}
	}
}

func classifyPragma(rawTokens, kwUpper, flags []string, snippet string) types.StatementSummary {
	pragmaName := extractPragmaName(rawTokens)
	hasEq := containsToken(kwUpper, "=")
	hasParen := containsToken(kwUpper, "(")

	if hasEq {
		return types.StatementSummary{
			StatementType: "PRAGMA_WRITE",
			RiskLevel:     types.RiskAdmin,
			Flags:         append(flags, "pragma_mutate"),
			Snippet:       snippet,
		}
	}
	if hasParen {
		if sqliteSafeParenPragmas[pragmaName] {
			return types.StatementSummary{
				StatementType: "PRAGMA_READ",
				RiskLevel:     types.RiskSafeRead,
				Flags:         flags,
				Snippet:       snippet,
			}
		}
		if sqliteHighCostPragmas[pragmaName] {
			return types.StatementSummary{
				StatementType: "PRAGMA_HIGH_COST",
				RiskLevel:     types.RiskHighCostRead,
				Flags:         append(flags, "pragma_high_cost"),
				Snippet:       snippet,
			}
		}
		return types.StatementSummary{
			StatementType: "PRAGMA_WRITE",
			RiskLevel:     types.RiskAdmin,
			Flags:         append(flags, "pragma_mutate"),
			Snippet:       snippet,
		}
	}
	if sqliteMutateBarePragmas[pragmaName] {
		return types.StatementSummary{
			StatementType: "PRAGMA_WRITE",
			RiskLevel:     types.RiskAdmin,
			Flags:         append(flags, "pragma_mutate"),
			Snippet:       snippet,
		}
	}
	if sqliteHighCostPragmas[pragmaName] {
		return types.StatementSummary{
			StatementType: "PRAGMA_HIGH_COST",
			RiskLevel:     types.RiskHighCostRead,
			Flags:         append(flags, "pragma_high_cost"),
			Snippet:       snippet,
		}
	}
	return types.StatementSummary{
		StatementType: "PRAGMA_READ",
		RiskLevel:     types.RiskSafeRead,
		Flags:         flags,
		Snippet:       snippet,
	}
}

func analyzeSelectQuery(stmtType string, rawTokens, upper, kwUpper, flags []string, snippet string) types.StatementSummary {
	fns := extractSQLFunctions(rawTokens)
	fnRisk := types.RiskSafeRead
	for _, fn := range fns {
		if sqlAdminFunctions[fn] {
			flags = append(flags, "dangerous_admin_function")
			if riskRank(types.RiskAdmin) > riskRank(fnRisk) {
				fnRisk = types.RiskAdmin
			}
		} else if sqlWriteFunctions[fn] {
			flags = append(flags, "side_effect_function")
			if riskRank(types.RiskWrite) > riskRank(fnRisk) {
				fnRisk = types.RiskWrite
			}
		} else if sqlHighCostFunctions[fn] {
			flags = append(flags, "high_cost_function")
			if riskRank(types.RiskHighCostRead) > riskRank(fnRisk) {
				fnRisk = types.RiskHighCostRead
			}
		}
	}
	if fnRisk != types.RiskSafeRead {
		return types.StatementSummary{
			StatementType: stmtType,
			RiskLevel:     fnRisk,
			Flags:         flags,
			Snippet:       snippet,
		}
	}

	if containsToken(flags, "locking_read") {
		return types.StatementSummary{
			StatementType: stmtType,
			RiskLevel:     types.RiskHighCostRead,
			Flags:         flags,
			Snippet:       snippet,
		}
	}

	hasFrom := containsToken(kwUpper, "FROM") || stmtType == "TABLE"
	hasWhere := containsToken(kwUpper, "WHERE")
	hasLimit := containsToken(kwUpper, "LIMIT") || containsSequence(kwUpper, "FETCH", "FIRST") || containsSequence(kwUpper, "FETCH", "NEXT") || containsToken(kwUpper, "TOP")
	hasCrossJoin := containsSequence(kwUpper, "CROSS", "JOIN")
	hasCommaJoin := hasImplicitCommaJoin(upper)
	isRecursive := containsToken(flags, "recursive_cte")

	if hasCrossJoin {
		flags = append(flags, "cross_join")
	}
	if hasCommaJoin {
		flags = append(flags, "implicit_cross_join")
	}
	if containsToken(kwUpper, "SQL_CALC_FOUND_ROWS") {
		flags = append(flags, "sql_calc_found_rows")
	}
	if hasOrderByRandom(upper) {
		flags = append(flags, "order_by_random")
	}
	if hasDeepOffset(upper) {
		flags = append(flags, "deep_offset")
	}

	if stmtType == "TABLE" && !hasLimit {
		flags = append(flags, "missing_where", "missing_limit", "table_full_scan")
	} else {
		// Recursive CTEs can amplify into millions of rows even under scalar aggregates.
		scalarAgg := !isRecursive && (isScalarAggregateOnly(kwUpper) || isOracleDualQuery(kwUpper))
		hasBoundedLimit := hasBoundedTopLevelLimit(upper, 1000)
		if hasFrom && !hasWhere && !hasLimit && !scalarAgg {
			flags = append(flags, "missing_where", "missing_limit")
		} else if hasFrom && !hasLimit && !scalarAgg {
			flags = append(flags, "missing_limit")
		}
		if hasFrom && hasSelectStar(upper) && !hasWhere && !hasBoundedLimit && !scalarAgg {
			flags = append(flags, "select_star_no_where")
		}
	}

	risk := types.RiskSafeRead
	if isRecursive ||
		containsToken(flags, "order_by_random") ||
		containsToken(flags, "sql_calc_found_rows") ||
		containsToken(flags, "deep_offset") ||
		containsToken(flags, "implicit_cross_join") ||
		(hasFrom && (containsToken(flags, "missing_where") || containsToken(flags, "cross_join") || containsToken(flags, "select_star_no_where") || containsToken(flags, "table_full_scan"))) {
		risk = types.RiskHighCostRead
	}
	return types.StatementSummary{
		StatementType: stmtType,
		RiskLevel:     risk,
		Flags:         flags,
		Snippet:       snippet,
	}
}

func parseExplainInner(rawTokens []string) (bool, []string) {
	if len(rawTokens) <= 1 {
		return false, nil
	}
	isAnalyze := false
	i := 1
	n := len(rawTokens)
	if i < n && rawTokens[i] == "(" {
		depth := 0
		for i < n {
			u := strings.ToUpper(rawTokens[i])
			if u == "(" {
				depth++
			} else if u == ")" {
				depth--
				if depth <= 0 {
					i++
					break
				}
			} else if u == "ANALYZE" || u == "ANALYSE" {
				nextOff := false
				if i+1 < n {
					nextU := strings.ToUpper(rawTokens[i+1])
					if nextU == "FALSE" || nextU == "OFF" || nextU == "0" {
						nextOff = true
					}
				}
				if !nextOff {
					isAnalyze = true
				}
			}
			i++
		}
	}
	for i < n {
		u := strings.ToUpper(rawTokens[i])
		if u == "ANALYZE" || u == "ANALYSE" {
			isAnalyze = true
			i++
			continue
		}
		if sqlExplainModifiers[u] {
			i++
			continue
		}
		// ClickHouse EXPLAIN key=val options (e.g. EXPLAIN PLAN indexes = 1 SELECT ...)
		if i+2 < n && rawTokens[i+1] == "=" {
			i += 3
			continue
		}
		// Oracle EXPLAIN PLAN [SET STATEMENT_ID = ...] [INTO tbl] FOR <stmt>
		if u == "FOR" {
			i++
			break
		}
		if u == "SET" && i+3 < n && rawTokens[i+2] == "=" {
			i += 4
			continue
		}
		if u == "INTO" && i+1 < n {
			i += 2
			continue
		}
		break
	}
	if i >= n {
		return isAnalyze, nil
	}
	return isAnalyze, rawTokens[i:]
}

func filterPunctuation(tokens []string) []string {
	out := make([]string, 0, len(tokens))
	for _, t := range tokens {
		if t == "," || t == "." || t == ";" {
			continue
		}
		out = append(out, t)
	}
	return out
}

func hasImplicitCommaJoin(upper []string) bool {
	inFrom := map[int]bool{}
	depth := 0
	for i := 0; i < len(upper); i++ {
		tok := upper[i]
		switch tok {
		case "(":
			depth++
		case ")":
			delete(inFrom, depth)
			if depth > 0 {
				depth--
			}
		case "FROM":
			inFrom[depth] = true
		case "WHERE", "GROUP", "HAVING", "ORDER", "LIMIT", "FETCH", "OFFSET", "UNION", "INTERSECT", "EXCEPT", "WINDOW", "FOR", "LOCK", "INTO", "RETURNING", "SET", ";":
			inFrom[depth] = false
		case ",":
			if inFrom[depth] && i+1 < len(upper) {
				next := upper[i+1]
				if next != ")" && next != ";" && next != "LATERAL" || (next == "LATERAL" && i+2 < len(upper)) {
					return true
				}
			}
		}
	}
	return false
}

func hasOrderByRandom(upper []string) bool {
	for i := 0; i+1 < len(upper); i++ {
		if upper[i] == "ORDER" && upper[i+1] == "BY" {
			depth := 0
			for j := i + 2; j < len(upper); j++ {
				t := upper[j]
				if t == "(" {
					depth++
				} else if t == ")" {
					if depth == 0 {
						break
					}
					depth--
				} else if depth == 0 && (t == "LIMIT" || t == "OFFSET" || t == "FETCH" || t == "FOR" || t == "UNION" || t == "INTERSECT" || t == "EXCEPT" || t == ";") {
					break
				}
				if (t == "RAND" || t == "RANDOM") && j+1 < len(upper) && upper[j+1] == "(" {
					return true
				}
			}
		}
	}
	return false
}

func hasDeepOffset(upper []string) bool {
	for i := 0; i < len(upper); i++ {
		if upper[i] == "OFFSET" && i+1 < len(upper) {
			if n, err := strconv.ParseInt(upper[i+1], 10, 64); err == nil && n >= 10000 {
				return true
			}
		}
		if upper[i] == "LIMIT" && i+3 < len(upper) && upper[i+2] == "," {
			if n, err := strconv.ParseInt(upper[i+1], 10, 64); err == nil && n >= 10000 {
				return true
			}
		}
	}
	return false
}

// hasBoundedTopLevelLimit returns true when the outermost query enforces a positive numeric LIMIT/FETCH/TOP <= maxCap.
func hasBoundedTopLevelLimit(upper []string, maxCap int64) bool {
	depth := 0
	for i := 0; i < len(upper); i++ {
		tok := upper[i]
		switch tok {
		case "(":
			depth++
			continue
		case ")":
			if depth > 0 {
				depth--
			}
			continue
		}
		if depth != 0 {
			continue
		}
		switch tok {
		case "LIMIT":
			if i+3 < len(upper) && upper[i+2] == "," {
				if n, err := strconv.ParseInt(upper[i+3], 10, 64); err == nil && n > 0 && n <= maxCap {
					return true
				}
			} else if i+1 < len(upper) {
				if n, err := strconv.ParseInt(upper[i+1], 10, 64); err == nil && n > 0 && n <= maxCap {
					return true
				}
			}
		case "FETCH":
			if i+2 < len(upper) && (upper[i+1] == "FIRST" || upper[i+1] == "NEXT") {
				if n, err := strconv.ParseInt(upper[i+2], 10, 64); err == nil && n > 0 && n <= maxCap {
					return true
				}
			}
		case "TOP":
			if i+1 < len(upper) {
				if n, err := strconv.ParseInt(upper[i+1], 10, 64); err == nil && n > 0 && n <= maxCap {
					return true
				}
			}
		}
	}
	return false
}

// HasReturningClause lexically detects a top-level RETURNING clause in a single SQL statement,
// ignoring string literals and comments.
func HasReturningClause(raw string) bool {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return false
	}
	stmts, unclosed := splitSQLStatements(trimmed)
	if unclosed || len(stmts) != 1 {
		return false
	}
	tokens := tokenizeSQLWithPunctuation(stmts[0])
	depth := 0
	for _, tok := range tokens {
		switch tok {
		case "(":
			depth++
		case ")":
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 && strings.EqualFold(tok, "RETURNING") {
				return true
			}
		}
	}
	return false
}

func extractSQLFunctions(rawTokens []string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(name string) {
		if name != "" && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	for i := 1; i < len(rawTokens); i++ {
		if rawTokens[i] != "(" {
			continue
		}
		prev := rawTokens[i-1]
		if prev == "(" || prev == ")" || prev == "," || prev == "." || prev == "*" || prev == "=" || prev == ";" {
			continue
		}
		u := strings.ToUpper(prev)
		if sqlNonFunctionKeywords[u] {
			continue
		}
		fn := strings.ToLower(stripIdentifierQuotes(prev))
		if fn == "" || fn == "'str'" {
			continue
		}
		if i >= 3 && rawTokens[i-2] == "." {
			schema := strings.ToLower(stripIdentifierQuotes(rawTokens[i-3]))
			if schema != "" {
				add(schema + "." + fn)
			}
		}
		add(fn)
	}
	return out
}

func extractPragmaName(rawTokens []string) string {
	if len(rawTokens) < 2 {
		return ""
	}
	if len(rawTokens) >= 4 && rawTokens[2] == "." {
		return strings.ToLower(stripIdentifierQuotes(rawTokens[3]))
	}
	return strings.ToLower(stripIdentifierQuotes(rawTokens[1]))
}

func extractSQLTables(rawTokens []string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(tbl string) {
		if tbl != "" && !seen[tbl] {
			seen[tbl] = true
			out = append(out, tbl)
		}
	}
	inFrom := map[int]bool{}
	depth := 0
	for i := 0; i < len(rawTokens); i++ {
		tok := rawTokens[i]
		u := strings.ToUpper(tok)
		switch u {
		case "(":
			depth++
			continue
		case ")":
			delete(inFrom, depth)
			if depth > 0 {
				depth--
			}
			continue
		case "WHERE", "GROUP", "HAVING", "ORDER", "LIMIT", "FETCH", "OFFSET", "UNION", "INTERSECT", "EXCEPT", "WINDOW", "FOR", "LOCK", "INTO", "RETURNING", "SET", ";":
			inFrom[depth] = false
			continue
		}

		expectTable := false
		switch u {
		case "FROM":
			inFrom[depth] = true
			expectTable = true
		case "JOIN", "UPDATE", "TABLE", "TRUNCATE":
			expectTable = true
		case "INTO":
			// INSERT INTO tbl / COPY ... INTO / SELECT ... INTO tbl
			expectTable = true
		case ",":
			if inFrom[depth] {
				expectTable = true
			}
		}
		if !expectTable {
			continue
		}
		j := i + 1
		for j < len(rawTokens) {
			nu := strings.ToUpper(rawTokens[j])
			if nu == "ONLY" || nu == "LATERAL" {
				j++
				continue
			}
			break
		}
		if j >= len(rawTokens) {
			continue
		}
		next := rawTokens[j]
		if next == "(" || next == "," || next == ";" || next == ")" || next == "'str'" || next == "*" {
			continue
		}
		nextU := strings.ToUpper(next)
		if nextU == "VALUES" || nextU == "SELECT" || nextU == "WITH" || nextU == "PROGRAM" || nextU == "STDIN" || nextU == "STDOUT" || nextU == "OUTFILE" || nextU == "DUMPFILE" {
			continue
		}
		name := strings.ToLower(stripIdentifierQuotes(next))
		if j+2 < len(rawTokens) && rawTokens[j+1] == "." {
			part2 := strings.ToLower(stripIdentifierQuotes(rawTokens[j+2]))
			if part2 != "" && part2 != "*" {
				add(name + "." + part2)
				add(part2)
				i = j + 2
				continue
			}
		}
		add(name)
		i = j
	}
	return out
}

func stripIdentifierQuotes(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') ||
			(s[0] == '`' && s[len(s)-1] == '`') ||
			(s[0] == '[' && s[len(s)-1] == ']') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func isOracleDualQuery(kwUpper []string) bool {
	for i := 0; i < len(kwUpper)-1; i++ {
		if kwUpper[i] == "FROM" && kwUpper[i+1] == "DUAL" {
			if i+2 == len(kwUpper) {
				return true
			}
			next := kwUpper[i+2]
			if next == "WHERE" || next == "ORDER" || next == "GROUP" || next == "LIMIT" || next == "FETCH" {
				return true
			}
		}
	}
	return false
}

func isScalarAggregateOnly(upper []string) bool {
	if containsToken(upper, "GROUP") {
		return false
	}
	// Heuristic: SELECT count(*)/min/max/sum/avg without GROUP BY returns 1 row, though still inspected by EXPLAIN preflight.
	for i := 0; i < len(upper)-1; i++ {
		if upper[i] == "FROM" {
			break
		}
		if upper[i] == "COUNT" || upper[i] == "SUM" || upper[i] == "AVG" || upper[i] == "MIN" || upper[i] == "MAX" {
			return true
		}
	}
	return false
}

func hasSelectStar(upper []string) bool {
	for i, tok := range upper {
		if tok == "FROM" {
			break
		}
		if i > 0 && tok == "*" && upper[i-1] != "(" {
			return true
		}
	}
	return false
}

func selectIntoTable(upper []string) bool {
	for i := 0; i < len(upper); i++ {
		if upper[i] == "FROM" {
			return false
		}
		if upper[i] == "INTO" {
			return true
		}
	}
	return false
}

// splitSQLStatements splits multi-statement SQL while honoring quotes, PG dollar quotes, and comments.
func splitSQLStatements(s string) ([]string, bool) {
	var stmts []string
	var cur strings.Builder
	i := 0
	n := len(s)
	inSingle := false
	inDouble := false
	inBacktick := false
	lineComment := false
	blockDepth := 0
	inMySQLExec := false
	dollarTag := ""

	for i < n {
		ch := s[i]
		if lineComment {
			if ch == '\n' {
				lineComment = false
				cur.WriteByte(ch)
			}
			i++
			continue
		}
		if blockDepth > 0 {
			if ch == '/' && i+1 < n && s[i+1] == '*' {
				blockDepth++
				i += 2
				continue
			}
			if ch == '*' && i+1 < n && s[i+1] == '/' {
				blockDepth--
				i += 2
				continue
			}
			i++
			continue
		}
		if inMySQLExec && ch == '*' && i+1 < n && s[i+1] == '/' {
			inMySQLExec = false
			cur.WriteByte(' ')
			i += 2
			continue
		}
		if dollarTag != "" {
			if strings.HasPrefix(s[i:], dollarTag) {
				cur.WriteString(dollarTag)
				i += len(dollarTag)
				dollarTag = ""
				continue
			}
			cur.WriteByte(ch)
			i++
			continue
		}
		if inSingle {
			cur.WriteByte(ch)
			if ch == '\\' && i+1 < n {
				cur.WriteByte(s[i+1])
				i += 2
				continue
			}
			if ch == '\'' {
				if i+1 < n && s[i+1] == '\'' {
					cur.WriteByte('\'')
					i += 2
					continue
				}
				inSingle = false
			}
			i++
			continue
		}
		if inDouble {
			cur.WriteByte(ch)
			if ch == '"' {
				if i+1 < n && s[i+1] == '"' {
					cur.WriteByte('"')
					i += 2
					continue
				}
				inDouble = false
			}
			i++
			continue
		}
		if inBacktick {
			cur.WriteByte(ch)
			if ch == '`' {
				if i+1 < n && s[i+1] == '`' {
					cur.WriteByte('`')
					i += 2
					continue
				}
				inBacktick = false
			}
			i++
			continue
		}

		// Outside quotes/comments:
		if ch == '-' && i+1 < n && s[i+1] == '-' {
			lineComment = true
			i += 2
			continue
		}
		if ch == '#' {
			lineComment = true
			i++
			continue
		}
		if ch == '/' && i+1 < n && s[i+1] == '*' {
			// Treat MySQL conditional comment /*!50000 ... */ as executable SQL by stripping the wrapper.
			if i+2 < n && s[i+2] == '!' {
				cur.WriteByte(' ')
				i += 3
				for k := 0; k < 5 && i < n && s[i] >= '0' && s[i] <= '9'; k++ {
					i++
				}
				inMySQLExec = true
				continue
			}
			blockDepth = 1
			i += 2
			continue
		}
		if ch == '\'' {
			inSingle = true
			cur.WriteByte(ch)
			i++
			continue
		}
		if ch == '"' {
			inDouble = true
			cur.WriteByte(ch)
			i++
			continue
		}
		if ch == '`' {
			inBacktick = true
			cur.WriteByte(ch)
			i++
			continue
		}
		if ch == '$' {
			if tag, ok := parseDollarTag(s[i:]); ok {
				dollarTag = tag
				cur.WriteString(tag)
				i += len(tag)
				continue
			}
		}
		if ch == ';' {
			part := strings.TrimSpace(cur.String())
			if part != "" {
				stmts = append(stmts, part)
			}
			cur.Reset()
			i++
			continue
		}
		cur.WriteByte(ch)
		i++
	}

	if inSingle || inDouble || inBacktick || blockDepth > 0 || dollarTag != "" {
		return stmts, true
	}
	if tail := strings.TrimSpace(cur.String()); tail != "" {
		stmts = append(stmts, tail)
	}
	return stmts, false
}

func parseDollarTag(rest string) (string, bool) {
	if len(rest) < 2 || rest[0] != '$' {
		return "", false
	}
	if rest[1] == '$' {
		return "$$", true
	}
	for i := 1; i < len(rest) && i < 64; i++ {
		c := rest[i]
		if c == '$' {
			return rest[:i+1], true
		}
		if !unicode.IsLetter(rune(c)) && !unicode.IsDigit(rune(c)) && c != '_' {
			return "", false
		}
	}
	return "", false
}

func tokenizeSQLWithPunctuation(stmt string) []string {
	var tokens []string
	i := 0
	n := len(stmt)
	for i < n {
		ch := stmt[i]
		if unicode.IsSpace(rune(ch)) {
			i++
			continue
		}
		if ch == ',' || ch == ';' || ch == '.' || ch == '(' || ch == ')' || ch == '*' || ch == '=' {
			tokens = append(tokens, string(ch))
			i++
			continue
		}
		if ch == '\'' {
			i++
			for i < n {
				if stmt[i] == '\\' && i+1 < n {
					i += 2
					continue
				}
				if stmt[i] == '\'' {
					if i+1 < n && stmt[i+1] == '\'' {
						i += 2
						continue
					}
					i++
					break
				}
				i++
			}
			tokens = append(tokens, "'str'")
			continue
		}
		if ch == '"' || ch == '`' {
			quote := ch
			start := i
			i++
			for i < n {
				if stmt[i] == quote {
					if i+1 < n && stmt[i+1] == quote {
						i += 2
						continue
					}
					i++
					break
				}
				i++
			}
			tokens = append(tokens, stmt[start:i])
			continue
		}
		if ch == '$' {
			if tag, ok := parseDollarTag(stmt[i:]); ok {
				end := strings.Index(stmt[i+len(tag):], tag)
				if end >= 0 {
					i += len(tag) + end + len(tag)
					tokens = append(tokens, "'str'")
					continue
				}
			}
		}
		start := i
		for i < n {
			c := stmt[i]
			if unicode.IsSpace(rune(c)) || c == ',' || c == ';' || c == '.' || c == '(' || c == ')' || c == '*' || c == '=' || c == '\'' || c == '"' || c == '`' {
				break
			}
			i++
		}
		tokens = append(tokens, stmt[start:i])
	}
	return tokens
}

func containsToken(list []string, target string) bool {
	for _, s := range list {
		if s == target {
			return true
		}
	}
	return false
}

func containsSequence(list []string, seq ...string) bool {
	if len(seq) == 0 || len(list) < len(seq) {
		return false
	}
	for i := 0; i <= len(list)-len(seq); i++ {
		match := true
		for j := range seq {
			if list[i+j] != seq[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func riskRank(r types.RiskLevel) int {
	switch r {
	case types.RiskSafeRead:
		return 1
	case types.RiskHighCostRead:
		return 2
	case types.RiskWrite:
		return 3
	case types.RiskDDL:
		return 4
	case types.RiskAdmin:
		return 5
	case types.RiskUnknown:
		return 6
	default:
		return 6
	}
}

func truncateSnippet(s string, maxLen int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func sortStrings(ss []string) {
	for i := 1; i < len(ss); i++ {
		for j := i; j > 0 && ss[j] < ss[j-1]; j-- {
			ss[j], ss[j-1] = ss[j-1], ss[j]
		}
	}
}
