package classify

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/x0c/agent-dbctl/internal/types"
)

// Classify evaluates raw statements/commands for an engine and returns fail-closed risk classification.
func Classify(engine, raw string) types.Classification {
	eng := normalizeEngine(engine)
	switch eng {
	case "mongodb":
		return classifyMongo(engine, raw)
	case "redis":
		return classifyRedis(engine, raw)
	default:
		return classifySQL(engine, raw)
	}
}

func normalizeEngine(engine string) string {
	e := strings.ToLower(strings.TrimSpace(engine))
	switch {
	case strings.Contains(e, "mongo"):
		return "mongodb"
	case strings.Contains(e, "redis"), strings.Contains(e, "valkey"):
		return "redis"
	default:
		return e
	}
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
	tokens := tokenizeSQLKeywordsAndStructure(stmt)
	snippet := truncateSnippet(stmt, 120)
	if len(tokens) == 0 {
		return types.StatementSummary{
			StatementType: "UNKNOWN",
			RiskLevel:     types.RiskUnknown,
			Flags:         []string{"empty_statement"},
			Snippet:       snippet,
		}
	}

	upper := make([]string, len(tokens))
	for i, t := range tokens {
		upper[i] = strings.ToUpper(t)
	}
	first := upper[0]

	var flags []string
	if containsSequence(upper, "FOR", "UPDATE") || containsSequence(upper, "FOR", "SHARE") ||
		containsSequence(upper, "FOR", "NO", "KEY", "UPDATE") || containsSequence(upper, "LOCK", "IN", "SHARE", "MODE") {
		flags = append(flags, "locking_read")
	}
	if containsToken(upper, "INTO") && (first == "SELECT" || first == "WITH") &&
		(containsSequence(upper, "INTO", "OUTFILE") || containsSequence(upper, "INTO", "DUMPFILE") || !containsToken(upper, "INSERT")) {
		// SELECT ... INTO creates a table or writes a file in PG/MySQL.
		if containsSequence(upper, "INTO", "OUTFILE") || containsSequence(upper, "INTO", "DUMPFILE") || selectIntoTable(upper) {
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
		if containsToken(upper[1:], "ANALYZE") || containsToken(upper[1:], "ANALYSE") {
			return types.StatementSummary{
				StatementType: "EXPLAIN_ANALYZE",
				RiskLevel:     types.RiskHighCostRead,
				Flags:         append(flags, "explain_analyze"),
				Snippet:       snippet,
			}
		}
		// Ensure EXPLAIN doesn't wrap a DML unless explicitly flagged.
		inner := findInnerVerbAfterExplain(upper[1:])
		if inner == "INSERT" || inner == "UPDATE" || inner == "DELETE" || inner == "MERGE" {
			return types.StatementSummary{
				StatementType: "EXPLAIN_" + inner,
				RiskLevel:     types.RiskHighCostRead,
				Flags:         append(flags, "explain_dml"),
				Snippet:       snippet,
			}
		}
		return types.StatementSummary{
			StatementType: "EXPLAIN",
			RiskLevel:     types.RiskSafeRead,
			Flags:         flags,
			Snippet:       snippet,
		}

	case "WITH":
		// Detect data-modifying CTEs (e.g. WITH del AS (DELETE FROM t RETURNING *) SELECT * FROM del).
		for _, kw := range upper[1:] {
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
		return analyzeSelectQuery("WITH_SELECT", upper, flags, snippet)

	case "SELECT", "VALUES", "TABLE":
		return analyzeSelectQuery(first, upper, flags, snippet)

	case "SHOW", "DESCRIBE", "DESC":
		return types.StatementSummary{
			StatementType: first,
			RiskLevel:     types.RiskSafeRead,
			Flags:         flags,
			Snippet:       snippet,
		}

	case "PRAGMA":
		if containsToken(upper, "=") {
			return types.StatementSummary{
				StatementType: "PRAGMA_WRITE",
				RiskLevel:     types.RiskAdmin,
				Flags:         append(flags, "pragma_mutate"),
				Snippet:       snippet,
			}
		}
		return types.StatementSummary{
			StatementType: "PRAGMA_READ",
			RiskLevel:     types.RiskSafeRead,
			Flags:         flags,
			Snippet:       snippet,
		}

	case "INSERT", "REPLACE":
		return types.StatementSummary{
			StatementType: first,
			RiskLevel:     types.RiskWrite,
			Flags:         flags,
			Snippet:       snippet,
		}

	case "UPDATE", "DELETE", "MERGE":
		if !containsToken(upper, "WHERE") && first != "MERGE" {
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

	case "GRANT", "REVOKE", "COPY", "LOAD", "CALL", "EXEC", "EXECUTE", "VACUUM", "ANALYZE", "REINDEX", "CLUSTER", "KILL", "FLUSH", "LOCK", "UNLOCK", "SET", "USE", "ATTACH", "DETACH":
		if first == "COPY" && containsToken(upper, "PROGRAM") {
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

func analyzeSelectQuery(stmtType string, upper []string, flags []string, snippet string) types.StatementSummary {
	if containsToken(flags, "locking_read") {
		return types.StatementSummary{
			StatementType: stmtType,
			RiskLevel:     types.RiskHighCostRead,
			Flags:         flags,
			Snippet:       snippet,
		}
	}
	hasFrom := containsToken(upper, "FROM")
	hasWhere := containsToken(upper, "WHERE")
	hasLimit := containsToken(upper, "LIMIT") || containsSequence(upper, "FETCH", "FIRST") || containsSequence(upper, "FETCH", "NEXT") || containsToken(upper, "TOP")
	hasCrossJoin := containsSequence(upper, "CROSS", "JOIN")

	if hasCrossJoin {
		flags = append(flags, "cross_join")
	}
	// Queries with FROM and neither WHERE nor LIMIT risk scanning entire tables.
	if hasFrom && !hasWhere && !hasLimit && !isScalarAggregateOnly(upper) {
		flags = append(flags, "missing_where", "missing_limit")
	} else if hasFrom && !hasLimit && !isSinglePointOrAggregate(upper) {
		flags = append(flags, "missing_limit")
	}
	if hasFrom && hasSelectStar(upper) && !hasWhere {
		flags = append(flags, "select_star_no_where")
	}

	risk := types.RiskSafeRead
	if hasFrom && (containsToken(flags, "missing_where") || containsToken(flags, "cross_join") || containsToken(flags, "select_star_no_where")) {
		risk = types.RiskHighCostRead
	}
	return types.StatementSummary{
		StatementType: stmtType,
		RiskLevel:     risk,
		Flags:         flags,
		Snippet:       snippet,
	}
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

func isSinglePointOrAggregate(upper []string) bool {
	return isScalarAggregateOnly(upper)
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

func findInnerVerbAfterExplain(rest []string) string {
	for _, tok := range rest {
		switch tok {
		case "ANALYZE", "ANALYSE", "VERBOSE", "COSTS", "SETTINGS", "BUFFERS", "WAL", "TIMING", "SUMMARY", "FORMAT", "JSON", "TEXT", "XML", "YAML", "EXTENDED", "PARTITIONS", "TREE":
			continue
		default:
			return tok
		}
	}
	return ""
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

func tokenizeSQLKeywordsAndStructure(stmt string) []string {
	var tokens []string
	i := 0
	n := len(stmt)
	for i < n {
		ch := stmt[i]
		if unicode.IsSpace(rune(ch)) || ch == ',' || ch == ';' {
			i++
			continue
		}
		if ch == '(' || ch == ')' || ch == '*' || ch == '=' {
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
			if unicode.IsSpace(rune(c)) || c == ',' || c == ';' || c == '(' || c == ')' || c == '*' || c == '=' || c == '\'' || c == '"' || c == '`' {
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
