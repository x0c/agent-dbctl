package classify

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/x0c/agent-dbctl/internal/types"
)

var mongoshMethodRe = regexp.MustCompile(`(?s)^db\.(?:getCollection\(["']([^"']+)["']\)|([A-Za-z0-9_$-]+))\.([A-Za-z0-9_]+)\((.*)\)(?:\.[A-Za-z0-9_]+\(.*\))*\s*;?$`)

func classifyMongo(engine, raw string) types.Classification {
	trimmed := strings.TrimSpace(raw)
	out := types.Classification{
		Engine:         engine,
		Family:         types.FamilyDocument,
		RiskLevel:      types.RiskUnknown,
		IsReadOnly:     false,
		StatementCount: 1,
	}
	if trimmed == "" {
		out.RiskFlags = []string{"empty_query"}
		out.Summary = "Empty MongoDB command (fail-closed)"
		return out
	}

	lower := strings.ToLower(trimmed)
	if lower == "show dbs" || lower == "show databases" || lower == "show collections" || lower == "show tables" {
		out.RiskLevel = types.RiskSafeRead
		out.IsReadOnly = true
		out.Summary = "MongoDB metadata command"
		return out
	}

	// 1. JSON RunCommand form.
	if strings.HasPrefix(trimmed, "{") {
		var doc map[string]any
		if err := json.Unmarshal([]byte(trimmed), &doc); err != nil {
			out.RiskFlags = []string{"invalid_json_command"}
			out.Summary = "Invalid MongoDB JSON command (fail-closed)"
			return out
		}
		return classifyMongoDoc(engine, doc)
	}

	// 2. mongosh form: db.<coll>.<method>(...)
	m := mongoshMethodRe.FindStringSubmatch(trimmed)
	if len(m) == 0 {
		out.RiskFlags = []string{"unrecognized_mongosh_syntax"}
		out.Summary = "Unrecognized MongoDB syntax (fail-closed)"
		return out
	}
	method := strings.ToLower(m[3])
	argsBody := strings.TrimSpace(m[4])
	var flags []string

	if strings.Contains(trimmed, "$where") {
		flags = append(flags, "where_js_eval")
	}
	if strings.Contains(trimmed, "$function") || strings.Contains(trimmed, "$accumulator") {
		flags = append(flags, "js_eval_operator")
	}
	if strings.Contains(trimmed, "$lookup") || strings.Contains(trimmed, "$graphLookup") {
		flags = append(flags, "aggregate_join")
	}
	if strings.Contains(lower, "allowdiskuse") {
		flags = append(flags, "allow_disk_use")
	}
	if strings.Contains(lower, "nocursortimeout") {
		flags = append(flags, "no_cursor_timeout")
	}
	if strings.Contains(lower, ".explain(") && (strings.Contains(lower, "executionstats") || strings.Contains(lower, "allplansexecution")) {
		flags = append(flags, "explain_execution_stats")
	}

	switch method {
	case "find", "findone":
		risk := types.RiskSafeRead
		if method == "find" {
			hasLimit := strings.Contains(lower, ".limit(")
			emptyFilter := argsBody == "" || strings.HasPrefix(strings.ReplaceAll(argsBody, " ", ""), "{}")
			if emptyFilter && !hasLimit {
				flags = append(flags, "empty_filter_no_limit")
				risk = types.RiskHighCostRead
			} else if !hasLimit {
				flags = append(flags, "missing_limit")
				risk = types.RiskHighCostRead
			}
		}
		if hasAnyFlag(flags, "where_js_eval", "js_eval_operator", "no_cursor_timeout", "allow_disk_use", "explain_execution_stats") {
			risk = types.RiskHighCostRead
		}
		out.RiskLevel = risk
		out.IsReadOnly = true
		out.RiskFlags = flags
		out.Summary = fmt.Sprintf("MongoDB %s (%s)", method, risk)
		return out

	case "countdocuments", "estimateddocumentcount", "distinct", "getindexes", "stats":
		risk := types.RiskSafeRead
		if method == "countdocuments" && (argsBody == "" || strings.HasPrefix(strings.ReplaceAll(argsBody, " ", ""), "{}")) {
			flags = append(flags, "empty_filter_count")
			risk = types.RiskHighCostRead
		}
		if hasAnyFlag(flags, "where_js_eval", "js_eval_operator", "explain_execution_stats") {
			risk = types.RiskHighCostRead
		}
		out.RiskLevel = risk
		out.IsReadOnly = true
		out.RiskFlags = flags
		out.Summary = fmt.Sprintf("MongoDB %s (%s)", method, risk)
		return out

	case "aggregate":
		if strings.Contains(lower, `"$out"`) || strings.Contains(lower, "'$out'") || strings.Contains(lower, "$out:") ||
			strings.Contains(lower, `"$merge"`) || strings.Contains(lower, "'$merge'") || strings.Contains(lower, "$merge:") {
			out.RiskLevel = types.RiskWrite
			out.IsReadOnly = false
			out.RiskFlags = append(flags, "aggregate_write_stage")
			out.Summary = "MongoDB aggregate with write stage ($out/$merge)"
			return out
		}
		risk := types.RiskSafeRead
		if !strings.Contains(lower, "$limit") {
			flags = append(flags, "aggregate_missing_limit")
			risk = types.RiskHighCostRead
		}
		if hasAnyFlag(flags, "where_js_eval", "js_eval_operator", "aggregate_join", "allow_disk_use", "no_cursor_timeout", "explain_execution_stats") {
			risk = types.RiskHighCostRead
		}
		out.RiskLevel = risk
		out.IsReadOnly = true
		out.RiskFlags = flags
		out.Summary = fmt.Sprintf("MongoDB aggregate (%s)", risk)
		return out

	case "insertone", "insertmany", "insert", "updateone", "updatemany", "update", "replaceone", "deleteone", "deletemany", "remove", "findoneandupdate", "findoneandreplace", "findoneanddelete", "findandmodify", "bulkwrite":
		out.RiskLevel = types.RiskWrite
		out.IsReadOnly = false
		out.RiskFlags = flags
		out.Summary = fmt.Sprintf("MongoDB write (%s)", method)
		return out

	case "drop", "dropindex", "dropindexes", "createindex", "createindexes", "renamecollection":
		out.RiskLevel = types.RiskDDL
		out.IsReadOnly = false
		out.RiskFlags = flags
		out.Summary = fmt.Sprintf("MongoDB DDL (%s)", method)
		return out

	default:
		out.RiskFlags = append(flags, "unrecognized_mongo_method")
		out.Summary = fmt.Sprintf("Unrecognized MongoDB method %s (fail-closed)", method)
		return out
	}
}

func classifyMongoDoc(engine string, doc map[string]any) types.Classification {
	out := types.Classification{
		Engine:         engine,
		Family:         types.FamilyDocument,
		RiskLevel:      types.RiskUnknown,
		IsReadOnly:     false,
		StatementCount: 1,
	}
	hasKey := func(k string) bool {
		_, ok := doc[k]
		return ok
	}

	scannedFlags, ops := scanMongoDocHazards(doc)
	_ = ops

	switch {
	case hasKey("explain"):
		verbosity, _ := doc["verbosity"].(string)
		verbLower := strings.ToLower(strings.TrimSpace(verbosity))
		execStats := verbLower == "executionstats" || verbLower == "allplansexecution"

		var innerCls types.Classification
		if innerMap, ok := doc["explain"].(map[string]any); ok {
			innerCls = classifyMongoDoc(engine, innerMap)
		} else {
			innerCls = types.Classification{
				Engine:     engine,
				Family:     types.FamilyDocument,
				RiskLevel:  types.RiskUnknown,
				IsReadOnly: false,
				RiskFlags:  []string{"unrecognized_explain_target"},
			}
		}
		flags := deduplicateFlags(append(scannedFlags, innerCls.RiskFlags...))
		if execStats {
			flags = deduplicateFlags(append(flags, "explain_execution_stats"))
			if riskRank(innerCls.RiskLevel) >= riskRank(types.RiskWrite) {
				flags = deduplicateFlags(append(flags, "explain_executes_write"))
				out.RiskLevel = innerCls.RiskLevel
				out.IsReadOnly = false
				out.RiskFlags = flags
				out.Summary = fmt.Sprintf("MongoDB explain(%s) on %s command", verbosity, innerCls.RiskLevel)
				return out
			}
			out.RiskLevel = types.RiskHighCostRead
			out.IsReadOnly = true
			out.RiskFlags = flags
			out.Summary = fmt.Sprintf("MongoDB explain(%s) executes query", verbosity)
			return out
		}
		if riskRank(innerCls.RiskLevel) >= riskRank(types.RiskWrite) {
			out.RiskLevel = types.RiskHighCostRead
			out.IsReadOnly = true
			out.RiskFlags = deduplicateFlags(append(flags, "explain_dml"))
			out.Summary = "MongoDB explain wrapping mutating command"
			return out
		}
		if len(flags) > 0 {
			out.RiskLevel = types.RiskHighCostRead
			out.IsReadOnly = true
			out.RiskFlags = flags
			out.Summary = "MongoDB explain with high-cost query flags"
			return out
		}
		out.RiskLevel = types.RiskSafeRead
		out.IsReadOnly = true
		out.Summary = "MongoDB explain (queryPlanner)"

	case hasKey("ping"), hasKey("buildInfo"), hasKey("listCollections"), hasKey("listDatabases"), hasKey("distinct"):
		if len(scannedFlags) > 0 {
			out.RiskLevel = types.RiskHighCostRead
			out.RiskFlags = scannedFlags
		} else {
			out.RiskLevel = types.RiskSafeRead
		}
		out.IsReadOnly = true
		out.Summary = fmt.Sprintf("MongoDB read/metadata command (%s)", out.RiskLevel)

	case hasKey("count"):
		flags := append([]string{}, scannedFlags...)
		risk := types.RiskSafeRead
		queryMap, _ := doc["query"].(map[string]any)
		if len(queryMap) == 0 {
			flags = append(flags, "empty_filter_count")
			risk = types.RiskHighCostRead
		}
		if len(flags) > 0 {
			risk = types.RiskHighCostRead
		}
		out.RiskLevel = risk
		out.IsReadOnly = true
		out.RiskFlags = deduplicateFlags(flags)
		out.Summary = fmt.Sprintf("MongoDB count (%s)", risk)

	case hasKey("find"):
		risk := types.RiskSafeRead
		flags := append([]string{}, scannedFlags...)
		filter, _ := doc["filter"].(map[string]any)
		_, hasLimit := doc["limit"]
		if len(filter) == 0 && !hasLimit {
			flags = append(flags, "empty_filter_no_limit")
			risk = types.RiskHighCostRead
		} else if !hasLimit {
			flags = append(flags, "missing_limit")
			risk = types.RiskHighCostRead
		}
		if len(flags) > 0 {
			risk = types.RiskHighCostRead
		}
		out.RiskLevel = risk
		out.IsReadOnly = true
		out.RiskFlags = deduplicateFlags(flags)
		out.Summary = fmt.Sprintf("MongoDB find (%s)", risk)

	case hasKey("aggregate"):
		pipeline, _ := doc["pipeline"].([]any)
		hasLimit := false
		hasWriteStage := false
		for _, stage := range pipeline {
			m, ok := stage.(map[string]any)
			if !ok {
				continue
			}
			if _, ok := m["$out"]; ok {
				hasWriteStage = true
			}
			if _, ok := m["$merge"]; ok {
				hasWriteStage = true
			}
			if _, ok := m["$limit"]; ok {
				hasLimit = true
			}
		}
		if hasWriteStage {
			out.RiskLevel = types.RiskWrite
			out.RiskFlags = deduplicateFlags(append(scannedFlags, "aggregate_write_stage"))
			out.Summary = "MongoDB aggregate with $out/$merge"
			return out
		}
		out.IsReadOnly = true
		flags := append([]string{}, scannedFlags...)
		if !hasLimit {
			flags = append(flags, "aggregate_missing_limit")
		}
		if len(flags) > 0 {
			out.RiskLevel = types.RiskHighCostRead
			out.RiskFlags = deduplicateFlags(flags)
			out.Summary = "MongoDB aggregate (high_cost_read)"
		} else {
			out.RiskLevel = types.RiskSafeRead
			out.Summary = "MongoDB bounded aggregate"
		}

	case hasKey("insert"), hasKey("update"), hasKey("delete"), hasKey("findAndModify"):
		out.RiskLevel = types.RiskWrite
		out.RiskFlags = scannedFlags
		out.Summary = "MongoDB write command"
	case hasKey("create"), hasKey("drop"), hasKey("createIndexes"), hasKey("dropIndexes"), hasKey("dropDatabase"):
		out.RiskLevel = types.RiskDDL
		out.RiskFlags = scannedFlags
		out.Summary = "MongoDB DDL command"
	case hasKey("shutdown"), hasKey("fsync"), hasKey("killOp"), hasKey("eval"):
		out.RiskLevel = types.RiskAdmin
		out.RiskFlags = scannedFlags
		out.Summary = "MongoDB admin command"
	default:
		out.RiskFlags = deduplicateFlags(append(scannedFlags, "unrecognized_mongo_command"))
		out.Summary = "Unrecognized MongoDB command (fail-closed)"
	}
	return out
}

func scanMongoDocHazards(v any) ([]string, []string) {
	var flags []string
	var ops []string
	var walk func(cur any)
	walk = func(cur any) {
		switch x := cur.(type) {
		case map[string]any:
			for k, val := range x {
				if strings.HasPrefix(k, "$") {
					ops = append(ops, k)
				}
				switch k {
				case "$where":
					flags = append(flags, "where_js_eval")
				case "$function", "$accumulator":
					flags = append(flags, "js_eval_operator")
				case "$out", "$merge":
					flags = append(flags, "aggregate_write_stage")
				case "$lookup", "$graphLookup":
					flags = append(flags, "aggregate_join")
				case "$regex":
					if s, ok := val.(string); ok && s != "" && !strings.HasPrefix(s, "^") {
						flags = append(flags, "unanchored_regex")
					}
				case "allowDiskUse":
					if b, ok := val.(bool); ok && b {
						flags = append(flags, "allow_disk_use")
					}
				case "noCursorTimeout":
					if b, ok := val.(bool); ok && b {
						flags = append(flags, "no_cursor_timeout")
					}
				}
				walk(val)
			}
		case []any:
			for _, item := range x {
				walk(item)
			}
		}
	}
	walk(v)
	return deduplicateFlags(flags), deduplicateFlags(ops)
}

func hasAnyFlag(flags []string, targets ...string) bool {
	for _, t := range targets {
		if containsToken(flags, t) {
			return true
		}
	}
	return false
}

func deduplicateFlags(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sortStrings(out)
	return out
}
