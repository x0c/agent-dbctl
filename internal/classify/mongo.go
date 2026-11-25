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
			}
		}
		if containsToken(flags, "where_js_eval") {
			risk = types.RiskHighCostRead
		}
		out.RiskLevel = risk
		out.IsReadOnly = true
		out.RiskFlags = flags
		out.Summary = fmt.Sprintf("MongoDB %s (%s)", method, risk)
		return out

	case "countdocuments", "estimateddocumentcount", "distinct", "getindexes", "stats":
		out.RiskLevel = types.RiskSafeRead
		out.IsReadOnly = true
		out.Summary = fmt.Sprintf("MongoDB %s (safe_read)", method)
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

	switch {
	case hasKey("ping"), hasKey("buildInfo"), hasKey("listCollections"), hasKey("listDatabases"), hasKey("explain"), hasKey("count"), hasKey("distinct"):
		out.RiskLevel = types.RiskSafeRead
		out.IsReadOnly = true
		out.Summary = "MongoDB read/metadata command"
	case hasKey("find"):
		risk := types.RiskSafeRead
		var flags []string
		filter, _ := doc["filter"].(map[string]any)
		_, hasLimit := doc["limit"]
		if len(filter) == 0 && !hasLimit {
			flags = append(flags, "empty_filter_no_limit")
			risk = types.RiskHighCostRead
		}
		if filter != nil {
			if _, hasWhere := filter["$where"]; hasWhere {
				flags = append(flags, "where_js_eval")
				risk = types.RiskHighCostRead
			}
		}
		out.RiskLevel = risk
		out.IsReadOnly = true
		out.RiskFlags = flags
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
			out.RiskFlags = []string{"aggregate_write_stage"}
			out.Summary = "MongoDB aggregate with $out/$merge"
			return out
		}
		out.IsReadOnly = true
		if !hasLimit {
			out.RiskLevel = types.RiskHighCostRead
			out.RiskFlags = []string{"aggregate_missing_limit"}
			out.Summary = "MongoDB aggregate without $limit"
		} else {
			out.RiskLevel = types.RiskSafeRead
			out.Summary = "MongoDB bounded aggregate"
		}
	case hasKey("insert"), hasKey("update"), hasKey("delete"), hasKey("findAndModify"):
		out.RiskLevel = types.RiskWrite
		out.Summary = "MongoDB write command"
	case hasKey("create"), hasKey("drop"), hasKey("createIndexes"), hasKey("dropIndexes"), hasKey("dropDatabase"):
		out.RiskLevel = types.RiskDDL
		out.Summary = "MongoDB DDL command"
	case hasKey("shutdown"), hasKey("fsync"), hasKey("killOp"), hasKey("eval"):
		out.RiskLevel = types.RiskAdmin
		out.Summary = "MongoDB admin command"
	default:
		out.RiskFlags = []string{"unrecognized_mongo_command"}
		out.Summary = "Unrecognized MongoDB command (fail-closed)"
	}
	return out
}
