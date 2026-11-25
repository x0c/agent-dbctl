package driver

import (
	"fmt"
	"sort"
	"strings"

	"github.com/x0c/agent-dbctl/internal/types"
)

// CanPreflightSQL returns true when a single SQL statement can be safely wrapped in non-mutating EXPLAIN.
func CanPreflightSQL(cls types.Classification) bool {
	if cls.StatementCount != 1 || len(cls.Statements) != 1 {
		return false
	}
	st := cls.Statements[0].StatementType
	if strings.HasPrefix(st, "EXPLAIN") {
		return false
	}
	if cls.IsReadOnly {
		return true
	}
	switch st {
	case "INSERT", "REPLACE", "UPDATE", "DELETE", "MERGE":
		return true
	default:
		return false
	}
}

// NormalizeSchemaListLimit clamps schema listing limits to a safe bounded range (default 100, max 500).
func NormalizeSchemaListLimit(limit int) int {
	if limit <= 0 {
		return 100
	}
	if limit > 500 {
		return 500
	}
	return limit
}

// FilterAndCapSchemaObjects filters objects by substring search and caps the returned slice cleanly.
func FilterAndCapSchemaObjects(items []types.SchemaObjectSummary, search string, limit int) (out []types.SchemaObjectSummary, total int, truncated bool) {
	kw := strings.ToLower(strings.TrimSpace(search))
	lim := NormalizeSchemaListLimit(limit)
	var filtered []types.SchemaObjectSummary
	for _, it := range items {
		if kw != "" {
			hay := strings.ToLower(it.Schema + "." + it.Name + " " + it.Name + " " + it.Type)
			if !strings.Contains(hay, kw) {
				continue
			}
		}
		filtered = append(filtered, it)
	}
	total = len(filtered)
	if total > lim {
		return filtered[:lim], total, true
	}
	if filtered == nil {
		filtered = []types.SchemaObjectSummary{}
	}
	return filtered, total, false
}

// SplitQualifiedObject splits an optional "schema.table" name into trimmed components.
func SplitQualifiedObject(raw string) (schema string, name string) {
	trimmed := strings.TrimSpace(raw)
	if s, n, ok := strings.Cut(trimmed, "."); ok {
		return strings.Trim(s, `"`+"`[]"), strings.Trim(n, `"`+"`[]")
	}
	return "", strings.Trim(trimmed, `"`+"`[]")
}

// QuoteSQLiteIdent safely quotes a SQLite identifier after verification.
func QuoteSQLiteIdent(ident string) string {
	return `"` + strings.ReplaceAll(ident, `"`, `""`) + `"`
}

// ParsePGIndexColumns extracts the column expression list inside parentheses from a PostgreSQL indexdef string.
func ParsePGIndexColumns(indexDef string) []string {
	openIdx := strings.IndexByte(indexDef, '(')
	closeIdx := strings.LastIndexByte(indexDef, ')')
	if openIdx < 0 || closeIdx <= openIdx+1 {
		return nil
	}
	rawCols := strings.Split(indexDef[openIdx+1:closeIdx], ",")
	out := make([]string, 0, len(rawCols))
	for _, c := range rawCols {
		c = strings.TrimSpace(c)
		if c != "" {
			out = append(out, c)
		}
	}
	return out
}

// JSONTypeLabel returns a concise JSON-friendly type name for sampled document field values.
func JSONTypeLabel(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case bool:
		return "bool"
	case string:
		return "string"
	case int, int32, int64, uint, uint32, uint64, float32, float64:
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	default:
		return fmt.Sprintf("%T", x)
	}
}

// CollectSampleFields inspects normalized document maps and aggregates sorted field names and observed types.
func CollectSampleFields(docs []any) []types.SchemaSampleField {
	fieldTypes := map[string]map[string]bool{}
	for _, d := range docs {
		m, ok := d.(map[string]any)
		if !ok {
			continue
		}
		for k, v := range m {
			if fieldTypes[k] == nil {
				fieldTypes[k] = map[string]bool{}
			}
			fieldTypes[k][JSONTypeLabel(v)] = true
		}
	}
	keys := make([]string, 0, len(fieldTypes))
	for k := range fieldTypes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]types.SchemaSampleField, 0, len(keys))
	for _, k := range keys {
		ts := make([]string, 0, len(fieldTypes[k]))
		for t := range fieldTypes[k] {
			ts = append(ts, t)
		}
		sort.Strings(ts)
		out = append(out, types.SchemaSampleField{Name: k, Types: ts})
	}
	return out
}

// RedisKeyPrefix groups a key into a prefix pattern (split by ':' or '_') for bounded keyspace discovery.
func RedisKeyPrefix(key string) string {
	if idx := strings.IndexByte(key, ':'); idx > 0 {
		return key[:idx+1] + "*"
	}
	if idx := strings.IndexByte(key, '_'); idx > 0 {
		return key[:idx+1] + "*"
	}
	return key
}

// BuildRecordsFromSQL converts columnar SQL rows into object maps, disambiguating duplicate column names.
func BuildRecordsFromSQL(cols []types.Column, rows [][]any) []map[string]any {
	keys := make([]string, len(cols))
	seen := make(map[string]int, len(cols))
	for i, c := range cols {
		name := c.Name
		if name == "" {
			name = fmt.Sprintf("col_%d", i+1)
		}
		cnt := seen[name]
		seen[name] = cnt + 1
		if cnt > 0 {
			keys[i] = fmt.Sprintf("%s_%d", name, cnt+1)
		} else {
			keys[i] = name
		}
	}
	out := make([]map[string]any, len(rows))
	for rIdx, row := range rows {
		rec := make(map[string]any, len(keys))
		for cIdx, k := range keys {
			if cIdx < len(row) {
				rec[k] = row[cIdx]
			} else {
				rec[k] = nil
			}
		}
		out[rIdx] = rec
	}
	return out
}
