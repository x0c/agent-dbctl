package classify

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/x0c/agent-dbctl/internal/types"
)

// ParsedESCommand represents a normalized Elasticsearch/OpenSearch REST or JSON request.
type ParsedESCommand struct {
	Method string
	Path   string
	Body   string
	Doc    map[string]any
	Index  string
}

// ParseElasticsearchCommand parses either "METHOD /path\n{json}" or a JSON command envelope.
func ParseElasticsearchCommand(raw string) (ParsedESCommand, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ParsedESCommand{}, fmt.Errorf("empty elasticsearch command")
	}

	if strings.HasPrefix(trimmed, "{") {
		var doc map[string]any
		if err := json.Unmarshal([]byte(trimmed), &doc); err != nil {
			return ParsedESCommand{}, fmt.Errorf("invalid elasticsearch JSON command: %w", err)
		}
		if methodRaw, ok := doc["method"].(string); ok {
			pathRaw, _ := doc["path"].(string)
			pathRaw = strings.TrimSpace(pathRaw)
			if pathRaw == "" {
				return ParsedESCommand{}, fmt.Errorf("elasticsearch JSON command requires \"path\"")
			}
			if !strings.HasPrefix(pathRaw, "/") {
				pathRaw = "/" + pathRaw
			}
			var bodyStr string
			var bodyDoc map[string]any
			if b, hasBody := doc["body"]; hasBody && b != nil {
				switch x := b.(type) {
				case string:
					bodyStr = strings.TrimSpace(x)
					_ = json.Unmarshal([]byte(bodyStr), &bodyDoc)
				case map[string]any:
					bodyDoc = x
					if enc, err := json.Marshal(x); err == nil {
						bodyStr = string(enc)
					}
				}
			}
			return ParsedESCommand{
				Method: strings.ToUpper(strings.TrimSpace(methodRaw)),
				Path:   pathRaw,
				Body:   bodyStr,
				Doc:    bodyDoc,
				Index:  extractESIndexFromPath(pathRaw),
			}, nil
		}
		// Shorthand search envelope: {"index": "orders", "query": {...}, "size": 10} or {"sql": "SELECT ..."}
		if sqlText, ok := doc["sql"].(string); ok && strings.TrimSpace(sqlText) != "" {
			bodyBytes, _ := json.Marshal(map[string]any{"query": sqlText})
			return ParsedESCommand{
				Method: "POST",
				Path:   "/_sql",
				Body:   string(bodyBytes),
				Doc:    map[string]any{"query": sqlText},
			}, nil
		}
		indexName, _ := doc["index"].(string)
		indexName = strings.TrimSpace(indexName)
		searchPath := "/_search"
		if indexName != "" {
			searchPath = "/" + strings.TrimPrefix(indexName, "/") + "/_search"
		}
		bodyMap := make(map[string]any, len(doc))
		for k, v := range doc {
			if k == "index" {
				continue
			}
			bodyMap[k] = v
		}
		bodyBytes, _ := json.Marshal(bodyMap)
		return ParsedESCommand{
			Method: "POST",
			Path:   searchPath,
			Body:   string(bodyBytes),
			Doc:    bodyMap,
			Index:  extractESIndexFromPath(searchPath),
		}, nil
	}

	// HTTP line format: "GET /orders/_search\n{...}"
	lines := strings.SplitN(trimmed, "\n", 2)
	headerFields := strings.Fields(strings.TrimSpace(lines[0]))
	if len(headerFields) < 2 {
		return ParsedESCommand{}, fmt.Errorf("expected '<METHOD> /<path>' or JSON command")
	}
	method := strings.ToUpper(headerFields[0])
	switch method {
	case "GET", "HEAD", "POST", "PUT", "DELETE", "PATCH":
	default:
		return ParsedESCommand{}, fmt.Errorf("unsupported HTTP method %q", method)
	}
	path := strings.TrimSpace(headerFields[1])
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	var bodyStr string
	var bodyDoc map[string]any
	if len(lines) == 2 {
		bodyStr = strings.TrimSpace(lines[1])
		if strings.HasPrefix(bodyStr, "{") {
			if err := json.Unmarshal([]byte(bodyStr), &bodyDoc); err != nil {
				return ParsedESCommand{}, fmt.Errorf("invalid JSON request body: %w", err)
			}
		}
	}
	return ParsedESCommand{
		Method: method,
		Path:   path,
		Body:   bodyStr,
		Doc:    bodyDoc,
		Index:  extractESIndexFromPath(path),
	}, nil
}

func extractESIndexFromPath(rawPath string) string {
	u, err := url.Parse(rawPath)
	p := rawPath
	if err == nil && u.Path != "" {
		p = u.Path
	}
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return ""
	}
	first, _, _ := strings.Cut(p, "/")
	if strings.HasPrefix(first, "_") {
		return ""
	}
	return first
}

func classifyElasticsearch(engine, raw string) types.Classification {
	cmd, err := ParseElasticsearchCommand(raw)
	if err != nil {
		return types.Classification{
			Engine:         engine,
			Family:         types.FamilyDocument,
			RiskLevel:      types.RiskUnknown,
			IsReadOnly:     false,
			StatementCount: 1,
			RiskFlags:      []string{"invalid_es_command"},
			Summary:        "Unparseable Elasticsearch command (fail-closed): " + err.Error(),
		}
	}

	u, _ := url.Parse(cmd.Path)
	cleanPath := cmd.Path
	if u != nil && u.Path != "" {
		cleanPath = u.Path
	}
	lowerPath := strings.ToLower(cleanPath)
	snippet := truncateSnippet(cmd.Method+" "+cmd.Path, 120)

	// Admin endpoints
	if strings.HasPrefix(lowerPath, "/_cluster") ||
		strings.HasPrefix(lowerPath, "/_snapshot") ||
		strings.HasPrefix(lowerPath, "/_ilm") ||
		strings.HasPrefix(lowerPath, "/_slm") ||
		strings.HasPrefix(lowerPath, "/_security") ||
		strings.HasPrefix(lowerPath, "/_ingest") ||
		strings.Contains(lowerPath, "/_forcemerge") ||
		strings.Contains(lowerPath, "/_flush") ||
		strings.Contains(lowerPath, "/_close") ||
		strings.Contains(lowerPath, "/_open") ||
		(strings.Contains(lowerPath, "/_settings") && (cmd.Method == "PUT" || cmd.Method == "POST")) ||
		(strings.Contains(lowerPath, "/_tasks") && cmd.Method == "POST") {
		if cmd.Method == "GET" || cmd.Method == "HEAD" {
			return esResult(engine, "ES_CLUSTER_READ", types.RiskSafeRead, true, nil, snippet)
		}
		return esResult(engine, "ES_ADMIN", types.RiskAdmin, false, []string{"es_admin_endpoint"}, snippet)
	}

	// ES SQL endpoint delegates inner SQL classification.
	if lowerPath == "/_sql" || strings.HasSuffix(lowerPath, "/_sql") {
		if cmd.Doc != nil {
			if q, ok := cmd.Doc["query"].(string); ok {
				sqlCls := classifySQL(engine, q)
				sqlCls.Family = types.FamilyDocument
				return sqlCls
			}
		}
		return esResult(engine, "ES_SQL_UNKNOWN", types.RiskUnknown, false, []string{"es_sql_missing_query"}, snippet)
	}

	// Write & bulk mutation endpoints
	if strings.Contains(lowerPath, "/_bulk") ||
		strings.Contains(lowerPath, "/_delete_by_query") ||
		strings.Contains(lowerPath, "/_update_by_query") ||
		strings.HasPrefix(lowerPath, "/_reindex") ||
		strings.Contains(lowerPath, "/_update") ||
		strings.Contains(lowerPath, "/_doc") && (cmd.Method == "POST" || cmd.Method == "PUT" || cmd.Method == "DELETE") ||
		strings.Contains(lowerPath, "/_create") {
		return esResult(engine, "ES_WRITE", types.RiskWrite, false, []string{"es_write"}, snippet)
	}

	// DDL endpoints: index create/delete, mapping/aliases/templates
	if strings.Contains(lowerPath, "/_mapping") && (cmd.Method == "PUT" || cmd.Method == "POST") ||
		strings.HasPrefix(lowerPath, "/_aliases") && cmd.Method == "POST" ||
		strings.HasPrefix(lowerPath, "/_index_template") && cmd.Method != "GET" ||
		strings.HasPrefix(lowerPath, "/_template") && cmd.Method != "GET" ||
		cmd.Method == "DELETE" ||
		(cmd.Method == "PUT" && cmd.Index != "" && !strings.Contains(lowerPath, "/_doc/")) {
		return esResult(engine, "ES_DDL", types.RiskDDL, false, []string{"es_ddl"}, snippet)
	}

	// Read endpoints: _search, _msearch, _count, _cat, _mapping, _settings, _doc GET
	if cmd.Method == "GET" || cmd.Method == "HEAD" ||
		strings.HasSuffix(lowerPath, "/_search") || lowerPath == "/_search" ||
		strings.HasSuffix(lowerPath, "/_msearch") || lowerPath == "/_msearch" ||
		strings.HasSuffix(lowerPath, "/_count") || lowerPath == "/_count" ||
		strings.HasSuffix(lowerPath, "/_validate/query") {
		flags := inspectESReadHazards(cmd, lowerPath, u)
		if len(flags) > 0 {
			return esResult(engine, "ES_SEARCH", types.RiskHighCostRead, true, flags, snippet)
		}
		return esResult(engine, "ES_READ", types.RiskSafeRead, true, nil, snippet)
	}

	return esResult(engine, "ES_UNKNOWN", types.RiskUnknown, false, []string{"unrecognized_es_command"}, snippet)
}

func esResult(engine, stmtType string, risk types.RiskLevel, ro bool, flags []string, snippet string) types.Classification {
	sortStrings(flags)
	return types.Classification{
		Engine:         engine,
		Family:         types.FamilyDocument,
		RiskLevel:      risk,
		IsReadOnly:     ro,
		StatementCount: 1,
		Statements: []types.StatementSummary{{
			StatementType: stmtType,
			RiskLevel:     risk,
			Flags:         flags,
			Snippet:       snippet,
		}},
		RiskFlags: flags,
		Summary:   fmt.Sprintf("Elasticsearch %s (%s)", stmtType, risk),
	}
}

func inspectESReadHazards(cmd ParsedESCommand, lowerPath string, parsedURL *url.URL) []string {
	var flags []string
	isSearch := strings.HasSuffix(lowerPath, "/_search") || lowerPath == "/_search" || strings.HasSuffix(lowerPath, "/_msearch") || lowerPath == "/_msearch"
	if !isSearch {
		return nil
	}
	if strings.HasSuffix(lowerPath, "/_msearch") || lowerPath == "/_msearch" {
		flags = append(flags, "msearch_batch")
	}
	if parsedURL != nil && parsedURL.Query().Get("scroll") != "" {
		flags = append(flags, "scroll_scan")
	}
	if cmd.Index == "" || cmd.Index == "*" || cmd.Index == "_all" {
		flags = append(flags, "cross_index_scan")
	}
	if cmd.Doc != nil {
		if hasESKeyRecursive(cmd.Doc, "script") || hasESKeyRecursive(cmd.Doc, "script_fields") {
			flags = append(flags, "script_eval")
		}
		sizeVal, hasSize := asESInt(cmd.Doc["size"])
		if hasSize && sizeVal > 1000 {
			flags = append(flags, "large_size")
		}
		if parsedURL != nil {
			if qs := parsedURL.Query().Get("size"); qs != "" {
				if n, ok := asESInt(qs); ok && n > 1000 {
					flags = append(flags, "large_size")
				}
				hasSize = true
			}
		}
		if hasESKeyRecursive(cmd.Doc, "match_all") && !hasSize {
			flags = append(flags, "unbounded_match_all")
		}
		if fromVal, ok := asESInt(cmd.Doc["from"]); ok && fromVal >= 10000 {
			flags = append(flags, "deep_offset")
		}
	} else if parsedURL != nil {
		if qs := parsedURL.Query().Get("size"); qs != "" {
			if n, ok := asESInt(qs); ok && n > 1000 {
				flags = append(flags, "large_size")
			}
		}
	}
	return flags
}

func hasESKeyRecursive(v any, target string) bool {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if strings.EqualFold(k, target) {
				return true
			}
			if hasESKeyRecursive(val, target) {
				return true
			}
		}
	case []any:
		for _, item := range x {
			if hasESKeyRecursive(item, target) {
				return true
			}
		}
	}
	return false
}

func asESInt(v any) (int64, bool) {
	switch x := v.(type) {
	case float64:
		return int64(x), true
	case int64:
		return x, true
	case int:
		return int64(x), true
	case string:
		var n int64
		if _, err := fmt.Sscan(strings.TrimSpace(x), &n); err == nil {
			return n, true
		}
	}
	return 0, false
}
