package classify

import (
	"encoding/json"
	"strings"

	"github.com/x0c/agent-dbctl/internal/types"
)

// QueryContext captures normalized syntax and extracted structural metadata for policy pattern matching.
type QueryContext struct {
	Engine          string             `json:"engine"`
	Family          types.EngineFamily `json:"family"`
	Raw             string             `json:"raw"`
	Normalized      string             `json:"normalized"`
	NormalizedNoLit string             `json:"normalized_no_literals"`
	Tokens          []string           `json:"tokens,omitempty"`
	Functions       []string           `json:"functions,omitempty"`
	Tables          []string           `json:"tables,omitempty"`
	Pragmas         []string           `json:"pragmas,omitempty"`
	Commands        [][]string         `json:"commands,omitempty"`
	MongoDoc        map[string]any     `json:"mongo_doc,omitempty"`
	MongoOperators  []string           `json:"mongo_operators,omitempty"`
	HasLimit        bool               `json:"has_limit"`
	HasWhere        bool               `json:"has_where"`
}

// ExtractQueryContext parses and normalizes raw input for the given engine into structured matching metadata.
func ExtractQueryContext(engine, raw string) QueryContext {
	family := EngineFamily(engine)
	ctx := QueryContext{
		Engine: engine,
		Family: family,
		Raw:    raw,
	}

	switch family {
	case types.FamilySQL:
		stmts, _ := splitSQLStatements(strings.TrimSpace(raw))
		if len(stmts) > 0 {
			ctx.Normalized = strings.Join(strings.Fields(strings.Join(stmts, "; ")), " ")
		} else {
			ctx.Normalized = strings.Join(strings.Fields(raw), " ")
		}

		fnSeen := map[string]bool{}
		tblSeen := map[string]bool{}
		pragmaSeen := map[string]bool{}
		var noLitParts []string
		for _, stmt := range stmts {
			toks := tokenizeSQLWithPunctuation(stmt)
			ctx.Tokens = append(ctx.Tokens, toks...)
			if len(toks) > 0 {
				noLitParts = append(noLitParts, strings.Join(toks, " "))
			}
			for _, fn := range extractSQLFunctions(toks) {
				if !fnSeen[fn] {
					fnSeen[fn] = true
					ctx.Functions = append(ctx.Functions, fn)
				}
			}
			for _, tbl := range extractSQLTables(toks) {
				if !tblSeen[tbl] {
					tblSeen[tbl] = true
					ctx.Tables = append(ctx.Tables, tbl)
				}
			}
			if len(toks) > 0 && strings.EqualFold(toks[0], "PRAGMA") {
				pn := extractPragmaName(toks)
				if pn != "" && !pragmaSeen[pn] {
					pragmaSeen[pn] = true
					ctx.Pragmas = append(ctx.Pragmas, pn)
				}
			}
			kwUpper := filterPunctuation(upperTokens(toks))
			if containsToken(kwUpper, "LIMIT") || containsSequence(kwUpper, "FETCH", "FIRST") || containsSequence(kwUpper, "FETCH", "NEXT") || containsToken(kwUpper, "TOP") {
				ctx.HasLimit = true
			}
			if containsToken(kwUpper, "WHERE") {
				ctx.HasWhere = true
			}
		}
		if len(noLitParts) > 0 {
			ctx.NormalizedNoLit = strings.Join(noLitParts, " ; ")
		} else {
			ctx.NormalizedNoLit = ctx.Normalized
		}

	case types.FamilyDocument:
		trimmed := strings.TrimSpace(raw)
		ctx.Normalized = strings.Join(strings.Fields(trimmed), " ")
		ctx.NormalizedNoLit = ctx.Normalized
		if normalizeEngine(engine) == "elasticsearch" {
			if esCmd, err := ParseElasticsearchCommand(raw); err == nil {
				if esCmd.Index != "" {
					ctx.Tables = []string{strings.ToLower(esCmd.Index)}
				}
				if esCmd.Doc != nil {
					ctx.MongoDoc = esCmd.Doc
					if sizeVal, ok := asESInt(esCmd.Doc["size"]); ok && sizeVal > 0 {
						ctx.HasLimit = true
					}
				}
			}
			return ctx
		}
		if strings.HasPrefix(trimmed, "{") {
			var doc map[string]any
			if err := json.Unmarshal([]byte(trimmed), &doc); err == nil {
				ctx.MongoDoc = doc
				_, ctx.MongoOperators = scanMongoDocHazards(doc)
			}
		} else {
			var ops []string
			for _, op := range []string{"$where", "$function", "$accumulator", "$out", "$merge", "$lookup", "$graphLookup", "$regex", "$limit", "$match", "allowDiskUse", "noCursorTimeout", "executionStats", "allPlansExecution"} {
				if strings.Contains(trimmed, op) {
					ops = append(ops, op)
				}
			}
			ctx.MongoOperators = ops
			if m := mongoshMethodRe.FindStringSubmatch(trimmed); len(m) > 0 {
				coll := m[1]
				if coll == "" {
					coll = m[2]
				}
				if coll != "" {
					ctx.Tables = []string{strings.ToLower(coll)}
				}
			}
		}
		lower := strings.ToLower(trimmed)
		ctx.HasLimit = strings.Contains(lower, ".limit(") || strings.Contains(lower, `"limit"`) || strings.Contains(lower, "$limit")

	case types.FamilyKV:
		cmds, _ := ParseRedisLines(raw)
		ctx.Commands = cmds
		var norm []string
		for _, c := range cmds {
			norm = append(norm, strings.Join(c, " "))
		}
		if len(norm) > 0 {
			ctx.Normalized = strings.Join(norm, "\n")
		} else {
			ctx.Normalized = strings.TrimSpace(raw)
		}
		ctx.NormalizedNoLit = ctx.Normalized
	}

	return ctx
}

func upperTokens(toks []string) []string {
	out := make([]string, len(toks))
	for i, t := range toks {
		out[i] = strings.ToUpper(t)
	}
	return out
}
