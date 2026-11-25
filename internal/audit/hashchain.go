package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"unicode"
)

const GenesisPrevHash = "0000000000000000000000000000000000000000000000000000000000000000"

type hashInput struct {
	Seq          int64  `json:"seq"`
	PrevHash     string `json:"prev_hash"`
	Actor        string `json:"actor"`
	Action       string `json:"action"`
	TargetID     string `json:"target_id"`
	OperationID  string `json:"operation_id"`
	PayloadJSON  string `json:"payload_json"`
	CreatedAtUTC string `json:"created_at_utc"`
}

// ComputeEntryHash produces a deterministic SHA-256 hash without ambiguous separators.
func ComputeEntryHash(seq int64, prevHash, actor, action, targetID, operationID, payloadJSON, createdAtUTC string) string {
	b, _ := json.Marshal(hashInput{
		Seq:          seq,
		PrevHash:     prevHash,
		Actor:        actor,
		Action:       action,
		TargetID:     targetID,
		OperationID:  operationID,
		PayloadJSON:  payloadJSON,
		CreatedAtUTC: createdAtUTC,
	})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

var (
	uriPasswordRe     = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]*):([^@\s/]+)@`)
	redisAuthLineRe   = regexp.MustCompile(`(?im)(^|;)([ \t]*)(AUTH)\b([^\r\n;]*)`)
	redisACLLineRe    = regexp.MustCompile(`(?i)\bACL\s+SETUSER\b[^\r\n;]*`)
	redisACLTokenRe   = regexp.MustCompile(`(\s)([>#])[^\s;]+`)
	redisConfigPassRe = regexp.MustCompile(`(?i)(\bCONFIG\s+SET\s+(?:requirepass|masterauth)\s+)(?:"[^"]*"|'[^']*'|\S+)`)
	sqlIdentifiedByRe = regexp.MustCompile(`(?i)(\bIDENTIFIED\s+BY\s+)(?:"[^"]*"|'[^']*'|\S+)`)
	sqlWithPassRe     = regexp.MustCompile(`(?i)(\bWITH\s+PASSWORD\s+)(?:"[^"]*"|'[^']*'|\S+)`)
	sqlPasswordEqRe   = regexp.MustCompile(`(?i)(\bPASSWORD\s*=\s*)(?:"[^"]*"|'[^']*'|\S+)`)
	sqlSetPasswordRe  = regexp.MustCompile(`(?i)(\bSET\s+PASSWORD\b[^\r\n;=]*=\s*)(?:"[^"]*"|'[^']*'|\S+)`)
)

var sensitiveKeySubstrings = []string{
	"password",
	"passwd",
	"pwd",
	"secret",
	"token",
	"api_key",
	"apikey",
	"access_key",
	"private_key",
	"credential",
	"authorization",
	"cookie",
	"session_id",
	"ssn",
	"cvv",
	"pin",
}

var structuralMongoKeys = map[string]bool{
	"find":           true,
	"aggregate":      true,
	"count":          true,
	"distinct":       true,
	"update":         true,
	"insert":         true,
	"delete":         true,
	"findandmodify":  true,
	"collstats":      true,
	"listindexes":    true,
	"explain":        true,
	"createindexes":  true,
	"drop":           true,
	"dropindexes":    true,
	"collection":     true,
	"from":           true,
	"localfield":     true,
	"foreignfield":   true,
	"as":             true,
	"into":           true,
	"on":             true,
	"whenmatched":    true,
	"whennotmatched": true,
}

var dataSubtreeMongoKeys = map[string]bool{
	"filter":       true,
	"q":            true,
	"u":            true,
	"updates":      true,
	"documents":    true,
	"query":        true,
	"update":       true,
	"pipeline":     true,
	"$match":       true,
	"$set":         true,
	"$setoninsert": true,
	"$eq":          true,
	"$ne":          true,
	"$in":          true,
	"$nin":         true,
	"$regex":       true,
	"$gt":          true,
	"$gte":         true,
	"$lt":          true,
	"$lte":         true,
}

// RedactQuery masks string literals and inline secret tokens across SQL, PostgreSQL,
// MySQL, MongoDB JSON, and Redis commands for safe audit persistence.
func RedactQuery(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		if redacted, ok := tryRedactJSON(trimmed); ok {
			return redacted
		}
	}
	// Elasticsearch/OpenSearch HTTP-style command: "POST /index/_search\n{...}"
	if head, body, hasNL := strings.Cut(trimmed, "\n"); hasNL {
		bodyTrim := strings.TrimSpace(body)
		if strings.HasPrefix(bodyTrim, "{") || strings.HasPrefix(bodyTrim, "[") {
			if redactedBody, ok := tryRedactJSON(bodyTrim); ok {
				return strings.TrimSpace(head) + "\n" + redactedBody
			}
		}
	}

	masked := redactLexLiterals(raw)
	masked = uriPasswordRe.ReplaceAllString(masked, `$1:***@`)
	masked = redactRedisAuth(masked)
	masked = redisACLLineRe.ReplaceAllStringFunc(masked, func(cmd string) string {
		return redisACLTokenRe.ReplaceAllString(cmd, `$1$2***`)
	})
	masked = redisConfigPassRe.ReplaceAllString(masked, `$1***`)
	masked = sqlIdentifiedByRe.ReplaceAllString(masked, `$1***`)
	masked = sqlWithPassRe.ReplaceAllString(masked, `$1***`)
	masked = sqlPasswordEqRe.ReplaceAllString(masked, `$1***`)
	masked = sqlSetPasswordRe.ReplaceAllString(masked, `$1***`)
	return masked
}

func tryRedactJSON(raw string) (string, bool) {
	var parsed any
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return "", false
	}
	redacted := redactJSONValue(parsed, false, false)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(redacted); err != nil {
		return "", false
	}
	return strings.TrimRight(buf.String(), "\r\n"), true
}

func isSensitiveKey(key string) bool {
	lk := strings.ToLower(strings.TrimSpace(key))
	for _, sub := range sensitiveKeySubstrings {
		if strings.Contains(lk, sub) {
			return true
		}
	}
	return false
}

func redactJSONValue(v any, sensitiveCtx bool, dataSubtree bool) any {
	switch val := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, child := range val {
			lk := strings.ToLower(k)
			childSensitive := sensitiveCtx || isSensitiveKey(k)
			childData := dataSubtree || dataSubtreeMongoKeys[lk]
			if structuralMongoKeys[lk] && !childSensitive {
				if s, ok := child.(string); ok {
					out[k] = s
					continue
				}
			}
			out[k] = redactJSONValue(child, childSensitive, childData)
		}
		return out
	case []any:
		out := make([]any, len(val))
		for i, elem := range val {
			out[i] = redactJSONValue(elem, sensitiveCtx, dataSubtree)
		}
		return out
	case string:
		if sensitiveCtx {
			return "***"
		}
		if dataSubtree && !strings.HasPrefix(val, "$") {
			return "***"
		}
		return val
	case float64, json.Number, bool:
		if sensitiveCtx {
			return "***"
		}
		return val
	default:
		if sensitiveCtx && val != nil {
			return "***"
		}
		return val
	}
}

// redactLexLiterals performs a single-pass scan replacing single-quoted literals
// (supporting both SQL ” and backslash \') and PostgreSQL dollar-quoted literals.
func redactLexLiterals(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
	n := len(raw)
	for i := 0; i < n; {
		ch := raw[i]
		// Preserve double-quoted and backtick identifiers verbatim so internal quotes do not misalign.
		if ch == '"' || ch == '`' {
			quote := ch
			start := i
			i++
			for i < n {
				if raw[i] == '\\' && i+1 < n {
					i += 2
					continue
				}
				if raw[i] == quote {
					i++
					if i < n && raw[i] == quote {
						i++
						continue
					}
					break
				}
				i++
			}
			b.WriteString(raw[start:i])
			continue
		}
		// Single-quoted literal: handle both '' and \'.
		if ch == '\'' {
			i++
			for i < n {
				if raw[i] == '\\' && i+1 < n {
					i += 2
					continue
				}
				if raw[i] == '\'' {
					i++
					if i < n && raw[i] == '\'' {
						i++
						continue
					}
					break
				}
				i++
			}
			b.WriteString("'***'")
			continue
		}
		// PostgreSQL dollar-quoted literal: $$...$$ or $tag$...$tag$.
		if ch == '$' {
			if tag, endOpen, ok := parseDollarTag(raw, i); ok {
				if closeIdx := strings.Index(raw[endOpen:], tag); closeIdx >= 0 {
					b.WriteString(tag)
					b.WriteString("***")
					b.WriteString(tag)
					i = endOpen + closeIdx + len(tag)
					continue
				}
			}
		}
		b.WriteByte(ch)
		i++
	}
	return b.String()
}

func parseDollarTag(s string, start int) (tag string, end int, ok bool) {
	if start >= len(s) || s[start] != '$' {
		return "", 0, false
	}
	j := start + 1
	if j < len(s) && s[j] == '$' {
		return "$$", j + 1, true
	}
	if j >= len(s) {
		return "", 0, false
	}
	r0 := rune(s[j])
	if !unicode.IsLetter(r0) && r0 != '_' {
		return "", 0, false
	}
	j++
	for j < len(s) {
		c := s[j]
		if c == '$' {
			return s[start : j+1], j + 1, true
		}
		r := rune(c)
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && c != '_' {
			return "", 0, false
		}
		j++
	}
	return "", 0, false
}

func redactRedisAuth(s string) string {
	return redisAuthLineRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := redisAuthLineRe.FindStringSubmatch(m)
		if len(sub) < 5 {
			return m
		}
		sep, spaces, kw, rest := sub[1], sub[2], sub[3], sub[4]
		tokens := splitCmdTokens(rest)
		if len(tokens) == 0 {
			return m
		}
		if len(tokens) >= 2 {
			// Redis 6+ ACL AUTH <username> <password>
			return sep + spaces + kw + " " + tokens[0] + " ***"
		}
		// Legacy 1-arg AUTH <password>
		return sep + spaces + kw + " ***"
	})
}

func splitCmdTokens(s string) []string {
	var out []string
	i := 0
	n := len(s)
	for i < n {
		for i < n && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= n {
			break
		}
		if s[i] == '"' || s[i] == '\'' {
			q := s[i]
			start := i
			i++
			for i < n {
				if s[i] == '\\' && i+1 < n {
					i += 2
					continue
				}
				if s[i] == q {
					i++
					break
				}
				i++
			}
			out = append(out, s[start:i])
			continue
		}
		start := i
		for i < n && s[i] != ' ' && s[i] != '\t' {
			i++
		}
		out = append(out, s[start:i])
	}
	return out
}
