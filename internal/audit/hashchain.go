package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
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
	singleQuotedLitRe = regexp.MustCompile(`'(?:[^']|'')*'`)
	authCmdRe         = regexp.MustCompile(`(?i)\b(AUTH|IDENTIFIED\s+BY|PASSWORD\s*=)\s+\S+`)
)

// RedactQuery masks single-quoted string literals and inline password tokens for audit storage.
func RedactQuery(raw string) string {
	masked := singleQuotedLitRe.ReplaceAllString(raw, "'***'")
	masked = authCmdRe.ReplaceAllStringFunc(masked, func(m string) string {
		idx := strings.LastIndexAny(m, " \t=")
		if idx < 0 {
			return "***"
		}
		return m[:idx+1] + "***"
	})
	return masked
}
