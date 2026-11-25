package approval

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/x0c/agent-dbctl/internal/audit"
)

const (
	EnvWebhookURL     = "AGENT_DBCTL_WEBHOOK_URL"
	EnvWebhookSecret  = "AGENT_DBCTL_WEBHOOK_SECRET"
	EnvWebhookTimeout = "AGENT_DBCTL_WEBHOOK_TIMEOUT"

	defaultWebhookTimeout = 5 * time.Second
	maxWebhookTimeout     = 30 * time.Second
)

// WebhookConfig configures signed webhook notifications for external approval workflows.
type WebhookConfig struct {
	EndpointURL   string
	SigningSecret string
	Timeout       time.Duration
	LocalWeb      *LocalWebProvider
}

// WebhookProvider implements ApprovalProvider by sending signed JSON notifications
// to a configured HTTPS (or loopback HTTP) webhook endpoint.
type WebhookProvider struct {
	endpointURL   string
	signingSecret string
	localWeb      *LocalWebProvider
	client        *http.Client
}

// ValidateWebhookURL requires HTTPS for remote endpoints and allows HTTP strictly for loopback hosts.
func ValidateWebhookURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("webhook endpoint URL is required")
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid webhook URL: %w", err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("webhook URL must include host")
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "https":
		return u.String(), nil
	case "http":
		if !isLoopbackHost(u.Hostname()) {
			return "", fmt.Errorf("webhook URL %q must use https (http allowed only on loopback)", trimmed)
		}
		return u.String(), nil
	default:
		return "", fmt.Errorf("unsupported webhook URL scheme %q", u.Scheme)
	}
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// NewWebhookProvider validates config and builds a WebhookProvider.
func NewWebhookProvider(cfg WebhookConfig) (*WebhookProvider, error) {
	validURL, err := ValidateWebhookURL(cfg.EndpointURL)
	if err != nil {
		return nil, err
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultWebhookTimeout
	}
	if timeout > maxWebhookTimeout {
		timeout = maxWebhookTimeout
	}
	return &WebhookProvider{
		endpointURL:   validURL,
		signingSecret: cfg.SigningSecret,
		localWeb:      cfg.LocalWeb,
		client:        &http.Client{Timeout: timeout},
	}, nil
}

// NewWebhookProviderFromEnv builds a WebhookProvider when AGENT_DBCTL_WEBHOOK_URL is set.
// Returns (nil, nil) when unconfigured.
func NewWebhookProviderFromEnv(localWeb *LocalWebProvider) (*WebhookProvider, error) {
	rawURL := strings.TrimSpace(os.Getenv(EnvWebhookURL))
	if rawURL == "" {
		return nil, nil
	}
	timeout := defaultWebhookTimeout
	if rawTimeout := strings.TrimSpace(os.Getenv(EnvWebhookTimeout)); rawTimeout != "" {
		parsed, err := time.ParseDuration(rawTimeout)
		if err != nil {
			return nil, fmt.Errorf("invalid %s=%q: %w", EnvWebhookTimeout, rawTimeout, err)
		}
		timeout = parsed
	}
	return NewWebhookProvider(WebhookConfig{
		EndpointURL:   rawURL,
		SigningSecret: os.Getenv(EnvWebhookSecret),
		Timeout:       timeout,
		LocalWeb:      localWeb,
	})
}

func (p *WebhookProvider) Name() string {
	return "webhook"
}

func (p *WebhookProvider) SupportsInteractiveResolve() bool {
	return false
}

func (p *WebhookProvider) Submit(ctx context.Context, req SubmissionRequest) (*SubmissionResult, error) {
	reviewURL := ""
	if p.localWeb != nil && p.localWeb.BaseURL() != "" {
		// Never include the one-time token in webhook notifications; reviewers authenticate via local Web UI.
		reviewURL = fmt.Sprintf("%s/approvals/%s", p.localWeb.BaseURL(), req.ApprovalID)
	}
	queryRedacted := req.Operation.QueryRedacted
	if queryRedacted == "" {
		queryRedacted = audit.RedactQuery(req.Operation.QueryText)
	}

	payload := map[string]any{
		"event":            "approval.requested",
		"approval_id":      req.ApprovalID,
		"operation_id":     req.Operation.ID,
		"target_ref":       req.Operation.TargetRef,
		"system_slug":      req.Operation.SystemSlug,
		"environment_code": req.Operation.EnvironmentCode,
		"engine":           req.Operation.Engine,
		"actor":            req.Operation.Actor,
		"reason":           req.Operation.Reason,
		"risk_level":       req.Operation.RiskLevel,
		"trigger_reasons":  req.Operation.TriggerReasons,
		"matched_rules":    req.Operation.MatchedRules,
		"query_redacted":   queryRedacted,
		"preflight":        req.Operation.Preflight,
		"expires_at_utc":   req.ExpiresAtUTC,
		"review_url":       reviewURL,
	}
	rawResp, err := p.postSigned(ctx, payload)
	if err != nil {
		return nil, err
	}

	out := &SubmissionResult{
		ExternalTicketID:  req.ApprovalID,
		ExternalTicketURL: reviewURL,
	}
	if len(rawResp) > 0 {
		var parsed struct {
			TicketID  string `json:"ticket_id"`
			TicketURL string `json:"ticket_url"`
		}
		if json.Unmarshal(rawResp, &parsed) == nil {
			if strings.TrimSpace(parsed.TicketID) != "" {
				out.ExternalTicketID = strings.TrimSpace(parsed.TicketID)
			}
			if strings.TrimSpace(parsed.TicketURL) != "" {
				out.ExternalTicketURL = strings.TrimSpace(parsed.TicketURL)
			}
		}
	}
	return out, nil
}

func (p *WebhookProvider) Cancel(ctx context.Context, approvalID string, externalTicketID string) error {
	payload := map[string]any{
		"event":              "approval.cancelled",
		"approval_id":        approvalID,
		"external_ticket_id": externalTicketID,
	}
	_, err := p.postSigned(ctx, payload)
	return err
}

func (p *WebhookProvider) postSigned(ctx context.Context, payload map[string]any) ([]byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	reqCtx := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		reqCtx, cancel = context.WithTimeout(ctx, p.client.Timeout)
		defer cancel()
	}
	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, p.endpointURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if p.signingSecret != "" {
		ts := strconv.FormatInt(time.Now().UTC().Unix(), 10)
		mac := hmac.New(sha256.New, []byte(p.signingSecret))
		mac.Write([]byte(ts))
		mac.Write([]byte("."))
		mac.Write(body)
		httpReq.Header.Set("X-Agent-DBCTL-Timestamp", ts)
		httpReq.Header.Set("X-Agent-DBCTL-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("webhook delivery failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("webhook returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return raw, nil
}
