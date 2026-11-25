package approval

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/x0c/agent-dbctl/internal/config"
)

// LocalWebProvider opens the local embedded Web UI approval page on 127.0.0.1.
type LocalWebProvider struct {
	mu      sync.RWMutex
	baseURL string
	onEvent func(approvalID string)
}

// NewLocalWebProvider creates the default built-in local-web ApprovalProvider.
func NewLocalWebProvider(onEvent func(approvalID string)) *LocalWebProvider {
	return &LocalWebProvider{onEvent: onEvent}
}

// SetBaseURL sets the active loopback HTTP URL once the web listener starts.
func (p *LocalWebProvider) SetBaseURL(u string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.baseURL = strings.TrimRight(u, "/")
}

func (p *LocalWebProvider) BaseURL() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.baseURL
}

func (p *LocalWebProvider) Name() string {
	return "local-web"
}

func (p *LocalWebProvider) SupportsInteractiveResolve() bool {
	return true
}

func (p *LocalWebProvider) Submit(_ context.Context, req SubmissionRequest) (*SubmissionResult, error) {
	base := p.BaseURL()
	if base == "" {
		return nil, fmt.Errorf("local web UI server URL not initialized")
	}
	approvalURL := fmt.Sprintf("%s/approvals/%s?token=%s", base, req.ApprovalID, req.OneTimeToken)
	if p.onEvent != nil {
		p.onEvent(req.ApprovalID)
	}
	if os.Getenv(config.EnvNoBrowser) != "1" {
		_ = OpenBrowser(approvalURL)
	}
	return &SubmissionResult{
		ExternalTicketID:  req.ApprovalID,
		ExternalTicketURL: approvalURL,
	}, nil
}

func (p *LocalWebProvider) Cancel(_ context.Context, approvalID string, _ string) error {
	if p.onEvent != nil {
		p.onEvent(approvalID)
	}
	return nil
}
