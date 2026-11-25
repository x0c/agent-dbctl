package approval

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/x0c/agent-dbctl/internal/store"
	"github.com/x0c/agent-dbctl/internal/types"
)

// SubmissionRequest holds details passed to an ApprovalProvider.
type SubmissionRequest struct {
	ApprovalID   string
	Operation    types.Operation
	Target       types.TargetDetail
	OneTimeToken string
	ExpiresAtUTC string
}

// SubmissionResult holds provider-generated ticket links.
type SubmissionResult struct {
	ExternalTicketID  string
	ExternalTicketURL string
}

// Provider abstracts human approval channels (built-in local-web, Feishu, Slack, Ticket API).
type Provider interface {
	Name() string
	SupportsInteractiveResolve() bool
	Submit(ctx context.Context, req SubmissionRequest) (*SubmissionResult, error)
	Cancel(ctx context.Context, approvalID string, externalTicketID string) error
}

// Resolution represents a terminal approval decision delivered to waiters.
type Resolution struct {
	Approval types.ApprovalRequest
	Err      error
}

// Manager coordinates ApprovalProviders, SQLite persistence, and wall-clock expiration.
type Manager struct {
	store     *store.Store
	providers map[string]Provider

	mu      sync.Mutex
	waiters map[string]chan Resolution
	wg      sync.WaitGroup
}

// NewManager constructs an ApprovalManager backed by store.
func NewManager(st *store.Store) *Manager {
	return &Manager{
		store:     st,
		providers: make(map[string]Provider),
		waiters:   make(map[string]chan Resolution),
	}
}

// RegisterProvider registers an approval provider by name.
func (m *Manager) RegisterProvider(p Provider) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.providers[p.Name()] = p
}

// ProviderNames returns registered provider names.
func (m *Manager) ProviderNames() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	names := make([]string, 0, len(m.providers))
	for k := range m.providers {
		names = append(names, k)
	}
	return names
}

// Submit creates a pending approval ticket, notifies the provider, and starts expiry tracking.
func (m *Manager) Submit(ctx context.Context, providerName string, op types.Operation, detail types.TargetDetail, timeoutSec int) (types.ApprovalRequest, string, error) {
	if timeoutSec <= 0 {
		timeoutSec = 120
	}
	m.mu.Lock()
	prov, ok := m.providers[providerName]
	if !ok {
		prov = m.providers["local-web"]
	}
	m.mu.Unlock()
	if prov == nil {
		return types.ApprovalRequest{}, "", fmt.Errorf("approval provider %q not registered", providerName)
	}

	rawToken := randomToken()
	tokenHash := HashToken(rawToken)
	now := time.Now().Round(0).UTC()
	expiresAt := now.Add(time.Duration(timeoutSec) * time.Second)

	app := types.ApprovalRequest{
		OperationID:     op.ID,
		Provider:        prov.Name(),
		Status:          types.ApprovalPending,
		TargetRef:       op.TargetRef,
		SystemSlug:      op.SystemSlug,
		EnvironmentCode: op.EnvironmentCode,
		Engine:          op.Engine,
		Actor:           op.Actor,
		Reason:          op.Reason,
		WorkspaceCWD:    op.WorkspaceCWD,
		QueryText:       op.QueryText,
		RiskLevel:       op.RiskLevel,
		TriggerReasons:  op.TriggerReasons,
		Preflight:       op.Preflight,
		CreatedAtUTC:    now.Format(time.RFC3339Nano),
		ExpiresAtUTC:    expiresAt.Format(time.RFC3339Nano),
	}
	app, err := m.store.CreateApproval(ctx, op.Actor, app, tokenHash)
	if err != nil {
		return app, "", err
	}

	subRes, err := prov.Submit(ctx, SubmissionRequest{
		ApprovalID:   app.ID,
		Operation:    op,
		Target:       detail,
		OneTimeToken: rawToken,
		ExpiresAtUTC: app.ExpiresAtUTC,
	})
	if err != nil {
		_, _ = m.store.ResolveApproval(ctx, app.ID, types.ApprovalCancelled, "system", "provider submit failed: "+err.Error())
		return app, "", err
	}
	if subRes != nil {
		app.ExternalTicketID = subRes.ExternalTicketID
		app.ExternalTicketURL = subRes.ExternalTicketURL
	}

	m.mu.Lock()
	m.waiters[app.ID] = make(chan Resolution, 1)
	m.mu.Unlock()

	// Schedule wall-clock expiration monitor using time.Now().Round(0) for macOS sleep safety.
	m.wg.Add(1)
	go func(approvalID string, deadline time.Time) {
		defer m.wg.Done()
		m.watchDeadline(approvalID, deadline)
	}(app.ID, expiresAt)

	return app, subResURL(subRes), nil
}

func subResURL(r *SubmissionResult) string {
	if r == nil {
		return ""
	}
	return r.ExternalTicketURL
}

func (m *Manager) watchDeadline(approvalID string, deadline time.Time) {
	for {
		now := time.Now().Round(0).UTC()
		if !now.Before(deadline) {
			app, err := m.store.ResolveApproval(context.Background(), approvalID, types.ApprovalExpired, "system", "approval timed out")
			if err == nil {
				m.notifyWaiter(approvalID, Resolution{Approval: app})
			}
			return
		}
		m.mu.Lock()
		_, stillWaiting := m.waiters[approvalID]
		m.mu.Unlock()
		if !stillWaiting {
			return
		}
		sleepDur := deadline.Sub(now)
		if sleepDur > 5*time.Second {
			sleepDur = 5 * time.Second
		}
		time.Sleep(sleepDur)
	}
}

// Wait blocks until an approval is resolved or ctx is canceled.
func (m *Manager) Wait(ctx context.Context, approvalID string) (types.ApprovalRequest, error) {
	m.mu.Lock()
	ch, ok := m.waiters[approvalID]
	m.mu.Unlock()
	if !ok {
		app, _, err := m.store.GetApproval(ctx, approvalID)
		return app, err
	}
	select {
	case res := <-ch:
		return res.Approval, res.Err
	case <-ctx.Done():
		return types.ApprovalRequest{}, ctx.Err()
	}
}

// Resolve verifies the optional one-time token (or trusted UI session) and records decision atomically.
func (m *Manager) Resolve(ctx context.Context, approvalID string, approve bool, reviewer, note, token string, trustedUISession bool) (types.ApprovalRequest, error) {
	_, expectedHash, err := m.store.GetApproval(ctx, approvalID)
	if err != nil {
		return types.ApprovalRequest{}, err
	}
	if !trustedUISession {
		if token == "" || subtle.ConstantTimeCompare([]byte(HashToken(token)), []byte(expectedHash)) != 1 {
			return types.ApprovalRequest{}, fmt.Errorf("invalid or missing one-time approval token")
		}
	}

	next := types.ApprovalRejected
	if approve {
		next = types.ApprovalApproved
	}
	if reviewer == "" {
		reviewer = "local-human"
	}
	app, err := m.store.ResolveApproval(ctx, approvalID, next, reviewer, note)
	if err != nil {
		return app, err
	}
	m.notifyWaiter(approvalID, Resolution{Approval: app})
	return app, nil
}

// Cancel marks a pending approval cancelled and cancels the upstream provider ticket.
func (m *Manager) Cancel(ctx context.Context, approvalID, actor string) (types.ApprovalRequest, error) {
	app, err := m.store.ResolveApproval(ctx, approvalID, types.ApprovalCancelled, actor, "cancelled")
	if err != nil {
		return app, err
	}
	m.mu.Lock()
	prov := m.providers[app.Provider]
	m.mu.Unlock()
	if prov != nil {
		_ = prov.Cancel(ctx, approvalID, app.ExternalTicketID)
	}
	m.notifyWaiter(approvalID, Resolution{Approval: app})
	return app, nil
}

func (m *Manager) notifyWaiter(approvalID string, res Resolution) {
	m.mu.Lock()
	ch, ok := m.waiters[approvalID]
	if ok {
		delete(m.waiters, approvalID)
	}
	m.mu.Unlock()
	if ok {
		select {
		case ch <- res:
		default:
		}
		close(ch)
	}
}

// Shutdown waits for deadline monitor goroutines to exit cleanly.
func (m *Manager) Shutdown() {
	m.mu.Lock()
	for id, ch := range m.waiters {
		delete(m.waiters, id)
		close(ch)
	}
	m.mu.Unlock()
	m.wg.Wait()
}

// HashToken hashes an approval token using SHA-256.
func HashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

func randomToken() string {
	var b [24]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
