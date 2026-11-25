package daemon

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/x0c/agent-dbctl/internal/approval"
	"github.com/x0c/agent-dbctl/internal/policy"
	"github.com/x0c/agent-dbctl/internal/store"
	"github.com/x0c/agent-dbctl/internal/types"
)

// RegisterWebhookProviderFromEnv registers the built-in webhook approval provider
// when AGENT_DBCTL_WEBHOOK_URL is configured.
func (s *Service) RegisterWebhookProviderFromEnv() bool {
	wh, err := approval.NewWebhookProviderFromEnv(s.localWeb)
	if err != nil || wh == nil {
		return false
	}
	s.approvals.RegisterProvider(wh)
	return true
}

// RecoverOnStartup reconciles interrupted operations and expired approvals from previous
// daemon runs, and rehydrates waiter goroutines for still-valid pending approvals.
func (s *Service) RecoverOnStartup(ctx context.Context) (store.RecoveryReport, error) {
	report, err := s.store.RecoverOnStartup(ctx, "system")
	if err != nil {
		return report, err
	}

	for _, app := range report.ActivePendingApprovals {
		op, opErr := s.store.GetOperation(ctx, app.OperationID)
		if opErr != nil {
			_, _ = s.approvals.Cancel(ctx, app.ID, "system")
			continue
		}
		detail, detErr := s.ResolveTarget(ctx, op.TargetRef, op.WorkspaceCWD)
		if detErr != nil {
			_, _ = s.approvals.Cancel(ctx, app.ID, "system")
			op.Status = types.OpFailed
			op.ErrorCode = types.ErrCodeDBNotFound
			op.ErrorMessage = "Target database no longer exists in catalog."
			op.CompletedAtUTC = time.Now().UTC().Format(time.RFC3339Nano)
			_, _ = s.store.UpdateOperation(ctx, "system", "operation.reconciled", op)
			continue
		}

		if _, ok := s.approvals.Rehydrate(app); !ok {
			continue
		}

		eval := policy.Evaluate(detail.Target, detail.EffectivePolicy, op.Classification, op.Preflight)
		eval.Decision = op.Decision
		eval.TriggerReasons = op.TriggerReasons
		eval.CredentialMode = op.CredentialMode

		s.wg.Add(1)
		go func(opSnap types.Operation, detSnap types.TargetDetail, evalSnap types.PolicyEvaluation, approvalID string) {
			defer s.wg.Done()
			s.driveApprovalLifecycle(opSnap, detSnap, evalSnap, approvalID, 0, 0, 0)
		}(op, detail, eval, app.ID)
	}
	return report, nil
}

// CancelOperationAndWait cancels a waiting or active operation and waits briefly for
// its lifecycle goroutine to commit the terminal state in SQLite.
func (s *Service) CancelOperationAndWait(ctx context.Context, opID, actor string) (types.ExecResponse, error) {
	resp, err := s.CancelOperation(ctx, opID, actor)
	if err != nil {
		return resp, err
	}
	if isTerminalOpStatus(resp.Status) {
		return resp, nil
	}

	deadline := time.Now().Add(2 * time.Second)
	directFallbackAt := time.Now().Add(120 * time.Millisecond)
	fallbackDone := false

	for time.Now().Before(deadline) {
		cur, getErr := s.GetOperationStatus(ctx, opID)
		if getErr == nil && isTerminalOpStatus(cur.Status) {
			return cur, nil
		}
		// Handle orphaned waiting_approval rows that have no active lifecycle waiter.
		if !fallbackDone && time.Now().After(directFallbackAt) && getErr == nil && cur.Status == types.OpWaitingApproval {
			fallbackDone = true
			if op, opErr := s.store.GetOperation(ctx, opID); opErr == nil && op.Status == types.OpWaitingApproval {
				op.Status = types.OpCancelled
				op.ErrorCode = types.ErrCodePolicyDenied
				op.ErrorMessage = "Operation was cancelled."
				op.CompletedAtUTC = time.Now().UTC().Format(time.RFC3339Nano)
				_, _ = s.store.UpdateOperation(ctx, actor, "operation.cancelled", op)
				s.broadcast(Event{Type: "operation_updated", Data: op})
			}
		}
		select {
		case <-ctx.Done():
			return s.GetOperationStatus(context.Background(), opID)
		case <-time.After(25 * time.Millisecond):
		}
	}
	return s.GetOperationStatus(ctx, opID)
}

// WaitForOperation blocks until opID reaches a terminal status or timeout elapses.
func (s *Service) WaitForOperation(ctx context.Context, opID string, timeout time.Duration) (types.ExecResponse, error) {
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	if timeout > 600*time.Second {
		timeout = 600 * time.Second
	}

	resp, err := s.GetOperationStatus(ctx, opID)
	if err != nil {
		return resp, err
	}
	if isTerminalOpStatus(resp.Status) {
		return resp, nil
	}

	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	pollInterval := 80 * time.Millisecond
	if s.IsServerMode() {
		pollInterval = 250 * time.Millisecond
	}
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-waitCtx.Done():
			cur, getErr := s.GetOperationStatus(context.Background(), opID)
			if getErr != nil {
				return resp, getErr
			}
			if cur.Status == types.OpWaitingApproval && cur.ErrorCode == "" {
				cur.ErrorCode = types.ErrCodeWaitingApproval
				cur.ErrorMessage = fmt.Sprintf("Operation %s is still waiting for human approval (%s).", cur.OperationID, strings.Join(cur.Evaluation.TriggerReasons, ", "))
			}
			return cur, nil
		case <-ticker.C:
			cur, getErr := s.GetOperationStatus(waitCtx, opID)
			if getErr != nil {
				continue
			}
			if isTerminalOpStatus(cur.Status) {
				return cur, nil
			}
			resp = cur
		}
	}
}

func isTerminalOpStatus(st types.OperationStatus) bool {
	switch st {
	case types.OpSucceeded,
		types.OpFailed,
		types.OpDenied,
		types.OpRejected,
		types.OpExpired,
		types.OpCancelled,
		types.OpTimedOut:
		return true
	default:
		return false
	}
}
