package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/x0c/agent-dbctl/internal/audit"
	"github.com/x0c/agent-dbctl/internal/types"
)

// ErrApprovalExpired indicates an approval ticket already passed its expiration timestamp.
var ErrApprovalExpired = fmt.Errorf("%w: approval expired", ErrConflict)

// RecoveryReport summarizes interrupted operations and pending approvals reconciled on daemon startup.
type RecoveryReport struct {
	InterruptedOps         int                     `json:"interrupted_ops"`
	ExpiredApprovals       int                     `json:"expired_approvals"`
	ReconciledOps          int                     `json:"reconciled_ops"`
	ActivePendingApprovals []types.ApprovalRequest `json:"active_pending_approvals,omitempty"`
}

// AuditFilter narrows audit_logs queries with optional pagination.
type AuditFilter struct {
	Action      string
	TargetID    string
	OperationID string
	Actor       string
	SinceUTC    string
	UntilUTC    string
	Limit       int
	Offset      int
}

// RecordAuditEvent writes a standalone append-only audit entry in its own transaction.
func (s *Store) RecordAuditEvent(ctx context.Context, actor, action, targetID, opID string, payload any) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		return s.appendAuditTx(ctx, tx, actor, action, targetID, opID, payload, "")
	})
}

// CreateOperation writes the initial WAL operation and audit record in a single transaction.
func (s *Store) CreateOperation(ctx context.Context, op types.Operation) (types.Operation, error) {
	now := nowUTC()
	if op.ID == "" {
		op.ID = newID("op")
	}
	if op.CreatedAtUTC == "" {
		op.CreatedAtUTC = now
	}
	op.UpdatedAtUTC = now
	trigJSON, _ := json.Marshal(op.TriggerReasons)
	matchedJSON, _ := json.Marshal(op.MatchedRules)
	clsJSON, _ := json.Marshal(op.Classification)
	var preflightJSON string
	if op.Preflight != nil {
		b, _ := json.Marshal(op.Preflight)
		preflightJSON = string(b)
	}

	err := s.withTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO operations(
				id, target_id, target_ref, system_id, system_slug, environment_code, engine,
				actor, reason, workspace_cwd, query_text, query_redacted,
				risk_level, decision, trigger_reasons_json, matched_rules_json, classification_json, preflight_json,
				status, credential_mode, approval_id, fetched_rows, returned_rows, affected_rows,
				truncated, cutoff_reason, latency_ms, error_code, error_message, retryable,
				created_at_utc, updated_at_utc, completed_at_utc
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			op.ID, op.TargetID, op.TargetRef, op.SystemID, op.SystemSlug, op.EnvironmentCode, op.Engine,
			op.Actor, op.Reason, op.WorkspaceCWD, op.QueryText, op.QueryRedacted,
			string(op.RiskLevel), string(op.Decision), string(trigJSON), string(matchedJSON), string(clsJSON), preflightJSON,
			string(op.Status), string(op.CredentialMode), op.ApprovalID, op.FetchedRows, op.ReturnedRows, nullableInt64(op.AffectedRows),
			boolToInt(op.Truncated), op.CutoffReason, op.LatencyMs, op.ErrorCode, op.ErrorMessage, boolToInt(op.Retryable),
			op.CreatedAtUTC, op.UpdatedAtUTC, op.CompletedAtUTC)
		if err != nil {
			return err
		}
		auditPayload := map[string]any{
			"target_ref": op.TargetRef,
			"env":        op.EnvironmentCode,
			"engine":     op.Engine,
			"risk_level": op.RiskLevel,
			"decision":   op.Decision,
			"status":     op.Status,
			"reason":     op.Reason,
			"query":      op.QueryRedacted,
		}
		if len(op.MatchedRules) > 0 {
			auditPayload["matched_rules"] = op.MatchedRules
		}
		return s.appendAuditTx(ctx, tx, op.Actor, "operation.submit", op.TargetID, op.ID, auditPayload, now)
	})
	return op, err
}

// UpdateOperation updates an operation state and records an audit event atomically.
func (s *Store) UpdateOperation(ctx context.Context, actor, auditAction string, op types.Operation) (types.Operation, error) {
	now := nowUTC()
	op.UpdatedAtUTC = now
	trigJSON, _ := json.Marshal(op.TriggerReasons)
	var preflightJSON string
	if op.Preflight != nil {
		b, _ := json.Marshal(op.Preflight)
		preflightJSON = string(b)
	}

	err := s.withTx(ctx, func(tx *sql.Tx) error {
		return s.updateOperationTx(ctx, tx, actor, auditAction, &op, trigJSON, preflightJSON, now)
	})
	return op, err
}

func (s *Store) updateOperationTx(ctx context.Context, tx *sql.Tx, actor, auditAction string, op *types.Operation, trigJSON []byte, preflightJSON, ts string) error {
	op.UpdatedAtUTC = ts
	_, err := tx.ExecContext(ctx, `
		UPDATE operations SET
			decision = ?, trigger_reasons_json = ?, preflight_json = ?, status = ?,
			credential_mode = ?, approval_id = ?, fetched_rows = ?, returned_rows = ?,
			affected_rows = ?, truncated = ?, cutoff_reason = ?, latency_ms = ?,
			error_code = ?, error_message = ?, retryable = ?, updated_at_utc = ?, completed_at_utc = ?
		WHERE id = ?`,
		string(op.Decision), string(trigJSON), preflightJSON, string(op.Status),
		string(op.CredentialMode), op.ApprovalID, op.FetchedRows, op.ReturnedRows,
		nullableInt64(op.AffectedRows), boolToInt(op.Truncated), op.CutoffReason, op.LatencyMs,
		op.ErrorCode, op.ErrorMessage, boolToInt(op.Retryable), op.UpdatedAtUTC, op.CompletedAtUTC, op.ID)
	if err != nil {
		return err
	}
	return s.appendAuditTx(ctx, tx, actor, auditAction, op.TargetID, op.ID, map[string]any{
		"status":        op.Status,
		"fetched_rows":  op.FetchedRows,
		"returned_rows": op.ReturnedRows,
		"affected_rows": op.AffectedRows,
		"truncated":     op.Truncated,
		"latency_ms":    op.LatencyMs,
		"error_code":    op.ErrorCode,
	}, ts)
}

// GetOperation returns an operation by ID.
func (s *Store) GetOperation(ctx context.Context, id string) (types.Operation, error) {
	row := s.db.QueryRowContext(ctx, opSelectByIDQuery, id)
	return scanOperation(row)
}

// ListOperations filters operations for CLI/Web observation.
func (s *Store) ListOperations(ctx context.Context, targetRef, envCode, systemSlug, status, search string, limit int) ([]types.Operation, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	var conds []string
	var args []any
	if targetRef != "" {
		conds = append(conds, "target_ref = ?")
		args = append(args, targetRef)
	}
	if envCode != "" {
		conds = append(conds, "environment_code = ?")
		args = append(args, envCode)
	}
	if systemSlug != "" {
		conds = append(conds, "system_slug = ?")
		args = append(args, systemSlug)
	}
	if status != "" {
		conds = append(conds, "status = ?")
		args = append(args, status)
	}
	if search != "" {
		conds = append(conds, "(id LIKE ? OR query_redacted LIKE ? OR reason LIKE ? OR target_ref LIKE ?)")
		like := "%" + search + "%"
		args = append(args, like, like, like, like)
	}
	q := `SELECT id, target_id, target_ref, system_id, system_slug, environment_code, engine,
		actor, reason, workspace_cwd, query_text, query_redacted,
		risk_level, decision, trigger_reasons_json, matched_rules_json, classification_json, preflight_json,
		status, credential_mode, approval_id, fetched_rows, returned_rows, affected_rows,
		truncated, cutoff_reason, latency_ms, error_code, error_message, retryable,
		created_at_utc, updated_at_utc, completed_at_utc
	FROM operations`
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	q += " ORDER BY created_at_utc DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []types.Operation
	for rows.Next() {
		op, err := scanOperation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, op)
	}
	return out, rows.Err()
}

// CreateApproval persists a new approval record alongside an audit entry.
func (s *Store) CreateApproval(ctx context.Context, actor string, app types.ApprovalRequest, tokenHash string) (types.ApprovalRequest, error) {
	now := nowUTC()
	if app.ID == "" {
		app.ID = newID("apr")
	}
	if app.CreatedAtUTC == "" {
		app.CreatedAtUTC = now
	}
	trigJSON, _ := json.Marshal(app.TriggerReasons)
	matchedJSON, _ := json.Marshal(app.MatchedRules)
	var preflightJSON string
	if app.Preflight != nil {
		b, _ := json.Marshal(app.Preflight)
		preflightJSON = string(b)
	}
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO approvals(
				id, operation_id, provider, external_ticket_id, external_ticket_url, token_hash,
				status, target_ref, system_slug, environment_code, engine, actor, reason, workspace_cwd,
				query_text, risk_level, trigger_reasons_json, matched_rules_json, preflight_json,
				reviewer, reviewer_note, created_at_utc, expires_at_utc, resolved_at_utc
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			app.ID, app.OperationID, app.Provider, app.ExternalTicketID, app.ExternalTicketURL, tokenHash,
			string(app.Status), app.TargetRef, app.SystemSlug, app.EnvironmentCode, app.Engine, app.Actor, app.Reason, app.WorkspaceCWD,
			app.QueryText, string(app.RiskLevel), string(trigJSON), string(matchedJSON), preflightJSON,
			app.Reviewer, app.ReviewerNote, app.CreatedAtUTC, app.ExpiresAtUTC, app.ResolvedAtUTC)
		if err != nil {
			return err
		}
		auditPayload := map[string]any{
			"approval_id": app.ID,
			"provider":    app.Provider,
			"env":         app.EnvironmentCode,
			"risk_level":  app.RiskLevel,
		}
		if len(app.MatchedRules) > 0 {
			auditPayload["matched_rules"] = app.MatchedRules
		}
		return s.appendAuditTx(ctx, tx, actor, "approval.create", app.TargetRef, app.OperationID, auditPayload, now)
	})
	return app, err
}

// UpdateApprovalTicket persists sanitized external ticket metadata after ApprovalProvider.Submit succeeds.
func (s *Store) UpdateApprovalTicket(ctx context.Context, id, externalTicketID, externalTicketURL string) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE approvals SET external_ticket_id = ?, external_ticket_url = ? WHERE id = ?`,
			externalTicketID, externalTicketURL, id)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// GetApproval returns an approval ticket and its stored token hash.
func (s *Store) GetApproval(ctx context.Context, id string) (types.ApprovalRequest, string, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, operation_id, provider, external_ticket_id, external_ticket_url, token_hash,
			status, target_ref, system_slug, environment_code, engine, actor, reason, workspace_cwd,
			query_text, risk_level, trigger_reasons_json, matched_rules_json, preflight_json,
			reviewer, reviewer_note, created_at_utc, expires_at_utc, resolved_at_utc
		FROM approvals WHERE id = ?`, id)
	return scanApproval(row)
}

// ListApprovals returns approvals ordered newest first.
func (s *Store) ListApprovals(ctx context.Context, status string, limit int) ([]types.ApprovalRequest, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `SELECT id, operation_id, provider, external_ticket_id, external_ticket_url, token_hash,
		status, target_ref, system_slug, environment_code, engine, actor, reason, workspace_cwd,
		query_text, risk_level, trigger_reasons_json, matched_rules_json, preflight_json,
		reviewer, reviewer_note, created_at_utc, expires_at_utc, resolved_at_utc
	FROM approvals`
	var args []any
	if status != "" {
		q += " WHERE status = ?"
		args = append(args, status)
	}
	q += " ORDER BY created_at_utc DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []types.ApprovalRequest
	for rows.Next() {
		app, _, err := scanApproval(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, app)
	}
	return out, rows.Err()
}

// ResolveApproval atomically transitions a pending approval to approved/rejected/expired/cancelled and writes an audit entry.
// When approving an already-expired ticket, it commits the expired transition and returns ErrApprovalExpired.
func (s *Store) ResolveApproval(ctx context.Context, id string, nextStatus types.ApprovalStatus, reviewer, note string) (types.ApprovalRequest, error) {
	var updated types.ApprovalRequest
	var expiredErr error
	nowTime := time.Now().Round(0).UTC()
	now := nowTime.Format(time.RFC3339Nano)

	err := s.withTx(ctx, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `
			SELECT id, operation_id, provider, external_ticket_id, external_ticket_url, token_hash,
				status, target_ref, system_slug, environment_code, engine, actor, reason, workspace_cwd,
				query_text, risk_level, trigger_reasons_json, matched_rules_json, preflight_json,
				reviewer, reviewer_note, created_at_utc, expires_at_utc, resolved_at_utc
			FROM approvals WHERE id = ?`, id)
		cur, _, err := scanApproval(row)
		if err != nil {
			return err
		}
		if cur.Status != types.ApprovalPending {
			return fmt.Errorf("%w: approval %s already %s", ErrConflict, id, cur.Status)
		}

		if nextStatus == types.ApprovalApproved {
			if exp, ok := parseUTCTime(cur.ExpiresAtUTC); ok && !nowTime.Before(exp) {
				cur.Status = types.ApprovalExpired
				cur.Reviewer = "system"
				cur.ReviewerNote = "approval expired before resolution"
				cur.ResolvedAtUTC = now
				if _, err := tx.ExecContext(ctx, `
					UPDATE approvals SET status = ?, reviewer = ?, reviewer_note = ?, resolved_at_utc = ? WHERE id = ?`,
					string(cur.Status), cur.Reviewer, cur.ReviewerNote, now, id); err != nil {
					return err
				}
				if err := s.appendAuditTx(ctx, tx, "system", "approval.expired", cur.TargetRef, cur.OperationID, map[string]any{
					"approval_id":   id,
					"status":        cur.Status,
					"reviewer_note": cur.ReviewerNote,
				}, now); err != nil {
					return err
				}
				updated = cur
				expiredErr = ErrApprovalExpired
				// Return nil so the expired state and audit row commit cleanly.
				return nil
			}
		}

		cur.Status = nextStatus
		cur.Reviewer = reviewer
		cur.ReviewerNote = note
		cur.ResolvedAtUTC = now

		_, err = tx.ExecContext(ctx, `
			UPDATE approvals SET status = ?, reviewer = ?, reviewer_note = ?, resolved_at_utc = ? WHERE id = ?`,
			string(nextStatus), reviewer, note, now, id)
		if err != nil {
			return err
		}
		updated = cur
		return s.appendAuditTx(ctx, tx, reviewer, "approval."+string(nextStatus), cur.TargetRef, cur.OperationID, map[string]any{
			"approval_id":   id,
			"status":        nextStatus,
			"reviewer_note": note,
		}, now)
	})
	if err != nil {
		return updated, err
	}
	if expiredErr != nil {
		return updated, expiredErr
	}
	return updated, nil
}

// RecoverOnStartup reconciles interrupted operations, expires overdue pending approvals,
// and collects still-valid pending approvals inside one atomic transaction.
func (s *Store) RecoverOnStartup(ctx context.Context, actor string) (RecoveryReport, error) {
	if actor == "" {
		actor = "system"
	}
	nowTime := time.Now().Round(0).UTC()
	now := nowTime.Format(time.RFC3339Nano)
	var report RecoveryReport

	err := s.withTx(ctx, func(tx *sql.Tx) error {
		// 1. Mark any interrupted running/pending operations as failed with daemon_restarted.
		runningOps, err := queryOperationsTx(ctx, tx, `
			SELECT id, target_id, target_ref, system_id, system_slug, environment_code, engine,
				actor, reason, workspace_cwd, query_text, query_redacted,
				risk_level, decision, trigger_reasons_json, matched_rules_json, classification_json, preflight_json,
				status, credential_mode, approval_id, fetched_rows, returned_rows, affected_rows,
				truncated, cutoff_reason, latency_ms, error_code, error_message, retryable,
				created_at_utc, updated_at_utc, completed_at_utc
			FROM operations WHERE status IN ('running', 'pending')`)
		if err != nil {
			return err
		}
		for i := range runningOps {
			op := runningOps[i]
			op.Status = types.OpFailed
			op.ErrorCode = types.ErrCodeDaemonRestarted
			op.ErrorMessage = "Daemon restarted while operation was in progress; verify database state before retrying."
			op.Retryable = op.Classification.IsReadOnly
			op.CompletedAtUTC = now
			trigJSON, _ := json.Marshal(op.TriggerReasons)
			var preflightJSON string
			if op.Preflight != nil {
				b, _ := json.Marshal(op.Preflight)
				preflightJSON = string(b)
			}
			if err := s.updateOperationTx(ctx, tx, actor, "operation.interrupted", &op, trigJSON, preflightJSON, now); err != nil {
				return err
			}
			report.InterruptedOps++
		}

		// 2. Scan pending approvals: expire overdue ones and return active ones for waiter rehydration.
		pendingApps, err := queryApprovalsTx(ctx, tx, `
			SELECT id, operation_id, provider, external_ticket_id, external_ticket_url, token_hash,
				status, target_ref, system_slug, environment_code, engine, actor, reason, workspace_cwd,
				query_text, risk_level, trigger_reasons_json, matched_rules_json, preflight_json,
				reviewer, reviewer_note, created_at_utc, expires_at_utc, resolved_at_utc
			FROM approvals WHERE status = 'pending' ORDER BY created_at_utc ASC`)
		if err != nil {
			return err
		}

		for _, app := range pendingApps {
			if exp, ok := parseUTCTime(app.ExpiresAtUTC); ok && !nowTime.Before(exp) {
				if _, err := tx.ExecContext(ctx, `
					UPDATE approvals SET status = ?, reviewer = ?, reviewer_note = ?, resolved_at_utc = ? WHERE id = ?`,
					string(types.ApprovalExpired), "system", "approval expired during daemon downtime", now, app.ID); err != nil {
					return err
				}
				if err := s.appendAuditTx(ctx, tx, actor, "approval.expired", app.TargetRef, app.OperationID, map[string]any{
					"approval_id":   app.ID,
					"status":        types.ApprovalExpired,
					"reviewer_note": "approval expired during daemon downtime",
				}, now); err != nil {
					return err
				}
				report.ExpiredApprovals++

				// Transition linked waiting_approval operation if still waiting.
				opRow := tx.QueryRowContext(ctx, opSelectByIDQuery, app.OperationID)
				if op, opErr := scanOperation(opRow); opErr == nil && op.Status == types.OpWaitingApproval {
					op.Status = types.OpExpired
					op.ErrorCode = types.ErrCodeApprovalTimeout
					op.ErrorMessage = "Approval timed out while daemon was offline."
					op.Retryable = true
					op.CompletedAtUTC = now
					trigJSON, _ := json.Marshal(op.TriggerReasons)
					var preflightJSON string
					if op.Preflight != nil {
						b, _ := json.Marshal(op.Preflight)
						preflightJSON = string(b)
					}
					if err := s.updateOperationTx(ctx, tx, actor, "operation.expired", &op, trigJSON, preflightJSON, now); err != nil {
						return err
					}
					report.ReconciledOps++
				}
			} else {
				report.ActivePendingApprovals = append(report.ActivePendingApprovals, app)
			}
		}

		// 3. Reconcile any remaining waiting_approval operations whose approval is terminal or missing.
		waitingOps, err := queryOperationsTx(ctx, tx, `
			SELECT id, target_id, target_ref, system_id, system_slug, environment_code, engine,
				actor, reason, workspace_cwd, query_text, query_redacted,
				risk_level, decision, trigger_reasons_json, matched_rules_json, classification_json, preflight_json,
				status, credential_mode, approval_id, fetched_rows, returned_rows, affected_rows,
				truncated, cutoff_reason, latency_ms, error_code, error_message, retryable,
				created_at_utc, updated_at_utc, completed_at_utc
			FROM operations WHERE status = 'waiting_approval'`)
		if err != nil {
			return err
		}
		for i := range waitingOps {
			op := waitingOps[i]
			var appStatus types.ApprovalStatus
			var appFound bool
			if op.ApprovalID != "" {
				appRow := tx.QueryRowContext(ctx, `
					SELECT id, operation_id, provider, external_ticket_id, external_ticket_url, token_hash,
						status, target_ref, system_slug, environment_code, engine, actor, reason, workspace_cwd,
						query_text, risk_level, trigger_reasons_json, matched_rules_json, preflight_json,
						reviewer, reviewer_note, created_at_utc, expires_at_utc, resolved_at_utc
					FROM approvals WHERE id = ?`, op.ApprovalID)
				if app, _, appErr := scanApproval(appRow); appErr == nil {
					appStatus = app.Status
					appFound = true
				} else if !errors.Is(appErr, ErrNotFound) {
					return appErr
				}
			}
			if appFound && appStatus == types.ApprovalPending {
				continue
			}

			switch {
			case appFound && appStatus == types.ApprovalRejected:
				op.Status = types.OpRejected
				op.ErrorCode = types.ErrCodeApprovalRejected
				op.ErrorMessage = "Execution was rejected by human reviewer."
				op.Retryable = false
			case appFound && appStatus == types.ApprovalExpired:
				op.Status = types.OpExpired
				op.ErrorCode = types.ErrCodeApprovalTimeout
				op.ErrorMessage = "Approval timed out before a human responded."
				op.Retryable = true
			case appFound && appStatus == types.ApprovalCancelled:
				op.Status = types.OpCancelled
				op.ErrorCode = types.ErrCodePolicyDenied
				op.ErrorMessage = "Operation was cancelled."
				op.Retryable = false
			default:
				op.Status = types.OpFailed
				op.ErrorCode = types.ErrCodeDaemonRestarted
				op.ErrorMessage = "Daemon restarted while approved or unlinked operation was pending execution; verify database state before retrying."
				op.Retryable = op.Classification.IsReadOnly
			}
			op.CompletedAtUTC = now
			trigJSON, _ := json.Marshal(op.TriggerReasons)
			var preflightJSON string
			if op.Preflight != nil {
				b, _ := json.Marshal(op.Preflight)
				preflightJSON = string(b)
			}
			if err := s.updateOperationTx(ctx, tx, actor, "operation.reconciled", &op, trigJSON, preflightJSON, now); err != nil {
				return err
			}
			report.ReconciledOps++
		}
		return nil
	})
	return report, err
}

const opSelectByIDQuery = `
	SELECT id, target_id, target_ref, system_id, system_slug, environment_code, engine,
		actor, reason, workspace_cwd, query_text, query_redacted,
		risk_level, decision, trigger_reasons_json, matched_rules_json, classification_json, preflight_json,
		status, credential_mode, approval_id, fetched_rows, returned_rows, affected_rows,
		truncated, cutoff_reason, latency_ms, error_code, error_message, retryable,
		created_at_utc, updated_at_utc, completed_at_utc
	FROM operations WHERE id = ?`

func queryOperationsTx(ctx context.Context, tx *sql.Tx, q string, args ...any) ([]types.Operation, error) {
	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []types.Operation
	for rows.Next() {
		op, err := scanOperation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, op)
	}
	return out, rows.Err()
}

func queryApprovalsTx(ctx context.Context, tx *sql.Tx, q string, args ...any) ([]types.ApprovalRequest, error) {
	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []types.ApprovalRequest
	for rows.Next() {
		app, _, err := scanApproval(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, app)
	}
	return out, rows.Err()
}

// ListAuditEntries returns audit logs ordered newest first.
func (s *Store) ListAuditEntries(ctx context.Context, action, targetID, opID string, limit int) ([]types.AuditEntry, error) {
	items, _, err := s.ListAuditEntriesFiltered(ctx, AuditFilter{
		Action:      action,
		TargetID:    targetID,
		OperationID: opID,
		Limit:       limit,
	})
	return items, err
}

// ListAuditEntriesFiltered returns filtered audit entries along with the total matching row count.
func (s *Store) ListAuditEntriesFiltered(ctx context.Context, f AuditFilter) ([]types.AuditEntry, int, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 200
	} else if limit > 1000 {
		limit = 1000
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	var conds []string
	var args []any
	if f.Action != "" {
		conds = append(conds, "action LIKE ?")
		args = append(args, "%"+f.Action+"%")
	}
	if f.TargetID != "" {
		conds = append(conds, "target_id LIKE ?")
		args = append(args, "%"+f.TargetID+"%")
	}
	if f.OperationID != "" {
		conds = append(conds, "operation_id = ?")
		args = append(args, f.OperationID)
	}
	if f.Actor != "" {
		conds = append(conds, "actor = ?")
		args = append(args, f.Actor)
	}
	if f.SinceUTC != "" {
		conds = append(conds, "created_at_utc >= ?")
		args = append(args, f.SinceUTC)
	}
	if f.UntilUTC != "" {
		conds = append(conds, "created_at_utc <= ?")
		args = append(args, f.UntilUTC)
	}

	whereClause := ""
	if len(conds) > 0 {
		whereClause = " WHERE " + strings.Join(conds, " AND ")
	}

	var totalMatched int
	countQ := `SELECT COUNT(1) FROM audit_logs` + whereClause
	if err := s.db.QueryRowContext(ctx, countQ, args...).Scan(&totalMatched); err != nil {
		return nil, 0, err
	}

	q := `SELECT seq, id, actor, action, target_id, operation_id, payload_json, prev_hash, entry_hash, created_at_utc FROM audit_logs` +
		whereClause + ` ORDER BY seq DESC LIMIT ? OFFSET ?`
	pageArgs := append(append([]any{}, args...), limit, offset)

	rows, err := s.db.QueryContext(ctx, q, pageArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rows.Close() }()

	var out []types.AuditEntry
	for rows.Next() {
		var e types.AuditEntry
		if err := rows.Scan(&e.Seq, &e.ID, &e.Actor, &e.Action, &e.TargetID, &e.OperationID, &e.PayloadJSON, &e.PrevHash, &e.EntryHash, &e.CreatedAtUTC); err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, totalMatched, rows.Err()
}

// VerifyAuditChain checks SHA-256 chain continuity across all audit_logs rows.
func (s *Store) VerifyAuditChain(ctx context.Context) (types.AuditVerifyResult, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT seq, actor, action, target_id, operation_id, payload_json, prev_hash, entry_hash, created_at_utc
		FROM audit_logs ORDER BY seq ASC`)
	if err != nil {
		return types.AuditVerifyResult{}, err
	}
	defer func() { _ = rows.Close() }()

	res := types.AuditVerifyResult{Valid: true, LastHash: audit.GenesisPrevHash}
	expectedPrev := audit.GenesisPrevHash
	var expectedSeq int64 = 1

	for rows.Next() {
		var seq int64
		var actor, action, targetID, opID, payload, prevHash, entryHash, ts string
		if err := rows.Scan(&seq, &actor, &action, &targetID, &opID, &payload, &prevHash, &entryHash, &ts); err != nil {
			return res, err
		}
		res.CheckedCount++
		if seq != expectedSeq {
			res.Valid = false
			res.FirstBrokenAt = seq
			res.Reason = fmt.Sprintf("sequence gap: got %d, expected %d", seq, expectedSeq)
			return res, nil
		}
		if prevHash != expectedPrev {
			res.Valid = false
			res.FirstBrokenAt = seq
			res.Reason = fmt.Sprintf("prev_hash mismatch at seq %d", seq)
			return res, nil
		}
		computed := audit.ComputeEntryHash(seq, prevHash, actor, action, targetID, opID, payload, ts)
		if computed != entryHash {
			res.Valid = false
			res.FirstBrokenAt = seq
			res.Reason = fmt.Sprintf("entry_hash mismatch at seq %d", seq)
			return res, nil
		}
		expectedPrev = entryHash
		expectedSeq++
		res.LastHash = entryHash
	}
	return res, rows.Err()
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanOperation(r rowScanner) (types.Operation, error) {
	var op types.Operation
	var trigJSON, matchedJSON, clsJSON, preflightJSON string
	var affected sql.NullInt64
	var truncated, retryable int
	err := r.Scan(
		&op.ID, &op.TargetID, &op.TargetRef, &op.SystemID, &op.SystemSlug, &op.EnvironmentCode, &op.Engine,
		&op.Actor, &op.Reason, &op.WorkspaceCWD, &op.QueryText, &op.QueryRedacted,
		&op.RiskLevel, &op.Decision, &trigJSON, &matchedJSON, &clsJSON, &preflightJSON,
		&op.Status, &op.CredentialMode, &op.ApprovalID, &op.FetchedRows, &op.ReturnedRows, &affected,
		&truncated, &op.CutoffReason, &op.LatencyMs, &op.ErrorCode, &op.ErrorMessage, &retryable,
		&op.CreatedAtUTC, &op.UpdatedAtUTC, &op.CompletedAtUTC)
	if errors.Is(err, sql.ErrNoRows) {
		return op, ErrNotFound
	}
	if err != nil {
		return op, err
	}
	if affected.Valid {
		v := affected.Int64
		op.AffectedRows = &v
	}
	op.Truncated = truncated == 1
	op.Retryable = retryable == 1
	_ = json.Unmarshal([]byte(trigJSON), &op.TriggerReasons)
	_ = json.Unmarshal([]byte(matchedJSON), &op.MatchedRules)
	_ = json.Unmarshal([]byte(clsJSON), &op.Classification)
	if preflightJSON != "" {
		var pf types.PreflightReport
		if err := json.Unmarshal([]byte(preflightJSON), &pf); err == nil {
			op.Preflight = &pf
		}
	}
	return op, nil
}

func scanApproval(r rowScanner) (types.ApprovalRequest, string, error) {
	var app types.ApprovalRequest
	var tokenHash, trigJSON, matchedJSON, preflightJSON string
	err := r.Scan(
		&app.ID, &app.OperationID, &app.Provider, &app.ExternalTicketID, &app.ExternalTicketURL, &tokenHash,
		&app.Status, &app.TargetRef, &app.SystemSlug, &app.EnvironmentCode, &app.Engine, &app.Actor, &app.Reason, &app.WorkspaceCWD,
		&app.QueryText, &app.RiskLevel, &trigJSON, &matchedJSON, &preflightJSON,
		&app.Reviewer, &app.ReviewerNote, &app.CreatedAtUTC, &app.ExpiresAtUTC, &app.ResolvedAtUTC)
	if errors.Is(err, sql.ErrNoRows) {
		return app, "", ErrNotFound
	}
	if err != nil {
		return app, "", err
	}
	_ = json.Unmarshal([]byte(trigJSON), &app.TriggerReasons)
	_ = json.Unmarshal([]byte(matchedJSON), &app.MatchedRules)
	if preflightJSON != "" {
		var pf types.PreflightReport
		if err := json.Unmarshal([]byte(preflightJSON), &pf); err == nil {
			app.Preflight = &pf
		}
	}
	return app, tokenHash, nil
}

func nullableInt64(p *int64) sql.NullInt64 {
	if p == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: *p, Valid: true}
}

func parseUTCTime(raw string) (time.Time, bool) {
	if raw == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t.UTC(), true
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t.UTC(), true
	}
	return time.Time{}, false
}
