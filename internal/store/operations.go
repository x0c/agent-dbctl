package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/x0c/agent-dbctl/internal/audit"
	"github.com/x0c/agent-dbctl/internal/types"
)

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
				risk_level, decision, trigger_reasons_json, classification_json, preflight_json,
				status, credential_mode, approval_id, fetched_rows, returned_rows, affected_rows,
				truncated, cutoff_reason, latency_ms, error_code, error_message, retryable,
				created_at_utc, updated_at_utc, completed_at_utc
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			op.ID, op.TargetID, op.TargetRef, op.SystemID, op.SystemSlug, op.EnvironmentCode, op.Engine,
			op.Actor, op.Reason, op.WorkspaceCWD, op.QueryText, op.QueryRedacted,
			string(op.RiskLevel), string(op.Decision), string(trigJSON), string(clsJSON), preflightJSON,
			string(op.Status), string(op.CredentialMode), op.ApprovalID, op.FetchedRows, op.ReturnedRows, nullableInt64(op.AffectedRows),
			boolToInt(op.Truncated), op.CutoffReason, op.LatencyMs, op.ErrorCode, op.ErrorMessage, boolToInt(op.Retryable),
			op.CreatedAtUTC, op.UpdatedAtUTC, op.CompletedAtUTC)
		if err != nil {
			return err
		}
		return s.appendAuditTx(ctx, tx, op.Actor, "operation.submit", op.TargetID, op.ID, map[string]any{
			"target_ref":  op.TargetRef,
			"env":         op.EnvironmentCode,
			"engine":      op.Engine,
			"risk_level":  op.RiskLevel,
			"decision":    op.Decision,
			"status":      op.Status,
			"reason":      op.Reason,
			"query":       op.QueryRedacted,
		}, now)
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
		}, now)
	})
	return op, err
}

// GetOperation returns an operation by ID.
func (s *Store) GetOperation(ctx context.Context, id string) (types.Operation, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, target_id, target_ref, system_id, system_slug, environment_code, engine,
			actor, reason, workspace_cwd, query_text, query_redacted,
			risk_level, decision, trigger_reasons_json, classification_json, preflight_json,
			status, credential_mode, approval_id, fetched_rows, returned_rows, affected_rows,
			truncated, cutoff_reason, latency_ms, error_code, error_message, retryable,
			created_at_utc, updated_at_utc, completed_at_utc
		FROM operations WHERE id = ?`, id)
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
		risk_level, decision, trigger_reasons_json, classification_json, preflight_json,
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
				query_text, risk_level, trigger_reasons_json, preflight_json,
				reviewer, reviewer_note, created_at_utc, expires_at_utc, resolved_at_utc
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			app.ID, app.OperationID, app.Provider, app.ExternalTicketID, app.ExternalTicketURL, tokenHash,
			string(app.Status), app.TargetRef, app.SystemSlug, app.EnvironmentCode, app.Engine, app.Actor, app.Reason, app.WorkspaceCWD,
			app.QueryText, string(app.RiskLevel), string(trigJSON), preflightJSON,
			app.Reviewer, app.ReviewerNote, app.CreatedAtUTC, app.ExpiresAtUTC, app.ResolvedAtUTC)
		if err != nil {
			return err
		}
		return s.appendAuditTx(ctx, tx, actor, "approval.create", app.TargetRef, app.OperationID, map[string]any{
			"approval_id": app.ID,
			"provider":    app.Provider,
			"env":         app.EnvironmentCode,
			"risk_level":  app.RiskLevel,
		}, now)
	})
	return app, err
}

// GetApproval returns an approval ticket and its stored token hash.
func (s *Store) GetApproval(ctx context.Context, id string) (types.ApprovalRequest, string, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, operation_id, provider, external_ticket_id, external_ticket_url, token_hash,
			status, target_ref, system_slug, environment_code, engine, actor, reason, workspace_cwd,
			query_text, risk_level, trigger_reasons_json, preflight_json,
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
		query_text, risk_level, trigger_reasons_json, preflight_json,
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
func (s *Store) ResolveApproval(ctx context.Context, id string, nextStatus types.ApprovalStatus, reviewer, note string) (types.ApprovalRequest, error) {
	var updated types.ApprovalRequest
	now := nowUTC()
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `
			SELECT id, operation_id, provider, external_ticket_id, external_ticket_url, token_hash,
				status, target_ref, system_slug, environment_code, engine, actor, reason, workspace_cwd,
				query_text, risk_level, trigger_reasons_json, preflight_json,
				reviewer, reviewer_note, created_at_utc, expires_at_utc, resolved_at_utc
			FROM approvals WHERE id = ?`, id)
		cur, _, err := scanApproval(row)
		if err != nil {
			return err
		}
		if cur.Status != types.ApprovalPending {
			return fmt.Errorf("%w: approval %s already %s", ErrConflict, id, cur.Status)
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
	return updated, err
}

// ListAuditEntries returns audit logs ordered newest first.
func (s *Store) ListAuditEntries(ctx context.Context, action, targetID, opID string, limit int) ([]types.AuditEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	var conds []string
	var args []any
	if action != "" {
		conds = append(conds, "action LIKE ?")
		args = append(args, "%"+action+"%")
	}
	if targetID != "" {
		conds = append(conds, "target_id LIKE ?")
		args = append(args, "%"+targetID+"%")
	}
	if opID != "" {
		conds = append(conds, "operation_id = ?")
		args = append(args, opID)
	}
	q := `SELECT seq, id, actor, action, target_id, operation_id, payload_json, prev_hash, entry_hash, created_at_utc FROM audit_logs`
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	q += " ORDER BY seq DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []types.AuditEntry
	for rows.Next() {
		var e types.AuditEntry
		if err := rows.Scan(&e.Seq, &e.ID, &e.Actor, &e.Action, &e.TargetID, &e.OperationID, &e.PayloadJSON, &e.PrevHash, &e.EntryHash, &e.CreatedAtUTC); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
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
	var trigJSON, clsJSON, preflightJSON string
	var affected sql.NullInt64
	var truncated, retryable int
	err := r.Scan(
		&op.ID, &op.TargetID, &op.TargetRef, &op.SystemID, &op.SystemSlug, &op.EnvironmentCode, &op.Engine,
		&op.Actor, &op.Reason, &op.WorkspaceCWD, &op.QueryText, &op.QueryRedacted,
		&op.RiskLevel, &op.Decision, &trigJSON, &clsJSON, &preflightJSON,
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
	var tokenHash, trigJSON, preflightJSON string
	err := r.Scan(
		&app.ID, &app.OperationID, &app.Provider, &app.ExternalTicketID, &app.ExternalTicketURL, &tokenHash,
		&app.Status, &app.TargetRef, &app.SystemSlug, &app.EnvironmentCode, &app.Engine, &app.Actor, &app.Reason, &app.WorkspaceCWD,
		&app.QueryText, &app.RiskLevel, &trigJSON, &preflightJSON,
		&app.Reviewer, &app.ReviewerNote, &app.CreatedAtUTC, &app.ExpiresAtUTC, &app.ResolvedAtUTC)
	if errors.Is(err, sql.ErrNoRows) {
		return app, "", ErrNotFound
	}
	if err != nil {
		return app, "", err
	}
	_ = json.Unmarshal([]byte(trigJSON), &app.TriggerReasons)
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
