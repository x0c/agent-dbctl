package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/x0c/agent-dbctl/internal/policy"
	"github.com/x0c/agent-dbctl/internal/types"
)

// ListRiskPatternRules returns all configured custom/preset high-risk pattern rules.
func (s *Store) ListRiskPatternRules(ctx context.Context) ([]types.RiskPatternRule, error) {
	rows, err := s.dbQuery(ctx, `
		SELECT id, name, description, scope_type, scope_id, enabled, builtin_pack,
			engines_json, families_json, action, confirm_title, confirm_message,
			approval_provider, condition_json, priority, created_at_utc, updated_at_utc
		FROM risk_pattern_rules
		ORDER BY priority DESC, name ASC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []types.RiskPatternRule
	for rows.Next() {
		var r types.RiskPatternRule
		var enabledInt int
		var enginesJSON, familiesJSON, condJSON string
		if err := rows.Scan(
			&r.ID, &r.Name, &r.Description, &r.ScopeType, &r.ScopeID, &enabledInt, &r.BuiltinPack,
			&enginesJSON, &familiesJSON, &r.Action, &r.ConfirmTitle, &r.ConfirmMessage,
			&r.ApprovalProvider, &condJSON, &r.Priority, &r.CreatedAtUTC, &r.UpdatedAtUTC,
		); err != nil {
			return nil, err
		}
		r.Enabled = enabledInt == 1
		_ = json.Unmarshal([]byte(enginesJSON), &r.Engines)
		_ = json.Unmarshal([]byte(familiesJSON), &r.Families)
		_ = json.Unmarshal([]byte(condJSON), &r.Condition)
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpsertRiskPatternRule validates and saves a RiskPatternRule atomically with an audit log entry.
func (s *Store) UpsertRiskPatternRule(ctx context.Context, actor string, r types.RiskPatternRule) (types.RiskPatternRule, error) {
	now := nowUTC()
	var saved types.RiskPatternRule
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		var err error
		saved, err = s.upsertRiskPatternRuleTx(ctx, tx, actor, r, now)
		return err
	})
	if err != nil {
		return r, err
	}
	return saved, nil
}

func (s *Store) upsertRiskPatternRuleTx(ctx context.Context, tx *sql.Tx, actor string, r types.RiskPatternRule, now string) (types.RiskPatternRule, error) {
	r.Name = strings.TrimSpace(r.Name)
	if r.ScopeType == "global" {
		r.ScopeID = "global"
	} else {
		r.ScopeID = s.canonicalizeScopeIDTx(ctx, tx, r.ScopeType, r.ScopeID)
	}
	if err := policy.ValidateRiskPatternRule(r); err != nil {
		return r, err
	}
	if r.ID == "" {
		r.ID = newID("pat")
	}

	var existingCreated string
	err := s.txQueryRow(ctx, tx, `SELECT created_at_utc FROM risk_pattern_rules WHERE id = ?`, r.ID).Scan(&existingCreated)
	action := "risk_pattern.create"
	if err == nil {
		action = "risk_pattern.update"
		r.CreatedAtUTC = existingCreated
	} else if errors.Is(err, sql.ErrNoRows) {
		r.CreatedAtUTC = now
	} else {
		return r, err
	}
	r.UpdatedAtUTC = now

	if r.Engines == nil {
		r.Engines = []string{}
	}
	if r.Families == nil {
		r.Families = []types.EngineFamily{}
	}
	enginesJSON, _ := json.Marshal(r.Engines)
	familiesJSON, _ := json.Marshal(r.Families)
	condJSON, _ := json.Marshal(r.Condition)

	_, err = s.txExec(ctx, tx, `
		INSERT INTO risk_pattern_rules(
			id, name, description, scope_type, scope_id, enabled, builtin_pack,
			engines_json, families_json, action, confirm_title, confirm_message,
			approval_provider, condition_json, priority, created_at_utc, updated_at_utc
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name,
			description = excluded.description,
			scope_type = excluded.scope_type,
			scope_id = excluded.scope_id,
			enabled = excluded.enabled,
			builtin_pack = excluded.builtin_pack,
			engines_json = excluded.engines_json,
			families_json = excluded.families_json,
			action = excluded.action,
			confirm_title = excluded.confirm_title,
			confirm_message = excluded.confirm_message,
			approval_provider = excluded.approval_provider,
			condition_json = excluded.condition_json,
			priority = excluded.priority,
			updated_at_utc = excluded.updated_at_utc`,
		r.ID, r.Name, r.Description, r.ScopeType, r.ScopeID, boolToInt(r.Enabled), r.BuiltinPack,
		string(enginesJSON), string(familiesJSON), string(r.Action), r.ConfirmTitle, r.ConfirmMessage,
		r.ApprovalProvider, string(condJSON), r.Priority, r.CreatedAtUTC, r.UpdatedAtUTC)
	if err != nil {
		if isUniqueErr(err) {
			return r, fmt.Errorf("%w: duplicate pattern rule %q in scope %s:%s", ErrConflict, r.Name, r.ScopeType, r.ScopeID)
		}
		return r, err
	}
	if err := s.appendAuditTx(ctx, tx, actor, action, r.ID, "", r, now); err != nil {
		return r, err
	}
	return r, nil
}

// DeleteRiskPatternRule removes a custom pattern rule and writes an audit record in the same tx.
func (s *Store) DeleteRiskPatternRule(ctx context.Context, actor, id string) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		res, err := s.txExec(ctx, tx, `DELETE FROM risk_pattern_rules WHERE id = ?`, id)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return ErrNotFound
		}
		return s.appendAuditTx(ctx, tx, actor, "risk_pattern.delete", id, "", map[string]any{"id": id}, nowUTC())
	})
}

// InstallBuiltinRulePack installs or updates all rules of a preset pack for the chosen scope atomically.
func (s *Store) InstallBuiltinRulePack(ctx context.Context, actor, packID, scopeType, scopeID string) ([]types.RiskPatternRule, error) {
	pack, ok := policy.GetBuiltinRulePack(packID)
	if !ok {
		return nil, fmt.Errorf("%w: unknown builtin rule pack %q", ErrNotFound, packID)
	}
	if scopeType == "" {
		scopeType = "global"
	}
	if scopeType == "global" {
		scopeID = "global"
	} else if strings.TrimSpace(scopeID) == "" {
		return nil, fmt.Errorf("scope_id is required for scope_type %q", scopeType)
	}

	now := nowUTC()
	var installed []types.RiskPatternRule
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		canonicalScopeID := scopeID
		if scopeType != "global" {
			canonicalScopeID = s.canonicalizeScopeIDTx(ctx, tx, scopeType, scopeID)
		}
		for _, tmpl := range pack.Rules {
			tmpl.ScopeType = scopeType
			tmpl.ScopeID = canonicalScopeID
			var existingID string
			err := s.txQueryRow(ctx, tx, `SELECT id FROM risk_pattern_rules WHERE scope_type = ? AND scope_id = ? AND name = ?`,
				scopeType, canonicalScopeID, tmpl.Name).Scan(&existingID)
			if err == nil {
				tmpl.ID = existingID
			} else if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			saved, err := s.upsertRiskPatternRuleTx(ctx, tx, actor, tmpl, now)
			if err != nil {
				return err
			}
			installed = append(installed, saved)
		}
		return s.appendAuditTx(ctx, tx, actor, "risk_pattern.pack_install", packID, "", map[string]any{
			"pack_id":    packID,
			"scope_type": scopeType,
			"scope_id":   canonicalScopeID,
			"rule_count": len(installed),
		}, now)
	})
	if err != nil {
		return nil, err
	}
	return installed, nil
}
