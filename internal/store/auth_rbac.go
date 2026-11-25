package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/x0c/agent-dbctl/internal/types"
)

// CountUsers returns the number of registered human users.
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var cnt int
	err := s.dbQueryRow(ctx, `SELECT COUNT(1) FROM users`).Scan(&cnt)
	return cnt, err
}

// CreateUser creates a new user and optionally writes an audit event in the same transaction.
func (s *Store) CreateUser(ctx context.Context, actor string, u types.User) (types.User, error) {
	u.Email = strings.ToLower(strings.TrimSpace(u.Email))
	if u.Email == "" {
		return u, fmt.Errorf("user email is required")
	}
	if u.ID == "" {
		u.ID = newID("usr")
	}
	if u.Status == "" {
		u.Status = "active"
	}
	now := nowUTC()
	if u.CreatedAtUTC == "" {
		u.CreatedAtUTC = now
	}
	u.UpdatedAtUTC = now

	err := s.withTx(ctx, func(tx *sql.Tx) error {
		_, err := s.txExec(ctx, tx, `
			INSERT INTO users(id, email, display_name, oidc_issuer, oidc_subject, password_hash, status, created_at_utc, updated_at_utc)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			u.ID, u.Email, u.DisplayName, u.OIDCIssuer, u.OIDCSubject, u.PasswordHash, u.Status, u.CreatedAtUTC, u.UpdatedAtUTC)
		if err != nil {
			if isUniqueErr(err) {
				return fmt.Errorf("%w: user email %q already exists", ErrConflict, u.Email)
			}
			return err
		}
		return s.appendAuditTx(ctx, tx, actor, "user.create", u.ID, "", map[string]any{
			"email":        u.Email,
			"display_name": u.DisplayName,
			"oidc_issuer":  u.OIDCIssuer,
			"status":       u.Status,
		}, now)
	})
	return u, err
}

// UpsertOIDCUser finds or creates a user matching (oidc_issuer, oidc_subject) or email.
func (s *Store) UpsertOIDCUser(ctx context.Context, issuer, subject, email, displayName string) (types.User, bool, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return types.User{}, false, fmt.Errorf("oidc user missing email claim")
	}
	var out types.User
	var created bool
	now := nowUTC()
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		row := s.txQueryRow(ctx, tx, `
			SELECT id, email, display_name, oidc_issuer, oidc_subject, password_hash, status, created_at_utc, updated_at_utc
			FROM users WHERE (oidc_issuer = ? AND oidc_subject = ?) OR email = ? LIMIT 1`, issuer, subject, email)
		u, err := scanUser(row)
		if errors.Is(err, ErrNotFound) {
			created = true
			u = types.User{
				ID:           newID("usr"),
				Email:        email,
				DisplayName:  displayName,
				OIDCIssuer:   issuer,
				OIDCSubject:  subject,
				Status:       "active",
				CreatedAtUTC: now,
				UpdatedAtUTC: now,
			}
			if _, err := s.txExec(ctx, tx, `
				INSERT INTO users(id, email, display_name, oidc_issuer, oidc_subject, password_hash, status, created_at_utc, updated_at_utc)
				VALUES (?, ?, ?, ?, ?, '', 'active', ?, ?)`,
				u.ID, u.Email, u.DisplayName, u.OIDCIssuer, u.OIDCSubject, u.CreatedAtUTC, u.UpdatedAtUTC); err != nil {
				return err
			}
			if err := s.appendAuditTx(ctx, tx, "user:"+u.Email, "user.oidc_provision", u.ID, "", map[string]any{
				"email":  u.Email,
				"issuer": issuer,
			}, now); err != nil {
				return err
			}
			out = u
			return nil
		}
		if err != nil {
			return err
		}
		if u.Status != "active" {
			return fmt.Errorf("user %q is disabled", u.Email)
		}
		if displayName != "" {
			u.DisplayName = displayName
		}
		u.OIDCIssuer = issuer
		u.OIDCSubject = subject
		u.UpdatedAtUTC = now
		if _, err := s.txExec(ctx, tx, `
			UPDATE users SET display_name = ?, oidc_issuer = ?, oidc_subject = ?, updated_at_utc = ? WHERE id = ?`,
			u.DisplayName, u.OIDCIssuer, u.OIDCSubject, u.UpdatedAtUTC, u.ID); err != nil {
			return err
		}
		out = u
		return nil
	})
	return out, created, err
}

// GetUserByID fetches a user by ID.
func (s *Store) GetUserByID(ctx context.Context, id string) (types.User, error) {
	return scanUser(s.dbQueryRow(ctx, `
		SELECT id, email, display_name, oidc_issuer, oidc_subject, password_hash, status, created_at_utc, updated_at_utc
		FROM users WHERE id = ?`, id))
}

// GetUserByEmail fetches a user by normalized email.
func (s *Store) GetUserByEmail(ctx context.Context, email string) (types.User, error) {
	return scanUser(s.dbQueryRow(ctx, `
		SELECT id, email, display_name, oidc_issuer, oidc_subject, password_hash, status, created_at_utc, updated_at_utc
		FROM users WHERE email = ?`, strings.ToLower(strings.TrimSpace(email))))
}

// ListUsers returns all users ordered by email.
func (s *Store) ListUsers(ctx context.Context) ([]types.User, error) {
	rows, err := s.dbQuery(ctx, `
		SELECT id, email, display_name, oidc_issuer, oidc_subject, password_hash, status, created_at_utc, updated_at_utc
		FROM users ORDER BY email ASC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []types.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// UpdateUserStatus updates a user's active/disabled status with an audit event.
func (s *Store) UpdateUserStatus(ctx context.Context, actor, id, status string) error {
	if status != "active" && status != "disabled" {
		return fmt.Errorf("invalid user status %q", status)
	}
	now := nowUTC()
	return s.withTx(ctx, func(tx *sql.Tx) error {
		res, err := s.txExec(ctx, tx, `UPDATE users SET status = ?, updated_at_utc = ? WHERE id = ?`, status, now, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return s.appendAuditTx(ctx, tx, actor, "user.status_update", id, "", map[string]any{"status": status}, now)
	})
}

func scanUser(r rowScanner) (types.User, error) {
	var u types.User
	err := r.Scan(&u.ID, &u.Email, &u.DisplayName, &u.OIDCIssuer, &u.OIDCSubject, &u.PasswordHash, &u.Status, &u.CreatedAtUTC, &u.UpdatedAtUTC)
	if errors.Is(err, sql.ErrNoRows) {
		return u, ErrNotFound
	}
	return u, err
}

// ListRoleBindings returns all role bindings, optionally filtered by user_id.
func (s *Store) ListRoleBindings(ctx context.Context, userID string) ([]types.RoleBinding, error) {
	q := `SELECT id, user_id, role, scope_type, scope_id, created_by, created_at_utc FROM role_bindings`
	var args []any
	if userID != "" {
		q += ` WHERE user_id = ?`
		args = append(args, userID)
	}
	q += ` ORDER BY created_at_utc ASC`
	rows, err := s.dbQuery(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []types.RoleBinding
	for rows.Next() {
		var b types.RoleBinding
		if err := rows.Scan(&b.ID, &b.UserID, &b.Role, &b.ScopeType, &b.ScopeID, &b.CreatedBy, &b.CreatedAtUTC); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// UpsertRoleBinding creates a role binding if not already present and writes an audit entry.
func (s *Store) UpsertRoleBinding(ctx context.Context, actor string, b types.RoleBinding) (types.RoleBinding, error) {
	if strings.TrimSpace(b.UserID) == "" || b.Role == "" || b.ScopeType == "" {
		return b, fmt.Errorf("user_id, role, and scope_type are required")
	}
	if b.ScopeType == types.ScopeGlobal {
		b.ScopeID = ""
	}
	if b.ID == "" {
		b.ID = newID("rb")
	}
	now := nowUTC()
	if b.CreatedAtUTC == "" {
		b.CreatedAtUTC = now
	}
	if b.CreatedBy == "" {
		b.CreatedBy = actor
	}
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		var existingID string
		err := s.txQueryRow(ctx, tx, `SELECT id FROM role_bindings WHERE user_id = ? AND role = ? AND scope_type = ? AND scope_id = ?`,
			b.UserID, string(b.Role), string(b.ScopeType), b.ScopeID).Scan(&existingID)
		if err == nil {
			b.ID = existingID
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if _, err := s.txExec(ctx, tx, `
			INSERT INTO role_bindings(id, user_id, role, scope_type, scope_id, created_by, created_at_utc)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			b.ID, b.UserID, string(b.Role), string(b.ScopeType), b.ScopeID, b.CreatedBy, b.CreatedAtUTC); err != nil {
			return err
		}
		return s.appendAuditTx(ctx, tx, actor, "role_binding.grant", b.UserID, "", b, now)
	})
	return b, err
}

// DeleteRoleBinding removes a role binding with an audit event.
func (s *Store) DeleteRoleBinding(ctx context.Context, actor, id string) error {
	now := nowUTC()
	return s.withTx(ctx, func(tx *sql.Tx) error {
		res, err := s.txExec(ctx, tx, `DELETE FROM role_bindings WHERE id = ?`, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return s.appendAuditTx(ctx, tx, actor, "role_binding.revoke", id, "", map[string]any{"id": id}, now)
	})
}

// CreateAPIToken stores a scoped agent API token hash in the same tx as its audit row.
func (s *Store) CreateAPIToken(ctx context.Context, actor string, tok types.APIToken) (types.APIToken, error) {
	if tok.UserID == "" || strings.TrimSpace(tok.Name) == "" || tok.TokenHash == "" {
		return tok, fmt.Errorf("user_id, name, and token_hash are required")
	}
	if tok.ID == "" {
		tok.ID = newID("tok")
	}
	if tok.PrincipalKind == "" {
		tok.PrincipalKind = types.PrincipalAgentToken
	}
	now := nowUTC()
	if tok.CreatedAtUTC == "" {
		tok.CreatedAtUTC = now
	}
	sysJSON, _ := json.Marshal(tok.AllowedSystems)
	envJSON, _ := json.Marshal(tok.AllowedEnvs)
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		_, err := s.txExec(ctx, tx, `
			INSERT INTO api_tokens(
				id, user_id, name, token_prefix, token_hash, principal_kind, role_ceiling,
				allowed_systems_json, allowed_envs_json, read_only_forced,
				expires_at_utc, last_used_at_utc, revoked_at_utc, created_at_utc
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', '', ?)`,
			tok.ID, tok.UserID, tok.Name, tok.TokenPrefix, tok.TokenHash, string(tok.PrincipalKind), string(tok.RoleCeiling),
			string(sysJSON), string(envJSON), boolToInt(tok.ReadOnlyForced), tok.ExpiresAtUTC, tok.CreatedAtUTC)
		if err != nil {
			if isUniqueErr(err) {
				return fmt.Errorf("%w: token %q already exists for user", ErrConflict, tok.Name)
			}
			return err
		}
		return s.appendAuditTx(ctx, tx, actor, "api_token.create", tok.ID, "", map[string]any{
			"name":             tok.Name,
			"user_id":          tok.UserID,
			"principal_kind":   tok.PrincipalKind,
			"role_ceiling":     tok.RoleCeiling,
			"allowed_systems":  tok.AllowedSystems,
			"allowed_envs":     tok.AllowedEnvs,
			"read_only_forced": tok.ReadOnlyForced,
			"expires_at_utc":   tok.ExpiresAtUTC,
		}, now)
	})
	return tok, err
}

// LookupAPITokenByHash loads an active, non-revoked API token and its owner User.
func (s *Store) LookupAPITokenByHash(ctx context.Context, tokenHash string) (types.APIToken, types.User, error) {
	row := s.dbQueryRow(ctx, `
		SELECT t.id, t.user_id, t.name, t.token_prefix, t.token_hash, t.principal_kind, t.role_ceiling,
			t.allowed_systems_json, t.allowed_envs_json, t.read_only_forced,
			t.expires_at_utc, t.last_used_at_utc, t.revoked_at_utc, t.created_at_utc,
			u.id, u.email, u.display_name, u.oidc_issuer, u.oidc_subject, u.password_hash, u.status, u.created_at_utc, u.updated_at_utc
		FROM api_tokens t
		JOIN users u ON u.id = t.user_id
		WHERE t.token_hash = ?`, tokenHash)
	var tok types.APIToken
	var u types.User
	var kindRaw, sysJSON, envJSON string
	var roInt int
	err := row.Scan(
		&tok.ID, &tok.UserID, &tok.Name, &tok.TokenPrefix, &tok.TokenHash, &kindRaw, &tok.RoleCeiling,
		&sysJSON, &envJSON, &roInt,
		&tok.ExpiresAtUTC, &tok.LastUsedAtUTC, &tok.RevokedAtUTC, &tok.CreatedAtUTC,
		&u.ID, &u.Email, &u.DisplayName, &u.OIDCIssuer, &u.OIDCSubject, &u.PasswordHash, &u.Status, &u.CreatedAtUTC, &u.UpdatedAtUTC,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return tok, u, ErrNotFound
	}
	if err != nil {
		return tok, u, err
	}
	tok.PrincipalKind = types.PrincipalKind(kindRaw)
	if tok.PrincipalKind == "" {
		tok.PrincipalKind = types.PrincipalAgentToken
	}
	tok.OwnerEmail = u.Email
	tok.ReadOnlyForced = roInt == 1
	_ = json.Unmarshal([]byte(sysJSON), &tok.AllowedSystems)
	_ = json.Unmarshal([]byte(envJSON), &tok.AllowedEnvs)
	return tok, u, nil
}

// TouchAPITokenLastUsed updates last_used_at_utc asynchronously without emitting noisy audit rows.
func (s *Store) TouchAPITokenLastUsed(ctx context.Context, tokenID string) {
	_, _ = s.dbExec(ctx, `UPDATE api_tokens SET last_used_at_utc = ? WHERE id = ?`, nowUTC(), tokenID)
}

// ListAPITokens lists tokens, optionally filtered by user_id.
func (s *Store) ListAPITokens(ctx context.Context, userID string) ([]types.APIToken, error) {
	q := `SELECT t.id, t.user_id, u.email, t.name, t.token_prefix, t.principal_kind, t.role_ceiling,
		t.allowed_systems_json, t.allowed_envs_json, t.read_only_forced,
		t.expires_at_utc, t.last_used_at_utc, t.revoked_at_utc, t.created_at_utc
	FROM api_tokens t JOIN users u ON u.id = t.user_id`
	var args []any
	if userID != "" {
		q += ` WHERE t.user_id = ?`
		args = append(args, userID)
	}
	q += ` ORDER BY t.created_at_utc DESC`
	rows, err := s.dbQuery(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []types.APIToken
	for rows.Next() {
		var tok types.APIToken
		var kindRaw, sysJSON, envJSON string
		var roInt int
		if err := rows.Scan(&tok.ID, &tok.UserID, &tok.OwnerEmail, &tok.Name, &tok.TokenPrefix, &kindRaw, &tok.RoleCeiling,
			&sysJSON, &envJSON, &roInt, &tok.ExpiresAtUTC, &tok.LastUsedAtUTC, &tok.RevokedAtUTC, &tok.CreatedAtUTC); err != nil {
			return nil, err
		}
		tok.PrincipalKind = types.PrincipalKind(kindRaw)
		if tok.PrincipalKind == "" {
			tok.PrincipalKind = types.PrincipalAgentToken
		}
		tok.ReadOnlyForced = roInt == 1
		_ = json.Unmarshal([]byte(sysJSON), &tok.AllowedSystems)
		_ = json.Unmarshal([]byte(envJSON), &tok.AllowedEnvs)
		out = append(out, tok)
	}
	return out, rows.Err()
}

// RevokeAPIToken revokes a token by ID or name (scoped to ownerUserID if non-empty).
func (s *Store) RevokeAPIToken(ctx context.Context, actor, idOrName, ownerUserID string) error {
	now := nowUTC()
	return s.withTx(ctx, func(tx *sql.Tx) error {
		q := `UPDATE api_tokens SET revoked_at_utc = ? WHERE (id = ? OR name = ?) AND revoked_at_utc = ''`
		args := []any{now, idOrName, idOrName}
		if ownerUserID != "" {
			q += ` AND user_id = ?`
			args = append(args, ownerUserID)
		}
		res, err := s.txExec(ctx, tx, q, args...)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return s.appendAuditTx(ctx, tx, actor, "api_token.revoke", idOrName, "", map[string]any{"revoked_at_utc": now}, now)
	})
}

// CreateWebSession persists an authenticated browser session across restarts/replicas.
func (s *Store) CreateWebSession(ctx context.Context, sess types.WebSession) error {
	now := nowUTC()
	if sess.CreatedAtUTC == "" {
		sess.CreatedAtUTC = now
	}
	_, err := s.dbExec(ctx, `
		INSERT INTO web_sessions(id_hash, user_id, csrf_token_hash, expires_at_utc, created_at_utc)
		VALUES (?, ?, ?, ?, ?)`,
		sess.IDHash, sess.UserID, sess.CSRFTokenHash, sess.ExpiresAtUTC, sess.CreatedAtUTC)
	return err
}

// GetWebSessionByHash loads a non-expired browser session and its User.
func (s *Store) GetWebSessionByHash(ctx context.Context, idHash string) (types.WebSession, types.User, error) {
	row := s.dbQueryRow(ctx, `
		SELECT s.id_hash, s.user_id, s.csrf_token_hash, s.expires_at_utc, s.created_at_utc,
			u.id, u.email, u.display_name, u.oidc_issuer, u.oidc_subject, u.password_hash, u.status, u.created_at_utc, u.updated_at_utc
		FROM web_sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.id_hash = ?`, idHash)
	var sess types.WebSession
	var u types.User
	err := row.Scan(
		&sess.IDHash, &sess.UserID, &sess.CSRFTokenHash, &sess.ExpiresAtUTC, &sess.CreatedAtUTC,
		&u.ID, &u.Email, &u.DisplayName, &u.OIDCIssuer, &u.OIDCSubject, &u.PasswordHash, &u.Status, &u.CreatedAtUTC, &u.UpdatedAtUTC,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return sess, u, ErrNotFound
	}
	if err != nil {
		return sess, u, err
	}
	if exp, ok := parseUTCTime(sess.ExpiresAtUTC); !ok || time.Now().UTC().After(exp) {
		_, _ = s.dbExec(ctx, `DELETE FROM web_sessions WHERE id_hash = ?`, idHash)
		return sess, u, ErrNotFound
	}
	return sess, u, nil
}

// DeleteWebSession revokes a browser session.
func (s *Store) DeleteWebSession(ctx context.Context, idHash string) error {
	_, err := s.dbExec(ctx, `DELETE FROM web_sessions WHERE id_hash = ?`, idHash)
	return err
}

// CreateOIDCAuthState stores ephemeral PKCE + return_to state for OIDC logins.
func (s *Store) CreateOIDCAuthState(ctx context.Context, st types.OIDCAuthState) error {
	now := nowUTC()
	if st.CreatedAtUTC == "" {
		st.CreatedAtUTC = now
	}
	_, _ = s.dbExec(ctx, `DELETE FROM oidc_auth_states WHERE expires_at_utc < ?`, now)
	_, err := s.dbExec(ctx, `
		INSERT INTO oidc_auth_states(state_hash, nonce, pkce_verifier, return_to, expires_at_utc, created_at_utc)
		VALUES (?, ?, ?, ?, ?, ?)`,
		st.StateHash, st.Nonce, st.PKCEVerifier, st.ReturnTo, st.ExpiresAtUTC, st.CreatedAtUTC)
	return err
}

// ConsumeOIDCAuthState atomically pops and validates a non-expired OIDC state row.
func (s *Store) ConsumeOIDCAuthState(ctx context.Context, stateHash string) (types.OIDCAuthState, error) {
	var st types.OIDCAuthState
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		q := `SELECT state_hash, nonce, pkce_verifier, return_to, expires_at_utc, created_at_utc
			FROM oidc_auth_states WHERE state_hash = ?`
		if s.isPG() {
			q += ` FOR UPDATE`
		}
		row := s.txQueryRow(ctx, tx, q, stateHash)
		err := row.Scan(&st.StateHash, &st.Nonce, &st.PKCEVerifier, &st.ReturnTo, &st.ExpiresAtUTC, &st.CreatedAtUTC)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		delRes, delErr := s.txExec(ctx, tx, `DELETE FROM oidc_auth_states WHERE state_hash = ?`, stateHash)
		if delErr != nil {
			return delErr
		}
		if n, _ := delRes.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		if exp, ok := parseUTCTime(st.ExpiresAtUTC); !ok || time.Now().UTC().After(exp) {
			return ErrNotFound
		}
		return nil
	})
	return st, err
}

// CreateCLIDeviceCode persists an ephemeral CLI browser confirmation request.
func (s *Store) CreateCLIDeviceCode(ctx context.Context, dc types.CLIDeviceCode) error {
	now := nowUTC()
	if dc.CreatedAtUTC == "" {
		dc.CreatedAtUTC = now
	}
	if dc.Status == "" {
		dc.Status = "pending"
	}
	_, _ = s.dbExec(ctx, `DELETE FROM cli_device_codes WHERE expires_at_utc < ?`, now)
	_, err := s.dbExec(ctx, `
		INSERT INTO cli_device_codes(device_code_hash, user_code, status, user_id, expires_at_utc, created_at_utc)
		VALUES (?, ?, ?, ?, ?, ?)`,
		dc.DeviceCodeHash, strings.ToUpper(strings.TrimSpace(dc.UserCode)), dc.Status, dc.UserID, dc.ExpiresAtUTC, dc.CreatedAtUTC)
	return err
}

// DecideCLIDeviceCode marks a pending CLI device code approved or rejected by an authenticated Web user.
func (s *Store) DecideCLIDeviceCode(ctx context.Context, actor, userCode, userID string, approve bool) (types.CLIDeviceCode, error) {
	norm := strings.ToUpper(strings.TrimSpace(userCode))
	if norm == "" {
		return types.CLIDeviceCode{}, fmt.Errorf("user_code is required")
	}
	var out types.CLIDeviceCode
	now := nowUTC()
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		row := s.txQueryRow(ctx, tx, `
			SELECT device_code_hash, user_code, status, user_id, expires_at_utc, created_at_utc
			FROM cli_device_codes WHERE user_code = ?`, norm)
		if err := row.Scan(&out.DeviceCodeHash, &out.UserCode, &out.Status, &out.UserID, &out.ExpiresAtUTC, &out.CreatedAtUTC); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("%w: confirmation code not found", ErrNotFound)
			}
			return err
		}
		if exp, ok := parseUTCTime(out.ExpiresAtUTC); !ok || time.Now().UTC().After(exp) {
			return fmt.Errorf("%w: confirmation code has expired", ErrConflict)
		}
		if out.Status != "pending" {
			return fmt.Errorf("%w: confirmation code already processed (%s)", ErrConflict, out.Status)
		}
		nextStatus := "rejected"
		if approve {
			nextStatus = "approved"
		}
		if _, err := s.txExec(ctx, tx, `
			UPDATE cli_device_codes SET status = ?, user_id = ? WHERE device_code_hash = ?`,
			nextStatus, userID, out.DeviceCodeHash); err != nil {
			return err
		}
		out.Status = nextStatus
		out.UserID = userID
		return s.appendAuditTx(ctx, tx, actor, "auth.device_decide", out.UserCode, "", map[string]any{
			"decision": nextStatus,
			"user_id":  userID,
		}, now)
	})
	return out, err
}

// PollCLIDeviceCode inspects a pending/decided CLI device code and consumes approved/rejected entries atomically.
func (s *Store) PollCLIDeviceCode(ctx context.Context, deviceCodeHash string) (status string, userID string, err error) {
	err = s.withTx(ctx, func(tx *sql.Tx) error {
		var dc types.CLIDeviceCode
		row := s.txQueryRow(ctx, tx, `
			SELECT device_code_hash, user_code, status, user_id, expires_at_utc, created_at_utc
			FROM cli_device_codes WHERE device_code_hash = ?`, deviceCodeHash)
		scanErr := row.Scan(&dc.DeviceCodeHash, &dc.UserCode, &dc.Status, &dc.UserID, &dc.ExpiresAtUTC, &dc.CreatedAtUTC)
		if errors.Is(scanErr, sql.ErrNoRows) {
			status = "expired"
			return nil
		}
		if scanErr != nil {
			return scanErr
		}
		if exp, ok := parseUTCTime(dc.ExpiresAtUTC); !ok || time.Now().UTC().After(exp) {
			_, _ = s.txExec(ctx, tx, `DELETE FROM cli_device_codes WHERE device_code_hash = ?`, deviceCodeHash)
			status = "expired"
			return nil
		}
		switch dc.Status {
		case "pending":
			status = "pending"
		case "rejected":
			_, _ = s.txExec(ctx, tx, `DELETE FROM cli_device_codes WHERE device_code_hash = ?`, deviceCodeHash)
			status = "denied"
		case "approved":
			res, uErr := s.txExec(ctx, tx, `DELETE FROM cli_device_codes WHERE device_code_hash = ? AND status = 'approved'`, deviceCodeHash)
			if uErr != nil {
				return uErr
			}
			n, _ := res.RowsAffected()
			if n != 1 {
				status = "expired"
				return nil
			}
			status = "approved"
			userID = dc.UserID
		default:
			status = "expired"
		}
		return nil
	})
	return status, userID, err
}

// GetEncryptedSecret implements secrets.EnvelopeRecordStore.
func (s *Store) GetEncryptedSecret(ctx context.Context, key string) (types.EncryptedSecretRecord, error) {
	var rec types.EncryptedSecretRecord
	err := s.dbQueryRow(ctx, `
		SELECT secret_key, key_version, nonce, ciphertext, updated_at_utc
		FROM encrypted_secrets WHERE secret_key = ?`, key).
		Scan(&rec.Key, &rec.KeyVersion, &rec.Nonce, &rec.Ciphertext, &rec.UpdatedAtUTC)
	if errors.Is(err, sql.ErrNoRows) {
		return rec, ErrNotFound
	}
	return rec, err
}

// PutEncryptedSecret implements secrets.EnvelopeRecordStore.
func (s *Store) PutEncryptedSecret(ctx context.Context, rec types.EncryptedSecretRecord) error {
	if rec.UpdatedAtUTC == "" {
		rec.UpdatedAtUTC = nowUTC()
	}
	_, err := s.dbExec(ctx, `
		INSERT INTO encrypted_secrets(secret_key, key_version, nonce, ciphertext, updated_at_utc)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(secret_key) DO UPDATE SET
			key_version = excluded.key_version,
			nonce = excluded.nonce,
			ciphertext = excluded.ciphertext,
			updated_at_utc = excluded.updated_at_utc`,
		rec.Key, rec.KeyVersion, rec.Nonce, rec.Ciphertext, rec.UpdatedAtUTC)
	return err
}

// DeleteEncryptedSecret implements secrets.EnvelopeRecordStore.
func (s *Store) DeleteEncryptedSecret(ctx context.Context, key string) error {
	_, err := s.dbExec(ctx, `DELETE FROM encrypted_secrets WHERE secret_key = ?`, key)
	return err
}

// HasEncryptedSecret implements secrets.EnvelopeRecordStore.
func (s *Store) HasEncryptedSecret(ctx context.Context, key string) (bool, error) {
	var cnt int
	err := s.dbQueryRow(ctx, `SELECT COUNT(1) FROM encrypted_secrets WHERE secret_key = ?`, key).Scan(&cnt)
	return cnt > 0, err
}

// CheckAndStoreWebhookNonce rejects replayed webhook callback event IDs atomically.
func (s *Store) CheckAndStoreWebhookNonce(ctx context.Context, provider, eventID, expiresAtUTC string) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		_, _ = s.txExec(ctx, tx, `DELETE FROM webhook_callback_nonces WHERE expires_at_utc < ?`, nowUTC())
		_, err := s.txExec(ctx, tx, `
			INSERT INTO webhook_callback_nonces(provider, event_id, expires_at_utc) VALUES (?, ?, ?)`,
			provider, eventID, expiresAtUTC)
		if err != nil && isUniqueErr(err) {
			return fmt.Errorf("%w: replayed webhook event %q", ErrConflict, eventID)
		}
		return err
	})
}

// TryClaimWaitingOperation atomically transitions waiting_approval -> running for a specific node lease.
func (s *Store) TryClaimWaitingOperation(ctx context.Context, opID, nodeID string, leaseTTL time.Duration) (bool, error) {
	now := nowUTC()
	leaseUntil := time.Now().UTC().Add(leaseTTL).Format(time.RFC3339Nano)
	res, err := s.dbExec(ctx, `
		UPDATE operations
		SET status = 'running', owner_node_id = ?, lease_expires_at_utc = ?, updated_at_utc = ?
		WHERE id = ? AND status = 'waiting_approval'`,
		nodeID, leaseUntil, now, opID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// RenewOperationLease extends an active execution lease and reports whether remote cancel was requested.
func (s *Store) RenewOperationLease(ctx context.Context, opID, nodeID string, leaseTTL time.Duration) (cancelRequested bool, err error) {
	now := nowUTC()
	leaseUntil := time.Now().UTC().Add(leaseTTL).Format(time.RFC3339Nano)
	_, err = s.dbExec(ctx, `
		UPDATE operations SET lease_expires_at_utc = ?, updated_at_utc = ?
		WHERE id = ? AND owner_node_id = ? AND status = 'running'`,
		leaseUntil, now, opID, nodeID)
	if err != nil {
		return false, err
	}
	var cancelAt string
	if qErr := s.dbQueryRow(ctx, `SELECT cancel_requested_at_utc FROM operations WHERE id = ?`, opID).Scan(&cancelAt); qErr == nil {
		return strings.TrimSpace(cancelAt) != "", nil
	}
	return false, nil
}

// RequestOperationCancel marks cancel_requested_at_utc so the owning node can cancel a running query across replicas.
func (s *Store) RequestOperationCancel(ctx context.Context, opID string) error {
	now := nowUTC()
	_, err := s.dbExec(ctx, `
		UPDATE operations SET cancel_requested_at_utc = ?, updated_at_utc = ?
		WHERE id = ? AND cancel_requested_at_utc = ''`, now, now, opID)
	return err
}

// PutOperationResult stores a serialized ExecResult in the shared DB fallback table for multi-replica mode.
func (s *Store) PutOperationResult(ctx context.Context, opID string, raw []byte, expiresAtUTC string) error {
	_, err := s.dbExec(ctx, `
		INSERT INTO operation_results(operation_id, result_json, expires_at_utc)
		VALUES (?, ?, ?)
		ON CONFLICT(operation_id) DO UPDATE SET
			result_json = excluded.result_json,
			expires_at_utc = excluded.expires_at_utc`,
		opID, raw, expiresAtUTC)
	return err
}

// GetOperationResult fetches a serialized ExecResult from the shared DB fallback table if unexpired.
func (s *Store) GetOperationResult(ctx context.Context, opID string) ([]byte, bool, error) {
	var raw []byte
	var expStr string
	err := s.dbQueryRow(ctx, `SELECT result_json, expires_at_utc FROM operation_results WHERE operation_id = ?`, opID).Scan(&raw, &expStr)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if exp, ok := parseUTCTime(expStr); !ok || time.Now().UTC().After(exp) {
		_, _ = s.dbExec(ctx, `DELETE FROM operation_results WHERE operation_id = ?`, opID)
		return nil, false, nil
	}
	return raw, true, nil
}

// PurgeExpiredOperationResults removes expired cached results from operation_results.
func (s *Store) PurgeExpiredOperationResults(ctx context.Context) error {
	_, err := s.dbExec(ctx, `DELETE FROM operation_results WHERE expires_at_utc < ?`, nowUTC())
	return err
}
