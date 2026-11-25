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

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
)

// ListSystems returns all business systems ordered by slug.
func (s *Store) ListSystems(ctx context.Context) ([]types.System, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, slug, name, owner, description, tags_json, workspace_paths_json, default_policy_id, created_at_utc, updated_at_utc
		FROM systems ORDER BY slug ASC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []types.System
	for rows.Next() {
		var sys types.System
		var tagsJSON, wsJSON string
		if err := rows.Scan(&sys.ID, &sys.Slug, &sys.Name, &sys.Owner, &sys.Description, &tagsJSON, &wsJSON, &sys.DefaultPolicyID, &sys.CreatedAtUTC, &sys.UpdatedAtUTC); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(tagsJSON), &sys.Tags)
		_ = json.Unmarshal([]byte(wsJSON), &sys.WorkspacePaths)
		if sys.Tags == nil {
			sys.Tags = []string{}
		}
		if sys.WorkspacePaths == nil {
			sys.WorkspacePaths = []string{}
		}
		out = append(out, sys)
	}
	return out, rows.Err()
}

// UpsertSystem creates or updates a System and records an audit entry in the same transaction.
func (s *Store) UpsertSystem(ctx context.Context, actor string, sys types.System) (types.System, error) {
	now := nowUTC()
	var saved types.System
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		var err error
		saved, err = s.upsertSystemTx(ctx, tx, actor, sys, now)
		return err
	})
	if err != nil {
		return sys, err
	}
	return saved, nil
}

func (s *Store) upsertSystemTx(ctx context.Context, tx *sql.Tx, actor string, sys types.System, now string) (types.System, error) {
	if strings.TrimSpace(sys.Slug) == "" || strings.TrimSpace(sys.Name) == "" {
		return sys, fmt.Errorf("system slug and name are required")
	}
	if sys.ID == "" {
		sys.ID = newID("sys")
	}
	if sys.Tags == nil {
		sys.Tags = []string{}
	}
	if sys.WorkspacePaths == nil {
		sys.WorkspacePaths = []string{}
	}
	tagsJSON, _ := json.Marshal(sys.Tags)
	wsJSON, _ := json.Marshal(sys.WorkspacePaths)

	var existingCreated string
	err := tx.QueryRowContext(ctx, `SELECT created_at_utc FROM systems WHERE id = ?`, sys.ID).Scan(&existingCreated)
	action := "system.create"
	if err == nil {
		action = "system.update"
		sys.CreatedAtUTC = existingCreated
	} else if errors.Is(err, sql.ErrNoRows) {
		sys.CreatedAtUTC = now
	} else {
		return sys, err
	}
	if err := requirePolicyExistsTx(ctx, tx, sys.DefaultPolicyID); err != nil {
		return sys, err
	}
	sys.UpdatedAtUTC = now
	_, err = tx.ExecContext(ctx, `
		INSERT INTO systems(id, slug, name, owner, description, tags_json, workspace_paths_json, default_policy_id, created_at_utc, updated_at_utc)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			slug = excluded.slug,
			name = excluded.name,
			owner = excluded.owner,
			description = excluded.description,
			tags_json = excluded.tags_json,
			workspace_paths_json = excluded.workspace_paths_json,
			default_policy_id = excluded.default_policy_id,
			updated_at_utc = excluded.updated_at_utc`,
		sys.ID, sys.Slug, sys.Name, sys.Owner, sys.Description, string(tagsJSON), string(wsJSON), sys.DefaultPolicyID, sys.CreatedAtUTC, sys.UpdatedAtUTC)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return sys, fmt.Errorf("%w: duplicate system slug %q", ErrConflict, sys.Slug)
		}
		return sys, err
	}
	if err := s.appendAuditTx(ctx, tx, actor, action, sys.ID, "", sys, now); err != nil {
		return sys, err
	}
	return sys, nil
}

// DeleteSystem removes a system if no targets depend on it, and cleans up unreferenced scoped policies/patterns.
func (s *Store) DeleteSystem(ctx context.Context, actor, id string) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		var slug string
		_ = tx.QueryRowContext(ctx, `SELECT slug FROM systems WHERE id = ?`, id).Scan(&slug)
		res, err := tx.ExecContext(ctx, `DELETE FROM systems WHERE id = ?`, id)
		if err != nil {
			return fmt.Errorf("%w: cannot delete system %s in use: %v", ErrConflict, id, err)
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return ErrNotFound
		}
		now := nowUTC()
		if err := s.cleanupScopedPoliciesAndRulesTx(ctx, tx, actor, "system", id, slug, now); err != nil {
			return err
		}
		return s.appendAuditTx(ctx, tx, actor, "system.delete", id, "", map[string]any{"id": id}, now)
	})
}

// ListEnvironments returns all environments ordered by sort_order.
func (s *Store) ListEnvironments(ctx context.Context) ([]types.Environment, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT code, safety_tier, labels_json, color, sort_order, default_policy_id, created_at_utc, updated_at_utc
		FROM environments ORDER BY sort_order ASC, code ASC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []types.Environment
	for rows.Next() {
		var env types.Environment
		var labelsJSON string
		if err := rows.Scan(&env.Code, &env.SafetyTier, &labelsJSON, &env.Color, &env.SortOrder, &env.DefaultPolicyID, &env.CreatedAtUTC, &env.UpdatedAtUTC); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(labelsJSON), &env.Labels)
		if env.Labels == nil {
			env.Labels = map[string]string{"en": env.Code}
		}
		out = append(out, env)
	}
	return out, rows.Err()
}

// UpsertEnvironment creates or updates an Environment and records an audit entry.
func (s *Store) UpsertEnvironment(ctx context.Context, actor string, env types.Environment) (types.Environment, error) {
	now := nowUTC()
	var saved types.Environment
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		var err error
		saved, err = s.upsertEnvironmentTx(ctx, tx, actor, env, now)
		return err
	})
	if err != nil {
		return env, err
	}
	return saved, nil
}

func (s *Store) upsertEnvironmentTx(ctx context.Context, tx *sql.Tx, actor string, env types.Environment, now string) (types.Environment, error) {
	if strings.TrimSpace(env.Code) == "" {
		return env, fmt.Errorf("environment code is required")
	}
	if env.SafetyTier == "" {
		env.SafetyTier = types.SafetyTierGuarded
	}
	if len(env.Labels) == 0 {
		env.Labels = map[string]string{"en": env.Code}
	}
	if env.Color == "" {
		env.Color = "#6B7280"
	}
	labelsJSON, _ := json.Marshal(env.Labels)

	var existingCreated string
	err := tx.QueryRowContext(ctx, `SELECT created_at_utc FROM environments WHERE code = ?`, env.Code).Scan(&existingCreated)
	action := "environment.create"
	if err == nil {
		action = "environment.update"
		env.CreatedAtUTC = existingCreated
	} else if errors.Is(err, sql.ErrNoRows) {
		env.CreatedAtUTC = now
	} else {
		return env, err
	}
	if err := requirePolicyExistsTx(ctx, tx, env.DefaultPolicyID); err != nil {
		return env, err
	}
	env.UpdatedAtUTC = now
	_, err = tx.ExecContext(ctx, `
		INSERT INTO environments(code, safety_tier, labels_json, color, sort_order, default_policy_id, created_at_utc, updated_at_utc)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(code) DO UPDATE SET
			safety_tier = excluded.safety_tier,
			labels_json = excluded.labels_json,
			color = excluded.color,
			sort_order = excluded.sort_order,
			default_policy_id = excluded.default_policy_id,
			updated_at_utc = excluded.updated_at_utc`,
		env.Code, string(env.SafetyTier), string(labelsJSON), env.Color, env.SortOrder, env.DefaultPolicyID, env.CreatedAtUTC, env.UpdatedAtUTC)
	if err != nil {
		return env, err
	}
	if err := s.appendAuditTx(ctx, tx, actor, action, env.Code, "", env, now); err != nil {
		return env, err
	}
	return env, nil
}

// ListNetworkProfiles returns all reusable network profiles.
func (s *Store) ListNetworkProfiles(ctx context.Context) ([]types.NetworkProfile, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, mode, proxy_url, bastion_host, bastion_port, bastion_user, bastion_credential_id, ssh_strict_host_key, tls_mode, created_at_utc, updated_at_utc
		FROM network_profiles ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []types.NetworkProfile
	for rows.Next() {
		var np types.NetworkProfile
		var strict int
		if err := rows.Scan(&np.ID, &np.Name, &np.Mode, &np.ProxyURL, &np.BastionHost, &np.BastionPort, &np.BastionUser, &np.BastionCredentialID, &strict, &np.TLSMode, &np.CreatedAtUTC, &np.UpdatedAtUTC); err != nil {
			return nil, err
		}
		np.SSHStrictHostKey = strict == 1
		out = append(out, np)
	}
	return out, rows.Err()
}

// UpsertNetworkProfile saves a network profile in the same transaction as its audit row.
func (s *Store) UpsertNetworkProfile(ctx context.Context, actor string, np types.NetworkProfile) (types.NetworkProfile, error) {
	now := nowUTC()
	var saved types.NetworkProfile
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		var err error
		saved, err = s.upsertNetworkProfileTx(ctx, tx, actor, np, now)
		return err
	})
	if err != nil {
		return np, err
	}
	return saved, nil
}

func (s *Store) upsertNetworkProfileTx(ctx context.Context, tx *sql.Tx, actor string, np types.NetworkProfile, now string) (types.NetworkProfile, error) {
	if strings.TrimSpace(np.Name) == "" {
		return np, fmt.Errorf("network profile name is required")
	}
	if np.Mode == "" {
		np.Mode = types.NetworkDirect
	}
	if np.BastionPort == 0 && np.Mode == types.NetworkSSHTunnel {
		np.BastionPort = 22
	}
	if np.ID == "" {
		np.ID = newID("net")
	}
	strictInt := 0
	if np.SSHStrictHostKey {
		strictInt = 1
	}

	var existingCreated string
	err := tx.QueryRowContext(ctx, `SELECT created_at_utc FROM network_profiles WHERE id = ?`, np.ID).Scan(&existingCreated)
	action := "network_profile.create"
	if err == nil {
		action = "network_profile.update"
		np.CreatedAtUTC = existingCreated
	} else if errors.Is(err, sql.ErrNoRows) {
		np.CreatedAtUTC = now
	} else {
		return np, err
	}
	if err := requireCredentialExistsTx(ctx, tx, np.BastionCredentialID); err != nil {
		return np, err
	}
	np.UpdatedAtUTC = now
	_, err = tx.ExecContext(ctx, `
		INSERT INTO network_profiles(id, name, mode, proxy_url, bastion_host, bastion_port, bastion_user, bastion_credential_id, ssh_strict_host_key, tls_mode, created_at_utc, updated_at_utc)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name,
			mode = excluded.mode,
			proxy_url = excluded.proxy_url,
			bastion_host = excluded.bastion_host,
			bastion_port = excluded.bastion_port,
			bastion_user = excluded.bastion_user,
			bastion_credential_id = excluded.bastion_credential_id,
			ssh_strict_host_key = excluded.ssh_strict_host_key,
			tls_mode = excluded.tls_mode,
			updated_at_utc = excluded.updated_at_utc`,
		np.ID, np.Name, string(np.Mode), np.ProxyURL, np.BastionHost, np.BastionPort, np.BastionUser, np.BastionCredentialID, strictInt, np.TLSMode, np.CreatedAtUTC, np.UpdatedAtUTC)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return np, fmt.Errorf("%w: duplicate network profile name %q", ErrConflict, np.Name)
		}
		return np, err
	}
	if err := s.appendAuditTx(ctx, tx, actor, action, np.ID, "", np, now); err != nil {
		return np, err
	}
	return np, nil
}

// DeleteNetworkProfile removes a network profile if no instances reference it.
func (s *Store) DeleteNetworkProfile(ctx context.Context, actor, id string) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		var refCount int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM instances WHERE network_profile_id = ?`, id).Scan(&refCount); err != nil {
			return err
		}
		if refCount > 0 {
			return fmt.Errorf("%w: cannot delete network profile %s referenced by %d instance(s)", ErrConflict, id, refCount)
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM network_profiles WHERE id = ?`, id)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return ErrNotFound
		}
		return s.appendAuditTx(ctx, tx, actor, "network_profile.delete", id, "", map[string]any{"id": id}, nowUTC())
	})
}

// ListCredentialProfiles lists secret-free credential metadata.
func (s *Store) ListCredentialProfiles(ctx context.Context) ([]types.CredentialProfile, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, kind, access_level, username, env_var_name, exec_command, created_at_utc, updated_at_utc
		FROM credential_profiles ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []types.CredentialProfile
	for rows.Next() {
		var cp types.CredentialProfile
		if err := rows.Scan(&cp.ID, &cp.Name, &cp.Kind, &cp.AccessLevel, &cp.Username, &cp.EnvVarName, &cp.ExecCommand, &cp.CreatedAtUTC, &cp.UpdatedAtUTC); err != nil {
			return nil, err
		}
		out = append(out, cp)
	}
	return out, rows.Err()
}

// UpsertCredentialProfile stores credential metadata (never raw secrets).
func (s *Store) UpsertCredentialProfile(ctx context.Context, actor string, cp types.CredentialProfile) (types.CredentialProfile, error) {
	now := nowUTC()
	var saved types.CredentialProfile
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		var err error
		saved, err = s.upsertCredentialProfileTx(ctx, tx, actor, cp, now)
		return err
	})
	if err != nil {
		return cp, err
	}
	return saved, nil
}

func (s *Store) upsertCredentialProfileTx(ctx context.Context, tx *sql.Tx, actor string, cp types.CredentialProfile, now string) (types.CredentialProfile, error) {
	if strings.TrimSpace(cp.Name) == "" {
		return cp, fmt.Errorf("credential name is required")
	}
	if cp.Kind == "" {
		cp.Kind = types.CredKeychain
	}
	if cp.AccessLevel == "" {
		cp.AccessLevel = types.AccessReadOnly
	}
	if cp.ID == "" {
		cp.ID = newID("cred")
	}

	var existingCreated string
	err := tx.QueryRowContext(ctx, `SELECT created_at_utc FROM credential_profiles WHERE id = ?`, cp.ID).Scan(&existingCreated)
	action := "credential_profile.create"
	if err == nil {
		action = "credential_profile.update"
		cp.CreatedAtUTC = existingCreated
	} else if errors.Is(err, sql.ErrNoRows) {
		cp.CreatedAtUTC = now
	} else {
		return cp, err
	}
	cp.UpdatedAtUTC = now
	_, err = tx.ExecContext(ctx, `
		INSERT INTO credential_profiles(id, name, kind, access_level, username, env_var_name, exec_command, created_at_utc, updated_at_utc)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name,
			kind = excluded.kind,
			access_level = excluded.access_level,
			username = excluded.username,
			env_var_name = excluded.env_var_name,
			exec_command = excluded.exec_command,
			updated_at_utc = excluded.updated_at_utc`,
		cp.ID, cp.Name, string(cp.Kind), string(cp.AccessLevel), cp.Username, cp.EnvVarName, cp.ExecCommand, cp.CreatedAtUTC, cp.UpdatedAtUTC)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return cp, fmt.Errorf("%w: duplicate credential name %q", ErrConflict, cp.Name)
		}
		return cp, err
	}
	if err := s.appendAuditTx(ctx, tx, actor, action, cp.ID, "", cp, now); err != nil {
		return cp, err
	}
	return cp, nil
}

// DeleteCredentialProfile removes a credential profile if no target or bastion references it.
func (s *Store) DeleteCredentialProfile(ctx context.Context, actor, id string) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		var tgtCount, netCount int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM targets WHERE ro_credential_id = ? OR rw_credential_id = ?`, id, id).Scan(&tgtCount); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM network_profiles WHERE bastion_credential_id = ?`, id).Scan(&netCount); err != nil {
			return err
		}
		if tgtCount > 0 || netCount > 0 {
			return fmt.Errorf("%w: cannot delete credential profile %s in use (targets=%d, networks=%d)", ErrConflict, id, tgtCount, netCount)
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM credential_profiles WHERE id = ?`, id)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return ErrNotFound
		}
		return s.appendAuditTx(ctx, tx, actor, "credential_profile.delete", id, "", map[string]any{"id": id}, nowUTC())
	})
}

// ListInstances returns all database instances.
func (s *Store) ListInstances(ctx context.Context) ([]types.Instance, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, engine, host, port, role, primary_instance_id, network_profile_id, tls_mode, params_json, capabilities_json, capabilities_detected_at_utc, created_at_utc, updated_at_utc
		FROM instances ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []types.Instance
	for rows.Next() {
		var inst types.Instance
		var paramsJSON, capsJSON string
		if err := rows.Scan(&inst.ID, &inst.Name, &inst.Engine, &inst.Host, &inst.Port, &inst.Role, &inst.PrimaryInstanceID, &inst.NetworkProfileID, &inst.TLSMode, &paramsJSON, &capsJSON, &inst.CapabilitiesDetectedAt, &inst.CreatedAtUTC, &inst.UpdatedAtUTC); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(paramsJSON), &inst.Params)
		if inst.Params == nil {
			inst.Params = map[string]string{}
		}
		inst.Capabilities = unmarshalServerCapabilities(capsJSON, inst.CapabilitiesDetectedAt)
		out = append(out, inst)
	}
	return out, rows.Err()
}

// GetInstance returns a single instance by ID.
func (s *Store) GetInstance(ctx context.Context, id string) (types.Instance, error) {
	var inst types.Instance
	var paramsJSON, capsJSON string
	err := s.db.QueryRowContext(ctx, `
		SELECT id, name, engine, host, port, role, primary_instance_id, network_profile_id, tls_mode, params_json, capabilities_json, capabilities_detected_at_utc, created_at_utc, updated_at_utc
		FROM instances WHERE id = ?`, id).
		Scan(&inst.ID, &inst.Name, &inst.Engine, &inst.Host, &inst.Port, &inst.Role, &inst.PrimaryInstanceID, &inst.NetworkProfileID, &inst.TLSMode, &paramsJSON, &capsJSON, &inst.CapabilitiesDetectedAt, &inst.CreatedAtUTC, &inst.UpdatedAtUTC)
	if errors.Is(err, sql.ErrNoRows) {
		return inst, ErrNotFound
	}
	if err != nil {
		return inst, err
	}
	_ = json.Unmarshal([]byte(paramsJSON), &inst.Params)
	if inst.Params == nil {
		inst.Params = map[string]string{}
	}
	inst.Capabilities = unmarshalServerCapabilities(capsJSON, inst.CapabilitiesDetectedAt)
	return inst, nil
}

// UpsertInstance saves an instance and writes an audit entry.
func (s *Store) UpsertInstance(ctx context.Context, actor string, inst types.Instance) (types.Instance, error) {
	now := nowUTC()
	var saved types.Instance
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		var err error
		saved, err = s.upsertInstanceTx(ctx, tx, actor, inst, now)
		return err
	})
	if err != nil {
		return inst, err
	}
	return saved, nil
}

func (s *Store) upsertInstanceTx(ctx context.Context, tx *sql.Tx, actor string, inst types.Instance, now string) (types.Instance, error) {
	if strings.TrimSpace(inst.Name) == "" || strings.TrimSpace(inst.Engine) == "" {
		return inst, fmt.Errorf("instance name and engine are required")
	}
	if inst.Role == "" {
		inst.Role = types.RoleStandalone
	}
	if inst.Params == nil {
		inst.Params = map[string]string{}
	}
	if inst.ID == "" {
		inst.ID = newID("inst")
	}
	paramsJSON, _ := json.Marshal(inst.Params)

	var existingCreated, existingCapsJSON, existingCapsAt string
	err := tx.QueryRowContext(ctx, `SELECT created_at_utc, capabilities_json, capabilities_detected_at_utc FROM instances WHERE id = ?`, inst.ID).
		Scan(&existingCreated, &existingCapsJSON, &existingCapsAt)
	action := "instance.create"
	if err == nil {
		action = "instance.update"
		inst.CreatedAtUTC = existingCreated
	} else if errors.Is(err, sql.ErrNoRows) {
		inst.CreatedAtUTC = now
		existingCapsJSON = "{}"
	} else {
		return inst, err
	}
	if inst.NetworkProfileID != "" {
		var cnt int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM network_profiles WHERE id = ?`, inst.NetworkProfileID).Scan(&cnt); err != nil {
			return inst, err
		}
		if cnt == 0 {
			return inst, fmt.Errorf("%w: network_profile_id %q does not exist", ErrNotFound, inst.NetworkProfileID)
		}
	}
	if inst.PrimaryInstanceID != "" {
		if inst.PrimaryInstanceID == inst.ID {
			return inst, fmt.Errorf("instance %q cannot set primary_instance_id to itself", inst.ID)
		}
		var cnt int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM instances WHERE id = ?`, inst.PrimaryInstanceID).Scan(&cnt); err != nil {
			return inst, err
		}
		if cnt == 0 {
			return inst, fmt.Errorf("%w: primary_instance_id %q does not exist", ErrNotFound, inst.PrimaryInstanceID)
		}
	}
	capsJSON := existingCapsJSON
	capsAt := existingCapsAt
	if inst.Capabilities != nil {
		if b, mErr := json.Marshal(inst.Capabilities); mErr == nil {
			capsJSON = string(b)
			capsAt = inst.Capabilities.DetectedAtUTC
			if capsAt == "" {
				capsAt = now
			}
			inst.CapabilitiesDetectedAt = capsAt
		}
	} else {
		inst.Capabilities = unmarshalServerCapabilities(capsJSON, capsAt)
		inst.CapabilitiesDetectedAt = capsAt
	}

	inst.UpdatedAtUTC = now
	_, err = tx.ExecContext(ctx, `
		INSERT INTO instances(id, name, engine, host, port, role, primary_instance_id, network_profile_id, tls_mode, params_json, capabilities_json, capabilities_detected_at_utc, created_at_utc, updated_at_utc)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name,
			engine = excluded.engine,
			host = excluded.host,
			port = excluded.port,
			role = excluded.role,
			primary_instance_id = excluded.primary_instance_id,
			network_profile_id = excluded.network_profile_id,
			tls_mode = excluded.tls_mode,
			params_json = excluded.params_json,
			capabilities_json = excluded.capabilities_json,
			capabilities_detected_at_utc = excluded.capabilities_detected_at_utc,
			updated_at_utc = excluded.updated_at_utc`,
		inst.ID, inst.Name, inst.Engine, inst.Host, inst.Port, string(inst.Role), inst.PrimaryInstanceID, inst.NetworkProfileID, inst.TLSMode, string(paramsJSON), capsJSON, capsAt, inst.CreatedAtUTC, inst.UpdatedAtUTC)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return inst, fmt.Errorf("%w: duplicate instance name %q", ErrConflict, inst.Name)
		}
		return inst, err
	}
	if err := s.appendAuditTx(ctx, tx, actor, action, inst.ID, "", inst, now); err != nil {
		return inst, err
	}
	return inst, nil
}

// UpdateInstanceCapabilities caches detected live ServerCapabilities for an instance when changed.
func (s *Store) UpdateInstanceCapabilities(ctx context.Context, id string, caps *types.ServerCapabilities) error {
	if id == "" || caps == nil {
		return nil
	}
	return s.withTx(ctx, func(tx *sql.Tx) error {
		var prevJSON string
		if err := tx.QueryRowContext(ctx, `SELECT capabilities_json FROM instances WHERE id = ?`, id).Scan(&prevJSON); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		snap := *caps
		snap.DetectedAtUTC = ""
		prevCaps := unmarshalServerCapabilities(prevJSON, "")
		if prevCaps != nil {
			prevCopy := *prevCaps
			prevCopy.DetectedAtUTC = ""
			if prevBytes, _ := json.Marshal(prevCopy); string(prevBytes) != "" {
				if nextBytes, _ := json.Marshal(snap); string(prevBytes) == string(nextBytes) {
					return nil
				}
			}
		}
		now := nowUTC()
		if caps.DetectedAtUTC == "" {
			caps.DetectedAtUTC = now
		}
		raw, err := json.Marshal(caps)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE instances SET capabilities_json = ?, capabilities_detected_at_utc = ?, updated_at_utc = ? WHERE id = ?`,
			string(raw), caps.DetectedAtUTC, now, id); err != nil {
			return err
		}
		return s.appendAuditTx(ctx, tx, "system", "instance.capabilities_detected", id, "", caps, now)
	})
}

// DeleteInstance removes an unused instance (rejecting if targets or replica instances reference it).
func (s *Store) DeleteInstance(ctx context.Context, actor, id string) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		var repCount int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM instances WHERE primary_instance_id = ?`, id).Scan(&repCount); err != nil {
			return err
		}
		if repCount > 0 {
			return fmt.Errorf("%w: cannot delete primary instance %s referenced by %d replica(s)", ErrConflict, id, repCount)
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM instances WHERE id = ?`, id)
		if err != nil {
			return fmt.Errorf("%w: cannot delete instance %s in use: %v", ErrConflict, id, err)
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return ErrNotFound
		}
		return s.appendAuditTx(ctx, tx, actor, "instance.delete", id, "", map[string]any{"id": id}, nowUTC())
	})
}

// ListTargets returns all targets including linked system IDs.
func (s *Store) ListTargets(ctx context.Context) ([]types.Target, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, ref, alias, owner_system_id, environment_code, instance_id, database_name, ro_credential_id, rw_credential_id, policy_override_id, status, description, created_at_utc, updated_at_utc
		FROM targets ORDER BY ref ASC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []types.Target
	for rows.Next() {
		var t types.Target
		if err := rows.Scan(&t.ID, &t.Ref, &t.Alias, &t.OwnerSystemID, &t.EnvironmentCode, &t.InstanceID, &t.DatabaseName, &t.ROCredentialID, &t.RWCredentialID, &t.PolicyOverrideID, &t.Status, &t.Description, &t.CreatedAtUTC, &t.UpdatedAtUTC); err != nil {
			return nil, err
		}
		t.LinkedSystemIDs = []string{}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	linkRows, err := s.db.QueryContext(ctx, `SELECT target_id, system_id FROM target_linked_systems ORDER BY system_id ASC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = linkRows.Close() }()
	links := map[string][]string{}
	for linkRows.Next() {
		var tid, sid string
		if err := linkRows.Scan(&tid, &sid); err != nil {
			return nil, err
		}
		links[tid] = append(links[tid], sid)
	}
	for i := range out {
		if l, ok := links[out[i].ID]; ok {
			out[i].LinkedSystemIDs = l
		}
	}
	return out, linkRows.Err()
}

// UpsertTarget saves a target and its linked systems atomically with an audit entry.
func (s *Store) UpsertTarget(ctx context.Context, actor string, t types.Target) (types.Target, error) {
	now := nowUTC()
	var saved types.Target
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		var err error
		saved, err = s.upsertTargetTx(ctx, tx, actor, t, now)
		return err
	})
	if err != nil {
		return t, err
	}
	return saved, nil
}

func (s *Store) upsertTargetTx(ctx context.Context, tx *sql.Tx, actor string, t types.Target, now string) (types.Target, error) {
	if strings.TrimSpace(t.Ref) == "" || strings.TrimSpace(t.OwnerSystemID) == "" || strings.TrimSpace(t.EnvironmentCode) == "" || strings.TrimSpace(t.InstanceID) == "" {
		return t, fmt.Errorf("target ref, owner_system_id, environment_code, and instance_id are required")
	}
	if t.Status == "" {
		t.Status = types.TargetActive
	}
	if t.LinkedSystemIDs == nil {
		t.LinkedSystemIDs = []string{}
	}
	if t.ID == "" {
		t.ID = newID("tgt")
	}

	var existingCreated string
	err := tx.QueryRowContext(ctx, `SELECT created_at_utc FROM targets WHERE id = ?`, t.ID).Scan(&existingCreated)
	action := "target.create"
	if err == nil {
		action = "target.update"
		t.CreatedAtUTC = existingCreated
	} else if errors.Is(err, sql.ErrNoRows) {
		t.CreatedAtUTC = now
	} else {
		return t, err
	}
	if err := requireCredentialExistsTx(ctx, tx, t.ROCredentialID); err != nil {
		return t, err
	}
	if err := requireCredentialExistsTx(ctx, tx, t.RWCredentialID); err != nil {
		return t, err
	}
	if err := requirePolicyExistsTx(ctx, tx, t.PolicyOverrideID); err != nil {
		return t, err
	}
	t.UpdatedAtUTC = now
	_, err = tx.ExecContext(ctx, `
		INSERT INTO targets(id, ref, alias, owner_system_id, environment_code, instance_id, database_name, ro_credential_id, rw_credential_id, policy_override_id, status, description, created_at_utc, updated_at_utc)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			ref = excluded.ref,
			alias = excluded.alias,
			owner_system_id = excluded.owner_system_id,
			environment_code = excluded.environment_code,
			instance_id = excluded.instance_id,
			database_name = excluded.database_name,
			ro_credential_id = excluded.ro_credential_id,
			rw_credential_id = excluded.rw_credential_id,
			policy_override_id = excluded.policy_override_id,
			status = excluded.status,
			description = excluded.description,
			updated_at_utc = excluded.updated_at_utc`,
		t.ID, t.Ref, t.Alias, t.OwnerSystemID, t.EnvironmentCode, t.InstanceID, t.DatabaseName, t.ROCredentialID, t.RWCredentialID, t.PolicyOverrideID, string(t.Status), t.Description, t.CreatedAtUTC, t.UpdatedAtUTC)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return t, fmt.Errorf("%w: duplicate target ref %q", ErrConflict, t.Ref)
		}
		return t, err
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM target_linked_systems WHERE target_id = ?`, t.ID); err != nil {
		return t, err
	}
	seen := map[string]bool{t.OwnerSystemID: true}
	for _, sid := range t.LinkedSystemIDs {
		if sid == "" || seen[sid] {
			continue
		}
		seen[sid] = true
		if _, err := tx.ExecContext(ctx, `INSERT INTO target_linked_systems(target_id, system_id) VALUES (?, ?)`, t.ID, sid); err != nil {
			return t, err
		}
	}
	if err := s.appendAuditTx(ctx, tx, actor, action, t.ID, "", t, now); err != nil {
		return t, err
	}
	return t, nil
}

// DeleteTarget deletes a target, cleans up unreferenced target-scoped policies/patterns, and writes an audit entry.
func (s *Store) DeleteTarget(ctx context.Context, actor, id string) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		var ref string
		_ = tx.QueryRowContext(ctx, `SELECT ref FROM targets WHERE id = ?`, id).Scan(&ref)
		res, err := tx.ExecContext(ctx, `DELETE FROM targets WHERE id = ?`, id)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return ErrNotFound
		}
		now := nowUTC()
		if err := s.cleanupScopedPoliciesAndRulesTx(ctx, tx, actor, "target", id, ref, now); err != nil {
			return err
		}
		return s.appendAuditTx(ctx, tx, actor, "target.delete", id, "", map[string]any{"id": id}, now)
	})
}

// GetGlobalSecurityConfig returns the global security guardrails.
func (s *Store) GetGlobalSecurityConfig(ctx context.Context) (types.GlobalSecurityConfig, error) {
	var cfg types.GlobalSecurityConfig
	var freeze, blockMulti, redact int
	err := s.db.QueryRowContext(ctx, `
		SELECT exec_timeout_sec, approval_timeout_sec, max_rows, max_bytes, explain_max_rows,
			prod_read_only_freeze, block_multi_statement_in_prod, default_approval_provider, redact_audit_literals, updated_at_utc
		FROM global_security_config WHERE id = 1`).
		Scan(&cfg.ExecTimeoutSec, &cfg.ApprovalTimeoutSec, &cfg.MaxRows, &cfg.MaxBytes, &cfg.ExplainMaxRows,
			&freeze, &blockMulti, &cfg.DefaultApprovalProvider, &redact, &cfg.UpdatedAtUTC)
	if err != nil {
		return cfg, err
	}
	cfg.ProdReadOnlyFreeze = freeze == 1
	cfg.BlockMultiStatementInProd = blockMulti == 1
	cfg.RedactAuditLiterals = redact == 1
	return cfg, nil
}

// UpdateGlobalSecurityConfig updates global security guardrails and writes an audit entry.
func (s *Store) UpdateGlobalSecurityConfig(ctx context.Context, actor string, cfg types.GlobalSecurityConfig) (types.GlobalSecurityConfig, error) {
	if err := policy.ValidateGlobalConfig(cfg); err != nil {
		return cfg, err
	}
	if cfg.DefaultApprovalProvider == "" {
		cfg.DefaultApprovalProvider = "local-web"
	}
	now := nowUTC()
	cfg.UpdatedAtUTC = now
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			UPDATE global_security_config SET
				exec_timeout_sec = ?,
				approval_timeout_sec = ?,
				max_rows = ?,
				max_bytes = ?,
				explain_max_rows = ?,
				prod_read_only_freeze = ?,
				block_multi_statement_in_prod = ?,
				default_approval_provider = ?,
				redact_audit_literals = ?,
				updated_at_utc = ?
			WHERE id = 1`,
			cfg.ExecTimeoutSec, cfg.ApprovalTimeoutSec, cfg.MaxRows, cfg.MaxBytes, cfg.ExplainMaxRows,
			boolToInt(cfg.ProdReadOnlyFreeze), boolToInt(cfg.BlockMultiStatementInProd),
			cfg.DefaultApprovalProvider, boolToInt(cfg.RedactAuditLiterals), now)
		if err != nil {
			return err
		}
		return s.appendAuditTx(ctx, tx, actor, "global_security.update", "global", "", cfg, now)
	})
	return cfg, err
}

// ListPolicies returns all policy rule sets.
func (s *Store) ListPolicies(ctx context.Context) ([]types.PolicyRuleSet, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, scope_type, scope_id,
			allow_safe_read, require_approval_on_high_cost_read, require_approval_on_write,
			require_approval_on_ddl, require_approval_on_admin, require_approval_on_unknown,
			allow_multi_statement, exec_timeout_sec, approval_timeout_sec, max_rows, max_bytes, explain_max_rows,
			approval_provider, created_at_utc, updated_at_utc
		FROM policies ORDER BY scope_type ASC, name ASC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []types.PolicyRuleSet
	for rows.Next() {
		var p types.PolicyRuleSet
		var aSafe, rHigh, rWrite, rDDL, rAdmin, rUnk, aMulti sql.NullInt64
		var execT, appT, maxR sql.NullInt64
		var maxB, expR sql.NullInt64
		if err := rows.Scan(&p.ID, &p.Name, &p.ScopeType, &p.ScopeID,
			&aSafe, &rHigh, &rWrite, &rDDL, &rAdmin, &rUnk, &aMulti,
			&execT, &appT, &maxR, &maxB, &expR,
			&p.ApprovalProvider, &p.CreatedAtUTC, &p.UpdatedAtUTC); err != nil {
			return nil, err
		}
		p.AllowSafeRead = nullIntToBoolPtr(aSafe)
		p.RequireApprovalOnHighCostRead = nullIntToBoolPtr(rHigh)
		p.RequireApprovalOnWrite = nullIntToBoolPtr(rWrite)
		p.RequireApprovalOnDDL = nullIntToBoolPtr(rDDL)
		p.RequireApprovalOnAdmin = nullIntToBoolPtr(rAdmin)
		p.RequireApprovalOnUnknown = nullIntToBoolPtr(rUnk)
		p.AllowMultiStatement = nullIntToBoolPtr(aMulti)
		p.ExecTimeoutSec = nullIntToIntPtr(execT)
		p.ApprovalTimeoutSec = nullIntToIntPtr(appT)
		p.MaxRows = nullIntToIntPtr(maxR)
		p.MaxBytes = nullIntToInt64Ptr(maxB)
		p.ExplainMaxRows = nullIntToInt64Ptr(expR)
		out = append(out, p)
	}
	return out, rows.Err()
}

// UpsertPolicy creates or updates a policy rule set in the same tx as its audit log.
func (s *Store) UpsertPolicy(ctx context.Context, actor string, p types.PolicyRuleSet) (types.PolicyRuleSet, error) {
	now := nowUTC()
	var saved types.PolicyRuleSet
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		var err error
		saved, err = s.upsertPolicyTx(ctx, tx, actor, p, now)
		return err
	})
	if err != nil {
		return p, err
	}
	return saved, nil
}

func (s *Store) upsertPolicyTx(ctx context.Context, tx *sql.Tx, actor string, p types.PolicyRuleSet, now string) (types.PolicyRuleSet, error) {
	if p.ScopeType != "env" {
		p.ScopeID = canonicalizeScopeIDTx(ctx, tx, p.ScopeType, p.ScopeID)
	} else {
		p.ScopeID = canonicalizeScopeIDTx(ctx, tx, "env", p.ScopeID)
	}
	if err := policy.ValidateRuleSet(p); err != nil {
		return p, err
	}
	if p.ID == "" {
		p.ID = newID("pol")
	}
	var existingCreated string
	err := tx.QueryRowContext(ctx, `SELECT created_at_utc FROM policies WHERE id = ?`, p.ID).Scan(&existingCreated)
	action := "policy.create"
	if err == nil {
		action = "policy.update"
		p.CreatedAtUTC = existingCreated
	} else if errors.Is(err, sql.ErrNoRows) {
		p.CreatedAtUTC = now
	} else {
		return p, err
	}
	p.UpdatedAtUTC = now
	_, err = tx.ExecContext(ctx, `
		INSERT INTO policies(
			id, name, scope_type, scope_id,
			allow_safe_read, require_approval_on_high_cost_read, require_approval_on_write,
			require_approval_on_ddl, require_approval_on_admin, require_approval_on_unknown,
			allow_multi_statement, exec_timeout_sec, approval_timeout_sec, max_rows, max_bytes, explain_max_rows,
			approval_provider, created_at_utc, updated_at_utc
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name,
			scope_type = excluded.scope_type,
			scope_id = excluded.scope_id,
			allow_safe_read = excluded.allow_safe_read,
			require_approval_on_high_cost_read = excluded.require_approval_on_high_cost_read,
			require_approval_on_write = excluded.require_approval_on_write,
			require_approval_on_ddl = excluded.require_approval_on_ddl,
			require_approval_on_admin = excluded.require_approval_on_admin,
			require_approval_on_unknown = excluded.require_approval_on_unknown,
			allow_multi_statement = excluded.allow_multi_statement,
			exec_timeout_sec = excluded.exec_timeout_sec,
			approval_timeout_sec = excluded.approval_timeout_sec,
			max_rows = excluded.max_rows,
			max_bytes = excluded.max_bytes,
			explain_max_rows = excluded.explain_max_rows,
			approval_provider = excluded.approval_provider,
			updated_at_utc = excluded.updated_at_utc`,
		p.ID, p.Name, p.ScopeType, p.ScopeID,
		boolPtrToNullInt(p.AllowSafeRead), boolPtrToNullInt(p.RequireApprovalOnHighCostRead), boolPtrToNullInt(p.RequireApprovalOnWrite),
		boolPtrToNullInt(p.RequireApprovalOnDDL), boolPtrToNullInt(p.RequireApprovalOnAdmin), boolPtrToNullInt(p.RequireApprovalOnUnknown),
		boolPtrToNullInt(p.AllowMultiStatement), intPtrToNullInt(p.ExecTimeoutSec), intPtrToNullInt(p.ApprovalTimeoutSec),
		intPtrToNullInt(p.MaxRows), int64PtrToNullInt(p.MaxBytes), int64PtrToNullInt(p.ExplainMaxRows),
		p.ApprovalProvider, p.CreatedAtUTC, p.UpdatedAtUTC)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return p, fmt.Errorf("%w: duplicate policy name %q", ErrConflict, p.Name)
		}
		return p, err
	}
	if err := s.appendAuditTx(ctx, tx, actor, action, p.ID, "", p, now); err != nil {
		return p, err
	}
	return p, nil
}

// DeletePolicy deletes a policy rule set if no environment, system, or target references it.
func (s *Store) DeletePolicy(ctx context.Context, actor, id string) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		var envCount, sysCount, tgtCount int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM environments WHERE default_policy_id = ?`, id).Scan(&envCount); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM systems WHERE default_policy_id = ?`, id).Scan(&sysCount); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM targets WHERE policy_override_id = ?`, id).Scan(&tgtCount); err != nil {
			return err
		}
		if envCount > 0 || sysCount > 0 || tgtCount > 0 {
			return fmt.Errorf("%w: cannot delete policy %s in use (envs=%d, systems=%d, targets=%d)", ErrConflict, id, envCount, sysCount, tgtCount)
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM policies WHERE id = ?`, id)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return ErrNotFound
		}
		return s.appendAuditTx(ctx, tx, actor, "policy.delete", id, "", map[string]any{"id": id}, nowUTC())
	})
}

// ExportTopology exports a secret-free TopologyBundle.
func (s *Store) ExportTopology(ctx context.Context) (types.TopologyBundle, error) {
	var b types.TopologyBundle
	b.SchemaVersion = 1
	b.ExportedAtUTC = nowUTC()
	var err error
	if cfg, gErr := s.GetGlobalSecurityConfig(ctx); gErr == nil {
		b.GlobalSecurity = &cfg
	}
	if b.Environments, err = s.ListEnvironments(ctx); err != nil {
		return b, err
	}
	if b.Systems, err = s.ListSystems(ctx); err != nil {
		return b, err
	}
	if b.NetworkProfiles, err = s.ListNetworkProfiles(ctx); err != nil {
		return b, err
	}
	if b.CredentialProfiles, err = s.ListCredentialProfiles(ctx); err != nil {
		return b, err
	}
	if b.Instances, err = s.ListInstances(ctx); err != nil {
		return b, err
	}
	for i := range b.Instances {
		b.Instances[i].Capabilities = nil
		b.Instances[i].CapabilitiesDetectedAt = ""
	}
	if b.Targets, err = s.ListTargets(ctx); err != nil {
		return b, err
	}
	if b.Policies, err = s.ListPolicies(ctx); err != nil {
		return b, err
	}
	if b.RiskPatternRules, err = s.ListRiskPatternRules(ctx); err != nil {
		return b, err
	}
	return b, nil
}

// ImportTopology imports a TopologyBundle in a single atomic transaction, resolving natural keys
// (Code/Slug/Name/Ref) to preserve local IDs and Keychain bindings without overwriting local secrets.
func (s *Store) ImportTopology(ctx context.Context, actor string, b types.TopologyBundle) error {
	if b.SchemaVersion < 0 || b.SchemaVersion > 1 {
		return fmt.Errorf("unsupported topology schema_version %d (supported: 1)", b.SchemaVersion)
	}
	if b.GlobalSecurity != nil {
		if err := policy.ValidateGlobalConfig(*b.GlobalSecurity); err != nil {
			return fmt.Errorf("invalid global_security in topology: %w", err)
		}
	}
	now := nowUTC()
	return s.withTx(ctx, func(tx *sql.Tx) error {
		if b.GlobalSecurity != nil {
			cfg := *b.GlobalSecurity
			if cfg.DefaultApprovalProvider == "" {
				cfg.DefaultApprovalProvider = "local-web"
			}
			cfg.UpdatedAtUTC = now
			if _, err := tx.ExecContext(ctx, `
				UPDATE global_security_config SET
					exec_timeout_sec = ?,
					approval_timeout_sec = ?,
					max_rows = ?,
					max_bytes = ?,
					explain_max_rows = ?,
					prod_read_only_freeze = ?,
					block_multi_statement_in_prod = ?,
					default_approval_provider = ?,
					redact_audit_literals = ?,
					updated_at_utc = ?
				WHERE id = 1`,
				cfg.ExecTimeoutSec, cfg.ApprovalTimeoutSec, cfg.MaxRows, cfg.MaxBytes, cfg.ExplainMaxRows,
				boolToInt(cfg.ProdReadOnlyFreeze), boolToInt(cfg.BlockMultiStatementInProd),
				cfg.DefaultApprovalProvider, boolToInt(cfg.RedactAuditLiterals), now); err != nil {
				return err
			}
			if err := s.appendAuditTx(ctx, tx, actor, "global_security.update", "global", "", cfg, now); err != nil {
				return err
			}
		}

		envCodeMap := map[string]string{}
		envs := make([]types.Environment, len(b.Environments))
		for i, env := range b.Environments {
			var existingCode string
			if err := tx.QueryRowContext(ctx, `SELECT code FROM environments WHERE LOWER(code) = LOWER(?)`, env.Code).Scan(&existingCode); err == nil {
				envCodeMap[strings.ToLower(env.Code)] = existingCode
				env.Code = existingCode
			} else {
				envCodeMap[strings.ToLower(env.Code)] = env.Code
			}
			envs[i] = env
		}

		sysIDMap := map[string]string{}
		systems := make([]types.System, len(b.Systems))
		for i, sys := range b.Systems {
			origID := sys.ID
			var existingID, existingWSJSON string
			err := tx.QueryRowContext(ctx, `SELECT id, workspace_paths_json FROM systems WHERE id = ? OR LOWER(slug) = LOWER(?) LIMIT 1`, sys.ID, sys.Slug).
				Scan(&existingID, &existingWSJSON)
			if err == nil {
				sys.ID = existingID
				if len(sys.WorkspacePaths) == 0 {
					var localWS []string
					_ = json.Unmarshal([]byte(existingWSJSON), &localWS)
					if len(localWS) > 0 {
						sys.WorkspacePaths = localWS
					}
				}
			} else if sys.ID == "" {
				sys.ID = newID("sys")
			}
			if origID != "" {
				sysIDMap[origID] = sys.ID
			}
			if sys.Slug != "" {
				sysIDMap["slug:"+strings.ToLower(sys.Slug)] = sys.ID
			}
			systems[i] = sys
		}

		cpIDMap := map[string]string{}
		creds := make([]types.CredentialProfile, len(b.CredentialProfiles))
		for i, cp := range b.CredentialProfiles {
			origID := cp.ID
			var existingID string
			if err := tx.QueryRowContext(ctx, `SELECT id FROM credential_profiles WHERE id = ? OR LOWER(name) = LOWER(?) LIMIT 1`, cp.ID, cp.Name).
				Scan(&existingID); err == nil {
				cp.ID = existingID
			} else if cp.ID == "" {
				cp.ID = newID("cred")
			}
			if origID != "" {
				cpIDMap[origID] = cp.ID
			}
			creds[i] = cp
		}

		npIDMap := map[string]string{}
		nets := make([]types.NetworkProfile, len(b.NetworkProfiles))
		for i, np := range b.NetworkProfiles {
			origID := np.ID
			var existingID string
			if err := tx.QueryRowContext(ctx, `SELECT id FROM network_profiles WHERE id = ? OR LOWER(name) = LOWER(?) LIMIT 1`, np.ID, np.Name).
				Scan(&existingID); err == nil {
				np.ID = existingID
			} else if np.ID == "" {
				np.ID = newID("net")
			}
			if origID != "" {
				npIDMap[origID] = np.ID
			}
			nets[i] = np
		}

		instIDMap := map[string]string{}
		insts := make([]types.Instance, len(b.Instances))
		for i, inst := range b.Instances {
			origID := inst.ID
			var existingID string
			if err := tx.QueryRowContext(ctx, `SELECT id FROM instances WHERE id = ? OR LOWER(name) = LOWER(?) LIMIT 1`, inst.ID, inst.Name).
				Scan(&existingID); err == nil {
				inst.ID = existingID
			} else if inst.ID == "" {
				inst.ID = newID("inst")
			}
			if origID != "" {
				instIDMap[origID] = inst.ID
			}
			insts[i] = inst
		}

		tgtIDMap := map[string]string{}
		targets := make([]types.Target, len(b.Targets))
		for i, tgt := range b.Targets {
			origID := tgt.ID
			var existingID string
			if err := tx.QueryRowContext(ctx, `SELECT id FROM targets WHERE id = ? OR LOWER(ref) = LOWER(?) LIMIT 1`, tgt.ID, tgt.Ref).
				Scan(&existingID); err == nil {
				tgt.ID = existingID
			} else if tgt.ID == "" {
				tgt.ID = newID("tgt")
			}
			if origID != "" {
				tgtIDMap[origID] = tgt.ID
			}
			if tgt.Ref != "" {
				tgtIDMap["ref:"+strings.ToLower(tgt.Ref)] = tgt.ID
			}
			targets[i] = tgt
		}

		polIDMap := map[string]string{}
		policies := make([]types.PolicyRuleSet, len(b.Policies))
		for i, pol := range b.Policies {
			origID := pol.ID
			var existingID string
			if err := tx.QueryRowContext(ctx, `SELECT id FROM policies WHERE id = ? OR LOWER(name) = LOWER(?) LIMIT 1`, pol.ID, pol.Name).
				Scan(&existingID); err == nil {
				pol.ID = existingID
			} else if pol.ID == "" {
				pol.ID = newID("pol")
			}
			if origID != "" {
				polIDMap[origID] = pol.ID
			}
			pol.ScopeID = remapScopeID(pol.ScopeType, pol.ScopeID, envCodeMap, sysIDMap, tgtIDMap)
			policies[i] = pol
		}

		for _, pol := range policies {
			if _, err := s.upsertPolicyTx(ctx, tx, actor, pol, now); err != nil {
				return err
			}
		}
		for _, env := range envs {
			if mapped, ok := polIDMap[env.DefaultPolicyID]; ok {
				env.DefaultPolicyID = mapped
			}
			if _, err := s.upsertEnvironmentTx(ctx, tx, actor, env, now); err != nil {
				return err
			}
		}
		for _, sys := range systems {
			if mapped, ok := polIDMap[sys.DefaultPolicyID]; ok {
				sys.DefaultPolicyID = mapped
			}
			if _, err := s.upsertSystemTx(ctx, tx, actor, sys, now); err != nil {
				return err
			}
		}
		for _, cp := range creds {
			if _, err := s.upsertCredentialProfileTx(ctx, tx, actor, cp, now); err != nil {
				return err
			}
		}
		for _, np := range nets {
			if mapped, ok := cpIDMap[np.BastionCredentialID]; ok {
				np.BastionCredentialID = mapped
			}
			if _, err := s.upsertNetworkProfileTx(ctx, tx, actor, np, now); err != nil {
				return err
			}
		}

		// Upsert non-replica / root instances before replicas so PrimaryInstanceID checks pass regardless of bundle order.
		for pass := 0; pass < 2; pass++ {
			for _, inst := range insts {
				isDependent := inst.PrimaryInstanceID != ""
				if (pass == 0 && isDependent) || (pass == 1 && !isDependent) {
					continue
				}
				if mapped, ok := npIDMap[inst.NetworkProfileID]; ok {
					inst.NetworkProfileID = mapped
				}
				if mapped, ok := instIDMap[inst.PrimaryInstanceID]; ok {
					inst.PrimaryInstanceID = mapped
				}
				if _, err := s.upsertInstanceTx(ctx, tx, actor, inst, now); err != nil {
					return err
				}
			}
		}

		for _, tgt := range targets {
			if mapped, ok := sysIDMap[tgt.OwnerSystemID]; ok {
				tgt.OwnerSystemID = mapped
			}
			for j, lid := range tgt.LinkedSystemIDs {
				if mapped, ok := sysIDMap[lid]; ok {
					tgt.LinkedSystemIDs[j] = mapped
				}
			}
			if mapped, ok := envCodeMap[strings.ToLower(tgt.EnvironmentCode)]; ok {
				tgt.EnvironmentCode = mapped
			}
			if mapped, ok := instIDMap[tgt.InstanceID]; ok {
				tgt.InstanceID = mapped
			}
			if mapped, ok := cpIDMap[tgt.ROCredentialID]; ok {
				tgt.ROCredentialID = mapped
			}
			if mapped, ok := cpIDMap[tgt.RWCredentialID]; ok {
				tgt.RWCredentialID = mapped
			}
			if mapped, ok := polIDMap[tgt.PolicyOverrideID]; ok {
				tgt.PolicyOverrideID = mapped
			}
			if _, err := s.upsertTargetTx(ctx, tx, actor, tgt, now); err != nil {
				return err
			}
		}

		for _, pat := range b.RiskPatternRules {
			if pat.ScopeType != "global" {
				pat.ScopeID = remapScopeID(pat.ScopeType, pat.ScopeID, envCodeMap, sysIDMap, tgtIDMap)
			}
			var existingID string
			if err := tx.QueryRowContext(ctx, `SELECT id FROM risk_pattern_rules WHERE id = ? OR (scope_type = ? AND scope_id = ? AND name = ?) LIMIT 1`,
				pat.ID, pat.ScopeType, pat.ScopeID, pat.Name).Scan(&existingID); err == nil {
				pat.ID = existingID
			}
			if _, err := s.upsertRiskPatternRuleTx(ctx, tx, actor, pat, now); err != nil {
				return err
			}
		}
		return s.appendAuditTx(ctx, tx, actor, "topology.import", "catalog", "", map[string]any{
			"schema_version":      b.SchemaVersion,
			"environments":        len(envs),
			"systems":             len(systems),
			"credential_profiles": len(creds),
			"network_profiles":    len(nets),
			"instances":           len(insts),
			"targets":             len(targets),
			"policies":            len(policies),
			"risk_pattern_rules":  len(b.RiskPatternRules),
		}, now)
	})
}

func remapScopeID(scopeType, scopeID string, envCodeMap, sysIDMap, tgtIDMap map[string]string) string {
	trimmed := strings.TrimSpace(scopeID)
	switch scopeType {
	case "env":
		if mapped, ok := envCodeMap[strings.ToLower(trimmed)]; ok {
			return mapped
		}
	case "system":
		if mapped, ok := sysIDMap[trimmed]; ok {
			return mapped
		}
		if mapped, ok := sysIDMap["slug:"+strings.ToLower(trimmed)]; ok {
			return mapped
		}
	case "target":
		if mapped, ok := tgtIDMap[trimmed]; ok {
			return mapped
		}
		if mapped, ok := tgtIDMap["ref:"+strings.ToLower(trimmed)]; ok {
			return mapped
		}
	}
	return trimmed
}

func canonicalizeScopeIDTx(ctx context.Context, tx *sql.Tx, scopeType, scopeID string) string {
	trimmed := strings.TrimSpace(scopeID)
	if trimmed == "" {
		return ""
	}
	switch scopeType {
	case "env":
		var code string
		if err := tx.QueryRowContext(ctx, `SELECT code FROM environments WHERE LOWER(code) = LOWER(?) LIMIT 1`, trimmed).Scan(&code); err == nil {
			return code
		}
	case "system":
		var id string
		if err := tx.QueryRowContext(ctx, `SELECT id FROM systems WHERE id = ? OR LOWER(slug) = LOWER(?) LIMIT 1`, trimmed, trimmed).Scan(&id); err == nil {
			return id
		}
	case "target":
		var id string
		if err := tx.QueryRowContext(ctx, `SELECT id FROM targets WHERE id = ? OR LOWER(ref) = LOWER(?) LIMIT 1`, trimmed, trimmed).Scan(&id); err == nil {
			return id
		}
	}
	return trimmed
}

func requirePolicyExistsTx(ctx context.Context, tx *sql.Tx, id string) error {
	if id == "" {
		return nil
	}
	var cnt int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM policies WHERE id = ?`, id).Scan(&cnt); err != nil {
		return err
	}
	if cnt == 0 {
		return fmt.Errorf("%w: policy %q does not exist", ErrNotFound, id)
	}
	return nil
}

func requireCredentialExistsTx(ctx context.Context, tx *sql.Tx, id string) error {
	if id == "" {
		return nil
	}
	var cnt int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM credential_profiles WHERE id = ?`, id).Scan(&cnt); err != nil {
		return err
	}
	if cnt == 0 {
		return fmt.Errorf("%w: credential profile %q does not exist", ErrNotFound, id)
	}
	return nil
}

func (s *Store) cleanupScopedPoliciesAndRulesTx(ctx context.Context, tx *sql.Tx, actor, scopeType, id, naturalKey, now string) error {
	match := func(col string) (string, []any) {
		if naturalKey != "" {
			return fmt.Sprintf(`scope_type = ? AND (%s = ? OR LOWER(%s) = LOWER(?))`, col, col), []any{scopeType, id, naturalKey}
		}
		return fmt.Sprintf(`scope_type = ? AND %s = ?`, col), []any{scopeType, id}
	}

	polWhere, polArgs := match("scope_id")
	polQuery := `SELECT id FROM policies WHERE ` + polWhere + `
		AND id NOT IN (SELECT default_policy_id FROM environments WHERE default_policy_id != '')
		AND id NOT IN (SELECT default_policy_id FROM systems WHERE default_policy_id != '')
		AND id NOT IN (SELECT policy_override_id FROM targets WHERE policy_override_id != '')`
	polRows, err := tx.QueryContext(ctx, polQuery, polArgs...)
	if err != nil {
		return err
	}
	var polIDs []string
	for polRows.Next() {
		var pid string
		if scanErr := polRows.Scan(&pid); scanErr != nil {
			_ = polRows.Close()
			return scanErr
		}
		polIDs = append(polIDs, pid)
	}
	_ = polRows.Close()
	for _, pid := range polIDs {
		if _, err := tx.ExecContext(ctx, `DELETE FROM policies WHERE id = ?`, pid); err != nil {
			return err
		}
		if err := s.appendAuditTx(ctx, tx, actor, "policy.delete", pid, "", map[string]any{"id": pid, "cascade_scope": scopeType + ":" + id}, now); err != nil {
			return err
		}
	}

	patWhere, patArgs := match("scope_id")
	patRows, err := tx.QueryContext(ctx, `SELECT id FROM risk_pattern_rules WHERE `+patWhere, patArgs...)
	if err != nil {
		return err
	}
	var patIDs []string
	for patRows.Next() {
		var rid string
		if scanErr := patRows.Scan(&rid); scanErr != nil {
			_ = patRows.Close()
			return scanErr
		}
		patIDs = append(patIDs, rid)
	}
	_ = patRows.Close()
	for _, rid := range patIDs {
		if _, err := tx.ExecContext(ctx, `DELETE FROM risk_pattern_rules WHERE id = ?`, rid); err != nil {
			return err
		}
		if err := s.appendAuditTx(ctx, tx, actor, "risk_pattern.delete", rid, "", map[string]any{"id": rid, "cascade_scope": scopeType + ":" + id}, now); err != nil {
			return err
		}
	}
	return nil
}

func unmarshalServerCapabilities(raw, detectedAt string) *types.ServerCapabilities {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "{}" || trimmed == "null" {
		return nil
	}
	var caps types.ServerCapabilities
	if err := json.Unmarshal([]byte(trimmed), &caps); err != nil {
		return nil
	}
	if caps.Engine == "" && caps.Dialect == "" && caps.ServerVersion == "" {
		return nil
	}
	if caps.DetectedAtUTC == "" && detectedAt != "" {
		caps.DetectedAtUTC = detectedAt
	}
	return &caps
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func boolPtrToNullInt(p *bool) sql.NullInt64 {
	if p == nil {
		return sql.NullInt64{}
	}
	if *p {
		return sql.NullInt64{Int64: 1, Valid: true}
	}
	return sql.NullInt64{Int64: 0, Valid: true}
}

func intPtrToNullInt(p *int) sql.NullInt64 {
	if p == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(*p), Valid: true}
}

func int64PtrToNullInt(p *int64) sql.NullInt64 {
	if p == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: *p, Valid: true}
}

func nullIntToBoolPtr(v sql.NullInt64) *bool {
	if !v.Valid {
		return nil
	}
	b := v.Int64 != 0
	return &b
}

func nullIntToIntPtr(v sql.NullInt64) *int {
	if !v.Valid {
		return nil
	}
	n := int(v.Int64)
	return &n
}

func nullIntToInt64Ptr(v sql.NullInt64) *int64 {
	if !v.Valid {
		return nil
	}
	n := v.Int64
	return &n
}
