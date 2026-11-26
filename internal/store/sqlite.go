package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/x0c/agent-dbctl/internal/audit"
	"github.com/x0c/agent-dbctl/internal/config"
	"github.com/x0c/agent-dbctl/internal/types"
)

type pendingAudit struct {
	actor    string
	action   string
	targetID string
	opID     string
	payload  string
	ts       string
}

type auditBatch struct {
	items []pendingAudit
}

// Store manages the transactional SQLite or PostgreSQL catalog, policy, operations, auth, and hash-chain audit store.
type Store struct {
	db        *sql.DB
	pgPool    *pgxpool.Pool
	dbPath    string
	dialect   Dialect
	writeMu   sync.Mutex
	batchMu   sync.Mutex
	txBatches map[*sql.Tx]*auditBatch
}

// Open initializes the SQLite database with WAL mode verification and migrations.
func Open(ctx context.Context, dbPath string) (*Store, error) {
	if err := config.EnsurePrivateDir(filepath.Dir(dbPath)); err != nil {
		return nil, err
	}
	// Configure busy_timeout and foreign_keys via DSN pragmas so every pooled connection inherits them.
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", dbPath, err)
	}
	// SQLite single writer; limit open conns so PRAGMA checks and writes stay predictable.
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}

	var mode string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode=WAL;").Scan(&mode); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("enable WAL mode: %w", err)
	}
	var effectiveMode string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode;").Scan(&effectiveMode); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("readback WAL mode: %w", err)
	}
	if !strings.EqualFold(effectiveMode, "wal") {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite journal_mode mismatch: got %q, want wal", effectiveMode)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(dbPath, 0o600); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("chmod 0600 %s: %w", dbPath, err)
		}
	}

	s := &Store{
		db:        db,
		dbPath:    dbPath,
		dialect:   DialectSQLite,
		txBatches: make(map[*sql.Tx]*auditBatch),
	}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := s.seedDefaults(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the underlying SQLite or PostgreSQL pool.
func (s *Store) Close() error {
	err := s.db.Close()
	if s.pgPool != nil {
		s.pgPool.Close()
	}
	return err
}

// VerifyWAL returns the live journal_mode read back from SQLite (or "postgres" for PostgreSQL).
func (s *Store) VerifyWAL(ctx context.Context) (string, error) {
	if s.isPG() {
		return "postgres", nil
	}
	var mode string
	if err := s.db.QueryRowContext(ctx, "PRAGMA journal_mode;").Scan(&mode); err != nil {
		return "", err
	}
	return mode, nil
}

func (s *Store) migrate(ctx context.Context) error {
	if !s.isPG() && s.isCurrentSQLiteSchema(ctx) {
		return nil
	}
	const schema = `
CREATE TABLE IF NOT EXISTS schema_migrations (
	version INTEGER PRIMARY KEY,
	applied_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS systems (
	id TEXT PRIMARY KEY,
	slug TEXT NOT NULL UNIQUE,
	name TEXT NOT NULL,
	owner TEXT NOT NULL DEFAULT '',
	description TEXT NOT NULL DEFAULT '',
	tags_json TEXT NOT NULL DEFAULT '[]',
	workspace_paths_json TEXT NOT NULL DEFAULT '[]',
	git_remotes_json TEXT NOT NULL DEFAULT '[]',
	default_policy_id TEXT NOT NULL DEFAULT '',
	created_at_utc TEXT NOT NULL,
	updated_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS environments (
	code TEXT PRIMARY KEY,
	safety_tier TEXT NOT NULL,
	labels_json TEXT NOT NULL,
	color TEXT NOT NULL,
	sort_order INTEGER NOT NULL DEFAULT 0,
	default_policy_id TEXT NOT NULL DEFAULT '',
	created_at_utc TEXT NOT NULL,
	updated_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS network_profiles (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL UNIQUE,
	mode TEXT NOT NULL,
	proxy_url TEXT NOT NULL DEFAULT '',
	bastion_host TEXT NOT NULL DEFAULT '',
	bastion_port INTEGER NOT NULL DEFAULT 22,
	bastion_user TEXT NOT NULL DEFAULT '',
	bastion_credential_id TEXT NOT NULL DEFAULT '',
	ssh_strict_host_key INTEGER NOT NULL DEFAULT 1,
	tls_mode TEXT NOT NULL DEFAULT '',
	created_at_utc TEXT NOT NULL,
	updated_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS credential_profiles (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL UNIQUE,
	kind TEXT NOT NULL,
	access_level TEXT NOT NULL,
	username TEXT NOT NULL DEFAULT '',
	env_var_name TEXT NOT NULL DEFAULT '',
	exec_command TEXT NOT NULL DEFAULT '',
	created_at_utc TEXT NOT NULL,
	updated_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS instances (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL UNIQUE,
	engine TEXT NOT NULL,
	host TEXT NOT NULL DEFAULT '',
	port INTEGER NOT NULL DEFAULT 0,
	role TEXT NOT NULL DEFAULT 'standalone',
	primary_instance_id TEXT NOT NULL DEFAULT '',
	network_profile_id TEXT NOT NULL DEFAULT '',
	tls_mode TEXT NOT NULL DEFAULT '',
	params_json TEXT NOT NULL DEFAULT '{}',
	created_at_utc TEXT NOT NULL,
	updated_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS targets (
	id TEXT PRIMARY KEY,
	ref TEXT NOT NULL UNIQUE,
	alias TEXT NOT NULL DEFAULT '',
	owner_system_id TEXT NOT NULL REFERENCES systems(id) ON DELETE RESTRICT,
	environment_code TEXT NOT NULL REFERENCES environments(code) ON DELETE RESTRICT,
	instance_id TEXT NOT NULL REFERENCES instances(id) ON DELETE RESTRICT,
	database_name TEXT NOT NULL DEFAULT '',
	ro_credential_id TEXT NOT NULL DEFAULT '',
	rw_credential_id TEXT NOT NULL DEFAULT '',
	policy_override_id TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL DEFAULT 'active',
	description TEXT NOT NULL DEFAULT '',
	created_at_utc TEXT NOT NULL,
	updated_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS target_linked_systems (
	target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
	system_id TEXT NOT NULL REFERENCES systems(id) ON DELETE CASCADE,
	PRIMARY KEY (target_id, system_id)
);

CREATE TABLE IF NOT EXISTS policies (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL UNIQUE,
	scope_type TEXT NOT NULL,
	scope_id TEXT NOT NULL,
	allow_safe_read INTEGER,
	require_approval_on_high_cost_read INTEGER,
	require_approval_on_write INTEGER,
	require_approval_on_ddl INTEGER,
	require_approval_on_admin INTEGER,
	require_approval_on_unknown INTEGER,
	allow_multi_statement INTEGER,
	exec_timeout_sec INTEGER,
	approval_timeout_sec INTEGER,
	max_rows INTEGER,
	max_bytes INTEGER,
	explain_max_rows INTEGER,
	approval_provider TEXT NOT NULL DEFAULT '',
	scan_read_mode TEXT NOT NULL DEFAULT '',
	created_at_utc TEXT NOT NULL,
	updated_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS global_security_config (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	exec_timeout_sec INTEGER NOT NULL,
	approval_timeout_sec INTEGER NOT NULL,
	max_rows INTEGER NOT NULL,
	max_bytes INTEGER NOT NULL,
	explain_max_rows INTEGER NOT NULL,
	prod_read_only_freeze INTEGER NOT NULL,
	block_multi_statement_in_prod INTEGER NOT NULL,
	default_approval_provider TEXT NOT NULL,
	redact_audit_literals INTEGER NOT NULL,
	require_reason_for_approval INTEGER NOT NULL DEFAULT 1,
	updated_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS operations (
	id TEXT PRIMARY KEY,
	target_id TEXT NOT NULL,
	target_ref TEXT NOT NULL,
	system_id TEXT NOT NULL,
	system_slug TEXT NOT NULL,
	environment_code TEXT NOT NULL,
	engine TEXT NOT NULL,
	actor TEXT NOT NULL,
	reason TEXT NOT NULL DEFAULT '',
	workspace_cwd TEXT NOT NULL DEFAULT '',
	query_text TEXT NOT NULL,
	query_redacted TEXT NOT NULL,
	risk_level TEXT NOT NULL,
	decision TEXT NOT NULL,
	trigger_reasons_json TEXT NOT NULL DEFAULT '[]',
	matched_rules_json TEXT NOT NULL DEFAULT '[]',
	classification_json TEXT NOT NULL DEFAULT '{}',
	preflight_json TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL,
	credential_mode TEXT NOT NULL,
	approval_id TEXT NOT NULL DEFAULT '',
	fetched_rows INTEGER NOT NULL DEFAULT 0,
	returned_rows INTEGER NOT NULL DEFAULT 0,
	affected_rows INTEGER,
	truncated INTEGER NOT NULL DEFAULT 0,
	cutoff_reason TEXT NOT NULL DEFAULT '',
	latency_ms INTEGER NOT NULL DEFAULT 0,
	error_code TEXT NOT NULL DEFAULT '',
	error_message TEXT NOT NULL DEFAULT '',
	retryable INTEGER NOT NULL DEFAULT 0,
	created_at_utc TEXT NOT NULL,
	updated_at_utc TEXT NOT NULL,
	completed_at_utc TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS approvals (
	id TEXT PRIMARY KEY,
	operation_id TEXT NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
	provider TEXT NOT NULL,
	external_ticket_id TEXT NOT NULL DEFAULT '',
	external_ticket_url TEXT NOT NULL DEFAULT '',
	token_hash TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL,
	target_ref TEXT NOT NULL,
	system_slug TEXT NOT NULL,
	environment_code TEXT NOT NULL,
	engine TEXT NOT NULL,
	actor TEXT NOT NULL,
	reason TEXT NOT NULL DEFAULT '',
	workspace_cwd TEXT NOT NULL DEFAULT '',
	query_text TEXT NOT NULL,
	risk_level TEXT NOT NULL,
	trigger_reasons_json TEXT NOT NULL DEFAULT '[]',
	matched_rules_json TEXT NOT NULL DEFAULT '[]',
	preflight_json TEXT NOT NULL DEFAULT '',
	reviewer TEXT NOT NULL DEFAULT '',
	reviewer_note TEXT NOT NULL DEFAULT '',
	created_at_utc TEXT NOT NULL,
	expires_at_utc TEXT NOT NULL,
	resolved_at_utc TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS audit_logs (
	seq INTEGER PRIMARY KEY AUTOINCREMENT,
	id TEXT NOT NULL UNIQUE,
	actor TEXT NOT NULL,
	action TEXT NOT NULL,
	target_id TEXT NOT NULL,
	operation_id TEXT NOT NULL DEFAULT '',
	payload_json TEXT NOT NULL,
	prev_hash TEXT NOT NULL,
	entry_hash TEXT NOT NULL,
	created_at_utc TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS audit_logs_no_update
BEFORE UPDATE ON audit_logs
BEGIN
	SELECT RAISE(ABORT, 'audit_logs is append-only');
END;

CREATE TRIGGER IF NOT EXISTS audit_logs_no_delete
BEFORE DELETE ON audit_logs
BEGIN
	SELECT RAISE(ABORT, 'audit_logs is append-only');
END;

CREATE TABLE IF NOT EXISTS risk_pattern_rules (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	scope_type TEXT NOT NULL,
	scope_id TEXT NOT NULL,
	enabled INTEGER NOT NULL DEFAULT 1,
	builtin_pack TEXT NOT NULL DEFAULT '',
	engines_json TEXT NOT NULL DEFAULT '[]',
	families_json TEXT NOT NULL DEFAULT '[]',
	action TEXT NOT NULL,
	confirm_title TEXT NOT NULL DEFAULT '',
	confirm_message TEXT NOT NULL DEFAULT '',
	approval_provider TEXT NOT NULL DEFAULT '',
	condition_json TEXT NOT NULL DEFAULT '{}',
	priority INTEGER NOT NULL DEFAULT 0,
	created_at_utc TEXT NOT NULL,
	updated_at_utc TEXT NOT NULL,
	UNIQUE(scope_type, scope_id, name)
);

CREATE INDEX IF NOT EXISTS idx_operations_created ON operations(created_at_utc DESC);
CREATE INDEX IF NOT EXISTS idx_operations_status ON operations(status);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status, created_at_utc DESC);
CREATE INDEX IF NOT EXISTS idx_approvals_operation ON approvals(operation_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(seq DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action, seq DESC);
CREATE INDEX IF NOT EXISTS idx_policies_scope ON policies(scope_type, scope_id);
CREATE INDEX IF NOT EXISTS idx_targets_alias ON targets(alias);
CREATE INDEX IF NOT EXISTS idx_risk_patterns_scope ON risk_pattern_rules(scope_type, scope_id);
`
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("apply sqlite schema: %w", err)
	}
	if err := s.ensureColumnLocked(ctx, "operations", "matched_rules_json", "TEXT NOT NULL DEFAULT '[]'"); err != nil {
		return err
	}
	if err := s.ensureColumnLocked(ctx, "approvals", "matched_rules_json", "TEXT NOT NULL DEFAULT '[]'"); err != nil {
		return err
	}
	if err := s.ensureColumnLocked(ctx, "instances", "capabilities_json", "TEXT NOT NULL DEFAULT '{}'"); err != nil {
		return err
	}
	if err := s.ensureColumnLocked(ctx, "instances", "capabilities_detected_at_utc", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumnLocked(ctx, "global_security_config", "require_reason_for_approval", "INTEGER NOT NULL DEFAULT 1"); err != nil {
		return err
	}
	if err := s.ensureColumnLocked(ctx, "systems", "git_remotes_json", "TEXT NOT NULL DEFAULT '[]'"); err != nil {
		return err
	}
	if err := s.ensureColumnLocked(ctx, "policies", "scan_read_mode", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumnLocked(ctx, "network_profiles", "scope_type", "TEXT NOT NULL DEFAULT 'global'"); err != nil {
		return err
	}
	if err := s.ensureColumnLocked(ctx, "network_profiles", "scope_id", "TEXT NOT NULL DEFAULT 'global'"); err != nil {
		return err
	}
	if err := s.ensureColumnLocked(ctx, "credential_profiles", "scope_type", "TEXT NOT NULL DEFAULT 'global'"); err != nil {
		return err
	}
	if err := s.ensureColumnLocked(ctx, "credential_profiles", "scope_id", "TEXT NOT NULL DEFAULT 'global'"); err != nil {
		return err
	}
	if err := s.ensureColumnLocked(ctx, "instances", "scope_type", "TEXT NOT NULL DEFAULT 'global'"); err != nil {
		return err
	}
	if err := s.ensureColumnLocked(ctx, "instances", "scope_id", "TEXT NOT NULL DEFAULT 'global'"); err != nil {
		return err
	}
	if err := s.ensureColumnLocked(ctx, "global_security_config", "forbid_self_approval", "INTEGER NOT NULL DEFAULT 1"); err != nil {
		return err
	}
	for _, col := range []struct{ name, def string }{
		{"principal_id", "TEXT NOT NULL DEFAULT ''"},
		{"principal_kind", "TEXT NOT NULL DEFAULT ''"},
		{"owner_user_id", "TEXT NOT NULL DEFAULT ''"},
		{"owner_node_id", "TEXT NOT NULL DEFAULT ''"},
		{"lease_expires_at_utc", "TEXT NOT NULL DEFAULT ''"},
		{"cancel_requested_at_utc", "TEXT NOT NULL DEFAULT ''"},
	} {
		if err := s.ensureColumnLocked(ctx, "operations", col.name, col.def); err != nil {
			return err
		}
	}
	if err := s.ensureColumnLocked(ctx, "approvals", "principal_id", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumnLocked(ctx, "approvals", "reviewer_user_id", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}

	const csSchema = `
CREATE TABLE IF NOT EXISTS users (
	id TEXT PRIMARY KEY,
	email TEXT NOT NULL UNIQUE,
	display_name TEXT NOT NULL DEFAULT '',
	oidc_issuer TEXT NOT NULL DEFAULT '',
	oidc_subject TEXT NOT NULL DEFAULT '',
	password_hash TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL DEFAULT 'active',
	created_at_utc TEXT NOT NULL,
	updated_at_utc TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_oidc_identity ON users(oidc_issuer, oidc_subject)
WHERE oidc_issuer <> '' AND oidc_subject <> '';

CREATE TABLE IF NOT EXISTS role_bindings (
	id TEXT PRIMARY KEY,
	user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	role TEXT NOT NULL,
	scope_type TEXT NOT NULL,
	scope_id TEXT NOT NULL DEFAULT '',
	created_by TEXT NOT NULL DEFAULT '',
	created_at_utc TEXT NOT NULL,
	UNIQUE(user_id, role, scope_type, scope_id)
);

CREATE TABLE IF NOT EXISTS api_tokens (
	id TEXT PRIMARY KEY,
	user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	name TEXT NOT NULL,
	token_prefix TEXT NOT NULL,
	token_hash TEXT NOT NULL UNIQUE,
	principal_kind TEXT NOT NULL DEFAULT 'agent_token',
	role_ceiling TEXT NOT NULL DEFAULT '',
	allowed_systems_json TEXT NOT NULL DEFAULT '[]',
	allowed_envs_json TEXT NOT NULL DEFAULT '[]',
	read_only_forced INTEGER NOT NULL DEFAULT 0,
	expires_at_utc TEXT NOT NULL DEFAULT '',
	last_used_at_utc TEXT NOT NULL DEFAULT '',
	revoked_at_utc TEXT NOT NULL DEFAULT '',
	created_at_utc TEXT NOT NULL,
	UNIQUE(user_id, name)
);

CREATE TABLE IF NOT EXISTS web_sessions (
	id_hash TEXT PRIMARY KEY,
	user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	csrf_token_hash TEXT NOT NULL,
	expires_at_utc TEXT NOT NULL,
	created_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS oidc_auth_states (
	state_hash TEXT PRIMARY KEY,
	nonce TEXT NOT NULL,
	pkce_verifier TEXT NOT NULL,
	return_to TEXT NOT NULL DEFAULT '/',
	expires_at_utc TEXT NOT NULL,
	created_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cli_device_codes (
	device_code_hash TEXT PRIMARY KEY,
	user_code TEXT NOT NULL UNIQUE,
	status TEXT NOT NULL DEFAULT 'pending',
	user_id TEXT NOT NULL DEFAULT '',
	expires_at_utc TEXT NOT NULL,
	created_at_utc TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cli_device_codes_user_code ON cli_device_codes(user_code);

CREATE TABLE IF NOT EXISTS encrypted_secrets (
	secret_key TEXT PRIMARY KEY,
	key_version INTEGER NOT NULL DEFAULT 1,
	nonce BLOB NOT NULL,
	ciphertext BLOB NOT NULL,
	updated_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS webhook_callback_nonces (
	provider TEXT NOT NULL,
	event_id TEXT NOT NULL,
	expires_at_utc TEXT NOT NULL,
	PRIMARY KEY(provider, event_id)
);

CREATE TABLE IF NOT EXISTS operation_results (
	operation_id TEXT PRIMARY KEY,
	result_json BLOB NOT NULL,
	expires_at_utc TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_operations_lease ON operations(status, lease_expires_at_utc);
CREATE INDEX IF NOT EXISTS idx_role_bindings_user ON role_bindings(user_id);
CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_web_sessions_user ON web_sessions(user_id);
`
	if _, err := s.db.ExecContext(ctx, csSchema); err != nil {
		return fmt.Errorf("apply sqlite c/s schema: %w", err)
	}
	if err := s.ensureColumnLocked(ctx, "api_tokens", "principal_kind", "TEXT NOT NULL DEFAULT 'agent_token'"); err != nil {
		return err
	}

	now := nowUTC()
	if _, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO schema_migrations(version, applied_at_utc) VALUES (1, ?), (2, ?), (3, ?), (4, ?), (5, ?), (6, ?), (7, ?)`, now, now, now, now, now, now, now); err != nil {
		return fmt.Errorf("record schema migration: %w", err)
	}
	return nil
}

func (s *Store) isCurrentSQLiteSchema(ctx context.Context) bool {
	var hasMig int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM schema_migrations WHERE version = 7`).Scan(&hasMig); err != nil || hasMig == 0 {
		return false
	}
	var hasLatestTbl int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name='operation_results'`).Scan(&hasLatestTbl); err != nil || hasLatestTbl == 0 {
		return false
	}
	return true
}

func (s *Store) ensureColumnLocked(ctx context.Context, table, column, colDef string) error {
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return fmt.Errorf("inspect %s columns: %w", table, err)
	}
	defer func() { _ = rows.Close() }()
	found := false
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return fmt.Errorf("scan %s column: %w", table, err)
		}
		if strings.EqualFold(name, column) {
			found = true
			break
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if !found {
		if _, err := s.db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, colDef)); err != nil {
			return fmt.Errorf("add %s.%s column (%s): %w", table, column, colDef, err)
		}
	}
	return nil
}

func (s *Store) seedDefaults(ctx context.Context) error {
	var secCount, envCount int
	if err := s.dbQueryRow(ctx, `SELECT COUNT(1) FROM global_security_config`).Scan(&secCount); err == nil && secCount > 0 {
		if err := s.dbQueryRow(ctx, `SELECT COUNT(1) FROM environments`).Scan(&envCount); err == nil && envCount > 0 {
			return nil
		}
	}
	return s.withTx(ctx, func(tx *sql.Tx) error {
		var count int
		if err := s.txQueryRow(ctx, tx, `SELECT COUNT(1) FROM global_security_config`).Scan(&count); err != nil {
			return err
		}
		now := nowUTC()
		if count == 0 {
			_, err := s.txExec(ctx, tx, `
				INSERT INTO global_security_config(
					id, exec_timeout_sec, approval_timeout_sec, max_rows, max_bytes,
					explain_max_rows, prod_read_only_freeze, block_multi_statement_in_prod,
					default_approval_provider, redact_audit_literals, require_reason_for_approval, forbid_self_approval, updated_at_utc
				) VALUES (1, 15, 120, 200, 262144, 100000, 0, 1, 'local-web', 1, 1, 1, ?)`, now)
			if err != nil {
				return err
			}
			if err := s.appendAuditTx(ctx, tx, "system", "global_security.init", "global", "", map[string]any{"version": 1}, now); err != nil {
				return err
			}
		}

		var envCount int
		if err := s.txQueryRow(ctx, tx, `SELECT COUNT(1) FROM environments`).Scan(&envCount); err != nil {
			return err
		}
		if envCount == 0 {
			defaults := []types.Environment{
				{
					Code:       "dev",
					SafetyTier: types.SafetyTierYOLO,
					Labels:     map[string]string{"en": "Development", "zh": "开发环境"},
					Color:      "#16A34A",
					SortOrder:  10,
				},
				{
					Code:       "staging",
					SafetyTier: types.SafetyTierGuarded,
					Labels:     map[string]string{"en": "Staging", "zh": "预发环境"},
					Color:      "#D97706",
					SortOrder:  20,
				},
				{
					Code:       "prod",
					SafetyTier: types.SafetyTierStrict,
					Labels:     map[string]string{"en": "Production", "zh": "生产环境"},
					Color:      "#DC2626",
					SortOrder:  30,
				},
			}
			for _, env := range defaults {
				labelsJSON, _ := json.Marshal(env.Labels)
				if _, err := s.txExec(ctx, tx, `
					INSERT INTO environments(code, safety_tier, labels_json, color, sort_order, default_policy_id, created_at_utc, updated_at_utc)
					VALUES (?, ?, ?, ?, ?, '', ?, ?)`,
					env.Code, string(env.SafetyTier), string(labelsJSON), env.Color, env.SortOrder, now, now); err != nil {
					return err
				}
				if err := s.appendAuditTx(ctx, tx, "system", "environment.seed", env.Code, "", env, now); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func (s *Store) withTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	if !s.isPG() {
		s.writeMu.Lock()
		defer s.writeMu.Unlock()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	batch := &auditBatch{}
	s.batchMu.Lock()
	if s.txBatches == nil {
		s.txBatches = make(map[*sql.Tx]*auditBatch)
	}
	s.txBatches[tx] = batch
	s.batchMu.Unlock()
	defer func() {
		s.batchMu.Lock()
		delete(s.txBatches, tx)
		s.batchMu.Unlock()
	}()

	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	// Flush all buffered audit entries at the very end of the transaction so
	// PostgreSQL locks audit_chain_head strictly after business rows (deadlock-free).
	if err := s.flushAuditBatchTx(ctx, tx, batch); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (s *Store) appendAuditTx(ctx context.Context, tx *sql.Tx, actor, action, targetID, opID string, payload any, ts string) error {
	if actor == "" {
		actor = "human"
	}
	if ts == "" {
		ts = nowUTC()
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	item := pendingAudit{
		actor:    actor,
		action:   action,
		targetID: targetID,
		opID:     opID,
		payload:  string(payloadBytes),
		ts:       ts,
	}

	s.batchMu.Lock()
	batch := s.txBatches[tx]
	s.batchMu.Unlock()
	if batch != nil {
		batch.items = append(batch.items, item)
		return nil
	}
	return s.flushAuditBatchTx(ctx, tx, &auditBatch{items: []pendingAudit{item}})
}

func (s *Store) flushAuditBatchTx(ctx context.Context, tx *sql.Tx, batch *auditBatch) error {
	if batch == nil || len(batch.items) == 0 {
		return nil
	}
	var prevSeq int64
	var prevHash string
	if s.isPG() {
		err := s.txQueryRow(ctx, tx, `SELECT last_seq, last_hash FROM audit_chain_head WHERE id = 1 FOR UPDATE`).Scan(&prevSeq, &prevHash)
		if errors.Is(err, sql.ErrNoRows) {
			if _, insErr := s.txExec(ctx, tx, `INSERT INTO audit_chain_head(id, last_seq, last_hash) VALUES (1, 0, ?) ON CONFLICT(id) DO NOTHING`, audit.GenesisPrevHash); insErr != nil {
				return insErr
			}
			// Re-select FOR UPDATE so concurrent cold-start transactions serialize on row id=1.
			if selErr := s.txQueryRow(ctx, tx, `SELECT last_seq, last_hash FROM audit_chain_head WHERE id = 1 FOR UPDATE`).Scan(&prevSeq, &prevHash); selErr != nil {
				return selErr
			}
		} else if err != nil {
			return err
		}
	} else {
		err := s.txQueryRow(ctx, tx, `SELECT seq, entry_hash FROM audit_logs ORDER BY seq DESC LIMIT 1`).Scan(&prevSeq, &prevHash)
		if errors.Is(err, sql.ErrNoRows) {
			prevSeq = 0
			prevHash = audit.GenesisPrevHash
		} else if err != nil {
			return err
		}
	}

	for _, it := range batch.items {
		nextSeq := prevSeq + 1
		id := newID("aud")
		entryHash := audit.ComputeEntryHash(nextSeq, prevHash, it.actor, it.action, it.targetID, it.opID, it.payload, it.ts)
		if _, err := s.txExec(ctx, tx, `
			INSERT INTO audit_logs(seq, id, actor, action, target_id, operation_id, payload_json, prev_hash, entry_hash, created_at_utc)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			nextSeq, id, it.actor, it.action, it.targetID, it.opID, it.payload, prevHash, entryHash, it.ts); err != nil {
			return err
		}
		prevSeq = nextSeq
		prevHash = entryHash
	}

	if s.isPG() {
		if _, err := s.txExec(ctx, tx, `UPDATE audit_chain_head SET last_seq = ?, last_hash = ? WHERE id = 1`, prevSeq, prevHash); err != nil {
			return err
		}
	}
	batch.items = nil
	return nil
}

func nowUTC() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func newID(prefix string) string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return prefix + "_" + hex.EncodeToString(b[:])
}
