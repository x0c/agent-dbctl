package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/x0c/agent-dbctl/internal/audit"
)

// Dialect identifies the backing SQL engine for Store.
type Dialect string

const (
	DialectSQLite   Dialect = "sqlite"
	DialectPostgres Dialect = "postgres"
)

func (s *Store) isPG() bool {
	return s.dialect == DialectPostgres
}

func (s *Store) likeOp() string {
	if s.isPG() {
		return "ILIKE"
	}
	return "LIKE"
}

func (s *Store) forUpdateClause() string {
	if s.isPG() {
		return " FOR UPDATE"
	}
	return ""
}

func (s *Store) q(query string) string {
	if !s.isPG() {
		return query
	}
	return rebindPostgres(query)
}

func (s *Store) dbExec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if !s.isPG() {
		// A standalone commit between a deferred transaction's first read and
		// write invalidates that snapshot with SQLITE_BUSY_SNAPSHOT. Share the
		// same writer lock used by withTx so every SQLite writer is serialized.
		s.writeMu.Lock()
		defer s.writeMu.Unlock()
	}
	return s.db.ExecContext(ctx, s.q(query), args...)
}

func (s *Store) dbQuery(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return s.db.QueryContext(ctx, s.q(query), args...)
}

func (s *Store) dbQueryRow(ctx context.Context, query string, args ...any) *sql.Row {
	return s.db.QueryRowContext(ctx, s.q(query), args...)
}

func (s *Store) txExec(ctx context.Context, tx *sql.Tx, query string, args ...any) (sql.Result, error) {
	return tx.ExecContext(ctx, s.q(query), args...)
}

func (s *Store) txQuery(ctx context.Context, tx *sql.Tx, query string, args ...any) (*sql.Rows, error) {
	return tx.QueryContext(ctx, s.q(query), args...)
}

func (s *Store) txQueryRow(ctx context.Context, tx *sql.Tx, query string, args ...any) *sql.Row {
	return tx.QueryRowContext(ctx, s.q(query), args...)
}

// rebindPostgres converts ? placeholders to $1, $2, ... outside single-quoted SQL literals.
func rebindPostgres(query string) string {
	if !strings.ContainsRune(query, '?') {
		return query
	}
	var b strings.Builder
	b.Grow(len(query) + 16)
	inSingle := false
	argIdx := 1
	for i := 0; i < len(query); i++ {
		ch := query[i]
		if ch == '\'' {
			b.WriteByte(ch)
			if inSingle && i+1 < len(query) && query[i+1] == '\'' {
				b.WriteByte(query[i+1])
				i++
				continue
			}
			inSingle = !inSingle
			continue
		}
		if ch == '?' && !inSingle {
			_, _ = fmt.Fprintf(&b, "$%d", argIdx)
			argIdx++
			continue
		}
		b.WriteByte(ch)
	}
	return b.String()
}

func isUniqueErr(err error) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return true
	}
	msg := strings.ToUpper(err.Error())
	return strings.Contains(msg, "UNIQUE") || strings.Contains(msg, "23505")
}

const postgresSchemaVersion = 7

// OpenPostgres initializes a Store with migrations and defaults under the schema owner.
func OpenPostgres(ctx context.Context, dsn string) (*Store, error) {
	return openPostgres(ctx, dsn, true)
}

// OpenPreparedPostgres opens a migrated store without schema or bootstrap writes.
func OpenPreparedPostgres(ctx context.Context, dsn string) (*Store, error) {
	return openPostgres(ctx, dsn, false)
}

func openPostgres(ctx context.Context, dsn string, migrate bool) (*Store, error) {
	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("invalid PostgreSQL store DSN")
	}
	if poolCfg.MaxConns == 0 || poolCfg.MaxConns < 16 {
		poolCfg.MaxConns = 32
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("connect postgres store: %w", err)
	}
	db := stdlib.OpenDBFromPool(pool)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		pool.Close()
		return nil, fmt.Errorf("ping postgres store: %w", err)
	}

	s := &Store{
		db:        db,
		pgPool:    pool,
		dialect:   DialectPostgres,
		txBatches: make(map[*sql.Tx]*auditBatch),
	}
	if migrate {
		if err := s.migratePostgres(ctx); err != nil {
			_ = s.Close()
			return nil, err
		}
		if err := s.seedDefaults(ctx); err != nil {
			_ = s.Close()
			return nil, err
		}
	} else {
		var version int
		err := db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&version)
		if err != nil || version != postgresSchemaVersion {
			_ = s.Close()
			return nil, fmt.Errorf("PostgreSQL schema must be at version %d; run serve --migrate-only with the schema owner first", postgresSchemaVersion)
		}
	}
	return s, nil
}

func (s *Store) migratePostgres(ctx context.Context) error {
	// Serialize concurrent replica migrations with a cluster-wide advisory lock.
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	const migrationLockKey int64 = 0x61646263746c01 // "adbctl\x01"
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, migrationLockKey); err != nil {
		return fmt.Errorf("acquire postgres migration lock: %w", err)
	}
	defer func() {
		_, _ = conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, migrationLockKey)
	}()

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
	scope_type TEXT NOT NULL DEFAULT 'global',
	scope_id TEXT NOT NULL DEFAULT 'global',
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
	scope_type TEXT NOT NULL DEFAULT 'global',
	scope_id TEXT NOT NULL DEFAULT 'global',
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
	scope_type TEXT NOT NULL DEFAULT 'global',
	scope_id TEXT NOT NULL DEFAULT 'global',
	engine TEXT NOT NULL,
	host TEXT NOT NULL DEFAULT '',
	port INTEGER NOT NULL DEFAULT 0,
	role TEXT NOT NULL DEFAULT 'standalone',
	primary_instance_id TEXT NOT NULL DEFAULT '',
	network_profile_id TEXT NOT NULL DEFAULT '',
	tls_mode TEXT NOT NULL DEFAULT '',
	params_json TEXT NOT NULL DEFAULT '{}',
	capabilities_json TEXT NOT NULL DEFAULT '{}',
	capabilities_detected_at_utc TEXT NOT NULL DEFAULT '',
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
	max_bytes BIGINT,
	explain_max_rows BIGINT,
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
	max_bytes BIGINT NOT NULL,
	explain_max_rows BIGINT NOT NULL,
	prod_read_only_freeze INTEGER NOT NULL,
	block_multi_statement_in_prod INTEGER NOT NULL,
	default_approval_provider TEXT NOT NULL,
	redact_audit_literals INTEGER NOT NULL,
	require_reason_for_approval INTEGER NOT NULL DEFAULT 1,
	forbid_self_approval INTEGER NOT NULL DEFAULT 1,
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
	principal_id TEXT NOT NULL DEFAULT '',
	principal_kind TEXT NOT NULL DEFAULT '',
	owner_user_id TEXT NOT NULL DEFAULT '',
	owner_node_id TEXT NOT NULL DEFAULT '',
	lease_expires_at_utc TEXT NOT NULL DEFAULT '',
	cancel_requested_at_utc TEXT NOT NULL DEFAULT '',
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
	affected_rows BIGINT,
	truncated INTEGER NOT NULL DEFAULT 0,
	cutoff_reason TEXT NOT NULL DEFAULT '',
	latency_ms BIGINT NOT NULL DEFAULT 0,
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
	principal_id TEXT NOT NULL DEFAULT '',
	reason TEXT NOT NULL DEFAULT '',
	workspace_cwd TEXT NOT NULL DEFAULT '',
	query_text TEXT NOT NULL,
	risk_level TEXT NOT NULL,
	trigger_reasons_json TEXT NOT NULL DEFAULT '[]',
	matched_rules_json TEXT NOT NULL DEFAULT '[]',
	preflight_json TEXT NOT NULL DEFAULT '',
	reviewer TEXT NOT NULL DEFAULT '',
	reviewer_user_id TEXT NOT NULL DEFAULT '',
	reviewer_note TEXT NOT NULL DEFAULT '',
	created_at_utc TEXT NOT NULL,
	expires_at_utc TEXT NOT NULL,
	resolved_at_utc TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS audit_logs (
	seq BIGINT PRIMARY KEY,
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

CREATE TABLE IF NOT EXISTS audit_chain_head (
	id SMALLINT PRIMARY KEY CHECK (id = 1),
	last_seq BIGINT NOT NULL,
	last_hash TEXT NOT NULL
);

CREATE OR REPLACE FUNCTION audit_logs_append_only_fn() RETURNS trigger AS $$
BEGIN
	RAISE EXCEPTION 'audit_logs is append-only';
END;
$$ LANGUAGE plpgsql;

DO $$
BEGIN
	IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'audit_logs_no_update') THEN
		CREATE TRIGGER audit_logs_no_update BEFORE UPDATE ON audit_logs FOR EACH ROW EXECUTE FUNCTION audit_logs_append_only_fn();
	END IF;
	IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'audit_logs_no_delete') THEN
		CREATE TRIGGER audit_logs_no_delete BEFORE DELETE ON audit_logs FOR EACH ROW EXECUTE FUNCTION audit_logs_append_only_fn();
	END IF;
END $$;

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
	nonce BYTEA NOT NULL,
	ciphertext BYTEA NOT NULL,
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
	result_json BYTEA NOT NULL,
	expires_at_utc TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_operations_created ON operations(created_at_utc DESC);
CREATE INDEX IF NOT EXISTS idx_operations_status ON operations(status);
CREATE INDEX IF NOT EXISTS idx_operations_lease ON operations(status, lease_expires_at_utc);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status, created_at_utc DESC);
CREATE INDEX IF NOT EXISTS idx_approvals_operation ON approvals(operation_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(seq DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action, seq DESC);
CREATE INDEX IF NOT EXISTS idx_policies_scope ON policies(scope_type, scope_id);
CREATE INDEX IF NOT EXISTS idx_targets_alias ON targets(alias);
CREATE INDEX IF NOT EXISTS idx_risk_patterns_scope ON risk_pattern_rules(scope_type, scope_id);
CREATE INDEX IF NOT EXISTS idx_role_bindings_user ON role_bindings(user_id);
CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_web_sessions_user ON web_sessions(user_id);
`
	if _, err := conn.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("apply postgres schema: %w", err)
	}
	if _, err := conn.ExecContext(ctx, `ALTER TABLE api_tokens ADD COLUMN IF NOT EXISTS principal_kind TEXT NOT NULL DEFAULT 'agent_token'`); err != nil {
		return fmt.Errorf("migrate api_tokens.principal_kind: %w", err)
	}
	if _, err := conn.ExecContext(ctx, `
		INSERT INTO audit_chain_head(id, last_seq, last_hash)
		VALUES (1, COALESCE((SELECT MAX(seq) FROM audit_logs), 0), COALESCE((SELECT entry_hash FROM audit_logs ORDER BY seq DESC LIMIT 1), $1))
		ON CONFLICT(id) DO NOTHING`, audit.GenesisPrevHash); err != nil {
		return fmt.Errorf("init audit_chain_head: %w", err)
	}
	now := nowUTC()
	if _, err := conn.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at_utc) VALUES (1, $1), (2, $1), (3, $1), (4, $1), (5, $1), (6, $1), (7, $1) ON CONFLICT DO NOTHING`, now); err != nil {
		return fmt.Errorf("record postgres schema migrations: %w", err)
	}
	return nil
}
