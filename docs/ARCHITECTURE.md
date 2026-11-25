# agent-dbctl Architecture

## 1. Product Positioning & Scope Boundary

`agent-dbctl` is a single-binary local database execution gate, enterprise system/database catalog, and audit console built for both human engineers and coding agents:

- **Agents** interact through the `agent-dbctl` CLI (and companion `SKILL.md`) with non-interactive structured JSON output, automatic workspace-to-system resolution, risk preflight, and full auditability.
- **Humans** manage systems, environments, network profiles, credentials, database targets, safety guardrails, production approvals, and audit trails through an embedded TypeScript Web Console served locally on `127.0.0.1` (`go:embed`).
- **Strict Boundary**: `agent-dbctl` forwards queries/commands **verbatim** to each database engine. It does **not** perform cross-dialect SQL translation or ORM-style query rewriting.

### Reference Attribution & Exclusions

The architecture adapts proven mechanisms from three open-source references while explicitly excluding features outside scope:

- **`bytebase/omni` (MIT, Go)**: Adopted the clean split between "reaching the server" (resolved credentials, TLS, custom `Dial`) and "engine protocol conversation" (`Driver`/`Conn`, typed `Value`, `Result.Truncated`, `Plan`), plus engine-aware read/write/DDL/high-cost classification principles across SQL, MongoDB, and Redis. Excluded Bytebase's schema migration/GitOps workflow and any enterprise-licensed modules.
- **`dbward-dev/dbward` (Apache-2.0, Rust)**: Adopted first-class `--preflight` (`EXPLAIN` without `ANALYZE`), `CancellationGuard` (discard dirty pooled connections on timeout/cancel), in-memory TTL `ResultSlot` keeping query payloads out of the audit DB, and tamper-evident SHA-256 hash-chain audit logging. Excluded multi-node remote poll agents and database migration runners (`migrate up/down`).
- **`t8y2/dbx` (Apache-2.0, Rust)**: Adopted strict unidirectional package layering, `manifest.json` + SHA-256 + `host_api_version` verification for external driver plugins, and explicit `doctor`/`capabilities` probes. Excluded JVM/JDBC Java agents (strictly zero JVM), Tauri desktop shells, and CLI override flags (`--allow-writes`/`--allow-dangerous-sql`) so agents cannot self-escalate privileges.

---

## 2. High-Level Component Architecture

```text
CLI (agent-dbctl) ──[Unix Socket / Loopback RPC]──▶ Local On-Demand Daemon
                                                        │
Web Console (127.0.0.1 HTTP + SSE, go:embed) ───────────┼──▶ Catalog (SQLite WAL)
                                                        ├──▶ Secrets (Keychain / File / Env / Exec)
                                                        ├──▶ NetDial (Direct / SSH Bastion / SOCKS5 / HTTP Proxy)
                                                        ├──▶ Classify + Preflight (SQL / Mongo / Redis)
                                                        ├──▶ Policy Engine (4-level monotonic inheritance)
                                                        ├──▶ ApprovalManager (ApprovalProvider: local-web / webhook / extensible)
                                                        ├──▶ Audit (Append-only Hash Chain + ResultSlot)
                                                        └──▶ Driver Execution Plane
                                                               ├── Tier 1 Built-in Pure Go (PG, MySQL, SQLite, Mongo, Redis)
                                                               └── Tier 3 External gRPC Subprocess (hashicorp/go-plugin)
```

### Dependency Direction

`internal/types` -> `internal/config` / `internal/secrets` / `internal/netdial` / `internal/classify` -> `internal/driver` -> `internal/store` / `internal/audit` / `internal/policy` / `internal/approval` -> `internal/daemon` -> `internal/cli` / `cmd/*`.

Lower layers never import `daemon` or `cli`.

---

## 3. Enterprise Database Asset Management (Four-Layer Catalog)

Enterprise environments involve multiple business systems, shared jump hosts, primary/replica topologies, and multi-database instances. `agent-dbctl` models assets in four decoupled layers:

1. **System (`systems`)**:
   - Logical business system (`id`, `slug`, `name`, `owner`, `description`, `tags`, `workspace_paths`).
   - `workspace_paths` binds local repository paths (e.g. `~/Codes/order-core`, with `~/` expanded against the active home directory) to the system so `agent-dbctl db list` automatically prioritizes databases belonging to or linked with the agent's current working directory.
2. **Environment (`environments`)**:
   - Classifications such as `dev`, `staging`, `prod`, each carrying `safety_tier` (`yolo` | `guarded` | `strict`), server-driven localized labels (`en`, `zh`), `#RRGGBB` display color, display order, and `default_policy_id`.
3. **NetworkProfile (`network_profiles`) & CredentialProfile (`credential_profiles`)**:
   - **NetworkProfile**: Reusable connectivity template (`direct`, `ssh_tunnel` bastion, `socks5`, `http_proxy`, TLS mode). Multiple instances share one bastion definition.
   - **CredentialProfile**: Reusable auth definition (`keychain`, `env_ref`, `exec_provider`), `access_level` (`read_only` | `read_write`). Actual secrets live strictly in the OS Keychain (macOS `security -i` over stdin, rejecting whitespace, quotes, and control chars on service/account names), env vars, or shell-free quote-aware external secret-manager commands (`SplitExecArgs`, 64 KiB stdout cap, no secret echo on errors)—never in SQLite or CLI output.
4. **Instance (`instances`) & Target (`targets`)**:
   - **Instance**: Physical/logical endpoint (`engine`, `host`, `port`, `role`: `primary` | `replica` | `standalone`, `primary_instance_id`, `network_profile_id`). Supports live database/schema discovery (`POST /api/v1/instances/{id}/discover`).
   - **Target**: Logical addressable target (`ref` e.g. `order-core/prod/orders`, short `alias` e.g. `prod-orders`, `owner_system_id`, many-to-many `linked_system_ids`, `instance_id`, `database_name`, `ro_credential_id`, `rw_credential_id`, `policy_override_id`, `status`: `active` | `maintenance` | `disabled`). Supports concurrent fleet connectivity probing (`agent-dbctl db test --all` / `POST /api/v1/targets/test-all` via bounded 8-worker `Service.PingTargets`).

### Sanitized Topology Portability

`GET/POST /api/v1/topology` exports and imports `System`, `Environment`, `NetworkProfile`, `CredentialProfile` metadata (without secrets), `Instance`, `Target`, `Policy`, and `RiskPatternRule` definitions as YAML or JSON so teams can share catalog topology and custom high-risk detection rules via Git while keeping credentials local or vault-backed. `ImportTopology` executes inside a single atomic SQLite transaction (validating `schema_version <= 1` and writing a `topology.import` audit entry), and deleting referenced `NetworkProfile`, `CredentialProfile`, or `PolicyRuleSet` records returns `ErrConflict`.

---

## 4. Pluggable Drivers, Classification & Policy Engine

### Driver Tiers (Zero JVM)

- **Tier 1 (Built-in Pure Go, `CGO_ENABLED=0`)**: PostgreSQL (`pgx/v5`), MySQL / MariaDB / TiDB (`go-sql-driver/mysql` via per-connection `mysql.NewConnector`), SQLite (`modernc.org/sqlite`), MongoDB (`mongo-go-driver/v2`), Redis / Valkey (`go-redis/v9`). Drivers adapt across server versions and restricted privilege tiers (e.g., `EXPLAIN` JSON/tree/tabular fallbacks, `transaction_read_only`/`tx_read_only`, `hello`/`isMaster`/`buildInfo` probes, RESP2/RESP3 normalization, and PgBouncer `exec_mode=simple_protocol`).
- **Tier 3 (External gRPC Subprocess Plugins)**: Loaded via `hashicorp/go-plugin` over gRPC (`VersionedPlugins`, supporting both `v1` `Struct` and `v2` typed Protobuf + `Cancel` RPC at `host_api_version: 1..2`) from `<config_home>/plugins/<id>/manifest.json`. Verified against `host_api_version` and binary SHA-256 before execution, with capability-gated host dispatch; crashes are isolated to the subprocess, and daemon-managed network tunnels (`ssh_tunnel`, `socks5`, `http_proxy`) are bridged over an ephemeral authenticated loopback forwarder when `DialContext` is active. See [PLUGIN_PROTOCOL.md](PLUGIN_PROTOCOL.md).

### Connection Lifecycle & Multi-Version Contracts

- **Per-Operation Lifecycle & Cancel Discard**: `Service.openDriverConn` currently resolves credentials and builds a `netdial` dialer per operation (`Ping`, `DiscoverInstance`, `Preflight`, `Execute`, with `Service.Execute` reusing one read-only connection from `Preflight` into `Execute`), wrapping cleanup hooks with `driver.CloseOnce`. On timeout or cancellation, `ExecuteWithCancelGuard` invokes `Conn.CancelAndDiscard()` (including when `ctx.Err() != nil` on the result branch); PostgreSQL issues `CancelRequest`, MySQL issues `KILL QUERY <connection_id>` over a short-lived side connection, and `v2` plugins issue an out-of-band `Cancel` RPC before closing.
- **Engine-Specific Multi-Version & Read-Only Enforcement**:
  - **PostgreSQL**: Builds `pgx.ConnConfig` directly (safe for IPv6 and special database names), supports `exec_mode=simple_protocol` for PgBouncer/proxies, protects `default_transaction_read_only=on` after `Params` when `ReadOnly` is true, queries `SELECT version()` first (fallback `SHOW server_version`) to negotiate dialect (`postgres`, `cockroachdb`, `redshift`, `yugabytedb`, `greenplum`, `alloydb`), skips `EXPLAIN (FORMAT JSON)` straight to text `EXPLAIN` when `!SupportsExplainJSON`, detects `Parallel Seq Scan` / `Foreign Scan` in JSON plans, and implements `SessionResetter` (`PgConn().TxStatus() == 'I'`).
  - **MySQL / MariaDB / TiDB**: Uses `mysql.NewConnector` (avoiding global `RegisterTLSConfig`/`RegisterDialContext` leaks), wraps `driver.Connector.Connect` to enforce `SET SESSION TRANSACTION READ ONLY` -> `tx_read_only = 1` -> `transaction_read_only = 1` on every physical connection (failing closed if all fail), blocks `MultiStatements`/`AllowAllFiles`/`AllowCleartextPasswords` overrides in read-only mode, detects dialect (`mysql`, `mariadb`, `tidb`, `oceanbase_mysql`, `starrocks`, `doris`), fast-paths to tabular `EXPLAIN` when `!SupportsExplainJSON`, parses MySQL v1 JSON, MySQL 8.4 `explain_json_format_version=2`, MariaDB `rows`, and tabular `EXPLAIN` (MySQL 5.5 / TiDB), and implements `SessionResetter`.
  - **SQLite**: Encodes `file:` URIs cleanly, applies `mode=ro` + `query_only(1)` on non-`:memory:` read-only targets (preventing empty file creation on probes), honors allowlisted pragmas, Base64-encodes non-UTF-8 `BLOB` columns, and implements `Dialect`/`ServerCapabilities` + `SessionResetter`.
  - **MongoDB**: Iterates full cursors via `getMore` + `killCursors` cleanup, auto-enables `directConnection=true` when dialing a single host over a tunnel/proxy unless overridden, defaults `ReadOnly` to `SecondaryPreferred`, falls back `Ping` from `buildInfo` to `hello`/`isMaster` with dialect detection (`mongodb`, `documentdb`, `ferretdb`, `cosmosdb_mongo`) and `ListDatabases` to `authorizedDatabases: true`, normalizes `Decimal128`/`Timestamp`/`Regex`/non-finite floats, inspects only `queryPlanner.winningPlan` (unwrapping SBE `winningPlan.queryPlan`, sharded `shards[]`, and aggregation `stages[].$cursor`, ignoring `rejectedPlans`) where `LIMIT` (`0 < limit <= 1000`) -> `COLLSCAN` without blocking stages (`SORT*`, `SHARD_MERGE_SORT`, `GROUP`, `COUNT`, large `SKIP`) is treated as bounded (`FullScan = false`), skips `EXPLAIN` cleanly on `show dbs`/`show collections`, and warns explicitly when `mongosh` syntax is passed instead of JSON RunCommand.
  - **Redis / Valkey**: Uses `redis.NewUniversalClient` (standalone or `cluster=true` / comma-separated seeds, configurable `protocol=2|3`), falls back `Ping` past ACL-restricted `INFO server`, parses `INFO server` dialect banners (`valkey_version:`, `dragonfly_version:`, `keydb_version:`, `redis_version:`) for `ServerCapabilities` (`SupportsRESP3`, `ClusterMode`), normalizes RESP3 `map[any]any` for JSON marshaling, and caps single-command array/map replies via `RowBuffer`.

### Connection Pooling & Dialect Capabilities (Core Implemented; Daemon Wiring Pending)

1. **Implemented Primitives (Library & Driver Layer)**:
   - `internal/netdial.TunnelPool`: Keepalive-monitored (`keepalive@openssh.com` with bounded timer) `*ssh.Client` pool keyed by redacted `(network_profile_id, bastion_host, port, user, strict_host_key, sha256(secret))` fingerprint, single-flight dial deduplication, idle TTL eviction, automatic reconnect on dead transport, and `InvalidateProfile` / `InvalidateAll`.
   - `internal/driver.ConnPool`: Read-only `driver.Conn` pool with unconditional write bypass (`!ReadOnly`), SQLite `:memory:` bypass, shorter `ExecProviderMaxAge` (`2m` default; `< 0` disables) for `exec_provider` tokens, `SessionResetter` validation before reuse, permanent poison+discard on `CancelAndDiscard()` or cancelled contexts, `HealthCheckAfter` idle probing, and target/instance/network/credential invalidation.
   - `internal/driver.DetectServerCapabilities`, `types.ServerCapabilities`, `PingResult.Dialect` / `Capabilities`, and `driver.DialectAwareConn` across all 5 built-in drivers.
2. **Remaining Integration (Pending Daemon Wiring)**:
   - Wire `TunnelPool`, `ConnPool`, catalog-mutation invalidation hooks, and cached per-instance `ServerCapabilities` into `internal/daemon/service.go` (`openDriverConn`, `PingTarget`, `PingInstance`, `Shutdown`) and `internal/daemon/http_server.go` (deferred until active concurrent catalog/policy work releases those files).

### Risk Classification, Normalized Context & Preflight

- **Multi-statement safety**: Multi-statement SQL scripts are split respecting quotes, dollar-quotes, comments, and MySQL conditional comments; overall classification takes the maximum severity across all statements.
- **Fail-closed unknown syntax**: Unrecognized syntax is classified as `unknown` (`high_risk`), which still runs under `dev` (`yolo`) if allowed, but forces human approval under `guarded`/`strict` environments.
- **Hardened high-cost & dangerous read detection**:
  - **SQL**: missing `LIMIT` / `WHERE`, `SELECT *` without `WHERE`, `TABLE <tbl>` shorthand without `LIMIT`, `CROSS JOIN` & implicit comma joins (`FROM a, b`), `WITH RECURSIVE`, `ORDER BY RAND()/RANDOM()`, `SQL_CALC_FOUND_ROWS`, deep `OFFSET >= 10000`, locking reads (`FOR UPDATE`/`FOR SHARE`/`FOR NO KEY UPDATE`/`FOR KEY SHARE`/`LOCK IN SHARE MODE`), `EXPLAIN` & `EXPLAIN ANALYZE` inner-DML propagation (preserving `IsReadOnly = false` when analyzing DML/admin so `prod_read_only_freeze` still blocks it), SQLite parenthesized `PRAGMA fn(...)` allowlisting (`table_info`, `table_xinfo`, `index_list`, `index_info`, `index_xinfo`, `foreign_key_list` safe-read; mutating pragmas like `query_only(0)`/`wal_checkpoint` elevated to `admin`), and dangerous scalar/side-effect calls even without `FROM` (`pg_read_file`/`lo_export`/`dblink`/`load_extension` as `admin`, `nextval`/`setval`/`pg_advisory_lock`/`get_lock` as `write`, `pg_sleep`/`sleep`/`benchmark`/`randomblob`/`zeroblob`/`generate_series`/`xmlparse` as `high_cost_read`).
  - **MongoDB**: recursive operator scanning (`$where`, `$function`, `$accumulator`, `$lookup`/`$graphLookup`, `allowDiskUse`, `noCursorTimeout`, unanchored `$regex`), write stages (`$out`/`$merge`), and `explain` verbosity/inner-query checks (`executionStats`/`allPlansExecution`).
  - **Redis / Valkey**: subcommand allowlisting for `CLIENT` (`ID`/`GETNAME`/`INFO` safe; `LIST` high-cost; `PAUSE`/`KILL`/others admin) and `MEMORY` (`STATS`/`MALLOC-STATS`/`DOCTOR` safe; `USAGE ... SAMPLES 0` high-cost; `PURGE`/others admin), bounded `SCAN`/`ZRANGEBYSCORE`/`GEOSEARCH` count checks, and blocking list/stream commands.
- **Normalized `QueryContext` extraction**: `classify.ExtractQueryContext` exposes comment-stripped/literal-redacted text, parsed SQL tokens/functions/tables/pragmas, parsed Redis command vectors, and parsed MongoDB JSON documents/operators for downstream pattern evaluation.
- **Preflight (`EXPLAIN` without `ANALYZE`)**: In `guarded`/`strict` environments (or when an active `preflight_metric` pattern rule applies), safe reads undergo `EXPLAIN` preflight before execution; full scans (`Seq Scan`, `ALL`, uncapped MongoDB `COLLSCAN`, SQLite `SCAN`—excluding bounded MongoDB `LIMIT (<= 1000) -> COLLSCAN` without blocking stages) or estimated rows exceeding `explain_max_rows` escalate to `require_approval`, attaching the plan summary to the approval card. See [READ_RISK_AUDIT.md](READ_RISK_AUDIT.md) for empirically verified high-risk read patterns.

### Four-Level Monotonic Policy Inheritance & Custom High-Risk Patterns

Effective policy resolves in order: `GlobalSecurityConfig` -> `Environment` -> `System` -> `Target`.
Lower levels can **tighten** restrictions monotonically across both numeric ceilings (shorter timeout, lower row/byte cap, lower `explain_max_rows`) and boolean guardrails (`AllowSafeRead`, `RequireApprovalOn*`, `AllowMultiStatement`, with provenance tracked in `Sources`)—validated via `ValidateRuleSet` and `ValidateGlobalConfig`—but never exceed global hard upper bounds or override `prod_read_only_freeze`.

- **Configurable High-Risk Pattern Rules (`RiskPatternRule`)**: Layered atop the built-in classifier across `global -> env -> system -> target` scopes, filtered by target engine/family. Lower scopes can add rules or tighten actions (`elevate_high_cost -> require_approval -> deny`) and enrich confirmation copy/provider overrides, but cannot disable or weaken an enabled ancestor rule. Rules persist in SQLite (`risk_pattern_rules`) with same-transaction hash-chain audit logging and `/api/v1/topology` portability; CLI remains configuration-read-only.
- **Multi-Modal Composable Matchers**: Rules compose `all` / `any` / `not` conditions over 8 matcher types: `function_call`, `table_ref`, `pragma_name`, `command_arg`, `json_path`, `regex` (Go RE2 with AST node & length limits, defaulting to comment-stripped normalized queries), `risk_flag`, and `preflight_metric`.
- **Secondary Confirmation & Dry-Run Sandbox**: Matched `require_approval` rules force human approval even in `dev` (`yolo`) targets, surfacing structured `MatchedRule` details (`confirm_title`, `confirm_message`, `matched_fragment`, scope, action) in CLI JSON/hints, Web UI approval cards, webhooks, and `audit_logs`. The Web Console includes 5 official preset rule packs (`pg-side-effect`, `sqlite-pragma-blob`, `redis-single-thread`, `mongo-js-explain`, `mysql-dos-guard`) and an offline dry-run test sandbox (`POST /api/v1/risk-patterns/test`).

---

## 5. Pluggable Approval Abstraction (`ApprovalProvider`)

Approval workflow is decoupled behind `internal/approval.Provider`:

- **Built-in `local-web` provider**: Persists an approval record with a cryptographic one-time `approval_token` (stored hashed), broadcasts an SSE event, and opens `http://127.0.0.1:<port>/approvals/<id>?token=<token>` in the local browser (suppressed when `AGENT_DBCTL_NO_BROWSER=1`). `SanitizeTicketURL` strips `?token=` before persisting `external_ticket_url` in SQLite.
- **Built-in `webhook` provider**: Enabled via `AGENT_DBCTL_WEBHOOK_URL` (`https://` required for remote hosts; `http://` restricted to loopback), optional HMAC-SHA256 signing (`AGENT_DBCTL_WEBHOOK_SECRET` -> `X-Agent-DBCTL-Timestamp` + `X-Agent-DBCTL-Signature`), and `AGENT_DBCTL_WEBHOOK_TIMEOUT` (`5s` default, `30s` max). Posts redacted `approval.requested` (with token-free `review_url`) and `approval.cancelled` JSON payloads and accepts optional `{ticket_id, ticket_url}` fields from 2xx responses.
- **Lifecycle & restart recovery**: `ResolveApproval` enforces wall-clock expiry atomically (committing `expired` + audit row and returning `ErrApprovalExpired`); deadline watchers use `time.NewTimer` + stop/done channels for immediate daemon shutdown; `RecoverOnStartup` reconciles interrupted `running`/`pending` operations on daemon startup as `failed` (`daemon_restarted`, `retryable = is_read_only`), expires overdue approvals, and rehydrates still-valid pending approvals via `Manager.Rehydrate`.
- **Enterprise extensibility**: External approval flows (Feishu, WeCom, Slack, internal ticket APIs) implement `ApprovalProvider` (`Submit`, `Cancel`, external status sync), while fully air-gapped DMS platforms can be integrated as Tier-3 `Driver` plugins—preserving the exact CLI (`--wait=false` + `op status`/`op wait`) and audit contract.

---

## 6. Audit Integrity, Result Isolation & Security

- **SQLite WAL, `0600` Mode & Hash Chain**: `~/.config/agent-dbctl/agent-dbctl.db` (dir `0700`, explicit Unix `os.Chmod(dbPath, 0o600)` in `store.Open`) enables `PRAGMA journal_mode=WAL` and `busy_timeout=5000`, verified via readback on open. SQLite triggers forbid `UPDATE` and `DELETE` on `audit_logs`. Multi-engine lexical/JSON `RedactQuery` scrubs SQL literals, dollar-quotes, password clauses, URI credentials, Redis `AUTH`/`ACL SETUSER`/`CONFIG SET`, and MongoDB literal values (preserving collection names and `$` operators) before persistence. Each audit row chains `prev_hash` + `entry_hash` (SHA-256) and records `actor`, `action`, `target_id`, `operation_id`, `payload_json`, and `created_at_utc`.
- **In-Memory `ResultSlot`**: Query rows are streamed up to `max_rows` / `max_bytes` on complete row boundaries, stored in a bounded memory cache (`maxSlots = 64`, `maxTotalBytes = 32 MiB`, oldest-entry eviction) with wall-clock TTL (`time.Now().Round(0)`), and never dumped into `audit_logs`.
- **Same-Origin Web Guard (Pending Session-Token Hardening)**: Mutating local HTTP endpoints run behind `SameOriginMiddleware`, validating `Origin` when present and non-`"null"`, falling back to `Sec-Fetch-Site: same-origin` or same-origin `Referer` when `Origin` is absent or `"null"` (Safari form compatibility), and rejecting explicit cross-origin or cross-site `"null"` POSTs; direct non-browser loopback calls without origin headers are currently allowed. Approval endpoints currently accept either the one-time `approval_token` or the static same-origin SPA header `X-Agent-DBCTL-UI: 1`. **Pending security hardening**: replace `X-Agent-DBCTL-UI: 1` and headerless loopback trust with a daemon-issued per-session cryptographic UI cookie/CSRF token.
- **Zero-Runtime-CDN Embedded Web Console**: `web/` bundles React, Lucide icons, Tailwind CSS v4, and `@x0c/ui` (sourced from its public GitHub Release tarball with lockfile integrity) via Vite 8 Rolldown vendor `codeSplitting` chunks (`web/vite.config.ts`) and embeds the compiled static assets directly via `go:embed` (`internal/webui`), requiring no private registries or runtime CDNs.

---

## 7. Companion Skill Auto-Sync (`internal/skillinstall`)

- **Canonical Skill**: Embedded from `skills/agent-dbctl/SKILL.md` (`cmd/agent-dbctl/skill.md`, verified identical in tests).
- **Safe Silent Sync**: On normal CLI invocations, `PersistentPreRun` performs a fast hash + target digest check against `<config_home>/skills/registrations.json`. It installs or updates only installed agent skill roots (`~/.claude/skills`, `~/.codex/skills`, `~/.cursor/skills`, `~/.config/opencode/skills`, `~/.agents/skills`, etc.), deduplicated by physical symlink resolution so shared symlinked skill roots receive a single copy.
- **Zero Interference**: Silent auto-sync never writes to stdout or stderr, acquires a cross-platform lock file (`O_CREATE|O_EXCL`), skips symlinks and locally edited files (preserving user modifications unless `--force`), and honors `AGENT_DBCTL_NO_SKILL_SYNC=1`, `AGENT_DBCTL_SKILLS_AUTO=0`, and `CI=true`.
