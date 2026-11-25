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
                                                        ├──▶ ApprovalManager (ApprovalProvider: local-web / extensible)
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
   - `workspace_paths` binds local repository paths (e.g. `~/Codes/order-core`) to the system so `agent-dbctl db list` automatically prioritizes databases belonging to or linked with the agent's current working directory.
2. **Environment (`environments`)**:
   - Classifications such as `dev`, `staging`, `prod`, each carrying `safety_tier` (`yolo` | `guarded` | `strict`), server-driven localized labels (`en`, `zh`), `#RRGGBB` display color, display order, and `default_policy_id`.
3. **NetworkProfile (`network_profiles`) & CredentialProfile (`credential_profiles`)**:
   - **NetworkProfile**: Reusable connectivity template (`direct`, `ssh_tunnel` bastion, `socks5`, `http_proxy`, TLS mode). Multiple instances share one bastion definition.
   - **CredentialProfile**: Reusable auth definition (`keychain`, `env_ref`, `exec_provider`), `access_level` (`read_only` | `read_write`). Actual secrets live strictly in the OS Keychain (macOS `security -i` over stdin), env vars, or external secret-manager commands—never in SQLite or CLI output.
4. **Instance (`instances`) & Target (`targets`)**:
   - **Instance**: Physical/logical endpoint (`engine`, `host`, `port`, `role`: `primary` | `replica` | `standalone`, `primary_instance_id`, `network_profile_id`). Supports live database/schema discovery (`POST /api/v1/instances/{id}/discover`).
   - **Target**: Logical addressable target (`ref` e.g. `order-core/prod/orders`, short `alias` e.g. `prod-orders`, `owner_system_id`, many-to-many `linked_system_ids`, `instance_id`, `database_name`, `ro_credential_id`, `rw_credential_id`, `policy_override_id`, `status`: `active` | `maintenance` | `disabled`).

### Sanitized Topology Portability

`GET/POST /api/v1/topology` exports and imports `System`, `Environment`, `NetworkProfile`, `CredentialProfile` metadata (without secrets), `Instance`, `Target`, and `Policy` definitions as YAML or JSON so teams can share catalog topology via Git while keeping credentials local or vault-backed.

---

## 4. Pluggable Drivers, Classification & Policy Engine

### Driver Tiers (Zero JVM)

- **Tier 1 (Built-in Pure Go, `CGO_ENABLED=0`)**: PostgreSQL (`pgx/v5`), MySQL / MariaDB / TiDB (`go-sql-driver/mysql` via per-connection `mysql.NewConnector`), SQLite (`modernc.org/sqlite`), MongoDB (`mongo-go-driver/v2`), Redis / Valkey (`go-redis/v9`). Drivers adapt across server versions and restricted privilege tiers (e.g., `EXPLAIN` JSON/tree/tabular fallbacks, `transaction_read_only`/`tx_read_only`, `hello`/`isMaster`/`buildInfo` probes, RESP2/RESP3 normalization, and PgBouncer `exec_mode=simple_protocol`).
- **Tier 3 (External gRPC Subprocess Plugins)**: Loaded via `hashicorp/go-plugin` over gRPC from `<config_home>/plugins/<id>/manifest.json`. Verified against `host_api_version` and binary SHA-256 before execution. Crashes are isolated to the subprocess; daemon-managed network tunnels (`ssh_tunnel`, `socks5`, `http_proxy`) are bridged over an ephemeral authenticated loopback forwarder when `DialContext` is active.

### Risk Classification & Preflight

- **Multi-statement safety**: Multi-statement SQL scripts are split respecting quotes, dollar-quotes, and comments; overall classification takes the maximum severity across all statements.
- **Fail-closed unknown syntax**: Unrecognized syntax is classified as `unknown` (`high_risk`), which still runs under `dev` (`yolo`) if allowed, but forces human approval under `guarded`/`strict` environments.
- **High-cost read detection**:
  - SQL: missing `LIMIT` / `WHERE`, `SELECT *` without `WHERE`, `FOR UPDATE` / `LOCK IN SHARE MODE`, `EXPLAIN ANALYZE`, `CROSS JOIN`, `SELECT INTO`, multi-statement queries.
  - MongoDB: empty filter `{}` without limit, `aggregate` without `$limit`, `$where`, write stages `$out`/`$merge`.
  - Redis: `KEYS`, `HGETALL`, `HKEYS`, `HVALS`, `SMEMBERS`, unbounded `LRANGE`/`ZRANGE`, `MONITOR`, `DUMP`, `SINTER`/`SUNION`/`SDIFF` (`high_cost_read`), plus writes/admin (`SET`, `DEL`, `FLUSHDB`, `FLUSHALL`, `EVAL`, etc.).
- **Preflight (`EXPLAIN` without `ANALYZE`)**: In `guarded`/`strict` environments, safe reads undergo `EXPLAIN` preflight before execution; full scans (`Seq Scan`, `ALL`, `COLLSCAN`, SQLite `SCAN`) or estimated rows exceeding `explain_max_rows` escalate to `require_approval`, attaching the plan summary to the approval card.

### Four-Level Monotonic Policy Inheritance

Effective policy resolves in order: `GlobalSecurityConfig` -> `Environment` -> `System` -> `Target`.
Lower levels can **tighten** restrictions (shorter timeout, lower row/byte cap, stricter approval requirement) but never exceed global hard upper bounds or override `prod_read_only_freeze`.

---

## 5. Pluggable Approval Abstraction (`ApprovalProvider`)

Approval workflow is decoupled behind `internal/approval.Provider`:

- **Built-in `local-web` provider**: Persists an approval record with a cryptographic one-time `approval_token` (stored hashed), broadcasts an SSE event, and opens `http://127.0.0.1:<port>/approvals/<id>?token=<token>` in the local browser (suppressed when `AGENT_DBCTL_NO_BROWSER=1`).
- **Enterprise extensibility**: External approval flows (Feishu, WeCom, Slack, internal ticket APIs) implement `ApprovalProvider` (`Submit`, `Cancel`, external status sync), while fully air-gapped DMS platforms can be integrated as Tier-3 `Driver` plugins—preserving the exact CLI (`--wait=false` + `op status`) and audit contract.

---

## 6. Audit Integrity, Result Isolation & Security

- **SQLite WAL + Hash Chain**: `~/.config/agent-dbctl/agent-dbctl.db` (dir `0700`, file `0600`) enables `PRAGMA journal_mode=WAL` and `busy_timeout=5000`, verified via readback on open. SQLite triggers forbid `UPDATE` and `DELETE` on `audit_logs`. Each audit row chains `prev_hash` + `entry_hash` (SHA-256) and records `actor`, `action`, `target_id`, `operation_id`, `payload_json`, and `created_at_utc`.
- **In-Memory `ResultSlot`**: Query rows are streamed up to `max_rows` / `max_bytes` on complete row boundaries, stored in memory with wall-clock TTL (`time.Now().Round(0)`), and never dumped into `audit_logs`.
- **Same-Origin Web Guard**: Mutating local HTTP endpoints validate `Origin` when present and non-`"null"`, falling back to `Sec-Fetch-Site: same-origin` or same-origin `Referer` when `Origin` is absent or `"null"` (Safari form compatibility). Approvals additionally require the one-time `approval_token` or active UI session token.
- **Zero-External-Dependency Embedded Web Console**: `web/` uses only public npm packages (`react`, `react-dom`, `lucide-react`, Tailwind CSS v4) with local self-contained UI primitives in `web/src/ui/` bundled directly via `go:embed` (`internal/webui`), requiring no private registries or runtime CDNs.

---

## 7. Companion Skill Auto-Sync (`internal/skillinstall`)

- **Canonical Skill**: Embedded from `skills/agent-dbctl/SKILL.md` (`cmd/agent-dbctl/skill.md`, verified identical in tests).
- **Safe Silent Sync**: On normal CLI invocations, `PersistentPreRun` performs a fast hash + target digest check against `<config_home>/skills/registrations.json`. It installs or updates only installed agent skill roots (`~/.claude/skills`, `~/.codex/skills`, `~/.cursor/skills`, `~/.config/opencode/skills`, `~/.agents/skills`, etc.), deduplicated by physical symlink resolution so shared symlinked skill roots receive a single copy.
- **Zero Interference**: Silent auto-sync never writes to stdout or stderr, acquires a cross-platform lock file (`O_CREATE|O_EXCL`), skips symlinks and locally edited files (preserving user modifications unless `--force`), and honors `AGENT_DBCTL_NO_SKILL_SYNC=1`, `AGENT_DBCTL_SKILLS_AUTO=0`, and `CI=true`.
