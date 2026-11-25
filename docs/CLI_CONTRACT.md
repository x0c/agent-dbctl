# agent-dbctl CLI Contract

`agent-dbctl` follows `agent-friendly-cli` P0/P1 design principles: dual-audience output (human tables in TTY, JSON envelope `{ok, data, error, meta}` on `--json` or non-TTY), strict stdout/stderr separation, single-source `describe`, semantic errors with concrete recovery commands, full catalog/topology/policy automation over the private daemon RPC channel, and human-only execution approval gates.

## 1. Output Envelope

When `--json` is passed OR `stdout` is not a TTY (`!isatty(stdout)`), **every** result—both success and failure—is printed as a single valid JSON object to `stdout`:

```json
{
  "ok": true,
  "data": {},
  "error": null,
  "meta": {
    "version": "v0.1.0",
    "session": "default",
    "duration_ms": 12
  }
}
```

On failure (`ok: false`, `data: null`):

```json
{
  "ok": false,
  "data": null,
  "error": {
    "code": "approval_rejected",
    "retryable": false,
    "message": "Production execution was rejected by reviewer.",
    "hint": "Reviewer note: Add LIMIT 100 and filter by tenant_id.",
    "context": {
      "operation_id": "op_01...",
      "target_ref": "order-core/prod/orders",
      "reviewer_note": "Add LIMIT 100 and filter by tenant_id."
    },
    "next_commands": [
      "/path/to/agent-dbctl exec --db order-core/prod/orders --preflight --sql \"SELECT ...\""
    ]
  },
  "meta": {
    "version": "v0.1.0",
    "session": "default"
  }
}
```

> Machine-contract keys are strictly English (`ok`, `data`, `error`, `meta`, `code`, `retryable`, `message`, `hint`, `context`, `next_commands`). `next_commands` uses the verified binary path so follow-up calls never drift to stale copies on `PATH`.

## 2. Exit Codes vs Semantic `error.code`

Operating system exit codes are constrained to integers `0..125` (codes `>= 126` are reserved by shells/signals). `agent-dbctl` maps broad operational categories to OS exit codes and carries fine-grained semantics in `error.code`:

| Exit Code | Category | Representative `error.code` values |
|---|---|---|
| `0` | Success | — (also returned for `--dry-run` / `--preflight` when analysis succeeds) |
| `1` | Execution / Internal Error | `driver_error`, `daemon_unavailable`, `daemon_restarted`, `internal_error`, `plugin_invalid`, `audit_tampered` |
| `2` | Usage / Validation Error | `invalid_usage`, `invalid_input`, `reason_required`, `unknown_flag`, `multi_target_write_forbidden` |
| `3` | Resource Not Found | `db_not_found`, `operation_not_found`, `system_not_found`, `not_found` |
| `4` | Policy / Approval Rejection | `policy_denied`, `approval_rejected`, `prod_frozen` |
| `5` | Conflict / Ambiguity | `ambiguous_target`, `daemon_version_mismatch`, `output_exists`, `conflict` |
| `6` | Timeout | `query_timeout`, `approval_timeout` |
| `7` | Async Pending Approval | `waiting_approval` (returned when `--wait=false` submits an approval request, or when `op wait --timeout` elapses while still `waiting_approval`) |

## 3. Command Hierarchy

```text
agent-dbctl db list [--system <slug>] [--env <code,...>] [--engine <eng>] [--tag <tag>] [--search <kw>] [--detail]
agent-dbctl db show <ref_or_alias> [--detail]
agent-dbctl db add [--dsn <uri> | --dsn-env <var> | --dsn-stdin] [--engine <eng> --host <host> --port <n> --database <db>]
                   [--tls-mode <mode>] [--param <k=v>...] [--system <slug>] [--system-name <name>]
                   [--workspace-path <path>...] [--git-remote <url>...] [--no-workspace] [--env <code|dev>]
                   [--safety-tier yolo|guarded|strict] [--scan-read-mode allow|reason_only|require_approval]
                   [--instance <name>] [--role standalone|primary|replica] [--network <name>]
                   [--ref <ref>] [--alias <alias>] [--user <name>] [--cred-name <name>]
                   [--cred-kind keychain|env_ref|exec_provider] [--access-level read_only|read_write]
                   [--ro-cred <name>] [--rw-cred <name>]
                   [--secret-env <var> | --secret-stdin | --secret-file <path>]
                   [--env-var-name <var>] [--exec-command <cmd>]
                   [--status active|maintenance|disabled] [--description <txt>] [--open-secret] [--dry-run] [--test]
agent-dbctl db set <ref_or_alias> [--ref <new_ref>] [--alias <alias>] [--system <slug>] [--env <code>]
                   [--instance <name>] [--database <db>] [--ro-cred <name>] [--rw-cred <name>]
                   [--policy <name>] [--scan-read-mode allow|reason_only|require_approval] [--clear-rw-cred] [--clear-policy]
                   [--status active|maintenance|disabled] [--description <txt>] [--dry-run]
agent-dbctl db delete <ref_or_alias_or_id> [--yes|-y]
agent-dbctl db schema <ref_or_alias> [table_or_collection] [--search <kw>] [--limit <n>] [--out <path> [--force]]
agent-dbctl db test [<ref_or_alias> | --all] [--system <slug>] [--env <code,...>]

agent-dbctl system list | set [<slug>] [--slug <slug>] [--name <name>] [--owner <owner>] [--description <txt>] [--tag <tag>...] [--workspace-path <path>...] [--git-remote <url>...] [--default-policy <name>] [--dry-run] | delete <slug_or_id> [--yes|-y]
agent-dbctl env list | set <code> [--safety-tier yolo|guarded|strict] [--label <k=v>...] [--color <hex>] [--sort-order <n>] [--default-policy <name>] [--dry-run] | delete <code> [--yes|-y]
agent-dbctl network list | set <name_or_id> [--mode direct|ssh_tunnel|socks5|http_proxy] [--proxy-url <url>] [--bastion-host <h>] [--bastion-port <n>] [--bastion-user <u>] [--bastion-cred <id>] [--strict-host-key] [--tls-mode <m>] [--dry-run] | delete <name_or_id> [--yes|-y]
agent-dbctl cred list | set <name_or_id> [--kind keychain|env_ref|exec_provider] [--access-level read_only|read_write] [--user <u>] [--secret-env <var> | --secret-stdin | --secret-file <path> | --clear-secret] [--env-var-name <var>] [--exec-command <cmd>] [--open-secret] [--dry-run] | delete <name_or_id> [--yes|-y]
agent-dbctl instance list | set <name_or_id> [--engine <eng>] [--host <h>] [--port <p>] [--role primary|replica|standalone] [--primary <name>] [--network <name>] [--tls-mode <m>] [--param <k=v>...] [--dry-run] | delete <name_or_id> [--yes|-y] | test <name_or_id> [--cred <name_or_id>] [--database <db>] | discover <name_or_id> [--cred <name_or_id>] [--database <db>]

agent-dbctl topology schema [--format yaml|json] [--out <path> [--force]]
agent-dbctl topology export [--format yaml|json] [--out <path> [--force]]
agent-dbctl topology apply [--file <path> | --stdin] [--dry-run] [--open-secret]

agent-dbctl security get | set [--exec-timeout-sec <sec>] [--approval-timeout-sec <sec>] [--max-rows <n>] [--max-bytes <n>] [--explain-max-rows <n>] [--prod-read-only-freeze] [--block-multi-statement-in-prod] [--default-approval-provider <p>] [--redact-audit-literals] [--require-reason-for-approval] [--dry-run]
agent-dbctl policy list | set [<name_or_id>] [--file <path>] --scope-type env|system|target --scope-id <id_or_key> [--scan-read-mode allow|reason_only|require_approval] [...] [--dry-run] | delete <name_or_id> [--yes|-y]
agent-dbctl pattern list | set [<name_or_id>] [--file <path> | --stdin] [--scope-type global|env|system|target] [--scope-id <id_or_key>] [--action elevate_high_cost|require_approval|deny] [--regex <pat>] [--engine <eng>...] [--dry-run] | delete <name_or_id> [--scope-type ... --scope-id ...] [--yes|-y] | install-pack <pack_id> [--scope-type ...] [--scope-id ...] [--dry-run] | test [--db <ref>] [--engine <eng>] [--safety-tier yolo|guarded|strict] [--query <q> | <q>]
agent-dbctl approval list [--status pending|approved|rejected|expired|cancelled] [--limit <n>]
agent-dbctl approval show <approval_id>
agent-dbctl driver list [--engine <name>]

agent-dbctl exec --db <ref_or_alias> [--sql <stmt> | --file <path> | --stdin | <stmt>]
                 [--reason <text>] [--dry-run | --preflight]
                 [--max-rows <n>] [--max-bytes <n>] [--timeout <dur>]
                 [--format auto|rows|objects] [--verbose]
                 [--out <path> [--force]] [--wait=true|false]
                 (flag aliases: --target/--source -> --db; --query/--cmd -> --sql; --limit -> --max-rows)

agent-dbctl op status <operation_id> [--format auto|rows|objects] [--verbose] [--out <path> [--force]]
agent-dbctl op wait <operation_id> [--timeout <dur>] [--format auto|rows|objects] [--verbose] [--out <path> [--force]]
agent-dbctl op list [--db <ref_or_alias>] [--env <code,...>] [--system <slug>] [--status <status>] [--limit <n>]
agent-dbctl op cancel <operation_id>

agent-dbctl ui open [--tab approvals|targets|catalog|policies|audit|drivers] [--credential <id_or_name>] [--no-open]
agent-dbctl daemon start | status | stop | restart
agent-dbctl plugin list | verify | reload
agent-dbctl audit verify
agent-dbctl audit list [--action <kw>] [--target <kw>] [--op <id>] [--actor <name>] [--since <time>] [--until <time>] [--limit <n>] [--offset <n>] [--out <path> [--force]]
agent-dbctl audit export [--format jsonl|csv] [--action <kw>] [--target <kw>] [--op <id>] [--actor <name>] [--since <time>] [--until <time>] [--limit <n>] [--out <path> [--force]]
agent-dbctl doctor [--live]
agent-dbctl describe [command...]
agent-dbctl version
agent-dbctl capabilities
agent-dbctl serve [--config <path>] [--listen <addr>] [--public-url <url>]
agent-dbctl context list | show | add <name> --endpoint <url> [--ca-cert <path>] [--client-cert <path> --client-key <path>] [--auth-mode oidc_device|bearer_token] | use <name> | remove <name>
agent-dbctl login [--context <name>] [--token-stdin | --token-env <var>]
agent-dbctl logout [--context <name>]
agent-dbctl whoami
agent-dbctl token list | create --name <name> [--role developer|viewer|system_admin] [--system <slug>...] [--env <code...>] [--read-only] [--ttl <dur>] | revoke <id_or_name>
agent-dbctl skill install [--dry-run] [--force] [--runtime <name>]
agent-dbctl skill status [--runtime <name>]
agent-dbctl skill uninstall [--dry-run] [--runtime <name>]
agent-dbctl skill print
```

### Global Flags

- `--json`: Force JSON envelope output (automatic when stdout is non-TTY).
- `--no-color`: Disable ANSI colors (also honors `NO_COLOR` and `TERM=dumb`).
- `--no-input` / `--non-interactive`: Disable interactive prompts (automatic when stdin/stdout is non-TTY).
- `--session <name>`: Select isolated local daemon session (default `default`, or `AGENT_DBCTL_SESSION`).
- `--context <name>`: Select client context (`local` or configured remote context, or `AGENT_DBCTL_CONTEXT`).

## 4. Safety & Behavioral Guarantees

1. **`--dry-run` vs `--preflight` (mutually exclusive)**:
   - `--dry-run`: Purely offline. Parses/classifies locally and resolves effective policy without dialing the database, creating approvals, or mutating business state.
   - `--preflight`: Connects using read-only credentials (where available), runs non-mutating `EXPLAIN` (never `ANALYZE`) on single-statement SQL reads or single-statement DML (`INSERT`/`REPLACE`/`UPDATE`/`DELETE`/`MERGE`) and `queryPlanner` on MongoDB JSON commands, and returns estimated scan/risk analysis without executing the statement or opening an approval popup.
2. **Write Timeout Non-Replay**: If a write/DDL/admin/unknown operation times out (`exit 6`, `query_timeout`), `error.retryable` is strictly `false` with a hint instructing read-only verification before any retry.
3. **Progressive Disclosure & Lean Agent Output**:
   - `db list` and `db show` return compact target summaries by default (`ref`, `alias`, `engine`, `env`, `safety_tier`, `status`, `writable`, `max_rows`, `query_syntax_hint`) and expand full `TargetDetail` metadata only with `--detail`.
   - `db schema <ref> [table]` provides unified read-only schema introspection across PostgreSQL, openGauss, KingbaseES, MySQL, SQLite, ClickHouse, SQL Server, Oracle, Dameng DM8, TDengine, MongoDB, Elasticsearch/OpenSearch/Easysearch, and Redis (listing tables/collections/indices/key-prefix patterns, or describing columns, indexes, foreign keys, and inferred document fields) without requiring raw dialect catalog queries.
   - On successful `exec` / `op status` / `op wait` (without `--dry-run`, `--preflight`, or `--verbose`), JSON output returns a flat, low-token outcome with `operation_id`, `status`, `target_ref`, `engine`, `columns`/`rows` (or `records` with `--format objects`), `documents`, `kv_result`, `affected_rows`, `fetched_rows`, `returned_rows`, `truncated`, `cutoff_reason`, and `latency_ms`, omitting `effective_policy` and raw `EXPLAIN` trees unless `--verbose` is passed.
   - When `--wait` is not explicitly set on `exec`, interactive TTY defaults to `--wait=true` while non-TTY/non-interactive agent calls default to `--wait=false` so human approvals immediately return `exit 7` (`waiting_approval`) with `operation_id`, `approval_url`, and concrete `op wait` / `op status` commands instead of risking shell tool timeouts (agents running inside PTY-allocated shells where stdin and stdout are both TTYs should pass `--wait=false` explicitly).
4. **Honest Coverage & Intact Truncation**: `exec` always returns `fetched_rows`, `returned_rows`, `truncated`, and `cutoff_reason` (`""` | `"max_rows"` | `"max_bytes"`). Truncation happens strictly on whole row/document boundaries.
5. **Atomic `--out` File Delivery**: Writes to a temporary file (`0600`) in the destination directory and atomically renames; refuses symlinks and overwrites unless `--force` is given.
6. **Single-Source `describe`**: `agent-dbctl describe` generates directly from the live Cobra command & flag definitions, exposing each command's `risk` (`read` | `write_local` | `execute_remote`), flags, types, defaults, and examples.
7. **Synchronous Cancel & Wait**: `op cancel` waits for the operation to settle before returning; `op wait` blocks until terminal status or `--timeout` (exit `7` if still `waiting_approval`, exit `6` if still `running`/`pending`) and supports `--out`, `--format`, and `--verbose` alongside `op status`.
8. **Audit Inspection & Offline Fallback**: `audit list` and `audit export --format jsonl|csv` query the running daemon (`/rpc/v1/audit`) and fall back to read-only SQLite access when the daemon is stopped, returning `total_matched`, `returned`, and `truncated`.
9. **Live Diagnostics & Connectivity Failures**: `doctor --live` verifies config/DB permissions (`0700`/`0600`), webhook readiness, plugin digests, and live target connectivity; `db test` returns `ok: false` (exit `1`) when all probed targets are unreachable.
10. **Multi-Word `describe` & Exit Codes**: `describe [command...]` accepts multi-word subcommand paths (e.g. `describe db list`) and includes the `exit_codes` catalog alongside live Cobra flags and risk metadata.
11. **Actionable `driver_error` Recovery**: Driver execution failures surface targeted `hint` guidance and concrete `next_commands` (such as `db schema <ref>` on missing table/column errors, `db show <ref>` on permission/syntax issues, or `db test <ref>` on connectivity failures) while omitting empty approval fields from `error.context`.
12. **Idempotent Declarative Configuration & Zero-Secret Web Handoff**: `db add`, `system set`, `env set|delete`, `network set`, `cred set`, `instance set`, `db set|delete`, `topology apply`, `security set`, `policy set`, and `pattern set` accept natural keys (`slug`/`name`/`ref`/`code`), support truly read-only `--dry-run`, converge to `status: "unchanged"` on repeat runs, and record `actor: "agent-cli"` in the hash-chain audit log; partial flag updates on `pattern set` merge into existing rules without wiping unchanged matchers/actions; target deletion (`db delete`) reports any newly orphaned instance, credential, or custom environment alongside concrete cleanup commands; target deletion/lookup also supports slash-containing natural refs (`system/env/db`). On `db add`, `--access-level` defaults to `read_write` in `yolo` environments and `read_only` in `guarded`/`strict`, while passing `--safety-tier` creates an unknown `--env` inline (omitting `--safety-tier` for a missing environment returns structured `hint` + `next_commands`). When a `keychain` credential has no stored secret, `db add`, `cred set`, and `topology apply` return `missing_secrets` with a deep-link `setup_url` (`/catalog?subtab=credentials&credential=<id>`); passing `--open-secret` (or `ui open --credential <name-or-id>`) opens the browser straight to the credential's password dialog without exposing secrets to the agent. Note that `--test` / `db test` probes use read-only connections (SQLite targets open with `mode=ro` and require an existing DB file).
13. **Daemon Version Upgrade & Single-Instance Lifecycle**: When the running daemon is older than the CLI (or shares the same base version with a different commit / `dev` build), CLI commands serialize on a per-session startup lock and automatically restart the stale daemon—provided `AGENT_DBCTL_NO_DAEMON_SPAWN` is not `1` and no operations are currently `running` (`waiting_approval` operations rehydrate cleanly on startup). If the running daemon is strictly newer than the CLI, if `running` operations are active, or if auto-spawn is disabled, the CLI returns exit `5` (`daemon_version_mismatch`) rather than silently downgrading or aborting in-flight queries. The daemon itself holds an exclusive per-session OS lock and closes SSE streams immediately on shutdown to prevent orphaned duplicate processes or socket races.
14. **Mandatory Approval Justification (`--reason`)**: When `GlobalSecurityConfig.RequireReasonForApproval` is enabled (default `true`), any `exec` invocation whose policy evaluation resolves to `require_approval` (or whose safe full-scan read matches a scoped `scan_read_mode: reason_only` policy) and is not `--dry-run`/`--preflight` requires a non-empty `--reason "<text>"`; omitting it fails fast with exit `2` (`reason_required`) and concrete recovery guidance without creating an empty approval ticket.

## 5. Environment Variables

| Variable | Purpose |
|---|---|
| `AGENT_DBCTL_CONFIG_HOME` | Override config, SQLite DB, socket, and plugin directory (default `$XDG_CONFIG_HOME/agent-dbctl` or `~/.config/agent-dbctl`) |
| `AGENT_DBCTL_SESSION` | Override daemon session name (use `dev-*` during development/testing) |
| `AGENT_DBCTL_SECRET_BACKEND` | Override secret backend (`keychain` on macOS by default, `file` for isolated tests/headless hosts) |
| `AGENT_DBCTL_WEB_PORT` | Pin local Web Console port (default random free loopback port) |
| `AGENT_DBCTL_NO_BROWSER` | Set `1` to disable automatic browser opening on `local-web` approvals and `ui open` |
| `AGENT_DBCTL_NO_DAEMON_SPAWN` | Set `1` to prevent CLI from auto-starting or auto-restarting the daemon |
| `AGENT_DBCTL_NO_SKILL_SYNC` | Set `1`/`true` to disable silent companion `SKILL.md` installation on CLI startup |
| `AGENT_DBCTL_SKILLS_AUTO` | Set `0`/`false` (equivalent to `AGENT_DBCTL_NO_SKILL_SYNC=1`) |
| `AGENT_DBCTL_SKILL_HOME` | Override target skill root directory cleanly (useful for isolated tests) |
| `AGENT_DBCTL_WEBHOOK_URL` | Enable built-in `webhook` approval provider pointing at an external approval endpoint (`https://`, or `http://` on loopback only) |
| `AGENT_DBCTL_WEBHOOK_SECRET` | Optional HMAC-SHA256 signing secret for `X-Agent-DBCTL-Signature` headers on webhook approval notifications |
| `AGENT_DBCTL_WEBHOOK_TIMEOUT` | Optional webhook HTTP timeout duration (e.g. `10s`; default `5s`, capped at `30s`) |
| `AGENT_DBCTL_CONTEXT` | Override active client context (`local` or a named remote context from `contexts.yaml`) |
| `AGENT_DBCTL_ENDPOINT` | Override remote server HTTPS URL directly for headless CI/agent environments |
| `AGENT_DBCTL_TOKEN` | Bearer token for `AGENT_DBCTL_ENDPOINT` or remote contexts without interactive `login` |
| `AGENT_DBCTL_SERVER_CONFIG` | Path to server YAML configuration for `agent-dbctl serve` |
| `AGENT_DBCTL_STORE_DSN` | Database DSN for server storage when `storage.driver: postgres` |
| `AGENT_DBCTL_MASTER_KEY` | Base64 or hex 32-byte KEK for server-side envelope-encrypted credential storage |
| `AGENT_DBCTL_REDIS_URL` | Optional Redis connection URL for multi-replica `ResultSlot` and `EventBus` |

## 6. Remote Context Behavior

When targeting a remote context (`mode: remote`):

1. **No Local Daemon Spawn**: `daemon start|stop|restart` return exit `2` (`invalid_usage` / `unsupported_in_remote_mode`), and `audit list|export` query `/rpc/v1/audit` directly without local SQLite fallback.
2. **HTTPS Transport & Auth**: Non-loopback endpoints require `https://` and attach `Authorization: Bearer <token>` (from Keychain/`0600` credential store or `AGENT_DBCTL_TOKEN`), supporting custom CA and mTLS client certificates.
3. **Chunked Long-Poll Wait**: `op wait` uses bounded server-side wait intervals (`/rpc/v1/ops/{id}/wait?timeout=25s`) in a loop until terminal state or overall client timeout, avoiding reverse-proxy gateway timeouts.
4. **Remote Web URL**: `ui open` and `--open-secret` use the server's configured `public_url` rather than `127.0.0.1` and never launch a browser on the server host.
