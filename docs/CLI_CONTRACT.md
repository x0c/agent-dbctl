# agent-dbctl CLI Contract

`agent-dbctl` follows `agent-friendly-cli` P0/P1 design principles: dual-audience output (human tables in TTY, JSON envelope `{ok, data, error, meta}` on `--json` or non-TTY), strict stdout/stderr separation, single-source `describe`, semantic errors with concrete recovery commands, and configuration read-only boundaries for agents.

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
| `1` | Execution / Internal Error | `driver_error`, `daemon_unavailable`, `internal_error`, `plugin_invalid`, `audit_tampered` |
| `2` | Usage / Validation Error | `invalid_usage`, `invalid_input`, `unknown_flag`, `multi_target_write_forbidden` |
| `3` | Resource Not Found | `db_not_found`, `operation_not_found`, `system_not_found` |
| `4` | Policy / Approval Rejection | `policy_denied`, `approval_rejected`, `prod_frozen` |
| `5` | Conflict / Ambiguity | `ambiguous_target`, `daemon_version_mismatch`, `output_exists` |
| `6` | Timeout | `query_timeout`, `approval_timeout` |
| `7` | Async Pending Approval | `waiting_approval` (returned only when `--wait=false` submits an approval request) |

## 3. Command Hierarchy

```text
agent-dbctl db list [--system <slug>] [--env <code,...>] [--engine <eng>] [--tag <tag>] [--search <kw>]
agent-dbctl db show <ref_or_alias>
agent-dbctl db test [<ref_or_alias> | --all] [--system <slug>] [--env <code,...>]

agent-dbctl exec --db <ref_or_alias> [--sql <stmt> | --file <path> | --stdin]
                 [--reason <text>] [--dry-run | --preflight]
                 [--max-rows <n>] [--max-bytes <n>] [--timeout <dur>]
                 [--out <path> [--force]] [--wait=true|false]
                 (flag aliases: --target/--source -> --db; --query/--cmd -> --sql; --limit -> --max-rows)

agent-dbctl op status <operation_id>
agent-dbctl op list [--db <ref_or_alias>] [--status <status>] [--limit <n>]
agent-dbctl op cancel <operation_id>

agent-dbctl ui open [--no-open]
agent-dbctl daemon start | status | stop | restart
agent-dbctl plugin list | verify | reload
agent-dbctl audit verify
agent-dbctl doctor [--live]
agent-dbctl describe [command]
agent-dbctl version
agent-dbctl capabilities
agent-dbctl skill install [--dry-run] [--force] [--runtime <name>]
agent-dbctl skill status [--runtime <name>]
agent-dbctl skill uninstall [--dry-run] [--runtime <name>]
agent-dbctl skill print
```

### Global Flags

- `--json`: Force JSON envelope output (automatic when stdout is non-TTY).
- `--no-color`: Disable ANSI colors (also honors `NO_COLOR` and `TERM=dumb`).
- `--no-input` / `--non-interactive`: Disable interactive prompts (automatic when stdin/stdout is non-TTY).
- `--session <name>`: Select isolated daemon session (default `default`, or `AGENT_DBCTL_SESSION`).

## 4. Safety & Behavioral Guarantees

1. **`--dry-run` vs `--preflight` (mutually exclusive)**:
   - `--dry-run`: Purely offline. Parses/classifies locally and resolves effective policy without dialing the database, creating approvals, or mutating business state.
   - `--preflight`: Connects using read-only credentials (where available), runs non-mutating `EXPLAIN` (never `ANALYZE`), and returns estimated scan/risk analysis without executing the statement or opening an approval popup.
2. **Write Timeout Non-Replay**: If a write/DDL/admin/unknown operation times out (`exit 6`, `query_timeout`), `error.retryable` is strictly `false` with a hint instructing read-only verification before any retry.
3. **Honest Coverage & Intact Truncation**: `exec` always returns `fetched_rows`, `returned_rows`, `truncated`, and `cutoff_reason` (`""` | `"max_rows"` | `"max_bytes"`). Truncation happens strictly on whole row/document boundaries.
4. **Atomic `--out` File Delivery**: Writes to a temporary file (`0600`) in the destination directory and atomically renames; refuses symlinks and overwrites unless `--force` is given.
5. **Single-Source `describe`**: `agent-dbctl describe` generates directly from the live Cobra command & flag definitions, exposing each command's `risk` (`read` | `write_local` | `execute_remote`), flags, types, defaults, and examples.

## 5. Environment Variables

| Variable | Purpose |
|---|---|
| `AGENT_DBCTL_CONFIG_HOME` | Override config, SQLite DB, socket, and plugin directory (default `$XDG_CONFIG_HOME/agent-dbctl` or `~/.config/agent-dbctl`) |
| `AGENT_DBCTL_SESSION` | Override daemon session name (use `dev-*` during development/testing) |
| `AGENT_DBCTL_SECRET_BACKEND` | Override secret backend (`keychain` on macOS by default, `file` for isolated tests/headless hosts) |
| `AGENT_DBCTL_WEB_PORT` | Pin local Web Console port (default random free loopback port) |
| `AGENT_DBCTL_NO_BROWSER` | Set `1` to disable automatic browser opening on `local-web` approvals and `ui open` |
| `AGENT_DBCTL_NO_DAEMON_SPAWN` | Set `1` to prevent CLI from auto-starting daemon if absent |
| `AGENT_DBCTL_NO_SKILL_SYNC` | Set `1`/`true` to disable silent companion `SKILL.md` installation on CLI startup |
| `AGENT_DBCTL_SKILLS_AUTO` | Set `0`/`false` (equivalent to `AGENT_DBCTL_NO_SKILL_SYNC=1`) |
| `AGENT_DBCTL_SKILL_HOME` | Override target skill root directory cleanly (useful for isolated tests) |
