---
name: agent-dbctl
description: "Query, inspect, debug, or modify databases (PostgreSQL, MySQL, SQLite, ClickHouse, SQL Server, Oracle, MongoDB, Elasticsearch, Redis) safely through agent-dbctl instead of raw psql, mysql, clickhouse-client, sqlcmd, sqlplus, mongosh, or redis-cli. Use whenever a task involves inspecting schemas or tables, debugging database state, running SQL/Mongo/Elasticsearch/Redis queries, checking EXPLAIN plans, or submitting staging/production data changes for human Web approval."
---

# agent-dbctl Skill

`agent-dbctl` is the mandatory database execution boundary. Never bypass it by invoking `psql`, `mysql`, `mongosh`, `redis-cli`, ad-hoc driver scripts, or reading Keychain/config secrets directly.

## 1. Probe Availability & Workspace Context First

Check the binary path, capabilities, and workspace-prioritized databases before running any query:

```sh
BIN="$(command -v agent-dbctl)"
"$BIN" version --json
"$BIN" capabilities --json
"$BIN" db list --json
```

If `agent-dbctl` is missing:

- macOS / Linux (Homebrew): `brew install x0c/tap/agent-dbctl`
- macOS / Linux (Shell): `curl -fsSL https://raw.githubusercontent.com/x0c/agent-dbctl/main/scripts/install.sh | bash`
- Windows (PowerShell): `irm https://raw.githubusercontent.com/x0c/agent-dbctl/main/scripts/install.ps1 | iex`

Pin and reuse the verified absolute binary path (`"$BIN"`) for the rest of the session.

## 2. Onboarding & Catalog Configuration (Agent-Driven)

When a database is not yet registered (`db list` returns empty or `db_not_found`), configure it directly through `agent-dbctl` CLI commands (every change is atomic, idempotent, and hash-chain audited):

1. **One-shot registration (`db add`)**:
   - **Zero-secret Web handoff (recommended when human will enter password)**: leave password blank and pass `--open-secret` so the browser opens straight to that credential's password dialog:
     ```sh
     "$BIN" db add --engine postgres --host 127.0.0.1 --port 5432 --database orders \
       --system order-core --env prod --user app_ro --open-secret --json
     ```
   - **DSN / automated secret sources**: pass `--dsn` / `--dsn-env` / `--dsn-stdin`, or pair flags with `--secret-env <VAR>` / `--secret-stdin` / `--secret-file <path>`, `--cred-kind env_ref --env-var-name <VAR>`, or `--cred-kind exec_provider --exec-command "<cmd>"`. Preview first with `--dry-run`; probe immediately with `--test`.
   - When `missing_secrets` appears in output, share `setup_url` or run `"$BIN" ui open --credential <name-or-id>` so the human enters the password into Keychain directly.
2. **Bulk declarative topology (`topology`)**:
   - Print the exact YAML schema & field guide offline: `"$BIN" topology schema`
   - Preview and apply sanitized topology: `"$BIN" topology apply --file topology.yaml --dry-run --json` then `"$BIN" topology apply --file topology.yaml --open-secret --json`
   - Export sanitized topology: `"$BIN" topology export --format yaml --out topology.yaml --json`
3. **Granular catalog, discovery, and guardrails**:
   - Assets: `system list|set|delete`, `env list|set`, `network list|set|delete`, `cred list|set|delete`, `instance list|set|delete|test|discover`, `db set|delete`
   - Drivers & syntax hints: `"$BIN" driver list --json` (shows all built-in + plugin engines, aliases, default ports, `params`, and query syntax)
   - Guardrails & approvals: `security get|set`, `policy list|set|delete`, `pattern list|set|delete|install-pack|test`, `approval list|show`

## 3. Standard Query & Execution Workflow

1. **Discover targets & inspect schema first** (read-only; discovers environment safety tier, engine, aliases, tables/collections, and column types without hand-writing dialect metadata SQL):
   ```sh
   "$BIN" db list --json
   "$BIN" db show <target-ref-or-alias> --json
   "$BIN" db schema <target-ref-or-alias> --json
   "$BIN" db schema <target-ref-or-alias> <table_or_collection> --json
   ```
   - Pass `--detail` to `db list` or `db show` only when you need full network/credential/policy provenance.
2. **Dry-run or Preflight before risky or production queries**:
   ```sh
   "$BIN" exec --db <ref> --dry-run --sql "<query>" --json
   "$BIN" exec --db <ref> --preflight --sql "<query>" --json
   ```
   - `--dry-run` evaluates classification and policy locally without touching the database.
   - `--preflight` connects read-only and runs non-mutating `EXPLAIN` (never `ANALYZE`) on SQL reads or single-statement DML (`INSERT`/`UPDATE`/`DELETE`/`MERGE`) to surface full scans and row estimates before execution.
   - Pass `--verbose` on `exec` when you want full `classification`, `preflight` (`plan_raw`), and `evaluation` (`matched_rules`, `effective_policy`) details alongside results.
3. **Execute verbatim queries with a clear business reason**:
   - Pass verbatim engine syntax (PostgreSQL/MySQL/SQLite/ClickHouse/MSSQL/Oracle SQL, MongoDB JSON `RunCommand` such as `{"find":"orders","limit":10}` or `show collections`, Elasticsearch HTTP+JSON or JSON search, or Redis commands). Do not ask `agent-dbctl` to translate dialects.
   - Pass queries via `--sql`, `--file <path>`, `--stdin`, or as a single optional positional argument (`exec --db <ref> "<query>"`). Prefer `--file <path>` or `--stdin` for multi-line SQL or JSON queries to avoid shell escaping errors.
   - Pass `--format objects` on SQL queries when working with wide tables and you want `records: [{col: val}]` instead of positional `columns` + `rows` arrays.
   - Always pass `--reason "<concise reason>"` on writes, production queries, or any operation that may trigger human approval; by default (`require_reason_for_approval`), approval requests without `--reason` are rejected with exit `2` (`reason_required`).
   - In non-TTY agent shells, `exec` defaults to `--wait=false` when `--wait` is omitted so approvals return `operation_id` immediately (`exit 7`) instead of hitting tool timeouts; follow up with `op wait` or `op status`:
     ```sh
     "$BIN" exec --db <ref> --reason "Backfill stuck order state" --sql "UPDATE ..." --json
     "$BIN" op wait <operation_id> --timeout 60s --json
     "$BIN" op status <operation_id> --json
     ```
   - Inspect or verify recent audit trails when auditing past runs:
     ```sh
     "$BIN" audit list --limit 20 --json
     "$BIN" audit verify --json
     ```

## 4. Reading Output & Recovering Safely

- Check `ok == true` (exit code `0`) rather than assuming non-empty stdout means success. On normal `exec` success, `data` directly exposes `operation_id`, `status`, `columns`/`rows` (or `records` with `--format objects`), `documents`, `kv_result`, `affected_rows`, `fetched_rows`, `returned_rows`, `truncated`, `cutoff_reason`, and `latency_ms`.
- **Exit `2` (`reason_required`)**: the operation triggered human approval but `--reason` was empty; re-run with `--reason "<concise business reason>"`.
- **Exit `7` (`waiting_approval`)**: human confirmation is open in the Web Console. Run `"$BIN" op wait <operation_id> --timeout 60s --json` or share `error.context.approval_url` with the user. Note that custom high-risk pattern rules (`error.context.matched_rules`) can force secondary confirmation even on `dev`/`yolo` targets; surface `confirm_title` and `confirm_message` alongside `approval_url`.
- **Exit `4` (`approval_rejected` / `policy_denied` / `prod_frozen`)**: read `error.hint`, `error.context.matched_rules` (when a custom high-risk pattern denied the statement), and `error.context.reviewer_note`. Never replay a rejected query verbatim; rewrite it according to the reviewer's feedback or stop.
- **Exit `1` (`driver_error`)**: inspect `error.hint` and `error.next_commands` (e.g. run `db schema <ref>` when a column or table name is wrong).
- **Exit `6` (`query_timeout`)**: if `error.retryable` is `false` (write/DDL/unknown), **do not auto-replay**. Run a bounded read-only query first to verify whether the write landed.
- **Truncation honesty**: always check `data.truncated`, `data.fetched_rows`, and `data.returned_rows`. Never claim a table has only `returned_rows` records when `truncated == true`.

## 5. Hard Safety Rules

- Never ask `agent-dbctl` to print passwords/DSNs, never edit `~/.config/agent-dbctl/` files directly, and never bypass `agent-dbctl` with raw DB CLIs (`psql`, `mysql`, `mongosh`, `redis-cli`, etc.).
- Execution approvals (`approve` / `reject`) are strictly human-confirmed in the Web Console or configured `ApprovalProvider`. Never attempt to forge or bypass human approvals.
- Keep exploratory queries bounded (`LIMIT`, `--max-rows`, `--timeout`).
- Export large query outputs cleanly with `--out <path>` (refuses symlinks and overwrites unless `--force`).
