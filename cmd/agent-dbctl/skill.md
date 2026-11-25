---
name: agent-dbctl
description: "Query, inspect, debug, or modify databases (PostgreSQL, MySQL, SQLite, MongoDB, Redis) safely through agent-dbctl instead of raw psql, mysql, mongosh, or redis-cli. Use whenever a task involves inspecting schemas or tables, debugging database state, running SQL/Mongo/Redis queries, checking EXPLAIN plans, or submitting staging/production data changes for human Web approval."
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

## 2. Standard Agent Workflow

1. **Inspect target metadata** (read-only; discovers environment safety tier, engine, aliases, and limits):
   ```sh
   "$BIN" db list --json
   "$BIN" db show <target-ref-or-alias> --json
   ```
2. **Dry-run or Preflight before risky or production queries**:
   ```sh
   "$BIN" exec --db <ref> --dry-run --sql "<query>" --json
   "$BIN" exec --db <ref> --preflight --sql "<query>" --json
   ```
   - `--dry-run` evaluates classification and policy locally without touching the database.
   - `--preflight` connects read-only and runs non-mutating `EXPLAIN` (never `ANALYZE`) to surface full scans and row estimates before execution.
3. **Execute verbatim queries with a clear business reason**:
   - Pass verbatim engine syntax (PostgreSQL/MySQL/SQLite SQL, MongoDB JSON `RunCommand`, or Redis commands). Do not ask `agent-dbctl` to translate dialects.
   - Prefer `--file <path>` or `--stdin` for multi-line SQL or JSON queries to avoid shell escaping errors.
   - Always pass `--reason "<concise reason>"` so human reviewers on the Web approval screen see why the operation is needed.
   - Use `--wait=false` when targeting `guarded`/`strict` (`staging`/`prod`) writes or broad reads, then poll `op status` or wait cleanly with `op wait`:
     ```sh
     "$BIN" exec --db <ref> --reason "Backfill stuck order state" --wait=false --sql "UPDATE ..." --json
     "$BIN" op status <operation_id> --json
     "$BIN" op wait <operation_id> --timeout 60s --json
     ```
   - Inspect or verify recent audit trails when auditing past runs:
     ```sh
     "$BIN" audit list --limit 20 --json
     "$BIN" audit verify --json
     ```

## 3. Reading Output & Recovering Safely

- Check `ok == true` (exit code `0`) rather than assuming non-empty stdout means success.
- **Exit `7` (`waiting_approval`)**: human confirmation is open in the Web Console. Poll `"$BIN" op status <operation_id> --json` or share `error.context.approval_url` with the user.
- **Exit `4` (`approval_rejected` / `policy_denied` / `prod_frozen`)**: read `error.hint` and `error.context.reviewer_note`. Never replay a rejected query verbatim; rewrite it according to the reviewer's feedback or stop.
- **Exit `6` (`query_timeout`)**: if `error.retryable` is `false` (write/DDL/unknown), **do not auto-replay**. Run a bounded read-only query first to verify whether the write landed.
- **Truncation honesty**: always check `data.truncated`, `data.fetched_rows`, and `data.returned_rows`. Never claim a table has only `returned_rows` records when `truncated == true`.

## 4. Hard Safety Rules

- Configuration writes (Systems, Environments, Networks, Credentials, Targets, Policies) and production approvals belong exclusively to the human Web Console (`agent-dbctl ui open`). Never ask the CLI for passwords/DSNs or modify `~/.config/agent-dbctl/` directly.
- Keep exploratory queries bounded (`LIMIT`, `--max-rows`, `--timeout`).
- Export large query outputs cleanly with `--out <path>` (refuses symlinks and overwrites unless `--force`).
