**Languages:** English | [简体中文](README.zh-CN.md)

<h1 align="center">agent-dbctl</h1>

<p align="center"><strong>Let AI coding agents query your databases — without sharing passwords or risking production.</strong></p>

<p align="center">A single zero-JVM binary for Claude Code, Codex, Cursor, and OpenCode with EXPLAIN scan checks, per-environment guardrails, human Web approvals, and hash-chained audit logs across 13 database families.</p>

<p align="center">
  <a href="https://github.com/x0c/agent-dbctl/releases/latest"><img src="https://img.shields.io/github/v/release/x0c/agent-dbctl" alt="Latest Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/x0c/agent-dbctl" alt="MIT License"></a>
</p>

> **100% Local Execution · Zero Telemetry · Zero JVM · Keychain-Backed Credentials · Hash-Chained Audit**

<p align="center">
  <img src="docs/images/approvals.png" alt="agent-dbctl local Web Console showing a production UPDATE awaiting human approval" />
</p>
<p align="center"><em>A production write paused for review in the local Web Console — inspect the exact query, target, and reason, then approve or reject with feedback for the agent.</em></p>

## Why Not Let Agents Run `psql` Directly?

Giving a coding agent raw database CLI tools means handing it connection strings with passwords, hoping it never runs an unindexed full table scan, and hoping it remembers `WHERE` on an `UPDATE`.

`agent-dbctl` sits between your coding agent and your databases:

1. **Credentials stay out of prompts and files.** Store passwords in your OS Keychain, environment variables, or external secret commands. You can register a database from the CLI and enter its password yourself in the browser.
2. **Risky reads are checked before they run.** On staging and production targets, `agent-dbctl` runs a non-mutating `EXPLAIN` check first (never `ANALYZE`) to catch full table scans and high-cost operations before touching data.
3. **You approve or reject in a local Web Console.** Writes, schema changes, and high-cost queries pause on `127.0.0.1`. If you reject a query with a note like *"Add LIMIT 100"*, the agent gets your feedback and can fix the query.
4. **Every action is hash-chained.** Catalog changes, queries, and approval decisions are recorded in a tamper-evident SHA-256 audit log, while sensitive query results stay out of the audit ledger.

## Supported Platforms

- **macOS** (Apple Silicon `arm64` & Intel `amd64`, with Keychain credential storage)
- **Linux** (`amd64` & `arm64`)
- **Windows** (`amd64` & `arm64`)

## Install

### macOS & Linux (Homebrew)

```sh
brew install x0c/tap/agent-dbctl
```

### macOS & Linux (Shell Installer)

```sh
curl -fsSL https://raw.githubusercontent.com/x0c/agent-dbctl/main/scripts/install.sh | bash
```

### Windows (PowerShell)

```powershell
irm https://raw.githubusercontent.com/x0c/agent-dbctl/main/scripts/install.ps1 | iex
```

If `agent-dbctl` is not found in a new shell, add the installer's reported directory to `PATH`.

<details>
<summary>Alternative: Build from source (Go 1.26.11+ & Node.js 22+)</summary>

```sh
git clone https://github.com/x0c/agent-dbctl.git
cd agent-dbctl
make install-local
```

</details>

## Quick Start

### 1. Register a database without exposing its password

Open the local Web Console (`127.0.0.1`) to configure targets visually, or register from the CLI and enter the password in the browser:

```sh
# Opens the Keychain password dialog in your browser — no password enters shell history or agent context
agent-dbctl db add --engine postgres --host 127.0.0.1 --port 5432 \
  --database core --system orders --env prod \
  --user app_rw --access-level read_write --open-secret
```

Or open the console directly:

```sh
agent-dbctl ui open
```

### 2. Let your coding agent discover targets and inspect schemas

Running `agent-dbctl` silently syncs its companion `SKILL.md` into detected local agent skill directories (`~/.claude/skills`, `~/.codex/skills`, `~/.cursor/skills`, `~/.config/opencode/skills`, `~/.agents/skills`) without altering other skills or your manual edits.

From inside any project directory, `agent-dbctl` automatically matches databases bound to that workspace path or Git remote (including worktrees):

```sh
agent-dbctl db list
agent-dbctl db schema orders/prod/core
```

<details>
<summary>Disable automatic skill sync or check sync status</summary>

```sh
agent-dbctl skill status
export AGENT_DBCTL_NO_SKILL_SYNC=1
```

</details>

### 3. Run reads safely and gate production changes

```sh
# Preview the query plan on production without executing
agent-dbctl exec --db orders/prod/core --preflight --sql "SELECT id, status FROM orders WHERE id = 42"

# Safe reads execute and return bounded rows
agent-dbctl exec --db orders/prod/core --sql "SELECT id, status FROM orders WHERE id = 42"

# Writes, DDL, and full scans on staging/prod pause for Web approval
agent-dbctl exec --db orders/prod/core --reason "Archive test order" \
  --sql "UPDATE orders SET status = 'archived' WHERE id = 2"
```

<details>
<summary>How coding agents handle pending approvals without timing out</summary>

When `agent-dbctl exec` runs in a non-TTY agent shell, it defaults to `--wait=false`. If human approval is needed, it exits immediately with code `7` (`waiting_approval`) and returns an `operation_id` plus `approval_url` so the agent can wait or check back cleanly:

```sh
agent-dbctl exec --db orders/prod/core --reason "Archive test order" --wait=false \
  --sql "UPDATE orders SET status = 'archived' WHERE id = 2" --json
agent-dbctl op wait <operation_id> --timeout 60s --json
```

</details>

<p>
  <img src="docs/images/catalog.png" alt="agent-dbctl Systems and Databases catalog view" width="49%" />
  <img src="docs/images/audit.png" alt="agent-dbctl Audit Logs and SHA-256 Hash Chain verification" width="49%" />
</p>
<p><em>Left: Organize systems, environments, and read/write credentials in one catalog. Right: Inspect executed queries and verify the SHA-256 audit hash chain.</em></p>

## Key Capabilities

- **Environment-based safety tiers**: `dev` runs freely; `staging` and `prod` run `EXPLAIN` preflight checks, require a `--reason`, and trigger bilingual (English / Chinese) Web approvals on writes, schema changes, full table scans, or expensive Redis/MongoDB commands.
- **Custom high-risk pattern rules**: Add regex or preset rule packs to block dangerous patterns or require extra confirmation — even on `dev` databases.
- **Separate read-only and read-write credentials**: Bind distinct `ro` and `rw` credentials per target so `db schema`, `--preflight`, and `--test` probes use read-only access whenever available.
- **Repo and worktree auto-matching**: Bind databases to workspace paths and Git remotes so agents automatically prioritize the right targets across clones and Git worktrees.
- **Declarative YAML/JSON topology**: Export and apply sanitized catalog and policy bundles (`agent-dbctl topology export` / `topology apply`) across machines without leaking secrets.
- **Agent-friendly CLI contract**: Human-readable tables in interactive terminals, structured JSON for agents, whole-row truncation counts, atomic `--out` file exports, and non-retryable write timeouts.
- **Pluggable approvals and external drivers**: Use the built-in local Web Console or signed webhook notifications, and extend to custom engines via SHA-256-verified gRPC driver plugins.

## Supported Databases

Queries are forwarded verbatim in each database's native syntax — with no lossy ORM mapping or cross-dialect rewriting. Run `agent-dbctl driver list` to inspect all dialect aliases and default ports.

| Category | Built-in Engines & Compatible Dialects |
|---|---|
| **PostgreSQL & Derivatives** | PostgreSQL, CockroachDB, Redshift, YugabyteDB, Greenplum, AlloyDB, HighGo, UXDB, OpenTenBase, PolarDB-PG, TDSQL-PG |
| **openGauss & Derivatives** | openGauss, GaussDB, Vastbase, MogDB, GBase 8c |
| **KingbaseES & Dameng** | KingbaseES (`kingbase8`, `kes`), Dameng DM8 (`dm`, `dm8`) |
| **MySQL & Derivatives** | MySQL, MariaDB, TiDB, OceanBase, PolarDB, TDSQL, GoldenDB, GreatSQL, GBase 8a, Apache Doris, StarRocks, SelectDB |
| **Embedded & Time-Series / OLAP** | SQLite, ClickHouse, TDengine |
| **Enterprise Commercial** | Microsoft SQL Server (Azure SQL), Oracle Database |
| **Document, Search & KV** | MongoDB (JSON `RunCommand` / `show collections`, DocumentDB, FerretDB), Elasticsearch / OpenSearch / Easysearch, Redis / Valkey / Dragonfly / KeyDB |
| **Custom Engines** | External gRPC driver subprocesses verified by SHA-256 checksum |

## Team Server Deployment (Optional)

For teams that want centralized PostgreSQL metadata, AES-256-GCM encrypted credential storage, Redis event/result relay, RBAC permissions, and remote Web approvals:

```sh
cp .env.example .env
# Set POSTGRES_PASSWORD, AGENT_DBCTL_MASTER_KEY (`openssl rand -hex 32`),
# and optionally AGENT_DBCTL_BOOTSTRAP_ADMIN_PASSWORD in .env
docker compose up -d --build
```

To enable automatic HTTPS via Caddy (for example, `https://dbctl.example.com`):

```sh
# Set SITE_HOST=dbctl.example.com and AGENT_DBCTL_PUBLIC_URL=https://dbctl.example.com in .env,
# and add your domain to allowed_hosts in a custom config referenced by AGENT_DBCTL_CONFIG_FILE.
docker compose --profile tls up -d --build
```

Connect your local CLI to the team server:

```sh
agent-dbctl context add prod --endpoint https://dbctl.example.com --use
agent-dbctl login --token-stdin
```

## Documentation

- [Architecture & Security Boundaries](docs/ARCHITECTURE.md)
- [CLI Contract & Exit Codes](docs/CLI_CONTRACT.md)
- [Read-Risk Audit Matrix](docs/READ_RISK_AUDIT.md)
- [External gRPC Driver & Approval Plugin Protocol](docs/PLUGIN_PROTOCOL.md)
- [Security Policy](SECURITY.md) · [Contributing](CONTRIBUTING.md) · [Changelog](CHANGELOG.md)

## License

[MIT License](LICENSE)

If `agent-dbctl` keeps your coding agents safely away from production accidents, consider starring the repository so it is easy to find later.

## Related Tools

| Repository | Description |
|---|---|
| **[corral](https://github.com/corral-dev/corral)** | Search, resume, and hand off local Claude Code, Codex CLI, Cursor, and OpenCode sessions. |
| **[subswap](https://github.com/x0c/subswap)** | Check remaining quota and switch Claude Code, Codex, Cursor, Kimi Code, and OpenCode accounts without logging out. |
| **[agentsync](https://github.com/x0c/agentsync)** | Sync `AGENTS.md`, `CLAUDE.md`, skills, and MCP configs across coding agents from one local source of truth. |
| **[agent-doc-skills](https://github.com/x0c/agent-doc-skills)** | Navigable project knowledge base skills (`doc-init`, `doc-update`, `doc-compact`) for coding agents. |
| **[shell-gate](https://github.com/x0c/shell-gate)** | Self-hosted Go browser terminal gateway for ttyd with passkeys, TOTP 2FA, and persistent tabs. |
| **[sesskit](https://github.com/x0c/sesskit)** | Parse and export local Claude Code, Codex CLI, and Cursor session transcript files from disk. |
