**Languages:** English | [简体中文](README.zh-CN.md)

# agent-dbctl

Run PostgreSQL, MySQL, SQLite, MongoDB, and Redis queries safely from Claude Code, Codex, Cursor, and OpenCode. Get EXPLAIN scan preflight, per-environment guardrails, human Web approvals, and immutable hash-chained audit logs in a single zero-JVM binary.

> **100% Local Execution · Zero Telemetry · Zero JVM · Keychain-Backed Credentials · Hash-Chained Audit**

![agent-dbctl approval queue](docs/images/approvals.png)

## Supported Platforms

- **macOS** (Apple Silicon `arm64` & Intel `amd64`, Keychain + embedded Web Console)
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

Add the installer's reported directory to `PATH` if `agent-dbctl` is not found in a new shell.

<details>
<summary>Alternative: Build from source (Go 1.26.11+ & Node.js 22+)</summary>

```sh
git clone https://github.com/x0c/agent-dbctl.git
cd agent-dbctl
make install-local
```

</details>

## Quick Start

1. **Open the local Web Console** (`127.0.0.1`) to register a system, instance, credentials (stored in your OS Keychain / env / exec provider), and database target:

   ```sh
   agent-dbctl ui open
   ```

2. **Let your coding agent discover targets matching the current repo and inspect or query safely**:

   ```sh
   agent-dbctl db list --json
   agent-dbctl exec --db order-core/prod/orders --preflight --sql "SELECT id, status FROM orders WHERE id = 42" --json
   agent-dbctl exec --db order-core/prod/orders --reason "Fix order state" --wait=false --sql "UPDATE orders SET status = 'paid' WHERE id = 42" --json
   agent-dbctl op status <operation_id> --json
   ```

3. **Automatic companion agent skill**: Running `agent-dbctl` silently syncs `SKILL.md` into detected local agent skill roots (`~/.claude/skills`, `~/.codex/skills`, `~/.cursor/skills`, `~/.config/opencode/skills`, `~/.agents/skills`) without touching unrelated skills or user-edited copies.

   ```sh
   agent-dbctl skill status --json
   # Disable auto-sync if preferred:
   export AGENT_DBCTL_NO_SKILL_SYNC=1
   ```

<p>
  <img src="docs/images/catalog.png" alt="agent-dbctl Systems and Databases catalog" width="49%" />
  <img src="docs/images/audit.png" alt="agent-dbctl Audit Logs and Hash Chain verification" width="49%" />
</p>

## Why agent-dbctl?

| Capability | Behavior |
|---|---|
| **Four-Layer Enterprise Catalog** | Organize `System` (with `workspace_paths` auto-priority) -> `Environment` -> `NetworkProfile` / `CredentialProfile` -> `Instance` / `Target` (`ro_credential_id` & `rw_credential_id` split). Export/import sanitized topology as YAML/JSON. |
| **Environment Safety Tiers** | **`dev` (`yolo`)** runs freely; **`staging` (`guarded`)** & **`prod` (`strict`)** run EXPLAIN preflight and trigger browser approval on writes, DDL, full table scans, or high-cost Redis/Mongo commands. |
| **Verbatim Dialect Forwarding** | Native PostgreSQL, MySQL/MariaDB/TiDB, SQLite, MongoDB (`RunCommand` JSON), and Redis commands forwarded verbatim—no lossy ORM or SQL translation. |
| **Agent-Friendly CLI Contract** | Dual-audience TTY tables + `--json` `{ok, data, error, meta}` envelope, single-source `describe`, bounded row/byte truncation on intact boundaries, atomic `--out`, and non-replayable write timeouts. |
| **Pluggable Approvals & Drivers** | Decoupled `ApprovalProvider` (`local-web` built in; extensible to external ticket flows) plus `hashicorp/go-plugin` gRPC external driver subprocesses verified by SHA-256 and `host_api_version`. |
| **Immutable Hash-Chain Audit** | Append-only SQLite WAL `audit_logs` chained via SHA-256 (`agent-dbctl audit verify`) with query result payloads kept out of the audit ledger. |

## Documentation

- [Architecture & Security Boundaries](docs/ARCHITECTURE.md)
- [CLI Contract & Exit Codes](docs/CLI_CONTRACT.md)
- [External gRPC Driver & Approval Plugin Protocol](docs/PLUGIN_PROTOCOL.md)
- [Security Policy](SECURITY.md) · [Contributing](CONTRIBUTING.md) · [Changelog](CHANGELOG.md)

## License

[MIT License](LICENSE)

## Related Tools

| Repository | Description |
|---|---|
| **[corral](https://github.com/corral-dev/corral)** | Search, resume, and hand off local Claude Code, Codex CLI, Cursor, and OpenCode sessions. |
| **[subswap](https://github.com/x0c/subswap)** | Check remaining quota and switch Claude Code, Codex, Cursor, Kimi Code, and OpenCode accounts without logging out. |
| **[agentsync](https://github.com/x0c/agentsync)** | Sync `AGENTS.md`, `CLAUDE.md`, skills, and MCP configs across coding agents from one local source of truth. |
| **[agent-doc-skills](https://github.com/x0c/agent-doc-skills)** | Navigable project knowledge base skills (`doc-init`, `doc-update`, `doc-compact`) for coding agents. |
| **[shell-gate](https://github.com/x0c/shell-gate)** | Self-hosted Go browser terminal gateway for ttyd with passkeys, TOTP 2FA, and persistent tabs. |
| **[sesskit](https://github.com/x0c/sesskit)** | Parse and export local Claude Code, Codex CLI, and Cursor session transcript files from disk. |
