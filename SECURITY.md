# Security Policy

## Local Execution & Data Handling

- **100% Local Execution**: `agent-dbctl` runs locally as a single Go binary with an embedded Web Console bound exclusively to loopback (`127.0.0.1`). Zero telemetry, cloud accounts, or analytics endpoints are contacted.
- **Credential & Webhook Hardening**: Passwords and SSH bastion keys live in your OS Keychain (`keychain` backend on macOS, validating `-s`/`-a` identifiers before `security -i` stdin formatting), environment variables (`env_ref`), or shell-free quote-aware external commands (`exec_provider`, 64 KiB stdout cap, no secret echo on errors)—never inside the SQLite catalog or CLI stdout. Remote webhook approval endpoints require `https://` (`http://` is limited to loopback), sign payloads with HMAC-SHA256 when configured, and omit one-time approval tokens from webhook notifications.
- **Private Storage & Append-Only Audit**: The config directory (`0700`) and SQLite database (explicitly `0600` on Unix) isolate local state; `audit_logs` is append-only with a SHA-256 hash chain and multi-engine credential/literal redaction, while query result payloads remain in a bounded in-memory `ResultSlot` cache (64 slots / 32 MiB) rather than SQLite.
- **Companion Skill Safety**: `agent-dbctl` syncs only its own `agent-dbctl/SKILL.md` into detected local coding-agent skill directories (`~/.claude/skills`, `~/.codex/skills`, `~/.cursor/skills`, `~/.config/opencode/skills`, `~/.agents/skills`, etc.), tracks ownership by SHA-256 in `<config_home>/skills/registrations.json`, refuses symlinks, preserves locally edited files unless `--force` is given, and can be disabled with `AGENT_DBCTL_NO_SKILL_SYNC=1`.

## Trust Boundary

- **CLI vs Human Approval Separation**: Coding agents and engineers can manage the four-layer catalog, topology bundles, instance discovery, security guardrails, and custom risk pattern rules via the `agent-dbctl` CLI over the private `0600` daemon RPC channel (`Unix` domain socket on macOS/Linux, `0600` loopback token on Windows). Execution approval decisions (`approve` / `reject`) are intentionally excluded from CLI/RPC and require human confirmation in the local Web Console or an external `ApprovalProvider`.
- **Hardened Local Web Console**: All `/api/v1/*` requests validate loopback `Host` headers (`127.0.0.1`, `localhost`, `[::1]`) against DNS rebinding. Mutating Web requests enforce strict browser same-origin headers (`Origin`/`Sec-Fetch-Site`/`Referer`, rejecting headerless requests) plus a per-daemon cryptographic `HttpOnly; SameSite=Strict` session cookie (`agent_dbctl_session`) and `X-Agent-DBCTL-CSRF` token (or a one-time `approval_token` for deep-link approval actions).
- **Zero-Secret Web Handoff**: Agents can register `keychain` credentials with a blank password via CLI and open `ui open --credential <name-or-id>` (or `--open-secret`) so humans enter passwords directly in the local Web UI without ever exposing secrets to the agent or CLI history. Production safety depends on assigning databases to `guarded` (`staging`) or `strict` (`prod`) environments and configuring separate read-only (`ro_credential_id`) vs read-write (`rw_credential_id`) credentials.

## Reporting a Vulnerability

Please report suspected security vulnerabilities privately through GitHub's private vulnerability reporting on `https://github.com/x0c/agent-dbctl/security/advisories/new`. Do not open public issues for unpatched security bugs.
