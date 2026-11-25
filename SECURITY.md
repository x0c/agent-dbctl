# Security Policy

## Local Execution & Data Handling

- **100% Local Execution**: `agent-dbctl` runs locally as a single Go binary with an embedded Web Console bound exclusively to loopback (`127.0.0.1`). Zero telemetry, cloud accounts, or analytics endpoints are contacted.
- **Credential & Webhook Hardening**: Passwords and SSH bastion keys live in your OS Keychain (`keychain` backend on macOS, validating `-s`/`-a` identifiers before `security -i` stdin formatting), environment variables (`env_ref`), or shell-free quote-aware external commands (`exec_provider`, 64 KiB stdout cap, no secret echo on errors)—never inside the SQLite catalog or CLI stdout. Remote webhook approval endpoints require `https://` (`http://` is limited to loopback), sign payloads with HMAC-SHA256 when configured, and omit one-time approval tokens from webhook notifications.
- **Private Storage & Append-Only Audit**: The config directory (`0700`) and SQLite database (explicitly `0600` on Unix) isolate local state; `audit_logs` is append-only with a SHA-256 hash chain and multi-engine credential/literal redaction, while query result payloads remain in a bounded in-memory `ResultSlot` cache (64 slots / 32 MiB) rather than SQLite.
- **Companion Skill Safety**: `agent-dbctl` syncs only its own `agent-dbctl/SKILL.md` into detected local coding-agent skill directories (`~/.claude/skills`, `~/.codex/skills`, `~/.cursor/skills`, `~/.config/opencode/skills`, `~/.agents/skills`, etc.), tracks ownership by SHA-256 in `<config_home>/skills/registrations.json`, refuses symlinks, preserves locally edited files unless `--force` is given, and can be disabled with `AGENT_DBCTL_NO_SKILL_SYNC=1`.

## Trust Boundary

- `agent-dbctl` separates configuration and approval writes (human-facing local Web UI) from agent CLI execution (configuration read-only). Local HTTP mutating endpoints enforce browser same-origin checks (`Origin`/`Sec-Fetch-Site`/`Referer`), while direct non-browser loopback requests and the static `X-Agent-DBCTL-UI: 1` SPA approval header are currently accepted pending replacement with a daemon-issued cryptographic UI session/CSRF token (`docs/ARCHITECTURE.md` §6); until then, the local OS user account is trusted against rogue local processes.
- Production safety depends on assigning databases to `guarded` (`staging`) or `strict` (`prod`) environments and configuring separate read-only (`ro_credential_id`) vs read-write (`rw_credential_id`) credentials.

## Reporting a Vulnerability

Please report suspected security vulnerabilities privately through GitHub's private vulnerability reporting on `https://github.com/x0c/agent-dbctl/security/advisories/new`. Do not open public issues for unpatched security bugs.
