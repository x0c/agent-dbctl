# Security Policy

## Local Execution & Data Handling

- **100% Local Execution**: `agent-dbctl` runs locally as a single Go binary with an embedded Web Console bound exclusively to loopback (`127.0.0.1`). Zero telemetry, cloud accounts, or analytics endpoints are contacted.
- **Credential Isolation**: Passwords and SSH bastion keys live in your OS Keychain (`keychain` backend on macOS), environment variables (`env_ref`), or external secret-manager commands (`exec_provider`)—never inside the SQLite catalog or CLI stdout.
- **Companion Skill Safety**: `agent-dbctl` syncs only its own `agent-dbctl/SKILL.md` into detected local coding-agent skill directories (`~/.claude/skills`, `~/.codex/skills`, `~/.cursor/skills`, `~/.config/opencode/skills`, `~/.agents/skills`, etc.), tracks ownership by SHA-256 in `<config_home>/skills/registrations.json`, refuses symlinks, preserves locally edited files unless `--force` is given, and can be disabled with `AGENT_DBCTL_NO_SKILL_SYNC=1`.

## Trust Boundary

- `agent-dbctl` separates configuration and approval writes (human-facing local Web UI with same-origin + token checks) from agent CLI execution (configuration read-only).
- Production safety depends on assigning databases to `guarded` (`staging`) or `strict` (`prod`) environments and configuring separate read-only (`ro_credential_id`) vs read-write (`rw_credential_id`) credentials.

## Reporting a Vulnerability

Please report suspected security vulnerabilities privately through GitHub's private vulnerability reporting on `https://github.com/x0c/agent-dbctl/security/advisories/new`. Do not open public issues for unpatched security bugs.
