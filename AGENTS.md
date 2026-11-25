# agent-dbctl

Database execution gate, system/database asset catalog, local Web approval console, and append-only hash-chain audit log for AI coding agents and engineers. Do not store credentials, personal paths, or private infrastructure addresses in repository files.

## Document Navigation

Read the relevant document(s) before making design, protocol, CLI contract, or UI changes:

- [README.md](README.md): Public overview, supported platforms, installation, and quick start.
- [README.zh-CN.md](README.zh-CN.md): Complete Simplified Chinese overview and quick start.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): System boundaries, four-layer catalog (`System` -> `Environment` -> `Instance` -> `Target`), network/credential decoupling, classifier + `EXPLAIN` preflight, 4-level monotonic policy inheritance, `ApprovalProvider` abstraction, append-only hash-chain audit log, and silent companion skill sync.
- [docs/CLI_CONTRACT.md](docs/CLI_CONTRACT.md): `agent-friendly-cli` contract, command hierarchy, flags and aliases, JSON envelope `{ok, data, error, meta}`, OS exit codes (`0..7`), semantic `error.code` catalog, `--dry-run` vs `--preflight`, `--wait=false` + `op status`, truncation & `--out`, companion skill management, and environment variable overrides.
- [docs/PLUGIN_PROTOCOL.md](docs/PLUGIN_PROTOCOL.md): Tier-3 external gRPC driver plugin protocol (`proto/driver/v1/driver.proto`), `manifest.json` schema, SHA-256 integrity verification, and `ApprovalProvider` extension contract.
- [skills/agent-dbctl/SKILL.md](skills/agent-dbctl/SKILL.md): Canonical companion coding-agent skill synced to local agent skill directories.
- [SECURITY.md](SECURITY.md): Threat model, local execution guarantees, and private vulnerability reporting.
- [CONTRIBUTING.md](CONTRIBUTING.md): Development checks and CI-independent local release packaging.
- [CHANGELOG.md](CHANGELOG.md): Bilingual release notes.

## Invariants

- **Zero JVM**: No Java/JDBC runtime or sidecar components. Built-in drivers are pure Go (`CGO_ENABLED=0`); external drivers run via language-agnostic gRPC subprocesses (`hashicorp/go-plugin`).
- **Control vs Execution Separation**: Configuration writes, environment tagging, policy changes, and production approvals happen strictly in the human-facing local Web UI (or verified local HTTP endpoints with same-origin + token checks). The CLI is read-only for catalog/policy configuration and never prints secrets or connection strings.
- **Verbatim Forwarding**: `agent-dbctl` never translates or rewrites SQL/Mongo/Redis dialects across engines (except read-only `EXPLAIN` preflight wrapping).
- **Same-Transaction Audit**: Every catalog/policy/approval mutation and every execution lifecycle event writes `actor`, `action`, `target_id`, and `timestamp` to the append-only hash-chain `audit_logs` table in the same SQLite transaction.
- **Silent Companion Skill Ownership**: Auto-sync never pollutes stdout/stderr, never overwrites symlinks or user-modified `SKILL.md` files unless `--force` is passed, and respects `AGENT_DBCTL_NO_SKILL_SYNC`.
- **Clean Public Exports**: Verify `python3 scripts/check-public.py` and keep committed trees free of private hosts, personal paths, or internal registry references.
