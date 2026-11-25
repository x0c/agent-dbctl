# agent-dbctl

Database execution gate, system/database asset catalog, local Web approval console, and append-only hash-chain audit log for AI coding agents and engineers. Do not store credentials, personal paths, or private infrastructure addresses in repository files.

## Document index

Read the relevant document(s) before making design, protocol, CLI contract, or UI changes:

- [README.md](README.md): Public overview, supported platforms, installation, and quick start.
- [README.zh-CN.md](README.zh-CN.md): Complete Simplified Chinese overview and quick start.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): System boundaries, four-layer catalog (`System` -> `Environment` -> `Instance` -> `Target`), declarative onboarding & read-only `PlanTopologyImport`, network/credential decoupling, driver connection/multi-version contracts, pooling/dialect primitives and pending daemon wiring, hardened classifier + custom `RiskPatternRule` + `EXPLAIN` preflight, 4-level monotonic policy inheritance, `ApprovalProvider` abstraction, append-only hash-chain audit log, hardened local Web session-cookie/CSRF guard, and silent companion skill sync.
- [docs/READ_RISK_AUDIT.md](docs/READ_RISK_AUDIT.md): Empirically verified dangerous and high-load read statement matrix across PostgreSQL, MySQL, SQLite, MongoDB, and Redis, audited classifier/preflight/policy gaps, implemented remediations, and remaining boundaries.
- [docs/CLI_CONTRACT.md](docs/CLI_CONTRACT.md): `agent-friendly-cli` contract, command hierarchy (including declarative `db add`/`set`/`delete`, `system`/`env`/`network`/`cred`/`instance`, `topology schema|export|apply`, `security`/`policy`/`pattern`, and zero-secret Keychain Web handoff `ui open --credential`), flags and aliases, JSON envelope `{ok, data, error, meta}`, OS exit codes (`0..7`), semantic `error.code` catalog, `--dry-run` vs `--preflight`, `--wait=false` + `op status`/`wait`/`cancel`, `audit list`/`export`, `doctor --live`, `describe`, truncation & `--out`, companion skill management, and environment variable overrides.
- [docs/PLUGIN_PROTOCOL.md](docs/PLUGIN_PROTOCOL.md): Tier-3 external gRPC driver plugin protocol (`v1` `Struct` & `v2` typed Protobuf + `Cancel` RPC), `manifest.json` schema, SHA-256 verification, capability-gated dispatch, loopback tunnel bridge, and `ApprovalProvider` (`local-web`, `webhook`, custom) contract.
- [skills/agent-dbctl/SKILL.md](skills/agent-dbctl/SKILL.md): Canonical companion coding-agent skill synced to local agent skill directories.
- [SECURITY.md](SECURITY.md): Threat model, local execution guarantees, and private vulnerability reporting.
- [CONTRIBUTING.md](CONTRIBUTING.md): Development checks, live multi-database test workflow, local binary installation caveats, and CI-independent local release packaging.
- [CHANGELOG.md](CHANGELOG.md): Bilingual release notes.

## Invariants

- **Zero JVM**: No Java/JDBC runtime or sidecar components. Built-in drivers are pure Go (`CGO_ENABLED=0`); external drivers run via language-agnostic gRPC subprocesses (`hashicorp/go-plugin`).
- **Control vs Execution Separation**: Both the CLI (over the private `0600` daemon RPC socket/token channel) and the local Web Console manage the four-layer catalog, topology, discovery, global security guardrails, scoped policies, and custom risk pattern rules with same-transaction hash-chain audit logging. Execution approval resolution (`approve`/`reject`) remains human-confirmed via the hardened local Web Console (loopback `Host`, same-origin checks, per-session `HttpOnly` cookie + `X-Agent-DBCTL-CSRF` token, or one-time `approval_token`) or external `ApprovalProvider`. The CLI never prints secrets or connection strings and supports blank Keychain password setup + Web handoff (`--open-secret` / `ui open --credential`) alongside env, stdin, file, `env_ref`, and `exec_provider`.
- **Verbatim Forwarding**: `agent-dbctl` never translates or rewrites SQL/Mongo/Elasticsearch/Redis dialects across engines (except read-only `EXPLAIN`/`SHOWPLAN`/`_validate` preflight wrapping).
- **Same-Transaction Audit**: Every catalog/policy/approval mutation and every execution lifecycle event writes `actor`, `action`, `target_id`, and `timestamp` to the append-only hash-chain `audit_logs` table in the same SQLite transaction.
- **Silent Companion Skill Ownership**: Auto-sync never pollutes stdout/stderr, never overwrites symlinks or user-modified `SKILL.md` files unless `--force` is passed, and respects `AGENT_DBCTL_NO_SKILL_SYNC`.
- **Clean Public Exports**: Verify `python3 scripts/check-public.py` and keep committed trees free of private hosts, personal paths, or internal registry references.
