# agent-dbctl Roadmap

This roadmap prioritizes verified behavior and adoption feedback over release count. Items move only when their acceptance path passes; local macOS success does not substitute for platform coverage.

## P0 — Trustworthy Releases

- **Three-platform quality gate**: Linux (`-race`), macOS (`-race`), and Windows tests must pass on the exact source commit. Investigate platform failures individually rather than treating repeated runs as a fix.
- **Stable release attestation**: `scripts/release.py` refuses stable archives without a successful `CI` run and all three platform jobs for that commit. Prerelease-only local packaging retains an explicit `--skip-ci-check` path.
- **Complete contributor checks**: Run the privacy check, Web typecheck/build, Go race tests, release-gate unit tests, lint, vulnerability scan, and targeted benchmarks from [CONTRIBUTING.md](../CONTRIBUTING.md), preserving complete diagnostics.
- **Real client/server acceptance**: Exercise the packaged deployment on Linux with PostgreSQL, Redis, OIDC/device login, remote CLI discovery, a guarded execution, human approval, and audit-chain verification. Record any environment boundary separately from product failures.

## P1 — Measurable User Feedback

- Route reproducible defects and feature requests through the GitHub issue forms, with version, platform, engine, redacted JSON output, and real-path evidence.
- Track issue-to-first-response time, issue-to-fixed-version lead time, release rollback/hotfix rate, and the proportion of stable releases with exact-commit green CI. Publish targets only after enough external reports exist to establish a baseline.
- Convert each confirmed user-visible defect into a regression test and update the relevant architecture, CLI, risk, or deployment authority in the same change.

## P2 — Predictable Adoption

- Keep one-command installation for macOS, Linux, and Windows, and document explicit version pinning for teams that need repeatable rollouts.
- Verify the published installer and checksum path on every supported platform for each stable release; packaging success alone is not installation evidence.
- Prefer small, acceptance-scoped stable versions over batches of unrelated features. Use prerelease archives for unverified local or experimental builds rather than promoting them to `latest`.

## Explicit Boundaries

- No feature enters a stable release solely because its implementation is complete; its documented real-user path must pass.
- No new engine bypasses the classifier, preflight, policy, regression-test, and [read-risk audit](READ_RISK_AUDIT.md) requirements.
- Roadmap order can change from reproducible user impact, security risk, or data-integrity evidence; it does not change from feature volume alone.
