# Contributing to agent-dbctl

Thank you for contributing!

## Prerequisites

- **Go 1.26.11+** (`CGO_ENABLED=0` for static builds; `-race` requires a C compiler)
- **Node.js 22+** and `npm` (only for rebuilding `web/` embedded UI assets)
- **golangci-lint v2** and **govulncheck** (recommended before pushing changes)

## Local Checks

```sh
python3 scripts/check-public.py
cd web && npm ci && npm run typecheck && npm run build && cd ..
go test -race -count=1 ./...
python3 -m unittest discover -s scripts/tests -v
go test -run=^$ -bench=. -benchmem ./internal/classify ./internal/policy ./internal/audit ./internal/driver ./internal/driver/builtin ./internal/store ./internal/daemon ./internal/skillinstall
golangci-lint run --max-same-issues=0 --max-issues-per-linter=0 ./...
govulncheck ./...
```

Do not include credentials, private network addresses, or personal home-directory paths anywhere in source files, tests, or screenshots.

### Live Multi-Database Integration Tests

To run `TestLiveMultiDatabaseEngines` against real database instances (PostgreSQL, MySQL, MongoDB, Redis, ClickHouse, SQL Server, Oracle, Elasticsearch, openGauss, Dameng DM8, TDengine, Easysearch) over your private test host, supply credentials strictly through environment variables (`AGENT_DBCTL_TEST_TDENGINE_PASS` defaults to `taosdata`):

```sh
AGENT_DBCTL_LIVE_TEST=1 \
AGENT_DBCTL_TEST_HOST=<test-host> \
AGENT_DBCTL_TEST_RW_PASS='<rw-password>' \
AGENT_DBCTL_TEST_RO_PASS='<ro-password>' \
go test -v ./internal/daemon -run TestLiveMultiDatabaseEngines
```

Without a validly licensed KingbaseES test instance, KingbaseES wire behavior (including default `TLSMode` SSL fallback) is verified offline via mock PostgreSQL wire-protocol tests in `internal/driver/builtin` and default-parameter daemon/CLI probes.

### Packaged Linux Server Smoke

On a Linux host with Docker Compose, build `dist/agent-dbctl` and run `python3 scripts/server_smoke.py`. The isolated stack uses PostgreSQL control-plane storage, Redis events/results, an RS256/PKCE OIDC fixture, real CLI device confirmation, two independent human approvals, readback, and audit verification. It creates synthetic users/data and removes its own containers, volumes, image, and temporary client configuration afterward. The CI `server-smoke` job is mandatory for stable release attestation.

> **macOS install note**: `make install-local` stages a temporary file and atomically replaces `~/.local/bin/agent-dbctl` (`mv -f`) to avoid in-place Mach-O signature invalidation (`SIGKILL` / exit 137) on Apple Silicon macOS.

## Local Release Packaging

Stable release archives require a successful `CI` workflow run for the exact source commit, including the Linux, macOS, and Windows jobs plus the Linux Compose/OIDC/remote-approval server smoke job. Packaging fails closed when that run is pending, failed, or unavailable; a green run for another commit or for macOS alone is not release evidence.

```sh
python3 scripts/release.py --version vX.Y.Z
```

Local packaging remains independent of CI queues only for versions with a prerelease suffix. `--skip-ci-check` is restricted to those prereleases and must not be used to publish a stable version:

```sh
python3 scripts/release.py --version vX.Y.Z-rc.1 --skip-ci-check
```

`agent-dbctl` source code is [MIT licensed](LICENSE).
