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
golangci-lint run --max-same-issues=0 --max-issues-per-linter=0 ./...
govulncheck ./...
```

Do not include credentials, private network addresses, or personal home-directory paths anywhere in source files, tests, or screenshots.

### Live Multi-Database Integration Tests

To run `TestLiveMultiDatabaseEngines` against real database instances (PostgreSQL, MySQL, MongoDB, Redis, ClickHouse, SQL Server, Oracle, Elasticsearch) over your private test host, supply credentials strictly through environment variables:

```sh
AGENT_DBCTL_LIVE_TEST=1 \
AGENT_DBCTL_TEST_HOST=<test-host> \
AGENT_DBCTL_TEST_RW_PASS='<rw-password>' \
AGENT_DBCTL_TEST_RO_PASS='<ro-password>' \
go test -v ./internal/daemon -run TestLiveMultiDatabaseEngines
```

> **macOS install note**: `make install-local` stages a temporary file and atomically replaces `~/.local/bin/agent-dbctl` (`mv -f`) to avoid in-place Mach-O signature invalidation (`SIGKILL` / exit 137) on Apple Silicon macOS.

## Local Release Packaging

Release packaging works locally without depending on CI queues:

```sh
python3 scripts/release.py --version vX.Y.Z
```

`agent-dbctl` source code is [MIT licensed](LICENSE).
