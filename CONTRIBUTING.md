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

## Local Release Packaging

Release packaging works locally without depending on CI queues:

```sh
python3 scripts/release.py --version vX.Y.Z
```

`agent-dbctl` source code is [MIT licensed](LICENSE).
