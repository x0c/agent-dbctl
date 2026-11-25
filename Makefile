VERSION := $(shell git describe --tags --always 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.buildCommit=$(COMMIT)
PLATFORMS := darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64 windows/arm64

.PHONY: all build-web sync-skill build build-all test lint vuln clean install-local

all: build

sync-skill:
	cp skills/agent-dbctl/SKILL.md cmd/agent-dbctl/skill.md

build-web:
	cd web && npm run typecheck && npm run build

build: build-web sync-skill
	CGO_ENABLED=0 GOTOOLCHAIN=go1.26.11 go build -trimpath -ldflags "$(LDFLAGS)" -o agent-dbctl ./cmd/agent-dbctl

build-all: build-web sync-skill
	mkdir -p dist
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		ext=""; if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
		out="dist/agent-dbctl-$$os-$$arch$$ext"; \
		echo "Building $$out..."; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch GOTOOLCHAIN=go1.26.11 go build -trimpath -ldflags "$(LDFLAGS)" -o "$$out" ./cmd/agent-dbctl || exit 1; \
	done
	./scripts/gen_manifest.sh "$(VERSION)" "$(COMMIT)"

test: build-web sync-skill
	GOTOOLCHAIN=go1.26.11 go test -race -v ./...

lint:
	GOTOOLCHAIN=go1.26.11 golangci-lint run --max-same-issues=0 --max-issues-per-linter=0 ./...

vuln:
	GOTOOLCHAIN=go1.26.11 govulncheck ./...

install-local: build
	mkdir -p ~/.local/bin
	cp agent-dbctl ~/.local/bin/agent-dbctl.tmp
	chmod 755 ~/.local/bin/agent-dbctl.tmp
	mv -f ~/.local/bin/agent-dbctl.tmp ~/.local/bin/agent-dbctl

clean:
	rm -rf agent-dbctl agent-dbctl-plugin-sqlite dist
