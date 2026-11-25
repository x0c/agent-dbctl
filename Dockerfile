# syntax=docker/dockerfile:1

FROM node:22-alpine AS web-builder
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN mkdir -p /src/internal/webui/dist && npm run typecheck && npm run build

FROM golang:1.26-alpine AS go-builder
ARG VERSION=dev
ARG COMMIT=dev
WORKDIR /src
ENV GOPROXY=https://goproxy.cn,direct
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN n=1; until [ $n -gt 3 ]; do \
      go mod download && exit 0; \
      echo "go mod download attempt $n failed; retrying" >&2; \
      n=$((n+1)); sleep 5; \
    done; exit 1
COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY skills/agent-dbctl/SKILL.md ./cmd/agent-dbctl/skill.md
COPY --from=web-builder /src/internal/webui/dist ./internal/webui/dist
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.buildCommit=${COMMIT}" \
    -o /out/agent-dbctl ./cmd/agent-dbctl

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -g 10001 -S agentdbctl \
    && adduser -u 10001 -S -G agentdbctl -h /var/lib/agent-dbctl agentdbctl \
    && mkdir -p /etc/agent-dbctl /var/lib/agent-dbctl/.config \
    && chown -R 10001:10001 /etc/agent-dbctl /var/lib/agent-dbctl

COPY --from=go-builder /out/agent-dbctl /usr/local/bin/agent-dbctl
COPY deploy/server.yaml.example /etc/agent-dbctl/server.yaml.example

ENV HOME=/var/lib/agent-dbctl \
    XDG_CONFIG_HOME=/var/lib/agent-dbctl/.config \
    AGENT_DBCTL_NO_SKILL_SYNC=1 \
    AGENT_DBCTL_LISTEN_ADDR=0.0.0.0:8080

USER 10001:10001
WORKDIR /var/lib/agent-dbctl
EXPOSE 8080
VOLUME ["/var/lib/agent-dbctl"]

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/agent-dbctl"]
CMD ["serve", "--config", "/etc/agent-dbctl/server.yaml"]
