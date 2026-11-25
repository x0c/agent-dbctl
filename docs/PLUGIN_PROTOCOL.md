# agent-dbctl Driver & Approval Plugin Protocol

## 1. Tier-3 External Driver Plugins (`hashicorp/go-plugin` over gRPC)

External database drivers run as isolated child processes managed via `hashicorp/go-plugin` using gRPC transport (`proto/driver/v1/driver.proto`). There is **zero JVM dependency**; plugins may be implemented in Go, Rust, Python, C++, or any language supporting gRPC.

### Discovery & `manifest.json`

Plugins live under `<config_home>/plugins/<plugin-id>/`:

```text
~/.config/agent-dbctl/plugins/
└── custom-sqlite/
    ├── manifest.json
    └── agent-dbctl-plugin-sqlite
```

`manifest.json` schema:

```json
{
  "id": "custom-sqlite",
  "engine": "sqlite-ext",
  "display_name": "External SQLite Plugin",
  "family": "sql",
  "version": "0.1.0",
  "host_api_version": 1,
  "binary": "agent-dbctl-plugin-sqlite",
  "sha256": "<lowercase-64-hex-sha256>",
  "capabilities": ["ping", "list_databases", "preflight", "execute_stream"]
}
```

### Verification Rules

1. **Host API compatibility**: `host_api_version` must match the supported host API (`1`). Incompatible manifests are marked invalid in `plugin list`/`doctor` and never spawned.
2. **SHA-256 verification**: Before spawning a plugin binary, the host computes its SHA-256 digest and rejects mismatches with `plugin_invalid` (blocking symlinked binaries outside the plugin directory).
3. **Crash isolation**: A panic or segfault inside a plugin process terminates only that subprocess without crashing the daemon or corrupting other database connections.

### gRPC Service Contract (`driver.v1.DriverPlugin`)

Defined in [proto/driver/v1/driver.proto](proto/driver/v1/driver.proto):

- `Metadata(Empty) -> DriverMetadata`: Reports engine name, family (`sql` | `document` | `kv` | `raw`), version, and capabilities.
- `Ping(TargetSpec) -> PingResult`: Verifies connectivity and returns server version + latency.
- `ListDatabases(TargetSpec) -> DatabaseList`: Enumerates logical databases/schemas on an instance.
- `Classify(ClassifyRequest) -> Classification`: Classifies raw query/command (`safe_read`, `high_cost_read`, `write`, `ddl`, `admin`, `unknown`) and risk flags.
- `Preflight(PreflightRequest) -> PreflightReport`: Runs non-mutating execution-plan inspection (`EXPLAIN` without `ANALYZE`).
- `Execute(ExecuteRequest) -> stream ExecuteChunk`: Streams columns, row/document batches, `affected_rows`, server messages, and final summary (`fetched_rows`, `truncated`, `cutoff_reason`, `latency_ms`) so large result sets can be capped cleanly at `max_rows` / `max_bytes` without OOM or lost truncation status.
- **Network Tunnel & TLS Forwarding**: `TargetSpec` carries `tls_mode`, and when the host configures a bastion/proxy `DialContext`, the host opens an ephemeral per-connection `127.0.0.1` TCP forwarder and rewrites `TargetSpec.Host`/`Port` to the local listener so plugins work transparently across SSH tunnels and proxies without embedding proxy/SSH logic.

---

## 2. Pluggable Approval Providers (`internal/approval.Provider`)

Approval gating is decoupled behind a small interface:

```go
type Provider interface {
    Name() string
    SupportsInteractiveResolve() bool
    Submit(ctx context.Context, req SubmissionRequest) (*SubmissionResult, error)
    Cancel(ctx context.Context, approvalID string, externalTicketID string) error
}
```

### Built-in Provider: `local-web`

- Generates a cryptographically random one-time `approval_token` (stored hashed as SHA-256 in SQLite).
- Returns `approval_url = http://127.0.0.1:<port>/approvals/<approval_id>?token=<approval_token>`.
- Opens the system default browser unless `AGENT_DBCTL_NO_BROWSER=1`.
- Approval/rejection endpoints enforce same-origin checks plus `approval_token` or active local console session token validation, and write the decision + audit hash-chain row in a single SQLite transaction.

### Enterprise Extensions

- **External approval system (e.g. Feishu / Slack / Internal Ticket)**: Implement `Provider` to create an external ticket (`external_ticket_id`, `external_ticket_url`), then resolve the pending approval via callback/poller into `approval.Manager.Resolve(...)`.
- **Air-gapped DMS/Work-Order Platform**: Implement a Tier-3 `Driver` plugin whose `Execute` submits to the enterprise DMS platform and streams approved/masked query results back through the standard `driver.v1.DriverPlugin` contract.
