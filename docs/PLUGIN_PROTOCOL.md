# agent-dbctl Driver & Approval Plugin Protocol

## 1. Tier-3 External Driver Plugins (`hashicorp/go-plugin` over gRPC)

External database drivers run as isolated child processes managed via `hashicorp/go-plugin` over gRPC transport using either `proto/driver/v1/driver.proto` (`host_api_version: 1`) or typed `proto/driver/v2/driver.proto` (`host_api_version: 2`). There is **zero JVM dependency**; plugins may be implemented in Go, Rust, Python, C++, or any language supporting gRPC.

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
  "version": "0.2.0",
  "host_api_version": 2,
  "binary": "agent-dbctl-plugin-sqlite",
  "sha256": "<lowercase-64-hex-sha256>",
  "capabilities": ["ping", "list_databases", "preflight", "execute_stream", "cancel"]
}
```

### Verification Rules & Capability Dispatch

1. **Host API compatibility**: `host_api_version` must be within the supported range (`1..2`). The host negotiates the manifest-declared protocol version explicitly via `hashicorp/go-plugin` `VersionedPlugins` and rejects mismatched negotiations or incompatible manifests in `plugin list`/`doctor` without spawning.
2. **SHA-256 verification**: Before spawning a plugin binary (and again right before spawn to prevent TOCTOU swaps), the host computes its SHA-256 digest and rejects mismatches with `plugin_invalid` (blocking symlinked binaries outside the plugin directory).
3. **Capability-gated host dispatch**: Declared `capabilities` govern host RPC routing:
   - `ListDatabases` is blocked before RPC dispatch unless `"list_databases"` is declared.
   - `Preflight` returns an explicit unsupported warning without making an RPC unless `"preflight"` is declared.
   - Out-of-band query `Cancel` is issued by `CancelAndDiscard()` only when `"cancel"` is declared on a `v2` plugin.
   - Legacy `v1` manifests that omit `capabilities` retain backward-compatible dispatch.
4. **Crash isolation**: A panic or segfault inside a plugin process terminates only that subprocess without crashing the daemon or corrupting other database connections.

### Typed gRPC Service Contract (`driver.v2.DriverPlugin`)

Defined in [proto/driver/v2/driver.proto](proto/driver/v2/driver.proto) (generated Go stubs in `internal/driver/plugin/v2pb`):

- **Lossless `TypedValue` `oneof`**: Encodes `null`, `bool`, signed `int64`, unsigned `uint64`, `float64` (sanitizing `NaN`/`±Inf`), `string`, `bytes`, nested `ListValue`/`StructValue`, and fallback JSON bytes without `google.protobuf.Struct` `float64` precision loss on 64-bit integer keys above $2^{53}$.
- `Metadata(Empty) -> DriverMetadata`: Reports engine name, family (`sql` | `document` | `kv` | `raw`), version, `host_api_version`, and capabilities.
- `Ping(TargetSpec) -> PingResult`: Verifies connectivity and returns `dialect`, `server_version`, `ServerCapabilities`, and `latency_ms`.
- `ListDatabases(TargetSpec) -> DatabaseList`: Enumerates logical databases/schemas on an instance (gated on `"list_databases"`).
- `Classify(ClassifyRequest) -> Classification`: Classifies raw query/command (`safe_read`, `high_cost_read`, `write`, `ddl`, `admin`, `unknown`) and risk flags.
- `Preflight(PreflightRequest) -> PreflightReport`: Runs non-mutating execution-plan inspection (`EXPLAIN` without `ANALYZE`, gated on `"preflight"`).
- `Execute(ExecuteRequest) -> stream ExecuteChunk`: Associates each execution with a host-generated `operation_id` and streams typed columns, `Row` batches, documents, `kv_result`, `affected_rows`, server messages, and final truncation metadata (`fetched_rows`, `truncated`, `cutoff_reason`, `latency_ms`).
- `Cancel(CancelRequest) -> CancelResponse`: Out-of-band cancellation RPC invoked by host `CancelAndDiscard()` to abort an active in-flight query by `operation_id` before closing the local stream and loopback dial bridge.
- **Network Tunnel & TLS Forwarding**: `TargetSpec` carries `tls_mode`, and when the host configures a bastion/proxy `DialContext`, the host opens an ephemeral per-connection `127.0.0.1` TCP forwarder and rewrites `TargetSpec.Host`/`Port` to the local listener so plugins work transparently across SSH tunnels and proxies without embedding proxy/SSH logic.

### Legacy `v1` Compatibility (`driver.v1.DriverPlugin`)

Defined in [proto/driver/v1/driver.proto](proto/driver/v1/driver.proto) using `google.protobuf.Struct` for backward compatibility with `host_api_version: 1` plugins. Dual-mode plugins (such as `cmd/agent-dbctl-plugin-sqlite`) serve both `{1: GRPCPlugin, 2: GRPCPluginV2}` under `VersionedHandshake` and `VersionedPlugins`, while legacy `v1`-only binaries remain supported with `host_api_version: 1` (without lossless 64-bit integer typing or out-of-band `Cancel` RPC).

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
- **Air-gapped DMS/Work-Order Platform**: Implement a Tier-3 `Driver` plugin whose `Execute` submits to the enterprise DMS platform and streams approved/masked query results back through the standard `driver.v1`/`v2.DriverPlugin` contract.
