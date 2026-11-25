# Changelog

## v0.1.0

### English

- **Four-layer enterprise catalog**: Model `System` (with `workspace_paths` auto-prioritization), `Environment` (`dev` YOLO / `staging` Guarded / `prod` Strict), reusable `NetworkProfile` (direct, SSH tunnel, SOCKS5, HTTP proxy, TLS), reusable `CredentialProfile` (macOS Keychain via `security -i`, env var, external exec provider), `Instance`, and `Target` (`RO`/`RW` credentials + many-to-many system links), with sanitized YAML/JSON topology export and import.
- **Built-in zero-JVM drivers + Tier-3 gRPC plugins**: Native pure-Go drivers for PostgreSQL, MySQL, SQLite, MongoDB, and Redis, plus language-agnostic subprocess plugins over `hashicorp/go-plugin` (`grpc-v1`) verified by `host_api_version` and SHA-256 checksums.
- **Safety preflight, policy inheritance, and pluggable approvals**: Engine-aware multi-statement risk classifier, non-mutating `EXPLAIN` preflight escalation on full scans or high estimated rows, 4-level monotonic policy inheritance (`Global -> Environment -> System -> Target`), `prod_read_only_freeze`, and decoupled `ApprovalProvider` (`local-web` built-in).
- **Agent-friendly CLI & companion skill auto-sync**: Dual-audience TTY/JSON output envelope `{ok, data, error, meta}`, single-source `describe`, semantic `error.code`, `--dry-run` vs `--preflight`, `--wait=false` + `op status`, bounded row/byte truncation, atomic `--out`, and quiet cross-agent `SKILL.md` sync (`agent-dbctl skill install|status|uninstall|print`) with `AGENT_DBCTL_NO_SKILL_SYNC=1` opt-out.
- **Embedded Web Console & immutable audit trail**: Self-contained React 19 + Tailwind CSS v4 console (`go:embed`) bound to `127.0.0.1` with same-origin guards, real-time SSE approval updates, one-click `prod_read_only_freeze`, and append-only SHA-256 hash-chained `audit_logs` in SQLite WAL mode.

### 简体中文

- **四层企业级资产目录**：支持业务系统（`System`，含 `workspace_paths` 工作区自动匹配）、环境分层（`dev` 放行 / `staging` 守卫 / `prod` 严格审批）、可复用网络配置（直连、SSH 跳板隧道、SOCKS5、HTTP 代理、TLS）、可复用凭据配置（macOS Keychain `security -i`、环境变量、外部命令）、实例与目标库（读写分离凭据及多系统关联），并支持脱敏后的 YAML/JSON 拓扑导入导出。
- **内置零 JVM 驱动与 Tier-3 gRPC 插件**：纯 Go 内置支持 PostgreSQL、MySQL、SQLite、MongoDB 与 Redis，并提供基于 `hashicorp/go-plugin`（`grpc-v1`）的跨语言子进程驱动扩展，强制校验 `host_api_version` 与二进制 SHA-256。
- **执行前风险预检、四级策略继承与可插拔审批**：覆盖多语句拆分的风险分类器、只读无副作用 `EXPLAIN` 全表扫描/高行数预检升级、`全局 -> 环境 -> 系统 -> 目标库` 四级单调收紧策略、生产只读紧急冻结开关，以及可对接外部审批流的 `ApprovalProvider` 抽象（内置 `local-web`）。
- **Agent 友好 CLI 与伴随 Skill 静默同步**：支持双受众 TTY/JSON 信封输出、`describe` 单源契约、语义化 `error.code`、`--dry-run` / `--preflight`、`--wait=false` + `op status` 异步审批轮询、整行边界截断与 `--out` 原子落盘，并在执行命令时自动静默同步伴随 `SKILL.md` 到本地各 Coding Agent 技能目录（支持 `--dry-run`/`--force` 管理及 `AGENT_DBCTL_NO_SKILL_SYNC=1` 关闭）。
- **内嵌 Web 控制台与防篡改审计账本**：零外部私有依赖的 React 19 + Tailwind CSS v4 控制台通过 `go:embed` 内嵌于单二进制，绑定 `127.0.0.1` 并强制同源校验，结合 SSE 实时审批通知与 SQLite WAL 只追加 SHA-256 哈希链审计表。
