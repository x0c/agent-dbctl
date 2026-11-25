# Changelog

## v0.3.0

### English

- **9 built-in zero-JVM drivers & unified schema introspection**: Added built-in pure-Go drivers for ClickHouse, Microsoft SQL Server (MSSQL), Oracle Database, and Elasticsearch / OpenSearch (plus compatible dialect aliases across PostgreSQL, MySQL, MongoDB, and Redis families) and implemented `db schema <ref> [table]` read-only introspection across all 9 engines.
- **Mandatory approval reason (`--reason`), DML preflight & 9 official risk packs**: Enabled `require_reason_for_approval` by default so operations triggering human approval without `--reason` fail fast with exit `2` (`reason_required`) and recovery guidance without creating blank tickets; extended non-mutating `EXPLAIN` preflight to single-statement DML and expanded built-in risk pattern packs to 9 (`pg-side-effect`, `sqlite-pragma-blob`, `redis-single-thread`, `mongo-js-explain`, `mysql-dos-guard`, `clickhouse-heavy-scan`, `mssql-proc-dos`, `oracle-sys-guard`, `es-unbounded-scan`).
- **Full CLI catalog/policy automation & zero-secret Web handoff**: Added idempotent `--dry-run`-capable `db add|set|delete`, `system|env|network|cred|instance` management, `topology schema|export|apply`, and `security|policy|pattern` administration over the private `0600` daemon RPC channel, plus zero-secret Keychain setup (`--open-secret` / `ui open --credential`).
- **Hardened Web Console security & bilingual English / Chinese UI**: Added `WebSecurityMiddleware` (loopback `Host` validation, strict same-origin checks, and per-daemon `HttpOnly; SameSite=Strict` session cookie + `X-Agent-DBCTL-CSRF` verification) and full English / Simplified Chinese (`EN` / `中文`) Web Console localization with auto-detection, instant topbar switching, and server-driven `DisplayCatalog` labels.
- **Audit framing, daemon upgrade & CLI ergonomics**: Hardened `audit_logs` SHA-256 hash-chain framing, added `--format objects` row output, synchronous `op cancel`, automatic single-instance daemon version upgrade with fast SSE shutdown, and richer `TargetLookupError` recovery hints.

### 简体中文

- **9 大零 JVM 内置驱动与跨引擎结构探查**：新增 ClickHouse、Microsoft SQL Server（MSSQL）、Oracle Database 与 Elasticsearch / OpenSearch 纯 Go 内置驱动（并完善各引擎方言别名映射），全部 9 类引擎统一支持只读 `db schema <ref> [table]` 库表/集合/索引与键前缀结构探查。
- **强制申请理由（`--reason`）、DML 预检与 9 套官方风险规则包**：默认开启全局护栏 `require_reason_for_approval`，触发人工审批却未传 `--reason` 时立即返回退出码 `2`（`reason_required`）与可执行恢复命令而不生成空白审批单；扩展只读 `EXPLAIN` 预检至单条 DML 语句，并将官方内置高危规则包扩充至 9 套。
- **全量 CLI 资产/策略自动化与零密钥 Web 录入交接**：通过私有 `0600` 守护进程 RPC 通道提供幂等且支持 `--dry-run` 的 `db add|set|delete`、`system|env|network|cred|instance` 管理、`topology schema|export|apply` 以及 `security|policy|pattern` 配置命令，并支持 `--open-secret` / `ui open --credential` 免暴露密码的 Keychain Web 录入交接。
- **Web 控制台安全加固与完整中英文双语界面**：新增 `WebSecurityMiddleware`（回环 `Host` 校验、严格同源检查以及每会话 `HttpOnly; SameSite=Strict` Cookie + `X-Agent-DBCTL-CSRF` 校验）；为 Web 控制台补齐完整简体中文 / 英文界面适配，默认跟随系统语言并提供顶栏一键切换，联动服务端下发的多语言 `DisplayCatalog` 标签。
- **审计哈希链加固、守护进程升级与 CLI 体验优化**：加固 `audit_logs` SHA-256 哈希链防歧义编码，新增 `--format objects` 对象数组输出、`op cancel` 同步等待收敛、单实例锁下的守护进程自动版本重启与 SSE 快速关闭，以及更清晰的模糊目标候选恢复提示。

## v0.2.0

### English

- **Hardened cross-engine read-risk classification & custom high-risk pattern gate**: Hardened SQL, MongoDB, and Redis/Valkey read-risk detection (`EXPLAIN ANALYZE` DML propagation preserving `IsReadOnly=false`, parenthesized SQLite `PRAGMA` allowlists, side-effect/admin scalar functions without `FROM`, `FOR KEY SHARE`, `TABLE` shorthand, implicit comma joins, `WITH RECURSIVE`, MongoDB `explain` verbosity and nested JS operator scans, Redis `CLIENT`/`MEMORY`/range/fanout guards). Added a 4-level monotonic `RiskPatternRule` engine (`global -> env -> system -> target`) with 8 composable matchers, 5 official preset packs, an offline dry-run sandbox, mandatory secondary confirmation even in `dev` (`yolo`) targets, and topology portability.
- **Connection pooling, dialect capabilities & Tier-3 gRPC plugin v2**: Added reusable SSH tunnel and read-only SQL connection pools, dialect capability negotiation, MongoDB `winningPlan` bounded-`LIMIT` preflight inspection with clearer `RunCommand` warnings, Tier-3 gRPC plugin `v2` typed Protobuf protocol with out-of-band `Cancel` RPC, and Windows SQLite `file:///C:/...` URI normalization.
- **Embedded Web Console & catalog UX**: Migrated the embedded console to `@x0c/ui@0.3.0` with Vite 8 Rolldown chunk splitting, added concurrent DB ping checks, `Policies -> High-Risk Patterns` rule management + Dry-Run Sandbox, and highlighted secondary confirmation banners on approval cards.
- **CLI & core security hardening**: Added concise TTY summaries for `--dry-run`/`--preflight`, single optional positional query support (`exec --db <ref> "<query>"`), `audit list`/`export`, `op wait`, `doctor --live`, monotonic boolean policy inheritance, configurable webhook `ApprovalProvider`, audit payload redaction, atomic store persistence, and daemon startup recovery.

### 简体中文

- **跨引擎高危读分类加固与自定义高危模式门禁**：加固 SQL、MongoDB 与 Redis/Valkey 高风险读取识别（`EXPLAIN ANALYZE` 透传内层 DML/DDL 非只读风险、SQLite 函数式 `PRAGMA` 白名单、无 `FROM` 副作用/管理标量函数、`FOR KEY SHARE`、`TABLE` 简写、隐式逗号连接、`WITH RECURSIVE`、MongoDB `explain` 深度模式与 JS 操作符递归扫描、Redis `CLIENT`/`MEMORY`/范围与扇出校验）；新增支持 `全局 -> 环境 -> 系统 -> 目标库` 四级单调收紧继承的 `RiskPatternRule` 引擎、8 类可组合匹配器、5 套官方预设规则包、离线 Dry-Run 演练沙箱，即使在 `dev`（YOLO）目标下命中规则也可强制触发带确认文案的二次审批，并随拓扑导出/导入。
- **连接池、方言能力探测与 Tier-3 gRPC 插件 v2**：实现可复用 SSH 跳板隧道池与只读连接池、方言能力协商、MongoDB `winningPlan` 有界 `LIMIT` 预检与更清晰的 `RunCommand` 提示、支持类型化 Protobuf 与带外 `Cancel` RPC 的 `v2` 外部插件协议，并修复 Windows 下 SQLite 盘符 `file:///C:/...` URI 解析问题。
- **内嵌 Web 控制台与资产目录体验**：控制台迁移至公开 `@x0c/ui@0.3.0` 组件库并启用 Vite 8 Rolldown 分包，新增并发数据库连通性测试、`Policies -> High-Risk Patterns` 策略管理与演练沙箱，并在审批卡片上高亮展示命中的自定义高危确认提示。
- **CLI 与核心安全加固**：为人类终端下的 `--dry-run`/`--preflight` 提供简洁摘要，支持单位置查询参数（`exec --db <ref> "<query>"`），新增 `audit list`/`export`、`op wait` 与 `doctor --live`，强制布尔策略四级单调收紧，补充 Webhook 审批扩展、审计日志脱敏、原子化存储落盘与守护进程重启恢复。

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
