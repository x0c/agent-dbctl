# Changelog

## v0.5.1

### English

- **SQLite write reliability**: Serialized standalone maintenance writes with read-write transactions, preventing `SQLITE_BUSY_SNAPSHOT` / `database is locked (517)` failures during concurrent server authentication and catalog mutations.
- **Verified stable release gate**: Stable local packaging now requires exact-commit green Linux, macOS, Windows, and Linux server-smoke CI jobs; prerelease-only `--skip-ci-check` preserves offline packaging.
- **Real server acceptance**: Added an isolated Compose smoke path covering PostgreSQL control-plane storage, Redis events/results, RS256/PKCE OIDC, CLI device confirmation, four-eyes approvals, readback, and audit verification. Added roadmap, issue forms, and repeatable-install documentation.
- **Cross-platform build reliability**: Fixed Windows test daemon cleanup and permission assertions, corrected the Docker module-download retry shell, bounded Compose retries to network failures, aligned `context add --auth` documentation, and made server acceptance run concurrently with the platform test matrix.

### 简体中文

- **SQLite 写入可靠性**：将独立维护写入与读写事务串行化，避免服务端认证和目录变更并发时出现 `SQLITE_BUSY_SNAPSHOT` / `database is locked (517)`。
- **稳定版发布硬门禁**：本地稳定版打包现在要求同一提交的 Linux、macOS、Windows 与 Linux 服务端烟雾 CI 作业全部通过；仅限预发布版本的 `--skip-ci-check` 仍支持离线打包。
- **真实服务端验收**：新增隔离 Compose 验收链路，覆盖 PostgreSQL 控制面、Redis 事件与结果通道、RS256/PKCE OIDC、CLI 设备确认、四眼审批、数据回读和审计验证；同时补充路线图、问题表单与可重复安装文档。
- **跨平台构建可靠性**：修复 Windows 测试 daemon 清理和权限断言、Docker 模块下载重试 shell，将 Compose 重试限定于网络故障，对齐 `context add --auth` 文档，并让服务端验收与平台测试矩阵并行运行。

## v0.5.0

### English

- **Enterprise Client/Server mode, PostgreSQL/Redis backends & container stack**: Added `agent-dbctl serve` with PostgreSQL catalog and hash-chained audit persistence (advisory-locked per chain), `AES-256-GCM` server-side encrypted credential storage (`encrypted_db`), Redis-backed SSE event bus and bounded query result relay, multi-stage `Dockerfile`, and `compose.yaml` (`--profile tls` Caddy ingress and password-protected Redis).
- **OIDC / SSO, scoped RBAC & remote CLI contexts**: Added OIDC authorization-code + PKCE authentication (`admin_emails` role mapping, auto-SSO, state-scoped error redirects) alongside local bootstrap admin login, 4-role scoped RBAC (`platform_admin`, `system_admin`, `approver`, `developer`), API token management in the Web Console `Access` tab (`CLI Session` badge support), and `agent-dbctl context add|use|list|delete`, `login`, and `logout` (with server token revocation).
- **SSRF protection, scoped UI dialogs & bootstrap resilience**: Blocked loopback, private, link-local, and cloud metadata destinations on server-initiated connections (including hostname and DNS resolution checks behind proxies and SSH tunnels), added inline `scope_type`/`scope_id` selectors across Instance, Network, and Credential dialogs, and added an explicit retry panel on non-401 Web Console bootstrap failures.
- **Dameng DM8 reliability & hot-path performance**: Retried `db schema` with uppercase schema fallback on Dameng `-2103` errors and optimized hot paths across the SQL classifier, policy engine, hash-chain audit serialization, driver pooling, catalog resolution, store queries, and skill sync.
- **Documentation**: Rewrote `README.md` and `README.zh-CN.md` from a user-first perspective and updated architecture, CLI contract, and deployment guides.

### 简体中文

- **企业级 Client/Server 模式、PostgreSQL/Redis 后端与容器化部署**：新增 `agent-dbctl serve` 中心服务模式，支持 PostgreSQL 资产与防篡改哈希链审计存储（链内咨询锁串行化）、`AES-256-GCM` 服务端加密凭据存储（`encrypted_db`）、基于 Redis 的 SSE 事件总线与有界查询结果接力，并提供多阶段 `Dockerfile` 与 `compose.yaml`（含 `--profile tls` Caddy 入口与强制口令认证的 Redis）。
- **OIDC 单点登录、分级 RBAC 与远程 CLI 上下文**：新增 OIDC 授权码 + PKCE 登录（支持 `admin_emails` 角色映射、自动 SSO 与基于 `state` 的安全错误回跳）及本地引导管理员登录，支持四级作用域角色（`platform_admin`、`system_admin`、`approver`、`developer`）、Web 控制台 `Access` 令牌管理（补齐 `CLI 会话` 标签）以及 `agent-dbctl context add|use|list|delete`、`login`、`logout`（同步吊销服务端令牌）。
- **SSRF 防护、作用域表单与引导容错**：在服务端发起的连接及代理/SSH 隧道出口默认拦截回环、内网、链路本地与云元数据目标（含代理后主机名与 DNS 解析校验），为实例、网络与凭据新建/编辑弹窗补齐 `scope_type`/`scope_id` 选择器，并在 Web 控制台非 401 引导失败时展示可重试错误面板，避免无限骨架屏卡死。
- **达梦 DM8 兼容性与核心链路性能优化**：为达梦 `db schema` 遇到 `-2103` 错误时增加大写模式名回退重试，并针对 SQL 分类器、策略引擎、审计哈希链序列化、驱动连接池、目录匹配、存储查询与伴随 Skill 同步进行了压测与热路径优化。
- **文档更新**：以用户视角重写 `README.md` 与 `README.zh-CN.md`，并同步更新架构、CLI 契约与部署运维文档。

## v0.4.1

### English

- **KingbaseES default TLS compatibility (`gokb`)**: Mapped unset/`prefer` TLS modes on `kingbase` away from unsupported `sslmode=prefer` to `sslmode=disable` (with automatic fallback retry to `sslmode=require` when the server mandates TLS and no custom `TLSConfig` is configured), preserving explicit `disable`/`require`/`verify-ca`/`verify-full`.
- **Actionable connectivity probe errors**: Guaranteed non-empty `PingResult.Error`, included per-target driver errors directly in `db test --json` `error.message` (with `db show <ref>` recovery hints), added next steps on failed `db add --test` probes, and surfaced unreachable reasons inline in the Web Console Databases table.
- **`env delete` symmetry & orphan cleanup hints on `db delete`**: Added `agent-dbctl env delete <code>` (`DELETE /rpc/v1/environments/{code...}` and `DELETE /api/v1/environments/{code...}`, supporting slash-containing codes and Web UI deletion with target-reference guards), and updated `db delete` to report newly orphaned instances, credentials, and unused custom environments with ready-to-run cleanup commands.

### 简体中文

- **修复人大金仓 KingbaseES 默认 TLS 模式兼容性（`gokb`）**：当 `kingbase` 未指定 `tls-mode` 或为 `prefer` 时，不再传入驱动拒绝的 `sslmode=prefer`，改为默认 `sslmode=disable`（若未配自定义证书且服务端强制要求 SSL 则自动回退重连 `sslmode=require`），同时保留显式 `disable`/`require`/`verify-ca`/`verify-full`。
- **连通性探测错误直接透出**：确保探测失败时 `PingResult.Error` 永不为空；`db test --json` 在全部不可达时直接在 `error.message` 透出各目标的真实驱动报错（并附 `db show <ref>` 恢复命令）；`db add --test` 失败时补充排查建议命令；Web 控制台列表直接内联显示不可达原因摘要。
- **补齐 `env delete` 与 `db delete` 孤儿资源提示**：新增 `agent-dbctl env delete <code>`（以及支持斜杠环境名的 `DELETE /rpc/v1/environments/{code...}` / `/api/v1/environments/{code...}` 与 Web 控制台删除操作，受目标引用冲突保护），并在 `db delete` 删除后自动识别新产生的孤儿实例、凭据与自定义环境，直接返回清理命令列表。

## v0.4.0

### English

- **13 zero-JVM built-in drivers & Xinchuang database dialects**: Added pure-Go drivers for **openGauss / GaussDB**, **KingbaseES**, **Dameng DM8**, and **TDengine**, plus **Easysearch** dialect support across schema introspection (`db schema`) and read-only `EXPLAIN` preflight.
- **Agent-friendly onboarding defaults & inline environment creation**: `db add` now defaults `--access-level` to `read_write` in `yolo` environments (keeping `read_only` in `guarded`/`strict`), supports `--safety-tier <yolo|guarded|strict>` to create missing `--env` entries inline (including `--dry-run`), returns full `TargetSummary` fields (`safety_tier`, `writable`, `scan_read_mode`) in `--dry-run`, and emits structured `hint` + runnable `next_commands` when environments, networks, or credentials are missing.
- **Scoped full-scan read policy (`scan_read_mode`)**: Added `allow` / `reason_only` / `require_approval` policy control on targets, systems, and environments via `--scan-read-mode` (`db add`, `db set`, `policy set`), topology export/apply, and the Web Console `Policies` modal—letting safe `EXPLAIN` full-scan reads (`SELECT COUNT(*)`, unindexed `LIMIT 1`) run immediately when `--reason` is passed under `reason_only` while failing fast with `reason_required` if omitted and keeping writes/DDL/custom risk rules gated by approval.
- **Portable Git remote workspace matching & Web UI refinements**: Added automatic normalized `git_remotes` binding (`system set --git-remote`, `db add --git-remote`) across Git worktrees and subdirectories; streamlined the Web Console around `Systems & Databases` with a one-shot `Add Database` modal, secondary `Resources` drawer, `Environments` under `Policies & Guardrails`, and a minimal topbar.
- **CLI diagnostics & partial rule updates**: Fixed `pattern set` partial CLI updates so `--enabled=false` or single-flag changes preserve existing conditions/actions; added recovery hints on read-only target write denials (`ErrCodePolicyDenied`) and full-scan waits; clarified non-existent SQLite `mode=ro` probe failures in `db add --test` and `db test`.

### 简体中文

- **13 大零 JVM 内置驱动与信创数据库适配**：新增 **openGauss / GaussDB**、**KingbaseES（人大金仓）**、**Dameng DM8（达梦）** 与 **TDengine** 纯 Go 内置驱动，并支持 **Easysearch** 方言，全部统一接入只读 `db schema` 结构探查与无副作用 `EXPLAIN` 预检。
- **更符合 Agent 直觉的接入默认值与内联建环境**：`db add` 在 `yolo` 环境中将 `--access-level` 默认提升为 `read_write`（`guarded`/`strict` 保持默认 `read_only`），新增 `--safety-tier <yolo|guarded|strict>` 支持在一次调用中内联创建缺失环境（含 `--dry-run` 预演），补全 `--dry-run` 下的 `safety_tier`/`writable`/`scan_read_mode` 摘要字段，并在缺少环境/网络/凭据时返回结构化 `hint` 与可直接执行的 `next_commands`。
- **分级全表扫描读策略（`scan_read_mode`）**：支持通过 `db add`、`db set`、`policy set` 的 `--scan-read-mode` 参数、拓扑导入导出及 Web 控制台 `Policies` 弹窗按目标/系统/环境配置 `allow` / `reason_only` / `require_approval`；开启 `reason_only` 后，`SELECT COUNT(*)`、无索引 `LIMIT 1` 等安全全表扫描读在提供 `--reason` 时免审批直接放行，未提供 `--reason` 时快速返回 `reason_required`，而写操作、DDL 及自定义高危规则仍严格走审批门禁。
- **Git Remote 跨工作区绑定与 Web 控制台精简化**：新增标准化 `git_remotes` 绑定与多工作树/子目录自动识别；Web 控制台聚焦 `Systems & Databases` 主视图（内置一键 `Add Database` 弹窗）、将实例/网络/凭据模板收敛进 `Resources` 抽屉、将 `Environments` 归入 `Policies & Guardrails`，并简化顶部控制栏。
- **CLI 诊断与部分参数更新修复**：修复 `pattern set` 仅传部分参数（如 `--enabled=false`）时覆盖原有匹配条件和动作的问题；为只读目标写入拒绝（`ErrCodePolicyDenied`）及全表扫描触发审批补充可执行恢复命令；为不存在的 SQLite 文件在 `db add --test` / `db test` 的 `mode=ro` 失败信息补充清晰原因说明。

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
