**语言：** [English](README.md) | 简体中文

<h1 align="center">agent-dbctl</h1>

<p align="center"><strong>让 AI Coding Agent 安全查询和操作数据库——不用交出密码，也不用担心误删生产库。</strong></p>

<p align="center">单个零 JVM 二进制，支持 Claude Code、Codex、Cursor 与 OpenCode，覆盖 13 类数据库引擎，内置 EXPLAIN 预检、分环境安全策略、本地 Web 人工审批与哈希链审计日志。</p>

<p align="center">
  <a href="https://github.com/x0c/agent-dbctl/releases/latest"><img src="https://img.shields.io/github/v/release/x0c/agent-dbctl" alt="Latest Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/x0c/agent-dbctl" alt="MIT License"></a>
</p>

> **100% 本地运行 · 零遥测 · 零 JVM · 钥匙串托管凭据 · SHA-256 哈希链审计**

<p align="center">
  <img src="docs/images/approvals.png" alt="agent-dbctl 本地 Web 控制台生产写操作审批界面" />
</p>
<p align="center"><em>生产库写操作在本地 Web 控制台暂停等待确认——你可以核对完整语句、目标库和申请理由，再决定放行或附带修改意见打回给 Agent。</em></p>

## 为什么不直接让 Agent 跑 `psql`？

直接把数据库 CLI 交给 Coding Agent，通常意味着把带密码的连接串放进提示词或环境变量，还得祈祷它不会顺手跑出全表扫描或漏写 `WHERE` 的 `UPDATE`。

`agent-dbctl` 作为中间执行门禁，帮你守住四道防线：

1. **凭据不进提示词和配置文件。** 密码由系统钥匙串、环境变量或外部命令按需提供。你也可以用 CLI 注册数据库后，直接在浏览器弹窗里手输密码。
2. **高风险读取先做预检再放行。** 面向测试和生产库时，先执行无副作用的 `EXPLAIN` 预检（绝不执行 `ANALYZE`），在真正查库前拦住全表扫描和高开销操作。
3. **写操作和危险操作由你亲自审批。** 写数据、改表结构或高危语句会在本地 `127.0.0.1` Web 控制台暂停等待确认；若填上意见（如「请加上 LIMIT 100」）打回，Agent 会按反馈重写语句。
4. **每次操作都记入防篡改审计链。** 目录变更、查询执行和审批记录都会按 SHA-256 串成只追加审计链，同时不会把查询结果数据写入审计库。

## 支持的平台

- **macOS**（Apple Silicon `arm64` 与 Intel `amd64`，支持钥匙串托管凭据）
- **Linux**（`amd64` 与 `arm64`）
- **Windows**（`amd64` 与 `arm64`）

## 安装

### macOS 与 Linux（Homebrew）

```sh
brew install x0c/tap/agent-dbctl
```

### macOS 与 Linux（一键安装脚本）

```sh
curl -fsSL https://raw.githubusercontent.com/x0c/agent-dbctl/main/scripts/install.sh | bash
```

### Windows（PowerShell）

```powershell
irm https://raw.githubusercontent.com/x0c/agent-dbctl/main/scripts/install.ps1 | iex
```

若新终端提示找不到 `agent-dbctl`，将安装脚本输出的目标目录加入 `PATH` 即可。

<details>
<summary>备选方式：从源码构建（需要 Go 1.26.11+ 与 Node.js 22+）</summary>

```sh
git clone https://github.com/x0c/agent-dbctl.git
cd agent-dbctl
make install-local
```

</details>

## 快速上手

### 1. 注册数据库（全程不向 Agent 暴露密码）

可以打开本地 Web 控制台（`127.0.0.1`）可视化添加，也可以用 CLI 注册后直接拉起浏览器录入密码：

```sh
# 注册库并自动打开浏览器钥匙串密码弹窗——密码不进 Shell 历史，也不进 Agent 上下文
agent-dbctl db add --engine postgres --host 127.0.0.1 --port 5432 \
  --database core --system orders --env prod \
  --user app_rw --access-level read_write --open-secret
```

或直接打开完整控制台：

```sh
agent-dbctl ui open
```

### 2. 让 Coding Agent 自动识别当前项目对应的数据库

运行 `agent-dbctl` 时，会自动将伴随 `SKILL.md` 同步到本机已安装的 Agent 技能目录（`~/.claude/skills`、`~/.codex/skills`、`~/.cursor/skills`、`~/.config/opencode/skills`、`~/.agents/skills` 等），保留你的手动修改和软链接，不影响任何其他技能。

在项目目录中工作时，`agent-dbctl` 会根据绑定的工作目录和 Git 远程地址（含 Git worktree）自动匹配关联的数据库：

```sh
agent-dbctl db list
agent-dbctl db schema orders/prod/core
```

<details>
<summary>查看技能同步状态或关闭自动同步</summary>

```sh
agent-dbctl skill status
export AGENT_DBCTL_NO_SKILL_SYNC=1
```

</details>

### 3. 安全执行查询，把控生产变更

```sh
# 仅在生产库上做只读 EXPLAIN 预检，不真正执行
agent-dbctl exec --db orders/prod/core --preflight --sql "SELECT id, status FROM orders WHERE id = 42"

# 安全查询直接执行，并按条数/字节上限返回
agent-dbctl exec --db orders/prod/core --sql "SELECT id, status FROM orders WHERE id = 42"

# 测试/生产库的写操作、DDL 与全表扫描会自动暂停，等待 Web 审批
agent-dbctl exec --db orders/prod/core --reason "归档测试订单" \
  --sql "UPDATE orders SET status = 'archived' WHERE id = 2"
```

<details>
<summary>Agent 如何在等待审批时不触发超时</summary>

在非交互式（non-TTY）Agent 终端中调用 `agent-dbctl exec` 时，默认启用 `--wait=false`。一旦触发人工审批，命令会立即以退出码 `7`（`waiting_approval`）返回 `operation_id` 和 `approval_url`，Agent 随后可按需等待结果：

```sh
agent-dbctl exec --db orders/prod/core --reason "归档测试订单" --wait=false \
  --sql "UPDATE orders SET status = 'archived' WHERE id = 2" --json
agent-dbctl op wait <operation_id> --timeout 60s --json
```

</details>

<p>
  <img src="docs/images/catalog.png" alt="agent-dbctl 系统与数据库目录界面" width="49%" />
  <img src="docs/images/audit.png" alt="agent-dbctl 审计日志与 SHA-256 哈希链校验界面" width="49%" />
</p>
<p><em>左：统一管理业务系统、环境与读写凭据。右：查看查询执行记录并一键校验 SHA-256 审计哈希链。</em></p>

## 核心能力

- **分环境安全护栏**：`dev` 环境免批直跑；`staging` 与 `prod` 执行前先跑 `EXPLAIN` 预检，触发写操作、改表、全表扫描或 Redis/MongoDB 高开销命令时强制填写 `--reason` 并拉起中英文 Web 审批。
- **自定义高危规则**：支持通过正则或内置规则包拦截特定高危语句，或要求二次确认——即使在 `dev` 库上也能生效。
- **读写凭据分离**：同一目标库可分别配置只读和读写凭据；`db schema`、`--preflight` 和连通性探测优先使用只读凭据。
- **代码仓与 Worktree 自动匹配**：将数据库绑定到工作目录和 Git 远程地址，在多个克隆目录或 Git worktree 间切换时自动优先匹配对应库。
- **可移植拓扑导入导出**：通过 `topology export` / `topology apply` 导出或批量应用脱敏后的 YAML/JSON 资产和策略配置，不含任何明文密码。
- **为 Agent 设计的 CLI 契约**：交互终端输出清晰表格，非交互调用或 `--json` 返回结构化 JSON；按整行边界截断并如实标明总行数；支持 `--out` 原子落盘；写超时严禁自动重放。
- **可扩展审批与外部驱动**：支持内置本地 Web 审批与签名 Webhook 通知，并可通过校验 SHA-256 的 gRPC 插件接入自定义数据库引擎。

## 支持的数据库

所有查询均以目标引擎原生语法原样透传，不做易出错的跨库 SQL 改写。运行 `agent-dbctl driver list` 可查看全部方言别名与默认端口。

| 类别 | 内置支持引擎与兼容方言 |
|---|---|
| **PostgreSQL 生态** | PostgreSQL、CockroachDB、Redshift、YugabyteDB、Greenplum、AlloyDB、瀚高（HighGo）、优炫（UXDB）、OpenTenBase、PolarDB-PG、TDSQL-PG |
| **openGauss 生态** | openGauss、GaussDB、Vastbase、MogDB、南大通用 GBase 8c |
| **金仓与达梦** | 人大金仓 KingbaseES（`kingbase8`、`kes`）、达梦 DM8（`dm`、`dm8`） |
| **MySQL 生态** | MySQL、MariaDB、TiDB、OceanBase、PolarDB、TDSQL、GoldenDB、GreatSQL、GBase 8a、Apache Doris、StarRocks、SelectDB |
| **嵌入式、时序与分析型** | SQLite、ClickHouse、TDengine |
| **商业数据库** | Microsoft SQL Server（Azure SQL）、Oracle Database |
| **文档、搜索与键值** | MongoDB（JSON `RunCommand` / `show collections`、DocumentDB、FerretDB）、Elasticsearch / OpenSearch / Easysearch、Redis / Valkey / Dragonfly / KeyDB |
| **自定义扩展** | 基于 SHA-256 校验的外部 gRPC 驱动子进程 |

## 团队服务端部署（可选）

如果团队需要集中管理资产，可部署服务端模式（PostgreSQL 存储元数据、AES-256-GCM 加密托管凭据、Redis 事件与结果中转、多角色权限控制与远程 Web 审批）：

```sh
cp .env.example .env
# 在 .env 中填写 POSTGRES_PASSWORD、AGENT_DBCTL_MASTER_KEY（可用 `openssl rand -hex 32` 生成）
# 以及首次初始化管理员所需的 AGENT_DBCTL_BOOTSTRAP_ADMIN_PASSWORD
docker compose up -d --build
```

如需通过 Caddy 自动签发 HTTPS 证书（例如 `https://dbctl.example.com`）：

```sh
# 在 .env 中设置 SITE_HOST=dbctl.example.com 与 AGENT_DBCTL_PUBLIC_URL=https://dbctl.example.com，
# 并在 AGENT_DBCTL_CONFIG_FILE 指向的配置文件中将域名加入 allowed_hosts：
docker compose --profile tls up -d --build
```

在开发机上连接团队服务端：

```sh
agent-dbctl context add prod --endpoint https://dbctl.example.com --use
agent-dbctl login --token-stdin
```

## 文档导航

- [架构设计与安全边界](docs/ARCHITECTURE.md)
- [CLI 契约与退出码](docs/CLI_CONTRACT.md)
- [高危读取风险审计矩阵](docs/READ_RISK_AUDIT.md)
- [外部 gRPC 驱动与审批扩展协议](docs/PLUGIN_PROTOCOL.md)
- [安全策略](SECURITY.md) · [贡献指南](CONTRIBUTING.md) · [更新日志](CHANGELOG.md)

## 许可证

[MIT License](LICENSE)

如果 `agent-dbctl` 帮你挡住了 Agent 对生产库的误操作，欢迎点个 Star 收藏，方便日后查找。

## 关联工具

| 仓库 | 简介 |
|---|---|
| **[corral](https://github.com/corral-dev/corral)** | 统一检索、恢复并交接本地 Claude Code、Codex CLI、Cursor 与 OpenCode 会话历史。 |
| **[subswap](https://github.com/x0c/subswap)** | 查看剩余额度并在 Claude Code、Codex、Cursor、Kimi Code 与 OpenCode 之间免退出切换账号。 |
| **[agentsync](https://github.com/x0c/agentsync)** | 从单一本地真源跨工具同步 `AGENTS.md`、`CLAUDE.md`、Skills 与 MCP 配置。 |
| **[agent-doc-skills](https://github.com/x0c/agent-doc-skills)** | 面向 Coding Agent 的可导航项目知识库技能套件（`doc-init`、`doc-update`、`doc-compact`）。 |
| **[shell-gate](https://github.com/x0c/shell-gate)** | 基于 Go 的自托管 ttyd 浏览器终端网关，支持 Passkey、TOTP 两步验证与持久标签页。 |
| **[sesskit](https://github.com/x0c/sesskit)** | 解析并导出本机 Claude Code、Codex CLI 与 Cursor 会话记录文件。 |
