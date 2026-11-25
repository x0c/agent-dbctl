# Read-Query Risk Matrix and Guardrail Audit

Empirical audit of dangerous or high-load read patterns across PostgreSQL (verified on 18.6), SQLite (verified on 3.50.6), MySQL (8.0+), MongoDB, and Redis/Valkey, alongside current `agent-dbctl` classifier, preflight, and policy-gate coverage.

## 1. Cross-Engine Read Hazard Categories

1. **Execution disguised as diagnostics**:
   - PostgreSQL / MySQL `EXPLAIN ANALYZE <DML>` executes the statement and mutates rows unless wrapped in an explicit rolled-back transaction.
   - MongoDB `explain` with `verbosity: "executionStats"` or `"allPlansExecution"` executes the query and any `$function`/`$accumulator` JavaScript (only `"queryPlanner"` is metadata-only).
2. **Side effects permitted inside read-only sessions**:
   - PostgreSQL `default_transaction_read_only = on` still allows `pg_advisory_lock()`, `pg_sleep()`, and server-file reads (`pg_read_file()`, `pg_ls_dir()`) when the role has privileges (`SUPERUSER` / `pg_read_server_files`).
   - SQLite `PRAGMA query_only = 1` does not block `PRAGMA query_only(0)` (function-style syntax resets it to `0`), `PRAGMA wal_checkpoint(TRUNCATE)`, `PRAGMA integrity_check`, or `ATTACH DATABASE`.
3. **Read-induced lock cascades and WAL starvation**:
   - PostgreSQL long-running `SELECT` holds `ACCESS SHARE`; a queued `ALTER TABLE` (`ACCESS EXCLUSIVE`) then blocks all subsequent queries—including indexed primary-key lookups—behind it in the FIFO lock queue.
   - SQLite unclosed read transactions pin WAL read marks and block `PRAGMA wal_checkpoint(TRUNCATE)` (`busy=1`), causing `-wal` growth.
   - Locking reads: `FOR UPDATE`, `FOR SHARE`, `FOR NO KEY UPDATE`, `FOR KEY SHARE`, `LOCK IN SHARE MODE`.
4. **CPU / memory / I/O amplification**:
   - `TABLE <tbl>` shorthand (PostgreSQL / MySQL 8.0.19+), implicit comma joins (`FROM a, b`) without join predicates, unbounded `WITH RECURSIVE`, large generators (`generate_series`), SQLite `randomblob()` / `zeroblob()`, `ORDER BY random()` / `RAND()`, deep `OFFSET`, and `SELECT` with `WHERE` but no `LIMIT`.
   - MySQL `SLEEP()`, `BENCHMARK()`, `LOAD_FILE()`, `GET_LOCK()`, `SQL_CALC_FOUND_ROWS`, and `REGEXP` (mitigated in 8.0+ by ICU `regexp_time_limit`, Error 3699 if exceeded).
   - MongoDB `$where`, `$function`, `$accumulator`, unanchored/case-insensitive `$regex`, unindexed `$lookup` / unbounded `$graphLookup`, `countDocuments({})`, `distinct`, `allowDiskUse: true`, `noCursorTimeout`.
   - Redis/Valkey single-thread stalls: `CLIENT PAUSE`, `MEMORY USAGE <key> SAMPLES 0` ($O(N)$ nested scan), huge `SCAN ... COUNT`, `EVAL_RO`/`FCALL_RO` loops, `KEYS`, `HGETALL`/`SMEMBERS`/`LRANGE 0 -1`, `SORT_RO ... BY ... GET`, large-radius `GEORADIUS`/`GEOSEARCH`, `MONITOR`, `XREAD BLOCK 0`.
5. **`EXPLAIN` planner blind spots**:
   - PostgreSQL `EXPLAIN` reports `MaxPlanRows=31, Cost=3.35, FullScan=false` on a 1,000,000-row `WITH RECURSIVE` query, and `Node=Result, MaxPlanRows=1, FullScan=false` on `SELECT pg_sleep(...)` / `pg_advisory_lock(...)`.
   - SQLite `EXPLAIN QUERY PLAN` reports `SCAN CONSTANT ROW` (not a table `SCAN`) for `randomblob(200000000)`.

---

## 2. Current `agent-dbctl` Classifier, Preflight, and Policy Gaps

Verified against `internal/classify/{sql,mongo,redis}.go`, `internal/driver/builtin/`, and `internal/policy/engine.go` under `prod` (`strict`) evaluation:

| Engine | Bypass / Gap Pattern | Current Behavior (`strict` tier) | Code Location |
|---|---|---|---|
| **SQLite** | `PRAGMA query_only(0)`, `PRAGMA wal_checkpoint(TRUNCATE)`, `PRAGMA integrity_check` | Classified `safe_read` (`PRAGMA_READ`), executes without approval (`query_only(0)` resets `query_only=1`) | [sql.go](../internal/classify/sql.go#L205-L219) |
| **PostgreSQL** | `WITH RECURSIVE ... SELECT count(*) FROM t` | `isScalarAggregateOnly` skips `missing_where`; `EXPLAIN` estimates `31` rows (`FullScan=false`); executes without approval | [sql.go](../internal/classify/sql.go#L308-L322) |
| **PG / MySQL / SQLite** | Dangerous scalar calls without `FROM` (`pg_sleep`, `pg_advisory_lock`, `pg_read_file`, `pg_terminate_backend`, `nextval`, `SLEEP`, `BENCHMARK`, `LOAD_FILE`, `GET_LOCK`, `randomblob`) | `hasFrom=false` skips `analyzeSelectQuery` high-cost flags; PG `EXPLAIN` reports `rows=1`; executes without approval | [sql.go](../internal/classify/sql.go#L278-L299) |
| **PG** | `SELECT ... FOR KEY SHARE` | Not matched by `locking_read` list (`FOR UPDATE` / `FOR SHARE` / `FOR NO KEY UPDATE` / `LOCK IN SHARE MODE`) | [sql.go](../internal/classify/sql.go#L127-L130) |
| **PG / MySQL** | `TABLE <tbl>` shorthand | Routed to `analyzeSelectQuery`, where `hasFrom=false` yields `safe_read` in `--dry-run` (caught only if live `EXPLAIN` detects full scan) | [sql.go](../internal/classify/sql.go#L194-L195) |
| **PG / MySQL** | Implicit comma join (`FROM a, b WHERE a.id = 1`) & `SELECT * FROM t WHERE ...` (no `LIMIT`) | Only `CROSS JOIN` sets `cross_join`; `missing_limit` alone does not raise `RiskLevel` to `high_cost_read` | [sql.go](../internal/classify/sql.go#L281-L299) |
| **SQL** | `EXPLAIN ANALYZE DELETE ...` | Classified `high_cost_read` with `IsReadOnly=true`, so `prod_read_only_freeze` does not hard-deny it | [sql.go](../internal/classify/sql.go#L95-L97), [engine.go](../internal/policy/engine.go#L208) |
| **MongoDB** | `SELECT`/`find` via `{"explain": {"find":..., "filter":{"$where":...}}, "verbosity":"executionStats"}` | Any JSON command with `"explain"` key is marked `safe_read` regardless of `verbosity` or inner query | [mongo.go](../internal/classify/mongo.go#L146) |
| **MongoDB** | `$function`, `$accumulator`, `allowDiskUse: true` with trailing `$limit`, `countDocuments({})`, `find` with non-empty filter and no `limit`, `mongosh` syntax | Marked `safe_read`; `mongosh` strings cannot be parsed by `parseMongoCommandDoc` and skip live `Preflight` | [mongo.go](../internal/classify/mongo.go#L64-L202), [mongodb.go](../internal/driver/builtin/mongodb.go#L121-L125) |
| **Redis** | `CLIENT PAUSE 60000`, `MEMORY USAGE k SAMPLES 0`, `SCAN 0 COUNT 10000000`, `GETRANGE k 0 -1` | Listed in `redisSafeReadCmds` (`CLIENT` only special-cases `CLIENT KILL`) and allowed without approval | [redis.go](../internal/classify/redis.go#L12-L23), [redis.go](../internal/classify/redis.go#L129-L134) |

---

## 3. Remediation Status (Built-in Hardening & Custom High-Risk Pattern Layer)

- **Built-in Classifier & Context Extraction (`internal/classify/`)**: Hardened SQL (`EXPLAIN`/`EXPLAIN ANALYZE` inner-DML propagation preserving `IsReadOnly=false`, parenthesized `PRAGMA` allowlist, dangerous/side-effect scalar functions even without `FROM`, `FOR KEY SHARE`, `TABLE` shorthand, implicit comma joins, `WITH RECURSIVE`, `ORDER BY RAND()/RANDOM()`, `SQL_CALC_FOUND_ROWS`, deep `OFFSET`), MongoDB (`explain` verbosity & inner-query analysis, recursive nested operator detection), and Redis/Valkey (`CLIENT` & `MEMORY` subcommand allowlisting, `SCAN` count bounds, range/geo/fanout/blocking guards), alongside normalized `QueryContext` extraction.
- **Custom High-Risk Pattern Engine (`internal/policy/`, `internal/store/`, Web Console)**: Layered `RiskPatternRule` evaluation (`global -> env -> system -> target` monotonic inheritance) with 8 composable matchers, 5 preset rule packs (`pg-side-effect`, `sqlite-pragma-blob`, `redis-single-thread`, `mongo-js-explain`, `mysql-dos-guard`), offline dry-run sandbox testing, and structured `MatchedRule` secondary confirmation on CLI and Web approval cards. Remaining planner blind-spot mitigation (`WITH RECURSIVE`, constant-row functions) relies on explicit classifier rules and user-configured pattern rules above static `EXPLAIN`.
