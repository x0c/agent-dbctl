package policy

import "github.com/x0c/agent-dbctl/internal/types"

// BuiltinRulePacks returns curated preset high-risk pattern rule packs matching audited database hazards.
func BuiltinRulePacks() []types.BuiltinRulePack {
	return []types.BuiltinRulePack{
		{
			ID:          "pg-side-effect",
			Name:        "PostgreSQL Side-Effect & Exfil Guard",
			Description: "Gates advisory locks, pg_sleep, large generators, recursive CTEs, and blocks server-file/dblink reads.",
			Engines:     []string{"postgres"},
			Rules: []types.RiskPatternRule{
				{
					Name:           "pg-server-file-and-dblink",
					Description:    "Block PostgreSQL server-side file reads, large-object export, and dblink execution.",
					BuiltinPack:    "pg-side-effect",
					Enabled:        true,
					Engines:        []string{"postgres"},
					Families:       []types.EngineFamily{types.FamilySQL},
					Action:         types.PatternActionDeny,
					ConfirmTitle:   "PostgreSQL Server-Side File / Extension Access Denied",
					ConfirmMessage: "Statement invokes server file access, large object export, or dblink external calls.",
					Priority:       100,
					Condition: types.PatternCondition{
						Type: types.MatcherFunctionCall,
						Values: []string{
							"pg_read_file", "pg_read_binary_file", "pg_ls_dir", "pg_stat_file",
							"lo_export", "lo_import", "dblink", "dblink_connect", "dblink_exec",
						},
					},
				},
				{
					Name:           "pg-sleep-and-locks",
					Description:    "Require human confirmation for pg_sleep, advisory locks, and sequence side-effects.",
					BuiltinPack:    "pg-side-effect",
					Enabled:        true,
					Engines:        []string{"postgres"},
					Families:       []types.EngineFamily{types.FamilySQL},
					Action:         types.PatternActionRequireApproval,
					ConfirmTitle:   "Confirm PostgreSQL Sleep or Session Side Effect",
					ConfirmMessage: "Query uses sleep, advisory locks, or sequence mutation that affects session/cluster state.",
					Priority:       90,
					Condition: types.PatternCondition{
						Type: types.MatcherFunctionCall,
						Values: []string{
							"pg_sleep*", "pg_advisory_*", "pg_try_advisory_*", "nextval", "setval", "xmlparse",
						},
					},
				},
				{
					Name:           "pg-recursive-or-generator",
					Description:    "Require human confirmation for WITH RECURSIVE or generate_series amplification.",
					BuiltinPack:    "pg-side-effect",
					Enabled:        true,
					Engines:        []string{"postgres"},
					Families:       []types.EngineFamily{types.FamilySQL},
					Action:         types.PatternActionRequireApproval,
					ConfirmTitle:   "Confirm Recursive CTE or Series Generator",
					ConfirmMessage: "EXPLAIN estimates cannot reliably bound recursive CTEs or large generate_series calls.",
					Priority:       80,
					Condition: types.PatternCondition{
						Any: []types.PatternCondition{
							{Type: types.MatcherRiskFlag, Values: []string{"recursive_cte"}},
							{Type: types.MatcherFunctionCall, Values: []string{"generate_series"}},
						},
					},
				},
			},
		},
		{
			ID:          "sqlite-pragma-blob",
			Name:        "SQLite PRAGMA & Blob Guard",
			Description: "Gates mutating/parenthesized SQLite PRAGMAs, WAL checkpoints, integrity_check, and huge randomblob/zeroblob.",
			Engines:     []string{"sqlite"},
			Rules: []types.RiskPatternRule{
				{
					Name:           "sqlite-mutating-pragma",
					Description:    "Require human confirmation for mutating PRAGMA or WAL checkpoint commands.",
					BuiltinPack:    "sqlite-pragma-blob",
					Enabled:        true,
					Engines:        []string{"sqlite"},
					Families:       []types.EngineFamily{types.FamilySQL},
					Action:         types.PatternActionRequireApproval,
					ConfirmTitle:   "Confirm SQLite PRAGMA / WAL Operation",
					ConfirmMessage: "SQLite PRAGMA can reset query_only protection, checkpoint WAL, or scan all database pages.",
					Priority:       95,
					Condition: types.PatternCondition{
						Type: types.MatcherPragmaName,
						Values: []string{
							"query_only", "writable_schema", "wal_checkpoint", "integrity_check", "quick_check", "optimize",
						},
					},
				},
				{
					Name:           "sqlite-blob-dos",
					Description:    "Require human confirmation for randomblob/zeroblob memory amplification or extension loading.",
					BuiltinPack:    "sqlite-pragma-blob",
					Enabled:        true,
					Engines:        []string{"sqlite"},
					Families:       []types.EngineFamily{types.FamilySQL},
					Action:         types.PatternActionRequireApproval,
					ConfirmTitle:   "Confirm SQLite Large Allocation / Extension Function",
					ConfirmMessage: "Function allocates large blobs in memory or loads native extensions outside EXPLAIN row estimates.",
					Priority:       85,
					Condition: types.PatternCondition{
						Type:   types.MatcherFunctionCall,
						Values: []string{"randomblob", "zeroblob", "load_extension"},
					},
				},
			},
		},
		{
			ID:          "redis-single-thread",
			Name:        "Redis Single-Thread Stall Guard",
			Description: "Blocks CLIENT PAUSE and requires confirmation for SAMPLES 0 scans or huge SCAN COUNT batches.",
			Engines:     []string{"redis"},
			Rules: []types.RiskPatternRule{
				{
					Name:           "redis-client-pause",
					Description:    "Deny Redis CLIENT PAUSE commands that block all connected clients.",
					BuiltinPack:    "redis-single-thread",
					Enabled:        true,
					Engines:        []string{"redis"},
					Families:       []types.EngineFamily{types.FamilyKV},
					Action:         types.PatternActionDeny,
					ConfirmTitle:   "Redis CLIENT PAUSE Blocked",
					ConfirmMessage: "CLIENT PAUSE suspends command processing across all clients on the Redis event loop.",
					Priority:       100,
					Condition: types.PatternCondition{
						Type:       types.MatcherCommandArg,
						Command:    "CLIENT",
						Subcommand: "PAUSE",
					},
				},
				{
					Name:           "redis-memory-usage-samples-zero",
					Description:    "Require confirmation when MEMORY USAGE uses SAMPLES 0 (full key traversal).",
					BuiltinPack:    "redis-single-thread",
					Enabled:        true,
					Engines:        []string{"redis"},
					Families:       []types.EngineFamily{types.FamilyKV},
					Action:         types.PatternActionRequireApproval,
					ConfirmTitle:   "Confirm Redis Full Key Memory Traversal",
					ConfirmMessage: "MEMORY USAGE with SAMPLES 0 traverses every nested element on the single-threaded event loop.",
					Priority:       90,
					Condition: types.PatternCondition{
						Type:       types.MatcherCommandArg,
						Command:    "MEMORY",
						Subcommand: "USAGE",
						ArgKeyword: "SAMPLES",
						ArgEquals:  "0",
					},
				},
				{
					Name:           "redis-scan-large-count",
					Description:    "Require confirmation when SCAN COUNT exceeds 10,000 keys per iteration.",
					BuiltinPack:    "redis-single-thread",
					Enabled:        true,
					Engines:        []string{"redis"},
					Families:       []types.EngineFamily{types.FamilyKV},
					Action:         types.PatternActionRequireApproval,
					ConfirmTitle:   "Confirm Large Redis SCAN Batch",
					ConfirmMessage: "SCAN COUNT > 10000 can block the Redis single thread for tens of milliseconds.",
					Priority:       80,
					Condition: types.PatternCondition{
						Type:     types.MatcherRiskFlag,
						Values:   []string{"scan_large_count"},
					},
				},
			},
		},
		{
			ID:          "mongo-js-explain",
			Name:        "MongoDB JS & ExecutionStats Guard",
			Description: "Gates $where/$function/$accumulator JS evaluation, allowDiskUse, and executionStats explain execution.",
			Engines:     []string{"mongodb"},
			Rules: []types.RiskPatternRule{
				{
					Name:           "mongo-js-operators",
					Description:    "Require human confirmation for server-side JavaScript operators ($where, $function, $accumulator).",
					BuiltinPack:    "mongo-js-explain",
					Enabled:        true,
					Engines:        []string{"mongodb"},
					Families:       []types.EngineFamily{types.FamilyDocument},
					Action:         types.PatternActionRequireApproval,
					ConfirmTitle:   "Confirm MongoDB Server-Side JavaScript Evaluation",
					ConfirmMessage: "Query uses $where, $function, or $accumulator which executes unindexed JS per document.",
					Priority:       95,
					Condition: types.PatternCondition{
						Any: []types.PatternCondition{
							{Type: types.MatcherJSONPath, JSONPath: "$where"},
							{Type: types.MatcherJSONPath, JSONPath: "$function"},
							{Type: types.MatcherJSONPath, JSONPath: "$accumulator"},
						},
					},
				},
				{
					Name:           "mongo-explain-execution-stats",
					Description:    "Require confirmation when MongoDB explain uses executionStats or allPlansExecution.",
					BuiltinPack:    "mongo-js-explain",
					Enabled:        true,
					Engines:        []string{"mongodb"},
					Families:       []types.EngineFamily{types.FamilyDocument},
					Action:         types.PatternActionRequireApproval,
					ConfirmTitle:   "Confirm Executable MongoDB Explain",
					ConfirmMessage: "executionStats/allPlansExecution actually executes the underlying query plan.",
					Priority:       85,
					Condition: types.PatternCondition{
						Any: []types.PatternCondition{
							{Type: types.MatcherJSONPath, JSONPath: "verbosity", Equals: "executionStats"},
							{Type: types.MatcherJSONPath, JSONPath: "verbosity", Equals: "allPlansExecution"},
						},
					},
				},
			},
		},
		{
			ID:          "mysql-dos-guard",
			Name:        "MySQL High-Cost & Sleep Guard",
			Description: "Gates MySQL SLEEP/BENCHMARK/LOAD_FILE/GET_LOCK and ORDER BY RAND() / SQL_CALC_FOUND_ROWS / deep OFFSET.",
			Engines:     []string{"mysql"},
			Rules: []types.RiskPatternRule{
				{
					Name:           "mysql-sleep-benchmark-file",
					Description:    "Require human confirmation for SLEEP, BENCHMARK, LOAD_FILE, or GET_LOCK calls.",
					BuiltinPack:    "mysql-dos-guard",
					Enabled:        true,
					Engines:        []string{"mysql"},
					Families:       []types.EngineFamily{types.FamilySQL},
					Action:         types.PatternActionRequireApproval,
					ConfirmTitle:   "Confirm MySQL Sleep / Benchmark / Lock Function",
					ConfirmMessage: "Statement invokes CPU loop, connection sleep, server file read, or named lock.",
					Priority:       90,
					Condition: types.PatternCondition{
						Type:   types.MatcherFunctionCall,
						Values: []string{"sleep", "benchmark", "load_file", "get_lock"},
					},
				},
				{
					Name:           "mysql-expensive-sort-offset",
					Description:    "Require confirmation for ORDER BY RAND(), SQL_CALC_FOUND_ROWS, or OFFSET >= 10000.",
					BuiltinPack:    "mysql-dos-guard",
					Enabled:        true,
					Engines:        []string{"mysql"},
					Families:       []types.EngineFamily{types.FamilySQL},
					Action:         types.PatternActionRequireApproval,
					ConfirmTitle:   "Confirm Expensive MySQL Sort / Deep Offset",
					ConfirmMessage: "Query triggers filesort over full rows or scans deep discarded offsets.",
					Priority:       75,
					Condition: types.PatternCondition{
						Type:   types.MatcherRiskFlag,
						Values: []string{"order_by_random", "sql_calc_found_rows", "deep_offset"},
					},
				},
			},
		},
	}
}

// GetBuiltinRulePack finds a preset pack by ID.
func GetBuiltinRulePack(id string) (types.BuiltinRulePack, bool) {
	for _, p := range BuiltinRulePacks() {
		if p.ID == id {
			return p, true
		}
	}
	return types.BuiltinRulePack{}, false
}
