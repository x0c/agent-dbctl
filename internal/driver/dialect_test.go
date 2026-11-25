package driver

import "testing"

func TestDetectServerCapabilities(t *testing.T) {
	cases := []struct {
		name         string
		engine       string
		version      string
		hints        DialectHints
		wantDialect  string
		wantExplain  string
		wantJSON     bool
		wantReturn   bool
		wantRESP3    bool
		wantAuthList bool
		wantMaj      int
		wantMin      int
	}{
		{
			name:        "postgres 16",
			engine:      "postgres",
			version:     "PostgreSQL 16.4 (Debian 16.4-1.pgdg120+1) on aarch64-unknown-linux-gnu",
			wantDialect: "postgres",
			wantExplain: "pg_json",
			wantJSON:    true,
			wantReturn:  true,
			wantMaj:     16,
			wantMin:     4,
		},
		{
			name:        "postgres 8.4 text explain fallback",
			engine:      "postgres",
			version:     "PostgreSQL 8.4.22 on x86_64-pc-linux-gnu",
			wantDialect: "postgres",
			wantExplain: "pg_text",
			wantJSON:    false,
			wantReturn:  true,
			wantMaj:     8,
			wantMin:     4,
		},
		{
			name:        "cockroachdb",
			engine:      "postgres",
			version:     "CockroachDB CCL v24.1.3 (x86_64-unknown-linux-gnu)",
			wantDialect: "cockroachdb",
			wantExplain: "pg_text",
			wantJSON:    false,
			wantReturn:  true,
			wantMaj:     24,
			wantMin:     1,
		},
		{
			name:        "redshift",
			engine:      "postgres",
			version:     "PostgreSQL 8.0.2 on i686-pc-linux-gnu, Amazon Redshift 1.0.70123",
			wantDialect: "redshift",
			wantExplain: "pg_text",
			wantJSON:    false,
			wantReturn:  false,
			wantMaj:     8,
			wantMin:     0,
		},
		{
			name:        "yugabytedb",
			engine:      "postgres",
			version:     "PostgreSQL 15.2-YB-2.23.0.0 on x86_64-pc-linux-gnu",
			wantDialect: "yugabytedb",
			wantExplain: "pg_json",
			wantJSON:    true,
			wantReturn:  true,
			wantMaj:     15,
			wantMin:     2,
		},
		{
			name:        "greenplum",
			engine:      "postgres",
			version:     "PostgreSQL 12.12 (Greenplum Database 7.1.0 build dev)",
			wantDialect: "greenplum",
			wantExplain: "pg_text",
			wantJSON:    false,
			wantReturn:  true,
			wantMaj:     7,
			wantMin:     1,
		},
		{
			name:        "alloydb",
			engine:      "postgres",
			version:     "PostgreSQL 15.5 AlloyDB",
			wantDialect: "alloydb",
			wantExplain: "pg_json",
			wantJSON:    true,
			wantReturn:  true,
			wantMaj:     15,
			wantMin:     5,
		},
		{
			name:        "mysql 8.4 json v2",
			engine:      "mysql",
			version:     "8.4.3",
			wantDialect: "mysql",
			wantExplain: "mysql_json_v2",
			wantJSON:    true,
			wantMaj:     8,
			wantMin:     4,
		},
		{
			name:        "mysql 5.7 json v1",
			engine:      "mysql",
			version:     "5.7.44-log",
			wantDialect: "mysql",
			wantExplain: "mysql_json_v1",
			wantJSON:    true,
			wantMaj:     5,
			wantMin:     7,
		},
		{
			name:        "mysql 5.5 tabular",
			engine:      "mysql",
			version:     "5.5.62",
			wantDialect: "mysql",
			wantExplain: "mysql_tabular",
			wantJSON:    false,
			wantMaj:     5,
			wantMin:     5,
		},
		{
			name:        "mariadb 11.4",
			engine:      "mysql",
			version:     "11.4.2-MariaDB-ubu2404",
			wantDialect: "mariadb",
			wantExplain: "mariadb_json",
			wantJSON:    true,
			wantReturn:  true,
			wantMaj:     11,
			wantMin:     4,
		},
		{
			name:        "mariadb 10.0 pre-json",
			engine:      "mysql",
			version:     "10.0.38-MariaDB",
			wantDialect: "mariadb",
			wantExplain: "mysql_tabular",
			wantJSON:    false,
			wantReturn:  false,
			wantMaj:     10,
			wantMin:     0,
		},
		{
			name:        "tidb v7.5",
			engine:      "mysql",
			version:     "8.0.11-TiDB-v7.5.2",
			wantDialect: "tidb",
			wantExplain: "mysql_tabular",
			wantJSON:    false,
			wantMaj:     7,
			wantMin:     5,
		},
		{
			name:        "oceanbase mysql tenant",
			engine:      "mysql",
			version:     "5.7.25-OceanBase_CE-v4.3.1",
			wantDialect: "oceanbase_mysql",
			wantExplain: "mysql_tabular",
			wantJSON:    false,
			wantMaj:     4,
			wantMin:     3,
		},
		{
			name:        "sqlite pre-returning 3.34",
			engine:      "sqlite",
			version:     "3.34.1",
			wantDialect: "sqlite",
			wantExplain: "sqlite_eqp",
			wantReturn:  false,
			wantMaj:     3,
			wantMin:     34,
		},
		{
			name:        "sqlite 3.46 returning",
			engine:      "sqlite",
			version:     "3.46.1",
			wantDialect: "sqlite",
			wantExplain: "sqlite_eqp",
			wantReturn:  true,
			wantMaj:     3,
			wantMin:     46,
		},
		{
			name:         "mongodb 7.0",
			engine:       "mongodb",
			version:      "7.0.14",
			wantDialect:  "mongodb",
			wantExplain:  "mongo_queryPlanner",
			wantJSON:     true,
			wantAuthList: true,
			wantMaj:      7,
			wantMin:      0,
		},
		{
			name:         "mongodb wire fallback + ferretdb",
			engine:       "mongodb",
			version:      "wire_v21",
			hints:        DialectHints{BuildInfoModules: []string{"FerretDB"}},
			wantDialect:  "ferretdb",
			wantExplain:  "mongo_queryPlanner",
			wantJSON:     true,
			wantAuthList: true,
			wantMaj:      7,
			wantMin:      0,
		},
		{
			name:        "redis 5.0",
			engine:      "redis",
			version:     "5.0.14",
			wantDialect: "redis",
			wantExplain: "none",
			wantRESP3:   false,
			wantMaj:     5,
			wantMin:     0,
		},
		{
			name:        "redis 7.2 cluster",
			engine:      "redis",
			version:     "7.2.5",
			hints:       DialectHints{ClusterMode: true},
			wantDialect: "redis",
			wantExplain: "none",
			wantRESP3:   true,
			wantMaj:     7,
			wantMin:     2,
		},
		{
			name:        "valkey 8.0",
			engine:      "redis",
			version:     "7.2.4",
			hints:       DialectHints{InfoServer: "# Server\r\nredis_version:7.2.4\r\nvalkey_version:8.0.1\r\n"},
			wantDialect: "valkey",
			wantExplain: "none",
			wantRESP3:   true,
			wantMaj:     8,
			wantMin:     0,
		},
		{
			name:        "dragonfly 1.21",
			engine:      "redis",
			version:     "6.2.0",
			hints:       DialectHints{InfoServer: "# Server\nredis_version:6.2.0\ndragonfly_version:df-v1.21.2\n"},
			wantDialect: "dragonfly",
			wantExplain: "none",
			wantRESP3:   true,
			wantMaj:     1,
			wantMin:     21,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DetectServerCapabilities(tc.engine, tc.version, tc.hints)
			if got.Dialect != tc.wantDialect {
				t.Fatalf("Dialect = %q, want %q", got.Dialect, tc.wantDialect)
			}
			if got.ExplainFormat != tc.wantExplain {
				t.Fatalf("ExplainFormat = %q, want %q", got.ExplainFormat, tc.wantExplain)
			}
			if got.SupportsExplainJSON != tc.wantJSON {
				t.Fatalf("SupportsExplainJSON = %v, want %v", got.SupportsExplainJSON, tc.wantJSON)
			}
			if got.SupportsReturning != tc.wantReturn {
				t.Fatalf("SupportsReturning = %v, want %v", got.SupportsReturning, tc.wantReturn)
			}
			if got.SupportsRESP3 != tc.wantRESP3 {
				t.Fatalf("SupportsRESP3 = %v, want %v", got.SupportsRESP3, tc.wantRESP3)
			}
			if got.SupportsAuthorizedDBList != tc.wantAuthList {
				t.Fatalf("SupportsAuthorizedDBList = %v, want %v", got.SupportsAuthorizedDBList, tc.wantAuthList)
			}
			if got.MajorVersion != tc.wantMaj || got.MinorVersion != tc.wantMin {
				t.Fatalf("Version = %d.%d, want %d.%d", got.MajorVersion, got.MinorVersion, tc.wantMaj, tc.wantMin)
			}
		})
	}
}
