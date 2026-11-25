package builtin

import (
	"context"
	"testing"

	"github.com/x0c/agent-dbctl/internal/driver"
	"github.com/x0c/agent-dbctl/internal/types"
)

func TestSQLiteLiveCapabilitiesAndResetSession(t *testing.T) {
	drv := &SQLiteDriver{}
	conn, err := drv.Open(context.Background(), driver.ConnectionConfig{
		Engine:       "sqlite",
		DatabaseName: ":memory:",
		ReadOnly:     true,
	})
	if err != nil {
		t.Fatalf("Open sqlite: %v", err)
	}
	defer func() { _ = conn.Close() }()

	res, err := conn.Ping(context.Background())
	if err != nil {
		t.Fatalf("Ping sqlite: %v", err)
	}
	if res.Dialect != "sqlite" || res.Capabilities == nil {
		t.Fatalf("expected sqlite dialect & capabilities, got %+v", res)
	}
	if !res.Capabilities.SupportsExplain || !res.Capabilities.SupportsReturning || res.Capabilities.MajorVersion < 3 {
		t.Fatalf("unexpected sqlite capabilities: %+v", res.Capabilities)
	}

	da, ok := conn.(driver.DialectAwareConn)
	if !ok || da.Capabilities() == nil || da.Capabilities().Dialect != "sqlite" {
		t.Fatalf("expected DialectAwareConn cached capabilities")
	}

	sr, ok := conn.(driver.SessionResetter)
	if !ok {
		t.Fatalf("expected sqliteConn to implement SessionResetter")
	}
	if err := sr.ResetSession(context.Background()); err != nil {
		t.Fatalf("ResetSession failed: %v", err)
	}
}

func TestParseRedisServerInfoDialects(t *testing.T) {
	cases := []struct {
		name string
		info string
		want string
	}{
		{
			name: "redis",
			info: "# Server\r\nredis_version:7.2.5\r\n",
			want: "7.2.5",
		},
		{
			name: "valkey over redis_version",
			info: "# Server\r\nredis_version:7.2.4\r\nvalkey_version:8.0.1\r\n",
			want: "8.0.1",
		},
		{
			name: "dragonfly",
			info: "# Server\nredis_version:6.2.0\ndragonfly_version:df-v1.21.2\n",
			want: "df-v1.21.2",
		},
		{
			name: "keydb",
			info: "# Server\nkeydb_version:6.3.4\n",
			want: "6.3.4",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseRedisServerInfo(tc.info); got != tc.want {
				t.Fatalf("parseRedisServerInfo = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCapabilitySeedingPreservedOnConn(t *testing.T) {
	seeded := &types.ServerCapabilities{
		Engine:              "postgres",
		Dialect:             "cockroachdb",
		SupportsExplain:     true,
		SupportsExplainJSON: false,
	}
	pc := &postgresConn{}
	cp := *seeded
	pc.caps.Store(&cp)
	if got := pc.Capabilities(); got == nil || got.Dialect != "cockroachdb" || got.SupportsExplainJSON {
		t.Fatalf("postgresConn capabilities mismatch: %+v", got)
	}

	mc := &mysqlConn{}
	mcp := types.ServerCapabilities{
		Engine:              "mysql",
		Dialect:             "tidb",
		SupportsExplain:     true,
		SupportsExplainJSON: false,
	}
	mc.caps.Store(&mcp)
	if got := mc.Capabilities(); got == nil || got.Dialect != "tidb" || got.SupportsExplainJSON {
		t.Fatalf("mysqlConn capabilities mismatch: %+v", got)
	}
}
