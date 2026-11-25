package driver_test

import (
	"testing"

	"github.com/x0c/agent-dbctl/internal/driver"
	"github.com/x0c/agent-dbctl/internal/secrets"
	"github.com/x0c/agent-dbctl/internal/types"
)

var (
	benchRowAcceptSink bool
	benchPoolKeySink   string
)

func BenchmarkRowBufferTryAcceptRow200(b *testing.B) {
	rows := make([][]any, 200)
	for i := range rows {
		rows[i] = []any{int64(i), "ord_20261125_abcdef", "paid", float64(199.95), true, "2026-11-25T12:00:00Z"}
	}
	b.ReportAllocs()
	for b.Loop() {
		buf := driver.RowBuffer{MaxRows: 200, MaxBytes: 262144}
		accepted := false
		for _, r := range rows {
			accepted = buf.TryAcceptRow(r)
		}
		benchRowAcceptSink = accepted
	}
}

func BenchmarkBuildConnPoolKey(b *testing.B) {
	meta := driver.ConnPoolMeta{
		TargetID:         "tgt_1",
		InstanceID:       "inst_1",
		NetworkProfileID: "net_1",
		CredentialID:     "cred_1",
		CredKind:         types.CredKeychain,
		ReadOnly:         true,
	}
	cfg := driver.ConnectionConfig{
		Engine:       "postgres",
		Host:         "db.example.internal",
		Port:         5432,
		DatabaseName: "orders",
		TLSMode:      "require",
		Params: map[string]string{
			"sslrootcert": "/etc/ssl/cert.pem",
			"exec_mode":   "simple_protocol",
		},
		Credential: secrets.ResolvedSecret{
			Username: "ro_agent",
			Secret:   "example-secret-value",
		},
	}
	b.ReportAllocs()
	for b.Loop() {
		benchPoolKeySink = driver.BuildConnPoolKey(meta, cfg, "net_1|direct|2026-11-25T00:00:00Z|require")
	}
}
