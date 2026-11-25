package builtin

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/x0c/agent-dbctl/internal/driver"
	"github.com/x0c/agent-dbctl/internal/types"
)

var benchSQLiteExecSink *types.ExecResult

func setupBenchSQLite(b *testing.B, rowCount int) (*sqliteConn, string) {
	b.Helper()
	dbPath := filepath.Join(b.TempDir(), "bench.sqlite")
	db, err := sql.Open("sqlite", "file:"+dbPath+"?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)")
	if err != nil {
		b.Fatalf("open sqlite: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE items (id INTEGER PRIMARY KEY, code TEXT NOT NULL, payload TEXT NOT NULL, amount REAL NOT NULL, raw BLOB)`); err != nil {
		b.Fatalf("create table: %v", err)
	}
	tx, err := db.Begin()
	if err != nil {
		b.Fatal(err)
	}
	stmt, err := tx.Prepare(`INSERT INTO items(id, code, payload, amount, raw) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		b.Fatal(err)
	}
	for i := 1; i <= rowCount; i++ {
		if _, err := stmt.Exec(i, "CODE_ABC_123", "some representative row payload string", float64(i)*1.25, []byte("plain-utf8-text")); err != nil {
			b.Fatal(err)
		}
	}
	_ = stmt.Close()
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
	_ = db.Close()

	drv := &SQLiteDriver{}
	conn, err := drv.Open(context.Background(), driver.ConnectionConfig{
		Engine:       "sqlite",
		Host:         dbPath,
		DatabaseName: dbPath,
		ReadOnly:     true,
	})
	if err != nil {
		b.Fatalf("driver open: %v", err)
	}
	b.Cleanup(func() { _ = conn.Close() })
	return conn.(*sqliteConn), dbPath
}

func BenchmarkSQLiteExecute200Rows(b *testing.B) {
	conn, _ := setupBenchSQLite(b, 500)
	ctx := context.Background()
	opts := driver.ExecOpts{MaxRows: 200, MaxBytes: 262144}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		res, err := conn.Execute(ctx, "SELECT id, code, payload, amount, raw FROM items ORDER BY id LIMIT 200", opts)
		if err != nil {
			b.Fatal(err)
		}
		benchSQLiteExecSink = res
	}
}

func BenchmarkSQLiteExecuteTruncatedLookahead(b *testing.B) {
	conn, _ := setupBenchSQLite(b, 2000)
	ctx := context.Background()
	opts := driver.ExecOpts{MaxRows: 200, MaxBytes: 262144}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		res, err := conn.Execute(ctx, "SELECT id, code, payload, amount, raw FROM items", opts)
		if err != nil {
			b.Fatal(err)
		}
		benchSQLiteExecSink = res
	}
}
