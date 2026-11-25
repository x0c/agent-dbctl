package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteStandaloneWritesSerializeWithReadWriteTransactions(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "writer.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = st.Close() }()

	for i := 0; i < 20; i++ {
		readReady := make(chan struct{})
		txDone := make(chan error, 1)
		go func() {
			txDone <- st.withTx(ctx, func(tx *sql.Tx) error {
				var code string
				if err := st.txQueryRow(ctx, tx, `SELECT code FROM environments WHERE code = 'dev'`).Scan(&code); err != nil {
					return err
				}
				close(readReady)
				// Give a standalone writer the opportunity to commit after this
				// transaction has established its SQLite read snapshot.
				time.Sleep(5 * time.Millisecond)
				_, err := st.txExec(ctx, tx, `UPDATE environments SET updated_at_utc = updated_at_utc WHERE code = 'dev'`)
				return err
			})
		}()

		<-readReady
		writeDone := make(chan error, 1)
		go func() {
			_, err := st.dbExec(ctx, `UPDATE global_security_config SET updated_at_utc = ? WHERE id = 1`, nowUTC())
			writeDone <- err
		}()

		if err := <-txDone; err != nil {
			t.Fatalf("read-write transaction %d: %v", i, err)
		}
		if err := <-writeDone; err != nil {
			t.Fatalf("standalone write %d: %v", i, err)
		}
	}
}
