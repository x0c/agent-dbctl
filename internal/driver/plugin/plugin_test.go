package plugin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/x0c/agent-dbctl/internal/driver"
	"github.com/x0c/agent-dbctl/internal/types"
)

type stubService struct {
	chunks []ExecuteChunk
}

func (s *stubService) Metadata(context.Context) (types.DriverMetadata, error) {
	return types.DriverMetadata{ID: "stub", Engine: "stub", Tier: "plugin"}, nil
}
func (s *stubService) Ping(context.Context, TargetSpec) (types.PingResult, error) {
	return types.PingResult{Reachable: true}, nil
}
func (s *stubService) ListDatabases(context.Context, TargetSpec) ([]string, error) {
	return []string{"db1"}, nil
}
func (s *stubService) Classify(context.Context, string) (types.Classification, error) {
	return types.Classification{}, nil
}
func (s *stubService) Preflight(context.Context, TargetSpec, string) (*types.PreflightReport, error) {
	return &types.PreflightReport{}, nil
}
func (s *stubService) ExecuteStream(_ context.Context, _ TargetSpec, _ string, _ int, _ int64, onChunk func(ExecuteChunk) error) error {
	for _, ch := range s.chunks {
		if err := onChunk(ch); err != nil {
			return err
		}
	}
	return nil
}

func TestPluginExecutePreservesSummaryTruncation(t *testing.T) {
	conn := &pluginConn{
		svc: &stubService{
			chunks: []ExecuteChunk{
				{Kind: "header", Family: "sql", Columns: []types.Column{{Name: "id", TypeName: "INT"}}},
				{Kind: "row", Rows: [][]any{{1}, {2}}},
				{Kind: "summary", Family: "sql", FetchedRows: 1002, Truncated: true, CutoffReason: "max_rows"},
			},
		},
	}

	res, err := conn.Execute(context.Background(), "SELECT id FROM t", driver.ExecOpts{MaxRows: 2})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !res.Truncated || res.CutoffReason != "max_rows" || res.FetchedRows != 1002 || res.ReturnedRows != 2 {
		t.Fatalf("expected plugin truncation metadata preserved, got %+v", res)
	}
}

func TestPluginExecuteStopsStreamOnHostRowLimit(t *testing.T) {
	conn := &pluginConn{
		svc: &stubService{
			chunks: []ExecuteChunk{
				{Kind: "header", Family: "sql", Columns: []types.Column{{Name: "id", TypeName: "INT"}}},
				{Kind: "row", Rows: [][]any{{1}, {2}, {3}}},
				{Kind: "row", Rows: [][]any{{4}, {5}}},
			},
		},
	}

	res, err := conn.Execute(context.Background(), "SELECT id FROM t", driver.ExecOpts{MaxRows: 2})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !res.Truncated || res.CutoffReason != "max_rows" || res.ReturnedRows != 2 {
		t.Fatalf("expected host-enforced truncation at 2 rows, got %+v", res)
	}
}

func TestDialBridgeForwardsTrafficAndCloses(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = echoLn.Close() }()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(cn net.Conn) {
				defer func() { _ = cn.Close() }()
				_, _ = io.Copy(cn, cn)
			}(c)
		}
	}()

	host, port, closeFn, err := startDialBridge(
		context.Background(),
		func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, echoLn.Addr().String())
		},
		"remote.internal:5432",
	)
	if err != nil {
		t.Fatalf("startDialBridge: %v", err)
	}

	c, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("dial bridge: %v", err)
	}
	_, _ = io.WriteString(c, "hello")
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if string(buf) != "hello" {
		t.Fatalf("expected hello via bridge, got %q", string(buf))
	}
	if err := closeFn(); err != nil {
		t.Fatalf("close bridge: %v", err)
	}
}

func TestScanPluginsValidation(t *testing.T) {
	dir := t.TempDir()

	// 1. Path traversal blocked.
	travDir := filepath.Join(dir, "trav")
	if err := os.MkdirAll(travDir, 0o700); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(travDir, "manifest.json"), []byte(`{
		"id":"trav","engine":"trav","host_api_version":1,"binary":"../evil","sha256":"abc"
	}`), 0o600)

	// 2. Host API mismatch blocked.
	apiDir := filepath.Join(dir, "oldapi")
	if err := os.MkdirAll(apiDir, 0o700); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(apiDir, "manifest.json"), []byte(`{
		"id":"oldapi","engine":"oldapi","host_api_version":99,"binary":"bin","sha256":"abc"
	}`), 0o600)

	// 3. Valid v1 manifest passes.
	okDir := filepath.Join(dir, "ok")
	if err := os.MkdirAll(okDir, 0o700); err != nil {
		t.Fatal(err)
	}
	binBytes := []byte("dummy-binary")
	sum := sha256.Sum256(binBytes)
	_ = os.WriteFile(filepath.Join(okDir, "bin"), binBytes, 0o700)
	_ = os.WriteFile(filepath.Join(okDir, "manifest.json"), []byte(fmt.Sprintf(`{
		"id":"ok","engine":"ok","host_api_version":1,"binary":"bin","sha256":%q
	}`, hex.EncodeToString(sum[:]))), 0o600)

	// 4. Valid v2 manifest passes.
	okV2Dir := filepath.Join(dir, "ok-v2")
	if err := os.MkdirAll(okV2Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(okV2Dir, "bin"), binBytes, 0o700)
	_ = os.WriteFile(filepath.Join(okV2Dir, "manifest.json"), []byte(fmt.Sprintf(`{
		"id":"ok-v2","engine":"ok-v2","host_api_version":2,"binary":"bin","sha256":%q
	}`, hex.EncodeToString(sum[:]))), 0o600)

	items, err := ScanPlugins(dir)
	if err != nil {
		t.Fatalf("ScanPlugins: %v", err)
	}
	if len(items) != 4 {
		t.Fatalf("expected 4 scanned plugins, got %d", len(items))
	}
	byID := map[string]DiscoveredPlugin{}
	for _, it := range items {
		byID[it.Manifest.ID] = it
	}
	if byID["trav"].Verified || !strings.Contains(byID["trav"].VerificationErr, "escapes") {
		t.Fatalf("expected traversal rejection, got %+v", byID["trav"])
	}
	if byID["oldapi"].Verified || !strings.Contains(byID["oldapi"].VerificationErr, "host_api_version") {
		t.Fatalf("expected host_api_version rejection, got %+v", byID["oldapi"])
	}
	if !byID["ok"].Verified || !byID["ok-v2"].Verified {
		t.Fatalf("expected valid v1 and v2 plugins verified, got v1=%+v v2=%+v", byID["ok"], byID["ok-v2"])
	}
}

func TestTypedValueRoundTrip(t *testing.T) {
	bigInt := int64(9007199254740993) // 2^53 + 1: would lose precision under float64
	rawBytes := []byte{0x00, 0xff, 0x10, 0xab}

	cases := []struct {
		name  string
		input any
		check func(t *testing.T, got any)
	}{
		{
			name:  "nil",
			input: nil,
			check: func(t *testing.T, got any) {
				if got != nil {
					t.Fatalf("expected nil, got %T(%v)", got, got)
				}
			},
		},
		{
			name:  "exact 64-bit integer above 2^53",
			input: bigInt,
			check: func(t *testing.T, got any) {
				v, ok := got.(int64)
				if !ok || v != bigInt {
					t.Fatalf("got %T(%v), want int64(%d)", got, got, bigInt)
				}
			},
		},
		{
			name:  "max int64",
			input: int64(math.MaxInt64),
			check: func(t *testing.T, got any) {
				v, ok := got.(int64)
				if !ok || v != math.MaxInt64 {
					t.Fatalf("got %T(%v), want MaxInt64", got, got)
				}
			},
		},
		{
			name:  "uint64",
			input: uint64(math.MaxUint64),
			check: func(t *testing.T, got any) {
				v, ok := got.(uint64)
				if !ok || v != math.MaxUint64 {
					t.Fatalf("got %T(%v), want MaxUint64", got, got)
				}
			},
		},
		{
			name:  "raw bytes",
			input: rawBytes,
			check: func(t *testing.T, got any) {
				v, ok := got.([]byte)
				if !ok || !bytes.Equal(v, rawBytes) {
					t.Fatalf("got %T(%x), want %x", got, v, rawBytes)
				}
			},
		},
		{
			name:  "non-finite float",
			input: math.NaN(),
			check: func(t *testing.T, got any) {
				if got != "NaN" {
					t.Fatalf("got %v, want NaN string", got)
				}
			},
		},
		{
			name:  "nested struct and list",
			input: map[string]any{"ids": []any{bigInt, int64(2)}, "ok": true},
			check: func(t *testing.T, got any) {
				want := map[string]any{"ids": []any{bigInt, int64(2)}, "ok": true}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("got %#v, want %#v", got, want)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tv := goToTypedValue(tc.input)
			got := typedValueToGo(tv)
			tc.check(t, got)
		})
	}
}

type countingService struct {
	stubService
	listCalls      atomic.Int64
	preflightCalls atomic.Int64
}

func (c *countingService) ListDatabases(ctx context.Context, spec TargetSpec) ([]string, error) {
	c.listCalls.Add(1)
	return c.stubService.ListDatabases(ctx, spec)
}

func (c *countingService) Preflight(ctx context.Context, spec TargetSpec, raw string) (*types.PreflightReport, error) {
	c.preflightCalls.Add(1)
	return c.stubService.Preflight(ctx, spec, raw)
}

func TestPluginCapabilityGating(t *testing.T) {
	cs := &countingService{}
	conn := &pluginConn{
		svc:             cs,
		spec:            TargetSpec{Engine: "custom"},
		protocolVersion: 2,
		capabilities: map[string]struct{}{
			"ping":           {},
			"execute_stream": {},
		},
	}

	if _, err := conn.ListDatabases(context.Background()); err == nil || !strings.Contains(err.Error(), "list_databases") {
		t.Fatalf("expected capability error for ListDatabases, got %v", err)
	}
	rep, err := conn.Preflight(context.Background(), "SELECT 1", driver.PreflightOpts{})
	if err != nil {
		t.Fatalf("Preflight error: %v", err)
	}
	if rep.Supported || len(rep.Warnings) == 0 {
		t.Fatalf("expected unsupported preflight warning when capability omitted, got %+v", rep)
	}
	if cs.listCalls.Load() != 0 || cs.preflightCalls.Load() != 0 {
		t.Fatalf("expected zero RPC dispatches when capabilities omitted")
	}
}

func TestSQLitePluginV1AndV2Subprocess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess plugin build test in -short mode")
	}

	root := t.TempDir()
	binName := "agent-dbctl-plugin-sqlite"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	binPath := filepath.Join(root, binName)
	buildCmd := exec.Command("go", "build", "-o", binPath, "../../../cmd/agent-dbctl-plugin-sqlite")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build plugin binary: %v\n%s", err, string(out))
	}
	binData, err := os.ReadFile(binPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(binData)
	sumHex := hex.EncodeToString(sum[:])

	setupPlugin := func(t *testing.T, id string, engine string, apiVer int, caps []string) *Manager {
		t.Helper()
		pluginsRoot := t.TempDir()
		pdir := filepath.Join(pluginsRoot, id)
		if err := os.MkdirAll(pdir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pdir, binName), binData, 0o700); err != nil {
			t.Fatal(err)
		}
		capsJSON := `"` + strings.Join(caps, `","`) + `"`
		manifest := fmt.Sprintf(`{
			"id": %q,
			"engine": %q,
			"display_name": "SQLite Ext",
			"family": "sql",
			"version": "0.2.0",
			"host_api_version": %d,
			"binary": %q,
			"sha256": %q,
			"capabilities": [%s]
		}`, id, engine, apiVer, binName, sumHex, capsJSON)
		if err := os.WriteFile(filepath.Join(pdir, "manifest.json"), []byte(manifest), 0o600); err != nil {
			t.Fatal(err)
		}
		reg := driver.NewRegistry()
		mgr := NewManager(pluginsRoot, reg)
		t.Cleanup(mgr.Shutdown)
		items, err := mgr.Reload()
		if err != nil || len(items) != 1 || !items[0].Verified {
			t.Fatalf("Reload failed for %s: items=%+v err=%v", id, items, err)
		}
		return mgr
	}

	t.Run("v2 typed int64 fidelity, capabilities, and Cancel RPC", func(t *testing.T) {
		mgr := setupPlugin(t, "sqlite-v2", "sqlite-v2", 2, []string{"ping", "list_databases", "preflight", "execute_stream", "cancel"})
		drv, ok := mgr.registry.Get("sqlite-v2")
		if !ok {
			t.Fatal("sqlite-v2 not registered")
		}
		conn, err := drv.Open(context.Background(), driver.ConnectionConfig{
			Engine:       "sqlite-v2",
			DatabaseName: ":memory:",
			ReadOnly:     true,
		})
		if err != nil {
			t.Fatalf("Open v2: %v", err)
		}
		defer func() { _ = conn.Close() }()

		pingRes, err := conn.Ping(context.Background())
		if err != nil || !pingRes.Reachable || pingRes.Dialect != "sqlite" || pingRes.Capabilities == nil {
			t.Fatalf("expected v2 PingResult with Dialect/Capabilities, got %+v err=%v", pingRes, err)
		}

		// Verify 64-bit integer precision (> 2^53) over v2 TypedValue.
		const wantID = int64(9007199254740993)
		execRes, err := conn.Execute(context.Background(), "SELECT 9007199254740993 AS big_id", driver.ExecOpts{MaxRows: 10})
		if err != nil {
			t.Fatalf("Execute v2: %v", err)
		}
		if len(execRes.Rows) != 1 || len(execRes.Rows[0]) != 1 {
			t.Fatalf("unexpected v2 rows: %+v", execRes.Rows)
		}
		gotID, ok := execRes.Rows[0][0].(int64)
		if !ok || gotID != wantID {
			t.Fatalf("v2 precision mismatch: got %T(%v), want int64(%d)", execRes.Rows[0][0], execRes.Rows[0][0], wantID)
		}

		// Verify out-of-band Cancel RPC aborts a long-running query promptly.
		conn2, err := drv.Open(context.Background(), driver.ConnectionConfig{
			Engine:       "sqlite-v2",
			DatabaseName: ":memory:",
			ReadOnly:     true,
		})
		if err != nil {
			t.Fatalf("Open v2 cancel test: %v", err)
		}
		defer func() { _ = conn2.Close() }()

		errCh := make(chan error, 1)
		go func() {
			_, e := conn2.Execute(context.Background(), "WITH RECURSIVE cnt(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM cnt WHERE x < 100000000) SELECT count(*) FROM cnt", driver.ExecOpts{MaxRows: 1})
			errCh <- e
		}()

		time.Sleep(80 * time.Millisecond)
		if cerr := conn2.CancelAndDiscard(); cerr != nil {
			t.Fatalf("CancelAndDiscard: %v", cerr)
		}
		select {
		case qErr := <-errCh:
			if qErr == nil {
				t.Fatalf("expected error after CancelAndDiscard")
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for cancelled plugin query to abort")
		}
	})

	t.Run("v1 backward compatibility negotiation", func(t *testing.T) {
		mgr := setupPlugin(t, "sqlite-v1", "sqlite-v1", 1, []string{"ping", "list_databases", "preflight", "execute_stream"})
		drv, ok := mgr.registry.Get("sqlite-v1")
		if !ok {
			t.Fatal("sqlite-v1 not registered")
		}
		conn, err := drv.Open(context.Background(), driver.ConnectionConfig{
			Engine:       "sqlite-v1",
			DatabaseName: ":memory:",
			ReadOnly:     true,
		})
		if err != nil {
			t.Fatalf("Open v1: %v", err)
		}
		defer func() { _ = conn.Close() }()

		pingRes, err := conn.Ping(context.Background())
		if err != nil || !pingRes.Reachable {
			t.Fatalf("v1 Ping failed: %+v err=%v", pingRes, err)
		}
		execRes, err := conn.Execute(context.Background(), "SELECT 42 AS answer", driver.ExecOpts{MaxRows: 10})
		if err != nil || len(execRes.Rows) != 1 {
			t.Fatalf("v1 Execute failed: %+v err=%v", execRes, err)
		}
	})
}
