package plugin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

	// 3. Valid manifest passes.
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

	items, err := ScanPlugins(dir)
	if err != nil {
		t.Fatalf("ScanPlugins: %v", err)
	}
	if len(items) != 3 {
		t.Fatalf("expected 3 scanned plugins, got %d", len(items))
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
	if !byID["ok"].Verified {
		t.Fatalf("expected valid plugin verified, got %+v", byID["ok"])
	}
}
