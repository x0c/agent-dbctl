package daemon_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/x0c/agent-dbctl/internal/daemon"
)

func TestWebAPIAddDatabaseEndpoint(t *testing.T) {
	srv, _ := setupIsolatedServer(t)
	handler := daemon.NewWebHandler(srv.Service())
	cookie, csrf := issueTestWebSession(t, handler)

	dbFile := filepath.Join(t.TempDir(), "web-add.sqlite")
	if err := os.WriteFile(dbFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	payload := fmt.Sprintf(`{"engine":"sqlite","host":%q,"system":"checkout","env":"dev","alias":"checkout-dev","test":true}`, dbFile)
	req := newAuthedWebPOST("/api/v1/db/add", strings.NewReader(payload), cookie, csrf)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/v1/db/add HTTP %d: %s", rec.Code, rec.Body.String())
	}
	var res daemon.DBAddResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if res.Status != "created" || res.Target.System != "checkout" || res.Ping == nil || !res.Ping.Reachable {
		t.Fatalf("unexpected /api/v1/db/add response: %+v", res)
	}
	// Verify Web UI onboarding does not bind daemon's CWD into System.WorkspacePaths.
	sys, err := srv.Service().Store().ResolveSystem(context.Background(), "checkout")
	if err != nil || len(sys.WorkspacePaths) != 0 {
		t.Fatalf("expected empty workspace_paths from Web UI db add, got %+v err=%v", sys, err)
	}
}
