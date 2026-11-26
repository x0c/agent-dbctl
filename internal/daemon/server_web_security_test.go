package daemon

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/x0c/agent-dbctl/internal/auth"
	"github.com/x0c/agent-dbctl/internal/config"
	"github.com/x0c/agent-dbctl/internal/store"
)

func TestOIDCErrorCallbackRequiresItsBrowser(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"authorization_endpoint":"https://login.example.com/authorize","token_endpoint":"https://login.example.com/token","jwks_uri":"https://login.example.com/jwks"}`))
	}))
	defer provider.Close()
	st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := &Service{
		serverCfg:  &config.ServerConfig{PublicURL: "https://dbctl.example.com"},
		store:      st,
		oidcClient: auth.NewOIDCClient(provider.URL, "client", "", nil),
	}
	h := NewRemoteServerHandler(svc)
	start := httptest.NewRecorder()
	h.ServeHTTP(start, httptest.NewRequest(http.MethodGet, "https://dbctl.example.com/api/v1/auth/oidc/login?return_to=%2Fcatalog", nil))
	if start.Code != http.StatusFound {
		t.Fatalf("OIDC login status = %d, response = %s", start.Code, start.Body)
	}
	res := start.Result()
	t.Cleanup(func() { _ = res.Body.Close() })
	if len(res.Cookies()) != 1 {
		t.Fatal("missing browser binding cookie")
	}
	cookie := res.Cookies()[0]
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" || cookie.Domain != "" || !strings.HasPrefix(cookie.Name, "__Host-") {
		t.Fatal("HTTPS browser binding cookie has unexpected attributes")
	}
	authURL, err := url.Parse(res.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	callback := "https://dbctl.example.com/api/v1/auth/oidc/callback?error=access_denied&state=" + url.QueryEscape(authURL.Query().Get("state"))
	for _, tt := range []struct {
		name   string
		cookie *http.Cookie
		status int
	}{
		{"missing browser", nil, http.StatusForbidden},
		{"original browser", cookie, http.StatusFound},
		{"consumed state", cookie, http.StatusForbidden},
	} {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, callback, nil)
			if tt.cookie != nil {
				r.AddCookie(tt.cookie)
			}
			h.ServeHTTP(w, r)
			if w.Code != tt.status || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("callback status = %d or unexpected caching: %s", w.Code, w.Header().Get("Cache-Control"))
			}
			if tt.status == http.StatusFound && !strings.HasPrefix(w.Header().Get("Location"), "/catalog?error=") {
				t.Fatal("missing same-origin recovery link")
			}
		})
	}
}

func TestPasswordLoginGuardAndSecurityHeaders(t *testing.T) {
	h := make(http.Header)
	setServerSecurityHeaders(h, "/rpc/v1/auth/status", &config.ServerConfig{PublicURL: "https://dbctl.example.com"})
	if h.Get("Cache-Control") != "no-store" || h.Get("Strict-Transport-Security") == "" ||
		h.Get("X-Content-Type-Options") != "nosniff" || h.Get("X-Frame-Options") != "DENY" || !strings.Contains(h.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatalf("missing security headers: %v", h)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	r.RemoteAddr = "192.0.2.10:4321"
	r.Header.Set("X-Forwarded-For", "198.51.100.1")
	if got := loginPeerIP(r, &config.ServerConfig{TrustProxyHeaders: true}); got != "192.0.2.10" {
		t.Fatalf("untrusted peer address = %s", got)
	}
	trusted := &config.ServerConfig{TrustProxyHeaders: true, TrustedProxyCIDRs: []string{"192.0.2.0/24"}}
	if got := loginPeerIP(r, trusted); got != "198.51.100.1" {
		t.Fatalf("proxied peer address = %s", got)
	}
	g, now := newPasswordLoginGuard(), time.Now()
	for range passwordRateBurst {
		if !g.allow("peer-a", now) {
			t.Fatal("rate guard denied bounded request burst")
		}
	}
	if g.allow("peer-a", now) || !g.allow("peer-b", now) || !g.allow("peer-a", now.Add(passwordRateWindow)) {
		t.Fatal("rate guard did not isolate peers and reset after its window")
	}
	for range 2 {
		if !g.tryVerify() {
			t.Fatal("available verifier was rejected")
		}
	}
	if g.tryVerify() {
		t.Fatal("unexpected concurrent verification cap")
	}
	g.endVerify()
	g.endVerify()
}
