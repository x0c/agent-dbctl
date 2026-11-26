package daemon

import (
	"encoding/hex"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/x0c/agent-dbctl/internal/auth"
	"github.com/x0c/agent-dbctl/internal/config"
)

const (
	oidcBrowserTTL     = 10 * time.Minute
	passwordRateWindow = time.Minute
	passwordRateBurst  = 12
	maxLoginPeers      = 4096

	// Public dummy verifier with the same work factor as a generated password hash.
	dummyLoginPasswordHash = "$argon2id$v=19$m=65536,t=2,p=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

func serverUsesHTTPS(cfg *config.ServerConfig) bool {
	return cfg != nil && strings.HasPrefix(cfg.PublicURL, "https://")
}

func oidcBrowserCookieName(cfg *config.ServerConfig) string {
	if serverUsesHTTPS(cfg) {
		return "__Host-agent_dbctl_oidc"
	}
	return "agent_dbctl_oidc"
}

func isHexToken(raw string, bytes int) bool {
	if len(raw) != bytes*2 {
		return false
	}
	_, err := hex.DecodeString(raw)
	return err == nil
}

func readOIDCBrowserKey(r *http.Request, cfg *config.ServerConfig) string {
	c, err := r.Cookie(oidcBrowserCookieName(cfg))
	if err != nil || !isHexToken(c.Value, 32) {
		return ""
	}
	return c.Value
}

func setOIDCBrowserKey(w http.ResponseWriter, cfg *config.ServerConfig, key string) {
	http.SetCookie(w, &http.Cookie{
		Name:     oidcBrowserCookieName(cfg),
		Value:    key,
		Path:     "/",
		HttpOnly: true,
		Secure:   serverUsesHTTPS(cfg),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(oidcBrowserTTL.Seconds()),
	})
}

func oidcBrowserStateHash(state, browserKey string) string {
	return auth.HashToken("oidc-browser-state:" + state + ":" + browserKey)
}

func setServerSecurityHeaders(h http.Header, path string, cfg *config.ServerConfig) {
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "same-origin")
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	if serverUsesHTTPS(cfg) {
		h.Set("Strict-Transport-Security", "max-age=31536000")
	}
	if strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, "/rpc/") || strings.HasPrefix(path, "/hooks/") {
		h.Set("Cache-Control", "no-store")
	}
}

// loginPeerIP accepts forwarded addresses only over a configured trusted proxy chain.
func loginPeerIP(r *http.Request, cfg *config.ServerConfig) string {
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peer = r.RemoteAddr
	}
	ip, err := netip.ParseAddr(peer)
	if err != nil {
		return "unknown"
	}
	ip = ip.Unmap()
	if cfg == nil || !cfg.TrustProxyHeaders || !isTrustedProxyAddr(ip.String(), cfg.TrustedProxyCIDRs) {
		return ip.String()
	}
	chain := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(chain) - 1; i >= 0; i-- {
		next, err := netip.ParseAddr(strings.TrimSpace(chain[i]))
		if err != nil || next.Zone() != "" {
			break
		}
		ip = next.Unmap()
		if !isTrustedProxyAddr(ip.String(), cfg.TrustedProxyCIDRs) {
			break
		}
	}
	return ip.String()
}

type passwordLoginGuard struct {
	mu        sync.Mutex
	end       time.Time
	attempts  map[string]int
	verifiers chan struct{}
}

func newPasswordLoginGuard() *passwordLoginGuard {
	return &passwordLoginGuard{attempts: make(map[string]int), verifiers: make(chan struct{}, 2)}
}

func (g *passwordLoginGuard) allow(peer string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !now.Before(g.end) {
		clear(g.attempts)
		g.end = now.Add(passwordRateWindow)
	}
	count, exists := g.attempts[peer]
	if count >= passwordRateBurst || (!exists && len(g.attempts) >= maxLoginPeers) {
		return false
	}
	g.attempts[peer] = count + 1
	return true
}

func (g *passwordLoginGuard) tryVerify() bool {
	select {
	case g.verifiers <- struct{}{}:
		return true
	default:
		return false
	}
}

func (g *passwordLoginGuard) endVerify() { <-g.verifiers }
