// oidc_provider is an isolated RS256/PKCE OIDC fixture for server smoke tests.
package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

const clientID = "smoke-client"

type authorization struct {
	Challenge string
	Nonce     string
	Expires   time.Time
}

type deviceAuthorization struct {
	UserCode string
	Approved bool
	Expires  time.Time
}

type provider struct {
	issuer      string
	externalURL string
	key         *rsa.PrivateKey
	kid         string
	mu          sync.Mutex
	codes       map[string]authorization
	devices     map[string]*deviceAuthorization
}

func main() {
	issuer := strings.TrimRight(os.Getenv("OIDC_ISSUER"), "/")
	if issuer == "" {
		issuer = "http://oidc:8081"
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	externalURL := strings.TrimRight(os.Getenv("OIDC_EXTERNAL_URL"), "/")
	if externalURL == "" {
		externalURL = "http://127.0.0.1:18081"
	}
	p := &provider{
		issuer: issuer, externalURL: externalURL, key: key, kid: "smoke-rsa-1",
		codes: map[string]authorization{}, devices: map[string]*deviceAuthorization{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /jwks", p.jwks)
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /token", p.token)
	mux.HandleFunc("POST /device_authorization", p.deviceAuthorization)
	mux.HandleFunc("GET /device", p.devicePage)
	mux.HandleFunc("POST /device", p.deviceDecision)
	mux.HandleFunc("GET /userinfo", p.userinfo)

	srv := &http.Server{
		Addr:              ":8081",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	log.Printf("isolated OIDC fixture listening on %s", issuer)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func (p *provider) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                p.issuer,
		"authorization_endpoint":                p.issuer + "/authorize",
		"token_endpoint":                        p.issuer + "/token",
		"jwks_uri":                              p.issuer + "/jwks",
		"userinfo_endpoint":                     p.issuer + "/userinfo",
		"device_authorization_endpoint":         p.issuer + "/device_authorization",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
	})
}

func (p *provider) jwks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": p.kid,
		"n":   base64.RawURLEncoding.EncodeToString(p.key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.key.E)).Bytes()),
	}}})
}

func (p *provider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirectURI, err := url.Parse(q.Get("redirect_uri"))
	if err != nil || !loopbackRedirect(redirectURI) {
		http.Error(w, "invalid loopback redirect_uri", http.StatusBadRequest)
		return
	}
	if q.Get("client_id") != clientID || q.Get("response_type") != "code" || q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		http.Error(w, "invalid authorization request", http.StatusBadRequest)
		return
	}
	code := randomToken(24)
	p.mu.Lock()
	p.codes[code] = authorization{
		Challenge: q.Get("code_challenge"),
		Nonce:     q.Get("nonce"),
		Expires:   time.Now().Add(5 * time.Minute),
	}
	p.mu.Unlock()
	query := redirectURI.Query()
	query.Set("code", code)
	query.Set("state", q.Get("state"))
	redirectURI.RawQuery = query.Encode()
	http.Redirect(w, r, redirectURI.String(), http.StatusFound)
}

func (p *provider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if r.Form.Get("client_id") != clientID {
		writeTokenError(w, "invalid_request")
		return
	}
	if r.Form.Get("grant_type") == "urn:ietf:params:oauth:grant-type:device_code" {
		p.deviceToken(w, r.Form.Get("device_code"))
		return
	}
	if r.Form.Get("grant_type") != "authorization_code" {
		writeTokenError(w, "invalid_request")
		return
	}
	code := r.Form.Get("code")
	p.mu.Lock()
	grant, ok := p.codes[code]
	delete(p.codes, code)
	p.mu.Unlock()
	if !ok || time.Now().After(grant.Expires) {
		writeTokenError(w, "invalid_grant")
		return
	}
	digest := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(digest[:]) != grant.Challenge {
		writeTokenError(w, "invalid_grant")
		return
	}
	p.issueTokens(w, grant.Nonce)
}

func (p *provider) deviceAuthorization(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || r.Form.Get("client_id") != clientID {
		writeTokenError(w, "invalid_request")
		return
	}
	deviceCode := randomToken(24)
	raw := make([]byte, 4)
	if _, err := rand.Read(raw); err != nil {
		http.Error(w, "random source failed", http.StatusInternalServerError)
		return
	}
	userCode := strings.ToUpper(hex.EncodeToString(raw))
	userCode = userCode[:4] + "-" + userCode[4:]
	p.mu.Lock()
	p.devices[deviceCode] = &deviceAuthorization{UserCode: userCode, Expires: time.Now().Add(10 * time.Minute)}
	p.mu.Unlock()
	verificationURI := p.externalURL + "/device"
	writeJSON(w, http.StatusOK, map[string]any{
		"device_code":               deviceCode,
		"user_code":                 userCode,
		"verification_uri":          verificationURI,
		"verification_uri_complete": verificationURI + "?user_code=" + userCode,
		"expires_in":                600,
		"interval":                  1,
	})
}

func (p *provider) devicePage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w, "<!doctype html><title>Isolated OIDC approval</title><form method=post><input name=user_code value=%q autofocus><button name=decision value=approve>Approve synthetic login</button></form>", r.URL.Query().Get("user_code"))
}

func (p *provider) deviceDecision(w http.ResponseWriter, r *http.Request) {
	var userCode, decision string
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var body struct {
			UserCode string `json:"user_code"`
			Decision string `json:"decision"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		userCode, decision = body.UserCode, body.Decision
	} else if err := r.ParseForm(); err == nil {
		userCode, decision = r.Form.Get("user_code"), r.Form.Get("decision")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, device := range p.devices {
		if device.UserCode == userCode && time.Now().Before(device.Expires) {
			device.Approved = decision == "approve"
			writeJSON(w, http.StatusOK, map[string]string{"status": "approved"})
			return
		}
	}
	http.Error(w, "unknown or expired user code", http.StatusNotFound)
}

func (p *provider) deviceToken(w http.ResponseWriter, deviceCode string) {
	p.mu.Lock()
	device, ok := p.devices[deviceCode]
	if !ok || time.Now().After(device.Expires) {
		p.mu.Unlock()
		writeTokenError(w, "expired_token")
		return
	}
	if !device.Approved {
		p.mu.Unlock()
		writeTokenError(w, "authorization_pending")
		return
	}
	delete(p.devices, deviceCode)
	p.mu.Unlock()
	p.issueTokens(w, "")
}

func (p *provider) issueTokens(w http.ResponseWriter, nonce string) {
	now := time.Now()
	idToken, err := p.signJWT(map[string]any{
		"iss":            p.issuer,
		"sub":            "smoke-admin-subject",
		"aud":            clientID,
		"exp":            now.Add(10 * time.Minute).Unix(),
		"iat":            now.Unix(),
		"nonce":          nonce,
		"email":          "admin@example.com",
		"email_verified": true,
		"name":           "Smoke Admin",
	})
	if err != nil {
		http.Error(w, "signing failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": randomToken(24),
		"token_type":   "Bearer",
		"expires_in":   600,
		"id_token":     idToken,
	})
}

func (p *provider) userinfo(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"sub":            "smoke-admin-subject",
		"email":          "admin@example.com",
		"email_verified": true,
		"name":           "Smoke Admin",
	})
}

func (p *provider) signJWT(claims map[string]any) (string, error) {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": p.kid})
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign JWT: %w", err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func loopbackRedirect(u *url.URL) bool {
	if u == nil || u.Scheme != "http" {
		return false
	}
	ip := net.ParseIP(u.Hostname())
	return u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())
}

func randomToken(bytes int) string {
	raw := make([]byte, bytes)
	if _, err := rand.Read(raw); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func writeTokenError(w http.ResponseWriter, code string) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": code})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
