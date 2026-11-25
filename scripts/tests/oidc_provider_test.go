package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func newTestProvider(t *testing.T) *provider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &provider{
		issuer: "http://oidc:8081", externalURL: "http://127.0.0.1:18081",
		key: key, kid: "smoke-rsa-1",
		codes: map[string]authorization{}, devices: map[string]*deviceAuthorization{},
	}
}

func tokenRequest(p *provider, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	p.token(rec, req)
	return rec
}

func verifyTestJWT(t *testing.T, p *provider, raw string, expectedNonce string) {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid JWT segments: %q", raw)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || rsa.VerifyPKCS1v15(&p.key.PublicKey, crypto.SHA256, digest[:], signature) != nil {
		t.Fatalf("invalid RS256 signature: %v", err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Issuer string `json:"iss"`
		Nonce  string `json:"nonce"`
		Email  string `json:"email"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != p.issuer || claims.Nonce != expectedNonce || claims.Email != "admin@example.com" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestOIDCProviderAuthorizationCodePKCE(t *testing.T) {
	p := newTestProvider(t)
	verifier := "correct-horse-battery-staple"
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	query := url.Values{
		"client_id": {clientID}, "response_type": {"code"},
		"redirect_uri": {"http://127.0.0.1:18080/api/v1/auth/oidc/callback"},
		"state":        {"state-1"}, "nonce": {"nonce-1"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest(http.MethodGet, "/authorize?"+query.Encode(), nil)
	rec := httptest.NewRecorder()
	p.authorize(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize status=%d body=%s", rec.Code, rec.Body.String())
	}
	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || location.Query().Get("state") != "state-1" {
		t.Fatalf("invalid redirect: %q err=%v", rec.Header().Get("Location"), err)
	}
	tokenRec := tokenRequest(p, url.Values{
		"grant_type": {"authorization_code"}, "client_id": {clientID},
		"code": {location.Query().Get("code")}, "code_verifier": {verifier},
	})
	if tokenRec.Code != http.StatusOK {
		t.Fatalf("token status=%d body=%s", tokenRec.Code, tokenRec.Body.String())
	}
	var tokens struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(tokenRec.Body.Bytes(), &tokens); err != nil || tokens.IDToken == "" {
		t.Fatalf("invalid token response: %s err=%v", tokenRec.Body.String(), err)
	}
	verifyTestJWT(t, p, tokens.IDToken, "nonce-1")
}

func TestOIDCProviderDeviceFlow(t *testing.T) {
	p := newTestProvider(t)
	req := httptest.NewRequest(http.MethodPost, "/device_authorization", strings.NewReader("client_id="+clientID))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	p.deviceAuthorization(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("device authorization status=%d body=%s", rec.Code, rec.Body.String())
	}
	var device struct {
		DeviceCode string `json:"device_code"`
		UserCode   string `json:"user_code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &device); err != nil || device.DeviceCode == "" || device.UserCode == "" {
		t.Fatalf("invalid device response: %s err=%v", rec.Body.String(), err)
	}
	pending := tokenRequest(p, url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"},
		"client_id":  {clientID}, "device_code": {device.DeviceCode},
	})
	if pending.Code != http.StatusBadRequest || !strings.Contains(pending.Body.String(), "authorization_pending") {
		t.Fatalf("pending device token status=%d body=%s", pending.Code, pending.Body.String())
	}

	decision := httptest.NewRequest(http.MethodPost, "/device", strings.NewReader(
		`{"user_code":`+strconvQuote(device.UserCode)+`,"decision":"approve"}`,
	))
	decision.Header.Set("Content-Type", "application/json")
	decisionRec := httptest.NewRecorder()
	p.deviceDecision(decisionRec, decision)
	if decisionRec.Code != http.StatusOK {
		t.Fatalf("device decision status=%d body=%s", decisionRec.Code, decisionRec.Body.String())
	}
	approved := tokenRequest(p, url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"},
		"client_id":  {clientID}, "device_code": {device.DeviceCode},
	})
	if approved.Code != http.StatusOK {
		t.Fatalf("approved device token status=%d body=%s", approved.Code, approved.Body.String())
	}
	var tokens struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(approved.Body.Bytes(), &tokens); err != nil {
		t.Fatal(err)
	}
	verifyTestJWT(t, p, tokens.IDToken, "")
}

func strconvQuote(value string) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}
