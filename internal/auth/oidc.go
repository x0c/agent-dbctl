package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// OIDCDiscovery holds OpenID Connect provider endpoints from .well-known/openid-configuration.
type OIDCDiscovery struct {
	Issuer                      string `json:"issuer"`
	AuthorizationEndpoint       string `json:"authorization_endpoint"`
	TokenEndpoint               string `json:"token_endpoint"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	UserinfoEndpoint            string `json:"userinfo_endpoint"`
	JWKSURI                     string `json:"jwks_uri"`
}

// DeviceAuthResponse is returned by an OIDC Device Authorization endpoint (RFC 8628).
type DeviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// TokenResponse represents an OAuth2/OIDC token exchange response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	ExpiresIn    int    `json:"expires_in"`
	Error        string `json:"error,omitempty"`
	ErrorDesc    string `json:"error_description,omitempty"`
}

// IDTokenClaims represents verified identity claims from an OIDC ID/Access JWT.
type IDTokenClaims struct {
	Issuer        string   `json:"iss"`
	Subject       string   `json:"sub"`
	Email         string   `json:"email"`
	EmailVerified *bool    `json:"email_verified,omitempty"`
	Name          string   `json:"name"`
	Groups        []string `json:"groups"`
	Nonce         string   `json:"nonce"`
	AudRaw        any      `json:"aud"`
	Exp           int64    `json:"exp"`
	Iat           int64    `json:"iat"`
}

type jwksSet struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// OIDCClient performs discovery, PKCE code exchange, Device Flow, and JWKS JWT verification.
type OIDCClient struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	Scopes       []string
	HTTPClient   *http.Client

	mu        sync.RWMutex
	discovery *OIDCDiscovery
	keys      map[string]any
	keysExp   time.Time
}

// NewOIDCClient creates an OIDC client with bounded HTTP timeouts and no automatic open redirects.
func NewOIDCClient(issuerURL, clientID, clientSecret string, scopes []string) *OIDCClient {
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	return &OIDCClient{
		IssuerURL:    strings.TrimRight(strings.TrimSpace(issuerURL), "/"),
		ClientID:     strings.TrimSpace(clientID),
		ClientSecret: clientSecret,
		Scopes:       scopes,
		HTTPClient:   &http.Client{Timeout: 10 * time.Second},
		keys:         make(map[string]any),
	}
}

// Discover fetches and caches the OIDC provider configuration.
func (c *OIDCClient) Discover(ctx context.Context) (OIDCDiscovery, error) {
	c.mu.RLock()
	if c.discovery != nil {
		d := *c.discovery
		c.mu.RUnlock()
		return d, nil
	}
	c.mu.RUnlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.IssuerURL+"/.well-known/openid-configuration", nil)
	if err != nil {
		return OIDCDiscovery{}, err
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return OIDCDiscovery{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return OIDCDiscovery{}, fmt.Errorf("oidc discovery HTTP %d", resp.StatusCode)
	}
	var disc OIDCDiscovery
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&disc); err != nil {
		return OIDCDiscovery{}, err
	}
	if disc.AuthorizationEndpoint == "" || disc.TokenEndpoint == "" {
		return OIDCDiscovery{}, fmt.Errorf("oidc discovery missing required endpoints")
	}
	c.mu.Lock()
	c.discovery = &disc
	c.mu.Unlock()
	return disc, nil
}

// AuthCodeURL constructs an OIDC Authorization Code + PKCE URL.
func (c *OIDCClient) AuthCodeURL(ctx context.Context, redirectURI, state, nonce, codeChallenge string) (string, error) {
	disc, err := c.Discover(ctx)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(disc.AuthorizationEndpoint)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", c.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", strings.Join(c.Scopes, " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// ExchangeCode exchanges an authorization code + PKCE verifier for tokens.
func (c *OIDCClient) ExchangeCode(ctx context.Context, code, redirectURI, codeVerifier string) (TokenResponse, error) {
	disc, err := c.Discover(ctx)
	if err != nil {
		return TokenResponse{}, err
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", c.ClientID)
	form.Set("code_verifier", codeVerifier)
	if c.ClientSecret != "" {
		form.Set("client_secret", c.ClientSecret)
	}
	return c.postTokenForm(ctx, disc.TokenEndpoint, form)
}

// StartDeviceAuth initiates RFC 8628 Device Authorization Flow for headless CLIs.
func (c *OIDCClient) StartDeviceAuth(ctx context.Context) (DeviceAuthResponse, error) {
	disc, err := c.Discover(ctx)
	if err != nil {
		return DeviceAuthResponse{}, err
	}
	if disc.DeviceAuthorizationEndpoint == "" {
		return DeviceAuthResponse{}, fmt.Errorf("oidc provider does not advertise device_authorization_endpoint")
	}
	form := url.Values{}
	form.Set("client_id", c.ClientID)
	form.Set("scope", strings.Join(c.Scopes, " "))
	if c.ClientSecret != "" {
		form.Set("client_secret", c.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, disc.DeviceAuthorizationEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return DeviceAuthResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return DeviceAuthResponse{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return DeviceAuthResponse{}, fmt.Errorf("device authorization HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out DeviceAuthResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return DeviceAuthResponse{}, err
	}
	if out.Interval <= 0 {
		out.Interval = 5
	}
	return out, nil
}

// PollDeviceToken polls the token endpoint once for a pending RFC 8628 device code.
func (c *OIDCClient) PollDeviceToken(ctx context.Context, deviceCode string) (TokenResponse, error) {
	disc, err := c.Discover(ctx)
	if err != nil {
		return TokenResponse{}, err
	}
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	form.Set("device_code", deviceCode)
	form.Set("client_id", c.ClientID)
	if c.ClientSecret != "" {
		form.Set("client_secret", c.ClientSecret)
	}
	return c.postTokenForm(ctx, disc.TokenEndpoint, form)
}

func (c *OIDCClient) postTokenForm(ctx context.Context, endpoint string, form url.Values) (TokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return TokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return TokenResponse{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	var out TokenResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return TokenResponse{}, fmt.Errorf("parse token response HTTP %d: %w", resp.StatusCode, err)
	}
	if resp.StatusCode >= 400 && out.Error == "" {
		out.Error = fmt.Sprintf("http_%d", resp.StatusCode)
		out.ErrorDesc = strings.TrimSpace(string(raw))
	}
	return out, nil
}

// VerifyJWT verifies an RS256/ES256 OIDC JWT signature against JWKS, checking issuer, audience, and expiry.
func (c *OIDCClient) VerifyJWT(ctx context.Context, token, expectedNonce string) (IDTokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return IDTokenClaims{}, fmt.Errorf("invalid JWT segment count")
	}
	hdrBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return IDTokenClaims{}, fmt.Errorf("decode JWT header: %w", err)
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		return IDTokenClaims{}, err
	}
	claimBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return IDTokenClaims{}, fmt.Errorf("decode JWT claims: %w", err)
	}
	var claims IDTokenClaims
	if err := json.Unmarshal(claimBytes, &claims); err != nil {
		return IDTokenClaims{}, err
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return IDTokenClaims{}, fmt.Errorf("decode JWT signature: %w", err)
	}

	pubKey, err := c.lookupJWK(ctx, hdr.Kid)
	if err != nil {
		return IDTokenClaims{}, err
	}
	signingInput := parts[0] + "." + parts[1]
	if err := verifyJWTSig(hdr.Alg, pubKey, []byte(signingInput), sigBytes); err != nil {
		return IDTokenClaims{}, err
	}

	now := time.Now().Unix()
	if claims.Exp <= now-30 {
		return IDTokenClaims{}, fmt.Errorf("JWT expired")
	}
	if strings.TrimRight(claims.Issuer, "/") != c.IssuerURL {
		return IDTokenClaims{}, fmt.Errorf("JWT issuer mismatch %q", claims.Issuer)
	}
	if c.ClientID != "" && !audContains(claims.AudRaw, c.ClientID) {
		return IDTokenClaims{}, fmt.Errorf("JWT audience mismatch")
	}
	if expectedNonce != "" && !ConstantTimeEqual(claims.Nonce, expectedNonce) {
		return IDTokenClaims{}, fmt.Errorf("JWT nonce mismatch")
	}
	return claims, nil
}

func (c *OIDCClient) lookupJWK(ctx context.Context, kid string) (any, error) {
	c.mu.RLock()
	if time.Now().Before(c.keysExp) {
		if k, ok := c.keys[kid]; ok {
			c.mu.RUnlock()
			return k, nil
		}
	}
	c.mu.RUnlock()

	disc, err := c.Discover(ctx)
	if err != nil {
		return nil, err
	}
	if disc.JWKSURI == "" {
		return nil, fmt.Errorf("oidc discovery missing jwks_uri")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, disc.JWKSURI, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	var set jwksSet
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&set); err != nil {
		return nil, err
	}
	parsed := make(map[string]any, len(set.Keys))
	for _, k := range set.Keys {
		if pk, err := parseJWK(k); err == nil {
			parsed[k.Kid] = pk
			if _, hasEmpty := parsed[""]; !hasEmpty {
				parsed[""] = pk
			}
		}
	}
	c.mu.Lock()
	c.keys = parsed
	c.keysExp = time.Now().Add(15 * time.Minute)
	c.mu.Unlock()

	pk, ok := parsed[kid]
	if !ok {
		return nil, fmt.Errorf("signing key %q not found in JWKS", kid)
	}
	return pk, nil
}

func parseJWK(k jwkKey) (any, error) {
	switch k.Kty {
	case "RSA":
		nb, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, err
		}
		eb, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, err
		}
		eInt := 0
		for _, b := range eb {
			eInt = eInt<<8 | int(b)
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: eInt}, nil
	case "EC":
		xb, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, err
		}
		yb, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, err
		}
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported EC curve %q", k.Crv)
		}
		coordLen := (curve.Params().BitSize + 7) / 8
		if len(xb) > coordLen || len(yb) > coordLen {
			return nil, fmt.Errorf("invalid EC JWK coordinate length")
		}
		uncompressed := make([]byte, 1+2*coordLen)
		uncompressed[0] = 0x04
		copy(uncompressed[1+coordLen-len(xb):1+coordLen], xb)
		copy(uncompressed[1+2*coordLen-len(yb):], yb)
		return ecdsa.ParseUncompressedPublicKey(curve, uncompressed)
	default:
		return nil, fmt.Errorf("unsupported JWK kty %q", k.Kty)
	}
}

func verifyJWTSig(alg string, pub any, input, sig []byte) error {
	switch alg {
	case "RS256":
		rsaKey, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("expected RSA public key for RS256")
		}
		sum := sha256.Sum256(input)
		return rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, sum[:], sig)
	case "ES256":
		ecKey, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("expected ECDSA public key for ES256")
		}
		if len(sig) != 64 {
			return fmt.Errorf("invalid ES256 signature length")
		}
		sum := sha256.Sum256(input)
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(ecKey, sum[:], r, s) {
			return fmt.Errorf("ES256 signature verification failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported JWT alg %q", alg)
	}
}

func audContains(raw any, expected string) bool {
	switch v := raw.(type) {
	case string:
		return v == expected
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == expected {
				return true
			}
		}
	}
	return false
}
