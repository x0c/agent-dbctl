package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPasswordAndTokenHelpers(t *testing.T) {
	hash, err := HashPassword("correct-horse-battery")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !VerifyPassword(hash, "correct-horse-battery") {
		t.Fatalf("expected VerifyPassword to succeed")
	}
	if VerifyPassword(hash, "wrong-password") {
		t.Fatalf("expected VerifyPassword to fail on wrong password")
	}

	plain, prefix, tokHash, err := GenerateAPIToken()
	if err != nil {
		t.Fatalf("GenerateAPIToken: %v", err)
	}
	if !strings.HasPrefix(plain, "adb_live_"+prefix+"_") {
		t.Fatalf("unexpected token format %q", plain)
	}
	if HashToken(plain) != tokHash {
		t.Fatalf("token hash mismatch")
	}

	verifier, challenge, err := GeneratePKCE()
	if err != nil || verifier == "" || challenge == "" || verifier == challenge {
		t.Fatalf("unexpected PKCE pair: %q %q err=%v", verifier, challenge, err)
	}
}

func TestOIDCDiscoveryDeviceFlowAndJWT(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	var srvURL string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(OIDCDiscovery{
			Issuer:                      srvURL,
			AuthorizationEndpoint:       srvURL + "/auth",
			TokenEndpoint:               srvURL + "/token",
			DeviceAuthorizationEndpoint: srvURL + "/device",
			JWKSURI:                     srvURL + "/jwks.json",
		})
	})
	mux.HandleFunc("GET /jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwksSet{
			Keys: []jwkKey{{
				Kty: "RSA",
				Kid: "k1",
				Alg: "RS256",
				Use: "sig",
				N:   base64.RawURLEncoding.EncodeToString(priv.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes()),
			}},
		})
	})
	mux.HandleFunc("POST /device", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(DeviceAuthResponse{
			DeviceCode:      "dev_123",
			UserCode:        "ABCD-EFGH",
			VerificationURI: srvURL + "/activate",
			ExpiresIn:       300,
			Interval:        1,
		})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, _ *http.Request) {
		hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"k1","typ":"JWT"}`))
		claimsRaw, _ := json.Marshal(IDTokenClaims{
			Issuer:  srvURL,
			Subject: "sub_alice",
			Email:   "alice@corp.com",
			Name:    "Alice",
			Nonce:   "n1",
			AudRaw:  "agent-dbctl",
			Exp:     time.Now().Add(time.Hour).Unix(),
		})
		pl := base64.RawURLEncoding.EncodeToString(claimsRaw)
		sum := sha256.Sum256([]byte(hdr + "." + pl))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, priv, 0x05 /* crypto.SHA256 */, sum[:])
		_ = json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: hdr + "." + pl + "." + base64.RawURLEncoding.EncodeToString(sig),
			IDToken:     hdr + "." + pl + "." + base64.RawURLEncoding.EncodeToString(sig),
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	})
	_ = x509.MarshalPKCS1PublicKey(&priv.PublicKey)

	srv := httptest.NewServer(mux)
	defer srv.Close()
	srvURL = srv.URL

	client := NewOIDCClient(srvURL, "agent-dbctl", "", nil)
	dev, err := client.StartDeviceAuth(t.Context())
	if err != nil || dev.UserCode != "ABCD-EFGH" {
		t.Fatalf("StartDeviceAuth: dev=%+v err=%v", dev, err)
	}
	tok, err := client.PollDeviceToken(t.Context(), dev.DeviceCode)
	if err != nil || tok.IDToken == "" {
		t.Fatalf("PollDeviceToken: tok=%+v err=%v", tok, err)
	}
	claims, err := client.VerifyJWT(t.Context(), tok.IDToken, "n1")
	if err != nil || claims.Email != "alice@corp.com" {
		t.Fatalf("VerifyJWT: claims=%+v err=%v", claims, err)
	}
}
