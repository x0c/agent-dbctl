package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const apiTokenPrefix = "adb_live_"

// HashPassword hashes a plaintext password with Argon2id and a 16-byte random salt.
func HashPassword(password string) (string, error) {
	if len(password) < 8 {
		return "", fmt.Errorf("password must be at least 8 characters")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	const (
		timeCost    = 2
		memoryKiB   = 64 * 1024
		parallelism = 2
		keyLen      = 32
	)
	hash := argon2.IDKey([]byte(password), salt, timeCost, memoryKiB, parallelism, keyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memoryKiB, timeCost, parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// VerifyPassword compares a plaintext password against an Argon2id PHC string in constant time.
func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	var mem uint32
	var t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &t, &p); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(expected) == 0 {
		return false
	}
	actual := argon2.IDKey([]byte(password), salt, t, mem, p, uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

// GenerateAPIToken creates a scoped agent bearer token ("adb_live_<prefix>_<secret>"),
// returning the full secret once alongside its display prefix and SHA-256 hash.
func GenerateAPIToken() (plaintext, prefix, tokenHash string, err error) {
	var pBytes [4]byte
	var sBytes [24]byte
	if _, err = rand.Read(pBytes[:]); err != nil {
		return "", "", "", err
	}
	if _, err = rand.Read(sBytes[:]); err != nil {
		return "", "", "", err
	}
	prefix = hex.EncodeToString(pBytes[:])
	secret := base64.RawURLEncoding.EncodeToString(sBytes[:])
	plaintext = apiTokenPrefix + prefix + "_" + secret
	tokenHash = HashToken(plaintext)
	return plaintext, prefix, tokenHash, nil
}

// HashToken computes a deterministic SHA-256 hex digest for session/API/OIDC tokens.
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// RandomHex generates nBytes of cryptographic entropy encoded as lowercase hex.
func RandomHex(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

const deviceCodeAlphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ" // 32 unambiguous chars

// GenerateDeviceUserCode generates an 8-character XXXX-YYYY confirmation code using unbiased entropy.
func GenerateDeviceUserCode() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := make([]byte, 9)
	for i := 0; i < 4; i++ {
		out[i] = deviceCodeAlphabet[b[i]&31]
	}
	out[4] = '-'
	for i := 0; i < 4; i++ {
		out[5+i] = deviceCodeAlphabet[b[4+i]&31]
	}
	return string(out), nil
}

// ConstantTimeEqual compares two strings without leaking length/prefix timing.
func ConstantTimeEqual(a, b string) bool {
	if len(a) == 0 || len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// GeneratePKCE creates a PKCE S256 verifier and challenge pair.
func GeneratePKCE() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}
