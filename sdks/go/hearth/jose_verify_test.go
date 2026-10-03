package hearth

// sdk-standard-libraries task 2.2 — VerifyToken delegates the JWS checks
// (signature, algorithm allow-list, critical headers) to go-jose. These tests
// pin the outcomes the library must give for tokens a handwritten verifier
// tends to get wrong.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// signWithHeader signs claims under an arbitrary protected header with the
// issuer's key, so a test can put `crit`, `b64` or a foreign `kid` in it.
func (ti *testIssuer) signWithHeader(t *testing.T, header map[string]any, claims map[string]any) string {
	t.Helper()
	if _, ok := claims["iss"]; !ok {
		claims["iss"] = ti.server.URL
	}
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = time.Now().Add(time.Hour).Unix()
	}
	hb, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	enc := base64.RawURLEncoding
	input := enc.EncodeToString(hb) + "." + enc.EncodeToString(cb)
	return input + "." + enc.EncodeToString(ed25519.Sign(ti.priv, []byte(input)))
}

func requireTokenInvalid(t *testing.T, claims *Claims, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected *TokenInvalidError, got claims %+v", claims)
	}
	var invalid *TokenInvalidError
	if !errors.As(err, &invalid) {
		t.Fatalf("expected *TokenInvalidError, got %T: %v", err, err)
	}
	if claims != nil {
		t.Fatalf("expected nil claims on failure, got %+v", claims)
	}
}

func TestJoseVerify_Ed25519TokenValidates(t *testing.T) {
	ti := newTestIssuer(t)
	token := ti.sign(t, map[string]any{"sub": "user-1", "scope": "read write"})

	claims, err := ti.client().VerifyToken(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if claims.Subject() != "user-1" {
		t.Fatalf("subject = %q, want user-1", claims.Subject())
	}
}

func TestJoseVerify_TamperedPayloadFails(t *testing.T) {
	ti := newTestIssuer(t)
	token := ti.sign(t, map[string]any{"sub": "user-1"})
	parts := strings.Split(token, ".")
	forged, err := json.Marshal(map[string]any{
		"sub": "admin", "iss": ti.URL(), "exp": time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	parts[1] = base64.RawURLEncoding.EncodeToString(forged)

	claims, err := ti.client().VerifyToken(context.Background(), strings.Join(parts, "."))
	requireTokenInvalid(t, claims, err)
}

func TestJoseVerify_AlgNoneFails(t *testing.T) {
	ti := newTestIssuer(t)
	enc := base64.RawURLEncoding
	hb, _ := json.Marshal(map[string]string{"alg": "none", "typ": "JWT", "kid": ti.kid})
	cb, _ := json.Marshal(map[string]any{
		"sub": "admin", "iss": ti.URL(), "exp": time.Now().Add(time.Hour).Unix(),
	})
	for _, token := range []string{
		enc.EncodeToString(hb) + "." + enc.EncodeToString(cb) + ".",
		enc.EncodeToString(hb) + "." + enc.EncodeToString(cb),
	} {
		claims, err := ti.client().VerifyToken(context.Background(), token)
		requireTokenInvalid(t, claims, err)
	}
}

func TestJoseVerify_WrongKidFails(t *testing.T) {
	ti := newTestIssuer(t)
	token := ti.signWithHeader(t,
		map[string]any{"alg": "EdDSA", "typ": "JWT", "kid": "not-published"},
		map[string]any{"sub": "user-1"})

	claims, err := ti.client().VerifyToken(context.Background(), token)
	if err == nil {
		t.Fatalf("expected an error for an unknown kid, got claims %+v", claims)
	}
	var fetchErr *JWKSFetchError
	if !errors.As(err, &fetchErr) {
		t.Fatalf("expected *JWKSFetchError for an unknown kid, got %T: %v", err, err)
	}
	if claims != nil {
		t.Fatalf("expected nil claims, got %+v", claims)
	}
}

// RFC 7515 §4.1.11: a recipient MUST reject a JWS whose `crit` names an
// extension it does not understand. The handwritten verifier ignored `crit`.
func TestJoseVerify_UnknownCriticalHeaderFails(t *testing.T) {
	ti := newTestIssuer(t)
	token := ti.signWithHeader(t,
		map[string]any{"alg": "EdDSA", "typ": "JWT", "kid": ti.kid,
			"crit": []string{"urn:example:must-understand"}, "urn:example:must-understand": true},
		map[string]any{"sub": "user-1"})

	claims, err := ti.client().VerifyToken(context.Background(), token)
	requireTokenInvalid(t, claims, err)
}

// RFC 7797 `b64:false` changes the signing input. Hearth never issues it, so a
// token that asks for it is refused rather than verified under the wrong input.
func TestJoseVerify_UnencodedPayloadOptionFails(t *testing.T) {
	ti := newTestIssuer(t)
	token := ti.signWithHeader(t,
		map[string]any{"alg": "EdDSA", "typ": "JWT", "kid": ti.kid,
			"b64": false, "crit": []string{"b64"}},
		map[string]any{"sub": "user-1"})

	claims, err := ti.client().VerifyToken(context.Background(), token)
	requireTokenInvalid(t, claims, err)
}
