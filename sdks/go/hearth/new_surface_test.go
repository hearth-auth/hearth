package hearth

// Unit tests for new SDK surface (TDD — written before implementation).
//
// Tests cover:
//   - JwksCache: TTL, cache-miss re-fetch, skip non-OKP keys, Cache-Control header
//   - VerifyToken: signature, expiry, issuer, audience, algorithm guard
//   - ClientCredentials: form encoding, required credentials, optional scope
//   - StartDeviceFlow / PollDeviceToken: response shapes, pending/slow_down handling
//   - RequestMagicLink: correct path, email in body, 202 is success, 429 raises error
//   - WebAuthn: registration and authentication round-trip shapes

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ─── helpers ──────────────────────────────────────────────────────────────────

// makeEd25519Key returns a fresh key pair plus the base64url-encoded public key x coordinate.
func makeEd25519Key(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	x := base64.RawURLEncoding.EncodeToString(pub)
	return priv, pub, x
}

// makeJWKS returns a JSON JWKS document for an Ed25519 key.
func makeJWKS(x, kid string) []byte {
	doc := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   x,
				"kid": kid,
				"use": "sig",
				"alg": "EdDSA",
			},
		},
	}
	b, _ := json.Marshal(doc)
	return b
}

// signJWT builds and signs a JWT with the given private key and header/payload.
func signJWT(t *testing.T, priv ed25519.PrivateKey, header, payload map[string]any) string {
	t.Helper()
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(payload)
	h64 := base64.RawURLEncoding.EncodeToString(hb)
	p64 := base64.RawURLEncoding.EncodeToString(pb)
	msg := h64 + "." + p64
	sig := ed25519.Sign(priv, []byte(msg))
	return msg + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// validPayload returns a set of claims that will pass VerifyToken with the given issuer.
func validPayload(issuer string) map[string]any {
	now := time.Now().Unix()
	return map[string]any{
		"sub": "user-abc",
		"iss": issuer,
		"aud": "client-1",
		"exp": now + 3600,
		"iat": now,
	}
}

// ─── JwksCache ────────────────────────────────────────────────────────────────

func TestJwksCache_CachesEd25519KeyByKid(t *testing.T) {
	priv, _, x := makeEd25519Key(t)
	kid := "key-1"
	_ = priv

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(makeJWKS(x, kid))
	}))
	defer srv.Close()

	cache := NewJwksCache(srv.URL+"/.well-known/jwks.json", nil, 0)
	key, err := cache.GetKey(kid)
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if len(key) == 0 {
		t.Fatal("returned empty key")
	}
}

func TestJwksCache_RaisesJWKSFetchErrorOnHTTPFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}))
	defer srv.Close()

	cache := NewJwksCache(srv.URL+"/.well-known/jwks.json", nil, 0)
	_, err := cache.GetKey("any")
	if err == nil {
		t.Fatal("expected error")
	}
	if _, ok := err.(*JWKSFetchError); !ok {
		t.Fatalf("expected *JWKSFetchError, got %T: %v", err, err)
	}
}

func TestJwksCache_ReFetchesOnKidCacheMiss(t *testing.T) {
	priv, _, x := makeEd25519Key(t)
	kid := "key-1"
	_ = priv

	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		callCount++
		if callCount == 1 {
			// First fetch returns no keys
			json.NewEncoder(w).Encode(map[string]any{"keys": []any{}})
		} else {
			w.Write(makeJWKS(x, kid))
		}
	}))
	defer srv.Close()

	cache := NewJwksCache(srv.URL+"/.well-known/jwks.json", nil, 0)
	key, err := cache.GetKey(kid)
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if len(key) == 0 {
		t.Fatal("empty key")
	}
	if callCount < 2 {
		t.Fatalf("expected at least 2 fetches (initial miss + retry), got %d", callCount)
	}
}

func TestJwksCache_RaisesOnKidNotFoundAfterRefetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{}})
	}))
	defer srv.Close()

	cache := NewJwksCache(srv.URL+"/.well-known/jwks.json", nil, 0)
	_, err := cache.GetKey("missing-kid")
	if err == nil {
		t.Fatal("expected error for missing kid")
	}
}

func TestJwksCache_SkipsNonOKPKeysWithoutError(t *testing.T) {
	_, _, x := makeEd25519Key(t)
	kid := "okp-1"

	jwks := map[string]any{
		"keys": []map[string]any{
			// RSA key — must be skipped, not an error
			{"kty": "RSA", "n": "abc", "e": "AQAB", "kid": "rsa-1"},
			// Valid OKP key
			{"kty": "OKP", "crv": "Ed25519", "x": x, "kid": kid, "use": "sig", "alg": "EdDSA"},
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	cache := NewJwksCache(srv.URL+"/.well-known/jwks.json", nil, 0)
	key, err := cache.GetKey(kid)
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if len(key) == 0 {
		t.Fatal("empty key")
	}
}

func TestJwksCache_RespectsMaxAgeCacheControl(t *testing.T) {
	_, _, x := makeEd25519Key(t)
	kid := "key-1"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=120")
		w.Header().Set("Content-Type", "application/json")
		w.Write(makeJWKS(x, kid))
	}))
	defer srv.Close()

	cache := NewJwksCache(srv.URL+"/.well-known/jwks.json", nil, 0)
	_, err := cache.GetKey(kid)
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if cache.ttl != 120*time.Second {
		t.Fatalf("expected ttl=120s, got %s", cache.ttl)
	}
}

func TestJwksCache_MaxAgeCappedAt24Hours(t *testing.T) {
	_, _, x := makeEd25519Key(t)
	kid := "key-1"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=999999")
		w.Header().Set("Content-Type", "application/json")
		w.Write(makeJWKS(x, kid))
	}))
	defer srv.Close()

	cache := NewJwksCache(srv.URL+"/.well-known/jwks.json", nil, 0)
	_, err := cache.GetKey(kid)
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if cache.ttl > 24*time.Hour {
		t.Fatalf("ttl exceeds 24h cap: %s", cache.ttl)
	}
}

// ─── VerifyToken ──────────────────────────────────────────────────────────────

// verifyTestClient returns a Client whose JWKS and discovery are backed by httptest servers.
func verifyTestClient(
	t *testing.T,
	x, kid, issuer string,
) (*Client, *httptest.Server) {
	t.Helper()

	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(makeJWKS(x, kid))
	}))

	discJSON, _ := json.Marshal(map[string]any{
		"issuer":   issuer,
		"jwks_uri": jwksSrv.URL + "/.well-known/jwks.json",
	})

	mainSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			w.Write(discJSON)
			return
		}
		http.NotFound(w, r)
	}))

	t.Cleanup(func() {
		jwksSrv.Close()
		mainSrv.Close()
	})

	c := NewClient(mainSrv.URL, "realm-1")
	// Override jwksURL to point to our test server
	c.jwksURLOverride = jwksSrv.URL + "/.well-known/jwks.json"
	return c, mainSrv
}

func TestVerifyToken_ReturnsClaimsForValidToken(t *testing.T) {
	priv, _, x := makeEd25519Key(t)
	kid := "test-key"
	issuer := "http://localhost:8420"

	client, _ := verifyTestClient(t, x, kid, issuer)
	token := signJWT(t, priv,
		map[string]any{"alg": "EdDSA", "kid": kid},
		validPayload(issuer),
	)

	claims, err := client.VerifyToken(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if claims.Subject() != "user-abc" {
		t.Fatalf("subject: %q", claims.Subject())
	}
	if claims.Issuer() != issuer {
		t.Fatalf("issuer: %q", claims.Issuer())
	}
}

func TestVerifyToken_RaisesTokenInvalidOnBadSignature(t *testing.T) {
	priv, _, _ := makeEd25519Key(t)
	_, _, xWrong := makeEd25519Key(t) // different key
	kid := "test-key"
	issuer := "http://localhost:8420"

	client, _ := verifyTestClient(t, xWrong, kid, issuer)
	token := signJWT(t, priv,
		map[string]any{"alg": "EdDSA", "kid": kid},
		validPayload(issuer),
	)

	_, err := client.VerifyToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for bad signature")
	}
	if _, ok := err.(*TokenInvalidError); !ok {
		t.Fatalf("expected *TokenInvalidError, got %T: %v", err, err)
	}
}

func TestVerifyToken_RaisesTokenExpiredError(t *testing.T) {
	priv, _, x := makeEd25519Key(t)
	kid := "test-key"
	issuer := "http://localhost:8420"

	client, _ := verifyTestClient(t, x, kid, issuer)
	payload := validPayload(issuer)
	payload["exp"] = time.Now().Unix() - 10 // already expired

	token := signJWT(t, priv,
		map[string]any{"alg": "EdDSA", "kid": kid},
		payload,
	)

	_, err := client.VerifyToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
	if _, ok := err.(*TokenExpiredError); !ok {
		t.Fatalf("expected *TokenExpiredError, got %T: %v", err, err)
	}
}

func TestVerifyToken_RaisesTokenIssuerError(t *testing.T) {
	priv, _, x := makeEd25519Key(t)
	kid := "test-key"
	correctIssuer := "http://localhost:8420"

	client, _ := verifyTestClient(t, x, kid, correctIssuer)
	payload := validPayload("https://wrong.example.com") // mismatched issuer
	token := signJWT(t, priv,
		map[string]any{"alg": "EdDSA", "kid": kid},
		payload,
	)

	_, err := client.VerifyToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for wrong issuer")
	}
	if _, ok := err.(*TokenIssuerError); !ok {
		t.Fatalf("expected *TokenIssuerError, got %T: %v", err, err)
	}
}

func TestVerifyToken_RaisesTokenAudienceError(t *testing.T) {
	priv, _, x := makeEd25519Key(t)
	kid := "test-key"
	issuer := "http://localhost:8420"

	client, _ := verifyTestClient(t, x, kid, issuer)
	token := signJWT(t, priv,
		map[string]any{"alg": "EdDSA", "kid": kid},
		validPayload(issuer), // aud is "client-1"
	)

	_, err := client.VerifyToken(context.Background(), token, "wrong-audience")
	if err == nil {
		t.Fatal("expected error for wrong audience")
	}
	if _, ok := err.(*TokenAudienceError); !ok {
		t.Fatalf("expected *TokenAudienceError, got %T: %v", err, err)
	}
}

func TestVerifyToken_AudienceCheckSkippedWhenNotSpecified(t *testing.T) {
	priv, _, x := makeEd25519Key(t)
	kid := "test-key"
	issuer := "http://localhost:8420"

	client, _ := verifyTestClient(t, x, kid, issuer)
	token := signJWT(t, priv,
		map[string]any{"alg": "EdDSA", "kid": kid},
		validPayload(issuer),
	)

	claims, err := client.VerifyToken(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyToken without audience: %v", err)
	}
	if claims.Subject() != "user-abc" {
		t.Fatalf("subject: %q", claims.Subject())
	}
}

func TestVerifyToken_RaisesTokenInvalidForWrongAlgorithm(t *testing.T) {
	priv, _, x := makeEd25519Key(t)
	kid := "test-key"
	issuer := "http://localhost:8420"

	client, _ := verifyTestClient(t, x, kid, issuer)
	// Use HS256 header
	token := signJWT(t, priv,
		map[string]any{"alg": "HS256", "kid": kid},
		validPayload(issuer),
	)

	_, err := client.VerifyToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for wrong algorithm")
	}
	if _, ok := err.(*TokenInvalidError); !ok {
		t.Fatalf("expected *TokenInvalidError, got %T: %v", err, err)
	}
}

func TestVerifyToken_RaisesTokenInvalidForMalformedJWT(t *testing.T) {
	priv, _, x := makeEd25519Key(t)
	kid := "test-key"
	issuer := "http://localhost:8420"
	_ = priv

	client, _ := verifyTestClient(t, x, kid, issuer)

	_, err := client.VerifyToken(context.Background(), "not.a.valid.jwt.at.all.extra")
	// The extra segment makes it not a valid 3-part JWT; any error is fine here.
	// If somehow we get a 3-part one, it should still fail signature verification.
	_ = err

	_, err = client.VerifyToken(context.Background(), "bad")
	if err == nil {
		t.Fatal("expected error for malformed JWT")
	}
	if _, ok := err.(*TokenInvalidError); !ok {
		t.Fatalf("expected *TokenInvalidError, got %T: %v", err, err)
	}
}

func TestVerifyToken_DoesNotFallBackToIntrospection(t *testing.T) {
	priv, _, x := makeEd25519Key(t)
	kid := "test-key"
	issuer := "http://localhost:8420"

	// Introspect is not mocked — if VerifyToken called it the test would hang or error.
	client, _ := verifyTestClient(t, x, kid, issuer)
	token := signJWT(t, priv,
		map[string]any{"alg": "EdDSA", "kid": kid},
		validPayload(issuer),
	)

	claims, err := client.VerifyToken(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if claims.Subject() == "" {
		t.Fatal("subject empty")
	}
}

// ─── ClientCredentials ────────────────────────────────────────────────────────

func TestClientCredentials_ReturnsTokenResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "eyJ...",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        "read:users",
		})
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "realm-1",
		WithClientCredentials("svc-client", "super-secret"),
	)
	resp, err := client.ClientCredentials(context.Background())
	if err != nil {
		t.Fatalf("ClientCredentials: %v", err)
	}
	if resp.AccessToken != "eyJ..." {
		t.Fatalf("access_token: %q", resp.AccessToken)
	}
	if resp.TokenType != "Bearer" {
		t.Fatalf("token_type: %q", resp.TokenType)
	}
	if resp.ExpiresIn != 3600 {
		t.Fatalf("expires_in: %d", resp.ExpiresIn)
	}
}

func TestClientCredentials_SendsCredentialsInFormBody(t *testing.T) {
	var capturedBody, capturedCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		capturedBody = r.Form.Encode()
		capturedCT = r.Header.Get("Content-Type")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "t", "token_type": "Bearer", "expires_in": 3600,
		})
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "realm-1",
		WithClientCredentials("my-client", "my-secret"),
	)
	_, err := client.ClientCredentials(context.Background())
	if err != nil {
		t.Fatalf("ClientCredentials: %v", err)
	}
	if !strings.Contains(capturedCT, "application/x-www-form-urlencoded") {
		t.Fatalf("expected form content-type, got %q", capturedCT)
	}
	if !strings.Contains(capturedBody, "client_id=my-client") {
		t.Fatalf("missing client_id in body: %q", capturedBody)
	}
	if !strings.Contains(capturedBody, "client_secret=my-secret") {
		t.Fatalf("missing client_secret in body: %q", capturedBody)
	}
	if !strings.Contains(capturedBody, "grant_type=client_credentials") {
		t.Fatalf("missing grant_type in body: %q", capturedBody)
	}
}

func TestClientCredentials_SendsOptionalScope(t *testing.T) {
	var capturedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		capturedBody = r.Form.Encode()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "t", "token_type": "Bearer", "expires_in": 3600,
		})
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "realm-1",
		WithClientCredentials("c", "s"),
	)
	_, err := client.ClientCredentials(context.Background(), "read:users")
	if err != nil {
		t.Fatalf("ClientCredentials: %v", err)
	}
	if !strings.Contains(capturedBody, "scope=") {
		t.Fatalf("missing scope in body: %q", capturedBody)
	}
}

func TestClientCredentials_RaisesConfigurationErrorWhenNoClientID(t *testing.T) {
	client := NewClient("http://localhost:8420", "realm-1")
	_, err := client.ClientCredentials(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if _, ok := err.(*ConfigurationError); !ok {
		t.Fatalf("expected *ConfigurationError, got %T: %v", err, err)
	}
}

func TestClientCredentials_RaisesConfigurationErrorWhenNoClientSecret(t *testing.T) {
	client := NewClient("http://localhost:8420", "realm-1",
		WithClientCredentials("id", ""),
	)
	_, err := client.ClientCredentials(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if _, ok := err.(*ConfigurationError); !ok {
		t.Fatalf("expected *ConfigurationError, got %T: %v", err, err)
	}
}

// ─── Device Flow ──────────────────────────────────────────────────────────────

func TestStartDeviceFlow_ReturnsResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"device_code":     "DEV123",
			"user_code":       "ABCD-1234",
			"verification_uri": "https://auth.example.com/activate",
			"expires_in":      300,
			"interval":        5,
		})
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "realm-1",
		WithClientCredentials("cli-app", ""),
	)
	resp, err := client.StartDeviceFlow(context.Background())
	if err != nil {
		t.Fatalf("StartDeviceFlow: %v", err)
	}
	if resp.DeviceCode != "DEV123" {
		t.Fatalf("device_code: %q", resp.DeviceCode)
	}
	if resp.UserCode != "ABCD-1234" {
		t.Fatalf("user_code: %q", resp.UserCode)
	}
	if resp.Interval != 5 {
		t.Fatalf("interval: %d", resp.Interval)
	}
}

func TestStartDeviceFlow_SendsClientID(t *testing.T) {
	var capturedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		capturedBody = r.Form.Encode()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"device_code": "d", "user_code": "u",
			"verification_uri": "v", "expires_in": 300, "interval": 5,
		})
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "realm-1",
		WithClientCredentials("cli-app", ""),
	)
	_, err := client.StartDeviceFlow(context.Background())
	if err != nil {
		t.Fatalf("StartDeviceFlow: %v", err)
	}
	if !strings.Contains(capturedBody, "client_id=cli-app") {
		t.Fatalf("missing client_id in body: %q", capturedBody)
	}
}

func TestStartDeviceFlow_RaisesConfigurationErrorWhenNoClientID(t *testing.T) {
	client := NewClient("http://localhost:8420", "realm-1")
	_, err := client.StartDeviceFlow(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if _, ok := err.(*ConfigurationError); !ok {
		t.Fatalf("expected *ConfigurationError, got %T: %v", err, err)
	}
}

func TestPollDeviceToken_ReturnTokensOnSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "eyJ...",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "realm-1",
		WithClientCredentials("cli-app", ""),
	)
	resp, err := client.PollDeviceToken(context.Background(), "DEV123")
	if err != nil {
		t.Fatalf("PollDeviceToken: %v", err)
	}
	if resp == nil {
		t.Fatal("expected token response")
	}
	if resp.AccessToken != "eyJ..." {
		t.Fatalf("access_token: %q", resp.AccessToken)
	}
}

func TestPollDeviceToken_ReturnsNilOnAuthorizationPending(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]any{"error": "authorization_pending"})
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "realm-1",
		WithClientCredentials("cli-app", ""),
	)
	resp, err := client.PollDeviceToken(context.Background(), "DEV123")
	if err != nil {
		t.Fatalf("PollDeviceToken pending: unexpected error: %v", err)
	}
	if resp != nil {
		t.Fatalf("expected nil response on pending, got: %+v", resp)
	}
}

func TestPollDeviceToken_ReturnsNilOnSlowDown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]any{"error": "slow_down"})
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "realm-1",
		WithClientCredentials("cli-app", ""),
	)
	resp, err := client.PollDeviceToken(context.Background(), "DEV123")
	if err != nil {
		t.Fatalf("PollDeviceToken slow_down: unexpected error: %v", err)
	}
	if resp != nil {
		t.Fatalf("expected nil response on slow_down, got: %+v", resp)
	}
}

func TestPollDeviceToken_RaisesTokenExpiredErrorOnExpiredToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]any{"error": "expired_token"})
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "realm-1",
		WithClientCredentials("cli-app", ""),
	)
	_, err := client.PollDeviceToken(context.Background(), "DEV123")
	if err == nil {
		t.Fatal("expected error for expired device code")
	}
	if _, ok := err.(*TokenExpiredError); !ok {
		t.Fatalf("expected *TokenExpiredError, got %T: %v", err, err)
	}
}

func TestPollDeviceToken_RaisesAPIErrorOnOtherErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]any{"error": "access_denied"})
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "realm-1",
		WithClientCredentials("cli-app", ""),
	)
	_, err := client.PollDeviceToken(context.Background(), "DEV123")
	if err == nil {
		t.Fatal("expected error for access_denied")
	}
}

// ─── Magic Link ───────────────────────────────────────────────────────────────

func TestRequestMagicLink_PostsToCorrectEndpoint(t *testing.T) {
	var capturedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.WriteHeader(202)
		json.NewEncoder(w).Encode(map[string]any{"message": "ok"})
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "realm-1")
	err := client.RequestMagicLink(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("RequestMagicLink: %v", err)
	}
	expected := "/v1/realm-1/auth/magic-link"
	if capturedPath != expected {
		t.Fatalf("path: expected %q, got %q", expected, capturedPath)
	}
}

func TestRequestMagicLink_SendsEmailInJSONBody(t *testing.T) {
	var capturedEmail string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		capturedEmail = body["email"]
		w.WriteHeader(202)
		json.NewEncoder(w).Encode(map[string]any{"message": "ok"})
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "realm-1")
	err := client.RequestMagicLink(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("RequestMagicLink: %v", err)
	}
	if capturedEmail != "user@example.com" {
		t.Fatalf("email: %q", capturedEmail)
	}
}

func TestRequestMagicLink_DoesNotRaiseOn202(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(202)
		json.NewEncoder(w).Encode(map[string]any{"message": "If an account exists, a magic link has been sent"})
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "realm-1")
	if err := client.RequestMagicLink(context.Background(), "nobody@example.com"); err != nil {
		t.Fatalf("expected no error on 202, got: %v", err)
	}
}

func TestRequestMagicLink_RaisesAPIErrorOn429(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(429)
		w.Write([]byte("too many requests"))
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "realm-1")
	err := client.RequestMagicLink(context.Background(), "user@example.com")
	if err == nil {
		t.Fatal("expected error on 429")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != 429 {
		t.Fatalf("expected 429, got %d", apiErr.StatusCode)
	}
}

// ─── ExchangeMagicLink ──────────────────────────────────────────────────────────

func TestExchangeMagicLink_PostsMagicLinkGrantWithTokenInBody(t *testing.T) {
	var capturedBody, capturedCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		capturedBody = r.Form.Encode()
		capturedCT = r.Header.Get("Content-Type")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "eyJ...", "token_type": "Bearer", "expires_in": 3600,
		})
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "realm-1", WithClientCredentials("my-client", "my-secret"))
	resp, err := client.ExchangeMagicLink(context.Background(), "magic-token-xyz")
	if err != nil {
		t.Fatalf("ExchangeMagicLink: %v", err)
	}
	if resp.AccessToken != "eyJ..." {
		t.Fatalf("access_token: %q", resp.AccessToken)
	}
	if !strings.Contains(capturedCT, "application/x-www-form-urlencoded") {
		t.Fatalf("expected form content-type, got %q", capturedCT)
	}
	if !strings.Contains(capturedBody, "grant_type=urn%3Ahearth%3Agrant-type%3Amagic-link") {
		t.Fatalf("missing magic-link grant_type in body: %q", capturedBody)
	}
	if !strings.Contains(capturedBody, "token=magic-token-xyz") {
		t.Fatalf("missing token in body: %q", capturedBody)
	}
}

func TestExchangeMagicLink_RaisesAPIErrorOnInvalidToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "realm-1", WithClientCredentials("my-client", "my-secret"))
	if _, err := client.ExchangeMagicLink(context.Background(), "expired"); err == nil {
		t.Fatal("expected error on invalid token")
	}
}

// ─── WebAuthn ─────────────────────────────────────────────────────────────────

func TestStartWebAuthnRegistration_ReturnsOptions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/webauthn/register/begin" {
			t.Errorf("unexpected path: %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"challenge":          "abc123",
			"rp_id":             "example.com",
			"rp_name":           "Example",
			"user_id":           "user-1",
			"user_name":         "alice",
			"user_display_name": "Alice",
			"attestation":       "none",
			"timeout":           uint64(60000),
		})
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "realm-1")
	opts, err := client.StartWebAuthnRegistration(context.Background(), "bearer-token")
	if err != nil {
		t.Fatalf("StartWebAuthnRegistration: %v", err)
	}
	if opts.Challenge != "abc123" {
		t.Fatalf("challenge: %q", opts.Challenge)
	}
	if opts.RPID != "example.com" {
		t.Fatalf("rp_id: %q", opts.RPID)
	}
}

func TestFinishWebAuthnRegistration_ReturnsCredential(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/webauthn/register/complete" {
			t.Errorf("unexpected path: %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"credential_id": "cred-abc",
			"algorithm":     int64(-7),
			"discoverable":  true,
		})
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "realm-1")
	resp, err := client.FinishWebAuthnRegistration(context.Background(), "bearer-token",
		WebAuthnRegistrationCompleteRequest{
			ClientDataJSON:    "eyJ...",
			AttestationObject: "o2N...",
			Origin:            "https://example.com",
		},
	)
	if err != nil {
		t.Fatalf("FinishWebAuthnRegistration: %v", err)
	}
	if resp.CredentialID != "cred-abc" {
		t.Fatalf("credential_id: %q", resp.CredentialID)
	}
}

func TestStartWebAuthnAuthentication_ReturnsOptions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/webauthn/auth/begin" {
			t.Errorf("unexpected path: %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"challenge":         "xyz789",
			"rp_id":            "example.com",
			"allow_credentials": []map[string]any{},
			"user_verification": "preferred",
			"timeout":           uint64(60000),
		})
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "realm-1")
	opts, err := client.StartWebAuthnAuthentication(context.Background(), "")
	if err != nil {
		t.Fatalf("StartWebAuthnAuthentication: %v", err)
	}
	if opts.Challenge != "xyz789" {
		t.Fatalf("challenge: %q", opts.Challenge)
	}
}

func TestFinishWebAuthnAuthentication_ReturnsTokens(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/webauthn/auth/complete" {
			t.Errorf("unexpected path: %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "eyJ...",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": "ref...",
		})
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "realm-1")
	resp, err := client.FinishWebAuthnAuthentication(context.Background(),
		WebAuthnAuthenticationCompleteRequest{
			CredentialID:      "cred-abc",
			ClientDataJSON:    "eyJ...",
			AuthenticatorData: "SZYN...",
			Signature:         "abc...",
			Origin:            "https://example.com",
		},
	)
	if err != nil {
		t.Fatalf("FinishWebAuthnAuthentication: %v", err)
	}
	if resp.AccessToken != "eyJ..." {
		t.Fatalf("access_token: %q", resp.AccessToken)
	}
}
