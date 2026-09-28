package hearth

// Task 26.55 — a realm whose clients selected RS256 ID tokens publishes an RSA
// "id-token-signing" key beside its Ed25519 key. VerifyToken verifies ACCESS
// tokens, which Hearth signs with EdDSA only, so it must (a) keep verifying
// EdDSA tokens against such a JWKS and (b) refuse an RS256 token even though
// the key that signed it is published — otherwise an ID token could be replayed
// as a bearer token.

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
)

const rs256IDTokenKid = "rsa-id-token-key"

// mixedJWKSClient serves a JWKS with an RS256 ID-token key and an Ed25519
// access-token key, plus the discovery document VerifyToken resolves.
func mixedJWKSClient(t *testing.T, rsaPub *rsa.PublicKey, x, edKid, issuer string) *Client {
	t.Helper()
	jwks, _ := json.Marshal(map[string]any{
		"keys": []map[string]any{
			{
				"kty":        "RSA",
				"alg":        "RS256",
				"use":        "sig",
				"kid":        rs256IDTokenKid,
				"n":          base64.RawURLEncoding.EncodeToString(rsaPub.N.Bytes()),
				"e":          base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaPub.E)).Bytes()),
				"x-key-role": "id-token-signing",
			},
			{
				"kty":        "OKP",
				"crv":        "Ed25519",
				"x":          x,
				"kid":        edKid,
				"use":        "sig",
				"alg":        "EdDSA",
				"x-key-role": "access-token-signing",
			},
		},
	})
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwks)
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
	c.jwksURLOverride = jwksSrv.URL + "/.well-known/jwks.json"
	return c
}

// signRS256 builds an RS256 JWS the way Hearth signs an RS256 ID token.
func signRS256(t *testing.T, key *rsa.PrivateKey, payload map[string]any) string {
	t.Helper()
	hb, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": rs256IDTokenKid})
	pb, _ := json.Marshal(payload)
	msg := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	digest := sha256.Sum256([]byte(msg))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("SignPKCS1v15: %v", err)
	}
	return msg + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestVerifyToken_JWKSWithAnRS256IDTokenKeyStillVerifiesEdDSA(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	priv, _, x := makeEd25519Key(t)
	issuer := "http://localhost:8420"
	client := mixedJWKSClient(t, &rsaKey.PublicKey, x, "ed-1", issuer)

	token := signJWT(t, priv, map[string]any{"alg": "EdDSA", "kid": "ed-1"}, validPayload(issuer))
	claims, err := client.VerifyToken(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyToken(EdDSA access token): %v", err)
	}
	if claims.Subject() != "user-abc" {
		t.Fatalf("subject: %q", claims.Subject())
	}
}

func TestVerifyToken_RefusesAnRS256TokenSignedByThePublishedRSAKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	_, _, x := makeEd25519Key(t)
	issuer := "http://localhost:8420"
	client := mixedJWKSClient(t, &rsaKey.PublicKey, x, "ed-1", issuer)

	payload := validPayload(issuer)
	payload["token_type"] = "id_token"
	idToken := signRS256(t, rsaKey, payload)

	_, err = client.VerifyToken(context.Background(), idToken)
	if err == nil {
		t.Fatal("VerifyToken accepted an RS256 ID token as an access token")
	}
	if _, ok := err.(*TokenInvalidError); !ok {
		t.Fatalf("expected *TokenInvalidError, got %T: %v", err, err)
	}
}
