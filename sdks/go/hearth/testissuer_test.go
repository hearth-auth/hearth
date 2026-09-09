package hearth

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// testIssuer is an httptest-backed stand-in for a Hearth deployment. It serves
// an OIDC discovery document plus a JWKS containing one Ed25519 public key, and
// can mint tokens signed by the matching private key.
//
// Use it wherever a test needs a token that a verifying gate will actually
// accept; use forgeJWT for the attacker's side of the same test.
type testIssuer struct {
	server *httptest.Server
	mux    *http.ServeMux
	priv   ed25519.PrivateKey
	kid    string
}

// handle mounts an extra route on the issuer's server, so a test can serve its
// own API (e.g. the session-version snapshot feed) from the same origin the
// JWKS lives on. Call it before the first request is made.
func (ti *testIssuer) handle(pattern string, h http.Handler) {
	ti.mux.Handle(pattern, h)
}

// newTestIssuer starts a discovery + JWKS server backed by a fresh Ed25519 key.
// The server is shut down when the test finishes.
func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	ti := &testIssuer{priv: priv, kid: "test-key-1"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "OKP",
				"crv": "Ed25519",
				"kid": ti.kid,
				"x":   base64.RawURLEncoding.EncodeToString(pub),
			}},
		})
	})
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":   ti.server.URL,
			"jwks_uri": ti.server.URL + "/.well-known/jwks.json",
		})
	})
	ti.mux = mux
	ti.server = httptest.NewServer(mux)
	t.Cleanup(ti.server.Close)
	return ti
}

// URL is the issuer's base URL — pass it to NewClient.
func (ti *testIssuer) URL() string { return ti.server.URL }

// client returns a Client wired to this issuer.
func (ti *testIssuer) client() *Client { return NewClient(ti.server.URL, "r1") }

// sign mints a properly signed EdDSA token. `iss` and `exp` are filled in when
// the caller does not supply them, so callers only state the claims they care
// about.
func (ti *testIssuer) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	body := make(map[string]any, len(claims)+2)
	for k, v := range claims {
		body[k] = v
	}
	if _, ok := body["iss"]; !ok {
		body["iss"] = ti.server.URL
	}
	if _, ok := body["exp"]; !ok {
		body["exp"] = time.Now().Add(time.Hour).Unix()
	}

	hb, err := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": ti.kid})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	cb, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(hb) + "." + enc.EncodeToString(cb)
	sig := ed25519.Sign(ti.priv, []byte(signingInput))
	return signingInput + "." + enc.EncodeToString(sig)
}
