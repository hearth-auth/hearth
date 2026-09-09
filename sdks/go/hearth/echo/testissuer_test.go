package hearthecho

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	hearth "github.com/hearth-auth/hearth/sdks/go/hearth"
)

// testIssuer is an httptest-backed stand-in for a Hearth deployment: it serves
// an OIDC discovery document plus a JWKS holding one Ed25519 public key, and
// mints tokens signed by the matching private key.
//
// HearthMiddleware verifies every bearer token against this JWKS, so tests that
// expect a request to be allowed must use testIssuer.sign; forgeJWT is reserved
// for the attacker's side.
type testIssuer struct {
	server *httptest.Server
	priv   ed25519.PrivateKey
	kid    string
}

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
	ti.server = httptest.NewServer(mux)
	t.Cleanup(ti.server.Close)
	return ti
}

// client returns a hearth.Client wired to this issuer.
func (ti *testIssuer) client() *hearth.Client {
	return hearth.NewClient(ti.server.URL, "r1")
}

// sign mints a properly signed EdDSA token, defaulting iss and exp.
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
	return signingInput + "." + enc.EncodeToString(ed25519.Sign(ti.priv, []byte(signingInput)))
}
