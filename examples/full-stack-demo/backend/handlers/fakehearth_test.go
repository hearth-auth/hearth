package handlers_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/hearth-auth/hearth/sdks/go/v4/hearth"
)

// fakeHearth stands in for a Hearth realm. It serves an OIDC discovery
// document and a JWKS with one Ed25519 key, signs tokens with the matching
// private key, and passes every other path to api, which a test sets.
//
// hearth.Client.HasRole and HasPermission verify the token's signature, iss,
// aud and exp before they read a claim, so the RBAC middleware under test
// needs tokens that this issuer signs.
type fakeHearth struct {
	server *httptest.Server
	priv   ed25519.PrivateKey
	kid    string

	mu  sync.Mutex
	api http.Handler
}

// hearthFake is shared by the package's tests; TestMain starts it.
var hearthFake *fakeHearth

func TestMain(m *testing.M) {
	hearthFake = newFakeHearth()
	code := m.Run()
	hearthFake.server.Close()
	os.Exit(code)
}

func newFakeHearth() *fakeHearth {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	f := &fakeHearth{priv: priv, kid: "demo-test-key"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":            f.server.URL,
			"jwks_uri":          f.server.URL + "/.well-known/jwks.json",
			"userinfo_endpoint": f.server.URL + "/userinfo",
		})
	})
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"keys": []map[string]string{{
			"kty": "OKP",
			"crv": "Ed25519",
			"kid": f.kid,
			"x":   base64.RawURLEncoding.EncodeToString(pub),
		}}})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		api := f.api
		f.mu.Unlock()
		if api == nil {
			http.Error(w, "no fake Hearth API handler for "+r.URL.Path, http.StatusNotFound)
			return
		}
		api.ServeHTTP(w, r)
	})
	f.server = httptest.NewServer(mux)
	return f
}

// client returns a hearth.Client whose base URL is this issuer.
func (f *fakeHearth) client() *hearth.Client {
	return hearth.NewClient(f.server.URL, "demo")
}

// serveAPI routes the non-OIDC paths to h until the test ends.
func (f *fakeHearth) serveAPI(t *testing.T, h http.Handler) {
	t.Helper()
	f.mu.Lock()
	f.api = h
	f.mu.Unlock()
	t.Cleanup(func() {
		f.mu.Lock()
		f.api = nil
		f.mu.Unlock()
	})
}

// makeToken returns an access token that this fake Hearth signed, with the
// given subject, roles and permissions.
func makeToken(sub string, roles, perms []string) string {
	claims, _ := json.Marshal(map[string]any{
		"sub":         sub,
		"iss":         hearthFake.server.URL,
		"aud":         hearth.DefaultAudience,
		"exp":         time.Now().Add(time.Hour).Unix(),
		"roles":       roles,
		"permissions": perms,
	})
	header, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": hearthFake.kid})
	enc := base64.RawURLEncoding
	input := enc.EncodeToString(header) + "." + enc.EncodeToString(claims)
	return input + "." + enc.EncodeToString(ed25519.Sign(hearthFake.priv, []byte(input)))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
