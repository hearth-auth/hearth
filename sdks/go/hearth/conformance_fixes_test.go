package hearth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// SDK.md §2 step 3: `iss` must match the CONFIGURED issuer. Reaching the same
// server as `localhost` gives the same keys and the same discovery document,
// but a token issued as 127.0.0.1 does not belong to the configured issuer.
func TestVerifyToken_IssuerComparedWithConfiguredIssuer(t *testing.T) {
	ti := newTestIssuer(t)
	token := ti.sign(t, map[string]any{"sub": "user-1"}) // iss = 127.0.0.1 URL

	configured := strings.Replace(ti.URL(), "127.0.0.1", "localhost", 1)
	claims, err := NewClient(configured, "r1").VerifyToken(context.Background(), token)

	var issuerErr *TokenIssuerError
	if !errors.As(err, &issuerErr) {
		t.Fatalf("expected *TokenIssuerError, got %T: %v (claims %+v)", err, err, claims)
	}
	if issuerErr.Expected != configured {
		t.Fatalf("Expected = %q, want the configured issuer %q", issuerErr.Expected, configured)
	}
}

func TestVerifyToken_ConfiguredIssuerWithTrailingSlashStillMatches(t *testing.T) {
	ti := newTestIssuer(t)
	token := ti.sign(t, map[string]any{"sub": "user-1"})

	if _, err := NewClient(ti.URL()+"/", "r1").VerifyToken(context.Background(), token); err != nil {
		t.Fatalf("expected the token to validate, got %T: %v", err, err)
	}
}

// The server reads X-Realm-ID as a realm UUID and refuses a realm-path request
// whose header names another realm (`400 realm_mismatch`). A realm NAME is
// never a valid X-Realm-ID, so the client sends the header only for a UUID.
func TestClientCredentials_RealmHeaderOnlyForUUID(t *testing.T) {
	for _, tc := range []struct {
		realm      string
		wantHeader string
	}{
		{realm: "conformance", wantHeader: ""},
		{realm: "e6efc997-46c2-4b55-b100-f7c125e9b39a", wantHeader: "e6efc997-46c2-4b55-b100-f7c125e9b39a"},
	} {
		var got string
		var seen bool
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got, seen = r.Header.Get("X-Realm-ID"), true
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "a.b.c", "token_type": "Bearer"})
		}))
		client := NewClient(srv.URL+"/realms/conformance", tc.realm, WithClientCredentials("id", "secret"))
		_, err := client.ClientCredentials(context.Background(), "openid")
		srv.Close()
		if err != nil {
			t.Fatalf("realm %q: unexpected error %T: %v", tc.realm, err, err)
		}
		if !seen || got != tc.wantHeader {
			t.Fatalf("realm %q: X-Realm-ID = %q, want %q", tc.realm, got, tc.wantHeader)
		}
	}
}
