package hearth

// Endpoint URLs come from OIDC discovery (openspec/specs/sdk-support-contract/spec.md,
// "Endpoint URLs come from OIDC discovery"): the token, device-authorization,
// introspection, userinfo and JWKS URLs are the ones the discovery document
// advertises, the document is fetched once per client, and a discovery failure
// is a *DiscoveryError, never a guessed path. The token and device-authorization
// endpoints take form-encoded bodies (RFC 6749 §2.3.1, RFC 8628 §3.1), and a
// request to a realm endpoint (/realms/{realm}/...) carries no X-Realm-ID: the
// path names the realm.

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sync"
	"testing"
)

// realmUUID is a realm id: the client sends it as X-Realm-ID, but only to an
// endpoint whose path does not name the realm.
const realmUUID = "e6efc997-46c2-4b55-b100-f7c125e9b39a"

// oauthDiscovery is the discovery document of a Hearth issuer: every endpoint
// hangs off the issuer URL, as Hearth's own discovery documents advertise them.
func oauthDiscovery(issuer string) map[string]any {
	return map[string]any{
		"issuer":                        issuer,
		"jwks_uri":                      issuer + "/.well-known/jwks.json",
		"token_endpoint":                issuer + "/token",
		"device_authorization_endpoint": issuer + "/device_authorization",
		"introspection_endpoint":        issuer + "/introspect",
		"userinfo_endpoint":             issuer + "/userinfo",
	}
}

// newOAuthServer starts a stub Hearth whose discovery document advertises its
// endpoints at the server's root, as Hearth's global discovery does. Every
// other request goes to h.
func newOAuthServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			writeJSON(t, w, oauthDiscovery(srv.URL))
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// recordedRequest is one request a realmStub received.
type recordedRequest struct {
	method      string
	path        string
	contentType string
	realmHeader string
	hasRealm    bool
	body        string
}

// form decodes the recorded body as application/x-www-form-urlencoded.
func (r recordedRequest) form() url.Values {
	v, err := url.ParseQuery(r.body)
	if err != nil {
		return nil
	}
	return v
}

// realmStub is a stub Hearth whose discovery document advertises realm
// endpoints under /realms/acme/: paths the SDK would never build from its base
// URL. It counts discovery fetches and records every other request.
type realmStub struct {
	srv *httptest.Server

	mu            sync.Mutex
	discoveryHits int
	requests      []recordedRequest
}

func newRealmStub(t *testing.T) *realmStub {
	t.Helper()
	s := &realmStub{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			s.mu.Lock()
			s.discoveryHits++
			s.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			writeJSON(t, w, oauthDiscovery(s.srv.URL+"/realms/acme"))
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("stub server: read body: %v", err)
		}
		_, hasRealm := r.Header["X-Realm-Id"]
		s.mu.Lock()
		s.requests = append(s.requests, recordedRequest{
			method:      r.Method,
			path:        r.URL.Path,
			contentType: r.Header.Get("Content-Type"),
			realmHeader: r.Header.Get("X-Realm-ID"),
			hasRealm:    hasRealm,
			body:        string(body),
		})
		s.mu.Unlock()
		// One answer that decodes as a token, device-authorization, userinfo
		// and introspection response alike.
		w.Header().Set("Content-Type", "application/json")
		writeJSON(t, w, map[string]any{
			"access_token":     "a.b.c",
			"token_type":       "Bearer",
			"expires_in":       3600,
			"device_code":      "DEV123",
			"user_code":        "ABCD-1234",
			"verification_uri": "https://hearth.example.com/device",
			"interval":         5,
			"active":           true,
			"sub":              "user-1",
		})
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *realmStub) URL() string { return s.srv.URL }

func (s *realmStub) recorded() []recordedRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]recordedRequest(nil), s.requests...)
}

func (s *realmStub) discoveryCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.discoveryHits
}

// Regression — Go and Python ignore the discovered token endpoint; Regression —
// Go sends JSON to the token endpoint; Regression — Go device flow sends JSON;
// Regression — Go sends X-Realm-ID to the token endpoint.
func TestFlows_UseDiscoveredRealmEndpoints(t *testing.T) {
	cases := []struct {
		name   string
		call   func(ctx context.Context, c *Client) error
		method string
		path   string
		// form is the exact form body the endpoint must receive; nil when the
		// request is not form-encoded.
		form url.Values
	}{
		{
			name: "ClientCredentials",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.ClientCredentials(ctx, "read:users")
				return err
			},
			method: http.MethodPost,
			path:   "/realms/acme/token",
			form: url.Values{
				"grant_type":    {"client_credentials"},
				"client_id":     {"svc"},
				"client_secret": {"s3cret"},
				"scope":         {"read:users"},
			},
		},
		{
			name: "StartDeviceFlow",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.StartDeviceFlow(ctx, "openid")
				return err
			},
			method: http.MethodPost,
			path:   "/realms/acme/device_authorization",
			form:   url.Values{"client_id": {"svc"}, "scope": {"openid"}},
		},
		{
			name: "PollDeviceToken",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.PollDeviceToken(ctx, "DEV123")
				return err
			},
			method: http.MethodPost,
			path:   "/realms/acme/token",
			form: url.Values{
				"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
				"device_code": {"DEV123"},
				"client_id":   {"svc"},
			},
		},
		{
			name: "ExchangeMagicLink",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.ExchangeMagicLink(ctx, "magic-token")
				return err
			},
			method: http.MethodPost,
			path:   "/realms/acme/token",
			form: url.Values{
				"grant_type": {"urn:hearth:grant-type:magic-link"},
				"token":      {"magic-token"},
				"client_id":  {"svc"},
			},
		},
		{
			name: "ExchangeCode",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.ExchangeCode(ctx, TokenRequest{
					ClientID:     "svc",
					GrantType:    "authorization_code",
					Code:         "code-1",
					RedirectURI:  "https://app.example.com/callback",
					CodeVerifier: "verifier-1",
				})
				return err
			},
			method: http.MethodPost,
			path:   "/realms/acme/token",
			form: url.Values{
				"grant_type":    {"authorization_code"},
				"client_id":     {"svc"},
				"code":          {"code-1"},
				"redirect_uri":  {"https://app.example.com/callback"},
				"code_verifier": {"verifier-1"},
			},
		},
		{
			name: "RefreshTokens",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.RefreshTokens(ctx, "svc", "refresh-1")
				return err
			},
			method: http.MethodPost,
			path:   "/realms/acme/token",
			form: url.Values{
				"grant_type":    {"refresh_token"},
				"client_id":     {"svc"},
				"refresh_token": {"refresh-1"},
			},
		},
		{
			name: "UserInfo",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.UserInfo(ctx, "access-token")
				return err
			},
			method: http.MethodGet,
			path:   "/realms/acme/userinfo",
		},
		{
			name: "Introspect",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.Introspect(ctx, IntrospectRequest{
					Token: "access-token", ClientID: "rs", ClientSecret: "rs-secret",
				})
				return err
			},
			method: http.MethodPost,
			path:   "/realms/acme/introspect",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := newRealmStub(t)
			c := NewClient(stub.URL(), realmUUID, WithClientCredentials("svc", "s3cret"))
			if err := tc.call(t.Context(), c); err != nil {
				t.Fatalf("%s: unexpected error %T: %v", tc.name, err, err)
			}
			reqs := stub.recorded()
			if len(reqs) != 1 {
				t.Fatalf("expected one request besides discovery, got %d: %+v", len(reqs), reqs)
			}
			got := reqs[0]
			if got.method != tc.method || got.path != tc.path {
				t.Errorf("request: %s %s, want %s %s (the discovered endpoint)",
					got.method, got.path, tc.method, tc.path)
			}
			if got.hasRealm {
				t.Errorf("X-Realm-ID: %q sent to a realm endpoint, want no header", got.realmHeader)
			}
			if tc.form == nil {
				return
			}
			if got.contentType != "application/x-www-form-urlencoded" {
				t.Errorf("Content-Type: %q, want application/x-www-form-urlencoded", got.contentType)
			}
			if form := got.form(); !reflect.DeepEqual(form, tc.form) {
				t.Errorf("form body: %v (raw %q), want %v", form, got.body, tc.form)
			}
		})
	}
}

// Regression — Go sends X-Realm-ID to the token endpoint. The realm endpoints
// name the realm in their path, so they get no header: the server answers
// `400 realm_mismatch` to a header that does not resolve to that realm. The
// global endpoints read the realm from the header, so a realm UUID is still
// sent there; a realm NAME is never a valid X-Realm-ID.
func TestTokenRequest_RealmHeader(t *testing.T) {
	for _, tc := range []struct {
		name      string
		tokenPath string
		realm     string
		want      string
	}{
		{name: "realm endpoint, realm name", tokenPath: "/realms/conformance/token", realm: "conformance"},
		{name: "realm endpoint, realm UUID", tokenPath: "/realms/conformance/token", realm: realmUUID},
		{name: "global endpoint, realm name", tokenPath: "/token", realm: "conformance"},
		{name: "global endpoint, realm UUID", tokenPath: "/token", realm: realmUUID, want: realmUUID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var (
				mu      sync.Mutex
				gotPath string
				got     string
				seen    bool
			)
			var srv *httptest.Server
			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/.well-known/openid-configuration" {
					writeJSON(t, w, map[string]any{
						"issuer":         srv.URL,
						"token_endpoint": srv.URL + tc.tokenPath,
					})
					return
				}
				mu.Lock()
				gotPath, got, seen = r.URL.Path, r.Header.Get("X-Realm-ID"), true
				mu.Unlock()
				writeJSON(t, w, map[string]any{"access_token": "a.b.c", "token_type": "Bearer"})
			}))
			defer srv.Close()

			client := NewClient(srv.URL, tc.realm, WithClientCredentials("id", "secret"))
			if _, err := client.ClientCredentials(t.Context(), "openid"); err != nil {
				t.Fatalf("unexpected error %T: %v", err, err)
			}
			mu.Lock()
			defer mu.Unlock()
			if !seen || gotPath != tc.tokenPath {
				t.Fatalf("token request went to %q, want the discovered %q", gotPath, tc.tokenPath)
			}
			if got != tc.want {
				t.Fatalf("X-Realm-ID = %q, want %q", got, tc.want)
			}
		})
	}
}

// Scenario: Discovery is fetched once.
func TestDiscovery_FetchedOncePerClient(t *testing.T) {
	stub := newRealmStub(t)
	c := NewClient(stub.URL(), realmUUID, WithClientCredentials("svc", "s3cret"))
	ctx := t.Context()
	if _, err := c.ClientCredentials(ctx); err != nil {
		t.Fatalf("ClientCredentials: %v", err)
	}
	if _, err := c.StartDeviceFlow(ctx); err != nil {
		t.Fatalf("StartDeviceFlow: %v", err)
	}
	if _, err := c.UserInfo(ctx, "access-token"); err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	if n := stub.discoveryCount(); n != 1 {
		t.Fatalf("discovery fetched %d times, want 1", n)
	}
}

// A failed discovery is a *DiscoveryError: the SDK does not post to a token
// path it built itself.
func TestClientCredentials_DiscoveryFailureIsDiscoveryError(t *testing.T) {
	var mu sync.Mutex
	var others []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		mu.Lock()
		others = append(others, r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		writeJSON(t, w, map[string]any{"access_token": "a.b.c", "token_type": "Bearer"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, realmUUID, WithClientCredentials("svc", "s3cret"))
	_, err := c.ClientCredentials(t.Context())
	var discErr *DiscoveryError
	if !errors.As(err, &discErr) {
		t.Errorf("expected *DiscoveryError, got %T: %v", err, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(others) != 0 {
		t.Errorf("the SDK guessed an endpoint after discovery failed: %v", others)
	}
}

// Regression — Go guesses the JWKS path (scenario "Discovery is down").
func TestVerifyToken_DiscoveryFailureDoesNotGuessJWKSPath(t *testing.T) {
	for _, tc := range []struct {
		name      string
		discovery func(w http.ResponseWriter, issuer string)
	}{
		{
			name: "discovery answers 503",
			discovery: func(w http.ResponseWriter, _ string) {
				w.WriteHeader(http.StatusServiceUnavailable)
			},
		},
		{
			name: "discovery names no jwks_uri",
			discovery: func(w http.ResponseWriter, issuer string) {
				w.Header().Set("Content-Type", "application/json")
				writeJSON(t, w, map[string]any{"issuer": issuer})
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			priv, _, x := makeEd25519Key(t)
			const kid = "k1"
			var mu sync.Mutex
			jwksHits := 0
			var srv *httptest.Server
			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/.well-known/openid-configuration":
					tc.discovery(w, srv.URL)
				case "/.well-known/jwks.json":
					mu.Lock()
					jwksHits++
					mu.Unlock()
					w.Header().Set("Content-Type", "application/json")
					writeBody(t, w, makeJWKS(x, kid))
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()

			token := signJWT(t, priv, map[string]any{"alg": "EdDSA", "kid": kid}, validPayload(srv.URL))
			claims, err := NewClient(srv.URL, "r1").VerifyToken(t.Context(), token)
			var discErr *DiscoveryError
			if !errors.As(err, &discErr) {
				t.Errorf("expected *DiscoveryError, got %T: %v (claims %+v)", err, err, claims)
			}
			mu.Lock()
			defer mu.Unlock()
			if jwksHits != 0 {
				t.Errorf("the SDK fetched the guessed /.well-known/jwks.json %d times", jwksHits)
			}
		})
	}
}
