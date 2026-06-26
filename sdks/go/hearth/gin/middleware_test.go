package hearthgin

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	hearth "github.com/hearth-auth/hearth/sdks/go/hearth"
	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// forgeJWT builds a syntactically valid three-segment JWT with the given claim
// body. The signature segment is a constant stub — the SDK's HasPermission
// decodes claims locally without verifying the signature.
func forgeJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := map[string]string{"alg": "EdDSA", "typ": "JWT"}
	hb, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("forge JWT header: %v", err)
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("forge JWT claims: %v", err)
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(hb) + "." + enc.EncodeToString(cb) + ".c2ln"
}

// newRouter builds a minimal Gin engine with HearthMiddleware applied globally
// and a GET /test route that writes HTTP 200 "ok".
func newRouter(client *hearth.Client, opts ...MiddlewareOption) *gin.Engine {
	r := gin.New()
	r.Use(HearthMiddleware(client, opts...))
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	return r
}

// serve fires a GET /test request against router with an optional bearer token.
func serve(router *gin.Engine, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

// ─── HearthMiddleware ────────────────────────────────────────────────────────

func TestHearthMiddlewareAllowsValidToken(t *testing.T) {
	client := hearth.NewClient("http://localhost", "r1")
	token := forgeJWT(t, map[string]any{"sub": "user_1"})
	rr := serve(newRouter(client), token)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestHearthMiddlewareMissingTokenReturns401(t *testing.T) {
	client := hearth.NewClient("http://localhost", "r1")
	rr := serve(newRouter(client), "")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing token, got %d", rr.Code)
	}
}

func TestHearthMiddlewareStoresTokenInContext(t *testing.T) {
	client := hearth.NewClient("http://localhost", "r1")
	token := forgeJWT(t, map[string]any{"sub": "user_1"})

	r := gin.New()
	r.Use(HearthMiddleware(client))

	var capturedToken string
	r.GET("/test", func(c *gin.Context) {
		capturedToken = GetToken(c)
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(httptest.NewRecorder(), req)

	if capturedToken != token {
		t.Fatalf("expected token %q in context, got %q", token, capturedToken)
	}
}

func TestHearthMiddlewareCustomExtractor(t *testing.T) {
	client := hearth.NewClient("http://localhost", "r1")
	token := forgeJWT(t, map[string]any{"sub": "user_1"})

	// Extract from X-Auth-Token header instead of Authorization.
	extractor := func(c *gin.Context) string {
		return c.GetHeader("X-Auth-Token")
	}

	r := gin.New()
	r.Use(HearthMiddleware(client, WithTokenExtractor(extractor)))
	r.GET("/test", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Auth-Token", token)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("custom extractor: expected 200, got %d", rr.Code)
	}
}

func TestHearthMiddlewareCustomUnauthorizedHandler(t *testing.T) {
	client := hearth.NewClient("http://localhost", "r1")

	customHandler := func(c *gin.Context) {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "no token"})
	}

	r := gin.New()
	r.Use(HearthMiddleware(client, WithOnUnauthorized(customHandler)))
	r.GET("/test", func(c *gin.Context) { c.Status(http.StatusOK) })

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/test", nil))

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 from custom handler, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct == "" {
		t.Fatal("expected JSON body from custom unauthorized handler")
	}
}

// ─── GetToken ────────────────────────────────────────────────────────────────

func TestGetTokenReturnsEmptyWhenNotSet(t *testing.T) {
	r := gin.New()
	var capturedToken string
	r.GET("/test", func(c *gin.Context) {
		capturedToken = GetToken(c)
		c.Status(http.StatusOK)
	})
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/test", nil))
	if capturedToken != "" {
		t.Fatalf("expected empty string when key absent, got %q", capturedToken)
	}
}

// ─── RequirePermission ───────────────────────────────────────────────────────

func TestRequirePermissionAllowed(t *testing.T) {
	client := hearth.NewClient("http://localhost", "r1")
	token := forgeJWT(t, map[string]any{"permissions": []string{"docs.edit"}})

	r := gin.New()
	r.Use(HearthMiddleware(client))
	r.Use(RequirePermission("docs.edit"))
	r.GET("/test", func(c *gin.Context) { c.Status(http.StatusOK) })

	rr := serve(r, token)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for permitted token, got %d", rr.Code)
	}
}

func TestRequirePermissionDenied(t *testing.T) {
	client := hearth.NewClient("http://localhost", "r1")
	token := forgeJWT(t, map[string]any{"permissions": []string{"docs.view"}})

	r := gin.New()
	r.Use(HearthMiddleware(client))
	r.Use(RequirePermission("docs.edit"))
	r.GET("/test", func(c *gin.Context) { c.Status(http.StatusOK) })

	rr := serve(r, token)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for insufficient permission, got %d", rr.Code)
	}
}

func TestRequirePermissionNoToken(t *testing.T) {
	// RequirePermission without HearthMiddleware — no token in context.
	client := hearth.NewClient("http://localhost", "r1")
	_ = client

	r := gin.New()
	r.Use(RequirePermission("docs.edit"))
	r.GET("/test", func(c *gin.Context) { c.Status(http.StatusOK) })

	rr := serve(r, "")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when no token in context, got %d", rr.Code)
	}
}

func TestRequirePermissionNoClientInContext(t *testing.T) {
	// Client is stored under ClientContextKey; if it is absent (e.g. RequirePermission
	// used without HearthMiddleware) the middleware must not panic — it returns 500.
	r := gin.New()
	// Manually set the token but not the client.
	r.Use(func(c *gin.Context) {
		c.Set(TokenContextKey, "some.token.stub")
		c.Next()
	})
	r.Use(RequirePermission("docs.edit"))
	r.GET("/test", func(c *gin.Context) { c.Status(http.StatusOK) })

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/test", nil))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when client absent from context, got %d", rr.Code)
	}
}

// ─── Integration: route-level protection via router.Use ─────────────────────

func TestRouteGroupProtection(t *testing.T) {
	client := hearth.NewClient("http://localhost", "r1")
	editToken := forgeJWT(t, map[string]any{"permissions": []string{"docs.edit"}})
	viewToken := forgeJWT(t, map[string]any{"permissions": []string{"docs.view"}})

	r := gin.New()
	r.Use(HearthMiddleware(client))

	// Public route — any authenticated user.
	r.GET("/public", func(c *gin.Context) { c.Status(http.StatusOK) })

	// Protected group — requires docs.edit.
	protected := r.Group("/protected")
	protected.Use(RequirePermission("docs.edit"))
	protected.GET("/resource", func(c *gin.Context) { c.Status(http.StatusOK) })

	cases := []struct {
		name   string
		path   string
		token  string
		expect int
	}{
		{"public with edit token", "/public", editToken, http.StatusOK},
		{"public with view token", "/public", viewToken, http.StatusOK},
		{"protected with edit token", "/protected/resource", editToken, http.StatusOK},
		{"protected with view token", "/protected/resource", viewToken, http.StatusForbidden},
		{"protected with no token", "/protected/resource", "", http.StatusUnauthorized},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)
			if rr.Code != tc.expect {
				t.Fatalf("%s: expected %d, got %d", tc.name, tc.expect, rr.Code)
			}
		})
	}
}
