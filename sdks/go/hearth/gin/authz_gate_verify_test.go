package hearthgin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// An attacker mints an unsigned token claiming admin.write. Wiring the adapter
// exactly as its own doc comment instructs — HearthMiddleware, then
// RequirePermission — must refuse it.
func TestHearthMiddlewareRejectsUnsignedToken(t *testing.T) {
	ti := newTestIssuer(t)
	client := ti.client()
	forged := forgeJWT(t, map[string]any{
		"sub":         "attacker",
		"iss":         ti.server.URL,
		"permissions": []string{"admin.write"},
	})

	handlerCalled := false
	r := gin.New()
	r.Use(HearthMiddleware(client))
	r.Use(RequirePermission("admin.write"))
	r.GET("/test", func(c *gin.Context) {
		handlerCalled = true
		c.Status(http.StatusOK)
	})

	rr := serve(r, forged)
	if handlerCalled {
		t.Fatal("guarded handler ran for a token with an invalid signature")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for an unverifiable token, got %d", rr.Code)
	}
}

// RequirePermission must not fall back to the raw token when HearthMiddleware
// stored one but no verified claims — that is exactly the shape that let an
// unverified token reach the permission decision.
func TestRequirePermissionIgnoresRawTokenWithoutVerifiedClaims(t *testing.T) {
	ti := newTestIssuer(t)
	client := ti.client()
	forged := forgeJWT(t, map[string]any{"permissions": []string{"admin.write"}})

	handlerCalled := false
	r := gin.New()
	r.Use(func(c *gin.Context) {
		// Simulate a hand-rolled upstream that stashes the token and client
		// without verifying.
		c.Set(TokenContextKey, forged)
		c.Set(ClientContextKey, client)
		c.Next()
	})
	r.Use(RequirePermission("admin.write"))
	r.GET("/test", func(c *gin.Context) {
		handlerCalled = true
		c.Status(http.StatusOK)
	})

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/test", nil))
	if handlerCalled {
		t.Fatal("RequirePermission trusted a raw token that nothing verified")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 when no verified claims are present, got %d", rr.Code)
	}
}
