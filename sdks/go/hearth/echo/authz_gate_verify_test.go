package hearthecho

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
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
	e := echo.New()
	e.HideBanner = true
	e.Use(HearthMiddleware(client))
	e.Use(RequirePermission("admin.write"))
	e.GET("/test", func(c echo.Context) error {
		handlerCalled = true
		return c.String(http.StatusOK, "ok")
	})

	rr := serve(e, forged)
	if handlerCalled {
		t.Fatal("guarded handler ran for a token with an invalid signature")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for an unverifiable token, got %d", rr.Code)
	}
}

// RequirePermission must not fall back to the raw token when an upstream stored
// one but no verified claims — that is exactly the shape that let an unverified
// token reach the permission decision.
func TestRequirePermissionIgnoresRawTokenWithoutVerifiedClaims(t *testing.T) {
	ti := newTestIssuer(t)
	client := ti.client()
	forged := forgeJWT(t, map[string]any{"permissions": []string{"admin.write"}})

	handlerCalled := false
	e := echo.New()
	e.HideBanner = true
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Set(TokenContextKey, forged)
			c.Set(ClientContextKey, client)
			return next(c)
		}
	})
	e.Use(RequirePermission("admin.write"))
	e.GET("/test", func(c echo.Context) error {
		handlerCalled = true
		return c.String(http.StatusOK, "ok")
	})

	rr := httptest.NewRecorder()
	e.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/test", nil))
	if handlerCalled {
		t.Fatal("RequirePermission trusted a raw token that nothing verified")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 when no verified claims are present, got %d", rr.Code)
	}
}
