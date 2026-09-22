// Package hearthecho provides Echo middleware integration for the Hearth identity SDK.
//
// Quick start:
//
//	import (
//	    hearth      "github.com/hearth-auth/hearth/sdks/go/hearth"
//	    hearthecho  "github.com/hearth-auth/hearth/sdks/go/hearth/echo"
//	)
//
//	client := hearth.NewClient("https://hearth.example.com", "<realm-id>")
//
//	e := echo.New()
//	e.Use(hearthecho.HearthMiddleware(client))         // authenticate every route
//
//	admin := e.Group("/admin")
//	admin.Use(hearthecho.RequirePermission("admin.write"))  // guard by permission
//
//	admin.GET("/users", func(c echo.Context) error {
//	    token := hearthecho.GetToken(c)
//	    _ = token
//	    return c.JSON(200, map[string]bool{"ok": true})
//	})
package hearthecho

import (
	"net/http"

	hearth "github.com/hearth-auth/hearth/sdks/go/hearth"
	"github.com/labstack/echo/v4"
)

const (
	// TokenContextKey is the echo.Context key under which HearthMiddleware stores the
	// bearer token. Retrieve it with GetToken.
	TokenContextKey = "hearth_token"

	// ClientContextKey is the echo.Context key under which HearthMiddleware stores the
	// *hearth.Client. Used internally by RequirePermission.
	ClientContextKey = "hearth_client"

	// ClaimsContextKey is the echo.Context key under which HearthMiddleware stores
	// the *hearth.Claims it obtained by verifying the bearer token. Retrieve it
	// with GetClaims. RequirePermission reads only from here, so an unverified
	// token can never reach a permission decision.
	ClaimsContextKey = "hearth_claims"
)

// MiddlewareOption is a functional option for HearthMiddleware.
type MiddlewareOption func(*middlewareConfig)

type middlewareConfig struct {
	tokenExtractor func(c echo.Context) string
	onUnauthorized func(c echo.Context) error
}

// WithTokenExtractor replaces the default Authorization: Bearer <token> extractor
// with a custom function. Use this when the token arrives via a cookie, query
// parameter, or any other transport.
func WithTokenExtractor(fn func(c echo.Context) string) MiddlewareOption {
	return func(cfg *middlewareConfig) {
		cfg.tokenExtractor = fn
	}
}

// WithOnUnauthorized replaces the default HTTP 401 handler that is called when
// no bearer token is found in the request. The function must return an error
// (typically an echo.HTTPError) to abort the request chain.
func WithOnUnauthorized(fn func(c echo.Context) error) MiddlewareOption {
	return func(cfg *middlewareConfig) {
		cfg.onUnauthorized = fn
	}
}

// defaultExtractor strips the "Bearer " prefix from the Authorization header.
func defaultExtractor(c echo.Context) string {
	auth := c.Request().Header.Get("Authorization")
	if len(auth) > 7 && auth[:7] == "Bearer " {
		return auth[7:]
	}
	return ""
}

// defaultUnauthorized returns echo.ErrUnauthorized (HTTP 401).
func defaultUnauthorized(_ echo.Context) error {
	return echo.ErrUnauthorized
}

// HearthMiddleware returns an echo.MiddlewareFunc that extracts the bearer token
// from the Authorization header, VERIFIES it against the realm's JWKS (EdDSA
// signature plus exp, nbf and iss), and stores it in the Echo context under
// TokenContextKey ("hearth_token"). The verified claims are stored under
// ClaimsContextKey ("hearth_claims") and the Hearth client under
// ClientContextKey ("hearth_client") so that downstream middleware (e.g.
// RequirePermission) can access them without requiring the caller to close over
// the variable manually.
//
// If no token is present, or the token does not verify, the request is aborted
// with HTTP 401 by default; override the abort behaviour with
// WithOnUnauthorized.
//
// The JWKS is cached by the client, so verification costs one HTTP round trip
// on the first request and is CPU-only thereafter.
//
// Mount at the router or group level with e.Use:
//
//	e := echo.New()
//	e.Use(hearthecho.HearthMiddleware(client))
func HearthMiddleware(client *hearth.Client, opts ...MiddlewareOption) echo.MiddlewareFunc {
	cfg := &middlewareConfig{
		tokenExtractor: defaultExtractor,
		onUnauthorized: defaultUnauthorized,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			token := cfg.tokenExtractor(c)
			if token == "" {
				return cfg.onUnauthorized(c)
			}
			claims, err := client.VerifyToken(c.Request().Context(), token)
			if err != nil {
				return cfg.onUnauthorized(c)
			}
			c.Set(TokenContextKey, token)
			c.Set(ClaimsContextKey, claims)
			c.Set(ClientContextKey, client)
			return next(c)
		}
	}
}

// GetClaims retrieves the verified Hearth claims stored in the Echo context by
// HearthMiddleware. Returns nil when HearthMiddleware has not run.
func GetClaims(c echo.Context) *hearth.Claims {
	val := c.Get(ClaimsContextKey)
	if val == nil {
		return nil
	}
	claims, _ := val.(*hearth.Claims)
	return claims
}

// GetToken retrieves the Hearth bearer token stored in the Echo context by
// HearthMiddleware. Returns an empty string when no token has been stored (i.e.
// HearthMiddleware has not run or the request had no token).
func GetToken(c echo.Context) string {
	val := c.Get(TokenContextKey)
	if val == nil {
		return ""
	}
	token, _ := val.(string)
	return token
}

// RequirePermission returns an echo.MiddlewareFunc that enforces an embedded-mode
// permission check against the VERIFIED claims stored in context by
// HearthMiddleware. No network call is made here — HearthMiddleware already
// verified the signature and populated the claims.
//
// HearthMiddleware must appear before RequirePermission in the middleware chain;
// it sets the token, the verified claims and the client in the Echo context.
// RequirePermission never reads the raw token, so there is no wiring in which
// an unverified token can reach the permission decision.
//
// Returns HTTP 401 when no verified claims are present (HearthMiddleware not
// wired, or the token did not verify),
// HTTP 403 when the token lacks the required permission,
// HTTP 500 when the client is not in context (misconfigured middleware chain).
//
// Mount at a group level to guard a set of routes:
//
//	admin := e.Group("/admin")
//	admin.Use(hearthecho.RequirePermission("admin.write"))
func RequirePermission(permission string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if GetToken(c) == "" {
				return echo.ErrUnauthorized
			}
			clientVal := c.Get(ClientContextKey)
			if clientVal == nil {
				return echo.NewHTTPError(http.StatusInternalServerError)
			}
			if _, ok := clientVal.(*hearth.Client); !ok {
				return echo.NewHTTPError(http.StatusInternalServerError)
			}
			// A token was stashed but nothing verified it — refuse. This is the
			// only place the raw token is consulted, and only to decide whether
			// to return 401 or 500; the permission decision below reads
			// exclusively from the verified claims.
			claims := GetClaims(c)
			if claims == nil {
				return echo.ErrUnauthorized
			}
			if !claims.HasPermission(permission) {
				return echo.ErrForbidden
			}
			return next(c)
		}
	}
}
