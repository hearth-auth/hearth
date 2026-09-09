// Package hearthgin provides Gin middleware integration for the Hearth identity SDK.
//
// Quick start:
//
//	import (
//	    hearth     "github.com/hearth-auth/hearth/sdks/go/hearth"
//	    hearthgin  "github.com/hearth-auth/hearth/sdks/go/hearth/gin"
//	)
//
//	client := hearth.NewClient("https://hearth.example.com", "<realm-id>")
//
//	r := gin.Default()
//	r.Use(hearthgin.HearthMiddleware(client))         // authenticate every route
//
//	admin := r.Group("/admin")
//	admin.Use(hearthgin.RequirePermission("admin.write"))  // guard by permission
//
//	admin.GET("/users", func(c *gin.Context) {
//	    token := hearthgin.GetToken(c)
//	    _ = token
//	    c.JSON(200, gin.H{"ok": true})
//	})
package hearthgin

import (
	"net/http"

	hearth "github.com/hearth-auth/hearth/sdks/go/hearth"
	"github.com/gin-gonic/gin"
)

const (
	// TokenContextKey is the gin.Context key under which HearthMiddleware stores the
	// bearer token. Retrieve it with GetToken.
	TokenContextKey = "hearth_token"

	// ClientContextKey is the gin.Context key under which HearthMiddleware stores the
	// *hearth.Client. Used internally by RequirePermission.
	ClientContextKey = "hearth_client"

	// ClaimsContextKey is the gin.Context key under which HearthMiddleware stores
	// the *hearth.Claims it obtained by verifying the bearer token. Retrieve it
	// with GetClaims. RequirePermission reads only from here, so an unverified
	// token can never reach a permission decision.
	ClaimsContextKey = "hearth_claims"
)

// MiddlewareOption is a functional option for HearthMiddleware.
type MiddlewareOption func(*middlewareConfig)

type middlewareConfig struct {
	tokenExtractor func(c *gin.Context) string
	onUnauthorized func(c *gin.Context)
}

// WithTokenExtractor replaces the default Authorization: Bearer <token> extractor
// with a custom function. Use this when the token arrives via a cookie, query
// parameter, or any other transport.
func WithTokenExtractor(fn func(c *gin.Context) string) MiddlewareOption {
	return func(cfg *middlewareConfig) {
		cfg.tokenExtractor = fn
	}
}

// WithOnUnauthorized replaces the default HTTP 401 handler that is called when
// no bearer token is found in the request.
func WithOnUnauthorized(fn func(c *gin.Context)) MiddlewareOption {
	return func(cfg *middlewareConfig) {
		cfg.onUnauthorized = fn
	}
}

// defaultExtractor strips the "Bearer " prefix from the Authorization header.
func defaultExtractor(c *gin.Context) string {
	auth := c.GetHeader("Authorization")
	if len(auth) > 7 && auth[:7] == "Bearer " {
		return auth[7:]
	}
	return ""
}

// defaultUnauthorized aborts the request chain and writes HTTP 401.
func defaultUnauthorized(c *gin.Context) {
	c.AbortWithStatus(http.StatusUnauthorized)
}

// HearthMiddleware returns a gin.HandlerFunc that extracts the bearer token from
// the Authorization header, VERIFIES it against the realm's JWKS (EdDSA
// signature plus exp, nbf and iss), and stores it in the Gin context under
// TokenContextKey ("hearth_token"). The verified claims are stored under
// ClaimsContextKey ("hearth_claims") and the Hearth client under
// ClientContextKey ("hearth_client") so that downstream middleware (e.g.
// RequirePermission) can access them without requiring the caller to close over
// the variable manually.
//
// If no token is present, or the token does not verify, the request is aborted.
// The default abort handler writes HTTP 401; override it with
// WithOnUnauthorized.
//
// The JWKS is cached by the client, so verification costs one HTTP round trip
// on the first request and is CPU-only thereafter.
//
// Mount at the router or group level with router.Use:
//
//	r := gin.Default()
//	r.Use(hearthgin.HearthMiddleware(client))
func HearthMiddleware(client *hearth.Client, opts ...MiddlewareOption) gin.HandlerFunc {
	cfg := &middlewareConfig{
		tokenExtractor: defaultExtractor,
		onUnauthorized: defaultUnauthorized,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	return func(c *gin.Context) {
		token := cfg.tokenExtractor(c)
		if token == "" {
			cfg.onUnauthorized(c)
			return
		}
		claims, err := client.VerifyToken(c.Request.Context(), token)
		if err != nil {
			cfg.onUnauthorized(c)
			return
		}
		c.Set(TokenContextKey, token)
		c.Set(ClaimsContextKey, claims)
		c.Set(ClientContextKey, client)
		c.Next()
	}
}

// GetClaims retrieves the verified Hearth claims stored in the Gin context by
// HearthMiddleware. Returns nil when HearthMiddleware has not run.
func GetClaims(c *gin.Context) *hearth.Claims {
	val, exists := c.Get(ClaimsContextKey)
	if !exists {
		return nil
	}
	claims, _ := val.(*hearth.Claims)
	return claims
}

// GetToken retrieves the Hearth bearer token stored in the Gin context by
// HearthMiddleware. Returns an empty string when no token has been stored (i.e.
// HearthMiddleware has not run or the request had no token).
func GetToken(c *gin.Context) string {
	val, exists := c.Get(TokenContextKey)
	if !exists {
		return ""
	}
	token, _ := val.(string)
	return token
}

// RequirePermission returns a gin.HandlerFunc that enforces an embedded-mode
// permission check against the VERIFIED claims stored in context by
// HearthMiddleware. No network call is made here — HearthMiddleware already
// verified the signature and populated the claims.
//
// HearthMiddleware must appear before RequirePermission in the middleware chain;
// it sets the token, the verified claims and the client in the Gin context.
// RequirePermission never reads the raw token, so there is no wiring in which
// an unverified token can reach the permission decision.
//
// Aborts with HTTP 401 when no verified claims are present (HearthMiddleware not
// wired, or the token did not verify), HTTP 403 when the token lacks the
// required permission.
//
// Mount at a group level to guard a set of routes:
//
//	admin := r.Group("/admin")
//	admin.Use(hearthgin.RequirePermission("admin.write"))
func RequirePermission(permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if GetToken(c) == "" {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		clientVal, exists := c.Get(ClientContextKey)
		if !exists {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		if _, ok := clientVal.(*hearth.Client); !ok {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		// A token was stashed but nothing verified it — refuse. This is the
		// only place the raw token is consulted, and only to decide whether to
		// return 401 or 500; the permission decision below reads exclusively
		// from the verified claims.
		claims := GetClaims(c)
		if claims == nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		if !claims.HasPermission(permission) {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		c.Next()
	}
}
