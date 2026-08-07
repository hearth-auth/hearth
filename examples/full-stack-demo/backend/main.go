// Command backend is the Go + Gin API server for the Hearth full-stack demo.
// It demonstrates JWT validation via JWKS, RBAC middleware, and the Admin SDK.
//
// Environment variables (see .env.example):
//
//	HEARTH_URL  — base URL of the running Hearth server (required)
//	REALM_ID    — realm name configured in hearth.yaml (required)
//	PORT        — TCP port to bind (default: 8421)
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hearth-auth/hearth/examples/full-stack-demo/backend/handlers"
	"github.com/hearth-auth/hearth/examples/full-stack-demo/backend/middleware"
	"github.com/hearth-auth/hearth/examples/full-stack-demo/backend/store"
	"github.com/hearth-auth/hearth/sdks/go/hearth"
)

func main() {
	hearthURL := mustEnv("HEARTH_URL")
	realmID := mustEnv("REALM_ID")     // UUID — used for admin API X-Realm-ID header
	realmSlug := mustEnv("REALM_SLUG") // slug — used for OIDC/JWKS URL path
	port := getenv("PORT", "8421")

	ctx := context.Background()

	client := hearth.NewClient(hearthURL, realmID)

	// JWKS lives at /realms/{slug}/.well-known/jwks.json (slug-based OIDC routes).
	jwksURL := fmt.Sprintf("%s/realms/%s/.well-known/jwks.json", hearthURL, realmSlug)

	validator, err := middleware.NewJWKSValidator(ctx, jwksURL)
	if err != nil {
		slog.Error("JWKS discovery failed", "url", jwksURL, "err", err)
		os.Exit(1)
	}
	slog.Info("JWKS loaded", "url", jwksURL)

	// Layer revocation-aware validation on top of the signature check. Signature
	// verification alone accepts a revoked-but-unexpired token (HEA-2094): a JWT
	// cannot express that its session was killed at Hearth after issuance. We ask
	// Hearth's realm-scoped introspection endpoint (RFC 7662) — which needs no
	// client credentials — and cache each verdict for a short TTL so introspection
	// is not a per-request network round-trip. See RevocationChecker for the
	// latency/consistency tradeoff.
	introspectURL := fmt.Sprintf("%s/realms/%s/introspect", hearthURL, realmSlug)
	ttl := introspectCacheTTL()
	validator = validator.WithRevocationCheck(middleware.NewRevocationChecker(introspectURL, ttl))
	slog.Info("revocation introspection enabled", "url", introspectURL, "cache_ttl", ttl)

	noteStore := store.NewNotes()
	notesH := handlers.NewNotes(noteStore, client)
	adminH := handlers.NewAdmin(client)

	r := gin.Default()

	// CORS: explicit origin allowlist for the SPA (not wildcard).
	// FRONTEND_ORIGIN is written by demo.sh; defaults to the dev value.
	frontendOrigin := getenv("FRONTEND_ORIGIN", "http://localhost:5173")
	r.Use(corsMiddleware([]string{frontendOrigin}))

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	auth := validator.Auth()
	requireEditor := middleware.RequirePermission(client, "content.write")
	requireAdmin := middleware.RequireRole(client, "admin")

	// /api/notes — content CRUD
	notes := r.Group("/api/notes", auth)
	{
		notes.GET("", notesH.List)                        // any authenticated user
		notes.POST("", requireEditor, notesH.Create)      // content.write
		notes.PATCH("/:id", requireEditor, notesH.Update) // content.write
		notes.DELETE("/:id", requireAdmin, notesH.Delete) // admin role only
	}

	// /admin — administrative operations
	admin := r.Group("/admin", auth, requireAdmin)
	{
		admin.GET("/users", adminH.ListUsers)
	}

	slog.Info("listening", "port", port)
	if err := r.Run(":" + port); err != nil {
		slog.Error("server error", "err", err)
		os.Exit(1)
	}
}

// corsMiddleware sets Access-Control headers for an explicit origin allowlist.
// Requests from origins not in the list receive no CORS headers (browser blocks them).
func corsMiddleware(allowOrigins []string) gin.HandlerFunc {
	allowed := make(map[string]struct{}, len(allowOrigins))
	for _, o := range allowOrigins {
		allowed[o] = struct{}{}
	}
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if _, ok := allowed[origin]; ok {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Credentials", "true")
			c.Header("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type")
			c.Header("Access-Control-Max-Age", "86400")
			c.Header("Vary", "Origin")
		}
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

// introspectCacheTTL reads INTROSPECT_CACHE_TTL (a Go duration string, e.g.
// "3s", "30s") and returns the revocation-cache TTL. It defaults to a short
// window so a revocation is observable interactively within seconds; production
// deployments tune this against their revocation-latency budget. "0" disables
// caching (introspect on every request).
func introspectCacheTTL() time.Duration {
	const def = 3 * time.Second
	v := os.Getenv("INTROSPECT_CACHE_TTL")
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		slog.Warn("invalid INTROSPECT_CACHE_TTL; using default", "value", v, "default", def)
		return def
	}
	return d
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		slog.Error("required env var not set", "key", key)
		os.Exit(1)
	}
	return v
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
