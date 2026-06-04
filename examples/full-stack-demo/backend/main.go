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

	"github.com/anthropics/hearth/examples/full-stack-demo/backend/handlers"
	"github.com/anthropics/hearth/examples/full-stack-demo/backend/middleware"
	"github.com/anthropics/hearth/examples/full-stack-demo/backend/store"
	"github.com/anthropics/hearth/sdks/go/hearth"
	"github.com/gin-gonic/gin"
)

func main() {
	hearthURL := mustEnv("HEARTH_URL")
	realmID := mustEnv("REALM_ID")
	port := getenv("PORT", "8421")

	ctx := context.Background()

	client := hearth.NewClient(hearthURL, realmID)

	// JWKS endpoint follows Hearth's realm-scoped OIDC discovery path.
	jwksURL := fmt.Sprintf("%s/%s/.well-known/jwks.json", hearthURL, realmID)

	validator, err := middleware.NewJWKSValidator(ctx, jwksURL)
	if err != nil {
		slog.Error("JWKS discovery failed", "url", jwksURL, "err", err)
		os.Exit(1)
	}
	slog.Info("JWKS loaded", "url", jwksURL)

	noteStore := store.NewNotes()
	notesH := handlers.NewNotes(noteStore, client)
	adminH := handlers.NewAdmin(client)

	r := gin.Default()

	// CORS: explicit origin allowlist for the SPA (not wildcard).
	// Equivalent to gin-contrib/cors with AllowOrigins: ["http://localhost:5173"].
	r.Use(corsMiddleware([]string{"http://localhost:5173"}))

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	auth := validator.Auth()
	requireEditor := middleware.RequirePermission(client, "content.write")
	requireAdmin := middleware.RequireRole(client, "admin")

	// /notes — content CRUD
	notes := r.Group("/notes", auth)
	{
		notes.GET("", notesH.List)                          // any authenticated user
		notes.POST("", requireEditor, notesH.Create)        // content.write
		notes.PATCH("/:id", requireEditor, notesH.Update)   // content.write
		notes.DELETE("/:id", requireAdmin, notesH.Delete)   // admin role only
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
