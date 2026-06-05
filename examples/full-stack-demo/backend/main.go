// Package main runs the Hearth full-stack demo API server.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/anthropics/hearth/sdks/go/hearth"
	"github.com/anthropics/hearth/examples/full-stack-demo/backend/handlers"
	"github.com/anthropics/hearth/examples/full-stack-demo/backend/middleware"
	"github.com/anthropics/hearth/examples/full-stack-demo/backend/store"
	"github.com/gin-gonic/gin"
)

func main() {
	hearthURL := envOrDefault("HEARTH_URL", "http://localhost:8420")
	realmID := envOrDefault("REALM_ID", "")
	port := envOrDefault("PORT", "8080")

	if realmID == "" {
		log.Fatal("REALM_ID is required — copy .env.example to .env and fill in the value")
	}

	// Fetch JWKS on startup; retry for up to 30 s to allow Hearth to be ready.
	jwksURL := fmt.Sprintf("%s/realms/%s/.well-known/jwks.json", hearthURL, realmID)
	keySet, err := middleware.FetchJWKS(context.Background(), jwksURL, 30*time.Second)
	if err != nil {
		log.Fatalf("failed to fetch JWKS from %s: %v", jwksURL, err)
	}

	hearthClient := hearth.NewClient(hearthURL, realmID)
	notes := store.NewNotes()

	r := gin.Default()

	// CORS — allow the Vite dev server origin.
	// SPA uses Authorization: Bearer tokens, not cookies — no credentials header.
	r.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "http://localhost:5173")
		c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	})

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	auth := middleware.RequireAuth(keySet)
	requireRole := middleware.RequireRole

	v1 := r.Group("/v1")
	v1.Use(auth)
	{
		v1.GET("/notes", handlers.ListNotes(notes))
		v1.POST("/notes", requireRole("editor", "admin"), handlers.CreateNote(notes))
		v1.PATCH("/notes/:id", requireRole("editor", "admin"), handlers.UpdateNote(notes))
		v1.DELETE("/notes/:id", requireRole("admin"), handlers.DeleteNote(notes))

		v1.GET("/admin/users", requireRole("admin"), handlers.ListUsers(hearthClient))
	}

	addr := ":" + port
	log.Printf("backend listening on %s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
