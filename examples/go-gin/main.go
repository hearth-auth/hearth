package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/anthropics/hearth/sdks/go/hearth"
	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// server holds shared dependencies.
type server struct {
	hearth  *hearth.Client
	jwksURL string
	jwksSet jwk.Set
}

func main() {
	baseURL := mustEnv("HEARTH_BASE_URL")
	realmID := mustEnv("HEARTH_REALM_ID")
	port := getenv("PORT", "8080")

	client := hearth.NewClient(baseURL, realmID)
	jwksURL := fmt.Sprintf("%s/realms/%s/jwks", baseURL, realmID)

	ctx := context.Background()

	// Fetch the JWKS on startup; the cache refreshes automatically on a key miss.
	jwksSet, err := fetchJWKS(ctx, jwksURL)
	if err != nil {
		slog.Error("failed to fetch JWKS", "err", err)
		os.Exit(1)
	}

	s := &server{hearth: client, jwksURL: jwksURL, jwksSet: jwksSet}

	r := gin.Default()

	// Public routes — no authentication required.
	r.GET("/health", s.handleHealth)
	r.GET("/", s.handleIndex)

	// Protected routes — require a valid Hearth JWT.
	protected := r.Group("/api")
	protected.Use(s.requireAuth())
	{
		protected.GET("/me", s.handleMe)
		protected.GET("/admin-only", s.requirePermission("hearth.admin"), s.handleAdminOnly)
	}

	slog.Info("listening", "port", port)
	if err := r.Run(":" + port); err != nil {
		slog.Error("server error", "err", err)
		os.Exit(1)
	}
}

// handleHealth is a liveness probe.
func (s *server) handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// handleIndex explains how to authenticate.
func (s *server) handleIndex(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Hearth Go/Gin example — authenticate via /api/me with a Bearer token",
	})
}

// handleMe returns claims from the verified JWT.
func (s *server) handleMe(c *gin.Context) {
	token := mustToken(c)
	accessToken := rawToken(c)

	perms, err := s.hearth.Permissions(c.Request.Context(), accessToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not fetch permissions"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"sub":         token.Subject(),
		"roles":       perms.Roles,
		"groups":      perms.Groups,
		"permissions": perms.Permissions,
	})
}

// handleAdminOnly is an example admin-gated endpoint.
func (s *server) handleAdminOnly(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Welcome, admin! This endpoint requires hearth.admin permission.",
	})
}

// requireAuth validates the Bearer token and stores the parsed JWT in the context.
func (s *server) requireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		raw, ok := bearerToken(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing or malformed Authorization header"})
			return
		}

		// Try to parse with the cached key set first.
		tok, err := parseJWT(raw, s.jwksSet)
		if err != nil {
			// On a key-miss (e.g., after a server key rotation), re-fetch once.
			refreshed, fetchErr := fetchJWKS(c.Request.Context(), s.jwksURL)
			if fetchErr == nil {
				s.jwksSet = refreshed
				tok, err = parseJWT(raw, s.jwksSet)
			}
			if err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
				return
			}
		}

		c.Set("jwt_token", tok)
		c.Set("raw_token", raw)
		c.Next()
	}
}

// requirePermission aborts with 403 when the JWT does not contain the permission.
// Must be chained after requireAuth.
func (s *server) requirePermission(permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw := rawToken(c)
		if !s.hearth.HasPermission(raw, permission) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":              "forbidden",
				"required_permission": permission,
			})
			return
		}
		c.Next()
	}
}

// requireRole aborts with 403 when the JWT does not contain the role.
func (s *server) requireRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw := rawToken(c)
		if !s.hearth.HasRole(raw, role) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":         "forbidden",
				"required_role": role,
			})
			return
		}
		c.Next()
	}
}

// --- helpers ---

func bearerToken(c *gin.Context) (string, bool) {
	h := c.GetHeader("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return "", false
	}
	tok := strings.TrimPrefix(h, "Bearer ")
	if tok == "" {
		return "", false
	}
	return tok, true
}

func parseJWT(raw string, keys jwk.Set) (jwt.Token, error) {
	tok, err := jwt.Parse([]byte(raw), jwt.WithKeySet(keys))
	if err != nil {
		return nil, fmt.Errorf("jwt parse: %w", err)
	}
	return tok, nil
}

func fetchJWKS(ctx context.Context, u string) (jwk.Set, error) {
	set, err := jwk.Fetch(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}
	return set, nil
}

func mustToken(c *gin.Context) jwt.Token {
	tok, ok := c.Get("jwt_token")
	if !ok {
		panic(errors.New("jwt_token not set — requireAuth middleware missing?"))
	}
	return tok.(jwt.Token)
}

func rawToken(c *gin.Context) string {
	raw, _ := c.Get("raw_token")
	if s, ok := raw.(string); ok {
		return s
	}
	return ""
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
