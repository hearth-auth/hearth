package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/hearth-auth/hearth/sdks/go/hearth"
	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// server holds shared dependencies.
type server struct {
	hearth    *hearth.Client
	baseURL   string     // trusted base URL — used to guard iss-derived JWKS fetches
	jwksCache sync.Map   // map[issuerURL]jwk.Set — refreshed on key miss
}

func main() {
	baseURL := mustEnv("HEARTH_BASE_URL")
	realmID := mustEnv("HEARTH_REALM_ID")
	port := getenv("PORT", "8080")

	client := hearth.NewClient(baseURL, realmID)

	s := &server{hearth: client, baseURL: baseURL}

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
//
// The JWKS URL is derived from the token's iss claim so the middleware works
// correctly for multi-realm Hearth deployments — each realm signs tokens with
// its own key, and the realm-scoped JWKS lives at {iss}/.well-known/jwks.json.
func (s *server) requireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		raw, ok := bearerToken(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing or malformed Authorization header"})
			return
		}

		// Derive the JWKS URL from the token's iss claim.
		issuer, err := extractIssuer(raw)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}
		// Guard against SSRF: the issuer must be rooted at the configured base URL.
		if !strings.HasPrefix(issuer, s.baseURL) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "untrusted issuer"})
			return
		}
		jwksURL := issuer + "/.well-known/jwks.json"

		// Try the cached key set first; fetch from JWKS endpoint on cache miss or
		// key-not-found error (e.g. after a server-side key rotation).
		var tok jwt.Token
		if cached, ok := s.jwksCache.Load(jwksURL); ok {
			tok, _ = parseJWT(raw, cached.(jwk.Set))
		}
		if tok == nil {
			refreshed, fetchErr := fetchJWKS(c.Request.Context(), jwksURL)
			if fetchErr != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
				return
			}
			s.jwksCache.Store(jwksURL, refreshed)
			var err error
			tok, err = parseJWT(raw, refreshed)
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

// extractIssuer decodes the JWT payload without verification and returns the iss claim.
func extractIssuer(raw string) (string, error) {
	parts := strings.SplitN(raw, ".", 3)
	if len(parts) != 3 {
		return "", fmt.Errorf("malformed JWT: expected 3 parts, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("invalid JWT payload encoding: %w", err)
	}
	var claims struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("invalid JWT claims: %w", err)
	}
	if claims.Iss == "" {
		return "", fmt.Errorf("JWT missing iss claim")
	}
	return claims.Iss, nil
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
