// Package middleware provides Gin middleware for Hearth JWT validation.
package middleware

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/anthropics/hearth/sdks/go/hearth"
	"github.com/gin-gonic/gin"
	jwtv5 "github.com/golang-jwt/jwt/v5"
)

const claimsKey = "hearth_claims"

// FetchJWKS fetches the JWKS from the given URL, retrying until timeout.
func FetchJWKS(ctx context.Context, url string, timeout time.Duration) ([]jwk, error) {
	deadline := time.Now().Add(timeout)
	for {
		keys, err := fetchJWKS(ctx, url)
		if err == nil {
			return keys, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out fetching JWKS: %w", err)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	// RSA/EC
	N string `json:"n"`
	E string `json:"e"`
	// EC
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	// OKP (Ed25519)
	OKPAlg string `json:"-"`
}

func fetchJWKS(ctx context.Context, url string) ([]jwk, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var ks jwks
	if err := json.Unmarshal(body, &ks); err != nil {
		return nil, err
	}
	return ks.Keys, nil
}

// publicKeyFor returns the crypto public key for the given key ID.
func publicKeyFor(keys []jwk, kid string) (interface{}, error) {
	for _, k := range keys {
		if k.Kid != kid && kid != "" {
			continue
		}
		switch k.Kty {
		case "OKP":
			xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
			if err != nil {
				return nil, fmt.Errorf("invalid OKP x: %w", err)
			}
			return ed25519.PublicKey(xBytes), nil
		case "EC":
			xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
			if err != nil {
				return nil, fmt.Errorf("invalid EC x: %w", err)
			}
			yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
			if err != nil {
				return nil, fmt.Errorf("invalid EC y: %w", err)
			}
			pub := &ecdsa.PublicKey{X: new(big.Int).SetBytes(xBytes), Y: new(big.Int).SetBytes(yBytes)}
			return pub, nil
		}
	}
	return nil, fmt.Errorf("no matching key for kid %q", kid)
}

// RequireAuth validates the Bearer JWT and stores parsed Claims in the context.
func RequireAuth(keys []jwk) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		if raw == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
			return
		}

		// Parse header to get kid.
		parts := strings.Split(raw, ".")
		if len(parts) != 3 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "malformed token"})
			return
		}
		hdrBytes, _ := base64.RawURLEncoding.DecodeString(parts[0])
		var hdr struct {
			Kid string `json:"kid"`
			Alg string `json:"alg"`
		}
		_ = json.Unmarshal(hdrBytes, &hdr)

		pub, err := publicKeyFor(keys, hdr.Kid)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unknown key"})
			return
		}

		// Verify signature and standard claims.
		_, err = jwtv5.Parse(raw, func(t *jwtv5.Token) (interface{}, error) {
			return pub, nil
		})
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		claims, err := hearth.ParseClaims(raw)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unparseable claims"})
			return
		}

		c.Set(claimsKey, claims)
		c.Set("raw_token", raw)
		c.Next()
	}
}

// RequireRole aborts with 403 if the caller lacks all of the given roles.
func RequireRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		v, ok := c.Get(claimsKey)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthenticated"})
			return
		}
		claims := v.(*hearth.Claims)
		for _, role := range roles {
			if claims.HasRole(role) {
				c.Next()
				return
			}
		}
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient role"})
	}
}

// RawToken retrieves the raw Bearer token stored by RequireAuth.
func RawToken(c *gin.Context) string {
	v, _ := c.Get("raw_token")
	s, _ := v.(string)
	return s
}
