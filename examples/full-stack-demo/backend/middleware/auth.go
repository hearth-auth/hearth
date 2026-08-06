// Package middleware provides Gin middleware for JWT authentication and RBAC.
package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// KeyRawToken is the gin.Context key under which the raw Bearer token string
// is stored after successful authentication.
//
// Downstream handlers forward this raw token to Hearth's Admin API so the
// original signature is preserved — re-serializing the parsed token would risk
// stripping claims or changing the canonical form, which could break Hearth's
// validation on the admin side.
const KeyRawToken = "raw_token"

// JWKSValidator validates JWTs against a cached JWKS key set.
//
// Why JWKS instead of a shared secret? Hearth signs tokens with Ed25519
// (asymmetric). The backend only needs the public key — it can verify signatures
// without ever seeing the private key. JWKS is the standard way to publish those
// public keys; fetching them from Hearth at startup means there is no out-of-band
// key distribution step.
//
// The key set is refreshed automatically on a key-miss (handles key rotation).
type JWKSValidator struct {
	// mu guards keySet during concurrent reads and during rotation replacement.
	// Reads hold a read-lock so they don't block each other; rotation holds a
	// write-lock only for the brief pointer swap.
	mu      sync.RWMutex
	keySet  jwk.Set
	jwksURL string

	// revoker, when set, adds revocation-aware validation after the local
	// signature+expiry check. nil leaves the validator signature-only (the
	// insufficient behavior HEA-2094 fixes — kept as an explicit opt-out so the
	// contrast is visible in the demo).
	revoker *RevocationChecker
}

// NewJWKSValidator fetches the JWKS from jwksURL and returns a ready validator.
//
// Fetching eagerly at startup ensures the server fails fast if Hearth is
// unreachable, rather than accepting requests and returning 401 on every one.
// Call this once at startup — subsequent key rotations are handled automatically.
func NewJWKSValidator(ctx context.Context, jwksURL string) (*JWKSValidator, error) {
	set, err := jwk.Fetch(ctx, jwksURL)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS from %s: %w", jwksURL, err)
	}
	return &JWKSValidator{keySet: set, jwksURL: jwksURL}, nil
}

// WithRevocationCheck enables revocation-aware validation: after the local
// signature+expiry check passes, Auth() additionally confirms the token is
// still active at Hearth via introspection (see RevocationChecker). Returns the
// receiver for chaining. Passing nil leaves the validator signature-only.
//
// Signature validation alone cannot detect revocation — a logged-out or killed
// session still carries a cryptographically valid token until it expires — so a
// resource server that cares about revocation MUST layer this check on top.
func (v *JWKSValidator) WithRevocationCheck(r *RevocationChecker) *JWKSValidator {
	v.revoker = r
	return v
}

// Auth returns a Gin middleware that validates the Authorization: Bearer token
// against the JWKS. On success the raw token string is stored under KeyRawToken.
func (v *JWKSValidator) Auth() gin.HandlerFunc {
	return func(c *gin.Context) {
		raw, ok := extractBearer(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "missing or malformed Authorization header",
			})
			return
		}

		// Try the cached key set first (fast path, no I/O).
		// On failure, re-fetch once from Hearth to handle key rotation — Hearth
		// rotates its Ed25519 signing key periodically. Without this re-fetch, a
		// deployment that rotates the key would force a backend restart to pick up
		// the new JWKS. One re-fetch per rotation event is an acceptable trade-off
		// vs. fetching on every request (which would add latency and DOS surface).
		_, err := v.parse(raw)
		if err != nil {
			if refreshed, fetchErr := jwk.Fetch(c.Request.Context(), v.jwksURL); fetchErr == nil {
				v.mu.Lock()
				v.keySet = refreshed
				v.mu.Unlock()
				_, err = v.parse(raw)
			}
		}
		if err != nil {
			// Return a generic 401 — do not echo the parse error to the client,
			// as error details can leak information about expected token structure.
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		// Signature + expiry are valid, but a JWT cannot express revocation: a
		// session logged out or killed at Hearth after this token was minted
		// still carries a valid signature until it expires. When a revocation
		// checker is configured, confirm the token is still active at Hearth
		// (RFC 7662 introspection, short-TTL cached). Fail closed: an
		// introspection outage rejects the request (503) rather than silently
		// falling back to signature-only acceptance.
		if v.revoker != nil {
			active, rerr := v.revoker.IsActive(c.Request.Context(), raw)
			if rerr != nil {
				c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
					"error": "token validation temporarily unavailable",
				})
				return
			}
			if !active {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token revoked"})
				return
			}
		}

		c.Set(KeyRawToken, raw)
		c.Next()
	}
}

func (v *JWKSValidator) parse(raw string) (jwt.Token, error) {
	v.mu.RLock()
	ks := v.keySet
	v.mu.RUnlock()
	return jwt.Parse([]byte(raw), jwt.WithKeySet(ks))
}

func extractBearer(c *gin.Context) (string, bool) {
	// Validate the Authorization scheme before touching the token value.
	// Rejecting non-Bearer credentials here prevents accidentally accepting
	// Basic or Digest auth strings as JWTs, which would produce confusing
	// parse errors rather than a clean 401.
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
