package hearth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// getJwksCache lazily creates the JWKS cache.
//
// If jwksURLOverride is set (test use), that URL is used directly.
// Otherwise the JWKS URI is read from the OIDC discovery document.
func (c *Client) getJwksCache(ctx context.Context) (*JwksCache, error) {
	c.jwksMu.Lock()
	defer c.jwksMu.Unlock()

	if c.jwksCache != nil {
		return c.jwksCache, nil
	}

	jwksURL := c.jwksURLOverride
	if jwksURL == "" {
		disc, err := c.getDiscovery(ctx)
		if err != nil {
			// Fall back to the well-known default path.
			jwksURL = c.baseURL + "/.well-known/jwks.json"
		} else if disc.JwksURI != "" {
			jwksURL = disc.JwksURI
		} else {
			jwksURL = c.baseURL + "/.well-known/jwks.json"
		}
	}

	c.jwksCache = NewJwksCache(jwksURL, c.http, c.jwksTTL)
	return c.jwksCache, nil
}

// getDiscovery lazily fetches and caches the OIDC discovery document.
func (c *Client) getDiscovery(ctx context.Context) (*oidcDiscovery, error) {
	c.discMu.Lock()
	defer c.discMu.Unlock()

	if c.discDoc != nil {
		return c.discDoc, nil
	}

	discURL := c.baseURL + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discURL, nil)
	if err != nil {
		return nil, &DiscoveryError{URL: discURL, Cause: err}
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, &DiscoveryError{URL: discURL, Cause: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &DiscoveryError{URL: discURL, Cause: fmt.Errorf("HTTP %d", resp.StatusCode)}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &DiscoveryError{URL: discURL, Cause: err}
	}

	var doc oidcDiscovery
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, &DiscoveryError{URL: discURL, Cause: err}
	}

	c.discDoc = &doc
	return &doc, nil
}

// VerifyToken verifies a JWT using JWKS-based Ed25519/EdDSA local signature
// verification and the mandatory five validation steps from spec §2.
//
// Optional audience — when supplied, the aud claim must contain it (step 4).
// Returns a typed Claims on success, or one of the §5 typed errors on failure.
//
// This method MUST NOT silently fall back to introspection.
func (c *Client) VerifyToken(ctx context.Context, token string, audience ...string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, &TokenInvalidError{Reason: "expected three dot-separated segments"}
	}

	// 1. Decode and validate the JWT header.
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		headerBytes, err = base64.URLEncoding.DecodeString(parts[0])
		if err != nil {
			return nil, &TokenInvalidError{Reason: "invalid header base64url encoding"}
		}
	}

	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, &TokenInvalidError{Reason: "invalid header JSON: " + err.Error()}
	}

	// Reject any algorithm that is not EdDSA (spec §2).
	if header.Alg != "EdDSA" {
		return nil, &TokenInvalidError{
			Reason: fmt.Sprintf("unsupported algorithm %q: only EdDSA is accepted", header.Alg),
		}
	}

	// 2. Look up the signing key from the JWKS cache.
	cache, err := c.getJwksCache(ctx)
	if err != nil {
		return nil, err
	}

	pubKey, err := cache.GetKey(header.Kid)
	if err != nil {
		return nil, err
	}

	// 3. Verify Ed25519 signature over header_b64.payload_b64 (RFC 8037).
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		sigBytes, err = base64.URLEncoding.DecodeString(parts[2])
		if err != nil {
			return nil, &TokenInvalidError{Reason: "invalid signature base64url encoding"}
		}
	}

	msg := []byte(parts[0] + "." + parts[1])
	if !ed25519.Verify(pubKey, msg, sigBytes) {
		return nil, &TokenInvalidError{Reason: "signature verification failed"}
	}

	// 4. Parse the payload into a typed Claims object.
	claims, err := ParseClaims(token)
	if err != nil {
		return nil, err
	}

	now := time.Now().Unix()

	// Step 1 (spec §2 validation order): verify exp.
	if claims.Expiry() != 0 && claims.Expiry() < now {
		return nil, &TokenExpiredError{ExpiredAt: claims.Expiry()}
	}

	// Step 2: verify iss matches the discovered issuer.
	issuer, err := c.resolveIssuer(ctx)
	if err != nil {
		// Could not discover — use baseURL as best-effort fallback.
		issuer = c.baseURL
	}
	if claims.Issuer() != issuer {
		return nil, &TokenIssuerError{Expected: issuer, Actual: claims.Issuer()}
	}

	// Step 3: verify aud (only when caller supplied an expected audience).
	if len(audience) > 0 && audience[0] != "" {
		found := false
		for _, aud := range claims.Audiences() {
			if aud == audience[0] {
				found = true
				break
			}
		}
		if !found {
			return nil, &TokenAudienceError{Expected: audience[0], Actual: claims.Audiences()}
		}
	}

	// Step 4: verify iat is not in the future (5 s clock skew allowed).
	if claims.IssuedAt() != 0 && claims.IssuedAt() > now+5 {
		return nil, &TokenNotYetValidError{NotBefore: claims.IssuedAt()}
	}

	return claims, nil
}

// resolveIssuer returns the issuer URL: discovered > baseURL fallback.
func (c *Client) resolveIssuer(ctx context.Context) (string, error) {
	disc, err := c.getDiscovery(ctx)
	if err != nil {
		return "", err
	}
	if disc.Issuer != "" {
		return disc.Issuer, nil
	}
	return c.baseURL, nil
}
