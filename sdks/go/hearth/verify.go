package hearth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
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
// verification through go-jose and the mandatory five validation steps from spec §2.
//
// Optional audience — when supplied, the aud claim must contain it (step 4).
// Returns a typed Claims on success, or one of the §5 typed errors on failure.
//
// This method MUST NOT silently fall back to introspection.
func (c *Client) VerifyToken(ctx context.Context, token string, audience ...string) (*Claims, error) {
	if strings.Count(token, ".") != 2 {
		return nil, &TokenInvalidError{Reason: "expected three dot-separated segments"}
	}

	// 1. Parse the compact JWS. go-jose enforces the algorithm allow-list
	// (EdDSA only, spec §2 — so `alg: none` and RS256 ID tokens are refused)
	// and rejects unknown critical headers (RFC 7515 §4.1.11).
	jws, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		return nil, &TokenInvalidError{Reason: "invalid token: " + err.Error()}
	}
	if len(jws.Headers) != 1 {
		return nil, &TokenInvalidError{Reason: "expected exactly one signature"}
	}

	// 2. Look up the signing key by kid from the JWKS cache.
	cache, err := c.getJwksCache(ctx)
	if err != nil {
		return nil, err
	}

	pubKey, err := cache.GetKey(jws.Headers[0].KeyID)
	if errors.Is(err, errKidNotFound) {
		// SDK.md §5: the JWKS endpoint answered; the token names a key it
		// does not publish. That is a bad token, not a fetch failure.
		return nil, &TokenInvalidError{Reason: "unknown signing key: kid=" + jws.Headers[0].KeyID}
	}
	if err != nil {
		return nil, err
	}

	// 3. Verify the Ed25519 signature (RFC 8037) through go-jose.
	var registered jwt.Claims
	if err := jws.Claims(pubKey, &registered); err != nil {
		return nil, &TokenInvalidError{Reason: "signature verification failed"}
	}

	// 4. Parse the payload into a typed Claims object.
	claims, err := ParseClaims(token)
	if err != nil {
		return nil, err
	}

	// 5. Registered claims (spec §2): go-jose checks iss, aud, nbf, exp and
	// iat with one 5 s clock-skew allowance.
	issuer, err := c.resolveIssuer(ctx)
	if err != nil {
		// Could not discover — use baseURL as best-effort fallback.
		issuer = c.baseURL
	}
	expected := jwt.Expected{Issuer: issuer, Time: c.clock()}
	if len(audience) > 0 && audience[0] != "" {
		expected.AnyAudience = jwt.Audience{audience[0]}
	}

	switch err := registered.ValidateWithLeeway(expected, clockSkew); {
	case err == nil:
		return claims, nil
	case errors.Is(err, jwt.ErrExpired):
		return nil, &TokenExpiredError{ExpiredAt: claims.Expiry()}
	case errors.Is(err, jwt.ErrInvalidIssuer):
		return nil, &TokenIssuerError{Expected: issuer, Actual: claims.Issuer()}
	case errors.Is(err, jwt.ErrInvalidAudience):
		return nil, &TokenAudienceError{Expected: audience[0], Actual: claims.Audiences()}
	case errors.Is(err, jwt.ErrNotValidYet):
		return nil, &TokenNotYetValidError{NotBefore: claims.NotBefore()}
	case errors.Is(err, jwt.ErrIssuedInTheFuture):
		return nil, &TokenNotYetValidError{NotBefore: claims.IssuedAt()}
	default:
		return nil, &TokenInvalidError{Reason: "invalid registered claims: " + err.Error()}
	}
}

// errKidNotFound marks a JWKS lookup whose kid is absent after the re-fetch.
var errKidNotFound = errors.New("key not found")

// clockSkew is the one allowance applied to exp, nbf and iat (spec §2).
const clockSkew = 5 * time.Second

// clock returns the time VerifyToken validates against.
func (c *Client) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
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
