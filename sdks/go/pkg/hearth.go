// Package hearth provides JWT verification middleware for Hearth authorization servers.
package hearth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type contextKey string

const ClaimsKey contextKey = "hearth:claims"

// Config holds the client configuration.
type Config struct {
	Issuer   string
	Audience string
	// JWKSUri overrides auto-discovery; leave empty to discover from /.well-known/openid-configuration.
	JWKSUri    string
	CacheTTL   time.Duration
	HTTPClient *http.Client
}

type discovery struct {
	JWKSURI string `json:"jwks_uri"`
	Issuer  string `json:"issuer"`
}

// Client performs JWKS-backed JWT verification.
type Client struct {
	config    Config
	mu        sync.RWMutex
	keySet    jwk.Set
	fetchedAt time.Time
	httpClient *http.Client
}

// NewClient creates a new Hearth client.
func NewClient(config Config) *Client {
	if config.CacheTTL == 0 {
		config.CacheTTL = 10 * time.Minute
	}
	hc := config.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	return &Client{config: config, httpClient: hc}
}

func (c *Client) fetchDiscovery() (discovery, error) {
	url := strings.TrimRight(c.config.Issuer, "/") + "/.well-known/openid-configuration"
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return discovery{}, fmt.Errorf("discovery fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return discovery{}, fmt.Errorf("discovery HTTP %d", resp.StatusCode)
	}
	var d discovery
	return d, json.NewDecoder(resp.Body).Decode(&d)
}

func (c *Client) getJWKSUri() (string, error) {
	if c.config.JWKSUri != "" {
		return c.config.JWKSUri, nil
	}
	d, err := c.fetchDiscovery()
	if err != nil {
		return "", err
	}
	return d.JWKSURI, nil
}

func (c *Client) refreshKeys() error {
	uri, err := c.getJWKSUri()
	if err != nil {
		return err
	}
	set, err := jwk.Fetch(context.Background(), uri, jwk.WithHTTPClient(c.httpClient))
	if err != nil {
		return fmt.Errorf("JWKS fetch: %w", err)
	}
	c.mu.Lock()
	c.keySet = set
	c.fetchedAt = time.Now()
	c.mu.Unlock()
	return nil
}

func (c *Client) keys() (jwk.Set, error) {
	c.mu.RLock()
	set := c.keySet
	age := time.Since(c.fetchedAt)
	c.mu.RUnlock()

	if set == nil || age > c.config.CacheTTL {
		if err := c.refreshKeys(); err != nil {
			return nil, err
		}
		c.mu.RLock()
		set = c.keySet
		c.mu.RUnlock()
	}
	return set, nil
}

// VerifyToken verifies a JWT and returns the parsed token.
func (c *Client) VerifyToken(tokenStr string) (jwt.Token, error) {
	keys, err := c.keys()
	if err != nil {
		return nil, err
	}

	opts := []jwt.ParseOption{
		jwt.WithKeySet(keys),
		jwt.WithValidate(true),
		jwt.WithIssuer(c.config.Issuer),
	}
	if c.config.Audience != "" {
		opts = append(opts, jwt.WithAudience(c.config.Audience))
	}

	token, err := jwt.Parse([]byte(tokenStr), opts...)
	if err != nil {
		// Retry once after cache reset in case of key rotation
		if refreshErr := c.refreshKeys(); refreshErr != nil {
			return nil, err
		}
		keys2, _ := c.keys()
		opts[0] = jwt.WithKeySet(keys2)
		token, err = jwt.Parse([]byte(tokenStr), opts...)
	}
	return token, err
}

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(auth, "Bearer ")
}

// MiddlewareOptions controls optional behaviour of the HTTP middleware.
type MiddlewareOptions struct {
	// AcceptCookieToken enables falling back to the hearth_access_token HttpOnly
	// cookie when no Authorization: Bearer header is present. Enable this on
	// resource servers that serve SPAs configured with token_delivery: cookie.
	// The Authorization header always takes priority.
	AcceptCookieToken bool
}

func extractToken(r *http.Request, opts MiddlewareOptions) string {
	if t := extractBearerToken(r); t != "" {
		return t
	}
	if opts.AcceptCookieToken {
		if cookie, err := r.Cookie("hearth_access_token"); err == nil {
			return cookie.Value
		}
	}
	return ""
}

// Middleware returns a net/http middleware that validates Bearer tokens.
func (c *Client) Middleware(next http.Handler) http.Handler {
	return c.MiddlewareWithOptions(next, MiddlewareOptions{})
}

// MiddlewareWithOptions returns a net/http middleware with configurable options.
// Use this variant when the Hearth client is configured with token_delivery: cookie
// and you want the resource server to accept the hearth_access_token cookie.
func (c *Client) MiddlewareWithOptions(next http.Handler, opts MiddlewareOptions) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenStr := extractToken(r, opts)
		if tokenStr == "" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		token, err := c.VerifyToken(tokenStr)
		if err != nil {
			http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), ClaimsKey, token)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// TokenFromContext returns the verified JWT token stored in the context by Middleware.
func TokenFromContext(ctx context.Context) (jwt.Token, bool) {
	t, ok := ctx.Value(ClaimsKey).(jwt.Token)
	return t, ok
}
