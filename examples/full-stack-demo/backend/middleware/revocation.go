package middleware

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// RevocationChecker adds revocation-aware validation on top of the local JWKS
// signature check.
//
// A JWT is self-contained: verifying its Ed25519 signature and `exp` proves the
// token was minted by Hearth and has not expired — but it says NOTHING about
// whether the session behind the token was revoked at Hearth *after* issuance.
// A user who logs out, an admin who kills a session, or a leaked-token
// revocation are all invisible to signature-only validation until the token
// expires naturally. That is why a signature-only resource server keeps
// honoring a revoked-but-unexpired token (the exact gap HEA-2094 closes).
//
// To close it, the resource server asks Hearth's introspection endpoint
// (RFC 7662) whether the token is still active. Because a network round-trip on
// every request would put Hearth on the request hot path and add latency plus a
// failure dependency, each verdict is cached for a short TTL.
//
// # The latency vs. consistency tradeoff
//
// The cache TTL bounds how stale the revocation view may be: a token revoked at
// Hearth is still accepted here for up to TTL after its last cached
// introspection. A shorter TTL propagates revocation faster but calls Hearth
// more often; a longer TTL is cheaper but widens the window in which a revoked
// token is honored. Choose the TTL from your revocation-latency budget — a few
// seconds for security-sensitive APIs, tens of seconds where call cost
// dominates. A TTL of 0 disables caching (introspect on every request: strongest
// consistency, highest cost). The demo defaults to a short TTL so a revocation
// performed in one browser tab is observable in another within seconds.
type RevocationChecker struct {
	introspectURL string
	httpClient    *http.Client
	ttl           time.Duration

	// nowFunc returns the current time; overridable in tests. Defaults to
	// time.Now.
	nowFunc func() time.Time

	mu    sync.Mutex
	cache map[string]revEntry
}

// revEntry is a cached introspection verdict and the instant it goes stale.
type revEntry struct {
	active    bool
	expiresAt time.Time
}

// NewRevocationChecker returns a checker that introspects tokens at
// introspectURL — Hearth's realm-scoped `POST /realms/{realm}/introspect`
// endpoint, which requires no client credentials and returns `{"active": bool}`
// — and caches each verdict for ttl. A ttl of 0 disables caching.
func NewRevocationChecker(introspectURL string, ttl time.Duration) *RevocationChecker {
	return &RevocationChecker{
		introspectURL: introspectURL,
		httpClient:    &http.Client{Timeout: 5 * time.Second},
		ttl:           ttl,
		nowFunc:       time.Now,
		cache:         make(map[string]revEntry),
	}
}

// IsActive reports whether Hearth still considers rawToken active — i.e. neither
// revoked nor expired — consulting the short-TTL cache first.
//
// It returns an error only when the introspection call itself fails (network
// error, non-2xx, unparseable body). Callers MUST fail closed on error:
// treating an introspection failure as "active" would reopen the very
// revocation gap this check exists to close.
func (r *RevocationChecker) IsActive(ctx context.Context, rawToken string) (bool, error) {
	key := cacheKey(rawToken)
	now := r.nowFunc()

	if r.ttl > 0 {
		r.mu.Lock()
		if e, ok := r.cache[key]; ok && now.Before(e.expiresAt) {
			r.mu.Unlock()
			return e.active, nil
		}
		r.mu.Unlock()
	}

	active, err := r.introspect(ctx, rawToken)
	if err != nil {
		return false, err
	}

	if r.ttl > 0 {
		r.mu.Lock()
		r.cache[key] = revEntry{active: active, expiresAt: now.Add(r.ttl)}
		r.mu.Unlock()
	}
	return active, nil
}

// introspect performs a single RFC 7662 introspection round-trip.
func (r *RevocationChecker) introspect(ctx context.Context, rawToken string) (bool, error) {
	body, err := json.Marshal(map[string]string{"token": rawToken})
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.introspectURL, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("introspection request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return false, fmt.Errorf("introspection returned HTTP %d", resp.StatusCode)
	}

	var out struct {
		Active bool `json:"active"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, fmt.Errorf("decode introspection response: %w", err)
	}
	return out.Active, nil
}

// cacheKey hashes the raw token so the cache map never retains bearer secrets as
// plaintext keys.
func cacheKey(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(sum[:])
}
