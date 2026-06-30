package hearth

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	jwksDefaultTTL = 5 * time.Minute
	jwksMaxAge     = 24 * time.Hour
)

type jwksKeyEntry struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	X   string `json:"x"`
}

type jwksDocument struct {
	Keys []json.RawMessage `json:"keys"`
}

// JwksCache is a spec §2 JWKS key cache for Ed25519/OKP signing keys.
//
// Keys are stored by kid. Old keys are never discarded (spec §2 rule 1 —
// supports key rotation). The TTL is read from Cache-Control: max-age on each
// fetch and capped at 24 h. On a kid cache miss, the endpoint is re-fetched
// once before returning an error (spec §2 rule 3).
type JwksCache struct {
	url           string
	http          *http.Client
	configuredTTL time.Duration

	mu        sync.RWMutex
	keys      map[string]ed25519.PublicKey
	fetchedAt time.Time
	ttl       time.Duration // effective TTL, updated on each fetch
}

// NewJwksCache creates a JWKS cache for the given URL.
//
// If httpClient is nil a default client with a 10 s timeout is used.
// If ttl is 0 the default (5 min, or Cache-Control from the server) applies.
func NewJwksCache(url string, httpClient *http.Client, ttl time.Duration) *JwksCache {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	if ttl == 0 {
		ttl = jwksDefaultTTL
	}
	return &JwksCache{
		url:           url,
		http:          httpClient,
		configuredTTL: ttl,
		keys:          make(map[string]ed25519.PublicKey),
		ttl:           ttl,
	}
}

// GetKey returns the Ed25519 public key for the given kid.
//
// If the cache is stale it is refreshed first. Whether the staleness-triggered
// refresh found the key or not, if the key is still absent a second fetch is
// performed (spec §2 rule 3: re-fetch once on cache miss). If the key is still
// not found after that single re-fetch, JWKSFetchError is returned.
func (j *JwksCache) GetKey(kid string) (ed25519.PublicKey, error) {
	j.mu.RLock()
	stale := j.fetchedAt.IsZero() || time.Since(j.fetchedAt) > j.ttl
	key, found := j.keys[kid]
	j.mu.RUnlock()

	if stale {
		if err := j.fetch(); err != nil {
			return nil, err
		}
		j.mu.RLock()
		key, found = j.keys[kid]
		j.mu.RUnlock()
	}

	if !found {
		// Spec §2 rule 3: re-fetch once on cache miss (covers both cold-start
		// misses and rotation-induced misses on an otherwise fresh cache).
		if err := j.fetch(); err != nil {
			return nil, err
		}
		j.mu.RLock()
		key, found = j.keys[kid]
		j.mu.RUnlock()
		if !found {
			return nil, &JWKSFetchError{URL: j.url, Cause: fmt.Errorf("key not found: kid=%q", kid)}
		}
	}

	return key, nil
}

func (j *JwksCache) fetch() error {
	resp, err := j.http.Get(j.url)
	if err != nil {
		return &JWKSFetchError{URL: j.url, Cause: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return &JWKSFetchError{URL: j.url, Cause: fmt.Errorf("HTTP %d", resp.StatusCode)}
	}

	// Honour Cache-Control: max-age, fall back to configured TTL.
	ttl := j.configuredTTL
	if cc := resp.Header.Get("Cache-Control"); cc != "" {
		for _, part := range strings.Split(cc, ",") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "max-age=") {
				if secs, parseErr := strconv.ParseFloat(part[8:], 64); parseErr == nil {
					ttl = time.Duration(secs * float64(time.Second))
				}
			}
		}
	}
	if ttl > jwksMaxAge {
		ttl = jwksMaxAge // spec §2 rule 5
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &JWKSFetchError{URL: j.url, Cause: err}
	}

	var doc jwksDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return &JWKSFetchError{URL: j.url, Cause: fmt.Errorf("parse failed: %w", err)}
	}

	newKeys := make(map[string]ed25519.PublicKey)
	for _, rawKey := range doc.Keys {
		var entry jwksKeyEntry
		if err := json.Unmarshal(rawKey, &entry); err != nil {
			continue
		}
		if entry.Kty != "OKP" {
			// Spec §2 rule 6: skip unrecognised key types without error.
			continue
		}
		if entry.Crv != "Ed25519" {
			continue
		}
		x, err := base64.RawURLEncoding.DecodeString(entry.X)
		if err != nil {
			// Try padded variant (some issuers emit padding).
			x, err = base64.URLEncoding.DecodeString(entry.X)
			if err != nil {
				continue
			}
		}
		if len(x) != ed25519.PublicKeySize {
			continue
		}
		newKeys[entry.Kid] = ed25519.PublicKey(x)
	}

	j.mu.Lock()
	// Merge: never discard previously cached keys (spec §2 rule 1).
	for kid, key := range newKeys {
		j.keys[kid] = key
	}
	j.ttl = ttl
	j.fetchedAt = time.Now()
	j.mu.Unlock()

	return nil
}
