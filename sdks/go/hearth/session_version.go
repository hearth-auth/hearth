package hearth

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"sync"
	"time"
)

// SessionVersionConfig configures the client-side session-version cache
// (RFC HEA-930 § 13).
//
// When Enabled is true the SDK fetches a snapshot of {sessionId → minSV}
// on startup, then polls the delta feed at PollIntervalMs intervals.
// Every permission check in the middleware additionally validates the `sv`
// claim against the local cache — no per-request network hop required.
type SessionVersionConfig struct {
	// Enabled toggles session-version validation.
	Enabled bool
	// PollIntervalMs is how often to fetch delta entries, in milliseconds.
	PollIntervalMs int
	// StaleThresholdMs is the maximum cache age before it is considered stale,
	// in milliseconds. Must be greater than PollIntervalMs.
	// Recommended: PollIntervalMs × 3.
	StaleThresholdMs int
	// OnStale controls behaviour when the cache exceeds StaleThresholdMs:
	// "reject" (default) — return 401 Unauthorized.
	// "introspect"       — fall back to per-request introspection.
	OnStale string
	// ServiceToken is a service-to-service access token with the
	// hearth.sv_feed scope. Required when Enabled is true.
	ServiceToken string
}

// SvCheckResult is the outcome of a session-version check.
type SvCheckResult int

const (
	// SvOK: token sv ≥ minSV for the session.
	SvOK SvCheckResult = iota
	// SvRevoked: token sv < minSV for the session.
	SvRevoked
	// SvStale: local cache age exceeds StaleThresholdMs.
	SvStale
	// SvSkip: no sv claim in the token (backward compat, RFC § 8.2).
	SvSkip
)

// wire shapes for the session-version endpoints.

type svSnapshotResponse struct {
	Realm      string            `json:"realm"`
	CurrentSeq int64             `json:"current_seq"`
	Versions   map[string]uint64 `json:"versions"`
}

type svDeltaEntry struct {
	Seq       int64  `json:"seq"`
	SessionID string `json:"session_id"`
	MinSV     uint64 `json:"min_sv"`
	BumpedAt  int64  `json:"bumped_at"`
}

type svDeltaResponse struct {
	Realm   string         `json:"realm"`
	NextSeq int64          `json:"next_seq"`
	Deltas  []svDeltaEntry `json:"deltas"`
}

// SessionVersionCache maintains a local {sessionId → minSV} map, refreshed
// by polling the Hearth delta feed. It provides fast, synchronous sv checks
// on the hot path via Check().
type SessionVersionCache struct {
	mu          sync.RWMutex
	versions    map[string]uint64
	seq         int64
	lastRefresh time.Time

	cfg     SessionVersionConfig
	baseURL string
	realmID string
	http    *http.Client
	done    chan struct{}
}

// newSessionVersionCache creates a SessionVersionCache but does not start
// the background goroutine. Call Start() to begin polling.
func newSessionVersionCache(
	baseURL, realmID string,
	cfg SessionVersionConfig,
	httpClient *http.Client,
) *SessionVersionCache {
	return &SessionVersionCache{
		versions: make(map[string]uint64),
		cfg:      cfg,
		baseURL:  baseURL,
		realmID:  realmID,
		http:     httpClient,
		done:     make(chan struct{}),
	}
}

// Start fetches the initial snapshot in a background goroutine, then polls
// at cfg.PollIntervalMs intervals. Snapshot errors are non-fatal; the cache
// age will eventually trip the stale threshold (fail-closed per § 8.1).
func (c *SessionVersionCache) Start() {
	go func() {
		ctx := context.Background()
		_ = c.fetchSnapshot(ctx)
		ticker := time.NewTicker(time.Duration(c.cfg.PollIntervalMs) * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-c.done:
				return
			case <-ticker.C:
				_ = c.poll(ctx)
			}
		}
	}()
}

// Stop signals the background goroutine to exit. It is safe to call once.
func (c *SessionVersionCache) Stop() {
	close(c.done)
}

// Age returns the time elapsed since the cache was last successfully refreshed.
// Returns a very large duration (10 years) when the cache has never been seeded.
func (c *SessionVersionCache) Age() time.Duration {
	c.mu.RLock()
	t := c.lastRefresh
	c.mu.RUnlock()
	if t.IsZero() {
		return 24 * time.Hour * 365 * 10
	}
	return time.Since(t)
}

// Check validates the sv claim against the local cache.
//
//   - svPresent=false → SvSkip (backward compat, RFC § 8.2).
//   - Age() > StaleThresholdMs → SvStale.
//   - sv < minSV for the session → SvRevoked.
//   - Otherwise → SvOK.
//
// Unknown session IDs default to minSV=1 (RFC § 3.2).
func (c *SessionVersionCache) Check(svPresent bool, sv uint64, sessionID string) SvCheckResult {
	if !svPresent {
		return SvSkip
	}
	if c.Age() > time.Duration(c.cfg.StaleThresholdMs)*time.Millisecond {
		return SvStale
	}
	c.mu.RLock()
	minSV, ok := c.versions[sessionID]
	c.mu.RUnlock()
	if !ok {
		minSV = 1
	}
	if sv < minSV {
		return SvRevoked
	}
	return SvOK
}

// ── Private ──────────────────────────────────────────────────────────────────

func (c *SessionVersionCache) fetchSnapshot(ctx context.Context) error {
	url := fmt.Sprintf("%s/oauth/session-versions/snapshot?realm=%s", c.baseURL, c.realmID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.ServiceToken)

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sv snapshot failed: HTTP %d", resp.StatusCode)
	}

	var data svSnapshotResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return err
	}

	c.mu.Lock()
	c.versions = make(map[string]uint64, len(data.Versions))
	maps.Copy(c.versions, data.Versions)
	c.seq = data.CurrentSeq
	c.lastRefresh = time.Now()
	c.mu.Unlock()
	return nil
}

func (c *SessionVersionCache) poll(ctx context.Context) error {
	c.mu.RLock()
	seq := c.seq
	c.mu.RUnlock()

	url := fmt.Sprintf("%s/oauth/session-versions?since=%d&realm=%s", c.baseURL, seq, c.realmID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.ServiceToken)

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNoContent:
		c.mu.Lock()
		c.lastRefresh = time.Now()
		c.mu.Unlock()
		return nil

	case http.StatusBadRequest:
		// Sequence predates retention window — must re-seed from snapshot.
		return c.fetchSnapshot(ctx)

	case http.StatusOK:
		var data svDeltaResponse
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			return err
		}
		c.mu.Lock()
		for _, d := range data.Deltas {
			c.versions[d.SessionID] = d.MinSV
		}
		c.seq = data.NextSeq
		c.lastRefresh = time.Now()
		c.mu.Unlock()
		return nil

	default:
		return fmt.Errorf("sv delta poll failed: HTTP %d", resp.StatusCode)
	}
}
