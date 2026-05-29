package hearth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func snapshotHandler(versions map[string]uint64, seq int64) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/session-versions/snapshot" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(svSnapshotResponse{
			Realm:      "r1",
			CurrentSeq: seq,
			Versions:   versions,
		})
	}
}

// buildCache creates a SessionVersionCache pointed at srv.URL with sensible defaults.
func buildCache(t *testing.T, srv *httptest.Server, cfg SessionVersionConfig) *SessionVersionCache {
	t.Helper()
	return newSessionVersionCache(srv.URL, "r1", cfg, &http.Client{})
}

const (
	testPollMs  = 50
	testStaleMs = 500
)

func testCfg() SessionVersionConfig {
	return SessionVersionConfig{
		Enabled:          true,
		PollIntervalMs:   testPollMs,
		StaleThresholdMs: testStaleMs,
		OnStale:          "reject",
		ServiceToken:     "svc-token",
	}
}

// ── SessionVersionCache unit tests ───────────────────────────────────────────

func TestSvCacheSnapshotSeedsVersions(t *testing.T) {
	srv := httptest.NewServer(snapshotHandler(map[string]uint64{
		"sess_01": 1,
		"sess_02": 5,
	}, 10))
	defer srv.Close()

	cache := buildCache(t, srv, testCfg())
	cache.Start()
	defer cache.Stop()

	// Give the snapshot goroutine time to complete.
	time.Sleep(100 * time.Millisecond)

	// sess_01 min=1: sv=1 → ok.
	if r := cache.Check(true, 1, "sess_01"); r != SvOK {
		t.Fatalf("expected SvOK for sv=1 min=1, got %v", r)
	}
	// sess_02 min=5: sv=4 → revoked.
	if r := cache.Check(true, 4, "sess_02"); r != SvRevoked {
		t.Fatalf("expected SvRevoked for sv=4 min=5, got %v", r)
	}
	// sess_02 min=5: sv=5 → ok.
	if r := cache.Check(true, 5, "sess_02"); r != SvOK {
		t.Fatalf("expected SvOK for sv=5 min=5, got %v", r)
	}
}

func TestSvCacheAppliesDeltas(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/session-versions/snapshot":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(svSnapshotResponse{
				Realm:      "r1",
				CurrentSeq: 10,
				Versions:   map[string]uint64{"sess_A": 1},
			})
		case "/oauth/session-versions":
			callCount++
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(svDeltaResponse{
				Realm:   "r1",
				NextSeq: 12,
				Deltas: []svDeltaEntry{
					{Seq: 11, SessionID: "sess_A", MinSV: 4, BumpedAt: 1700000900},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cache := buildCache(t, srv, testCfg())
	cache.Start()
	defer cache.Stop()

	// Wait for snapshot + at least one poll cycle.
	time.Sleep(time.Duration(testPollMs)*2*time.Millisecond + 50*time.Millisecond)

	// Delta bumped sess_A min → 4.
	if r := cache.Check(true, 3, "sess_A"); r != SvRevoked {
		t.Fatalf("expected SvRevoked after delta, got %v", r)
	}
	if r := cache.Check(true, 4, "sess_A"); r != SvOK {
		t.Fatalf("expected SvOK for sv=4 after delta, got %v", r)
	}
	if callCount == 0 {
		t.Fatal("expected at least one delta poll call")
	}
}

func TestSvCacheNoContentUpdatesLastRefresh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/session-versions/snapshot":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(svSnapshotResponse{
				Realm: "r1", CurrentSeq: 5, Versions: map[string]uint64{},
			})
		case "/oauth/session-versions":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cache := buildCache(t, srv, testCfg())
	cache.Start()
	defer cache.Stop()

	time.Sleep(time.Duration(testPollMs)*2*time.Millisecond + 50*time.Millisecond)

	// Cache was refreshed — age should be small.
	if age := cache.Age(); age > 500*time.Millisecond {
		t.Fatalf("expected age < 500ms after poll, got %s", age)
	}
}

func TestSvCacheBadRequestRefetches(t *testing.T) {
	pollCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/session-versions/snapshot":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(svSnapshotResponse{
				Realm:    "r1",
				CurrentSeq: 20,
				Versions: map[string]uint64{"sess_B": 5},
			})
		case "/oauth/session-versions":
			pollCount++
			if pollCount == 1 {
				w.WriteHeader(http.StatusBadRequest) // sequence too old
				return
			}
			// Second poll after re-snapshot succeeds with no deltas.
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cache := buildCache(t, srv, testCfg())
	cache.Start()
	defer cache.Stop()

	// Wait for initial snapshot + first poll (400) + second snapshot + second poll.
	time.Sleep(time.Duration(testPollMs)*3*time.Millisecond + 100*time.Millisecond)

	// After re-snapshot, sess_B min=5; sv=4 → revoked.
	if r := cache.Check(true, 4, "sess_B"); r != SvRevoked {
		t.Fatalf("expected SvRevoked, got %v", r)
	}
}

func TestSvCacheSkipWhenNoClaim(t *testing.T) {
	srv := httptest.NewServer(snapshotHandler(map[string]uint64{"sess_X": 99}, 1))
	defer srv.Close()

	cache := buildCache(t, srv, testCfg())
	cache.Start()
	defer cache.Stop()

	time.Sleep(100 * time.Millisecond)

	// svPresent=false → SvSkip regardless of cache contents.
	if r := cache.Check(false, 0, "sess_X"); r != SvSkip {
		t.Fatalf("expected SvSkip for absent sv, got %v", r)
	}
}

func TestSvCacheDefaultMinSvForUnknownSession(t *testing.T) {
	srv := httptest.NewServer(snapshotHandler(map[string]uint64{}, 1)) // empty
	defer srv.Close()

	cache := buildCache(t, srv, testCfg())
	cache.Start()
	defer cache.Stop()

	time.Sleep(100 * time.Millisecond)

	// Unknown session → minSV defaults to 1; sv=1 → ok.
	if r := cache.Check(true, 1, "brand_new"); r != SvOK {
		t.Fatalf("expected SvOK for unknown session sv=1, got %v", r)
	}
}

func TestSvCacheStaleDetection(t *testing.T) {
	// Server never responds — cache never refreshes.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Hang: don't respond.
	}))
	defer srv.Close()

	cfg := SessionVersionConfig{
		Enabled:          true,
		PollIntervalMs:   testPollMs,
		StaleThresholdMs: 10, // 10ms — extremely short so it trips immediately
		OnStale:          "reject",
		ServiceToken:     "svc-token",
	}
	cache := buildCache(t, srv, cfg)
	// Do NOT call Start — cache is never seeded (age = 10 years > 10ms threshold).

	if r := cache.Check(true, 1, "sess_stale"); r != SvStale {
		t.Fatalf("expected SvStale for unseeded cache, got %v", r)
	}
}

func TestSvCacheAgeNeverSeeded(t *testing.T) {
	// Create a cache but never start it — Age() should return a large value.
	cfg := testCfg()
	cache := newSessionVersionCache("http://localhost", "r1", cfg, &http.Client{})
	if cache.Age() < time.Hour {
		t.Fatalf("expected Age() to be very large when never seeded, got %s", cache.Age())
	}
}

// ── Middleware integration — sv claim in ModeEmbedded ─────────────────────

func TestMiddlewareEmbeddedSvRevokedReturns401(t *testing.T) {
	snapshotSrv := httptest.NewServer(snapshotHandler(map[string]uint64{"sess_R": 5}, 1))
	defer snapshotSrv.Close()

	c := NewClient(snapshotSrv.URL, "r1",
		WithSessionVersions(SessionVersionConfig{
			Enabled:          true,
			PollIntervalMs:   50,
			StaleThresholdMs: 5_000,
			OnStale:          "reject",
			ServiceToken:     "svc",
		}),
	)
	defer c.Stop()
	time.Sleep(100 * time.Millisecond) // wait for snapshot

	// Token has sv=3, but minSV for sess_R is 5 → revoked.
	var svVal uint64 = 3
	token := forgeJWT(t, map[string]any{
		"permissions": []string{"docs.edit"},
		"sv":          float64(svVal), // JSON numbers are float64
		"sid":         "sess_R",
	})
	rr := applyMiddleware(t, c, "docs.edit", MiddlewareConfig{ExpectedMode: ModeEmbedded}, token)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for revoked sv, got %d", rr.Code)
	}
}

func TestMiddlewareEmbeddedSvValidPasses(t *testing.T) {
	snapshotSrv := httptest.NewServer(snapshotHandler(map[string]uint64{"sess_V": 3}, 1))
	defer snapshotSrv.Close()

	c := NewClient(snapshotSrv.URL, "r1",
		WithSessionVersions(SessionVersionConfig{
			Enabled:          true,
			PollIntervalMs:   50,
			StaleThresholdMs: 5_000,
			OnStale:          "reject",
			ServiceToken:     "svc",
		}),
	)
	defer c.Stop()
	time.Sleep(100 * time.Millisecond)

	// sv=5 ≥ minSV=3 → ok.
	token := forgeJWT(t, map[string]any{
		"permissions": []string{"docs.edit"},
		"sv":          float64(5),
		"sid":         "sess_V",
	})
	rr := applyMiddleware(t, c, "docs.edit", MiddlewareConfig{ExpectedMode: ModeEmbedded}, token)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid sv, got %d", rr.Code)
	}
}

func TestMiddlewareEmbeddedNoSvClaimPasses(t *testing.T) {
	// No sv feature configured — backward compat.
	c := NewClient("http://localhost", "r1")
	token := forgeJWT(t, map[string]any{"permissions": []string{"docs.edit"}})
	rr := applyMiddleware(t, c, "docs.edit", MiddlewareConfig{ExpectedMode: ModeEmbedded}, token)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 when no sv claim, got %d", rr.Code)
	}
}

func TestMiddlewareEmbeddedSvStaleCacheReturns401(t *testing.T) {
	// Very short stale threshold — cache is stale immediately after creation.
	cfg := SessionVersionConfig{
		Enabled:          true,
		PollIntervalMs:   1_000,
		StaleThresholdMs: 1, // 1ms → stale almost immediately
		OnStale:          "reject",
		ServiceToken:     "svc",
	}
	// Server hangs — cache never gets seeded.
	hangSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer hangSrv.Close()

	c := NewClient(hangSrv.URL, "r1", WithSessionVersions(cfg))
	defer c.Stop()
	// Don't wait — stale threshold is 1ms which is already exceeded.

	token := forgeJWT(t, map[string]any{
		"permissions": []string{"docs.edit"},
		"sv":          float64(1),
		"sid":         "sess_stale",
	})
	rr := applyMiddleware(t, c, "docs.edit", MiddlewareConfig{ExpectedMode: ModeEmbedded}, token)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for stale cache, got %d", rr.Code)
	}
}

func TestMiddlewareEmbeddedCustomOnUnauthorized(t *testing.T) {
	cfg := SessionVersionConfig{
		Enabled:          true,
		PollIntervalMs:   1_000,
		StaleThresholdMs: 1,
		OnStale:          "reject",
		ServiceToken:     "svc",
	}
	hangSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer hangSrv.Close()

	c := NewClient(hangSrv.URL, "r1", WithSessionVersions(cfg))
	defer c.Stop()

	customCode := 0
	token := forgeJWT(t, map[string]any{"sv": float64(1), "sid": "sess_x", "permissions": []string{"x"}})
	rr := applyMiddleware(t, c, "x", MiddlewareConfig{
		ExpectedMode: ModeEmbedded,
		OnUnauthorized: func(w http.ResponseWriter, _ *http.Request) {
			customCode = 499
			w.WriteHeader(499)
		},
	}, token)
	if rr.Code != 499 || customCode != 499 {
		t.Fatalf("expected custom OnUnauthorized to be called, got %d", rr.Code)
	}
}

// ── errors ───────────────────────────────────────────────────────────────────

func TestSessionVersionRevokedError(t *testing.T) {
	err := &SessionVersionRevokedError{SessionID: "s", TokenSV: 2, MinSV: 5}
	if err.Error() == "" {
		t.Fatal("SessionVersionRevokedError.Error() returned empty string")
	}
}

func TestSessionVersionCacheStaleError(t *testing.T) {
	err := &SessionVersionCacheStaleError{Age: 70 * time.Second, OnStale: "reject"}
	if err.Error() == "" {
		t.Fatal("SessionVersionCacheStaleError.Error() returned empty string")
	}
}
