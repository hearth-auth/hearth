package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// introspectStub is a fake Hearth introspection endpoint. It records how many
// times it was called and returns the configured `active` verdict, letting the
// tests assert both the revocation semantics and the short-TTL caching.
type introspectStub struct {
	active atomic.Bool
	calls  atomic.Int64
	server *httptest.Server
}

func newIntrospectStub() *introspectStub {
	s := &introspectStub{}
	s.active.Store(true)
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if s.active.Load() {
			_, _ = w.Write([]byte(`{"active":true,"sub":"user_1"}`))
		} else {
			_, _ = w.Write([]byte(`{"active":false}`))
		}
	}))
	return s
}

func (s *introspectStub) close() { s.server.Close() }

func TestRevocationChecker_ActiveToken(t *testing.T) {
	stub := newIntrospectStub()
	defer stub.close()

	rc := NewRevocationChecker(stub.server.URL, 30*time.Second)
	active, err := rc.IsActive(context.Background(), "tok-abc")
	if err != nil {
		t.Fatalf("IsActive returned error: %v", err)
	}
	if !active {
		t.Fatal("expected live token to be reported active")
	}
}

// TestRevocationChecker_RevokedToken is the core regression guard for HEA-2094:
// once Hearth reports a token inactive, the checker must report it revoked.
func TestRevocationChecker_RevokedToken(t *testing.T) {
	stub := newIntrospectStub()
	defer stub.close()

	rc := NewRevocationChecker(stub.server.URL, 0) // no cache — observe every verdict
	stub.active.Store(false)

	active, err := rc.IsActive(context.Background(), "tok-revoked")
	if err != nil {
		t.Fatalf("IsActive returned error: %v", err)
	}
	if active {
		t.Fatal("expected revoked token to be reported inactive")
	}
}

// TestRevocationChecker_CachesWithinTTL proves the cache spares Hearth a
// round-trip on every request: repeated checks inside the TTL hit the cache.
func TestRevocationChecker_CachesWithinTTL(t *testing.T) {
	stub := newIntrospectStub()
	defer stub.close()

	rc := NewRevocationChecker(stub.server.URL, time.Minute)
	for i := 0; i < 5; i++ {
		if _, err := rc.IsActive(context.Background(), "tok-cached"); err != nil {
			t.Fatalf("IsActive[%d] error: %v", i, err)
		}
	}
	if got := stub.calls.Load(); got != 1 {
		t.Fatalf("expected a single introspection call within the TTL, got %d", got)
	}
}

// TestRevocationChecker_RevocationVisibleAfterTTL proves the latency/consistency
// tradeoff: a token cached as active is honored until the TTL lapses, after
// which the revocation becomes visible.
func TestRevocationChecker_RevocationVisibleAfterTTL(t *testing.T) {
	stub := newIntrospectStub()
	defer stub.close()

	// Drive time explicitly so the test is deterministic (no sleeps).
	var clock atomic.Int64 // unix nanoseconds
	base := time.Unix(1_000_000, 0)
	clock.Store(base.UnixNano())

	rc := NewRevocationChecker(stub.server.URL, 3*time.Second)
	rc.nowFunc = func() time.Time { return time.Unix(0, clock.Load()) }

	// t0: active, cached.
	active, err := rc.IsActive(context.Background(), "tok-ttl")
	if err != nil || !active {
		t.Fatalf("t0 expected active, got active=%v err=%v", active, err)
	}

	// Revoke at Hearth, but stay within the TTL — the cached "active" lingers.
	stub.active.Store(false)
	clock.Store(base.Add(1 * time.Second).UnixNano())
	if active, _ = rc.IsActive(context.Background(), "tok-ttl"); !active {
		t.Fatal("within TTL the cached active verdict should still be served")
	}

	// Past the TTL: the checker re-introspects and observes the revocation.
	clock.Store(base.Add(4 * time.Second).UnixNano())
	if active, _ = rc.IsActive(context.Background(), "tok-ttl"); active {
		t.Fatal("after the TTL the revocation must become visible")
	}
}

// TestRevocationChecker_FailsClosedOnError proves an introspection failure is
// surfaced as an error (callers reject) rather than silently reported active.
func TestRevocationChecker_FailsClosedOnError(t *testing.T) {
	stub := newIntrospectStub()
	stub.close() // server is down → every introspection call errors

	rc := NewRevocationChecker(stub.server.URL, time.Minute)
	active, err := rc.IsActive(context.Background(), "tok-x")
	if err == nil {
		t.Fatal("expected an error when introspection is unreachable")
	}
	if active {
		t.Fatal("a failed introspection must not report the token active")
	}
}
