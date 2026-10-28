package hearth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Regression — Go client without a timeout: every outbound call is bounded by
// a 10 s default (openspec/specs/sdk-support-contract/spec.md, "SDK client
// configuration"), so a server that never answers cannot hang the caller.
func TestNewClient_DefaultHTTPTimeout(t *testing.T) {
	c := NewClient("http://127.0.0.1:1", "r1")
	if c.http.Timeout != 10*time.Second {
		t.Fatalf("default HTTP timeout = %s, want 10s", c.http.Timeout)
	}
}

// WithHTTPTimeout sets the bound, and a call to a server that never answers
// fails once it passes.
func TestWithHTTPTimeout_BoundsAStalledCall(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) }) // runs first: unblocks the handler

	c := NewClient(srv.URL, "r1", WithHTTPTimeout(100*time.Millisecond))
	if c.http.Timeout != 100*time.Millisecond {
		t.Errorf("HTTP timeout = %s, want 100ms", c.http.Timeout)
	}

	done := make(chan error, 1)
	go func() {
		_, err := c.UserInfo(t.Context(), "access-token")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected a timeout error from a server that never answers")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the call to a stalled server did not time out within 5s")
	}
}

// A zero or negative WithHTTPTimeout keeps the default: it never turns the
// bound off.
func TestWithHTTPTimeout_NonPositiveKeepsDefault(t *testing.T) {
	for _, d := range []time.Duration{0, -time.Second} {
		c := NewClient("http://127.0.0.1:1", "r1", WithHTTPTimeout(d))
		if c.http.Timeout != 10*time.Second {
			t.Errorf("WithHTTPTimeout(%s): timeout = %s, want the 10s default", d, c.http.Timeout)
		}
	}
}
