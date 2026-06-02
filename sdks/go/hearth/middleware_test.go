package hearth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// okHandler is a sentinel inner handler — if the middleware passes through,
// it writes HTTP 200 with "ok".
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
})

// applyMiddleware wires up RequirePermission around okHandler and records the response.
func applyMiddleware(t *testing.T, c *Client, permission string, cfg MiddlewareConfig, token string) *httptest.ResponseRecorder {
	t.Helper()
	mw := RequirePermission(c, permission, cfg)
	handler := mw(okHandler)
	req := httptest.NewRequest("GET", "/test", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// ─── ModeEmbedded ────────────────────────────────────────────────────────────

func TestMiddlewareEmbeddedAllowed(t *testing.T) {
	c := NewClient("http://localhost", "r1")
	token := forgeJWT(t, map[string]any{"permissions": []string{"docs.edit"}})
	rr := applyMiddleware(t, c, "docs.edit", MiddlewareConfig{ExpectedMode: ModeEmbedded}, token)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestMiddlewareEmbeddedDenied(t *testing.T) {
	c := NewClient("http://localhost", "r1")
	token := forgeJWT(t, map[string]any{"permissions": []string{"docs.view"}})
	rr := applyMiddleware(t, c, "docs.edit", MiddlewareConfig{ExpectedMode: ModeEmbedded}, token)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

func TestMiddlewareEmbeddedMissingToken(t *testing.T) {
	c := NewClient("http://localhost", "r1")
	rr := applyMiddleware(t, c, "docs.edit", MiddlewareConfig{ExpectedMode: ModeEmbedded}, "")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

func TestMiddlewareEmbeddedNeverFallsBackToNetwork(t *testing.T) {
	// Token has NO permissions claim. Embedded mode must deny without a network call.
	// We point at a server that always returns 500 to prove no request is made.
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "r1")
	token := forgeJWT(t, map[string]any{"sub": "user_1"}) // no permissions claim
	rr := applyMiddleware(t, c, "docs.edit", MiddlewareConfig{ExpectedMode: ModeEmbedded}, token)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
	if callCount != 0 {
		t.Fatalf("embedded mode must not make network calls, but made %d", callCount)
	}
}

// ─── ModeDecision ────────────────────────────────────────────────────────────

func TestMiddlewareDecisionAllowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/authorize" || r.Method != "POST" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(CheckPermissionResponse{Allowed: true})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "r1")
	token := forgeJWT(t, map[string]any{"sub": "user_1"})
	rr := applyMiddleware(t, c, "docs.edit", MiddlewareConfig{ExpectedMode: ModeDecision}, token)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestMiddlewareDecisionDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/authorize" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(CheckPermissionResponse{Allowed: false})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "r1")
	token := forgeJWT(t, map[string]any{"sub": "user_1"})
	rr := applyMiddleware(t, c, "docs.edit", MiddlewareConfig{ExpectedMode: ModeDecision}, token)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

func TestMiddlewareDecisionFailClosed(t *testing.T) {
	// Server returns 500 — middleware must deny (fail-closed).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "r1")
	token := forgeJWT(t, map[string]any{"sub": "user_1"})
	rr := applyMiddleware(t, c, "docs.edit", MiddlewareConfig{ExpectedMode: ModeDecision}, token)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 (fail-closed), got %d", rr.Code)
	}
}

func TestMiddlewareDecisionSendsToken(t *testing.T) {
	// Verify the correct Authorization header is forwarded to /oauth/authorize.
	var receivedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(CheckPermissionResponse{Allowed: true})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "r1")
	token := forgeJWT(t, map[string]any{"sub": "user_1"})
	applyMiddleware(t, c, "docs.edit", MiddlewareConfig{ExpectedMode: ModeDecision}, token)
	if receivedAuth != "Bearer "+token {
		t.Fatalf("expected Authorization header %q, got %q", "Bearer "+token, receivedAuth)
	}
}

// ─── ModeIntrospection ───────────────────────────────────────────────────────

func introspectResponse(active bool, mode string, permissions []string) IntrospectResponse {
	return IntrospectResponse{
		Active:      active,
		Mode:        mode,
		Permissions: permissions,
		Sub:         "user_1",
	}
}

func TestMiddlewareIntrospectionAllowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/introspect" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(introspectResponse(true, "introspection", []string{"docs.edit"}))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "r1")
	token := forgeJWT(t, map[string]any{"sub": "user_1"})
	rr := applyMiddleware(t, c, "docs.edit", MiddlewareConfig{
		ExpectedMode: ModeIntrospection,
		ClientID:     "res-server",
		ClientSecret: "secret",
	}, token)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestMiddlewareIntrospectionDeniedInactiveToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/introspect" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(introspectResponse(false, "", nil))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "r1")
	token := forgeJWT(t, map[string]any{"sub": "user_1"})
	rr := applyMiddleware(t, c, "docs.edit", MiddlewareConfig{
		ExpectedMode: ModeIntrospection,
		ClientID:     "res-server",
		ClientSecret: "secret",
	}, token)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for inactive token, got %d", rr.Code)
	}
}

func TestMiddlewareIntrospectionModeMismatchRejected(t *testing.T) {
	// Server echoes mode="embedded" but the middleware expects "introspection".
	// Must reject — never fall back to local check.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/introspect" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// mode="embedded" echoed — mismatch with configured ModeIntrospection
		_ = json.NewEncoder(w).Encode(introspectResponse(true, "embedded", []string{"docs.edit"}))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "r1")
	token := forgeJWT(t, map[string]any{"permissions": []string{"docs.edit"}})
	rr := applyMiddleware(t, c, "docs.edit", MiddlewareConfig{
		ExpectedMode: ModeIntrospection,
		ClientID:     "res-server",
		ClientSecret: "secret",
	}, token)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("mode mismatch must deny (got %d), not fall through to embedded check", rr.Code)
	}
}

func TestMiddlewareIntrospectionAbsentModeDefaultsToEmbedded(t *testing.T) {
	// Server omits the mode field (old server or embedded client).
	// Absent mode defaults to "embedded" — mismatch against ModeIntrospection, so deny.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/introspect" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(introspectResponse(true, "", []string{"docs.edit"}))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "r1")
	token := forgeJWT(t, map[string]any{"sub": "user_1"})
	rr := applyMiddleware(t, c, "docs.edit", MiddlewareConfig{
		ExpectedMode: ModeIntrospection,
		ClientID:     "res-server",
	}, token)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("absent mode should default to embedded and mismatch → 403, got %d", rr.Code)
	}
}

func TestMiddlewareIntrospectionMissingPermission(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/introspect" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// Active with correct mode but no "docs.edit" permission.
		_ = json.NewEncoder(w).Encode(introspectResponse(true, "introspection", []string{"docs.view"}))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "r1")
	token := forgeJWT(t, map[string]any{"sub": "user_1"})
	rr := applyMiddleware(t, c, "docs.edit", MiddlewareConfig{
		ExpectedMode: ModeIntrospection,
		ClientID:     "res-server",
	}, token)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when permission absent, got %d", rr.Code)
	}
}

// ─── Required-action token guard (spec §6 rule 6) ────────────────────────────

func TestMiddlewareRequiredActionTokenReturns401(t *testing.T) {
	// A token with token_type="required_action" must yield 401, even when the
	// permission claim is present. The middleware must reject before checking perms.
	c := NewClient("http://localhost", "r1")
	token := forgeJWT(t, map[string]any{
		"token_type":       "required_action",
		"required_actions": []string{"VERIFY_EMAIL"},
		"permissions":      []string{"docs.edit"},
	})
	rr := applyMiddleware(t, c, "docs.edit", MiddlewareConfig{ExpectedMode: ModeEmbedded}, token)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("required_action token must return 401, got %d", rr.Code)
	}
}

func TestMiddlewareRequiredActionOnRequiredActionCallback(t *testing.T) {
	// When OnRequiredAction is provided, it must be called with the typed error.
	c := NewClient("http://localhost", "r1")
	token := forgeJWT(t, map[string]any{
		"token_type":       "required_action",
		"required_actions": []string{"VERIFY_EMAIL", "UPDATE_PASSWORD"},
	})

	var capturedErr *RequiredActionError
	cfg := MiddlewareConfig{
		ExpectedMode: ModeEmbedded,
		OnRequiredAction: func(w http.ResponseWriter, _ *http.Request, err *RequiredActionError) {
			capturedErr = err
			http.Error(w, "required action pending", http.StatusUnauthorized)
		},
	}
	rr := applyMiddleware(t, c, "docs.edit", cfg, token)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
	if capturedErr == nil {
		t.Fatal("OnRequiredAction was not called")
	}
	if len(capturedErr.RequiredActions) != 2 {
		t.Errorf("RequiredActions: %v", capturedErr.RequiredActions)
	}
	if capturedErr.RequiredActions[0] != "VERIFY_EMAIL" {
		t.Errorf("first action: %q", capturedErr.RequiredActions[0])
	}
}

func TestMiddlewareRequiredActionDoesNotCallNext(t *testing.T) {
	// next must NOT be called when token_type is required_action.
	c := NewClient("http://localhost", "r1")
	token := forgeJWT(t, map[string]any{
		"token_type":       "required_action",
		"required_actions": []string{"VERIFY_EMAIL"},
		"permissions":      []string{"docs.edit"},
	})
	nextCalled := false
	mw := RequirePermission(c, "docs.edit", MiddlewareConfig{ExpectedMode: ModeEmbedded})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	handler.ServeHTTP(httptest.NewRecorder(), req)
	if nextCalled {
		t.Error("next must not be called when token_type=required_action")
	}
}

// ─── CheckPermission direct API ──────────────────────────────────────────────

func TestCheckPermissionAllowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/authorize" || r.Method != "POST" {
			http.NotFound(w, r)
			return
		}
		var body CheckPermissionRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Permission != "docs.edit" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(CheckPermissionResponse{Allowed: false})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(CheckPermissionResponse{Allowed: true})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "r1")
	resp, err := c.CheckPermission(t.Context(), "my-token", CheckPermissionRequest{Permission: "docs.edit"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Allowed {
		t.Fatal("expected Allowed=true")
	}
}

func TestCheckPermissionNetworkErrorFailClosed(t *testing.T) {
	// Point at a closed server — CheckPermission must return Allowed=false, not error.
	c := NewClient("http://127.0.0.1:1", "r1")
	resp, err := c.CheckPermission(t.Context(), "tok", CheckPermissionRequest{Permission: "x"})
	if err != nil {
		t.Fatalf("CheckPermission should absorb network errors (fail-closed), got: %v", err)
	}
	if resp == nil || resp.Allowed {
		t.Fatal("expected Allowed=false on network error")
	}
}

// ─── Introspect direct API ───────────────────────────────────────────────────

func TestIntrospectActive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/introspect" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(IntrospectResponse{
			Active:      true,
			Sub:         "user_xyz",
			Mode:        "introspection",
			Permissions: []string{"billing.read"},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "r1")
	resp, err := c.Introspect(t.Context(), IntrospectRequest{
		Token:        "access-token",
		ClientID:     "res-server",
		ClientSecret: "secret",
	})
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if !resp.Active {
		t.Fatal("expected active=true")
	}
	if resp.Sub != "user_xyz" {
		t.Fatalf("sub: %q", resp.Sub)
	}
	if len(resp.Permissions) != 1 || resp.Permissions[0] != "billing.read" {
		t.Fatalf("permissions: %v", resp.Permissions)
	}
}
