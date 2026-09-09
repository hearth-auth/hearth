package hearth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// unsignedAdminToken builds an `alg: none` token that claims admin.write. It is
// the cheapest possible forgery: no key material, no interaction with Hearth.
// Every embedded-mode authorization gate MUST refuse it.
func unsignedAdminToken(t *testing.T, issuer string) string {
	t.Helper()
	hb, err := json.Marshal(map[string]string{"alg": "none", "typ": "JWT"})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	cb, err := json.Marshal(map[string]any{
		"sub":         "attacker",
		"iss":         issuer,
		"exp":         time.Now().Add(time.Hour).Unix(),
		"permissions": []string{"admin.write"},
		"roles":       []string{"admin"},
		"groups":      []string{"engineering"},
		"oid":         "org_42",
	})
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(hb) + "." + enc.EncodeToString(cb) + "."
}

// wrongKeyAdminToken is signed — with a key that is not in the issuer's JWKS.
func wrongKeyAdminToken(t *testing.T, issuer string) string {
	t.Helper()
	other := newTestIssuer(t) // a different key pair
	return other.signAs(t, issuer, map[string]any{
		"sub":         "attacker",
		"permissions": []string{"admin.write"},
		"roles":       []string{"admin"},
	})
}

// signAs signs with this issuer's key but stamps someone else's `iss`.
func (ti *testIssuer) signAs(t *testing.T, issuer string, claims map[string]any) string {
	t.Helper()
	c := make(map[string]any, len(claims)+1)
	for k, v := range claims {
		c[k] = v
	}
	c["iss"] = issuer
	return ti.sign(t, c)
}

func TestHasPermissionRejectsUnsignedToken(t *testing.T) {
	ti := newTestIssuer(t)
	c := ti.client()
	token := unsignedAdminToken(t, ti.URL())

	if c.HasPermission(context.Background(), token, "admin.write") {
		t.Fatal("HasPermission accepted an alg:none forgery claiming admin.write")
	}
	if c.HasRole(context.Background(), token, "admin") {
		t.Fatal("HasRole accepted an alg:none forgery claiming role admin")
	}
	if c.InGroup(context.Background(), token, "engineering") {
		t.Fatal("InGroup accepted an alg:none forgery")
	}
	if c.InOrg(context.Background(), token, "org_42") {
		t.Fatal("InOrg accepted an alg:none forgery")
	}
}

func TestHasPermissionRejectsWrongKeyToken(t *testing.T) {
	ti := newTestIssuer(t)
	c := ti.client()
	token := wrongKeyAdminToken(t, ti.URL())

	if c.HasPermission(context.Background(), token, "admin.write") {
		t.Fatal("HasPermission accepted a token signed by a key outside the JWKS")
	}
}

func TestHasPermissionRejectsExpiredToken(t *testing.T) {
	ti := newTestIssuer(t)
	c := ti.client()
	token := ti.sign(t, map[string]any{
		"permissions": []string{"admin.write"},
		"exp":         time.Now().Add(-time.Hour).Unix(),
	})

	if c.HasPermission(context.Background(), token, "admin.write") {
		t.Fatal("HasPermission accepted an expired token")
	}
}

func TestHasPermissionAcceptsSignedToken(t *testing.T) {
	ti := newTestIssuer(t)
	c := ti.client()
	token := ti.sign(t, map[string]any{
		"permissions": []string{"admin.write"},
		"roles":       []string{"admin"},
		"groups":      []string{"engineering"},
		"oid":         "org_42",
	})

	if !c.HasPermission(context.Background(), token, "admin.write") {
		t.Error("HasPermission rejected a properly signed token")
	}
	if c.HasPermission(context.Background(), token, "admin.delete") {
		t.Error("HasPermission granted a permission the token does not carry")
	}
	if !c.HasRole(context.Background(), token, "admin") {
		t.Error("HasRole rejected a properly signed token")
	}
	if !c.InGroup(context.Background(), token, "engineering") {
		t.Error("InGroup rejected a properly signed token")
	}
	if !c.InOrg(context.Background(), token, "org_42") {
		t.Error("InOrg rejected a properly signed token")
	}
}

// The net/http middleware is the surface a resource server actually mounts, so
// the forgery must be refused there too.
func TestMiddlewareEmbeddedRejectsUnsignedToken(t *testing.T) {
	ti := newTestIssuer(t)
	c := ti.client()
	token := unsignedAdminToken(t, ti.URL())

	reached := false
	mw := RequirePermission(c, "admin.write", MiddlewareConfig{ExpectedMode: ModeEmbedded})
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if reached {
		t.Fatal("RequirePermission(ModeEmbedded) called next for an alg:none forgery")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for an unverifiable token, got %d", rr.Code)
	}
}

func TestMiddlewareEmbeddedAcceptsSignedToken(t *testing.T) {
	ti := newTestIssuer(t)
	c := ti.client()
	token := ti.sign(t, map[string]any{"permissions": []string{"admin.write"}})

	mw := RequirePermission(c, "admin.write", MiddlewareConfig{ExpectedMode: ModeEmbedded})
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for a properly signed token, got %d", rr.Code)
	}
}

// 25.2 — `nbf` must be honoured on the verify path.
func TestVerifyTokenRejectsNotYetValidToken(t *testing.T) {
	ti := newTestIssuer(t)
	c := ti.client()
	token := ti.sign(t, map[string]any{
		"permissions": []string{"admin.write"},
		"nbf":         time.Now().Add(time.Hour).Unix(),
	})

	if _, err := c.VerifyToken(context.Background(), token); err == nil {
		t.Fatal("VerifyToken accepted a token whose nbf is an hour in the future")
	}
}

func TestVerifyTokenAcceptsPastNbf(t *testing.T) {
	ti := newTestIssuer(t)
	c := ti.client()
	token := ti.sign(t, map[string]any{
		"permissions": []string{"admin.write"},
		"nbf":         time.Now().Add(-time.Hour).Unix(),
	})

	if _, err := c.VerifyToken(context.Background(), token); err != nil {
		t.Fatalf("VerifyToken rejected a token whose nbf is in the past: %v", err)
	}
}
