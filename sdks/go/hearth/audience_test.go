package hearth

import (
	"context"
	"errors"
	"testing"
)

// The audience check is always on (sdk-support-contract, "JWT validation
// steps", check 4). With no configuration the SDK expects `hearth`, the
// audience Hearth mints when a client names no resource.

func TestVerifyToken_DefaultAudienceRejectsOtherAPI(t *testing.T) {
	ti := newTestIssuer(t)
	token := ti.sign(t, map[string]any{"sub": "u1", "aud": "other-api"})

	_, err := ti.client().VerifyToken(context.Background(), token)
	var audErr *TokenAudienceError
	if !errors.As(err, &audErr) {
		t.Fatalf("expected *TokenAudienceError, got %T: %v", err, err)
	}
	if audErr.Expected != DefaultAudience {
		t.Fatalf("Expected = %q, want %q", audErr.Expected, DefaultAudience)
	}
}

func TestVerifyToken_DefaultAudienceRejectsTokenWithoutAud(t *testing.T) {
	ti := newTestIssuer(t)
	token := ti.sign(t, map[string]any{"sub": "u1", "aud": nil})

	_, err := ti.client().VerifyToken(context.Background(), token)
	var audErr *TokenAudienceError
	if !errors.As(err, &audErr) {
		t.Fatalf("expected *TokenAudienceError, got %T: %v", err, err)
	}
}

func TestVerifyToken_DefaultAudienceAcceptsHearth(t *testing.T) {
	ti := newTestIssuer(t)
	token := ti.sign(t, map[string]any{"sub": "u1", "aud": "hearth"})

	claims, err := ti.client().VerifyToken(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if claims.Subject() != "u1" {
		t.Fatalf("subject = %q", claims.Subject())
	}
}

func TestVerifyToken_WithAudienceSetsProtectedResource(t *testing.T) {
	ti := newTestIssuer(t)
	client := NewClient(ti.URL(), "r1", WithAudience("https://api.example.com"))

	ok := ti.sign(t, map[string]any{"sub": "u1", "aud": "https://api.example.com"})
	if _, err := client.VerifyToken(context.Background(), ok); err != nil {
		t.Fatalf("token for the configured resource: %v", err)
	}

	other := ti.sign(t, map[string]any{"sub": "u1", "aud": "hearth"})
	var audErr *TokenAudienceError
	if _, err := client.VerifyToken(context.Background(), other); !errors.As(err, &audErr) {
		t.Fatalf("token for hearth: expected *TokenAudienceError, got %T: %v", err, err)
	}
}

func TestVerifyToken_ClientIDIsNotTheAudience(t *testing.T) {
	ti := newTestIssuer(t)
	client := NewClient(ti.URL(), "r1", WithClientCredentials("my-client", "secret"))
	token := ti.sign(t, map[string]any{"sub": "u1", "aud": "my-client"})

	var audErr *TokenAudienceError
	if _, err := client.VerifyToken(context.Background(), token); !errors.As(err, &audErr) {
		t.Fatalf("expected *TokenAudienceError, got %T: %v", err, err)
	}
}

func TestVerifyToken_EmptyAudienceOptionKeepsDefault(t *testing.T) {
	ti := newTestIssuer(t)
	client := NewClient(ti.URL(), "r1", WithAudience(""))
	token := ti.sign(t, map[string]any{"sub": "u1", "aud": "other-api"})

	var audErr *TokenAudienceError
	if _, err := client.VerifyToken(context.Background(), token, ""); !errors.As(err, &audErr) {
		t.Fatalf("expected *TokenAudienceError, got %T: %v", err, err)
	}
}
