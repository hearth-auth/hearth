package hearth

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// openspec/specs/sdk-support-contract/spec.md step 3: `iss` must match the CONFIGURED issuer. Reaching the same
// server as `localhost` gives the same keys and the same discovery document,
// but a token issued as 127.0.0.1 does not belong to the configured issuer.
func TestVerifyToken_IssuerComparedWithConfiguredIssuer(t *testing.T) {
	ti := newTestIssuer(t)
	token := ti.sign(t, map[string]any{"sub": "user-1"}) // iss = 127.0.0.1 URL

	configured := strings.Replace(ti.URL(), "127.0.0.1", "localhost", 1)
	claims, err := NewClient(configured, "r1").VerifyToken(context.Background(), token)

	var issuerErr *TokenIssuerError
	if !errors.As(err, &issuerErr) {
		t.Fatalf("expected *TokenIssuerError, got %T: %v (claims %+v)", err, err, claims)
	}
	if issuerErr.Expected != configured {
		t.Fatalf("Expected = %q, want the configured issuer %q", issuerErr.Expected, configured)
	}
}

func TestVerifyToken_ConfiguredIssuerWithTrailingSlashStillMatches(t *testing.T) {
	ti := newTestIssuer(t)
	token := ti.sign(t, map[string]any{"sub": "user-1"})

	if _, err := NewClient(ti.URL()+"/", "r1").VerifyToken(context.Background(), token); err != nil {
		t.Fatalf("expected the token to validate, got %T: %v", err, err)
	}
}
