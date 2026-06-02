package hearth

import (
	"testing"
)

func TestClaimsScope(t *testing.T) {
	token := forgeJWT(t, map[string]any{"scope": "openid profile email"})
	claims, err := ParseClaims(token)
	if err != nil {
		t.Fatalf("ParseClaims: %v", err)
	}
	if got := claims.Scope(); got != "openid profile email" {
		t.Errorf("Scope() = %q, want %q", got, "openid profile email")
	}
}

func TestClaimsScopeEmpty(t *testing.T) {
	token := forgeJWT(t, map[string]any{"sub": "user_1"})
	claims, err := ParseClaims(token)
	if err != nil {
		t.Fatalf("ParseClaims: %v", err)
	}
	if got := claims.Scope(); got != "" {
		t.Errorf("Scope() should be empty when absent, got %q", got)
	}
}

func TestClaimsInGroup(t *testing.T) {
	token := forgeJWT(t, map[string]any{"groups": []string{"engineering", "security"}})
	claims, err := ParseClaims(token)
	if err != nil {
		t.Fatalf("ParseClaims: %v", err)
	}
	if !claims.InGroup("engineering") {
		t.Error("InGroup(engineering) should be true")
	}
	if claims.InGroup("marketing") {
		t.Error("InGroup(marketing) should be false")
	}
}

func TestClaimsInGroupAbsent(t *testing.T) {
	token := forgeJWT(t, map[string]any{"sub": "user_1"})
	claims, err := ParseClaims(token)
	if err != nil {
		t.Fatalf("ParseClaims: %v", err)
	}
	if claims.InGroup("engineering") {
		t.Error("InGroup should return false when groups claim absent")
	}
}

func TestClaimsInOrg(t *testing.T) {
	token := forgeJWT(t, map[string]any{"oid": "org_42"})
	claims, err := ParseClaims(token)
	if err != nil {
		t.Fatalf("ParseClaims: %v", err)
	}
	if !claims.InOrg("org_42") {
		t.Error("InOrg(org_42) should be true")
	}
	if claims.InOrg("org_7") {
		t.Error("InOrg(org_7) should be false")
	}
}

func TestClaimsInOrgAbsent(t *testing.T) {
	token := forgeJWT(t, map[string]any{"sub": "user_1"})
	claims, err := ParseClaims(token)
	if err != nil {
		t.Fatalf("ParseClaims: %v", err)
	}
	if claims.InOrg("org_42") {
		t.Error("InOrg should return false when oid claim absent")
	}
	if claims.InOrg("") {
		t.Error("InOrg should return false for empty arg")
	}
}

func TestClaimsTokenType(t *testing.T) {
	for _, tt := range []struct {
		tokenType string
	}{
		{"access"},
		{"refresh"},
		{"required_action"},
	} {
		t.Run(tt.tokenType, func(t *testing.T) {
			token := forgeJWT(t, map[string]any{"token_type": tt.tokenType})
			claims, err := ParseClaims(token)
			if err != nil {
				t.Fatalf("ParseClaims: %v", err)
			}
			if got := claims.TokenType(); got != tt.tokenType {
				t.Errorf("TokenType() = %q, want %q", got, tt.tokenType)
			}
		})
	}
}

func TestClaimsTokenTypeAbsent(t *testing.T) {
	token := forgeJWT(t, map[string]any{"sub": "user_1"})
	claims, err := ParseClaims(token)
	if err != nil {
		t.Fatalf("ParseClaims: %v", err)
	}
	if got := claims.TokenType(); got != "" {
		t.Errorf("TokenType() should be empty when absent, got %q", got)
	}
}

func TestClaimsOrganizationId(t *testing.T) {
	token := forgeJWT(t, map[string]any{"oid": "org_42"})
	claims, err := ParseClaims(token)
	if err != nil {
		t.Fatalf("ParseClaims: %v", err)
	}
	if got := claims.OrganizationId(); got != "org_42" {
		t.Errorf("OrganizationId() = %q, want %q", got, "org_42")
	}
}

func TestClaimsOrganizationIdAbsent(t *testing.T) {
	token := forgeJWT(t, map[string]any{"sub": "user_1"})
	claims, err := ParseClaims(token)
	if err != nil {
		t.Fatalf("ParseClaims: %v", err)
	}
	if got := claims.OrganizationId(); got != "" {
		t.Errorf("OrganizationId() should be empty when absent, got %q", got)
	}
}

func TestClaimsOrgGroups(t *testing.T) {
	token := forgeJWT(t, map[string]any{"org_groups": []string{"/acme/engineering", "/acme/security"}})
	claims, err := ParseClaims(token)
	if err != nil {
		t.Fatalf("ParseClaims: %v", err)
	}
	got := claims.OrgGroups()
	if len(got) != 2 {
		t.Fatalf("OrgGroups() = %v, want 2 items", got)
	}
	if got[0] != "/acme/engineering" || got[1] != "/acme/security" {
		t.Errorf("OrgGroups() = %v", got)
	}
}

func TestClaimsOrgGroupsAbsent(t *testing.T) {
	token := forgeJWT(t, map[string]any{"sub": "user_1"})
	claims, err := ParseClaims(token)
	if err != nil {
		t.Fatalf("ParseClaims: %v", err)
	}
	if got := claims.OrgGroups(); got != nil {
		t.Errorf("OrgGroups() should be nil when absent, got %v", got)
	}
}

func TestClaimsAbsentClaimsNeverPanic(t *testing.T) {
	token := forgeJWT(t, map[string]any{"sub": "user_1"})
	claims, err := ParseClaims(token)
	if err != nil {
		t.Fatalf("ParseClaims: %v", err)
	}
	// All absent claims must return zero values, never panic.
	_ = claims.Scope()
	_ = claims.InGroup("any")
	_ = claims.InOrg("any")
	_ = claims.TokenType()
	_ = claims.OrganizationId()
	_ = claims.OrgGroups()
}
