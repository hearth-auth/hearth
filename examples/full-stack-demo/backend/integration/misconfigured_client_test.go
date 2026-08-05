//go:build integration

// Misconfigured-client negative tests (HEA-2057).
//
// Each test drives a *broken* relying party against a real Hearth and asserts
// Hearth REFUSES — with a concrete status (and error where Hearth returns one),
// not merely "the app didn't log in". This is the deterministic replacement for
// a generic scanner (ZAP/nuclei): it tests what pentesting was a proxy for and
// doubles as executable documentation of what a correct Hearth integration must
// do.
//
// Where an existing Rust `abuse_*`/conformance suite already covers the same
// refusal at the unit layer, it is cross-referenced in the case comment. The
// value HERE is proving the refusal holds OVER THE WIRE through a real client.
//
// Anything that is NOT refused is a security finding: stop and file it against
// SecurityAuditor rather than weakening the assertion.
package integration

import (
	"net/http"
	"strings"
	"testing"
)

// Case 1 — No PKCE.
//
// A public client (no client secret) that omits `code_challenge` must not be
// able to obtain an authorization code. PKCE is mandatory for public clients
// (CHANGELOG HEA-501). We exercise the mandatory-PKCE code path with a public
// client registered in the system realm (co-realm with the admin token, so the
// authorize call authenticates cleanly and the ONLY defect is the missing PKCE
// parameter). The demo's `hearth-hub` client is public and hits this same path.
//
// Rust unit coverage: tests/oauth_pkce_confidential.rs, tests/oidc.rs.
func TestNoPKCE_AuthorizationRejected(t *testing.T) {
	requireLive(t)

	body := map[string]any{
		"client_id":     hPublicClientID,
		"redirect_uri":  "https://app.example.com/cb",
		"scope":         "openid",
		"state":         "no-pkce-state",
		"response_type": "code",
		"user_id":       hCallerUUID,
		// code_challenge / code_challenge_method deliberately omitted.
	}
	var resp map[string]any
	err := postJSON(hBase, "/authorize", hAdmin, hSys, body, &resp)

	// postJSON returns an error on any non-2xx — that IS the refusal we want.
	if err == nil {
		t.Fatalf("Hearth issued a response without PKCE: %v — public-client authorization without code_challenge MUST be rejected (SECURITY FINDING)", resp)
	}
	if !strings.Contains(err.Error(), "→ 400") {
		t.Fatalf("expected 400 rejection for missing PKCE, got: %v", err)
	}
	if code, ok := resp["code"]; ok && code != "" {
		t.Fatalf("Hearth issued an authorization code without PKCE: %v (SECURITY FINDING)", code)
	}
}

// Case 2 — No / mismatched `state`.
//
// IMPORTANT (weaker result, called out per HEA-2057 rules): `state` is a
// client-side CSRF token. Per OAuth 2.0 it is OPTIONAL and the authorization
// server MUST round-trip it verbatim; enforcing that the value on the callback
// matches the value the client sent is the RELYING PARTY's responsibility, not
// Hearth's. So this case does NOT fail at Hearth — it fails in the demo client
// (frontend/src/pages/Callback.tsx compares the returned state to the stored
// one). What we assert at Hearth is the mechanism the RP relies on: Hearth
// echoes `state` faithfully (so a tampered/absent value is detectable) and does
// not smuggle a code back under a mismatched state.
func TestState_HearthRoundTripsButRPMustEnforce(t *testing.T) {
	requireLive(t)

	const sent = "rp-csrf-value-123"
	body := map[string]any{
		"client_id":             hPublicClientID,
		"redirect_uri":          "https://app.example.com/cb",
		"scope":                 "openid",
		"state":                 sent,
		"response_type":         "code",
		"user_id":               hCallerUUID,
		"code_challenge":        pkceChallengeS256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
		"code_challenge_method": "S256",
	}
	var resp struct {
		Code  string `json:"code"`
		State string `json:"state"`
	}
	if err := postJSON(hBase, "/authorize", hAdmin, hSys, body, &resp); err != nil {
		t.Fatalf("authorize failed: %v", err)
	}
	if resp.State != sent {
		t.Fatalf("Hearth did not round-trip state verbatim: sent %q, got %q — an RP cannot detect CSRF without this (SECURITY FINDING)", sent, resp.State)
	}
	// Documented gap: state MISMATCH enforcement lives in the RP. The demo's
	// Callback.tsx rejects a mismatched/absent state before exchanging the code.
}

// Case 3 — alg:none.
//
// A token whose header advertises `alg:none` (unsigned) must be rejected by
// Hearth's resource-server path. Hearth is Ed25519-only; accepting an unsigned
// token would be a total authentication bypass.
//
// Rust unit coverage: tests/token_adversarial.rs.
func TestAlgNone_Rejected(t *testing.T) {
	requireLive(t)

	forged := forgeUnsignedJWT("none", map[string]any{
		"sub": "user_00000000-0000-0000-0000-000000000001",
		"iss": hDemoIssuer,
		"aud": demoClientID,
	})
	status, body := getStatus(t, "/realms/demo/userinfo", map[string]string{
		"Authorization": "Bearer " + forged,
	})
	if status != http.StatusUnauthorized {
		t.Fatalf("alg:none token accepted at /realms/demo/userinfo: status %d body %s (SECURITY FINDING)", status, truncate(body))
	}
}

// Case 4 — Missing / wrong `aud` (audience binding).
//
// A validly-signed token minted for one realm's resource (system realm; its
// access token carries aud=%q of the system issuer) must be rejected by a
// DIFFERENT realm's resource server (the demo realm's /userinfo). Because the
// token is genuinely Ed25519-signed, this proves audience/issuer binding — not
// signature rejection. This overlaps the cross-realm case by construction; the
// dedicated same-realm audience-refresh unit test is tests/resource_aud_refresh.rs.
func TestWrongAudience_Rejected(t *testing.T) {
	requireLive(t)

	status, body := getStatus(t, "/realms/demo/userinfo", map[string]string{
		"Authorization": "Bearer " + hAccessToken,
	})
	if status != http.StatusUnauthorized {
		t.Fatalf("token for the system-realm audience accepted at the demo resource server: status %d body %s (SECURITY FINDING)", status, truncate(body))
	}
}

// Case 5 — Wrong `iss`.
//
// Two assertions:
//
//	(a) A forged token whose `iss` is an attacker-controlled issuer must be
//	    rejected at the resource server.
//	(b) The real, Hearth-minted ID token stamps `iss` from `oidc.issuer` (NOT
//	    `config.token.issuer`), per docs/specs/OIDC.md. We assert the minted
//	    token's `iss` equals the realm's advertised discovery issuer, which is
//	    derived from oidc.issuer.
//
// Rust unit coverage: tests/rfc9207_iss.rs, tests/oidc_conformance.rs.
func TestWrongIssuer_RejectedAndIssuerIsOidcIssuer(t *testing.T) {
	requireLive(t)

	// (a) attacker-controlled iss.
	forged := forgeUnsignedJWT("EdDSA", map[string]any{
		"sub": "user_00000000-0000-0000-0000-000000000001",
		"iss": "https://evil.attacker.example",
		"aud": demoClientID,
	})
	status, body := getStatus(t, "/realms/demo/userinfo", map[string]string{
		"Authorization": "Bearer " + forged,
	})
	if status != http.StatusUnauthorized {
		t.Fatalf("token with attacker-controlled iss accepted: status %d body %s (SECURITY FINDING)", status, truncate(body))
	}

	// (b) real minted ID token: iss must be the oidc.issuer-derived value.
	// The mint runs in the SYSTEM realm, whose OIDC issuer is the root
	// `oidc.issuer` (http://localhost:8420). This asserts Hearth stamps iss from
	// oidc.issuer rather than any token.issuer.
	var rootDisc struct {
		Issuer string `json:"issuer"`
	}
	if err := getJSON(hBase, "/.well-known/openid-configuration", nil, &rootDisc); err != nil {
		t.Fatalf("root discovery: %v", err)
	}
	gotIss, _ := jwtClaimAny(t, hIDToken, "iss").(string)
	if gotIss == "" || gotIss != rootDisc.Issuer {
		t.Fatalf("ID token iss %q != oidc.issuer %q (OIDC.md violation)", gotIss, rootDisc.Issuer)
	}
}

// Case 6 — Bearer-scheme confusion.
//
// Non-`Bearer` credentials must be rejected by Hearth's token-authenticated
// endpoints. The demo's Go middleware guards this too (middleware/auth.go
// extractBearer), but here we assert Hearth's OWN side refuses Basic and a
// bogus `token` scheme.
func TestBearerSchemeConfusion_Rejected(t *testing.T) {
	requireLive(t)

	cases := map[string]string{
		"basic":        "Basic dXNlcjpwYXNzd29yZA==",
		"custom-token": "token " + hAccessToken,
		"bare-jwt":     hAccessToken, // no scheme prefix at all
	}
	for name, authz := range cases {
		t.Run(name, func(t *testing.T) {
			status, body := getStatus(t, "/realms/demo/userinfo", map[string]string{
				"Authorization": authz,
			})
			if status != http.StatusUnauthorized {
				t.Fatalf("non-Bearer credential (%s) accepted: status %d body %s (SECURITY FINDING)", name, status, truncate(body))
			}
		})
	}
}

// Case 7 — Cross-realm token.
//
// A validly-signed token issued in realm A (system) must be rejected when
// presented to realm B (demo). This is the classic BOLA/tenancy-isolation
// check, proven with a genuinely signed token so the refusal is realm binding,
// not signature failure.
//
// Rust unit coverage: tests/rbac_cross_realm.rs, tests/admin_realm_bola.rs.
func TestCrossRealmToken_Rejected(t *testing.T) {
	requireLive(t)

	// Sanity: the token is a real, signed Hearth token (three JWT segments).
	if strings.Count(hAccessToken, ".") != 2 {
		t.Fatalf("expected a compact JWS access token, got %q", truncate([]byte(hAccessToken)))
	}
	status, body := getStatus(t, "/realms/demo/userinfo", map[string]string{
		"Authorization": "Bearer " + hAccessToken,
	})
	if status != http.StatusUnauthorized {
		t.Fatalf("system-realm token accepted at demo realm: status %d body %s (SECURITY FINDING)", status, truncate(body))
	}
}
