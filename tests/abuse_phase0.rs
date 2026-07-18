//! §3.41 adversarial test skeletons — Phase-0 abuse-prevention rows (HEA-1188).
//!
//! Each function is tagged with its A-N plan-row identifier so the CI gate
//! (`scripts/check-abuse-coverage.sh`) can verify coverage.
//!
//! Convention: include the identifier in the test function name OR in a
//! comment on the same line, e.g. `fn a2_something()` or `// A-2: reason`.
//! Replace the empty body with real assertions once HEA-1188 is merged.

// A-2: global request shaper (100 rps/IP, 1000 rps/realm) ────────────────────

/// Exceeding the per-IP rate limit must return HTTP 429.
/// A-2 — see src/abuse/shaper.rs (HEA-1188).
#[test]
fn a2_per_ip_rate_limit_exceeded_returns_429() {}

/// Exceeding the per-realm rate limit must return HTTP 429.
/// A-2 — see src/abuse/shaper.rs (HEA-1188).
#[test]
fn a2_per_realm_rate_limit_exceeded_returns_429() {}

// A-15: gRPC rate-limit interceptor ──────────────────────────────────────────

/// Saturating the gRPC budget must return RESOURCE_EXHAUSTED.
/// A-15 — see src/protocol/grpc/ (HEA-1188).
#[test]
fn a15_grpc_rate_limit_returns_resource_exhausted() {}

// A-21: JSON parse-bomb guard ─────────────────────────────────────────────────

/// A JSON body with nesting depth >128 must be rejected with HTTP 413.
/// A-21 — see src/abuse/guards.rs (HEA-1188).
#[test]
fn a21_json_depth_bomb_rejected_413() {}

/// A JSON array with ≥65536 elements must be rejected with HTTP 413.
/// A-21 — see src/abuse/guards.rs (HEA-1188).
#[test]
fn a21_json_array_bomb_rejected_413() {}

// A-22: Decompression-bomb cap ────────────────────────────────────────────────

/// A compressed body expanding beyond 4 MiB must be rejected with HTTP 413.
/// A-22 — see src/abuse/guards.rs (HEA-1188).
#[test]
fn a22_decompression_bomb_cap_rejected_413() {}

// A-23: Pagination hard cap ───────────────────────────────────────────────────

/// A `limit` query param above MAX_PAGE_SIZE must be clamped to 1000.
/// A-23 — see src/identity/mod.rs (HEA-1188).
#[test]
fn a23_pagination_limit_above_max_clamped() {}

// A-39: HTTP/2 rapid-reset defense ────────────────────────────────────────────

/// Exceeding the RST_STREAM budget must close the connection (CVE-2023-44487).
/// A-39 — see src/protocol/http.rs (HEA-1188).
#[test]
fn a39_http2_rapid_reset_budget_exceeded_closes_conn() {}

// A-40: Host allowlist + COOP/COEP + __Host- cookies ─────────────────────────

/// A request with a Host header not in the allowlist must be rejected.
/// A-40 — see src/protocol/web/middleware.rs (HEA-1188).
#[test]
fn a40_invalid_host_header_rejected() {}

/// Responses to authenticated requests must include Cross-Origin-Opener-Policy.
/// A-40 — see src/protocol/web/middleware.rs (HEA-1188).
#[test]
fn a40_coop_header_present_on_authenticated_responses() {}

/// Session cookies must carry their hardening attributes.
///
/// A-40 — see src/protocol/web/auth.rs (HEA-1188).
///
/// M1 (HEA-1757): the previous body was empty and asserted nothing (a vacuous
/// pass). The `hearth_ui_session` cookie is intentionally NOT `__Host-`-prefixed
/// because it is path-scoped to `/ui` (the `__Host-` prefix mandates `Path=/`),
/// so this test now pins the real attributes the cookie does carry: `HttpOnly`
/// (no JS access), `SameSite=Lax` (CSRF defence), `Path=/ui` (scope), and the
/// `Secure` flag whenever the request arrived over TLS. It also asserts `Secure`
/// is omitted for plaintext dev requests so local HTTP login still works.
#[test]
fn a40_session_cookie_hardening_attributes() {
    use hearth::core::{RealmId, SessionId};
    use hearth::protocol::web::auth::{issue_auth_cookies, SESSION_COOKIE};
    use hearth::protocol::web::CookieSecret;

    let secret = CookieSecret::random();
    let realm = RealmId::generate();
    let session = SessionId::generate();

    // Secure request (TLS): full attribute set including `Secure`.
    let secure = issue_auth_cookies(&secret, &realm, &session, true);
    let sc = secure.session_cookie;
    assert!(
        sc.starts_with(&format!("{SESSION_COOKIE}=")),
        "session cookie must be named {SESSION_COOKIE}: {sc}"
    );
    assert!(
        sc.contains("HttpOnly"),
        "session cookie must be HttpOnly: {sc}"
    );
    assert!(
        sc.contains("SameSite=Lax"),
        "session cookie must set SameSite=Lax: {sc}"
    );
    assert!(
        sc.contains("Path=/ui"),
        "session cookie must scope Path=/ui: {sc}"
    );
    assert!(
        sc.contains("; Secure"),
        "session cookie must set Secure over TLS: {sc}"
    );

    // Plaintext request (dev/local HTTP): identical hardening minus `Secure`.
    let insecure = issue_auth_cookies(&secret, &realm, &session, false);
    let ic = insecure.session_cookie;
    assert!(
        ic.contains("HttpOnly"),
        "session cookie must stay HttpOnly: {ic}"
    );
    assert!(
        !ic.contains("; Secure"),
        "session cookie must omit Secure for plaintext requests: {ic}"
    );
}

// A-47: deny_unknown_fields audit ─────────────────────────────────────────────

/// Unknown JSON fields in a request body must be rejected, not silently dropped.
/// A-47 — codebase-wide audit (HEA-1188).
#[test]
fn a47_unknown_fields_in_request_body_rejected() {}

// A-52: return_to / federation-redirect allowlist ─────────────────────────────

/// A `return_to` URL not in the allowlist must be refused.
/// A-52 — see src/protocol/web/saml.rs (HEA-1188).
#[test]
fn a52_return_to_not_in_allowlist_rejected() {}

/// An open-redirect attempt via malformed federation redirect must be blocked.
/// A-52 — see src/protocol/web/saml.rs (HEA-1188).
#[test]
fn a52_open_redirect_via_federation_blocked() {}

// A-1: AbuseGuard middleware + AbusePolicy trait ──────────────────────────────

/// A `Deny(reason)` decision from the abuse policy must reject the request and
/// emit the corresponding `AbuseDetected` audit event.
/// A-1 — unified `AbuseGuard` trait is not yet built; today's checks live in
/// `src/abuse/{shaper,detector,guards}.rs` and `AbuseGuard.check()` is the
/// planned facade. See docs/plans/HEA-1114-abuse-prevention.md row A-1.
#[test]
fn a1_abuse_guard_deny_decision_rejects_request() {}

/// A `Challenge` decision must surface `HEARTH_ABUSE_CHALLENGE_REQUIRED`
/// without leaking the underlying signal that tripped the policy.
/// A-1 — see docs/plans/HEA-1114-abuse-prevention.md row A-1.
#[test]
fn a1_abuse_guard_challenge_decision_returns_challenge_required() {}

// A-51: external audit-log attestation ────────────────────────────────────────

/// A tampered audit row between two attestation checkpoints must be detected
/// on next chain verification.
/// A-51 — external attestation shipping is not yet implemented; see
/// `src/audit/engine.rs` chain verification and docs/plans/HEA-1114-abuse-prevention.md row A-51.
#[test]
fn a51_tampered_row_between_attestations_detected() {}

/// On restart, a missing or mismatched prior attestation must fail closed
/// rather than silently re-seeding the chain.
/// A-51 — see docs/plans/HEA-1114-abuse-prevention.md row A-51.
#[test]
fn a51_missing_prior_attestation_fails_closed() {}
