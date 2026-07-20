#![allow(clippy::unwrap_used)]
//! §3.41 adversarial tests — Phase-0 abuse-prevention rows (HEA-1188, HEA-1825).
//!
//! Each function/marker is tagged with its A-N plan-row identifier so the CI
//! gate (`scripts/check-abuse-coverage.sh`) can verify coverage. The gate greps
//! `tests/abuse_*.rs` for each `A-N`, so keeping the identifier here (in a test
//! name or a `// A-N:` comment) preserves the row → test mapping.
//!
//! ## History (HEA-1825)
//!
//! This file used to contain 18 empty test bodies (`{}`) that passed
//! unconditionally — a false-confidence anti-pattern (TESTING.md §"Test Quality
//! Anti-Patterns", class B: zero-assert bodies). The stale docstrings also
//! claimed behaviours that do **not** match the implementation (e.g. HTTP 413
//! for JSON bombs — the guard actually returns 400; pagination "clamped to
//! 1000" — it is actually *rejected* with `InvalidInput`).
//!
//! The empty bodies were replaced with real assertions. Where a row's canonical
//! adversarial coverage already lives in a dedicated sibling file, that file is
//! the source of truth and this module carries a `// A-N: covered by …` marker
//! rather than a duplicate test. Controls that are specified but **not yet
//! implemented** (A-1 unified `AbuseGuard` facade, A-51 external attestation)
//! are `#[ignore]`d with a tracking note — an honest red-skip rather than a
//! green vacuous pass.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::header::{CONTENT_TYPE, HOST};
use axum::http::{Request, StatusCode};
use hearth::abuse::guards::{MAX_JSON_ARRAY_LEN, MAX_JSON_DEPTH};
use hearth::abuse::shaper::{RequestShaper, ShaperConfig};
use hearth::protocol::http::{router, AppState};
use tower::ServiceExt as _;

// A-2: global request shaper (per-IP + per-realm) ─────────────────────────────

/// Exceeding the per-IP rate limit must return HTTP 429 over a real router.
///
/// A-2 — this is the end-to-end HTTP-socket assertion the former empty skeleton
/// only claimed to make. See `src/abuse/shaper.rs` (limiter) and
/// `src/protocol/http.rs::http_rate_limit` (middleware).
#[tokio::test]
async fn a2_per_ip_rate_limit_exceeded_returns_429() {
    let h = common::TestHarness::embedded().await.unwrap();

    // ip_rps = 1: the second request in the same window must be rejected.
    let shaper = Arc::new(RequestShaper::with_config(ShaperConfig {
        ip_rps: Some(1),
        realm_rps: None,
    }));
    let state = Arc::new(
        AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc())
            .with_request_shaper(Arc::clone(&shaper)),
    );

    // First request is within the limit.
    let first = router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK, "first request must pass");

    // Second request from the same IP exceeds the 1 rps limit.
    let second = router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        second.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "second request must be rate-limited with HTTP 429"
    );
    assert_eq!(
        second
            .headers()
            .get("Retry-After")
            .and_then(|v| v.to_str().ok()),
        Some("1"),
        "429 response must carry Retry-After: 1"
    );
}

// A-2: per-realm 429 is exercised at the limiter layer in
// `tests/abuse_shaper.rs::a2_realm_rate_limit_enforced` and end-to-end in
// `tests/http_rate_limit.rs`. The HTTP middleware keys per-IP only (it passes an
// empty realm to `shaper.check`), so the per-realm dimension is asserted at the
// `RequestShaper` boundary rather than duplicated here.

// A-15: gRPC rate-limit interceptor ──────────────────────────────────────────
//
// A-15: `grpc_rate_limit_interceptor` (src/protocol/grpc/server.rs) is a thin
// wrapper that maps `ShaperOutcome::{IpLimited,RealmLimited}` to
// `tonic::Status::resource_exhausted`. The limiter decision it delegates to is
// covered adversarially in `tests/abuse_shaper.rs` (A-2/A-15 share the shaper).
// The interceptor cannot be unit-driven through a hand-built `tonic::Request`
// because it reads `remote_addr()`, which is `None` off a live transport and
// fail-opens — so exercising the exhausted branch requires a real gRPC server
// (out of scope for this black-box file).

// A-21: JSON parse-bomb guard ─────────────────────────────────────────────────

/// A JSON body nested beyond `MAX_JSON_DEPTH` must be rejected with HTTP 400.
///
/// A-21 — the guard (`json_depth_guard`, src/protocol/http.rs) runs as a
/// `route_layer` before any handler, so it returns 400 (not 413, as the stale
/// skeleton claimed, and not 401 even on auth-gated routes).
#[tokio::test]
async fn a21_json_depth_bomb_rejected_400() {
    let h = common::TestHarness::embedded().await.unwrap();
    let state = Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()));

    let mut body = String::new();
    for _ in 0..=MAX_JSON_DEPTH {
        body.push_str(r#"{"x":"#);
    }
    body.push('1');
    for _ in 0..=MAX_JSON_DEPTH {
        body.push('}');
    }

    let resp = router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/users")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "JSON nested beyond MAX_JSON_DEPTH must be rejected with 400"
    );
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        json["error"].as_str().unwrap_or("").contains("depth"),
        "error must identify the depth guard, got: {json}"
    );
}

/// A JSON array with `MAX_JSON_ARRAY_LEN` elements must be rejected with 400.
///
/// A-21 — see `src/abuse/guards.rs::check_json_depth`.
#[tokio::test]
async fn a21_json_array_bomb_rejected_400() {
    let h = common::TestHarness::embedded().await.unwrap();
    let state = Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()));

    let elements: Vec<String> = (0..MAX_JSON_ARRAY_LEN).map(|i| i.to_string()).collect();
    let body = format!("[{}]", elements.join(","));

    let resp = router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/users")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "JSON array at/above MAX_JSON_ARRAY_LEN must be rejected with 400"
    );
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        json["error"].as_str().unwrap_or("").contains("array"),
        "error must identify the array guard, got: {json}"
    );
}

// A-22: Decompression-bomb cap ────────────────────────────────────────────────
//
// A-22: Hearth installs NO inbound gzip decompressor on the HTTP surface, so a
// compressed-body 413 cannot fire end-to-end (there is nothing to inflate). The
// guard `check_decompressed_size` (src/abuse/guards.rs) is the enforcement
// point and is tested adversarially in `tests/abuse_http.rs`
// (`a22_decompression_bomb_rejected`). The former "expands beyond 4 MiB → 413"
// docstring here described a control that does not exist at this layer.

// A-23: Pagination hard cap ───────────────────────────────────────────────────
//
// A-23: a `limit` above `MAX_PAGE_SIZE` is *rejected* with
// `IdentityError::InvalidInput` — it is NOT silently clamped to 1000, as the
// stale skeleton claimed. `cap_page_size` is tested adversarially in
// `tests/abuse_pagination.rs` (`over_max_page_size_rejected`).

// A-39: HTTP/2 rapid-reset defense ────────────────────────────────────────────
//
// A-39: the RST_STREAM budget (CVE-2023-44487) is configured on the hyper/h2
// builder in `src/protocol/http/serve.rs` and smoke-tested via config in
// `tests/abuse_http.rs`. It cannot be driven through the in-process
// `Router::oneshot` path used here because that never negotiates HTTP/2 frames.

// A-40: Host allowlist + COOP/COEP + cookie hardening ─────────────────────────

/// A request whose `Host` header is not in a non-empty allowlist must be
/// rejected with HTTP 400 (DNS-rebinding defense).
///
/// A-40 — see `src/protocol/http.rs::enforce_host_allowlist`.
#[tokio::test]
async fn a40_invalid_host_header_rejected() {
    let h = common::TestHarness::embedded().await.unwrap();
    let state = Arc::new(
        AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc())
            .with_allowed_hosts(vec!["hearth.test".to_string()]),
    );

    // Host not on the allowlist → rejected before route dispatch.
    let rejected = router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .uri("/health")
                .header(HOST, "evil.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        rejected.status(),
        StatusCode::BAD_REQUEST,
        "non-allowlisted Host header must be rejected with 400"
    );

    // Allowlisted Host passes through to the handler.
    let allowed = router(state)
        .oneshot(
            Request::builder()
                .uri("/health")
                .header(HOST, "hearth.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        allowed.status(),
        StatusCode::OK,
        "allowlisted Host header must pass through"
    );
}

// A-40: COOP/COEP header emission is asserted in
// `tests/abuse_http.rs::a40_coop_coep_headers_present` (and its disabled
// counterpart). Those exercise the `SecurityHeadersLayer` that fronts the web
// UI; the REST router asserts its minimal header set in the same file.

/// Session cookies must carry their hardening attributes.
///
/// A-40 — see src/protocol/web/auth.rs.
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

/// An unknown JSON field in an admin request body must be rejected, not
/// silently dropped (extension-field bypass defense).
///
/// A-47 — the admin `ImportUsersBody`/`ImportUserEntry` shapes carry
/// `#[serde(deny_unknown_fields)]` (src/protocol/http/admin.rs). The `Json`
/// extractor runs before the auth check, so an unknown field is rejected with
/// HTTP 422 regardless of credentials — proving the guard fires at the wire.
#[tokio::test]
async fn a47_unknown_fields_in_request_body_rejected() {
    let h = common::TestHarness::embedded().await.unwrap();
    let state = Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()));

    // Valid JSON, valid shape, plus one field the struct does not declare.
    let body = r#"{"users":[],"unexpected_field":true}"#;

    let resp = router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/users/import")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "an unknown field must be rejected by deny_unknown_fields with 422, \
         not accepted or silently ignored"
    );
}

// A-52: return_to / federation-redirect allowlist ────────────────────────────
//
// A-52: the unified `validate_return_to` allowlist (src/abuse/redirect.rs) is
// tested adversarially in `tests/abuse_http.rs` against scheme-relative,
// backslash, `javascript:`, `data:`, CRLF-injection, cross-origin, and
// subdomain-of-allowlisted attack vectors — the canonical coverage for both
// SAML and OIDC federation redirects. Duplicating it here would add no signal.

// A-1: AbuseGuard middleware + AbusePolicy trait ──────────────────────────────

/// A `Deny(reason)` decision from the abuse policy must reject the request and
/// emit the corresponding `AbuseDetected` audit event.
///
/// A-1 — the unified `AbuseGuard` facade is not yet built; today's checks live
/// in `src/abuse/{shaper,detector,guards}.rs`. Ignored (not a vacuous pass)
/// until the facade lands. See docs/plans/HEA-1114-abuse-prevention.md row A-1.
#[test]
#[ignore = "A-1 unified AbuseGuard facade not yet implemented (HEA-1114)"]
fn a1_abuse_guard_deny_decision_rejects_request() {
    unimplemented!("A-1 AbuseGuard facade pending (HEA-1114)");
}

/// A `Challenge` decision must surface `HEARTH_ABUSE_CHALLENGE_REQUIRED`
/// without leaking the underlying signal that tripped the policy.
///
/// A-1 — see docs/plans/HEA-1114-abuse-prevention.md row A-1.
#[test]
#[ignore = "A-1 unified AbuseGuard facade not yet implemented (HEA-1114)"]
fn a1_abuse_guard_challenge_decision_returns_challenge_required() {
    unimplemented!("A-1 AbuseGuard facade pending (HEA-1114)");
}

// A-51: external audit-log attestation ────────────────────────────────────────

/// A tampered audit row between two attestation checkpoints must be detected
/// on next chain verification.
///
/// A-51 — external attestation shipping is not yet implemented. Ignored (not a
/// vacuous pass) until it lands. The in-process hash chain it would anchor is
/// verified in `tests/audit.rs`. See docs/plans/HEA-1114-abuse-prevention.md
/// row A-51.
#[test]
#[ignore = "A-51 external attestation not yet implemented (HEA-1114)"]
fn a51_tampered_row_between_attestations_detected() {
    unimplemented!("A-51 external attestation pending (HEA-1114)");
}

/// On restart, a missing or mismatched prior attestation must fail closed
/// rather than silently re-seeding the chain.
///
/// A-51 — see docs/plans/HEA-1114-abuse-prevention.md row A-51.
#[test]
#[ignore = "A-51 external attestation not yet implemented (HEA-1114)"]
fn a51_missing_prior_attestation_fails_closed() {
    unimplemented!("A-51 external attestation pending (HEA-1114)");
}
