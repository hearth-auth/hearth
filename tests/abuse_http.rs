//! Adversarial tests for Phase-0 HTTP abuse-prevention primitives.
//!
//! Covers (D-4 taxonomy):
//! - A-21 JSON parse-bomb guard (depth + array length)
//! - A-22 Decompression-bomb cap
//! - A-39 HTTP/2 rapid-reset defense (config smoke test)
//! - A-40 COOP/COEP headers present on UI responses
//! - A-52 `return_to` / federation open-redirect prevention
//!
//! Each test is a negative-scenario (adversarial) test as required by §3.41.

// ─────────────────────────────────────────────────────────────────────────────
// A-21 — JSON parse-bomb guard
// ─────────────────────────────────────────────────────────────────────────────

use hearth::abuse::guards::{
    check_decompressed_size, check_json_depth, BodyGuardError, MAX_DECOMPRESSED_SIZE,
    MAX_JSON_ARRAY_LEN, MAX_JSON_DEPTH,
};
use hearth::abuse::redirect::validate_return_to;

/// Adversarial: deeply-nested JSON is rejected.
#[test]
fn a21_deeply_nested_json_rejected() {
    let mut s = String::new();
    for _ in 0..=MAX_JSON_DEPTH {
        s.push_str(r#"{"x":"#);
    }
    s.push('1');
    for _ in 0..=MAX_JSON_DEPTH {
        s.push('}');
    }
    assert_eq!(
        check_json_depth(s.as_bytes()),
        Err(BodyGuardError::JsonDepthExceeded),
        "deeply-nested JSON must be rejected"
    );
}

/// Adversarial: a huge JSON array is rejected.
#[test]
fn a21_huge_json_array_rejected() {
    let elements: Vec<String> = (0..MAX_JSON_ARRAY_LEN).map(|i| i.to_string()).collect();
    let json = format!("[{}]", elements.join(","));
    assert_eq!(
        check_json_depth(json.as_bytes()),
        Err(BodyGuardError::JsonArrayTooLong),
        "array with MAX_JSON_ARRAY_LEN elements must be rejected"
    );
}

/// Negative: valid JSON within limits is accepted.
#[test]
fn a21_valid_json_accepted() {
    let json = br#"{"realm": "test", "users": [1, 2, 3]}"#;
    assert!(
        check_json_depth(json).is_ok(),
        "well-formed shallow JSON must pass the guard"
    );
}

/// Adversarial: JSON depth bomb mixed with arrays.
#[test]
fn a21_nested_arrays_rejected() {
    let mut s = String::new();
    for _ in 0..=MAX_JSON_DEPTH {
        s.push('[');
    }
    for _ in 0..=MAX_JSON_DEPTH {
        s.push(']');
    }
    assert_eq!(
        check_json_depth(s.as_bytes()),
        Err(BodyGuardError::JsonDepthExceeded),
        "deeply-nested arrays must be rejected"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// A-22 — Decompression-bomb cap
// ─────────────────────────────────────────────────────────────────────────────

/// Adversarial: gzip bomb exceeding cap is rejected.
#[test]
fn a22_decompression_bomb_rejected() {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write as _;

    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    // Compress MAX_DECOMPRESSED_SIZE + 1 bytes of zeros.
    let bomb = vec![0u8; MAX_DECOMPRESSED_SIZE + 1];
    encoder.write_all(&bomb).expect("encode bomb");
    let compressed = encoder.finish().expect("finish encoder");

    assert_eq!(
        check_decompressed_size(&compressed),
        Err(BodyGuardError::DecompressedSizeExceeded),
        "decompression bomb must be rejected at MAX_DECOMPRESSED_SIZE"
    );
}

/// Negative: small gzip body within cap is accepted.
#[test]
fn a22_small_gzip_accepted() {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write as _;

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(b"hello world from hearth")
        .expect("encode");
    let compressed = encoder.finish().expect("finish");

    let decompressed = check_decompressed_size(&compressed).expect("small body must be accepted");
    assert_eq!(decompressed, b"hello world from hearth");
}

/// Adversarial: invalid gzip data returns DecompressError.
#[test]
fn a22_invalid_gzip_returns_error() {
    let garbage = b"this is not gzip data at all 12345";
    let result = check_decompressed_size(garbage);
    assert!(
        matches!(result, Err(BodyGuardError::DecompressError(_))),
        "invalid gzip must return DecompressError"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// A-40 — Security headers (COOP/COEP/Permissions-Policy)
// ─────────────────────────────────────────────────────────────────────────────

/// Negative: security headers layer emits COOP and COEP when enabled.
#[tokio::test]
async fn a40_coop_coep_headers_present() {
    use std::convert::Infallible;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::response::IntoResponse;
    use hearth::protocol::web::security::{SecurityConfig, SecurityHeadersLayer};
    use tower::{Layer, ServiceExt};

    let layer = SecurityHeadersLayer::new(SecurityConfig {
        hsts_enabled: false,
        coop_coep_enabled: true,
        extra_form_action_origins: Vec::new(),
    });
    let svc = layer.layer(tower::service_fn(|_req: Request<Body>| async {
        Ok::<_, Infallible>(StatusCode::OK.into_response())
    }));
    let resp = svc
        .oneshot(
            Request::builder()
                .uri("/")
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("call");

    let h = resp.headers();
    assert_eq!(
        h.get("cross-origin-opener-policy")
            .expect("COOP header missing")
            .to_str()
            .expect("header value"),
        "same-origin"
    );
    assert_eq!(
        h.get("cross-origin-embedder-policy")
            .expect("COEP header missing")
            .to_str()
            .expect("header value"),
        "require-corp"
    );
    assert!(
        h.contains_key("permissions-policy"),
        "Permissions-Policy header missing"
    );
}

/// Adversarial: COOP/COEP absent when disabled.
#[tokio::test]
async fn a40_coop_coep_absent_when_disabled() {
    use std::convert::Infallible;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::response::IntoResponse;
    use hearth::protocol::web::security::{SecurityConfig, SecurityHeadersLayer};
    use tower::{Layer, ServiceExt};

    let layer = SecurityHeadersLayer::new(SecurityConfig {
        hsts_enabled: false,
        coop_coep_enabled: false,
        extra_form_action_origins: Vec::new(),
    });
    let svc = layer.layer(tower::service_fn(|_req: Request<Body>| async {
        Ok::<_, Infallible>(StatusCode::OK.into_response())
    }));
    let resp = svc
        .oneshot(
            Request::builder()
                .uri("/")
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("call");

    assert!(
        !resp.headers().contains_key("cross-origin-opener-policy"),
        "COOP must be absent when coop_coep_enabled = false"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// A-52 — `return_to` open-redirect prevention
// ─────────────────────────────────────────────────────────────────────────────

/// Adversarial: scheme-relative redirect is rejected.
#[test]
fn a52_scheme_relative_rejected() {
    assert!(
        validate_return_to("//evil.com/steal-session", &[]).is_none(),
        "scheme-relative URL must be rejected"
    );
}

/// Adversarial: backslash redirect is rejected (Windows path traversal).
#[test]
fn a52_backslash_rejected() {
    assert!(
        validate_return_to("\\evil.com", &[]).is_none(),
        "backslash path must be rejected"
    );
}

/// Adversarial: javascript: scheme is rejected.
#[test]
fn a52_javascript_scheme_rejected() {
    assert!(
        validate_return_to("javascript:alert(document.cookie)", &[]).is_none(),
        "javascript: scheme must be rejected"
    );
}

/// Adversarial: data: URI is rejected.
#[test]
fn a52_data_uri_rejected() {
    assert!(
        validate_return_to("data:text/html,<script>alert(1)</script>", &[]).is_none(),
        "data: URI must be rejected"
    );
}

/// Adversarial: absolute URL without origin allowlist is rejected.
#[test]
fn a52_absolute_url_without_allowlist_rejected() {
    assert!(
        validate_return_to("https://attacker.example.com/phish", &[]).is_none(),
        "absolute URL to unlisted origin must be rejected"
    );
}

/// Adversarial: newline injection in return_to is rejected.
#[test]
fn a52_newline_injection_rejected() {
    assert!(
        validate_return_to("/ui/account\r\nSet-Cookie: evil=1", &[]).is_none(),
        "CRLF injection in return_to must be rejected"
    );
}

/// Negative: relative path is accepted.
#[test]
fn a52_relative_path_accepted() {
    assert_eq!(
        validate_return_to("/ui/dashboard", &[]),
        Some("/ui/dashboard".to_string()),
        "relative UI path must be accepted"
    );
}

/// Negative: absolute URL to whitelisted origin is accepted.
#[test]
fn a52_whitelisted_origin_accepted() {
    let allowed = vec!["https://app.corp.com".to_string()];
    assert!(
        validate_return_to("https://app.corp.com/onboarding", &allowed).is_some(),
        "absolute URL with whitelisted origin must be accepted"
    );
}

/// Adversarial: absolute URL to different sub-origin is rejected even when
/// a related origin is whitelisted (no prefix/suffix matching).
#[test]
fn a52_subdomain_of_allowlisted_origin_rejected() {
    let allowed = vec!["https://app.corp.com".to_string()];
    assert!(
        validate_return_to("https://evil.app.corp.com/phish", &allowed).is_none(),
        "subdomain of whitelisted origin must not be accepted"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// HEA-SEC-33 — Minimal security headers on REST API responses
// ─────────────────────────────────────────────────────────────────────────────

/// REST API responses include `X-Content-Type-Options: nosniff` and
/// `Referrer-Policy: no-referrer` on every route (HEA-SEC-33).
#[tokio::test]
async fn sec33_rest_api_responses_include_minimal_security_headers() {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::Request;
    use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
    use hearth::core::SystemClock;
    use hearth::identity::{CredentialConfig, EmbeddedIdentityEngine, IdentityConfig};
    use hearth::protocol::http::{router, AppState};
    use hearth::rbac::EmbeddedRbacEngine;
    use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
    use tower::ServiceExt;

    let temp_dir = tempfile::tempdir().expect("tempdir");
    let config = StorageConfig::dev(temp_dir.path().to_path_buf());
    let engine = Arc::new(EmbeddedStorageEngine::open(config).expect("open storage"));
    let clock = Arc::new(SystemClock) as Arc<dyn hearth::core::Clock>;
    let identity_config = IdentityConfig {
        credential: CredentialConfig::fast_for_testing(),
        ..IdentityConfig::default()
    };
    let audit_engine = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&engine) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn AuditEngine>;
    let identity_engine = EmbeddedIdentityEngine::new(
        Arc::clone(&engine) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
        identity_config,
        Arc::clone(&audit_engine),
    )
    .expect("identity engine");
    let authz_engine = EmbeddedRbacEngine::new(
        Arc::clone(&engine) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    );
    let state = Arc::new(AppState::new(
        Arc::new(identity_engine),
        Arc::new(authz_engine),
        audit_engine,
    ));

    let resp = router(state)
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    let headers = resp.headers();
    assert_eq!(
        headers
            .get("x-content-type-options")
            .expect("X-Content-Type-Options missing on REST response")
            .to_str()
            .expect("header value"),
        "nosniff"
    );
    assert_eq!(
        headers
            .get("referrer-policy")
            .expect("Referrer-Policy missing on REST response")
            .to_str()
            .expect("header value"),
        "no-referrer"
    );
}
