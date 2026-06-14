//! Integration tests for the A-21 JSON parse-bomb guard middleware.
//!
//! Verifies that `POST`/`PUT`/`PATCH` requests with `Content-Type:
//! application/json` are rejected with HTTP 400 when the JSON body exceeds
//! [`hearth::abuse::guards::MAX_JSON_DEPTH`] nesting levels or
//! [`hearth::abuse::guards::MAX_JSON_ARRAY_LEN`] array items.
//!
//! A-22 (decompression-bomb) is not tested here because Hearth does not
//! install an inbound gzip decompressor — see ABUSE.md for rationale.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Request, StatusCode};
use hearth::abuse::guards::{MAX_JSON_ARRAY_LEN, MAX_JSON_DEPTH};
use hearth::protocol::http::{router, AppState};
use tower::ServiceExt as _;

fn build_app(h: &common::TestHarness) -> axum::Router {
    let state = Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()));
    router(state)
}

fn deeply_nested_json(depth: usize) -> Vec<u8> {
    let mut s = String::new();
    for _ in 0..depth {
        s.push_str(r#"{"x":"#);
    }
    s.push('1');
    for _ in 0..depth {
        s.push('}');
    }
    s.into_bytes()
}

fn json_array_with_n_elements(n: usize) -> Vec<u8> {
    let elements: Vec<String> = (0..n).map(|i| i.to_string()).collect();
    format!("[{}]", elements.join(",")).into_bytes()
}

// ===== A-21: depth guard =====

/// Deeply nested JSON body must be rejected with 400 before handler logic.
///
/// Even though /admin/users requires auth, the guard runs in a route_layer
/// before any handler extractor executes, so it returns 400 rather than 401.
#[tokio::test]
async fn a21_deeply_nested_json_rejected() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let app = build_app(&h);

    let body = deeply_nested_json(MAX_JSON_DEPTH + 1);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/users")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "guard must reject JSON nesting depth > MAX_JSON_DEPTH"
    );

    // Verify the error message identifies the guard, not a handler error.
    let bytes = axum::body::to_bytes(resp.into_body(), 65_536)
        .await
        .expect("body");
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("json error body");
    let error_str = json["error"].as_str().unwrap_or("");
    assert!(
        error_str.contains("depth"),
        "error message should mention depth, got: {error_str}"
    );
}

/// JSON body at exactly the maximum depth must pass the guard.
#[tokio::test]
async fn a21_json_at_exact_max_depth_passes_guard() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let app = build_app(&h);

    let body = deeply_nested_json(MAX_JSON_DEPTH);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/users")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .expect("request"),
        )
        .await
        .expect("response");

    // Guard passes; handler returns 401 (no auth token) — not 400 from the guard.
    assert_ne!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "JSON at exactly MAX_JSON_DEPTH must pass the guard"
    );
}

/// A JSON array with too many elements must be rejected.
#[tokio::test]
async fn a21_huge_json_array_rejected() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let app = build_app(&h);

    let body = json_array_with_n_elements(MAX_JSON_ARRAY_LEN);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/users")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "guard must reject array length >= MAX_JSON_ARRAY_LEN"
    );
    let bytes = axum::body::to_bytes(resp.into_body(), 65_536)
        .await
        .expect("body");
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("json error body");
    let error_str = json["error"].as_str().unwrap_or("");
    assert!(
        error_str.contains("array"),
        "error message should mention array, got: {error_str}"
    );
}

/// A normal, shallow JSON body must not be rejected by the guard.
#[tokio::test]
async fn a21_normal_json_passes_guard() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let app = build_app(&h);

    let body = br#"{"email": "user@example.com", "name": "Test User"}"#;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/users")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_vec()))
                .expect("request"),
        )
        .await
        .expect("response");

    // Guard passes; handler enforces auth → 401, not 400.
    assert_ne!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "normal JSON body must pass the A-21 guard"
    );
}

/// Non-JSON content type must skip the guard entirely.
#[tokio::test]
async fn a21_non_json_content_type_skips_guard() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let app = build_app(&h);

    // Content that looks like deeply nested JSON but is sent as text/plain.
    let body = deeply_nested_json(MAX_JSON_DEPTH + 10);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/users")
                .header(CONTENT_TYPE, "text/plain")
                .body(Body::from(body))
                .expect("request"),
        )
        .await
        .expect("response");

    // Guard should not fire for non-JSON content type.
    // Handler may return 415 (Unsupported Media Type) or 401, but not 400 from the guard.
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 65_536)
        .await
        .expect("body");
    // If 400, the error must NOT be from the depth guard.
    if status == StatusCode::BAD_REQUEST {
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
        let error_str = json["error"].as_str().unwrap_or("");
        assert!(
            !error_str.contains("depth") && !error_str.contains("array"),
            "guard must not fire for non-JSON content type; got: {error_str}"
        );
    }
}

/// GET requests (no body) must not trigger the guard.
#[tokio::test]
async fn a21_get_request_skips_guard() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let app = build_app(&h);

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "GET /health must not be affected by the JSON guard"
    );
}
