#![allow(clippy::unwrap_used)]
//! Integration tests for the HTTP rate-limit middleware (A-2).
//!
//! Tests that the `RequestShaper` Tower layer wired into the axum router
//! rejects requests that exceed the per-IP sliding-window limit with
//! HTTP 429 Too Many Requests.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hearth::abuse::shaper::{RequestShaper, ShaperConfig};
use hearth::protocol::http::{router, AppState};
use tower::ServiceExt as _;

// ===== Scenario RL-1: requests beyond per-IP limit receive 429 =====

/// Sending more requests than the per-IP limit within one second must return
/// HTTP 429 with `{"error":"too_many_requests"}` and a `Retry-After: 1` header.
#[tokio::test]
async fn http_rate_limit_ip_exceeded_returns_429() {
    let h = common::TestHarness::embedded().await.unwrap();

    // ip_rps = 1: the second request in the same second must be rejected.
    let shaper = Arc::new(RequestShaper::with_config(ShaperConfig {
        ip_rps: Some(1),
        realm_rps: None,
    }));
    let state = Arc::new(
        AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc())
            .with_request_shaper(Arc::clone(&shaper)),
    );

    // First request: within limit.
    let app1 = router(Arc::clone(&state));
    let resp1 = app1
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp1.status(), StatusCode::OK, "first request must succeed");

    // Second request: exceeds 1 rps/IP limit — must be rejected.
    let app2 = router(Arc::clone(&state));
    let resp2 = app2
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp2.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "second request must be rate-limited with 429"
    );
    assert_eq!(
        resp2
            .headers()
            .get("Retry-After")
            .and_then(|v| v.to_str().ok()),
        Some("1"),
        "429 response must include Retry-After: 1"
    );

    let body_bytes = axum::body::to_bytes(resp2.into_body(), 64 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(json["error"].as_str().unwrap(), "too_many_requests");
}

// ===== Scenario RL-2: requests within limit pass through =====

/// When the shaper is configured with a generous limit, a handful of sequential
/// requests should all succeed without spurious 429 responses.
#[tokio::test]
async fn http_rate_limit_within_limit_passes() {
    let h = common::TestHarness::embedded().await.unwrap();

    // ip_rps = 100 (default): a handful of requests must all succeed.
    let state = Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()));

    for i in 0..5_u8 {
        let app = router(Arc::clone(&state));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "request #{i} must not be rate-limited"
        );
    }
}
