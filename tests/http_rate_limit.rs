#![allow(clippy::unwrap_used)]
//! Integration tests for the HTTP rate-limit middleware (A-2).
//!
//! Tests that the `RequestShaper` Tower layer wired into the axum router
//! rejects requests that exceed the per-IP sliding-window limit with
//! HTTP 429 Too Many Requests, and that the admin-scoped per-user limiter
//! (`security.rate_limiting.admin_per_minute`) also returns 429 on admin
//! endpoints once the quota is exceeded.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hearth::abuse::shaper::{RequestShaper, ShaperConfig};
use hearth::identity::{CreateUserRequest, SessionContext};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
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

// ===== Scenario RL-3: admin-endpoint rate limiting =====

/// Excessive requests from a single admin to any admin endpoint must trigger
/// HTTP 429 with `{"limiter":"admin"}` once the per-minute quota is exceeded.
///
/// Phase 1 › Admin API › Adversarial: "Admin endpoint rate limiting: excessive
/// requests from single admin trigger throttling".
///
/// The admin-scoped limiter (`security.rate_limiting.admin_per_minute`) is
/// distinct from the global IP shaper: it tracks per-authenticated-user counts
/// inside a 1-minute sliding window. This test sets the limit to 2 so the
/// third request triggers 429 without waiting for the real 100-req/min cap.
#[tokio::test]
async fn admin_endpoint_rate_limit_exceeded_returns_429() {
    let h = common::TestHarness::embedded().await.unwrap();
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed rbac");

    // Create a user and grant the realm.admin role so the token carries
    // `hearth.realm.admin` and passes the `extract_admin_auth` permission gate.
    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "admin-rl@example.com".into(),
                display_name: "Admin RL".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let role = h
        .rbac()
        .get_role_by_name(&realm, "realm.admin")
        .expect("role lookup")
        .expect("realm.admin role seeded");
    h.rbac()
        .assign_role(
            &realm,
            &AssignRoleRequest {
                subject: Subject::User(user.id().clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign admin role");

    let session = h
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("create session");
    let token = h
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("issue tokens")
        .access_token()
        .to_string();

    // Set a very low admin rate limit (2 requests per minute).
    let state = Arc::new(
        AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc())
            .with_rate_limits(Some(2), None, None),
    );

    let realm_header = realm.as_uuid().to_string();

    // First two requests must succeed — they are within the 2-per-minute quota.
    for i in 0..2_u8 {
        let resp = router(Arc::clone(&state))
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/roles")
                    .header("Authorization", format!("Bearer {token}"))
                    .header("X-Realm-ID", &realm_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "request #{i} must not be rate-limited (got {})",
            resp.status()
        );
    }

    // Third request must be rate-limited — quota exhausted.
    let resp = router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/roles")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", &realm_header)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "third admin request must be rate-limited with HTTP 429"
    );

    let body_bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(
        json["limiter"].as_str().unwrap_or(""),
        "admin",
        "429 must be attributed to the admin rate limiter, not the IP shaper: {json}"
    );
}
