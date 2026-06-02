//! Tests that dev-only routes are absent from the router in production mode.
//!
//! Covers HEA-1138: `POST /admin/bootstrap` must not appear in the Axum
//! routing table in production so port scanners cannot fingerprint the server.
//!
//! The discriminating signal: Axum's unregistered-route 404 has an empty body
//! and no `content-type` header. The handler-level 404 (pre-fix) returns JSON
//! with `content-type: application/json`, so we can tell them apart.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hearth::protocol::http::{router, AppState};
use tower::ServiceExt as _;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn non_dev_app(harness: &common::TestHarness) -> axum::Router {
    let state = Arc::new(AppState::new(
        harness.identity_arc(),
        harness.rbac_arc(),
        harness.audit_arc(),
    ));
    router(state)
}

async fn dev_app(harness: &common::TestHarness) -> axum::Router {
    let state = Arc::new(AppState::new_dev(
        harness.identity_arc(),
        harness.rbac_arc(),
        harness.audit_arc(),
    ));
    router(state)
}

// ---------------------------------------------------------------------------
// Route-registration tests (HEA-1138)
// ---------------------------------------------------------------------------

/// In production (non-dev) mode the `/admin/bootstrap` route must be absent
/// from the routing table entirely.
///
/// We distinguish router-level 404 from handler-level 404 by inspecting the
/// response body: Axum's fallback for unregistered routes returns an empty
/// body, while the handler guard returns JSON.
#[tokio::test]
async fn bootstrap_route_absent_in_prod_mode() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness creation");
    let app = non_dev_app(&harness).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/bootstrap")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("request");

    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "should return 404 in production"
    );

    // The body must be empty: Axum's unregistered-route fallback has no body.
    // A non-empty body would mean the handler ran (route is still registered).
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body read");
    assert!(
        body.is_empty(),
        "expected empty body from router-level 404 (route should not be registered), got: {:?}",
        body
    );
}

/// In dev mode the route must be registered and reachable.
///
/// A 200 OK confirms the route exists in the routing table; a 404 would mean
/// it was incorrectly excluded.
#[tokio::test]
async fn bootstrap_route_present_in_dev_mode() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness creation");
    let app = dev_app(&harness).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/bootstrap")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("request");

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "bootstrap route must be reachable in dev mode"
    );
}
