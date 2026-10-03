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
    let harness = common::TestHarness::in_process()
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

/// Without the `dev-endpoints` cargo feature the route is absent even from a
/// **dev-mode** router: the feature, not the runtime flag, is what keeps
/// `/admin/bootstrap` out of a default (`cargo build`) binary.
#[cfg(not(feature = "dev-endpoints"))]
#[tokio::test]
async fn bootstrap_route_absent_in_dev_mode_without_the_feature() {
    let harness = common::TestHarness::in_process()
        .await
        .expect("harness creation");
    let app = dev_app(&harness).await;

    // Loopback peer: the request would pass the per-request guard, so a 404
    // here can only come from the route never having been compiled in.
    let response = app
        .oneshot(loopback_bootstrap_request())
        .await
        .expect("request");

    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "a binary built without `dev-endpoints` must not route /admin/bootstrap, even in dev mode"
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body read");
    assert!(
        body.is_empty(),
        "expected the router-level 404 (route not registered), got: {body:?}"
    );
}

/// In dev mode the route must be registered and reachable.
///
/// A 200 OK confirms the route exists in the routing table; a 404 would mean
/// it was incorrectly excluded.
#[cfg(feature = "dev-endpoints")]
#[tokio::test]
async fn bootstrap_route_present_in_dev_mode() {
    let harness = common::TestHarness::in_process()
        .await
        .expect("harness creation");
    let app = dev_app(&harness).await;

    let response = app
        .oneshot(loopback_bootstrap_request())
        .await
        .expect("request");

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "bootstrap route must be reachable in dev mode"
    );
}

/// Builds a bootstrap request that carries a loopback `ConnectInfo`.
///
/// The dev-only routes are loopback-gated (audit §4.7#2, task 20.1) and the
/// guard reads the socket peer straight out of `ConnectInfo`, treating its
/// absence as remote — `tower::oneshot` installs none. Every real serve path
/// sets it, so a test that drives the router directly has to supply it.
fn loopback_bootstrap_request() -> Request<Body> {
    let mut req = Request::builder()
        .method("POST")
        .uri("/admin/bootstrap")
        .body(Body::empty())
        .expect("build request");
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            51234,
        ))));
    req
}
