//! Integration tests for /admin/cluster/* HTTP endpoints.
//!
//! Coverage in this file (AC-4, AC-5, single-node 503):
//! - 401 when no Authorization header (all 3 endpoints)
//! - 403 when valid but non-admin token (all 3 endpoints)
//! - 503 when no ClusterEngine attached to AppState (all 3 endpoints)
//!
//! Multi-node happy-path tests (AC-1, AC-2, AC-3) are in HEA-738 where a
//! 3-node in-process harness can be spun up without the per-test overhead.

use std::sync::Arc;

use axum::{body::Body, http::Request};
use hearth::protocol::http::{cluster_admin_routes, AppState};
use tower::ServiceExt;

// ── Test fixture ──────────────────────────────────────────────────────────────

fn no_cluster_app() -> axum::Router {
    cluster_admin_routes(Arc::new(AppState {
        cluster: None,
        admin_tokens: vec!["test-admin".to_string()],
    }))
}

// ── AC-4: 401 when no Authorization header ────────────────────────────────────

#[tokio::test]
async fn bootstrap_no_auth_returns_401() {
    let resp = no_cluster_app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/cluster/bootstrap")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn status_no_auth_returns_401() {
    let resp = no_cluster_app()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/cluster/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn transfer_no_auth_returns_401() {
    let resp = no_cluster_app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/cluster/transfer-leadership")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
}

// ── AC-5: 403 when non-admin token ───────────────────────────────────────────

#[tokio::test]
async fn bootstrap_non_admin_token_returns_403() {
    let resp = no_cluster_app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/cluster/bootstrap")
                .header("Authorization", "Bearer user-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn status_non_admin_token_returns_403() {
    let resp = no_cluster_app()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/cluster/status")
                .header("Authorization", "Bearer user-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn transfer_non_admin_token_returns_403() {
    let resp = no_cluster_app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/cluster/transfer-leadership")
                .header("Authorization", "Bearer user-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
}

// ── Single-node 503 (no ClusterEngine) ───────────────────────────────────────

#[tokio::test]
async fn bootstrap_no_cluster_returns_503() {
    let resp = no_cluster_app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/cluster/bootstrap")
                .header("Authorization", "Bearer test-admin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn status_no_cluster_returns_503() {
    let resp = no_cluster_app()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/cluster/status")
                .header("Authorization", "Bearer test-admin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn transfer_no_cluster_returns_503() {
    let resp = no_cluster_app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/cluster/transfer-leadership")
                .header("Authorization", "Bearer test-admin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
}
