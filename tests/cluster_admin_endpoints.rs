//! Integration tests for `/admin/cluster/*` HTTP endpoints.
//!
//! Covers AC-4 (401 without auth), AC-5 (403 non-admin), and single-node
//! 503 responses for all three endpoints. AC-1/2/3/6 (multi-node Raft
//! behaviour) are deferred to HEA-738 which introduces the multi-node test
//! harness.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hearth::core::RealmId;
use hearth::identity::{CreateUserRequest, SessionContext};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use tower::ServiceExt as _;

async fn build_app(harness: &common::TestHarness) -> axum::Router {
    let state = Arc::new(AppState::new(
        harness.identity_arc(),
        harness.rbac_arc(),
        harness.audit_arc(),
    ));
    router(state)
}

async fn issue_token(
    harness: &common::TestHarness,
    realm: &RealmId,
    email: &str,
    with_admin: bool,
) -> String {
    let user = harness
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: email.into(),
                display_name: "T".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    if with_admin {
        let role = harness
            .rbac()
            .get_role_by_name(realm, "realm.admin")
            .expect("lookup")
            .expect("seeded");
        harness
            .rbac()
            .assign_role(
                realm,
                &AssignRoleRequest {
                    subject: Subject::User(user.id().clone()),
                    role_id: role.id,
                    scope: Scope::Realm,
                    assigned_by: None,
                },
            )
            .expect("assign admin");
    }

    let session = harness
        .identity()
        .create_session(realm, user.id(), &SessionContext::default())
        .expect("session");
    harness
        .identity()
        .issue_tokens(realm, user.id(), session.id())
        .expect("issue")
        .access_token()
        .to_string()
}

// ── AC-4: 401 without Authorization header ────────────────────────────────────

#[tokio::test]
async fn bootstrap_returns_401_without_auth() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/cluster/bootstrap")
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn status_returns_401_without_auth() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/cluster/status")
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn transfer_leadership_returns_401_without_auth() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/cluster/transfer-leadership")
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ── AC-5: 403 for non-admin token ─────────────────────────────────────────────

#[tokio::test]
async fn bootstrap_returns_403_for_non_admin() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = issue_token(&h, &realm, "user@example.com", false).await;
    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/cluster/bootstrap")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn status_returns_403_for_non_admin() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = issue_token(&h, &realm, "user@example.com", false).await;
    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/cluster/status")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn transfer_leadership_returns_403_for_non_admin() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = issue_token(&h, &realm, "user@example.com", false).await;
    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/cluster/transfer-leadership")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ── Single-node 503 for authenticated admin ───────────────────────────────────

#[tokio::test]
async fn bootstrap_returns_503_in_single_node_mode() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = issue_token(&h, &realm, "admin@example.com", true).await;
    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/cluster/bootstrap")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn status_returns_503_in_single_node_mode() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = issue_token(&h, &realm, "admin@example.com", true).await;
    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/cluster/status")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn transfer_leadership_returns_503_in_single_node_mode() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = issue_token(&h, &realm, "admin@example.com", true).await;
    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/cluster/transfer-leadership")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .header("content-type", "application/json")
                .body(Body::from(r#"{"target_node_id": 2}"#))
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}
