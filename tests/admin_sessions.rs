//! Integration tests for admin REST API session endpoints.
//!
//! Covers:
//! - `GET  /admin/users/{id}/sessions` — list active sessions for a user
//! - `DELETE /admin/sessions/{id}` — hard-revoke a specific session

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::core::RealmId;
use hearth::identity::{CreateUserRequest, SessionContext};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use tower::ServiceExt as _;

fn build_app(h: &common::TestHarness) -> axum::Router {
    let state = Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()));
    router(state)
}

fn issue_admin_token(h: &common::TestHarness, realm: &RealmId) -> String {
    let user = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("admin-{}@test.invalid", uuid::Uuid::new_v4()),
                display_name: "Admin".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create admin user");

    let role = h
        .rbac()
        .get_role_by_name(realm, "realm.admin")
        .expect("lookup")
        .expect("seeded");
    h.rbac()
        .assign_role(
            realm,
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
        .create_session(realm, user.id(), &SessionContext::default())
        .expect("create session");

    h.identity()
        .issue_tokens(realm, user.id(), session.id())
        .expect("issue tokens")
        .access_token()
        .to_string()
}

// ── GET /admin/users/{id}/sessions ───────────────────────────────────────────

#[tokio::test]
async fn list_sessions_returns_user_sessions() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = issue_admin_token(&h, &realm);

    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "alice@test.invalid".into(),
                display_name: "Alice".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    let session = h
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("create session");

    let resp = build_app(&h)
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/admin/users/{}/sessions", user.id().as_uuid()))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("parse JSON");
    let items = body["items"].as_array().expect("items array");
    assert!(!items.is_empty(), "should have at least one session");
    let found = items
        .iter()
        .any(|s| s["id"].as_str() == Some(&session.id().as_uuid().to_string()));
    assert!(found, "created session must appear in the list");
}

#[tokio::test]
async fn list_sessions_empty_for_user_with_no_sessions() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = issue_admin_token(&h, &realm);

    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "bob@test.invalid".into(),
                display_name: "Bob".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let resp = build_app(&h)
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/admin/users/{}/sessions", user.id().as_uuid()))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("parse JSON");
    let items = body["items"].as_array().expect("items array");
    assert!(
        items.is_empty(),
        "user with no sessions must return empty list"
    );
}

#[tokio::test]
async fn list_sessions_requires_auth() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();

    let resp = build_app(&h)
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/admin/users/{}/sessions", uuid::Uuid::new_v4()))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ── DELETE /admin/sessions/{id} ───────────────────────────────────────────────

#[tokio::test]
async fn revoke_session_returns_204() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = issue_admin_token(&h, &realm);

    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "carol@test.invalid".into(),
                display_name: "Carol".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    let session = h
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("create session");

    let resp = build_app(&h)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/admin/sessions/{}", session.id().as_uuid()))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "revoke must return 204"
    );
}

#[tokio::test]
async fn revoke_session_actually_invalidates_session() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = issue_admin_token(&h, &realm);

    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "dave@test.invalid".into(),
                display_name: "Dave".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    let session = h
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("create session");
    let session_id = session.id().clone();

    build_app(&h)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/admin/sessions/{}", session_id.as_uuid()))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send request");

    // Re-list sessions; the revoked session must not appear in the active list.
    let list_resp = build_app(&h)
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/admin/users/{}/sessions", user.id().as_uuid()))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send request");
    assert_eq!(list_resp.status(), StatusCode::OK);
    let bytes = to_bytes(list_resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("parse JSON");
    let items = body["items"].as_array().expect("items");
    assert!(
        items
            .iter()
            .all(|s| s["id"].as_str() != Some(&session_id.as_uuid().to_string())),
        "revoked session must not appear in subsequent list"
    );
}

#[tokio::test]
async fn revoke_session_unknown_id_returns_404() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = issue_admin_token(&h, &realm);

    let resp = build_app(&h)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/admin/sessions/{}", uuid::Uuid::new_v4()))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn revoke_session_requires_auth() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();

    let resp = build_app(&h)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/admin/sessions/{}", uuid::Uuid::new_v4()))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
