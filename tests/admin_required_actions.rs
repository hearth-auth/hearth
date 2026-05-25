//! Integration tests for the required-actions admin API (HEA-807).
//!
//! Covers AC-6, AC-7, AC-8:
//! - PATCH /admin/realms/{realm}/users/{id}/required-actions — assign/remove
//! - PATCH /admin/realms/{realm}/config — default_required_actions

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hearth::core::RealmId;
use hearth::identity::{CreateUserRequest, SessionContext};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use tower::ServiceExt as _;

// ===== Helpers =====

fn build_app(h: &common::TestHarness) -> axum::Router {
    router(Arc::new(AppState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
    )))
}

async fn admin_token(h: &common::TestHarness, realm: &RealmId) -> String {
    let user = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: "admin@ra-test.example".into(),
                display_name: "Admin".into(),
                first_name: "Admin".into(),
                last_name: "User".into(),
                attributes: Default::default(),
            },
        )
        .expect("create admin");

    let role = h
        .rbac()
        .get_role_by_name(realm, "realm.admin")
        .expect("lookup")
        .expect("realm.admin seeded");
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
        .expect("session");
    h.identity()
        .issue_tokens(realm, user.id(), session.id())
        .expect("issue")
        .access_token()
        .to_string()
}

async fn non_admin_token(h: &common::TestHarness, realm: &RealmId) -> String {
    let user = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: "nonadmin@ra-test.example".into(),
                display_name: "Non-Admin".into(),
                first_name: "Non".into(),
                last_name: "Admin".into(),
                attributes: Default::default(),
            },
        )
        .expect("create non-admin");

    let session = h
        .identity()
        .create_session(realm, user.id(), &SessionContext::default())
        .expect("session");
    h.identity()
        .issue_tokens(realm, user.id(), session.id())
        .expect("issue")
        .access_token()
        .to_string()
}

async fn create_target_user(h: &common::TestHarness, realm: &RealmId) -> String {
    let user = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: "target@ra-test.example".into(),
                display_name: "Target User".into(),
                first_name: "Target".into(),
                last_name: "User".into(),
                attributes: Default::default(),
            },
        )
        .expect("create target user");
    user.id().as_uuid().to_string()
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body bytes");
    serde_json::from_slice(&bytes).expect("parse JSON body")
}

// ===== required-actions endpoint tests =====

#[tokio::test]
async fn assign_adds_action_to_user() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;
    let uid = create_target_user(&h, &realm).await;
    let realm_uuid = realm.as_uuid().to_string();

    let app = build_app(&h);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!(
                    "/admin/realms/{realm_uuid}/users/{uid}/required-actions"
                ))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm_uuid.clone())
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"add":["VERIFY_EMAIL"],"remove":[]}"#))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let actions = body["required_actions"]
        .as_array()
        .expect("required_actions array");
    assert!(
        actions.iter().any(|v| v.as_str() == Some("VERIFY_EMAIL")),
        "VERIFY_EMAIL must appear in required_actions; got {actions:?}"
    );
}

#[tokio::test]
async fn remove_removes_action_from_user() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;
    let uid = create_target_user(&h, &realm).await;
    let realm_uuid = realm.as_uuid().to_string();
    let app = build_app(&h);

    // First assign VERIFY_EMAIL.
    app.clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!(
                    "/admin/realms/{realm_uuid}/users/{uid}/required-actions"
                ))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm_uuid.clone())
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"add":["VERIFY_EMAIL"],"remove":[]}"#))
                .expect("build"),
        )
        .await
        .expect("assign");

    // Now remove it.
    let resp = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!(
                    "/admin/realms/{realm_uuid}/users/{uid}/required-actions"
                ))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm_uuid.clone())
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"add":[],"remove":["VERIFY_EMAIL"]}"#))
                .expect("build"),
        )
        .await
        .expect("remove");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    // required_actions omitted when empty (skip_serializing_if) or present as []
    let actions = body["required_actions"].as_array();
    let is_empty = actions.map_or(true, |v| v.is_empty());
    assert!(
        is_empty,
        "required_actions must be empty after remove; got {body:?}"
    );
}

#[tokio::test]
async fn non_admin_gets_403() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = non_admin_token(&h, &realm).await;
    let uid = create_target_user(&h, &realm).await;
    let realm_uuid = realm.as_uuid().to_string();

    let app = build_app(&h);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!(
                    "/admin/realms/{realm_uuid}/users/{uid}/required-actions"
                ))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm_uuid.clone())
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"add":["VERIFY_EMAIL"],"remove":[]}"#))
                .expect("build"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "non-admin must receive 403"
    );
}

#[tokio::test]
async fn unknown_action_type_returns_400() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;
    let uid = create_target_user(&h, &realm).await;
    let realm_uuid = realm.as_uuid().to_string();

    let app = build_app(&h);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!(
                    "/admin/realms/{realm_uuid}/users/{uid}/required-actions"
                ))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm_uuid.clone())
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"add":["UNKNOWN_ACTION"],"remove":[]}"#))
                .expect("build"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "unknown action type must return 400"
    );
    let body = body_json(resp).await;
    assert!(
        body["error"]
            .as_str()
            .map(|s| s.contains("UNKNOWN_ACTION"))
            .unwrap_or(false),
        "error message must mention the bad value; got {body:?}"
    );
}

// ===== Realm config endpoint tests =====

#[tokio::test]
async fn patch_realm_config_sets_default_required_actions() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;
    let realm_uuid = realm.as_uuid().to_string();

    let app = build_app(&h);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/admin/realms/{realm_uuid}/config"))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm_uuid.clone())
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"default_required_actions":["VERIFY_EMAIL","UPDATE_PASSWORD"]}"#,
                ))
                .expect("build"),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::OK);

    // Verify it persisted in the identity engine.
    let updated_realm = h
        .identity()
        .get_realm(&realm)
        .expect("get")
        .expect("exists");
    let defaults = updated_realm.config().default_required_actions.clone();
    assert_eq!(
        defaults.len(),
        2,
        "realm config must have 2 default_required_actions; got {defaults:?}"
    );
}

#[tokio::test]
async fn patch_realm_config_unknown_action_returns_400() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;
    let realm_uuid = realm.as_uuid().to_string();

    let app = build_app(&h);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/admin/realms/{realm_uuid}/config"))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm_uuid.clone())
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"default_required_actions":["BOGUS"]}"#))
                .expect("build"),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
