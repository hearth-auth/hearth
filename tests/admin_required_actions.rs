//! Integration tests for HEA-755: POST/DELETE /admin/users/{id}/required-actions.
//!
//! Covers all five acceptance criteria from the issue spec.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::core::RealmId;
use hearth::identity::{CreateUserRequest, RequiredAction, SessionContext};
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

/// Creates a realm, seeds RBAC, and returns an admin token + a target user ID.
async fn setup(harness: &common::TestHarness) -> (RealmId, String, String) {
    let realm = harness.create_realm();
    harness.rbac().seed_realm(&realm).expect("seed rbac");

    // Target user (non-admin)
    let target = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "target@example.com".into(),
                display_name: "Target".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create target user");

    // Admin user
    let admin = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "admin@example.com".into(),
                display_name: "Admin".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create admin user");

    let role = harness
        .rbac()
        .get_role_by_name(&realm, "realm.admin")
        .expect("lookup role")
        .expect("role seeded");

    harness
        .rbac()
        .assign_role(
            &realm,
            &AssignRoleRequest {
                subject: Subject::User(admin.id().clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign admin role");

    let session = harness
        .identity()
        .create_session(&realm, admin.id(), &SessionContext::default())
        .expect("create session");
    let token = harness
        .identity()
        .issue_tokens(&realm, admin.id(), session.id())
        .expect("issue tokens")
        .access_token()
        .to_string();

    (realm, token, target.id().as_uuid().to_string())
}

// ---------------------------------------------------------------------------
// AC-1: POST adds action; returns 200 with user_id + pending_actions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ac1_add_action_returns_200_with_pending_set() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm, admin_token, target_id) = setup(&h).await;
    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/admin/users/{target_id}/required-actions"))
                .header("Authorization", format!("Bearer {admin_token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"action":"UPDATE_PASSWORD"}"#))
                .expect("build request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 1_000_000).await.expect("bytes");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");

    assert_eq!(body["user_id"].as_str().expect("user_id"), target_id);
    let actions: Vec<&str> = body["pending_actions"]
        .as_array()
        .expect("pending_actions array")
        .iter()
        .map(|v| v.as_str().expect("str"))
        .collect();
    assert!(
        actions.contains(&"UPDATE_PASSWORD"),
        "expected UPDATE_PASSWORD in {actions:?}"
    );
}

// ---------------------------------------------------------------------------
// AC-2: DELETE removes action; returns 200 with updated set
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ac2_delete_action_returns_200_with_updated_set() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm, admin_token, target_id) = setup(&h).await;

    let target_uuid: uuid::Uuid = target_id.parse().expect("uuid");
    let realm_id = realm.clone();
    let user_id = hearth::core::UserId::new(target_uuid);
    // Pre-seed the pending action directly via engine so we can test removal.
    h.identity()
        .add_required_action(&realm_id, &user_id, RequiredAction::UpdatePassword)
        .expect("pre-seed action");

    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/admin/users/{target_id}/required-actions/UPDATE_PASSWORD"
                ))
                .header("Authorization", format!("Bearer {admin_token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 1_000_000).await.expect("bytes");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");

    let actions: Vec<&str> = body["pending_actions"]
        .as_array()
        .expect("pending_actions array")
        .iter()
        .map(|v| v.as_str().expect("str"))
        .collect();
    assert!(
        !actions.contains(&"UPDATE_PASSWORD"),
        "UPDATE_PASSWORD should be removed, got {actions:?}"
    );
}

// ---------------------------------------------------------------------------
// AC-3: Unknown action name → 422 with descriptive error
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ac3_unknown_action_returns_422() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm, admin_token, target_id) = setup(&h).await;
    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/admin/users/{target_id}/required-actions"))
                .header("Authorization", format!("Bearer {admin_token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"action":"DOES_NOT_EXIST"}"#))
                .expect("build request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

// ---------------------------------------------------------------------------
// AC-4: Non-admin token → 403 Forbidden
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ac4_non_admin_token_returns_403() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed rbac");

    // Non-admin user
    let non_admin = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "user@example.com".into(),
                display_name: "User".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let session = h
        .identity()
        .create_session(&realm, non_admin.id(), &SessionContext::default())
        .expect("session");
    let token = h
        .identity()
        .issue_tokens(&realm, non_admin.id(), session.id())
        .expect("tokens")
        .access_token()
        .to_string();

    let app = build_app(&h).await;
    let fake_user_id = uuid::Uuid::new_v4().to_string();

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/admin/users/{fake_user_id}/required-actions"))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"action":"UPDATE_PASSWORD"}"#))
                .expect("build request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ---------------------------------------------------------------------------
// AC-5: Adding an already-present action is idempotent → 200, no duplicate
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ac5_add_idempotent_no_duplicate() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm, admin_token, target_id) = setup(&h).await;
    let app = build_app(&h).await;

    // First add
    let r1 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/admin/users/{target_id}/required-actions"))
                .header("Authorization", format!("Bearer {admin_token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"action":"UPDATE_PASSWORD"}"#))
                .expect("build r1"),
        )
        .await
        .expect("r1");
    assert_eq!(r1.status(), StatusCode::OK);

    // Second add (idempotent)
    let r2 = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/admin/users/{target_id}/required-actions"))
                .header("Authorization", format!("Bearer {admin_token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"action":"UPDATE_PASSWORD"}"#))
                .expect("build r2"),
        )
        .await
        .expect("r2");
    assert_eq!(r2.status(), StatusCode::OK);

    let bytes = to_bytes(r2.into_body(), 1_000_000).await.expect("bytes");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    let count = body["pending_actions"]
        .as_array()
        .expect("array")
        .iter()
        .filter(|v| v.as_str() == Some("UPDATE_PASSWORD"))
        .count();
    assert_eq!(
        count, 1,
        "UPDATE_PASSWORD must appear exactly once, not {count}"
    );
}
