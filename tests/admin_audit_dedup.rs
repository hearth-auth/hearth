//! Integration tests: admin-API user mutations emit exactly one audit event each.
//!
//! Regression guard for HEA-1950: admin_create_user / admin_update_user /
//! admin_delete_user previously emitted two events per mutation — one from the
//! identity layer with actor="system" and a second from the handler with
//! actor=<admin_user_id>.  After the fix each mutation emits exactly one event
//! carrying the real admin actor.
//!
//! Also confirms that the self-registration path (POST /users) is unaffected
//! and still emits exactly one UserCreated event.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hearth::audit::{AuditAction, AuditQuery};
use hearth::core::RealmId;
use hearth::identity::{CreateUserRequest, SessionContext};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use tower::ServiceExt as _;

// ===== helpers =====

fn build_app(h: &common::TestHarness) -> axum::Router {
    router(Arc::new(AppState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
    )))
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body bytes");
    serde_json::from_slice(&bytes).expect("parse JSON body")
}

/// Creates an admin user directly via the identity engine (not HTTP) and
/// returns (bearer_token, admin_user_id_string).
async fn setup_admin(h: &common::TestHarness, realm: &RealmId) -> (String, String) {
    let admin = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: "admin@audit-dedup.example".into(),
                display_name: "Admin".into(),
                first_name: "Admin".into(),
                last_name: "User".into(),
                attributes: Default::default(),
            },
        )
        .expect("create admin user");

    let admin_id = admin.id().as_uuid().to_string();

    let role = h
        .rbac()
        .get_role_by_name(realm, "realm.admin")
        .expect("role lookup")
        .expect("realm.admin seeded");
    h.rbac()
        .assign_role(
            realm,
            &AssignRoleRequest {
                subject: Subject::User(admin.id().clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign admin role");

    let session = h
        .identity()
        .create_session(realm, admin.id(), &SessionContext::default())
        .expect("session");
    let token = h
        .identity()
        .issue_tokens(realm, admin.id(), session.id())
        .expect("issue tokens")
        .access_token()
        .to_string();

    (token, admin_id)
}

// ===== UserCreated =====

/// Admin POST /admin/users must emit exactly one UserCreated event for the new
/// user, and that event's actor must be the admin's user ID — not "system".
///
/// Before the HEA-1950 fix this produces two UserCreated events: one from the
/// identity engine (actor="system") and one from the handler (actor=admin_id).
#[tokio::test]
async fn admin_create_user_emits_exactly_one_user_created_with_actor() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed realm");
    let (token, admin_id) = setup_admin(&h, &realm).await;
    let realm_uuid = realm.as_uuid().to_string();

    let app = build_app(&h);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/users")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", &realm_uuid)
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"email":"newuser@audit-dedup.example","display_name":"New User","first_name":"New","last_name":"User"}"#,
                ))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::CREATED, "expected 201 Created");
    let body = body_json(resp).await;
    let new_user_id = body["id"].as_str().expect("response contains user id");

    // Query UserCreated events for only the newly created user.
    let all_created = h
        .audit()
        .query(&AuditQuery {
            action: Some(AuditAction::UserCreated),
            ..AuditQuery::for_realm(realm.clone())
        })
        .expect("audit query");

    let for_new_user: Vec<_> = all_created
        .iter()
        .filter(|e| e.resource_id == new_user_id)
        .collect();

    assert_eq!(
        for_new_user.len(),
        1,
        "expected exactly 1 UserCreated for new user (got {}); \
         duplicate emit from admin handler not fixed",
        for_new_user.len()
    );
    assert_eq!(
        for_new_user[0].actor, admin_id,
        "UserCreated actor must be the admin's user ID, not 'system'"
    );
    // Confirm the metadata carries via=admin_api for auditability.
    let meta = for_new_user[0]
        .metadata
        .as_ref()
        .expect("UserCreated should carry metadata");
    assert_eq!(
        meta["via"].as_str(),
        Some("admin_api"),
        "metadata.via must be 'admin_api'"
    );
}

// ===== UserUpdated =====

/// Admin PATCH /admin/users/{id} must emit exactly one UserUpdated event with
/// the real admin actor — not "system".
#[tokio::test]
async fn admin_update_user_emits_exactly_one_user_updated_with_actor() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed realm");
    let (token, admin_id) = setup_admin(&h, &realm).await;
    let realm_uuid = realm.as_uuid().to_string();

    // Create the target user directly via the engine (no audit confusion).
    let target = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "target@audit-dedup.example".into(),
                display_name: "Target".into(),
                first_name: "Target".into(),
                last_name: "User".into(),
                attributes: Default::default(),
            },
        )
        .expect("create target user");
    let target_id = target.id().as_uuid().to_string();

    let app = build_app(&h);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/admin/users/{target_id}"))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", &realm_uuid)
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"display_name":"Updated Name"}"#))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::OK, "expected 200 OK");

    let updated_events = h
        .audit()
        .query(&AuditQuery {
            action: Some(AuditAction::UserUpdated),
            ..AuditQuery::for_realm(realm.clone())
        })
        .expect("audit query");

    let for_target: Vec<_> = updated_events
        .iter()
        .filter(|e| e.resource_id == target_id)
        .collect();

    assert_eq!(
        for_target.len(),
        1,
        "expected exactly 1 UserUpdated for target user (got {}); \
         duplicate emit from admin handler not fixed",
        for_target.len()
    );
    assert_eq!(
        for_target[0].actor, admin_id,
        "UserUpdated actor must be the admin's user ID, not 'system'"
    );
}

// ===== UserDeleted =====

/// Admin DELETE /admin/users/{id} must emit exactly one UserDeleted event with
/// the real admin actor — not "system".
#[tokio::test]
async fn admin_delete_user_emits_exactly_one_user_deleted_with_actor() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed realm");
    let (token, admin_id) = setup_admin(&h, &realm).await;
    let realm_uuid = realm.as_uuid().to_string();

    let target = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "target-del@audit-dedup.example".into(),
                display_name: "Delete Me".into(),
                first_name: "Delete".into(),
                last_name: "Me".into(),
                attributes: Default::default(),
            },
        )
        .expect("create target user");
    let target_id = target.id().as_uuid().to_string();

    let app = build_app(&h);
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/admin/users/{target_id}"))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", &realm_uuid)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::NO_CONTENT, "expected 204");

    let deleted_events = h
        .audit()
        .query(&AuditQuery {
            action: Some(AuditAction::UserDeleted),
            ..AuditQuery::for_realm(realm.clone())
        })
        .expect("audit query");

    let for_target: Vec<_> = deleted_events
        .iter()
        .filter(|e| e.resource_id == target_id)
        .collect();

    assert_eq!(
        for_target.len(),
        1,
        "expected exactly 1 UserDeleted for target user (got {}); \
         duplicate emit from admin handler not fixed",
        for_target.len()
    );
    assert_eq!(
        for_target[0].actor, admin_id,
        "UserDeleted actor must be the admin's user ID, not 'system'"
    );
}

// ===== Self-registration coverage (must still emit exactly one UserCreated) =====

/// POST /users (self-registration) must still emit exactly one UserCreated.
/// This is a retained-coverage check: the fix must not break non-admin paths.
#[tokio::test]
async fn self_registration_emits_exactly_one_user_created() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    let realm_uuid = realm.as_uuid().to_string();

    let app = build_app(&h);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/users")
                .header("X-Realm-ID", &realm_uuid)
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"email":"selfreg@audit-dedup.example","display_name":"Self Reg","first_name":"Self","last_name":"Reg"}"#,
                ))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::CREATED, "expected 201");
    let body = body_json(resp).await;
    let new_user_id = body["id"].as_str().expect("user id in response");

    let events = h
        .audit()
        .query(&AuditQuery {
            action: Some(AuditAction::UserCreated),
            ..AuditQuery::for_realm(realm.clone())
        })
        .expect("audit query");

    let for_user: Vec<_> = events
        .iter()
        .filter(|e| e.resource_id == new_user_id)
        .collect();

    assert_eq!(
        for_user.len(),
        1,
        "self-registration must emit exactly 1 UserCreated (got {})",
        for_user.len()
    );
    // Self-registration is anonymous — actor must be "system" (no attribution).
    assert_eq!(
        for_user[0].actor, "system",
        "self-registration actor should be 'system'"
    );
}
