//! `PATCH /admin/realms/{realm}/config` must be strict (audit §4.13#6, task 20.7).
//!
//! Two defects, one handler shape (the REST route in `protocol::http::admin`
//! and its `/ui` twin in `protocol::web::admin::realms` share it):
//!
//! 1. A misspelled key was silently ignored and the request answered `200`, so
//!    an operator's `defualt_required_actions` looked applied and was not.
//! 2. `default_required_actions` was *replaced* on every request, using an
//!    empty list when the key was absent — so a PATCH that only set
//!    `mfa_methods` wiped the realm's default required actions.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hearth::core::RealmId;
use hearth::identity::{CreateUserRequest, RequiredAction, SessionContext};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use tower::ServiceExt as _;

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
                email: "admin@patch-strict.example".into(),
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
        .expect("lookup role")
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
        .expect("issue tokens")
        .access_token()
        .to_string()
}

async fn patch_config(
    h: &common::TestHarness,
    realm: &RealmId,
    token: &str,
    body: &str,
) -> StatusCode {
    let realm_uuid = realm.as_uuid().to_string();
    build_app(h)
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/admin/realms/{realm_uuid}/config"))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm_uuid.clone())
                .header("Content-Type", "application/json")
                .body(Body::from(body.to_string()))
                .expect("build request"),
        )
        .await
        .expect("oneshot")
        .status()
}

#[tokio::test]
async fn a_misspelled_key_is_refused_instead_of_answering_200() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;

    let status = patch_config(
        &h,
        &realm,
        &token,
        r#"{"defualt_required_actions":["VERIFY_EMAIL"]}"#,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a misspelled key must be refused, not silently ignored with a 200"
    );
}

#[tokio::test]
async fn omitting_default_required_actions_leaves_them_intact() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;

    // Arrange: set a default required action.
    let status = patch_config(
        &h,
        &realm,
        &token,
        r#"{"default_required_actions":["VERIFY_EMAIL"]}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "setup PATCH must succeed");

    // Act: a PATCH that touches an unrelated field and omits the key.
    let status = patch_config(&h, &realm, &token, r#"{"mfa_methods":["totp"]}"#).await;
    assert_eq!(status, StatusCode::OK, "unrelated PATCH must succeed");

    // Assert: the default required actions survived.
    let updated = h
        .identity()
        .get_realm(&realm)
        .expect("get_realm")
        .expect("realm exists");
    assert_eq!(
        updated.config().default_required_actions,
        vec![RequiredAction::VerifyEmail],
        "a PATCH that omits default_required_actions must not clear it"
    );
}

#[tokio::test]
async fn an_explicit_empty_list_still_clears_default_required_actions() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;

    let status = patch_config(
        &h,
        &realm,
        &token,
        r#"{"default_required_actions":["VERIFY_EMAIL"]}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let status = patch_config(&h, &realm, &token, r#"{"default_required_actions":[]}"#).await;
    assert_eq!(status, StatusCode::OK);

    let updated = h
        .identity()
        .get_realm(&realm)
        .expect("get_realm")
        .expect("realm exists");
    assert!(
        updated.config().default_required_actions.is_empty(),
        "an explicit [] must still clear the list"
    );
}
