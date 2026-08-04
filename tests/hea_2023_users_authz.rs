//! HEA-2023 regression: `POST /users` must enforce admin authN + authZ.
//!
//! Before the fix this handler read only the `X-Realm-ID` header (a tenant
//! identifier, not a secret) and performed no token validation or permission
//! check — an unauthenticated caller could inject `Active` users into any realm
//! whose UUID they knew (registration-control bypass, federation pre-seeding,
//! attribute-driven claim injection).
//!
//! The handler now mirrors `admin_create_user`: it requires a valid admin
//! bearer token carrying `hearth.users.admin` (or `hearth.admin`) and binds the
//! target realm to the validated token, never to the raw header alone.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hearth::core::RealmId;
use hearth::identity::{CreateUserRequest, SessionContext};
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

/// Mints an access token for a freshly created user in `realm`, assigning the
/// named seeded role. Returns the bearer token string.
async fn token_with_role(
    h: &common::TestHarness,
    realm: &RealmId,
    email: &str,
    role_name: &str,
) -> String {
    let user = h
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

    let role = h
        .rbac()
        .get_role_by_name(realm, role_name)
        .expect("role lookup")
        .unwrap_or_else(|| panic!("seeded role '{role_name}' missing — realm seeded?"));
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
        .expect("assign role");

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

const CREATE_BODY: &str =
    r#"{"email":"victim@corp.example","display_name":"V","first_name":"V","last_name":"V"}"#;

/// No `Authorization` header at all → 401, and no user is created.
#[tokio::test]
async fn post_users_without_token_is_unauthorized() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    let app = build_app(&h);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/users")
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .header("Content-Type", "application/json")
                .body(Body::from(CREATE_BODY))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "unauthenticated POST /users must be rejected (was the HEA-2023 hole)"
    );
    assert!(
        h.identity()
            .get_user_by_email(&realm, "victim@corp.example")
            .expect("lookup")
            .is_none(),
        "no user may be created without authentication"
    );
}

/// A syntactically-bearer but invalid token → 401, and no user is created.
#[tokio::test]
async fn post_users_with_invalid_token_is_unauthorized() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    let app = build_app(&h);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/users")
                .header("Authorization", "Bearer not-a-real-token")
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .header("Content-Type", "application/json")
                .body(Body::from(CREATE_BODY))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(h
        .identity()
        .get_user_by_email(&realm, "victim@corp.example")
        .expect("lookup")
        .is_none());
}

/// An authenticated user WITHOUT a users-admin permission → 403.
#[tokio::test]
async fn post_users_with_non_admin_token_is_forbidden() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed realm");

    // A plain user with a session/token but no admin role.
    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "plain@corp.example".into(),
                display_name: "Plain".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    let session = h
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session");
    let token = h
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("issue")
        .access_token()
        .to_string();

    let app = build_app(&h);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/users")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .header("Content-Type", "application/json")
                .body(Body::from(CREATE_BODY))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a non-admin principal must not create users"
    );
    assert!(h
        .identity()
        .get_user_by_email(&realm, "victim@corp.example")
        .expect("lookup")
        .is_none());
}

/// A `hearth.users.admin` token in the matching realm → 201, user created there.
#[tokio::test]
async fn post_users_with_users_admin_token_succeeds() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed realm");
    let token = token_with_role(&h, &realm, "usersadmin@corp.example", "hearth.users.admin").await;

    let app = build_app(&h);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/users")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .header("Content-Type", "application/json")
                .body(Body::from(CREATE_BODY))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::CREATED, "expected 201 Created");
    assert!(
        h.identity()
            .get_user_by_email(&realm, "victim@corp.example")
            .expect("lookup")
            .is_some(),
        "user must be created in the admin's realm"
    );
}

/// A `hearth.users.admin` token issued in realm A cannot create a user in
/// realm B by spoofing the `X-Realm-ID` header: the token fails validation
/// against realm B's signing key, so the request is rejected (401) and no user
/// lands in realm B. This proves creation is bound to the validated token, not
/// the attacker-controllable header.
#[tokio::test]
async fn post_users_cannot_cross_realm_via_header_spoof() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm_a = h.create_realm();
    let realm_b = h.create_realm();
    h.rbac().seed_realm(&realm_a).expect("seed realm A");
    h.rbac().seed_realm(&realm_b).expect("seed realm B");

    let token_a = token_with_role(
        &h,
        &realm_a,
        "usersadmin-a@corp.example",
        "hearth.users.admin",
    )
    .await;

    let app = build_app(&h);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/users")
                // Realm A token, but claim to be operating in realm B.
                .header("Authorization", format!("Bearer {token_a}"))
                .header("X-Realm-ID", realm_b.as_uuid().to_string())
                .header("Content-Type", "application/json")
                .body(Body::from(CREATE_BODY))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "a realm-A token must not authenticate against realm B"
    );
    assert!(
        h.identity()
            .get_user_by_email(&realm_b, "victim@corp.example")
            .expect("lookup")
            .is_none(),
        "no user may be created in a realm the token is not scoped to"
    );
}
