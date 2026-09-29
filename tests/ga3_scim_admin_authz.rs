//! GA audit round 3 — SCIM authorization parity (G-5, G-6).
//!
//! ## G-5 — admin-JWT fallback dropped the permission set
//!
//! When a realm has no `scim_bearer_token_hash`, SCIM falls back to the admin
//! JWT. The outer admin gate admits *any* admin-grade permission, and the
//! resulting `ScimAuth` carried no permissions, so a caller holding only
//! `hearth.clients.admin` (or `hearth.agents.admin`, `hearth.realm.admin`)
//! could create, modify and delete every user in the realm — superusers
//! included — while the REST twin (`/admin/users*`) refuses it with 403.
//! SCIM must require the same permission REST does: `hearth.users.admin` for
//! `/Users`, `hearth.realm.admin` for `/Groups` (organizations).
//!
//! ## G-6 — provisioning-token principal guard covered two of five admin perms
//!
//! A realm-scoped SCIM bearer token may not act on principals that hold admin
//! authority. The guard protected only `hearth.admin` and `hearth.users.admin`;
//! a holder of `hearth.realm.admin`, `hearth.clients.admin` or
//! `hearth.agents.admin` was fair game. The protected set must be the same
//! list the admin gate itself accepts.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hearth::core::{RealmId, UserId};
use hearth::identity::{
    CreateRealmRequest, CreateUserRequest, RealmConfig, SessionContext, UpdateRealmRequest,
};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use serde_json::json;
use sha2::{Digest, Sha256};
use tower::ServiceExt as _;

// ── helpers ──────────────────────────────────────────────────────────────────

fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn build_app(h: &common::TestHarness) -> axum::Router {
    router(Arc::new(AppState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
    )))
}

/// A seeded realm with NO SCIM bearer token: the admin-JWT fallback is live.
fn jwt_realm(h: &common::TestHarness) -> RealmId {
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("ga3-scim-jwt-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");
    h.rbac().seed_realm(realm.id()).expect("seed realm");
    realm.id().clone()
}

/// A seeded realm WITH a SCIM bearer token; returns `(realm, plaintext token)`.
fn scim_token_realm(h: &common::TestHarness) -> (RealmId, String) {
    let token = format!("ga3-scim-token-{}", uuid::Uuid::new_v4());
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("ga3-scim-tok-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");
    h.identity()
        .update_realm(
            realm.id(),
            &UpdateRealmRequest {
                config: Some(RealmConfig {
                    scim_bearer_token_hash: Some(sha256_hex(&token)),
                    ..RealmConfig::default()
                }),
                ..UpdateRealmRequest::default()
            },
        )
        .expect("set scim token");
    h.rbac().seed_realm(realm.id()).expect("seed realm");
    (realm.id().clone(), token)
}

fn create_user(h: &common::TestHarness, realm: &RealmId, email: &str) -> UserId {
    h.identity()
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
        .expect("create user")
        .id()
        .clone()
}

/// Creates a user holding exactly the named seeded role (`hearth.clients.admin`,
/// `hearth.users.admin`, `realm.admin`, ...).
fn user_with_role(h: &common::TestHarness, realm: &RealmId, email: &str, role: &str) -> UserId {
    let user_id = create_user(h, realm, email);
    let role = h
        .rbac()
        .get_role_by_name(realm, role)
        .expect("role lookup")
        .unwrap_or_else(|| panic!("seeded role '{role}' missing"));
    h.rbac()
        .assign_role(
            realm,
            &AssignRoleRequest {
                subject: Subject::User(user_id.clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign role");
    user_id
}

fn mint_token(h: &common::TestHarness, realm: &RealmId, user_id: &UserId) -> String {
    let session = h
        .identity()
        .create_session(realm, user_id, &SessionContext::default())
        .expect("session");
    h.identity()
        .issue_tokens(realm, user_id, session.id())
        .expect("issue tokens")
        .access_token()
        .to_string()
}

/// Mints a bearer token for a fresh user holding exactly `role`.
fn token_with_role(h: &common::TestHarness, realm: &RealmId, role: &str) -> String {
    let user_id = user_with_role(
        h,
        realm,
        &format!("{role}-{}@ga3.test", uuid::Uuid::new_v4()),
        role,
    );
    mint_token(h, realm, &user_id)
}

async fn scim(
    app: &axum::Router,
    method: &str,
    path: &str,
    realm: &RealmId,
    bearer: &str,
    body: Option<serde_json::Value>,
) -> StatusCode {
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/scim+json")
        .header("x-realm-id", realm.as_uuid().to_string())
        .header("authorization", format!("Bearer {bearer}"))
        .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
        .expect("build request");
    app.clone().oneshot(req).await.expect("oneshot").status()
}

fn user_payload(email: &str) -> serde_json::Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": email,
        "name": {"givenName": "New", "familyName": "User"},
        "emails": [{"value": email, "primary": true}],
        "active": true
    })
}

fn patch_email_payload(email: &str) -> serde_json::Value {
    json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "replace",
            "path": "emails",
            "value": [{"value": email, "primary": true}]
        }]
    })
}

fn group_payload(name: &str) -> serde_json::Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": name
    })
}

// ── G-5: admin-JWT fallback must require the REST permission ─────────────────

/// `hearth.clients.admin` alone must not provision users over SCIM (REST
/// `POST /admin/users` answers 403 to the same token).
#[tokio::test]
async fn clients_admin_cannot_create_user_via_scim_fallback() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = jwt_realm(&h);
    let app = build_app(&h);
    let token = token_with_role(&h, &realm, "hearth.clients.admin");

    let status = scim(
        &app,
        "POST",
        "/scim/v2/Users",
        &realm,
        &token,
        Some(user_payload("victim@ga3.test")),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "clients.admin must be refused"
    );
    assert!(
        h.identity()
            .get_user_by_email(&realm, "victim@ga3.test")
            .expect("lookup")
            .is_none(),
        "no user may be created by a refused call"
    );
}

/// `hearth.users.admin` — the permission REST requires — still provisions.
#[tokio::test]
async fn users_admin_can_create_user_via_scim_fallback() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = jwt_realm(&h);
    let app = build_app(&h);
    let token = token_with_role(&h, &realm, "hearth.users.admin");

    let status = scim(
        &app,
        "POST",
        "/scim/v2/Users",
        &realm,
        &token,
        Some(user_payload("provisioned@ga3.test")),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
    assert!(h
        .identity()
        .get_user_by_email(&realm, "provisioned@ga3.test")
        .expect("lookup")
        .is_some());
}

/// The audit trigger: a clients-admin rewriting a superuser's email over SCIM
/// (then resetting the password) — must be 403 for PATCH, PUT and DELETE, and
/// the superuser must be untouched.
#[tokio::test]
async fn clients_admin_cannot_modify_or_delete_superuser_via_scim_fallback() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = jwt_realm(&h);
    let app = build_app(&h);
    let superuser = user_with_role(&h, &realm, "root@ga3.test", "realm.admin");
    let token = token_with_role(&h, &realm, "hearth.clients.admin");
    let uri = format!("/scim/v2/Users/{}", superuser.as_uuid());

    let patch = scim(
        &app,
        "PATCH",
        &uri,
        &realm,
        &token,
        Some(patch_email_payload("attacker@evil.test")),
    )
    .await;
    let put = scim(
        &app,
        "PUT",
        &uri,
        &realm,
        &token,
        Some(user_payload("attacker@evil.test")),
    )
    .await;
    let delete = scim(&app, "DELETE", &uri, &realm, &token, None).await;

    assert_eq!(patch, StatusCode::FORBIDDEN, "PATCH");
    assert_eq!(put, StatusCode::FORBIDDEN, "PUT");
    assert_eq!(delete, StatusCode::FORBIDDEN, "DELETE");
    let stored = h
        .identity()
        .get_user(&realm, &superuser)
        .expect("lookup")
        .expect("superuser must still exist");
    assert_eq!(stored.email(), "root@ga3.test", "email must be untouched");
}

/// Reads follow REST too: `GET /admin/users` needs `hearth.users.admin`, so a
/// clients-admin may not enumerate the directory over SCIM either.
#[tokio::test]
async fn clients_admin_cannot_list_users_via_scim_fallback() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = jwt_realm(&h);
    let app = build_app(&h);
    let token = token_with_role(&h, &realm, "hearth.clients.admin");

    let status = scim(&app, "GET", "/scim/v2/Users", &realm, &token, None).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// SCIM Groups are organizations; their admin twin (gRPC organization RPCs)
/// requires `hearth.realm.admin`. A users-admin may not create or delete them.
#[tokio::test]
async fn groups_require_realm_admin_via_scim_fallback() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = jwt_realm(&h);
    let app = build_app(&h);
    let users_admin = token_with_role(&h, &realm, "hearth.users.admin");
    let realm_admin = token_with_role(&h, &realm, "hearth.realm.admin");

    let refused = scim(
        &app,
        "POST",
        "/scim/v2/Groups",
        &realm,
        &users_admin,
        Some(group_payload("Refused")),
    )
    .await;
    let created = scim(
        &app,
        "POST",
        "/scim/v2/Groups",
        &realm,
        &realm_admin,
        Some(group_payload("Engineering")),
    )
    .await;

    assert_eq!(refused, StatusCode::FORBIDDEN, "users.admin on /Groups");
    assert_eq!(created, StatusCode::CREATED, "realm.admin on /Groups");
}

// ── G-6: the provisioning-token guard must cover every admin permission ──────

/// A SCIM bearer token may not modify, replace or delete a principal holding
/// any admin-grade permission — including the three the guard used to miss.
#[tokio::test]
async fn scim_token_cannot_act_on_any_sub_admin_principal() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm, token) = scim_token_realm(&h);
    let app = build_app(&h);

    for role in [
        "hearth.realm.admin",
        "hearth.clients.admin",
        "hearth.agents.admin",
    ] {
        let email = format!("{role}@ga3.test");
        let target = user_with_role(&h, &realm, &email, role);
        let uri = format!("/scim/v2/Users/{}", target.as_uuid());

        let patch = scim(
            &app,
            "PATCH",
            &uri,
            &realm,
            &token,
            Some(patch_email_payload("attacker@evil.test")),
        )
        .await;
        let put = scim(
            &app,
            "PUT",
            &uri,
            &realm,
            &token,
            Some(user_payload("attacker@evil.test")),
        )
        .await;
        let delete = scim(&app, "DELETE", &uri, &realm, &token, None).await;

        assert_eq!(patch, StatusCode::FORBIDDEN, "PATCH on {role} holder");
        assert_eq!(put, StatusCode::FORBIDDEN, "PUT on {role} holder");
        assert_eq!(delete, StatusCode::FORBIDDEN, "DELETE on {role} holder");
        let stored = h
            .identity()
            .get_user(&realm, &target)
            .expect("lookup")
            .unwrap_or_else(|| panic!("{role} holder must still exist"));
        assert_eq!(
            stored.email(),
            email,
            "{role} holder's email must be untouched"
        );
    }
}

/// Regression guard: the provisioning token still manages ordinary users.
#[tokio::test]
async fn scim_token_still_manages_plain_users() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm, token) = scim_token_realm(&h);
    let app = build_app(&h);
    let plain = create_user(&h, &realm, "plain@ga3.test");
    let uri = format!("/scim/v2/Users/{}", plain.as_uuid());

    let patch = scim(
        &app,
        "PATCH",
        &uri,
        &realm,
        &token,
        Some(patch_email_payload("renamed@ga3.test")),
    )
    .await;

    assert_eq!(patch, StatusCode::OK);
    let stored = h
        .identity()
        .get_user(&realm, &plain)
        .expect("lookup")
        .expect("plain user exists");
    assert_eq!(stored.email(), "renamed@ga3.test");
}
