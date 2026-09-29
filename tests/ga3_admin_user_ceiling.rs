//! GA audit round 3 — privilege ceiling on user administration.
//!
//! An admin may not modify, re-email, reset, disable or delete a user who
//! holds an admin-grade permission the admin lacks. `hearth.admin` outranks
//! every sub-admin; a sub-admin may act on a same-or-lower user only when it
//! holds every admin permission the target holds.
//!
//! Before the fix, `hearth.users.admin` alone could rewrite a superuser's
//! email over REST, gRPC or the SCIM admin-JWT fallback, then reset the
//! password — a sub-admin to `hearth.admin` escalation. One shared rule
//! (`hearth::protocol::admin_auth::check_user_admin_ceiling`) now guards every
//! user-administration surface; this file drives each of them.
//!
//! The web console is not here: it admits only `hearth.admin`, which clears
//! the ceiling by construction (pinned by
//! `web_ui_admin::system_realm_sub_admin_cannot_use_console_user_admin`).

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hearth::core::{RealmId, UserId};
use hearth::identity::{CreateRealmRequest, CreateUserRequest, SessionContext, UserStatus};
use hearth::protocol::admin_auth::AdminRateLimiter;
use hearth::protocol::grpc::identity::IdentityAdminSvc;
use hearth::protocol::grpc::server::GrpcState;
use hearth::protocol::http::{router, AppState};
use hearth::protocol::proto::identity::v1::{
    self as pb, identity_admin_service_server::IdentityAdminService,
};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use serde_json::json;
use tower::ServiceExt as _;

// ── fixture ──────────────────────────────────────────────────────────────────

struct Fixture {
    h: common::TestHarness,
    realm: RealmId,
    app: axum::Router,
}

impl Fixture {
    async fn new() -> Self {
        let h = common::TestHarness::embedded().await.expect("harness");
        let realm = h
            .identity()
            .create_realm(&CreateRealmRequest {
                name: format!("ga3-ceiling-{}", uuid::Uuid::new_v4()),
                config: None,
            })
            .expect("create realm")
            .id()
            .clone();
        h.rbac().seed_realm(&realm).expect("seed realm");
        let app = router(Arc::new(AppState::new(
            h.identity_arc(),
            h.rbac_arc(),
            h.audit_arc(),
        )));
        Self { h, realm, app }
    }

    fn grpc(&self) -> IdentityAdminSvc {
        IdentityAdminSvc::new(GrpcState::new(
            self.h.identity_arc(),
            self.h.rbac_arc(),
            self.h.audit_arc(),
            Arc::new(AdminRateLimiter::new()),
        ))
    }

    /// Creates a user holding exactly the named seeded roles.
    fn user(&self, label: &str, roles: &[&str]) -> UserId {
        let email = format!("{label}-{}@ga3.test", uuid::Uuid::new_v4());
        let user_id = self
            .h
            .identity()
            .create_user(
                &self.realm,
                &CreateUserRequest {
                    email,
                    display_name: label.into(),
                    first_name: String::new(),
                    last_name: String::new(),
                    attributes: Default::default(),
                },
            )
            .expect("create user")
            .id()
            .clone();
        for role in roles {
            let role = self
                .h
                .rbac()
                .get_role_by_name(&self.realm, role)
                .expect("role lookup")
                .unwrap_or_else(|| panic!("seeded role '{role}' missing"));
            self.h
                .rbac()
                .assign_role(
                    &self.realm,
                    &AssignRoleRequest {
                        subject: Subject::User(user_id.clone()),
                        role_id: role.id,
                        scope: Scope::Realm,
                        assigned_by: None,
                    },
                )
                .expect("assign role");
        }
        user_id
    }

    fn token(&self, user_id: &UserId) -> String {
        let session = self
            .h
            .identity()
            .create_session(&self.realm, user_id, &SessionContext::default())
            .expect("session");
        self.h
            .identity()
            .issue_tokens(&self.realm, user_id, session.id())
            .expect("issue tokens")
            .access_token()
            .to_string()
    }

    /// A token for a fresh user holding exactly `roles`.
    fn actor(&self, roles: &[&str]) -> String {
        let id = self.user("actor", roles);
        self.token(&id)
    }

    fn email(&self, user_id: &UserId) -> String {
        self.h
            .identity()
            .get_user(&self.realm, user_id)
            .expect("lookup")
            .expect("user must still exist")
            .email()
            .to_string()
    }

    fn status(&self, user_id: &UserId) -> UserStatus {
        self.h
            .identity()
            .get_user(&self.realm, user_id)
            .expect("lookup")
            .expect("user must still exist")
            .status()
    }

    async fn rest(
        &self,
        method: &str,
        uri: &str,
        bearer: &str,
        body: Option<serde_json::Value>,
        content_type: &str,
    ) -> StatusCode {
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", content_type)
            .header("x-realm-id", self.realm.as_uuid().to_string())
            .header("authorization", format!("Bearer {bearer}"))
            .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
            .expect("build request");
        self.app
            .clone()
            .oneshot(req)
            .await
            .expect("oneshot")
            .status()
    }

    async fn admin(
        &self,
        method: &str,
        uri: &str,
        bearer: &str,
        body: Option<serde_json::Value>,
    ) -> StatusCode {
        self.rest(method, uri, bearer, body, "application/json")
            .await
    }

    async fn scim(
        &self,
        method: &str,
        uri: &str,
        bearer: &str,
        body: Option<serde_json::Value>,
    ) -> StatusCode {
        self.rest(method, uri, bearer, body, "application/scim+json")
            .await
    }

    fn grpc_req<T>(&self, token: &str, msg: T) -> tonic::Request<T> {
        let mut r = tonic::Request::new(msg);
        r.metadata_mut().insert(
            "authorization",
            format!("Bearer {token}").parse().expect("valid header"),
        );
        r.metadata_mut().insert(
            "x-realm-id",
            self.realm
                .as_uuid()
                .to_string()
                .parse()
                .expect("valid header"),
        );
        r
    }
}

fn user_uri(id: &UserId) -> String {
    format!("/admin/users/{}", id.as_uuid())
}

fn scim_user_uri(id: &UserId) -> String {
    format!("/scim/v2/Users/{}", id.as_uuid())
}

fn scim_user_payload(email: &str) -> serde_json::Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": email,
        "emails": [{"value": email, "primary": true}],
        "active": true
    })
}

fn scim_patch_email(email: &str) -> serde_json::Value {
    json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "replace",
            "path": "emails",
            "value": [{"value": email, "primary": true}]
        }]
    })
}

// ── REST /admin/users* ───────────────────────────────────────────────────────

/// The escalation itself: a users-admin re-emails a superuser (then resets the
/// password). Must be 403, and the superuser untouched.
#[tokio::test]
async fn rest_users_admin_cannot_reemail_or_delete_superuser() {
    let f = Fixture::new().await;
    let superuser = f.user("root", &["realm.admin"]);
    let before = f.email(&superuser);
    let token = f.actor(&["hearth.users.admin"]);

    let patch = f
        .admin(
            "PATCH",
            &user_uri(&superuser),
            &token,
            Some(json!({"email": "attacker@evil.test"})),
        )
        .await;
    let delete = f.admin("DELETE", &user_uri(&superuser), &token, None).await;

    assert_eq!(patch, StatusCode::FORBIDDEN, "PATCH");
    assert_eq!(delete, StatusCode::FORBIDDEN, "DELETE");
    assert_eq!(f.email(&superuser), before, "email must be untouched");
}

/// Forcing a required action (e.g. `UPDATE_PASSWORD`) and erasing device
/// fingerprints are user modifications too.
#[tokio::test]
async fn rest_users_admin_cannot_reset_superuser_state() {
    let f = Fixture::new().await;
    let superuser = f.user("root", &["realm.admin"]);
    let token = f.actor(&["hearth.users.admin"]);

    let actions = f
        .admin(
            "PATCH",
            &format!(
                "/admin/realms/{}/users/{}/required-actions",
                f.realm.as_uuid(),
                superuser.as_uuid()
            ),
            &token,
            Some(json!({"add": ["UPDATE_PASSWORD"]})),
        )
        .await;
    let fingerprints = f
        .admin(
            "DELETE",
            &format!("/admin/users/{}/device-fingerprints", superuser.as_uuid()),
            &token,
            None,
        )
        .await;

    assert_eq!(actions, StatusCode::FORBIDDEN, "required-actions");
    assert_eq!(fingerprints, StatusCode::FORBIDDEN, "device-fingerprints");
    let stored =
        f.h.identity()
            .get_user(&f.realm, &superuser)
            .expect("lookup")
            .expect("superuser exists");
    assert!(
        stored.required_actions().is_empty(),
        "no required action may be forced on the superuser"
    );
}

/// A bulk disable that names an out-ranking user is refused as a whole: no
/// user in the batch is disabled.
#[tokio::test]
async fn rest_bulk_disable_refuses_a_batch_naming_a_superuser() {
    let f = Fixture::new().await;
    let superuser = f.user("root", &["realm.admin"]);
    let plain = f.user("plain", &[]);
    let token = f.actor(&["hearth.users.admin"]);

    let status = f
        .admin(
            "POST",
            "/admin/users/bulk",
            &token,
            Some(json!({
                "operation": "disable",
                "user_ids": [plain.as_uuid().to_string(), superuser.as_uuid().to_string()]
            })),
        )
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(f.status(&superuser), UserStatus::Active);
    assert_eq!(
        f.status(&plain),
        UserStatus::Active,
        "batch is all-or-nothing"
    );
}

/// A sub-admin may not act on a peer holding an admin permission it lacks,
/// even when they share one.
#[tokio::test]
async fn rest_sub_admin_cannot_act_on_peer_with_an_extra_admin_permission() {
    let f = Fixture::new().await;
    let peer = f.user("peer", &["hearth.users.admin", "hearth.clients.admin"]);
    let before = f.email(&peer);
    let token = f.actor(&["hearth.users.admin"]);

    let status = f
        .admin(
            "PATCH",
            &user_uri(&peer),
            &token,
            Some(json!({"email": "attacker@evil.test"})),
        )
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(f.email(&peer), before);
}

/// Same-or-lower targets stay manageable: plain users and same-level peers.
#[tokio::test]
async fn rest_users_admin_still_manages_plain_users_and_peers() {
    let f = Fixture::new().await;
    let plain = f.user("plain", &[]);
    let peer = f.user("peer", &["hearth.users.admin"]);
    let token = f.actor(&["hearth.users.admin"]);

    let plain_status = f
        .admin(
            "PATCH",
            &user_uri(&plain),
            &token,
            Some(json!({"email": "plain-renamed@ga3.test"})),
        )
        .await;
    let peer_status = f
        .admin(
            "PATCH",
            &user_uri(&peer),
            &token,
            Some(json!({"email": "peer-renamed@ga3.test"})),
        )
        .await;

    assert_eq!(plain_status, StatusCode::OK, "plain user");
    assert_eq!(peer_status, StatusCode::OK, "same-level peer");
    assert_eq!(f.email(&plain), "plain-renamed@ga3.test");
    assert_eq!(f.email(&peer), "peer-renamed@ga3.test");
}

/// `hearth.admin` outranks everyone, other superusers included.
#[tokio::test]
async fn rest_superuser_manages_another_superuser() {
    let f = Fixture::new().await;
    let other = f.user("root2", &["realm.admin"]);
    let token = f.actor(&["realm.admin"]);

    let status = f
        .admin(
            "PATCH",
            &user_uri(&other),
            &token,
            Some(json!({"email": "root2-renamed@ga3.test"})),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(f.email(&other), "root2-renamed@ga3.test");
}

// ── gRPC UpdateUser / DeleteUser ─────────────────────────────────────────────

#[tokio::test]
async fn grpc_users_admin_cannot_update_or_delete_superuser() {
    let f = Fixture::new().await;
    let svc = f.grpc();
    let superuser = f.user("root", &["realm.admin"]);
    let before = f.email(&superuser);
    let token = f.actor(&["hearth.users.admin"]);

    let update = svc
        .update_user(f.grpc_req(
            &token,
            pb::UpdateUserCall {
                id: superuser.as_uuid().to_string(),
                body: Some(pb::UpdateUserRequest {
                    email: Some("attacker@evil.test".into()),
                    ..Default::default()
                }),
            },
        ))
        .await
        .expect_err("UpdateUser on a superuser must be refused");
    let delete = svc
        .delete_user(f.grpc_req(
            &token,
            pb::DeleteUserRequest {
                id: superuser.as_uuid().to_string(),
            },
        ))
        .await
        .expect_err("DeleteUser on a superuser must be refused");

    assert_eq!(update.code(), tonic::Code::PermissionDenied, "UpdateUser");
    assert_eq!(delete.code(), tonic::Code::PermissionDenied, "DeleteUser");
    assert_eq!(f.email(&superuser), before);
}

#[tokio::test]
async fn grpc_users_admin_still_updates_plain_user() {
    let f = Fixture::new().await;
    let svc = f.grpc();
    let plain = f.user("plain", &[]);
    let token = f.actor(&["hearth.users.admin"]);

    let user = svc
        .update_user(f.grpc_req(
            &token,
            pb::UpdateUserCall {
                id: plain.as_uuid().to_string(),
                body: Some(pb::UpdateUserRequest {
                    email: Some("plain-renamed@ga3.test".into()),
                    ..Default::default()
                }),
            },
        ))
        .await
        .expect("UpdateUser on a plain user")
        .into_inner();

    assert_eq!(user.email, "plain-renamed@ga3.test");
}

// ── SCIM /Users (admin-JWT fallback) ─────────────────────────────────────────

/// G-5 narrowed the fallback to `hearth.users.admin`; the ceiling closes the
/// rest: a users-admin still may not rewrite or delete a superuser over SCIM.
#[tokio::test]
async fn scim_users_admin_cannot_modify_or_delete_superuser() {
    let f = Fixture::new().await;
    let superuser = f.user("root", &["realm.admin"]);
    let before = f.email(&superuser);
    let token = f.actor(&["hearth.users.admin"]);
    let uri = scim_user_uri(&superuser);

    let patch = f
        .scim(
            "PATCH",
            &uri,
            &token,
            Some(scim_patch_email("attacker@evil.test")),
        )
        .await;
    let put = f
        .scim(
            "PUT",
            &uri,
            &token,
            Some(scim_user_payload("attacker@evil.test")),
        )
        .await;
    let delete = f.scim("DELETE", &uri, &token, None).await;

    assert_eq!(patch, StatusCode::FORBIDDEN, "PATCH");
    assert_eq!(put, StatusCode::FORBIDDEN, "PUT");
    assert_eq!(delete, StatusCode::FORBIDDEN, "DELETE");
    assert_eq!(f.email(&superuser), before);
}

#[tokio::test]
async fn scim_users_admin_still_modifies_plain_user() {
    let f = Fixture::new().await;
    let plain = f.user("plain", &[]);
    let token = f.actor(&["hearth.users.admin"]);

    let status = f
        .scim(
            "PATCH",
            &scim_user_uri(&plain),
            &token,
            Some(scim_patch_email("plain-renamed@ga3.test")),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(f.email(&plain), "plain-renamed@ga3.test");
}
