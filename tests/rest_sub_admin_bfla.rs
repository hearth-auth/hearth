#![allow(clippy::unwrap_used)]
//! Per-operation admin permission checks (HEA-SEC-04) and the group / role
//! admin round trips, over REST.
//!
//! Ported from the removed `grpc_sub_admin_bfla.rs` and `grpc_rbac_admin.rs`
//! when the public gRPC API was deleted (scope-trim-trusted-core). Each
//! refusal is paired with an allowed control on the same route, so a route
//! that does not exist (404) or a fixture that cannot authenticate (401)
//! cannot make the refusal pass vacuously.
//!
//! The two gRPC tests that let a full admin create / update a role carrying
//! a reserved `hearth.*` permission are not ported: REST refuses reserved
//! permissions on purpose.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::core::{ClientId, OrganizationId, RealmId, UserId};
use hearth::identity::{
    ClientTrustLevel, CreateOrganizationRequest, CreateUserRequest, OrganizationRole,
    RegisterClientRequest, SessionContext,
};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use serde_json::{json, Value};
use tower::ServiceExt as _;

// ── fixture ──────────────────────────────────────────────────────────────────

struct Fixture {
    h: common::TestHarness,
    realm: RealmId,
    app: axum::Router,
}

impl Fixture {
    async fn new() -> Self {
        let h = common::TestHarness::in_process().await.expect("harness");
        let realm = h.create_realm();
        h.rbac().seed_realm(&realm).expect("seed realm");
        // Agent identity routes on, so `/v1/agents` is registered.
        let app = router(Arc::new(
            AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()).with_agent_identity(true),
        ));
        Self { h, realm, app }
    }

    fn user_in(&self, realm: &RealmId, label: &str) -> UserId {
        self.h
            .identity()
            .create_user(
                realm,
                &CreateUserRequest {
                    email: format!("{label}-{}@bfla.test", uuid::Uuid::new_v4()),
                    display_name: label.into(),
                    first_name: String::new(),
                    last_name: String::new(),
                    attributes: Default::default(),
                },
            )
            .expect("create user")
            .id()
            .clone()
    }

    fn user(&self, label: &str) -> UserId {
        self.user_in(&self.realm, label)
    }

    /// A token for a fresh user holding exactly the seeded role `role`.
    fn admin(&self, role: &str) -> String {
        let id = self.user(role);
        let role_id = self
            .h
            .rbac()
            .get_role_by_name(&self.realm, role)
            .expect("lookup")
            .unwrap_or_else(|| panic!("seed role '{role}' missing"))
            .id;
        self.h
            .rbac()
            .assign_role(
                &self.realm,
                &AssignRoleRequest {
                    subject: Subject::User(id.clone()),
                    role_id,
                    scope: Scope::Realm,
                    assigned_by: None,
                },
            )
            .expect("assign role");
        let session = self
            .h
            .identity()
            .create_session(&self.realm, &id, &SessionContext::default())
            .expect("session");
        self.h
            .identity()
            .issue_tokens(&self.realm, &id, session.id())
            .expect("tokens")
            .access_token()
            .to_string()
    }

    fn org(&self, name: &str) -> OrganizationId {
        self.h
            .identity()
            .create_organization(
                &self.realm,
                &CreateOrganizationRequest {
                    name: name.into(),
                    slug: format!("{name}-{}", uuid::Uuid::new_v4().simple()),
                    description: None,
                    config: None,
                    attributes: Default::default(),
                },
            )
            .expect("create org")
            .id()
            .clone()
    }

    fn client(&self) -> ClientId {
        self.h
            .identity()
            .register_client(
                &self.realm,
                &RegisterClientRequest {
                    client_name: format!("app-{}", uuid::Uuid::new_v4()),
                    redirect_uris: vec!["https://app.example.com/cb".into()],
                    grant_types: vec!["authorization_code".into()],
                    require_consent: true,
                    trust_level: ClientTrustLevel::ThirdParty,
                    declared_scopes: vec!["openid".into()],
                    ..RegisterClientRequest::default()
                },
            )
            .expect("register client")
            .client_id()
            .clone()
    }

    fn consent_clients(&self, user: &UserId) -> Vec<ClientId> {
        self.h
            .identity()
            .list_consents_by_user(&self.realm, user)
            .expect("list consents")
            .into_iter()
            .map(|c| c.record.client_id)
            .collect()
    }

    fn role_exists(&self, realm: &RealmId, name: &str) -> bool {
        self.h
            .rbac()
            .get_role_by_name(realm, name)
            .expect("lookup")
            .is_some()
    }

    async fn call_in(
        &self,
        realm: &RealmId,
        method: &str,
        uri: &str,
        bearer: &str,
        body: Option<&Value>,
    ) -> (StatusCode, Value) {
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .header("x-realm-id", realm.as_uuid().to_string())
            .header("authorization", format!("Bearer {bearer}"))
            .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
            .expect("request");
        let resp = self.app.clone().oneshot(req).await.expect("oneshot");
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.expect("body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn call(
        &self,
        method: &str,
        uri: &str,
        bearer: &str,
        body: Option<&Value>,
    ) -> (StatusCode, Value) {
        self.call_in(&self.realm, method, uri, bearer, body).await
    }

    /// `POST /admin/roles` for an empty role named `name`, so the privilege
    /// ceiling never decides the outcome — only the route permission does.
    async fn create_role(&self, bearer: &str, name: &str) -> (StatusCode, Value) {
        self.call(
            "POST",
            "/admin/roles",
            bearer,
            Some(&json!({"name": name, "permissions": []})),
        )
        .await
    }
}

// ── groups (from grpc_rbac_admin.rs) ─────────────────────────────────────────

/// Port 1: create, read, delete a group; a deleted group is gone (404).
#[tokio::test]
async fn group_crud_round_trip() {
    let f = Fixture::new().await;
    let admin = f.admin("realm.admin");

    let (status, created) = f
        .call(
            "POST",
            "/admin/groups",
            &admin,
            Some(&json!({"name": "Rest Group", "slug": "rest-group"})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["slug"], "rest-group", "{created}");
    assert_eq!(created["name"], "Rest Group", "name must round-trip");
    let id = created["id"].as_str().expect("group id").to_string();
    let uri = format!("/admin/groups/{id}");

    // Control: the group is retrievable before the delete.
    let (status, got) = f.call("GET", &uri, &admin, None).await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert_eq!(got["slug"], "rest-group", "{got}");

    let (status, body) = f.call("DELETE", &uri, &admin, None).await;
    assert!(status.is_success(), "delete: {status} {body}");

    let (status, body) = f.call("GET", &uri, &admin, None).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a deleted group must not be retrievable: {body}"
    );
}

/// Extra port (`grpc_rbac_admin::bola_cross_realm_create_role_rejected`):
/// a realm-A admin token aimed at realm B creates nothing in realm B.
#[tokio::test]
async fn cross_realm_role_create_is_refused() {
    let f = Fixture::new().await;
    let admin = f.admin("realm.admin");
    let realm_b = f.h.create_realm();
    f.h.rbac().seed_realm(&realm_b).expect("seed realm b");

    // Control: the token creates a role in its own realm.
    let (status, body) = f.create_role(&admin, "home-role").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert!(f.role_exists(&f.realm, "home-role"));

    let (status, body) = f
        .call_in(
            &realm_b,
            "POST",
            "/admin/roles",
            &admin,
            Some(&json!({"name": "attacker-role", "permissions": []})),
        )
        .await;
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
        "a realm-A token must not write into realm B: {status} {body}"
    );
    assert!(!f.role_exists(&realm_b, "attacker-role"));
}

// ── role creation needs hearth.realm.admin ───────────────────────────────────

async fn assert_role_create_denied_for(sub_admin_role: &str) {
    let f = Fixture::new().await;
    let control = f.admin("hearth.realm.admin");
    let (status, body) = f.create_role(&control, "control-role").await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "control: hearth.realm.admin creates a role: {body}"
    );
    assert!(f.role_exists(&f.realm, "control-role"));

    let token = f.admin(sub_admin_role);
    let (status, body) = f.create_role(&token, "denied-role").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "{sub_admin_role} must not create a role: {body}"
    );
    assert!(!f.role_exists(&f.realm, "denied-role"));
}

/// Port 2.
#[tokio::test]
async fn users_admin_denied_on_create_role() {
    assert_role_create_denied_for("hearth.users.admin").await;
}

/// Port 3.
#[tokio::test]
async fn clients_admin_denied_on_create_role() {
    assert_role_create_denied_for("hearth.clients.admin").await;
}

/// Port 4.
#[tokio::test]
async fn agents_admin_denied_on_create_role() {
    assert_role_create_denied_for("hearth.agents.admin").await;
}

// ── user creation needs hearth.users.admin ───────────────────────────────────

/// Port 5.
#[tokio::test]
async fn realm_admin_denied_on_create_user() {
    let f = Fixture::new().await;
    let users_admin = f.admin("hearth.users.admin");
    let (status, body) = f
        .call(
            "POST",
            "/admin/users",
            &users_admin,
            Some(&json!({"email": "allowed@bfla.test", "display_name": "Allowed"})),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "control: hearth.users.admin creates a user: {body}"
    );

    let realm_admin = f.admin("hearth.realm.admin");
    let (status, body) = f
        .call(
            "POST",
            "/admin/users",
            &realm_admin,
            Some(&json!({"email": "denied@bfla.test", "display_name": "Denied"})),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "hearth.realm.admin must not create users: {body}"
    );
    assert!(
        f.h.identity()
            .get_user_by_email(&f.realm, "denied@bfla.test")
            .expect("lookup")
            .is_none(),
        "no user may be created by a refused call"
    );
}

// ── application listing needs hearth.clients.admin ───────────────────────────

async fn assert_list_applications_denied_for(sub_admin_role: &str) {
    let f = Fixture::new().await;
    let control = f.admin("hearth.clients.admin");
    let (status, body) = f.call("GET", "/admin/applications", &control, None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "control: hearth.clients.admin lists applications: {body}"
    );

    let token = f.admin(sub_admin_role);
    let (status, body) = f.call("GET", "/admin/applications", &token, None).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "{sub_admin_role} must not list applications: {body}"
    );
}

/// Port 6.
#[tokio::test]
async fn realm_admin_denied_on_list_applications() {
    assert_list_applications_denied_for("hearth.realm.admin").await;
}

/// Port 7.
#[tokio::test]
async fn agents_admin_denied_on_list_applications() {
    assert_list_applications_denied_for("hearth.agents.admin").await;
}

/// Also from the gRPC matrix: `hearth.users.admin` cannot list applications.
#[tokio::test]
async fn users_admin_denied_on_list_applications() {
    assert_list_applications_denied_for("hearth.users.admin").await;
}

// ── agent listing needs hearth.agents.admin ──────────────────────────────────

/// Port 8.
#[tokio::test]
async fn realm_admin_denied_on_list_agents() {
    let f = Fixture::new().await;
    let control = f.admin("hearth.agents.admin");
    let (status, body) = f.call("GET", "/v1/agents", &control, None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "control: hearth.agents.admin lists agents: {body}"
    );

    let token = f.admin("hearth.realm.admin");
    let (status, body) = f.call("GET", "/v1/agents", &token, None).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "hearth.realm.admin must not list agents: {body}"
    );
}

// ── consent revocation needs hearth.users.admin ──────────────────────────────

/// Port 9: the revoke succeeds and the consent is gone; the other consent
/// the user holds is untouched.
#[tokio::test]
async fn users_admin_allowed_on_revoke_consent() {
    let f = Fixture::new().await;
    let token = f.admin("hearth.users.admin");
    let target = f.user("consent-target");
    let revoked = f.client();
    let kept = f.client();
    for client in [&revoked, &kept] {
        f.h.identity()
            .grant_consent(
                &f.realm,
                &hearth::identity::ConsentGrant {
                    key: hearth::identity::ConsentKey {
                        user_id: target.clone(),
                        client_id: client.clone(),
                        org_id: None,
                        resource: None,
                    },
                    scopes: vec!["openid".to_string()],
                    via: hearth::identity::ConsentSurface::Web,
                },
            )
            .expect("grant consent");
    }
    let before = f.consent_clients(&target);
    assert!(
        before.contains(&revoked) && before.contains(&kept),
        "precondition: both consents exist"
    );

    let (status, body) = f
        .call(
            "DELETE",
            &format!(
                "/admin/users/{}/consents/{}",
                target.as_uuid(),
                revoked.as_uuid()
            ),
            &token,
            None,
        )
        .await;
    assert!(
        status.is_success(),
        "hearth.users.admin must revoke a consent: {status} {body}"
    );

    let after = f.consent_clients(&target);
    assert!(!after.contains(&revoked), "the revoked consent is gone");
    assert!(after.contains(&kept), "the other consent is untouched");
}

// ── additional org roles ─────────────────────────────────────────────────────

/// Port 10: a full admin (seeded `realm.admin`, holding `hearth.admin`) may
/// add any role, including `realm.admin`, to an org member.
#[tokio::test]
async fn full_admin_can_add_any_role() {
    let f = Fixture::new().await;
    let full = f.admin("realm.admin");
    let org = f.org("full-admin-addrole");
    let target = f.user("target");
    f.h.identity()
        .add_member(&f.realm, &org, &target, OrganizationRole::Member)
        .expect("add member");
    let uri = format!(
        "/admin/organizations/{}/members/{}/roles",
        org.as_uuid(),
        target.as_uuid()
    );

    let (status, body) = f
        .call(
            "POST",
            &uri,
            &full,
            Some(&json!({"role_name": "realm.admin"})),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "hearth.admin must be able to add any role (HEA-1722): {body}"
    );

    let (status, list) = f.call("GET", &uri, &full, None).await;
    assert_eq!(status, StatusCode::OK, "{list}");
    assert_eq!(list["items"], json!(["realm.admin"]), "{list}");
}
