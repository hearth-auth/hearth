//! Role changes through the REST admin API write audit events (#620).
//!
//! The admin UI writes `RoleAssigned` / `RoleRevoked` for every role change.
//! The REST routes that make the same changes wrote nothing, so an operator
//! who manages roles through the API had no record of who gave a user more
//! access, or when.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::audit::{AuditAction, AuditEvent, AuditQuery};
use hearth::core::{OrganizationId, RealmId, UserId};
use hearth::identity::{
    CreateOrganizationRequest, CreateRealmRequest, CreateUserRequest, OrganizationRole,
    SessionContext,
};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, CreateGroupRequest, RoleId, Scope, Subject};
use serde_json::json;
use tower::ServiceExt as _;

/// The role every test hands out: a seeded role with one permission.
const ROLE: &str = "hearth.users.admin";

struct Fixture {
    h: common::TestHarness,
    realm: RealmId,
    app: axum::Router,
    admin: UserId,
    token: String,
}

impl Fixture {
    /// A seeded realm and an admin who holds `realm.admin`.
    async fn new() -> Self {
        let h = common::TestHarness::in_process().await.expect("harness");
        let realm = h
            .identity()
            .create_realm(&CreateRealmRequest {
                name: format!("role-audit-{}", uuid::Uuid::new_v4()),
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
        let mut f = Self {
            h,
            realm,
            app,
            admin: UserId::generate(),
            token: String::new(),
        };
        f.admin = f.user("admin");
        f.assign(&f.admin, &f.role_id("realm.admin"));
        let session =
            f.h.identity()
                .create_session(&f.realm, &f.admin, &SessionContext::default())
                .expect("session");
        f.token =
            f.h.identity()
                .issue_tokens(&f.realm, &f.admin, session.id())
                .expect("tokens")
                .access_token()
                .to_string();
        f
    }

    fn user(&self, label: &str) -> UserId {
        self.h
            .identity()
            .create_user(
                &self.realm,
                &CreateUserRequest {
                    email: format!("{label}-{}@role-audit.test", uuid::Uuid::new_v4()),
                    display_name: label.into(),
                    ..Default::default()
                },
            )
            .expect("create user")
            .id()
            .clone()
    }

    fn role_id(&self, name: &str) -> RoleId {
        self.h
            .rbac()
            .get_role_by_name(&self.realm, name)
            .expect("lookup")
            .unwrap_or_else(|| panic!("role '{name}' missing"))
            .id
    }

    fn assign(&self, user: &UserId, role: &RoleId) -> String {
        self.h
            .rbac()
            .assign_role(
                &self.realm,
                &AssignRoleRequest {
                    subject: Subject::User(user.clone()),
                    role_id: role.clone(),
                    scope: Scope::Realm,
                    assigned_by: None,
                },
            )
            .expect("assign role")
            .id
            .as_uuid()
            .to_string()
    }

    fn org_with_member(&self, member: &UserId) -> OrganizationId {
        let org = self
            .h
            .identity()
            .create_organization(
                &self.realm,
                &CreateOrganizationRequest {
                    name: "Audited".into(),
                    slug: format!("audited-{}", uuid::Uuid::new_v4().simple()),
                    description: None,
                    config: None,
                    attributes: Default::default(),
                },
            )
            .expect("create org")
            .id()
            .clone();
        self.h
            .identity()
            .add_member(&self.realm, &org, member, OrganizationRole::Member)
            .expect("add member");
        org
    }

    async fn call(
        &self,
        method: &str,
        uri: &str,
        body: Option<&serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .header("x-realm-id", self.realm.as_uuid().to_string())
            .header("authorization", format!("Bearer {}", self.token))
            .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
            .expect("request");
        let resp = self.app.clone().oneshot(req).await.expect("oneshot");
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.expect("body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    /// The `action` events this fixture's admin wrote.
    fn events(&self, action: AuditAction) -> Vec<AuditEvent> {
        let admin = self.admin.as_uuid().to_string();
        self.h
            .audit()
            .query(&AuditQuery {
                action: Some(action),
                ..AuditQuery::for_realm(self.realm.clone())
            })
            .expect("audit query")
            .into_iter()
            .filter(|e| e.actor == admin)
            .collect()
    }
}

/// The single event of `action` by the admin, checked for its target.
fn only_event(f: &Fixture, action: AuditAction, kind: &str, target: &str) -> AuditEvent {
    let events = f.events(action.clone());
    assert_eq!(
        events.len(),
        1,
        "exactly one {action:?} event by the admin, got {events:?}"
    );
    let event = events.into_iter().next().expect("one event");
    assert_eq!(event.resource_type, kind);
    assert_eq!(event.resource_id, target);
    event
}

fn meta<'a>(event: &'a AuditEvent, key: &str) -> Option<&'a str> {
    event.metadata.as_ref()?.get(key)?.as_str()
}

#[tokio::test]
async fn assigning_a_role_to_a_user_writes_role_assigned() {
    let f = Fixture::new().await;
    let user = f.user("target");
    let role = f.role_id(ROLE);

    let (status, _) = f
        .call(
            "POST",
            &format!("/admin/users/{}/roles", user.as_uuid()),
            Some(&json!({ "role_id": role.as_uuid().to_string() })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let event = only_event(
        &f,
        AuditAction::RoleAssigned,
        "user",
        &user.as_uuid().to_string(),
    );
    assert_eq!(meta(&event, "role"), Some(ROLE));
    assert_eq!(meta(&event, "via"), Some("api"));
}

#[tokio::test]
async fn removing_a_role_assignment_writes_role_revoked() {
    let f = Fixture::new().await;
    let user = f.user("target");
    let assignment = f.assign(&user, &f.role_id(ROLE));

    let (status, _) = f
        .call("DELETE", &format!("/admin/assignments/{assignment}"), None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let event = only_event(
        &f,
        AuditAction::RoleRevoked,
        "user",
        &user.as_uuid().to_string(),
    );
    assert_eq!(meta(&event, "role"), Some(ROLE));
    assert_eq!(meta(&event, "via"), Some("api"));
}

#[tokio::test]
async fn assigning_a_role_to_a_group_writes_role_assigned() {
    let f = Fixture::new().await;
    let group =
        f.h.rbac()
            .create_group(
                &f.realm,
                &CreateGroupRequest {
                    name: "Audited group".into(),
                    slug: format!("audited-{}", uuid::Uuid::new_v4().simple()),
                    description: None,
                },
            )
            .expect("create group");
    let role = f.role_id(ROLE);

    let (status, _) = f
        .call(
            "POST",
            &format!("/admin/groups/{}/roles", group.id.as_uuid()),
            Some(&json!({ "role_id": role.as_uuid().to_string() })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let event = only_event(
        &f,
        AuditAction::RoleAssigned,
        "group",
        &group.id.as_uuid().to_string(),
    );
    assert_eq!(meta(&event, "role"), Some(ROLE));
    assert_eq!(meta(&event, "via"), Some("api"));
}

#[tokio::test]
async fn adding_and_removing_an_extra_org_role_write_audit_events() {
    let f = Fixture::new().await;
    let user = f.user("member");
    let org = f.org_with_member(&user);
    let uri = format!(
        "/admin/organizations/{}/members/{}/roles",
        org.as_uuid(),
        user.as_uuid()
    );

    let (status, _) = f
        .call("POST", &uri, Some(&json!({ "role_name": ROLE })))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = f.call("DELETE", &format!("{uri}/{ROLE}"), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let org_id = org.as_uuid().to_string();
    for action in [AuditAction::RoleAssigned, AuditAction::RoleRevoked] {
        let event = only_event(&f, action.clone(), "user", &user.as_uuid().to_string());
        assert_eq!(meta(&event, "role"), Some(ROLE), "{action:?}");
        assert_eq!(meta(&event, "org_id"), Some(org_id.as_str()), "{action:?}");
        assert_eq!(meta(&event, "via"), Some("api"), "{action:?}");
    }
}
