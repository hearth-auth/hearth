#![allow(clippy::unwrap_used)]
//! scope-trim-trusted-core, group 4: REST parity for the admin operations
//! that used to exist only over gRPC.
//!
//! Sixteen operations — organization CRUD, group roles, role members, direct
//! user permissions, extra org roles, the realm permission list and audit
//! integrity — had no REST route. The public gRPC surface is being removed,
//! so each gets one here, and every authorization assertion the gRPC tests
//! made (`grpc_sub_admin_bfla.rs`, `ga3_demotion_ceiling.rs`,
//! `ga4_ceiling_org_role.rs`, `grpc_audit_service.rs`) is ported to it. Where
//! the gRPC handler was looser than the REST conventions (no ceiling on an
//! org suspension, `granted_by` taken from the body, no org-existence check,
//! a silently ignored `slug`), the REST route follows the stricter rule and a
//! test pins it.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::core::{OrganizationId, RealmId, UserId};
use hearth::identity::{
    CreateOrganizationRequest, CreateRealmRequest, CreateUserRequest, OrganizationRole,
    SessionContext,
};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{
    AssignRoleRequest, CreateGroupRequest, CreateRoleRequest, GroupId, GroupMember, Permission,
    RoleId, Scope, Subject, UserPermissionGrant,
};
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
        let h = common::TestHarness::embedded().await.expect("harness");
        let realm = h
            .identity()
            .create_realm(&CreateRealmRequest {
                name: format!("rest-parity-{}", uuid::Uuid::new_v4()),
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

    fn user(&self, label: &str) -> UserId {
        self.h
            .identity()
            .create_user(
                &self.realm,
                &CreateUserRequest {
                    email: format!("{label}-{}@parity.test", uuid::Uuid::new_v4()),
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

    fn role_id(&self, name: &str) -> RoleId {
        self.h
            .rbac()
            .get_role_by_name(&self.realm, name)
            .expect("lookup")
            .unwrap_or_else(|| panic!("role '{name}' missing"))
            .id
    }

    fn assign(&self, subject: Subject, role: &RoleId) -> String {
        let a = self
            .h
            .rbac()
            .assign_role(
                &self.realm,
                &AssignRoleRequest {
                    subject,
                    role_id: role.clone(),
                    scope: Scope::Realm,
                    assigned_by: None,
                },
            )
            .expect("assign role");
        a.id.as_uuid().to_string()
    }

    fn token(&self, user: &UserId) -> String {
        let session = self
            .h
            .identity()
            .create_session(&self.realm, user, &SessionContext::default())
            .expect("session");
        self.h
            .identity()
            .issue_tokens(&self.realm, user, session.id())
            .expect("tokens")
            .access_token()
            .to_string()
    }

    /// `(user, token)` for a fresh admin holding exactly the seeded `role`.
    fn admin(&self, role: &str) -> (UserId, String) {
        let id = self.user(role);
        self.assign(Subject::User(id.clone()), &self.role_id(role));
        let token = self.token(&id);
        (id, token)
    }

    /// As [`Self::admin`], plus direct realm grants of `extra` — granted
    /// before the token is minted, so the token carries them.
    fn admin_with(&self, role: &str, extra: &[&str]) -> (UserId, String) {
        let id = self.user(role);
        self.assign(Subject::User(id.clone()), &self.role_id(role));
        for p in extra {
            self.grant(&id, p, Scope::Realm);
        }
        let token = self.token(&id);
        (id, token)
    }

    fn plain_role(&self, name: &str, perms: &[&str]) -> RoleId {
        self.h
            .rbac()
            .create_role(
                &self.realm,
                &CreateRoleRequest {
                    name: name.into(),
                    description: None,
                    permissions: perms
                        .iter()
                        .map(|p| Permission::new(*p).expect("perm"))
                        .collect(),
                    parent_roles: vec![],
                    scope_kind: Default::default(),
                    allow_reserved_permissions: false,
                },
            )
            .expect("create role")
            .id
    }

    fn group(&self, name: &str) -> GroupId {
        self.h
            .rbac()
            .create_group(
                &self.realm,
                &CreateGroupRequest {
                    name: name.into(),
                    slug: format!("{name}-{}", uuid::Uuid::new_v4().simple()),
                    description: None,
                },
            )
            .expect("create group")
            .id
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

    fn join(&self, org: &OrganizationId, user: &UserId) {
        self.h
            .identity()
            .add_member(&self.realm, org, user, OrganizationRole::Member)
            .expect("add member");
    }

    fn grant(&self, user: &UserId, perm: &str, scope: Scope) {
        self.h
            .rbac()
            .grant_user_permission(
                &self.realm,
                &UserPermissionGrant {
                    realm_id: self.realm.clone(),
                    user_id: user.clone(),
                    permission: Permission::new(perm).expect("perm"),
                    scope,
                    granted_at: hearth::core::Timestamp::from_micros(0),
                    granted_by: None,
                },
            )
            .expect("grant");
    }

    /// A plain org member who holds `hearth.admin` only inside `org`.
    fn org_superuser(&self, org: &OrganizationId) -> UserId {
        let id = self.user("org-root");
        self.join(org, &id);
        self.grant(
            &id,
            "hearth.admin",
            Scope::Org {
                org_id: org.clone(),
            },
        );
        id
    }

    fn org_exists(&self, org: &OrganizationId) -> bool {
        self.h
            .identity()
            .get_organization(&self.realm, org)
            .expect("lookup")
            .is_some()
    }

    fn holds_superuser(&self, user: &UserId, org: Option<&OrganizationId>) -> bool {
        self.h
            .rbac()
            .resolve_permissions(user, &self.realm, org, None)
            .expect("resolve")
            .permissions
            .iter()
            .any(|p| p.as_str() == "hearth.admin")
    }

    async fn call(
        &self,
        method: &str,
        uri: &str,
        bearer: &str,
        body: Option<&Value>,
    ) -> (StatusCode, Value) {
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .header("x-realm-id", self.realm.as_uuid().to_string())
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
}

fn uuid_of(org: &OrganizationId) -> String {
    org.as_uuid().to_string()
}

// ── organizations ────────────────────────────────────────────────────────────

/// Full CRUD round trip, with the JSON shape the console and SDKs will use.
#[tokio::test]
async fn organization_crud_round_trip() {
    let f = Fixture::new().await;
    let (_, token) = f.admin("hearth.realm.admin");

    let (status, created) = f
        .call(
            "POST",
            "/admin/organizations",
            &token,
            Some(&json!({
                "slug": "acme-corp",
                "display_name": "Acme Corp",
                "member_limit": 25,
                "attributes": {"tier": "gold"}
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["slug"], "acme-corp");
    assert_eq!(created["display_name"], "Acme Corp");
    assert_eq!(created["status"], "active");
    assert_eq!(created["member_limit"], 25);
    assert_eq!(created["attributes"]["tier"], "gold");
    let id = created["id"].as_str().expect("id").to_string();

    let (status, got) = f
        .call("GET", &format!("/admin/organizations/{id}"), &token, None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(got["id"], id.as_str());

    let (status, page) = f.call("GET", "/admin/organizations", &token, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        page["items"]
            .as_array()
            .expect("items")
            .iter()
            .any(|o| o["id"] == id.as_str()),
        "{page}"
    );

    let (status, updated) = f
        .call(
            "PATCH",
            &format!("/admin/organizations/{id}"),
            &token,
            Some(&json!({"display_name": "Acme Corporation", "status": "suspended"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{updated}");
    assert_eq!(updated["display_name"], "Acme Corporation");
    assert_eq!(updated["status"], "suspended");

    let (status, _) = f
        .call(
            "DELETE",
            &format!("/admin/organizations/{id}"),
            &token,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = f
        .call("GET", &format!("/admin/organizations/{id}"), &token, None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn organization_list_pages_with_a_cursor() {
    let f = Fixture::new().await;
    let (_, token) = f.admin("hearth.realm.admin");
    for i in 0..3 {
        f.org(&format!("paged{i}"));
    }
    let (status, first) = f
        .call("GET", "/admin/organizations?limit=2", &token, None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["items"].as_array().expect("items").len(), 2);
    let cursor = first["next_cursor"].as_str().expect("a next cursor");
    let (_, second) = f
        .call(
            "GET",
            &format!("/admin/organizations?limit=2&cursor={cursor}"),
            &token,
            None,
        )
        .await;
    assert_eq!(second["items"].as_array().expect("items").len(), 1);
    assert!(second["next_cursor"].is_null(), "{second}");
}

#[tokio::test]
async fn organization_routes_require_realm_admin() {
    let f = Fixture::new().await;
    let (_, users_admin) = f.admin("hearth.users.admin");
    let org = f.org("guarded");
    for (method, uri, body) in [
        ("GET", "/admin/organizations".to_string(), None),
        (
            "POST",
            "/admin/organizations".to_string(),
            Some(json!({"slug": "nope-org", "display_name": "Nope"})),
        ),
        (
            "GET",
            format!("/admin/organizations/{}", uuid_of(&org)),
            None,
        ),
        (
            "PATCH",
            format!("/admin/organizations/{}", uuid_of(&org)),
            Some(json!({"display_name": "x"})),
        ),
        (
            "DELETE",
            format!("/admin/organizations/{}", uuid_of(&org)),
            None,
        ),
    ] {
        let (status, _) = f.call(method, &uri, &users_admin, body.as_ref()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri}");
    }
    assert!(f.org_exists(&org));
}

#[tokio::test]
async fn organization_unknown_and_malformed_ids() {
    let f = Fixture::new().await;
    let (_, token) = f.admin("hearth.realm.admin");
    let unknown = uuid::Uuid::new_v4();
    let (status, _) = f
        .call(
            "GET",
            &format!("/admin/organizations/{unknown}"),
            &token,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = f
        .call("GET", "/admin/organizations/not-a-uuid", &token, None)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// gRPC silently ignored a `slug` in an update. REST refuses it: the slug is
/// immutable, and an ignored field is a request the caller thinks succeeded.
#[tokio::test]
async fn organization_update_refuses_a_slug_change() {
    let f = Fixture::new().await;
    let (_, token) = f.admin("hearth.realm.admin");
    let org = f.org("fixed");
    let (status, body) = f
        .call(
            "PATCH",
            &format!("/admin/organizations/{}", uuid_of(&org)),
            &token,
            Some(&json!({"slug": "renamed"})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

/// Ported from `ga4_ceiling_org_role.rs`: deleting an org strips the
/// org-scoped `hearth.admin` of its members, so a sub-admin may not delete one
/// whose member out-ranks it, and may still delete a plain one.
#[tokio::test]
async fn organization_delete_honours_the_admin_ceiling() {
    let f = Fixture::new().await;
    let org = f.org("ranked");
    let root = f.org_superuser(&org);
    let plain = f.org("plain");
    f.join(&plain, &f.user("plain-member"));
    let (_, token) = f.admin("hearth.realm.admin");

    let (refused, _) = f
        .call(
            "DELETE",
            &format!("/admin/organizations/{}", uuid_of(&org)),
            &token,
            None,
        )
        .await;
    let (allowed, _) = f
        .call(
            "DELETE",
            &format!("/admin/organizations/{}", uuid_of(&plain)),
            &token,
            None,
        )
        .await;

    assert_eq!(refused, StatusCode::FORBIDDEN);
    assert!(f.org_exists(&org), "the refused org must survive");
    assert!(
        f.holds_superuser(&root, Some(&org)),
        "the superuser keeps the authority"
    );
    assert_eq!(allowed, StatusCode::NO_CONTENT);
    assert!(!f.org_exists(&plain));
}

/// gRPC had no ceiling on suspending an org, though suspension strips the
/// same org-scoped authority a delete does. REST applies it.
#[tokio::test]
async fn organization_suspension_honours_the_admin_ceiling() {
    let f = Fixture::new().await;
    let org = f.org("suspend-ranked");
    f.org_superuser(&org);
    let (_, sub) = f.admin("hearth.realm.admin");
    let (_, full) = f.admin("realm.admin");
    let uri = format!("/admin/organizations/{}", uuid_of(&org));

    let (refused, _) = f
        .call("PATCH", &uri, &sub, Some(&json!({"status": "suspended"})))
        .await;
    assert_eq!(refused, StatusCode::FORBIDDEN);
    let (still, got) = f.call("GET", &uri, &full, None).await;
    assert_eq!(still, StatusCode::OK);
    assert_eq!(
        got["status"], "active",
        "the refused suspension changed nothing"
    );

    // A rename does not strip authority: the sub-admin may make it.
    let (renamed, _) = f
        .call(
            "PATCH",
            &uri,
            &sub,
            Some(&json!({"display_name": "Renamed"})),
        )
        .await;
    assert_eq!(renamed, StatusCode::OK);
    // The full admin out-ranks everyone and may suspend.
    let (suspended, _) = f
        .call("PATCH", &uri, &full, Some(&json!({"status": "suspended"})))
        .await;
    assert_eq!(suspended, StatusCode::OK);
}

// ── group roles ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn group_role_assignment_honours_the_ceiling_and_scope() {
    let f = Fixture::new().await;
    let (caller, token) = f.admin_with("hearth.realm.admin", &["docs.read"]);
    let group = f.group("ops");
    let uri = format!("/admin/groups/{}/roles", group.as_uuid());
    let plain = f.plain_role("reader", &["docs.read"]);

    let (refused, _) = f
        .call(
            "POST",
            &uri,
            &token,
            Some(&json!({"role_id": f.role_id("realm.admin").as_uuid().to_string()})),
        )
        .await;
    assert_eq!(refused, StatusCode::FORBIDDEN, "a role above the caller");

    let (unknown_org, _) = f
        .call(
            "POST",
            &uri,
            &token,
            Some(&json!({
                "role_id": plain.as_uuid().to_string(),
                "org_id": uuid::Uuid::new_v4().to_string()
            })),
        )
        .await;
    assert_eq!(
        unknown_org,
        StatusCode::NOT_FOUND,
        "an org that does not exist"
    );

    let (created, body) = f
        .call(
            "POST",
            &uri,
            &token,
            Some(&json!({"role_id": plain.as_uuid().to_string()})),
        )
        .await;
    assert_eq!(created, StatusCode::CREATED, "{body}");
    assert_eq!(body["assigned_by"], caller.as_uuid().to_string());

    let (no_group, _) = f
        .call(
            "POST",
            &format!("/admin/groups/{}/roles", uuid::Uuid::new_v4()),
            &token,
            Some(&json!({"role_id": plain.as_uuid().to_string()})),
        )
        .await;
    assert_eq!(
        no_group,
        StatusCode::NOT_FOUND,
        "a group that does not exist"
    );
}

/// Ported from `ga3_demotion_ceiling.rs`: unassigning a group's role demotes
/// every member, so a sub-admin may not strip a group that holds a superuser,
/// and may still unassign a plain group's role. REST does this through the
/// existing `DELETE /admin/assignments/{id}`.
#[tokio::test]
async fn group_role_unassignment_honours_the_ceiling() {
    let f = Fixture::new().await;
    let su_group = f.group("superusers");
    let root = f.user("root");
    f.h.rbac()
        .add_group_member(&f.realm, &su_group, &GroupMember::User(root.clone()))
        .expect("member");
    let su_assignment = f.assign(Subject::Group(su_group.clone()), &f.role_id("realm.admin"));
    let plain_group = f.group("readers");
    let plain_assignment = f.assign(
        Subject::Group(plain_group),
        &f.plain_role("viewer", &["docs.view"]),
    );
    let (_, token) = f.admin("hearth.realm.admin");

    let (refused, _) = f
        .call(
            "DELETE",
            &format!("/admin/assignments/{su_assignment}"),
            &token,
            None,
        )
        .await;
    assert_eq!(refused, StatusCode::FORBIDDEN);
    assert!(
        f.holds_superuser(&root, None),
        "the superuser keeps hearth.admin"
    );
    let (allowed, _) = f
        .call(
            "DELETE",
            &format!("/admin/assignments/{plain_assignment}"),
            &token,
            None,
        )
        .await;
    assert_eq!(allowed, StatusCode::NO_CONTENT);
}

// ── role members ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn role_members_lists_users_and_groups() {
    let f = Fixture::new().await;
    let (_, token) = f.admin("hearth.realm.admin");
    let role = f.plain_role("auditor", &["audit.read"]);
    let member = f.user("member");
    f.assign(Subject::User(member.clone()), &role);
    let group = f.group("auditors");
    f.assign(Subject::Group(group.clone()), &role);

    let (status, body) = f
        .call(
            "GET",
            &format!("/admin/roles/{}/members", role.as_uuid()),
            &token,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let members = body["items"].as_array().expect("items");
    assert!(
        members
            .iter()
            .any(|m| m["subject_type"] == "user" && m["subject_id"] == member.as_uuid().to_string()),
        "{body}"
    );
    assert!(
        members
            .iter()
            .any(|m| m["subject_type"] == "group" && m["subject_id"] == group.as_uuid().to_string()),
        "{body}"
    );
}

// ── direct user permissions ──────────────────────────────────────────────────

/// Ported from `grpc_sub_admin_bfla.rs` and `ga3_demotion_ceiling.rs`.
#[tokio::test]
async fn user_permission_grants_honour_the_ceiling() {
    let f = Fixture::new().await;
    let (caller, sub) = f.admin("hearth.realm.admin");
    let (_, full) = f.admin("realm.admin");
    let target = f.user("target");
    let uri = format!("/admin/users/{}/permissions", target.as_uuid());

    let (refused, _) = f
        .call(
            "POST",
            &uri,
            &sub,
            Some(&json!({"permission": "hearth.admin"})),
        )
        .await;
    assert_eq!(
        refused,
        StatusCode::FORBIDDEN,
        "a permission the caller lacks"
    );
    assert!(!f.holds_superuser(&target, None));

    let (held, body) = f
        .call(
            "POST",
            &uri,
            &sub,
            Some(&json!({"permission": "hearth.realm.admin"})),
        )
        .await;
    assert_eq!(held, StatusCode::CREATED, "{body}");
    assert_eq!(
        body["granted_by"],
        caller.as_uuid().to_string(),
        "granted_by is the caller"
    );

    let (any, _) = f
        .call(
            "POST",
            &uri,
            &full,
            Some(&json!({"permission": "docs.anything"})),
        )
        .await;
    assert_eq!(any, StatusCode::CREATED, "hearth.admin grants anything");

    let (status, list) = f.call("GET", &uri, &sub, None).await;
    assert_eq!(status, StatusCode::OK);
    let names: Vec<&str> = list["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter_map(|p| p["permission"].as_str())
        .collect();
    assert!(
        names.contains(&"hearth.realm.admin") && names.contains(&"docs.anything"),
        "{list}"
    );

    let (revoked, _) = f
        .call("DELETE", &format!("{uri}/docs.anything"), &sub, None)
        .await;
    assert_eq!(revoked, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn user_permission_grant_needs_an_existing_org_scope() {
    let f = Fixture::new().await;
    let (_, full) = f.admin("realm.admin");
    let target = f.user("target");
    let uri = format!("/admin/users/{}/permissions", target.as_uuid());
    // Control: the route exists and accepts a real org, so the 404 below is
    // the org check and not a missing route.
    let org = f.org("real");
    let (control, body) = f
        .call(
            "POST",
            &uri,
            &full,
            Some(&json!({"permission": "docs.read", "org_id": uuid_of(&org)})),
        )
        .await;
    assert_eq!(control, StatusCode::CREATED, "{body}");
    assert_eq!(body["scope_type"], "org", "{body}");
    assert_eq!(body["org_id"], uuid_of(&org), "{body}");
    let (status, _) = f
        .call(
            "POST",
            &uri,
            &full,
            Some(&json!({"permission": "docs.read", "org_id": uuid::Uuid::new_v4().to_string()})),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn user_permission_revocation_honours_the_ceiling() {
    let f = Fixture::new().await;
    let root = f.user("root");
    f.grant(&root, "hearth.admin", Scope::Realm);
    let (_, sub) = f.admin("hearth.realm.admin");
    let (status, _) = f
        .call(
            "DELETE",
            &format!("/admin/users/{}/permissions/hearth.admin", root.as_uuid()),
            &sub,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        f.holds_superuser(&root, None),
        "the superuser keeps hearth.admin"
    );
}

// ── extra org roles ──────────────────────────────────────────────────────────

#[tokio::test]
async fn additional_org_roles_honour_membership_and_the_ceiling() {
    let f = Fixture::new().await;
    let org = f.org("roles");
    let member = f.user("member");
    f.join(&org, &member);
    let outsider = f.user("outsider");
    f.plain_role("org-reader", &["docs.read"]);
    let (_, sub) = f.admin_with("hearth.realm.admin", &["docs.read"]);
    let (_, full) = f.admin("realm.admin");
    let member_uri = format!(
        "/admin/organizations/{}/members/{}/roles",
        uuid_of(&org),
        member.as_uuid()
    );

    let (above, _) = f
        .call(
            "POST",
            &member_uri,
            &sub,
            Some(&json!({"role_name": "realm.admin"})),
        )
        .await;
    assert_eq!(above, StatusCode::FORBIDDEN, "a role above the caller");

    let (not_member, _) = f
        .call(
            "POST",
            &format!(
                "/admin/organizations/{}/members/{}/roles",
                uuid_of(&org),
                outsider.as_uuid()
            ),
            &full,
            Some(&json!({"role_name": "org-reader"})),
        )
        .await;
    assert_eq!(not_member, StatusCode::CONFLICT, "the user is not a member");

    let (unknown_role, _) = f
        .call(
            "POST",
            &member_uri,
            &full,
            Some(&json!({"role_name": "no-such-role"})),
        )
        .await;
    assert_eq!(unknown_role, StatusCode::NOT_FOUND);

    let (added, _) = f
        .call(
            "POST",
            &member_uri,
            &sub,
            Some(&json!({"role_name": "org-reader"})),
        )
        .await;
    assert_eq!(added, StatusCode::NO_CONTENT);
    let (_, list) = f.call("GET", &member_uri, &sub, None).await;
    assert_eq!(list["items"], json!(["org-reader"]), "{list}");
    let (removed, _) = f
        .call("DELETE", &format!("{member_uri}/org-reader"), &sub, None)
        .await;
    assert_eq!(removed, StatusCode::NO_CONTENT);
    let (_, list) = f.call("GET", &member_uri, &sub, None).await;
    assert_eq!(list["items"], json!([]), "{list}");
}

/// Ported from `ga3_demotion_ceiling.rs`: removing an extra role from a
/// superuser demotes them.
#[tokio::test]
async fn additional_org_role_removal_honours_the_ceiling() {
    let f = Fixture::new().await;
    let org = f.org("demote");
    let root = f.user("root");
    f.join(&org, &root);
    f.h.rbac()
        .add_additional_role(&f.realm, &org, &root, "realm.admin", None)
        .expect("extra role");
    let (_, sub) = f.admin("hearth.realm.admin");
    let (status, _) = f
        .call(
            "DELETE",
            &format!(
                "/admin/organizations/{}/members/{}/roles/realm.admin",
                uuid_of(&org),
                root.as_uuid()
            ),
            &sub,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(f.holds_superuser(&root, Some(&org)));
}

// ── realm permissions ────────────────────────────────────────────────────────

/// The registry holds the seeded and YAML-declared permissions. (gRPC built
/// this list from the permissions found on one page of roles instead.)
#[tokio::test]
async fn realm_permissions_list_the_registry() {
    let f = Fixture::new().await;
    let (_, token) = f.admin("hearth.realm.admin");
    let (status, body) = f.call("GET", "/admin/permissions", &token, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let names: Vec<&str> = body["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter_map(|p| p["name"].as_str())
        .collect();
    assert!(names.contains(&"hearth.admin"), "{body}");
    assert!(names.contains(&"org.read"), "{body}");
    assert!(
        body["items"]
            .as_array()
            .expect("items")
            .iter()
            .all(|p| p["status"] == "active"),
        "{body}"
    );
}

// ── audit integrity ──────────────────────────────────────────────────────────

/// Ported from `grpc_audit_service.rs` and `grpc_sub_admin_bfla.rs`.
#[tokio::test]
async fn audit_verify_reports_the_chain_and_requires_realm_admin() {
    let f = Fixture::new().await;
    // Organization writes emit audit events.
    for i in 0..3 {
        f.org(&format!("audited{i}"));
    }
    let (_, users_admin) = f.admin("hearth.users.admin");
    let (denied, _) = f
        .call("POST", "/admin/audit/verify", &users_admin, None)
        .await;
    assert_eq!(denied, StatusCode::FORBIDDEN);

    let (_, realm_admin) = f.admin("hearth.realm.admin");
    let (status, body) = f
        .call("POST", "/admin/audit/verify", &realm_admin, None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["ok"], true);
    assert!(body["event_count"].as_u64().expect("count") >= 3, "{body}");
}
