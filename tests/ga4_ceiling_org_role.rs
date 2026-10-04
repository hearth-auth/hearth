//! GA sweep 4 — the admin privilege ceiling covers organization and role
//! changes.
//!
//! Round 3 applied `admin_auth::check_user_admin_ceiling` to every operation
//! that demotes one user or one group's members. Two families still demoted
//! out-ranking users without it:
//!
//! - **Organizations.** Removing a member, or deleting the organization,
//!   strips every admin permission the member held only in that organization
//!   (REST `DELETE /admin/organizations/{id}`; SCIM `PUT`/`PATCH`/`DELETE /Groups`).
//! - **Role definitions.** Removing an admin permission from a role (directly,
//!   through its parents, or by renaming it away from the org members who hold
//!   it as an additional role), or deleting the role, demotes every holder
//!   (REST `PATCH`/`DELETE /admin/roles/{id}`).
//!
//! Every such operation now runs the same rule on each affected user.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::core::{OrganizationId, RealmId, UserId};
use hearth::identity::{
    CreateOrganizationRequest, CreateRealmRequest, CreateUserRequest, OrganizationRole,
    RealmConfig, SessionContext, UpdateRealmRequest,
};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{
    AssignRoleRequest, CreateGroupRequest, CreateRoleRequest, GroupMember, Permission, RoleId,
    Scope, Subject, UserPermissionGrant,
};
use serde_json::json;
use sha2::{Digest, Sha256};
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
        let realm = h
            .identity()
            .create_realm(&CreateRealmRequest {
                name: format!("ga4-ceiling-{}", uuid::Uuid::new_v4()),
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
                    email: format!("{label}-{}@ga4.test", uuid::Uuid::new_v4()),
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

    fn assign(&self, user: &UserId, role: &RoleId) {
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
            .expect("assign role");
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

    /// A token for a fresh sub-admin holding exactly the seeded `role`.
    fn sub_admin(&self, role: &str) -> String {
        let id = self.user("sub");
        self.assign(&id, &self.role_id(role));
        self.token(&id)
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

    /// A plain org member who holds `hearth.admin` only inside `org`.
    fn org_superuser(&self, org: &OrganizationId) -> UserId {
        let id = self.user("org-root");
        self.join(org, &id);
        self.h
            .rbac()
            .seed_user_permission_unchecked(
                &self.realm,
                &UserPermissionGrant {
                    realm_id: self.realm.clone(),
                    user_id: id.clone(),
                    permission: Permission::new("hearth.admin").expect("perm"),
                    scope: Scope::Org {
                        org_id: org.clone(),
                    },
                    granted_at: hearth::core::Timestamp::from_micros(0),
                    granted_by: None,
                },
            )
            .expect("org-scoped grant");
        id
    }

    fn is_member(&self, org: &OrganizationId, user: &UserId) -> bool {
        self.h
            .identity()
            .get_membership(&self.realm, org, user)
            .expect("lookup")
            .is_some()
    }

    fn org_exists(&self, org: &OrganizationId) -> bool {
        self.h
            .identity()
            .get_organization(&self.realm, org)
            .expect("lookup")
            .is_some()
    }

    /// Whether `user` holds `hearth.admin` at realm level or in `org`.
    fn holds_superuser(&self, user: &UserId, org: Option<&OrganizationId>) -> bool {
        self.h
            .rbac()
            .resolve_permissions(user, &self.realm, org, None)
            .expect("resolve")
            .permissions
            .iter()
            .any(|p| p.as_str() == "hearth.admin")
    }

    fn role_exists(&self, role: &RoleId) -> bool {
        self.h
            .rbac()
            .get_role(&self.realm, role)
            .expect("lookup")
            .is_some()
    }

    async fn call(
        &self,
        method: &str,
        uri: &str,
        content_type: &str,
        bearer: &str,
        body: Option<&serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", content_type)
            .header("x-realm-id", self.realm.as_uuid().to_string())
            .header("authorization", format!("Bearer {bearer}"))
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

    async fn rest(
        &self,
        method: &str,
        uri: &str,
        bearer: &str,
        body: Option<&serde_json::Value>,
    ) -> StatusCode {
        self.call(method, uri, "application/json", bearer, body)
            .await
            .0
    }

    async fn scim(
        &self,
        method: &str,
        uri: &str,
        bearer: &str,
        body: Option<&serde_json::Value>,
    ) -> StatusCode {
        self.call(method, uri, "application/scim+json", bearer, body)
            .await
            .0
    }

    /// Configures a SCIM provisioning token on the realm; returns it.
    fn scim_token(&self) -> String {
        let token = format!("ga4-scim-{}", uuid::Uuid::new_v4());
        let mut h = Sha256::new();
        h.update(token.as_bytes());
        let hash: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
        self.h
            .identity()
            .update_realm(
                &self.realm,
                &UpdateRealmRequest {
                    config: Some(RealmConfig {
                        scim_bearer_token_hash: Some(hash),
                        ..RealmConfig::default()
                    }),
                    ..UpdateRealmRequest::default()
                },
            )
            .expect("set scim token");
        token
    }
}

fn group_uri(org: &OrganizationId) -> String {
    format!("/scim/v2/Groups/{}", org.as_uuid())
}

fn group_body(name: &str, members: &[&UserId]) -> serde_json::Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": name,
        "members": members
            .iter()
            .map(|u| json!({"value": u.as_uuid().to_string(), "type": "User"}))
            .collect::<Vec<_>>(),
    })
}

fn remove_member_patch(user: &UserId) -> serde_json::Value {
    json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "remove",
            "path": "members",
            "value": [{"value": user.as_uuid().to_string()}],
        }]
    })
}

// ── organizations over REST ──────────────────────────────────────────────────

/// `DELETE /admin/organizations/{id}` strips the org-scoped `hearth.admin` of its members:
/// a realm sub-admin may not delete an organization one of whose members
/// out-ranks it, but may still delete one whose members do not.
#[tokio::test]
async fn realm_sub_admin_cannot_delete_an_org_holding_an_org_scoped_superuser() {
    let f = Fixture::new().await;
    let org = f.org("acme");
    let root = f.org_superuser(&org);
    let plain_org = f.org("plain");
    f.join(&plain_org, &f.user("plain"));
    let token = f.sub_admin("hearth.realm.admin");

    let refused = f
        .rest(
            "DELETE",
            &format!("/admin/organizations/{}", org.as_uuid()),
            &token,
            None,
        )
        .await;
    let allowed = f
        .rest(
            "DELETE",
            &format!("/admin/organizations/{}", plain_org.as_uuid()),
            &token,
            None,
        )
        .await;

    assert_eq!(
        refused,
        StatusCode::FORBIDDEN,
        "deleting an org superuser's org"
    );
    assert!(f.org_exists(&org), "the refused org must survive");
    assert!(f.is_member(&org, &root), "the superuser stays a member");
    assert_eq!(
        allowed,
        StatusCode::NO_CONTENT,
        "an org of plain members stays deletable"
    );
    assert!(!f.org_exists(&plain_org), "the plain org is gone");
}

// ── organizations over SCIM ──────────────────────────────────────────────────

/// SCIM `/Groups` with an admin JWT: a realm sub-admin may not drop an
/// out-ranking member through `PUT` or `PATCH`, nor delete the group; it may
/// still drop a plain member.
#[tokio::test]
async fn scim_realm_sub_admin_cannot_remove_or_delete_an_org_superuser() {
    let f = Fixture::new().await;
    let org = f.org("acme");
    let root = f.org_superuser(&org);
    let plain = f.user("plain");
    f.join(&org, &plain);
    let token = f.sub_admin("hearth.realm.admin");
    let uri = group_uri(&org);

    let put = f
        .scim("PUT", &uri, &token, Some(&group_body("acme", &[&plain])))
        .await;
    let patch = f
        .scim("PATCH", &uri, &token, Some(&remove_member_patch(&root)))
        .await;
    let delete = f.scim("DELETE", &uri, &token, None).await;

    assert_eq!(put, StatusCode::FORBIDDEN, "PUT dropping the superuser");
    assert_eq!(patch, StatusCode::FORBIDDEN, "PATCH removing the superuser");
    assert_eq!(delete, StatusCode::FORBIDDEN, "DELETE of the group");
    assert!(f.org_exists(&org), "the org must survive");
    assert!(f.is_member(&org, &root), "the superuser stays a member");
    assert!(f.holds_superuser(&root, Some(&org)));

    let drop_plain = f
        .scim("PUT", &uri, &token, Some(&group_body("acme", &[&root])))
        .await;
    assert_eq!(drop_plain, StatusCode::OK, "a plain member stays removable");
    assert!(!f.is_member(&org, &plain), "the plain member is gone");
    assert!(f.is_member(&org, &root));
}

/// The SCIM provisioning token acts with no admin permission, so it may not
/// delete even a group it created once an admin principal is a member, nor
/// drop that member.
#[tokio::test]
async fn scim_token_cannot_delete_its_group_once_an_admin_is_a_member() {
    let f = Fixture::new().await;
    let token = f.scim_token();
    let (created, body) = f
        .call(
            "POST",
            "/scim/v2/Groups",
            "application/scim+json",
            &token,
            Some(&group_body("scim-made", &[])),
        )
        .await;
    assert_eq!(
        created,
        StatusCode::CREATED,
        "fixture: SCIM creates the group"
    );
    let org = OrganizationId::new(
        body["id"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .expect("the created group's id"),
    );
    let root = f.org_superuser(&org);
    let uri = group_uri(&org);

    let patch = f
        .scim("PATCH", &uri, &token, Some(&remove_member_patch(&root)))
        .await;
    let delete = f.scim("DELETE", &uri, &token, None).await;

    assert_eq!(patch, StatusCode::FORBIDDEN, "PATCH removing an admin");
    assert_eq!(
        delete,
        StatusCode::FORBIDDEN,
        "DELETE of a group with an admin"
    );
    assert!(f.org_exists(&org));
    assert!(f.is_member(&org, &root));
}

// ── role definitions over REST ───────────────────────────────────────────────

/// A realm sub-admin may not strip `hearth.admin` from the role a superuser
/// holds (directly, or through a child role that inherits it), nor delete the
/// role. Edits that remove no admin permission, and deletion of a plain role,
/// stay allowed; a peer superuser is not limited.
#[tokio::test]
async fn rest_realm_sub_admin_cannot_demote_through_a_role_definition() {
    let f = Fixture::new().await;
    let admin_role = f.role_id("realm.admin");
    let root = f.user("root");
    f.assign(&root, &admin_role);
    // `child` grants hearth.admin only through its parent.
    let child =
        f.h.rbac()
            .create_role(
                &f.realm,
                &CreateRoleRequest {
                    name: "ops-lead".into(),
                    description: None,
                    permissions: vec![],
                    parent_roles: vec![admin_role.clone()],
                    scope_kind: Default::default(),
                    allow_reserved_permissions: false,
                },
            )
            .expect("child role")
            .id;
    let heir = f.user("heir");
    f.assign(&heir, &child);
    let plain_role =
        f.h.rbac()
            .create_role(
                &f.realm,
                &CreateRoleRequest {
                    name: "reader".into(),
                    description: None,
                    permissions: vec![Permission::new("docs.read").expect("perm")],
                    parent_roles: vec![],
                    scope_kind: Default::default(),
                    allow_reserved_permissions: false,
                },
            )
            .expect("plain role")
            .id;
    f.assign(&root, &plain_role);
    let token = f.sub_admin("hearth.realm.admin");
    let admin_uri = format!("/admin/roles/{}", admin_role.as_uuid());
    let child_uri = format!("/admin/roles/{}", child.as_uuid());

    let strip = f
        .rest(
            "PATCH",
            &admin_uri,
            &token,
            Some(&json!({"permissions": []})),
        )
        .await;
    let unparent = f
        .rest(
            "PATCH",
            &child_uri,
            &token,
            Some(&json!({"parent_roles": []})),
        )
        .await;
    let delete = f.rest("DELETE", &admin_uri, &token, None).await;
    let delete_child = f.rest("DELETE", &child_uri, &token, None).await;

    assert_eq!(strip, StatusCode::FORBIDDEN, "strip hearth.admin");
    assert_eq!(unparent, StatusCode::FORBIDDEN, "drop the admin parent");
    assert_eq!(delete, StatusCode::FORBIDDEN, "delete the admin role");
    assert_eq!(delete_child, StatusCode::FORBIDDEN, "delete the child role");
    assert!(f.holds_superuser(&root, None), "root keeps hearth.admin");
    assert!(f.holds_superuser(&heir, None), "heir keeps hearth.admin");

    let describe = f
        .rest(
            "PATCH",
            &admin_uri,
            &token,
            Some(&json!({"description": "superusers"})),
        )
        .await;
    let delete_plain = f
        .rest(
            "DELETE",
            &format!("/admin/roles/{}?cascade=true", plain_role.as_uuid()),
            &token,
            None,
        )
        .await;
    assert_eq!(describe, StatusCode::OK, "an edit removing nothing");
    assert_eq!(delete_plain, StatusCode::NO_CONTENT, "a plain role");
    assert!(!f.role_exists(&plain_role));

    let peer = f.sub_admin("realm.admin");
    let peer_delete = f
        .rest("DELETE", &format!("{child_uri}?cascade=true"), &peer, None)
        .await;
    assert_eq!(peer_delete, StatusCode::NO_CONTENT, "a peer superuser");
}

/// A user who holds `realm.admin` only as an additional role in an
/// organization is demoted when the role is deleted or renamed (the extra
/// role is stored by name).
#[tokio::test]
async fn rest_realm_sub_admin_cannot_demote_an_additional_role_holder() {
    let f = Fixture::new().await;
    let admin_role = f.role_id("realm.admin");
    let org = f.org("acme");
    let root = f.user("root");
    f.join(&org, &root);
    f.h.rbac()
        .add_additional_role(&f.realm, &org, &root, "realm.admin", None)
        .expect("additional role");
    assert!(
        f.holds_superuser(&root, Some(&org)),
        "fixture: superuser in the org"
    );
    let token = f.sub_admin("hearth.realm.admin");
    let uri = format!("/admin/roles/{}", admin_role.as_uuid());

    let rename = f
        .rest("PATCH", &uri, &token, Some(&json!({"name": "retired"})))
        .await;
    let delete = f.rest("DELETE", &uri, &token, None).await;

    assert_eq!(
        rename,
        StatusCode::FORBIDDEN,
        "rename orphans the extra role"
    );
    assert_eq!(delete, StatusCode::FORBIDDEN, "delete the role");
    assert!(f.holds_superuser(&root, Some(&org)));
}

// ── round 2: SCIM Groups see the whole membership ────────────────────────────

impl Fixture {
    /// Adds `n` fresh plain users to `org`, on several threads so the
    /// storage engine coalesces their durable writes.
    fn fill(&self, org: &OrganizationId, n: usize) {
        const THREADS: usize = 16;
        let identity = self.h.identity_arc();
        std::thread::scope(|scope| {
            for t in 0..THREADS {
                let identity = identity.clone();
                scope.spawn(move || {
                    for i in (t..n).step_by(THREADS) {
                        let user = identity
                            .create_user(
                                &self.realm,
                                &CreateUserRequest {
                                    email: format!("m{i}-{}@ga4.test", uuid::Uuid::new_v4()),
                                    display_name: format!("m{i}"),
                                    first_name: String::new(),
                                    last_name: String::new(),
                                    attributes: Default::default(),
                                },
                            )
                            .expect("create user");
                        identity
                            .add_member(&self.realm, org, user.id(), OrganizationRole::Member)
                            .expect("add member");
                    }
                });
            }
        });
    }

    fn member_count(&self, org: &OrganizationId) -> usize {
        let mut n = 0;
        let mut cursor: Option<String> = None;
        loop {
            let page = self
                .h
                .identity()
                .list_members(&self.realm, org, cursor.as_deref(), 500)
                .expect("list members");
            n += page.items.len();
            match page.next_cursor {
                Some(c) => cursor = Some(c),
                None => return n,
            }
        }
    }

    fn org_name(&self, org: &OrganizationId) -> String {
        self.h
            .identity()
            .get_organization(&self.realm, org)
            .expect("lookup")
            .expect("exists")
            .name()
            .to_string()
    }
}

/// An organization larger than one 1,000-member page. SCIM used to read only
/// the first page: `GET` showed 1,000 members, the ceiling checked only the
/// removals it could see, and `PUT` could not remove the members beyond it.
#[tokio::test]
async fn scim_groups_handle_every_member_beyond_the_first_page() {
    const MEMBERS: usize = 1_030;
    let f = Fixture::new().await;
    let org = f.org("big");
    f.fill(&org, MEMBERS);
    // An out-ranking member who is NOT on the first page of the listing.
    let first_page: std::collections::HashSet<UserId> =
        f.h.identity()
            .list_members(&f.realm, &org, None, 1000)
            .expect("first page")
            .items
            .iter()
            .map(|m| m.user_id().clone())
            .collect();
    let (hidden, all_but_hidden, keep) = {
        let mut cursor: Option<String> = None;
        let mut all = Vec::new();
        loop {
            let page =
                f.h.identity()
                    .list_members(&f.realm, &org, cursor.as_deref(), 500)
                    .expect("list");
            all.extend(page.items.iter().map(|m| m.user_id().clone()));
            match page.next_cursor {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }
        let hidden = all
            .iter()
            .find(|u| !first_page.contains(*u))
            .expect("a member beyond the first page")
            .clone();
        // Keep everyone but the hidden member and two members of page one,
        // so the PUT must remove on both pages (and stays quick).
        let dropped_first: Vec<&UserId> = all
            .iter()
            .filter(|u| first_page.contains(*u))
            .take(2)
            .collect();
        let keep: Vec<UserId> = all
            .iter()
            .filter(|u| **u != hidden && !dropped_first.contains(u))
            .cloned()
            .collect();
        let all_but_hidden: Vec<UserId> = all.iter().filter(|u| **u != hidden).cloned().collect();
        (hidden, all_but_hidden, keep)
    };
    f.h.rbac()
        .seed_user_permission_unchecked(
            &f.realm,
            &UserPermissionGrant {
                realm_id: f.realm.clone(),
                user_id: hidden.clone(),
                permission: Permission::new("hearth.admin").expect("perm"),
                scope: Scope::Org {
                    org_id: org.clone(),
                },
                granted_at: hearth::core::Timestamp::from_micros(0),
                granted_by: None,
            },
        )
        .expect("org-scoped grant");
    let sub = f.sub_admin("hearth.realm.admin");
    let root = f.sub_admin("realm.admin");
    let uri = group_uri(&org);

    // The ceiling sees the out-ranking member beyond page one. (Only that
    // member is dropped: each ceiling check resolves the user's permissions,
    // so a walk over the whole org would dominate the test's runtime.)
    let others: Vec<&UserId> = all_but_hidden.iter().collect();
    let refused = f
        .scim("PUT", &uri, &sub, Some(&group_body("big", &others)))
        .await;
    assert_eq!(
        refused,
        StatusCode::FORBIDDEN,
        "sub-admin dropping the admin"
    );
    assert_eq!(f.member_count(&org), MEMBERS, "nothing was removed");
    assert!(f.is_member(&org, &hidden));

    // GET shows every member.
    let (status, body) = f
        .call("GET", &uri, "application/scim+json", &root, None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["members"].as_array().map(Vec::len),
        Some(MEMBERS),
        "every member is listed"
    );

    // PUT removes members on every page.
    let keep_refs: Vec<&UserId> = keep.iter().collect();
    let put = f
        .scim("PUT", &uri, &root, Some(&group_body("big", &keep_refs)))
        .await;
    assert_eq!(put, StatusCode::OK);
    assert_eq!(f.member_count(&org), MEMBERS - 3, "three members removed");
    assert!(
        !f.is_member(&org, &hidden),
        "the member beyond page one too"
    );
    assert!(
        keep.iter().all(|u| f.is_member(&org, u)),
        "the rest are kept"
    );
}

/// A membership change that names an unknown user is refused before
/// anything is written — not after the group was renamed.
#[tokio::test]
async fn scim_put_with_an_unknown_member_changes_nothing() {
    let f = Fixture::new().await;
    let org = f.org("acme");
    let plain = f.user("plain");
    f.join(&org, &plain);
    let root = f.sub_admin("realm.admin");
    let ghost = UserId::new(uuid::Uuid::new_v4());

    let status = f
        .scim(
            "PUT",
            &group_uri(&org),
            &root,
            Some(&group_body("renamed", &[&ghost])),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_ne!(f.org_name(&org), "renamed", "the rename was not applied");
    assert!(f.is_member(&org, &plain), "no member was removed");
}

// ── round 2: role deletion never leaves dangling references ──────────────────

/// A role with an assignment, a group assignment, a child role and an extra
/// org-role row.
struct ReferencedRole {
    role: RoleId,
    child: RoleId,
    user: UserId,
    group: hearth::rbac::GroupId,
    org: OrganizationId,
    member: UserId,
}

impl Fixture {
    fn referenced_role(&self, name: &str) -> ReferencedRole {
        let rbac = self.h.rbac();
        let role = rbac
            .create_role(
                &self.realm,
                &CreateRoleRequest {
                    name: name.into(),
                    description: None,
                    permissions: vec![Permission::new("docs.read").expect("perm")],
                    parent_roles: vec![],
                    scope_kind: Default::default(),
                    allow_reserved_permissions: false,
                },
            )
            .expect("role")
            .id;
        let child = rbac
            .create_role(
                &self.realm,
                &CreateRoleRequest {
                    name: format!("{name}-child"),
                    description: None,
                    permissions: vec![],
                    parent_roles: vec![role.clone()],
                    scope_kind: Default::default(),
                    allow_reserved_permissions: false,
                },
            )
            .expect("child")
            .id;
        let user = self.user("holder");
        self.assign(&user, &role);
        let group = rbac
            .create_group(
                &self.realm,
                &CreateGroupRequest {
                    name: format!("{name}-g"),
                    slug: format!("{name}-g"),
                    description: None,
                },
            )
            .expect("group")
            .id;
        rbac.add_group_member(&self.realm, &group, &GroupMember::User(self.user("gm")))
            .expect("group member");
        rbac.assign_role(
            &self.realm,
            &AssignRoleRequest {
                subject: Subject::Group(group.clone()),
                role_id: role.clone(),
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("group assignment");
        let org = self.org(name);
        let member = self.user("extra");
        self.join(&org, &member);
        rbac.add_additional_role(&self.realm, &org, &member, name, None)
            .expect("extra role");
        ReferencedRole {
            role,
            child,
            user,
            group,
            org,
            member,
        }
    }

    /// Asserts nothing refers to the deleted role any more.
    fn assert_no_references(&self, r: &ReferencedRole, name: &str) {
        let rbac = self.h.rbac();
        assert!(!self.role_exists(&r.role), "the role is gone");
        assert!(
            rbac.list_role_members(&self.realm, &r.role, None, 10)
                .expect("members")
                .items
                .is_empty(),
            "no by-role assignment index remains"
        );
        assert!(
            rbac.list_user_assignments(&self.realm, &r.user)
                .expect("user assignments")
                .iter()
                .all(|a| a.role_id != r.role),
            "the user's assignment is gone"
        );
        assert!(
            rbac.list_group_assignments(&self.realm, &r.group)
                .expect("group assignments")
                .iter()
                .all(|a| a.role_id != r.role),
            "the group's assignment is gone"
        );
        let child = rbac
            .get_role(&self.realm, &r.child)
            .expect("lookup")
            .expect("the child role survives");
        assert!(
            !child.parent_roles.contains(&r.role),
            "the parent link is gone: {:?}",
            child.parent_roles
        );
        assert!(
            !rbac
                .list_additional_roles(&self.realm, &r.org, &r.member)
                .expect("extra roles")
                .iter()
                .any(|n| n == name),
            "the extra org-role row is gone"
        );
    }
}

/// `DELETE /admin/roles/{id}` refuses a referenced role without `cascade`
/// (it used to delete the role and leave every reference dangling) and, with
/// `?cascade=true`, removes every reference with it.
#[tokio::test]
async fn rest_role_delete_refuses_references_or_cascades_them() {
    let f = Fixture::new().await;
    let r = f.referenced_role("editor");
    let root = f.sub_admin("realm.admin");
    let uri = format!("/admin/roles/{}", r.role.as_uuid());

    let (status, body) = f
        .call("DELETE", &uri, "application/json", &root, None)
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "role_in_use");
    assert!(f.role_exists(&r.role), "a refused delete keeps the role");

    let cascaded = f
        .rest("DELETE", &format!("{uri}?cascade=true"), &root, None)
        .await;
    assert_eq!(cascaded, StatusCode::NO_CONTENT);
    f.assert_no_references(&r, "editor");

    // An unreferenced role needs no cascade.
    let lone =
        f.h.rbac()
            .create_role(
                &f.realm,
                &CreateRoleRequest {
                    name: "lone".into(),
                    description: None,
                    permissions: vec![],
                    parent_roles: vec![],
                    scope_kind: Default::default(),
                    allow_reserved_permissions: false,
                },
            )
            .expect("role")
            .id;
    let plain = f
        .rest(
            "DELETE",
            &format!("/admin/roles/{}", lone.as_uuid()),
            &root,
            None,
        )
        .await;
    assert_eq!(plain, StatusCode::NO_CONTENT);
}

/// The ceiling covers a cascade: a sub-admin may not cascade-delete a role a
/// superuser holds, though it may cascade-delete a referenced plain role.
#[tokio::test]
async fn rest_role_cascade_delete_honours_the_ceiling() {
    let f = Fixture::new().await;
    let r = f.referenced_role("auditor");
    let sub = f.sub_admin("hearth.realm.admin");
    let admin_role = f.role_id("realm.admin");
    let holder = f.user("root");
    f.assign(&holder, &admin_role);

    // The ceiling: the superuser's own role, even with cascade.
    let denied = f
        .rest(
            "DELETE",
            &format!("/admin/roles/{}?cascade=true", admin_role.as_uuid()),
            &sub,
            None,
        )
        .await;
    assert_eq!(
        denied,
        StatusCode::FORBIDDEN,
        "cascade-deleting the superuser role"
    );
    assert!(f.role_exists(&admin_role));
    assert!(f.holds_superuser(&holder, None));

    // Control: the same caller cascade-deletes a referenced plain role.
    let allowed = f
        .rest(
            "DELETE",
            &format!("/admin/roles/{}?cascade=true", r.role.as_uuid()),
            &sub,
            None,
        )
        .await;
    assert_eq!(
        allowed,
        StatusCode::NO_CONTENT,
        "cascade delete of a plain role"
    );
    f.assert_no_references(&r, "auditor");
}

// ── round 2: org-scoped authority of non-members ─────────────────────────────

/// Permission resolution honours an org-scoped grant or group assignment of a
/// user who is NOT a member of that organization (`GET
/// /v1/me/permissions?org_id=` reports it), so the ceiling counts it too; and
/// an additional org role can no longer be given to a non-member.
#[tokio::test]
async fn non_member_org_scoped_authority_counts_for_the_ceiling() {
    let f = Fixture::new().await;
    let org = f.org("acme");
    // Direct org-scoped grant, no membership.
    let granted = f.user("granted");
    f.h.rbac()
        .seed_user_permission_unchecked(
            &f.realm,
            &UserPermissionGrant {
                realm_id: f.realm.clone(),
                user_id: granted.clone(),
                permission: Permission::new("hearth.admin").expect("perm"),
                scope: Scope::Org {
                    org_id: org.clone(),
                },
                granted_at: hearth::core::Timestamp::from_micros(0),
                granted_by: None,
            },
        )
        .expect("grant");
    // Org-scoped assignment through a group, no membership.
    let grouped = f.user("grouped");
    let group =
        f.h.rbac()
            .create_group(
                &f.realm,
                &CreateGroupRequest {
                    name: "ops".into(),
                    slug: "ops".into(),
                    description: None,
                },
            )
            .expect("group")
            .id;
    f.h.rbac()
        .add_group_member(&f.realm, &group, &GroupMember::User(grouped.clone()))
        .expect("group member");
    f.h.rbac()
        .assign_role(
            &f.realm,
            &AssignRoleRequest {
                subject: Subject::Group(group),
                role_id: f.role_id("realm.admin"),
                scope: Scope::Org {
                    org_id: org.clone(),
                },
                assigned_by: None,
            },
        )
        .expect("org-scoped group assignment");
    assert!(!f.is_member(&org, &granted) && !f.is_member(&org, &grouped));

    // Evidence: resolution honours it without membership.
    let (status, body) = f
        .call(
            "GET",
            &format!("/v1/me/permissions?org_id={}", org.as_uuid()),
            "application/json",
            &f.token(&granted),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body["permissions"]
            .as_array()
            .is_some_and(|p| p.iter().any(|v| v == "hearth.admin")),
        "a non-member's org-scoped grant is honoured: {body}"
    );

    let token = f.sub_admin("hearth.users.admin");
    for target in [&granted, &grouped] {
        let status = f
            .rest(
                "PATCH",
                &format!("/admin/users/{}", target.as_uuid()),
                &token,
                Some(&json!({"email": format!("x-{}@evil.test", target.as_uuid())})),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{}", target.as_uuid());
    }

    // An additional org role belongs to a membership.
    let stranger = f.user("stranger");
    let status = f
        .rest(
            "POST",
            &format!(
                "/admin/organizations/{}/members/{}/roles",
                org.as_uuid(),
                stranger.as_uuid()
            ),
            &f.sub_admin("realm.admin"),
            Some(&json!({"role_name": "realm.admin"})),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "an additional role for a non-member"
    );
}

// ── round 3: the ceiling's cost does not grow with non-admin members ─────────

/// Deleting a 5,000-member organization runs the ceiling on every member.
/// Resolving each member's permissions cost ~40 ms in a debug build (minutes
/// for the org); the check now resolves only the realm's admin-permission
/// holders, so plain members cost nothing. With one out-ranking member the
/// delete is refused, without one it succeeds — both well inside the test
/// timeout.
#[tokio::test]
async fn org_delete_ceiling_scales_to_large_orgs() {
    const MEMBERS: usize = 5_000;
    let f = Fixture::new().await;
    let guarded = f.org("guarded");
    f.fill(&guarded, MEMBERS);
    let root = f.org_superuser(&guarded);
    let open = f.org("open");
    f.fill(&open, MEMBERS);
    let token = f.sub_admin("hearth.realm.admin");
    let started = std::time::Instant::now();

    let refused = f
        .rest(
            "DELETE",
            &format!("/admin/organizations/{}", guarded.as_uuid()),
            &token,
            None,
        )
        .await;
    let allowed = f
        .rest(
            "DELETE",
            &format!("/admin/organizations/{}", open.as_uuid()),
            &token,
            None,
        )
        .await;
    let elapsed = started.elapsed();

    assert_eq!(
        refused,
        StatusCode::FORBIDDEN,
        "an org with an out-ranking member"
    );
    assert!(f.org_exists(&guarded) && f.is_member(&guarded, &root));
    assert_eq!(allowed, StatusCode::NO_CONTENT, "an org of plain members");
    assert!(!f.org_exists(&open));
    // Per-member resolution took minutes here; the holder-set check must not.
    assert!(
        elapsed < std::time::Duration::from_secs(60),
        "two 5,000-member ceiling checks took {elapsed:?}"
    );
}

impl Fixture {
    /// Puts `user` in a child group nested in a parent group that is
    /// assigned `role`.
    fn nested_group_holder(&self, user: &UserId, role: &RoleId) {
        let rbac = self.h.rbac();
        let mk_group = |slug: &str| {
            rbac.create_group(
                &self.realm,
                &CreateGroupRequest {
                    name: slug.into(),
                    slug: slug.into(),
                    description: None,
                },
            )
            .expect("group")
            .id
        };
        let (parent, child) = (mk_group("parent"), mk_group("child"));
        rbac.add_group_member(&self.realm, &child, &GroupMember::User(user.clone()))
            .expect("member");
        rbac.add_group_member(&self.realm, &parent, &GroupMember::Group(child))
            .expect("nest");
        rbac.assign_role(
            &self.realm,
            &AssignRoleRequest {
                subject: Subject::Group(parent),
                role_id: role.clone(),
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("group assignment");
    }
}

/// Past its first few users a multi-user check resolves only the realm's
/// admin holders, so that set must include every way a user can hold an
/// admin permission. Each out-ranking user below comes last, after 20 plain
/// users, so it is judged through the holder set.
#[tokio::test]
async fn admin_holder_set_covers_every_source_of_admin_permission() {
    use hearth::protocol::admin_auth::{check_users_admin_ceiling, UserCeilingError};

    let f = Fixture::new().await;
    let admin_role = f.role_id("realm.admin");
    let plain: Vec<UserId> = (0..20).map(|i| f.user(&format!("p{i}"))).collect();
    let actor = vec!["hearth.realm.admin".to_string()];
    let org = f.org("acme");
    let rbac = f.h.rbac();

    // Realm-level assignment of an admin role.
    let direct = f.user("direct");
    f.assign(&direct, &admin_role);
    // Through a nested group: child group ⊂ parent group, parent assigned.
    let nested = f.user("nested");
    f.nested_group_holder(&nested, &admin_role);
    // A role that inherits an admin role.
    let heir = f.user("heir");
    let lead = rbac
        .create_role(
            &f.realm,
            &CreateRoleRequest {
                name: "lead".into(),
                description: None,
                permissions: vec![],
                parent_roles: vec![admin_role.clone()],
                scope_kind: Default::default(),
                allow_reserved_permissions: false,
            },
        )
        .expect("role")
        .id;
    f.assign(&heir, &lead);
    // An extra org role.
    let extra = f.user("extra");
    f.join(&org, &extra);
    rbac.add_additional_role(&f.realm, &org, &extra, "realm.admin", None)
        .expect("extra role");
    // An org-scoped assignment for a non-member.
    let scoped = f.user("scoped");
    rbac.assign_role(
        &f.realm,
        &AssignRoleRequest {
            subject: Subject::User(scoped.clone()),
            role_id: admin_role.clone(),
            scope: Scope::Org {
                org_id: org.clone(),
            },
            assigned_by: None,
        },
    )
    .expect("org-scoped assignment");
    // A direct grant of an admin permission the actor lacks.
    let granted = f.user("granted");
    rbac.seed_user_permission_unchecked(
        &f.realm,
        &UserPermissionGrant {
            realm_id: f.realm.clone(),
            user_id: granted.clone(),
            permission: Permission::new("hearth.users.admin").expect("perm"),
            scope: Scope::Realm,
            granted_at: hearth::core::Timestamp::from_micros(0),
            granted_by: None,
        },
    )
    .expect("grant");

    let check = |last: Option<&UserId>| {
        let users: Vec<&UserId> = plain.iter().chain(last).collect();
        check_users_admin_ceiling(f.h.identity(), rbac, &f.realm, users, &actor)
    };
    assert_eq!(check(None), Ok(()), "plain users only");
    for (source, user) in [
        ("realm assignment", &direct),
        ("nested group", &nested),
        ("inherited role", &heir),
        ("extra org role", &extra),
        ("org-scoped assignment, non-member", &scoped),
        ("direct grant", &granted),
    ] {
        assert_eq!(
            check(Some(user)),
            Err(UserCeilingError::Exceeded),
            "{source}"
        );
    }
}

/// `POST /scim/v2/Groups` checks every member before creating the
/// organization: an unknown or malformed member leaves no half-created group.
#[tokio::test]
async fn scim_create_group_with_a_bad_member_creates_nothing() {
    let f = Fixture::new().await;
    let root = f.sub_admin("realm.admin");
    let plain = f.user("plain");
    let ghost = UserId::new(uuid::Uuid::new_v4());
    let malformed = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "malformed",
        "members": [{"value": "not-a-user-id", "type": "User"}],
    });

    let unknown = f
        .scim(
            "POST",
            "/scim/v2/Groups",
            &root,
            Some(&group_body("unknown", &[&plain, &ghost])),
        )
        .await;
    let bad = f
        .scim("POST", "/scim/v2/Groups", &root, Some(&malformed))
        .await;

    assert_eq!(unknown, StatusCode::BAD_REQUEST, "unknown member");
    assert_eq!(bad, StatusCode::BAD_REQUEST, "malformed member");
    let names: Vec<String> =
        f.h.identity()
            .list_user_organizations(&f.realm, &plain, None, 10)
            .expect("orgs")
            .items
            .iter()
            .map(|m| m.org_id().as_uuid().to_string())
            .collect();
    assert!(
        names.is_empty(),
        "the plain member joined nothing: {names:?}"
    );
    for slug in ["unknown", "malformed"] {
        assert!(
            f.h.identity()
                .get_organization_by_slug(&f.realm, slug)
                .expect("lookup")
                .is_none(),
            "no organization '{slug}' was created"
        );
    }
}
