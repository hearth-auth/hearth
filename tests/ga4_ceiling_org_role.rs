//! GA sweep 4 — the admin privilege ceiling covers organization and role
//! changes.
//!
//! Round 3 applied `admin_auth::check_user_admin_ceiling` to every operation
//! that demotes one user or one group's members. Two families still demoted
//! out-ranking users without it:
//!
//! - **Organizations.** Removing a member, or deleting the organization,
//!   strips every admin permission the member held only in that organization
//!   (gRPC `DeleteOrganization`; SCIM `PUT`/`PATCH`/`DELETE /Groups`).
//! - **Role definitions.** Removing an admin permission from a role (directly,
//!   through its parents, or by renaming it away from the org members who hold
//!   it as an additional role), or deleting the role, demotes every holder
//!   (REST `PATCH`/`DELETE /admin/roles/{id}`; gRPC `UpdateRole`/`DeleteRole`).
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
use hearth::protocol::admin_auth::AdminRateLimiter;
use hearth::protocol::grpc::identity::IdentityAdminSvc;
use hearth::protocol::grpc::rbac_admin::RbacAdminSvc;
use hearth::protocol::grpc::server::GrpcState;
use hearth::protocol::http::{router, AppState};
use hearth::protocol::proto::identity::v1::{
    self as idpb, identity_admin_service_server::IdentityAdminService,
};
use hearth::protocol::proto::rbac::v1::{self as pb, rbac_admin_service_server::RbacAdminService};
use hearth::rbac::{
    AssignRoleRequest, CreateRoleRequest, Permission, RoleId, Scope, Subject, UserPermissionGrant,
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
        let h = common::TestHarness::embedded().await.expect("harness");
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

    fn state(&self) -> GrpcState {
        GrpcState::new(
            self.h.identity_arc(),
            self.h.rbac_arc(),
            self.h.audit_arc(),
            Arc::new(AdminRateLimiter::new()),
        )
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
            .grant_user_permission(
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

// ── organizations over gRPC ──────────────────────────────────────────────────

/// `DeleteOrganization` strips the org-scoped `hearth.admin` of its members:
/// a realm sub-admin may not delete an organization one of whose members
/// out-ranks it, but may still delete one whose members do not.
#[tokio::test]
async fn grpc_realm_sub_admin_cannot_delete_an_org_holding_an_org_scoped_superuser() {
    let f = Fixture::new().await;
    let svc = IdentityAdminSvc::new(f.state());
    let org = f.org("acme");
    let root = f.org_superuser(&org);
    let plain_org = f.org("plain");
    f.join(&plain_org, &f.user("plain"));
    let token = f.sub_admin("hearth.realm.admin");

    let refused = svc
        .delete_organization(f.grpc_req(
            &token,
            idpb::DeleteOrganizationRequest {
                id: org.as_uuid().to_string(),
            },
        ))
        .await
        .expect_err("DeleteOrganization demoting an org superuser");
    let allowed = svc
        .delete_organization(f.grpc_req(
            &token,
            idpb::DeleteOrganizationRequest {
                id: plain_org.as_uuid().to_string(),
            },
        ))
        .await;

    assert_eq!(refused.code(), tonic::Code::PermissionDenied);
    assert!(f.org_exists(&org), "the refused org must survive");
    assert!(f.is_member(&org, &root), "the superuser stays a member");
    allowed.expect("an org of plain members stays deletable");
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
            &format!("/admin/roles/{}", plain_role.as_uuid()),
            &token,
            None,
        )
        .await;
    assert_eq!(describe, StatusCode::OK, "an edit removing nothing");
    assert_eq!(delete_plain, StatusCode::NO_CONTENT, "a plain role");
    assert!(!f.role_exists(&plain_role));

    let peer = f.sub_admin("realm.admin");
    let peer_delete = f.rest("DELETE", &child_uri, &peer, None).await;
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

// ── role definitions over gRPC ───────────────────────────────────────────────

#[tokio::test]
async fn grpc_realm_sub_admin_cannot_demote_through_a_role_definition() {
    let f = Fixture::new().await;
    let svc = RbacAdminSvc::new(f.state());
    let admin_role = f.role_id("realm.admin");
    let root = f.user("root");
    f.assign(&root, &admin_role);
    let token = f.sub_admin("hearth.realm.admin");
    let realm_id = f.realm.as_uuid().to_string();

    let update = svc
        .update_role(f.grpc_req(
            &token,
            pb::UpdateRoleRequest {
                realm_id: realm_id.clone(),
                role_id: admin_role.as_uuid().to_string(),
                name: String::new(),
                description: String::new(),
                permissions: vec![],
                parent_role_ids: vec![],
            },
        ))
        .await
        .expect_err("UpdateRole stripping hearth.admin");
    let delete = svc
        .delete_role(f.grpc_req(
            &token,
            pb::DeleteRoleRequest {
                realm_id: realm_id.clone(),
                role_id: admin_role.as_uuid().to_string(),
                cascade: false,
            },
        ))
        .await
        .expect_err("DeleteRole of the superuser's role");

    assert_eq!(update.code(), tonic::Code::PermissionDenied, "UpdateRole");
    assert_eq!(delete.code(), tonic::Code::PermissionDenied, "DeleteRole");
    assert!(f.role_exists(&admin_role));
    assert!(f.holds_superuser(&root, None));
}
