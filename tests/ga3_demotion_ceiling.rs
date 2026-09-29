//! GA audit round 3 — the privilege ceiling covers demotion and revocation.
//!
//! Round 2 stopped a sub-admin from modifying or deleting a user who
//! out-ranks it. The same sub-admin could still *demote* that user — unassign
//! the role that makes them a superuser, revoke a direct grant, drop them from
//! the group that carries the role, or delete that group — and could revoke
//! their sessions and consents. Every such operation now runs
//! `admin_auth::check_user_admin_ceiling` (or its group form) on each affected
//! user, over REST and gRPC. The ceiling also counts admin permissions a user
//! holds only through an organization-scoped grant.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hearth::core::{OrganizationId, RealmId, SessionId, UserId};
use hearth::identity::{
    CreateOrganizationRequest, CreateRealmRequest, CreateUserRequest, OrganizationRole,
    SessionContext,
};
use hearth::protocol::admin_auth::AdminRateLimiter;
use hearth::protocol::grpc::rbac_admin::RbacAdminSvc;
use hearth::protocol::grpc::server::GrpcState;
use hearth::protocol::http::{router, AppState};
use hearth::protocol::proto::rbac::v1::{self as pb, rbac_admin_service_server::RbacAdminService};
use hearth::rbac::{
    AssignRoleRequest, AssignmentId, CreateGroupRequest, GroupId, GroupMember, Permission, Scope,
    Subject, UserPermissionGrant,
};
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
                name: format!("ga3-demote-{}", uuid::Uuid::new_v4()),
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

    fn grpc(&self) -> RbacAdminSvc {
        RbacAdminSvc::new(GrpcState::new(
            self.h.identity_arc(),
            self.h.rbac_arc(),
            self.h.audit_arc(),
            Arc::new(AdminRateLimiter::new()),
        ))
    }

    fn user(&self, label: &str) -> UserId {
        self.h
            .identity()
            .create_user(
                &self.realm,
                &CreateUserRequest {
                    email: format!("{label}-{}@ga3.test", uuid::Uuid::new_v4()),
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

    fn assign(&self, subject: Subject, role: &str) -> AssignmentId {
        let role = self
            .h
            .rbac()
            .get_role_by_name(&self.realm, role)
            .expect("lookup")
            .unwrap_or_else(|| panic!("seeded role '{role}' missing"));
        self.h
            .rbac()
            .assign_role(
                &self.realm,
                &AssignRoleRequest {
                    subject,
                    role_id: role.id,
                    scope: Scope::Realm,
                    assigned_by: None,
                },
            )
            .expect("assign role")
            .id
    }

    /// A superuser (seeded `realm.admin`): `(user, its assignment)`.
    fn superuser(&self) -> (UserId, AssignmentId) {
        let id = self.user("root");
        let a = self.assign(Subject::User(id.clone()), "realm.admin");
        (id, a)
    }

    fn session(&self, user: &UserId) -> SessionId {
        self.h
            .identity()
            .create_session(&self.realm, user, &SessionContext::default())
            .expect("session")
            .id()
            .clone()
    }

    fn token(&self, user: &UserId) -> String {
        let session = self.session(user);
        self.h
            .identity()
            .issue_tokens(&self.realm, user, &session)
            .expect("tokens")
            .access_token()
            .to_string()
    }

    /// A token for a fresh sub-admin holding exactly `role`.
    fn sub_admin(&self, role: &str) -> String {
        let id = self.user("sub");
        self.assign(Subject::User(id.clone()), role);
        self.token(&id)
    }

    fn group_with(&self, member: GroupMember) -> GroupId {
        let group = self
            .h
            .rbac()
            .create_group(
                &self.realm,
                &CreateGroupRequest {
                    name: format!("g-{}", uuid::Uuid::new_v4().simple()),
                    slug: format!("g-{}", uuid::Uuid::new_v4().simple()),
                    description: None,
                },
            )
            .expect("create group");
        self.h
            .rbac()
            .add_group_member(&self.realm, &group.id, &member)
            .expect("add member");
        group.id
    }

    fn holds_superuser(&self, user: &UserId) -> bool {
        self.h
            .rbac()
            .resolve_permissions(user, &self.realm, None, None)
            .expect("resolve")
            .permissions
            .iter()
            .any(|p| p.as_str() == "hearth.admin")
    }

    async fn rest(&self, method: &str, uri: &str, bearer: &str) -> StatusCode {
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header("x-realm-id", self.realm.as_uuid().to_string())
            .header("authorization", format!("Bearer {bearer}"))
            .body(Body::empty())
            .expect("request");
        self.app
            .clone()
            .oneshot(req)
            .await
            .expect("oneshot")
            .status()
    }

    async fn rest_json(
        &self,
        method: &str,
        uri: &str,
        bearer: &str,
        body: &serde_json::Value,
    ) -> StatusCode {
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .header("x-realm-id", self.realm.as_uuid().to_string())
            .header("authorization", format!("Bearer {bearer}"))
            .body(Body::from(body.to_string()))
            .expect("request");
        self.app
            .clone()
            .oneshot(req)
            .await
            .expect("oneshot")
            .status()
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

// ── demotion over REST ───────────────────────────────────────────────────────

/// `DELETE /admin/assignments/{id}` on a superuser's role, by a realm
/// sub-admin, must be refused; the same sub-admin may still unassign a role
/// from a plain user.
#[tokio::test]
async fn rest_realm_sub_admin_cannot_unassign_a_superusers_role() {
    let f = Fixture::new().await;
    let (root, root_assignment) = f.superuser();
    let plain = f.user("plain");
    let plain_assignment = f.assign(Subject::User(plain.clone()), "realm.member");
    let token = f.sub_admin("hearth.realm.admin");

    let refused = f
        .rest(
            "DELETE",
            &format!("/admin/assignments/{}", root_assignment.as_uuid()),
            &token,
        )
        .await;
    let allowed = f
        .rest(
            "DELETE",
            &format!("/admin/assignments/{}", plain_assignment.as_uuid()),
            &token,
        )
        .await;

    assert_eq!(refused, StatusCode::FORBIDDEN, "superuser's assignment");
    assert!(
        f.holds_superuser(&root),
        "the superuser must keep hearth.admin"
    );
    assert_eq!(allowed, StatusCode::NO_CONTENT, "plain user's assignment");
}

/// Dropping a superuser from the group that carries their role, deleting that
/// group, or unassigning the role from the group, all demote them.
#[tokio::test]
async fn rest_realm_sub_admin_cannot_demote_through_a_group() {
    let f = Fixture::new().await;
    let root = f.user("root");
    let group = f.group_with(GroupMember::User(root.clone()));
    let group_assignment = f.assign(Subject::Group(group.clone()), "realm.admin");
    assert!(f.holds_superuser(&root), "fixture: superuser via the group");
    let token = f.sub_admin("hearth.realm.admin");

    let remove_member = f
        .rest(
            "DELETE",
            &format!(
                "/admin/groups/{}/members/{}",
                group.as_uuid(),
                root.as_uuid()
            ),
            &token,
        )
        .await;
    let unassign = f
        .rest(
            "DELETE",
            &format!("/admin/assignments/{}", group_assignment.as_uuid()),
            &token,
        )
        .await;
    let delete_group = f
        .rest(
            "DELETE",
            &format!("/admin/groups/{}", group.as_uuid()),
            &token,
        )
        .await;

    assert_eq!(remove_member, StatusCode::FORBIDDEN, "remove group member");
    assert_eq!(unassign, StatusCode::FORBIDDEN, "unassign the group's role");
    assert_eq!(delete_group, StatusCode::FORBIDDEN, "delete the group");
    assert!(
        f.holds_superuser(&root),
        "the superuser must keep hearth.admin"
    );
}

// ── sessions and consents over REST ──────────────────────────────────────────

/// A users-admin may not revoke (or sv-bump) a superuser's session, nor
/// revoke their consents; a plain user's session is still revocable.
#[tokio::test]
async fn rest_sub_admin_cannot_revoke_a_superusers_sessions_or_consents() {
    let f = Fixture::new().await;
    let (root, _) = f.superuser();
    let root_session = f.session(&root);
    let plain = f.user("plain");
    let plain_session = f.session(&plain);
    let users_admin = f.sub_admin("hearth.users.admin");
    let realm_admin = f.sub_admin("hearth.realm.admin");
    let client = uuid::Uuid::new_v4();

    let revoke = f
        .rest(
            "DELETE",
            &format!("/admin/sessions/{}", root_session.as_uuid()),
            &users_admin,
        )
        .await;
    let bump = f
        .rest(
            "POST",
            &format!("/admin/sessions/{}/sv-bump", root_session.as_uuid()),
            &realm_admin,
        )
        .await;
    let consent = f
        .rest(
            "DELETE",
            &format!("/admin/users/{}/consents/{client}", root.as_uuid()),
            &users_admin,
        )
        .await;
    let plain_revoke = f
        .rest(
            "DELETE",
            &format!("/admin/sessions/{}", plain_session.as_uuid()),
            &users_admin,
        )
        .await;

    assert_eq!(revoke, StatusCode::FORBIDDEN, "revoke session");
    assert_eq!(bump, StatusCode::FORBIDDEN, "sv-bump session");
    assert_eq!(consent, StatusCode::FORBIDDEN, "revoke consent");
    assert!(
        f.h.identity()
            .get_session(&f.realm, &root_session)
            .expect("lookup")
            .is_some(),
        "the superuser's session must survive"
    );
    assert_eq!(plain_revoke, StatusCode::NO_CONTENT, "plain user's session");
}

// ── organization-scoped admin permissions ────────────────────────────────────

/// `hearth.admin` held only through an organization-scoped grant still
/// out-ranks a realm-level users-admin.
#[tokio::test]
async fn org_scoped_admin_permission_counts_for_the_ceiling() {
    let f = Fixture::new().await;
    let target = f.user("org-root");
    let org: OrganizationId =
        f.h.identity()
            .create_organization(
                &f.realm,
                &CreateOrganizationRequest {
                    name: "Acme".into(),
                    slug: format!("acme-{}", uuid::Uuid::new_v4().simple()),
                    description: None,
                    config: None,
                    attributes: Default::default(),
                },
            )
            .expect("create org")
            .id()
            .clone();
    f.h.identity()
        .add_member(&f.realm, &org, &target, OrganizationRole::Member)
        .expect("add member");
    f.h.rbac()
        .grant_user_permission(
            &f.realm,
            &UserPermissionGrant {
                realm_id: f.realm.clone(),
                user_id: target.clone(),
                permission: Permission::new("hearth.admin").expect("perm"),
                scope: Scope::Org {
                    org_id: org.clone(),
                },
                granted_at: hearth::core::Timestamp::from_micros(0),
                granted_by: None,
            },
        )
        .expect("org-scoped grant");
    let before =
        f.h.identity()
            .get_user(&f.realm, &target)
            .expect("lookup")
            .expect("exists")
            .email()
            .to_string();
    let token = f.sub_admin("hearth.users.admin");

    let status = f
        .rest_json(
            "PATCH",
            &format!("/admin/users/{}", target.as_uuid()),
            &token,
            &json!({"email": "attacker@evil.test"}),
        )
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    let after =
        f.h.identity()
            .get_user(&f.realm, &target)
            .expect("lookup")
            .expect("exists")
            .email()
            .to_string();
    assert_eq!(after, before);
}

// ── demotion and consents over gRPC ──────────────────────────────────────────

#[tokio::test]
async fn grpc_realm_sub_admin_cannot_demote_a_superuser() {
    let f = Fixture::new().await;
    let svc = f.grpc();
    let (root, root_assignment) = f.superuser();
    f.h.rbac()
        .grant_user_permission(
            &f.realm,
            &UserPermissionGrant {
                realm_id: f.realm.clone(),
                user_id: root.clone(),
                permission: Permission::new("hearth.users.admin").expect("perm"),
                scope: Scope::Realm,
                granted_at: hearth::core::Timestamp::from_micros(0),
                granted_by: None,
            },
        )
        .expect("direct grant");
    let group = f.group_with(GroupMember::User(root.clone()));
    let token = f.sub_admin("hearth.realm.admin");
    let realm_id = f.realm.as_uuid().to_string();

    let unassign = svc
        .unassign_user_role(f.grpc_req(
            &token,
            pb::UnassignUserRoleRequest {
                realm_id: realm_id.clone(),
                user_id: root.as_uuid().to_string(),
                assignment_id: root_assignment.as_uuid().to_string(),
            },
        ))
        .await
        .expect_err("UnassignUserRole on a superuser");
    let revoke = svc
        .revoke_user_permission(f.grpc_req(
            &token,
            pb::RevokeUserPermissionRequest {
                realm_id: realm_id.clone(),
                user_id: root.as_uuid().to_string(),
                permission: "hearth.users.admin".to_string(),
                scope_type: "realm".to_string(),
                org_id: String::new(),
            },
        ))
        .await
        .expect_err("RevokeUserPermission on a superuser");
    let remove = svc
        .remove_group_member(f.grpc_req(
            &token,
            pb::RemoveGroupMemberRequest {
                realm_id: realm_id.clone(),
                group_id: group.as_uuid().to_string(),
                member: Some(pb::GroupMember {
                    r#type: pb::group_member::Type::User as i32,
                    id: root.as_uuid().to_string(),
                }),
            },
        ))
        .await
        .expect_err("RemoveGroupMember of a superuser");
    let delete = svc
        .delete_group(f.grpc_req(
            &token,
            pb::DeleteGroupRequest {
                realm_id: realm_id.clone(),
                group_id: group.as_uuid().to_string(),
            },
        ))
        .await
        .expect_err("DeleteGroup holding a superuser");

    for (name, err) in [
        ("UnassignUserRole", unassign),
        ("RevokeUserPermission", revoke),
        ("RemoveGroupMember", remove),
        ("DeleteGroup", delete),
    ] {
        assert_eq!(err.code(), tonic::Code::PermissionDenied, "{name}");
    }
    assert!(f.holds_superuser(&root));
}

#[tokio::test]
async fn grpc_users_sub_admin_cannot_revoke_a_superusers_consent() {
    let f = Fixture::new().await;
    let svc = f.grpc();
    let (root, _) = f.superuser();
    let token = f.sub_admin("hearth.users.admin");

    let err = svc
        .revoke_consent(f.grpc_req(
            &token,
            pb::RevokeConsentRequest {
                realm_id: f.realm.as_uuid().to_string(),
                user_id: root.as_uuid().to_string(),
                client_id: uuid::Uuid::new_v4().to_string(),
            },
        ))
        .await
        .expect_err("RevokeConsent on a superuser");

    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}
