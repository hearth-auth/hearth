#![allow(clippy::unwrap_used)]
//! Task 26.34 (follow-up to 26.16) — the gRPC half of the organisation kill
//! switch.
//!
//! Task 26.16 made `OrganizationStatus::Suspended` mean something: token
//! issuance in a suspended org context is refused, and the live-RBAC paths drop
//! the org context so org-scoped authority evaporates while realm-scoped
//! authority survives. It closed four paths — `issue_tokens_with_context`,
//! `introspect`, `decide_token_permission` and `GET /me/permissions`.
//!
//! `RbacAdminService::ResolveEffectivePermissions` is the fifth, and it was
//! missed. It takes a caller-supplied `org_id` straight off the wire and hands
//! it to `resolve_permissions` unchecked, so an operator who froze a tenant was
//! still told over gRPC exactly which org-scoped permissions that tenant's
//! members hold — and any integration resolving through this RPC still acted on
//! them.
//!
//! The shape of the test matches the HTTP one in
//! `tests/org_suspension_kill_switch.rs`: two roles, one realm-scoped and one
//! org-scoped, so a suspension that killed both would be as wrong as one that
//! killed neither.

mod common;

use std::sync::Arc;

use hearth::core::{OrganizationId, RealmId, UserId};
use hearth::identity::{
    CreateOrganizationRequest, CreateUserRequest, OrganizationConfig, OrganizationRole,
    OrganizationStatus, UpdateOrganizationRequest,
};
use hearth::protocol::admin_auth::AdminRateLimiter;
use hearth::protocol::grpc::rbac_admin::RbacAdminSvc;
use hearth::protocol::grpc::server::GrpcState;
use hearth::protocol::proto::rbac::v1::{self as pb, rbac_admin_service_server::RbacAdminService};
use hearth::rbac::{AssignRoleRequest, CreateRoleRequest, Permission, Scope, Subject};
use tonic::Request;

struct Ctx {
    h: common::TestHarness,
    realm: RealmId,
    org: OrganizationId,
    user: UserId,
    token: String,
    svc: RbacAdminSvc,
}

fn perms(list: &[&str]) -> Vec<Permission> {
    list.iter()
        .map(|p| Permission::new(*p).expect("valid perm"))
        .collect()
}

/// Builds a realm with an organisation, a member holding one realm-scoped role
/// and one org-scoped role, and an admin token for the gRPC service.
#[allow(clippy::too_many_lines)] // Fixture setup: one realm, one org, four roles, two users.
async fn ctx() -> Ctx {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");

    let org = h
        .identity()
        .create_organization(
            &realm,
            &CreateOrganizationRequest {
                name: "acme-grpc".to_string(),
                slug: "acme-grpc".to_string(),
                description: None,
                config: Some(OrganizationConfig { max_members: None }),
                ..Default::default()
            },
        )
        .expect("create org")
        .id()
        .clone();

    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("member-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Member".into(),
                ..Default::default()
            },
        )
        .expect("create user")
        .id()
        .clone();
    h.identity()
        .add_member(&realm, &org, &user, OrganizationRole::Member)
        .expect("add member");

    for (name, permission) in [("realm-reader", "docs.read"), ("org-writer", "docs.write")] {
        h.rbac()
            .create_role(
                &realm,
                &CreateRoleRequest {
                    name: name.into(),
                    description: None,
                    permissions: perms(&[permission]),
                    parent_roles: vec![],
                    ..Default::default()
                },
            )
            .expect("create role");
    }
    for (name, scope) in [
        ("realm-reader", Scope::Realm),
        (
            "org-writer",
            Scope::Org {
                org_id: org.clone(),
            },
        ),
    ] {
        let role = h
            .rbac()
            .get_role_by_name(&realm, name)
            .expect("get role")
            .expect("role exists");
        h.rbac()
            .assign_role(
                &realm,
                &AssignRoleRequest {
                    subject: Subject::User(user.clone()),
                    role_id: role.id,
                    scope,
                    assigned_by: None,
                },
            )
            .expect("assign role");
    }

    // The admin identity the RPC authenticates as.
    let admin = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("admin-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Admin".into(),
                ..Default::default()
            },
        )
        .expect("create admin");
    let admin_role = h
        .rbac()
        .get_role_by_name(&realm, "realm.admin")
        .expect("lookup")
        .expect("seed role");
    h.rbac()
        .assign_role(
            &realm,
            &AssignRoleRequest {
                subject: Subject::User(admin.id().clone()),
                role_id: admin_role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign admin");
    let session = h
        .identity()
        .create_session(&realm, admin.id(), &Default::default())
        .expect("session");
    let token = h
        .identity()
        .issue_tokens(&realm, admin.id(), session.id())
        .expect("issue")
        .access_token()
        .to_string();

    let state = GrpcState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
        Arc::new(AdminRateLimiter::new()),
    );
    let svc = RbacAdminSvc::new(state);

    Ctx {
        h,
        realm,
        org,
        user,
        token,
        svc,
    }
}

/// Runs `ResolveEffectivePermissions` in `ctx.org`'s context.
async fn resolve(ctx: &Ctx) -> Vec<String> {
    let mut req = Request::new(pb::ResolveEffectivePermissionsRequest {
        realm_id: ctx.realm.as_uuid().to_string(),
        user_id: ctx.user.as_uuid().to_string(),
        org_id: ctx.org.as_uuid().to_string(),
        scope: String::new(),
    });
    req.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", ctx.token).parse().expect("meta"),
    );
    req.metadata_mut().insert(
        "x-realm-id",
        ctx.realm.as_uuid().to_string().parse().expect("realm meta"),
    );
    ctx.svc
        .resolve_effective_permissions(req)
        .await
        .expect("resolve must succeed")
        .into_inner()
        .permissions
}

/// A suspended organisation must stop granting its org-scoped permissions over
/// gRPC, exactly as it does over HTTP.
#[tokio::test]
async fn a_suspended_org_stops_granting_over_grpc() {
    let ctx = ctx().await;

    // Precondition: while Active the org-scoped permission resolves. Without
    // this the assertion below would also pass against a fixture that never
    // granted it.
    let active = resolve(&ctx).await;
    assert!(
        active.iter().any(|p| p == "docs.write"),
        "precondition: an active org must grant its org-scoped permission; got {active:?}"
    );

    ctx.h
        .identity()
        .update_organization(
            &ctx.realm,
            &ctx.org,
            &UpdateOrganizationRequest {
                status: Some(OrganizationStatus::Suspended),
                ..Default::default()
            },
        )
        .expect("suspend org");

    let suspended = resolve(&ctx).await;
    assert!(
        !suspended.iter().any(|p| p == "docs.write"),
        "a suspended org must not keep granting its org-scoped permission over \
         gRPC; got {suspended:?}"
    );
    // Realm-scoped authority is untouched: suspension kills the org, not the
    // member's account. A change that dropped both would be as wrong as one
    // that dropped neither.
    assert!(
        suspended.iter().any(|p| p == "docs.read"),
        "realm-scoped permissions must survive an org suspension; got {suspended:?}"
    );
}
