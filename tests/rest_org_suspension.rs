#![allow(clippy::unwrap_used)]
//! Task 26.34 (follow-up to 26.16) — the organisation kill switch on the admin
//! effective-permissions read.
//!
//! Task 26.16 made `OrganizationStatus::Suspended` mean something: token
//! issuance in a suspended org context is refused, and the live-RBAC paths drop
//! the org context so org-scoped authority evaporates while realm-scoped
//! authority survives. The admin resolver
//! (`GET /admin/users/{id}/effective-permissions?org_id=`, formerly also the
//! gRPC `ResolveEffectivePermissions`) takes a caller-supplied `org_id`; an
//! operator who froze a tenant must not still be told that tenant's members
//! hold their org-scoped permissions.
//!
//! The shape matches `tests/org_suspension_kill_switch.rs`: two roles, one
//! realm-scoped and one org-scoped, so a suspension that killed both would be
//! as wrong as one that killed neither. Ported from the removed
//! `grpc_org_suspension.rs`.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::core::{OrganizationId, RealmId, UserId};
use hearth::identity::{
    CreateOrganizationRequest, CreateUserRequest, OrganizationConfig, OrganizationRole,
    OrganizationStatus, UpdateOrganizationRequest,
};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, CreateRoleRequest, Permission, Scope, Subject};
use serde_json::Value;
use tower::ServiceExt as _;

struct Ctx {
    h: common::TestHarness,
    realm: RealmId,
    org: OrganizationId,
    user: UserId,
    token: String,
    app: axum::Router,
}

fn perms(list: &[&str]) -> Vec<Permission> {
    list.iter()
        .map(|p| Permission::new(*p).expect("valid perm"))
        .collect()
}

/// Builds a realm with an organisation, a member holding one realm-scoped role
/// and one org-scoped role, and an admin token for the REST admin API.
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
                name: "acme-rest".to_string(),
                slug: "acme-rest".to_string(),
                description: None,
                config: Some(OrganizationConfig::default()),
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

    // The admin identity the REST call authenticates as.
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

    let app = router(Arc::new(AppState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
    )));

    Ctx {
        h,
        realm,
        org,
        user,
        token,
        app,
    }
}

/// `GET /admin/users/{id}/effective-permissions` in `ctx.org`'s context.
async fn resolve(ctx: &Ctx) -> Vec<String> {
    let req = Request::builder()
        .method("GET")
        .uri(format!(
            "/admin/users/{}/effective-permissions?org_id={}",
            ctx.user.as_uuid(),
            ctx.org.as_uuid()
        ))
        .header("x-realm-id", ctx.realm.as_uuid().to_string())
        .header("authorization", format!("Bearer {}", ctx.token))
        .body(Body::empty())
        .expect("request");
    let resp = ctx.app.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.expect("body");
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    assert_eq!(status, StatusCode::OK, "resolve must succeed: {body}");
    body["permissions"]
        .as_array()
        .unwrap_or_else(|| panic!("no permissions array: {body}"))
        .iter()
        .filter_map(|p| p.as_str().map(str::to_owned))
        .collect()
}

/// A suspended organisation must stop granting its org-scoped permissions over
/// the admin resolver, exactly as it does in tokens and `/v1/me/permissions`.
#[tokio::test]
async fn a_suspended_org_stops_granting_on_the_admin_resolver() {
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
        "a suspended org must not keep granting its org-scoped permission on \
         the admin resolver; got {suspended:?}"
    );
    // Realm-scoped authority is untouched: suspension kills the org, not the
    // member's account. A change that dropped both would be as wrong as one
    // that dropped neither.
    assert!(
        suspended.iter().any(|p| p == "docs.read"),
        "realm-scoped permissions must survive an org suspension; got {suspended:?}"
    );
}
