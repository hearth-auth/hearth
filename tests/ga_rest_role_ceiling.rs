//! GA audit 2026-09-28 M6 — REST role create/update privilege ceiling.
//!
//! gRPC `CreateRole`/`UpdateRole` refuse a sub-admin who defines a role
//! carrying a permission they do not hold themselves; the REST twins
//! (`POST /admin/roles`, `PATCH /admin/roles/{id}`) did not. A
//! `hearth.realm.admin` sub-admin could therefore add a permission it lacks to
//! a role that is already assigned to it and raise its own authority without
//! the assignment-time ceiling ever running. The ceiling also covers
//! `parent_roles`: naming a parent role grants its permissions too.

#![allow(clippy::unwrap_used)]

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use hearth::core::RealmId;
use hearth::identity::{CreateUserRequest, SessionContext};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, CreateRoleRequest, Permission, Role, Scope, Subject};
use tower::ServiceExt as _;

fn create_role(h: &common::TestHarness, realm: &RealmId, name: &str, perms: &[&str]) -> Role {
    h.rbac()
        .create_role(
            realm,
            &CreateRoleRequest {
                name: name.to_string(),
                description: None,
                permissions: perms
                    .iter()
                    .map(|p| Permission::new((*p).to_string()).unwrap())
                    .collect(),
                parent_roles: Vec::new(),
                scope_kind: hearth::rbac::RoleScopeKind::Realm,
                allow_reserved_permissions: false,
            },
        )
        .unwrap()
}

/// A token for a user holding the seeded `hearth.realm.admin` role plus the
/// custom role `extra`.
fn sub_admin_token(h: &common::TestHarness, realm: &RealmId, extra: &Role) -> String {
    let user = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("sub-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Sub".into(),
                ..CreateUserRequest::default()
            },
        )
        .unwrap();
    let seeded = h
        .rbac()
        .get_role_by_name(realm, "hearth.realm.admin")
        .unwrap()
        .expect("seeded hearth.realm.admin role");
    for role_id in [seeded.id, extra.id.clone()] {
        h.rbac()
            .assign_role(
                realm,
                &AssignRoleRequest {
                    subject: Subject::User(user.id().clone()),
                    role_id,
                    scope: Scope::Realm,
                    assigned_by: None,
                },
            )
            .unwrap();
    }
    let session = h
        .identity()
        .create_session(realm, user.id(), &SessionContext::default())
        .unwrap();
    h.identity()
        .issue_tokens(realm, user.id(), session.id())
        .unwrap()
        .access_token()
        .to_string()
}

async fn send(
    h: &common::TestHarness,
    method: Method,
    uri: &str,
    token: &str,
    realm: &RealmId,
    body: serde_json::Value,
) -> StatusCode {
    let state = Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()));
    router(state)
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .header("Content-Type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

struct Env {
    h: common::TestHarness,
    realm: RealmId,
    own_role: Role,
    token: String,
}

async fn env() -> Env {
    let h = common::TestHarness::embedded().await.unwrap();
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).unwrap();
    let own_role = create_role(&h, &realm, "docs-reader", &["docs.read"]);
    let token = sub_admin_token(&h, &realm, &own_role);
    Env {
        h,
        realm,
        own_role,
        token,
    }
}

#[tokio::test]
async fn sub_admin_cannot_add_a_permission_it_lacks_to_its_own_role() {
    let e = env().await;
    let uri = format!("/admin/roles/{}", e.own_role.id);

    // Control: re-stating a permission the caller holds is allowed.
    let ok = send(
        &e.h,
        Method::PATCH,
        &uri,
        &e.token,
        &e.realm,
        serde_json::json!({"permissions": ["docs.read"]}),
    )
    .await;
    assert_eq!(ok, StatusCode::OK, "a permission the caller holds is fine");

    let escalated = send(
        &e.h,
        Method::PATCH,
        &uri,
        &e.token,
        &e.realm,
        serde_json::json!({"permissions": ["docs.read", "user.impersonate"]}),
    )
    .await;
    assert_eq!(
        escalated,
        StatusCode::FORBIDDEN,
        "a sub-admin must not add a permission it does not hold to a role"
    );
    let role =
        e.h.rbac()
            .get_role(&e.realm, &e.own_role.id)
            .unwrap()
            .unwrap();
    assert!(
        !role
            .permissions
            .iter()
            .any(|p| p.as_str() == "user.impersonate"),
        "the refused update must not have been written"
    );
}

#[tokio::test]
async fn sub_admin_cannot_create_a_role_exceeding_its_own_permissions() {
    let e = env().await;
    let ok = send(
        &e.h,
        Method::POST,
        "/admin/roles",
        &e.token,
        &e.realm,
        serde_json::json!({"name": "held-only", "permissions": ["docs.read"]}),
    )
    .await;
    assert_eq!(ok, StatusCode::CREATED, "control: held permissions only");

    let escalated = send(
        &e.h,
        Method::POST,
        "/admin/roles",
        &e.token,
        &e.realm,
        serde_json::json!({"name": "escalated", "permissions": ["user.impersonate"]}),
    )
    .await;
    assert_eq!(escalated, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn sub_admin_cannot_inherit_permissions_it_lacks_through_parent_roles() {
    let e = env().await;
    let powerful = create_role(&e.h, &e.realm, "impersonators", &["user.impersonate"]);

    let created = send(
        &e.h,
        Method::POST,
        "/admin/roles",
        &e.token,
        &e.realm,
        serde_json::json!({
            "name": "child",
            "permissions": [],
            "parent_roles": [powerful.id.to_string()],
        }),
    )
    .await;
    assert_eq!(created, StatusCode::FORBIDDEN, "create with a parent role");

    let updated = send(
        &e.h,
        Method::PATCH,
        &format!("/admin/roles/{}", e.own_role.id),
        &e.token,
        &e.realm,
        serde_json::json!({"parent_roles": [powerful.id.to_string()]}),
    )
    .await;
    assert_eq!(updated, StatusCode::FORBIDDEN, "update with a parent role");
}

#[tokio::test]
async fn full_admin_is_not_bound_by_the_ceiling() {
    let h = common::TestHarness::embedded().await.unwrap();
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).unwrap();
    let own_role = create_role(&h, &realm, "docs-reader", &["docs.read"]);
    // `realm.admin` carries `hearth.admin`.
    let full = h
        .rbac()
        .get_role_by_name(&realm, "realm.admin")
        .unwrap()
        .unwrap();
    let token = sub_admin_token(&h, &realm, &full);

    let status = send(
        &h,
        Method::PATCH,
        &format!("/admin/roles/{}", own_role.id),
        &token,
        &realm,
        serde_json::json!({"permissions": ["docs.read", "user.impersonate"]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

/// gRPC twin: the ceiling covered only the direct permissions; a parent role
/// granting a permission the caller lacks slipped through.
#[tokio::test]
async fn grpc_sub_admin_cannot_inherit_permissions_it_lacks_through_parent_roles() {
    use hearth::protocol::admin_auth::AdminRateLimiter;
    use hearth::protocol::grpc::rbac_admin::RbacAdminSvc;
    use hearth::protocol::grpc::server::GrpcState;
    use hearth::protocol::proto::rbac::v1::{
        self as pb, rbac_admin_service_server::RbacAdminService,
    };

    let e = env().await;
    let powerful = create_role(&e.h, &e.realm, "impersonators", &["user.impersonate"]);
    let svc = RbacAdminSvc::new(GrpcState::new(
        e.h.identity_arc(),
        e.h.rbac_arc(),
        e.h.audit_arc(),
        Arc::new(AdminRateLimiter::new()),
    ));
    let request = |parents: Vec<String>| {
        let mut r = tonic::Request::new(pb::CreateRoleRequest {
            realm_id: e.realm.as_uuid().to_string(),
            name: format!("child-{}", uuid::Uuid::new_v4()),
            description: String::new(),
            permissions: vec!["docs.read".into()],
            parent_role_ids: parents,
        });
        r.metadata_mut().insert(
            "authorization",
            format!("Bearer {}", e.token).parse().unwrap(),
        );
        r.metadata_mut()
            .insert("x-realm-id", e.realm.as_uuid().to_string().parse().unwrap());
        r
    };

    svc.create_role(request(vec![e.own_role.id.to_string()]))
        .await
        .expect("control: a parent whose permissions the caller holds");
    let err = svc
        .create_role(request(vec![powerful.id.to_string()]))
        .await
        .expect_err("a parent granting user.impersonate must be refused");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}
