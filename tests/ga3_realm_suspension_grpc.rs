//! GA audit round 3 — gRPC `SuspendRealm` / `UnsuspendRealm`, the twins of
//! `POST /admin/realms/{id}/suspend` / `unsuspend` (see
//! `ga3_realm_suspension.rs` for the full REST contract). Same gate: only a
//! system-realm admin with `hearth.realm.admin` (or `hearth.admin`).

mod common;

use std::sync::Arc;

use hearth::core::{RealmId, UserId};
use hearth::identity::{CreateRealmRequest, CreateUserRequest, RealmStatus, SessionContext};
use hearth::protocol::admin_auth::AdminRateLimiter;
use hearth::protocol::grpc::identity::IdentityAdminSvc;
use hearth::protocol::grpc::server::GrpcState;
use hearth::protocol::proto::identity::v1::{
    self as pb, identity_admin_service_server::IdentityAdminService,
};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use tonic::Code;

fn system_realm() -> RealmId {
    RealmId::new(uuid::Uuid::nil())
}

fn user_with_realm_admin(h: &common::TestHarness, realm: &RealmId) -> UserId {
    let req = CreateUserRequest {
        email: format!("admin-{}@ga3.test", uuid::Uuid::new_v4()),
        display_name: "Admin".into(),
        first_name: String::new(),
        last_name: String::new(),
        attributes: Default::default(),
    };
    let user = if realm == &system_realm() {
        h.identity().create_admin_user(&req)
    } else {
        h.identity().create_user(realm, &req)
    }
    .expect("create user");
    let role = h
        .rbac()
        .get_role_by_name(realm, "realm.admin")
        .expect("role lookup")
        .expect("realm.admin seeded");
    h.rbac()
        .assign_role(
            realm,
            &AssignRoleRequest {
                subject: Subject::User(user.id().clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign role");
    user.id().clone()
}

fn token(h: &common::TestHarness, realm: &RealmId, user: &UserId) -> String {
    let session = h
        .identity()
        .create_session(realm, user, &SessionContext::default())
        .expect("session");
    h.identity()
        .issue_tokens(realm, user, session.id())
        .expect("issue tokens")
        .access_token()
        .to_string()
}

fn req<T>(token: &str, caller: &RealmId, msg: T) -> tonic::Request<T> {
    let mut r = tonic::Request::new(msg);
    r.metadata_mut().insert(
        "authorization",
        format!("Bearer {token}").parse().expect("valid header"),
    );
    r.metadata_mut().insert(
        "x-realm-id",
        caller.as_uuid().to_string().parse().expect("valid header"),
    );
    r
}

#[tokio::test]
async fn grpc_suspend_and_unsuspend_realm() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let svc = IdentityAdminSvc::new(GrpcState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
        Arc::new(AdminRateLimiter::new()),
    ));
    h.rbac().seed_realm(&system_realm()).expect("seed system");
    let operator_id = user_with_realm_admin(&h, &system_realm());
    let operator = token(&h, &system_realm(), &operator_id);
    let tenant = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("ga3-susp-grpc-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();
    h.rbac().seed_realm(&tenant).expect("seed tenant");
    let tenant_admin_id = user_with_realm_admin(&h, &tenant);
    let tenant_admin = token(&h, &tenant, &tenant_admin_id);
    let status = |h: &common::TestHarness| {
        h.identity()
            .get_realm(&tenant)
            .expect("lookup")
            .expect("realm exists")
            .status()
    };

    let refused = svc
        .suspend_realm(req(
            &tenant_admin,
            &tenant,
            pb::SuspendRealmRequest {
                id: tenant.as_uuid().to_string(),
            },
        ))
        .await
        .expect_err("a tenant admin may not suspend its realm");
    assert_eq!(refused.code(), Code::PermissionDenied);
    assert_eq!(status(&h), RealmStatus::Active);

    let suspended = svc
        .suspend_realm(req(
            &operator,
            &system_realm(),
            pb::SuspendRealmRequest {
                id: tenant.as_uuid().to_string(),
            },
        ))
        .await
        .expect("SuspendRealm")
        .into_inner();
    assert_eq!(suspended.status, pb::RealmStatus::Suspended as i32);
    assert_eq!(status(&h), RealmStatus::Suspended);

    let active = svc
        .unsuspend_realm(req(
            &operator,
            &system_realm(),
            pb::UnsuspendRealmRequest {
                id: tenant.as_uuid().to_string(),
            },
        ))
        .await
        .expect("UnsuspendRealm")
        .into_inner();
    assert_eq!(active.status, pb::RealmStatus::Active as i32);
    assert_eq!(status(&h), RealmStatus::Active);

    let system = svc
        .suspend_realm(req(
            &operator,
            &system_realm(),
            pb::SuspendRealmRequest {
                id: system_realm().as_uuid().to_string(),
            },
        ))
        .await
        .expect_err("the system realm cannot be suspended");
    assert_eq!(system.code(), Code::PermissionDenied);
}
