//! Adversarial regression tests for HEA-799: gRPC cross-realm BFLA.
//!
//! ## Coverage matrix
//!
//! | Scenario | Test |
//! |---|---|
//! | realm-A admin → delete realm-B | `cross_realm_delete_realm_denied` |
//! | realm-A admin → get realm-B | `cross_realm_get_realm_denied` |
//! | realm-A admin → update realm-B | `cross_realm_update_realm_denied` |
//! | realm-A admin → create_realm | `cross_realm_create_realm_denied` |
//! | realm-A admin → list_realms | `list_realms_scoped_to_own_realm` |
//! | system admin → get realm-A | `system_admin_can_get_any_realm` (positive) |
//! | realm-A admin → get realm-A | `realm_admin_can_get_own_realm` (positive) |

mod common;

use std::sync::Arc;

use hearth::core::RealmId;
use hearth::identity::{CreateRealmRequest, CreateUserRequest, SessionContext};
use hearth::protocol::admin_auth::AdminRateLimiter;
use hearth::protocol::grpc::identity::IdentityAdminSvc;
use hearth::protocol::grpc::server::GrpcState;
use hearth::protocol::proto::identity::v1::{
    self as pb, identity_admin_service_server::IdentityAdminService,
};
use hearth::rbac::{AssignRoleRequest, Scope as RbacScope, Subject};
use tonic::{Code, Request};

fn system_realm_id() -> RealmId {
    RealmId::new(uuid::Uuid::nil())
}

fn make_svc(h: &common::TestHarness) -> IdentityAdminSvc {
    IdentityAdminSvc::new(GrpcState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
        Arc::new(AdminRateLimiter::new()),
    ))
}

/// Creates a realm, seeds RBAC, creates an admin user, and returns (realm_id, access_token).
fn setup_realm_admin(h: &common::TestHarness, suffix: &str) -> (RealmId, String) {
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("bfla-{suffix}"),
            config: None,
        })
        .expect("create realm");
    let realm_id = realm.id().clone();
    h.rbac().seed_realm(&realm_id).expect("seed rbac");

    let user = h
        .identity()
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: format!("admin-{suffix}@bfla.test"),
                display_name: "Test Admin".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let role = h
        .rbac()
        .get_role_by_name(&realm_id, "realm.admin")
        .expect("get role")
        .expect("realm.admin role must exist after seed");
    h.rbac()
        .assign_role(
            &realm_id,
            &AssignRoleRequest {
                subject: Subject::User(user.id().clone()),
                role_id: role.id,
                scope: RbacScope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign realm.admin");

    let session = h
        .identity()
        .create_session(&realm_id, user.id(), &SessionContext::default())
        .expect("create session");
    let token = h
        .identity()
        .issue_tokens(&realm_id, user.id(), session.id())
        .expect("issue tokens")
        .access_token()
        .to_string();

    (realm_id, token)
}

/// Creates an admin user in the system realm and returns their access token.
fn setup_system_admin(h: &common::TestHarness) -> String {
    let sys = system_realm_id();
    h.rbac().seed_realm(&sys).expect("seed system rbac");

    let user = h
        .identity()
        .create_admin_user(&CreateUserRequest {
            email: format!("sysadmin-{}@bfla.test", uuid::Uuid::new_v4()),
            display_name: "Sys Admin".into(),
            first_name: String::new(),
            last_name: String::new(),
            attributes: Default::default(),
        })
        .expect("create system admin user");

    let role = h
        .rbac()
        .get_role_by_name(&sys, "realm.admin")
        .expect("get role")
        .expect("realm.admin must exist after seed");
    h.rbac()
        .assign_role(
            &sys,
            &AssignRoleRequest {
                subject: Subject::User(user.id().clone()),
                role_id: role.id,
                scope: RbacScope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign realm.admin to system admin");

    let session = h
        .identity()
        .create_session(&sys, user.id(), &SessionContext::default())
        .expect("create session");
    h.identity()
        .issue_tokens(&sys, user.id(), session.id())
        .expect("issue tokens")
        .access_token()
        .to_string()
}

fn grpc_req<T>(realm_id: &RealmId, token: &str, msg: T) -> Request<T> {
    let mut r = Request::new(msg);
    r.metadata_mut().insert(
        "authorization",
        format!("Bearer {token}").parse().expect("valid header"),
    );
    r.metadata_mut().insert(
        "x-realm-id",
        realm_id
            .as_uuid()
            .to_string()
            .parse()
            .expect("valid header"),
    );
    r
}

// ---------------------------------------------------------------------------
// Adversarial tests — cross-realm calls must be rejected
// ---------------------------------------------------------------------------

/// Realm-A admin calling delete_realm on realm-B must get PermissionDenied.
#[tokio::test]
async fn cross_realm_delete_realm_denied() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let svc = make_svc(&h);

    let (realm_a, token_a) = setup_realm_admin(&h, &uuid::Uuid::new_v4().to_string());
    let (realm_b, _token_b) = setup_realm_admin(&h, &uuid::Uuid::new_v4().to_string());

    let result = svc
        .delete_realm(grpc_req(
            &realm_a,
            &token_a,
            pb::DeleteRealmRequest {
                id: realm_b.as_uuid().to_string(),
            },
        ))
        .await;

    assert!(
        result.is_err(),
        "cross-realm delete_realm must be denied, got Ok"
    );
    assert_eq!(
        result.expect_err("must error").code(),
        Code::PermissionDenied,
        "must return PermissionDenied"
    );
}

/// Realm-A admin calling get_realm on realm-B must get PermissionDenied.
#[tokio::test]
async fn cross_realm_get_realm_denied() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let svc = make_svc(&h);

    let (realm_a, token_a) = setup_realm_admin(&h, &uuid::Uuid::new_v4().to_string());
    let (realm_b, _token_b) = setup_realm_admin(&h, &uuid::Uuid::new_v4().to_string());

    let result = svc
        .get_realm(grpc_req(
            &realm_a,
            &token_a,
            pb::GetRealmRequest {
                id: realm_b.as_uuid().to_string(),
            },
        ))
        .await;

    assert!(result.is_err(), "cross-realm get_realm must be denied");
    assert_eq!(result.expect_err("must error").code(), Code::PermissionDenied);
}

/// Realm-A admin calling update_realm on realm-B must get PermissionDenied.
#[tokio::test]
async fn cross_realm_update_realm_denied() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let svc = make_svc(&h);

    let (realm_a, token_a) = setup_realm_admin(&h, &uuid::Uuid::new_v4().to_string());
    let (realm_b, _token_b) = setup_realm_admin(&h, &uuid::Uuid::new_v4().to_string());

    let result = svc
        .update_realm(grpc_req(
            &realm_a,
            &token_a,
            pb::UpdateRealmCall {
                id: realm_b.as_uuid().to_string(),
                body: Some(pb::UpdateRealmRequest {
                    name: Some("pwned".into()),
                    ..Default::default()
                }),
            },
        ))
        .await;

    assert!(result.is_err(), "cross-realm update_realm must be denied");
    assert_eq!(result.expect_err("must error").code(), Code::PermissionDenied);
}

/// Non-system realm admin calling create_realm must get PermissionDenied.
/// Only system-realm admins may create new realms.
#[tokio::test]
async fn cross_realm_create_realm_denied() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let svc = make_svc(&h);

    let (realm_a, token_a) = setup_realm_admin(&h, &uuid::Uuid::new_v4().to_string());

    let result = svc
        .create_realm(grpc_req(
            &realm_a,
            &token_a,
            pb::CreateRealmRequest {
                name: format!("new-realm-{}", uuid::Uuid::new_v4()),
                config: None,
            },
        ))
        .await;

    assert!(
        result.is_err(),
        "non-system realm admin must not be able to create realms"
    );
    assert_eq!(result.expect_err("must error").code(), Code::PermissionDenied);
}

/// Realm-A admin calling list_realms must see only their own realm, not realm-B.
#[tokio::test]
async fn list_realms_scoped_to_own_realm() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let svc = make_svc(&h);

    let (realm_a, token_a) = setup_realm_admin(&h, &uuid::Uuid::new_v4().to_string());
    let (realm_b, _token_b) = setup_realm_admin(&h, &uuid::Uuid::new_v4().to_string());

    let page = svc
        .list_realms(grpc_req(
            &realm_a,
            &token_a,
            pb::ListRealmsRequest {
                limit: None,
                cursor: None,
            },
        ))
        .await
        .expect("list_realms must succeed for own realm")
        .into_inner();

    assert_eq!(
        page.items.len(),
        1,
        "realm-A admin must see exactly one realm in the list"
    );
    assert_eq!(
        page.items[0].id,
        realm_a.as_uuid().to_string(),
        "the single returned realm must be realm-A"
    );
    assert!(
        !page
            .items
            .iter()
            .any(|r| r.id == realm_b.as_uuid().to_string()),
        "realm-B must not appear in realm-A admin's list_realms response"
    );
}

// ---------------------------------------------------------------------------
// Positive tests — legitimate access must still work
// ---------------------------------------------------------------------------

/// System realm admin can call get_realm on any tenant realm.
#[tokio::test]
async fn system_admin_can_get_any_realm() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let svc = make_svc(&h);

    let sys_token = setup_system_admin(&h);
    let (realm_a, _token_a) = setup_realm_admin(&h, &uuid::Uuid::new_v4().to_string());

    let result = svc
        .get_realm(grpc_req(
            &system_realm_id(),
            &sys_token,
            pb::GetRealmRequest {
                id: realm_a.as_uuid().to_string(),
            },
        ))
        .await;

    assert!(
        result.is_ok(),
        "system realm admin must be able to get any realm, got: {result:?}"
    );
    assert_eq!(
        result.expect("must succeed").into_inner().id,
        realm_a.as_uuid().to_string()
    );
}

/// Regular realm admin can call get_realm on their own realm.
#[tokio::test]
async fn realm_admin_can_get_own_realm() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let svc = make_svc(&h);

    let (realm_a, token_a) = setup_realm_admin(&h, &uuid::Uuid::new_v4().to_string());

    let result = svc
        .get_realm(grpc_req(
            &realm_a,
            &token_a,
            pb::GetRealmRequest {
                id: realm_a.as_uuid().to_string(),
            },
        ))
        .await;

    assert!(
        result.is_ok(),
        "realm admin must be able to get own realm, got: {result:?}"
    );
    assert_eq!(
        result.expect("must succeed").into_inner().id,
        realm_a.as_uuid().to_string()
    );
}
