//! Adversarial regression tests for HEA-799 — gRPC cross-realm BFLA.
//!
//! Verifies that all five realm-management gRPC handlers enforce a system-realm
//! gate so that an admin of realm A cannot read or mutate realm B.
//!
//! Scenario: realm-A admin token + `x-realm-id: realm-a` calling any realm
//! management RPC must receive `PermissionDenied`, not `Ok`.

mod common;

use std::sync::Arc;

use hearth::core::RealmId;
use hearth::identity::{CreateUserRequest, SessionContext};
use hearth::protocol::admin_auth::AdminRateLimiter;
use hearth::protocol::grpc::identity::IdentityAdminSvc;
use hearth::protocol::grpc::server::GrpcState;
use hearth::protocol::proto::identity::v1::{
    self as pb, identity_admin_service_server::IdentityAdminService,
};
use hearth::rbac::{AssignRoleRequest, Scope as RbacScope, Subject};
use tonic::Request;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct BflaRig {
    _h: common::TestHarness,
    /// Token issued for realm-A admin — must be rejected by realm RPCs.
    realm_a_token: String,
    realm_a_id: RealmId,
    /// Token issued for system-realm admin — must be accepted by realm RPCs.
    sys_token: String,
    sys_realm_id: RealmId,
    /// A second realm created so get/update/delete have a target.
    victim_realm_id: RealmId,
    svc: IdentityAdminSvc,
}

async fn setup() -> BflaRig {
    let h = common::TestHarness::embedded().await.expect("harness");

    // ---- system realm ----
    let sys_realm_id = RealmId::new(uuid::Uuid::nil());
    h.rbac().seed_realm(&sys_realm_id).expect("seed sys realm");
    let sys_user = h
        .identity()
        .create_admin_user(&CreateUserRequest {
            email: format!("sysadmin-{}@example.com", uuid::Uuid::new_v4()),
            display_name: "SysAdmin".into(),
            first_name: String::new(),
            last_name: String::new(),
            attributes: Default::default(),
        })
        .expect("sys user");
    let sys_admin_role = h
        .rbac()
        .get_role_by_name(&sys_realm_id, "realm.admin")
        .expect("lookup")
        .expect("role");
    h.rbac()
        .assign_role(
            &sys_realm_id,
            &AssignRoleRequest {
                subject: Subject::User(sys_user.id().clone()),
                role_id: sys_admin_role.id,
                scope: RbacScope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign sys role");
    let sys_session = h
        .identity()
        .create_session(&sys_realm_id, sys_user.id(), &SessionContext::default())
        .expect("sys session");
    let sys_token = h
        .identity()
        .issue_tokens(&sys_realm_id, sys_user.id(), sys_session.id())
        .expect("sys tokens")
        .access_token()
        .to_string();

    // ---- realm A (attacker's realm) ----
    let realm_a_id = h.create_realm();
    h.rbac().seed_realm(&realm_a_id).expect("seed realm A");
    let a_user = h
        .identity()
        .create_user(
            &realm_a_id,
            &CreateUserRequest {
                email: format!("admin-a-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "AdminA".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("realm A user");
    let a_admin_role = h
        .rbac()
        .get_role_by_name(&realm_a_id, "realm.admin")
        .expect("lookup")
        .expect("role");
    h.rbac()
        .assign_role(
            &realm_a_id,
            &AssignRoleRequest {
                subject: Subject::User(a_user.id().clone()),
                role_id: a_admin_role.id,
                scope: RbacScope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign A role");
    let a_session = h
        .identity()
        .create_session(&realm_a_id, a_user.id(), &SessionContext::default())
        .expect("A session");
    let realm_a_token = h
        .identity()
        .issue_tokens(&realm_a_id, a_user.id(), a_session.id())
        .expect("A tokens")
        .access_token()
        .to_string();

    // ---- realm B (victim realm) ----
    let victim_realm_id = h.create_realm();

    let state = GrpcState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
        Arc::new(AdminRateLimiter::new()),
    );
    let svc = IdentityAdminSvc::new(state);

    BflaRig {
        _h: h,
        realm_a_token,
        realm_a_id,
        sys_token,
        sys_realm_id,
        victim_realm_id,
        svc,
    }
}

/// Build a request with the given token and realm-id metadata.
fn req_with<T>(msg: T, token: &str, realm_id: &RealmId) -> Request<T> {
    let mut r = Request::new(msg);
    r.metadata_mut().insert(
        "authorization",
        format!("Bearer {token}").parse().expect("auth meta"),
    );
    r.metadata_mut().insert(
        "x-realm-id",
        realm_id.as_uuid().to_string().parse().expect("realm meta"),
    );
    r
}

// ---------------------------------------------------------------------------
// Rejection tests — realm-A admin must be denied on every realm RPC
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_realms_rejects_non_system_realm_admin() {
    let rig = setup().await;
    let result = rig
        .svc
        .list_realms(req_with(
            pb::ListRealmsRequest {
                cursor: None,
                limit: None,
            },
            &rig.realm_a_token,
            &rig.realm_a_id,
        ))
        .await;
    let err = result.expect_err("must be rejected");
    assert_eq!(
        err.code(),
        tonic::Code::PermissionDenied,
        "list_realms: {err}"
    );
}

#[tokio::test]
async fn get_realm_rejects_non_system_realm_admin() {
    let rig = setup().await;
    let result = rig
        .svc
        .get_realm(req_with(
            pb::GetRealmRequest {
                id: rig.victim_realm_id.as_uuid().to_string(),
            },
            &rig.realm_a_token,
            &rig.realm_a_id,
        ))
        .await;
    let err = result.expect_err("must be rejected");
    assert_eq!(
        err.code(),
        tonic::Code::PermissionDenied,
        "get_realm: {err}"
    );
}

#[tokio::test]
async fn create_realm_rejects_non_system_realm_admin() {
    let rig = setup().await;
    let result = rig
        .svc
        .create_realm(req_with(
            pb::CreateRealmRequest {
                name: "attacker-created".into(),
                config: None,
            },
            &rig.realm_a_token,
            &rig.realm_a_id,
        ))
        .await;
    let err = result.expect_err("must be rejected");
    assert_eq!(
        err.code(),
        tonic::Code::PermissionDenied,
        "create_realm: {err}"
    );
}

#[tokio::test]
async fn update_realm_rejects_non_system_realm_admin() {
    let rig = setup().await;
    let result = rig
        .svc
        .update_realm(req_with(
            pb::UpdateRealmCall {
                id: rig.victim_realm_id.as_uuid().to_string(),
                body: Some(pb::UpdateRealmRequest {
                    name: Some("hijacked".into()),
                    status: None,
                    config: None,
                }),
            },
            &rig.realm_a_token,
            &rig.realm_a_id,
        ))
        .await;
    let err = result.expect_err("must be rejected");
    assert_eq!(
        err.code(),
        tonic::Code::PermissionDenied,
        "update_realm: {err}"
    );
}

#[tokio::test]
async fn delete_realm_rejects_non_system_realm_admin() {
    let rig = setup().await;
    let result = rig
        .svc
        .delete_realm(req_with(
            pb::DeleteRealmRequest {
                id: rig.victim_realm_id.as_uuid().to_string(),
            },
            &rig.realm_a_token,
            &rig.realm_a_id,
        ))
        .await;
    let err = result.expect_err("must be rejected");
    assert_eq!(
        err.code(),
        tonic::Code::PermissionDenied,
        "delete_realm: {err}"
    );
}

// ---------------------------------------------------------------------------
// Acceptance test — system-realm admin must succeed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn system_realm_admin_can_list_realms() {
    let rig = setup().await;
    let result = rig
        .svc
        .list_realms(req_with(
            pb::ListRealmsRequest {
                cursor: None,
                limit: Some(10),
            },
            &rig.sys_token,
            &rig.sys_realm_id,
        ))
        .await;
    assert!(
        result.is_ok(),
        "system admin must be able to list realms: {result:?}"
    );
}

#[tokio::test]
async fn system_realm_admin_can_get_realm() {
    let rig = setup().await;
    let result = rig
        .svc
        .get_realm(req_with(
            pb::GetRealmRequest {
                id: rig.victim_realm_id.as_uuid().to_string(),
            },
            &rig.sys_token,
            &rig.sys_realm_id,
        ))
        .await;
    assert!(
        result.is_ok(),
        "system admin must be able to get realm: {result:?}"
    );
}
