//! Regression tests for HEA-SEC-04: per-operation gRPC permission checks.
//! HEA-1722: privilege-ceiling enforcement on GrantUserPermission / AddAdditionalRole.
//!
//! ## Coverage matrix
//!
//! Each row is (caller permission, target service/method, expected outcome).
//!
//! | Caller                | Method                               | Expected          |
//! |---------------------- |--------------------------------------|-------------------|
//! | hearth.users.admin    | RbacAdmin::create_role               | PERMISSION_DENIED |
//! | hearth.clients.admin  | RbacAdmin::create_role               | PERMISSION_DENIED |
//! | hearth.agents.admin   | RbacAdmin::create_role               | PERMISSION_DENIED |
//! | hearth.realm.admin    | Identity::list_users                 | PERMISSION_DENIED |
//! | hearth.realm.admin    | Identity::create_user                | PERMISSION_DENIED |
//! | hearth.realm.admin    | AppAdmin::list_applications          | PERMISSION_DENIED |
//! | hearth.users.admin    | AppAdmin::list_applications          | PERMISSION_DENIED |
//! | hearth.agents.admin   | AppAdmin::list_applications          | PERMISSION_DENIED |
//! | hearth.clients.admin  | Identity::list_users                 | PERMISSION_DENIED |
//! | hearth.realm.admin    | Identity::list_agents                | PERMISSION_DENIED |
//! | hearth.realm.admin    | grant_user_permission(hearth.admin)  | PERMISSION_DENIED |
//! | hearth.realm.admin    | add_additional_role(realm.admin)     | PERMISSION_DENIED |
//! | hearth.users.admin    | RbacAdmin::revoke_consent            | OK                |
//! | hearth.realm.admin    | RbacAdmin::create_role               | OK                |
//! | hearth.agents.admin   | Identity::list_agents                | OK                |
//! | hearth.clients.admin  | AppAdmin::list_applications          | OK                |
//! | hearth.realm.admin    | grant_user_permission(hearth.realm.admin) | OK           |
//! | hearth.admin (full)   | RbacAdmin::create_role               | OK                |
//! | hearth.admin (full)   | Identity::list_users                 | OK                |
//! | hearth.admin (full)   | AppAdmin::list_applications          | OK                |
//! | hearth.admin (full)   | grant_user_permission(hearth.admin)  | OK                |
//! | hearth.admin (full)   | add_additional_role(realm.admin)     | OK                |

mod common;

use std::sync::Arc;

use hearth::core::RealmId;
use hearth::identity::{CreateOrganizationRequest, CreateUserRequest, SessionContext};
use hearth::protocol::admin_auth::AdminRateLimiter;
use hearth::protocol::grpc::identity::{AppAdminSvc, IdentityAdminSvc};
use hearth::protocol::grpc::rbac_admin::RbacAdminSvc;
use hearth::protocol::grpc::server::GrpcState;
use hearth::protocol::proto::identity::v1::{
    self as id_pb, application_admin_service_server::ApplicationAdminService,
    identity_admin_service_server::IdentityAdminService,
};
use hearth::protocol::proto::rbac::v1::{self as pb, rbac_admin_service_server::RbacAdminService};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use tonic::{Code, Request};

// ─── Service bundle ──────────────────────────────────────────────────────────

struct Services {
    h: common::TestHarness,
    realm: RealmId,
    rbac_svc: RbacAdminSvc,
    id_svc: IdentityAdminSvc,
    app_svc: AppAdminSvc,
}

fn make_services(h: common::TestHarness, realm: RealmId) -> Services {
    let state = GrpcState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
        Arc::new(AdminRateLimiter::new()),
    );
    Services {
        rbac_svc: RbacAdminSvc::new(state.clone()),
        id_svc: IdentityAdminSvc::new(state.clone()),
        app_svc: AppAdminSvc::new(state),
        h,
        realm,
    }
}

// ─── Token helpers ────────────────────────────────────────────────────────────

/// Issues a token carrying only the named seed sub-admin role permission
/// (e.g. `"hearth.users.admin"`). The realm must already be seeded.
fn issue_sub_admin_token(svc: &Services, email: &str, role_name: &str) -> String {
    let user = svc
        .h
        .identity()
        .create_user(
            &svc.realm,
            &CreateUserRequest {
                email: email.into(),
                display_name: "SubAdmin".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let role = svc
        .h
        .rbac()
        .get_role_by_name(&svc.realm, role_name)
        .expect("lookup")
        .unwrap_or_else(|| panic!("seed role '{role_name}' not found"));
    svc.h
        .rbac()
        .assign_role(
            &svc.realm,
            &AssignRoleRequest {
                subject: Subject::User(user.id().clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign role");

    let session = svc
        .h
        .identity()
        .create_session(&svc.realm, user.id(), &SessionContext::default())
        .expect("session");
    svc.h
        .identity()
        .issue_tokens(&svc.realm, user.id(), session.id())
        .expect("issue")
        .access_token()
        .to_string()
}

/// Attaches bearer + realm metadata to a `Request`.
fn with_token<T>(token: &str, realm: &RealmId, body: T) -> Request<T> {
    let mut r = Request::new(body);
    r.metadata_mut().insert(
        "authorization",
        format!("Bearer {token}").parse().expect("meta"),
    );
    r.metadata_mut().insert(
        "x-realm-id",
        realm.as_uuid().to_string().parse().expect("realm meta"),
    );
    r
}

// ─── Test setup ───────────────────────────────────────────────────────────────

async fn setup() -> Services {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed rbac");
    make_services(h, realm)
}

// ─── NEGATIVE: wrong sub-permission → PERMISSION_DENIED ──────────────────────

#[tokio::test]
async fn users_admin_denied_on_create_role() {
    let svc = setup().await;
    let token = issue_sub_admin_token(&svc, "usersadmin-role@bfla.test", "hearth.users.admin");
    let err = svc
        .rbac_svc
        .create_role(with_token(
            &token,
            &svc.realm,
            pb::CreateRoleRequest {
                realm_id: svc.realm.as_uuid().to_string(),
                name: "should-fail".into(),
                ..Default::default()
            },
        ))
        .await
        .expect_err("should be denied");
    assert_eq!(
        err.code(),
        Code::PermissionDenied,
        "hearth.users.admin must not create roles"
    );
}

#[tokio::test]
async fn clients_admin_denied_on_create_role() {
    let svc = setup().await;
    let token = issue_sub_admin_token(&svc, "clientsadmin-role@bfla.test", "hearth.clients.admin");
    let err = svc
        .rbac_svc
        .create_role(with_token(
            &token,
            &svc.realm,
            pb::CreateRoleRequest {
                realm_id: svc.realm.as_uuid().to_string(),
                name: "should-fail".into(),
                ..Default::default()
            },
        ))
        .await
        .expect_err("should be denied");
    assert_eq!(
        err.code(),
        Code::PermissionDenied,
        "hearth.clients.admin must not create roles"
    );
}

#[tokio::test]
async fn agents_admin_denied_on_create_role() {
    let svc = setup().await;
    let token = issue_sub_admin_token(&svc, "agentsadmin-role@bfla.test", "hearth.agents.admin");
    let err = svc
        .rbac_svc
        .create_role(with_token(
            &token,
            &svc.realm,
            pb::CreateRoleRequest {
                realm_id: svc.realm.as_uuid().to_string(),
                name: "should-fail".into(),
                ..Default::default()
            },
        ))
        .await
        .expect_err("should be denied");
    assert_eq!(
        err.code(),
        Code::PermissionDenied,
        "hearth.agents.admin must not create roles"
    );
}

#[tokio::test]
async fn realm_admin_denied_on_list_users() {
    let svc = setup().await;
    let token = issue_sub_admin_token(&svc, "realmadmin-users@bfla.test", "hearth.realm.admin");
    let err = svc
        .id_svc
        .list_users(with_token(
            &token,
            &svc.realm,
            id_pb::ListUsersRequest::default(),
        ))
        .await
        .expect_err("should be denied");
    assert_eq!(
        err.code(),
        Code::PermissionDenied,
        "hearth.realm.admin must not list users"
    );
}

#[tokio::test]
async fn realm_admin_denied_on_create_user() {
    let svc = setup().await;
    let token = issue_sub_admin_token(&svc, "realmadmin-cuser@bfla.test", "hearth.realm.admin");
    let err = svc
        .id_svc
        .create_user(with_token(
            &token,
            &svc.realm,
            id_pb::CreateUserRequest {
                email: "new@bfla.test".into(),
                display_name: "x".into(),
                ..Default::default()
            },
        ))
        .await
        .expect_err("should be denied");
    assert_eq!(
        err.code(),
        Code::PermissionDenied,
        "hearth.realm.admin must not create users"
    );
}

#[tokio::test]
async fn realm_admin_denied_on_list_applications() {
    let svc = setup().await;
    let token = issue_sub_admin_token(&svc, "realmadmin-apps@bfla.test", "hearth.realm.admin");
    let err = svc
        .app_svc
        .list_applications(with_token(
            &token,
            &svc.realm,
            id_pb::ListApplicationsRequest::default(),
        ))
        .await
        .expect_err("should be denied");
    assert_eq!(
        err.code(),
        Code::PermissionDenied,
        "hearth.realm.admin must not list applications"
    );
}

#[tokio::test]
async fn users_admin_denied_on_list_applications() {
    let svc = setup().await;
    let token = issue_sub_admin_token(&svc, "usersadmin-apps@bfla.test", "hearth.users.admin");
    let err = svc
        .app_svc
        .list_applications(with_token(
            &token,
            &svc.realm,
            id_pb::ListApplicationsRequest::default(),
        ))
        .await
        .expect_err("should be denied");
    assert_eq!(
        err.code(),
        Code::PermissionDenied,
        "hearth.users.admin must not list applications"
    );
}

#[tokio::test]
async fn agents_admin_denied_on_list_applications() {
    let svc = setup().await;
    let token = issue_sub_admin_token(&svc, "agentsadmin-apps@bfla.test", "hearth.agents.admin");
    let err = svc
        .app_svc
        .list_applications(with_token(
            &token,
            &svc.realm,
            id_pb::ListApplicationsRequest::default(),
        ))
        .await
        .expect_err("should be denied");
    assert_eq!(
        err.code(),
        Code::PermissionDenied,
        "hearth.agents.admin must not list applications"
    );
}

#[tokio::test]
async fn clients_admin_denied_on_list_users() {
    let svc = setup().await;
    let token = issue_sub_admin_token(&svc, "clientsadmin-users@bfla.test", "hearth.clients.admin");
    let err = svc
        .id_svc
        .list_users(with_token(
            &token,
            &svc.realm,
            id_pb::ListUsersRequest::default(),
        ))
        .await
        .expect_err("should be denied");
    assert_eq!(
        err.code(),
        Code::PermissionDenied,
        "hearth.clients.admin must not list users"
    );
}

#[tokio::test]
async fn realm_admin_denied_on_list_agents() {
    let svc = setup().await;
    let token = issue_sub_admin_token(&svc, "realmadmin-agents@bfla.test", "hearth.realm.admin");
    let err = svc
        .id_svc
        .list_agents(with_token(
            &token,
            &svc.realm,
            id_pb::ListAgentsRequest::default(),
        ))
        .await
        .expect_err("should be denied");
    assert_eq!(
        err.code(),
        Code::PermissionDenied,
        "hearth.realm.admin must not list agents"
    );
}

// ─── POSITIVE: correct sub-permission → OK ───────────────────────────────────

#[tokio::test]
async fn users_admin_allowed_on_revoke_consent() {
    let svc = setup().await;
    let token = issue_sub_admin_token(&svc, "usersadmin-consent@bfla.test", "hearth.users.admin");

    // Create a target user to revoke consent for (even though no consent exists,
    // PERMISSION_DENIED would fire before any not-found error).
    let target_user = svc
        .h
        .identity()
        .create_user(
            &svc.realm,
            &CreateUserRequest {
                email: "consent-target@bfla.test".into(),
                display_name: "Target".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("target user");

    let result = svc
        .rbac_svc
        .revoke_consent(with_token(
            &token,
            &svc.realm,
            pb::RevokeConsentRequest {
                realm_id: svc.realm.as_uuid().to_string(),
                user_id: target_user.id().as_uuid().to_string(),
                client_id: uuid::Uuid::new_v4().to_string(),
            },
        ))
        .await;
    // May be NotFound (no consent) but must NOT be PermissionDenied.
    if let Err(e) = &result {
        assert_ne!(
            e.code(),
            Code::PermissionDenied,
            "hearth.users.admin must be allowed to revoke_consent; got: {e:?}"
        );
    }
}

#[tokio::test]
async fn realm_admin_allowed_on_create_role() {
    let svc = setup().await;
    let token = issue_sub_admin_token(
        &svc,
        "realmadmin-createrole@bfla.test",
        "hearth.realm.admin",
    );
    svc.rbac_svc
        .create_role(with_token(
            &token,
            &svc.realm,
            pb::CreateRoleRequest {
                realm_id: svc.realm.as_uuid().to_string(),
                name: "grpc-bfla-test-role".into(),
                ..Default::default()
            },
        ))
        .await
        .expect("hearth.realm.admin must be allowed to create roles");
}

#[tokio::test]
async fn agents_admin_allowed_on_list_agents() {
    let svc = setup().await;
    let token = issue_sub_admin_token(
        &svc,
        "agentsadmin-listagents@bfla.test",
        "hearth.agents.admin",
    );
    svc.id_svc
        .list_agents(with_token(
            &token,
            &svc.realm,
            id_pb::ListAgentsRequest::default(),
        ))
        .await
        .expect("hearth.agents.admin must be allowed to list agents");
}

#[tokio::test]
async fn clients_admin_allowed_on_list_applications() {
    let svc = setup().await;
    let token = issue_sub_admin_token(
        &svc,
        "clientsadmin-listapps@bfla.test",
        "hearth.clients.admin",
    );
    svc.app_svc
        .list_applications(with_token(
            &token,
            &svc.realm,
            id_pb::ListApplicationsRequest::default(),
        ))
        .await
        .expect("hearth.clients.admin must be allowed to list applications");
}

// ─── hearth.admin (full superuser) bypasses all sub-permission checks ─────────

#[tokio::test]
async fn full_admin_allowed_on_create_role() {
    let svc = setup().await;
    // realm.admin role carries hearth.admin (the full superuser permission).
    let token = issue_sub_admin_token(&svc, "fulladmin-role@bfla.test", "realm.admin");
    svc.rbac_svc
        .create_role(with_token(
            &token,
            &svc.realm,
            pb::CreateRoleRequest {
                realm_id: svc.realm.as_uuid().to_string(),
                name: "full-admin-role".into(),
                ..Default::default()
            },
        ))
        .await
        .expect("hearth.admin must bypass all sub-permission checks for create_role");
}

#[tokio::test]
async fn full_admin_allowed_on_list_users() {
    let svc = setup().await;
    let token = issue_sub_admin_token(&svc, "fulladmin-users@bfla.test", "realm.admin");
    svc.id_svc
        .list_users(with_token(
            &token,
            &svc.realm,
            id_pb::ListUsersRequest::default(),
        ))
        .await
        .expect("hearth.admin must bypass all sub-permission checks for list_users");
}

#[tokio::test]
async fn full_admin_allowed_on_list_applications() {
    let svc = setup().await;
    let token = issue_sub_admin_token(&svc, "fulladmin-apps@bfla.test", "realm.admin");
    svc.app_svc
        .list_applications(with_token(
            &token,
            &svc.realm,
            id_pb::ListApplicationsRequest::default(),
        ))
        .await
        .expect("hearth.admin must bypass all sub-permission checks for list_applications");
}

// ─── HEA-1722: Privilege-ceiling enforcement on GrantUserPermission ───────────

/// A hearth.realm.admin token MUST NOT be able to grant hearth.admin to anyone —
/// that would be a vertical privilege-escalation (sub-admin self-escalates to superuser).
#[tokio::test]
async fn realm_admin_cannot_grant_permission_it_does_not_hold() {
    let svc = setup().await;
    let token = issue_sub_admin_token(&svc, "realm-admin-grant@hea1722.test", "hearth.realm.admin");
    let target = svc
        .h
        .identity()
        .create_user(
            &svc.realm,
            &CreateUserRequest {
                email: "target-escalate@hea1722.test".into(),
                display_name: "Target".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create target user");

    let err = svc
        .rbac_svc
        .grant_user_permission(with_token(
            &token,
            &svc.realm,
            pb::GrantUserPermissionRequest {
                realm_id: svc.realm.as_uuid().to_string(),
                user_id: format!("user_{}", target.id().as_uuid()),
                permission: "hearth.admin".to_string(),
                scope_type: "realm".to_string(),
                ..Default::default()
            },
        ))
        .await
        .expect_err("hearth.realm.admin must not grant hearth.admin (HEA-1722)");

    assert_eq!(
        err.code(),
        Code::PermissionDenied,
        "hearth.realm.admin granting hearth.admin must return PERMISSION_DENIED (HEA-1722)"
    );
}

/// A hearth.realm.admin token CAN grant a permission it already holds.
#[tokio::test]
async fn realm_admin_can_grant_permission_it_holds() {
    let svc = setup().await;
    let token =
        issue_sub_admin_token(&svc, "realm-admin-own-grant@hea1722.test", "hearth.realm.admin");
    let target = svc
        .h
        .identity()
        .create_user(
            &svc.realm,
            &CreateUserRequest {
                email: "target-own-perm@hea1722.test".into(),
                display_name: "Target".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create target user");

    svc.rbac_svc
        .grant_user_permission(with_token(
            &token,
            &svc.realm,
            pb::GrantUserPermissionRequest {
                realm_id: svc.realm.as_uuid().to_string(),
                user_id: format!("user_{}", target.id().as_uuid()),
                // hearth.realm.admin holds this permission — ceiling allows it
                permission: "hearth.realm.admin".to_string(),
                scope_type: "realm".to_string(),
                ..Default::default()
            },
        ))
        .await
        .expect("hearth.realm.admin must be able to grant hearth.realm.admin (HEA-1722)");
}

/// A hearth.admin (full superuser) token can grant ANY permission including itself.
#[tokio::test]
async fn full_admin_can_grant_any_permission() {
    let svc = setup().await;
    let token = issue_sub_admin_token(&svc, "full-admin-grant@hea1722.test", "realm.admin");
    let target = svc
        .h
        .identity()
        .create_user(
            &svc.realm,
            &CreateUserRequest {
                email: "target-full-grant@hea1722.test".into(),
                display_name: "Target".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create target user");

    svc.rbac_svc
        .grant_user_permission(with_token(
            &token,
            &svc.realm,
            pb::GrantUserPermissionRequest {
                realm_id: svc.realm.as_uuid().to_string(),
                user_id: format!("user_{}", target.id().as_uuid()),
                permission: "hearth.admin".to_string(),
                scope_type: "realm".to_string(),
                ..Default::default()
            },
        ))
        .await
        .expect("hearth.admin must be able to grant any permission (HEA-1722)");
}

// ─── HEA-1722: Privilege-ceiling enforcement on AddAdditionalRole ─────────────

/// A hearth.realm.admin token MUST NOT be able to add the realm.admin role
/// to an org member — that role carries hearth.admin, which would be an escalation.
#[tokio::test]
async fn realm_admin_cannot_add_role_exceeding_ceiling() {
    let svc = setup().await;
    let token =
        issue_sub_admin_token(&svc, "realm-admin-addrole@hea1722.test", "hearth.realm.admin");

    let org = svc
        .h
        .identity()
        .create_organization(
            &svc.realm,
            &CreateOrganizationRequest {
                name: "Test Org 1722-a".to_string(),
                slug: "test-org-1722-a".to_string(),
                ..Default::default()
            },
        )
        .expect("create org");

    let target = svc
        .h
        .identity()
        .create_user(
            &svc.realm,
            &CreateUserRequest {
                email: "target-addrole@hea1722.test".into(),
                display_name: "Target".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create target user");

    let err = svc
        .rbac_svc
        .add_additional_role(with_token(
            &token,
            &svc.realm,
            pb::AddAdditionalRoleRequest {
                realm_id: svc.realm.as_uuid().to_string(),
                org_id: org.id().as_uuid().to_string(),
                user_id: format!("user_{}", target.id().as_uuid()),
                // realm.admin carries hearth.admin — sub-admin must not add it
                role_name: "realm.admin".to_string(),
                ..Default::default()
            },
        ))
        .await
        .expect_err("hearth.realm.admin must not add realm.admin role (HEA-1722)");

    assert_eq!(
        err.code(),
        Code::PermissionDenied,
        "adding role that exceeds assigner's permissions must return PERMISSION_DENIED (HEA-1722)"
    );
}

/// A hearth.admin (full superuser) token can add ANY role via add_additional_role.
#[tokio::test]
async fn full_admin_can_add_any_role() {
    let svc = setup().await;
    let token = issue_sub_admin_token(&svc, "full-admin-addrole@hea1722.test", "realm.admin");

    let org = svc
        .h
        .identity()
        .create_organization(
            &svc.realm,
            &CreateOrganizationRequest {
                name: "Test Org 1722-b".to_string(),
                slug: "test-org-1722-b".to_string(),
                ..Default::default()
            },
        )
        .expect("create org");

    let target = svc
        .h
        .identity()
        .create_user(
            &svc.realm,
            &CreateUserRequest {
                email: "target-full-addrole@hea1722.test".into(),
                display_name: "Target".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create target user");

    svc.rbac_svc
        .add_additional_role(with_token(
            &token,
            &svc.realm,
            pb::AddAdditionalRoleRequest {
                realm_id: svc.realm.as_uuid().to_string(),
                org_id: org.id().as_uuid().to_string(),
                user_id: format!("user_{}", target.id().as_uuid()),
                role_name: "realm.admin".to_string(),
                ..Default::default()
            },
        ))
        .await
        .expect("hearth.admin must be able to add any role (HEA-1722)");
}
