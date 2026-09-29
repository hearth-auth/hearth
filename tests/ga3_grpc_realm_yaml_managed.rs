//! GA audit round 3 — G-7: gRPC `CreateRealm` / `UpdateRealm` are refused.
//!
//! Realms are declared in `hearth.yaml`; REST `POST /admin/realms` and
//! `PATCH /admin/realms/{id}` answer 405 for that reason. The gRPC twins were
//! still live, and `UpdateRealm` replaced the realm's WHOLE config with the
//! three fields the proto carries plus defaults — a "change the session TTL"
//! call silently dropped `mfa_required`, the CIDR policy, the lockout policy,
//! the SCIM bearer token, webhooks and the FAPI profile until the next YAML
//! reload. Both RPCs now answer `FAILED_PRECONDITION` with the REST message,
//! after admin authentication, and touch nothing.

mod common;

use std::sync::Arc;

use hearth::core::RealmId;
use hearth::identity::{
    CreateRealmRequest, CreateUserRequest, RealmConfig, RealmStatus, SessionContext,
};
use hearth::protocol::admin_auth::AdminRateLimiter;
use hearth::protocol::grpc::identity::IdentityAdminSvc;
use hearth::protocol::grpc::server::GrpcState;
use hearth::protocol::proto::identity::v1::{
    self as pb, identity_admin_service_server::IdentityAdminService,
};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use tonic::{Code, Request};

const REFUSAL: &str = "Realms are managed via hearth.yaml. Remove this endpoint from your client.";

fn make_svc(h: &common::TestHarness) -> IdentityAdminSvc {
    IdentityAdminSvc::new(GrpcState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
        Arc::new(AdminRateLimiter::new()),
    ))
}

fn assign_realm_admin(h: &common::TestHarness, realm: &RealmId, user: &hearth::identity::User) {
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
}

fn mint(h: &common::TestHarness, realm: &RealmId, user: &hearth::identity::User) -> String {
    let session = h
        .identity()
        .create_session(realm, user.id(), &SessionContext::default())
        .expect("session");
    h.identity()
        .issue_tokens(realm, user.id(), session.id())
        .expect("issue tokens")
        .access_token()
        .to_string()
}

/// A tenant realm whose config carries a SCIM bearer token, a lockout policy
/// and a custom session TTL, plus a realm-admin token for it. (Not
/// `mfa_required`: the fixture must still mint a password-only admin token.)
fn tenant_realm_with_config(h: &common::TestHarness) -> (RealmId, String) {
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("ga3-g7-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                session_ttl_micros: Some(1_800_000_000),
                scim_bearer_token_hash: Some("f".repeat(64)),
                max_failed_logins: Some(3),
                ..RealmConfig::default()
            }),
        })
        .expect("create realm");
    let realm_id = realm.id().clone();
    h.rbac().seed_realm(&realm_id).expect("seed realm");
    let user = h
        .identity()
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: format!("admin-{}@ga3.test", uuid::Uuid::new_v4()),
                display_name: "Admin".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create admin");
    assign_realm_admin(h, &realm_id, &user);
    let token = mint(h, &realm_id, &user);
    (realm_id, token)
}

fn system_admin_token(h: &common::TestHarness) -> String {
    let sys = RealmId::new(uuid::Uuid::nil());
    h.rbac().seed_realm(&sys).expect("seed system rbac");
    let user = h
        .identity()
        .create_admin_user(&CreateUserRequest {
            email: format!("sysadmin-{}@ga3.test", uuid::Uuid::new_v4()),
            display_name: "Sys".into(),
            first_name: String::new(),
            last_name: String::new(),
            attributes: Default::default(),
        })
        .expect("create system admin");
    assign_realm_admin(h, &sys, &user);
    mint(h, &sys, &user)
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

/// The audit trigger: a realm admin "changes the session TTL" over gRPC. This
/// must be refused and the stored config must keep every field it had.
#[tokio::test]
async fn update_realm_is_refused_and_leaves_config_intact() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let svc = make_svc(&h);
    let (realm_id, token) = tenant_realm_with_config(&h);

    let err = svc
        .update_realm(grpc_req(
            &realm_id,
            &token,
            pb::UpdateRealmCall {
                id: realm_id.as_uuid().to_string(),
                body: Some(pb::UpdateRealmRequest {
                    name: None,
                    status: None,
                    config: Some(pb::RealmConfig {
                        session_ttl_micros: Some(3_600_000_000),
                        password_memory_cost: None,
                        password_time_cost: None,
                    }),
                }),
            },
        ))
        .await
        .expect_err("gRPC UpdateRealm must be refused: realms are YAML-managed");

    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_eq!(err.message(), REFUSAL);
    let stored = h
        .identity()
        .get_realm(&realm_id)
        .expect("lookup")
        .expect("realm exists");
    let cfg = stored.config();
    assert_eq!(cfg.session_ttl_micros, Some(1_800_000_000), "TTL unchanged");
    assert_eq!(
        cfg.scim_bearer_token_hash.as_deref(),
        Some("f".repeat(64).as_str())
    );
    assert_eq!(
        cfg.max_failed_logins,
        Some(3),
        "lockout policy must survive"
    );
}

/// The status and rename variants are refused the same way: a realm cannot be
/// suspended or detached from its YAML entry over gRPC.
#[tokio::test]
async fn update_realm_status_and_name_are_refused() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let svc = make_svc(&h);
    let (realm_id, token) = tenant_realm_with_config(&h);
    let original_name = h
        .identity()
        .get_realm(&realm_id)
        .expect("lookup")
        .expect("realm exists")
        .name()
        .to_string();

    let err = svc
        .update_realm(grpc_req(
            &realm_id,
            &token,
            pb::UpdateRealmCall {
                id: realm_id.as_uuid().to_string(),
                body: Some(pb::UpdateRealmRequest {
                    name: Some("detached".into()),
                    status: Some(pb::RealmStatus::Suspended as i32),
                    config: None,
                }),
            },
        ))
        .await
        .expect_err("status/name update must be refused");

    assert_eq!(err.code(), Code::FailedPrecondition);
    let stored = h
        .identity()
        .get_realm(&realm_id)
        .expect("lookup")
        .expect("realm exists");
    assert_eq!(stored.status(), RealmStatus::Active);
    assert_eq!(stored.name(), original_name);
}

/// System-realm admins could create realms over gRPC while REST answers 405.
#[tokio::test]
async fn create_realm_is_refused_for_system_admin() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let svc = make_svc(&h);
    let token = system_admin_token(&h);
    let name = format!("ga3-created-{}", uuid::Uuid::new_v4());

    let err = svc
        .create_realm(grpc_req(
            &RealmId::new(uuid::Uuid::nil()),
            &token,
            pb::CreateRealmRequest {
                name: name.clone(),
                config: None,
            },
        ))
        .await
        .expect_err("gRPC CreateRealm must be refused: realms are YAML-managed");

    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_eq!(err.message(), REFUSAL);
    assert!(
        h.identity()
            .get_realm_by_name(&name)
            .expect("lookup")
            .is_none(),
        "no realm may be created by a refused call"
    );
}

/// The refusal sits behind admin authentication like every other RPC on the
/// service: an anonymous caller learns nothing but `UNAUTHENTICATED`.
#[tokio::test]
async fn refused_realm_rpcs_still_authenticate_first() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let svc = make_svc(&h);
    let (realm_id, _token) = tenant_realm_with_config(&h);

    let update = svc
        .update_realm(Request::new(pb::UpdateRealmCall {
            id: realm_id.as_uuid().to_string(),
            body: Some(pb::UpdateRealmRequest::default()),
        }))
        .await
        .expect_err("anonymous update must fail");
    let create = svc
        .create_realm(Request::new(pb::CreateRealmRequest {
            name: "anon".into(),
            config: None,
        }))
        .await
        .expect_err("anonymous create must fail");

    assert_eq!(update.code(), Code::Unauthenticated);
    assert_eq!(create.code(), Code::Unauthenticated);
}
