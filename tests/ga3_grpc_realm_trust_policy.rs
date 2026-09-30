//! GA audit round 3 — gRPC `GetRealm` / `DeleteRealm` honour the target
//! realm's cross-realm trust policy, as REST `/admin/realms/{id}` does.
//!
//! A realm opts into enforcement by storing a policy that names the system
//! realm as its source. REST routes every `/admin/realms/{id}` request through
//! `scoped_realm`, which refuses the crossing when such a policy withholds
//! `hearth.admin`. The gRPC twins checked only "same realm, or caller is the
//! system realm", so the same system-realm token read and deleted a realm REST
//! refused it. Both surfaces now call
//! `hearth::protocol::admin_auth::admin_realm_scope`.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hearth::core::RealmId;
use hearth::identity::{
    CreateCrossRealmPolicyRequest, CreateRealmRequest, CreateUserRequest, RealmStatus,
    SessionContext, UpdateRealmRequest,
};
use hearth::protocol::admin_auth::AdminRateLimiter;
use hearth::protocol::grpc::identity::IdentityAdminSvc;
use hearth::protocol::grpc::server::GrpcState;
use hearth::protocol::http::{router, AppState};
use hearth::protocol::proto::identity::v1::{
    self as pb, identity_admin_service_server::IdentityAdminService,
};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use tonic::Code;
use tower::ServiceExt as _;

fn system_realm() -> RealmId {
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

/// A system-realm `realm.admin` (holds `hearth.admin`) and its token.
fn system_admin_token(h: &common::TestHarness) -> String {
    system_admin(h).1
}

/// A system-realm `realm.admin`: `(user id, token)`.
fn system_admin(h: &common::TestHarness) -> (hearth::core::UserId, String) {
    let sys = system_realm();
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
    let role = h
        .rbac()
        .get_role_by_name(&sys, "realm.admin")
        .expect("role lookup")
        .expect("realm.admin seeded");
    h.rbac()
        .assign_role(
            &sys,
            &AssignRoleRequest {
                subject: Subject::User(user.id().clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign role");
    let session = h
        .identity()
        .create_session(&sys, user.id(), &SessionContext::default())
        .expect("session");
    let token = h
        .identity()
        .issue_tokens(&sys, user.id(), session.id())
        .expect("issue tokens")
        .access_token()
        .to_string();
    (user.id().clone(), token)
}

fn tenant_realm(h: &common::TestHarness) -> RealmId {
    h.identity()
        .create_realm(&CreateRealmRequest {
            name: format!("ga3-trust-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone()
}

/// Stores a policy in `target` naming the system realm as source but granting
/// only an unrelated capability — i.e. the realm refuses admin crossings.
fn deny_system_crossings(h: &common::TestHarness, target: &RealmId) {
    h.identity()
        .create_cross_realm_policy(
            target,
            &CreateCrossRealmPolicyRequest {
                source_realm_id: system_realm(),
                allowed_capabilities: vec!["search:read".to_string()],
                expires_in_secs: None,
            },
        )
        .expect("store policy");
}

fn grpc_req<T>(token: &str, msg: T) -> tonic::Request<T> {
    let mut r = tonic::Request::new(msg);
    r.metadata_mut().insert(
        "authorization",
        format!("Bearer {token}").parse().expect("valid header"),
    );
    r.metadata_mut().insert(
        "x-realm-id",
        system_realm()
            .as_uuid()
            .to_string()
            .parse()
            .expect("valid header"),
    );
    r
}

async fn rest_get_realm(h: &common::TestHarness, token: &str, target: &RealmId) -> StatusCode {
    let app = router(Arc::new(AppState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
    )));
    let req = Request::builder()
        .method("GET")
        .uri(format!("/admin/realms/{}", target.as_uuid()))
        .header("x-realm-id", system_realm().as_uuid().to_string())
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .expect("build request");
    app.oneshot(req).await.expect("oneshot").status()
}

/// The REST control and the gRPC twin side by side: both must refuse.
#[tokio::test]
async fn get_realm_refused_when_target_policy_denies_system_realm() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let svc = make_svc(&h);
    let token = system_admin_token(&h);
    let target = tenant_realm(&h);
    deny_system_crossings(&h, &target);

    let rest = rest_get_realm(&h, &token, &target).await;
    let grpc = svc
        .get_realm(grpc_req(
            &token,
            pb::GetRealmRequest {
                id: target.as_uuid().to_string(),
            },
        ))
        .await;

    assert_eq!(rest, StatusCode::FORBIDDEN, "REST control");
    assert_eq!(
        grpc.expect_err("gRPC GetRealm must honour the trust policy")
            .code(),
        Code::PermissionDenied
    );
}

/// The destructive variant: an archived realm whose policy refuses the system
/// realm may not be purged over gRPC either.
#[tokio::test]
async fn delete_realm_refused_when_target_policy_denies_system_realm() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let svc = make_svc(&h);
    let token = system_admin_token(&h);
    let target = tenant_realm(&h);
    // The policy first: a non-active realm refuses new policies.
    deny_system_crossings(&h, &target);
    h.identity()
        .update_realm(
            &target,
            &UpdateRealmRequest {
                status: Some(RealmStatus::Archived),
                ..UpdateRealmRequest::default()
            },
        )
        .expect("archive realm");

    let err = svc
        .delete_realm(grpc_req(
            &token,
            pb::DeleteRealmRequest {
                id: target.as_uuid().to_string(),
            },
        ))
        .await
        .expect_err("gRPC DeleteRealm must honour the trust policy");

    assert_eq!(err.code(), Code::PermissionDenied);
    assert!(
        h.identity().get_realm(&target).expect("lookup").is_some(),
        "the realm must not be deleted"
    );
}

/// Ungoverned pairs stay permissive-with-audit, and a policy that grants
/// `hearth.admin` allows the crossing — the gRPC side must not over-refuse.
#[tokio::test]
async fn get_realm_permitted_when_ungoverned_or_granted() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let svc = make_svc(&h);
    let token = system_admin_token(&h);
    let ungoverned = tenant_realm(&h);
    let granted = tenant_realm(&h);
    h.identity()
        .create_cross_realm_policy(
            &granted,
            &CreateCrossRealmPolicyRequest {
                source_realm_id: system_realm(),
                allowed_capabilities: vec!["hearth.admin".to_string()],
                expires_in_secs: None,
            },
        )
        .expect("store policy");

    for target in [&ungoverned, &granted] {
        let realm = svc
            .get_realm(grpc_req(
                &token,
                pb::GetRealmRequest {
                    id: target.as_uuid().to_string(),
                },
            ))
            .await
            .expect("crossing must be permitted")
            .into_inner();
        assert_eq!(realm.id, target.as_uuid().to_string());
    }
}

/// gRPC `DeleteRealm` writes the audit event REST `DELETE /admin/realms/{id}`
/// writes: `realm_deleted`, in the system realm (the deleted realm's own key
/// space must stay empty), attributed to the caller.
#[tokio::test]
async fn grpc_delete_realm_is_audited_like_rest() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let svc = make_svc(&h);
    let (operator_id, token) = system_admin(&h);
    let target = tenant_realm(&h);
    h.identity()
        .update_realm(
            &target,
            &UpdateRealmRequest {
                status: Some(RealmStatus::Archived),
                ..UpdateRealmRequest::default()
            },
        )
        .expect("archive realm");

    svc.delete_realm(grpc_req(
        &token,
        pb::DeleteRealmRequest {
            id: target.as_uuid().to_string(),
        },
    ))
    .await
    .expect("DeleteRealm on an archived realm");

    let events = h
        .audit()
        .query(&hearth::audit::AuditQuery {
            realm_id: system_realm(),
            start_time: None,
            end_time: None,
            actor: Some(operator_id.as_uuid().to_string()),
            action: Some(hearth::audit::AuditAction::RealmDeleted),
            limit: None,
            agent_id: None,
            tool: None,
        })
        .expect("audit query");
    let deleted: Vec<_> = events
        .iter()
        .filter(|e| e.action == hearth::audit::AuditAction::RealmDeleted)
        .collect();
    assert_eq!(deleted.len(), 1, "one realm_deleted event: {events:?}");
    assert_eq!(deleted[0].resource_id, target.as_uuid().to_string());
    assert_eq!(deleted[0].resource_type, "realm");
}
