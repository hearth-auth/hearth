//! Integration tests for the gRPC `AuditService` transport (HEA-1834, gap 5).
//!
//! `ListEvents` / `VerifyIntegrity` were previously exercised only at the
//! `AuditEngine` level (`src/audit/engine.rs`). These tests drive them through
//! the generated `AuditService` trait impl (`src/protocol/grpc/audit.rs`) with a
//! `tonic::Request` carrying real bearer metadata — proving the transport wiring
//! (auth gate, realm scoping via `x-realm-id`, proto conversion) end-to-end.
//!
//! ## Coverage matrix
//!
//! | Claim | Test |
//! |---|---|
//! | `ListEvents` returns appended events for the authenticated realm | `list_events_returns_realm_events` |
//! | `VerifyIntegrity` reports ok + event count over the transport | `verify_integrity_reports_ok_and_count` |
//! | `ListEvents` requires a bearer token | `list_events_without_token_unauthenticated` |
//! | `ListEvents` requires the admin permission | `list_events_without_admin_permission_denied` |

mod common;

use std::sync::Arc;

use hearth::audit::{AuditAction, CreateAuditEvent};
use hearth::core::RealmId;
use hearth::identity::{CreateUserRequest, SessionContext};
use hearth::protocol::admin_auth::AdminRateLimiter;
use hearth::protocol::grpc::audit::AuditSvc;
use hearth::protocol::grpc::server::GrpcState;
use hearth::protocol::proto::events::v1::{self as pb, audit_service_server::AuditService};
use hearth::rbac::{AssignRoleRequest, Scope as RbacScope, Subject};
use tonic::{Code, Request};

struct GrpcCtx {
    h: common::TestHarness,
    realm: RealmId,
    token: String,
    svc: AuditSvc,
}

async fn grpc_ctx_with_admin(with_admin: bool) -> GrpcCtx {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("auditor-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Auditor".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("user");
    if with_admin {
        let role = h
            .rbac()
            .get_role_by_name(&realm, "realm.admin")
            .expect("lookup")
            .expect("seed");
        h.rbac()
            .assign_role(
                &realm,
                &AssignRoleRequest {
                    subject: Subject::User(user.id().clone()),
                    role_id: role.id,
                    scope: RbacScope::Realm,
                    assigned_by: None,
                },
            )
            .expect("assign");
    }
    let session = h
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("sess");
    let token = h
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("issue")
        .access_token()
        .to_string();

    let state = GrpcState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
        Arc::new(AdminRateLimiter::new()),
    );
    let svc = AuditSvc::new(state);

    GrpcCtx {
        h,
        realm,
        token,
        svc,
    }
}

/// Appends `n` audit events to the context realm so `ListEvents` has data.
fn seed_events(ctx: &GrpcCtx, actions: &[AuditAction]) {
    for (i, action) in actions.iter().enumerate() {
        ctx.h
            .audit()
            .append(&CreateAuditEvent {
                realm_id: ctx.realm.clone(),
                actor: format!("actor-{i}"),
                action: action.clone(),
                resource_type: "test".into(),
                resource_id: format!("res-{i}"),
                metadata: None,
            })
            .expect("append audit event");
    }
}

/// Builds a request with valid admin bearer + realm metadata.
fn admin_req<T>(ctx: &GrpcCtx, msg: T) -> Request<T> {
    let mut r = Request::new(msg);
    r.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", ctx.token).parse().expect("auth meta"),
    );
    r.metadata_mut().insert(
        "x-realm-id",
        ctx.realm.as_uuid().to_string().parse().expect("realm meta"),
    );
    r
}

#[tokio::test]
async fn list_events_returns_realm_events() {
    let ctx = grpc_ctx_with_admin(true).await;
    seed_events(
        &ctx,
        &[AuditAction::UserCreated, AuditAction::SessionCreated],
    );

    let resp = ctx
        .svc
        .list_events(admin_req(&ctx, pb::AuditQuery::default()))
        .await
        .expect("list_events over gRPC transport");
    let page = resp.into_inner();

    assert!(
        page.events.len() >= 2,
        "ListEvents must return the appended events, got {}",
        page.events.len()
    );
    assert!(
        page.events.iter().any(|e| e.actor == "actor-0"),
        "returned page must contain the seeded actor-0 event"
    );
}

#[tokio::test]
async fn verify_integrity_reports_ok_and_count() {
    let ctx = grpc_ctx_with_admin(true).await;
    seed_events(
        &ctx,
        &[
            AuditAction::UserCreated,
            AuditAction::SessionCreated,
            AuditAction::TokenIssued,
        ],
    );

    let resp = ctx
        .svc
        .verify_integrity(admin_req(&ctx, pb::VerifyIntegrityRequest {}))
        .await
        .expect("verify_integrity over gRPC transport");
    let out = resp.into_inner();

    assert!(
        out.ok,
        "intact hash chain must verify ok over the transport"
    );
    assert!(
        out.broken_at_event_id.is_none(),
        "no broken event id on an intact chain"
    );
    assert!(
        out.event_count >= 3,
        "event_count must reflect the seeded events, got {}",
        out.event_count
    );
}

#[tokio::test]
async fn list_events_without_token_unauthenticated() {
    let ctx = grpc_ctx_with_admin(true).await;
    // No authorization / x-realm-id metadata.
    let err = ctx
        .svc
        .list_events(Request::new(pb::AuditQuery::default()))
        .await
        .expect_err("missing bearer must be rejected");
    assert_eq!(
        err.code(),
        Code::Unauthenticated,
        "unauthenticated ListEvents must map to gRPC Unauthenticated, got {err:?}"
    );
}

#[tokio::test]
async fn list_events_without_admin_permission_denied() {
    // Authenticated user WITHOUT the realm.admin role.
    let ctx = grpc_ctx_with_admin(false).await;
    let err = ctx
        .svc
        .list_events(admin_req(&ctx, pb::AuditQuery::default()))
        .await
        .expect_err("non-admin must be denied");
    assert_eq!(
        err.code(),
        Code::PermissionDenied,
        "non-admin ListEvents must map to gRPC PermissionDenied, got {err:?}"
    );
}
