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
//! | Granular admin lacking `hearth.realm.admin` is denied | `list_events_granular_admin_without_realm_admin_denied` |
//! | Body `realm_id` is ignored in favour of `x-realm-id` | `list_events_ignores_body_realm_id` |

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
    grpc_ctx_with_role(with_admin.then_some("realm.admin")).await
}

/// Builds a gRPC test context whose caller is assigned `role_name` (if any).
///
/// `Some("realm.admin")` grants the full admin bundle (incl. `hearth.realm.admin`).
/// `Some("hearth.users.admin")` grants only the granular user-admin permission —
/// it clears the coarse `authenticate_admin` gate but NOT the per-RPC
/// `grpc_require_permission("hearth.realm.admin")` refinement.
/// `None` leaves the caller with no roles at all.
async fn grpc_ctx_with_role(role_name: Option<&str>) -> GrpcCtx {
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
    if let Some(role_name) = role_name {
        let role = h
            .rbac()
            .get_role_by_name(&realm, role_name)
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
    // NOTE: `broken_at_event_id` is not asserted here — the product hardcodes it
    // to `None` (`src/protocol/grpc/audit.rs`), so any assertion on it would be
    // vacuous (TESTING.md anti-pattern). Re-add a meaningful check once the RPC
    // populates the field on a genuinely broken chain (HEA-1842 finding 1).
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

/// A caller holding only `hearth.users.admin` clears the coarse
/// `authenticate_admin` gate (which accepts any granular sub-admin permission)
/// but must still be denied `ListEvents`, which requires the per-RPC
/// `grpc_require_permission("hearth.realm.admin")` refinement. This binds the
/// second-stage authorization check, which the no-roles negative test above
/// cannot reach (that one is stopped at the coarse gate). (HEA-1842 finding 2.)
#[tokio::test]
async fn list_events_granular_admin_without_realm_admin_denied() {
    let ctx = grpc_ctx_with_role(Some("hearth.users.admin")).await;
    let err = ctx
        .svc
        .list_events(admin_req(&ctx, pb::AuditQuery::default()))
        .await
        .expect_err("granular users.admin without realm.admin must be denied");
    assert_eq!(
        err.code(),
        Code::PermissionDenied,
        "users.admin-only caller must be denied ListEvents, got {err:?}"
    );
}

/// Defence in depth: the realm the events are read from is bound to the
/// `x-realm-id` metadata, NOT to the `realm_id` field of the request body.
/// A caller authenticated against realm A who stuffs a foreign realm id into
/// the `AuditQuery` body must still see only realm A's events. Binds the
/// `proto_query_to_domain` guard that discards `q.realm_id`. (HEA-1842 finding 3.)
#[tokio::test]
async fn list_events_ignores_body_realm_id() {
    let ctx = grpc_ctx_with_admin(true).await;
    seed_events(
        &ctx,
        &[AuditAction::UserCreated, AuditAction::SessionCreated],
    );

    // Foreign realm id in the body — must be ignored.
    let foreign = uuid::Uuid::new_v4().to_string();
    assert_ne!(
        foreign,
        ctx.realm.as_uuid().to_string(),
        "test fixture: foreign id must differ from the auth realm"
    );
    let query = pb::AuditQuery {
        realm_id: foreign,
        ..Default::default()
    };

    let page = ctx
        .svc
        .list_events(admin_req(&ctx, query))
        .await
        .expect("list_events must succeed and ignore the body realm_id")
        .into_inner();

    // The body's foreign realm has no events; the auth realm has the seeded
    // ones. Non-empty proves the query resolved against `x-realm-id`, not body.
    assert!(
        page.events.iter().any(|e| e.actor == "actor-0"),
        "events must resolve against x-realm-id, not the body realm_id"
    );
}
