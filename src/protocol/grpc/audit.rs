//! `AuditService` gRPC implementation.

use tonic::{Request, Response, Status};

use crate::audit::{AuditAction, AuditQuery};
use crate::core::{RealmId, Timestamp};
use crate::protocol::proto::events::v1 as pb;
use crate::protocol::proto::events::v1::audit_service_server::AuditService;

use super::auth::authenticate_admin;
use super::convert::{audit_error_to_status, identity_to_status};
use super::server::GrpcState;

/// Implements [`AuditService`] by delegating to the injected [`AuditEngine`].
pub struct AuditSvc {
    state: GrpcState,
}

impl AuditSvc {
    pub fn new(state: GrpcState) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl AuditService for AuditSvc {
    async fn list_events(
        &self,
        req: Request<pb::AuditQuery>,
    ) -> Result<Response<pb::AuditEventPage>, Status> {
        let auth = authenticate_admin(req.metadata(), &self.state)?;
        let q = req.into_inner();
        let query = proto_query_to_domain(&q, auth.realm_id);
        let events = self
            .state
            .audit
            .query(&query)
            .map_err(audit_error_to_status)?;
        Ok(Response::new(pb::AuditEventPage {
            events: events.iter().map(pb::AuditEvent::from).collect(),
        }))
    }

    async fn verify_integrity(
        &self,
        req: Request<pb::VerifyIntegrityRequest>,
    ) -> Result<Response<pb::VerifyIntegrityResponse>, Status> {
        let auth = authenticate_admin(req.metadata(), &self.state)?;
        let ok = self
            .state
            .audit
            .verify_integrity(&auth.realm_id, None, None)
            .map_err(audit_error_to_status)?;
        // Determine event count for ops visibility.
        let events = self
            .state
            .audit
            .query(&AuditQuery::for_realm(auth.realm_id))
            .map_err(audit_error_to_status)?;
        Ok(Response::new(pb::VerifyIntegrityResponse {
            ok,
            broken_at_event_id: None,
            event_count: events.len() as u64,
        }))
    }
}

fn proto_query_to_domain(q: &pb::AuditQuery, realm_id: RealmId) -> AuditQuery {
    // `x-realm-id` metadata is authoritative — the body's realm_id is ignored
    // for defence in depth (prevents a caller from querying another realm
    // while authenticated against their own).
    let _ = &q.realm_id;
    AuditQuery {
        realm_id,
        start_time: q.start_time.map(Timestamp::from_micros),
        end_time: q.end_time.map(Timestamp::from_micros),
        actor: q.actor.clone(),
        action: q.action.and_then(proto_action_to_domain),
        limit: q.limit.map(|v| v as usize),
    }
}

fn proto_action_to_domain(v: i32) -> Option<AuditAction> {
    let p = pb::AuditAction::try_from(v).ok()?;
    crate::protocol::convert::audit::proto_audit_action_to_domain(p)
}

#[allow(dead_code)]
fn _referenced(err: crate::identity::IdentityError) -> Status {
    // Keep `identity_to_status` imported for potential future use here.
    identity_to_status(err)
}
