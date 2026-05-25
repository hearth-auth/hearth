use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::cluster::ClusterError;
use crate::protocol::http::{extract_admin_auth, AppState};

// ── Response types ────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct BootstrapResp {
    pub node_id: u64,
    pub term: u64,
    pub leader_id: u64,
}

#[derive(Serialize)]
pub struct PeerResp {
    pub id: u64,
    pub addr: String,
    pub is_healthy: bool,
}

#[derive(Serialize)]
pub struct StatusResp {
    pub role: String,
    pub term: u64,
    pub last_applied_index: Option<u64>,
    pub peers: Vec<PeerResp>,
}

#[derive(Serialize)]
pub struct TransferResp {
    pub new_leader_id: u64,
    pub exact_target: bool,
}

// ── Handlers ─────────────────────────────────────────────────────────────────

/// POST /admin/cluster/bootstrap
pub async fn bootstrap(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(s) = extract_admin_auth(&headers, &state) {
        return s.into_response();
    }
    let Some(engine) = &state.cluster else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match engine.bootstrap().await {
        Ok(r) => Json(BootstrapResp {
            node_id: r.node_id,
            term: r.term,
            leader_id: r.leader_id,
        })
        .into_response(),
        Err(ClusterError::AlreadyBootstrapped) => {
            StatusCode::CONFLICT.into_response()
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// GET /admin/cluster/status
pub async fn status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(s) = extract_admin_auth(&headers, &state) {
        return s.into_response();
    }
    let Some(engine) = &state.cluster else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let s = engine.status();
    Json(StatusResp {
        role: s.role,
        term: s.term,
        last_applied_index: s.last_applied_index,
        peers: s
            .peers
            .into_iter()
            .map(|p| PeerResp { id: p.id, addr: p.addr, is_healthy: p.is_healthy })
            .collect(),
    })
    .into_response()
}

/// POST /admin/cluster/transfer-leadership
///
/// Body (optional): `{"target_node_id": <u64>}`
/// Empty body is accepted — leadership transfers to whichever node wins the
/// next election.
pub async fn transfer_leadership(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    if let Err(s) = extract_admin_auth(&headers, &state) {
        return s.into_response();
    }
    let Some(engine) = &state.cluster else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let preferred: Option<u64> = if body.is_empty() {
        None
    } else {
        #[derive(Deserialize)]
        struct Req {
            target_node_id: u64,
        }
        serde_json::from_slice::<Req>(&body).ok().map(|r| r.target_node_id)
    };
    match engine.transfer_leadership(preferred).await {
        Ok(new_leader) => Json(TransferResp {
            new_leader_id: new_leader,
            exact_target: preferred == Some(new_leader),
        })
        .into_response(),
        Err(ClusterError::NotLeader { .. }) => StatusCode::CONFLICT.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
