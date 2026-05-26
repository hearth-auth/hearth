//! Cluster admin HTTP handlers.
//!
//! Implements three operator-facing endpoints that expose the Raft consensus
//! layer to cluster administrators:
//!
//! | Method | Route | Purpose |
//! |--------|-------|---------|
//! | `POST` | `/admin/cluster/bootstrap` | Initialize cluster membership |
//! | `GET`  | `/admin/cluster/status`    | Node role, term, peer health |
//! | `POST` | `/admin/cluster/transfer-leadership` | Graceful leader handoff |
//!
//! All endpoints require a valid admin token (`hearth.admin` permission) via
//! `Authorization: Bearer <token>` and `X-Realm-ID: <nil-uuid>` headers.
//! The realm ID **must** be the system (nil) realm; tenant-realm tokens are
//! rejected with 403 to prevent privilege escalation (HEA-763).

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use openraft::ServerState;
use serde::Deserialize;

use crate::cluster::ClusterError;
use crate::protocol::http::{extract_cluster_admin_auth, AppState};

// ── Bootstrap ─────────────────────────────────────────────────────────────────

/// `POST /admin/cluster/bootstrap`
///
/// Initializes Raft membership from the node's configured `cluster.peers`.
/// Must be called exactly once on one designated bootstrap node after all
/// cluster nodes are running. Subsequent calls are idempotent (openraft
/// rejects double-initialization with an error, surfaced as HTTP 409).
///
/// Returns 503 when the server is running in single-node mode.
pub(crate) async fn admin_cluster_bootstrap(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = extract_cluster_admin_auth(&headers, &state) {
        return e.into_response();
    }

    let Some(cluster) = state.cluster.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "not in cluster mode"})),
        )
            .into_response();
    };

    let members = cluster.initial_members().cloned().unwrap_or_default();

    if let Err(e) = cluster.initialize_cluster(members).await {
        let status = if e.to_string().contains("already initialized")
            || e.to_string().contains("NotAllowed")
        {
            StatusCode::CONFLICT
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        };
        return (status, Json(serde_json::json!({"error": e.to_string()}))).into_response();
    }

    // Wait up to 3 s for this node to confirm leadership after the election.
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(3);
    loop {
        if let Some(m) = cluster.raft_metrics() {
            if m.current_leader.is_some() {
                break;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    let node_id = cluster.node_id().unwrap_or(0);
    let (term, leader_id) = cluster.raft_metrics().map_or((0, node_id), |m| {
        (m.current_term, m.current_leader.unwrap_or(node_id))
    });

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "node_id": node_id,
            "term": term,
            "leader_id": leader_id,
        })),
    )
        .into_response()
}

// ── Status ────────────────────────────────────────────────────────────────────

/// `GET /admin/cluster/status`
///
/// Returns the current Raft state for this node: role, term,
/// last-applied log index, and per-peer health. Peer health is derived from
/// the leader's replication map; on a follower all peers show
/// `is_healthy: false` (the follower has no replication state).
///
/// Returns 503 when the server is running in single-node mode.
pub(crate) async fn admin_cluster_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = extract_cluster_admin_auth(&headers, &state) {
        return e.into_response();
    }

    let Some(cluster) = state.cluster.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "not in cluster mode"})),
        )
            .into_response();
    };

    let Some(metrics) = cluster.raft_metrics() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "raft not initialized"})),
        )
            .into_response();
    };

    let role = match metrics.state {
        ServerState::Leader => "leader",
        ServerState::Follower => "follower",
        ServerState::Candidate => "candidate",
        ServerState::Learner => "learner",
        _ => "unknown",
    };

    let last_applied_index = metrics.last_applied.as_ref().map(|l| l.index);

    let self_id = metrics.id;
    let peers: Vec<serde_json::Value> = metrics
        .membership_config
        .nodes()
        .filter(|(id, _)| **id != self_id)
        .map(|(id, node)| {
            // Replication map is only present on the leader.
            let is_healthy = metrics
                .replication
                .as_ref()
                .map_or(false, |r| r.contains_key(id));
            serde_json::json!({
                "id": id,
                "addr": node.addr,
                "is_healthy": is_healthy,
            })
        })
        .collect();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "role": role,
            "term": metrics.current_term,
            "last_applied_index": last_applied_index,
            "peers": peers,
        })),
    )
        .into_response()
}

// ── Transfer leadership ───────────────────────────────────────────────────────

/// Request body for `POST /admin/cluster/transfer-leadership`.
#[derive(Debug, Deserialize)]
pub(crate) struct TransferLeadershipRequest {
    /// Preferred target node ID for the new leader.
    ///
    /// Accepted for forward-compatibility; openraft 0.9 has no targeted
    /// transfer API so the election winner is not guaranteed to match this
    /// value. Inspect `exact_target` in the response to verify.
    pub target_node_id: Option<u64>,
}

/// `POST /admin/cluster/transfer-leadership`
///
/// Gracefully transfers Raft leadership from this node to another. This node
/// must be the current leader; returns 409 otherwise.
///
/// The `target_node_id` field is accepted for forward-compatibility but not
/// enforced in Phase A (openraft 0.9 has no targeted transfer API). The
/// `exact_target` field in the response indicates whether the winner matches
/// the requested target.
///
/// **Availability note:** writes will fail with `NoLeader` for up to one
/// election timeout (~1.5–3 s) during the step-down window.
///
/// Returns 503 when the server is running in single-node mode.
pub(crate) async fn admin_cluster_transfer_leadership(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    // Use Bytes (no content-type check) so auth/cluster checks fire before
    // body parsing — otherwise Json<T> returns 415 before the handler runs.
    raw: axum::body::Bytes,
) -> Response {
    if let Err(e) = extract_cluster_admin_auth(&headers, &state) {
        return e.into_response();
    }

    let body: TransferLeadershipRequest = if raw.is_empty() {
        TransferLeadershipRequest {
            target_node_id: None,
        }
    } else {
        match serde_json::from_slice(&raw) {
            Ok(b) => b,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": e.to_string()})),
                )
                    .into_response();
            }
        }
    };

    let Some(cluster) = state.cluster.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "not in cluster mode"})),
        )
            .into_response();
    };

    match cluster.transfer_leadership().await {
        Ok(new_leader_id) => {
            let exact_target = body.target_node_id.map_or(false, |t| t == new_leader_id);
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "new_leader_id": new_leader_id,
                    "exact_target": exact_target,
                })),
            )
                .into_response()
        }
        Err(ClusterError::NotLeader { .. }) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "this node is not the leader"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}
