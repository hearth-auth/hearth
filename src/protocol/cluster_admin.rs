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
// A-47: admin request bodies use deny_unknown_fields. Here it also closes the
// task 26.60 hole from the other side: a target sent under any other spelling
// (`targetNodeId`, `target`, `node_id`) is refused with 400 instead of being
// dropped and followed by a step-down that answers 200.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TransferLeadershipRequest {
    /// Node the caller wants to become leader.
    ///
    /// **Not supported; a request that sets it is refused with 422** (task
    /// 26.60). openraft 0.9.25 has no targeted-transfer API, so the winner of
    /// the election this node stands down from is whichever voter's timer
    /// fires first. Accepting the field and stepping down anyway would report
    /// success for a request the server did not carry out. The field stays in
    /// the schema so its refusal names the reason (422) rather than the
    /// generic unknown-field 400 every other key gets; `null` is treated as
    /// absent.
    pub target_node_id: Option<u64>,
}

/// Error returned when a caller names a `target_node_id`.
pub(crate) const TARGETED_TRANSFER_UNSUPPORTED: &str =
    "targeted leadership transfer is not supported: the Raft library Hearth pins (openraft \
     0.9.25) cannot hand leadership to a chosen node. Omit target_node_id to step this node \
     down; the response's new_leader_id reports which voter won the election";

/// `POST /admin/cluster/transfer-leadership`
///
/// Steps this node down so another voter takes over. This node must be the
/// current leader; returns 409 otherwise.
///
/// This is a **step-down, not a targeted transfer.** openraft 0.9.25 exposes
/// no API for handing leadership to a chosen peer (`Trigger::transfer_leader`
/// arrived in 0.10). A body naming a `target_node_id` is therefore refused
/// with **422** before anything is changed, rather than answered with a
/// step-down to whichever voter happens to win, and any other body field is
/// refused with **400**. The response reports the winner in `new_leader_id`
/// (plus the deprecated, always-`false` `exact_target`).
///
/// Why no targeted transfer can be built from the 0.9.25 public API: asking
/// the target to `trigger().elect()` fails while the followers' leader
/// leases are live (`Engine::handle_vote_req` rejects every vote inside the
/// lease), and once the leases lapse every other follower's election timer
/// races the target's. Only suppressing elections cluster-wide would make the
/// outcome deterministic, and a lost "re-enable" would leave a voter that can
/// never stand again.
///
/// **Availability note:** this deliberately lets the followers' leader leases
/// expire, so the cluster is without a leader for
/// `leader_lease + election_timeout` — 4.5–6 s under Hearth's Raft config —
/// and writes fail with `NoLeader`/`NotLeader` throughout. Do not call it
/// during a write burst. The call itself waits up to 20 s (task 26.57; the
/// previous 5 s bound was *below* openraft's own floor, so it reported
/// failure on transfers that were about to succeed).
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

    // Refuse a named target before touching Raft: the step-down below cannot
    // choose its winner, so going ahead would report success for a request
    // the server did not carry out (task 26.60).
    if body.target_node_id.is_some() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": TARGETED_TRANSFER_UNSUPPORTED})),
        )
            .into_response();
    }

    let Some(cluster) = state.cluster.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "not in cluster mode"})),
        )
            .into_response();
    };

    match cluster.transfer_leadership().await {
        Ok(new_leader_id) => (StatusCode::OK, Json(step_down_body(new_leader_id))).into_response(),
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

/// JSON body of a successful `POST /admin/cluster/transfer-leadership`.
///
/// `exact_target` is **deprecated** and always `false`. 1.0.0 documented the
/// body as `{new_leader_id, exact_target}`, and dropping a documented field is
/// a breaking change under VERSIONING.md, so it stays until 2.0. It is still
/// accurate: a request naming a target is refused with 422 and never gets
/// here, so no request reaching this body had its target matched.
fn step_down_body(new_leader_id: u64) -> serde_json::Value {
    serde_json::json!({ "new_leader_id": new_leader_id, "exact_target": false })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn step_down_body_keeps_the_documented_exact_target_field() {
        // 1.0.0 documented the 200 body as `{new_leader_id, exact_target}`
        // (VERSIONING.md: dropping a documented response field is breaking).
        // Every request reaching the 200 path names no target, so the field
        // is always `false` — deprecated, but still present.
        assert_eq!(
            step_down_body(2),
            serde_json::json!({ "new_leader_id": 2, "exact_target": false })
        );
    }

    #[test]
    fn transfer_request_refuses_unknown_fields() {
        // A-47: a target under any other spelling must not be dropped
        // silently and then followed by a step-down (task 26.60).
        for body in [
            r#"{"targetNodeId": 2}"#,
            r#"{"target": 2}"#,
            r#"{"node_id": 2}"#,
        ] {
            let err = serde_json::from_str::<TransferLeadershipRequest>(body)
                .expect_err(&format!("{body} must be refused"));
            assert!(
                err.to_string().contains("unknown field"),
                "{body}: expected an unknown-field error, got {err}"
            );
        }
        let ok: TransferLeadershipRequest =
            serde_json::from_str(r#"{"target_node_id": null}"#).expect("known field");
        assert_eq!(ok.target_node_id, None);
    }
}
