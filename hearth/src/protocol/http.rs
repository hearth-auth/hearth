use std::sync::Arc;

use axum::{
    Router,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};

use crate::cluster::ClusterEngine;
use crate::protocol::cluster_admin::{bootstrap, status, transfer_leadership};

/// Shared application state threaded through every cluster-admin handler.
pub struct AppState {
    /// Present when this node participates in a cluster.  Absent → 503.
    pub cluster: Option<Arc<ClusterEngine>>,
    /// Tokens that confer admin-level access to `/admin/*` routes.
    pub admin_tokens: Vec<String>,
}

/// Check the `Authorization: Bearer <token>` header against the admin list.
///
/// Returns `Ok(())` for admin callers, `Err(401)` for missing/malformed
/// headers, and `Err(403)` for valid but non-admin tokens.
pub fn extract_admin_auth(
    headers: &HeaderMap,
    state: &AppState,
) -> Result<(), StatusCode> {
    let Some(hv) = headers.get("Authorization") else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    let Ok(raw) = hv.to_str() else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    let token = raw.strip_prefix("Bearer ").unwrap_or("");
    if state.admin_tokens.iter().any(|t| t == token) {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

/// Build the `/admin/cluster/*` sub-router wired to the given state.
pub fn cluster_admin_routes(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/admin/cluster/bootstrap", post(bootstrap))
        .route("/admin/cluster/status", get(status))
        .route("/admin/cluster/transfer-leadership", post(transfer_leadership))
        .with_state(state)
}
