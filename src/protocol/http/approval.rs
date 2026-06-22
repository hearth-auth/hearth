//! Approval request endpoints (Phase C.4–C.5 — AGENT_AUTH.md §9).
//!
//! Routes (all require admin bearer token):
//!   POST /v1/approval-requests              — create approval request
//!   GET  /v1/approval-requests              — list (optional ?status= filter)
//!   GET  /v1/approval-requests/{id}         — get single request
//!   POST /v1/approval-requests/{id}/approve — approve → returns capability token
//!   POST /v1/approval-requests/{id}/deny    — deny

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::core::AgentId;
use crate::identity::{ApprovalRequestStatus, CreateApprovalRequestInput, IdentityError};

use super::{
    auth::{extract_admin_auth, require_admin_permission},
    identity_error_to_response, AppState,
};

/// Registers all approval-request routes (Phase C).
///
/// Called from the main router only when `agent_auth.capabilities.approval = true`.
pub(super) fn routes() -> axum::Router<Arc<AppState>> {
    use axum::routing::{get, post};
    axum::Router::new()
        .route(
            "/v1/approval-requests",
            get(list_approval_requests).post(create_approval_request),
        )
        .route("/v1/approval-requests/{id}", get(get_approval_request))
        .route(
            "/v1/approval-requests/{id}/approve",
            post(approve_approval_request),
        )
        .route(
            "/v1/approval-requests/{id}/deny",
            post(deny_approval_request),
        )
}

// ── Wire types ───────────────────────────────────────────────────────────────

/// JSON body for creating an approval request.
#[derive(Debug, Deserialize)]
struct CreateApprovalRequestBody {
    agent_id: String,
    tool: String,
    #[serde(default = "default_action")]
    action: String,
    #[serde(default)]
    context: serde_json::Value,
    #[serde(default)]
    delegation_chain: Vec<String>,
    expires_in_secs: Option<i64>,
}

fn default_action() -> String {
    "invoke".to_string()
}

/// JSON body for denying an approval request.
#[derive(Debug, Deserialize)]
struct DenyBody {
    reason: Option<String>,
}

/// JSON body for approving an approval request.
#[derive(Debug, Deserialize)]
struct ApproveBody {
    capability_ttl_secs: Option<i64>,
}

/// Query parameters for listing approval requests.
#[derive(Debug, Deserialize)]
struct ListQuery {
    status: Option<String>,
    cursor: Option<String>,
    #[serde(default = "default_limit")]
    limit: usize,
}

fn default_limit() -> usize {
    25
}

/// JSON representation of an approval request.
#[derive(Debug, Serialize)]
struct ApprovalRequestJson {
    request_id: String,
    agent_id: String,
    tool: String,
    action: String,
    context: serde_json::Value,
    delegation_chain: Vec<String>,
    status: String,
    requested_at_secs: i64,
    expires_at_secs: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    resolved_at_secs: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    denial_reason: Option<String>,
}

fn status_str(s: &ApprovalRequestStatus) -> &'static str {
    match s {
        ApprovalRequestStatus::Pending => "pending",
        ApprovalRequestStatus::Approved => "approved",
        ApprovalRequestStatus::Denied => "denied",
        ApprovalRequestStatus::Expired => "expired",
    }
}

fn parse_status(s: &str) -> Option<ApprovalRequestStatus> {
    match s {
        "pending" => Some(ApprovalRequestStatus::Pending),
        "approved" => Some(ApprovalRequestStatus::Approved),
        "denied" => Some(ApprovalRequestStatus::Denied),
        "expired" => Some(ApprovalRequestStatus::Expired),
        _ => None,
    }
}

// ── Handlers ─────────────────────────────────────────────────────────────────

async fn create_approval_request(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateApprovalRequestBody>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let realm_id = auth.realm_id.clone();
    if let Err(e) = require_admin_permission(&auth, "hearth.agents.admin") {
        return e.into_response();
    }

    let agent_id = match body.agent_id.parse::<AgentId>() {
        Ok(a) => a,
        Err(_) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": "invalid agent_id"})),
            )
                .into_response()
        }
    };

    let input = CreateApprovalRequestInput {
        agent_id,
        tool: body.tool,
        action: body.action,
        context: body.context,
        delegation_chain: body.delegation_chain,
        expires_in_secs: body.expires_in_secs,
    };

    let identity = Arc::clone(&state.identity);
    match tokio::task::spawn_blocking(move || identity.create_approval_request(&realm_id, &input))
        .await
    {
        Ok(Ok(req)) => (StatusCode::CREATED, Json(to_json(&req))).into_response(),
        Ok(Err(e)) => identity_error_to_response(&e).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "create_approval_request panicked");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn list_approval_requests(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<ListQuery>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let realm_id = auth.realm_id.clone();
    if let Err(e) = require_admin_permission(&auth, "hearth.agents.admin") {
        return e.into_response();
    }

    let status_filter = params.status.as_deref().and_then(parse_status);
    let cursor = params.cursor;
    let limit = params.limit.clamp(1, 100);

    let identity = Arc::clone(&state.identity);
    match tokio::task::spawn_blocking(move || {
        identity.list_approval_requests(&realm_id, status_filter, cursor.as_deref(), limit)
    })
    .await
    {
        Ok(Ok(page)) => {
            let items: Vec<ApprovalRequestJson> = page.items.iter().map(to_json).collect();
            Json(serde_json::json!({
                "items": items,
                "next_cursor": page.next_cursor,
            }))
            .into_response()
        }
        Ok(Err(e)) => identity_error_to_response(&e).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "list_approval_requests panicked");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn get_approval_request(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let realm_id = auth.realm_id.clone();
    if let Err(e) = require_admin_permission(&auth, "hearth.agents.admin") {
        return e.into_response();
    }

    let identity = Arc::clone(&state.identity);
    match tokio::task::spawn_blocking(move || identity.get_approval_request(&realm_id, &id)).await {
        Ok(Ok(req)) => Json(to_json(&req)).into_response(),
        Ok(Err(IdentityError::ApprovalRequestNotFound)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(e)) => identity_error_to_response(&e).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "get_approval_request panicked");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn approve_approval_request(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Option<Json<ApproveBody>>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let realm_id = auth.realm_id.clone();
    if let Err(e) = require_admin_permission(&auth, "hearth.agents.admin") {
        return e.into_response();
    }

    let ttl = body.and_then(|b| b.capability_ttl_secs);
    let identity = Arc::clone(&state.identity);
    match tokio::task::spawn_blocking(move || {
        identity.approve_approval_request(&realm_id, &id, ttl)
    })
    .await
    {
        Ok(Ok(resp)) => Json(serde_json::json!({
            "request_id": resp.request_id,
            "status": status_str(&resp.status),
            "capability_token": resp.capability_token.as_ref().map(|t| serde_json::json!({
                "token": t.token,
                "expires_in_secs": t.expires_in_secs,
            })),
        }))
        .into_response(),
        Ok(Err(e)) => identity_error_to_response(&e).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "approve_approval_request panicked");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn deny_approval_request(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Option<Json<DenyBody>>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let realm_id = auth.realm_id.clone();
    if let Err(e) = require_admin_permission(&auth, "hearth.agents.admin") {
        return e.into_response();
    }

    let reason = body.and_then(|b| b.0.reason);
    let identity = Arc::clone(&state.identity);
    match tokio::task::spawn_blocking(move || {
        identity.deny_approval_request(&realm_id, &id, reason)
    })
    .await
    {
        Ok(Ok(resp)) => Json(serde_json::json!({
            "request_id": resp.request_id,
            "status": status_str(&resp.status),
        }))
        .into_response(),
        Ok(Err(e)) => identity_error_to_response(&e).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "deny_approval_request panicked");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn to_json(req: &crate::identity::ApprovalRequest) -> ApprovalRequestJson {
    ApprovalRequestJson {
        request_id: req.request_id.clone(),
        agent_id: req.agent_id.to_string(),
        tool: req.tool.clone(),
        action: req.action.clone(),
        context: req.context.clone(),
        delegation_chain: req.delegation_chain.clone(),
        status: status_str(&req.status).to_string(),
        requested_at_secs: req.requested_at.as_micros() / 1_000_000,
        expires_at_secs: req.expires_at.as_micros() / 1_000_000,
        resolved_at_secs: req.resolved_at.map(|t| t.as_micros() / 1_000_000),
        denial_reason: req.denial_reason.clone(),
    }
}
