//! Tool-invocation authorization check endpoint (Phase C — AGENT_AUTH.md §5).
//!
//! Route:
//!   POST /v1/tools/invoke  — server-side capability-token enforcement
//!
//! MCP proxy servers call this endpoint before executing any tool invocation.
//! The endpoint enforces the Saltzer & Schroeder Complete Mediation principle:
//! every access must be checked every time at the server, not in the client.
//!
//! # Decision flow
//!
//! 1. Validate the caller's bearer token and extract permissions.
//! 2. Call `evaluate_tool_access()` with the permissions.
//!    - `Allow` → 200 OK — the invocation is authorized.
//!    - `RequireApproval` → require `X-Capability-Token` header.
//!      - Present + valid → 200 OK (single-use JTI is consumed).
//!      - Absent or invalid → 403 `HEARTH_TOOL_APPROVAL_REQUIRED`.
//!    - `Deny` → 403 `HEARTH_TOOL_ACCESS_DENIED`.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::identity::tool_permissions::{evaluate_tool_access, ToolAccessDecision, ToolGroupMap};

use super::{auth::extract_realm_id, identity_error_to_response, AppState};

/// Registers the tool-invocation check routes (Phase C).
///
/// Called from the main router only when `agent_auth.capabilities.approval = true`.
pub(super) fn routes() -> axum::Router<Arc<AppState>> {
    use axum::routing::post;
    axum::Router::new().route("/v1/tools/invoke", post(invoke_tool))
}

// ── Wire types ───────────────────────────────────────────────────────────────

/// Request body for the tool invocation check.
#[derive(Debug, Deserialize)]
struct InvokeToolBody {
    /// Tool name being invoked (e.g. `"delete_file"`).
    tool: String,
    /// Action being requested (e.g. `"invoke"`).
    #[serde(default = "default_action")]
    action: String,
}

fn default_action() -> String {
    "invoke".to_string()
}

/// Response body returned on authorized invocation.
#[derive(Debug, Serialize)]
struct InvokeToolResponse {
    authorized: bool,
    agent_id: Option<String>,
}

// ── Handler ──────────────────────────────────────────────────────────────────

/// `POST /v1/tools/invoke`
///
/// Checks whether the authenticated caller is authorized to invoke `tool` with
/// `action`. Returns `200 { authorized: true }` when allowed, or `403` with an
/// error code when denied or when approval is required but the capability token
/// is absent/invalid.
async fn invoke_tool(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<InvokeToolBody>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };

    // Extract and validate the bearer token.
    let token = match super::auth::extract_bearer_token(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let claims = match state.identity.validate_token(&realm_id, &token) {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "invalid_token"})),
            )
                .into_response()
        }
    };

    // Tool groups come from realm config; fall back to empty map when not configured.
    // Empty map is safe: groups can only expand access, never restrict it.
    let tool_groups = ToolGroupMap::default();

    let decision = evaluate_tool_access(&claims.permissions, &body.tool, &tool_groups);

    match decision {
        ToolAccessDecision::Allow => (
            StatusCode::OK,
            Json(InvokeToolResponse {
                authorized: true,
                agent_id: None,
            }),
        )
            .into_response(),

        ToolAccessDecision::Deny => {
            identity_error_to_response(&crate::identity::IdentityError::ToolAccessDenied {
                tool: body.tool.clone(),
            })
            .into_response()
        }

        ToolAccessDecision::RequireApproval => {
            // Check for X-Capability-Token header.
            let cap_token = headers
                .get("x-capability-token")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);

            let Some(cap_token) = cap_token else {
                // No capability token present — tell the caller to obtain approval.
                return identity_error_to_response(
                    &crate::identity::IdentityError::ToolApprovalRequired {
                        tool: body.tool.clone(),
                    },
                )
                .into_response();
            };

            // Validate the capability token (signature, type, aud, exp, tool/action, JTI).
            let tool = body.tool.clone();
            let action = body.action.clone();
            let identity = Arc::clone(&state.identity);
            let realm_id_c = realm_id.clone();
            let result = tokio::task::spawn_blocking(move || {
                identity.validate_capability_token(&realm_id_c, &cap_token, &tool, &action)
            })
            .await;

            match result {
                Ok(Ok(agent_id)) => {
                    // Capability token valid and consumed (JTI written to blocklist in engine).
                    (
                        StatusCode::OK,
                        Json(InvokeToolResponse {
                            authorized: true,
                            agent_id: Some(agent_id.to_string()),
                        }),
                    )
                        .into_response()
                }
                Ok(Err(e)) => identity_error_to_response(&e).into_response(),
                Err(e) => {
                    tracing::error!(error = %e, "invoke_tool spawn_blocking panicked");
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                }
            }
        }
    }
}
