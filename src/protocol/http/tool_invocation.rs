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
//!    - If the token has `cnf.jkt`, require + validate a matching DPoP proof (M4).
//! 2. Load the realm's tool-group map from config. Fail closed on error (H2).
//! 3. Call `evaluate_tool_access()` with the permissions and tool-group map.
//!    - `Allow` → emit `AgentToolInvocation` audit record, then 200 OK (M6).
//!    - `RequireApproval` → require `X-Capability-Token` header.
//!      - Present + valid for this caller (M5) → 200 OK (single-use JTI consumed).
//!      - Absent or invalid → 403 `HEARTH_TOOL_APPROVAL_REQUIRED`.
//!    - `Deny` → 403 `HEARTH_TOOL_ACCESS_DENIED`.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::audit::{AuditAction, CreateAuditEvent};
use crate::identity::tool_permissions::{evaluate_tool_access, ToolAccessDecision};

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
    let raw_token = match super::auth::extract_bearer_token(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let claims = match state.identity.validate_token(&realm_id, &raw_token) {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "invalid_token"})),
            )
                .into_response()
        }
    };

    // M4 — DPoP enforcement at the tool gate.
    // When the access token carries a `cnf.jkt` binding, the caller MUST
    // present a matching DPoP proof. A stolen bound token replayed as plain
    // bearer is rejected here.
    if let Some(cnf) = &claims.cnf {
        let expected_jkt = &cnf.jkt;
        let proof = match headers.get("DPoP").and_then(|v| v.to_str().ok()) {
            Some(p) => p,
            None => {
                // Bound token with no DPoP proof — reject with 401 + DPoP-Nonce.
                let now_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                let nonce = state
                    .identity
                    .get_realm_dpop_nonce_secret(&realm_id)
                    .ok()
                    .map(|s| crate::identity::dpop::current_dpop_nonce(&s, now_secs))
                    .unwrap_or_else(|| state.dpop.current_nonce(now_secs));
                let mut resp = (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({"error": "use_dpop_nonce", "error_description": "DPoP proof required for bound access token"})),
                )
                    .into_response();
                if let Ok(val) = axum::http::HeaderValue::from_str(&nonce) {
                    resp.headers_mut().insert("DPoP-Nonce", val);
                }
                return resp;
            }
        };

        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let expected_htu = format!(
            "{}/v1/tools/invoke",
            state.identity.oidc_discovery().issuer
        );
        let nonce_secret = state
            .identity
            .get_realm_dpop_nonce_secret(&realm_id)
            .ok();

        let validated = match crate::identity::dpop::validate_dpop_proof(
            proof,
            "POST",
            &expected_htu,
            now_secs,
            None, // nonce optional on resource endpoints (no nonce-challenge loop here)
            Some(raw_token.as_str()),
        ) {
            Ok(v) => v,
            Err(e) => return identity_error_to_response(&e).into_response(),
        };

        // Nonce check — accept current or previous window.
        if let Some(presented_nonce) = validated.nonce.as_deref() {
            let valid = nonce_secret
                .map(|s| crate::identity::dpop::is_valid_dpop_nonce(&s, presented_nonce, now_secs))
                .unwrap_or_else(|| state.dpop.is_valid_nonce(presented_nonce, now_secs));
            if !valid {
                return identity_error_to_response(
                    &crate::identity::IdentityError::DPopNonceInvalid,
                )
                .into_response();
            }
        }

        // JTI replay prevention.
        if let Err(e) = state
            .identity
            .check_and_record_dpop_jti(&realm_id, &validated.jti, now_secs)
        {
            return identity_error_to_response(&e).into_response();
        }

        // Thumbprint binding check.
        if validated.jkt != *expected_jkt {
            return identity_error_to_response(
                &crate::identity::IdentityError::DPopBindingMismatch,
            )
            .into_response();
        }
    }

    // H2 — Load the realm's tool-group map from stored realm config.
    // Fail closed: if the realm can't be loaded, deny the invocation rather
    // than silently falling back to an empty map that would bypass group denies.
    let tool_groups = match state.identity.get_realm(&realm_id) {
        Ok(Some(realm)) => realm.config().tool_groups.clone(),
        Ok(None) => {
            tracing::error!(realm_id = %realm_id, "invoke_tool: realm not found");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "realm_not_found"})),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, realm_id = %realm_id, "invoke_tool: failed to load realm config");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal_error"})),
            )
                .into_response();
        }
    };

    let decision = evaluate_tool_access(&claims.permissions, &body.tool, &tool_groups);

    match decision {
        ToolAccessDecision::Allow => {
            // M6 — Audit every authorized (Allow) invocation.
            let _ = state.audit.append(&CreateAuditEvent {
                realm_id: realm_id.clone(),
                actor: claims.sub.clone(),
                action: AuditAction::AgentToolInvocation,
                resource_type: "tool".to_string(),
                resource_id: format!("{}.{}", body.tool, body.action),
                metadata: None,
            });
            (
                StatusCode::OK,
                Json(InvokeToolResponse {
                    authorized: true,
                    agent_id: None,
                }),
            )
                .into_response()
        }

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
            // M5 — pass caller sub so the engine can verify the token was minted for this caller.
            let tool = body.tool.clone();
            let action = body.action.clone();
            let caller_sub = claims.sub.clone();
            let identity = Arc::clone(&state.identity);
            let realm_id_c = realm_id.clone();
            let result = tokio::task::spawn_blocking(move || {
                identity.validate_capability_token(
                    &realm_id_c,
                    &cap_token,
                    &tool,
                    &action,
                    &caller_sub,
                )
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
