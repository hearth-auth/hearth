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

    // M4 — When the access token carries a `cnf.jkt` binding, require a matching DPoP proof.
    if let Some(cnf) = &claims.cnf {
        if let Err(resp) =
            validate_dpop_if_bound(&state, &headers, &realm_id, &cnf.jkt, raw_token.as_str())
        {
            return resp;
        }
    }

    // H2 — Fail closed: load realm config so tool-group denies are never bypassed.
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

    match evaluate_tool_access(&claims.permissions, &body.tool, &tool_groups) {
        ToolAccessDecision::Allow => {
            // M6 — Audit every authorized invocation.
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
            check_capability_token(&state, &realm_id, &headers, &body, &claims.sub).await
        }
    }
}

/// M4 — Validates the DPoP proof when the access token carries a `cnf.jkt` binding.
///
/// Returns `Err(response)` with the appropriate HTTP response on any failure,
/// `Ok(())` when the proof is valid and the JTI has been consumed.
fn validate_dpop_if_bound(
    state: &AppState,
    headers: &HeaderMap,
    realm_id: &crate::core::RealmId,
    expected_jkt: &str,
    raw_token: &str,
) -> Result<(), axum::response::Response> {
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let nonce_secret = state.identity.get_realm_dpop_nonce_secret(realm_id).ok();

    let proof = match headers.get("DPoP").and_then(|v| v.to_str().ok()) {
        Some(p) => p,
        None => {
            let nonce = nonce_secret
                .as_ref()
                .map(|s| crate::identity::dpop::current_dpop_nonce(s, now_secs))
                .unwrap_or_else(|| state.dpop.current_nonce(now_secs));
            let mut resp = (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "use_dpop_nonce",
                    "error_description": "DPoP proof required for bound access token"})),
            )
                .into_response();
            if let Ok(val) = axum::http::HeaderValue::from_str(&nonce) {
                resp.headers_mut().insert("DPoP-Nonce", val);
            }
            return Err(resp);
        }
    };

    let expected_htu = format!("{}/v1/tools/invoke", state.identity.oidc_discovery().issuer);
    let validated = crate::identity::dpop::validate_dpop_proof(
        proof,
        "POST",
        &expected_htu,
        now_secs,
        None,
        Some(raw_token),
    )
    .map_err(|e| identity_error_to_response(&e).into_response())?;

    if let Some(presented_nonce) = validated.nonce.as_deref() {
        let valid = nonce_secret
            .map(|s| crate::identity::dpop::is_valid_dpop_nonce(&s, presented_nonce, now_secs))
            .unwrap_or_else(|| state.dpop.is_valid_nonce(presented_nonce, now_secs));
        if !valid {
            return Err(identity_error_to_response(
                &crate::identity::IdentityError::DPopNonceInvalid,
            )
            .into_response());
        }
    }

    state
        .identity
        .check_and_record_dpop_jti(realm_id, &validated.jti, now_secs)
        .map_err(|e| identity_error_to_response(&e).into_response())?;

    if validated.jkt != expected_jkt {
        return Err(identity_error_to_response(
            &crate::identity::IdentityError::DPopBindingMismatch,
        )
        .into_response());
    }
    Ok(())
}

/// M5 — Validates the `X-Capability-Token` header for `RequireApproval` decisions.
async fn check_capability_token(
    state: &Arc<AppState>,
    realm_id: &crate::core::RealmId,
    headers: &HeaderMap,
    body: &InvokeToolBody,
    caller_sub: &str,
) -> axum::response::Response {
    let Some(cap_token) = headers
        .get("x-capability-token")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
    else {
        return identity_error_to_response(&crate::identity::IdentityError::ToolApprovalRequired {
            tool: body.tool.clone(),
        })
        .into_response();
    };

    let tool = body.tool.clone();
    let action = body.action.clone();
    let sub = caller_sub.to_string();
    let identity = Arc::clone(state);
    let realm_id_c = realm_id.clone();
    let result = tokio::task::spawn_blocking(move || {
        identity
            .identity
            .validate_capability_token(&realm_id_c, &cap_token, &tool, &action, &sub)
    })
    .await;

    match result {
        Ok(Ok(agent_id)) => (
            StatusCode::OK,
            Json(InvokeToolResponse {
                authorized: true,
                agent_id: Some(agent_id.to_string()),
            }),
        )
            .into_response(),
        Ok(Err(e)) => identity_error_to_response(&e).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "invoke_tool spawn_blocking panicked");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
