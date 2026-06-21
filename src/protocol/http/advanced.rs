//! Phase D advanced agent routes (AGENT_AUTH.md §4, §8, §11).
//!
//! Routes (all require admin bearer token):
//!   POST   /v1/aats                        — issue root AAT
//!   POST   /v1/aats/derive                 — derive child AAT (narrowing scope)
//!   POST   /v1/aats/validate               — validate AAT chain
//!   DELETE /v1/aats/{jti}                  — revoke AAT by JTI
//!   POST   /v1/transaction-tokens          — issue single-use transaction token
//!   POST   /v1/transaction-tokens/consume  — consume/validate token (single-use)
//!   POST   /v1/spiffe-mappings             — register SPIFFE ID → AgentId mapping
//!   GET    /v1/spiffe-mappings/{agent_id}  — get SPIFFE mapping for an agent
//!   DELETE /v1/spiffe-mappings/{agent_id}  — delete SPIFFE mapping
//!   POST   /v1/cross-realm-policies        — create cross-realm trust policy
//!   GET    /v1/cross-realm-policies        — list policies in realm
//!   GET    /v1/cross-realm-policies/{id}   — get single policy
//!   DELETE /v1/cross-realm-policies/{id}   — delete policy

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;

use crate::core::AgentId;
use crate::identity::{
    CreateCrossRealmPolicyRequest, CreateTransactionTokenRequest, DeriveAatRequest, IdentityError,
    IssueAatRequest, RegisterSpiffeIdRequest,
};

use super::{
    auth::{extract_admin_auth, require_admin_permission},
    identity_error_to_response, AppState,
};

const PERM: &str = "hearth.agents.admin";

/// Registers all Phase-D advanced agent routes.
///
/// Called from the main router only when `agent_auth.capabilities.advanced = true`.
pub(super) fn routes() -> axum::Router<Arc<AppState>> {
    use axum::routing::{delete, get, post};
    axum::Router::new()
        // AATs
        .route("/v1/aats", post(issue_aat))
        .route("/v1/aats/derive", post(derive_aat))
        .route("/v1/aats/validate", post(validate_aat))
        .route("/v1/aats/{jti}", delete(revoke_aat))
        // Transaction tokens
        .route("/v1/transaction-tokens", post(issue_transaction_token))
        .route(
            "/v1/transaction-tokens/consume",
            post(consume_transaction_token),
        )
        // SPIFFE mappings
        .route("/v1/spiffe-mappings", post(register_spiffe_mapping))
        .route(
            "/v1/spiffe-mappings/{agent_id}",
            get(get_spiffe_mapping).delete(delete_spiffe_mapping),
        )
        // Cross-realm trust policies
        .route(
            "/v1/cross-realm-policies",
            get(list_cross_realm_policies).post(create_cross_realm_policy),
        )
        .route(
            "/v1/cross-realm-policies/{id}",
            get(get_cross_realm_policy).delete(delete_cross_realm_policy),
        )
}

// ── AAT handlers ─────────────────────────────────────────────────────────────

async fn issue_aat(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<IssueAatRequest>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let realm_id = auth.realm_id.clone();
    if let Err(e) = require_admin_permission(&auth, PERM) {
        return e.into_response();
    }
    let identity = Arc::clone(&state.identity);
    match tokio::task::spawn_blocking(move || identity.issue_aat(&realm_id, &body)).await {
        Ok(Ok(resp)) => (StatusCode::CREATED, Json(resp)).into_response(),
        Ok(Err(e)) => identity_error_to_response(&e).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "issue_aat panicked");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn derive_aat(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<DeriveAatRequest>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let realm_id = auth.realm_id.clone();
    if let Err(e) = require_admin_permission(&auth, PERM) {
        return e.into_response();
    }
    let identity = Arc::clone(&state.identity);
    match tokio::task::spawn_blocking(move || identity.derive_aat(&realm_id, &body)).await {
        Ok(Ok(resp)) => Json(resp).into_response(),
        Ok(Err(e)) => identity_error_to_response(&e).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "derive_aat panicked");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn validate_aat(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let realm_id = auth.realm_id.clone();
    let aat = match body.get("aat").and_then(|v| v.as_str()).map(str::to_string) {
        Some(s) => s,
        None => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": "missing 'aat' field"})),
            )
                .into_response()
        }
    };
    let identity = Arc::clone(&state.identity);
    match tokio::task::spawn_blocking(move || identity.validate_aat(&realm_id, &aat)).await {
        Ok(Ok(claims)) => Json(claims).into_response(),
        Ok(Err(IdentityError::AatChainBroken { .. } | IdentityError::AatExpired)) => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "aat_invalid"})),
        )
            .into_response(),
        Ok(Err(IdentityError::AatRevoked)) => (
            StatusCode::GONE,
            Json(serde_json::json!({"error": "aat_revoked"})),
        )
            .into_response(),
        Ok(Err(e)) => identity_error_to_response(&e).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "validate_aat panicked");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn revoke_aat(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(jti): Path<String>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let realm_id = auth.realm_id.clone();
    if let Err(e) = require_admin_permission(&auth, PERM) {
        return e.into_response();
    }
    let identity = Arc::clone(&state.identity);
    match tokio::task::spawn_blocking(move || identity.revoke_aat(&realm_id, &jti)).await {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(e)) => identity_error_to_response(&e).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "revoke_aat panicked");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

// ── Transaction token handlers ────────────────────────────────────────────────

async fn issue_transaction_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateTransactionTokenRequest>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let realm_id = auth.realm_id.clone();
    if let Err(e) = require_admin_permission(&auth, PERM) {
        return e.into_response();
    }
    let identity = Arc::clone(&state.identity);
    match tokio::task::spawn_blocking(move || identity.issue_transaction_token(&realm_id, &body))
        .await
    {
        Ok(Ok(resp)) => (StatusCode::CREATED, Json(resp)).into_response(),
        Ok(Err(IdentityError::TransactionTokenReplayed)) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "transaction_token_replayed"})),
        )
            .into_response(),
        Ok(Err(e)) => identity_error_to_response(&e).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "issue_transaction_token panicked");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn consume_transaction_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let realm_id = auth.realm_id.clone();
    let token = match body
        .get("token")
        .and_then(|v| v.as_str())
        .map(str::to_string)
    {
        Some(s) => s,
        None => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": "missing 'token' field"})),
            )
                .into_response()
        }
    };
    let identity = Arc::clone(&state.identity);
    match tokio::task::spawn_blocking(move || identity.consume_transaction_token(&realm_id, &token))
        .await
    {
        Ok(Ok(claims)) => Json(claims).into_response(),
        Ok(Err(IdentityError::TransactionTokenReplayed)) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "transaction_token_replayed"})),
        )
            .into_response(),
        Ok(Err(e)) => identity_error_to_response(&e).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "consume_transaction_token panicked");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

// ── SPIFFE handlers ───────────────────────────────────────────────────────────

async fn register_spiffe_mapping(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<RegisterSpiffeIdRequest>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let realm_id = auth.realm_id.clone();
    if let Err(e) = require_admin_permission(&auth, PERM) {
        return e.into_response();
    }
    let identity = Arc::clone(&state.identity);
    match tokio::task::spawn_blocking(move || identity.register_spiffe_mapping(&realm_id, &body))
        .await
    {
        Ok(Ok(mapping)) => (StatusCode::CREATED, Json(mapping)).into_response(),
        Ok(Err(e)) => identity_error_to_response(&e).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "register_spiffe_mapping panicked");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn get_spiffe_mapping(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(agent_id_str): Path<String>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let realm_id = auth.realm_id.clone();
    let agent_id = match agent_id_str.parse::<AgentId>() {
        Ok(a) => a,
        Err(_) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": "invalid agent_id"})),
            )
                .into_response()
        }
    };
    let identity = Arc::clone(&state.identity);
    match tokio::task::spawn_blocking(move || {
        identity.lookup_agent_by_spiffe_id(
            &realm_id,
            // Lookup by agent_id returns Option<spiffe_id> via the inverse index
            // We re-use the engine's forward lookup for now
            &agent_id.to_string(),
        )
    })
    .await
    {
        Ok(Ok(Some(found))) => {
            Json(serde_json::json!({"agent_id": found.to_string()})).into_response()
        }
        Ok(Ok(None)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(e)) => identity_error_to_response(&e).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "get_spiffe_mapping panicked");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn delete_spiffe_mapping(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(agent_id_str): Path<String>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let realm_id = auth.realm_id.clone();
    if let Err(e) = require_admin_permission(&auth, PERM) {
        return e.into_response();
    }
    let agent_id = match agent_id_str.parse::<AgentId>() {
        Ok(a) => a,
        Err(_) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": "invalid agent_id"})),
            )
                .into_response()
        }
    };
    let identity = Arc::clone(&state.identity);
    match tokio::task::spawn_blocking(move || identity.delete_spiffe_mapping(&realm_id, &agent_id))
        .await
    {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(e)) => identity_error_to_response(&e).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "delete_spiffe_mapping panicked");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

// ── Cross-realm trust policy handlers ────────────────────────────────────────

async fn create_cross_realm_policy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateCrossRealmPolicyRequest>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let realm_id = auth.realm_id.clone();
    if let Err(e) = require_admin_permission(&auth, PERM) {
        return e.into_response();
    }
    let identity = Arc::clone(&state.identity);
    match tokio::task::spawn_blocking(move || identity.create_cross_realm_policy(&realm_id, &body))
        .await
    {
        Ok(Ok(policy)) => (StatusCode::CREATED, Json(policy)).into_response(),
        Ok(Err(e)) => identity_error_to_response(&e).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "create_cross_realm_policy panicked");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn list_cross_realm_policies(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let realm_id = auth.realm_id.clone();
    let identity = Arc::clone(&state.identity);
    match tokio::task::spawn_blocking(move || identity.list_cross_realm_policies(&realm_id)).await {
        Ok(Ok(policies)) => Json(serde_json::json!({"items": policies})).into_response(),
        Ok(Err(e)) => identity_error_to_response(&e).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "list_cross_realm_policies panicked");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn get_cross_realm_policy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let realm_id = auth.realm_id.clone();
    let identity = Arc::clone(&state.identity);
    match tokio::task::spawn_blocking(move || identity.get_cross_realm_policy(&realm_id, &id)).await
    {
        Ok(Ok(Some(policy))) => Json(policy).into_response(),
        Ok(Ok(None)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(e)) => identity_error_to_response(&e).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "get_cross_realm_policy panicked");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn delete_cross_realm_policy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let auth = match extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    let realm_id = auth.realm_id.clone();
    if let Err(e) = require_admin_permission(&auth, PERM) {
        return e.into_response();
    }
    let identity = Arc::clone(&state.identity);
    match tokio::task::spawn_blocking(move || identity.delete_cross_realm_policy(&realm_id, &id))
        .await
    {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(e)) => identity_error_to_response(&e).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "delete_cross_realm_policy panicked");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
