//! Agent management endpoints (A.3, A.4, A.7 — AGENT_AUTH.md Phase A).
//!
//! Routes:
//!   GET  /.well-known/agent.json          — Agent Card (by `?agent_id=`)
//!   GET  /v1/agents                       — list agents
//!   POST /v1/agents                       — create agent
//!   GET  /v1/agents/{id}                  — get agent
//!   PATCH /v1/agents/{id}                 — update agent
//!   DELETE /v1/agents/{id}                — delete agent
//!   POST /v1/agents/{id}/credentials/keys — issue API key
//!   GET  /v1/agents/{id}/credentials      — list credentials
//!   DELETE /v1/agents/{id}/credentials/{cred_id} — revoke credential

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::core::{AgentCredentialId, AgentId};
use crate::identity::{
    AgentCredentialKind, AgentOwner, AgentStatus, CreateAgentApiKeyRequest, CreateAgentRequest,
    ListAgentsQuery, UpdateAgentRequest,
};

use super::{extract_realm_id, identity_error_to_response, AppState};

/// Registers all agent routes (Phase A).
///
/// Called from the main router only when `agent_auth.capabilities.identity = true`.
pub(super) fn routes() -> axum::Router<Arc<AppState>> {
    use axum::routing::{delete, get, post};
    axum::Router::new()
        .route("/.well-known/agent.json", get(agent_card))
        .route("/v1/agents", get(list_agents).post(create_agent))
        .route(
            "/v1/agents/{id}",
            get(get_agent).patch(update_agent).delete(delete_agent),
        )
        .route("/v1/agents/{id}/credentials/keys", post(create_api_key))
        .route("/v1/agents/{id}/credentials", get(list_credentials))
        .route(
            "/v1/agents/{id}/credentials/{cred_id}",
            delete(revoke_credential),
        )
}

// ── Wire types ───────────────────────────────────────────────────────────────

/// JSON representation of an agent (no secrets).
#[derive(Serialize)]
struct AgentResponse {
    id: String,
    realm_id: String,
    owner: AgentOwnerWire,
    display_name: String,
    description: String,
    capabilities: Vec<String>,
    status: &'static str,
    max_delegation_depth: u8,
    created_at: i64,
    updated_at: i64,
}

#[derive(Serialize)]
struct AgentOwnerWire {
    r#type: &'static str,
    id: String,
}

/// JSON representation of an agent credential (no secret material).
#[derive(Serialize)]
struct CredentialResponse {
    id: String,
    agent_id: String,
    kind: &'static str,
    label: String,
    created_at: i64,
    revoked_at: Option<i64>,
}

/// Agent Card per A2A protocol spec (A.4).
#[derive(Serialize)]
struct AgentCard {
    name: String,
    description: String,
    url: String,
    capabilities: Vec<String>,
    authentication: Vec<&'static str>,
    version: u32,
}

// ── Converters ───────────────────────────────────────────────────────────────

fn agent_to_wire(a: &crate::identity::Agent) -> AgentResponse {
    let (owner_type, owner_id) = match a.owner() {
        AgentOwner::User(uid) => ("user", uid.as_uuid().to_string()),
        AgentOwner::Organization(oid) => ("organization", oid.as_uuid().to_string()),
    };
    AgentResponse {
        id: a.id().to_string(),
        realm_id: a.realm_id().as_uuid().to_string(),
        owner: AgentOwnerWire {
            r#type: owner_type,
            id: owner_id,
        },
        display_name: a.display_name().to_string(),
        description: a.description().to_string(),
        capabilities: a.capabilities().to_vec(),
        status: match a.status() {
            AgentStatus::Active => "active",
            AgentStatus::Suspended => "suspended",
            AgentStatus::Revoked => "revoked",
        },
        max_delegation_depth: a.max_delegation_depth(),
        created_at: a.created_at().as_micros(),
        updated_at: a.updated_at().as_micros(),
    }
}

fn cred_to_wire(c: &crate::identity::AgentCredential) -> CredentialResponse {
    CredentialResponse {
        id: c.id().to_string(),
        agent_id: c.agent_id().to_string(),
        kind: match c.kind() {
            AgentCredentialKind::ApiKey => "api_key",
            AgentCredentialKind::Ed25519PublicKey => "ed25519_public_key",
            AgentCredentialKind::MtlsCert => "mtls_cert",
        },
        label: c.label().to_string(),
        created_at: c.created_at().as_micros(),
        revoked_at: c.revoked_at().map(|t| t.as_micros()),
    }
}

// ── Handlers ─────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct AgentCardQuery {
    agent_id: Option<String>,
}

/// `GET /.well-known/agent.json?agent_id={id}`
///
/// Returns the Agent Card for the specified agent. No secret material.
async fn agent_card(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<AgentCardQuery>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };

    let agent_id_str = match query.agent_id {
        Some(s) => s,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "agent_id query parameter required"})),
            )
                .into_response()
        }
    };

    let agent_id = match agent_id_str.parse::<AgentId>() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid agent_id format"})),
            )
                .into_response()
        }
    };

    let identity = Arc::clone(&state.identity);
    let result = tokio::task::spawn_blocking(move || identity.get_agent(&realm_id, &agent_id))
        .await
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "agent_card spawn_blocking panicked");
            Err(crate::identity::IdentityError::Storage(Box::new(e)))
        });

    match result {
        Ok(Some(agent)) => {
            let card = AgentCard {
                name: agent.display_name().to_string(),
                description: agent.description().to_string(),
                url: String::new(), // operator configures this externally
                capabilities: agent.capabilities().to_vec(),
                authentication: vec!["api_key"],
                version: 1,
            };
            (
                StatusCode::OK,
                Json(serde_json::to_value(card).unwrap_or_default()),
            )
                .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "agent not found"})),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

#[derive(Deserialize)]
struct CreateAgentBody {
    display_name: String,
    #[serde(default)]
    description: Option<String>,
    owner_type: String,
    owner_id: String,
    #[serde(default)]
    capabilities: Vec<String>,
    #[serde(default = "default_delegation_depth")]
    max_delegation_depth: u8,
}

fn default_delegation_depth() -> u8 {
    1
}

/// `POST /v1/agents`
async fn create_agent(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateAgentBody>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };

    let owner = match parse_owner(&body.owner_type, &body.owner_id) {
        Ok(o) => o,
        Err(msg) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": msg})),
            )
                .into_response()
        }
    };

    let request = CreateAgentRequest {
        display_name: body.display_name,
        description: body.description,
        owner,
        capabilities: body.capabilities,
        max_delegation_depth: body.max_delegation_depth,
    };

    let identity = Arc::clone(&state.identity);
    let result = tokio::task::spawn_blocking(move || identity.create_agent(&realm_id, &request))
        .await
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "create_agent spawn_blocking panicked");
            Err(crate::identity::IdentityError::Storage(Box::new(e)))
        });

    match result {
        Ok(agent) => (
            StatusCode::CREATED,
            Json(serde_json::to_value(agent_to_wire(&agent)).unwrap_or_default()),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// `GET /v1/agents`
async fn list_agents(State(state): State<Arc<AppState>>, headers: HeaderMap) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };

    let identity = Arc::clone(&state.identity);
    let result = tokio::task::spawn_blocking(move || {
        identity.list_agents(&realm_id, &ListAgentsQuery::default(), None, 100)
    })
    .await
    .unwrap_or_else(|e| {
        tracing::error!(error = %e, "list_agents spawn_blocking panicked");
        Err(crate::identity::IdentityError::Storage(Box::new(e)))
    });

    match result {
        Ok(page) => {
            let items: Vec<_> = page.items.iter().map(agent_to_wire).collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({"items": items, "next_cursor": page.next_cursor})),
            )
                .into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// `GET /v1/agents/{id}`
async fn get_agent(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let agent_id = match id.parse::<AgentId>() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid agent id"})),
            )
                .into_response()
        }
    };

    let identity = Arc::clone(&state.identity);
    let result = tokio::task::spawn_blocking(move || identity.get_agent(&realm_id, &agent_id))
        .await
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "get_agent spawn_blocking panicked");
            Err(crate::identity::IdentityError::Storage(Box::new(e)))
        });

    match result {
        Ok(Some(agent)) => (
            StatusCode::OK,
            Json(serde_json::to_value(agent_to_wire(&agent)).unwrap_or_default()),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "agent not found"})),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

#[derive(Deserialize)]
struct UpdateAgentBody {
    display_name: Option<String>,
    description: Option<String>,
    capabilities: Option<Vec<String>>,
    max_delegation_depth: Option<u8>,
}

/// `PATCH /v1/agents/{id}`
async fn update_agent(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<UpdateAgentBody>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let agent_id = match id.parse::<AgentId>() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid agent id"})),
            )
                .into_response()
        }
    };

    let request = UpdateAgentRequest {
        display_name: body.display_name,
        description: body.description,
        capabilities: body.capabilities,
        max_delegation_depth: body.max_delegation_depth,
    };

    let identity = Arc::clone(&state.identity);
    let result =
        tokio::task::spawn_blocking(move || identity.update_agent(&realm_id, &agent_id, &request))
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "update_agent spawn_blocking panicked");
                Err(crate::identity::IdentityError::Storage(Box::new(e)))
            });

    match result {
        Ok(agent) => (
            StatusCode::OK,
            Json(serde_json::to_value(agent_to_wire(&agent)).unwrap_or_default()),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// `DELETE /v1/agents/{id}`
async fn delete_agent(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let agent_id = match id.parse::<AgentId>() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid agent id"})),
            )
                .into_response()
        }
    };

    let identity = Arc::clone(&state.identity);
    let result = tokio::task::spawn_blocking(move || identity.delete_agent(&realm_id, &agent_id))
        .await
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "delete_agent spawn_blocking panicked");
            Err(crate::identity::IdentityError::Storage(Box::new(e)))
        });

    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

#[derive(Deserialize)]
struct CreateApiKeyBody {
    label: String,
}

/// `POST /v1/agents/{id}/credentials/keys`
async fn create_api_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<CreateApiKeyBody>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let agent_id = match id.parse::<AgentId>() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid agent id"})),
            )
                .into_response()
        }
    };

    let request = CreateAgentApiKeyRequest { label: body.label };

    let identity = Arc::clone(&state.identity);
    let result = tokio::task::spawn_blocking(move || {
        identity.create_agent_api_key(&realm_id, &agent_id, &request)
    })
    .await
    .unwrap_or_else(|e| {
        tracing::error!(error = %e, "create_api_key spawn_blocking panicked");
        Err(crate::identity::IdentityError::Storage(Box::new(e)))
    });

    match result {
        Ok(resp) => {
            let body = serde_json::json!({
                "credential": cred_to_wire(&resp.credential),
                // Show-once: included only in this response.
                "key": resp.plaintext_key.expose_once(),
            });
            (StatusCode::CREATED, Json(body)).into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// `GET /v1/agents/{id}/credentials`
async fn list_credentials(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let agent_id = match id.parse::<AgentId>() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid agent id"})),
            )
                .into_response()
        }
    };

    let identity = Arc::clone(&state.identity);
    let result =
        tokio::task::spawn_blocking(move || identity.list_agent_credentials(&realm_id, &agent_id))
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "list_credentials spawn_blocking panicked");
                Err(crate::identity::IdentityError::Storage(Box::new(e)))
            });

    match result {
        Ok(creds) => {
            let items: Vec<_> = creds.iter().map(cred_to_wire).collect();
            (StatusCode::OK, Json(serde_json::json!({"items": items}))).into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// `DELETE /v1/agents/{id}/credentials/{cred_id}`
async fn revoke_credential(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, cred_id)): Path<(String, String)>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let agent_id = match id.parse::<AgentId>() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid agent id"})),
            )
                .into_response()
        }
    };
    let cred_id = match cred_id.parse::<AgentCredentialId>() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid credential id"})),
            )
                .into_response()
        }
    };

    let identity = Arc::clone(&state.identity);
    let result = tokio::task::spawn_blocking(move || {
        identity.revoke_agent_credential(&realm_id, &agent_id, &cred_id)
    })
    .await
    .unwrap_or_else(|e| {
        tracing::error!(error = %e, "revoke_credential spawn_blocking panicked");
        Err(crate::identity::IdentityError::Storage(Box::new(e)))
    });

    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn parse_owner(owner_type: &str, owner_id: &str) -> Result<AgentOwner, &'static str> {
    let uuid = uuid::Uuid::parse_str(owner_id).map_err(|_| "invalid owner_id: must be a UUID")?;
    match owner_type {
        "user" => Ok(AgentOwner::User(crate::core::UserId::new(uuid))),
        "organization" => Ok(AgentOwner::Organization(crate::core::OrganizationId::new(
            uuid,
        ))),
        _ => Err("owner_type must be 'user' or 'organization'"),
    }
}
