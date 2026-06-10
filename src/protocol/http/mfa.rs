//! TOTP / WebAuthn / passkey and magic-link endpoints.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::core::UserId;

use super::{
    extract_realm_id, extract_user_auth, identity_error_to_response, make_ip_rate_limit_response,
    resolve_realm_by_name, AppState, FALLBACK_PEER,
};

/// Registers WebAuthn and magic-link routes.
pub(super) fn routes() -> axum::Router<Arc<AppState>> {
    use axum::routing::{delete, get, post};
    axum::Router::new()
        .route("/webauthn/register/begin", post(webauthn_register_begin))
        .route(
            "/webauthn/register/complete",
            post(webauthn_register_complete),
        )
        .route("/webauthn/auth/begin", post(webauthn_auth_begin))
        .route("/webauthn/auth/complete", post(webauthn_auth_complete))
        .route("/webauthn/credentials", get(webauthn_list_credentials))
        .route(
            "/webauthn/credentials/{credential_id}",
            delete(webauthn_delete_credential),
        )
        .route(
            "/v1/{realm}/auth/magic-link",
            post(magic_link_request).route_layer(axum::extract::DefaultBodyLimit::max(
                super::BODY_LIMIT_SMALL,
            )),
        )
}

fn b64_decode(s: &str) -> Result<Vec<u8>, (StatusCode, Json<serde_json::Value>)> {
    URL_SAFE_NO_PAD.decode(s).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("invalid base64url: {e}")})),
        )
    })
}

fn b64_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

#[derive(Debug, Deserialize)]
struct WbrBeginReq {
    rp_id: Option<String>,
    discoverable: Option<bool>,
}

#[derive(Debug, Serialize)]
struct WbrBeginRes {
    challenge: String,
    rp_id: String,
    rp_name: String,
    user_id: String,
    user_name: String,
    user_display_name: String,
    attestation: String,
    timeout: u64,
}

#[derive(Debug, Deserialize)]
struct WbrCompleteReq {
    client_data_json: String,
    attestation_object: String,
    origin: String,
    discoverable: Option<bool>,
}

#[derive(Debug, Serialize)]
struct WbrCompleteRes {
    credential_id: String,
    algorithm: i64,
    discoverable: bool,
}

#[derive(Debug, Deserialize)]
struct WbaBeginReq {
    rp_id: Option<String>,
    user_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct WbaBeginRes {
    challenge: String,
    rp_id: String,
    allow_credentials: Vec<WbaAllowCred>,
    user_verification: String,
    timeout: u64,
}

#[derive(Debug, Serialize)]
struct WbaAllowCred {
    id: String,
    #[serde(rename = "type")]
    ty: String,
}

#[derive(Debug, Deserialize)]
struct WbaCompleteReq {
    credential_id: String,
    client_data_json: String,
    authenticator_data: String,
    signature: String,
    user_handle: Option<String>,
    origin: String,
}

#[derive(Debug, Serialize)]
struct WbaCompleteRes {
    credential_id: String,
    user_id: String,
    sign_count: u32,
}

#[derive(Debug, Serialize)]
struct WbCredsRes {
    credentials: Vec<WbCredEntry>,
}

#[derive(Debug, Serialize)]
struct WbCredEntry {
    credential_id: String,
    algorithm: i64,
    discoverable: bool,
}

async fn webauthn_register_begin(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<WbrBeginReq>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let user_id = match extract_user_auth(&headers, &state, &realm_id) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    let options = crate::identity::webauthn::RegistrationOptions {
        rp_id: body.rp_id.unwrap_or_default(),
        discoverable: body.discoverable.unwrap_or(true),
    };
    match state
        .identity
        .start_webauthn_registration(&realm_id, &user_id, &options)
    {
        Ok(challenge) => (
            StatusCode::OK,
            Json(WbrBeginRes {
                challenge: b64_encode(&challenge),
                rp_id: options.rp_id,
                rp_name: "Hearth".to_string(),
                user_id: user_id.to_string(),
                user_name: user_id.to_string(),
                user_display_name: user_id.to_string(),
                attestation: "none".to_string(),
                timeout: 60,
            }),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

async fn webauthn_register_complete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<WbrCompleteReq>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let user_id = match extract_user_auth(&headers, &state, &realm_id) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    let client_data_json = match b64_decode(&body.client_data_json) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let attestation_object = match b64_decode(&body.attestation_object) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    match state.identity.complete_webauthn_registration(
        &realm_id,
        &user_id,
        &client_data_json,
        &attestation_object,
        &body.origin,
        body.discoverable.unwrap_or(false),
    ) {
        Ok(info) => (
            StatusCode::OK,
            Json(WbrCompleteRes {
                credential_id: b64_encode(info.credential_id()),
                algorithm: info.algorithm(),
                discoverable: info.discoverable(),
            }),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

async fn webauthn_auth_begin(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<WbaBeginReq>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let user_id: Option<UserId> = match body.user_id.as_deref().map(uuid::Uuid::parse_str) {
        Some(Ok(u)) => Some(UserId::new(u)),
        Some(Err(_)) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid user_id"})),
            )
                .into_response()
        }
        None => None,
    };
    let options = crate::identity::webauthn::AuthenticationOptions {
        rp_id: body.rp_id.unwrap_or_default(),
    };
    match state
        .identity
        .start_webauthn_authentication(&realm_id, user_id.as_ref(), &options)
    {
        Ok(challenge) => {
            let allow_credentials = match user_id.as_ref() {
                Some(uid) => match state.identity.list_webauthn_credentials(&realm_id, uid) {
                    Ok(creds) => creds
                        .into_iter()
                        .map(|c| WbaAllowCred {
                            id: b64_encode(c.credential_id()),
                            ty: "public-key".to_string(),
                        })
                        .collect(),
                    Err(_) => Vec::new(),
                },
                None => Vec::new(),
            };
            (
                StatusCode::OK,
                Json(WbaBeginRes {
                    challenge: b64_encode(&challenge),
                    rp_id: options.rp_id,
                    allow_credentials,
                    user_verification: "preferred".to_string(),
                    timeout: 60,
                }),
            )
                .into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

async fn webauthn_auth_complete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<WbaCompleteReq>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let credential_id = match b64_decode(&body.credential_id) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let client_data_json = match b64_decode(&body.client_data_json) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let authenticator_data = match b64_decode(&body.authenticator_data) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let signature = match b64_decode(&body.signature) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let uh_vec = match body
        .user_handle
        .as_deref()
        .map(|s| b64_decode(s))
        .transpose()
    {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let params = crate::identity::webauthn::CompleteAuthenticationParams {
        credential_id: &credential_id,
        client_data_json: &client_data_json,
        authenticator_data: &authenticator_data,
        signature: &signature,
        user_handle: uh_vec.as_deref(),
        origin: &body.origin,
    };
    match state
        .identity
        .complete_webauthn_authentication(&realm_id, &params)
    {
        Ok(result) => (
            StatusCode::OK,
            Json(WbaCompleteRes {
                credential_id: b64_encode(result.credential_id()),
                user_id: result.user_id().to_string(),
                sign_count: result.sign_count(),
            }),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

async fn webauthn_list_credentials(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let user_id = match extract_user_auth(&headers, &state, &realm_id) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    match state
        .identity
        .list_webauthn_credentials(&realm_id, &user_id)
    {
        Ok(creds) => (
            StatusCode::OK,
            Json(WbCredsRes {
                credentials: creds
                    .into_iter()
                    .map(|c| WbCredEntry {
                        credential_id: b64_encode(c.credential_id()),
                        algorithm: c.algorithm(),
                        discoverable: c.discoverable(),
                    })
                    .collect(),
            }),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

async fn webauthn_delete_credential(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(credential_id_b64): Path<String>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let user_id = match extract_user_auth(&headers, &state, &realm_id) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    let credential_id = match b64_decode(&credential_id_b64) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    match state
        .identity
        .revoke_webauthn_credential(&realm_id, &user_id, &credential_id)
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// Query parameters for the magic-link request.
#[derive(Deserialize)]
struct MagicLinkRequestBody {
    email: String,
}

/// POST /v1/{realm}/auth/magic-link
///
/// Requests a magic-link login email. Always returns 202 regardless of whether
/// the email is registered (enumeration resistance). Returns 429 when the
/// caller's IP has exceeded the per-IP rate limit.
async fn magic_link_request(
    State(state): State<Arc<AppState>>,
    Path(realm_name): Path<String>,
    headers: HeaderMap,
    Json(body): Json<MagicLinkRequestBody>,
) -> impl IntoResponse {
    let realm_id = match resolve_realm_by_name(&state, &realm_name) {
        Ok(id) => id,
        Err(e) => return e,
    };

    // Per-IP rate limit. Real IP arrives via X-Forwarded-For in production;
    // FALLBACK_PEER is used when ConnectInfo is unavailable (tests).
    let client_ip =
        crate::protocol::client_info::extract_client_ip(&headers, FALLBACK_PEER, &state.trusted_proxies);
    if state
        .identity
        .check_ip_login_rate_limit(&realm_id, &client_ip)
        .is_err()
    {
        let retry_after = state
            .identity
            .ip_login_retry_after_secs(&realm_id, &client_ip);
        return make_ip_rate_limit_response(retry_after as u32);
    }

    // Request magic link; ignore per-email RateLimited to prevent enumeration.
    let _ = state.identity.request_magic_link(&realm_id, &body.email);

    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "message": "If an account exists, a magic link has been sent"
        })),
    )
        .into_response()
}
