//! OAuth 2.0, OIDC, and related endpoints.

#![allow(clippy::too_many_lines)]

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::audit::CreateAuditEvent;
use crate::core::{ClientId, RealmId, UserId};
use crate::identity::{JwtBearerRequest, PasswordGrantRequest, StepUpMfaGrantRequest};
use crate::protocol::client_info::extract_client_ip;
use crate::protocol::convert::oauth::{
    proto_authorize_to_domain, proto_client_creds_to_domain, proto_token_exchange_to_domain,
};
use crate::protocol::proto::identity::v1 as pb;

use super::now_micros;
use super::{
    check_token_rate_limit, extract_bearer_token, extract_realm_id, extract_user_auth,
    identity_error_to_response, make_ip_rate_limit_response, proto_to_rest_json,
    rbac_error_to_response, resolve_realm_by_name, AppState, FALLBACK_PEER,
};

/// Registers global OAuth/OIDC routes.
pub(super) fn routes() -> axum::Router<Arc<AppState>> {
    use axum::extract::DefaultBodyLimit;
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/.well-known/openid-configuration", get(oidc_discovery))
        .route(
            "/.well-known/oauth-protected-resource",
            get(protected_resource_metadata),
        )
        .route("/jwks", get(jwks))
        .route("/certs", get(jwks))
        .route("/.well-known/jwks.json", get(jwks))
        .route("/clients", post(register_client))
        .route(
            "/register",
            post(register_client_dynamic)
                .route_layer(DefaultBodyLimit::max(super::BODY_LIMIT_SMALL)),
        )
        .route("/authorize", post(authorize))
        .route(
            "/as/par",
            post(pushed_authorization_request)
                .route_layer(DefaultBodyLimit::max(super::BODY_LIMIT_SMALL)),
        )
        .route("/token", post(token_exchange).options(token_preflight))
        .route(
            "/revoke",
            post(token_revocation)
                .options(token_preflight)
                .route_layer(DefaultBodyLimit::max(super::BODY_LIMIT_SMALL)),
        )
        .route(
            "/introspect",
            post(token_introspection)
                .options(token_preflight)
                .route_layer(DefaultBodyLimit::max(super::BODY_LIMIT_SMALL)),
        )
        .route(
            "/device_authorization",
            post(device_authorization).options(token_preflight),
        )
        .route("/userinfo", get(userinfo))
        .route("/v1/me/permissions", get(me_permissions))
        .route(
            "/oauth/authorize",
            post(oauth_decide_permission)
                .route_layer(DefaultBodyLimit::max(super::BODY_LIMIT_SMALL)),
        )
        .route("/oauth/consents", get(self_list_consents))
        .route(
            "/oauth/consents/{client_id}",
            axum::routing::delete(self_revoke_consent),
        )
}

/// Registers realm-scoped OAuth/OIDC routes (mounted under `/realms/{realm_name}`).
pub(super) fn realm_routes() -> axum::Router<Arc<AppState>> {
    use axum::extract::DefaultBodyLimit;
    use axum::routing::{get, post};
    axum::Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(realm_oidc_discovery),
        )
        .route("/.well-known/jwks.json", get(realm_jwks))
        .route(
            "/authorize",
            get(realm_authorize_browser_redirect).post(realm_authorize),
        )
        .route(
            "/as/par",
            post(realm_pushed_authorization_request)
                .route_layer(DefaultBodyLimit::max(super::BODY_LIMIT_SMALL)),
        )
        .route(
            "/token",
            post(realm_token_exchange).options(realm_token_preflight),
        )
        .route(
            "/revoke",
            post(realm_token_revocation)
                .options(realm_token_preflight)
                .route_layer(DefaultBodyLimit::max(super::BODY_LIMIT_SMALL)),
        )
        .route(
            "/introspect",
            post(realm_token_introspection)
                .options(realm_token_preflight)
                .route_layer(DefaultBodyLimit::max(super::BODY_LIMIT_SMALL)),
        )
        .route(
            "/device_authorization",
            post(realm_device_authorization).options(realm_token_preflight),
        )
        .route("/userinfo", get(realm_userinfo))
        .route(
            "/register",
            post(realm_register_client_dynamic)
                .route_layer(DefaultBodyLimit::max(super::BODY_LIMIT_SMALL)),
        )
}

/// Response body for `GET /v1/me/permissions`.
#[derive(Debug, Serialize)]
struct MePermissionsResponse {
    roles: Vec<String>,
    groups: Vec<String>,
    permissions: Vec<String>,
    scope: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Handler implementations extracted verbatim from src/protocol/http.rs
// ─────────────────────────────────────────────────────────────────────────────
async fn oidc_discovery(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // A-10: per-IP rate cap on all key-discovery endpoints.
    let client_ip = extract_client_ip(&headers, FALLBACK_PEER, &state.trusted_proxies);
    let now_micros = now_micros();
    if !state.jwks_rate_limiter.check(&client_ip, now_micros) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", "1")],
            Json(serde_json::json!({"error": "too_many_requests"})),
        )
            .into_response();
    }
    // Serialize the domain type directly so optional fields like
    // end_session_endpoint are included without proto schema changes.
    let doc = state.identity.oidc_discovery();
    (StatusCode::OK, Json(doc)).into_response()
}

/// Protected Resource Metadata endpoint (RFC 9728 §3, AGENT_AUTH.md §2.4 / B.3).
///
/// Returns Hearth's own PRM document at `/.well-known/oauth-protected-resource`.
/// MCP clients use this to discover which authorization server to use and
/// which scopes Hearth itself exposes.
async fn protected_resource_metadata(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let discovery = state.identity.oidc_discovery();
    let doc = serde_json::json!({
        "resource": discovery.issuer,
        "authorization_servers": [discovery.issuer],
        "jwks_uri": discovery.jwks_uri,
        "scopes_supported": [
            "openid",
            "profile",
            "email",
            "mcp:tools:invoke",
            "mcp:tools:list",
            "mcp:resources:read",
            "mcp:resources:write",
            "mcp:prompts:read",
        ],
        "bearer_methods_supported": ["header"],
        "resource_signing_alg_values_supported": ["EdDSA"],
    });
    (StatusCode::OK, Json(doc))
}

/// JWKS endpoint (`/jwks`, `/certs`, and `/.well-known/jwks.json`).
///
/// Returns the JSON Web Key Set containing the server's public signing
/// keys for external token verification, per RFC 7517. Includes one entry
/// per supported algorithm — Ed25519 (`EdDSA`) as the primary signer,
/// plus RSA-2048 (`RS256`) and EC P-256 (`ES256`) for ecosystem
/// compatibility with OIDC clients (e.g. `jose` / `python-jose`).
///
/// Renders the domain [`crate::identity::tokens::JwksDocument`] directly
/// as JSON, bypassing the proto `JsonWebKey` type — that proto only
/// carries the OKP/Ed25519 field set and would drop RSA `n`/`e` and EC
/// `y` coordinates.
///
/// A-10: subject to the per-IP JWKS rate cap (default 60 rps).
async fn jwks(State(state): State<Arc<AppState>>, headers: HeaderMap) -> impl IntoResponse {
    // A-10: per-IP rate cap.
    let client_ip = extract_client_ip(&headers, FALLBACK_PEER, &state.trusted_proxies);
    let now_micros = now_micros();
    if !state.jwks_rate_limiter.check(&client_ip, now_micros) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", "1")],
            Json(serde_json::json!({"error": "too_many_requests"})),
        )
            .into_response();
    }
    let doc = state.identity.jwks();
    (
        StatusCode::OK,
        [(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("max-age=3600, must-revalidate"),
        )],
        Json(doc),
    )
        .into_response()
}

/// HTTP request body for token exchange.
///
/// Uses a flat struct because the proto `TokenExchangeRequest` doesn't cover
/// the multi-grant-type dispatch (`authorization_code` vs `refresh_token`).
#[derive(Debug, Deserialize)]
struct HttpTokenRequest {
    client_id: String,
    #[serde(default)]
    grant_type: Option<String>,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    redirect_uri: Option<String>,
    #[serde(default)]
    code_verifier: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    // Client credentials fields
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    // Device code field
    #[serde(default)]
    device_code: Option<String>,
    // ROPC (password grant) fields — RFC 6749 §4.3
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    // Step-up MFA completion (HEA-836)
    #[serde(default)]
    mfa_code: Option<String>,
    // JWT Bearer assertion (RFC 7523)
    #[serde(default)]
    assertion: Option<String>,
    // private_key_jwt client authentication (RFC 7523 §2.2)
    #[serde(default)]
    client_assertion_type: Option<String>,
    #[serde(default)]
    client_assertion: Option<String>,
    // RFC 8693 Token Exchange fields
    #[serde(default)]
    subject_token: Option<String>,
    #[serde(default)]
    subject_token_type: Option<String>,
    #[serde(default)]
    actor_token: Option<String>,
    #[serde(default)]
    actor_token_type: Option<String>,
    #[serde(default)]
    requested_token_type: Option<String>,
    #[serde(default)]
    resource: Option<String>,
    #[serde(default)]
    audience: Option<String>,
}

/// HTTP request body for token revocation (RFC 7009).
///
/// Extends the proto type with optional client credentials for HTTP endpoints.
/// Clients may authenticate via HTTP Basic Auth or via these body fields
/// per RFC 6749 §2.3.1.
#[derive(Debug, Deserialize)]
struct HttpRevocationBody {
    token: String,
    #[serde(default)]
    token_type_hint: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
}

/// HTTP request body for token introspection (RFC 7662).
///
/// Extends the proto type with optional client credentials for HTTP endpoints.
/// Clients may authenticate via HTTP Basic Auth or via these body fields
/// per RFC 6749 §2.3.1.
#[derive(Debug, Deserialize)]
struct HttpIntrospectionBody {
    token: String,
    #[serde(default)]
    token_type_hint: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
}

/// Parses HTTP Basic Auth credentials from the `Authorization` header.
///
/// Returns `Some((client_id, client_secret))` on success, `None` if the header
/// is absent or not Basic Auth.
fn parse_basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let encoded = value.strip_prefix("Basic ")?;
    use base64::Engine as _;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let decoded_str = String::from_utf8(decoded).ok()?;
    let (id, secret) = decoded_str.split_once(':')?;
    Some((id.to_string(), secret.to_string()))
}

/// Extracts client credentials from HTTP Basic Auth or body parameters and
/// verifies them against the stored client record.
///
/// Returns the authenticated `ClientId` on success, or a 401 response if
/// client_id is missing, the client does not exist, or the secret is wrong.
/// Confidential clients require a secret; public clients are accepted with
/// client_id alone.
fn verify_endpoint_client(
    state: &AppState,
    realm_id: &RealmId,
    headers: &HeaderMap,
    body_client_id: Option<&str>,
    body_client_secret: Option<&str>,
) -> Result<ClientId, Response> {
    // Prefer Basic Auth (RFC 6749 §2.3.1); fall back to body parameters.
    let (raw_id, secret) = if let Some((id, sec)) = parse_basic_auth(headers) {
        (id, Some(sec))
    } else if let Some(id) = body_client_id {
        (id.to_string(), body_client_secret.map(str::to_string))
    } else {
        return Err((
            StatusCode::UNAUTHORIZED,
            [("www-authenticate", "Basic realm=\"hearth\"")],
            Json(serde_json::json!({"error": "client_id required"})),
        )
            .into_response());
    };

    // RFC 6749 §5.2: the `error` field MUST be a registered code. Use
    // `invalid_client` uniformly across every arm that authenticates the
    // endpoint client (client_credentials, token-exchange, revoke, introspect)
    // so strict OAuth clients recognize the failure and so this path matches the
    // code/refresh arms — a single opaque code also avoids the enumeration
    // oracle documented in `http::auth::identity_error_to_response`.
    let client_uuid = raw_id.parse::<uuid::Uuid>().map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid_client"})),
        )
            .into_response()
    })?;
    let client_id = ClientId::new(client_uuid);

    state
        .identity
        .authenticate_client(realm_id, &client_id, secret.as_deref())
        .map(|()| client_id)
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "invalid_client"})),
            )
                .into_response()
        })
}

/// Enforces confidential-client authentication on the `authorization_code`
/// exchange arm (O2, HEA-1755).
///
/// The code-exchange path never verified `client_secret`, so a confidential
/// client's authorization code could be redeemed without proving possession of
/// the secret. This checks the secret when — and only when — the request names a
/// registered confidential client:
/// - unparseable or unknown `client_id` → `Ok(())`, so the exchange itself
///   surfaces `invalid_grant` for the (bad) code rather than leaking client
///   existence via a differing error;
/// - public clients (no `client_secret_hash`) → `Ok(())`, since PKCE alone
///   authenticates them (RFC 9700 §2.1.1);
/// - confidential clients → the secret (HTTP Basic Auth preferred, body
///   `client_secret` fallback) must verify, else `Err` with a 401.
fn enforce_confidential_client_auth(
    state: &AppState,
    realm_id: &RealmId,
    headers: &HeaderMap,
    body_client_id: &str,
    body_client_secret: Option<&str>,
) -> Result<(), Response> {
    let Ok(uuid) = body_client_id.parse::<uuid::Uuid>() else {
        return Ok(());
    };
    let client_id = ClientId::new(uuid);
    let client = match state.identity.get_client(realm_id, &client_id) {
        Ok(Some(c)) => c,
        Ok(None) => return Ok(()),
        Err(e) => return Err(identity_error_to_response(&e).into_response()),
    };
    if !client.is_confidential() {
        return Ok(());
    }
    // Confidential client: a valid secret is mandatory. Prefer HTTP Basic Auth
    // credentials (RFC 6749 §2.3.1), fall back to the body `client_secret`.
    let secret = parse_basic_auth(headers)
        .map(|(_, s)| s)
        .or_else(|| body_client_secret.map(str::to_string));
    state
        .identity
        .authenticate_client(realm_id, &client_id, secret.as_deref())
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                [("www-authenticate", "Basic realm=\"hearth\"")],
                Json(serde_json::json!({
                    "error": "invalid_client",
                    "error_description": "client authentication failed"
                })),
            )
                .into_response()
        })
}

/// Returns the CORS `Access-Control-Allow-Origin` value for `origin` if it
/// matches an entry in the client's dedicated `cors_origins` allowlist.
///
/// Deliberately does NOT fall back to `redirect_uris` — those serve a
/// different security purpose (post-auth redirect target validation) and must
/// not implicitly grant cross-origin token-endpoint access.
fn cors_origin_for_client(
    state: &AppState,
    realm_id: &RealmId,
    client_id: &ClientId,
    request_origin: &str,
) -> Option<axum::http::HeaderValue> {
    let client = state.identity.get_client(realm_id, client_id).ok()??;
    let origin_base = extract_origin_base(request_origin)?;
    let allowed = client.cors_origins().iter().any(|allowed_origin| {
        extract_origin_base(allowed_origin)
            .map(|base| base == origin_base)
            .unwrap_or(false)
    });
    if allowed {
        axum::http::HeaderValue::from_str(request_origin).ok()
    } else {
        None
    }
}

/// Extracts `scheme://host[:port]` from a URI string.
fn extract_origin_base(uri: &str) -> Option<String> {
    // Fast path: find "://" then take up to the next "/"
    let after_scheme = uri.find("://")?;
    let rest = &uri[after_scheme + 3..];
    let host_end = rest.find('/').unwrap_or(rest.len());
    let host = &rest[..host_end];
    Some(format!("{}://{host}", &uri[..after_scheme]))
}

/// Appends CORS headers to `response` when the request `Origin` is authorised
/// for the given authenticated client.
fn apply_cors_to_response(
    resp: &mut Response,
    state: &AppState,
    realm_id: &RealmId,
    client_id: &ClientId,
    request_headers: &HeaderMap,
) {
    let Some(origin_val) = request_headers.get(axum::http::header::ORIGIN) else {
        return;
    };
    let Ok(origin_str) = origin_val.to_str() else {
        return;
    };
    if let Some(allow_origin) = cors_origin_for_client(state, realm_id, client_id, origin_str) {
        let h = resp.headers_mut();
        h.insert(
            axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
            allow_origin,
        );
        // Deliberately omit Access-Control-Allow-Credentials: PKCE token flows
        // use authorization codes, not cookies.
    }
}

/// Handles `OPTIONS` preflight for token endpoints.
///
/// Always returns `204 No Content` with the same CORS preflight headers
/// regardless of whether the requesting `Origin` is registered. This closes
/// the CORS-oracle information-disclosure: previously the presence or absence
/// of `Access-Control-Allow-Origin` in the 204 revealed which origins have
/// registered clients (OAUTH-10 / HEA-SEC-28).
///
/// The actual origin-allowlist check lives in `append_cors_headers`, which is
/// called on every POST /token response. The browser's Same-Origin Policy
/// enforces the real boundary: an unregistered origin receives a 204 preflight
/// here but then gets no `Access-Control-Allow-Origin` on the actual response,
/// so the browser blocks it. Non-browser clients bypass preflights entirely.
async fn token_options_preflight(
    State(_state): State<Arc<AppState>>,
    headers: HeaderMap,
    _realm_id: RealmId,
) -> Response {
    build_cors_preflight_response(headers.get(axum::http::header::ORIGIN))
}

/// Constructs a uniform CORS preflight 204 response.
///
/// Reflects the requesting `Origin` back as `Access-Control-Allow-Origin` when
/// present and valid. Response structure is identical for registered and
/// unregistered origins, preventing origin enumeration (HEA-SEC-28 / OAUTH-10).
fn build_cors_preflight_response(origin: Option<&axum::http::HeaderValue>) -> Response {
    let mut resp = StatusCode::NO_CONTENT.into_response();
    let h = resp.headers_mut();
    h.insert(
        axum::http::header::ACCESS_CONTROL_ALLOW_METHODS,
        axum::http::HeaderValue::from_static("POST, OPTIONS"),
    );
    h.insert(
        axum::http::HeaderName::from_static("access-control-allow-headers"),
        axum::http::HeaderValue::from_static("Authorization, Content-Type"),
    );
    // Deliberately omit Access-Control-Allow-Credentials: PKCE token flows
    // use authorization codes, not cookies.
    h.insert(
        axum::http::HeaderName::from_static("access-control-max-age"),
        axum::http::HeaderValue::from_static("86400"),
    );
    // Reflect the requesting origin unconditionally. The actual enforcement
    // (allowlist check) happens in append_cors_headers on POST /token.
    if let Some(origin_hv) = origin {
        if let Ok(hv) = axum::http::HeaderValue::try_from(origin_hv.as_bytes()) {
            h.insert(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN, hv);
        }
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CORS oracle fix (HEA-SEC-28 / OAUTH-10): OPTIONS preflight MUST return
    /// identical header structure regardless of origin registration status.
    ///
    /// Before this fix the handler returned a bare 204 for unregistered origins
    /// and a 204 + CORS headers for registered ones, leaking which origins have
    /// clients.
    #[test]
    fn preflight_identical_for_any_origin() {
        let registered = axum::http::HeaderValue::from_static("https://registered.example.com");
        let unregistered = axum::http::HeaderValue::from_static("https://unknown.attacker.com");

        let r_reg = build_cors_preflight_response(Some(&registered));
        let r_unreg = build_cors_preflight_response(Some(&unregistered));
        let r_none = build_cors_preflight_response(None);

        assert_eq!(r_reg.status(), StatusCode::NO_CONTENT);
        assert_eq!(r_unreg.status(), StatusCode::NO_CONTENT);
        assert_eq!(r_none.status(), StatusCode::NO_CONTENT);

        for name in &[
            "access-control-allow-methods",
            "access-control-allow-headers",
            "access-control-max-age",
        ] {
            assert_eq!(
                r_reg.headers().get(*name),
                r_unreg.headers().get(*name),
                "header {name} must be identical for registered and unregistered origins"
            );
        }

        assert_eq!(
            r_reg
                .headers()
                .get(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .map(|v| v.as_bytes()),
            Some(registered.as_bytes()),
        );
        assert_eq!(
            r_unreg
                .headers()
                .get(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .map(|v| v.as_bytes()),
            Some(unregistered.as_bytes()),
        );
        assert!(
            r_none
                .headers()
                .get(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none(),
            "no-origin request must not get Access-Control-Allow-Origin"
        );
    }
}

/// `OPTIONS /token` — CORS preflight.
async fn token_preflight(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Ok(realm_id) = extract_realm_id(&headers) else {
        return StatusCode::NO_CONTENT.into_response();
    };
    token_options_preflight(State(state), headers, realm_id).await
}

/// `OPTIONS /realms/{realm}/token` — CORS preflight.
async fn realm_token_preflight(
    State(state): State<Arc<AppState>>,
    Path(realm_name): Path<String>,
    headers: HeaderMap,
) -> Response {
    let realm_id = match resolve_realm_by_name(&state, &realm_name) {
        Ok(id) => id,
        Err(_) => return StatusCode::NO_CONTENT.into_response(),
    };
    token_options_preflight(State(state), headers, realm_id).await
}

/// Register an OAuth 2.0 client (privileged admin API).
///
/// Requires `X-Realm-ID` header and an admin bearer token carrying
/// `hearth.clients.admin` (or `hearth.admin`). Unauthenticated dynamic
/// registration is served by `POST /register`, which is gated by the realm's
/// `dcr_policy`. HEA-1750 (A1): this handler previously skipped both gates,
/// letting anyone mint OAuth clients — it now enforces the same authorization
/// as the `/admin/clients` handler.
async fn register_client(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<pb::RegisterClientRequest>,
) -> impl IntoResponse {
    let auth = match super::extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = super::require_admin_permission(&auth, "hearth.clients.admin") {
        return e.into_response();
    }

    let mut request = crate::identity::RegisterClientRequest::from(body);
    request.client_secret = None;

    match state.identity.register_client(&auth.realm_id, &request) {
        Ok(client) => {
            let _ = state.audit.append(&CreateAuditEvent {
                realm_id: auth.realm_id.clone(),
                actor: auth.user_id.as_uuid().to_string(),
                action: crate::audit::AuditAction::ClientRegistered,
                resource_type: "client".to_string(),
                resource_id: client.client_id().as_uuid().to_string(),
                metadata: Some(serde_json::json!({"via": "clients_api"})),
            });
            (
                StatusCode::CREATED,
                Json(proto_to_rest_json(&pb::OAuthClient::from(&client))),
            )
                .into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// RFC 7591 Dynamic Client Registration response.
#[derive(Debug, Serialize)]
struct DcrResponse {
    client_id: String,
    client_secret: String,
    client_name: String,
    redirect_uris: Vec<String>,
    grant_types: Vec<String>,
    client_secret_expires_at: u64,
    token_endpoint_auth_method: String,
    client_id_issued_at: i64,
}

/// Dynamic Client Registration (RFC 7591) endpoint.
///
/// Accepts `POST /register` with `X-Realm-ID` header. The realm's
/// `dcr_policy` must be `Open` — returns 403 otherwise. The server
/// generates a random client secret and slug; the client does not
/// supply these. Returns an RFC 7591-compatible JSON response.
async fn register_client_dynamic(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<pb::RegisterClientRequest>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    // Look up the realm to check DCR policy.
    let realm = match state.identity.get_realm(&realm_id) {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "realm not found"})),
            )
                .into_response();
        }
        Err(e) => return identity_error_to_response(&e).into_response(),
    };

    let dcr_policy = realm.config().dcr_policy.clone().unwrap_or_default();

    match dcr_policy {
        crate::identity::DcrPolicy::Disabled => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error": "dynamic client registration is disabled for this realm"})),
            )
                .into_response();
        }
        crate::identity::DcrPolicy::Open => {
            tracing::warn!(
                realm_id = %realm_id.as_uuid(),
                "Open DCR policy allows unauthenticated client registration; \
                 consider switching to `authenticated` mode"
            );
        }
        crate::identity::DcrPolicy::Authenticated => {
            let token = match extract_bearer_token(&headers) {
                Ok(t) => t,
                Err((status, body)) => return (status, body).into_response(),
            };
            if state.identity.validate_token(&realm_id, &token).is_err() {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({
                        "error": "unauthorized",
                        "error_description": "a valid bearer token is required to register clients in this realm"
                    })),
                )
                    .into_response();
            }
        }
    }

    // Strip any client-supplied secret — the server generates its own.
    let mut request = crate::identity::RegisterClientRequest::from(body);
    request.client_secret = None;

    // Generate server-side random secret.
    use base64::Engine as _;
    use ring::rand::SecureRandom;
    let rng = ring::rand::SystemRandom::new();
    let mut secret_bytes = [0u8; 32];
    #[allow(clippy::unwrap_used)]
    // INVARIANT: SystemRandom::fill fails only on catastrophic OS RNG failure.
    rng.fill(&mut secret_bytes).unwrap();
    let generated_secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret_bytes);
    request.client_secret = Some(generated_secret.clone());

    // Force ThirdParty trust and consent for DCR-registered clients.
    request.trust_level = crate::identity::ClientTrustLevel::ThirdParty;
    request.require_consent = true;

    // Generate a unique slug: base name + random hex suffix.
    let base_slug = request.client_name.to_lowercase().replace(' ', "-");
    let slug = generate_unique_slug(state.clone(), &realm_id, &base_slug).await;
    request.slug = Some(slug);

    match state.identity.register_client(&realm_id, &request) {
        Ok(client) => {
            let _ = state.audit.append(&CreateAuditEvent {
                realm_id: realm_id.clone(),
                actor: "anonymous".to_string(),
                action: crate::audit::AuditAction::ClientRegistered,
                resource_type: "client".to_string(),
                resource_id: client.client_id().as_uuid().to_string(),
                metadata: Some(serde_json::json!({"via": "dynamic_registration"})),
            });

            let response = DcrResponse {
                client_id: client.client_id().as_uuid().to_string(),
                client_secret: generated_secret,
                client_name: client.client_name().to_string(),
                redirect_uris: client.redirect_uris().to_vec(),
                grant_types: client.grant_types().to_vec(),
                client_secret_expires_at: 0,
                token_endpoint_auth_method: "client_secret_basic".to_string(),
                #[allow(clippy::cast_possible_truncation)]
                client_id_issued_at: client.created_at().as_micros() / 1_000_000,
            };

            (
                StatusCode::CREATED,
                Json(serde_json::to_value(response).unwrap_or_default()),
            )
                .into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// Generates a unique client slug for DCR by appending a random suffix to the
/// base name. Scans existing clients to avoid collisions, retrying up to 5
/// times.
#[allow(dead_code)]
async fn generate_unique_slug(state: Arc<AppState>, realm_id: &RealmId, base: &str) -> String {
    for _ in 0..5 {
        let suffix = uuid::Uuid::new_v4().to_string();
        let candidate = format!("{base}-{}", &suffix[..8]);

        // Check for collision against existing clients.
        match state.identity.list_clients(
            realm_id,
            &crate::core::PageRequest::new(0, crate::core::MAX_PAGE_LIMIT),
        ) {
            Ok(page) => {
                let collision = page.items.iter().any(|c| c.slug() == candidate);
                if !collision {
                    return candidate;
                }
            }
            Err(_) => {
                // If listing fails, use the candidate anyway — low collision
                // probability makes this acceptable.
                return candidate;
            }
        }
    }

    // After 5 retries, use the last attempt. The 8-hex-char suffix provides
    // ~2^32 collision space — retries are a belt-and-suspenders guard.
    let suffix = uuid::Uuid::new_v4().to_string();
    format!("{base}-{}", &suffix[..8])
}

/// Initiate an OAuth 2.0 authorization code flow.
///
/// Requires `X-Realm-ID` header and a valid Bearer token. The token's `sub`
/// claim determines the user on whose behalf the code is issued — the caller
/// cannot supply an arbitrary `user_id` (HEA-1721).
async fn authorize(
    State(state): State<Arc<AppState>>,
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    Json(body): Json<pb::AuthorizationRequest>,
) -> impl IntoResponse {
    use crate::identity::{AuthorizationRequest, IdentityError};

    let realm_id = match extract_realm_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    // HEA-1721: authenticate the caller; their token's `sub` is the authoritative
    // user identity.  The body's `user_id` field is ignored to prevent unauthenticated
    // account takeover via caller-supplied user IDs.
    let htu = format!("{}{}", state.identity.oidc_discovery().issuer, uri.path());
    let authenticated_user_id =
        match extract_user_auth(&headers, &state, &realm_id, method.as_str(), &htu) {
            Ok(uid) => uid,
            Err(e) => return e.into_response(),
        };

    // PAR path: when `request_uri` is present, consume the stored entry to
    // obtain the pre-validated parameters and set `via_par = true`.
    let request = if let Some(ref request_uri) = body.request_uri {
        let stored = match state.identity.consume_par(&realm_id, request_uri) {
            Ok(s) => s,
            Err(IdentityError::InvalidPushedAuthorizationRequest) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_request",
                        "error_description": "invalid or expired request_uri"
                    })),
                )
                    .into_response();
            }
            Err(e) => {
                tracing::warn!(error = %e, "consume_par failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };

        // RFC 9126 §4: if client_id is present in the request body, it MUST
        // match the client_id stored in the PAR entry.
        if !body.client_id.is_empty() {
            let body_client_id = match uuid::Uuid::parse_str(&body.client_id) {
                Ok(u) => ClientId::new(u),
                Err(_) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "error": "invalid_request",
                            "error_description": "invalid client_id"
                        })),
                    )
                        .into_response();
                }
            };
            if body_client_id != stored.client_id {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_request",
                        "error_description": "client_id mismatch with pushed authorization request"
                    })),
                )
                    .into_response();
            }
        }

        AuthorizationRequest {
            client_id: stored.client_id,
            redirect_uri: stored.redirect_uri,
            scope: stored.scope,
            state: stored.state,
            resource: stored.resource,
            response_type: stored.response_type,
            user_id: authenticated_user_id,
            code_challenge: stored.code_challenge,
            code_challenge_method: stored.code_challenge_method,
            nonce: stored.nonce,
            amr_values: Vec::new(),
            response_mode: None,
            request: None,
            via_par: true,
        }
    } else {
        let r = match proto_authorize_to_domain(body) {
            Ok(r) => r,
            Err(msg) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": msg})),
                )
                    .into_response();
            }
        };
        // Override body-supplied user_id with the authenticated identity (HEA-1721).
        AuthorizationRequest {
            user_id: authenticated_user_id,
            ..r
        }
    };

    match state.identity.authorize(&realm_id, &request) {
        Ok(response) => (
            StatusCode::OK,
            Json(proto_to_rest_json(&pb::AuthorizationResponse::from(
                &response,
            ))),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// HTTP request body for a Pushed Authorization Request (RFC 9126).
#[derive(Debug, serde::Deserialize)]
struct HttpParRequest {
    client_id: String,
    redirect_uri: String,
    #[serde(default)]
    scope: String,
    #[serde(default)]
    state: String,
    resource: Option<String>,
    #[serde(default = "default_response_type")]
    response_type: String,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    nonce: Option<String>,
    /// Signed JAR JWT (RFC 9101) — required for FAPI Advanced.
    request: Option<String>,
    response_mode: Option<String>,
}

fn default_response_type() -> String {
    "code".to_string()
}

/// Push authorization parameters (RFC 9126) — header-realm variant.
async fn pushed_authorization_request(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<HttpParRequest>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    par_handler(&state, &realm_id, body).await.into_response()
}

/// Push authorization parameters (RFC 9126) — realm-scoped via path.
async fn realm_pushed_authorization_request(
    State(state): State<Arc<AppState>>,
    Path(realm_name): Path<String>,
    Json(body): Json<HttpParRequest>,
) -> impl IntoResponse {
    let realm_id = match resolve_realm_by_name(&state, &realm_name) {
        Ok(id) => id,
        Err(e) => return e,
    };
    par_handler(&state, &realm_id, body).await.into_response()
}

async fn par_handler(
    state: &AppState,
    realm_id: &crate::core::RealmId,
    body: HttpParRequest,
) -> impl IntoResponse {
    use crate::identity::{CodeChallengeMethod, PushedAuthorizationRequest};

    let client_id = match body.client_id.parse::<uuid::Uuid>() {
        Ok(u) => crate::core::ClientId::new(u),
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid_client", "error_description": "invalid client_id"})),
            )
                .into_response();
        }
    };

    let code_challenge_method = match body.code_challenge_method.as_deref() {
        Some("S256") => Some(CodeChallengeMethod::S256),
        Some(m) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid_request", "error_description": format!("unsupported code_challenge_method: {m}")})),
            )
                .into_response();
        }
        None => None,
    };

    let request = PushedAuthorizationRequest {
        client_id,
        redirect_uri: body.redirect_uri,
        scope: body.scope,
        state: body.state,
        resource: body.resource,
        response_type: body.response_type,
        code_challenge: body.code_challenge,
        code_challenge_method,
        nonce: body.nonce,
        request: body.request,
        response_mode: body.response_mode,
    };

    match state
        .identity
        .push_authorization_request(realm_id, &request)
    {
        Ok(resp) => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "request_uri": resp.request_uri,
                "expires_in": resp.expires_in,
            })),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// Exchange an authorization code or refresh token for tokens.
///
/// Requires `X-Realm-ID` header.
///
/// Supports multiple grant types:
/// - `authorization_code` (default): exchange a code for access, ID, and refresh tokens
/// - `refresh_token`: exchange a refresh token for a new token pair
/// - `client_credentials`: issue an access token for a confidential client
/// - `urn:ietf:params:oauth:grant-type:device_code`: poll for device authorization
async fn token_exchange(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<HttpTokenRequest>,
) -> Response {
    // Parse client_id and realm_id before dispatch so CORS can be applied to
    // every response path, including grant-type-specific error branches.
    let maybe_client_id = body.client_id.parse::<uuid::Uuid>().ok().map(ClientId::new);
    let maybe_realm_id = extract_realm_id(&headers).ok();

    let mut resp = token_exchange_impl(Arc::clone(&state), headers.clone(), body).await;

    if let (Some(ref realm_id), Some(ref client_id)) = (&maybe_realm_id, &maybe_client_id) {
        apply_cors_to_response(&mut resp, &state, realm_id, client_id, &headers);
    }

    // RFC 9449 §9: always return DPoP-Nonce so clients can use it in the next proof.
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let nonce = maybe_realm_id
        .as_ref()
        .and_then(|rid| state.identity.get_realm_dpop_nonce_secret(rid).ok())
        .map(|s| crate::identity::dpop::current_dpop_nonce(&s, now_secs))
        .unwrap_or_else(|| state.dpop.current_nonce(now_secs));
    if let Ok(val) = axum::http::HeaderValue::from_str(&nonce) {
        resp.headers_mut().insert("DPoP-Nonce", val);
    }

    resp
}

/// Inner implementation of [`token_exchange`].
///
/// Separated from the outer handler so that CORS application can wrap all
/// exit paths without touching every early-return site.
#[allow(clippy::too_many_lines)]
async fn token_exchange_impl(
    state: Arc<AppState>,
    headers: HeaderMap,
    body: HttpTokenRequest,
) -> Response {
    let realm_id = match extract_realm_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    // Rate limit per client_id before any grant-type dispatch.
    if let Ok(client_uuid) = body.client_id.parse::<uuid::Uuid>() {
        let client_id = ClientId::new(client_uuid);
        if let Err(resp) = check_token_rate_limit(&state, &realm_id, &client_id) {
            return resp;
        }
    }

    let grant_type = body.grant_type.as_deref().unwrap_or("authorization_code");

    // Per-IP rate limiting for the ROPC password grant and step-up-mfa grant.
    // In production traffic goes through a reverse proxy so the real IP
    // arrives via X-Forwarded-For; FALLBACK_PEER is used when ConnectInfo is
    // unavailable (e.g. tower::ServiceExt::oneshot in tests).
    let client_ip = extract_client_ip(&headers, FALLBACK_PEER, &state.trusted_proxies);
    if (grant_type == "password" || grant_type == "urn:hearth:params:grant-type:step-up-mfa")
        && state
            .identity
            .check_ip_login_rate_limit(&realm_id, &client_ip)
            .is_err()
    {
        let retry_after = state
            .identity
            .ip_login_retry_after_secs(&realm_id, &client_ip);
        return make_ip_rate_limit_response(retry_after as u32);
    }

    // Extract and validate DPoP proof if present (RFC 9449).
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let dpop_jkt: Option<String> =
        if let Some(proof) = headers.get("DPoP").and_then(|v| v.to_str().ok()) {
            let expected_htu = state.identity.oidc_discovery().token_endpoint.clone();
            match crate::identity::dpop::validate_dpop_proof(
                proof,
                "POST",
                &expected_htu,
                now_secs,
                None,
                None, // token endpoint: no access_token to bind yet
            ) {
                Ok(validated) => {
                    // RFC 9449 §9.1: nonce is mandatory — server always issues a
                    // DPoP-Nonce header, so the client must include it on every proof.
                    // Two-window acceptance (current + previous) handles clock drift
                    // across the 5-minute rotation boundary.
                    let nonce_valid = match validated.nonce.as_deref() {
                        None => false,
                        Some(n) => state
                            .identity
                            .get_realm_dpop_nonce_secret(&realm_id)
                            .ok()
                            .map(|s| crate::identity::dpop::is_valid_dpop_nonce(&s, n, now_secs))
                            .unwrap_or_else(|| state.dpop.is_valid_nonce(n, now_secs)),
                    };
                    if !nonce_valid {
                        return identity_error_to_response(
                            &crate::identity::error::IdentityError::DPopNonceInvalid,
                        )
                        .into_response();
                    }
                    if let Err(e) = state.identity.check_and_record_dpop_jti(
                        &realm_id,
                        &validated.jti,
                        now_secs,
                    ) {
                        return identity_error_to_response(&e).into_response();
                    }
                    Some(validated.jkt)
                }
                Err(e) => return identity_error_to_response(&e).into_response(),
            }
        } else {
            None
        };

    match grant_type {
        "authorization_code" => {
            // O2 (HEA-1755): confidential clients must authenticate on the
            // code-exchange arm; public (PKCE) clients and unknown clients pass
            // through unchanged.
            if let Err(resp) = enforce_confidential_client_auth(
                &state,
                &realm_id,
                &headers,
                &body.client_id,
                body.client_secret.as_deref(),
            ) {
                return resp;
            }

            let (Some(code), Some(redirect_uri)) = (body.code, body.redirect_uri) else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "code and redirect_uri required for authorization_code grant"})),
                )
                    .into_response();
            };

            let proto_req = pb::TokenExchangeRequest {
                client_id: body.client_id,
                code,
                redirect_uri,
                code_verifier: body.code_verifier,
            };

            let mut request = match proto_token_exchange_to_domain(&proto_req) {
                Ok(r) => r,
                Err(msg) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": msg})),
                    )
                        .into_response();
                }
            };
            request.dpop_jkt = dpop_jkt.clone();
            request.client_assertion_type = body.client_assertion_type;
            request.client_assertion = body.client_assertion;

            match state
                .identity
                .exchange_authorization_code(&realm_id, &request)
            {
                Ok(response) => {
                    crate::metrics::metrics()
                        .tokens_issued_total
                        .with_label_values(&[
                            realm_id.as_uuid().to_string().as_str(),
                            "authorization_code",
                        ])
                        .inc();
                    crate::metrics::metrics().active_sessions.inc();
                    let mut token_resp = pb::OidcTokenResponse::from(&response);
                    if dpop_jkt.is_some() {
                        token_resp.token_type = "DPoP".to_string();
                    }
                    (StatusCode::OK, Json(proto_to_rest_json(&token_resp))).into_response()
                }
                Err(e) => identity_error_to_response(&e).into_response(),
            }
        }
        "refresh_token" => {
            let Some(refresh_token) = body.refresh_token else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "refresh_token required for refresh_token grant"})),
                )
                    .into_response();
            };

            // O1 (HEA-1755): authenticate the presenting client. Confidential
            // clients MUST supply a valid secret; public clients are identified
            // by client_id alone. The engine binds the grant family to this
            // authenticated identity in rotate_grant_family. Requests with no
            // client_id and no Basic Auth (legacy session refresh) pass through
            // unauthenticated — those grant families carry no client binding.
            let authenticated_client_id =
                if parse_basic_auth(&headers).is_some() || !body.client_id.trim().is_empty() {
                    match verify_endpoint_client(
                        &state,
                        &realm_id,
                        &headers,
                        Some(body.client_id.as_str()),
                        body.client_secret.as_deref(),
                    ) {
                        Ok(cid) => Some(cid),
                        Err(resp) => return resp,
                    }
                } else {
                    None
                };

            let refresh_bind = crate::identity::RefreshBindContext {
                user_agent: headers
                    .get(axum::http::header::USER_AGENT)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string),
                asn: None,
                authenticated_client_id,
            };

            match state.identity.refresh_tokens(
                &realm_id,
                &refresh_token,
                dpop_jkt.as_deref(),
                Some(&refresh_bind),
            ) {
                Ok(tokens) => {
                    crate::metrics::metrics()
                        .tokens_issued_total
                        .with_label_values(&[
                            realm_id.as_uuid().to_string().as_str(),
                            "refresh_token",
                        ])
                        .inc();
                    let resp = pb::OidcTokenResponse {
                        access_token: tokens.access_token().to_string(),
                        id_token: String::new(),
                        token_type: if dpop_jkt.is_some() { "DPoP" } else { "Bearer" }.to_string(),
                        expires_in: 900,
                        refresh_token: tokens.refresh_token().to_string(),
                    };
                    (StatusCode::OK, Json(proto_to_rest_json(&resp))).into_response()
                }
                Err(e) => identity_error_to_response(&e).into_response(),
            }
        }
        "client_credentials" => {
            let proto_req = pb::ClientCredentialsRequest {
                client_id: body.client_id,
                client_secret: body.client_secret.unwrap_or_default(),
                scope: body.scope,
            };

            let mut request = match proto_client_creds_to_domain(&proto_req) {
                Ok(r) => r,
                Err(msg) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": msg})),
                    )
                        .into_response();
                }
            };
            request.dpop_jkt = dpop_jkt.clone();
            request.client_assertion_type = body.client_assertion_type;
            request.client_assertion = body.client_assertion;

            let realm_str = realm_id.as_uuid().to_string();
            match state.identity.client_credentials_token(&realm_id, &request) {
                Ok(response) => {
                    crate::metrics::metrics()
                        .auth_attempts_total
                        .with_label_values(&[realm_str.as_str(), "success"])
                        .inc();
                    crate::metrics::metrics()
                        .tokens_issued_total
                        .with_label_values(&[realm_str.as_str(), "client_credentials"])
                        .inc();
                    let mut cc_resp = pb::ClientCredentialsResponse::from(&response);
                    if dpop_jkt.is_some() {
                        cc_resp.token_type = "DPoP".to_string();
                    }
                    (StatusCode::OK, Json(proto_to_rest_json(&cc_resp))).into_response()
                }
                Err(e) => {
                    crate::metrics::metrics()
                        .auth_attempts_total
                        .with_label_values(&[realm_str.as_str(), "failure"])
                        .inc();
                    identity_error_to_response(&e).into_response()
                }
            }
        }
        "urn:ietf:params:oauth:grant-type:device_code" => {
            let Some(device_code) = body.device_code else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(
                        serde_json::json!({"error": "device_code required for device_code grant"}),
                    ),
                )
                    .into_response();
            };

            let oauth_client_id = match body.client_id.parse::<uuid::Uuid>() {
                Ok(u) => ClientId::new(u),
                Err(_) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "invalid client_id UUID"})),
                    )
                        .into_response();
                }
            };

            match state
                .identity
                .poll_device_token(&realm_id, &device_code, &oauth_client_id)
            {
                Ok(response) => {
                    crate::metrics::metrics()
                        .tokens_issued_total
                        .with_label_values(&[
                            realm_id.as_uuid().to_string().as_str(),
                            "urn:ietf:params:oauth:grant-type:device_code",
                        ])
                        .inc();
                    crate::metrics::metrics().active_sessions.inc();
                    (
                        StatusCode::OK,
                        Json(proto_to_rest_json(&pb::OidcTokenResponse::from(&response))),
                    )
                        .into_response()
                }
                Err(e) => identity_error_to_response(&e).into_response(),
            }
        }
        "password" => {
            // Gate: per-client grant type check (RFC 9700 §2.4). If the client_id
            // resolves to a registered client, it must declare the "password" grant.
            if let Ok(client_uuid) = body.client_id.parse::<uuid::Uuid>() {
                let ropc_client_id = ClientId::new(client_uuid);
                match state.identity.get_client(&realm_id, &ropc_client_id) {
                    Ok(Some(client)) => {
                        if !client.grant_types().contains(&"password".to_string()) {
                            return (
                                StatusCode::BAD_REQUEST,
                                Json(serde_json::json!({
                                    "error": "unauthorized_client",
                                    "error_description": "this client is not authorized for the password grant type"
                                })),
                            )
                                .into_response();
                        }
                    }
                    Ok(None) => {} // Unknown client — password_grant_token will reject it.
                    Err(e) => return identity_error_to_response(&e).into_response(),
                }
            }
            let (Some(email), Some(password)) = (body.username, body.password) else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "username and password required for password grant"})),
                )
                    .into_response();
            };
            let request = PasswordGrantRequest {
                email,
                password,
                scope: body.scope,
                client_ip: Some(client_ip.clone()),
                user_agent: headers
                    .get(axum::http::header::USER_AGENT)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string),
            };
            let realm_str = realm_id.as_uuid().to_string();
            let identity = Arc::clone(&state.identity);
            let realm_id_2 = realm_id.clone();
            let result = tokio::task::spawn_blocking(move || {
                identity.password_grant_token(&realm_id_2, &request)
            })
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "password_grant spawn_blocking panicked");
                Err(crate::identity::IdentityError::Internal {
                    reason: e.to_string(),
                })
            });
            match result {
                Ok(response) => {
                    crate::metrics::metrics()
                        .tokens_issued_total
                        .with_label_values(&[realm_str.as_str(), "password"])
                        .inc();
                    crate::metrics::metrics().active_sessions.inc();
                    (
                        StatusCode::OK,
                        Json(serde_json::json!({
                            "access_token": response.access_token(),
                            "refresh_token": response.refresh_token(),
                            "token_type": response.token_type,
                            "expires_in": response.expires_in,
                        })),
                    )
                        .into_response()
                }
                Err(
                    ref e @ (crate::identity::IdentityError::InvalidCredential { .. }
                    | crate::identity::IdentityError::RateLimited),
                ) => {
                    // Record the failed attempt against the IP for credential failures.
                    state
                        .identity
                        .record_ip_login_attempt(&realm_id, &client_ip);
                    identity_error_to_response(e).into_response()
                }
                Err(e) => identity_error_to_response(&e).into_response(),
            }
        }
        "urn:hearth:params:grant-type:step-up-mfa" => {
            let (Some(email), Some(password), Some(mfa_code)) =
                (body.username, body.password, body.mfa_code)
            else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "username, password, and mfa_code required for step-up-mfa grant"})),
                )
                    .into_response();
            };
            let request = StepUpMfaGrantRequest {
                email,
                password,
                mfa_code,
                scope: body.scope,
                client_ip: Some(client_ip.clone()),
                user_agent: headers
                    .get(axum::http::header::USER_AGENT)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string),
            };
            let realm_str = realm_id.as_uuid().to_string();
            match state.identity.step_up_mfa_grant_token(&realm_id, &request) {
                Ok(response) => {
                    crate::metrics::metrics()
                        .tokens_issued_total
                        .with_label_values(&[realm_str.as_str(), "step_up_mfa"])
                        .inc();
                    crate::metrics::metrics().active_sessions.inc();
                    (
                        StatusCode::OK,
                        Json(serde_json::json!({
                            "access_token": response.access_token(),
                            "refresh_token": response.refresh_token(),
                            "token_type": response.token_type,
                            "expires_in": response.expires_in,
                        })),
                    )
                        .into_response()
                }
                Err(
                    ref e @ (crate::identity::IdentityError::InvalidCredential { .. }
                    | crate::identity::IdentityError::RateLimited),
                ) => {
                    state
                        .identity
                        .record_ip_login_attempt(&realm_id, &client_ip);
                    identity_error_to_response(e).into_response()
                }
                Err(e) => identity_error_to_response(&e).into_response(),
            }
        }
        "urn:ietf:params:oauth:grant-type:jwt-bearer" => {
            let Some(assertion) = body.assertion else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "assertion required for jwt-bearer grant"})),
                )
                    .into_response();
            };
            let oauth_client_id = match body.client_id.parse::<uuid::Uuid>() {
                Ok(u) => ClientId::new(u),
                Err(_) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "invalid client_id UUID"})),
                    )
                        .into_response();
                }
            };
            let request = JwtBearerRequest {
                client_id: oauth_client_id,
                assertion,
                scope: body.scope,
                dpop_jkt: dpop_jkt.clone(),
            };
            match state.identity.jwt_bearer_token(&realm_id, &request) {
                Ok(response) => {
                    crate::metrics::metrics()
                        .tokens_issued_total
                        .with_label_values(&[realm_id.as_uuid().to_string().as_str(), "jwt_bearer"])
                        .inc();
                    let token_resp = pb::OidcTokenResponse {
                        access_token: response.access_token().to_string(),
                        id_token: String::new(),
                        token_type: if dpop_jkt.is_some() {
                            "DPoP".to_string()
                        } else {
                            "Bearer".to_string()
                        },
                        expires_in: response.expires_in(),
                        refresh_token: String::new(),
                    };
                    (StatusCode::OK, Json(proto_to_rest_json(&token_resp))).into_response()
                }
                Err(e) => identity_error_to_response(&e).into_response(),
            }
        }
        // RFC 8693 Token Exchange (AGENT_AUTH.md §3.3 / B.4)
        "urn:ietf:params:oauth:grant-type:token-exchange" => {
            // M2: token-exchange MUST authenticate the requesting client (RFC 8693 §2.1).
            // Derive actor_sub from the authenticated identity, not the unauthenticated body.
            let authenticated_client_id = match verify_endpoint_client(
                &state,
                &realm_id,
                &headers,
                Some(&body.client_id),
                body.client_secret.as_deref(),
            ) {
                Ok(id) => id,
                Err(resp) => return resp,
            };

            let subject_token = match body.subject_token {
                Some(t) => t,
                None => return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_request",
                        "error_description": "subject_token is required for token-exchange grant"
                    })),
                )
                    .into_response(),
            };
            let request = crate::identity::Rfc8693Request {
                client_id: authenticated_client_id,
                subject_token,
                subject_token_type: body
                    .subject_token_type
                    .unwrap_or_else(|| "urn:ietf:params:oauth:token-type:access_token".to_string()),
                actor_token: body.actor_token,
                actor_token_type: body.actor_token_type,
                requested_token_type: body.requested_token_type,
                scope: body.scope,
                resource: body.resource,
                audience: body.audience,
                dpop_jkt: dpop_jkt.clone(),
            };
            match state.identity.rfc8693_token_exchange(&realm_id, &request) {
                Ok(resp) => {
                    crate::metrics::metrics()
                        .tokens_issued_total
                        .with_label_values(&[
                            realm_id.as_uuid().to_string().as_str(),
                            "token_exchange",
                        ])
                        .inc();
                    (
                        StatusCode::OK,
                        Json(serde_json::json!({
                            "access_token": resp.access_token,
                            "issued_token_type": resp.issued_token_type,
                            "token_type": resp.token_type,
                            "expires_in": resp.expires_in,
                            "scope": resp.scope,
                        })),
                    )
                        .into_response()
                }
                Err(e) => identity_error_to_response(&e).into_response(),
            }
        }
        _ => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "unsupported_grant_type",
                "error_code": crate::protocol::error_codes::UNSUPPORTED_GRANT_TYPE,
            })),
        )
            .into_response(),
    }
}

// === Token Revocation (RFC 7009) ===

/// POST /revoke — revokes an OAuth 2.0 token.
///
/// Per RFC 7009, returns 200 OK regardless of whether the token was
/// actually revoked (to prevent information leakage). Requires client
/// authentication via HTTP Basic Auth or body `client_id`/`client_secret`.
async fn token_revocation(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<HttpRevocationBody>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let client_id = match verify_endpoint_client(
        &state,
        &realm_id,
        &headers,
        body.client_id.as_deref(),
        body.client_secret.as_deref(),
    ) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    if let Err(resp) = check_token_rate_limit(&state, &realm_id, &client_id) {
        return resp;
    }

    let request = crate::identity::TokenRevocationRequest {
        token: body.token,
        token_type_hint: body.token_type_hint,
    };

    let mut resp = match state.identity.revoke_token(&realm_id, &request) {
        Ok(()) => {
            // A successful revoke ends a session; keep the gauge consistent.
            crate::metrics::metrics().active_sessions.dec();
            StatusCode::OK.into_response()
        }
        Err(crate::identity::IdentityError::InvalidToken) => {
            // RFC 7009: always return 200 OK
            StatusCode::OK.into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    };
    apply_cors_to_response(&mut resp, &state, &realm_id, &client_id, &headers);
    resp
}

// === Token Introspection (RFC 7662) ===

/// POST /introspect — introspects an OAuth 2.0 token.
///
/// Returns metadata about the token including its active status. Requires
/// client authentication via HTTP Basic Auth or body `client_id`/`client_secret`.
async fn token_introspection(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<HttpIntrospectionBody>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let client_id = match verify_endpoint_client(
        &state,
        &realm_id,
        &headers,
        body.client_id.as_deref(),
        body.client_secret.as_deref(),
    ) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    if let Err(resp) = check_token_rate_limit(&state, &realm_id, &client_id) {
        return resp;
    }

    let request = crate::identity::TokenIntrospectionRequest {
        token: body.token,
        token_type_hint: body.token_type_hint,
        introspecting_client_id: Some(client_id.clone()),
    };

    let mut resp = match state.identity.introspect_token(&realm_id, &request) {
        // Use the domain type directly: the domain IntrospectionResponse has
        // #[derive(Serialize)] and always emits `active: false` for inactive
        // tokens. The proto-generated serde omits proto3 default values (false)
        // which would violate RFC 7662 §2.2 by leaving `active` absent.
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    };
    apply_cors_to_response(&mut resp, &state, &realm_id, &client_id, &headers);
    resp
}

// === Decision Endpoint (HEA-922) ===

/// POST `/oauth/authorize` — per-request permission decision for Decision-mode clients.
///
/// Validates the bearer token and resolves live RBAC to decide whether the
/// token holder has the requested permission.  Fail-closed: invalid tokens,
/// missing permissions, or resolution errors all return `allowed: false`.
async fn oauth_decide_permission(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let token = match headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        Some(t) => t.to_string(),
        None => {
            return (StatusCode::OK, Json(serde_json::json!({"allowed": false}))).into_response()
        }
    };

    let permission = match body.get("permission").and_then(|v| v.as_str()) {
        Some(p) => p.to_string(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "permission field required"})),
            )
                .into_response()
        }
    };

    let organization_id = body
        .get("organization_id")
        .and_then(|v| v.as_str())
        .map(String::from);
    let resource = body
        .get("resource")
        .and_then(|v| v.as_str())
        .map(String::from);

    let request = crate::identity::oidc::DecidePermissionRequest {
        token,
        permission,
        organization_id,
        resource,
    };

    match state.identity.decide_token_permission(&realm_id, &request) {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

// === Device Authorization (RFC 8628) ===

/// POST `/device_authorization` — initiates a device authorization flow.
///
/// Returns a device code, user code, and verification URI.
async fn device_authorization(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<pb::DeviceAuthorizationRequest>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let client_id = match body.client_id.parse::<uuid::Uuid>() {
        Ok(u) => ClientId::new(u),
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid client_id UUID"})),
            )
                .into_response();
        }
    };
    if let Err(resp) = check_token_rate_limit(&state, &realm_id, &client_id) {
        return resp;
    }

    let request = crate::identity::DeviceAuthorizationRequest {
        client_id,
        scope: body.scope,
    };

    match state.identity.device_authorize(&realm_id, &request) {
        Ok(response) => (
            StatusCode::OK,
            Json(proto_to_rest_json(&pb::DeviceAuthorizationResponse::from(
                &response,
            ))),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

// === UserInfo endpoint (OIDC Core §5.3) ===

/// GET /userinfo — returns claims about the authenticated user.
async fn userinfo(State(state): State<Arc<AppState>>, headers: HeaderMap) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    // Extract Bearer token from Authorization header
    let Some(token) = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid_token"})),
        )
            .into_response();
    };

    match state.identity.userinfo(&realm_id, token) {
        Ok(info) => (
            StatusCode::OK,
            Json(proto_to_rest_json(&pb::UserInfoResponse::from(&info))),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

// === Claims-based permissions endpoint ===

/// `GET /v1/me/permissions` — resolves and returns the authenticated user's
/// effective roles, groups, and permissions FRESHLY (not from the JWT).
///
/// Accepts optional `org_id` and `scope` query parameters.
async fn me_permissions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> axum::response::Response {
    let realm_id = match extract_realm_id(&headers) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };

    let Some(token) = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid_token"})),
        )
            .into_response();
    };

    let claims = match state.identity.validate_token(&realm_id, token) {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "invalid_token"})),
            )
                .into_response();
        }
    };

    let uuid_str = claims.sub.strip_prefix("user_").unwrap_or(&claims.sub);
    let user_uuid: uuid::Uuid = match uuid_str.parse() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "invalid_token"})),
            )
                .into_response();
        }
    };
    let user_id = UserId::new(user_uuid);

    let org_id = params.get("org_id").and_then(|s| {
        uuid::Uuid::parse_str(s)
            .ok()
            .map(crate::core::OrganizationId::new)
    });
    let scope = params.get("scope").cloned();

    let resolved =
        match state
            .rbac
            .resolve_permissions(&user_id, &realm_id, org_id.as_ref(), scope.as_deref())
        {
            Ok(r) => r,
            Err(e) => return rbac_error_to_response(&e).into_response(),
        };

    (
        StatusCode::OK,
        Json(MePermissionsResponse {
            roles: resolved.roles,
            groups: resolved.groups,
            permissions: resolved
                .permissions
                .into_iter()
                .map(|p| p.into_string())
                .collect(),
            scope,
        }),
    )
        .into_response()
}

async fn self_list_consents(
    State(state): State<Arc<AppState>>,
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    let htu = format!("{}{}", state.identity.oidc_discovery().issuer, uri.path());
    let user_id = match extract_user_auth(&headers, &state, &realm_id, method.as_str(), &htu) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    match state.identity.list_consents_by_user(&realm_id, &user_id) {
        Ok(entries) => {
            let body = serde_json::json!({
                "items": entries.iter().map(|e| serde_json::json!({
                    "client_id": e.record.client_id.as_uuid().to_string(),
                    "client_name": e.client_name,
                    "client_logo_url": e.client_logo_url,
                    "scopes": e.record.granted_scopes,
                    "granted_at": e.record.granted_at.as_micros(),
                    "updated_at": e.record.updated_at.as_micros(),
                })).collect::<Vec<_>>(),
            });
            (StatusCode::OK, Json(body)).into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// `DELETE /oauth/consents/{client_id}` — revokes the current user's
/// consent for a specific client.
async fn self_revoke_consent(
    State(state): State<Arc<AppState>>,
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    axum::extract::Path(client_id_str): axum::extract::Path<String>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    let htu = format!("{}{}", state.identity.oidc_discovery().issuer, uri.path());
    let user_id = match extract_user_auth(&headers, &state, &realm_id, method.as_str(), &htu) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    let Ok(uuid) = client_id_str.parse::<uuid::Uuid>() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid client_id"})),
        )
            .into_response();
    };
    let client_id = crate::core::ClientId::new(uuid);
    match state
        .identity
        .revoke_consent(&realm_id, &user_id, &client_id)
    {
        Ok(()) => {
            // Engine now emits ConsentRevoked internally.
            (StatusCode::NO_CONTENT, ()).into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// `GET /admin/users/{id}/consents` — admin: list any user's consents in
/// the admin's current realm.
async fn realm_oidc_discovery(
    State(state): State<Arc<AppState>>,
    Path(realm_name): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let client_ip = extract_client_ip(&headers, FALLBACK_PEER, &state.trusted_proxies);
    let now_micros = now_micros();
    if !state.jwks_rate_limiter.check(&client_ip, now_micros) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", "1")],
            Json(serde_json::json!({"error": "too_many_requests"})),
        )
            .into_response();
    }
    let realm_id = match resolve_realm_by_name(&state, &realm_name) {
        Ok(id) => id,
        Err(e) => return e,
    };
    match state.identity.realm_oidc_discovery(&realm_id) {
        // Serialize the domain type directly so optional fields like
        // end_session_endpoint are included without proto schema changes.
        Ok(doc) => (StatusCode::OK, Json(doc)).into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// A-10: per-IP rate cap on all key-discovery endpoints.
async fn realm_jwks(
    State(state): State<Arc<AppState>>,
    Path(realm_name): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let client_ip = extract_client_ip(&headers, FALLBACK_PEER, &state.trusted_proxies);
    let now_micros = now_micros();
    if !state.jwks_rate_limiter.check(&client_ip, now_micros) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", "1")],
            Json(serde_json::json!({"error": "too_many_requests"})),
        )
            .into_response();
    }
    let realm_id = match resolve_realm_by_name(&state, &realm_name) {
        Ok(id) => id,
        Err(e) => return e,
    };
    match state.identity.realm_jwks(&realm_id) {
        Ok(doc) => (StatusCode::OK, Json(doc)).into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

/// `GET /realms/{realm}/authorize` — browser redirect shim.
///
/// The OIDC discovery document advertises `authorization_endpoint` as
/// `{issuer}/authorize`.  Browser-based PKCE clients (SPAs) redirect the
/// user's browser here via GET.  The interactive login+consent UI lives at
/// `/ui/realms/{realm}/oauth/authorize`, so this handler 302-redirects the
/// browser there, preserving all query parameters.
async fn realm_authorize_browser_redirect(
    Path(realm_name): Path<String>,
    uri: axum::http::Uri,
) -> impl IntoResponse {
    let query = uri.query().map(|q| format!("?{q}")).unwrap_or_default();
    let target = format!("/ui/realms/{realm_name}/oauth/authorize{query}");
    axum::response::Redirect::to(&target)
}

async fn realm_authorize(
    State(state): State<Arc<AppState>>,
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    Path(realm_name): Path<String>,
    Json(body): Json<pb::AuthorizationRequest>,
) -> impl IntoResponse {
    let realm_id = match resolve_realm_by_name(&state, &realm_name) {
        Ok(id) => id,
        Err(e) => return e,
    };

    // HEA-1721: authenticate the caller; their token's `sub` is the authoritative user identity.
    let htu = format!("{}{}", state.identity.oidc_discovery().issuer, uri.path());
    let authenticated_user_id =
        match extract_user_auth(&headers, &state, &realm_id, method.as_str(), &htu) {
            Ok(uid) => uid,
            Err(e) => return e.into_response(),
        };

    let mut request = match proto_authorize_to_domain(body) {
        Ok(r) => r,
        Err(msg) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": msg})),
            )
                .into_response()
        }
    };
    // Override body-supplied user_id with the authenticated identity (HEA-1721).
    request.user_id = authenticated_user_id;
    match state.identity.authorize(&realm_id, &request) {
        Ok(response) => (
            StatusCode::OK,
            Json(proto_to_rest_json(&pb::AuthorizationResponse::from(
                &response,
            ))),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

#[allow(clippy::too_many_lines)]
async fn realm_token_exchange(
    State(state): State<Arc<AppState>>,
    Path(realm_name): Path<String>,
    headers: HeaderMap,
    Json(body): Json<HttpTokenRequest>,
) -> Response {
    let realm_id = match resolve_realm_by_name(&state, &realm_name) {
        Ok(id) => id,
        Err(e) => return e,
    };
    // Rate limit per client_id before any grant-type dispatch.
    if let Ok(client_uuid) = body.client_id.parse::<uuid::Uuid>() {
        let client_id = ClientId::new(client_uuid);
        if let Err(resp) = check_token_rate_limit(&state, &realm_id, &client_id) {
            return resp;
        }
    }
    let grant_type = body.grant_type.as_deref().unwrap_or("authorization_code");

    // Per-IP rate limiting for the ROPC password grant and step-up-mfa grant.
    // Real IP arrives via X-Forwarded-For in production; FALLBACK_PEER used in tests.
    let client_ip = extract_client_ip(&headers, FALLBACK_PEER, &state.trusted_proxies);
    if (grant_type == "password" || grant_type == "urn:hearth:params:grant-type:step-up-mfa")
        && state
            .identity
            .check_ip_login_rate_limit(&realm_id, &client_ip)
            .is_err()
    {
        let retry_after = state
            .identity
            .ip_login_retry_after_secs(&realm_id, &client_ip);
        return make_ip_rate_limit_response(retry_after as u32);
    }

    // Extract and validate DPoP proof if present (RFC 9449).
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let dpop_jkt: Option<String> =
        if let Some(proof) = headers.get("DPoP").and_then(|v| v.to_str().ok()) {
            let base_issuer = state.identity.oidc_discovery().issuer;
            let expected_htu = format!("{base_issuer}/realms/{realm_name}/token");
            match crate::identity::dpop::validate_dpop_proof(
                proof,
                "POST",
                &expected_htu,
                now_secs,
                None,
                None, // token endpoint: no access_token to bind yet
            ) {
                Ok(validated) => {
                    // RFC 9449 §9.1: nonce is mandatory — server always issues a
                    // DPoP-Nonce header, so the client must include it on every proof.
                    // Two-window acceptance (current + previous) handles clock drift.
                    let nonce_valid = match validated.nonce.as_deref() {
                        None => false,
                        Some(n) => state
                            .identity
                            .get_realm_dpop_nonce_secret(&realm_id)
                            .ok()
                            .map(|s| crate::identity::dpop::is_valid_dpop_nonce(&s, n, now_secs))
                            .unwrap_or_else(|| state.dpop.is_valid_nonce(n, now_secs)),
                    };
                    if !nonce_valid {
                        // Include DPoP-Nonce in the error so the client can retry.
                        // (The success-path DPoP-Nonce at the bottom of this fn is
                        //  not reached on early return.)
                        let mut err_resp = identity_error_to_response(
                            &crate::identity::error::IdentityError::DPopNonceInvalid,
                        )
                        .into_response();
                        let current_nonce = state
                            .identity
                            .get_realm_dpop_nonce_secret(&realm_id)
                            .ok()
                            .map(|s| crate::identity::dpop::current_dpop_nonce(&s, now_secs))
                            .unwrap_or_else(|| state.dpop.current_nonce(now_secs));
                        if let Ok(val) = axum::http::HeaderValue::from_str(&current_nonce) {
                            err_resp.headers_mut().insert("DPoP-Nonce", val);
                        }
                        return err_resp;
                    }
                    if let Err(e) = state.identity.check_and_record_dpop_jti(
                        &realm_id,
                        &validated.jti,
                        now_secs,
                    ) {
                        return identity_error_to_response(&e).into_response();
                    }
                    Some(validated.jkt)
                }
                Err(e) => return identity_error_to_response(&e).into_response(),
            }
        } else {
            None
        };

    let mut resp = match grant_type {
        "authorization_code" => {
            // O2 (HEA-1755): confidential clients must authenticate on the
            // code-exchange arm; public (PKCE) clients and unknown clients pass
            // through unchanged.
            if let Err(resp) = enforce_confidential_client_auth(
                &state,
                &realm_id,
                &headers,
                &body.client_id,
                body.client_secret.as_deref(),
            ) {
                return resp;
            }
            let (Some(code), Some(redirect_uri)) = (body.code, body.redirect_uri) else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "code and redirect_uri required"})),
                )
                    .into_response();
            };
            let proto_req = pb::TokenExchangeRequest {
                client_id: body.client_id,
                code,
                redirect_uri,
                code_verifier: body.code_verifier,
            };
            let mut request = match proto_token_exchange_to_domain(&proto_req) {
                Ok(r) => r,
                Err(msg) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": msg})),
                    )
                        .into_response()
                }
            };
            request.dpop_jkt = dpop_jkt.clone();
            request.client_assertion_type = body.client_assertion_type;
            request.client_assertion = body.client_assertion;
            match state
                .identity
                .exchange_authorization_code(&realm_id, &request)
            {
                Ok(response) => {
                    let mut token_resp = pb::OidcTokenResponse::from(&response);
                    if dpop_jkt.is_some() {
                        token_resp.token_type = "DPoP".to_string();
                    }
                    (StatusCode::OK, Json(proto_to_rest_json(&token_resp))).into_response()
                }
                Err(e) => identity_error_to_response(&e).into_response(),
            }
        }
        "refresh_token" => {
            let Some(refresh_token) = body.refresh_token else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "refresh_token required"})),
                )
                    .into_response();
            };
            // O1 (HEA-1755): authenticate the presenting client (see the
            // header-realm handler for rationale). The engine binds the grant
            // family to this authenticated identity in rotate_grant_family.
            let authenticated_client_id =
                if parse_basic_auth(&headers).is_some() || !body.client_id.trim().is_empty() {
                    match verify_endpoint_client(
                        &state,
                        &realm_id,
                        &headers,
                        Some(body.client_id.as_str()),
                        body.client_secret.as_deref(),
                    ) {
                        Ok(cid) => Some(cid),
                        Err(resp) => return resp,
                    }
                } else {
                    None
                };
            let refresh_bind = crate::identity::RefreshBindContext {
                user_agent: headers
                    .get(axum::http::header::USER_AGENT)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string),
                asn: None,
                authenticated_client_id,
            };
            match state.identity.refresh_tokens(
                &realm_id,
                &refresh_token,
                dpop_jkt.as_deref(),
                Some(&refresh_bind),
            ) {
                Ok(tokens) => {
                    let resp = pb::OidcTokenResponse {
                        access_token: tokens.access_token().to_string(),
                        id_token: String::new(),
                        token_type: if dpop_jkt.is_some() { "DPoP" } else { "Bearer" }.to_string(),
                        expires_in: 900,
                        refresh_token: tokens.refresh_token().to_string(),
                    };
                    (StatusCode::OK, Json(proto_to_rest_json(&resp))).into_response()
                }
                Err(e) => identity_error_to_response(&e).into_response(),
            }
        }
        "client_credentials" => {
            let proto_req = pb::ClientCredentialsRequest {
                client_id: body.client_id,
                client_secret: body.client_secret.unwrap_or_default(),
                scope: body.scope,
            };
            let mut request = match proto_client_creds_to_domain(&proto_req) {
                Ok(r) => r,
                Err(msg) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": msg})),
                    )
                        .into_response()
                }
            };
            request.dpop_jkt = dpop_jkt.clone();
            request.client_assertion_type = body.client_assertion_type;
            request.client_assertion = body.client_assertion;
            match state.identity.client_credentials_token(&realm_id, &request) {
                Ok(response) => {
                    let resp = pb::OidcTokenResponse {
                        access_token: response.access_token().to_string(),
                        id_token: String::new(),
                        token_type: if dpop_jkt.is_some() {
                            "DPoP".to_string()
                        } else {
                            "Bearer".to_string()
                        },
                        expires_in: response.expires_in(),
                        refresh_token: String::new(),
                    };
                    (StatusCode::OK, Json(proto_to_rest_json(&resp))).into_response()
                }
                Err(e) => identity_error_to_response(&e).into_response(),
            }
        }
        "urn:ietf:params:oauth:grant-type:device_code" => {
            let Some(device_code) = body.device_code else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "device_code required"})),
                )
                    .into_response();
            };
            let oauth_client_id = match body.client_id.parse::<uuid::Uuid>() {
                Ok(u) => ClientId::new(u),
                Err(_) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "invalid client_id UUID"})),
                    )
                        .into_response()
                }
            };
            match state
                .identity
                .poll_device_token(&realm_id, &device_code, &oauth_client_id)
            {
                Ok(response) => (
                    StatusCode::OK,
                    Json(proto_to_rest_json(&pb::OidcTokenResponse::from(&response))),
                )
                    .into_response(),
                Err(e) => identity_error_to_response(&e).into_response(),
            }
        }
        "password" => {
            // Per-client grant type gate — mirrors the check in token_exchange_impl.
            if let Ok(client_uuid) = body.client_id.parse::<uuid::Uuid>() {
                let ropc_client_id = ClientId::new(client_uuid);
                match state.identity.get_client(&realm_id, &ropc_client_id) {
                    Ok(Some(client)) => {
                        if !client.grant_types().contains(&"password".to_string()) {
                            return (
                                StatusCode::BAD_REQUEST,
                                Json(serde_json::json!({
                                    "error": "unauthorized_client",
                                    "error_description": "this client is not authorized for the password grant type"
                                })),
                            )
                                .into_response();
                        }
                    }
                    Ok(None) => {}
                    Err(e) => return identity_error_to_response(&e).into_response(),
                }
            }
            let (Some(email), Some(password)) = (body.username, body.password) else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "username and password required for password grant"})),
                )
                    .into_response();
            };
            let request = PasswordGrantRequest {
                email,
                password,
                scope: body.scope,
                client_ip: Some(client_ip.clone()),
                user_agent: headers
                    .get(axum::http::header::USER_AGENT)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string),
            };
            let identity = Arc::clone(&state.identity);
            let realm_id_2 = realm_id.clone();
            let result = tokio::task::spawn_blocking(move || {
                identity.password_grant_token(&realm_id_2, &request)
            })
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "password_grant spawn_blocking panicked");
                Err(crate::identity::IdentityError::Internal {
                    reason: e.to_string(),
                })
            });
            match result {
                Ok(response) => (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "access_token": response.access_token(),
                        "refresh_token": response.refresh_token(),
                        "token_type": response.token_type,
                        "expires_in": response.expires_in,
                    })),
                )
                    .into_response(),
                Err(
                    ref e @ (crate::identity::IdentityError::InvalidCredential { .. }
                    | crate::identity::IdentityError::RateLimited),
                ) => {
                    state
                        .identity
                        .record_ip_login_attempt(&realm_id, &client_ip);
                    identity_error_to_response(e).into_response()
                }
                Err(e) => identity_error_to_response(&e).into_response(),
            }
        }
        "urn:hearth:params:grant-type:step-up-mfa" => {
            let (Some(email), Some(password), Some(mfa_code)) =
                (body.username, body.password, body.mfa_code)
            else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "username, password, and mfa_code required for step-up-mfa grant"})),
                )
                    .into_response();
            };
            let request = StepUpMfaGrantRequest {
                email,
                password,
                mfa_code,
                scope: body.scope,
                client_ip: Some(client_ip.clone()),
                user_agent: headers
                    .get(axum::http::header::USER_AGENT)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string),
            };
            match state.identity.step_up_mfa_grant_token(&realm_id, &request) {
                Ok(response) => (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "access_token": response.access_token(),
                        "refresh_token": response.refresh_token(),
                        "token_type": response.token_type,
                        "expires_in": response.expires_in,
                    })),
                )
                    .into_response(),
                Err(
                    ref e @ (crate::identity::IdentityError::InvalidCredential { .. }
                    | crate::identity::IdentityError::RateLimited),
                ) => {
                    state
                        .identity
                        .record_ip_login_attempt(&realm_id, &client_ip);
                    identity_error_to_response(e).into_response()
                }
                Err(e) => identity_error_to_response(&e).into_response(),
            }
        }
        "urn:ietf:params:oauth:grant-type:jwt-bearer" => {
            let Some(assertion) = body.assertion else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "assertion required for jwt-bearer grant"})),
                )
                    .into_response();
            };
            let oauth_client_id = match body.client_id.parse::<uuid::Uuid>() {
                Ok(u) => ClientId::new(u),
                Err(_) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "invalid client_id UUID"})),
                    )
                        .into_response();
                }
            };
            let request = JwtBearerRequest {
                client_id: oauth_client_id,
                assertion,
                scope: body.scope,
                dpop_jkt: dpop_jkt.clone(),
            };
            match state.identity.jwt_bearer_token(&realm_id, &request) {
                Ok(response) => {
                    crate::metrics::metrics()
                        .tokens_issued_total
                        .with_label_values(&[realm_id.as_uuid().to_string().as_str(), "jwt_bearer"])
                        .inc();
                    let token_resp = pb::OidcTokenResponse {
                        access_token: response.access_token().to_string(),
                        id_token: String::new(),
                        token_type: if dpop_jkt.is_some() {
                            "DPoP".to_string()
                        } else {
                            "Bearer".to_string()
                        },
                        expires_in: response.expires_in(),
                        refresh_token: String::new(),
                    };
                    (StatusCode::OK, Json(proto_to_rest_json(&token_resp))).into_response()
                }
                Err(e) => identity_error_to_response(&e).into_response(),
            }
        }
        // RFC 8693 Token Exchange (AGENT_AUTH.md §3.3 / B.4)
        "urn:ietf:params:oauth:grant-type:token-exchange" => {
            let subject_token = match body.subject_token {
                Some(t) => t,
                None => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "error": "invalid_request",
                            "error_description": "subject_token is required"
                        })),
                    )
                        .into_response();
                }
            };
            let client_uuid = match uuid::Uuid::parse_str(&body.client_id) {
                Ok(u) => u,
                Err(_) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "invalid_client"})),
                    )
                        .into_response();
                }
            };
            let request = crate::identity::Rfc8693Request {
                client_id: crate::core::ClientId::new(client_uuid),
                subject_token,
                subject_token_type: body
                    .subject_token_type
                    .unwrap_or_else(|| "urn:ietf:params:oauth:token-type:access_token".to_string()),
                actor_token: body.actor_token,
                actor_token_type: body.actor_token_type,
                requested_token_type: body.requested_token_type,
                scope: body.scope,
                resource: body.resource,
                audience: body.audience,
                dpop_jkt: dpop_jkt.clone(),
            };
            match state.identity.rfc8693_token_exchange(&realm_id, &request) {
                Ok(resp) => {
                    crate::metrics::metrics()
                        .tokens_issued_total
                        .with_label_values(&[
                            realm_id.as_uuid().to_string().as_str(),
                            "token_exchange",
                        ])
                        .inc();
                    (
                        StatusCode::OK,
                        Json(serde_json::json!({
                            "access_token": resp.access_token,
                            "issued_token_type": resp.issued_token_type,
                            "token_type": resp.token_type,
                            "expires_in": resp.expires_in,
                            "scope": resp.scope,
                        })),
                    )
                        .into_response()
                }
                Err(e) => identity_error_to_response(&e).into_response(),
            }
        }
        other => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("unsupported grant_type: {other}")})),
        )
            .into_response(),
    };

    // RFC 9449 §9: always return DPoP-Nonce so clients can use it in the next proof.
    let nonce = state
        .identity
        .get_realm_dpop_nonce_secret(&realm_id)
        .ok()
        .map(|s| crate::identity::dpop::current_dpop_nonce(&s, now_secs))
        .unwrap_or_else(|| state.dpop.current_nonce(now_secs));
    if let Ok(val) = axum::http::HeaderValue::from_str(&nonce) {
        resp.headers_mut().insert("DPoP-Nonce", val);
    }

    resp
}

async fn realm_token_revocation(
    State(state): State<Arc<AppState>>,
    Path(realm_name): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let realm_id = match resolve_realm_by_name(&state, &realm_name) {
        Ok(id) => id,
        Err(e) => return e,
    };
    let token = match body.get("token").and_then(|v| v.as_str()) {
        Some(t) => t.to_string(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "token required"})),
            )
                .into_response()
        }
    };
    let request = crate::identity::TokenRevocationRequest {
        token,
        token_type_hint: None,
    };
    match state.identity.revoke_token(&realm_id, &request) {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

async fn realm_token_introspection(
    State(state): State<Arc<AppState>>,
    Path(realm_name): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let realm_id = match resolve_realm_by_name(&state, &realm_name) {
        Ok(id) => id,
        Err(e) => return e,
    };
    let token = match body.get("token").and_then(|v| v.as_str()) {
        Some(t) => t.to_string(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "token required"})),
            )
                .into_response()
        }
    };
    let request = crate::identity::TokenIntrospectionRequest {
        token,
        token_type_hint: None,
        introspecting_client_id: None,
    };
    match state.identity.introspect_token(&realm_id, &request) {
        Ok(info) => (
            StatusCode::OK,
            Json(proto_to_rest_json(&pb::IntrospectionResponse::from(&info))),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

async fn realm_userinfo(
    State(state): State<Arc<AppState>>,
    Path(realm_name): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let realm_id = match resolve_realm_by_name(&state, &realm_name) {
        Ok(id) => id,
        Err(e) => return e,
    };
    let Some(token) = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid_token"})),
        )
            .into_response();
    };
    match state.identity.userinfo(&realm_id, token) {
        Ok(info) => (
            StatusCode::OK,
            Json(proto_to_rest_json(&pb::UserInfoResponse::from(&info))),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

async fn realm_device_authorization(
    State(state): State<Arc<AppState>>,
    Path(realm_name): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let realm_id = match resolve_realm_by_name(&state, &realm_name) {
        Ok(id) => id,
        Err(e) => return e,
    };
    let client_id_str = match body.get("client_id").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "client_id required"})),
            )
                .into_response()
        }
    };
    let client_id = match client_id_str.parse::<uuid::Uuid>() {
        Ok(u) => ClientId::new(u),
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid client_id UUID"})),
            )
                .into_response()
        }
    };
    if let Err(resp) = check_token_rate_limit(&state, &realm_id, &client_id) {
        return resp;
    }
    let request = crate::identity::DeviceAuthorizationRequest {
        client_id,
        scope: body
            .get("scope")
            .and_then(|v| v.as_str())
            .map(str::to_string),
    };
    match state.identity.device_authorize(&realm_id, &request) {
        Ok(response) => (
            StatusCode::OK,
            Json(proto_to_rest_json(&pb::DeviceAuthorizationResponse::from(
                &response,
            ))),
        )
            .into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}

async fn realm_register_client_dynamic(
    State(state): State<Arc<AppState>>,
    Path(realm_name): Path<String>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let realm_id = match resolve_realm_by_name(&state, &realm_name) {
        Ok(id) => id,
        Err(e) => return e,
    };
    let realm = match state.identity.get_realm(&realm_id) {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "realm not found"})),
            )
                .into_response()
        }
        Err(e) => return identity_error_to_response(&e).into_response(),
    };
    let dcr_policy = realm.config().dcr_policy.clone().unwrap_or_default();
    match dcr_policy {
        crate::identity::DcrPolicy::Disabled => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error": "dynamic client registration is disabled for this realm"})),
            )
                .into_response();
        }
        crate::identity::DcrPolicy::Open => {
            tracing::warn!(
                realm_id = %realm_id.as_uuid(),
                "Open DCR policy allows unauthenticated client registration; \
                 consider switching to `authenticated` mode"
            );
        }
        crate::identity::DcrPolicy::Authenticated => {
            let token = match extract_bearer_token(&headers) {
                Ok(t) => t,
                Err((status, body)) => return (status, body).into_response(),
            };
            if state.identity.validate_token(&realm_id, &token).is_err() {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({
                        "error": "unauthorized",
                        "error_description": "a valid bearer token is required to register clients in this realm"
                    })),
                )
                    .into_response();
            }
        }
    }
    let client_name = body
        .get("client_name")
        .and_then(|v| v.as_str())
        .unwrap_or("Dynamic Client")
        .to_string();
    let redirect_uris: Vec<String> = body
        .get("redirect_uris")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let base_slug = client_name
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect::<String>();
    let slug = generate_unique_slug(state.clone(), &realm_id, &base_slug).await;
    let request = crate::identity::RegisterClientRequest {
        client_name,
        redirect_uris,
        cors_origins: Vec::new(),
        client_secret: None,
        grant_types: vec!["authorization_code".to_string()],
        require_consent: true,
        client_logo_url: None,
        slug: Some(slug),
        trust_level: crate::identity::ClientTrustLevel::ThirdParty,
        declared_scopes: vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ],
        consent_spans_orgs: false,
        access_token_authorization: crate::identity::AccessTokenAuthorization::Embedded,
        jwks: None,
        jwks_uri: None,
        authorization_signed_response_alg: None,
        profile: crate::identity::ClientProfile::Standard,
        mfa_required: None,
    };
    match state.identity.register_client(&realm_id, &request) {
        Ok(client) => {
            let resp = serde_json::json!({
                "client_id": client.client_id().to_string(),
                "client_name": client.client_name(),
                "redirect_uris": client.redirect_uris(),
                "grant_types": client.grant_types(),
            });
            (StatusCode::CREATED, Json(resp)).into_response()
        }
        Err(e) => identity_error_to_response(&e).into_response(),
    }
}
