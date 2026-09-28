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
use crate::identity::{JwtBearerRequest, StepUpMfaGrantRequest};
use crate::protocol::client_info::{extract_client_ip, PeerAddr};
use crate::protocol::convert::oauth::{
    proto_authorize_to_domain, proto_client_creds_to_domain, proto_token_exchange_to_domain,
};
use crate::protocol::proto::identity::v1 as pb;

use super::now_micros;
use super::{
    check_anonymous_token_rate_limit, check_token_rate_limit, extract_bearer_token,
    extract_realm_id, extract_user_auth, identity_error_response, identity_error_to_response,
    kdf_shed_json_response, make_ip_rate_limit_response, proto_to_rest_json,
    rbac_error_to_response, resolve_realm_by_name, validate_user_token_with_dpop, AppState,
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
        .route(
            "/register",
            post(register_client_dynamic)
                .route_layer(DefaultBodyLimit::max(super::BODY_LIMIT_SMALL)),
        )
        .route(
            "/authorize",
            get(authorize_browser_redirect).post(authorize),
        )
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

/// The one administratively-authenticated route in the OAuth family.
///
/// `POST /clients` is the only handler here that goes through
/// `extract_admin_auth`, so it is the only one that needs the DPoP
/// sender-constraint layer (task 25.17). It is split out of [`routes`] rather
/// than layered in place because the rest of that router must **not** get the
/// layer: those handlers call `validate_user_token_with_dpop` themselves, and
/// validating the proof twice would record its `jti` on the first pass and then
/// reject the second as a replay (RFC 9449 §11.1).
pub(super) fn admin_routes() -> axum::Router<Arc<AppState>> {
    axum::Router::new().route("/clients", axum::routing::post(register_client))
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
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
) -> impl IntoResponse {
    // A-10: per-IP rate cap on all key-discovery endpoints.
    let client_ip = extract_client_ip(&headers, peer_addr, &state.trusted_proxies);
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
/// keys for external token verification, per RFC 7517.
///
/// **Ed25519 (`EdDSA`) only** — this global document carries the global key
/// and the system realm's keys, and the system realm never holds an RS256
/// ID-token key (it has no OAuth clients). A realm whose clients selected RS256
/// ID tokens publishes its RSA key in the realm-scoped JWKS instead
/// (`/realms/{realm}/.well-known/jwks.json`, task 26.55). RSA-2048
/// (`RS256`) and EC P-256 (`ES256`) entries were once published here "for
/// ecosystem compatibility"; Hearth signed with neither, and the ES256 private
/// key was regenerated on every process start, so a relying party that
/// selected that entry cached — for the `max-age=3600` below — a public key
/// whose private half no longer existed (audit 2026-08-28 §4.2#4, §4.15#5).
///
/// Renders the domain [`crate::identity::tokens::JwksDocument`] directly
/// as JSON rather than through the proto `JsonWebKey` type, which carries
/// only a subset of the RFC 7517 field set.
///
/// A-10: subject to the per-IP JWKS rate cap (default 60 rps).
async fn jwks(
    State(state): State<Arc<AppState>>,
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
) -> impl IntoResponse {
    // A-10: per-IP rate cap.
    let client_ip = extract_client_ip(&headers, peer_addr, &state.trusted_proxies);
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

/// Request-body extractor that accepts **either** JSON or
/// `application/x-www-form-urlencoded`.
///
/// RFC 6749 §4.1.3, RFC 7009 §2.1, and RFC 7662 §2.1 mandate that the token,
/// revocation, and introspection endpoints accept form-encoded bodies — a
/// spec-compliant OAuth client or off-the-shelf library sends
/// `application/x-www-form-urlencoded`, and a bare [`Json`] extractor rejects
/// that with `415 Unsupported Media Type` (HEA-2077). Hearth additionally keeps
/// accepting JSON for SDK/programmatic convenience.
///
/// The `Content-Type` header selects the decoder: form-encoded bodies are
/// parsed with `serde_urlencoded`; everything else falls through to the JSON
/// decoder, preserving the historical JSON behaviour (and its rejection
/// responses) for existing clients.
pub(super) struct JsonOrForm<T>(pub(super) T);

impl<T, S> axum::extract::FromRequest<S> for JsonOrForm<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: axum::extract::Request, state: &S) -> Result<Self, Self::Rejection> {
        let is_form = req
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| {
                ct.trim_start()
                    .to_ascii_lowercase()
                    .starts_with("application/x-www-form-urlencoded")
            });

        if is_form {
            let bytes = axum::body::Bytes::from_request(req, state)
                .await
                .map_err(axum::response::IntoResponse::into_response)?;
            let value = serde_urlencoded::from_bytes::<T>(&bytes).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_request",
                        "error_description": e.to_string(),
                    })),
                )
                    .into_response()
            })?;
            Ok(JsonOrForm(value))
        } else {
            let Json(value) = Json::<T>::from_request(req, state)
                .await
                .map_err(axum::response::IntoResponse::into_response)?;
            Ok(JsonOrForm(value))
        }
    }
}

/// Hearth's private grant type for redeeming a magic link at `/token`.
///
/// All seven SDKs post this value; the endpoint had no arm for it, so the
/// passwordless flow could not complete (audit 2026-08-28 §4.24#6).
const MAGIC_LINK_GRANT_TYPE: &str = "urn:hearth:grant-type:magic-link";

/// Redeems a magic-link token and issues an access/refresh pair.
///
/// Single use is enforced by `validate_magic_link`, which marks the record
/// consumed before returning. The resulting session is a normal browserless
/// session, so revocation and the session-version feed behave as usual.
fn exchange_magic_link(
    state: &Arc<AppState>,
    realm_id: &crate::core::RealmId,
    token: &str,
    dpop_jkt: Option<&str>,
) -> Result<serde_json::Value, crate::identity::IdentityError> {
    let user_id = state.identity.validate_magic_link(realm_id, token)?;
    let session = state.identity.create_session(
        realm_id,
        &user_id,
        &crate::identity::SessionContext::default(),
    )?;
    let tokens = state
        .identity
        .issue_tokens(realm_id, &user_id, session.id())?;
    crate::metrics::metrics()
        .tokens_issued_total
        .with_label_values(&[realm_id.as_uuid().to_string().as_str(), "magic_link"])
        .inc();
    Ok(serde_json::json!({
        "access_token": tokens.access_token(),
        "refresh_token": tokens.refresh_token(),
        "token_type": if dpop_jkt.is_some() { "DPoP" } else { "Bearer" },
        "expires_in": 900,
    }))
}

/// HTTP request body for token exchange.
///
/// Uses a flat struct because the proto `TokenExchangeRequest` doesn't cover
/// the multi-grant-type dispatch (`authorization_code` vs `refresh_token`).
#[derive(Debug, Deserialize)]
struct HttpTokenRequest {
    /// RFC 6749 §3.2.1: REQUIRED only "if the client is not authenticating
    /// with the authorization server" — a strict `client_secret_basic` client
    /// omits it, so the handlers backfill it from the Basic username via
    /// [`backfill_client_id_from_basic`] before any dispatch (HEA-2112).
    #[serde(default)]
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
    // Magic-link grant (`urn:hearth:grant-type:magic-link`) — the opaque
    // single-use token from the emailed link (audit 2026-08-28 §4.24#6).
    #[serde(default)]
    token: Option<String>,
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
/// per RFC 6749 §2.3.1, or with a `private_key_jwt` assertion (RFC 7523
/// §2.2) — the only method a secretless `private_key_jwt` client has.
#[derive(Debug, Deserialize)]
struct HttpRevocationBody {
    token: String,
    #[serde(default)]
    token_type_hint: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    client_assertion_type: Option<String>,
    #[serde(default)]
    client_assertion: Option<String>,
}

/// HTTP request body for token introspection (RFC 7662).
///
/// Extends the proto type with optional client credentials for HTTP endpoints.
/// Clients may authenticate via HTTP Basic Auth or via these body fields
/// per RFC 6749 §2.3.1, or with a `private_key_jwt` assertion (RFC 7523 §2.2).
/// Only confidential clients are served (RFC 7662 §2.1, task 26.43).
#[derive(Debug, Deserialize)]
struct HttpIntrospectionBody {
    token: String,
    #[serde(default)]
    token_type_hint: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    client_assertion_type: Option<String>,
    #[serde(default)]
    client_assertion: Option<String>,
}

/// Parses HTTP Basic Auth credentials from the `Authorization` header.
///
/// Returns `Some((client_id, client_secret))` on success, `None` if the header
/// is absent or not Basic Auth. Both values are form-urldecoded per RFC 6749
/// §2.3.1, which requires clients to apply the `application/x-www-form-urlencoded`
/// encoding to the userid and password before base64 (HEA-2112).
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
    Some((form_urldecode_lenient(id), form_urldecode_lenient(secret)))
}

/// Returns the numeric value of an ASCII hex digit, or `None`.
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decodes an `application/x-www-form-urlencoded` value per RFC 6749
/// Appendix B: `+` becomes a space and `%XX` a percent-encoded octet.
///
/// Lenient on malformed input so legacy clients that never encoded keep
/// authenticating: a `%` not followed by two hex digits passes through
/// unchanged, and invalid UTF-8 after decoding falls back to the raw input.
fn form_urldecode_lenient(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => match (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                (Some(hi), Some(lo)) => {
                    out.push((hi << 4) | lo);
                    i += 3;
                }
                _ => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| input.to_string())
}

/// Returns `true` when a body `client_secret` is absent or equals the Basic
/// one. The comparison is constant-time and length-blind
/// ([`crate::core::ct_eq_secret_str`]) because the operands are client
/// secrets, even though both arrive in the same request.
fn body_secret_agrees(body_secret: Option<&str>, basic_secret: &str) -> bool {
    body_secret.is_none_or(|b| crate::core::ct_eq_secret_str(b, basic_secret))
}

/// Builds the RFC 6749 §5.2 `invalid_request` rejection for a request that
/// supplies both Basic and body client credentials that disagree — using
/// more than one client authentication mechanism per request is forbidden
/// by RFC 6749 §2.3.1 (HEA-2112).
fn basic_body_mismatch_response() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "error": "invalid_request",
            "error_description":
                "client credentials in Authorization header and request body disagree"
        })),
    )
        .into_response()
}

/// Resolves the one effective client credential pair for a request, applying
/// RFC 6749 §2.3.1 to the `client_secret_basic` header and the
/// `client_secret_post` body fields.
///
/// This is the single place the two mechanisms are reconciled. `Authorization:
/// Basic` wins when present; when both are supplied they must agree, because
/// §2.3.1 forbids using more than one client authentication mechanism per
/// request. An explicitly empty body field (`client_id=` / `client_secret=`)
/// normalizes to absent so it cannot read as a disagreeing credential
/// (HEA-2112).
///
/// Returns `(None, None)` when the request carries no client identity at all —
/// each caller decides whether that is an error, since the token grant arms and
/// the endpoint-auth helper report it differently. Audit §4.22#5 (task 22.14):
/// the `client_credentials` arm previously read `body` alone, so a client
/// following the `client_secret_basic` method that discovery and DCR advertise
/// arrived with an empty secret and could never authenticate.
fn resolve_client_credentials(
    headers: &HeaderMap,
    body_client_id: Option<&str>,
    body_client_secret: Option<&str>,
) -> Result<(Option<String>, Option<String>), Response> {
    // Normalize at the helper boundary so every endpoint that authenticates
    // through here gets the empty-field-is-absent rule by construction —
    // applying it callsite-by-callsite is how /introspect and /revoke were
    // missed (HEA-2112).
    let body_client_id = body_client_id.and_then(non_empty_credential);
    let body_client_secret = body_client_secret.and_then(non_empty_credential);

    if let Some((id, sec)) = parse_basic_auth(headers) {
        // `Basic base64("<id>:")` carries an identifier and NO secret: an
        // empty password is absent, as an empty body field is. Returned as
        // `Some("")` it read as a (wrong) secret, so a public client that
        // identified itself this way was refused at `/as/par` and `/revoke`
        // while the code exchange accepted it.
        let sec = non_empty_credential(&sec).map(str::to_string);
        let agrees = match (&sec, body_client_secret) {
            (Some(basic), body) => body_secret_agrees(body, basic),
            (None, body) => body.is_none(),
        };
        if body_client_id.is_some_and(|b| b != id) || !agrees {
            return Err(basic_body_mismatch_response());
        }
        return Ok((Some(id), sec));
    }
    Ok((
        body_client_id.map(str::to_string),
        body_client_secret.map(str::to_string),
    ))
}

/// Extracts client credentials from HTTP Basic Auth or body parameters and
/// verifies them against the stored client record.
///
/// Returns the authenticated `ClientId` on success, or a 401 response if
/// client_id is missing, the client does not exist, or the secret is wrong.
/// Confidential clients require a secret; clients with no stored secret are
/// accepted with client_id alone — including a `private_key_jwt` client, so
/// `/revoke` layers [`verify_revocation_client`] on top, and `/introspect`
/// uses [`verify_introspection_client`] instead (task 26.43).
async fn verify_endpoint_client(
    state: &AppState,
    realm_id: &RealmId,
    headers: &HeaderMap,
    body_client_id: Option<&str>,
    body_client_secret: Option<&str>,
) -> Result<ClientId, Response> {
    // Prefer Basic Auth (RFC 6749 §2.3.1); fall back to body parameters.
    let (raw_id, secret) =
        match resolve_client_credentials(headers, body_client_id, body_client_secret)? {
            (Some(id), secret) => (id, secret),
            (None, _) => {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    [("www-authenticate", "Basic realm=\"hearth\"")],
                    Json(serde_json::json!({"error": "client_id required"})),
                )
                    .into_response())
            }
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

    crate::identity::client_auth::authenticate_client(
        &state.identity,
        realm_id,
        &client_id,
        secret.as_deref(),
    )
    .await
    .map(|()| client_id)
    .map_err(|e| client_auth_refusal(&e))
}

/// The response for a failed client authentication: a shed Argon2id
/// verification is `503` + `Retry-After`; a FAPI auth-method refusal is `401
/// invalid_client` saying `private_key_jwt` is required; anything else is the
/// uniform `401 invalid_client` (RFC 6749 §5.2), which reveals nothing about
/// the client.
fn client_auth_refusal(err: &crate::identity::IdentityError) -> Response {
    match err {
        crate::identity::IdentityError::KdfOverloaded { retry_after } => {
            kdf_shed_json_response(*retry_after)
        }
        crate::identity::IdentityError::PrivateKeyJwtRequired => {
            let mut resp = identity_error_to_response(err).into_response();
            resp.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_static("Basic realm=\"hearth\""),
            );
            resp
        }
        _ => invalid_client_response(),
    }
}

/// Refuses a request that carries no `private_key_jwt` assertion in a FAPI
/// 2.0 Advanced realm (`docs/specs/OIDC.md` §2.1.2 item 6) — for the paths
/// that would otherwise accept a public client (`none`) without asking the
/// engine. The answer depends on the realm alone.
fn refuse_none_in_fapi_advanced_realm(
    state: &AppState,
    realm_id: &RealmId,
) -> Result<(), Response> {
    let advanced = state
        .identity
        .get_realm(realm_id)
        .map_err(|e| identity_error_to_response(&e).into_response())?
        .is_some_and(|realm| {
            realm.config().fapi_profile == Some(crate::identity::FapiProfile::Advanced)
        });
    if advanced {
        return Err(client_auth_refusal(
            &crate::identity::IdentityError::PrivateKeyJwtRequired,
        ));
    }
    Ok(())
}

/// Which per-client budget an endpoint draws on.
#[derive(Clone, Copy)]
enum ClientBudget {
    /// The `/token` bucket (`/introspect`, `/revoke`).
    Token,
    /// `/as/par`'s own bucket, same limit.
    Par,
}

/// Checks the per-client rate limit for an endpoint that authenticates a
/// client (`/as/par`, `/introspect`, `/revoke` and their twins) BEFORE the
/// client is verified, as `/token` does: keyed on the CLAIMED client (body
/// `client_id`, else the Basic username) or, when none parses, on the client
/// IP. Limiting only after verification let a flood of wrong secrets through
/// unbounded — each one hashed.
fn check_claimed_client_rate_limit(
    state: &AppState,
    realm_id: &RealmId,
    headers: &HeaderMap,
    body_client_id: Option<&str>,
    peer_addr: std::net::SocketAddr,
    budget: ClientBudget,
) -> Result<(), Response> {
    let claimed = body_client_id
        .and_then(non_empty_credential)
        .map(str::to_string)
        .or_else(|| parse_basic_auth(headers).map(|(id, _)| id));
    let claimed = claimed
        .and_then(|raw| raw.parse::<uuid::Uuid>().ok())
        .map(ClientId::new);
    match (budget, claimed) {
        (ClientBudget::Par, claimed) => {
            let client_ip = extract_client_ip(headers, peer_addr, &state.trusted_proxies);
            super::auth::check_client_or_ip_rate_limit(
                &state.par_rate_limiter,
                realm_id,
                claimed.as_ref(),
                &client_ip,
            )
        }
        (ClientBudget::Token, Some(client_id)) => {
            check_token_rate_limit(state, realm_id, &client_id)
        }
        (ClientBudget::Token, None) => {
            let client_ip = extract_client_ip(headers, peer_addr, &state.trusted_proxies);
            check_anonymous_token_rate_limit(state, realm_id, &client_ip)
        }
    }
}

/// Authenticates a client by its `private_key_jwt` assertion when the request
/// carries one, else as [`verify_endpoint_client`] does (a secret, or a
/// public client's `client_id`). For the token-endpoint arms that the engine
/// does not authenticate itself (`refresh_token`, token exchange).
async fn verify_endpoint_client_or_assertion(
    state: &AppState,
    realm_id: &RealmId,
    headers: &HeaderMap,
    body_client_id: Option<&str>,
    body_client_secret: Option<&str>,
    assertion_type: Option<&str>,
    assertion: Option<&str>,
) -> Result<ClientId, Response> {
    let assertion_type = assertion_type.and_then(non_empty_credential);
    let assertion = assertion.and_then(non_empty_credential);
    if assertion_type.is_some() || assertion.is_some() {
        return verify_assertion_client(
            state,
            realm_id,
            headers,
            body_client_id,
            body_client_secret,
            assertion_type,
            assertion,
        );
    }
    verify_endpoint_client(state, realm_id, headers, body_client_id, body_client_secret).await
}

/// The uniform RFC 6749 §5.2 `invalid_client` refusal for introspection and
/// revocation.
fn invalid_client_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [("www-authenticate", "Basic realm=\"hearth\"")],
        Json(serde_json::json!({"error": "invalid_client"})),
    )
        .into_response()
}

/// Authenticates the caller of the token-introspection endpoint, which serves
/// CONFIDENTIAL clients only (RFC 7662 §2.1 and §4, task 26.43).
///
/// A public client is refused with `401 invalid_client`: its `client_id` is
/// public by construction — it travels in every browser authorization request
/// and dynamic registration hands it out — so accepting it alone made the
/// endpoint an anonymous token-information oracle. Accepted methods are
/// `client_secret_basic`, `client_secret_post` and `private_key_jwt`, matching
/// `introspection_endpoint_auth_methods_supported` in discovery.
///
/// `/revoke` uses [`verify_revocation_client`], which accepts a public client:
/// RFC 7009 §2.1 lets public clients revoke.
async fn verify_introspection_client(
    state: &AppState,
    realm_id: &RealmId,
    headers: &HeaderMap,
    body: &HttpIntrospectionBody,
) -> Result<ClientId, Response> {
    let assertion_type = body
        .client_assertion_type
        .as_deref()
        .and_then(non_empty_credential);
    let assertion = body
        .client_assertion
        .as_deref()
        .and_then(non_empty_credential);

    if assertion_type.is_none() && assertion.is_none() {
        let (raw_id, secret) = match resolve_client_credentials(
            headers,
            body.client_id.as_deref(),
            body.client_secret.as_deref(),
        )? {
            (Some(id), secret) => (id, secret),
            (None, _) => return Err(invalid_client_response()),
        };
        let client_id = raw_id
            .parse::<uuid::Uuid>()
            .map(ClientId::new)
            .map_err(|_| invalid_client_response())?;
        return crate::identity::client_auth::authenticate_confidential_client(
            &state.identity,
            realm_id,
            &client_id,
            secret.as_deref(),
        )
        .await
        .map(|()| client_id)
        .map_err(|e| client_auth_refusal(&e));
    }
    verify_assertion_client(
        state,
        realm_id,
        headers,
        body.client_id.as_deref(),
        body.client_secret.as_deref(),
        assertion_type,
        assertion,
    )
}

/// Authenticates the revocation caller (RFC 7009 §2.1).
///
/// A public client is accepted on its `client_id` alone and a secret-bearing
/// confidential client by its secret, exactly as [`verify_endpoint_client`]
/// does. A `private_key_jwt` client authenticates with its assertion — and,
/// because its `client_id` is as public as anyone's, is REFUSED when it
/// presents no assertion: [`verify_endpoint_client`] treats any client with no
/// stored secret as public, so a FAPI 2.0 client (which may not hold a secret)
/// could otherwise be impersonated here by anyone who knew its identifier.
async fn verify_revocation_client(
    state: &AppState,
    realm_id: &RealmId,
    headers: &HeaderMap,
    body: &HttpRevocationBody,
) -> Result<ClientId, Response> {
    let assertion_type = body
        .client_assertion_type
        .as_deref()
        .and_then(non_empty_credential);
    let assertion = body
        .client_assertion
        .as_deref()
        .and_then(non_empty_credential);
    if assertion_type.is_some() || assertion.is_some() {
        return verify_assertion_client(
            state,
            realm_id,
            headers,
            body.client_id.as_deref(),
            body.client_secret.as_deref(),
            assertion_type,
            assertion,
        );
    }

    let client_id = verify_endpoint_client(
        state,
        realm_id,
        headers,
        body.client_id.as_deref(),
        body.client_secret.as_deref(),
    )
    .await?;
    match state.identity.get_client(realm_id, &client_id) {
        Ok(Some(client)) if client.requires_client_assertion() => Err(invalid_client_response()),
        Ok(_) => Ok(client_id),
        Err(e) => Err(identity_error_to_response(&e).into_response()),
    }
}

/// The `private_key_jwt` fields of a request, and who verifies them.
#[derive(Clone, Copy)]
pub(super) struct ClientAssertion<'a> {
    /// `client_assertion_type`, if present.
    pub(super) assertion_type: Option<&'a str>,
    /// `client_assertion`, if present.
    pub(super) assertion: Option<&'a str>,
    /// Who verifies a presented assertion.
    pub(super) check: AssertionCheck,
}

#[cfg(test)]
impl ClientAssertion<'_> {
    /// A request shape that has no assertion fields.
    pub(super) const NONE: Self = ClientAssertion {
        assertion_type: None,
        assertion: None,
        check: AssertionCheck::Here,
    };
}

/// Who verifies a `private_key_jwt` assertion presented to a grant arm.
#[derive(Clone, Copy)]
pub(super) enum AssertionCheck {
    /// The engine's grant verifies it (the `authorization_code` exchange).
    ByEngine,
    /// The protocol layer verifies it before the grant runs.
    Here,
}

/// `400 invalid_request`: more than one client authentication method (RFC
/// 6749 §2.3).
fn multiple_auth_methods_response() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "error": "invalid_request",
            "error_description": "more than one client authentication method was used"
        })),
    )
        .into_response()
}

/// Token-endpoint grants whose arm authenticates the client itself, and so
/// verifies a presented `private_key_jwt` assertion (directly or in the
/// engine's grant).
const GRANTS_AUTHENTICATING_CLIENT: [&str; 5] = [
    "authorization_code",
    "refresh_token",
    "client_credentials",
    "urn:ietf:params:oauth:grant-type:device_code",
    "urn:ietf:params:oauth:grant-type:token-exchange",
];

/// Screens the `private_key_jwt` fields of a request (RFC 7523 §2.2) before
/// anything else authenticates the client.
///
/// A request that carries EITHER `client_assertion` or `client_assertion_type`
/// has attempted `private_key_jwt`, whatever the values: it never falls
/// through to a secret, to `none`, or to "no client authentication". So:
///
/// - neither field (blank counts as absent) → `Ok(None)`;
/// - a field plus a secret, Basic or body → `400 invalid_request` (RFC 6749
///   §2.3: one authentication method per request);
/// - a type other than the jwt-bearer URN, no type, or no assertion → `401
///   invalid_client`;
/// - otherwise `Ok(Some(assertion))`, which the caller MUST verify (here via
///   [`verify_assertion_client`], or by the engine's grant).
fn screen_presented_assertion<'a>(
    headers: &HeaderMap,
    body_client_secret: Option<&str>,
    assertion_type: Option<&'a str>,
    assertion: Option<&'a str>,
) -> Result<Option<&'a str>, Response> {
    let presented =
        crate::identity::client_auth::presented_client_assertion(assertion_type, assertion);
    if matches!(presented, Ok(None)) {
        return Ok(None);
    }
    // RFC 6749 §2.3 / §5.2: a client MUST NOT use more than one
    // authentication mechanism in a request.
    if parse_basic_auth(headers).is_some()
        || body_client_secret.and_then(non_empty_credential).is_some()
    {
        return Err(multiple_auth_methods_response());
    }
    presented.map_err(|_| invalid_client_response())
}

/// Authenticates a client by its `private_key_jwt` assertion (RFC 7523 §2.2)
/// at an endpoint that also accepts secrets (`/introspect`, `/revoke`).
///
/// The request is screened by [`screen_presented_assertion`] (a secret beside
/// the assertion is `400 invalid_request`); any other failure — including a
/// request with no assertion at all — is `401 invalid_client`.
fn verify_assertion_client(
    state: &AppState,
    realm_id: &RealmId,
    headers: &HeaderMap,
    body_client_id: Option<&str>,
    body_client_secret: Option<&str>,
    assertion_type: Option<&str>,
    assertion: Option<&str>,
) -> Result<ClientId, Response> {
    let Some(assertion) =
        screen_presented_assertion(headers, body_client_secret, assertion_type, assertion)?
    else {
        return Err(invalid_client_response());
    };
    // The assertion's `iss`/`sub` must equal this id — the engine checks it.
    let client_id = body_client_id
        .and_then(non_empty_credential)
        .and_then(|raw| raw.parse::<uuid::Uuid>().ok())
        .map(ClientId::new)
        .ok_or_else(invalid_client_response)?;
    state
        .identity
        .verify_client_assertion(realm_id, &client_id, assertion)
        .map(|()| client_id)
        .map_err(|_| invalid_client_response())
}

/// Backfills an absent or empty body `client_id` from the Basic Auth username.
///
/// RFC 6749 §3.2.1 requires body `client_id` only when the client is not
/// authenticating with the authorization server; a strictly compliant
/// `client_secret_basic` client carries its identity solely in the
/// Authorization header. Running this before dispatch gives per-client rate
/// limiting, CORS, client-auth enforcement, and every grant arm one effective
/// client identity. The §2.3.1 disagreement checks downstream are unaffected:
/// a backfilled id always equals the Basic username.
fn backfill_client_id_from_basic(headers: &HeaderMap, body: &mut HttpTokenRequest) {
    if body.client_id.trim().is_empty() {
        if let Some((basic_id, _)) = parse_basic_auth(headers) {
            body.client_id = basic_id;
        }
    }
}

/// Treats an explicitly empty form credential (`client_id=` /
/// `client_secret=`) as absent so it cannot read as a disagreeing credential
/// next to Basic auth — RFC 6749 §2.3.1 rejects conflicting credentials, not
/// empty fields. Applied inside `verify_endpoint_client` and
/// `enforce_confidential_client_auth`, so every endpoint authenticating
/// through them gets the rule without per-callsite plumbing (HEA-2112).
fn non_empty_credential(field: &str) -> Option<&str> {
    let trimmed = field.trim();
    (!trimmed.is_empty()).then_some(field)
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
/// - public clients (no secret, no assertion key, no JWKS) → `Ok(())`, since
///   PKCE alone authenticates them (RFC 9700 §2.1.1) — except in a FAPI 2.0
///   Advanced realm, which accepts only `private_key_jwt`;
/// - every other client → the secret (HTTP Basic Auth preferred, body
///   `client_secret` fallback) must verify, else `Err` with a 401. A client
///   that holds keys instead of a secret authenticates only with its
///   assertion.
///
/// A request carrying a `private_key_jwt` assertion must use no other method
/// (`400 invalid_request`); the assertion is verified by the engine's grant
/// ([`AssertionCheck::ByEngine`], `authorization_code`) or here
/// ([`AssertionCheck::Here`]: the `device_code` grant and
/// `/device_authorization`, both routes, which read `client_assertion` /
/// `client_assertion_type` from a form or JSON body).
///
/// 22.25 (audit 2026-08-28 §4.25#3): the *decision* above is unchanged, but the
/// *work* is no longer a function of what the lookup found. Equalising
/// `IdentityEngine::authenticate_client` alone did not close the oracle,
/// because this gate short-circuits on the unknown and public arms before ever
/// reaching the engine — so `POST /token` still answered an unknown
/// `client_id` in microseconds and a registered confidential one in
/// Argon2id-milliseconds. Hashing now depends only on the caller's own input:
/// a presented secret costs exactly one verification on every arm (against a
/// realm-parameterised dummy hash when there is no stored one), and presenting
/// no secret costs none, which keeps the public-client browser flow off the
/// Argon2id path entirely.
pub(super) async fn enforce_confidential_client_auth(
    state: &AppState,
    realm_id: &RealmId,
    headers: &HeaderMap,
    body_client_id: &str,
    body_client_secret: Option<&str>,
    assertion: ClientAssertion<'_>,
) -> Result<(), Response> {
    // Same boundary normalization as `verify_endpoint_client` (HEA-2112).
    let body_client_secret = body_client_secret.and_then(non_empty_credential);

    // A presented assertion field is a `private_key_jwt` attempt: screened
    // here (one method, the jwt-bearer type, an assertion present) and then
    // verified — never read as "no assertion" and waved on to the secret
    // check, which let a secret-holding client redeem a code with a junk
    // assertion and no secret.
    if screen_presented_assertion(
        headers,
        body_client_secret,
        assertion.assertion_type,
        assertion.assertion,
    )?
    .is_some()
    {
        return match assertion.check {
            // The grant verifies the (well-formed) assertion itself.
            AssertionCheck::ByEngine => Ok(()),
            AssertionCheck::Here => verify_assertion_client(
                state,
                realm_id,
                headers,
                Some(body_client_id),
                body_client_secret,
                assertion.assertion_type,
                assertion.assertion,
            )
            .map(|_| ()),
        };
    }
    // No assertion: this request authenticates with a secret or with `none`,
    // neither of which a FAPI 2.0 Advanced realm accepts.
    refuse_none_in_fapi_advanced_realm(state, realm_id)?;

    // RFC 6749 §2.3.1: a request must not use more than one client
    // authentication mechanism. If a Basic header is present, its username
    // must name the same client as the body `client_id` (previously the
    // Basic secret was verified against the *body's* client id) and any
    // body `client_secret` must match the Basic one (HEA-2112).
    // An empty Basic password is no secret, as in `resolve_client_credentials`.
    let basic = parse_basic_auth(headers)
        .map(|(id, secret)| (id, non_empty_credential(&secret).map(str::to_string)));
    if let Some((basic_id, basic_secret)) = &basic {
        // An absent/empty body client_id is fine — RFC 6749 §4.1.3 only
        // requires it when the client is not otherwise authenticating.
        let secrets_agree = match basic_secret {
            Some(basic_secret) => body_secret_agrees(body_client_secret, basic_secret),
            None => body_client_secret.is_none(),
        };
        if non_empty_credential(body_client_id).is_some_and(|b| basic_id != b) || !secrets_agree {
            return Err(basic_body_mismatch_response());
        }
    }
    let Ok(uuid) = body_client_id.parse::<uuid::Uuid>() else {
        return Ok(());
    };
    let client_id = ClientId::new(uuid);
    let client = match state.identity.get_client(realm_id, &client_id) {
        Ok(c) => c,
        Err(e) => return Err(identity_error_to_response(&e).into_response()),
    };
    // A valid secret is mandatory for a confidential client. Prefer HTTP Basic
    // Auth credentials (RFC 6749 §2.3.1), fall back to the body
    // `client_secret`.
    let secret = basic
        .and_then(|(_, s)| s)
        .or_else(|| body_client_secret.map(str::to_string));

    // 22.25: run the verification before the outcome is decided, on every arm,
    // whenever the caller presented a secret. `authenticate_client` performs
    // exactly one Argon2id verification for a presented secret regardless of
    // whether the client exists or holds a hash, so the unknown and public arms
    // below now cost what the confidential arm costs. The result is discarded
    // on the arms that do not consult it — the work is the point.
    let verified = match secret.as_deref() {
        Some(s) => Some(
            crate::identity::client_auth::authenticate_client(
                &state.identity,
                realm_id,
                &client_id,
                Some(s),
            )
            .await,
        ),
        None => None,
    };

    // A shed Argon2id verification answers 503 on every arm: the caller's
    // own request cost the gate a slot either way. A FAPI auth-method refusal
    // (the realm is Advanced, or a FAPI 2.0 client proved a secret) says so.
    if let Some(Err(
        e @ (crate::identity::IdentityError::KdfOverloaded { .. }
        | crate::identity::IdentityError::PrivateKeyJwtRequired),
    )) = &verified
    {
        return Err(client_auth_refusal(e));
    }
    let Some(client) = client else {
        return Ok(());
    };
    if client.is_public() {
        return Ok(());
    }
    match verified {
        Some(Ok(())) => Ok(()),
        _ => Err((
            StatusCode::UNAUTHORIZED,
            [("www-authenticate", "Basic realm=\"hearth\"")],
            Json(serde_json::json!({
                "error": "invalid_client",
                "error_description": "client authentication failed"
            })),
        )
            .into_response()),
    }
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

    // ===== HEA-2112: RFC 6749 §2.3.1 form-urldecoding of Basic credentials =====

    #[test]
    fn form_urldecode_decodes_escapes_and_plus() {
        assert_eq!(
            form_urldecode_lenient("sec+ret%25%2B%3A%26%3D"),
            "sec ret%+:&="
        );
        assert_eq!(form_urldecode_lenient("plain-secret"), "plain-secret");
        assert_eq!(form_urldecode_lenient(""), "");
    }

    #[test]
    fn form_urldecode_passes_invalid_escapes_through() {
        // `%` not followed by two hex digits is not an escape.
        assert_eq!(form_urldecode_lenient("100%legit"), "100%legit");
        assert_eq!(form_urldecode_lenient("trailing%"), "trailing%");
        assert_eq!(form_urldecode_lenient("short%2"), "short%2");
    }

    #[test]
    fn form_urldecode_falls_back_to_raw_on_invalid_utf8() {
        // %FF decodes to a lone 0xFF byte — invalid UTF-8, so the raw
        // input is returned unchanged.
        assert_eq!(form_urldecode_lenient("bad%FFseq"), "bad%FFseq");
    }

    #[test]
    fn parse_basic_auth_form_urldecodes_both_credentials() {
        use base64::Engine as _;
        let mut headers = HeaderMap::new();
        let encoded = base64::engine::general_purpose::STANDARD.encode("client%2Did:sec+ret%25end");
        headers.insert(
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderValue::from_str(&format!("Basic {encoded}")).expect("valid header"),
        );
        let (id, secret) = parse_basic_auth(&headers).expect("must parse");
        assert_eq!(id, "client-id");
        assert_eq!(secret, "sec ret%end");
    }

    fn basic_headers(id: &str, secret: &str) -> HeaderMap {
        use base64::Engine as _;
        let mut headers = HeaderMap::new();
        let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{id}:{secret}"));
        headers.insert(
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderValue::from_str(&format!("Basic {encoded}")).expect("valid header"),
        );
        headers
    }

    #[test]
    fn body_secret_agreement_accepts_a_match_or_an_absent_body() {
        assert!(body_secret_agrees(Some("s3cret-value"), "s3cret-value"));
        assert!(body_secret_agrees(None, "s3cret-value"));
    }

    #[test]
    fn body_secret_agreement_rejects_a_same_length_mismatch() {
        assert!(!body_secret_agrees(Some("s3cret-valuf"), "s3cret-value"));
    }

    #[test]
    fn body_secret_agreement_rejects_a_different_length() {
        assert!(!body_secret_agrees(Some("s3cret-valu"), "s3cret-value"));
        assert!(!body_secret_agrees(Some("s3cret-value0"), "s3cret-value"));
    }

    #[test]
    fn resolve_client_credentials_checks_the_body_secret_against_basic() {
        let headers = basic_headers("cid", "s3cret-value");
        let (id, sec) = resolve_client_credentials(&headers, Some("cid"), Some("s3cret-value"))
            .expect("agreeing Basic and body credentials must resolve");
        assert_eq!(id.as_deref(), Some("cid"));
        assert_eq!(sec.as_deref(), Some("s3cret-value"));

        for wrong in ["s3cret-valuf", "s3cret-valu", "s3cret-value0"] {
            let err = resolve_client_credentials(&headers, Some("cid"), Some(wrong))
                .expect_err("a disagreeing body secret must be refused");
            assert_eq!(err.status(), StatusCode::BAD_REQUEST, "wrong = {wrong}");
        }
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

/// Registration metadata the proto `RegisterClientRequest` does not carry,
/// taken out of a registration request's raw JSON body before the rest is
/// decoded as the proto (which refuses unknown fields).
#[derive(Default)]
struct RegistrationExtras {
    /// `jwks` (RFC 7591 §2) as the JSON the engine stores.
    jwks: Option<String>,
    /// `jwks_uri` (RFC 7591 §2).
    jwks_uri: Option<String>,
    /// `profile`: `"standard"` or `"fapi2"`.
    profile: Option<crate::identity::ClientProfile>,
    /// `authorization_signed_response_alg` (JARM).
    authorization_signed_response_alg: Option<String>,
    /// `token_endpoint_auth_method` (RFC 7591 §2).
    token_endpoint_auth_method: Option<String>,
}

/// Splits a registration body into the proto request and the
/// [`RegistrationExtras`]. `jwks` may be the RFC 7591 JSON object or a JSON
/// string holding one (the form the admin API documented). `Err` is a
/// description for the caller's error body.
fn split_registration_body(
    raw: serde_json::Value,
) -> Result<(pb::RegisterClientRequest, RegistrationExtras), String> {
    let serde_json::Value::Object(mut map) = raw else {
        return Err("the registration body must be a JSON object".to_string());
    };
    let optional_string = |value: Option<serde_json::Value>, field: &str| match value {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(format!("{field} must be a string")),
    };
    let jwks = match map.remove("jwks") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(s)) => Some(s),
        Some(object @ serde_json::Value::Object(_)) => Some(object.to_string()),
        Some(_) => return Err("jwks must be a JSON Web Key Set object".to_string()),
    };
    let jwks_uri = optional_string(map.remove("jwks_uri"), "jwks_uri")?;
    let profile = match optional_string(map.remove("profile"), "profile")?.as_deref() {
        None => None,
        Some("standard") => Some(crate::identity::ClientProfile::Standard),
        Some("fapi2") => Some(crate::identity::ClientProfile::Fapi2),
        Some(_) => return Err("profile must be \"standard\" or \"fapi2\"".to_string()),
    };
    let authorization_signed_response_alg = optional_string(
        map.remove("authorization_signed_response_alg"),
        "authorization_signed_response_alg",
    )?;
    let token_endpoint_auth_method = optional_string(
        map.remove("token_endpoint_auth_method"),
        "token_endpoint_auth_method",
    )?;
    // RFC 7591 `response_types`: only `code` is served; accept it (the FAPI
    // guide's example sends it) and refuse anything else.
    if let Some(types) = map.remove("response_types") {
        let only_code = types
            .as_array()
            .is_some_and(|t| t.iter().all(|v| v.as_str() == Some("code")));
        if !only_code {
            return Err("response_types must be [\"code\"]".to_string());
        }
    }
    let body: pb::RegisterClientRequest = serde_json::from_value(serde_json::Value::Object(map))
        .map_err(|e| format!("invalid registration metadata: {e}"))?;
    Ok((
        body,
        RegistrationExtras {
            jwks,
            jwks_uri,
            profile,
            authorization_signed_response_alg,
            token_endpoint_auth_method,
        },
    ))
}

/// Decodes an administrative registration body (`POST /clients`, `POST
/// /admin/applications`) into the domain request, including `jwks`,
/// `jwks_uri`, `profile` and `authorization_signed_response_alg` — without
/// which an operator could not register a FAPI 2.0 (`private_key_jwt`) client
/// over REST. A secret in the body is dropped (Hearth mints secrets itself).
///
/// # Errors
///
/// `422` with a description when the body does not decode.
pub(super) fn admin_registration_request(
    raw: serde_json::Value,
) -> Result<crate::identity::RegisterClientRequest, Response> {
    let (body, extras) = split_registration_body(raw).map_err(|description| {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": description})),
        )
            .into_response()
    })?;
    let mut request = crate::identity::RegisterClientRequest::from(body);
    request.client_secret = None;
    request.jwks = extras.jwks;
    request.jwks_uri = extras.jwks_uri;
    if let Some(profile) = extras.profile {
        request.profile = profile;
    }
    request.authorization_signed_response_alg = extras.authorization_signed_response_alg;
    Ok(request)
}

/// How a dynamically registered client authenticates at the token endpoint
/// (RFC 7591 §2 `token_endpoint_auth_method`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum DcrAuthMethod {
    /// `client_secret_basic`: Hearth mints a secret.
    SecretBasic,
    /// `client_secret_post`: Hearth mints a secret.
    SecretPost,
    /// `private_key_jwt` with the registered inline `jwks`.
    PrivateKeyJwt,
    /// `none`: a public client (PKCE).
    None,
}

impl DcrAuthMethod {
    fn as_str(self) -> &'static str {
        match self {
            Self::SecretBasic => "client_secret_basic",
            Self::SecretPost => "client_secret_post",
            Self::PrivateKeyJwt => "private_key_jwt",
            Self::None => "none",
        }
    }

    fn mints_secret(self) -> bool {
        matches!(self, Self::SecretBasic | Self::SecretPost)
    }
}

/// Resolves and checks a dynamic registration's client authentication.
///
/// - `jwks` (validated: public signing keys only) and `jwks_uri` are mutually
///   exclusive (RFC 7591 §2);
/// - an omitted method is `private_key_jwt` when the client registered a
///   `jwks`, else `default`;
/// - `private_key_jwt` needs an inline `jwks` — a `jwks_uri` is never
///   fetched, so such a client could never authenticate;
/// - a FAPI 2.0 Advanced realm accepts `private_key_jwt` only
///   (`docs/specs/OIDC.md` §2.1.2 item 6): a secret or public client
///   registered there could never authenticate.
///
/// `Err` is the RFC 7591 §3.2.2 `invalid_client_metadata` response.
fn resolve_dcr_auth_method(
    extras: &RegistrationExtras,
    default: DcrAuthMethod,
    fapi_advanced: bool,
) -> Result<DcrAuthMethod, Response> {
    if extras.jwks.is_some() && extras.jwks_uri.is_some() {
        return Err(dcr_invalid_metadata(
            "jwks and jwks_uri must not both be present",
        ));
    }
    if let Some(jwks) = extras.jwks.as_deref() {
        if let Err(reason) = crate::identity::validate_client_jwks(jwks) {
            return Err(dcr_invalid_metadata(&format!("invalid jwks: {reason}")));
        }
    }
    let method = match extras.token_endpoint_auth_method.as_deref() {
        None if extras.jwks.is_some() => DcrAuthMethod::PrivateKeyJwt,
        None => default,
        Some("client_secret_basic") => DcrAuthMethod::SecretBasic,
        Some("client_secret_post") => DcrAuthMethod::SecretPost,
        Some("private_key_jwt") => DcrAuthMethod::PrivateKeyJwt,
        Some("none") => DcrAuthMethod::None,
        Some(_) => {
            return Err(dcr_invalid_metadata(
                "token_endpoint_auth_method must be client_secret_basic, client_secret_post, \
                 private_key_jwt or none",
            ))
        }
    };
    if method == DcrAuthMethod::PrivateKeyJwt && extras.jwks.is_none() {
        return Err(dcr_invalid_metadata(
            "private_key_jwt requires the client's public keys inline in jwks; \
             jwks_uri is not fetched",
        ));
    }
    if fapi_advanced && method != DcrAuthMethod::PrivateKeyJwt {
        return Err(dcr_invalid_metadata(
            "this realm uses the FAPI 2.0 Advanced profile and accepts only \
             token_endpoint_auth_method private_key_jwt with jwks",
        ));
    }
    Ok(method)
}

/// Maps an engine refusal of a dynamic registration: metadata the engine
/// will not accept (invalid input, a FAPI rule) is RFC 7591 §3.2.2
/// `invalid_client_metadata`; anything else keeps its usual response.
fn dcr_engine_refusal(err: &crate::identity::IdentityError) -> Response {
    match err {
        crate::identity::IdentityError::InvalidInput { reason }
        | crate::identity::IdentityError::FapiViolation { reason } => dcr_invalid_metadata(reason),
        _ => identity_error_to_response(err).into_response(),
    }
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
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let auth = match super::extract_admin_auth(&headers, &state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = super::require_admin_permission(&auth, "hearth.clients.admin") {
        return e.into_response();
    }

    let request = match admin_registration_request(body) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    match state.identity.register_client(&auth.realm_id, &request) {
        Ok(client) => {
            crate::protocol::audit_log::record(
                state.audit.as_ref(),
                &CreateAuditEvent {
                    realm_id: auth.realm_id.clone(),
                    actor: auth.user_id.as_uuid().to_string(),
                    action: crate::audit::AuditAction::ClientRegistered,
                    resource_type: "client".to_string(),
                    resource_id: client.client_id().as_uuid().to_string(),
                    metadata: Some(serde_json::json!({"via": "clients_api"})),
                },
            );
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
    /// Minted only for a `client_secret_*` method.
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<String>,
    client_name: String,
    redirect_uris: Vec<String>,
    grant_types: Vec<String>,
    /// Present with `client_secret` (RFC 7591 §3.2.1).
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret_expires_at: Option<u64>,
    token_endpoint_auth_method: String,
    /// The registered key set, echoed (RFC 7591 §3.2.1).
    #[serde(skip_serializing_if = "Option::is_none")]
    jwks: Option<serde_json::Value>,
    client_id_issued_at: i64,
    /// The registered ID-token algorithm — RFC 7591 §3.2.1 returns every
    /// registered value, including one the server defaulted (task 26.55).
    id_token_signed_response_alg: String,
}

/// Error description for an `id_token_signed_response_alg` this server cannot
/// honour. The rejected value is deliberately not echoed.
const DCR_UNSUPPORTED_ID_TOKEN_ALG: &str = "id_token_signed_response_alg must be RS256 or EdDSA";

/// Error description for RS256 requested in a FAPI realm.
const DCR_FAPI_FORBIDS_RS256: &str =
    "id_token_signed_response_alg RS256 is not permitted in a FAPI 2.0 realm; use EdDSA";

/// Resolves a dynamic registration's `id_token_signed_response_alg`.
///
/// Omitted means RS256 — the default OpenID Connect Dynamic Client
/// Registration 1.0 §2 prescribes, and what a certification client registering
/// without the parameter expects (task 26.55) — except in a realm with a FAPI
/// profile (`fapi_realm`): FAPI 2.0 Security Profile §5.4.1 permits only
/// PS256, ES256 and EdDSA, so there it means EdDSA and an explicit RS256 is
/// refused. Anything but `RS256`/`EdDSA` (notably `none` and every `HS*`) is
/// refused too. `Err` carries the `error_description` for RFC 7591 §3.2.2
/// `invalid_client_metadata`.
fn resolve_dcr_id_token_alg(
    requested: Option<&str>,
    fapi_realm: bool,
) -> Result<String, &'static str> {
    use crate::identity::IdTokenSigningAlg;
    let alg = match requested {
        None if fapi_realm => IdTokenSigningAlg::EdDsa,
        None => IdTokenSigningAlg::Rs256,
        Some(alg) => IdTokenSigningAlg::parse(alg).map_err(|_| DCR_UNSUPPORTED_ID_TOKEN_ALG)?,
    };
    if fapi_realm && alg == IdTokenSigningAlg::Rs256 {
        return Err(DCR_FAPI_FORBIDS_RS256);
    }
    Ok(alg.as_str().to_string())
}

/// Dynamic Client Registration (RFC 7591) endpoint.
///
/// Accepts `POST /register` with `X-Realm-ID` header. The realm's
/// `dcr_policy` must be `Open` — returns 403 otherwise. The server
/// generates a random client secret and slug; the client does not
/// supply these. Returns an RFC 7591-compatible JSON response.
/// The permission an RFC 7591 §3.1 initial access token must carry under the
/// `authenticated` DCR policy (GA audit M9), besides `hearth.admin`: the same
/// authority the admin `POST /clients` API requires. Any valid realm token
/// used to be enough, so any end user could register clients.
const DCR_INITIAL_ACCESS_PERMISSION: &str = "hearth.clients.admin";

/// Refuses (`403 insufficient_scope`, RFC 6750 §3.1) a valid bearer token that
/// is not an initial access token: one without `hearth.clients.admin` or
/// `hearth.admin` in its `permissions` claim.
fn require_dcr_initial_access(claims: &crate::identity::TokenClaims) -> Result<(), Response> {
    if claims
        .permissions
        .iter()
        .any(|p| p == "hearth.admin" || p == DCR_INITIAL_ACCESS_PERMISSION)
    {
        return Ok(());
    }
    Err((
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "error": "insufficient_scope",
            "error_description": "the initial access token must carry the hearth.clients.admin permission"
        })),
    )
        .into_response())
}

async fn register_client_dynamic(
    State(state): State<Arc<AppState>>,
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
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
            // Enforce the DPoP sender-constraint (RFC 9449 §7.2) for cnf-bound
            // initial-access-tokens, so a stolen bound token cannot be replayed
            // as a plain Bearer to register clients in this realm (HEA-2039).
            // Global route ⇒ plain `Uri` yields the full request path.
            let htu = format!("{}{}", state.identity.oidc_discovery().issuer, uri.path());
            let Ok(claims) = validate_user_token_with_dpop(
                &headers,
                &state,
                &realm_id,
                &token,
                method.as_str(),
                &htu,
            ) else {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({
                        "error": "unauthorized",
                        "error_description": "a valid bearer token is required to register clients in this realm"
                    })),
                )
                    .into_response();
            };
            if let Err(resp) = require_dcr_initial_access(&claims) {
                return resp;
            }
        }
    }

    let (body, extras) = match split_registration_body(body) {
        Ok(split) => split,
        Err(description) => return dcr_invalid_metadata(&description),
    };
    // RFC 7591 §2: the client says how it will authenticate; the default
    // (no keys, no method) stays `client_secret_basic` on this route.
    let auth_method = match resolve_dcr_auth_method(
        &extras,
        DcrAuthMethod::SecretBasic,
        realm.config().fapi_profile == Some(crate::identity::FapiProfile::Advanced),
    ) {
        Ok(m) => m,
        Err(resp) => return resp,
    };

    // Strip any client-supplied secret — the server generates its own.
    // RFC 7591 DCR is anonymous; callers cannot self-grant first-party trust.
    let mut request = crate::identity::RegisterClientRequest::from(body);
    request.client_secret = None;
    request.trust_level = crate::identity::ClientTrustLevel::ThirdParty;
    request.jwks = extras.jwks.clone();
    request.jwks_uri = extras.jwks_uri.clone();
    if let Some(profile) = extras.profile {
        request.profile = profile;
    }
    request.authorization_signed_response_alg = extras.authorization_signed_response_alg.clone();

    // OIDC Registration §2: omitted means RS256 — EdDSA in a FAPI realm,
    // where FAPI 2.0 forbids RS256 (task 26.55).
    match resolve_dcr_id_token_alg(
        request.id_token_signed_response_alg.as_deref(),
        realm.config().fapi_profile.is_some(),
    ) {
        Ok(alg) => request.id_token_signed_response_alg = Some(alg),
        Err(description) => return dcr_invalid_metadata(description),
    }

    // Generate a server-side random secret (256 CSPRNG bits) for a secret
    // method only. It travels as a `GeneratedClientSecret`, which is what lets
    // the engine store it as a fast SHA-256 digest rather than an Argon2id
    // hash. A `private_key_jwt` or `none` client gets no secret.
    let generated_secret = if auth_method.mints_secret() {
        let generated = crate::identity::GeneratedClientSecret::generate();
        let exposed = generated.expose().to_string();
        request.generated_client_secret = Some(generated);
        Some(exposed)
    } else {
        None
    };

    // Force ThirdParty trust and consent for DCR-registered clients.
    request.trust_level = crate::identity::ClientTrustLevel::ThirdParty;
    request.require_consent = true;

    // Generate a unique slug: base name + random hex suffix.
    let base_slug = request.client_name.to_lowercase().replace(' ', "-");
    let slug = generate_unique_slug(state.clone(), &realm_id, &base_slug).await;
    request.slug = Some(slug);

    match state.identity.register_client(&realm_id, &request) {
        Ok(client) => {
            crate::protocol::audit_log::record(
                state.audit.as_ref(),
                &CreateAuditEvent {
                    realm_id: realm_id.clone(),
                    actor: "anonymous".to_string(),
                    action: crate::audit::AuditAction::ClientRegistered,
                    resource_type: "client".to_string(),
                    resource_id: client.client_id().as_uuid().to_string(),
                    metadata: Some(serde_json::json!({"via": "dynamic_registration"})),
                },
            );

            let response = DcrResponse {
                client_id: client.client_id().as_uuid().to_string(),
                client_secret_expires_at: generated_secret.as_ref().map(|_| 0),
                client_secret: generated_secret,
                client_name: client.client_name().to_string(),
                redirect_uris: client.redirect_uris().to_vec(),
                grant_types: client.grant_types().to_vec(),
                token_endpoint_auth_method: auth_method.as_str().to_string(),
                jwks: client.jwks().and_then(|j| serde_json::from_str(j).ok()),
                #[allow(clippy::cast_possible_truncation)]
                client_id_issued_at: client.created_at().as_micros() / 1_000_000,
                id_token_signed_response_alg: client
                    .id_token_signed_response_alg()
                    .as_str()
                    .to_string(),
            };

            (
                StatusCode::CREATED,
                Json(serde_json::to_value(response).unwrap_or_default()),
            )
                .into_response()
        }
        Err(e) => dcr_engine_refusal(&e),
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

/// `GET /authorize` — browser redirect shim.
///
/// OIDC discovery advertises `authorization_endpoint` as `{issuer}/authorize`.
/// The top-level `POST /authorize` is Hearth's JSON authorization API (Bearer +
/// `X-Realm-ID`, returns `200 + JSON`) — not an interactive browser endpoint. A
/// conformant RP that follows the discovery document redirects the user's
/// browser here via GET, which without this shim hits the POST-only route and
/// receives a 405. This handler 302-redirects the browser to the interactive
/// login+consent UI at `/ui/oauth/authorize`, preserving all query parameters
/// (HEA-2105).
async fn authorize_browser_redirect(uri: axum::http::Uri) -> impl IntoResponse {
    let query = uri.query().map(|q| format!("?{q}")).unwrap_or_default();
    let target = format!("/ui/oauth/authorize{query}");
    axum::response::Redirect::to(&target)
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
///
/// Carries the client authentication fields the token endpoint accepts
/// (RFC 9126 §2: "the same method it uses at the token endpoint"). No `Debug`:
/// the body holds a client secret or assertion.
#[derive(serde::Deserialize)]
struct HttpParRequest {
    /// Optional for a `client_secret_basic` client, which may carry its
    /// identity in the `Authorization` header alone (RFC 6749 §3.2.1).
    #[serde(default)]
    client_id: String,
    /// `client_secret_post` (RFC 6749 §2.3.1).
    #[serde(default)]
    client_secret: Option<String>,
    /// `private_key_jwt` (RFC 7523 §2.2).
    #[serde(default)]
    client_assertion_type: Option<String>,
    /// `private_key_jwt` (RFC 7523 §2.2).
    #[serde(default)]
    client_assertion: Option<String>,
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
    /// OIDC `prompt` (`none`, `consent`). The authorize endpoint ignores a
    /// `prompt` beside `request_uri`, so it must be pushed here.
    prompt: Option<String>,
}

fn default_response_type() -> String {
    "code".to_string()
}

/// Push authorization parameters (RFC 9126) — header-realm variant.
async fn pushed_authorization_request(
    State(state): State<Arc<AppState>>,
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
    JsonOrForm(body): JsonOrForm<HttpParRequest>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    par_handler(&state, &realm_id, &headers, body, peer_addr)
        .await
        .into_response()
}

/// Push authorization parameters (RFC 9126) — realm-scoped via path.
async fn realm_pushed_authorization_request(
    State(state): State<Arc<AppState>>,
    Path(realm_name): Path<String>,
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
    JsonOrForm(body): JsonOrForm<HttpParRequest>,
) -> impl IntoResponse {
    let realm_id = match resolve_realm_by_name(&state, &realm_name) {
        Ok(id) => id,
        Err(e) => return e,
    };
    par_handler(&state, &realm_id, &headers, body, peer_addr)
        .await
        .into_response()
}

/// Authenticates the client pushing an authorization request (RFC 9126 §2).
///
/// RFC 9126 §2: a confidential client "MUST authenticate itself using the same
/// method it uses at the token endpoint"; a public client identifies itself
/// with `client_id` alone. The endpoint accepts exactly the methods discovery
/// advertises in `token_endpoint_auth_methods_supported` (RFC 9126 §5):
///
/// - `private_key_jwt` — [`verify_assertion_client`], the `/introspect` and
///   `/revoke` rules: the assertion's `iss`/`sub` must be the body
///   `client_id`, and combining it with a secret is `400 invalid_request`;
/// - `client_secret_basic` / `client_secret_post` — reconciled by
///   [`resolve_client_credentials`] (a Basic username naming a different
///   client than the body is `400 invalid_request`), then verified by
///   `authenticate_confidential_client`: a public or `private_key_jwt`-only
///   client presenting a secret it cannot hold is refused, not waved through;
/// - `none` — accepted only for a public client: no stored secret AND no
///   assertion key (`OAuthClient::requires_client_assertion`).
///
/// Every refusal is the uniform `401 invalid_client` with `WWW-Authenticate:
/// Basic` (RFC 6749 §5.2). The work follows the caller's input, never the
/// lookup: a presented secret costs one verification on every arm (unknown,
/// public, confidential — a dummy hash when none is stored), and no secret
/// costs none, as at the token endpoint. An Argon2id verification the KDF gate
/// sheds is `503` + `Retry-After`.
async fn verify_par_client(
    state: &AppState,
    realm_id: &RealmId,
    headers: &HeaderMap,
    body: &HttpParRequest,
) -> Result<ClientId, Response> {
    let assertion_type = body
        .client_assertion_type
        .as_deref()
        .and_then(non_empty_credential);
    let assertion = body
        .client_assertion
        .as_deref()
        .and_then(non_empty_credential);
    if assertion_type.is_some() || assertion.is_some() {
        return verify_assertion_client(
            state,
            realm_id,
            headers,
            Some(body.client_id.as_str()),
            body.client_secret.as_deref(),
            assertion_type,
            assertion,
        );
    }

    let (raw_id, secret) = match resolve_client_credentials(
        headers,
        Some(body.client_id.as_str()),
        body.client_secret.as_deref(),
    )? {
        (Some(id), secret) => (id, secret),
        (None, _) => return Err(invalid_client_response()),
    };
    let client_id = raw_id
        .parse::<uuid::Uuid>()
        .map(ClientId::new)
        .map_err(|_| invalid_client_response())?;

    if let Some(secret) = secret {
        return crate::identity::client_auth::authenticate_confidential_client(
            &state.identity,
            realm_id,
            &client_id,
            Some(&secret),
        )
        .await
        .map(|()| client_id)
        .map_err(|e| client_auth_refusal(&e));
    }

    // No credential (`none`): only a public client — no secret, no assertion
    // key, no JWKS — may push on its `client_id` alone, and never in a FAPI
    // 2.0 Advanced realm.
    refuse_none_in_fapi_advanced_realm(state, realm_id)?;
    match state.identity.get_client(realm_id, &client_id) {
        Ok(Some(client)) if client.is_public() => Ok(client_id),
        Ok(_) => Err(invalid_client_response()),
        Err(e) => Err(identity_error_to_response(&e).into_response()),
    }
}

async fn par_handler(
    state: &AppState,
    realm_id: &crate::core::RealmId,
    headers: &HeaderMap,
    body: HttpParRequest,
    peer_addr: std::net::SocketAddr,
) -> impl IntoResponse {
    use crate::identity::{CodeChallengeMethod, PushedAuthorizationRequest};

    // Rate limit before authenticating the client, as `/token` does — from
    // PAR's own bucket.
    if let Err(resp) = check_claimed_client_rate_limit(
        state,
        realm_id,
        headers,
        Some(body.client_id.as_str()),
        peer_addr,
        ClientBudget::Par,
    ) {
        return resp;
    }

    // RFC 9126 §2: authenticate the client before anything is stored in its
    // name. The pushed request carries the AUTHENTICATED identity, so the
    // engine's request-object checks (`iss` and `client_id` must name the
    // client, RFC 9101 §6.3) bind the request object to it too.
    let client_id = match verify_par_client(state, realm_id, headers, &body).await {
        Ok(id) => id,
        Err(resp) => return resp,
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
        prompt: body.prompt,
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
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
    JsonOrForm(mut body): JsonOrForm<HttpTokenRequest>,
) -> Response {
    // A strict `client_secret_basic` client omits body `client_id`
    // (RFC 6749 §3.2.1) — adopt the Basic username before anything keys off
    // the client identity, including the CORS lookup and, inside the impl,
    // the per-client token rate limit.
    backfill_client_id_from_basic(&headers, &mut body);

    // Parse client_id and realm_id before dispatch so CORS can be applied to
    // every response path, including grant-type-specific error branches.
    let maybe_client_id = body.client_id.parse::<uuid::Uuid>().ok().map(ClientId::new);
    let maybe_realm_id = extract_realm_id(&headers).ok();

    let mut resp = token_exchange_impl(Arc::clone(&state), headers.clone(), body, peer_addr).await;

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
    peer_addr: std::net::SocketAddr,
) -> Response {
    let realm_id = match extract_realm_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    // Per-IP client address, resolved through the trusted-proxy walk. Needed
    // before the rate limiter so a request with no client identity still has
    // a bucket to fall back on.
    //
    // The real peer is threaded from the outer handler via `peer_addr`; it
    // falls back to FALLBACK_PEER only in tests that bypass
    // `into_make_service_with_connect_info`.
    let client_ip = extract_client_ip(&headers, peer_addr, &state.trusted_proxies);

    // Rate limit before any grant-type dispatch. Prefer the per-client
    // bucket; a request with no parseable `client_id` — the clientless
    // `refresh_token` session-refresh shape — is bucketed by client IP so it
    // cannot flood the endpoint unbounded (audit 2026-08-28 §4.16#8).
    let rate_limited = match body.client_id.parse::<uuid::Uuid>() {
        Ok(client_uuid) => check_token_rate_limit(&state, &realm_id, &ClientId::new(client_uuid)),
        Err(_) => check_anonymous_token_rate_limit(&state, &realm_id, &client_ip),
    };
    if let Err(resp) = rate_limited {
        return resp;
    }

    // A presented `client_assertion` / `client_assertion_type` is a
    // `private_key_jwt` attempt on EVERY grant: a malformed one is refused
    // here, before any arm can read it as absent; a well-formed one is
    // verified by the arm (or its engine grant).
    let assertion_presented = match screen_presented_assertion(
        &headers,
        body.client_secret.as_deref(),
        body.client_assertion_type.as_deref(),
        body.client_assertion.as_deref(),
    ) {
        Ok(presented) => presented.is_some(),
        Err(resp) => return resp,
    };

    let grant_type = body.grant_type.as_deref().unwrap_or("authorization_code");

    // A grant that does not authenticate the client (step-up MFA, the
    // jwt-bearer and magic-link grants) still never ignores a presented
    // assertion: it must verify for the named client.
    if assertion_presented && !GRANTS_AUTHENTICATING_CLIENT.contains(&grant_type) {
        if let Err(resp) = verify_assertion_client(
            &state,
            &realm_id,
            &headers,
            Some(body.client_id.as_str()),
            body.client_secret.as_deref(),
            body.client_assertion_type.as_deref(),
            body.client_assertion.as_deref(),
        ) {
            return resp;
        }
    }

    // Per-IP login rate limiting for the step-up-mfa grant.
    if grant_type == "urn:hearth:params:grant-type:step-up-mfa"
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
                ClientAssertion {
                    assertion_type: body.client_assertion_type.as_deref(),
                    assertion: body.client_assertion.as_deref(),
                    check: AssertionCheck::ByEngine,
                },
            )
            .await
            {
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
            let authenticated_client_id = if parse_basic_auth(&headers).is_some()
                || !body.client_id.trim().is_empty()
                || assertion_presented
            {
                match verify_endpoint_client_or_assertion(
                    &state,
                    &realm_id,
                    &headers,
                    Some(body.client_id.as_str()),
                    body.client_secret.as_deref(),
                    body.client_assertion_type.as_deref(),
                    body.client_assertion.as_deref(),
                )
                .await
                {
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
            // Audit §4.22#5: read `client_secret_basic` through the shared
            // resolver instead of the request body alone. Discovery and DCR
            // both tell clients to authenticate with the Authorization header,
            // and this arm used to ignore it. The engine's own `None` arm on
            // `client_secret` is `InvalidClientSecret`, so an unresolved
            // credential still fails closed.
            let (cc_client_id, cc_client_secret) = match resolve_client_credentials(
                &headers,
                Some(body.client_id.as_str()),
                body.client_secret.as_deref(),
            ) {
                Ok(pair) => pair,
                Err(resp) => return resp,
            };
            let proto_req = pb::ClientCredentialsRequest {
                client_id: cc_client_id.unwrap_or_default(),
                client_secret: cc_client_secret.unwrap_or_default(),
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
            match crate::identity::client_auth::client_credentials_token(
                &state.identity,
                &realm_id,
                request,
            )
            .await
            {
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
                    identity_error_response(&e)
                }
            }
        }
        "urn:ietf:params:oauth:grant-type:device_code" => {
            // RFC 8628 §3.4: the device access token request authenticates the
            // client exactly as the `authorization_code` arm does
            // (audit §4.19#4, §4.22#6).
            if let Err(resp) = enforce_confidential_client_auth(
                &state,
                &realm_id,
                &headers,
                &body.client_id,
                body.client_secret.as_deref(),
                ClientAssertion {
                    assertion_type: body.client_assertion_type.as_deref(),
                    assertion: body.client_assertion.as_deref(),
                    check: AssertionCheck::Here,
                },
            )
            .await
            {
                return resp;
            }

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
            let realm_id_clone = realm_id.clone();
            let identity = Arc::clone(&state.identity);
            // step_up_mfa_grant_token verifies Argon2id — route through the
            // shared KDF admission gate (HEA-1910 / HEA-1889 F3) so this grant
            // joins the permit pool rather than blocking Tokio workers directly.
            let result = match super::run_kdf_gated_rest(
                move || identity.step_up_mfa_grant_token(&realm_id_clone, &request),
                |e| {
                    tracing::error!(error = %e, "step_up_mfa_grant KDF task failed");
                    Err(crate::identity::IdentityError::Storage(Box::new(e)))
                },
            )
            .await
            {
                Ok(r) => r,
                Err(shed) => return shed,
            };
            match result {
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
            let authenticated_client_id = match verify_endpoint_client_or_assertion(
                &state,
                &realm_id,
                &headers,
                Some(body.client_id.as_str()),
                body.client_secret.as_deref(),
                body.client_assertion_type.as_deref(),
                body.client_assertion.as_deref(),
            )
            .await
            {
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
        // Magic-link grant — completes the passwordless flow the SDKs start
        // with `requestMagicLink`. Previously unimplemented, so every SDK's
        // exchange was rejected (audit 2026-08-28 §4.24#6).
        MAGIC_LINK_GRANT_TYPE => {
            let Some(link_token) = body.token.clone() else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_request",
                        "error_description": "token is required for the magic-link grant"
                    })),
                )
                    .into_response();
            };
            match exchange_magic_link(&state, &realm_id, &link_token, dpop_jkt.as_deref()) {
                Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
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
/// authentication via HTTP Basic Auth, body `client_id`/`client_secret`, or
/// a `private_key_jwt` assertion (mandatory for a secretless
/// `private_key_jwt` client), and revokes only a token issued to the
/// authenticated client (RFC 7009 §2.1); any other token is a silent 200
/// no-op.
async fn token_revocation(
    State(state): State<Arc<AppState>>,
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
    JsonOrForm(body): JsonOrForm<HttpRevocationBody>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    // Rate limit the claimed client before verifying it, as `/token` does.
    if let Err(resp) = check_claimed_client_rate_limit(
        &state,
        &realm_id,
        &headers,
        body.client_id.as_deref(),
        peer_addr,
        ClientBudget::Token,
    ) {
        return resp;
    }
    let client_id = match verify_revocation_client(&state, &realm_id, &headers, &body).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // RFC 7009 §2.1: only a token issued to the authenticated client is
    // revoked; any other token is a silent 200 no-op (task 26.43 follow-up).
    let request = crate::identity::TokenRevocationRequest {
        token: body.token,
        token_type_hint: body.token_type_hint,
        revoking_client_id: Some(client_id.clone()),
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
/// Returns metadata about the token including its active status. Serves
/// confidential clients only — `client_secret_basic`, `client_secret_post` or
/// `private_key_jwt`; a public client gets `401 invalid_client` (task 26.43).
async fn token_introspection(
    State(state): State<Arc<AppState>>,
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
    JsonOrForm(body): JsonOrForm<HttpIntrospectionBody>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    // Rate limit the claimed client before verifying it, as `/token` does.
    if let Err(resp) = check_claimed_client_rate_limit(
        &state,
        &realm_id,
        &headers,
        body.client_id.as_deref(),
        peer_addr,
        ClientBudget::Token,
    ) {
        return resp;
    }
    let client_id = match verify_introspection_client(&state, &realm_id, &headers, &body).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };

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
    method: axum::http::Method,
    uri: axum::http::Uri,
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

    // Enforce DPoP sender-constraint for cnf-bound tokens (RFC 9449 §7.2)
    // before resolving live RBAC. This endpoint is fail-closed: a stolen
    // DPoP-bound token replayed as a plain Bearer must not yield an authorization
    // decision, so DPoP failure denies (`allowed: false`) rather than leaking a
    // distinguishable error (HEA-2031).
    let htu = format!("{}{}", state.identity.oidc_discovery().issuer, uri.path());
    if validate_user_token_with_dpop(&headers, &state, &realm_id, &token, method.as_str(), &htu)
        .is_err()
    {
        return (StatusCode::OK, Json(serde_json::json!({"allowed": false}))).into_response();
    }

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
    JsonOrForm(body): JsonOrForm<pb::DeviceAuthorizationRequest>,
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

    // RFC 8628 §3.1: a confidential client authenticates here exactly as it
    // does at the token endpoint. Without this, a party holding only the
    // client identifier ran the whole flow under that client's identity
    // (audit §4.19#4, §4.22#6). Public clients pass through unchanged.
    if let Err(resp) = enforce_confidential_client_auth(
        &state,
        &realm_id,
        &headers,
        &body.client_id,
        body.client_secret.as_deref(),
        ClientAssertion {
            assertion_type: body.client_assertion_type.as_deref(),
            assertion: body.client_assertion.as_deref(),
            check: AssertionCheck::Here,
        },
    )
    .await
    {
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
async fn userinfo(
    State(state): State<Arc<AppState>>,
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
) -> impl IntoResponse {
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

    // Enforce DPoP sender-constraint for cnf-bound tokens (RFC 9449 §7.2)
    // before handing the raw token to the identity layer (HEA-2031).
    let htu = format!("{}{}", state.identity.oidc_discovery().issuer, uri.path());
    if let Err(e) =
        validate_user_token_with_dpop(&headers, &state, &realm_id, token, method.as_str(), &htu)
    {
        return e.into_response();
    }

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
    method: axum::http::Method,
    uri: axum::http::Uri,
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

    // Validate the token AND enforce DPoP sender-constraint for cnf-bound
    // tokens (RFC 9449 §7.2) before resolving live RBAC (HEA-2031).
    let htu = format!("{}{}", state.identity.oidc_discovery().issuer, uri.path());
    let claims = match validate_user_token_with_dpop(
        &headers,
        &state,
        &realm_id,
        token,
        method.as_str(),
        &htu,
    ) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
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

    // A suspended or archived organisation grants nothing: drop the org
    // context so only realm-scoped authority is reported
    // (subsystem audit 2026-09-21, finding O-2).
    let org_id = params
        .get("org_id")
        .and_then(|s| {
            uuid::Uuid::parse_str(s)
                .ok()
                .map(crate::core::OrganizationId::new)
        })
        .filter(|oid| {
            matches!(
                state.identity.get_organization(&realm_id, oid),
                Ok(Some(ref org))
                    if org.status() == crate::identity::OrganizationStatus::Active
            )
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
    PeerAddr(peer_addr): PeerAddr,
    Path(realm_name): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let client_ip = extract_client_ip(&headers, peer_addr, &state.trusted_proxies);
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
    PeerAddr(peer_addr): PeerAddr,
    Path(realm_name): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let client_ip = extract_client_ip(&headers, peer_addr, &state.trusted_proxies);
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
    PeerAddr(peer_addr): PeerAddr,
    Path(realm_name): Path<String>,
    headers: HeaderMap,
    JsonOrForm(mut body): JsonOrForm<HttpTokenRequest>,
) -> Response {
    let realm_id = match resolve_realm_by_name(&state, &realm_name) {
        Ok(id) => id,
        Err(e) => return e,
    };
    // A strict `client_secret_basic` client omits body `client_id`
    // (RFC 6749 §3.2.1) — adopt the Basic username before the rate limiter
    // and grant dispatch key off the client identity.
    backfill_client_id_from_basic(&headers, &mut body);

    // Real peer threaded from the outer handler; FALLBACK_PEER only in tests
    // without ConnectInfo. Resolved before the rate limiter so a request with
    // no client identity still has a bucket.
    let client_ip = extract_client_ip(&headers, peer_addr, &state.trusted_proxies);

    // Rate limit before any grant-type dispatch — per client when one is
    // supplied, per client IP for the clientless `refresh_token` shape that
    // otherwise bypasses the limiter entirely (audit 2026-08-28 §4.16#8).
    let rate_limited = match body.client_id.parse::<uuid::Uuid>() {
        Ok(client_uuid) => check_token_rate_limit(&state, &realm_id, &ClientId::new(client_uuid)),
        Err(_) => check_anonymous_token_rate_limit(&state, &realm_id, &client_ip),
    };
    if let Err(resp) = rate_limited {
        return resp;
    }

    // A presented `client_assertion` / `client_assertion_type` is a
    // `private_key_jwt` attempt on EVERY grant: a malformed one is refused
    // here, before any arm can read it as absent; a well-formed one is
    // verified by the arm (or its engine grant).
    let assertion_presented = match screen_presented_assertion(
        &headers,
        body.client_secret.as_deref(),
        body.client_assertion_type.as_deref(),
        body.client_assertion.as_deref(),
    ) {
        Ok(presented) => presented.is_some(),
        Err(resp) => return resp,
    };
    let grant_type = body.grant_type.as_deref().unwrap_or("authorization_code");

    // A grant that does not authenticate the client (step-up MFA, the
    // jwt-bearer and magic-link grants) still never ignores a presented
    // assertion: it must verify for the named client.
    if assertion_presented && !GRANTS_AUTHENTICATING_CLIENT.contains(&grant_type) {
        if let Err(resp) = verify_assertion_client(
            &state,
            &realm_id,
            &headers,
            Some(body.client_id.as_str()),
            body.client_secret.as_deref(),
            body.client_assertion_type.as_deref(),
            body.client_assertion.as_deref(),
        ) {
            return resp;
        }
    }

    // Per-IP login rate limiting for the step-up-mfa grant.
    if grant_type == "urn:hearth:params:grant-type:step-up-mfa"
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
                ClientAssertion {
                    assertion_type: body.client_assertion_type.as_deref(),
                    assertion: body.client_assertion.as_deref(),
                    check: AssertionCheck::ByEngine,
                },
            )
            .await
            {
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
            let authenticated_client_id = if parse_basic_auth(&headers).is_some()
                || !body.client_id.trim().is_empty()
                || assertion_presented
            {
                match verify_endpoint_client_or_assertion(
                    &state,
                    &realm_id,
                    &headers,
                    Some(body.client_id.as_str()),
                    body.client_secret.as_deref(),
                    body.client_assertion_type.as_deref(),
                    body.client_assertion.as_deref(),
                )
                .await
                {
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
            // Audit §4.22#5 — same shared credential resolution as the global
            // `/token` arm above.
            let (cc_client_id, cc_client_secret) = match resolve_client_credentials(
                &headers,
                Some(body.client_id.as_str()),
                body.client_secret.as_deref(),
            ) {
                Ok(pair) => pair,
                Err(resp) => return resp,
            };
            let proto_req = pb::ClientCredentialsRequest {
                client_id: cc_client_id.unwrap_or_default(),
                client_secret: cc_client_secret.unwrap_or_default(),
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
            match crate::identity::client_auth::client_credentials_token(
                &state.identity,
                &realm_id,
                request,
            )
            .await
            {
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
                Err(e) => identity_error_response(&e),
            }
        }
        "urn:ietf:params:oauth:grant-type:device_code" => {
            // RFC 8628 §3.4 — same rule as the header-routed twin
            // (audit §4.19#4, §4.22#6).
            if let Err(resp) = enforce_confidential_client_auth(
                &state,
                &realm_id,
                &headers,
                &body.client_id,
                body.client_secret.as_deref(),
                ClientAssertion {
                    assertion_type: body.client_assertion_type.as_deref(),
                    assertion: body.client_assertion.as_deref(),
                    check: AssertionCheck::Here,
                },
            )
            .await
            {
                return resp;
            }

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
            let realm_id_clone = realm_id.clone();
            let identity = Arc::clone(&state.identity);
            // step_up_mfa_grant_token verifies Argon2id — route through the
            // shared KDF admission gate (HEA-1910 / HEA-1889 F3) so this grant
            // joins the permit pool rather than blocking Tokio workers directly.
            let result = match super::run_kdf_gated_rest(
                move || identity.step_up_mfa_grant_token(&realm_id_clone, &request),
                |e| {
                    tracing::error!(error = %e, "realm_step_up_mfa_grant KDF task failed");
                    Err(crate::identity::IdentityError::Storage(Box::new(e)))
                },
            )
            .await
            {
                Ok(r) => r,
                Err(shed) => return shed,
            };
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
            // HEA-2024 (F1): token-exchange MUST authenticate the requesting client
            // (RFC 8693 §2.1), exactly as the header-realm handler does. Without this
            // the actor identity is unverified, letting any subject-token holder mint a
            // token with an attacker-controlled `aud`/`resource`/`cnf.jkt`. Derive the
            // `ClientId` from the authenticated identity, not the unauthenticated body.
            let authenticated_client_id = match verify_endpoint_client_or_assertion(
                &state,
                &realm_id,
                &headers,
                Some(body.client_id.as_str()),
                body.client_secret.as_deref(),
                body.client_assertion_type.as_deref(),
                body.client_assertion.as_deref(),
            )
            .await
            {
                Ok(id) => id,
                Err(resp) => return resp,
            };
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
        // Magic-link grant — completes the passwordless flow the SDKs start
        // with `requestMagicLink`. Previously unimplemented, so every SDK's
        // exchange was rejected (audit 2026-08-28 §4.24#6).
        MAGIC_LINK_GRANT_TYPE => {
            let Some(link_token) = body.token.clone() else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_request",
                        "error_description": "token is required for the magic-link grant"
                    })),
                )
                    .into_response();
            };
            match exchange_magic_link(&state, &realm_id, &link_token, dpop_jkt.as_deref()) {
                Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
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

/// `POST /realms/{realm}/revoke` — realm-scoped twin of `/revoke`.
///
/// Requires client authentication and applies the same rate limit, RFC 7009
/// semantics and §2.1 token-ownership check as the header-form twin. Before this the route read no
/// client credentials at all, so an anonymous internet caller could destroy
/// any session it held a token string for (audit 2026-08-28 §4.1#3,
/// §4.19#2, §4.22#1, §4.25#1).
async fn realm_token_revocation(
    State(state): State<Arc<AppState>>,
    Path(realm_name): Path<String>,
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
    JsonOrForm(body): JsonOrForm<HttpRevocationBody>,
) -> impl IntoResponse {
    let realm_id = match resolve_realm_by_name(&state, &realm_name) {
        Ok(id) => id,
        Err(e) => return e,
    };
    // Rate limit the claimed client before verifying it, as `/token` does.
    if let Err(resp) = check_claimed_client_rate_limit(
        &state,
        &realm_id,
        &headers,
        body.client_id.as_deref(),
        peer_addr,
        ClientBudget::Token,
    ) {
        return resp;
    }
    let client_id = match verify_revocation_client(&state, &realm_id, &headers, &body).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // RFC 7009 §2.1: only a token issued to the authenticated client is
    // revoked; any other token is a silent 200 no-op (task 26.43 follow-up).
    let request = crate::identity::TokenRevocationRequest {
        token: body.token,
        token_type_hint: body.token_type_hint,
        revoking_client_id: Some(client_id.clone()),
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

/// `POST /realms/{realm}/introspect` — realm-scoped twin of `/introspect`.
///
/// Requires confidential-client authentication (task 26.43), applies the
/// RFC 7662 §2 audience restriction via `introspecting_client_id`, and
/// answers with the same
/// wire format as the header-form twin — the domain type always emits
/// `active: false` for inactive tokens, where the previous proto3
/// serialization omitted it (audit 2026-08-28 §4.1#3, §4.1#4).
async fn realm_token_introspection(
    State(state): State<Arc<AppState>>,
    Path(realm_name): Path<String>,
    PeerAddr(peer_addr): PeerAddr,
    headers: HeaderMap,
    JsonOrForm(body): JsonOrForm<HttpIntrospectionBody>,
) -> impl IntoResponse {
    let realm_id = match resolve_realm_by_name(&state, &realm_name) {
        Ok(id) => id,
        Err(e) => return e,
    };
    // Rate limit the claimed client before verifying it, as `/token` does.
    if let Err(resp) = check_claimed_client_rate_limit(
        &state,
        &realm_id,
        &headers,
        body.client_id.as_deref(),
        peer_addr,
        ClientBudget::Token,
    ) {
        return resp;
    }
    let client_id = match verify_introspection_client(&state, &realm_id, &headers, &body).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let request = crate::identity::TokenIntrospectionRequest {
        token: body.token,
        token_type_hint: body.token_type_hint,
        introspecting_client_id: Some(client_id.clone()),
    };
    let mut resp = match state.identity.introspect_token(&realm_id, &request) {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(e) => identity_error_to_response(&e).into_response(),
    };
    apply_cors_to_response(&mut resp, &state, &realm_id, &client_id, &headers);
    resp
}

async fn realm_userinfo(
    State(state): State<Arc<AppState>>,
    Path(realm_name): Path<String>,
    method: axum::http::Method,
    // Realm routes are nested under `/realms/{realm_name}`; the plain `Uri`
    // extractor strips that prefix, so use `OriginalUri` to reconstruct the
    // full request path a DPoP client signs into its `htu` claim.
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
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
    // Enforce DPoP sender-constraint for cnf-bound tokens (RFC 9449 §7.2)
    // before handing the raw token to the identity layer (HEA-2031).
    let htu = format!("{}{}", state.identity.oidc_discovery().issuer, uri.path());
    if let Err(e) =
        validate_user_token_with_dpop(&headers, &state, &realm_id, token, method.as_str(), &htu)
    {
        return e.into_response();
    }
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
    headers: HeaderMap,
    JsonOrForm(body): JsonOrForm<serde_json::Value>,
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
    // RFC 8628 §3.1 — same confidential-client rule as the header-routed twin
    // (audit §4.19#4, §4.22#6).
    if let Err(resp) = enforce_confidential_client_auth(
        &state,
        &realm_id,
        &headers,
        &client_id_str,
        body.get("client_secret").and_then(|v| v.as_str()),
        ClientAssertion {
            assertion_type: body.get("client_assertion_type").and_then(|v| v.as_str()),
            assertion: body.get("client_assertion").and_then(|v| v.as_str()),
            check: AssertionCheck::Here,
        },
    )
    .await
    {
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

/// Builds the RFC 7591 §3.2.2 `invalid_client_metadata` rejection for a
/// dynamic registration whose metadata this server cannot honour.
fn dcr_invalid_metadata(description: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "error": "invalid_client_metadata",
            "error_description": description,
        })),
    )
        .into_response()
}

async fn realm_register_client_dynamic(
    State(state): State<Arc<AppState>>,
    Path(realm_name): Path<String>,
    method: axum::http::Method,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
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
            // Enforce the DPoP sender-constraint (RFC 9449 §7.2) for cnf-bound
            // initial-access-tokens (HEA-2039). Nested route ⇒ `OriginalUri`
            // preserves the `/realms/{name}` prefix so a legitimate proof's
            // `htu` matches the full request path.
            let htu = format!("{}{}", state.identity.oidc_discovery().issuer, uri.path());
            let Ok(claims) = validate_user_token_with_dpop(
                &headers,
                &state,
                &realm_id,
                &token,
                method.as_str(),
                &htu,
            ) else {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({
                        "error": "unauthorized",
                        "error_description": "a valid bearer token is required to register clients in this realm"
                    })),
                )
                    .into_response();
            };
            if let Err(resp) = require_dcr_initial_access(&claims) {
                return resp;
            }
        }
    }
    // RFC 7591 §2 key and client-authentication metadata. This route
    // registers a public (`none`) client by default, as it always has.
    let mut body = body;
    let extras = {
        let mut keys_only = serde_json::Map::new();
        if let serde_json::Value::Object(map) = &mut body {
            for field in [
                "jwks",
                "jwks_uri",
                "token_endpoint_auth_method",
                "profile",
                "authorization_signed_response_alg",
            ] {
                if let Some(v) = map.remove(field) {
                    keys_only.insert(field.to_string(), v);
                }
            }
        }
        match split_registration_body(serde_json::Value::Object(keys_only)) {
            Ok((_, extras)) => extras,
            Err(description) => return dcr_invalid_metadata(&description),
        }
    };
    let auth_method = match resolve_dcr_auth_method(
        &extras,
        DcrAuthMethod::None,
        realm.config().fapi_profile == Some(crate::identity::FapiProfile::Advanced),
    ) {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    let generated = auth_method
        .mints_secret()
        .then(crate::identity::GeneratedClientSecret::generate);
    let generated_secret = generated.as_ref().map(|g| g.expose().to_string());
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
    // Audit §4.22#9: honour the RFC 7591 `grant_types` metadata instead of
    // silently overwriting it with `authorization_code`. A grant type this
    // deployment does not support is refused with `invalid_client_metadata`
    // (RFC 7591 §3.2.2) rather than narrowed to something the caller did not
    // ask for — silent narrowing hands back a client that cannot run the flow
    // it registered for.
    let grant_types: Vec<String> = match body.get("grant_types") {
        None | Some(serde_json::Value::Null) => vec!["authorization_code".to_string()],
        Some(serde_json::Value::Array(items)) => {
            let supported = state.identity.oidc_discovery().grant_types_supported;
            let mut requested = Vec::with_capacity(items.len());
            for item in items {
                let Some(name) = item.as_str() else {
                    return dcr_invalid_metadata("grant_types entries must be strings");
                };
                if !supported.iter().any(|s| s == name) {
                    return dcr_invalid_metadata(&format!(
                        "grant_type '{name}' is not supported by this authorization server"
                    ));
                }
                if !requested.iter().any(|g: &String| g == name) {
                    requested.push(name.to_string());
                }
            }
            if requested.is_empty() {
                return dcr_invalid_metadata("grant_types must not be empty");
            }
            requested
        }
        Some(_) => return dcr_invalid_metadata("grant_types must be an array of strings"),
    };
    // OIDC Registration §2: omitted (or null) means RS256 — EdDSA in a FAPI
    // realm, where FAPI 2.0 forbids RS256; anything but RS256/EdDSA is refused
    // rather than narrowed (task 26.55).
    let requested_id_token_alg = match body.get("id_token_signed_response_alg") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(alg)) => Some(alg.as_str()),
        Some(_) => return dcr_invalid_metadata(DCR_UNSUPPORTED_ID_TOKEN_ALG),
    };
    let id_token_signed_response_alg = match resolve_dcr_id_token_alg(
        requested_id_token_alg,
        realm.config().fapi_profile.is_some(),
    ) {
        Ok(alg) => alg,
        Err(description) => return dcr_invalid_metadata(description),
    };
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
        generated_client_secret: generated,
        grant_types,
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
        jwks: extras.jwks.clone(),
        jwks_uri: extras.jwks_uri.clone(),
        authorization_signed_response_alg: extras.authorization_signed_response_alg.clone(),
        id_token_signed_response_alg: Some(id_token_signed_response_alg),
        profile: extras
            .profile
            .unwrap_or(crate::identity::ClientProfile::Standard),
        mfa_required: None,
    };
    match state.identity.register_client(&realm_id, &request) {
        Ok(client) => {
            // Audit §4.22#9: every token-endpoint arm parses `client_id` with
            // `uuid::Uuid::parse_str`. The `ClientId` `Display` impl prefixes
            // the UUID (`client_<uuid>`), so rendering it here handed back an
            // id that could never authenticate. Emit the bare UUID, matching
            // the global `POST /register` response.
            let mut resp = serde_json::json!({
                "client_id": client.client_id().as_uuid().to_string(),
                "client_name": client.client_name(),
                "redirect_uris": client.redirect_uris(),
                "grant_types": client.grant_types(),
                // RFC 7591 §3.2.1: echo registered metadata, defaults included.
                "id_token_signed_response_alg": client.id_token_signed_response_alg().as_str(),
                "token_endpoint_auth_method": auth_method.as_str(),
            });
            if let Some(secret) = generated_secret {
                resp["client_secret"] = serde_json::json!(secret);
                resp["client_secret_expires_at"] = serde_json::json!(0);
            }
            if let Some(jwks) = client
                .jwks()
                .and_then(|j| serde_json::from_str::<serde_json::Value>(j).ok())
            {
                resp["jwks"] = jwks;
            }
            (StatusCode::CREATED, Json(resp)).into_response()
        }
        Err(e) => dcr_engine_refusal(&e),
    }
}
