//! Session management endpoints: RP-initiated logout and session-version feed.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use serde::Deserialize;

use super::{
    extract_bearer_token, extract_realm_id, identity_error_to_response, resolve_realm_by_name,
    AppState,
};

/// Registers session management and session-version feed routes.
pub(super) fn routes() -> axum::Router<Arc<AppState>> {
    use axum::routing::get;
    axum::Router::new()
        .route("/end_session", get(end_session).post(end_session))
        .route("/oauth/session-versions", get(oauth_sv_delta_feed))
        .route("/oauth/session-versions/snapshot", get(oauth_sv_snapshot))
}

/// Registers realm-scoped session routes (nested under `/realms/{realm_name}`).
pub(super) fn realm_routes() -> axum::Router<Arc<AppState>> {
    use axum::routing::get;
    axum::Router::new().route(
        "/end_session",
        get(realm_end_session).post(realm_end_session),
    )
}

/// Query parameters for `GET /end_session`.
#[derive(Debug, Deserialize, Default)]
struct EndSessionParams {
    /// ID token previously issued to the RP. Accepted even when expired.
    id_token_hint: Option<String>,
    /// Post-logout URI (must be registered on the client when `client_id` is present).
    post_logout_redirect_uri: Option<String>,
    /// Client ID — used to validate `post_logout_redirect_uri`.
    client_id: Option<String>,
    /// Opaque state — echoed to `post_logout_redirect_uri` as `?state=…`.
    state: Option<String>,
}

/// `GET /realms/{realm}/end_session` — realm-path-scoped RP-initiated logout.
///
/// Identical to [`end_session`] but resolves the realm from the URL path
/// instead of the `X-Realm-ID` header, so browser navigations from SPAs work.
#[allow(clippy::too_many_lines)]
async fn realm_end_session(
    State(state): State<Arc<AppState>>,
    Path(realm_name): Path<String>,
    headers: HeaderMap,
    Query(params): Query<EndSessionParams>,
) -> impl IntoResponse {
    let realm_id = match resolve_realm_by_name(&state, &realm_name) {
        Ok(id) => id,
        Err(e) => return e,
    };
    // Synthesise an X-Realm-ID header so the shared end_session logic can be
    // reused by constructing a fake HeaderMap with the resolved realm UUID.
    let mut h = headers.clone();
    if let Ok(val) = axum::http::HeaderValue::from_str(&realm_id.as_uuid().to_string()) {
        h.insert("x-realm-id", val);
    }
    let is_secure = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("https"))
        .unwrap_or(false);

    // Delegate to the core OIDC end_session handler.
    let mut resp = end_session(State(state), h, Query(params))
        .await
        .into_response();

    // Also clear the Hearth UI session cookies so the browser login form
    // requires re-authentication on the next authorize redirect.
    for cookie in crate::protocol::web::auth::clearing_cookies(is_secure) {
        if let Ok(val) = axum::http::HeaderValue::from_str(&cookie) {
            resp.headers_mut()
                .append(axum::http::header::SET_COOKIE, val);
        }
    }
    resp
}

/// `GET /end_session` — RP-initiated logout.
///
/// Revokes the session identified by `id_token_hint`, fans out back-channel
/// logout tokens to all registered RPs, and either redirects to
/// `post_logout_redirect_uri` or renders a front-channel logout page.
///
/// All parameters are optional; when neither `id_token_hint` nor a session
/// can be inferred, the endpoint returns 400.
#[allow(clippy::too_many_lines)]
async fn end_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<EndSessionParams>,
) -> impl IntoResponse {
    let realm_id = match extract_realm_id(&headers) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let client_id = params
        .client_id
        .as_deref()
        .and_then(|s| s.parse::<uuid::Uuid>().ok())
        .map(crate::core::ClientId::new);

    let request = crate::identity::oidc::RpLogoutRequest {
        id_token_hint: params.id_token_hint,
        session_id: None,
        post_logout_redirect_uri: params.post_logout_redirect_uri.clone(),
        client_id,
        state: params.state.clone(),
    };

    let result = match state.identity.initiate_logout(&realm_id, &request) {
        Ok(r) => r,
        Err(crate::identity::IdentityError::SessionNotFound) => {
            // Session already gone. Do NOT redirect to post_logout_redirect_uri here —
            // we cannot validate it without a known client, so accepting it would be
            // an open redirect (OIDC RP-Initiated Logout 1.0 §3).
            return (
                StatusCode::OK,
                Json(serde_json::json!({"message": "logged out"})),
            )
                .into_response();
        }
        Err(crate::identity::IdentityError::InvalidToken) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid_request", "error_description": "id_token_hint could not be parsed"})),
            )
                .into_response();
        }
        Err(e) => return identity_error_to_response(&e).into_response(),
    };

    // Fan out back-channel logout notifications asynchronously (fire-and-forget).
    // ureq is a blocking client; run each POST on the blocking thread pool.
    for target in result.backchannel_targets {
        tokio::spawn(async move {
            let uri = target.uri.clone();
            let outcome = tokio::task::spawn_blocking(move || {
                let body = form_urlencoded::Serializer::new(String::new())
                    .append_pair("logout_token", &target.logout_token)
                    .finish();
                ureq::post(&target.uri)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .send(body.as_bytes())
            })
            .await;
            match outcome {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    tracing::warn!(uri = %uri, error = %e, "backchannel logout delivery failed");
                }
                Err(e) => {
                    tracing::warn!(uri = %uri, error = %e, "backchannel logout spawn_blocking panicked");
                }
            }
        });
    }

    // Serve front-channel logout page (with iframes) or redirect directly.
    if !result.frontchannel_targets.is_empty() {
        let sid = result.session_id.as_uuid().to_string();
        let issuer_enc =
            form_urlencoded::byte_serialize(state.identity.oidc_discovery().issuer.as_bytes())
                .collect::<String>();
        let sid_enc = form_urlencoded::byte_serialize(sid.as_bytes()).collect::<String>();

        let iframes: Vec<String> = result
            .frontchannel_targets
            .iter()
            .map(|t| {
                // Append iss and sid query params per OIDC FCL spec.
                let sep = if t.uri.contains('?') { '&' } else { '?' };
                format!(
                    r#"<iframe src="{uri}{sep}iss={issuer}&sid={sid}" style="display:none;width:0;height:0;border:0"></iframe>"#,
                    uri = html_escape(&t.uri),
                    sep = sep,
                    issuer = issuer_enc,
                    sid = sid_enc,
                )
            })
            .collect();

        let redirect_meta = result
            .post_logout_redirect_uri
            .as_deref()
            .map(|uri| {
                let escaped = html_escape(uri);
                format!(r#"<meta http-equiv="refresh" content="2;url={escaped}">"#)
            })
            .unwrap_or_default();

        let html = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Signing out…</title>
{redirect_meta}
</head>
<body>
{iframes}
</body>
</html>"#,
            redirect_meta = redirect_meta,
            iframes = iframes.join("\n"),
        );

        return (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
            html,
        )
            .into_response();
    }

    end_session_redirect(result.post_logout_redirect_uri, result.state)
}

/// Builds the post-logout redirect response, appending `state` when present.
fn end_session_redirect(uri: Option<String>, state: Option<String>) -> Response {
    match uri {
        None => (
            StatusCode::OK,
            Json(serde_json::json!({"message": "logged out"})),
        )
            .into_response(),
        Some(base_uri) => {
            let redirect_uri = match state {
                None => base_uri,
                Some(s) => {
                    let sep = if base_uri.contains('?') { '&' } else { '?' };
                    let state_enc =
                        form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
                    format!("{base_uri}{sep}state={state_enc}")
                }
            };
            Redirect::to(&redirect_uri).into_response()
        }
    }
}

/// HTML-escapes the five special characters to prevent XSS in inline HTML.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

// ── Session-version feed endpoints ───────────────────────────────────────────

/// Query parameters for the delta feed.
#[derive(Deserialize)]
struct SvDeltaQuery {
    since: u64,
    limit: Option<usize>,
}

/// `GET /oauth/session-versions?since=<seq>` — session-version delta feed.
///
/// Returns all bump events with `seq > since`, up to `limit` (default: 1000).
/// Returns 204 when there are no new deltas.
/// Returns 400 when `since` is older than the retention window.
/// Returns 404 when session versioning is disabled for the realm.
/// Requires a bearer token with `hearth.sv_feed` permission.
async fn oauth_sv_delta_feed(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<SvDeltaQuery>,
) -> Response {
    // Validate token — extract realm and check hearth.sv_feed permission.
    let Ok(realm_id) = extract_realm_id(&headers) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "missing X-Realm-ID header"})),
        )
            .into_response();
    };

    let token = match extract_bearer_token(&headers) {
        Ok(t) => t,
        Err(r) => return r.into_response(),
    };

    let claims = match state.identity.validate_token(&realm_id, &token) {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "invalid token"})),
            )
                .into_response()
        }
    };

    let has_feed_perm = claims.permissions.iter().any(|p| p == "hearth.sv_feed");
    let is_admin = claims.permissions.iter().any(|p| p == "hearth.admin");
    if !has_feed_perm && !is_admin {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "requires hearth.sv_feed permission"})),
        )
            .into_response();
    }

    let limit = params.limit.unwrap_or(1000).min(5000);

    let result = tokio::task::spawn_blocking({
        let identity = Arc::clone(&state.identity);
        let realm_id = realm_id.clone();
        let since = params.since;
        move || identity.sv_list_deltas(&realm_id, since, limit)
    })
    .await;

    match result {
        Ok(Ok(Some(resp))) => {
            if resp.deltas.is_empty() {
                StatusCode::NO_CONTENT.into_response()
            } else {
                Json(resp).into_response()
            }
        }
        Ok(Ok(None)) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "since is older than retention window; fetch snapshot first"
            })),
        )
            .into_response(),
        Ok(Err(crate::identity::IdentityError::SessionVersionDisabled)) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "session versioning disabled for realm"})),
        )
            .into_response(),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "internal error"})),
        )
            .into_response(),
    }
}

/// `GET /oauth/session-versions/snapshot` — full session-version snapshot.
///
/// Returns gzip-compressed JSON with `{realm, current_seq, versions}`.
/// Returns 404 when session versioning is disabled for the realm.
/// Requires a bearer token with `hearth.sv_feed` permission.
async fn oauth_sv_snapshot(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Ok(realm_id) = extract_realm_id(&headers) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "missing X-Realm-ID header"})),
        )
            .into_response();
    };

    let token = match extract_bearer_token(&headers) {
        Ok(t) => t,
        Err(r) => return r.into_response(),
    };

    let claims = match state.identity.validate_token(&realm_id, &token) {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "invalid token"})),
            )
                .into_response()
        }
    };

    let has_feed_perm = claims.permissions.iter().any(|p| p == "hearth.sv_feed");
    let is_admin = claims.permissions.iter().any(|p| p == "hearth.admin");
    if !has_feed_perm && !is_admin {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "requires hearth.sv_feed permission"})),
        )
            .into_response();
    }

    let result = tokio::task::spawn_blocking({
        let identity = Arc::clone(&state.identity);
        let realm_id = realm_id.clone();
        move || identity.sv_snapshot(&realm_id)
    })
    .await;

    match result {
        Ok(Ok(snapshot)) => {
            use flate2::write::GzEncoder;
            use flate2::Compression;
            use std::io::Write;

            let json_bytes = match serde_json::to_vec(&snapshot) {
                Ok(b) => b,
                Err(e) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": e.to_string()})),
                    )
                        .into_response()
                }
            };

            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            if encoder.write_all(&json_bytes).is_err() {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "compression error"})),
                )
                    .into_response();
            }
            let compressed = match encoder.finish() {
                Ok(b) => b,
                Err(_) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": "compression error"})),
                    )
                        .into_response()
                }
            };

            axum::http::Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .header("Content-Encoding", "gzip")
                .body(axum::body::Body::from(compressed))
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
        Ok(Err(crate::identity::IdentityError::SessionVersionDisabled)) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "session versioning disabled for realm"})),
        )
            .into_response(),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "internal error"})),
        )
            .into_response(),
    }
}
