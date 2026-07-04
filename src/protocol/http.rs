//! HTTP server and route definitions.
//!
//! Builds an [`axum::Router`] with health, OIDC discovery, JWKS, OAuth 2.0,
//! and Admin API endpoints. The server is configured with shared application
//! state containing the identity, RBAC, and audit engines.
//!
//! The protocol layer is a thin, stateless adapter: it translates HTTP requests
//! into domain calls on `IdentityEngine` and maps `IdentityError` to HTTP
//! status codes. No business logic lives here.

use std::sync::Arc;
use std::time::Instant;

use axum::extract::{DefaultBodyLimit, MatchedPath, Request};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Router;
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::Level;

// ── Sub-modules ──────────────────────────────────────────────────────────────

mod admin;
mod advanced;
mod agents;
mod approval;
mod auth;
mod health;
mod mfa;
mod oauth;
mod serve;
mod session;
mod state;
#[cfg(test)]
mod tests;
mod tool_invocation;
mod users;

// ── Public API (preserve existing import paths for external crates) ───────────

pub use serve::{serve, serve_redirect, serve_router, serve_tls, serve_tls_router};
pub use state::AppState;

// ── Crate-internal re-exports (used by scim, cluster_admin, and handler mods) ──

pub(crate) use auth::AdminAuth;
pub(crate) use auth::{
    extract_admin_auth, extract_cluster_admin_auth, require_admin_permission,
    require_any_admin_permission,
};

// Re-export all shared helpers so child handler modules can use `super::name`.
// Child modules need these accessible at the `crate::protocol::http` level.
pub(crate) use auth::{
    check_export_capability, check_export_rate_limit, check_token_rate_limit,
    emit_export_watermark, extract_bearer_token, extract_realm_id, extract_user_auth,
    identity_error_to_response, make_ip_rate_limit_response, now_micros, proto_to_rest_json,
    rbac_error_to_response, resolve_realm_by_name, verify_manifest_signature,
};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Fallback peer address when `ConnectInfo` is unavailable (e.g. test
/// harnesses that use `tower::oneshot` without connect-info).
const FALLBACK_PEER: std::net::SocketAddr =
    std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0);

/// HTTP/2 maximum concurrent streams per connection (A-39, CVE-2023-44487).
const HTTP2_MAX_CONCURRENT_STREAMS: u32 = 100;

/// HTTP/2 maximum pending RST_STREAM frames per connection (A-39).
const HTTP2_MAX_PENDING_RESET_STREAMS: usize = 10;

/// Default maximum request body size (1 MiB).
const BODY_LIMIT_DEFAULT: usize = 1024 * 1024;

/// Reduced body limit (64 KiB) for endpoints that only accept short codes
/// or token strings (e.g. introspection, revocation).
const BODY_LIMIT_SMALL: usize = 64 * 1024;

/// Maximum body size (4 GiB) for the `POST /admin/backup/restore` endpoint.
pub const BACKUP_RESTORE_BODY_LIMIT: usize = 4 * 1024 * 1024 * 1024;

// ── Observability middleware ──────────────────────────────────────────────────

/// Tower middleware that records HTTP request latency into the Prometheus
/// `hearth_http_request_duration_seconds` histogram.
///
/// Must be applied via [`Router::route_layer`] so that [`MatchedPath`] is
/// already populated by the router before this middleware runs.
pub(crate) async fn track_metrics(request: Request, next: Next) -> Response {
    let path = request
        .extensions()
        .get::<MatchedPath>()
        .map(|mp| mp.as_str().to_owned())
        .unwrap_or_else(|| request.uri().path().to_owned());
    let method = request.method().as_str().to_owned();

    let start = Instant::now();
    let response = next.run(request).await;
    let elapsed = start.elapsed().as_secs_f64();

    let status = response.status().as_u16().to_string();
    crate::metrics::metrics()
        .http_request_duration_seconds
        .with_label_values(&[&method, &path, &status])
        .observe(elapsed);

    response
}

/// A-21: JSON parse-bomb guard middleware (depth + array length).
///
/// Intercepts `POST`, `PUT`, and `PATCH` requests with `Content-Type:
/// application/json` and validates the body's nesting depth and array
/// length before the request reaches any handler. Bodies exceeding
/// [`crate::abuse::guards::MAX_JSON_DEPTH`] levels or
/// [`crate::abuse::guards::MAX_JSON_ARRAY_LEN`] array items are rejected
/// with HTTP 400 before any handler logic executes.
///
/// Must be applied via [`Router::route_layer`] so it only runs on matched
/// routes (not on 404 paths) and runs inside the [`DefaultBodyLimit`] layer,
/// ensuring the body is already capped at [`BODY_LIMIT_DEFAULT`] before we
/// attempt to collect it.
async fn json_depth_guard(req: Request, next: Next) -> Response {
    use axum::http::header::CONTENT_TYPE;
    use axum::http::Method;

    let is_json_body = matches!(req.method(), &Method::POST | &Method::PUT | &Method::PATCH)
        && req
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|ct| ct.starts_with("application/json"))
            .unwrap_or(false);

    if !is_json_body {
        return next.run(req).await;
    }

    let (parts, body) = req.into_parts();
    let bytes = match axum::body::to_bytes(body, BODY_LIMIT_DEFAULT).await {
        Ok(b) => b,
        Err(_) => {
            return (
                axum::http::StatusCode::PAYLOAD_TOO_LARGE,
                axum::Json(serde_json::json!({"error": "request body too large"})),
            )
                .into_response();
        }
    };

    if let Err(e) = crate::abuse::guards::check_json_depth(&bytes) {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response();
    }

    let req = Request::from_parts(parts, axum::body::Body::from(bytes));
    next.run(req).await
}

/// A-26: removes the `Server:` response header from every response so the
/// runtime identity is not disclosed to callers.
async fn strip_server_header(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    resp.headers_mut().remove(axum::http::header::SERVER);
    resp
}

/// Fail-closed bearer-token presence guard for the agent router (HEA-1412).
///
/// Checks that an `Authorization: Bearer …` header is present before the
/// request reaches any handler. Full token validation and permission checks
/// still happen per-handler — this layer ensures future handlers added to the
/// agent router return `401` even when a developer forgets the per-handler
/// auth call.
async fn require_bearer_token(req: Request, next: Next) -> Response {
    use axum::http::StatusCode;
    let has_bearer = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.starts_with("Bearer "))
        .unwrap_or(false);
    if !has_bearer {
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({"error": "missing authorization header"})),
        )
            .into_response();
    }
    next.run(req).await
}

// ── Router ────────────────────────────────────────────────────────────────────

/// Builds the HTTP router with all configured routes.
///
/// The returned router is ready to be served with [`serve`].
pub fn router(state: Arc<AppState>) -> Router {
    let admin_routes = admin::admin_api_routes();
    let realm_routes = oauth::realm_routes().merge(session::realm_routes());

    let mut base = Router::new()
        .merge(health::routes())
        .merge(users::routes())
        .merge(oauth::routes())
        .merge(mfa::routes())
        .merge(session::routes())
        .nest("/admin", admin_routes)
        .nest("/scim/v2", crate::protocol::scim::router())
        .merge(crate::protocol::web::openapi::openapi_router())
        .nest("/realms/{realm_name}", realm_routes);

    // Register agent routes only when the identity capability is enabled.
    // This prevents route fingerprinting when the feature is off.
    // route_layer wraps all agent routes with a fail-closed bearer-token guard
    // (HEA-1412) so future handlers are protected by default even without
    // per-handler auth calls.
    if state.agent_identity_enabled {
        base = base
            .merge(agents::routes().route_layer(axum::middleware::from_fn(require_bearer_token)));
    }

    // Register approval + tool-invocation check routes only when Phase C is enabled.
    // Tool invocation enforcement requires approval to be available (Phase C complete mediation).
    if state.agent_approval_enabled {
        base = base.merge(approval::routes());
        base = base.merge(tool_invocation::routes());
    }

    // Register Phase-D advanced routes (AAT, txn-token, SPIFFE, cross-realm).
    if state.agent_advanced_enabled {
        base = base.merge(advanced::routes());
    }

    // Registered only in dev mode so the route is absent from the table in
    // production, preventing fingerprinting via port scanners (HEA-1138).
    if state.dev_mode {
        base = base.route(
            "/admin/bootstrap",
            axum::routing::post(admin::admin_bootstrap),
        );
    }

    base.route_layer(axum::middleware::from_fn(track_metrics))
        // A-21: JSON parse-bomb guard — runs before handler logic on all matched routes.
        .route_layer(axum::middleware::from_fn(json_depth_guard))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(
                    DefaultMakeSpan::new()
                        .level(Level::INFO)
                        .include_headers(false),
                )
                .on_response(DefaultOnResponse::new().level(Level::DEBUG)),
        )
        .layer(DefaultBodyLimit::max(BODY_LIMIT_DEFAULT))
        // A-26: strip Server: header so the runtime identity is not disclosed.
        .layer(axum::middleware::from_fn(strip_server_header))
        .with_state(state)
}
