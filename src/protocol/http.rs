//! HTTP server and route definitions.
//!
//! Builds an [`axum::Router`] with health, OIDC discovery, JWKS, OAuth 2.0,
//! and Admin API endpoints. The server is configured with shared application
//! state containing the identity, RBAC, and audit engines.
//!
//! The protocol layer is a thin, stateless adapter: it translates HTTP requests
//! into domain calls on `IdentityEngine` and maps `IdentityError` to HTTP
//! status codes. No business logic lives here.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{ConnectInfo, DefaultBodyLimit, MatchedPath, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Router;
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::Level;

use crate::abuse::shaper::ShaperOutcome;

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

pub use auth::has_export_capability;
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

// ── KDF admission gate (HEA-1887 / R1, extended by HEA-1891) ──────────────────

/// Runs a blocking Argon2id-bearing REST closure under the shared process-global
/// KDF admission gate, mapping shed to a `503` JSON response.
///
/// Every REST handler whose engine call performs an Argon2id hash or verify
/// (`create_user`, `import_user`, …) MUST route through this helper so it shares
/// the *one* permit pool with the UI login/register/reset/change-password paths.
/// That shared bound is what makes the `permits × ~19 MiB` peak-memory guarantee
/// hold across **all** Argon2 callers rather than per-callsite (HEA-1889 F3).
///
/// The permit is acquired *before* `spawn_blocking`, so a waiting request holds
/// neither a blocking-pool thread nor a 19 MiB allocation. A `Join` failure
/// (panic/cancel) is surfaced to the caller as [`IdentityError::Storage`] via
/// `on_join`, matching the previous ad-hoc `spawn_blocking(...).unwrap_or_else`.
pub(crate) async fn run_kdf_gated_rest<F, T>(
    f: F,
    on_join: impl FnOnce(crate::identity::KdfGateError) -> T,
) -> Result<T, Response>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    match crate::identity::gate().run(f).await {
        Ok(v) => Ok(v),
        Err(crate::identity::KdfGateError::Overloaded { retry_after }) => {
            Err(kdf_shed_json_response(retry_after))
        }
        Err(e @ crate::identity::KdfGateError::Join(_)) => Ok(on_join(e)),
    }
}

/// Builds the `503 Service Unavailable` JSON shed response for an overloaded
/// KDF gate, carrying a `Retry-After` header (seconds, floored to 1).
pub(crate) fn kdf_shed_json_response(retry_after: std::time::Duration) -> Response {
    let secs = retry_after.as_secs().max(1);
    let mut resp = (
        StatusCode::SERVICE_UNAVAILABLE,
        axum::Json(serde_json::json!({
            "error": "kdf_overloaded",
            "error_description": "Server is busy hashing credentials. Please retry shortly.",
        })),
    )
        .into_response();
    resp.headers_mut().insert(
        axum::http::header::RETRY_AFTER,
        axum::http::HeaderValue::from(secs),
    );
    resp
}

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

/// A-40: Host header allowlist enforcement (DNS rebinding protection).
///
/// When `allowed_hosts` is non-empty in [`AppState`], rejects requests whose
/// `Host` header is absent or does not match any entry (case-insensitive).
/// An empty list means accept any host (fail-open for backward compatibility
/// with existing deployments that predate this control).
///
/// Applied as the outermost layer so the check runs before route dispatch and
/// before any handler logic can execute.
async fn enforce_host_allowlist(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    if state.allowed_hosts.is_empty() {
        return next.run(req).await;
    }
    let host = req
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if state
        .allowed_hosts
        .iter()
        .any(|h| h.eq_ignore_ascii_case(host))
    {
        next.run(req).await
    } else {
        (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({"error": "host not allowed"})),
        )
            .into_response()
    }
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

/// A-2: Global HTTP per-IP rate-limit middleware.
///
/// Applied to every matched route via [`Router::route_layer`] so 404 paths
/// do not consume shaper budget.  Returns `429 Too Many Requests` with a
/// `Retry-After: 1` hint when the per-IP (or per-realm) sliding-window limit
/// is exceeded.  The shaper is shared with the gRPC surface via `Arc` so
/// a caller cannot evade the limit by switching protocols.
async fn http_rate_limit(State(state): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    let peer = req
        .extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0)
        .unwrap_or(FALLBACK_PEER);

    let ip_str = crate::protocol::client_info::extract_client_ip(
        req.headers(),
        peer,
        &state.trusted_proxies,
    );
    let ip: IpAddr = ip_str.parse().unwrap_or_else(|_| peer.ip());

    match state.request_shaper.check(ip, "") {
        ShaperOutcome::Allow => next.run(req).await,
        _ => (
            StatusCode::TOO_MANY_REQUESTS,
            [("Retry-After", "1")],
            axum::Json(serde_json::json!({"error": "too_many_requests"})),
        )
            .into_response(),
    }
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
        base = base
            .route(
                "/admin/bootstrap",
                axum::routing::post(admin::admin_bootstrap),
            )
            .route("/dev/probe-user", axum::routing::get(admin::dev_probe_user));
    }

    base.route_layer(axum::middleware::from_fn(track_metrics))
        // A-21: JSON parse-bomb guard — runs before handler logic on all matched routes.
        .route_layer(axum::middleware::from_fn(json_depth_guard))
        // A-2: global HTTP rate limiter — runs before body parsing on all matched routes.
        .route_layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            http_rate_limit,
        ))
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
        // HEA-SEC-33: minimal security headers on every REST API response.
        .layer(axum::middleware::from_fn(minimal_security_headers))
        // A-40: Host header allowlist — outermost layer so it runs before route
        // dispatch. Uses from_fn_with_state so the middleware can read
        // state.allowed_hosts without a separate Arc capture.
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            enforce_host_allowlist,
        ))
        .with_state(state)
}

/// Adds `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer` to every
/// REST API response. Unlike the web UI's full [`SecurityHeadersLayer`], these two headers
/// are safe for machine-API responses and do not require UI-specific context.
async fn minimal_security_headers(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(
        axum::http::HeaderName::from_static("x-content-type-options"),
        axum::http::HeaderValue::from_static("nosniff"),
    );
    h.insert(
        axum::http::HeaderName::from_static("referrer-policy"),
        axum::http::HeaderValue::from_static("no-referrer"),
    );
    resp
}
