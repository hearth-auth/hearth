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
pub mod limits;
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
pub use serve::{
    serve, serve_redirect, serve_router, serve_router_on, serve_tls, serve_tls_router,
};
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
    check_anonymous_token_rate_limit, check_export_capability, check_export_rate_limit,
    check_token_rate_limit, emit_export_watermark, extract_bearer_token, extract_realm_id,
    extract_user_auth, identity_error_to_response, make_ip_rate_limit_response, now_micros,
    proto_to_rest_json, rbac_error_to_response, resolve_realm_by_name,
    validate_user_token_with_dpop, verify_manifest_signature,
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

/// Body limit (4 MiB) for the SAML front-channel POST bindings — the SP
/// assertion consumer service and the IdP `SSO` / `SLO` POST endpoints.
///
/// A SAML message arrives as base64 of a signed XML document, so the wire form
/// is ~33 % larger than the XML itself, and the XML carries the signing
/// certificate chain plus an arbitrary attribute statement. Real IdPs (ADFS
/// with a large group claim set, in particular) routinely exceed the 1 MiB
/// [`BODY_LIMIT_DEFAULT`] that suits a JSON API body, so forcing one number
/// across both shapes would break federation (task 21.1).
pub(crate) const BODY_LIMIT_SAML: usize = 4 * 1024 * 1024;

/// Body limit (16 MiB) for the admin CSV user-import uploads.
///
/// These are the only browser routes that take a `multipart/form-data` file
/// upload. 16 MiB is roughly 200 000 user rows — far beyond a realistic
/// single import, and still four orders of magnitude below the
/// [`BACKUP_RESTORE_BODY_LIMIT`] (task 21.1).
pub(crate) const BODY_LIMIT_CSV_IMPORT: usize = 16 * 1024 * 1024;

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

/// Refuses a dev-only endpoint whenever the connecting peer is not loopback
/// (audit §4.7#2, task 20.1).
///
/// # Why the socket address and nothing else
///
/// The peer is read straight out of `ConnectInfo<SocketAddr>`, never through
/// `PeerAddr` and never through `X-Forwarded-For`. `PeerAddr` substitutes
/// `FALLBACK_PEER` — which is `127.0.0.1` — when the extension is absent, so
/// using it here would make the guard fail **open** on exactly the deployment
/// shape it exists to protect. `X-Forwarded-For` is attacker-controlled from
/// an untrusted peer and must never decide a loopback question.
///
/// An absent `ConnectInfo` is therefore treated as *not loopback* outside the
/// crate's own unit tests: both accept loops install the extension, so its
/// absence in a real server means a caller assembled their own service without
/// it — the embedded case this guard is for.
///
/// IPv4-mapped IPv6 (`::ffff:127.0.0.1`) counts as loopback: that is what a
/// dual-stack `[::]` listener reports for a local IPv4 client, and `make dev`
/// would otherwise break on a `::`-bound server.
///
/// The refusal is `404`, not `403`, so the response is byte-identical to the
/// one a production build (no `dev-endpoints` feature, or `dev_mode = false`)
/// returns. A remote scanner cannot tell a dev server from a production one.
#[cfg(feature = "dev-endpoints")]
async fn dev_loopback_only(req: Request, next: Next) -> Response {
    use std::net::{IpAddr, SocketAddr};

    let peer = req
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0);

    let is_loopback = match peer {
        Some(addr) => match addr.ip() {
            IpAddr::V4(v4) => v4.is_loopback(),
            IpAddr::V6(v6) => {
                v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
            }
        },
        // In-crate unit tests drive handlers through `tower::oneshot`, which
        // installs no `ConnectInfo`. Every other build treats the absence as
        // remote.
        None => cfg!(test),
    };

    if is_loopback {
        next.run(req).await
    } else {
        tracing::warn!(
            "dev endpoint refused: the peer is not loopback. Dev and test endpoints are \
             never served to a remote client, whatever the bind address."
        );
        StatusCode::NOT_FOUND.into_response()
    }
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
///
/// Since task 21.1 this layer also covers the browser routes (`/ui/*`, the SAML
/// front channel, the pre-auth recovery pages), which were previously merged
/// *beside* this stack and therefore never saw it.
///
/// # Dev-mode grace
///
/// `make dev` serves the console on `127.0.0.1:8420` and the reference
/// integration drives it from `localhost:5173` / `localhost:5399`. An operator
/// whose `hearth.yaml` names only the production hostname would, now that the
/// allowlist reaches `/ui/*`, be locked out of their own dev console. Under
/// `--dev` only, a loopback `Host` is therefore always admitted. Production
/// (`dev_mode == false`) is unchanged: the list is the whole truth.
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
    let permitted = state
        .allowed_hosts
        .iter()
        .any(|h| h.eq_ignore_ascii_case(host))
        || (state.dev_mode && is_loopback_host(host));
    if permitted {
        next.run(req).await
    } else {
        (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({"error": "host not allowed"})),
        )
            .into_response()
    }
}

/// Strips an optional `:port` suffix from a `Host` header value, handling the
/// bracketed IPv6 literal form (`[::1]:8420`).
fn host_without_port(host: &str) -> &str {
    if let Some(rest) = host.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    match host.rsplit_once(':') {
        Some((h, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => host,
    }
}

/// `true` when a `Host` header names the loopback interface — `localhost`, or
/// any address that parses as a loopback IP.
fn is_loopback_host(host: &str) -> bool {
    let bare = host_without_port(host);
    bare.eq_ignore_ascii_case("localhost")
        || bare
            .parse::<IpAddr>()
            .is_ok_and(|ip: IpAddr| ip.is_loopback())
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
    if is_shaper_exempt(&req) {
        return next.run(req).await;
    }

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
        // Tagged with its source so a shed request can be attributed to the
        // shaper rather than to one of the endpoint limiters (HEA-2010).
        _ => (
            StatusCode::TOO_MANY_REQUESTS,
            [("Retry-After", "1")],
            axum::Json(auth::rate_limit_body(
                auth::LIMITER_SHAPER,
                "rate limit exceeded",
            )),
        )
            .into_response(),
    }
}

/// `true` when a matched route is exempt from the per-IP request shaper.
///
/// Only the browser static-asset routes qualify. They serve bytes compiled into
/// the binary (or loaded once at startup) and touch no engine, but `app.css`,
/// `theme.css` and the per-realm theme are served `no-cache` + `ETag`, so every
/// page navigation re-validates each of them. Counting those against the
/// caller's per-IP budget would spend a page-load's worth of quota on requests
/// that carry no attack leverage, and would make the cap fire on ordinary
/// browsing rather than on abuse (task 21.1).
///
/// Everything else under `/ui/*` — every form post, every htmx fragment, the
/// SAML front channel, the pre-auth recovery pages — stays under the cap.
fn is_shaper_exempt(req: &Request) -> bool {
    let path = req
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| req.uri().path(), MatchedPath::as_str);
    path.starts_with("/ui/static/") || path == "/favicon.ico" || path == "/favicon.svg"
}

/// Rejects a realm-path request whose `X-Realm-ID` header names a *different*
/// realm than the `/realms/{realm_name}/…` path segment (audit §4.16#12).
///
/// The deployment guide tells operators to front Hearth with a proxy that maps
/// a tenant subdomain onto `X-Realm-ID`. The realm-path routes resolve their
/// realm from the path alone, so before this guard a request to
/// `tenant-a.example.com/realms/tenant-b/token` was served as tenant B while
/// the proxy believed it had pinned tenant A — silent tenant confusion.
///
/// Semantics (the safe reading): the header may only *confirm* the path realm,
/// never select or override it.
///
/// * No `X-Realm-ID` header — unchanged behaviour, the path decides.
/// * Header present and equal to the path realm's id — unchanged behaviour.
/// * Header present and different, or not a UUID — `400 realm_mismatch`.
/// * Path realm unknown — passed through so the handler still answers `404`.
async fn realm_path_header_agreement(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(realm_name): axum::extract::Path<String>,
    req: Request,
    next: Next,
) -> Response {
    // Parsed eagerly into an owned value so the borrow of `req` ends here and
    // `req` can still be handed to `next`. The outer `Option` is header
    // presence; the inner one is "parsed as a UUID".
    let Some(claimed) = req
        .headers()
        .get("x-realm-id")
        .map(|v| v.to_str().ok().and_then(|s| s.parse::<uuid::Uuid>().ok()))
    else {
        return next.run(req).await;
    };

    // The path realm is authoritative. If it does not resolve we let the
    // handler produce its own 404 rather than masking it with a 400.
    let Ok(Some(realm)) = state.identity.get_realm_by_name(&realm_name) else {
        return next.run(req).await;
    };

    if claimed.is_some_and(|id| id == *realm.id().as_uuid()) {
        return next.run(req).await;
    }

    tracing::warn!(
        path_realm = %realm_name,
        "X-Realm-ID disagrees with the realm named in the request path"
    );
    (
        StatusCode::BAD_REQUEST,
        axum::Json(serde_json::json!({
            "error": "realm_mismatch",
            "error_description":
                "X-Realm-ID does not match the realm named in the request path",
        })),
    )
        .into_response()
}

// ── Router ────────────────────────────────────────────────────────────────────

/// Builds the HTTP router with all configured routes.
///
/// The returned router is ready to be served with [`serve`].
pub fn router(state: Arc<AppState>) -> Router {
    router_with(state, Router::new())
}

/// Builds the HTTP router, merging `extra` **under** the shared guard stack.
///
/// `main.rs` passes the browser router (`protocol::web::router`, plus the
/// dev-only mailcatcher router) as `extra`. It used to compose the tree as
/// `router(state).merge(web::router(..))` instead — but [`Router::layer`] wraps
/// only the routes registered before it, so every guard this function installs
/// stopped at the API surface and none of them reached `/ui/*`, the SAML ACS
/// and `begin` endpoints, or the pre-auth recovery pages (task 21.1, audit
/// §4.5#1–#4, §4.10#8, §4.24#8).
///
/// Merging before the layers means the browser routes now get, in order from
/// the outside in: the `Host` allowlist, the minimal security headers, the
/// `Server:`-header strip, the 1 MiB [`DefaultBodyLimit`], the trace layer,
/// the per-IP request shaper, the JSON parse-bomb depth guard and the
/// request-duration histogram.
///
/// Per-route overrides still win, because they are applied inside the
/// `MethodRouter` and therefore run last on the request path: the SAML front
/// channel keeps [`BODY_LIMIT_SAML`], the admin CSV imports keep
/// [`BODY_LIMIT_CSV_IMPORT`], and `POST /admin/backup/restore` keeps
/// [`BACKUP_RESTORE_BODY_LIMIT`].
///
/// The three `route_layer` guards do not run on unmatched paths, so the web
/// router's branded 404 fallback is not rate-limited or body-parsed — it is
/// still covered by the outer `layer` stack, including the `Host` allowlist.
pub fn router_with(state: Arc<AppState>, extra: Router) -> Router {
    // A `cnf`-bound admin or SCIM token must present a matching DPoP proof;
    // without this layer it was replayable as a plain Bearer for every admin
    // read and write (audit 2026-08-28 §4.19#8). `route_layer` so it runs only
    // on a matched route and leaves 404s untouched.
    let admin_routes = admin::admin_api_routes().route_layer(axum::middleware::from_fn_with_state(
        Arc::clone(&state),
        auth::enforce_admin_dpop,
    ));
    let scim_routes = crate::protocol::scim::router().route_layer(
        axum::middleware::from_fn_with_state(Arc::clone(&state), auth::enforce_admin_dpop),
    );
    // Every route nested under `/realms/{realm_name}` gets the agreement guard
    // via `route_layer`, so it runs only on a matched realm route and leaves
    // 404s untouched (audit §4.16#12).
    let realm_routes = oauth::realm_routes()
        .merge(session::realm_routes())
        .route_layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            realm_path_header_agreement,
        ));

    let mut base = Router::new()
        .merge(health::routes())
        .merge(users::routes())
        .merge(oauth::routes())
        .merge(mfa::routes())
        .merge(session::routes())
        .nest("/admin", admin_routes)
        .nest("/scim/v2", scim_routes)
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

    // Dev-only endpoints. Three independent gates, because each closes a
    // different hole (audit §4.7#2, task 20.1):
    //
    // 1. **Compile time** — the `dev-endpoints` cargo feature. It is on by
    //    default so `make dev`, `cargo nextest` and the Playwright suite are
    //    unaffected; the shipped container image builds with
    //    `--no-default-features`, so these handlers are not in the production
    //    binary at all. A runtime boolean alone left the code, the
    //    hard-coded `admin@hearth.test` password and the seeding logic
    //    compiled into every release.
    // 2. **Run time** — `state.dev_mode`, unchanged, so the routes are absent
    //    from the table in a non-dev process and cannot be fingerprinted.
    // 3. **Per request** — `dev_loopback_only`. `main.rs` refuses a non-
    //    loopback bind under `--dev`, but the *embedded* path has no such
    //    check: a library consumer who builds this router and serves it
    //    themselves published `/admin/bootstrap` and the `/dev/seed-*` family
    //    on whatever address they chose. The guard travels with the routes, so
    //    it holds on every serve path — plaintext, TLS and embedded alike.
    #[cfg(feature = "dev-endpoints")]
    if state.dev_mode {
        base = base.merge(
            Router::new()
                .route(
                    "/admin/bootstrap",
                    axum::routing::post(admin::admin_bootstrap),
                )
                .route("/dev/probe-user", axum::routing::get(admin::dev_probe_user))
                .route(
                    "/dev/seed-session",
                    axum::routing::post(admin::dev_seed_session),
                )
                .route(
                    "/dev/seed-token",
                    axum::routing::post(admin::dev_seed_token),
                )
                .route(
                    "/dev/seed-password",
                    axum::routing::post(admin::dev_seed_password),
                )
                .route_layer(axum::middleware::from_fn(dev_loopback_only)),
        );
    }

    // The API subtree resolves its state here so the browser router — which
    // carries its own `WebState` and is therefore already a `Router<()>` — can
    // be merged in *before* the guard layers below rather than after them.
    base.with_state(Arc::clone(&state))
        .merge(extra)
        .route_layer(axum::middleware::from_fn(track_metrics))
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
            state,
            enforce_host_allowlist,
        ))
}

/// Adds `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer` to every
/// REST API response. Unlike the web UI's full `SecurityHeadersLayer`, these two headers
/// are safe for machine-API responses and do not require UI-specific context.
///
/// Both headers are **only** added when absent. Since task 21.1 this layer also
/// sees the browser responses, and the web tree's `SecurityHeadersLayer` runs
/// inside it with a deliberately different, browser-appropriate
/// `Referrer-Policy: strict-origin-when-cross-origin`. An unconditional
/// `insert` here would silently overwrite it on every UI page.
async fn minimal_security_headers(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    let nosniff = axum::http::HeaderName::from_static("x-content-type-options");
    if !h.contains_key(&nosniff) {
        h.insert(nosniff, axum::http::HeaderValue::from_static("nosniff"));
    }
    let referrer = axum::http::HeaderName::from_static("referrer-policy");
    if !h.contains_key(&referrer) {
        h.insert(
            referrer,
            axum::http::HeaderValue::from_static("no-referrer"),
        );
    }
    resp
}
