//! Health and metrics endpoints: `/health`, `/healthz`, `/readyz`, `/metrics`.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;

use super::AppState;

/// Registers all health-check and metrics routes.
pub(super) fn routes() -> axum::Router<Arc<AppState>> {
    use axum::routing::get;
    axum::Router::new()
        .route("/health", get(health))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics_handler))
}

/// Liveness probe endpoint.
///
/// Returns `200 OK` immediately — if the process can serve HTTP it is alive.
/// Kubernetes uses this to decide when to restart a crashed or deadlocked pod.
/// Unlike `/readyz`, this endpoint does **not** check external dependencies.
async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({"status": "ok"})))
}

/// Readiness probe endpoint.
///
/// Returns `200 OK` when the storage engine is accessible and the server is
/// prepared to handle traffic. Returns `503 Service Unavailable` when the
/// storage layer is unreachable (e.g. during startup or after a corruption
/// event). Kubernetes gates inbound traffic behind this check.
async fn readyz(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let identity = Arc::clone(&state.identity);
    let healthy = tokio::task::spawn_blocking(move || identity.is_storage_healthy())
        .await
        .unwrap_or(false);

    if healthy {
        (
            StatusCode::OK,
            Json(serde_json::json!({"status": "ready", "storage": "ok"})),
        )
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"status": "not_ready", "storage": "unavailable"})),
        )
    }
}

/// Prometheus metrics scrape endpoint (`/metrics`).
///
/// Returns the current metric snapshot in the Prometheus text exposition
/// format (version 0.0.4). Operators should point their Prometheus scrape
/// config at this path.
///
/// When `metrics.bearer_token` is set in `hearth.yaml`, requests must supply
/// a matching `Authorization: Bearer <token>` header or receive HTTP 401
/// (A-26). When no token is configured the endpoint is unauthenticated —
/// operators SHOULD firewall it at the network layer or bind to loopback.
async fn metrics_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !state.metrics_enabled {
        return (
            StatusCode::NOT_FOUND,
            [(axum::http::header::CONTENT_TYPE, "text/plain")],
            String::new(),
        )
            .into_response();
    }

    // A-26: enforce Bearer auth when a token is configured (constant-time).
    if let Some(expected) = &state.metrics_bearer_token {
        use subtle::ConstantTimeEq as _;
        let supplied = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .unwrap_or("");
        let ok: bool = supplied.as_bytes().ct_eq(expected.as_bytes()).into();
        if !ok {
            return (
                StatusCode::UNAUTHORIZED,
                [(axum::http::header::WWW_AUTHENTICATE, "Bearer")],
                String::new(),
            )
                .into_response();
        }
    }

    let body = crate::metrics::metrics().render();
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

/// Health check endpoint.
///
/// Returns 200 OK with a JSON body indicating the server is healthy.
/// Used by load balancers, monitoring, and CLI integration tests.
///
/// Prefer `/healthz` (liveness) or `/readyz` (readiness) for Kubernetes probes.
async fn health() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({"status": "ok"})))
}
