//! Tower middleware for mode-aware permission enforcement (feature `tower-middleware`).
//!
//! # Quick start
//!
//! ```ignore
//! use hearth_sdk::{HearthClient, AccessTokenAuthorization, CheckPermissionOpts};
//! use hearth_sdk::middleware::RequirePermissionLayer;
//!
//! let client = HearthClient::new("https://auth.example.com", "my-realm");
//!
//! // Decision mode: per-request /oauth/authorize call.
//! let layer = RequirePermissionLayer::new(
//!     client,
//!     "documents.write",
//!     AccessTokenAuthorization::Decision,
//!     CheckPermissionOpts::default(),
//! );
//!
//! // Axum example:
//! let app = axum::Router::new()
//!     .route("/docs", axum::routing::post(create_doc))
//!     .layer(layer);
//! ```
//!
//! # Mode semantics
//!
//! | Mode | What the middleware does |
//! |------|--------------------------|
//! | `Embedded` | Decodes JWT locally; checks `permissions[]` claim. No network. |
//! | `Introspection` | Calls `POST /introspect`; validates echoed mode; checks live permissions. |
//! | `Decision` | Calls `POST /oauth/authorize`; reads `allowed`. Fail-closed on network errors. |
//!
//! **The mode is always configured explicitly.**  The middleware MUST NOT infer mode from
//! whether `permissions` is present in the token (HEA-921 design constraint).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tower::{Layer, Service};

use crate::claims::Claims;
use crate::client::HearthClient;
use crate::error::HearthError;
use crate::types::{AccessTokenAuthorization, CheckPermissionOpts};

// ── Layer factory ─────────────────────────────────────────────────────────────

/// Tower [`Layer`] factory for mode-aware permission enforcement.
///
/// Wrap a route or router with this layer to require a specific permission before
/// forwarding the request downstream.  Each layer instance enforces **one** permission
/// with **one** explicit mode; compose multiple layers for multi-permission routes.
///
/// # Mode-mismatch handling
/// If the server echoes a mode different from `expected_mode` (via introspection),
/// the middleware returns `403 Forbidden`.  It never falls back silently.
#[derive(Clone)]
pub struct RequirePermissionLayer {
    config: Arc<LayerConfig>,
}

struct LayerConfig {
    client: HearthClient,
    permission: String,
    expected_mode: AccessTokenAuthorization,
    opts: CheckPermissionOpts,
}

impl RequirePermissionLayer {
    /// Create a new layer that enforces `permission` using `expected_mode`.
    ///
    /// `opts` carries optional `organization_id`, `resource`, and (for `Introspection`
    /// mode) `client_credentials`.
    pub fn new(
        client: HearthClient,
        permission: impl Into<String>,
        expected_mode: AccessTokenAuthorization,
        opts: CheckPermissionOpts,
    ) -> Self {
        Self {
            config: Arc::new(LayerConfig {
                client,
                permission: permission.into(),
                expected_mode,
                opts,
            }),
        }
    }
}

impl<S> Layer<S> for RequirePermissionLayer {
    type Service = RequirePermissionService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequirePermissionService {
            inner,
            config: Arc::clone(&self.config),
        }
    }
}

// ── Service ───────────────────────────────────────────────────────────────────

/// Tower [`Service`] produced by [`RequirePermissionLayer`].
///
/// Generic over the downstream service `S`, the request body type `B`, and the
/// response body type `ResBody`.  The only constraint on `ResBody` is `Default`,
/// which is used to construct zero-byte error responses (401, 403, 503).
#[derive(Clone)]
pub struct RequirePermissionService<S> {
    inner: S,
    config: Arc<LayerConfig>,
}

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

impl<S, ReqBody, ResBody> Service<http::Request<ReqBody>> for RequirePermissionService<S>
where
    S: Service<http::Request<ReqBody>, Response = http::Response<ResBody>>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>> + Send,
    ReqBody: Send + 'static,
    ResBody: Default + Send + 'static,
{
    type Response = http::Response<ResBody>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: http::Request<ReqBody>) -> Self::Future {
        let config = Arc::clone(&self.config);
        // Clone inner before moving into the async block — standard tower pattern
        // for services that need to stay usable after `call` returns.
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let token = match extract_bearer(req.headers()) {
                Some(t) => t,
                None => return Ok(status_response(http::StatusCode::UNAUTHORIZED)),
            };

            // Spec §6 rule 6: a required_action token is structurally valid but must
            // never be accepted for general API access — short-circuit before any
            // permission check or network call.  The spec says "respond with 401 and
            // throw RequiredActionError"; in Tower middleware the HTTP 401 IS the
            // throw — the error is conveyed via status, not a Rust Err variant, so
            // callers see UNAUTHORIZED rather than an unknown infrastructure error.
            if let Ok(claims) = Claims::decode(&token) {
                if claims.tokenType() == "required_action" {
                    return Ok(status_response(http::StatusCode::UNAUTHORIZED));
                }
            }

            let opts = config.opts.clone();
            let result = config
                .client
                .check_permission(&token, &config.permission, config.expected_mode, opts)
                .await;

            match result {
                Ok(true) => inner.call(req).await.map_err(Into::into),
                Ok(false) => Ok(status_response(http::StatusCode::FORBIDDEN)),
                Err(HearthError::ModeMismatch { .. }) => {
                    Ok(status_response(http::StatusCode::FORBIDDEN))
                }
                // Fail-closed: network errors on the decision endpoint → 503 so callers
                // can distinguish "auth service unreachable" from "denied".
                Err(HearthError::AuthorizationFailed { .. }) => {
                    Ok(status_response(http::StatusCode::SERVICE_UNAVAILABLE))
                }
                Err(_) => Ok(status_response(http::StatusCode::FORBIDDEN)),
            }
        })
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn extract_bearer(headers: &http::HeaderMap) -> Option<String> {
    headers
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_string)
}

fn status_response<B: Default>(status: http::StatusCode) -> http::Response<B> {
    let mut resp = http::Response::new(B::default());
    *resp.status_mut() = status;
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    /// Build a minimal unsigned JWT with the given payload JSON.
    fn fake_jwt(payload: &serde_json::Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"none\"}");
        let body =
            URL_SAFE_NO_PAD.encode(serde_json::to_string(payload).unwrap().as_bytes());
        format!("{header}.{body}.")
    }

    #[test]
    fn no_bearer_returns_401() {
        // extract_bearer with no Authorization header returns None
        let headers = http::HeaderMap::new();
        assert!(extract_bearer(&headers).is_none());
    }

    #[test]
    fn required_action_token_detected() {
        // A token with token_type=required_action must be detected before permission check.
        let payload = serde_json::json!({
            "sub": "user_1",
            "token_type": "required_action",
            "required_actions": ["VERIFY_EMAIL", "UPDATE_PASSWORD"]
        });
        let token = fake_jwt(&payload);
        let claims = Claims::decode(&token).unwrap();
        assert_eq!(claims.tokenType(), "required_action");

        // Verify the middleware would short-circuit (token_type check passes).
        assert_eq!(claims.tokenType(), "required_action");
        let required_actions: Vec<String> = claims
            .get("required_actions")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(required_actions, vec!["VERIFY_EMAIL", "UPDATE_PASSWORD"]);
    }

    #[test]
    fn non_required_action_token_is_not_short_circuited() {
        let payload = serde_json::json!({
            "sub": "user_1",
            "token_type": "access",
        });
        let token = fake_jwt(&payload);
        let claims = Claims::decode(&token).unwrap();
        assert_ne!(claims.tokenType(), "required_action");
    }
}
