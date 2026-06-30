//! Actix-web middleware for mode-aware permission enforcement (feature `actix-middleware`).
//!
//! # Quick start
//!
//! ```ignore
//! use actix_web::{web, App, HttpResponse, HttpServer};
//! use hearth_sdk::{AccessTokenAuthorization, CheckPermissionOpts, HearthClient};
//! use hearth_sdk::actix::{HearthActixMiddleware, RequirePermission};
//!
//! let client = HearthClient::new("https://auth.example.com", "my-realm");
//!
//! HttpServer::new(move || {
//!     App::new().service(
//!         web::resource("/docs")
//!             .wrap(HearthActixMiddleware::new(
//!                 client.clone(),
//!                 "documents.write",
//!                 AccessTokenAuthorization::Embedded,
//!                 CheckPermissionOpts::default(),
//!             ))
//!             .route(web::post().to(create_doc)),
//!     )
//! });
//!
//! async fn create_doc(auth: RequirePermission) -> HttpResponse {
//!     HttpResponse::Ok().json(serde_json::json!({ "user": auth.claims.subject() }))
//! }
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
//! **The mode is always configured explicitly.** The middleware MUST NOT infer mode from
//! whether `permissions` is present in the token (HEA-921 design constraint).

use std::future::{ready, Ready};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll};

use actix_web::body::EitherBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::{FromRequest, HttpMessage, HttpRequest, HttpResponse};

use crate::claims::Claims;
use crate::client::HearthClient;
use crate::error::HearthError;
use crate::types::{AccessTokenAuthorization, CheckPermissionOpts};

// ── Verified-token marker ─────────────────────────────────────────────────────

/// Raw bearer token string stored in request extensions after successful authentication.
///
/// Internal marker; downstream handlers should use [`RequirePermission`] instead.
#[doc(hidden)]
pub struct VerifiedToken(String);

// ── Middleware factory ────────────────────────────────────────────────────────

struct MiddlewareConfig {
    client: HearthClient,
    permission: String,
    expected_mode: AccessTokenAuthorization,
    opts: CheckPermissionOpts,
}

/// Actix-web [`Transform`] factory for mode-aware permission enforcement.
///
/// Wrap a resource or scope with `.wrap(HearthActixMiddleware::new(...))` to require
/// a specific permission before forwarding the request downstream.  Each instance
/// enforces **one** permission with **one** explicit mode; compose multiple layers for
/// multi-permission routes.
///
/// On success, the raw bearer token is stored in request extensions so that the
/// [`RequirePermission`] extractor can decode [`Claims`] without an additional network call.
///
/// # Mode-mismatch handling
/// If the server echoes a mode different from `expected_mode` (introspection), the middleware
/// returns `403 Forbidden`. It never falls back silently.
#[derive(Clone)]
pub struct HearthActixMiddleware {
    config: Arc<MiddlewareConfig>,
}

impl HearthActixMiddleware {
    /// Create a new middleware factory that enforces `permission` using `expected_mode`.
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
            config: Arc::new(MiddlewareConfig {
                client,
                permission: permission.into(),
                expected_mode,
                opts,
            }),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for HearthActixMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = actix_web::Error;
    type Transform = HearthActixMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(HearthActixMiddlewareService {
            service: Rc::new(service),
            config: Arc::clone(&self.config),
        }))
    }
}

// ── Middleware service ────────────────────────────────────────────────────────

/// Actix-web [`Service`] produced by [`HearthActixMiddleware`].
///
/// Not constructed directly; obtained via [`HearthActixMiddleware::new_transform`].
pub struct HearthActixMiddlewareService<S> {
    service: Rc<S>,
    config: Arc<MiddlewareConfig>,
}

type LocalBoxFuture<T> = Pin<Box<dyn std::future::Future<Output = T>>>;

impl<S, B> Service<ServiceRequest> for HearthActixMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = actix_web::Error;
    type Future = LocalBoxFuture<Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);
        let config = Arc::clone(&self.config);

        Box::pin(async move {
            // Extract Bearer token; 401 on missing Authorization header.
            let token = match extract_bearer(req.headers()) {
                Some(t) => t,
                None => return short_circuit(req, actix_web::http::StatusCode::UNAUTHORIZED),
            };

            // Spec §6 rule 6: required_action tokens must never be accepted for general API
            // access — short-circuit before any permission check or network call.
            if let Ok(claims) = Claims::decode(&token) {
                if claims.tokenType() == "required_action" {
                    return short_circuit(req, actix_web::http::StatusCode::UNAUTHORIZED);
                }
            }

            let opts = config.opts.clone();
            let result = config
                .client
                .check_permission(&token, &config.permission, config.expected_mode, opts)
                .await;

            match result {
                Ok(true) => {
                    // Store the verified token so `RequirePermission` can decode claims.
                    req.extensions_mut().insert(VerifiedToken(token));
                    let resp = service.call(req).await?;
                    Ok(resp.map_into_left_body())
                }
                Ok(false) => short_circuit(req, actix_web::http::StatusCode::FORBIDDEN),
                Err(HearthError::ModeMismatch { .. }) => {
                    short_circuit(req, actix_web::http::StatusCode::FORBIDDEN)
                }
                // Fail-closed: network errors on the decision endpoint → 503 so callers
                // can distinguish "auth service unreachable" from "denied".
                Err(HearthError::AuthorizationFailed { .. }) => {
                    short_circuit(req, actix_web::http::StatusCode::SERVICE_UNAVAILABLE)
                }
                Err(_) => short_circuit(req, actix_web::http::StatusCode::FORBIDDEN),
            }
        })
    }
}

// ── Extractor ─────────────────────────────────────────────────────────────────

/// Actix-web extractor for the verified Hearth [`Claims`].
///
/// Reads the bearer token inserted into request extensions by [`HearthActixMiddleware`]
/// and decodes the JWT payload into [`Claims`].  Returns `401 Unauthorized` when no
/// verified token is present (i.e. the route is not protected by the middleware).
///
/// # Example
///
/// ```ignore
/// use actix_web::{web, HttpResponse};
/// use hearth_sdk::actix::RequirePermission;
///
/// async fn create_doc(auth: RequirePermission) -> HttpResponse {
///     HttpResponse::Ok().json(serde_json::json!({ "user": auth.claims.subject() }))
/// }
/// ```
pub struct RequirePermission {
    /// The decoded JWT claims verified by the middleware.
    pub claims: Claims,
}

impl FromRequest for RequirePermission {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
        let result = req
            .extensions()
            .get::<VerifiedToken>()
            .map(|vt| vt.0.clone())
            .ok_or_else(|| actix_web::error::ErrorUnauthorized("missing Hearth authentication"))
            .and_then(|token| {
                Claims::decode(&token)
                    .map(|claims| RequirePermission { claims })
                    .map_err(|_| actix_web::error::ErrorUnauthorized("invalid bearer token"))
            });
        ready(result)
    }
}

// ── Error type (ResponseError mapping) ───────────────────────────────────────

/// Actix-web error type for Hearth authentication/authorization failures.
///
/// Implements [`actix_web::ResponseError`] so Hearth errors can be returned from
/// handlers using the `?` operator.
#[derive(Debug, thiserror::Error)]
pub enum HearthActixError {
    /// The request lacked a valid Bearer token.
    #[error("unauthorized")]
    Unauthorized,
    /// The token holder does not have the required permission.
    #[error("forbidden")]
    Forbidden,
    /// The Hearth authorization service could not be reached (fail-closed).
    #[error("auth service unavailable")]
    ServiceUnavailable,
}

impl actix_web::ResponseError for HearthActixError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        match self {
            Self::Unauthorized => actix_web::http::StatusCode::UNAUTHORIZED,
            Self::Forbidden => actix_web::http::StatusCode::FORBIDDEN,
            Self::ServiceUnavailable => actix_web::http::StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

impl From<HearthError> for HearthActixError {
    fn from(err: HearthError) -> Self {
        match err {
            HearthError::ModeMismatch { .. } => Self::Forbidden,
            HearthError::AuthorizationFailed { .. } => Self::ServiceUnavailable,
            HearthError::TokenExpiredError { .. }
            | HearthError::TokenNotYetValidError { .. }
            | HearthError::TokenInvalidError { .. }
            | HearthError::RequiredActionError { .. } => Self::Unauthorized,
            _ => Self::Forbidden,
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn extract_bearer(headers: &actix_web::http::header::HeaderMap) -> Option<String> {
    headers
        .get(actix_web::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_string)
}

fn short_circuit<B: 'static>(
    req: ServiceRequest,
    status: actix_web::http::StatusCode,
) -> Result<ServiceResponse<EitherBody<B>>, actix_web::Error> {
    let (http_req, _) = req.into_parts();
    let resp = HttpResponse::build(status).finish();
    Ok(ServiceResponse::new(http_req, resp).map_into_right_body())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::http::header::{HeaderMap, HeaderValue, AUTHORIZATION};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    // Do NOT import `actix_web::test` as a bare name — it shadows the built-in
    // `#[test]` attribute (actix's `test` is a proc macro that requires async fn).
    // Use fully qualified `actix_web::test::TestRequest` in the async tests instead.

    fn fake_jwt(payload: &serde_json::Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"none\"}");
        let body = URL_SAFE_NO_PAD.encode(serde_json::to_string(payload).unwrap().as_bytes());
        format!("{header}.{body}.")
    }

    // ── extract_bearer ────────────────────────────────────────────────────────

    #[test]
    fn no_auth_header_returns_none() {
        assert!(extract_bearer(&HeaderMap::new()).is_none());
    }

    #[test]
    fn valid_bearer_is_extracted() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer tok.en.here"));
        assert_eq!(extract_bearer(&headers).as_deref(), Some("tok.en.here"));
    }

    #[test]
    fn basic_scheme_returns_none() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Basic dXNlcjpwYXNz"));
        assert!(extract_bearer(&headers).is_none());
    }

    #[test]
    fn bearer_prefix_is_stripped() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer my.actual.token"),
        );
        let token = extract_bearer(&headers).unwrap();
        assert!(!token.starts_with("Bearer "));
        assert_eq!(token, "my.actual.token");
    }

    // ── required_action detection ─────────────────────────────────────────────

    #[test]
    fn required_action_token_is_detected() {
        let token = fake_jwt(&serde_json::json!({
            "sub": "user_1",
            "token_type": "required_action",
            "required_actions": ["VERIFY_EMAIL", "UPDATE_PASSWORD"]
        }));
        let claims = Claims::decode(&token).unwrap();
        assert_eq!(claims.tokenType(), "required_action");
    }

    #[test]
    fn access_token_is_not_short_circuited() {
        let token = fake_jwt(&serde_json::json!({
            "sub": "user_1",
            "token_type": "access"
        }));
        let claims = Claims::decode(&token).unwrap();
        assert_ne!(claims.tokenType(), "required_action");
    }

    // ── HearthActixError ──────────────────────────────────────────────────────

    #[test]
    fn hearth_actix_error_status_codes() {
        use actix_web::ResponseError;
        assert_eq!(
            HearthActixError::Unauthorized.status_code(),
            actix_web::http::StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            HearthActixError::Forbidden.status_code(),
            actix_web::http::StatusCode::FORBIDDEN
        );
        assert_eq!(
            HearthActixError::ServiceUnavailable.status_code(),
            actix_web::http::StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn hearth_error_mode_mismatch_maps_to_forbidden() {
        use crate::types::AccessTokenAuthorization;
        let err = HearthError::ModeMismatch {
            expected: AccessTokenAuthorization::Embedded,
            actual: AccessTokenAuthorization::Decision,
        };
        assert!(matches!(
            HearthActixError::from(err),
            HearthActixError::Forbidden
        ));
    }

    #[test]
    fn hearth_error_authorization_failed_maps_to_service_unavailable() {
        let err = HearthError::AuthorizationFailed {
            reason: "network timeout".into(),
        };
        assert!(matches!(
            HearthActixError::from(err),
            HearthActixError::ServiceUnavailable
        ));
    }

    // ── RequirePermission extractor ───────────────────────────────────────────

    #[actix_web::test]
    async fn extractor_returns_401_without_verified_token() {
        let req = actix_web::test::TestRequest::default().to_http_request();
        let mut payload = actix_web::dev::Payload::None;
        let result = RequirePermission::from_request(&req, &mut payload).await;
        assert!(
            result.is_err(),
            "extractor must fail when no VerifiedToken is in extensions"
        );
    }

    #[actix_web::test]
    async fn extractor_succeeds_with_verified_token_in_extensions() {
        let token = fake_jwt(&serde_json::json!({
            "sub": "user_42",
            "token_type": "access"
        }));

        let req = actix_web::test::TestRequest::default().to_http_request();
        req.extensions_mut().insert(VerifiedToken(token));

        let mut payload = actix_web::dev::Payload::None;
        let result = RequirePermission::from_request(&req, &mut payload).await;
        assert!(result.is_ok(), "extractor must succeed with VerifiedToken");
        assert_eq!(result.unwrap().claims.subject(), "user_42");
    }

    #[actix_web::test]
    async fn extractor_returns_claims_with_correct_sub() {
        let token = fake_jwt(&serde_json::json!({
            "sub": "user_abc",
            "permissions": ["docs.read", "docs.write"],
            "roles": ["editor"]
        }));

        let req = actix_web::test::TestRequest::default().to_http_request();
        req.extensions_mut().insert(VerifiedToken(token));

        let mut payload = actix_web::dev::Payload::None;
        let auth = RequirePermission::from_request(&req, &mut payload)
            .await
            .unwrap();

        assert_eq!(auth.claims.subject(), "user_abc");
        assert!(auth.claims.hasPermission("docs.write"));
        assert!(auth.claims.hasRole("editor"));
    }
}
