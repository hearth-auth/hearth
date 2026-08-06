//! Tower middleware that appends security response headers to every UI response.
//!
//! Headers applied:
//! - `Content-Security-Policy` — restricts script/style/connect sources.
//! - `X-Frame-Options: DENY` — prevents clickjacking.
//! - `X-Content-Type-Options: nosniff` — blocks MIME-type sniffing.
//! - `Referrer-Policy: strict-origin-when-cross-origin`
//! - `Strict-Transport-Security` — only when TLS is enabled.
//! - `Cross-Origin-Opener-Policy: same-origin` (A-40)
//! - `Cross-Origin-Embedder-Policy: require-corp` (A-40)
//! - `Permissions-Policy` — disables powerful features (A-40)

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::http::{HeaderName, HeaderValue, Request, Response};
use tower::{Layer, Service};

/// Settings that control which optional headers are emitted.
#[derive(Clone, Debug)]
pub struct SecurityConfig {
    /// Emit HSTS header (only set when the server is serving TLS).
    pub hsts_enabled: bool,
    /// Emit COOP/COEP headers (A-40). Default: `true`.
    pub coop_coep_enabled: bool,
    /// Extra origins appended to the CSP `form-action` directive beyond
    /// `'self'`.
    ///
    /// MUST be empty in production so the emitted directive is byte-identical
    /// to `form-action 'self'`. Populated only under `--dev` (HEA-2072) so the
    /// reference-integration Playwright suite can POST to the demo SPA's Vite
    /// dev server (`http://localhost:5173`) and companion service
    /// (`http://localhost:5399`). Gating this behind dev mode keeps the two
    /// plaintext-http localhost origins out of every production response.
    pub extra_form_action_origins: Vec<String>,
}

/// Tower layer that wraps services with security header injection.
#[derive(Clone)]
pub struct SecurityHeadersLayer {
    config: Arc<SecurityConfig>,
    /// Precomputed CSP header value (form-action origins are known at
    /// construction time, so the string is built once rather than per request).
    csp: HeaderValue,
}

impl SecurityHeadersLayer {
    /// Creates a new layer. Set `hsts_enabled` to `true` when TLS is active.
    #[must_use]
    pub fn new(config: SecurityConfig) -> Self {
        let csp = build_csp(&config.extra_form_action_origins);
        Self {
            config: Arc::new(config),
            csp,
        }
    }
}

impl<S> Layer<S> for SecurityHeadersLayer {
    type Service = SecurityHeadersService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SecurityHeadersService {
            inner,
            config: Arc::clone(&self.config),
            csp: self.csp.clone(),
        }
    }
}

/// Tower service produced by [`SecurityHeadersLayer`].
#[derive(Clone)]
pub struct SecurityHeadersService<S> {
    inner: S,
    config: Arc<SecurityConfig>,
    csp: HeaderValue,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for SecurityHeadersService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    S::Future: Send + 'static,
    S::Error: 'static,
    ReqBody: 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let hsts_enabled = self.config.hsts_enabled;
        let coop_coep_enabled = self.config.coop_coep_enabled;
        let csp = self.csp.clone();
        let fut = self.inner.call(req);
        Box::pin(async move {
            let mut resp = fut.await?;
            let headers = resp.headers_mut();
            insert(headers, "x-frame-options", "DENY");
            insert(headers, "x-content-type-options", "nosniff");
            insert(
                headers,
                "referrer-policy",
                "strict-origin-when-cross-origin",
            );
            // Alpine.js removed (HEA-850), Hyperscript removed (HEA-1049):
            // 'unsafe-eval' and 'unsafe-inline' are no longer needed. All
            // interactivity is vanilla JS via data-component attributes backed
            // by components.js. Fonts and scripts are self-hosted (HEA-630).
            //
            // The value is precomputed in `build_csp`; `form-action` carries any
            // dev-only extra origins (HEA-2072) and is byte-identical to
            // `form-action 'self'` in production.
            headers.insert(
                HeaderName::from_static("content-security-policy"),
                csp,
            );
            if hsts_enabled {
                insert(
                    headers,
                    "strict-transport-security",
                    "max-age=31536000; includeSubDomains; preload",
                );
            }
            if coop_coep_enabled {
                // A-40: Cross-origin isolation headers.
                // COOP prevents cross-origin windows from retaining a reference
                // to the opener, blocking cross-site leaks via window.opener.
                insert(headers, "cross-origin-opener-policy", "same-origin");
                // COEP prevents the page from loading cross-origin resources
                // that don't grant explicit permission, enabling SharedArrayBuffer
                // isolation.
                insert(headers, "cross-origin-embedder-policy", "require-corp");
                // Permissions-Policy: disable all powerful/tracking features
                // not required by an IdP UI.
                insert(
                    headers,
                    "permissions-policy",
                    "camera=(), microphone=(), geolocation=(), \
                     payment=(), usb=(), bluetooth=(), \
                     interest-cohort=()",
                );
            }
            // L8: Prevent authenticated HTML pages from being stored in shared or
            // private caches. Applied to HTML only so that static assets (CSS, JS,
            // fonts) remain cacheable; cache-busting for assets is handled by the
            // server-side build pipeline.
            let is_html = headers
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(|ct| ct.starts_with("text/html"))
                .unwrap_or(false);
            if is_html {
                insert(headers, "cache-control", "no-store");
            }
            Ok(resp)
        })
    }
}

fn insert(headers: &mut axum::http::HeaderMap, name: &'static str, value: &'static str) {
    headers.insert(
        HeaderName::from_static(name),
        HeaderValue::from_static(value),
    );
}

/// Builds the `Content-Security-Policy` header value.
///
/// With `extra_form_action_origins` empty (production), the `form-action`
/// directive is exactly `form-action 'self'`, making the whole header
/// byte-identical to the historical static policy. Each extra origin (dev only,
/// HEA-2072) is appended space-separated after `'self'`.
///
/// If any extra origin contains bytes that are invalid in an HTTP header value,
/// the function fails closed to the strict `'self'`-only policy rather than
/// emitting a malformed or attacker-influenced header.
fn build_csp(extra_form_action_origins: &[String]) -> HeaderValue {
    /// Strict policy with `form-action 'self'` only — the production baseline
    /// and the fail-closed fallback.
    const STRICT_CSP: &str = "default-src 'self'; \
         script-src 'self'; \
         style-src 'self'; \
         font-src 'self'; \
         img-src 'self' data:; \
         connect-src 'self'; \
         object-src 'none'; \
         form-action 'self'; \
         frame-ancestors 'none'; \
         base-uri 'self'";

    if extra_form_action_origins.is_empty() {
        return HeaderValue::from_static(STRICT_CSP);
    }

    let mut form_action = String::from("form-action 'self'");
    for origin in extra_form_action_origins {
        form_action.push(' ');
        form_action.push_str(origin);
    }
    let csp = format!(
        "default-src 'self'; \
         script-src 'self'; \
         style-src 'self'; \
         font-src 'self'; \
         img-src 'self' data:; \
         connect-src 'self'; \
         object-src 'none'; \
         {form_action}; \
         frame-ancestors 'none'; \
         base-uri 'self'"
    );
    HeaderValue::from_str(&csp).unwrap_or_else(|_| HeaderValue::from_static(STRICT_CSP))
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::response::IntoResponse;
    use tower::ServiceExt;

    use super::*;

    async fn ok_handler(_req: Request<Body>) -> Result<axum::response::Response, Infallible> {
        Ok(StatusCode::OK.into_response())
    }

    #[tokio::test]
    async fn security_headers_present() {
        let layer = SecurityHeadersLayer::new(SecurityConfig {
            hsts_enabled: false,
            coop_coep_enabled: true,
            extra_form_action_origins: Vec::new(),
        });
        let svc = layer.layer(tower::service_fn(ok_handler));
        let resp = svc
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("service call");

        let headers = resp.headers();
        assert_eq!(headers["x-frame-options"], "DENY");
        assert_eq!(headers["x-content-type-options"], "nosniff");
        assert!(headers.contains_key("content-security-policy"));
        assert!(!headers.contains_key("strict-transport-security"));
    }

    /// HEA-2072: the CSP `form-action` directive must NOT advertise the
    /// plaintext-http localhost demo origins in a production (non-dev) build.
    /// Those origins are only needed by the reference-integration Playwright
    /// suite and must be gated behind dev mode.
    #[tokio::test]
    async fn form_action_is_self_only_in_production() {
        let layer = SecurityHeadersLayer::new(SecurityConfig {
            hsts_enabled: false,
            coop_coep_enabled: true,
            extra_form_action_origins: Vec::new(),
        });
        let svc = layer.layer(tower::service_fn(ok_handler));
        let resp = svc
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("service call");

        let csp = resp.headers()["content-security-policy"]
            .to_str()
            .expect("CSP header must be valid ASCII");
        assert!(
            csp.contains("form-action 'self';"),
            "production CSP must keep form-action 'self', got: {csp}"
        );
        assert!(
            !csp.contains("localhost"),
            "production CSP must not advertise localhost form-action origins, got: {csp}"
        );
    }

    /// HEA-2072: in dev mode the demo SPA origins are appended so the
    /// integration suite can POST to the Vite dev server.
    #[tokio::test]
    async fn form_action_includes_extra_origins_in_dev() {
        let layer = SecurityHeadersLayer::new(SecurityConfig {
            hsts_enabled: false,
            coop_coep_enabled: true,
            extra_form_action_origins: vec![
                "http://localhost:5173".to_string(),
                "http://localhost:5399".to_string(),
            ],
        });
        let svc = layer.layer(tower::service_fn(ok_handler));
        let resp = svc
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("service call");

        let csp = resp.headers()["content-security-policy"]
            .to_str()
            .expect("CSP header must be valid ASCII");
        assert!(
            csp.contains("form-action 'self' http://localhost:5173 http://localhost:5399;"),
            "dev CSP must append the demo origins after 'self', got: {csp}"
        );
    }

    #[tokio::test]
    async fn hsts_emitted_when_tls_enabled() {
        let layer = SecurityHeadersLayer::new(SecurityConfig {
            hsts_enabled: true,
            coop_coep_enabled: false,
            extra_form_action_origins: Vec::new(),
        });
        let svc = layer.layer(tower::service_fn(ok_handler));
        let resp = svc
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("service call");

        let hsts = resp.headers()["strict-transport-security"]
            .to_str()
            .expect("HSTS header must be valid ASCII");
        assert!(hsts.contains("max-age=31536000"), "HSTS missing max-age");
        assert!(
            hsts.contains("includeSubDomains"),
            "HSTS missing includeSubDomains"
        );
        assert!(hsts.contains("preload"), "HSTS missing preload directive");
    }

    // ===== L8: Cache-Control: no-store for HTML responses =====

    async fn html_handler(_req: Request<Body>) -> Result<axum::response::Response, Infallible> {
        Ok((
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
            "<html></html>",
        )
            .into_response())
    }

    async fn css_handler(_req: Request<Body>) -> Result<axum::response::Response, Infallible> {
        Ok((
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "text/css")],
            "body {}",
        )
            .into_response())
    }

    #[tokio::test]
    async fn cache_control_no_store_on_html_responses() {
        let layer = SecurityHeadersLayer::new(SecurityConfig {
            hsts_enabled: false,
            coop_coep_enabled: false,
            extra_form_action_origins: Vec::new(),
        });
        let svc = layer.layer(tower::service_fn(html_handler));
        let resp = svc
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(Body::empty())
                    .expect("req"),
            )
            .await
            .expect("service call");
        assert_eq!(
            resp.headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok()),
            Some("no-store"),
            "HTML responses must carry Cache-Control: no-store"
        );
    }

    #[tokio::test]
    async fn cache_control_no_store_absent_for_non_html() {
        let layer = SecurityHeadersLayer::new(SecurityConfig {
            hsts_enabled: false,
            coop_coep_enabled: false,
            extra_form_action_origins: Vec::new(),
        });
        let svc = layer.layer(tower::service_fn(css_handler));
        let resp = svc
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(Body::empty())
                    .expect("req"),
            )
            .await
            .expect("service call");
        assert!(
            resp.headers().get("cache-control").is_none(),
            "non-HTML responses must not get Cache-Control: no-store"
        );
    }
}
