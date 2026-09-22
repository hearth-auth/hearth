//! Tower middleware that appends security response headers to every UI response.
//!
//! Headers applied:
//! - `Content-Security-Policy` — restricts script/style/connect sources.
//! - `X-Frame-Options: DENY` — prevents clickjacking.
//! - `X-Content-Type-Options: nosniff` — blocks MIME-type sniffing.
//! - `Referrer-Policy: strict-origin-when-cross-origin`
//! - `Strict-Transport-Security` — when Hearth serves TLS, or when a trusted
//!   proxy attests `X-Forwarded-Proto: https` (21.9).
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
    /// Emit HSTS header unconditionally (set when Hearth itself is serving TLS).
    pub hsts_enabled: bool,
    /// Emit HSTS on a plaintext request that a trusted proxy has attested
    /// arrived over HTTPS (`X-Forwarded-Proto: https`).
    ///
    /// Set from `server.trust_forwarded_proto`, which production validation
    /// only accepts alongside a non-empty `server.trusted_proxies` — so when
    /// this is `true` the forwarded value came through a proxy the operator
    /// named. When it is `false` the header is ignored entirely, and no client
    /// can talk Hearth into pinning a domain to HTTPS it cannot serve.
    ///
    /// Without this, the modal deployment — TLS terminated at nginx/Envoy/an
    /// ALB, plaintext on the hop to Hearth — never emitted HSTS at all, while
    /// `docs/guides/security-hardening.md` told the operator it was automatic
    /// (audit 2026-08-28 §4.23#8, §4.5 critic objection).
    pub hsts_on_forwarded_proto: bool,
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
        // Decide HSTS before the request is consumed. `hsts_enabled` covers
        // Hearth-terminated TLS; the forwarded-proto arm covers the modal
        // proxy-terminated deployment, and is only consulted when the operator
        // configured a trusted proxy (21.9 / §4.23#8).
        let hsts_enabled = self.config.hsts_enabled
            || (self.config.hsts_on_forwarded_proto && forwarded_proto_is_https(req.headers()));
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
            //
            // Inserted only when the handler did not set its own (task 21.8).
            // The blanket `script-src 'self'; form-action 'self'` policy breaks
            // Hearth's own SAML HTTP-POST binding, which has to run an
            // auto-submit script and POST to the peer's ACS URL. That handler
            // builds a strictly narrower per-response policy — a nonce for the
            // one script, and the one destination origin for `form-action` —
            // and an unconditional `insert` here would stomp it.
            let csp_name = HeaderName::from_static("content-security-policy");
            if !headers.contains_key(&csp_name) {
                headers.insert(csp_name, csp);
            }
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

/// Returns `true` when the request carries `X-Forwarded-Proto: https`.
///
/// Callers MUST gate this on [`SecurityConfig::hsts_on_forwarded_proto`], which
/// is only set when the operator configured a trusted proxy. A comma-separated
/// value (proxy chain) is read left-to-right, RFC 7239 style: the first element
/// is the scheme the original client used.
fn forwarded_proto_is_https(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("https"))
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
            hsts_on_forwarded_proto: false,
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
            hsts_on_forwarded_proto: false,
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
            hsts_on_forwarded_proto: false,
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

    /// HEA-2084: a custom port configured via `security.dev_csp_form_action_origins`
    /// must appear in the dev-mode CSP but never in production.
    #[tokio::test]
    async fn form_action_custom_port_reaches_dev_csp() {
        let custom = vec!["http://localhost:3000".to_string()];

        // In dev mode the custom origin is emitted.
        let dev_layer = SecurityHeadersLayer::new(SecurityConfig {
            hsts_enabled: false,
            hsts_on_forwarded_proto: false,
            coop_coep_enabled: false,
            extra_form_action_origins: custom.clone(),
        });
        let dev_resp = dev_layer
            .layer(tower::service_fn(ok_handler))
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("service call");
        let dev_csp = dev_resp.headers()["content-security-policy"]
            .to_str()
            .expect("CSP header must be valid ASCII");
        assert!(
            dev_csp.contains("form-action 'self' http://localhost:3000;"),
            "dev CSP must include the custom port, got: {dev_csp}"
        );

        // In production (empty extra_form_action_origins) the custom origin is not emitted.
        let prod_layer = SecurityHeadersLayer::new(SecurityConfig {
            hsts_enabled: false,
            hsts_on_forwarded_proto: false,
            coop_coep_enabled: false,
            extra_form_action_origins: Vec::new(),
        });
        let prod_resp = prod_layer
            .layer(tower::service_fn(ok_handler))
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("service call");
        let prod_csp = prod_resp.headers()["content-security-policy"]
            .to_str()
            .expect("CSP header must be valid ASCII");
        assert!(
            !prod_csp.contains("localhost"),
            "production CSP must not contain any localhost origin, got: {prod_csp}"
        );
    }

    #[tokio::test]
    async fn hsts_emitted_when_tls_enabled() {
        let layer = SecurityHeadersLayer::new(SecurityConfig {
            hsts_enabled: true,
            hsts_on_forwarded_proto: false,
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

    // ===== 21.9 (audit §4.23#8): HSTS behind a TLS-terminating proxy =====

    /// Runs one request through the layer and reports whether HSTS was set.
    async fn hsts_present(hsts_on_forwarded_proto: bool, forwarded_proto: Option<&str>) -> bool {
        let layer = SecurityHeadersLayer::new(SecurityConfig {
            hsts_enabled: false,
            hsts_on_forwarded_proto,
            coop_coep_enabled: false,
            extra_form_action_origins: Vec::new(),
        });
        let svc = layer.layer(tower::service_fn(ok_handler));
        let mut builder = Request::builder().uri("/");
        if let Some(proto) = forwarded_proto {
            builder = builder.header("x-forwarded-proto", proto);
        }
        let resp = svc
            .oneshot(builder.body(Body::empty()).expect("build request"))
            .await
            .expect("service call");
        resp.headers().contains_key("strict-transport-security")
    }

    /// The modal production deployment: TLS terminates at nginx/Envoy/an ALB
    /// and Hearth itself serves plaintext, so `hsts_enabled` is false. Before
    /// 21.9 that meant HSTS was never emitted anywhere, while the hardening
    /// guide told the operator it was automatic "when TLS is enabled".
    #[tokio::test]
    async fn hsts_emitted_behind_a_trusted_tls_terminating_proxy() {
        assert!(
            hsts_present(true, Some("https")).await,
            "a trusted proxy attesting https must produce HSTS"
        );
    }

    /// A proxy chain reports the original client's scheme first.
    #[tokio::test]
    async fn hsts_reads_the_first_element_of_a_forwarded_proto_chain() {
        assert!(hsts_present(true, Some("https, http")).await);
        assert!(!hsts_present(true, Some("http, https")).await);
    }

    /// A plaintext hop that the proxy itself reports as plaintext must not
    /// pin the domain to HTTPS.
    #[tokio::test]
    async fn hsts_not_emitted_when_the_trusted_proxy_reports_http() {
        assert!(!hsts_present(true, Some("http")).await);
        assert!(!hsts_present(true, None).await);
    }

    /// Without `server.trust_forwarded_proto` (and therefore without a
    /// configured `server.trusted_proxies`) the header is attacker-settable,
    /// so it must not be able to pin a domain to HTTPS it cannot serve.
    #[tokio::test]
    async fn forwarded_proto_cannot_force_hsts_when_no_proxy_is_trusted() {
        assert!(
            !hsts_present(false, Some("https")).await,
            "X-Forwarded-Proto must be ignored when no proxy is trusted"
        );
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
            hsts_on_forwarded_proto: false,
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
            hsts_on_forwarded_proto: false,
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
