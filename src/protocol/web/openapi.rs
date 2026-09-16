//! OpenAPI spec serving (HEA-972).
//!
//! Serves the committed spec artifacts at:
//! - `GET /openapi.json` — merged OpenAPI 3.0 JSON
//! - `GET /openapi.yaml` — supplement-only OpenAPI 3.0 YAML (hand-written routes)
//! - `GET /docs` — Swagger UI (loads spec from `/openapi.json`)
//!
//! Both specs are embedded at compile time via `include_str!` so the binary
//! serves them without any runtime file I/O.  The merged JSON is produced by
//! `make openapi` (runs `scripts/merge_openapi.py`); the supplement YAML is
//! hand-maintained and covers routes that have no proto service definition.
//!
//! # Drift gate
//! `tests/openapi.rs` contains a parity gate that verifies every expected
//! Axum route appears in the merged spec.  Run it with `cargo nextest run
//! --test openapi`.

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;

/// Merged OpenAPI 3.0 JSON spec (proto-derived + supplement).
///
/// Produced by `make openapi` (`scripts/merge_openapi.py`) and committed at
/// `docs/api/openapi.json`.  Embedded at compile time so the binary has no
/// runtime file dependency.
pub const MERGED_SPEC_JSON: &str = include_str!("../../../docs/api/openapi.json");

/// Hand-written OpenAPI 3.0 YAML supplement covering proto-less routes.
///
/// Committed at `docs/api/openapi.supplement.yaml`.
pub const SUPPLEMENT_SPEC: &str = include_str!("../../../docs/api/openapi.supplement.yaml");

/// Vendored Swagger UI stylesheet (`swagger-ui-dist@5.17.14`).
///
/// Vendored at `vendor/swagger-ui-5.17.14/` rather than pulled from a CDN
/// (task 21.7, audit §4.23#6). `/docs` is unauthenticated and shares an origin
/// with the admin console, so a compromised or hijacked CDN — or anyone able to
/// MITM the `unpkg.com` fetch — could run script in that origin. Same-origin
/// assets also mean the strict [`DOCS_CSP`] can forbid every remote source
/// outright rather than allowlisting a third party.
const SWAGGER_UI_CSS: &str = include_str!("../../../vendor/swagger-ui-5.17.14/swagger-ui.css");

/// Vendored Swagger UI bundle (`swagger-ui-dist@5.17.14`, ~1.5 MB).
///
/// The `StandaloneLayout` preset (a further ~350 KB) is deliberately NOT
/// vendored — it only adds the URL-explorer topbar, which is noise for a
/// single-spec deployment.
const SWAGGER_UI_BUNDLE_JS: &str =
    include_str!("../../../vendor/swagger-ui-5.17.14/swagger-ui-bundle.js");

/// Swagger UI bootstrap. Served as its own file rather than inlined so the
/// page needs no `'unsafe-inline'` and no per-response nonce: plain
/// `script-src 'self'` covers it.
const SWAGGER_INIT_JS: &str = r##"window.addEventListener("load", function () {
  SwaggerUIBundle({
    url: "/openapi.json",
    dom_id: "#swagger-ui",
    deepLinking: true,
    presets: [SwaggerUIBundle.presets.apis],
  });
});
"##;

/// Content-Security-Policy for `/docs` and its assets.
///
/// The API router carries no CSP of its own (only `minimal_security_headers`),
/// so before task 21.7 this unauthenticated page had none at all. Swagger UI
/// injects `<style>` elements at runtime, hence `style-src 'unsafe-inline'`;
/// its icons are inline SVG data URIs, hence `img-src data:`. Everything else
/// is locked to this origin, and `form-action 'none'` plus `base-uri 'none'`
/// remove the two escape hatches that would let injected markup exfiltrate.
const DOCS_CSP: &str = "default-src 'none'; \
     script-src 'self'; \
     style-src 'self' 'unsafe-inline'; \
     img-src 'self' data:; \
     font-src 'self' data:; \
     connect-src 'self'; \
     object-src 'none'; \
     base-uri 'none'; \
     form-action 'none'; \
     frame-ancestors 'none'";

/// Swagger UI HTML page. All sub-resources are same-origin.
const SWAGGER_UI_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Hearth API Docs</title>
  <link rel="stylesheet" href="/docs/assets/swagger-ui.css" />
</head>
<body>
<div id="swagger-ui"></div>
<script src="/docs/assets/swagger-ui-bundle.js"></script>
<script src="/docs/assets/init.js"></script>
</body>
</html>
"#;

/// Returns a router for `/openapi.json`, `/openapi.yaml`, `/docs`, and the
/// same-origin Swagger UI assets under `/docs/assets/`.
///
/// Mount at the root (no prefix) so all paths are at the top level.
pub fn openapi_router<S: Clone + Send + Sync + 'static>() -> Router<S> {
    Router::new()
        .route("/openapi.json", axum::routing::get(serve_openapi_json))
        .route("/openapi.yaml", axum::routing::get(serve_openapi_yaml))
        .route("/docs", axum::routing::get(serve_swagger_ui))
        .route(
            "/docs/assets/swagger-ui.css",
            axum::routing::get(serve_swagger_css),
        )
        .route(
            "/docs/assets/swagger-ui-bundle.js",
            axum::routing::get(serve_swagger_bundle),
        )
        .route(
            "/docs/assets/init.js",
            axum::routing::get(serve_swagger_init),
        )
}

/// Builds a cacheable asset response carrying the docs CSP.
fn asset_response(content_type: &'static str, body: &'static str) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "public, max-age=86400"),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; sandbox",
            ),
        ],
        body,
    )
        .into_response()
}

/// `GET /docs/assets/swagger-ui.css`
async fn serve_swagger_css() -> Response {
    asset_response("text/css; charset=utf-8", SWAGGER_UI_CSS)
}

/// `GET /docs/assets/swagger-ui-bundle.js`
async fn serve_swagger_bundle() -> Response {
    asset_response("text/javascript; charset=utf-8", SWAGGER_UI_BUNDLE_JS)
}

/// `GET /docs/assets/init.js`
async fn serve_swagger_init() -> Response {
    asset_response("text/javascript; charset=utf-8", SWAGGER_INIT_JS)
}

/// `GET /openapi.json` — merged OpenAPI 3.0 spec as JSON.
async fn serve_openapi_json() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
        MERGED_SPEC_JSON,
    )
        .into_response()
}

/// `GET /openapi.yaml` — supplement-only OpenAPI 3.0 spec as YAML.
async fn serve_openapi_yaml() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/yaml; charset=utf-8")],
        SUPPLEMENT_SPEC,
    )
        .into_response()
}

/// `GET /docs` — Swagger UI explorer.
async fn serve_swagger_ui() -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CONTENT_SECURITY_POLICY, DOCS_CSP),
        ],
        SWAGGER_UI_HTML,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merged_spec_json_is_non_empty() {
        #[allow(clippy::const_is_empty)]
        let non_empty = !MERGED_SPEC_JSON.is_empty();
        assert!(non_empty, "MERGED_SPEC_JSON must not be empty");
    }

    #[test]
    fn merged_spec_json_starts_with_openapi_key() {
        assert!(
            MERGED_SPEC_JSON.contains("\"openapi\""),
            "MERGED_SPEC_JSON must contain 'openapi' key"
        );
    }

    /// Task 21.7 / audit §4.23#6: `/docs` is unauthenticated and shares the
    /// admin console's origin, so it must not load script or style from a
    /// third-party CDN. Nothing in the page may reference a remote host.
    #[test]
    fn swagger_ui_page_has_no_remote_sub_resources() {
        for needle in ["unpkg.com", "cdn.jsdelivr.net", "cdnjs", "//"] {
            let offending = SWAGGER_UI_HTML
                .lines()
                .find(|l| l.contains(needle) && (l.contains("src=") || l.contains("href=")));
            assert!(
                offending.is_none(),
                "Swagger UI page still references a remote sub-resource ({needle}): {offending:?}"
            );
        }
        assert!(
            SWAGGER_UI_HTML.contains("/docs/assets/swagger-ui.css"),
            "page must load the vendored stylesheet"
        );
        assert!(
            SWAGGER_UI_HTML.contains("/docs/assets/swagger-ui-bundle.js"),
            "page must load the vendored bundle"
        );
    }

    /// The bootstrap must live in its own file, so `script-src 'self'` is
    /// enough and the page needs neither `'unsafe-inline'` nor a nonce.
    #[test]
    fn swagger_ui_page_has_no_inline_script_body() {
        for line in SWAGGER_UI_HTML.lines() {
            if let Some(rest) = line.split_once("<script") {
                assert!(
                    rest.1.contains("src="),
                    "inline <script> body in the docs page would require \
                     'unsafe-inline' in DOCS_CSP: {line}"
                );
            }
        }
    }

    /// The docs CSP must actually be restrictive, not a placeholder.
    #[test]
    fn docs_csp_locks_the_page_down() {
        for directive in [
            "default-src 'none'",
            "script-src 'self'",
            "object-src 'none'",
            "base-uri 'none'",
            "form-action 'none'",
            "frame-ancestors 'none'",
        ] {
            assert!(
                DOCS_CSP.contains(directive),
                "DOCS_CSP is missing `{directive}`: {DOCS_CSP}"
            );
        }
        assert!(
            !DOCS_CSP.contains("script-src 'self' 'unsafe-inline'"),
            "script-src must not allow inline script: {DOCS_CSP}"
        );
    }

    /// The vendored assets must actually be present and be the real thing.
    #[test]
    fn vendored_swagger_assets_are_embedded() {
        assert!(
            SWAGGER_UI_BUNDLE_JS.len() > 500_000,
            "vendored swagger-ui-bundle.js looks truncated: {} bytes",
            SWAGGER_UI_BUNDLE_JS.len()
        );
        assert!(
            SWAGGER_UI_CSS.len() > 50_000,
            "vendored swagger-ui.css looks truncated: {} bytes",
            SWAGGER_UI_CSS.len()
        );
        assert!(
            SWAGGER_INIT_JS.contains("SwaggerUIBundle"),
            "bootstrap must call SwaggerUIBundle"
        );
    }

    #[test]
    fn supplement_spec_is_non_empty() {
        #[allow(clippy::const_is_empty)]
        let non_empty = !SUPPLEMENT_SPEC.is_empty();
        assert!(non_empty, "SUPPLEMENT_SPEC must not be empty");
    }
}
