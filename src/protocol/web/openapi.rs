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

/// Swagger UI HTML page (loads spec from `/openapi.json` via CDN assets).
const SWAGGER_UI_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Hearth API Docs</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
</head>
<body>
<div id="swagger-ui"></div>
<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>
  SwaggerUIBundle({
    url: "/openapi.json",
    dom_id: "#swagger-ui",
    deepLinking: true,
    presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
    layout: "StandaloneLayout"
  });
</script>
</body>
</html>
"##;

/// Returns a router for `/openapi.json`, `/openapi.yaml`, and `/docs`.
///
/// Mount at the root (no prefix) so all three paths are at the top level.
pub fn openapi_router<S: Clone + Send + Sync + 'static>() -> Router<S> {
    Router::new()
        .route("/openapi.json", axum::routing::get(serve_openapi_json))
        .route("/openapi.yaml", axum::routing::get(serve_openapi_yaml))
        .route("/docs", axum::routing::get(serve_swagger_ui))
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
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        SWAGGER_UI_HTML,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merged_spec_json_is_non_empty() {
        assert!(
            !MERGED_SPEC_JSON.is_empty(),
            "MERGED_SPEC_JSON must not be empty"
        );
    }

    #[test]
    fn merged_spec_json_starts_with_openapi_key() {
        assert!(
            MERGED_SPEC_JSON.contains("\"openapi\""),
            "MERGED_SPEC_JSON must contain 'openapi' key"
        );
    }

    #[test]
    fn supplement_spec_is_non_empty() {
        assert!(
            !SUPPLEMENT_SPEC.is_empty(),
            "SUPPLEMENT_SPEC must not be empty"
        );
    }
}
