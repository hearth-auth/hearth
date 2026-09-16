//! `/docs` must serve Swagger UI from this origin, under a CSP
//! (production-readiness task 21.7, audit §4.23#6).
//!
//! `/docs` is unauthenticated and shares an origin with the admin console. It
//! used to `<script src="https://unpkg.com/swagger-ui-dist@5/...">` with no
//! Subresource Integrity and no CSP, so a hijacked CDN — or anyone who could
//! MITM that fetch — got script execution in the console's origin, where the
//! `hearth_ui_csrf` cookie is readable and the session cookie is attached to
//! every same-origin request.

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use axum::Router;
use hearth::protocol::web::openapi::openapi_router;
use tower::ServiceExt;

fn app() -> Router {
    Router::new().merge(openapi_router::<()>())
}

async fn get(uri: &str) -> (StatusCode, Vec<(String, String)>, String) {
    let resp = app()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .body(Body::empty())
                .expect("test invariant"),
        )
        .await
        .expect("test invariant");
    let status = resp.status();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let bytes = to_bytes(resp.into_body(), 8 << 20)
        .await
        .expect("test invariant");
    (
        status,
        headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// The page must not pull script or style from any third party.
#[tokio::test]
async fn docs_page_loads_no_third_party_assets() {
    let (status, _headers, body) = get("/docs").await;
    assert_eq!(status, StatusCode::OK);
    for host in ["unpkg.com", "jsdelivr", "cdnjs", "googleapis"] {
        assert!(
            !body.contains(host),
            "/docs still references {host}:\n{body}"
        );
    }
    assert!(
        body.contains("/docs/assets/swagger-ui-bundle.js"),
        "/docs must load the same-origin bundle:\n{body}"
    );
}

/// The page must carry a CSP that forbids remote script outright.
#[tokio::test]
async fn docs_page_carries_a_restrictive_csp() {
    let (_status, headers, _body) = get("/docs").await;
    let csp = header_value(&headers, "content-security-policy")
        .expect("/docs must set Content-Security-Policy");
    assert!(
        csp.contains("default-src 'none'"),
        "docs CSP must default-deny: {csp}"
    );
    assert!(
        csp.contains("script-src 'self'") && !csp.contains("script-src 'self' http"),
        "docs CSP must restrict script to this origin: {csp}"
    );
    assert!(
        csp.contains("frame-ancestors 'none'"),
        "docs CSP must forbid framing: {csp}"
    );
}

/// The vendored assets must actually be served, with the right media types.
#[tokio::test]
async fn vendored_swagger_assets_are_served_same_origin() {
    let (status, headers, body) = get("/docs/assets/swagger-ui-bundle.js").await;
    assert_eq!(status, StatusCode::OK, "bundle not served");
    assert!(
        header_value(&headers, "content-type")
            .unwrap_or("")
            .contains("javascript"),
        "bundle served with wrong content-type: {headers:?}"
    );
    assert!(
        body.len() > 500_000,
        "bundle looks truncated: {} bytes",
        body.len()
    );

    let (status, headers, body) = get("/docs/assets/swagger-ui.css").await;
    assert_eq!(status, StatusCode::OK, "stylesheet not served");
    assert!(
        header_value(&headers, "content-type")
            .unwrap_or("")
            .contains("text/css"),
        "stylesheet served with wrong content-type: {headers:?}"
    );
    assert!(
        body.len() > 50_000,
        "stylesheet looks truncated: {} bytes",
        body.len()
    );

    let (status, _headers, body) = get("/docs/assets/init.js").await;
    assert_eq!(status, StatusCode::OK, "bootstrap not served");
    assert!(
        body.contains("SwaggerUIBundle"),
        "bootstrap must call SwaggerUIBundle: {body}"
    );
}

/// Guard against a partial revert: if `header::CONTENT_TYPE` were left off the
/// bundle route, browsers would refuse to execute it and the docs page would
/// silently render blank.
#[tokio::test]
async fn docs_assets_are_cacheable_and_sandboxed() {
    let (_status, headers, _body) = get("/docs/assets/init.js").await;
    assert!(
        header_value(&headers, "cache-control").is_some(),
        "assets should be cacheable: {headers:?}"
    );
    assert!(
        header_value(&headers, "content-security-policy").is_some(),
        "assets should carry their own CSP: {headers:?}"
    );
}
