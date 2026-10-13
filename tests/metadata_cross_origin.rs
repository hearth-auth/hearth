#![allow(clippy::unwrap_used)]
//! Public metadata answers cross-origin reads (OpenSpec change
//! `metadata-cross-origin`).
//!
//! A browser application verifies Hearth's tokens with the TypeScript SDK,
//! which fetches the issuer's discovery document and its `jwks_uri` from the
//! page's own origin. Hearth sent no `Access-Control-Allow-Origin` on those
//! responses, so the browser withheld them from a page on another origin, and
//! every role and permission check reported `false`.
//!
//! The documents are public and read without credentials, so they answer
//! with `Access-Control-Allow-Origin: *` and no
//! `Access-Control-Allow-Credentials`. No other route gets the header.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hearth::identity::CreateRealmRequest;
use hearth::protocol::http::{router, AppState};
use tower::ServiceExt as _;

const REALM: &str = "cors-acme";
const PAGE_ORIGIN: &str = "https://app.example.com";

fn app(h: &common::TestHarness) -> axum::Router {
    router(Arc::new(AppState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
    )))
}

async fn harness() -> common::TestHarness {
    let h = common::TestHarness::in_process().await.expect("harness");
    h.identity()
        .create_realm(&CreateRealmRequest {
            name: REALM.to_string(),
            config: None,
        })
        .expect("create realm");
    h
}

/// A cross-origin `GET` of `path`, as a browser page on `PAGE_ORIGIN` sends
/// it. Returns the status and the two CORS response headers.
async fn cross_origin_get(
    app: &axum::Router,
    path: &str,
) -> (StatusCode, Option<String>, Option<String>) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(path)
                .header("origin", PAGE_ORIGIN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let header = |name: &str| {
        resp.headers()
            .get(name)
            .map(|v| v.to_str().unwrap().to_string())
    };
    (
        resp.status(),
        header("access-control-allow-origin"),
        header("access-control-allow-credentials"),
    )
}

#[tokio::test]
async fn every_metadata_document_answers_a_cross_origin_read() {
    let h = harness().await;
    let app = app(&h);
    for path in [
        "/.well-known/openid-configuration".to_string(),
        format!("/realms/{REALM}/.well-known/openid-configuration"),
        "/.well-known/jwks.json".to_string(),
        "/jwks".to_string(),
        "/certs".to_string(),
        format!("/realms/{REALM}/.well-known/jwks.json"),
        "/.well-known/oauth-protected-resource".to_string(),
    ] {
        let (status, allow_origin, allow_credentials) = cross_origin_get(&app, &path).await;
        assert_eq!(
            allow_origin.as_deref(),
            Some("*"),
            "GET {path} ({status}) must allow any origin"
        );
        assert_eq!(
            allow_credentials, None,
            "GET {path} must not allow credentials"
        );
    }
}

/// The realm documents the SDK reads must also be served (200), not only
/// carry the header.
#[tokio::test]
async fn the_realm_documents_the_sdk_reads_are_served() {
    let h = harness().await;
    let app = app(&h);
    for path in [
        format!("/realms/{REALM}/.well-known/openid-configuration"),
        format!("/realms/{REALM}/.well-known/jwks.json"),
    ] {
        let (status, allow_origin, _) = cross_origin_get(&app, &path).await;
        assert_eq!(status, StatusCode::OK, "GET {path}");
        assert_eq!(allow_origin.as_deref(), Some("*"), "GET {path}");
    }
}

/// An unknown realm's error is readable too, so the page can report it.
#[tokio::test]
async fn an_unknown_realms_error_is_readable() {
    let h = harness().await;
    let app = app(&h);
    let (status, allow_origin, _) =
        cross_origin_get(&app, "/realms/no-such-realm/.well-known/jwks.json").await;
    assert!(status.is_client_error(), "got {status}");
    assert_eq!(allow_origin.as_deref(), Some("*"));
}

/// Endpoints that take a credential stay closed to other origins.
#[tokio::test]
async fn a_credentialed_endpoint_gets_no_wildcard() {
    let h = harness().await;
    let app = app(&h);
    for path in ["/userinfo".to_string(), format!("/realms/{REALM}/userinfo")] {
        let (status, allow_origin, _) = cross_origin_get(&app, &path).await;
        assert_eq!(
            allow_origin, None,
            "GET {path} ({status}) must not allow other origins"
        );
    }
}
