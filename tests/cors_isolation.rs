#![allow(clippy::unwrap_used)]
//! Integration tests for CORS isolation: HEA-SEC-06.
//!
//! Verifies that:
//! 1. An origin matching only a redirect_uri (not listed in cors_origins) receives
//!    no CORS headers from the token endpoint — redirect URIs must not implicitly
//!    grant cross-origin token access.
//! 2. The token endpoint never emits `Access-Control-Allow-Credentials: true` —
//!    PKCE flows use authorization codes, not cookies.
//! 3. An origin listed in cors_origins does receive `Access-Control-Allow-Origin`.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hearth::identity::{
    CreateRealmRequest, DcrPolicy, RealmConfig, RegisterClientRequest, UpdateClientRequest,
};
use hearth::protocol::http::{router, AppState};
use tower::ServiceExt as _;

async fn build_app(harness: &common::TestHarness) -> axum::Router {
    let state = Arc::new(AppState::new(
        harness.identity_arc(),
        harness.rbac_arc(),
        harness.audit_arc(),
    ));
    router(state)
}

fn open_dcr_realm_config() -> RealmConfig {
    RealmConfig {
        dcr_policy: Some(DcrPolicy::Open),
        ..Default::default()
    }
}

// ===== Test 1: redirect_uri origin does NOT get CORS headers =====
//
// Register a client with redirect_uri https://app.example.com/callback but
// NO cors_origins. A POST token request from https://app.example.com must NOT
// receive Access-Control-Allow-Origin in the response.
//
// HEA-SEC-28: OPTIONS preflights now echo any origin uniformly (closing the
// CORS-oracle leak). The real security boundary is the POST /token response —
// only origins in cors_origins are reflected there.

#[tokio::test]
async fn cors_redirect_uri_origin_gets_no_cors_headers() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "cors-iso-1".to_string(),
            config: Some(open_dcr_realm_config()),
        })
        .expect("create realm");
    let realm_id = realm.id().as_uuid().to_string();

    // Register a client with a redirect_uri but NO cors_origins.
    let client = h
        .identity()
        .register_client(
            realm.id(),
            &RegisterClientRequest {
                client_name: "No-CORS App".to_string(),
                redirect_uris: vec!["https://app.example.com/callback".to_string()],
                client_secret: Some("no-cors-secret-123!".to_string()),
                grant_types: vec!["client_credentials".to_string()],
                // cors_origins deliberately left empty (default)
                ..Default::default()
            },
        )
        .expect("register client");

    let app = build_app(&h).await;

    // POST token request from the redirect_uri base origin.
    let body = serde_json::json!({
        "grant_type": "client_credentials",
        "client_id": client.client_id().as_uuid().to_string(),
        "client_secret": "no-cors-secret-123!",
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("X-Realm-ID", &realm_id)
                .header("Content-Type", "application/json")
                .header("Origin", "https://app.example.com")
                .body(Body::from(serde_json::to_vec(&body).expect("serialize")))
                .expect("build request"),
        )
        .await
        .expect("response");

    // Must NOT reflect the origin — redirect_uri base must not grant CORS access.
    let headers = resp.headers();
    assert!(
        headers.get("access-control-allow-origin").is_none(),
        "redirect_uri origin must not appear in Access-Control-Allow-Origin on POST response"
    );
    assert!(
        headers.get("access-control-allow-credentials").is_none(),
        "Allow-Credentials must never appear on token endpoint"
    );
}

// ===== Test 2: cors_origins entry DOES get CORS header, still no Allow-Credentials =====
//
// Register a client with an explicit cors_origins entry. The preflight should
// be allowed (Access-Control-Allow-Origin echoed back), but Allow-Credentials
// must remain absent.

#[tokio::test]
async fn cors_explicit_origin_allowed_without_credentials_header() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "cors-iso-2".to_string(),
            config: Some(open_dcr_realm_config()),
        })
        .expect("create realm");
    let realm_id = realm.id().as_uuid().to_string();

    let client = h
        .identity()
        .register_client(
            realm.id(),
            &RegisterClientRequest {
                client_name: "CORS App".to_string(),
                redirect_uris: vec!["https://app.example.com/callback".to_string()],
                cors_origins: vec!["https://spa.example.com".to_string()],
                ..Default::default()
            },
        )
        .expect("register client");

    // Explicitly set cors_origins via update_client to double-check the path.
    h.identity()
        .update_client(
            realm.id(),
            client.client_id(),
            &UpdateClientRequest {
                cors_origins: Some(vec!["https://spa.example.com".to_string()]),
                ..Default::default()
            },
        )
        .expect("update client");

    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/token")
                .header("X-Realm-ID", &realm_id)
                .header("Origin", "https://spa.example.com")
                .header("Access-Control-Request-Method", "POST")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let headers = resp.headers();
    assert_eq!(
        headers
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("https://spa.example.com"),
        "cors_origins entry must be reflected in Access-Control-Allow-Origin"
    );
    assert!(
        headers.get("access-control-allow-credentials").is_none(),
        "Allow-Credentials must never appear on token endpoint even for allowed origins"
    );
}

// ===== Test 3: redirect_uri-only origin gets no CORS on actual token POST =====
//
// A POST to /token with Origin matching only a redirect_uri (not cors_origins)
// must not get Access-Control-Allow-Origin or Allow-Credentials in the response.

#[tokio::test]
async fn cors_token_post_redirect_uri_origin_gets_no_cors_headers() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "cors-iso-3".to_string(),
            config: Some(open_dcr_realm_config()),
        })
        .expect("create realm");
    let realm_id = realm.id().as_uuid().to_string();

    h.identity()
        .register_client(
            realm.id(),
            &RegisterClientRequest {
                client_name: "Token POST Test".to_string(),
                redirect_uris: vec!["https://app.example.com/callback".to_string()],
                // No cors_origins
                ..Default::default()
            },
        )
        .expect("register client");

    let app = build_app(&h).await;

    // POST /token with Origin that matches redirect_uri base origin only.
    // The request will fail with 400/401 (no valid grant), but we only care
    // that the RESPONSE HEADERS do not include CORS headers.
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("X-Realm-ID", &realm_id)
                .header("Origin", "https://app.example.com")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(Body::from("grant_type=authorization_code&code=fake"))
                .expect("build request"),
        )
        .await
        .expect("response");

    let headers = resp.headers();
    assert!(
        headers.get("access-control-allow-origin").is_none(),
        "token POST: redirect_uri origin must not get ACAO header"
    );
    assert!(
        headers.get("access-control-allow-credentials").is_none(),
        "token POST: Allow-Credentials must never appear"
    );
}
