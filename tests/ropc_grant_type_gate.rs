#![allow(clippy::unwrap_used)]
//! Integration tests for per-client ROPC (password grant) gating (HEA-1671).
//!
//! Verifies that the `password` grant type is blocked at the HTTP layer when
//! the client's registered `grant_types` do not include `"password"`. This
//! closes OAUTH-01: an attacker that guesses a client_id previously could use
//! any client for ROPC even if it was not intended for that grant type.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, PasswordGrantRequest,
    RegisterClientRequest,
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

// ===== ROPC-G1: client without password grant is rejected (OAUTH-01 fix) =====

/// A client registered with only `authorization_code` must not be usable for
/// the ROPC (`password`) grant type. The token endpoint must return 400
/// `unauthorized_client` before performing any credential check.
#[tokio::test]
async fn ropc_rejected_when_client_not_registered_for_password_grant() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("ropc-gate-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");
    let realm_id = realm.id().clone();
    let realm_id_str = realm_id.as_uuid().to_string();

    let client = h
        .identity()
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "AuthCode Only".to_string(),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: true,
                ..Default::default()
            },
        )
        .expect("register client");

    let user = h
        .identity()
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "ropc-user@example.com".to_string(),
                display_name: "ROPC Test".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    h.identity()
        .set_password(
            &realm_id,
            user.id(),
            &CleartextPassword::from_string("HearthRopc123!".to_string()),
        )
        .expect("set password");

    let app = build_app(&h).await;

    let body = serde_json::to_string(&serde_json::json!({
        "grant_type": "password",
        "client_id": client.client_id().as_uuid().to_string(),
        "username": "ropc-user@example.com",
        "password": "HearthRopc123!"
    }))
    .unwrap();

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("X-Realm-ID", &realm_id_str)
                .header("Content-Type", "application/json")
                .body(Body::from(body))
                .expect("req"),
        )
        .await
        .expect("resp");

    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "ROPC must be rejected for a client not registered for the password grant"
    );

    let body_bytes = to_bytes(resp.into_body(), 1024 * 1024).await.expect("body");
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).expect("json");
    assert_eq!(
        body["error"].as_str().unwrap_or(""),
        "unauthorized_client",
        "error must be `unauthorized_client`, got: {body}"
    );
}

// ===== ROPC-G2: client with password grant succeeds (positive path) =====

/// A client explicitly registered with `grant_types: ["password"]` must
/// succeed with ROPC. This is the regression-positive counterpart.
#[tokio::test]
async fn ropc_succeeds_when_client_registered_for_password_grant() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("ropc-ok-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");
    let realm_id = realm.id().clone();
    let realm_id_str = realm_id.as_uuid().to_string();

    let client = h
        .identity()
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "ROPC Client".to_string(),
                redirect_uris: vec!["https://ropc.example.com/cb".to_string()],
                client_secret: None,
                grant_types: vec!["password".to_string()],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("register client");

    let user = h
        .identity()
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "ropc-ok@example.com".to_string(),
                display_name: "ROPC OK".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    h.identity()
        .set_password(
            &realm_id,
            user.id(),
            &CleartextPassword::from_string("HearthRopcOk123!".to_string()),
        )
        .expect("set password");

    // Verify via engine directly to confirm credentials are valid.
    let _ = tokio::task::spawn_blocking({
        let identity = h.identity_arc();
        let realm_id = realm_id.clone();
        move || {
            identity.password_grant_token(
                &realm_id,
                &PasswordGrantRequest {
                    email: "ropc-ok@example.com".to_string(),
                    password: "HearthRopcOk123!".to_string(),
                    scope: None,
                    client_ip: None,
                    user_agent: None,
                },
            )
        }
    })
    .await
    .expect("spawn_blocking")
    .expect("engine-level password_grant must succeed");

    let app = build_app(&h).await;

    let body = serde_json::to_string(&serde_json::json!({
        "grant_type": "password",
        "client_id": client.client_id().as_uuid().to_string(),
        "username": "ropc-ok@example.com",
        "password": "HearthRopcOk123!"
    }))
    .unwrap();

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("X-Realm-ID", &realm_id_str)
                .header("Content-Type", "application/json")
                .body(Body::from(body))
                .expect("req"),
        )
        .await
        .expect("resp");

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "ROPC must succeed for a client registered for the password grant"
    );

    let body_bytes = to_bytes(resp.into_body(), 1024 * 1024).await.expect("body");
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).expect("json");
    assert!(
        body["access_token"].as_str().is_some_and(|s| !s.is_empty()),
        "response must include access_token: {body}"
    );
}
