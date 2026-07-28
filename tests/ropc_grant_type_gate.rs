#![allow(clippy::unwrap_used)]
//! Integration tests for ROPC (`password` grant) removal at the HTTP layer
//! (HEA-1862, superseding the per-client gate of HEA-1671).
//!
//! HEA-1671 originally gated the `password` grant per client: a client whose
//! registered `grant_types` omitted `"password"` got `unauthorized_client`,
//! while a client that opted in could still mint tokens from a raw
//! username/password. That opt-in path bypassed interactive and step-up MFA,
//! so HEA-1862 removed the grant from both token endpoints outright.
//!
//! These tests assert the stronger property that replaced the gate: the
//! `password` grant is refused with `unsupported_grant_type` for **every**
//! client, including one explicitly registered for it, and the refusal happens
//! before any credential check (so it leaks no user-existence or
//! password-validity signal).

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, RegisterClientRequest,
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

/// Fixture: a realm with one user (known-good password) and one client whose
/// registered `grant_types` are exactly `grant_types`.
struct Fixture {
    realm_id_str: String,
    client_id: String,
    email: String,
    password: String,
}

async fn fixture(h: &common::TestHarness, label: &str, grant_types: &[&str]) -> Fixture {
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("ropc-{label}-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");
    let realm_id = realm.id().clone();

    let client = h
        .identity()
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: format!("ROPC {label}"),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                client_secret: None,
                grant_types: grant_types.iter().map(|g| (*g).to_string()).collect(),
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("register client");

    let email = format!("ropc-{label}@example.com");
    let password = "HearthRopc123!".to_string();
    let user = h
        .identity()
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: email.clone(),
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
            &CleartextPassword::from_string(password.clone()),
        )
        .expect("set password");

    Fixture {
        realm_id_str: realm_id.as_uuid().to_string(),
        client_id: client.client_id().as_uuid().to_string(),
        email,
        password,
    }
}

/// POST a `grant_type=password` request to `/token` and return
/// (status, parsed JSON body).
async fn post_ropc(
    app: axum::Router,
    f: &Fixture,
    password: &str,
) -> (StatusCode, serde_json::Value) {
    let body = serde_json::to_string(&serde_json::json!({
        "grant_type": "password",
        "client_id": f.client_id,
        "username": f.email,
        "password": password,
    }))
    .unwrap();

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("X-Realm-ID", &f.realm_id_str)
                .header("Content-Type", "application/json")
                .body(Body::from(body))
                .expect("req"),
        )
        .await
        .expect("resp");

    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.expect("body");
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    (status, json)
}

// ===== ROPC-G1: client without the password grant is rejected =====

/// A client registered with only `authorization_code` must not be usable for
/// the `password` grant. Post-HEA-1862 the endpoint no longer reaches the
/// per-client check at all, so the refusal is `unsupported_grant_type`.
#[tokio::test]
async fn ropc_rejected_when_client_not_registered_for_password_grant() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let f = fixture(&h, "gate", &["authorization_code"]).await;

    let (status, body) = post_ropc(build_app(&h).await, &f, &f.password).await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "ROPC must be rejected for a client not registered for the password grant"
    );
    assert_eq!(
        body["error"].as_str().unwrap_or(""),
        "unsupported_grant_type",
        "error must be `unsupported_grant_type`, got: {body}"
    );
    assert!(
        body["access_token"].is_null(),
        "no token may be issued: {body}"
    );
}

// ===== ROPC-G2: even an opted-in client is rejected (HEA-1862) =====

/// The HEA-1671 positive path is gone. A client explicitly registered with
/// `grant_types: ["password"]`, sending a **correct** username and password,
/// must still be refused — the grant no longer exists on the endpoint, so
/// opting in cannot resurrect the MFA bypass.
#[tokio::test]
async fn ropc_rejected_even_when_client_registered_for_password_grant() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let f = fixture(&h, "optin", &["password"]).await;

    let (status, body) = post_ropc(build_app(&h).await, &f, &f.password).await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "ROPC must be refused even for a client registered for the password grant"
    );
    assert_eq!(
        body["error"].as_str().unwrap_or(""),
        "unsupported_grant_type",
        "error must be `unsupported_grant_type`, got: {body}"
    );
    assert!(
        body["access_token"].is_null(),
        "credentials were valid, so a token here would be an MFA bypass: {body}"
    );
}

// ===== ROPC-G3: refusal precedes any credential check =====

/// The refusal must not depend on the supplied password. A correct and an
/// incorrect password must produce byte-identical responses, proving the
/// handler rejects on grant type alone and exposes no user-enumeration or
/// password-validity oracle.
#[tokio::test]
async fn ropc_refusal_is_identical_for_valid_and_invalid_passwords() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let f = fixture(&h, "oracle", &["password"]).await;

    let (good_status, good_body) = post_ropc(build_app(&h).await, &f, &f.password).await;
    let invalid_password = format!("invalid-for-{}", f.username);
    let (bad_status, bad_body) =
        post_ropc(build_app(&h).await, &f, invalid_password.as_str()).await;

    assert_eq!(
        good_status,
        StatusCode::BAD_REQUEST,
        "valid-password ROPC must be refused"
    );
    assert_eq!(
        good_status, bad_status,
        "status must not vary with password validity"
    );
    assert_eq!(
        good_body, bad_body,
        "response body must not vary with password validity: {good_body} vs {bad_body}"
    );
    assert_eq!(
        good_body["error"].as_str().unwrap_or(""),
        "unsupported_grant_type",
        "error must be `unsupported_grant_type`, got: {good_body}"
    );
}
