//! §4.22#5 (task 22.14) — `client_credentials` must read `client_secret_basic`.
//!
//! Discovery advertises `client_secret_basic` in
//! `token_endpoint_auth_methods_supported` and Dynamic Client Registration
//! hands every client `"token_endpoint_auth_method": "client_secret_basic"`.
//! A client that follows those instructions puts its credentials in the
//! `Authorization: Basic` header and nothing in the body — but the
//! `client_credentials` grant arm built its request out of `body.client_id` and
//! `body.client_secret` alone, so the secret arrived empty and the exchange
//! failed with `invalid_client_secret`.
//!
//! Both the global `/token` and the realm-scoped `/realms/{realm}/token`
//! endpoints carry the arm, so both are covered here.

#![allow(clippy::unwrap_used)]

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use hearth::core::RealmId;
use hearth::identity::{CreateRealmRequest, RegisterClientRequest};
use hearth::protocol::http::{router, AppState};
use tower::ServiceExt as _;

const SECRET: &str = "cc-basic-secret-value";

struct Fixture {
    state: Arc<AppState>,
    realm_id_str: String,
    realm_name: String,
    client_id: String,
}

async fn fixture() -> Fixture {
    let h = common::TestHarness::embedded().await.unwrap();
    let realm_name = format!("ccbasic-{}", uuid::Uuid::new_v4());
    let realm: RealmId = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: realm_name.clone(),
            config: None,
        })
        .unwrap()
        .id()
        .clone();
    let client = h
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: format!("ccbasic-{}", uuid::Uuid::new_v4()),
                redirect_uris: Vec::new(),
                client_secret: Some(SECRET.to_string()),
                grant_types: vec!["client_credentials".to_string()],
                require_consent: false,
                // A machine-to-machine client. First-party so the exchange does
                // not additionally require an explicit `scope` (third-party
                // clients must request at least one).
                trust_level: hearth::identity::ClientTrustLevel::FirstParty,
                ..Default::default()
            },
        )
        .unwrap();

    Fixture {
        state: Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc())),
        realm_id_str: realm.as_uuid().to_string(),
        realm_name,
        client_id: client.client_id().as_uuid().to_string(),
    }
}

fn basic_header(user: &str, password: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
    )
}

async fn post_token(
    f: &Fixture,
    path: &str,
    authorization: Option<&str>,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header("X-Realm-ID", &f.realm_id_str)
        .header("Content-Type", "application/json");
    if let Some(auth) = authorization {
        builder = builder.header("Authorization", auth);
    }
    let resp = router(Arc::clone(&f.state))
        .oneshot(
            builder
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

/// The headline case: credentials in the `Authorization: Basic` header only,
/// exactly as discovery and DCR instruct.
#[tokio::test]
async fn client_credentials_authenticates_with_basic_header_only() {
    let f = fixture().await;
    let (status, body) = post_token(
        &f,
        "/token",
        Some(&basic_header(&f.client_id, SECRET)),
        serde_json::json!({"grant_type": "client_credentials"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "basic-only exchange failed: {body}");
    assert!(body["access_token"].as_str().is_some_and(|s| !s.is_empty()));
}

/// Same, on the realm-scoped token endpoint — the arm is duplicated there.
#[tokio::test]
async fn client_credentials_basic_header_only_on_realm_path() {
    let f = fixture().await;
    let path = format!("/realms/{}/token", f.realm_name);
    let (status, body) = post_token(
        &f,
        &path,
        Some(&basic_header(&f.client_id, SECRET)),
        serde_json::json!({"grant_type": "client_credentials"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "basic-only exchange failed: {body}");
    assert!(body["access_token"].as_str().is_some_and(|s| !s.is_empty()));
}

/// A Basic header carrying the client id but the wrong secret must still fail
/// — the header must be *read*, not merely tolerated.
#[tokio::test]
async fn client_credentials_basic_header_with_wrong_secret_is_rejected() {
    let f = fixture().await;
    let (status, _) = post_token(
        &f,
        "/token",
        Some(&basic_header(&f.client_id, "not-the-secret")),
        serde_json::json!({"grant_type": "client_credentials"}),
    )
    .await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a wrong Basic secret must not mint a token"
    );
}

/// RFC 6749 §2.3.1 forbids more than one client authentication mechanism per
/// request; a Basic secret that disagrees with a body secret is a bad request,
/// not a silently-resolved preference.
#[tokio::test]
async fn client_credentials_basic_and_body_disagreement_is_rejected() {
    let f = fixture().await;
    let (status, body) = post_token(
        &f,
        "/token",
        Some(&basic_header(&f.client_id, SECRET)),
        serde_json::json!({
            "grant_type": "client_credentials",
            "client_id": f.client_id,
            "client_secret": "a-different-secret",
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "expected rejection: {body}"
    );
    assert_eq!(body["error"].as_str(), Some("invalid_request"));
}

/// Fence: the historical body-only (`client_secret_post`) form keeps working.
#[tokio::test]
async fn client_credentials_body_credentials_still_work() {
    let f = fixture().await;
    let (status, body) = post_token(
        &f,
        "/token",
        None,
        serde_json::json!({
            "grant_type": "client_credentials",
            "client_id": f.client_id,
            "client_secret": SECRET,
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "body-credential exchange failed: {body}"
    );
    assert!(body["access_token"].as_str().is_some_and(|s| !s.is_empty()));
}
