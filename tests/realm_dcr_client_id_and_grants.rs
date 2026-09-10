//! §4.22#9 (task 22.17) — realm-scoped Dynamic Client Registration.
//!
//! `POST /realms/{realm}/register` had two defects the global `POST /register`
//! endpoint does not share:
//!
//! 1. It rendered `client_id` with the [`hearth::core::ClientId`] `Display`
//!    impl, which prefixes the UUID (`client_<uuid>`). Every token-endpoint arm
//!    parses `client_id` with `uuid::Uuid::parse_str`, so the id handed back by
//!    registration could never authenticate — the client was born unusable.
//! 2. It hard-coded `grant_types` to `["authorization_code"]`, silently
//!    discarding whatever the RFC 7591 request asked for.

#![allow(clippy::unwrap_used)]

mod common;

use std::str::FromStr as _;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::core::{ClientId, RealmId};
use hearth::identity::{
    AuthorizationRequest, CodeChallengeMethod, CreateRealmRequest, CreateUserRequest, DcrPolicy,
    RealmConfig,
};
use hearth::protocol::http::{router, AppState};
use tower::ServiceExt as _;

const REDIRECT_URI: &str = "https://app.example.com/cb";

struct Realm {
    state: Arc<AppState>,
    name: String,
}

async fn open_dcr_realm(h: &common::TestHarness) -> (Realm, RealmId) {
    let name = format!("dcr-{}", uuid::Uuid::new_v4());
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: name.clone(),
            config: Some(RealmConfig {
                dcr_policy: Some(DcrPolicy::Open),
                ..Default::default()
            }),
        })
        .unwrap();
    let realm_id = realm.id().clone();
    let state = Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()));
    (Realm { state, name }, realm_id)
}

async fn register(realm: &Realm, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
    let resp = router(Arc::clone(&realm.state))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/realms/{}/register", realm.name))
                .header("Content-Type", "application/json")
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

/// A registration is only useful if the `client_id` it returns is the exact
/// string the token endpoint accepts. This asserts the parse rule directly and
/// then proves it end-to-end with a real authorization-code exchange against
/// the same realm's token endpoint.
#[tokio::test]
async fn realm_dcr_client_id_is_accepted_by_the_token_endpoint() {
    let h = common::TestHarness::embedded().await.unwrap();
    let (realm, realm_id) = open_dcr_realm(&h).await;

    let (status, body) = register(
        &realm,
        serde_json::json!({
            "client_name": "Parseable App",
            "redirect_uris": [REDIRECT_URI],
            "grant_types": ["authorization_code"],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "registration failed: {body}");

    let client_id = body["client_id"].as_str().expect("client_id").to_string();
    assert!(
        uuid::Uuid::parse_str(&client_id).is_ok(),
        "the token endpoint parses client_id as a bare UUID, but registration \
         returned {client_id:?}"
    );

    // End-to-end: mint a code for this client and redeem it at the realm's
    // token endpoint using the *returned* client_id string verbatim.
    let user = h
        .identity()
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: format!("u-{}@dcr.test", uuid::Uuid::new_v4()),
                display_name: "DCR User".to_string(),
                first_name: "D".to_string(),
                last_name: "U".to_string(),
                attributes: std::collections::BTreeMap::new(),
            },
        )
        .unwrap()
        .id()
        .clone();

    let verifier = "dcr-verifier-abcdefghijklmnopqrstuvwxyz-0123456789".to_string();
    let digest = ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes());
    let challenge = {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.as_ref())
    };

    let domain_client_id = ClientId::from_str(&client_id).expect("client_id is a ClientId");
    let code = h
        .identity()
        .authorize(
            &realm_id,
            &AuthorizationRequest {
                client_id: domain_client_id,
                redirect_uri: REDIRECT_URI.to_string(),
                scope: "openid".to_string(),
                state: "st".to_string(),
                response_type: "code".to_string(),
                user_id: user,
                code_challenge: Some(challenge),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: None,
                resource: None,
                amr_values: Vec::new(),
                response_mode: None,
                request: None,
                via_par: false,
            },
        )
        .expect("authorize")
        .code()
        .to_string();

    let resp = router(Arc::clone(&realm.state))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/realms/{}/token", realm.name))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "grant_type": "authorization_code",
                        "client_id": client_id,
                        "code": code,
                        "redirect_uri": REDIRECT_URI,
                        "code_verifier": verifier,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let token: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
    assert_eq!(
        status,
        StatusCode::OK,
        "token endpoint rejected the registered client_id: {token}"
    );
    assert!(token["access_token"]
        .as_str()
        .is_some_and(|s| !s.is_empty()));
}

/// RFC 7591 §2 — the registered `grant_types` must reflect what was asked for.
/// The handler used to overwrite the request with `["authorization_code"]`.
#[tokio::test]
async fn realm_dcr_honours_requested_grant_types() {
    let h = common::TestHarness::embedded().await.unwrap();
    let (realm, _realm_id) = open_dcr_realm(&h).await;

    let (status, body) = register(
        &realm,
        serde_json::json!({
            "client_name": "Refreshing App",
            "redirect_uris": [REDIRECT_URI],
            "grant_types": ["authorization_code", "refresh_token"],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "registration failed: {body}");

    let granted: Vec<String> = body["grant_types"]
        .as_array()
        .expect("grant_types")
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    assert!(
        granted.contains(&"refresh_token".to_string()),
        "requested refresh_token was silently dropped: {granted:?}"
    );
    assert!(granted.contains(&"authorization_code".to_string()));
}

/// A grant type the deployment does not support must be refused outright —
/// RFC 7591 §3.2.2 `invalid_client_metadata` — rather than silently narrowed
/// to something the caller did not ask for.
#[tokio::test]
async fn realm_dcr_rejects_an_unsupported_grant_type() {
    let h = common::TestHarness::embedded().await.unwrap();
    let (realm, _realm_id) = open_dcr_realm(&h).await;

    let (status, body) = register(
        &realm,
        serde_json::json!({
            "client_name": "Legacy App",
            "redirect_uris": [REDIRECT_URI],
            "grant_types": ["authorization_code", "password"],
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "unsupported grant_type must be refused, got {status}: {body}"
    );
    assert_eq!(body["error"].as_str(), Some("invalid_client_metadata"));
}

/// Omitting `grant_types` keeps the RFC 7591 §2 default of
/// `["authorization_code"]`.
#[tokio::test]
async fn realm_dcr_defaults_to_authorization_code_when_unspecified() {
    let h = common::TestHarness::embedded().await.unwrap();
    let (realm, _realm_id) = open_dcr_realm(&h).await;

    let (status, body) = register(
        &realm,
        serde_json::json!({
            "client_name": "Default App",
            "redirect_uris": [REDIRECT_URI],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "registration failed: {body}");
    assert_eq!(
        body["grant_types"],
        serde_json::json!(["authorization_code"])
    );
}
