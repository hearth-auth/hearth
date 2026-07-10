//! M2 — Token-exchange grant requires client authentication (RFC 8693 §2.1).
//!
//! Tests that the `urn:ietf:params:oauth:grant-type:token-exchange` grant at the
//! HTTP layer rejects requests that do not authenticate the client, and that the
//! `act.sub` claim in the issued token derives from the authenticated client
//! identity rather than the unauthenticated body `client_id`.

#![allow(clippy::unwrap_used)]

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use hearth::core::RealmId;
use hearth::identity::{
    ClientTrustLevel, CreateRealmRequest, CreateUserRequest, RegisterClientRequest, SessionContext,
    TokenIssuanceContext,
};
use hearth::protocol::http::{router, AppState};
use tower::ServiceExt as _;

async fn setup_realm_and_client(
    h: &common::TestHarness,
) -> (String, String, String, hearth::core::UserId) {
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("m2-test-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .unwrap();

    let secret = "m2-client-secret-xyz!".to_string();
    let client = h
        .identity()
        .register_client(
            realm.id(),
            &RegisterClientRequest {
                client_name: "m2-agent-client".to_string(),
                redirect_uris: vec!["https://agent.example.com/callback".to_string()],
                client_secret: Some(secret.clone()),
                grant_types: vec!["urn:ietf:params:oauth:grant-type:token-exchange".to_string()],
                require_consent: false,
                trust_level: ClientTrustLevel::FirstParty,
                ..Default::default()
            },
        )
        .unwrap();

    let user = h
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("u-{}@m2.test", uuid::Uuid::new_v4()),
                display_name: "M2 Test User".to_string(),
                first_name: "M2".to_string(),
                last_name: "User".to_string(),
                attributes: std::collections::BTreeMap::new(),
            },
        )
        .unwrap();

    (
        realm.id().as_uuid().to_string(),
        client.client_id().as_uuid().to_string(),
        secret,
        user.id().clone(),
    )
}

/// Issues a subject token (real Ed25519-signed access token) for the given user.
fn make_subject_token(
    h: &common::TestHarness,
    realm_id_str: &str,
    user_id: &hearth::core::UserId,
) -> String {
    use std::collections::BTreeSet;
    let realm_id = RealmId::new(uuid::Uuid::parse_str(realm_id_str).expect("parse realm uuid"));
    let session = h
        .identity()
        .create_session(&realm_id, user_id, &SessionContext::default())
        .expect("create session");
    h.identity()
        .issue_tokens_with_context(
            &realm_id,
            user_id,
            session.id(),
            &TokenIssuanceContext {
                client_id: None,
                granted_scopes: BTreeSet::from(["openid".to_string()]),
                oid: None,
                resource: None,
            },
        )
        .expect("issue subject token")
        .access_token()
        .to_string()
}

// M2-01: Token exchange without any client credentials → 401 invalid_client.
#[tokio::test]
async fn m2_01_token_exchange_without_client_auth_is_rejected() {
    let h = common::TestHarness::embedded().await.unwrap();
    let (realm_id, client_id, _secret, user_id) = setup_realm_and_client(&h).await;
    let subject_token = make_subject_token(&h, &realm_id, &user_id);

    let state = Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()));

    // No client_secret supplied.
    let body = serde_json::json!({
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": &client_id,
        "subject_token": &subject_token,
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token"
    });

    let resp = router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("X-Realm-ID", &realm_id)
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "token-exchange without client auth must return 401"
    );

    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        json["error"].as_str().is_some(),
        "401 response must include an error field; got: {json}"
    );
}

// M2-02: Token exchange with wrong client secret → 401.
#[tokio::test]
async fn m2_02_token_exchange_with_wrong_secret_is_rejected() {
    let h = common::TestHarness::embedded().await.unwrap();
    let (realm_id, client_id, _correct_secret, user_id) = setup_realm_and_client(&h).await;
    let subject_token = make_subject_token(&h, &realm_id, &user_id);

    let state = Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()));

    let body = serde_json::json!({
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": &client_id,
        "client_secret": "wrong-secret-value",
        "subject_token": &subject_token,
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token"
    });

    let resp = router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("X-Realm-ID", &realm_id)
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "token-exchange with wrong client secret must return 401"
    );
}

// M2-03: Token exchange with correct credentials → 200, act.sub is the authenticated client.
#[tokio::test]
async fn m2_03_token_exchange_with_correct_credentials_succeeds() {
    let h = common::TestHarness::embedded().await.unwrap();
    let (realm_id, client_id, secret, user_id) = setup_realm_and_client(&h).await;
    let subject_token = make_subject_token(&h, &realm_id, &user_id);

    let state = Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()));

    let body = serde_json::json!({
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": &client_id,
        "client_secret": &secret,
        "subject_token": &subject_token,
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token"
    });

    let resp = router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("X-Realm-ID", &realm_id)
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "token-exchange with correct credentials must succeed"
    );

    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    let access_token = json["access_token"]
        .as_str()
        .expect("access_token must be present");

    // Decode the issued token and verify act.sub is the authenticated client.
    let parts: Vec<&str> = access_token.splitn(3, '.').collect();
    assert_eq!(parts.len(), 3);
    let claims_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("decode claims");
    let claims: serde_json::Value = serde_json::from_slice(&claims_bytes).expect("parse claims");

    // act.sub must match the authenticated client_id UUID string.
    let act_sub = claims["act"]["sub"]
        .as_str()
        .expect("act.sub must be present in issued token");
    assert_eq!(
        act_sub, &client_id,
        "act.sub must be the authenticated client_id, not a forged body value"
    );
}

// M2-04: Token exchange via HTTP Basic Auth also works correctly.
#[tokio::test]
async fn m2_04_token_exchange_via_basic_auth_succeeds() {
    let h = common::TestHarness::embedded().await.unwrap();
    let (realm_id, client_id, secret, user_id) = setup_realm_and_client(&h).await;
    let subject_token = make_subject_token(&h, &realm_id, &user_id);

    let state = Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()));

    let credentials = format!("{client_id}:{secret}");
    let basic_auth = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(&credentials)
    );

    let body = serde_json::json!({
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": &client_id,
        "subject_token": &subject_token,
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token"
    });

    let resp = router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("X-Realm-ID", &realm_id)
                .header("Content-Type", "application/json")
                .header("Authorization", &basic_auth)
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "token-exchange with HTTP Basic Auth must succeed"
    );
}
