//! HEA-2024 — Realm token endpoint `/realms/{realm}/token` token-exchange must
//! authenticate the client (F1, RFC 8693 §2.1) and must preserve the DPoP
//! sender-constraint of a `cnf`-bound subject token across the exchange (F2,
//! RFC 9449).
//!
//! F1: the path-realm handler `realm_token_exchange` previously dispatched the
//! `urn:ietf:params:oauth:grant-type:token-exchange` arm with NO client
//! authentication (unlike the header-realm `/token` handler). Any holder of a
//! valid subject token could mint a token with an attacker-controlled
//! `aud`/`resource`/`cnf.jkt`.
//!
//! F2: `rfc8693_token_exchange` validated the subject token without requiring a
//! DPoP proof, then copied the requested `dpop_jkt` verbatim into the new
//! `cnf` — allowing a stolen DPoP-bound token to be re-bound to the attacker's
//! key. The exchange now demands a DPoP proof matching the subject's `cnf.jkt`.

#![allow(clippy::unwrap_used)]

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use hearth::core::RealmId;
use hearth::identity::{
    AuthorizationRequest, ClientTrustLevel, CodeChallengeMethod, CreateRealmRequest,
    CreateUserRequest, IdentityError, RegisterClientRequest, Rfc8693Request, SessionContext,
    TokenExchangeRequest, TokenIssuanceContext,
};
use hearth::protocol::http::{router, AppState};
use tower::ServiceExt as _;

const REDIRECT_URI: &str = "https://agent.example.com/callback";
const PKCE_VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567";
const SUBJECT_JKT: &str = "subject-dpop-thumbprint-xyz";
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

fn pkce_challenge() -> String {
    let hash = ring::digest::digest(&ring::digest::SHA256, PKCE_VERIFIER.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash.as_ref())
}

/// Creates a realm (returning both its name and id), a confidential client, and
/// a user. The realm NAME is what the `/realms/{realm}/token` route resolves.
async fn setup(
    h: &common::TestHarness,
) -> (
    String,
    RealmId,
    String,
    String,
    hearth::core::ClientId,
    hearth::core::UserId,
) {
    let realm_name = format!("hea2024-{}", uuid::Uuid::new_v4());
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: realm_name.clone(),
            config: None,
        })
        .unwrap();

    let secret = "hea2024-client-secret!".to_string();
    let client = h
        .identity()
        .register_client(
            realm.id(),
            &RegisterClientRequest {
                client_name: "hea2024-agent-client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: Some(secret.clone()),
                grant_types: vec![
                    "authorization_code".to_string(),
                    "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
                ],
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
                email: format!("u-{}@hea2024.test", uuid::Uuid::new_v4()),
                display_name: "HEA-2024 User".to_string(),
                first_name: "HEA".to_string(),
                last_name: "User".to_string(),
                attributes: std::collections::BTreeMap::new(),
            },
        )
        .unwrap();

    (
        realm_name,
        realm.id().clone(),
        client.client_id().as_uuid().to_string(),
        secret,
        client.client_id().clone(),
        user.id().clone(),
    )
}

/// Issues a plain (non-sender-constrained) subject access token for `user_id`.
fn make_subject_token(
    h: &common::TestHarness,
    realm_id: &RealmId,
    user_id: &hearth::core::UserId,
) -> String {
    use std::collections::BTreeSet;
    let session = h
        .identity()
        .create_session(realm_id, user_id, &SessionContext::default())
        .expect("create session");
    h.identity()
        .issue_tokens_with_context(
            realm_id,
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

/// Issues a DPoP-bound (`cnf.jkt = SUBJECT_JKT`) subject access token via the
/// authorization-code flow, so the returned token carries a `cnf` claim.
fn make_dpop_bound_subject_token(
    h: &common::TestHarness,
    realm_id: &RealmId,
    user_id: &hearth::core::UserId,
    client_id: &hearth::core::ClientId,
) -> String {
    let auth = h
        .identity()
        .authorize(
            realm_id,
            &AuthorizationRequest {
                client_id: client_id.clone(),
                redirect_uri: REDIRECT_URI.to_string(),
                response_type: "code".to_string(),
                scope: "openid".to_string(),
                state: uuid::Uuid::new_v4().to_string(),
                nonce: None,
                code_challenge: Some(pkce_challenge()),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                resource: None,
                user_id: user_id.clone(),
                amr_values: vec![],
                response_mode: None,
                request: None,
                via_par: false,
            },
        )
        .expect("authorize");

    h.identity()
        .exchange_authorization_code(
            realm_id,
            &TokenExchangeRequest {
                client_id: client_id.clone(),
                code: auth.code().to_string(),
                redirect_uri: REDIRECT_URI.to_string(),
                code_verifier: Some(PKCE_VERIFIER.to_string()),
                dpop_jkt: Some(SUBJECT_JKT.to_string()),
                client_assertion_type: None,
                client_assertion: None,
            },
        )
        .expect("exchange auth code")
        .access_token()
        .to_string()
}

fn exchange_body(client_id: &str, secret: Option<&str>, subject_token: &str) -> serde_json::Value {
    let mut body = serde_json::json!({
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": client_id,
        "subject_token": subject_token,
        "subject_token_type": ACCESS_TOKEN_TYPE,
    });
    if let Some(s) = secret {
        body["client_secret"] = serde_json::Value::String(s.to_string());
    }
    body
}

async fn post_realm_token(
    state: Arc<AppState>,
    realm_name: &str,
    body: &serde_json::Value,
) -> axum::response::Response {
    router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/realms/{realm_name}/token"))
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_string(body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
}

// F1-01: token-exchange on the realm endpoint with NO client credentials → 401.
#[tokio::test]
async fn f1_01_realm_token_exchange_without_client_auth_is_rejected() {
    let h = common::TestHarness::embedded().await.unwrap();
    let (realm_name, realm_id, client_id, _secret, _cid, user_id) = setup(&h).await;
    let subject_token = make_subject_token(&h, &realm_id, &user_id);
    let state = Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()));

    let body = exchange_body(&client_id, None, &subject_token);
    let resp = post_realm_token(state, &realm_name, &body).await;

    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "realm token-exchange without client auth must return 401"
    );
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        json["error"].as_str(),
        Some("invalid_client"),
        "401 must carry the RFC 6749 invalid_client code; got: {json}"
    );
}

// F1-02: token-exchange with a wrong client secret → 401.
#[tokio::test]
async fn f1_02_realm_token_exchange_with_wrong_secret_is_rejected() {
    let h = common::TestHarness::embedded().await.unwrap();
    let (realm_name, realm_id, client_id, _secret, _cid, user_id) = setup(&h).await;
    let subject_token = make_subject_token(&h, &realm_id, &user_id);
    let state = Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()));

    let body = exchange_body(&client_id, Some("wrong-secret"), &subject_token);
    let resp = post_realm_token(state, &realm_name, &body).await;

    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "realm token-exchange with a wrong secret must return 401"
    );
}

// F1-03: correct credentials → 200 and act.sub is the authenticated client.
#[tokio::test]
async fn f1_03_realm_token_exchange_with_correct_credentials_succeeds() {
    let h = common::TestHarness::embedded().await.unwrap();
    let (realm_name, realm_id, client_id, secret, _cid, user_id) = setup(&h).await;
    let subject_token = make_subject_token(&h, &realm_id, &user_id);
    let state = Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()));

    let body = exchange_body(&client_id, Some(&secret), &subject_token);
    let resp = post_realm_token(state, &realm_name, &body).await;

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "realm token-exchange with correct credentials must succeed"
    );
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let access_token = json["access_token"].as_str().expect("access_token present");
    let parts: Vec<&str> = access_token.splitn(3, '.').collect();
    let claims_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("decode claims");
    let claims: serde_json::Value = serde_json::from_slice(&claims_bytes).unwrap();
    assert_eq!(
        claims["act"]["sub"].as_str(),
        Some(client_id.as_str()),
        "act.sub must be the authenticated client_id, not a forged body value"
    );
}

// F2-01: exchanging a cnf-bound subject token with NO DPoP proof is rejected.
#[tokio::test]
async fn f2_01_cnf_bound_subject_without_dpop_is_rejected() {
    let h = common::TestHarness::embedded().await.unwrap();
    let (_realm_name, realm_id, _client_id, _secret, cid, user_id) = setup(&h).await;
    let subject_token = make_dpop_bound_subject_token(&h, &realm_id, &user_id, &cid);

    let request = Rfc8693Request {
        client_id: cid.clone(),
        subject_token,
        subject_token_type: ACCESS_TOKEN_TYPE.to_string(),
        actor_token: None,
        actor_token_type: None,
        requested_token_type: None,
        scope: None,
        resource: None,
        audience: None,
        dpop_jkt: None, // no DPoP proof presented
    };
    let err = h
        .identity()
        .rfc8693_token_exchange(&realm_id, &request)
        .expect_err("cnf-bound subject without a DPoP proof must be rejected");
    assert!(
        matches!(err, IdentityError::TokenExchangeRejected { .. }),
        "expected TokenExchangeRejected, got {err:?}"
    );
}

// F2-02: exchanging a cnf-bound subject token with a WRONG DPoP thumbprint is rejected.
#[tokio::test]
async fn f2_02_cnf_bound_subject_with_wrong_dpop_is_rejected() {
    let h = common::TestHarness::embedded().await.unwrap();
    let (_realm_name, realm_id, _client_id, _secret, cid, user_id) = setup(&h).await;
    let subject_token = make_dpop_bound_subject_token(&h, &realm_id, &user_id, &cid);

    let request = Rfc8693Request {
        client_id: cid.clone(),
        subject_token,
        subject_token_type: ACCESS_TOKEN_TYPE.to_string(),
        actor_token: None,
        actor_token_type: None,
        requested_token_type: None,
        scope: None,
        resource: None,
        audience: None,
        dpop_jkt: Some("attacker-controlled-key".to_string()),
    };
    let err = h
        .identity()
        .rfc8693_token_exchange(&realm_id, &request)
        .expect_err("cnf-bound subject with a mismatched DPoP key must be rejected");
    assert!(
        matches!(err, IdentityError::TokenExchangeRejected { .. }),
        "expected TokenExchangeRejected, got {err:?}"
    );
}

// F2-03: exchanging a cnf-bound subject token with the MATCHING DPoP thumbprint succeeds.
#[tokio::test]
async fn f2_03_cnf_bound_subject_with_matching_dpop_succeeds() {
    let h = common::TestHarness::embedded().await.unwrap();
    let (_realm_name, realm_id, _client_id, _secret, cid, user_id) = setup(&h).await;
    let subject_token = make_dpop_bound_subject_token(&h, &realm_id, &user_id, &cid);

    let request = Rfc8693Request {
        client_id: cid.clone(),
        subject_token,
        subject_token_type: ACCESS_TOKEN_TYPE.to_string(),
        actor_token: None,
        actor_token_type: None,
        requested_token_type: None,
        scope: None,
        resource: None,
        audience: None,
        dpop_jkt: Some(SUBJECT_JKT.to_string()), // matches subject cnf.jkt
    };
    let resp = h
        .identity()
        .rfc8693_token_exchange(&realm_id, &request)
        .expect("matching DPoP proof must allow the exchange");
    // The re-issued token stays bound to the same key.
    let parts: Vec<&str> = resp.access_token.splitn(3, '.').collect();
    let claims_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("decode claims");
    let claims: serde_json::Value = serde_json::from_slice(&claims_bytes).unwrap();
    assert_eq!(
        claims["cnf"]["jkt"].as_str(),
        Some(SUBJECT_JKT),
        "issued token must remain bound to the subject's DPoP key"
    );
}
