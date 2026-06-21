//! RFC 8707 Resource Indicators for OAuth 2.0 — conformance fixtures.
//!
//! Validates `aud` claim binding from `tests/fixtures/rfc8707/conformance_vectors.json`.
//!
//! Coverage:
//! - RES-01: resource indicator → `aud` contains both base audience and resource URI
//! - RES-02: absent resource indicator → `aud` is a single base-audience string
//! - RES-03: resource indicator preserved across token refresh rotation
//!
//! Spec refs: RFC 8707 §2
//! Test vectors: tests/fixtures/rfc8707/conformance_vectors.json

#![allow(clippy::unwrap_used)]

mod common;

use hearth::core::RealmId;
use hearth::identity::{
    tokens::{decode_claims_unverified, Audience},
    AuthorizationRequest, CodeChallengeMethod, CreateRealmRequest, CreateUserRequest,
    IdentityEngine, OAuthClient, RegisterClientRequest, TokenExchangeRequest,
};
use serde_json::Value;

const VECTORS: &str = include_str!("fixtures/rfc8707/conformance_vectors.json");
const PKCE_VERIFIER: &str = "Rfc8707ConformanceVerifier1234567890abcdef";

fn pkce_challenge(verifier: &str) -> String {
    use data_encoding::BASE64URL_NOPAD;
    BASE64URL_NOPAD
        .encode(ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes()).as_ref())
}

fn make_realm(identity: &dyn IdentityEngine) -> RealmId {
    identity
        .create_realm(&CreateRealmRequest {
            name: format!("rfc8707-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone()
}

fn make_client(identity: &dyn IdentityEngine, realm_id: &RealmId) -> OAuthClient {
    identity
        .register_client(
            realm_id,
            &RegisterClientRequest {
                client_name: "RFC8707 Test Client".to_string(),
                redirect_uris: vec!["https://app.example.com/callback".to_string()],
                client_secret: None,
                grant_types: vec![
                    "authorization_code".to_string(),
                    "refresh_token".to_string(),
                ],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("register client")
}

fn authorize_and_exchange(
    identity: &dyn IdentityEngine,
    realm_id: &RealmId,
    user_id: &hearth::core::UserId,
    client: &OAuthClient,
    resource: Option<&str>,
) -> hearth::identity::OidcTokenResponse {
    let auth = identity
        .authorize(
            realm_id,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                scope: "openid".to_string(),
                state: "csrf".to_string(),
                response_type: "code".to_string(),
                user_id: user_id.clone(),
                code_challenge: Some(pkce_challenge(PKCE_VERIFIER)),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: None,
                resource: resource.map(str::to_string),
                amr_values: Vec::new(),
                response_mode: None,
                request: None,
                via_par: false,
            },
        )
        .expect("authorize");

    identity
        .exchange_authorization_code(
            realm_id,
            &TokenExchangeRequest {
                client_id: client.client_id().clone(),
                code: auth.code().to_string(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                code_verifier: Some(PKCE_VERIFIER.to_string()),
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
            },
        )
        .expect("exchange code")
}

// ── Fixture structure test ────────────────────────────────────────────────────

/// Fixture JSON parses correctly and contains the expected vector IDs.
#[test]
fn fixture_parses_and_has_all_vectors() {
    let doc: Value = serde_json::from_str(VECTORS).expect("parse rfc8707 fixture JSON");
    let vectors = doc["aud_binding_vectors"]
        .as_array()
        .expect("aud_binding_vectors");

    let ids: Vec<&str> = vectors.iter().map(|v| v["id"].as_str().unwrap()).collect();

    for expected in &["RES-01", "RES-02", "RES-03"] {
        assert!(
            ids.contains(expected),
            "fixture must contain vector {expected}"
        );
    }
}

// ── RES-01: resource → Multi aud ─────────────────────────────────────────────

/// RES-01: token with resource indicator carries Multi aud [base, resource_uri].
#[tokio::test]
async fn res01_resource_indicator_produces_multi_aud() {
    let doc: Value = serde_json::from_str(VECTORS).expect("parse fixture");
    let v = &doc["aud_binding_vectors"][0]; // RES-01
    assert_eq!(v["id"].as_str().unwrap(), "RES-01");

    let resource_uri = v["input"]["resource"].as_str().unwrap();

    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = identity
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: format!("u-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "RFC8707 User".to_string(),
                ..Default::default()
            },
        )
        .expect("create user")
        .id()
        .clone();
    let client = make_client(identity, &realm_id);

    let tokens = authorize_and_exchange(identity, &realm_id, &user_id, &client, Some(resource_uri));
    let claims = decode_claims_unverified(tokens.access_token()).expect("decode access token");

    assert!(
        matches!(&claims.aud, Audience::Multi(list) if list.len() == 2),
        "RES-01: aud must be Multi with 2 entries when resource indicator is present; got {:?}",
        claims.aud
    );

    let aud_list = match &claims.aud {
        Audience::Multi(list) => list.clone(),
        _ => unreachable!(),
    };

    // Fixture lists which URIs must be present.
    let must_contain: Vec<&str> = v["expected_aud_contains"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap())
        .collect();

    for uri in must_contain {
        assert!(
            aud_list.iter().any(|a| a == uri),
            "RES-01: aud must contain '{uri}'; actual aud: {aud_list:?}"
        );
    }
}

// ── RES-02: no resource → Single aud ─────────────────────────────────────────

/// RES-02: token without resource indicator carries Single aud = base string.
#[tokio::test]
async fn res02_no_resource_produces_single_aud() {
    let doc: Value = serde_json::from_str(VECTORS).expect("parse fixture");
    let v = &doc["aud_binding_vectors"][1]; // RES-02
    assert_eq!(v["id"].as_str().unwrap(), "RES-02");
    assert_eq!(v["expected_aud_type"].as_str().unwrap(), "single");

    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = identity
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: format!("u-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "RFC8707 User".to_string(),
                ..Default::default()
            },
        )
        .expect("create user")
        .id()
        .clone();
    let client = make_client(identity, &realm_id);

    let tokens = authorize_and_exchange(identity, &realm_id, &user_id, &client, None);
    let claims = decode_claims_unverified(tokens.access_token()).expect("decode access token");

    assert!(
        matches!(&claims.aud, Audience::Single(s) if !s.is_empty()),
        "RES-02: aud must be Single when no resource indicator is provided; got {:?}",
        claims.aud
    );
}

// ── RES-03: resource preserved through refresh ────────────────────────────────

/// RES-03: resource indicator in the aud claim survives token refresh rotation.
#[tokio::test]
async fn res03_resource_aud_preserved_through_refresh() {
    let doc: Value = serde_json::from_str(VECTORS).expect("parse fixture");
    let v = &doc["aud_binding_vectors"][2]; // RES-03
    assert_eq!(v["id"].as_str().unwrap(), "RES-03");
    assert!(
        v["verify_after_refresh"].as_bool().unwrap_or(false),
        "RES-03 fixture must set verify_after_refresh: true"
    );

    let resource_uri = v["input"]["resource"].as_str().unwrap();

    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm_id = make_realm(identity);
    let user_id = identity
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: format!("u-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "RFC8707 User".to_string(),
                ..Default::default()
            },
        )
        .expect("create user")
        .id()
        .clone();
    let client = make_client(identity, &realm_id);

    let tokens = authorize_and_exchange(identity, &realm_id, &user_id, &client, Some(resource_uri));

    // Rotate: get a new access token via refresh.
    let refreshed = identity
        .refresh_tokens(&realm_id, tokens.refresh_token(), None, None)
        .expect("refresh_tokens");

    let claims = decode_claims_unverified(refreshed.access_token()).expect("decode refreshed");

    assert!(
        matches!(&claims.aud, Audience::Multi(list) if list.len() == 2),
        "RES-03: refreshed access token aud must remain Multi; got {:?}",
        claims.aud
    );

    let aud_list = match &claims.aud {
        Audience::Multi(list) => list.clone(),
        _ => unreachable!(),
    };

    let must_contain: Vec<&str> = v["expected_aud_contains"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap())
        .collect();

    for uri in must_contain {
        assert!(
            aud_list.iter().any(|a| a == uri),
            "RES-03: refreshed aud must still contain '{uri}'; actual: {aud_list:?}"
        );
    }
}
