//! M1 — Refresh token DPoP sender constraint (RFC 9449 §5).
//!
//! Verifies that when a DPoP proof is presented at authorization-code exchange,
//! the issued refresh token carries `cnf.jkt`, the grant family records the bound
//! thumbprint, and subsequent refreshes enforce the binding:
//!   - Wrong JKT  → `DPopBindingMismatch`
//!   - Missing JKT → `DPopBindingMismatch`
//!   - Correct JKT → success, and the rotated refresh token also carries `cnf.jkt`
//!
//! Also verifies backward compatibility: an exchange without DPoP still allows
//! refresh without any JKT.

#![allow(clippy::unwrap_used)]

mod common;

use base64::Engine as _;
use hearth::core::{ClientId, RealmId};
use hearth::identity::{
    AuthorizationRequest, CodeChallengeMethod, CreateRealmRequest, CreateUserRequest,
    IdentityError, RegisterClientRequest, TokenExchangeRequest,
};

const REDIRECT_URI: &str = "https://example.com/callback";
const PKCE_VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567";
const DPOP_JKT: &str = "thumbprint_abc123";

fn pkce_challenge() -> String {
    let hash = ring::digest::digest(&ring::digest::SHA256, PKCE_VERIFIER.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash.as_ref())
}

fn decode_claims_json(token: &str) -> serde_json::Value {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    assert_eq!(parts.len(), 3, "token must be a 3-part JWT");
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("base64-decode claims");
    serde_json::from_slice(&payload).expect("parse claims JSON")
}

async fn setup() -> (common::TestHarness, RealmId, hearth::core::UserId, ClientId) {
    let h = common::TestHarness::embedded().await.expect("harness");

    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("m1-dpop-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();

    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("u-{}@dpop.test", uuid::Uuid::new_v4()),
                display_name: "DPoP Test User".to_string(),
                first_name: "DPoP".to_string(),
                last_name: "User".to_string(),
                attributes: std::collections::BTreeMap::new(),
            },
        )
        .expect("create user");

    let client = h
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "dpop-refresh-test".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: None,
                grant_types: vec![
                    "authorization_code".to_string(),
                    "refresh_token".to_string(),
                ],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("register client");

    (h, realm, user.id().clone(), client.client_id().clone())
}

fn exchange_code(
    h: &common::TestHarness,
    realm: &RealmId,
    user_id: &hearth::core::UserId,
    client_id: &ClientId,
    dpop_jkt: Option<String>,
) -> hearth::identity::OidcTokenResponse {
    let auth = h
        .identity()
        .authorize(
            realm,
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
            realm,
            &TokenExchangeRequest {
                client_id: client_id.clone(),
                code: auth.code().to_string(),
                redirect_uri: REDIRECT_URI.to_string(),
                code_verifier: Some(PKCE_VERIFIER.to_string()),
                dpop_jkt,
                client_assertion_type: None,
                client_assertion: None,
            },
        )
        .expect("exchange auth code")
}

// M1-01: DPoP-bound exchange → refresh token carries cnf.jkt.
#[tokio::test]
async fn m1_01_refresh_token_carries_cnf_jkt_when_bound() {
    let (h, realm, user_id, client_id) = setup().await;

    let tokens = exchange_code(&h, &realm, &user_id, &client_id, Some(DPOP_JKT.to_string()));

    let refresh_claims = decode_claims_json(tokens.refresh_token());
    assert_eq!(
        refresh_claims["cnf"]["jkt"].as_str(),
        Some(DPOP_JKT),
        "refresh token must carry cnf.jkt matching the DPoP thumbprint used at exchange"
    );
}

// M1-02: Refresh with the correct JKT succeeds; rotated refresh also carries cnf.jkt.
#[tokio::test]
async fn m1_02_refresh_with_correct_jkt_succeeds_and_rotates_binding() {
    let (h, realm, user_id, client_id) = setup().await;

    let tokens = exchange_code(&h, &realm, &user_id, &client_id, Some(DPOP_JKT.to_string()));

    let refreshed = h
        .identity()
        .refresh_tokens(&realm, tokens.refresh_token(), Some(DPOP_JKT), None)
        .expect("refresh with matching JKT must succeed");

    let refresh_claims = decode_claims_json(refreshed.refresh_token());
    assert_eq!(
        refresh_claims["cnf"]["jkt"].as_str(),
        Some(DPOP_JKT),
        "rotated refresh token must still carry cnf.jkt"
    );
}

// M1-03: Refresh with a different JKT on a bound family → DPopBindingMismatch.
#[tokio::test]
async fn m1_03_refresh_with_wrong_jkt_is_rejected() {
    let (h, realm, user_id, client_id) = setup().await;

    let tokens = exchange_code(&h, &realm, &user_id, &client_id, Some(DPOP_JKT.to_string()));

    let err = h
        .identity()
        .refresh_tokens(
            &realm,
            tokens.refresh_token(),
            Some("attacker_key_thumbprint"),
            None,
        )
        .expect_err("refresh with mismatched JKT must fail");

    assert!(
        matches!(err, IdentityError::DPopBindingMismatch),
        "expected DPopBindingMismatch for mismatched JKT, got: {err:?}"
    );
}

// M1-04: Refresh without any JKT on a bound family → DPopBindingMismatch.
#[tokio::test]
async fn m1_04_refresh_without_jkt_rejected_on_bound_family() {
    let (h, realm, user_id, client_id) = setup().await;

    let tokens = exchange_code(&h, &realm, &user_id, &client_id, Some(DPOP_JKT.to_string()));

    let err = h
        .identity()
        .refresh_tokens(&realm, tokens.refresh_token(), None, None)
        .expect_err("refresh without JKT on bound family must fail");

    assert!(
        matches!(err, IdentityError::DPopBindingMismatch),
        "expected DPopBindingMismatch when no JKT presented on bound family, got: {err:?}"
    );
}

// M1-05: Non-DPoP exchange leaves refresh unbound; refresh without JKT succeeds.
#[tokio::test]
async fn m1_05_non_dpop_exchange_allows_refresh_without_jkt() {
    let (h, realm, user_id, client_id) = setup().await;

    let tokens = exchange_code(&h, &realm, &user_id, &client_id, None);

    let refresh_claims = decode_claims_json(tokens.refresh_token());
    assert!(
        refresh_claims["cnf"].is_null(),
        "non-DPoP refresh token must not carry cnf claim"
    );

    h.identity()
        .refresh_tokens(&realm, tokens.refresh_token(), None, None)
        .expect("non-DPoP refresh must succeed without JKT");
}
