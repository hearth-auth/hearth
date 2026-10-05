#![allow(clippy::unwrap_used)]
//! GA audit 2026-09-28 M7 — a client's registered `grant_types` were enforced
//! only for `client_credentials` and the jwt-bearer grant.
//!
//! Every other grant ignored them: a client registered for
//! `authorization_code` alone still received and redeemed refresh tokens, and
//! any client could start a device flow (the phishing path of B3). The admin
//! console's refresh-token toggle therefore did nothing.
//!
//! Every grant now checks the client's `grant_types`:
//!
//! * `/authorize` and the code exchange need `authorization_code`;
//! * a refresh token is issued, and redeemed, only for `refresh_token`;
//! * the device grant needs `urn:ietf:params:oauth:grant-type:device_code`.
//!
//! (RFC 8693 token exchange is gated separately by the per-client
//! token-exchange policy, GA audit M8.)
//!
//! Compatibility: a client registered without `grant_types` now defaults to
//! `["authorization_code", "refresh_token"]`, and a client record written
//! before this release keeps the refresh tokens every client used to receive
//! until its grant types are next edited.

mod common;

use base64::Engine as _;
use hearth::core::{ClientId, RealmId, UserId};
use hearth::identity::{
    AuthorizationRequest, ClientTrustLevel, CodeChallengeMethod, CreateUserRequest,
    DeviceAuthorizationRequest, IdentityError, OAuthClient, RegisterClientRequest,
    TokenExchangeRequest, UpdateClientRequest,
};

const REDIRECT_URI: &str = "https://grants.example.com/cb";
const VERIFIER: &str = "S4gKJfVNgWiFl2PQ8RxXS7E6Mhr9BqyTvUIe3WoA5Zc";
const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
const SECRET: &str = "grant-types-enforced-secret-32chars!";

fn user(h: &common::TestHarness, realm: &RealmId) -> UserId {
    h.identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("u-{}@grants.test", uuid::Uuid::new_v4()),
                display_name: "Grants".into(),
                ..Default::default()
            },
        )
        .expect("create user")
        .id()
        .clone()
}

fn register(
    h: &common::TestHarness,
    realm: &RealmId,
    grant_types: &[&str],
    secret: Option<&str>,
) -> OAuthClient {
    h.identity()
        .register_client(
            realm,
            &RegisterClientRequest {
                client_name: "grants".into(),
                redirect_uris: vec![REDIRECT_URI.into()],
                client_secret: secret.map(str::to_string),
                grant_types: grant_types.iter().map(|g| (*g).to_string()).collect(),
                require_consent: false,
                trust_level: ClientTrustLevel::FirstParty,
                ..Default::default()
            },
        )
        .expect("register client")
}

fn authorize(
    h: &common::TestHarness,
    realm: &RealmId,
    client: &ClientId,
    user: &UserId,
) -> Result<String, IdentityError> {
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(ring::digest::digest(&ring::digest::SHA256, VERIFIER.as_bytes()).as_ref());
    h.identity()
        .authorize(
            realm,
            &AuthorizationRequest {
                client_id: client.clone(),
                redirect_uri: REDIRECT_URI.into(),
                scope: "openid".into(),
                state: "s".into(),
                response_type: "code".into(),
                user_id: user.clone(),
                code_challenge: Some(challenge),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: None,
                resource: None,
                amr_values: Vec::new(),
                response_mode: None,
                request: None,
            },
        )
        .map(|r| r.code().to_string())
}

/// Runs the code grant and returns `(access_token, refresh_token)`.
fn code_grant(
    h: &common::TestHarness,
    realm: &RealmId,
    client: &ClientId,
    user: &UserId,
) -> (String, String) {
    let code = authorize(h, realm, client, user).expect("authorize");
    let pair = h
        .identity()
        .exchange_authorization_code(
            realm,
            &TokenExchangeRequest {
                client_id: client.clone(),
                code,
                redirect_uri: REDIRECT_URI.into(),
                code_verifier: Some(VERIFIER.into()),
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
                resource: None,
            },
        )
        .expect("exchange");
    (
        pair.access_token().to_string(),
        pair.refresh_token().to_string(),
    )
}

#[tokio::test]
async fn authorize_refuses_a_client_not_registered_for_authorization_code() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = h.create_realm();
    let user = user(&h, &realm);
    let client = register(&h, &realm, &["client_credentials"], Some(SECRET));

    let outcome = authorize(&h, &realm, client.client_id(), &user);
    assert!(
        matches!(outcome, Err(IdentityError::UnsupportedGrantType)),
        "a client_credentials-only client must not obtain an authorization \
         code; got {outcome:?}"
    );
}

#[tokio::test]
async fn code_exchange_issues_no_refresh_token_without_the_refresh_token_grant() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = h.create_realm();
    let user = user(&h, &realm);
    let client = register(&h, &realm, &["authorization_code"], None);

    let (access, refresh) = code_grant(&h, &realm, client.client_id(), &user);
    assert!(!access.is_empty(), "the access token is still issued");
    assert!(
        refresh.is_empty(),
        "a client registered without refresh_token must not receive a refresh token"
    );
}

#[tokio::test]
async fn refresh_is_refused_once_the_refresh_token_grant_is_removed() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = h.create_realm();
    let user = user(&h, &realm);
    let client = register(&h, &realm, &["authorization_code", "refresh_token"], None);

    let (_, refresh) = code_grant(&h, &realm, client.client_id(), &user);
    assert!(
        !refresh.is_empty(),
        "precondition: a refresh token was issued"
    );
    let rotated = h
        .identity()
        .refresh_tokens(&realm, &refresh, None, None)
        .expect("control: the refresh grant is allowed while declared");

    // The console's refresh toggle: turn the grant off.
    h.identity()
        .update_client(
            &realm,
            client.client_id(),
            &UpdateClientRequest {
                grant_types: Some(vec!["authorization_code".into()]),
                ..Default::default()
            },
        )
        .expect("update client");
    let outcome = h
        .identity()
        .refresh_tokens(&realm, rotated.refresh_token(), None, None);
    assert!(
        matches!(outcome, Err(IdentityError::UnsupportedGrantType)),
        "a refresh token must not be redeemed once the client no longer holds \
         the refresh_token grant; got {:?}",
        outcome.map(|_| "tokens")
    );
}

#[tokio::test]
async fn a_client_registered_without_grant_types_defaults_to_code_and_refresh() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = h.create_realm();
    let user = user(&h, &realm);
    let client = register(&h, &realm, &[], None);
    assert_eq!(
        client.grant_types(),
        [
            "authorization_code".to_string(),
            "refresh_token".to_string()
        ],
        "the default grant set must keep refresh tokens working for clients \
         that never named their grant types"
    );
    let (_, refresh) = code_grant(&h, &realm, client.client_id(), &user);
    h.identity()
        .refresh_tokens(&realm, &refresh, None, None)
        .expect("the default client refreshes");
}

#[tokio::test]
async fn device_grant_refuses_a_client_not_registered_for_it() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = h.create_realm();
    let client = register(&h, &realm, &["authorization_code"], None);
    let outcome = h.identity().device_authorize(
        &realm,
        &DeviceAuthorizationRequest {
            client_id: client.client_id().clone(),
            scope: Some("openid".into()),
        },
    );
    assert!(
        matches!(outcome, Err(IdentityError::UnsupportedGrantType)),
        "any client could start a device flow; got {:?}",
        outcome.map(|r| r.user_code)
    );

    let device = register(&h, &realm, &[DEVICE_GRANT], None);
    h.identity()
        .device_authorize(
            &realm,
            &DeviceAuthorizationRequest {
                client_id: device.client_id().clone(),
                scope: Some("openid".into()),
            },
        )
        .expect("control: a device client starts the flow");
}
