#![allow(clippy::unwrap_used)]
//! GA audit 2026-09-28 M10 — `userinfo` evaluated claim-release gates as if
//! every caller were a first-party client.
//!
//! It looked the client up from `aud` with a `client_` prefix, but an access
//! token's `aud` is always the Hearth audience, so the lookup never found a
//! client and the first-party sentinel stood in. A claim an operator marked
//! `first_party_only` was therefore released to any third-party client that
//! called `/userinfo`. The endpoint now evaluates the gates against the client
//! the token was issued to (its `client_id` claim).

mod common;

use base64::Engine as _;
use hearth::core::{ClientId, RealmId, UserId};
use hearth::identity::claims_config::{ClaimMapping, ClaimProfile, ClaimSource};
use hearth::identity::{
    AuthorizationRequest, ClientTrustLevel, CodeChallengeMethod, CreateRealmRequest,
    CreateUserRequest, RealmConfig, RegisterClientRequest, TokenExchangeRequest,
};

const REDIRECT_URI: &str = "https://rp.example.com/cb";
const VERIFIER: &str = "S4gKJfVNgWiFl2PQ8RxXS7E6Mhr9BqyTvUIe3WoA5Zc";

fn setup(h: &common::TestHarness) -> (RealmId, UserId) {
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("userinfo-gates-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                claim_profile: Some(ClaimProfile {
                    mappings: vec![ClaimMapping {
                        claim: "employee_id".into(),
                        source: ClaimSource::Constant {
                            value: serde_json::json!("E-1001"),
                        },
                        include_in_access_token: false,
                        include_in_id_token: false,
                        include_in_userinfo: true,
                        first_party_only: true,
                        required_scopes: None,
                        allowed_clients: None,
                    }],
                    updated_at: None,
                }),
                ..RealmConfig::default()
            }),
        })
        .expect("create realm")
        .id()
        .clone();
    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("u-{}@userinfo.test", uuid::Uuid::new_v4()),
                display_name: "Userinfo".into(),
                ..Default::default()
            },
        )
        .expect("create user")
        .id()
        .clone();
    (realm, user)
}

fn access_token_for(
    h: &common::TestHarness,
    realm: &RealmId,
    user: &UserId,
    trust_level: ClientTrustLevel,
) -> String {
    let client: ClientId = h
        .identity()
        .register_client(
            realm,
            &RegisterClientRequest {
                client_name: "rp".into(),
                redirect_uris: vec![REDIRECT_URI.into()],
                grant_types: vec!["authorization_code".into()],
                require_consent: false,
                trust_level,
                ..Default::default()
            },
        )
        .expect("register")
        .client_id()
        .clone();
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(ring::digest::digest(&ring::digest::SHA256, VERIFIER.as_bytes()).as_ref());
    let code = h
        .identity()
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
        .expect("authorize")
        .code()
        .to_string();
    h.identity()
        .exchange_authorization_code(
            realm,
            &TokenExchangeRequest {
                client_id: client,
                code,
                redirect_uri: REDIRECT_URI.into(),
                code_verifier: Some(VERIFIER.into()),
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
            },
        )
        .expect("exchange")
        .access_token()
        .to_string()
}

#[tokio::test]
async fn userinfo_withholds_first_party_only_claims_from_a_third_party_client() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm, user) = setup(&h);

    let first = access_token_for(&h, &realm, &user, ClientTrustLevel::FirstParty);
    let first = h.identity().userinfo(&realm, &first).expect("userinfo");
    assert_eq!(
        first.custom.get("employee_id"),
        Some(&serde_json::json!("E-1001")),
        "control: a first-party client receives the first_party_only claim"
    );

    let third = access_token_for(&h, &realm, &user, ClientTrustLevel::ThirdParty);
    let third = h.identity().userinfo(&realm, &third).expect("userinfo");
    assert!(
        !third.custom.contains_key("employee_id"),
        "a first_party_only claim must not reach a third-party client through \
         userinfo; got {:?}",
        third.custom
    );
}
