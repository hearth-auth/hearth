#![allow(clippy::unwrap_used)]
//! Tier 1 claim names never come from mapper output (`scope-consent-integrity`
//! design §3). Config load refuses a mapping that targets a Tier 1 name, but a
//! claim profile can reach the engine without that check (a realm config set
//! through the API, a restored backup). Issuance drops such mappings, so core
//! issuance alone writes Tier 1 claims.
//!
//! Scenario "Tier 1 names never come from mapper output" of `custom-permissions`.

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

fn constant(claim: &str, value: serde_json::Value) -> ClaimMapping {
    ClaimMapping {
        claim: claim.into(),
        source: ClaimSource::Constant { value },
        include_in_access_token: true,
        include_in_id_token: true,
        include_in_userinfo: true,
        first_party_only: false,
        required_scopes: None,
        allowed_clients: None,
    }
}

/// A realm whose claim profile, never checked at load, maps Tier 1 names.
fn setup(h: &common::TestHarness) -> (RealmId, UserId) {
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("tier1-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                claim_profile: Some(ClaimProfile {
                    mappings: vec![
                        constant("sub", serde_json::json!("admin")),
                        constant("permissions", serde_json::json!(["hearth.admin"])),
                        constant("oid", serde_json::json!("acme")),
                    ],
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
                email: format!("u-{}@tier1.test", uuid::Uuid::new_v4()),
                display_name: "Tier1".into(),
                ..Default::default()
            },
        )
        .expect("create user")
        .id()
        .clone();
    (realm, user)
}

fn access_token_for(h: &common::TestHarness, realm: &RealmId, user: &UserId) -> String {
    let client: ClientId = h
        .identity()
        .register_client(
            realm,
            &RegisterClientRequest {
                client_name: "rp".into(),
                redirect_uris: vec![REDIRECT_URI.into()],
                grant_types: vec!["authorization_code".into()],
                require_consent: false,
                trust_level: ClientTrustLevel::FirstParty,
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

/// The payload of a compact JWT, as raw JSON text.
fn payload_text(jwt: &str) -> String {
    let payload = jwt.split('.').nth(1).expect("payload segment");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("base64url payload");
    String::from_utf8(bytes).expect("utf-8 payload")
}

#[tokio::test]
async fn tier1_names_never_come_from_mapper_output() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let (realm, user) = setup(&h);

    let token = access_token_for(&h, &realm, &user);
    let text = payload_text(&token);
    assert_eq!(
        text.matches("\"sub\":").count(),
        1,
        "the payload carries `sub` once"
    );
    let payload: serde_json::Value = serde_json::from_str(&text).expect("json payload");
    assert_eq!(
        payload["sub"].as_str(),
        Some(user.to_string().as_str()),
        "`sub` is the user's ID"
    );
    assert!(
        !text.contains("hearth.admin"),
        "a mapper never adds permissions"
    );
    assert!(
        payload.get("oid").is_none(),
        "a mapper never sets the organization"
    );
}
