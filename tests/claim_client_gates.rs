#![allow(clippy::unwrap_used)]
//! `allowed_clients` names managed clients only (`scope-consent-integrity`
//! design §3). A client registered through Dynamic Client Registration never
//! passes a gate, even when its name reads like a managed client's slug.
//!
//! Scenario "Slug gates match managed clients only" of `custom-permissions`.

mod common;

use base64::Engine as _;
use hearth::core::{ClientId, RealmId, UserId};
use hearth::identity::claims_config::{ClaimMapping, ClaimProfile, ClaimSource};
use hearth::identity::reconcile::deterministic_client_id;
use hearth::identity::{
    AuthorizationRequest, ClientTrustLevel, CodeChallengeMethod, CreateRealmRequest,
    CreateUserRequest, RealmConfig, RegisterClientRequest, TokenExchangeRequest,
};

const REDIRECT_URI: &str = "https://rp.example.com/cb";
const VERIFIER: &str = "S4gKJfVNgWiFl2PQ8RxXS7E6Mhr9BqyTvUIe3WoA5Zc";

/// A realm whose `portal_tier` claim is gated on the managed client
/// `customer-portal`.
fn setup(h: &common::TestHarness) -> (RealmId, UserId) {
    let realm_name = format!("gates-{}", uuid::Uuid::new_v4());
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: realm_name.clone(),
            config: Some(RealmConfig {
                claim_profile: Some(ClaimProfile {
                    mappings: vec![ClaimMapping {
                        claim: "portal_tier".into(),
                        source: ClaimSource::Constant {
                            value: serde_json::json!("gold"),
                        },
                        include_in_access_token: false,
                        include_in_id_token: false,
                        include_in_userinfo: true,
                        first_party_only: false,
                        required_scopes: None,
                        // The managed client `customer-portal` of this realm.
                        allowed_clients: Some(vec![deterministic_client_id(
                            &realm_name,
                            "customer-portal",
                        )]),
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
                email: format!("u-{}@gates.test", uuid::Uuid::new_v4()),
                display_name: "Gates".into(),
                ..Default::default()
            },
        )
        .expect("create user")
        .id()
        .clone();
    (realm, user)
}

fn access_token_for(h: &common::TestHarness, realm: &RealmId, user: &UserId) -> String {
    // A self-registered client whose name lower-cases to the managed slug.
    let client: ClientId = h
        .identity()
        .register_client(
            realm,
            &RegisterClientRequest {
                client_name: "Customer Portal".into(),
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

#[tokio::test]
async fn slug_gates_match_managed_clients_only() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let (realm, user) = setup(&h);

    let token = access_token_for(&h, &realm, &user);
    let info = h.identity().userinfo(&realm, &token).expect("userinfo");
    assert!(
        !info.custom.contains_key("portal_tier"),
        "a self-registered client must not pass a managed client's gate"
    );
}
