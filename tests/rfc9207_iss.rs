//! Integration tests for RFC 9207 — Authorization Server Issuer Identification.
//!
//! RFC 9207 prevents mix-up attacks by appending an `iss` query parameter to
//! successful authorization responses. The client must verify the `iss` value
//! matches the authorization server it sent the request to.
//!
//! These tests verify:
//! - `iss` is present and non-empty in every successful `AuthorizationResponse`
//! - `iss` matches the global OIDC discovery document's `issuer` field
//! - The discovery document advertises `authorization_response_iss_parameter_supported: true`
//! - Per-realm discovery also advertises support
//! - `iss` is stable across multiple authorization requests for the same realm

mod common;

use hearth::core::UserId;
use hearth::identity::{
    AuthorizationRequest, CodeChallengeMethod, CreateRealmRequest, CreateUserRequest, OAuthClient,
    RegisterClientRequest,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const REDIRECT_URI: &str = "https://app.example.com/callback";
const PKCE_VERIFIER: &str = "S4gKJfVNgWiFl2PQ8RxXS7E6Mhr9BqyTvUIe3WoA5Zc";

fn pkce_challenge(verifier: &str) -> String {
    use data_encoding::BASE64URL_NOPAD;
    BASE64URL_NOPAD
        .encode(ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes()).as_ref())
}

struct Env {
    harness: common::TestHarness,
    realm: hearth::core::RealmId,
    user_id: UserId,
    client: OAuthClient,
}

async fn setup() -> Env {
    let harness = common::TestHarness::embedded()
        .await
        .expect("embedded harness");

    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("rfc9207-test-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();

    let user_id = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("user-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Test User".to_string(),
                ..CreateUserRequest::default()
            },
        )
        .expect("create user")
        .id()
        .clone();

    let client = harness
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "RFC 9207 Test App".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                client_logo_url: None,
                ..Default::default()
            },
        )
        .expect("register client");

    Env {
        harness,
        realm,
        user_id,
        client,
    }
}

fn auth_request(env: &Env) -> AuthorizationRequest {
    AuthorizationRequest {
        client_id: env.client.client_id().clone(),
        redirect_uri: REDIRECT_URI.to_string(),
        scope: "openid".to_string(),
        state: format!("state-{}", uuid::Uuid::new_v4()),
        resource: None,
        response_type: "code".to_string(),
        user_id: env.user_id.clone(),
        code_challenge: Some(pkce_challenge(PKCE_VERIFIER)),
        code_challenge_method: Some(CodeChallengeMethod::S256),
        nonce: Some(uuid::Uuid::new_v4().to_string()),
        amr_values: vec![],
    }
}

// ---------------------------------------------------------------------------
// ISS-01: iss is present and non-empty in every successful authorization response
// ---------------------------------------------------------------------------

#[tokio::test]
async fn iss_is_present_in_authorization_response() {
    let env = setup().await;

    let resp = env
        .harness
        .identity()
        .authorize(&env.realm, &auth_request(&env))
        .expect("authorize");

    assert!(
        !resp.iss().is_empty(),
        "RFC 9207: iss must be non-empty in authorization response"
    );
}

// ---------------------------------------------------------------------------
// ISS-02: iss matches the global OIDC discovery document's issuer
// ---------------------------------------------------------------------------

#[tokio::test]
async fn iss_matches_global_oidc_discovery_issuer() {
    let env = setup().await;

    let resp = env
        .harness
        .identity()
        .authorize(&env.realm, &auth_request(&env))
        .expect("authorize");

    let discovery = env.harness.identity().oidc_discovery();

    assert_eq!(
        resp.iss(),
        discovery.issuer,
        "RFC 9207: iss in authorization response must match the discovery document issuer"
    );
}

// ---------------------------------------------------------------------------
// ISS-03: discovery document advertises authorization_response_iss_parameter_supported
// ---------------------------------------------------------------------------

#[tokio::test]
async fn global_discovery_advertises_iss_parameter_supported() {
    let env = setup().await;

    let discovery = env.harness.identity().oidc_discovery();

    assert!(
        discovery.authorization_response_iss_parameter_supported,
        "RFC 9207: discovery must advertise authorization_response_iss_parameter_supported: true"
    );
}

// ---------------------------------------------------------------------------
// ISS-04: per-realm discovery document also advertises iss support
// ---------------------------------------------------------------------------

#[tokio::test]
async fn realm_discovery_advertises_iss_parameter_supported() {
    let env = setup().await;

    let realm_discovery = env
        .harness
        .identity()
        .realm_oidc_discovery(&env.realm)
        .expect("realm_oidc_discovery");

    assert!(
        realm_discovery.authorization_response_iss_parameter_supported,
        "RFC 9207: per-realm discovery must advertise authorization_response_iss_parameter_supported: true"
    );
}

// ---------------------------------------------------------------------------
// ISS-05: iss is stable across repeated authorization requests for the same realm
// ---------------------------------------------------------------------------

#[tokio::test]
async fn iss_is_stable_across_multiple_requests() {
    let env = setup().await;

    let resp1 = env
        .harness
        .identity()
        .authorize(&env.realm, &auth_request(&env))
        .expect("authorize first");

    let resp2 = env
        .harness
        .identity()
        .authorize(&env.realm, &auth_request(&env))
        .expect("authorize second");

    assert_eq!(
        resp1.iss(),
        resp2.iss(),
        "RFC 9207: iss must be identical across authorization responses for the same realm"
    );
}

// ---------------------------------------------------------------------------
// ISS-06: iss is non-empty even when state is a minimal single character
// ---------------------------------------------------------------------------

#[tokio::test]
async fn iss_present_with_minimal_state() {
    let env = setup().await;

    let req = AuthorizationRequest {
        state: "x".to_string(),
        ..auth_request(&env)
    };

    let resp = env
        .harness
        .identity()
        .authorize(&env.realm, &req)
        .expect("authorize");

    assert!(
        !resp.iss().is_empty(),
        "RFC 9207: iss must be present regardless of state value length"
    );
    assert_eq!(resp.state(), "x", "state must be echoed back unchanged");
}
