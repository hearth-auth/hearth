//! Integration tests for Pushed Authorization Request — RFC 9126.
//!
//! Tests the public `IdentityEngine` surface: `push_authorization_request`
//! and `realm_oidc_discovery`. Replay-protection and TTL-expiry behaviour
//! are covered by unit tests in `src/identity/engine.rs` because those
//! scenarios require calling `consume_par`, which returns a `pub(crate)` type.

use std::sync::Arc;

use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{Clock, FakeClock, RealmId, Timestamp};
use hearth::identity::{
    CodeChallengeMethod, CreateRealmRequest, CredentialConfig, EmbeddedIdentityEngine,
    IdentityConfig, IdentityEngine, IdentityError, PushedAuthorizationRequest,
    RegisterClientRequest,
};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

const EPOCH_MICROS: i64 = 1_700_000_000 * 1_000_000;
const REDIRECT_URI: &str = "https://example.com/callback";
const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

fn pkce_challenge(verifier: &str) -> String {
    use data_encoding::BASE64URL_NOPAD;
    BASE64URL_NOPAD
        .encode(ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes()).as_ref())
}

struct TestEnv {
    engine: EmbeddedIdentityEngine,
    realm: RealmId,
    _dir: tempfile::TempDir,
}

fn setup() -> TestEnv {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf())).expect("storage"),
    );
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(EPOCH_MICROS)));
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock) as Arc<dyn Clock>,
    )) as Arc<dyn AuditEngine>;
    let engine = EmbeddedIdentityEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock) as Arc<dyn Clock>,
        IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        },
        audit,
    )
    .expect("engine");

    let realm = engine
        .create_realm(&CreateRealmRequest {
            name: format!("par-test-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();

    TestEnv {
        engine,
        realm,
        _dir: dir,
    }
}

fn register_public_client(env: &TestEnv) -> hearth::identity::OAuthClient {
    env.engine
        .register_client(
            &env.realm,
            &RegisterClientRequest {
                client_name: "PAR Test Public".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                client_logo_url: None,
                ..Default::default()
            },
        )
        .expect("register client")
}

fn par_request_with_pkce(client_id: hearth::core::ClientId) -> PushedAuthorizationRequest {
    PushedAuthorizationRequest {
        client_id,
        redirect_uri: REDIRECT_URI.to_string(),
        scope: "openid".to_string(),
        state: "state-abc".to_string(),
        resource: None,
        response_type: "code".to_string(),
        code_challenge: Some(pkce_challenge(PKCE_VERIFIER)),
        code_challenge_method: Some(CodeChallengeMethod::S256),
        nonce: None,
    }
}

// ===== P-01: Happy path =====

#[test]
fn happy_path_returns_request_uri_and_expiry() {
    let env = setup();
    let client = register_public_client(&env);

    let resp = env
        .engine
        .push_authorization_request(
            &env.realm,
            &par_request_with_pkce(client.client_id().clone()),
        )
        .expect("PAR push should succeed");

    assert!(
        resp.request_uri
            .starts_with("urn:ietf:params:oauth:request_uri:"),
        "request_uri must use the RFC 9126 URN scheme, got: {}",
        resp.request_uri
    );
    assert_eq!(
        resp.expires_in, 90,
        "TTL must be 90 seconds per RFC 9126 §2.2"
    );
}

// ===== P-02: PKCE enforcement =====

#[test]
fn public_client_without_pkce_rejected() {
    let env = setup();
    let client = register_public_client(&env);

    let req = PushedAuthorizationRequest {
        client_id: client.client_id().clone(),
        redirect_uri: REDIRECT_URI.to_string(),
        scope: "openid".to_string(),
        state: "state-abc".to_string(),
        resource: None,
        response_type: "code".to_string(),
        code_challenge: None,
        code_challenge_method: None,
        nonce: None,
    };

    assert!(
        matches!(
            env.engine.push_authorization_request(&env.realm, &req),
            Err(IdentityError::InvalidInput { .. })
        ),
        "public client without PKCE must be rejected with InvalidInput"
    );
}

// ===== P-03: Invalid response_type =====

#[test]
fn non_code_response_type_rejected() {
    let env = setup();
    let client = register_public_client(&env);

    let req = PushedAuthorizationRequest {
        client_id: client.client_id().clone(),
        redirect_uri: REDIRECT_URI.to_string(),
        scope: "openid".to_string(),
        state: "state-abc".to_string(),
        resource: None,
        response_type: "token".to_string(),
        code_challenge: Some(pkce_challenge(PKCE_VERIFIER)),
        code_challenge_method: Some(CodeChallengeMethod::S256),
        nonce: None,
    };

    assert!(
        matches!(
            env.engine.push_authorization_request(&env.realm, &req),
            Err(IdentityError::InvalidInput { .. })
        ),
        "response_type other than 'code' must be rejected"
    );
}

// ===== P-04: Discovery document =====

#[test]
fn discovery_advertises_par_endpoint() {
    let env = setup();
    let doc = env
        .engine
        .realm_oidc_discovery(&env.realm)
        .expect("discovery");

    let ep = doc
        .pushed_authorization_request_endpoint
        .expect("pushed_authorization_request_endpoint must be present in discovery document");
    assert!(
        ep.ends_with("/as/par"),
        "PAR endpoint must end with /as/par, got: {ep}"
    );
}
