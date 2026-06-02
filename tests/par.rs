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
    AuthorizationRequest, CodeChallengeMethod, CreateRealmRequest, CreateUserRequest,
    CredentialConfig, EmbeddedIdentityEngine, FapiProfile, IdentityConfig, IdentityEngine,
    IdentityError, PushedAuthorizationRequest, RegisterClientRequest, UpdateRealmRequest,
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
        request: None,
        response_mode: None,
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
        request: None,
        response_mode: None,
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
        request: None,
        response_mode: None,
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

// ===== P-05: PAR → authorize end-to-end (FAPI gate regression) =====
//
// Verifies that the web/REST handler correctly propagates `via_par = true`
// after consuming a pushed authorization request.  On old code the handler
// always set `via_par = false`, causing FAPI 2.0 Baseline realms to reject
// every browser-based authorization request.
//
// The test cannot call the private `consume_par` method, so it simulates the
// handler's behaviour: push PAR to get a `request_uri`, then call `authorize`
// with the same parameters and `via_par = true`.  The negative half confirms
// that the same call with `via_par = false` is rejected — which is exactly
// what the un-fixed handler was producing.

#[test]
fn par_authorize_via_par_true_succeeds_on_fapi_realm() {
    let env = setup();

    // Create a FAPI Baseline realm.
    let realm_rec = env
        .engine
        .create_realm(&CreateRealmRequest {
            name: format!("par-fapi-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create fapi realm");
    let fapi_realm = realm_rec.id().clone();
    let mut config = realm_rec.config().clone();
    config.fapi_profile = Some(FapiProfile::Baseline);
    env.engine
        .update_realm(
            &fapi_realm,
            &UpdateRealmRequest {
                config: Some(config),
                ..Default::default()
            },
        )
        .expect("update realm");

    // Register a confidential client in the FAPI realm.
    let fapi_client = env
        .engine
        .register_client(
            &fapi_realm,
            &RegisterClientRequest {
                client_name: "FAPI PAR Test Client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: Some("test-secret".to_string()),
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("register fapi client");

    // Create a subject user in the FAPI realm.
    let user_id = env
        .engine
        .create_user(
            &fapi_realm,
            &CreateUserRequest {
                email: format!("par-user-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "PAR User".to_string(),
                ..Default::default()
            },
        )
        .expect("create user")
        .id()
        .clone();

    // Push a PAR to obtain a request_uri.
    let par_req = par_request_with_pkce(fapi_client.client_id().clone());
    let par_resp = env
        .engine
        .push_authorization_request(&fapi_realm, &par_req)
        .expect("PAR push must succeed on FAPI realm");
    assert!(
        par_resp
            .request_uri
            .starts_with("urn:ietf:params:oauth:request_uri:"),
        "request_uri must use RFC 9126 URN scheme"
    );

    // Positive: authorize with via_par = true — simulates the fixed web
    // handler consuming the request_uri and propagating via_par = true.
    let auth_req = AuthorizationRequest {
        client_id: fapi_client.client_id().clone(),
        redirect_uri: REDIRECT_URI.to_string(),
        scope: par_req.scope.clone(),
        state: par_req.state.clone(),
        resource: None,
        response_type: par_req.response_type.clone(),
        user_id: user_id.clone(),
        code_challenge: par_req.code_challenge.clone(),
        code_challenge_method: par_req.code_challenge_method,
        nonce: None,
        amr_values: Vec::new(),
        response_mode: None,
        request: None,
        via_par: true,
    };
    env.engine
        .authorize(&fapi_realm, &auth_req)
        .expect("FAPI realm + via_par=true must issue a code");

    // Negative: the same parameters with via_par = false are rejected by the
    // FAPI engine guard.  This is exactly what the un-fixed handler produced
    // (it always passed via_par = false regardless of request_uri presence).
    let direct_req = AuthorizationRequest {
        via_par: false,
        ..auth_req
    };
    let err = env
        .engine
        .authorize(&fapi_realm, &direct_req)
        .expect_err("FAPI realm + via_par=false must be rejected");
    assert!(
        matches!(err, IdentityError::FapiViolation { .. }),
        "expected FapiViolation, got: {err:?}"
    );
}
