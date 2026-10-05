//! Integration tests for `private_key_jwt` client authentication (RFC 7523 §2.2).
//!
//! `private_key_jwt` lets confidential clients authenticate to the token endpoint
//! by presenting a self-signed JWT assertion instead of (or in addition to) a
//! `client_secret`. The AS verifies the assertion against the client's registered
//! public key and enforces replay protection via JTI tracking.
//!
//! Covers:
//! - PKJ-01: valid assertion → client_credentials token issued
//! - PKJ-02: valid assertion → auth code exchange succeeds
//! - PKJ-03: expired assertion rejected
//! - PKJ-04: replayed JTI rejected
//! - PKJ-05: wrong audience rejected
//! - PKJ-06: wrong iss (client_id mismatch) rejected
//! - PKJ-07: tampered signature rejected
//! - PKJ-08: no assertion public key registered → rejected
//! - PKJ-09: discovery advertises `private_key_jwt` in token_endpoint_auth_methods_supported
//! - PKJ-10: assertion without jti rejected (replay prevention is mandatory)
//! - PKJ-11: assertion with lifetime > 5 min rejected (max-lifetime enforcement)
//! - PKJ-12: private_key_jwt client without assertion bypassed auth code exchange → rejected
//! - JWKS-only clients (no secret, no assertion key) are never public: they are
//!   refused on `client_id` alone and authenticate with an assertion signed by
//!   a key from their JWKS (ES256 / EdDSA, by `kid`) — see `jwks_only_client`.

mod common;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hearth::identity::tokens::{Audience, JwtAssertionClaims};
use hearth::identity::{
    AuthorizationRequest, ClientCredentialsRequest, ClientTrustLevel, CodeChallengeMethod,
    CreateRealmRequest, CreateUserRequest, IdentityError, RegisterClientRequest, SigningKey,
    TokenExchangeRequest, UpdateClientRequest,
};

const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const REDIRECT_URI: &str = "https://app.example.com/callback";
const PKCE_VERIFIER: &str = "S4gKJfVNgWiFl2PQ8RxXS7E6Mhr9BqyTvUIe3WoA5Zc";

fn pkce_challenge(verifier: &str) -> String {
    use data_encoding::BASE64URL_NOPAD;
    BASE64URL_NOPAD
        .encode(ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes()).as_ref())
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_secs() as i64
}

/// Returns the token endpoint audience for a realm.
fn token_endpoint_aud(harness: &common::TestHarness, realm: &hearth::core::RealmId) -> String {
    let base = harness.identity().oidc_discovery().issuer;
    let realm_obj = harness
        .identity()
        .get_realm(realm)
        .expect("get_realm")
        .expect("realm exists");
    format!("{}/realms/{}", base, realm_obj.name())
}

fn make_assertion(
    key: &SigningKey,
    client_id: &str,
    audience: &str,
    exp_offset_secs: i64,
    jti: Option<String>,
) -> String {
    let now = now_secs();
    let claims = JwtAssertionClaims {
        iss: client_id.to_string(),
        sub: client_id.to_string(),
        aud: Audience::single(audience.to_string()),
        exp: now + exp_offset_secs,
        jti,
        iat: Some(now),
    };
    key.issue_assertion_jwt(&claims).expect("sign assertion")
}

// ---------------------------------------------------------------------------
// Setup helpers
// ---------------------------------------------------------------------------

struct Env {
    harness: common::TestHarness,
    realm: hearth::core::RealmId,
    auth_key: SigningKey,
    client_id: hearth::core::ClientId,
    user_id: hearth::core::UserId,
}

async fn setup_cc_client() -> Env {
    let harness = common::TestHarness::in_process().await.expect("harness");

    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("pkjwt-cc-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();

    let auth_key = SigningKey::generate().expect("generate key");
    let pk_b64 = URL_SAFE_NO_PAD.encode(auth_key.public_key_bytes());

    let client = harness
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "PKJ CC Client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: None,
                grant_types: vec!["client_credentials".to_string()],
                require_consent: false,
                trust_level: ClientTrustLevel::FirstParty,
                ..Default::default()
            },
        )
        .expect("register client");

    harness
        .identity()
        .update_client(
            &realm,
            client.client_id(),
            &UpdateClientRequest {
                assertion_public_key: Some(Some(pk_b64)),
                ..Default::default()
            },
        )
        .expect("set assertion_public_key");

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

    Env {
        harness,
        realm,
        auth_key,
        client_id: client.client_id().clone(),
        user_id,
    }
}

async fn setup_auth_code_client() -> Env {
    let harness = common::TestHarness::in_process().await.expect("harness");

    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("pkjwt-ac-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();

    let auth_key = SigningKey::generate().expect("generate key");
    let pk_b64 = URL_SAFE_NO_PAD.encode(auth_key.public_key_bytes());

    let client = harness
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "PKJ Auth Code Client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: Some("ignored-secret".to_string()),
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("register client");

    harness
        .identity()
        .update_client(
            &realm,
            client.client_id(),
            &UpdateClientRequest {
                assertion_public_key: Some(Some(pk_b64)),
                ..Default::default()
            },
        )
        .expect("set assertion_public_key");

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

    Env {
        harness,
        realm,
        auth_key,
        client_id: client.client_id().clone(),
        user_id,
    }
}

// ---------------------------------------------------------------------------
// PKJ-01: valid assertion → client_credentials token issued
// ---------------------------------------------------------------------------

#[tokio::test]
async fn valid_assertion_issues_client_credentials_token() {
    let env = setup_cc_client().await;
    let aud = token_endpoint_aud(&env.harness, &env.realm);
    let assertion = make_assertion(
        &env.auth_key,
        &env.client_id.as_uuid().to_string(),
        &aud,
        300,
        Some(uuid::Uuid::new_v4().to_string()),
    );

    let resp = env
        .harness
        .identity()
        .client_credentials_token(
            &env.realm,
            &ClientCredentialsRequest {
                client_id: env.client_id.clone(),
                client_secret: None,
                client_assertion_type: Some(CLIENT_ASSERTION_TYPE.to_string()),
                client_assertion: Some(assertion),
                resource: None,
                scope: None,
                dpop_jkt: None,
            },
        )
        .expect("client_credentials with private_key_jwt should succeed");

    assert!(
        !resp.access_token().is_empty(),
        "access token must be non-empty"
    );
}

// ---------------------------------------------------------------------------
// PKJ-02: valid assertion → auth code exchange succeeds
// ---------------------------------------------------------------------------

#[tokio::test]
async fn valid_assertion_exchanges_auth_code() {
    let env = setup_auth_code_client().await;
    let aud = token_endpoint_aud(&env.harness, &env.realm);

    // Issue auth code
    let auth_resp = env
        .harness
        .identity()
        .authorize(
            &env.realm,
            &AuthorizationRequest {
                client_id: env.client_id.clone(),
                redirect_uri: REDIRECT_URI.to_string(),
                scope: "openid".to_string(),
                state: "state-123".to_string(),
                resource: None,
                response_type: "code".to_string(),
                user_id: env.user_id.clone(),
                code_challenge: Some(pkce_challenge(PKCE_VERIFIER)),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: Some("nonce-abc".to_string()),
                amr_values: vec![],
                response_mode: None,
                request: None,
            },
        )
        .expect("authorize");

    let assertion = make_assertion(
        &env.auth_key,
        &env.client_id.as_uuid().to_string(),
        &aud,
        300,
        Some(uuid::Uuid::new_v4().to_string()),
    );

    let token_resp = env
        .harness
        .identity()
        .exchange_authorization_code(
            &env.realm,
            &TokenExchangeRequest {
                client_id: env.client_id.clone(),
                code: auth_resp.code().to_string(),
                redirect_uri: REDIRECT_URI.to_string(),
                code_verifier: Some(PKCE_VERIFIER.to_string()),
                dpop_jkt: None,
                client_assertion_type: Some(CLIENT_ASSERTION_TYPE.to_string()),
                client_assertion: Some(assertion),
                resource: None,
            },
        )
        .expect("exchange_authorization_code with private_key_jwt should succeed");

    assert!(
        !token_resp.access_token().is_empty(),
        "access token must be non-empty"
    );
}

// ---------------------------------------------------------------------------
// PKJ-03: expired assertion rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn expired_assertion_rejected() {
    let env = setup_cc_client().await;
    let aud = token_endpoint_aud(&env.harness, &env.realm);
    let assertion = make_assertion(
        &env.auth_key,
        &env.client_id.as_uuid().to_string(),
        &aud,
        -60, // expired 60 seconds ago
        Some(uuid::Uuid::new_v4().to_string()),
    );

    let err = env
        .harness
        .identity()
        .client_credentials_token(
            &env.realm,
            &ClientCredentialsRequest {
                client_id: env.client_id.clone(),
                client_secret: None,
                client_assertion_type: Some(CLIENT_ASSERTION_TYPE.to_string()),
                client_assertion: Some(assertion),
                resource: None,
                scope: None,
                dpop_jkt: None,
            },
        )
        .expect_err("expired assertion must be rejected");

    assert!(
        matches!(
            err,
            IdentityError::InvalidClientAssertion { .. }
                | IdentityError::JwtBearerAssertionInvalid { .. }
        ),
        "expected assertion error, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// PKJ-04: replayed JTI rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn replayed_jti_rejected() {
    let env = setup_cc_client().await;
    let aud = token_endpoint_aud(&env.harness, &env.realm);
    let jti = uuid::Uuid::new_v4().to_string();

    let assertion = make_assertion(
        &env.auth_key,
        &env.client_id.as_uuid().to_string(),
        &aud,
        300,
        Some(jti.clone()),
    );

    // First use — must succeed
    env.harness
        .identity()
        .client_credentials_token(
            &env.realm,
            &ClientCredentialsRequest {
                client_id: env.client_id.clone(),
                client_secret: None,
                client_assertion_type: Some(CLIENT_ASSERTION_TYPE.to_string()),
                client_assertion: Some(assertion.clone()),
                resource: None,
                scope: None,
                dpop_jkt: None,
            },
        )
        .expect("first use must succeed");

    // Second use — must be rejected (replay)
    let err = env
        .harness
        .identity()
        .client_credentials_token(
            &env.realm,
            &ClientCredentialsRequest {
                client_id: env.client_id.clone(),
                client_secret: None,
                client_assertion_type: Some(CLIENT_ASSERTION_TYPE.to_string()),
                client_assertion: Some(assertion),
                resource: None,
                scope: None,
                dpop_jkt: None,
            },
        )
        .expect_err("replayed JTI must be rejected");

    assert!(
        matches!(
            err,
            IdentityError::InvalidClientAssertion { .. }
                | IdentityError::JwtBearerAssertionInvalid { .. }
        ),
        "expected assertion replay error, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// PKJ-05: wrong audience rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn wrong_audience_rejected() {
    let env = setup_cc_client().await;
    let assertion = make_assertion(
        &env.auth_key,
        &env.client_id.as_uuid().to_string(),
        "https://wrong-audience.example.com/token",
        300,
        Some(uuid::Uuid::new_v4().to_string()),
    );

    let err = env
        .harness
        .identity()
        .client_credentials_token(
            &env.realm,
            &ClientCredentialsRequest {
                client_id: env.client_id.clone(),
                client_secret: None,
                client_assertion_type: Some(CLIENT_ASSERTION_TYPE.to_string()),
                client_assertion: Some(assertion),
                resource: None,
                scope: None,
                dpop_jkt: None,
            },
        )
        .expect_err("wrong audience must be rejected");

    assert!(
        matches!(
            err,
            IdentityError::InvalidClientAssertion { .. }
                | IdentityError::JwtBearerAssertionInvalid { .. }
        ),
        "expected assertion error, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// PKJ-06: iss ≠ client_id rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn iss_mismatch_rejected() {
    let env = setup_cc_client().await;
    let aud = token_endpoint_aud(&env.harness, &env.realm);
    let assertion = make_assertion(
        &env.auth_key,
        "wrong-client-id",
        &aud,
        300,
        Some(uuid::Uuid::new_v4().to_string()),
    );

    let err = env
        .harness
        .identity()
        .client_credentials_token(
            &env.realm,
            &ClientCredentialsRequest {
                client_id: env.client_id.clone(),
                client_secret: None,
                client_assertion_type: Some(CLIENT_ASSERTION_TYPE.to_string()),
                client_assertion: Some(assertion),
                resource: None,
                scope: None,
                dpop_jkt: None,
            },
        )
        .expect_err("iss mismatch must be rejected");

    assert!(
        matches!(
            err,
            IdentityError::InvalidClientAssertion { .. }
                | IdentityError::JwtBearerAssertionInvalid { .. }
        ),
        "expected assertion error, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// PKJ-07: tampered signature rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tampered_signature_rejected() {
    let env = setup_cc_client().await;
    let aud = token_endpoint_aud(&env.harness, &env.realm);
    let assertion = make_assertion(
        &env.auth_key,
        &env.client_id.as_uuid().to_string(),
        &aud,
        300,
        Some(uuid::Uuid::new_v4().to_string()),
    );

    // Flip one byte in the signature (last JWT part)
    let mut parts: Vec<&str> = assertion.split('.').collect();
    let mut sig = URL_SAFE_NO_PAD.decode(parts[2]).expect("decode sig");
    sig[0] ^= 0xff;
    let bad_sig = URL_SAFE_NO_PAD.encode(&sig);
    parts[2] = Box::leak(bad_sig.into_boxed_str());
    let tampered = parts.join(".");

    let err = env
        .harness
        .identity()
        .client_credentials_token(
            &env.realm,
            &ClientCredentialsRequest {
                client_id: env.client_id.clone(),
                client_secret: None,
                client_assertion_type: Some(CLIENT_ASSERTION_TYPE.to_string()),
                client_assertion: Some(tampered),
                resource: None,
                scope: None,
                dpop_jkt: None,
            },
        )
        .expect_err("tampered signature must be rejected");

    assert!(
        matches!(
            err,
            IdentityError::InvalidClientAssertion { .. }
                | IdentityError::JwtBearerAssertionInvalid { .. }
                | IdentityError::InvalidToken
        ),
        "expected signature error, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// PKJ-08: no assertion public key registered → rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn no_assertion_key_registered_rejected() {
    let harness = common::TestHarness::in_process().await.expect("harness");

    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("pkjwt-nokey-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();

    // Register client WITHOUT assertion_public_key
    let client = harness
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "No-Key Client".to_string(),
                redirect_uris: vec![],
                client_secret: None,
                grant_types: vec!["client_credentials".to_string()],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("register client");

    let orphan_key = SigningKey::generate().expect("generate orphan key");
    let aud = format!(
        "{}/realms/{}",
        harness.identity().oidc_discovery().issuer,
        "pkjwt-nokey"
    );
    let assertion = make_assertion(
        &orphan_key,
        &client.client_id().as_uuid().to_string(),
        &aud,
        300,
        Some(uuid::Uuid::new_v4().to_string()),
    );

    let err = harness
        .identity()
        .client_credentials_token(
            &realm,
            &ClientCredentialsRequest {
                client_id: client.client_id().clone(),
                client_secret: None,
                client_assertion_type: Some(CLIENT_ASSERTION_TYPE.to_string()),
                client_assertion: Some(assertion),
                resource: None,
                scope: None,
                dpop_jkt: None,
            },
        )
        .expect_err("no key registered must be rejected");

    assert!(
        matches!(
            err,
            IdentityError::InvalidClientAssertion { .. }
                | IdentityError::JwtBearerAssertionInvalid { .. }
        ),
        "expected assertion error, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// PKJ-09: discovery advertises private_key_jwt
// ---------------------------------------------------------------------------

#[tokio::test]
async fn discovery_advertises_private_key_jwt_auth_method() {
    let harness = common::TestHarness::in_process().await.expect("harness");

    let discovery = harness.identity().oidc_discovery();

    assert!(
        discovery
            .token_endpoint_auth_methods_supported
            .contains(&"private_key_jwt".to_string()),
        "discovery must advertise private_key_jwt in token_endpoint_auth_methods_supported, got: {:?}",
        discovery.token_endpoint_auth_methods_supported
    );
}

// ---------------------------------------------------------------------------
// PKJ-10: assertion without jti rejected (replay prevention is mandatory)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn assertion_without_jti_rejected() {
    let env = setup_cc_client().await;
    let aud = token_endpoint_aud(&env.harness, &env.realm);

    // Omit jti entirely — the server must reject rather than silently skip replay protection.
    let claims = JwtAssertionClaims {
        iss: env.client_id.as_uuid().to_string(),
        sub: env.client_id.as_uuid().to_string(),
        aud: Audience::single(aud),
        exp: now_secs() + 60,
        jti: None,
        iat: Some(now_secs()),
    };
    let assertion = env
        .auth_key
        .issue_assertion_jwt(&claims)
        .expect("sign assertion");

    let err = env
        .harness
        .identity()
        .client_credentials_token(
            &env.realm,
            &ClientCredentialsRequest {
                client_id: env.client_id.clone(),
                client_secret: None,
                client_assertion_type: Some(CLIENT_ASSERTION_TYPE.to_string()),
                client_assertion: Some(assertion),
                resource: None,
                scope: None,
                dpop_jkt: None,
            },
        )
        .expect_err("jti-less assertion must be rejected");

    assert!(
        matches!(err, IdentityError::InvalidClientAssertion { .. }),
        "expected InvalidClientAssertion, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// PKJ-11: assertion with lifetime > 5 min rejected (max-lifetime enforcement)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn assertion_excessive_lifetime_rejected() {
    let env = setup_cc_client().await;
    let aud = token_endpoint_aud(&env.harness, &env.realm);

    // exp = now + 301 seconds — just over the 5-minute ceiling.
    let assertion = make_assertion(
        &env.auth_key,
        &env.client_id.as_uuid().to_string(),
        &aud,
        301,
        Some(uuid::Uuid::new_v4().to_string()),
    );

    let err = env
        .harness
        .identity()
        .client_credentials_token(
            &env.realm,
            &ClientCredentialsRequest {
                client_id: env.client_id.clone(),
                client_secret: None,
                client_assertion_type: Some(CLIENT_ASSERTION_TYPE.to_string()),
                client_assertion: Some(assertion),
                resource: None,
                scope: None,
                dpop_jkt: None,
            },
        )
        .expect_err("assertion with lifetime > 5 min must be rejected");

    assert!(
        matches!(err, IdentityError::InvalidClientAssertion { .. }),
        "expected InvalidClientAssertion, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// PKJ-12: private_key_jwt client bypasses assertion in auth code flow → rejected
// ---------------------------------------------------------------------------
// Attack: attacker captures the authorization code and replays it without
// providing client_assertion_type, hoping the server skips client auth.
// The client is registered with ONLY an assertion_public_key and no client_secret,
// so it has no other authentication channel.

#[tokio::test]
async fn auth_code_exchange_without_assertion_rejected_for_pkjwt_client() {
    let harness = common::TestHarness::in_process().await.expect("harness");

    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("pkjwt-bypass-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();

    let auth_key = SigningKey::generate().expect("generate key");
    let pk_b64 = URL_SAFE_NO_PAD.encode(auth_key.public_key_bytes());

    // Register with NO client_secret — private_key_jwt is the only auth channel.
    let client = harness
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "PKJ Auth-Only Client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                trust_level: ClientTrustLevel::FirstParty,
                ..Default::default()
            },
        )
        .expect("register client");

    harness
        .identity()
        .update_client(
            &realm,
            client.client_id(),
            &UpdateClientRequest {
                assertion_public_key: Some(Some(pk_b64)),
                ..Default::default()
            },
        )
        .expect("set assertion_public_key");

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

    let auth = harness
        .identity()
        .authorize(
            &realm,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: REDIRECT_URI.to_string(),
                response_type: "code".to_string(),
                scope: "openid".to_string(),
                state: "s".to_string(),
                nonce: None,
                code_challenge: Some(pkce_challenge(PKCE_VERIFIER)),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                resource: None,
                user_id: user_id.clone(),
                amr_values: vec![],
                response_mode: None,
                request: None,
            },
        )
        .expect("authorize");

    // Attempt the exchange WITHOUT providing client_assertion_type or client_assertion.
    let err = harness
        .identity()
        .exchange_authorization_code(
            &realm,
            &TokenExchangeRequest {
                client_id: client.client_id().clone(),
                code: auth.code().to_string(),
                redirect_uri: REDIRECT_URI.to_string(),
                code_verifier: Some(PKCE_VERIFIER.to_string()),
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
                resource: None,
            },
        )
        .expect_err("private_key_jwt client must authenticate — no assertion should be rejected");

    assert!(
        matches!(err, IdentityError::InvalidClientAssertion { .. }),
        "expected InvalidClientAssertion, got: {err:?}"
    );
}

// ── JWKS-only clients (ported from the removed `fapi_client_auth.rs`) ───────
//
// A client that registered only a JWKS used to count as PUBLIC: assertions
// were verified only against the separate `assertion_public_key`, and
// "public" meant "no stored secret". So such a client could not authenticate
// with its registered keys, and every surface that accepts a public client on
// its `client_id` alone — `/as/par`, the `authorization_code` and
// `refresh_token` arms of `/token` — accepted it with nothing. An assertion
// now verifies against the client's JWKS (ES256 / EdDSA, key chosen by `kid`)
// and a client holding a JWKS is never public. Pinned on both the header-realm
// and `/realms/{name}/…` routes.
mod jwks_only_client {
    use super::common;

    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use base64::Engine as _;
    use hearth::core::{ClientId, RealmId};
    use hearth::identity::{
        AuthorizationRequest, ClientTrustLevel, CodeChallengeMethod, CreateRealmRequest,
        CreateUserRequest, RegisterClientRequest,
    };
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, Ed25519KeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

    const REDIRECT_URI: &str = "https://app.example.com/cb";
    const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    /// S256 of [`PKCE_VERIFIER`] (RFC 7636 Appendix B).
    const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    // ── keys ─────────────────────────────────────────────────────────────────────

    /// A client signing key registered in the client's JWKS.
    enum ClientKey {
        Es256(EcdsaKeyPair),
        EdDsa(Ed25519KeyPair),
    }

    impl ClientKey {
        fn es256() -> Self {
            let rng = SystemRandom::new();
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .expect("test setup");
            Self::Es256(
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                    .expect("test setup"),
            )
        }

        fn eddsa() -> Self {
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("test setup");
            Self::EdDsa(Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("test setup"))
        }

        fn alg(&self) -> &'static str {
            match self {
                Self::Es256(_) => "ES256",
                Self::EdDsa(_) => "EdDSA",
            }
        }

        fn kid(&self) -> &'static str {
            match self {
                Self::Es256(_) => "client-es256",
                Self::EdDsa(_) => "client-eddsa",
            }
        }

        /// The public key as a JWK (no `kid`/`alg`).
        fn public_jwk(&self) -> serde_json::Value {
            match self {
                Self::Es256(k) => {
                    let p = k.public_key().as_ref();
                    serde_json::json!({
                        "crv": "P-256", "kty": "EC",
                        "x": URL_SAFE_NO_PAD.encode(&p[1..33]),
                        "y": URL_SAFE_NO_PAD.encode(&p[33..65]),
                    })
                }
                Self::EdDsa(k) => serde_json::json!({
                    "crv": "Ed25519", "kty": "OKP",
                    "x": URL_SAFE_NO_PAD.encode(k.public_key().as_ref()),
                }),
            }
        }

        /// A one-key JWKS for registration.
        fn jwks(&self) -> String {
            let mut jwk = self.public_jwk();
            jwk["kid"] = serde_json::json!(self.kid());
            jwk["alg"] = serde_json::json!(self.alg());
            jwk["use"] = serde_json::json!("sig");
            serde_json::json!({ "keys": [jwk] }).to_string()
        }

        fn sign(&self, data: &[u8]) -> Vec<u8> {
            match self {
                Self::Es256(k) => k
                    .sign(&SystemRandom::new(), data)
                    .expect("test setup")
                    .as_ref()
                    .to_vec(),
                Self::EdDsa(k) => k.sign(data).as_ref().to_vec(),
            }
        }

        fn jws(&self, header: &serde_json::Value, claims: &serde_json::Value) -> String {
            let input = format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(header.to_string()),
                URL_SAFE_NO_PAD.encode(claims.to_string())
            );
            let sig = self.sign(input.as_bytes());
            format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig))
        }

        /// A `private_key_jwt` client assertion (RFC 7523 §2.2).
        fn assertion(&self, client: &ClientId, aud: &str) -> String {
            let now = now_secs();
            self.jws(
                &serde_json::json!({"alg": self.alg(), "kid": self.kid(), "typ": "JWT"}),
                &serde_json::json!({
                    "iss": client.as_uuid().to_string(),
                    "sub": client.as_uuid().to_string(),
                    "aud": aud,
                    "exp": now + 60,
                    "iat": now,
                    "jti": uuid::Uuid::new_v4().to_string(),
                }),
            )
        }

        /// A DPoP proof (RFC 9449) for `POST htu`.
        fn dpop(&self, htu: &str, nonce: &str) -> String {
            self.jws(
                &serde_json::json!({"alg": self.alg(), "typ": "dpop+jwt", "jwk": self.public_jwk()}),
                &serde_json::json!({
                    "htm": "POST",
                    "htu": htu,
                    "iat": now_secs(),
                    "jti": uuid::Uuid::new_v4().to_string(),
                    "nonce": nonce,
                }),
            )
        }
    }

    fn now_secs() -> i64 {
        i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("test setup")
                .as_secs(),
        )
        .expect("test setup")
    }

    // ── environment ──────────────────────────────────────────────────────────────

    struct Env {
        h: common::TestHarness,
        base: String,
        realm_name: String,
        realm_id: RealmId,
        /// The realm issuer: the `aud` of client assertions.
        issuer: String,
    }

    async fn env() -> Env {
        let h = common::TestHarness::server().await.expect("server harness");
        let base = h.base_url().expect("base_url").to_string();
        let realm_name = format!("jwks-auth-{}", uuid::Uuid::new_v4());
        let realm_id = h
            .identity()
            .create_realm(&CreateRealmRequest {
                name: realm_name.clone(),
                config: None,
            })
            .expect("create realm")
            .id()
            .clone();
        let issuer = format!(
            "{}/realms/{realm_name}",
            h.identity().oidc_discovery().issuer
        );
        Env {
            h,
            base,
            realm_name,
            realm_id,
            issuer,
        }
    }

    impl Env {
        fn register(&self, req: RegisterClientRequest) -> ClientId {
            self.h
                .identity()
                .register_client(
                    &self.realm_id,
                    &RegisterClientRequest {
                        client_name: format!("jwks-client-{}", uuid::Uuid::new_v4()),
                        redirect_uris: vec![REDIRECT_URI.to_string()],
                        require_consent: false,
                        // First-party: `client_credentials` without a scope.
                        trust_level: ClientTrustLevel::FirstParty,
                        ..req
                    },
                )
                .expect("register client")
                .client_id()
                .clone()
        }

        /// A client that registered only a JWKS — no secret, no separate
        /// assertion key.
        fn jwks_only_client(&self, key: &ClientKey) -> ClientId {
            self.register(RegisterClientRequest {
                jwks: Some(key.jwks()),
                grant_types: vec![
                    "authorization_code".to_string(),
                    "refresh_token".to_string(),
                    "client_credentials".to_string(),
                ],
                ..Default::default()
            })
        }

        fn url(&self, route: Route, endpoint: &str) -> String {
            match route {
                Route::Header => format!("{}/{endpoint}", self.base),
                Route::Realm => format!("{}/realms/{}/{endpoint}", self.base, self.realm_name),
            }
        }

        /// The `htu` the server expects in a token-endpoint DPoP proof.
        fn token_htu(&self, route: Route) -> String {
            match route {
                Route::Header => self.h.identity().oidc_discovery().token_endpoint,
                Route::Realm => format!("{}/token", self.issuer),
            }
        }

        /// An authorization code for `client`.
        async fn code(&self, client: &ClientId) -> String {
            let user = self
                .h
                .identity()
                .create_user(
                    &self.realm_id,
                    &CreateUserRequest {
                        email: format!("jwks-{}@example.com", uuid::Uuid::new_v4()),
                        display_name: "JWKS user".to_string(),
                        ..Default::default()
                    },
                )
                .expect("create user")
                .id()
                .clone();
            self.h
                .identity()
                .authorize(
                    &self.realm_id,
                    &AuthorizationRequest {
                        client_id: client.clone(),
                        redirect_uri: REDIRECT_URI.to_string(),
                        response_type: "code".to_string(),
                        scope: "openid".to_string(),
                        state: "jwks-state".to_string(),
                        nonce: None,
                        code_challenge: Some(PKCE_CHALLENGE.to_string()),
                        code_challenge_method: Some(CodeChallengeMethod::S256),
                        resource: None,
                        user_id: user,
                        amr_values: vec![],
                        response_mode: None,
                        request: None,
                    },
                )
                .expect("authorize")
                .code()
                .to_string()
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum Route {
        /// `POST /{endpoint}` with `X-Realm-ID`.
        Header,
        /// `POST /realms/{name}/{endpoint}`.
        Realm,
    }

    const ROUTES: [Route; 2] = [Route::Header, Route::Realm];

    struct Answer {
        status: u16,
        body: serde_json::Value,
    }

    /// POSTs a form to `url`; `basic` adds `client_secret_basic` credentials and
    /// `dpop` a `DPoP` header.
    async fn post(
        env: &Env,
        route: Route,
        endpoint: &str,
        form: &[(&str, String)],
        basic: Option<(&ClientId, &str)>,
        dpop: Option<&ClientKey>,
    ) -> Answer {
        let client = reqwest::Client::new();
        let url = env.url(route, endpoint);
        let mut nonce = String::new();
        if dpop.is_some() {
            // Every token response carries the current DPoP-Nonce (RFC 9449 §9).
            let mut probe = client.post(&url).form(&[("grant_type", "nonce-probe")]);
            if matches!(route, Route::Header) {
                probe = probe.header("X-Realm-ID", env.realm_id.as_uuid().to_string());
            }
            let resp = probe.send().await.expect("nonce probe");
            nonce = resp
                .headers()
                .get("DPoP-Nonce")
                .and_then(|v| v.to_str().ok())
                .expect("token responses carry DPoP-Nonce")
                .to_string();
        }
        let mut req = client.post(&url).form(form);
        if matches!(route, Route::Header) {
            req = req.header("X-Realm-ID", env.realm_id.as_uuid().to_string());
        }
        if let Some((id, secret)) = basic {
            req = req.header(
                "Authorization",
                format!(
                    "Basic {}",
                    STANDARD.encode(format!("{}:{secret}", id.as_uuid()))
                ),
            );
        }
        if let Some(key) = dpop {
            req = req.header("DPoP", key.dpop(&env.token_htu(route), &nonce));
        }
        let resp = req.send().await.expect("request");
        let status = resp.status().as_u16();
        let body = resp.json().await.unwrap_or(serde_json::Value::Null);
        Answer { status, body }
    }

    fn assert_invalid_client(a: &Answer, what: &str) {
        assert_eq!(
            a.status, 401,
            "{what}: expected 401 invalid_client, got {} {}",
            a.status, a.body
        );
        assert_eq!(a.body["error"], "invalid_client", "{what}: {}", a.body);
    }

    /// The `private_key_jwt` fields (the caller adds `client_id` when its form
    /// has none).
    fn assertion_form(
        key: &ClientKey,
        client: &ClientId,
        aud: &str,
    ) -> Vec<(&'static str, String)> {
        vec![
            ("client_assertion_type", CLIENT_ASSERTION_TYPE.to_string()),
            ("client_assertion", key.assertion(client, aud)),
        ]
    }

    /// A client id as a form field: the bare UUID.
    fn id(client: &ClientId) -> String {
        client.as_uuid().to_string()
    }

    fn par_form(client: &ClientId) -> Vec<(&'static str, String)> {
        vec![
            ("client_id", id(client)),
            ("redirect_uri", REDIRECT_URI.to_string()),
            ("scope", "openid".to_string()),
            ("state", "par-state".to_string()),
            ("response_type", "code".to_string()),
            ("code_challenge", PKCE_CHALLENGE.to_string()),
            ("code_challenge_method", "S256".to_string()),
        ]
    }

    fn code_form(client: &ClientId, code: String) -> Vec<(&'static str, String)> {
        vec![
            ("grant_type", "authorization_code".to_string()),
            ("client_id", id(client)),
            ("code", code),
            ("redirect_uri", REDIRECT_URI.to_string()),
            ("code_verifier", PKCE_VERIFIER.to_string()),
        ]
    }

    /// Presenting nothing but its `client_id`, a JWKS-only client is refused at PAR and at every token-endpoint arm that used to take it for a
    /// public client.
    #[tokio::test]
    async fn a_jwks_only_client_presenting_nothing_is_refused() {
        let env = env().await;
        let key = ClientKey::es256();
        let client = env.jwks_only_client(&key);
        for route in ROUTES {
            let a = post(&env, route, "as/par", &par_form(&client), None, None).await;
            assert_invalid_client(&a, &format!("{route:?} /as/par, client_id only"));

            let code = env.code(&client).await;
            let a = post(
                &env,
                route,
                "token",
                &code_form(&client, code),
                None,
                Some(&key),
            )
            .await;
            assert_invalid_client(
                &a,
                &format!("{route:?} /token authorization_code, client_id only"),
            );

            let a = post(
                &env,
                route,
                "token",
                &[
                    ("grant_type", "client_credentials".to_string()),
                    ("client_id", id(&client)),
                ],
                None,
                Some(&key),
            )
            .await;
            assert_invalid_client(
                &a,
                &format!("{route:?} /token client_credentials, client_id only"),
            );
        }
    }

    /// With an assertion signed by a key from its registered JWKS — ES256 or
    /// EdDSA, chosen by `kid` — the same client authenticates at PAR and at the
    /// token endpoint, and can refresh with an assertion but not without one.
    #[tokio::test]
    async fn a_jwks_only_client_authenticates_with_its_jwks() {
        for key in [ClientKey::es256(), ClientKey::eddsa()] {
            let env = env().await;
            let client = env.jwks_only_client(&key);
            for route in ROUTES {
                let what = format!("{route:?} {}", key.alg());
                let mut form = par_form(&client);
                form.extend(assertion_form(&key, &client, &env.issuer));
                let a = post(&env, route, "as/par", &form, None, None).await;
                assert_eq!(a.status, 201, "{what} /as/par with assertion: {}", a.body);

                let code = env.code(&client).await;
                let mut form = code_form(&client, code);
                form.extend(assertion_form(&key, &client, &env.issuer));
                let a = post(&env, route, "token", &form, None, Some(&key)).await;
                assert_eq!(
                    a.status, 200,
                    "{what} /token authorization_code with assertion: {}",
                    a.body
                );
                let refresh = a.body["refresh_token"]
                    .as_str()
                    .expect("test setup")
                    .to_string();

                let a = post(
                    &env,
                    route,
                    "token",
                    &[
                        ("grant_type", "refresh_token".to_string()),
                        ("client_id", id(&client)),
                        ("refresh_token", refresh.clone()),
                    ],
                    None,
                    Some(&key),
                )
                .await;
                assert_invalid_client(&a, &format!("{what} /token refresh_token, client_id only"));

                let mut form = vec![
                    ("grant_type", "refresh_token".to_string()),
                    ("client_id", id(&client)),
                    ("refresh_token", refresh),
                ];
                form.extend(assertion_form(&key, &client, &env.issuer));
                let a = post(&env, route, "token", &form, None, Some(&key)).await;
                assert_eq!(
                    a.status, 200,
                    "{what} /token refresh_token with assertion: {}",
                    a.body
                );

                let mut form = vec![
                    ("grant_type", "client_credentials".to_string()),
                    ("client_id", id(&client)),
                ];
                form.extend(assertion_form(&key, &client, &env.issuer));
                let a = post(&env, route, "token", &form, None, Some(&key)).await;
                assert_eq!(
                    a.status, 200,
                    "{what} /token client_credentials with assertion: {}",
                    a.body
                );
            }
        }
    }

    /// An assertion signed by a key the client did not register is refused.
    #[tokio::test]
    async fn an_assertion_signed_by_an_unregistered_key_is_refused() {
        let env = env().await;
        let key = ClientKey::es256();
        let client = env.jwks_only_client(&key);
        let stranger = ClientKey::es256();
        for route in ROUTES {
            let mut form = par_form(&client);
            form.extend(assertion_form(&stranger, &client, &env.issuer));
            let a = post(&env, route, "as/par", &form, None, None).await;
            assert_invalid_client(&a, &format!("{route:?} /as/par, foreign key"));
        }
    }
}
