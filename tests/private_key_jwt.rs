//! Integration tests for `private_key_jwt` client authentication (RFC 7523 §2.2 / FAPI 2.0).
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
    let harness = common::TestHarness::embedded().await.expect("harness");

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
    let harness = common::TestHarness::embedded().await.expect("harness");

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
        &env.client_id.to_string(),
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
                via_par: false,
            },
        )
        .expect("authorize");

    let assertion = make_assertion(
        &env.auth_key,
        &env.client_id.to_string(),
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
        &env.client_id.to_string(),
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
        &env.client_id.to_string(),
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
        &env.client_id.to_string(),
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
        &env.client_id.to_string(),
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
    let harness = common::TestHarness::embedded().await.expect("harness");

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
        &client.client_id().to_string(),
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
    let harness = common::TestHarness::embedded().await.expect("harness");

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
        iss: env.client_id.to_string(),
        sub: env.client_id.to_string(),
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
        &env.client_id.to_string(),
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
    let harness = common::TestHarness::embedded().await.expect("harness");

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
                via_par: false,
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
            },
        )
        .expect_err("private_key_jwt client must authenticate — no assertion should be rejected");

    assert!(
        matches!(err, IdentityError::InvalidClientAssertion { .. }),
        "expected InvalidClientAssertion, got: {err:?}"
    );
}
