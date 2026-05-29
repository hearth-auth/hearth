//! FAPI 2.0 Security Profile — per-client (`ClientProfile::Fapi2`) conformance tests.
//!
//! These tests exercise the client-level FAPI 2.0 enforcement rules:
//!
//! - FAPI2-REG-01: client_secret rejected at registration for FAPI2 clients
//! - FAPI2-REG-02: No JWKS rejected at registration for FAPI2 clients
//! - FAPI2-REG-03: FAPI2 client registration with JWKS succeeds
//! - FAPI2-AUTH-01: Direct /authorize (no PAR) rejected for FAPI2 clients
//! - FAPI2-AUTH-02: PAR-based authorization accepted for FAPI2 clients
//! - FAPI2-TOKEN-01: Token exchange without DPoP rejected for FAPI2 clients
//! - FAPI2-TOKEN-02: Token exchange with DPoP accepted for FAPI2 clients
//! - FAPI2-JARM-01: JARM response includes s_hash for FAPI2 clients with state
//! - FAPI2-JARM-02: JARM response does NOT include s_hash for standard clients
//! - FAPI2-STD-01: Standard clients not subject to FAPI2 constraints
//!
//! Spec refs:
//!   FAPI 2.0 Security Profile 1.0, RFC 9126 (PAR), RFC 9449 (DPoP), JARM
//!
//! Test vectors: tests/fixtures/fapi2/conformance_vectors.json

#![allow(clippy::unwrap_used)]

mod common;

use base64::prelude::{Engine as _, BASE64_URL_SAFE_NO_PAD};
use hearth::core::RealmId;
use hearth::identity::oidc::{ClientProfile, CodeChallengeMethod, ResponseMode};
use hearth::identity::{
    AuthorizationRequest, CreateRealmRequest, CreateUserRequest, IdentityError,
    RegisterClientRequest, TokenExchangeRequest,
};

// ── Constants ──────────────────────────────────────────────────────────────────

const REDIRECT_URI: &str = "https://app.example.com/callback";
const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

fn pkce_challenge() -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(PKCE_VERIFIER.as_bytes());
    BASE64_URL_SAFE_NO_PAD.encode(hash.as_slice())
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/// Minimal JWKS JSON for registration (key details not verified in these tests).
fn minimal_jwks() -> String {
    r#"{"keys":[{"kty":"OKP","use":"sig","alg":"EdDSA","crv":"Ed25519","kid":"fapi2-test"}]}"#
        .to_string()
}

async fn create_realm(h: &common::TestHarness) -> RealmId {
    h.identity()
        .create_realm(&CreateRealmRequest {
            name: format!("fapi2-test-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone()
}

/// Registers a FAPI2 client (with JWKS, no client_secret).
fn register_fapi2_client(h: &common::TestHarness, realm: &RealmId) -> hearth::core::ClientId {
    h.identity()
        .register_client(
            realm,
            &RegisterClientRequest {
                client_name: "FAPI2 Test Client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                jwks: Some(minimal_jwks()),
                profile: ClientProfile::Fapi2,
                ..Default::default()
            },
        )
        .expect("register FAPI2 client")
        .client_id()
        .clone()
}

/// Registers a standard (non-FAPI2) client.
fn register_std_client(h: &common::TestHarness, realm: &RealmId) -> hearth::core::ClientId {
    h.identity()
        .register_client(
            realm,
            &RegisterClientRequest {
                client_name: "Standard Test Client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: Some("test-secret".to_string()),
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("register standard client")
        .client_id()
        .clone()
}

async fn create_user(h: &common::TestHarness, realm: &RealmId) -> hearth::core::UserId {
    h.identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("fapi2-user-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "FAPI2 User".to_string(),
                ..Default::default()
            },
        )
        .expect("create user")
        .id()
        .clone()
}

// ── FAPI2-REG: Registration constraints ──────────────────────────────────────

/// FAPI2-REG-01: FAPI2 client registration with client_secret rejected.
/// Spec: FAPI 2.0 §5.3.1.1 — only private_key_jwt or mTLS allowed.
#[tokio::test]
async fn fapi2_reg01_client_secret_rejected() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm(&h).await;

    let err = h
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "FAPI2 Bad Client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: Some("should-be-rejected".to_string()),
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                jwks: Some(minimal_jwks()),
                profile: ClientProfile::Fapi2,
                ..Default::default()
            },
        )
        .expect_err("FAPI2 client with client_secret must be rejected");

    assert!(
        matches!(err, IdentityError::FapiViolation { .. }),
        "expected FapiViolation, got: {err:?}"
    );
}

/// FAPI2-REG-02: FAPI2 client registration without JWKS rejected.
/// Spec: FAPI 2.0 §5.3.1.1 — clients must register a JWKS.
#[tokio::test]
async fn fapi2_reg02_no_jwks_rejected() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm(&h).await;

    let err = h
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "FAPI2 No-JWKS Client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                jwks: None,
                jwks_uri: None,
                profile: ClientProfile::Fapi2,
                ..Default::default()
            },
        )
        .expect_err("FAPI2 client without JWKS must be rejected");

    assert!(
        matches!(err, IdentityError::FapiViolation { .. }),
        "expected FapiViolation, got: {err:?}"
    );
}

/// FAPI2-REG-03: FAPI2 client registration with JWKS succeeds.
/// Spec: FAPI 2.0 §5.3.1.1
#[tokio::test]
async fn fapi2_reg03_with_jwks_succeeds() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm(&h).await;

    let client = h
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "FAPI2 Valid Client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                jwks: Some(minimal_jwks()),
                profile: ClientProfile::Fapi2,
                ..Default::default()
            },
        )
        .expect("FAPI2 registration with JWKS must succeed");

    assert_eq!(
        client.profile(),
        ClientProfile::Fapi2,
        "registered client must have Fapi2 profile"
    );
}

// ── FAPI2-AUTH: PAR enforcement ──────────────────────────────────────────────

/// FAPI2-AUTH-01: Direct /authorize (no PAR) rejected for FAPI2 clients.
/// Spec: FAPI 2.0 §5.3.2 — PAR mandatory.
#[tokio::test]
async fn fapi2_auth01_direct_authorize_rejected() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm(&h).await;
    let client_id = register_fapi2_client(&h, &realm);
    let user_id = create_user(&h, &realm).await;

    let err = h
        .identity()
        .authorize(
            &realm,
            &AuthorizationRequest {
                client_id: client_id.clone(),
                redirect_uri: REDIRECT_URI.to_string(),
                response_type: "code".to_string(),
                scope: "openid".to_string(),
                state: "fapi2-state".to_string(),
                nonce: None,
                code_challenge: Some(pkce_challenge()),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                resource: None,
                user_id,
                amr_values: vec![],
                response_mode: None,
                request: None,
                via_par: false, // direct authorize, no PAR
            },
        )
        .expect_err("FAPI2 client direct /authorize must be rejected");

    assert!(
        matches!(err, IdentityError::FapiViolation { .. }),
        "expected FapiViolation for direct authorize, got: {err:?}"
    );
}

/// FAPI2-AUTH-02: PAR-based authorization accepted for FAPI2 clients.
/// Spec: FAPI 2.0 §5.3.2
#[tokio::test]
async fn fapi2_auth02_par_based_authorize_accepted() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm(&h).await;
    let client_id = register_fapi2_client(&h, &realm);
    let user_id = create_user(&h, &realm).await;

    let resp = h
        .identity()
        .authorize(
            &realm,
            &AuthorizationRequest {
                client_id: client_id.clone(),
                redirect_uri: REDIRECT_URI.to_string(),
                response_type: "code".to_string(),
                scope: "openid".to_string(),
                state: "fapi2-state".to_string(),
                nonce: None,
                code_challenge: Some(pkce_challenge()),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                resource: None,
                user_id,
                amr_values: vec![],
                response_mode: None,
                request: None,
                via_par: true, // simulates PAR consumption
            },
        )
        .expect("FAPI2 PAR-based authorize must succeed");

    assert!(
        !resp.code().is_empty(),
        "authorization code must be non-empty"
    );
}

// ── FAPI2-TOKEN: DPoP enforcement ────────────────────────────────────────────

/// FAPI2-TOKEN-01: Token exchange without DPoP rejected for FAPI2 clients.
/// Spec: FAPI 2.0 §5.3.3 — sender-constrained tokens mandatory.
#[tokio::test]
async fn fapi2_token01_no_dpop_rejected() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm(&h).await;
    let client_id = register_fapi2_client(&h, &realm);
    let user_id = create_user(&h, &realm).await;

    let auth_resp = h
        .identity()
        .authorize(
            &realm,
            &AuthorizationRequest {
                client_id: client_id.clone(),
                redirect_uri: REDIRECT_URI.to_string(),
                response_type: "code".to_string(),
                scope: "openid".to_string(),
                state: "token-test-state".to_string(),
                nonce: None,
                code_challenge: Some(pkce_challenge()),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                resource: None,
                user_id,
                amr_values: vec![],
                response_mode: None,
                request: None,
                via_par: true,
            },
        )
        .expect("authorize");

    let err = h
        .identity()
        .exchange_authorization_code(
            &realm,
            &TokenExchangeRequest {
                client_id: client_id.clone(),
                code: auth_resp.code().to_string(),
                redirect_uri: REDIRECT_URI.to_string(),
                code_verifier: Some(PKCE_VERIFIER.to_string()),
                dpop_jkt: None, // no DPoP
                client_assertion_type: None,
                client_assertion: None,
            },
        )
        .expect_err("FAPI2 token exchange without DPoP must fail");

    assert!(
        matches!(err, IdentityError::FapiViolation { .. }),
        "expected FapiViolation for missing DPoP, got: {err:?}"
    );
}

/// FAPI2-TOKEN-02: Token exchange with DPoP accepted for FAPI2 clients.
/// Spec: FAPI 2.0 §5.3.3
#[tokio::test]
async fn fapi2_token02_with_dpop_accepted() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm(&h).await;
    let client_id = register_fapi2_client(&h, &realm);
    let user_id = create_user(&h, &realm).await;

    let auth_resp = h
        .identity()
        .authorize(
            &realm,
            &AuthorizationRequest {
                client_id: client_id.clone(),
                redirect_uri: REDIRECT_URI.to_string(),
                response_type: "code".to_string(),
                scope: "openid".to_string(),
                state: "dpop-state".to_string(),
                nonce: None,
                code_challenge: Some(pkce_challenge()),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                resource: None,
                user_id,
                amr_values: vec![],
                response_mode: None,
                request: None,
                via_par: true,
            },
        )
        .expect("authorize");

    let token_resp = h
        .identity()
        .exchange_authorization_code(
            &realm,
            &TokenExchangeRequest {
                client_id: client_id.clone(),
                code: auth_resp.code().to_string(),
                redirect_uri: REDIRECT_URI.to_string(),
                code_verifier: Some(PKCE_VERIFIER.to_string()),
                dpop_jkt: Some("abc123_thumbprint".to_string()),
                client_assertion_type: None,
                client_assertion: None,
            },
        )
        .expect("FAPI2 token exchange with DPoP must succeed");

    assert!(
        !token_resp.access_token().is_empty(),
        "access token must be non-empty"
    );
}

// ── FAPI2-JARM: s_hash enforcement ──────────────────────────────────────────

/// FAPI2-JARM-01: JARM response includes s_hash for FAPI2 clients with state.
/// Spec: FAPI 2.0 §5.3.2.3 — s_hash = BASE64URL(LEFT(SHA-256(state), 16))
#[tokio::test]
async fn fapi2_jarm01_s_hash_present_for_fapi2_client() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm(&h).await;
    let user_id = create_user(&h, &realm).await;

    // FAPI2 client must have authorization_signed_response_alg to get JARM.
    let client_id = h
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "FAPI2 JARM Client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                jwks: Some(minimal_jwks()),
                authorization_signed_response_alg: Some("EdDSA".to_string()),
                profile: ClientProfile::Fapi2,
                ..Default::default()
            },
        )
        .expect("register FAPI2 JARM client")
        .client_id()
        .clone();

    let state = "test-state-value";
    let resp = h
        .identity()
        .authorize(
            &realm,
            &AuthorizationRequest {
                client_id,
                redirect_uri: REDIRECT_URI.to_string(),
                response_type: "code".to_string(),
                scope: "openid".to_string(),
                state: state.to_string(),
                nonce: None,
                code_challenge: Some(pkce_challenge()),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                resource: None,
                user_id,
                amr_values: vec![],
                response_mode: Some(ResponseMode::QueryJwt),
                request: None,
                via_par: true,
            },
        )
        .expect("authorize FAPI2 JARM");

    let jwt = resp
        .jarm_jwt()
        .expect("JARM JWT must be present for JARM-enabled FAPI2 client");

    // Decode claims from the JARM JWT.
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3, "JARM JWT must be a 3-part JWS");
    let claims_json = BASE64_URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("decode claims");
    let claims: serde_json::Value = serde_json::from_slice(&claims_json).expect("parse claims");

    assert!(
        claims["s_hash"].is_string(),
        "FAPI2 JARM response must include s_hash when state is present; got: {claims}"
    );

    // Verify s_hash = BASE64URL(LEFT(SHA-256(state), 16)).
    let expected = {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(state.as_bytes());
        BASE64_URL_SAFE_NO_PAD.encode(&hash[..16])
    };
    assert_eq!(
        claims["s_hash"].as_str().unwrap_or(""),
        expected,
        "s_hash must equal BASE64URL(LEFT(SHA-256(state), 16))"
    );
}

/// FAPI2-JARM-02: JARM response does NOT include s_hash for standard clients.
/// Spec: s_hash is FAPI2-only.
#[tokio::test]
async fn fapi2_jarm02_no_s_hash_for_standard_client() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm(&h).await;
    let user_id = create_user(&h, &realm).await;

    // Standard client with JARM enabled (but NOT FAPI2 profile).
    let client_id = h
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "Standard JARM Client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: Some("secret".to_string()),
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                authorization_signed_response_alg: Some("EdDSA".to_string()),
                profile: ClientProfile::Standard, // not FAPI2
                ..Default::default()
            },
        )
        .expect("register standard JARM client")
        .client_id()
        .clone();

    let resp = h
        .identity()
        .authorize(
            &realm,
            &AuthorizationRequest {
                client_id,
                redirect_uri: REDIRECT_URI.to_string(),
                response_type: "code".to_string(),
                scope: "openid".to_string(),
                state: "test-state-value".to_string(),
                nonce: None,
                code_challenge: Some(pkce_challenge()),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                resource: None,
                user_id,
                amr_values: vec![],
                response_mode: Some(ResponseMode::QueryJwt),
                request: None,
                via_par: false,
            },
        )
        .expect("authorize standard JARM");

    let jwt = resp
        .jarm_jwt()
        .expect("JARM JWT must be present for JARM-enabled client");

    let parts: Vec<&str> = jwt.split('.').collect();
    let claims_json = BASE64_URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("decode claims");
    let claims: serde_json::Value = serde_json::from_slice(&claims_json).expect("parse claims");

    assert!(
        claims["s_hash"].is_null() || !claims["s_hash"].is_string(),
        "standard client JARM response must NOT include s_hash; got: {claims}"
    );
}

// ── FAPI2-STD-01: Standard clients unaffected ────────────────────────────────

/// FAPI2-STD-01: Standard clients are not subject to FAPI2 constraints.
/// Spec: Standard profile has no additional restrictions.
#[tokio::test]
async fn fapi2_std01_standard_client_not_restricted() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm(&h).await;
    let client_id = register_std_client(&h, &realm);
    let user_id = create_user(&h, &realm).await;

    // Standard client: direct authorize (no PAR) with no DPoP — all should succeed.
    let auth_resp = h
        .identity()
        .authorize(
            &realm,
            &AuthorizationRequest {
                client_id: client_id.clone(),
                redirect_uri: REDIRECT_URI.to_string(),
                response_type: "code".to_string(),
                scope: "openid".to_string(),
                state: "std-state".to_string(),
                nonce: None,
                code_challenge: Some(pkce_challenge()),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                resource: None,
                user_id,
                amr_values: vec![],
                response_mode: None,
                request: None,
                via_par: false, // no PAR — allowed for standard clients
            },
        )
        .expect("standard client direct authorize must succeed");

    let token_resp = h
        .identity()
        .exchange_authorization_code(
            &realm,
            &TokenExchangeRequest {
                client_id,
                code: auth_resp.code().to_string(),
                redirect_uri: REDIRECT_URI.to_string(),
                code_verifier: Some(PKCE_VERIFIER.to_string()),
                dpop_jkt: None, // no DPoP — allowed for standard clients
                client_assertion_type: None,
                client_assertion: None,
            },
        )
        .expect("standard client token exchange without DPoP must succeed");

    assert!(
        !token_resp.access_token().is_empty(),
        "standard client must receive an access token"
    );
}
