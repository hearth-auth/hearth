//! FAPI 2.0 Security Profile — conformance harness.
//!
//! Tests realm-level `fapi_profile` enforcement for both Baseline and Advanced.
//!
//! # Scenario index
//!
//! ## Baseline (FAPI-B)
//! - FAPI-B-01: Missing PKCE rejected in PAR under Baseline
//! - FAPI-B-02: Direct authorize without PAR rejected under Baseline
//! - FAPI-B-03: Valid Baseline request (PAR + PKCE) accepted
//! - FAPI-B-04: Discovery advertises `fapi_profile = "baseline"`
//!
//! ## Advanced (FAPI-A)
//! - FAPI-A-01: Missing JAR rejected under Advanced
//! - FAPI-A-02: Client without JWKS rejected (private_key_jwt requirement)
//! - FAPI-A-03: Client without JARM config rejected under Advanced
//! - FAPI-A-04: Valid Advanced request (PAR + PKCE + JAR + JARM client) accepted
//! - FAPI-A-05: Discovery advertises `fapi_profile = "advanced"`

#![allow(clippy::unwrap_used)]

mod common;

use base64::Engine as _;
use hearth::core::{ClientId, RealmId, UserId};
use hearth::identity::oidc::CodeChallengeMethod;
use hearth::identity::{
    AuthorizationRequest, CreateRealmRequest, CreateUserRequest, FapiProfile, IdentityError,
    PushedAuthorizationRequest, RegisterClientRequest, UpdateRealmRequest,
};

// ── Constants ──────────────────────────────────────────────────────────────────

const REDIRECT_URI: &str = "https://app.example.com/callback";
const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

// ── Test environment ───────────────────────────────────────────────────────────

struct Env {
    harness: common::TestHarness,
    realm: RealmId,
    client_id: ClientId,
    user_id: UserId,
}

async fn setup_with_profile(profile: FapiProfile) -> Env {
    let harness = common::TestHarness::embedded().await.expect("harness");

    let realm_rec = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("fapi-{}-{}", profile_str(profile), uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");
    let realm = realm_rec.id().clone();

    // Apply FAPI profile to the realm config.
    let mut config = realm_rec.config().clone();
    config.fapi_profile = Some(profile);
    harness
        .identity()
        .update_realm(
            &realm,
            &UpdateRealmRequest {
                config: Some(config),
                ..Default::default()
            },
        )
        .expect("update realm config");

    let client = harness
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "FAPI Test Client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: Some("test-secret".to_string()),
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("register client");

    let user_id = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("user-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "FAPI User".to_string(),
                ..Default::default()
            },
        )
        .expect("create user")
        .id()
        .clone();

    Env {
        harness,
        realm,
        client_id: client.client_id().clone(),
        user_id,
    }
}

fn profile_str(p: FapiProfile) -> &'static str {
    match p {
        FapiProfile::Baseline => "baseline",
        FapiProfile::Advanced => "advanced",
        _ => "unknown",
    }
}

/// Returns a minimal valid PAR request with PKCE.
fn par_with_pkce(client_id: &ClientId) -> PushedAuthorizationRequest {
    PushedAuthorizationRequest {
        client_id: client_id.clone(),
        redirect_uri: REDIRECT_URI.to_string(),
        scope: "openid".to_string(),
        state: "fapi-state".to_string(),
        resource: None,
        response_type: "code".to_string(),
        code_challenge: Some(PKCE_CHALLENGE.to_string()),
        code_challenge_method: Some(CodeChallengeMethod::S256),
        nonce: Some("fapi-nonce".to_string()),
        request: None,
    }
}

/// Returns a minimal valid PAR request without PKCE.
fn par_without_pkce(client_id: &ClientId) -> PushedAuthorizationRequest {
    PushedAuthorizationRequest {
        client_id: client_id.clone(),
        redirect_uri: REDIRECT_URI.to_string(),
        scope: "openid".to_string(),
        state: "fapi-state".to_string(),
        resource: None,
        response_type: "code".to_string(),
        code_challenge: None,
        code_challenge_method: None,
        nonce: None,
        request: None,
    }
}

// ── Ed25519 JAR helpers ────────────────────────────────────────────────────────

fn generate_ed25519() -> (Vec<u8>, Vec<u8>) {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).expect("keygen");
    let pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("from_pkcs8");
    let pub_bytes = ring::signature::KeyPair::public_key(&pair)
        .as_ref()
        .to_vec();
    (pkcs8.as_ref().to_vec(), pub_bytes)
}

fn jwks_json(pub_bytes: &[u8]) -> String {
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pub_bytes);
    format!(
        r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","kid":"fapi-key","x":"{x}"}}]}}"#
    )
}

/// Signs a minimal JAR JWT for the given client + realm issuer.
fn sign_jar(pkcs8_bytes: &[u8], client_id: &str, issuer: &str) -> String {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let header = serde_json::json!({"alg": "EdDSA", "kid": "fapi-key"});
    let claims = serde_json::json!({
        "iss": client_id,
        "aud": issuer,
        "exp": now + 300,
        "iat": now,
        "jti": uuid::Uuid::new_v4().to_string(),
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": "openid",
        "state": "jar-state",
        "code_challenge": PKCE_CHALLENGE,
        "code_challenge_method": "S256"
    });

    let header_b64 = b64.encode(serde_json::to_vec(&header).unwrap());
    let claims_b64 = b64.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{header_b64}.{claims_b64}");

    let pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes).unwrap();
    // Ed25519KeyPair::sign is a method on the concrete type, not the KeyPair trait.
    let sig = pair.sign(signing_input.as_bytes());
    let sig_b64 = b64.encode(sig.as_ref());

    format!("{signing_input}.{sig_b64}")
}

/// Builds an `AuthorizationRequest` from a `PushedAuthorizationRequest`, setting
/// `via_par = true`. Used to simulate the web layer consuming a PAR entry.
fn auth_req_from_par(par: &PushedAuthorizationRequest, user_id: UserId) -> AuthorizationRequest {
    AuthorizationRequest {
        client_id: par.client_id.clone(),
        redirect_uri: par.redirect_uri.clone(),
        response_type: par.response_type.clone(),
        scope: par.scope.clone(),
        state: par.state.clone(),
        nonce: par.nonce.clone(),
        code_challenge: par.code_challenge.clone(),
        code_challenge_method: par.code_challenge_method.clone(),
        resource: par.resource.clone(),
        user_id,
        amr_values: vec![],
        response_mode: None,
        // JAR was validated and consumed at PAR time; not re-submitted in authorize.
        request: None,
        via_par: true,
    }
}

// ── FAPI-B: Baseline tests ─────────────────────────────────────────────────────

/// FAPI-B-01: PAR without PKCE is rejected under Baseline.
#[tokio::test]
async fn fapi_b01_par_missing_pkce_rejected() {
    let env = setup_with_profile(FapiProfile::Baseline).await;
    let req = par_without_pkce(&env.client_id);
    let err = env
        .harness
        .identity()
        .push_authorization_request(&env.realm, &req)
        .expect_err("should reject missing PKCE");
    assert!(
        matches!(err, IdentityError::FapiViolation { .. }),
        "expected FapiViolation, got: {err:?}"
    );
}

/// FAPI-B-02: Direct authorize (no PAR, `via_par = false`) rejected under Baseline.
#[tokio::test]
async fn fapi_b02_direct_authorize_without_par_rejected() {
    let env = setup_with_profile(FapiProfile::Baseline).await;
    let req = AuthorizationRequest {
        client_id: env.client_id.clone(),
        redirect_uri: REDIRECT_URI.to_string(),
        response_type: "code".to_string(),
        scope: "openid".to_string(),
        state: "state".to_string(),
        nonce: None,
        code_challenge: Some(PKCE_CHALLENGE.to_string()),
        code_challenge_method: Some(CodeChallengeMethod::S256),
        resource: None,
        user_id: env.user_id.clone(),
        amr_values: vec![],
        response_mode: None,
        request: None,
        via_par: false,
    };
    let err = env
        .harness
        .identity()
        .authorize(&env.realm, &req)
        .expect_err("should reject non-PAR authorize");
    assert!(
        matches!(err, IdentityError::FapiViolation { .. }),
        "expected FapiViolation, got: {err:?}"
    );
}

/// FAPI-B-03: Valid Baseline request (PAR + PKCE) accepted end-to-end.
#[tokio::test]
async fn fapi_b03_valid_baseline_request_accepted() {
    let env = setup_with_profile(FapiProfile::Baseline).await;
    let par_req = par_with_pkce(&env.client_id);

    let par_resp = env
        .harness
        .identity()
        .push_authorization_request(&env.realm, &par_req)
        .expect("PAR should succeed");
    assert!(!par_resp.request_uri.is_empty());

    // Build the authorize request from the original PAR fields (via_par = true).
    let auth_req = auth_req_from_par(&par_req, env.user_id.clone());

    let resp = env
        .harness
        .identity()
        .authorize(&env.realm, &auth_req)
        .expect("authorize should succeed");
    assert!(
        !resp.code().is_empty(),
        "authorization code should be non-empty"
    );
}

/// FAPI-B-04: Discovery document advertises `fapi_profile = "baseline"`.
#[tokio::test]
async fn fapi_b04_discovery_advertises_baseline_profile() {
    let env = setup_with_profile(FapiProfile::Baseline).await;
    let realm_rec = env
        .harness
        .identity()
        .get_realm(&env.realm)
        .expect("get_realm")
        .expect("realm exists");

    let doc = env
        .harness
        .identity()
        .realm_oidc_discovery(&env.realm)
        .expect("discovery");
    assert_eq!(
        doc.fapi_profile.as_deref(),
        Some("baseline"),
        "discovery should advertise fapi_profile=baseline, realm name: {}",
        realm_rec.name()
    );
}

// ── FAPI-A: Advanced tests ─────────────────────────────────────────────────────

/// FAPI-A-01: PAR without JAR rejected under Advanced.
#[tokio::test]
async fn fapi_a01_par_without_jar_rejected() {
    let env = setup_with_profile(FapiProfile::Advanced).await;
    // PAR with PKCE but no signed request object — Advanced requires JAR.
    let req = par_with_pkce(&env.client_id);
    let err = env
        .harness
        .identity()
        .push_authorization_request(&env.realm, &req)
        .expect_err("Advanced requires JAR in PAR");
    assert!(
        matches!(err, IdentityError::FapiViolation { .. }),
        "expected FapiViolation, got: {err:?}"
    );
}

/// FAPI-A-02: Authorize without JARM-configured client rejected under Advanced.
///
/// Advanced requires JARM (signed authorization responses). A client without
/// `authorization_signed_response_alg` therefore cannot use a FAPI Advanced realm.
#[tokio::test]
async fn fapi_a02_authorize_without_jarm_client_rejected() {
    let env = setup_with_profile(FapiProfile::Advanced).await;

    // Register a JAR-capable client (JWKS present) but without JARM config.
    let (pkcs8, pub_bytes) = generate_ed25519();
    let jwks = jwks_json(&pub_bytes);
    let client = env
        .harness
        .identity()
        .register_client(
            &env.realm,
            &RegisterClientRequest {
                client_name: "FAPI-A No-JARM Client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                jwks: Some(jwks),
                authorization_signed_response_alg: None, // no JARM
                ..Default::default()
            },
        )
        .expect("register client");

    let realm_rec = env
        .harness
        .identity()
        .get_realm(&env.realm)
        .expect("get_realm")
        .unwrap();
    let issuer = format!("https://hearth.local/realms/{}", realm_rec.name());
    let cid_str = client.client_id().to_string();
    let jar = sign_jar(&pkcs8, &cid_str, &issuer);

    let par_req = PushedAuthorizationRequest {
        client_id: client.client_id().clone(),
        redirect_uri: REDIRECT_URI.to_string(),
        scope: "openid".to_string(),
        state: "adv-state".to_string(),
        resource: None,
        response_type: "code".to_string(),
        code_challenge: Some(PKCE_CHALLENGE.to_string()),
        code_challenge_method: Some(CodeChallengeMethod::S256),
        nonce: Some("adv-nonce".to_string()),
        request: Some(jar),
    };

    // PAR itself is gate-free for JAR presence — the JARM check fires in authorize.
    let _par_resp = env
        .harness
        .identity()
        .push_authorization_request(&env.realm, &par_req)
        .expect("PAR with JAR should succeed");

    // Build auth request from PAR fields (via_par = true).
    let auth_req = auth_req_from_par(&par_req, env.user_id.clone());

    let err = env
        .harness
        .identity()
        .authorize(&env.realm, &auth_req)
        .expect_err("should reject: no JARM on client");
    assert!(
        matches!(err, IdentityError::FapiViolation { .. }),
        "expected FapiViolation (no JARM), got: {err:?}"
    );
}

/// FAPI-A-03: Client without JWKS rejected in authorize under Advanced.
///
/// `private_key_jwt` requirement means the client MUST have a JWKS.
#[tokio::test]
async fn fapi_a03_authorize_without_jwks_rejected() {
    let env = setup_with_profile(FapiProfile::Advanced).await;

    // The default client (from setup_with_profile) has no JWKS.
    // Attempt a via_par=true authorize — Advanced should reject lack of JWKS.
    let auth_req = AuthorizationRequest {
        client_id: env.client_id.clone(),
        redirect_uri: REDIRECT_URI.to_string(),
        response_type: "code".to_string(),
        scope: "openid".to_string(),
        state: "adv-state".to_string(),
        nonce: None,
        code_challenge: Some(PKCE_CHALLENGE.to_string()),
        code_challenge_method: Some(CodeChallengeMethod::S256),
        resource: None,
        user_id: env.user_id.clone(),
        amr_values: vec![],
        response_mode: None,
        request: None,
        via_par: true,
    };

    let err = env
        .harness
        .identity()
        .authorize(&env.realm, &auth_req)
        .expect_err("should reject: no JWKS (private_key_jwt required)");
    assert!(
        matches!(err, IdentityError::FapiViolation { .. }),
        "expected FapiViolation (no JWKS), got: {err:?}"
    );
}

/// FAPI-A-04: Valid Advanced request (PAR + PKCE + JAR + JARM client) accepted.
#[tokio::test]
async fn fapi_a04_valid_advanced_request_accepted() {
    let env = setup_with_profile(FapiProfile::Advanced).await;

    let (pkcs8, pub_bytes) = generate_ed25519();
    let jwks = jwks_json(&pub_bytes);

    let client = env
        .harness
        .identity()
        .register_client(
            &env.realm,
            &RegisterClientRequest {
                client_name: "FAPI-A Full Client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                jwks: Some(jwks),
                authorization_signed_response_alg: Some("EdDSA".to_string()),
                ..Default::default()
            },
        )
        .expect("register FAPI-A client");

    let realm_rec = env
        .harness
        .identity()
        .get_realm(&env.realm)
        .expect("get_realm")
        .unwrap();
    let issuer = format!("https://hearth.local/realms/{}", realm_rec.name());
    let cid_str = client.client_id().to_string();
    let jar = sign_jar(&pkcs8, &cid_str, &issuer);

    let par_req = PushedAuthorizationRequest {
        client_id: client.client_id().clone(),
        redirect_uri: REDIRECT_URI.to_string(),
        scope: "openid".to_string(),
        state: "adv-full-state".to_string(),
        resource: None,
        response_type: "code".to_string(),
        code_challenge: Some(PKCE_CHALLENGE.to_string()),
        code_challenge_method: Some(CodeChallengeMethod::S256),
        nonce: Some("adv-full-nonce".to_string()),
        request: Some(jar),
    };

    let _par_resp = env
        .harness
        .identity()
        .push_authorization_request(&env.realm, &par_req)
        .expect("PAR with JAR should succeed");

    // Build auth request from PAR fields (via_par = true).
    let auth_req = auth_req_from_par(&par_req, env.user_id.clone());

    let resp = env
        .harness
        .identity()
        .authorize(&env.realm, &auth_req)
        .expect("Advanced authorize should succeed");
    assert!(
        !resp.code().is_empty(),
        "authorization code should be non-empty"
    );
}

/// FAPI-A-05: Discovery document advertises `fapi_profile = "advanced"`.
#[tokio::test]
async fn fapi_a05_discovery_advertises_advanced_profile() {
    let env = setup_with_profile(FapiProfile::Advanced).await;
    let doc = env
        .harness
        .identity()
        .realm_oidc_discovery(&env.realm)
        .expect("discovery");
    assert_eq!(
        doc.fapi_profile.as_deref(),
        Some("advanced"),
        "discovery should advertise fapi_profile=advanced"
    );
}
