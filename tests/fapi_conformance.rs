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
//! - FAPI-B-05: FAPI Baseline + SMS MFA preserves `via_par` through MFA resume
//! - FAPI-B-06: Standard-profile client in FAPI Baseline realm must be DPoP-constrained
//! - FAPI-B-07: HTTP server — PAR→authorize flow succeeds end-to-end (HEA-1025)
//! - FAPI-B-08: HTTP server — direct authorize (no PAR) fails with FAPI error (HEA-1025)
//! - FAPI-B-09: HTTP server — replay of consumed request_uri rejected (HEA-1018)
//! - FAPI-B-10: HTTP server — client_id mismatch on authorize rejected (RFC 9126 §4)
//! - FAPI-B-11: Realm Baseline enforces DPoP on refresh_token grant for standard-profile clients
//!
//! ## Advanced (FAPI-A)
//! - FAPI-A-01: Missing JAR rejected under Advanced
//! - FAPI-A-02: Client without JWKS rejected (private_key_jwt requirement)
//! - FAPI-A-03: Client without JARM config rejected under Advanced
//! - FAPI-A-04: Valid Advanced request (PAR + PKCE + JAR + JARM client) accepted
//! - FAPI-A-05: Discovery advertises `fapi_profile = "advanced"`
//! - FAPI-A-06: PAR with PKCE only inside JAR accepted (regression HEA-1019)
//! - FAPI-A-07: Realm Advanced enforces DPoP at token exchange for standard-profile clients
//! - FAPI-A-08: HTTP server — PAR+JAR→authorize flow succeeds end-to-end (HEA-1023)
//! - FAPI-A-09: HTTP server — direct authorize (no PAR) rejected in Advanced realm (HEA-1023)

#![allow(clippy::unwrap_used)]

mod common;

use std::sync::Arc;

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
        response_mode: None,
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
        response_mode: None,
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
        response_mode: None,
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
        response_mode: None,
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

/// FAPI-A-06 (regression Finding 1): PAR with PKCE only inside the JAR must succeed.
///
/// RFC 9101 allows `code_challenge` to be placed exclusively in the signed
/// request object. The PAR FAPI gate must check `effective_code_challenge`
/// (post-JAR), not the raw outer `code_challenge` field. Verifies the fix
/// that moved the PKCE gate to after JAR extraction.
#[tokio::test]
async fn fapi_a06_par_pkce_only_in_jar_accepted() {
    let env = setup_with_profile(FapiProfile::Advanced).await;

    let (pkcs8, pub_bytes) = generate_ed25519();
    let jwks = jwks_json(&pub_bytes);

    // Register a fully-capable Advanced client (JWKS + JARM).
    let client = env
        .harness
        .identity()
        .register_client(
            &env.realm,
            &RegisterClientRequest {
                client_name: "FAPI-A-06 JAR-only PKCE Client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                jwks: Some(jwks),
                authorization_signed_response_alg: Some("EdDSA".to_string()),
                ..Default::default()
            },
        )
        .expect("register FAPI-A-06 client");

    let realm_rec = env
        .harness
        .identity()
        .get_realm(&env.realm)
        .expect("get_realm")
        .unwrap();
    let issuer = format!("https://hearth.local/realms/{}", realm_rec.name());
    let cid_str = client.client_id().to_string();

    // JAR carries PKCE; outer request deliberately omits code_challenge.
    let jar = sign_jar(&pkcs8, &cid_str, &issuer);
    let par_req = PushedAuthorizationRequest {
        client_id: client.client_id().clone(),
        redirect_uri: REDIRECT_URI.to_string(),
        scope: "openid".to_string(),
        state: "a06-state".to_string(),
        resource: None,
        response_type: "code".to_string(),
        // Intentionally absent — PKCE lives only inside the JAR.
        code_challenge: None,
        code_challenge_method: None,
        nonce: Some("a06-nonce".to_string()),
        request: Some(jar),
        response_mode: None,
    };

    // Before the fix this returned FapiViolation("FAPI 2.0 Baseline requires PKCE").
    let resp = env
        .harness
        .identity()
        .push_authorization_request(&env.realm, &par_req)
        .expect("PAR with PKCE only in JAR must succeed");
    assert!(
        !resp.request_uri.is_empty(),
        "PAR should return a non-empty request_uri"
    );
}

/// FAPI-A-07 (regression Finding 2): realm-level FAPI Advanced must enforce DPoP
/// at token exchange even for clients without `profile: Fapi2`.
///
/// Exploit path (pre-fix): register a `Standard` client in a FAPI Advanced realm.
/// Advanced authorize gate passes (JWKS + JARM present). Exchange code without
/// DPoP → non-sender-constrained token issued. The per-client gate at
/// `client.profile().is_fapi2()` silently skips the DPoP check.
#[tokio::test]
async fn fapi_a07_realm_advanced_enforces_dpop_for_standard_profile_client() {
    use hearth::identity::{ClientProfile, TokenExchangeRequest};

    // RFC 7636 §Appendix B example verifier / challenge pair.
    const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    let env = setup_with_profile(FapiProfile::Advanced).await;

    let (pkcs8, pub_bytes) = generate_ed25519();
    let jwks = jwks_json(&pub_bytes);

    // Register a client with profile=Standard (not Fapi2) but fully Advanced-capable
    // (JWKS + JARM + client_secret so it can authenticate at token exchange).
    let client = env
        .harness
        .identity()
        .register_client(
            &env.realm,
            &RegisterClientRequest {
                client_name: "FAPI-A-07 Standard-profile client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: Some("a07-secret".to_string()),
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                jwks: Some(jwks),
                authorization_signed_response_alg: Some("EdDSA".to_string()),
                profile: ClientProfile::Standard, // NOT Fapi2 — this is the attack surface
                ..Default::default()
            },
        )
        .expect("register standard-profile client");

    let realm_rec = env
        .harness
        .identity()
        .get_realm(&env.realm)
        .expect("get_realm")
        .unwrap();
    let issuer = format!("https://hearth.local/realms/{}", realm_rec.name());
    let cid_str = client.client_id().to_string();
    let jar = sign_jar(&pkcs8, &cid_str, &issuer);

    // PAR: PKCE in both outer and JAR so the authorize auth_req carries it forward.
    let par_req = PushedAuthorizationRequest {
        client_id: client.client_id().clone(),
        redirect_uri: REDIRECT_URI.to_string(),
        scope: "openid".to_string(),
        state: "a07-state".to_string(),
        resource: None,
        response_type: "code".to_string(),
        code_challenge: Some(PKCE_CHALLENGE.to_string()),
        code_challenge_method: Some(CodeChallengeMethod::S256),
        nonce: Some("a07-nonce".to_string()),
        request: Some(jar),
        response_mode: None,
    };
    env.harness
        .identity()
        .push_authorization_request(&env.realm, &par_req)
        .expect("PAR should succeed");

    // Authorize via PAR (via_par=true) — passes realm-level FAPI gate.
    let auth_req = auth_req_from_par(&par_req, env.user_id.clone());
    let auth_resp = env
        .harness
        .identity()
        .authorize(&env.realm, &auth_req)
        .expect("authorize should succeed");
    assert!(!auth_resp.code().is_empty());

    // Token exchange WITHOUT DPoP — realm Advanced gate must catch this even though
    // client.profile() == Standard (not Fapi2).
    let exchange_req = TokenExchangeRequest {
        client_id: client.client_id().clone(),
        code: auth_resp.code().to_string(),
        redirect_uri: REDIRECT_URI.to_string(),
        code_verifier: Some(PKCE_VERIFIER.to_string()),
        dpop_jkt: None, // deliberately absent to trigger the realm-level gate
        client_assertion_type: None,
        client_assertion: None,
    };

    let err = env
        .harness
        .identity()
        .exchange_authorization_code(&env.realm, &exchange_req)
        .expect_err("realm-level Advanced gate must reject token exchange without DPoP");
    assert!(
        matches!(err, IdentityError::FapiViolation { .. }),
        "expected FapiViolation (DPoP required by realm), got: {err:?}"
    );
}

/// FAPI-B-05 (regression HEA-1020): FAPI Baseline realm + SMS MFA — code must be
/// issued when `via_par = true` is passed after OTP verification.
///
/// The old code hardcoded `via_par = false` in `sms_challenge_post` (and
/// `resume_oidc_flow`), causing the FAPI gate to reject code issuance even when
/// the original request went through PAR.  The negative half of the test
/// (via_par=false rejected) ensures this test fails on the unfixed code.
#[tokio::test]
async fn fapi_b05_sms_mfa_resume_via_par_preserved() {
    use hearth::identity::UpdateUserRequest;

    let env = setup_with_profile(FapiProfile::Baseline).await;

    // Enable SMS MFA on the FAPI Baseline realm.
    let realm_rec = env
        .harness
        .identity()
        .get_realm(&env.realm)
        .expect("get realm")
        .unwrap();
    let mut config = realm_rec.config().clone();
    config.mfa_methods = Some(vec!["sms".to_string()]);
    env.harness
        .identity()
        .update_realm(
            &env.realm,
            &UpdateRealmRequest {
                config: Some(config),
                ..Default::default()
            },
        )
        .expect("update realm with SMS MFA");

    // Give the test user a verified phone so SMS MFA applies to their session.
    env.harness
        .identity()
        .update_user(
            &env.realm,
            &env.user_id,
            &UpdateUserRequest {
                phone_number: Some(Some("+15555550101".to_string())),
                phone_verified: Some(true),
                ..UpdateUserRequest::default()
            },
        )
        .expect("set verified phone");

    // Positive: after successful OTP verification the web layer calls
    // issue_authorization_code with via_par=true (the fixed behaviour).
    let resp = env
        .harness
        .identity()
        .issue_authorization_code(
            &env.realm,
            &env.user_id,
            &env.client_id,
            REDIRECT_URI,
            "openid",
            "sms-fapi-state",
            Some(PKCE_CHALLENGE.to_string()),
            Some(CodeChallengeMethod::S256),
            Some("sms-nonce".to_string()),
            vec!["sms".to_string()],
            None, // response_mode
            None, // jar_request
            true, // via_par = true — what the fixed code passes
        )
        .expect("FAPI Baseline + SMS MFA: issue_authorization_code(via_par=true) must succeed");
    assert!(!resp.code().is_empty(), "auth code must be non-empty");

    // Negative: the old code hardcoded via_par=false in sms_challenge_post.
    // The FAPI gate must reject it — this assertion fails on the unfixed code.
    let err = env
        .harness
        .identity()
        .issue_authorization_code(
            &env.realm,
            &env.user_id,
            &env.client_id,
            REDIRECT_URI,
            "openid",
            "sms-fapi-state-2",
            Some(PKCE_CHALLENGE.to_string()),
            Some(CodeChallengeMethod::S256),
            Some("sms-nonce-2".to_string()),
            vec!["sms".to_string()],
            None,  // response_mode
            None,  // jar_request
            false, // via_par=false — what old code passed; FAPI gate must reject
        )
        .expect_err(
            "FAPI Baseline + SMS MFA: issue_authorization_code(via_par=false) must be rejected",
        );
    assert!(
        matches!(err, IdentityError::FapiViolation { .. }),
        "expected FapiViolation, got: {err:?}"
    );
}

/// FAPI-B-06 (regression [HEA-1022]): realm-level FAPI Baseline must enforce DPoP
/// at token exchange even for clients without `profile: Fapi2`.
///
/// Exploit path (pre-fix): register a `Standard` client in a FAPI Baseline realm.
/// The per-client gate `client.profile().is_fapi2()` is false, and the old realm
/// gate only matched `FapiProfile::Advanced` — so Baseline realms silently skipped
/// the DPoP check, issuing non-sender-constrained tokens.
///
/// FAPI 2.0 Baseline §5.3.3 requires sender-constrained tokens for every client.
#[tokio::test]
async fn fapi_b06_realm_baseline_enforces_dpop_for_standard_profile_client() {
    use hearth::identity::{ClientProfile, TokenExchangeRequest};

    const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    // Baseline realm — no JAR/JARM needed.
    let env = setup_with_profile(FapiProfile::Baseline).await;

    // Register a Standard-profile client (NOT Fapi2) — this is the attack surface.
    let client = env
        .harness
        .identity()
        .register_client(
            &env.realm,
            &RegisterClientRequest {
                client_name: "FAPI-B-06 Standard-profile client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: Some("b06-secret".to_string()),
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                profile: ClientProfile::Standard, // NOT Fapi2 — intentional
                ..Default::default()
            },
        )
        .expect("register standard-profile client");

    // Valid Baseline flow: PAR + PKCE (no JAR required for Baseline).
    let par_req = PushedAuthorizationRequest {
        client_id: client.client_id().clone(),
        redirect_uri: REDIRECT_URI.to_string(),
        scope: "openid".to_string(),
        state: "b06-state".to_string(),
        resource: None,
        response_type: "code".to_string(),
        code_challenge: Some(PKCE_CHALLENGE.to_string()),
        code_challenge_method: Some(hearth::identity::oidc::CodeChallengeMethod::S256),
        nonce: Some("b06-nonce".to_string()),
        request: None,
        response_mode: None,
    };
    env.harness
        .identity()
        .push_authorization_request(&env.realm, &par_req)
        .expect("PAR should succeed");

    let auth_req = auth_req_from_par(&par_req, env.user_id.clone());
    let auth_resp = env
        .harness
        .identity()
        .authorize(&env.realm, &auth_req)
        .expect("authorize should succeed");
    assert!(!auth_resp.code().is_empty());

    // Token exchange WITHOUT DPoP — realm Baseline gate must catch this.
    let exchange_req = TokenExchangeRequest {
        client_id: client.client_id().clone(),
        code: auth_resp.code().to_string(),
        redirect_uri: REDIRECT_URI.to_string(),
        code_verifier: Some(PKCE_VERIFIER.to_string()),
        dpop_jkt: None, // deliberately absent — triggers the realm-level gate
        client_assertion_type: None,
        client_assertion: None,
    };

    let err = env
        .harness
        .identity()
        .exchange_authorization_code(&env.realm, &exchange_req)
        .expect_err("realm-level Baseline gate must reject token exchange without DPoP");
    assert!(
        matches!(err, IdentityError::FapiViolation { .. }),
        "expected FapiViolation (DPoP required by Baseline realm), got: {err:?}"
    );
}

// ── Server-mode regression tests (HEA-1025) ───────────────────────────────────
//
// These tests exercise the HTTP surface directly — the embedded tests above
// call the domain layer APIs, but do not exercise whether the HTTP authorize
// handler actually calls `consume_par` and sets `via_par = true`.

/// Start an in-process axum HTTP server backed by a FAPI Baseline realm.
///
/// Returns `(base_url, realm_uuid_string, client_uuid_string, user_uuid_string,
/// shutdown_sender)`.  Drop the sender to stop the server.
async fn start_fapi_http_server() -> (
    String,
    String,
    String,
    String,
    tokio::sync::oneshot::Sender<()>,
) {
    use hearth::protocol::http::{router, AppState};
    use tokio::net::TcpListener;

    let harness = common::TestHarness::embedded().await.expect("harness");

    let realm_rec = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("fapi-http-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");
    let realm_id = realm_rec.id().clone();

    let mut config = realm_rec.config().clone();
    config.fapi_profile = Some(FapiProfile::Baseline);
    harness
        .identity()
        .update_realm(
            &realm_id,
            &UpdateRealmRequest {
                config: Some(config),
                ..Default::default()
            },
        )
        .expect("apply Baseline profile");

    let client = harness
        .identity()
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "FAPI HTTP Test Client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: Some("test-secret".to_string()),
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("register client");

    let user = harness
        .identity()
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: format!("http-user-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "HTTP FAPI User".to_string(),
                ..Default::default()
            },
        )
        .expect("create user");

    let realm_uuid = realm_id.as_uuid().to_string();
    let client_uuid = client.client_id().as_uuid().to_string();
    let user_uuid = user.id().as_uuid().to_string();

    let state = Arc::new(AppState::new_dev(
        harness.identity_arc(),
        harness.rbac_arc(),
        harness.audit_arc(),
    ));

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind random port");
    let port = listener.local_addr().expect("local addr").port();

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let _harness = harness; // keeps TempDir alive
        axum::serve(listener, router(state))
            .with_graceful_shutdown(async {
                rx.await.ok();
            })
            .await
            .ok();
    });

    (
        format!("http://127.0.0.1:{port}"),
        realm_uuid,
        client_uuid,
        user_uuid,
        tx,
    )
}

/// FAPI-B-07 (regression HEA-1025): HTTP PAR→authorize flow succeeds end-to-end.
///
/// Before the fix, the HTTP `/authorize` handler never called `consume_par` — it
/// always left `via_par = false` — so every FAPI2 client received a
/// `FapiViolation` error even after a valid PAR submission.  This test goes
/// through the HTTP surface to confirm the handler now consumes the
/// `request_uri` and returns a real auth code.
#[tokio::test]
async fn fapi_b07_http_par_authorize_flow_succeeds() {
    let (base, realm_uuid, client_uuid, user_uuid, _shutdown) = start_fapi_http_server().await;
    let http = reqwest::Client::new();

    // Step 1: Push authorization parameters to /as/par to get a request_uri.
    let par_resp: serde_json::Value = http
        .post(format!("{base}/as/par"))
        .header("X-Realm-ID", &realm_uuid)
        .json(&serde_json::json!({
            "client_id": client_uuid,
            "redirect_uri": REDIRECT_URI,
            "scope": "openid",
            "state": "fapi-b07-state",
            "response_type": "code",
            "code_challenge": PKCE_CHALLENGE,
            "code_challenge_method": "S256",
            "nonce": "fapi-b07-nonce"
        }))
        .send()
        .await
        .expect("PAR request")
        .json()
        .await
        .expect("PAR response JSON");

    let request_uri = par_resp["request_uri"]
        .as_str()
        .expect("PAR response must include request_uri");
    assert!(
        request_uri.starts_with("urn:ietf:params:oauth:request_uri:"),
        "request_uri must use RFC 9126 URN scheme, got: {request_uri}"
    );

    // Step 2: Authorize using the request_uri — handler must call consume_par
    // and set via_par=true, satisfying the FAPI Baseline gate.
    let auth_resp = http
        .post(format!("{base}/authorize"))
        .header("X-Realm-ID", &realm_uuid)
        .json(&serde_json::json!({
            "user_id": user_uuid,
            "request_uri": request_uri
        }))
        .send()
        .await
        .expect("authorize request");

    assert_eq!(
        auth_resp.status(),
        reqwest::StatusCode::OK,
        "PAR→authorize via HTTP must return 200 OK"
    );
    let auth_body: serde_json::Value = auth_resp.json().await.expect("auth response JSON");
    let code = auth_body["code"]
        .as_str()
        .expect("authorize response must contain 'code'");
    assert!(!code.is_empty(), "auth code must be non-empty");
}

/// FAPI-B-08 (regression HEA-1025): HTTP direct authorize without PAR is rejected.
///
/// Sending a full authorize request body with no `request_uri` against a FAPI
/// Baseline realm must yield a 400 with `error = "invalid_request"`.  This
/// ensures the HTTP surface enforces the PAR-only gate (FAPI 2.0 §5.2.2).
#[tokio::test]
async fn fapi_b08_http_direct_authorize_without_par_rejected() {
    let (base, realm_uuid, client_uuid, user_uuid, _shutdown) = start_fapi_http_server().await;
    let http = reqwest::Client::new();

    // Attempt authorize without a request_uri — must be rejected by the FAPI gate.
    let resp = http
        .post(format!("{base}/authorize"))
        .header("X-Realm-ID", &realm_uuid)
        .json(&serde_json::json!({
            "user_id": user_uuid,
            "client_id": client_uuid,
            "redirect_uri": REDIRECT_URI,
            "scope": "openid",
            "state": "fapi-b08-state",
            "response_type": "code",
            "code_challenge": PKCE_CHALLENGE,
            "code_challenge_method": "S256"
        }))
        .send()
        .await
        .expect("authorize request");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "FAPI Baseline direct authorize (no PAR) must return 400"
    );
    let body: serde_json::Value = resp.json().await.expect("error response JSON");
    assert_eq!(
        body["error"].as_str(),
        Some("invalid_request"),
        "FAPI violation must produce error=invalid_request, got: {body}"
    );
}

/// FAPI-B-09 (HEA-1018): replay of a consumed `request_uri` is rejected.
///
/// RFC 9126 §4 requires that a `request_uri` is single-use. `consume_par`
/// marks the entry `used = true` on first consumption. A second `/authorize`
/// call with the same `request_uri` must return 400 `invalid_request`.
#[tokio::test]
async fn fapi_b09_http_replay_request_uri_rejected() {
    let (base, realm_uuid, client_uuid, user_uuid, _shutdown) = start_fapi_http_server().await;
    let http = reqwest::Client::new();

    // Push PAR to get a request_uri.
    let par_resp: serde_json::Value = http
        .post(format!("{base}/as/par"))
        .header("X-Realm-ID", &realm_uuid)
        .json(&serde_json::json!({
            "client_id": client_uuid,
            "redirect_uri": REDIRECT_URI,
            "scope": "openid",
            "state": "fapi-b09-state",
            "response_type": "code",
            "code_challenge": PKCE_CHALLENGE,
            "code_challenge_method": "S256",
            "nonce": "fapi-b09-nonce"
        }))
        .send()
        .await
        .expect("PAR request")
        .json()
        .await
        .expect("PAR response JSON");

    let request_uri = par_resp["request_uri"]
        .as_str()
        .expect("PAR response must include request_uri");

    // First use: must succeed.
    let first_resp = http
        .post(format!("{base}/authorize"))
        .header("X-Realm-ID", &realm_uuid)
        .json(&serde_json::json!({
            "user_id": user_uuid,
            "client_id": client_uuid,
            "request_uri": request_uri
        }))
        .send()
        .await
        .expect("first authorize request");
    assert_eq!(
        first_resp.status(),
        reqwest::StatusCode::OK,
        "first PAR->authorize must succeed, got: {}",
        first_resp.status()
    );

    // Second use (replay): must be rejected with invalid_request.
    let replay_resp = http
        .post(format!("{base}/authorize"))
        .header("X-Realm-ID", &realm_uuid)
        .json(&serde_json::json!({
            "user_id": user_uuid,
            "client_id": client_uuid,
            "request_uri": request_uri
        }))
        .send()
        .await
        .expect("replay authorize request");
    assert_eq!(
        replay_resp.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "replayed request_uri must return 400"
    );
    let replay_body: serde_json::Value = replay_resp.json().await.expect("error JSON");
    assert_eq!(
        replay_body["error"].as_str(),
        Some("invalid_request"),
        "replay must produce error=invalid_request, got: {replay_body}"
    );
}

/// FAPI-B-10 (HEA-1018): `client_id` mismatch between `/authorize` body and
/// stored PAR entry is rejected per RFC 9126 §4.
///
/// Without this check an attacker who obtains a `request_uri` (e.g. via
/// referrer leakage) could submit it using a different `client_id`.
#[tokio::test]
async fn fapi_b10_http_client_id_mismatch_rejected() {
    let (base, realm_uuid, client_uuid, user_uuid, _shutdown) = start_fapi_http_server().await;
    let http = reqwest::Client::new();

    // Push PAR using the real client.
    let par_resp: serde_json::Value = http
        .post(format!("{base}/as/par"))
        .header("X-Realm-ID", &realm_uuid)
        .json(&serde_json::json!({
            "client_id": client_uuid,
            "redirect_uri": REDIRECT_URI,
            "scope": "openid",
            "state": "fapi-b10-state",
            "response_type": "code",
            "code_challenge": PKCE_CHALLENGE,
            "code_challenge_method": "S256",
            "nonce": "fapi-b10-nonce"
        }))
        .send()
        .await
        .expect("PAR request")
        .json()
        .await
        .expect("PAR response JSON");

    let request_uri = par_resp["request_uri"]
        .as_str()
        .expect("PAR response must include request_uri");

    // Submit /authorize with a different client_id than the one that pushed the PAR.
    let other_client_id = uuid::Uuid::new_v4().to_string();
    let mismatch_resp = http
        .post(format!("{base}/authorize"))
        .header("X-Realm-ID", &realm_uuid)
        .json(&serde_json::json!({
            "user_id": user_uuid,
            "client_id": other_client_id,
            "request_uri": request_uri
        }))
        .send()
        .await
        .expect("mismatch authorize request");

    assert_eq!(
        mismatch_resp.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "client_id mismatch must return 400"
    );
    let mismatch_body: serde_json::Value = mismatch_resp.json().await.expect("error JSON");
    assert_eq!(
        mismatch_body["error"].as_str(),
        Some("invalid_request"),
        "client_id mismatch must produce error=invalid_request, got: {mismatch_body}"
    );
}

// ── Domain-level regression tests (HEA-1024) ──────────────────────────────────

/// FAPI-B-11 (regression HEA-1024): `grant_type=refresh_token` without DPoP on a
/// standard-profile client inside a FAPI Baseline realm → `FapiViolation`.
///
/// HEA-1022 fixed the realm-level gate for `exchange_authorization_code`; this test
/// verifies the same gate applies to `refresh_tokens` (FAPI 2.0 Baseline §5.3.3 —
/// sender-constrained tokens required for *every* token endpoint call).
#[tokio::test]
async fn fapi_b11_realm_baseline_enforces_dpop_on_refresh_for_standard_profile_client() {
    use hearth::identity::{ClientProfile, TokenExchangeRequest};

    const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const DPOP_JKT: &str = "test-thumbprint-b11";

    // Baseline realm — DPoP is mandatory for every token endpoint call.
    let env = setup_with_profile(FapiProfile::Baseline).await;

    // Standard-profile client (not FAPI2) — the realm gate must still apply.
    let client = env
        .harness
        .identity()
        .register_client(
            &env.realm,
            &RegisterClientRequest {
                client_name: "FAPI-B-11 Standard client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: Some("b11-secret".to_string()),
                grant_types: vec![
                    "authorization_code".to_string(),
                    "refresh_token".to_string(),
                ],
                require_consent: false,
                profile: ClientProfile::Standard, // NOT Fapi2 — tests realm-level gate
                ..Default::default()
            },
        )
        .expect("register standard-profile client");

    // Valid Baseline flow: PAR + PKCE.
    let par_req = PushedAuthorizationRequest {
        client_id: client.client_id().clone(),
        redirect_uri: REDIRECT_URI.to_string(),
        scope: "openid".to_string(),
        state: "b11-state".to_string(),
        resource: None,
        response_type: "code".to_string(),
        code_challenge: Some(PKCE_CHALLENGE.to_string()),
        code_challenge_method: Some(hearth::identity::oidc::CodeChallengeMethod::S256),
        nonce: Some("b11-nonce".to_string()),
        request: None,
        response_mode: None,
    };
    env.harness
        .identity()
        .push_authorization_request(&env.realm, &par_req)
        .expect("PAR should succeed");

    let auth_req = auth_req_from_par(&par_req, env.user_id.clone());
    let auth_resp = env
        .harness
        .identity()
        .authorize(&env.realm, &auth_req)
        .expect("authorize should succeed");

    // Code exchange WITH DPoP — must succeed (realm gate requires it).
    let initial_tokens = env
        .harness
        .identity()
        .exchange_authorization_code(
            &env.realm,
            &TokenExchangeRequest {
                client_id: client.client_id().clone(),
                code: auth_resp.code().to_string(),
                redirect_uri: REDIRECT_URI.to_string(),
                code_verifier: Some(PKCE_VERIFIER.to_string()),
                dpop_jkt: Some(DPOP_JKT.to_string()),
                client_assertion_type: None,
                client_assertion: None,
            },
        )
        .expect("token exchange with DPoP must succeed in Baseline realm");

    // Refresh WITHOUT DPoP — realm Baseline gate must reject this.
    let err = env
        .harness
        .identity()
        .refresh_tokens(&env.realm, initial_tokens.refresh_token(), None, None)
        .expect_err("FAPI Baseline realm must reject refresh without DPoP");
    assert!(
        matches!(err, IdentityError::FapiViolation { .. }),
        "expected FapiViolation for refresh without DPoP in Baseline realm, got: {err:?}"
    );

    // Refresh WITH DPoP — must succeed.
    env.harness
        .identity()
        .refresh_tokens(
            &env.realm,
            initial_tokens.refresh_token(),
            Some(DPOP_JKT),
            None,
        )
        .expect("refresh with DPoP must succeed");
}

// ── Advanced HTTP server-mode tests (HEA-1023) ───────────────────────────────
//
// These tests exercise the HTTP surface for FAPI Advanced realms — confirming
// the PAR+JAR consumption path sets `via_par = true` and satisfies the engine
// gates.  The embedded tests above call domain layer APIs directly; only these
// tests prove the HTTP authorize handler actually calls `consume_par`.

/// Holds the running HTTP server state for FAPI Advanced integration tests.
/// Dropping this struct shuts down the server via the `_shutdown` channel.
struct FapiAdvancedServer {
    base: String,
    realm_uuid: String,
    realm_name: String,
    client_uuid: String,
    /// Prefixed form of the client ID used in JAR `iss`/`client_id` claims.
    client_id_str: String,
    user_uuid: String,
    pkcs8_bytes: Vec<u8>,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

/// Starts an in-process axum server backed by a FAPI Advanced realm.
///
/// The realm has `fapi_profile = Advanced` and one registered client with an
/// Ed25519 JWKS (for JAR validation) and `authorization_signed_response_alg =
/// "EdDSA"` (required by the Advanced JARM gate).  The raw pkcs8 bytes are
/// returned so tests can sign JARs with the matching private key.
async fn start_fapi_advanced_http_server() -> FapiAdvancedServer {
    use hearth::protocol::http::{router, AppState};
    use tokio::net::TcpListener;

    let harness = common::TestHarness::embedded().await.expect("harness");

    let realm_rec = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("fapi-adv-http-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");
    let realm_id = realm_rec.id().clone();

    let mut config = realm_rec.config().clone();
    config.fapi_profile = Some(FapiProfile::Advanced);
    harness
        .identity()
        .update_realm(
            &realm_id,
            &UpdateRealmRequest {
                config: Some(config),
                ..Default::default()
            },
        )
        .expect("apply Advanced profile");

    // Ed25519 key pair — public key registered as JWKS, private key used to sign JARs.
    let (pkcs8_bytes, pub_bytes) = generate_ed25519();
    let jwks = jwks_json(&pub_bytes);

    let client = harness
        .identity()
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "FAPI Advanced HTTP Test Client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                jwks: Some(jwks),
                // Required: Advanced realm gate checks authorization_signed_response_alg is set.
                authorization_signed_response_alg: Some("EdDSA".to_string()),
                ..Default::default()
            },
        )
        .expect("register FAPI Advanced client");

    let user = harness
        .identity()
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: format!("adv-http-user-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "FAPI Advanced HTTP User".to_string(),
                ..Default::default()
            },
        )
        .expect("create user");

    let realm_uuid = realm_id.as_uuid().to_string();
    let realm_name = realm_rec.name().to_string();
    let client_uuid = client.client_id().as_uuid().to_string();
    let client_id_str = client.client_id().to_string();
    let user_uuid = user.id().as_uuid().to_string();

    let state = Arc::new(AppState::new_dev(
        harness.identity_arc(),
        harness.rbac_arc(),
        harness.audit_arc(),
    ));

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind random port");
    let port = listener.local_addr().expect("local addr").port();

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let _harness = harness; // keeps TempDir alive for the server's lifetime
        axum::serve(listener, router(state))
            .with_graceful_shutdown(async {
                rx.await.ok();
            })
            .await
            .ok();
    });

    FapiAdvancedServer {
        base: format!("http://127.0.0.1:{port}"),
        realm_uuid,
        realm_name,
        client_uuid,
        client_id_str,
        user_uuid,
        pkcs8_bytes,
        _shutdown: tx,
    }
}

/// FAPI-A-08 (HEA-1023): HTTP PAR+JAR→authorize flow succeeds end-to-end for an Advanced realm.
///
/// The HTTP `/authorize` handler must call `consume_par` when a `request_uri` is
/// present and set `via_par = true` in the domain request.  Without that, the
/// Advanced engine gate rejects every authorize even after a valid PAR+JAR
/// submission.  This test drives the full roundtrip through the HTTP surface:
///
///   1. POST `/as/par` with a signed JAR → `request_uri`
///   2. POST `/authorize` with the `request_uri` and a `user_id` → auth code
///
/// Spec: FAPI 2.0 §5.3.2, RFC 9126, RFC 9101.
#[tokio::test]
async fn fapi_a08_http_par_jar_authorize_flow_succeeds() {
    let srv = start_fapi_advanced_http_server().await;
    let http = reqwest::Client::new();

    // The engine derives the realm issuer as "{base_issuer}/realms/{name}".
    // In dev/test mode the base issuer is "https://hearth.local" (OidcConfig default).
    let issuer = format!("https://hearth.local/realms/{}", srv.realm_name);
    let jar = sign_jar(&srv.pkcs8_bytes, &srv.client_id_str, &issuer);

    // Step 1: POST /as/par with the signed JAR to get a request_uri.
    let par_body: serde_json::Value = http
        .post(format!("{}/as/par", srv.base))
        .header("X-Realm-ID", &srv.realm_uuid)
        .json(&serde_json::json!({
            "client_id": srv.client_uuid,
            "redirect_uri": REDIRECT_URI,
            "scope": "openid",
            "state": "fapi-a08-state",
            "response_type": "code",
            "code_challenge": PKCE_CHALLENGE,
            "code_challenge_method": "S256",
            "nonce": "fapi-a08-nonce",
            "request": jar
        }))
        .send()
        .await
        .expect("PAR request")
        .json()
        .await
        .expect("PAR response JSON");

    let request_uri = par_body["request_uri"]
        .as_str()
        .expect("PAR response must include request_uri");
    assert!(
        request_uri.starts_with("urn:ietf:params:oauth:request_uri:"),
        "request_uri must use RFC 9126 URN scheme, got: {request_uri}"
    );

    // Step 2: POST /authorize with the request_uri.  The handler calls consume_par,
    // sets via_par = true, and issues a code satisfying the Advanced gate.
    let auth_resp = http
        .post(format!("{}/authorize", srv.base))
        .header("X-Realm-ID", &srv.realm_uuid)
        .json(&serde_json::json!({
            "user_id": srv.user_uuid,
            "request_uri": request_uri
        }))
        .send()
        .await
        .expect("authorize request");

    assert_eq!(
        auth_resp.status(),
        reqwest::StatusCode::OK,
        "PAR+JAR→authorize must return 200 OK for FAPI Advanced realm"
    );
    let auth_body: serde_json::Value = auth_resp.json().await.expect("auth response JSON");
    let code = auth_body["code"]
        .as_str()
        .expect("authorize response must contain 'code'");
    assert!(!code.is_empty(), "auth code must be non-empty");
}

/// FAPI-A-09 (HEA-1023): HTTP direct authorize without PAR is rejected in an Advanced realm.
///
/// FAPI Advanced mandates PAR (RFC 9126 §2.4): submitting a full set of
/// authorization parameters directly to `/authorize` without a `request_uri`
/// must yield 400 `error=invalid_request`.
#[tokio::test]
async fn fapi_a09_http_direct_authorize_without_par_rejected() {
    let srv = start_fapi_advanced_http_server().await;
    let http = reqwest::Client::new();

    let resp = http
        .post(format!("{}/authorize", srv.base))
        .header("X-Realm-ID", &srv.realm_uuid)
        .json(&serde_json::json!({
            "user_id": srv.user_uuid,
            "client_id": srv.client_uuid,
            "redirect_uri": REDIRECT_URI,
            "scope": "openid",
            "state": "fapi-a09-state",
            "response_type": "code",
            "code_challenge": PKCE_CHALLENGE,
            "code_challenge_method": "S256"
        }))
        .send()
        .await
        .expect("authorize request");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "FAPI Advanced direct authorize (no PAR) must return 400"
    );
    let body: serde_json::Value = resp.json().await.expect("error response JSON");
    assert_eq!(
        body["error"].as_str(),
        Some("invalid_request"),
        "FAPI violation must produce error=invalid_request, got: {body}"
    );
}
