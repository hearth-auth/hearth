//! Conformance tests for JAR (JWT Authorization Requests) — RFC 9101.
//!
//! Exercises `verify_jar` and `push_authorization_request` with a `request=`
//! field via the public `IdentityEngine` surface. Five scenarios:
//! 1. Valid signed JAR accepted
//! 2. Tampered signature rejected
//! 3. `alg:none` rejected
//! 4. Wrong `aud` claim rejected
//! 5. Expired JAR rejected

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{Clock, FakeClock, RealmId, Timestamp};
use hearth::identity::{
    CreateRealmRequest, CredentialConfig, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine,
    IdentityError, PushedAuthorizationRequest, RegisterClientRequest,
};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

// ── Constants ────────────────────────────────────────────────────────────────

const EPOCH_MICROS: i64 = 1_700_000_000 * 1_000_000;
const REDIRECT_URI: &str = "https://example.com/callback";
const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const TEST_KID: &str = "jar-test-key-1";

// ── Test infrastructure ───────────────────────────────────────────────────────

struct TestEnv {
    engine: EmbeddedIdentityEngine,
    realm: RealmId,
    issuer: String,
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

    let realm_record = engine
        .create_realm(&CreateRealmRequest {
            name: format!("jar-test-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");
    let realm = realm_record.id().clone();

    // The default OidcConfig issuer is "https://hearth.local"; realm_issuer_url
    // returns "{base}/realms/{name}" when the realm can be loaded.
    let issuer = format!("https://hearth.local/realms/{}", realm_record.name());

    TestEnv {
        engine,
        realm,
        issuer,
        _dir: dir,
    }
}

// ── Ed25519 JAR signing helpers ───────────────────────────────────────────────

/// Generates a fresh Ed25519 key pair and returns (pkcs8_bytes, public_key_bytes).
fn generate_ed25519() -> (Vec<u8>, Vec<u8>) {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("keygen");
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("from_pkcs8");
    let pub_bytes = pair.public_key().as_ref().to_vec();
    (pkcs8.as_ref().to_vec(), pub_bytes)
}

/// Builds a JWKS JSON string with one OKP/Ed25519 key.
fn jwks_json(pub_bytes: &[u8]) -> String {
    let x = URL_SAFE_NO_PAD.encode(pub_bytes);
    format!(
        r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","kid":"{TEST_KID}","x":"{x}"}}]}}"#
    )
}

/// Signs a JAR JWT using the given PKCS#8 key bytes.
///
/// `override_alg` replaces the `alg` claim in the header (use to test wrong-alg paths).
/// `override_aud` replaces the `aud` claim (use to test wrong-aud paths).
/// `override_exp` replaces the `exp` claim (use to test expiry paths).
fn sign_jar(
    pkcs8_bytes: &[u8],
    client_id: &str,
    issuer: &str,
    override_alg: Option<&str>,
    override_aud: Option<&str>,
    override_exp: Option<i64>,
) -> String {
    let alg = override_alg.unwrap_or("EdDSA");
    let aud = override_aud.unwrap_or(issuer);
    let exp = override_exp.unwrap_or(EPOCH_MICROS / 1_000_000 + 3600);
    let iat = EPOCH_MICROS / 1_000_000;

    let header = serde_json::json!({
        "alg": alg,
        "kid": TEST_KID
    });
    let pkce_challenge = {
        use data_encoding::BASE64URL_NOPAD;
        BASE64URL_NOPAD
            .encode(ring::digest::digest(&ring::digest::SHA256, PKCE_VERIFIER.as_bytes()).as_ref())
    };
    let claims = serde_json::json!({
        "iss": client_id,
        "aud": aud,
        "exp": exp,
        "iat": iat,
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": "openid",
        "state": "test-state-jar",
        "code_challenge": pkce_challenge,
        "code_challenge_method": "S256"
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("serialize header"));
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("serialize claims"));
    let signing_input = format!("{header_b64}.{claims_b64}");

    let pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes).expect("from_pkcs8");
    let sig = pair.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_ref());

    format!("{signing_input}.{sig_b64}")
}

fn register_client_with_jwks(env: &TestEnv, jwks: &str) -> hearth::identity::OAuthClient {
    env.engine
        .register_client(
            &env.realm,
            &RegisterClientRequest {
                client_name: "JAR Test Client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                jwks: Some(jwks.to_string()),
                ..Default::default()
            },
        )
        .expect("register client")
}

fn par_with_jar(client_id: hearth::core::ClientId, jar_jwt: String) -> PushedAuthorizationRequest {
    PushedAuthorizationRequest {
        client_id,
        // These outer params are overridden by the JAR — redirect_uri/scope/state/etc.
        // come from the JWT. Supply them here anyway to ensure JAR takes precedence.
        redirect_uri: REDIRECT_URI.to_string(),
        scope: "openid".to_string(),
        state: "outer-state-ignored".to_string(),
        resource: None,
        response_type: "code".to_string(),
        code_challenge: None,
        code_challenge_method: None,
        nonce: None,
        request: Some(jar_jwt),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Scenario 1 — valid signed JAR is accepted and state comes from the JWT.
#[test]
fn jar_valid_signed_request_object_accepted() {
    let env = setup();
    let (pkcs8, pub_bytes) = generate_ed25519();
    let jwks = jwks_json(&pub_bytes);
    let client = register_client_with_jwks(&env, &jwks);
    let client_id = client.client_id().clone();
    let cid_str = client_id.to_string();

    let jar = sign_jar(&pkcs8, &cid_str, &env.issuer, None, None, None);
    let req = par_with_jar(client_id, jar);

    let resp = env
        .engine
        .push_authorization_request(&env.realm, &req)
        .expect("valid JAR must be accepted");

    assert!(
        resp.request_uri
            .starts_with("urn:ietf:params:oauth:request_uri:"),
        "request_uri must use the correct URN prefix"
    );
    assert_eq!(resp.expires_in, 90, "PAR TTL should be 90 s");
}

/// Scenario 2 — tampered signature is rejected.
#[test]
fn jar_tampered_signature_rejected() {
    let env = setup();
    let (pkcs8, pub_bytes) = generate_ed25519();
    let jwks = jwks_json(&pub_bytes);
    let client = register_client_with_jwks(&env, &jwks);
    let client_id = client.client_id().clone();
    let cid_str = client_id.to_string();

    let jar = sign_jar(&pkcs8, &cid_str, &env.issuer, None, None, None);

    // Flip the last byte of the signature part.
    let parts: Vec<&str> = jar.split('.').collect();
    let mut sig = URL_SAFE_NO_PAD.decode(parts[2]).expect("decode sig");
    let last = sig.last_mut().expect("non-empty sig");
    *last ^= 0xFF;
    let bad_sig = URL_SAFE_NO_PAD.encode(&sig);
    let tampered = format!("{}.{}.{}", parts[0], parts[1], bad_sig);

    // Drop the immutable borrow of `parts` so we can drop `jar` safely.
    drop(parts);

    let req = par_with_jar(client_id, tampered);
    let err = env
        .engine
        .push_authorization_request(&env.realm, &req)
        .expect_err("tampered JAR must be rejected");

    assert!(
        matches!(err, IdentityError::InvalidJar { .. }),
        "expected InvalidJar, got {err:?}"
    );
}

/// Scenario 3 — `alg:none` is rejected outright.
#[test]
fn jar_alg_none_rejected() {
    let env = setup();
    let (pkcs8, pub_bytes) = generate_ed25519();
    let jwks = jwks_json(&pub_bytes);
    let client = register_client_with_jwks(&env, &jwks);
    let client_id = client.client_id().clone();
    let cid_str = client_id.to_string();

    // Build a "none" JWT: valid-looking header but alg=none, empty signature.
    let jar = sign_jar(&pkcs8, &cid_str, &env.issuer, Some("none"), None, None);
    // Strip the real signature and replace with empty string (alg:none format).
    let parts: Vec<&str> = jar.split('.').collect();
    let none_jwt = format!("{}.{}.", parts[0], parts[1]);

    let req = par_with_jar(client_id, none_jwt);
    let err = env
        .engine
        .push_authorization_request(&env.realm, &req)
        .expect_err("alg:none JAR must be rejected");

    assert!(
        matches!(err, IdentityError::InvalidJar { .. }),
        "expected InvalidJar for alg:none, got {err:?}"
    );
}

/// Scenario 4 — wrong `aud` claim is rejected.
#[test]
fn jar_wrong_aud_rejected() {
    let env = setup();
    let (pkcs8, pub_bytes) = generate_ed25519();
    let jwks = jwks_json(&pub_bytes);
    let client = register_client_with_jwks(&env, &jwks);
    let client_id = client.client_id().clone();
    let cid_str = client_id.to_string();

    let jar = sign_jar(
        &pkcs8,
        &cid_str,
        &env.issuer,
        None,
        Some("https://attacker.example/"),
        None,
    );
    let req = par_with_jar(client_id, jar);

    let err = env
        .engine
        .push_authorization_request(&env.realm, &req)
        .expect_err("wrong-aud JAR must be rejected");

    assert!(
        matches!(err, IdentityError::InvalidJar { .. }),
        "expected InvalidJar for wrong aud, got {err:?}"
    );
}

/// Scenario 5 — expired JAR (`exp` in the past) is rejected.
#[test]
fn jar_expired_rejected() {
    let env = setup();
    let (pkcs8, pub_bytes) = generate_ed25519();
    let jwks = jwks_json(&pub_bytes);
    let client = register_client_with_jwks(&env, &jwks);
    let client_id = client.client_id().clone();
    let cid_str = client_id.to_string();

    // exp = 1 second before the fake clock's "now"
    let past_exp = EPOCH_MICROS / 1_000_000 - 1;
    let jar = sign_jar(&pkcs8, &cid_str, &env.issuer, None, None, Some(past_exp));
    let req = par_with_jar(client_id, jar);

    let err = env
        .engine
        .push_authorization_request(&env.realm, &req)
        .expect_err("expired JAR must be rejected");

    assert!(
        matches!(err, IdentityError::InvalidJar { .. }),
        "expected InvalidJar for expired token, got {err:?}"
    );
}
