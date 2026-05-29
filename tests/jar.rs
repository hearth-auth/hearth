//! Conformance tests for JAR (JWT Authorization Requests) — RFC 9101.
//!
//! Exercises `verify_jar` and `push_authorization_request` with a `request=`
//! field via the public `IdentityEngine` surface. Nine scenarios:
//! 1. Valid signed JAR accepted
//! 2. Tampered signature rejected
//! 3. `alg:none` rejected
//! 4. Wrong `aud` claim rejected
//! 5. Expired JAR rejected
//! 6. Missing `jti` rejected (RFC 9101 §4 requires jti)
//! 7. Replayed `jti` rejected
//! 8. `nbf` in the future rejected
//! 9. `crv != Ed25519` OKP key rejected

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, Ed25519KeyPair, KeyPair};

use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{ClientId, Clock, FakeClock, RealmId, Timestamp, UserId};
use hearth::identity::{
    AuthorizationResponse, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, IdentityError,
    PushedAuthorizationRequest, RegisterClientRequest,
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
/// - `override_alg` replaces the `alg` header claim (test wrong-alg paths).
/// - `override_aud` replaces the `aud` claim (test wrong-aud paths).
/// - `override_exp` replaces the `exp` claim (test expiry paths).
/// - `jti` — `Some(v)` includes `"jti": v`; `None` omits it entirely (test missing-jti path).
/// - `nbf` — when `Some(v)`, sets the `nbf` claim.
fn sign_jar(
    pkcs8_bytes: &[u8],
    client_id: &str,
    issuer: &str,
    override_alg: Option<&str>,
    override_aud: Option<&str>,
    override_exp: Option<i64>,
    jti: Option<&str>,
    nbf: Option<i64>,
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
    let mut claims = serde_json::json!({
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
    if let Some(j) = jti {
        claims["jti"] = serde_json::Value::String(j.to_string());
    }
    if let Some(n) = nbf {
        claims["nbf"] = serde_json::Value::Number(n.into());
    }

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

    let jar = sign_jar(
        &pkcs8,
        &cid_str,
        &env.issuer,
        None,
        None,
        None,
        Some("jti-valid-1"),
        None,
    );
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

    let jar = sign_jar(
        &pkcs8,
        &cid_str,
        &env.issuer,
        None,
        None,
        None,
        Some("jti-tampered-1"),
        None,
    );

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
    let jar = sign_jar(
        &pkcs8,
        &cid_str,
        &env.issuer,
        Some("none"),
        None,
        None,
        Some("jti-none-1"),
        None,
    );
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
        Some("jti-wrong-aud-1"),
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
    let jar = sign_jar(
        &pkcs8,
        &cid_str,
        &env.issuer,
        None,
        None,
        Some(past_exp),
        Some("jti-expired-1"),
        None,
    );
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

/// Scenario 6 — JAR without `jti` is rejected (RFC 9101 §4 requires jti).
#[test]
fn jar_missing_jti_rejected() {
    let env = setup();
    let (pkcs8, pub_bytes) = generate_ed25519();
    let jwks = jwks_json(&pub_bytes);
    let client = register_client_with_jwks(&env, &jwks);
    let client_id = client.client_id().clone();
    let cid_str = client_id.to_string();

    // Pass None to omit jti entirely.
    let jar = sign_jar(&pkcs8, &cid_str, &env.issuer, None, None, None, None, None);
    let req = par_with_jar(client_id, jar);

    let err = env
        .engine
        .push_authorization_request(&env.realm, &req)
        .expect_err("JAR without jti must be rejected");

    assert!(
        matches!(err, IdentityError::InvalidJar { .. }),
        "expected InvalidJar for missing jti, got {err:?}"
    );
}

/// Scenario 7 — replaying the same `jti` is rejected.
#[test]
fn jar_jti_replay_rejected() {
    let env = setup();
    let (pkcs8, pub_bytes) = generate_ed25519();
    let jwks = jwks_json(&pub_bytes);
    let client = register_client_with_jwks(&env, &jwks);
    let client_id = client.client_id().clone();
    let cid_str = client_id.to_string();

    // First use — must succeed.
    let jar1 = sign_jar(
        &pkcs8,
        &cid_str,
        &env.issuer,
        None,
        None,
        None,
        Some("replay-jti-1"),
        None,
    );
    let req1 = par_with_jar(client_id.clone(), jar1);
    env.engine
        .push_authorization_request(&env.realm, &req1)
        .expect("first JAR with this jti must be accepted");

    // Second use of the same jti — must be rejected.
    let jar2 = sign_jar(
        &pkcs8,
        &cid_str,
        &env.issuer,
        None,
        None,
        None,
        Some("replay-jti-1"),
        None,
    );
    let req2 = par_with_jar(client_id, jar2);
    let err = env
        .engine
        .push_authorization_request(&env.realm, &req2)
        .expect_err("replayed jti must be rejected");

    assert!(
        matches!(err, IdentityError::InvalidJar { .. }),
        "expected InvalidJar for replayed jti, got {err:?}"
    );
}

/// Scenario 8 — `nbf` in the future is rejected.
#[test]
fn jar_nbf_in_future_rejected() {
    let env = setup();
    let (pkcs8, pub_bytes) = generate_ed25519();
    let jwks = jwks_json(&pub_bytes);
    let client = register_client_with_jwks(&env, &jwks);
    let client_id = client.client_id().clone();
    let cid_str = client_id.to_string();

    // nbf = 60 seconds after the fake clock's "now"
    let future_nbf = EPOCH_MICROS / 1_000_000 + 60;
    let jar = sign_jar(
        &pkcs8,
        &cid_str,
        &env.issuer,
        None,
        None,
        None,
        Some("jti-nbf-1"),
        Some(future_nbf),
    );
    let req = par_with_jar(client_id, jar);

    let err = env
        .engine
        .push_authorization_request(&env.realm, &req)
        .expect_err("JAR with future nbf must be rejected");

    assert!(
        matches!(err, IdentityError::InvalidJar { .. }),
        "expected InvalidJar for future nbf, got {err:?}"
    );
}

/// Scenario 9 — OKP key with `crv != Ed25519` is rejected.
#[test]
fn jar_wrong_crv_rejected() {
    let env = setup();
    let (pkcs8, pub_bytes) = generate_ed25519();

    // Register the client with a JWKS that has crv=Ed448 instead of Ed25519.
    let x = URL_SAFE_NO_PAD.encode(&pub_bytes);
    let bad_crv_jwks = format!(
        r#"{{"keys":[{{"kty":"OKP","crv":"Ed448","alg":"EdDSA","kid":"{TEST_KID}","x":"{x}"}}]}}"#
    );
    let client = register_client_with_jwks(&env, &bad_crv_jwks);
    let client_id = client.client_id().clone();
    let cid_str = client_id.to_string();

    let jar = sign_jar(
        &pkcs8,
        &cid_str,
        &env.issuer,
        None,
        None,
        None,
        Some("jti-crv-1"),
        None,
    );
    let req = par_with_jar(client_id, jar);

    let err = env
        .engine
        .push_authorization_request(&env.realm, &req)
        .expect_err("EdDSA JWK with crv=Ed448 must be rejected");

    assert!(
        matches!(err, IdentityError::InvalidJar { .. }),
        "expected InvalidJar for crv=Ed448, got {err:?}"
    );
}

// ── ES256 (ECDSA P-256 SHA-256) JAR helpers ──────────────────────────────────

const ES256_KID: &str = "jar-test-ec-key";

/// Generates a fresh P-256 key pair. Returns `(pkcs8_bytes, x_bytes, y_bytes)`.
fn generate_es256() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    use ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING;
    let rng = SystemRandom::new();
    let pkcs8 =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).expect("es256 keygen");
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
        .expect("es256 from_pkcs8");
    // ring emits the uncompressed SEC1 point: 0x04 || x(32) || y(32).
    let pub_bytes = pair.public_key().as_ref().to_vec();
    assert_eq!(pub_bytes.len(), 65, "P-256 public key must be 65 bytes");
    assert_eq!(pub_bytes[0], 0x04, "must be uncompressed point");
    (
        pkcs8.as_ref().to_vec(),
        pub_bytes[1..33].to_vec(),
        pub_bytes[33..65].to_vec(),
    )
}

/// Builds a JWKS JSON string with one EC/P-256 key.
fn jwks_json_es256(x: &[u8], y: &[u8]) -> String {
    let xb64 = URL_SAFE_NO_PAD.encode(x);
    let yb64 = URL_SAFE_NO_PAD.encode(y);
    format!(
        r#"{{"keys":[{{"kty":"EC","crv":"P-256","alg":"ES256","kid":"{ES256_KID}","x":"{xb64}","y":"{yb64}"}}]}}"#
    )
}

/// Signs a JAR JWT using ES256 (ECDSA P-256 SHA-256).
fn sign_jar_es256(pkcs8_bytes: &[u8], client_id: &str, issuer: &str, jti: &str) -> String {
    use ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING;
    let rng = SystemRandom::new();
    let exp = EPOCH_MICROS / 1_000_000 + 3600;
    let iat = EPOCH_MICROS / 1_000_000;
    let pkce_challenge = {
        use data_encoding::BASE64URL_NOPAD;
        BASE64URL_NOPAD
            .encode(ring::digest::digest(&ring::digest::SHA256, PKCE_VERIFIER.as_bytes()).as_ref())
    };
    let header = serde_json::json!({"alg": "ES256", "kid": ES256_KID});
    let claims = serde_json::json!({
        "iss": client_id, "aud": issuer, "exp": exp, "iat": iat, "jti": jti,
        "client_id": client_id, "response_type": "code", "redirect_uri": REDIRECT_URI,
        "scope": "openid", "state": "test-state-es256",
        "code_challenge": pkce_challenge, "code_challenge_method": "S256",
    });
    let h_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header"));
    let c_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("claims"));
    let signing_input = format!("{h_b64}.{c_b64}");

    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8_bytes, &rng)
        .expect("from_pkcs8");
    let sig = pair.sign(&rng, signing_input.as_bytes()).expect("sign");
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()))
}

// ── RS256 (RSA PKCS#1-v1.5 SHA-256) JAR helpers ──────────────────────────────

const RS256_KID: &str = "jar-test-rsa-key";

struct Rs256TestKey {
    pkcs8: Vec<u8>,
    n_b64: String,
    e_b64: String,
}

/// Generates a fresh RSA-2048 key via `rcgen` (aws_lc_rs backend).
/// Returns PKCS#8 DER plus the base64url-encoded `n` and `e` for the JWKS.
fn generate_rs256() -> Rs256TestKey {
    let keypair = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).expect("rsa keygen");
    let pkcs8 = keypair.serialize_der();
    let ring_key = ring::signature::RsaKeyPair::from_pkcs8(&pkcs8).expect("ring from_pkcs8");
    let (n_bytes, e_bytes) = pkcs1_public_key_components(ring_key.public().as_ref());
    Rs256TestKey {
        pkcs8,
        n_b64: URL_SAFE_NO_PAD.encode(&n_bytes),
        e_b64: URL_SAFE_NO_PAD.encode(&e_bytes),
    }
}

/// Builds a JWKS JSON string with one RSA key.
fn jwks_json_rs256(n_b64: &str, e_b64: &str) -> String {
    format!(
        r#"{{"keys":[{{"kty":"RSA","alg":"RS256","kid":"{RS256_KID}","n":"{n_b64}","e":"{e_b64}"}}]}}"#
    )
}

/// Signs a JAR JWT using RS256 (RSA PKCS#1-v1.5 SHA-256).
fn sign_jar_rs256(pkcs8_bytes: &[u8], client_id: &str, issuer: &str, jti: &str) -> String {
    let rng = SystemRandom::new();
    let exp = EPOCH_MICROS / 1_000_000 + 3600;
    let iat = EPOCH_MICROS / 1_000_000;
    let pkce_challenge = {
        use data_encoding::BASE64URL_NOPAD;
        BASE64URL_NOPAD
            .encode(ring::digest::digest(&ring::digest::SHA256, PKCE_VERIFIER.as_bytes()).as_ref())
    };
    let header = serde_json::json!({"alg": "RS256", "kid": RS256_KID});
    let claims = serde_json::json!({
        "iss": client_id, "aud": issuer, "exp": exp, "iat": iat, "jti": jti,
        "client_id": client_id, "response_type": "code", "redirect_uri": REDIRECT_URI,
        "scope": "openid", "state": "test-state-rs256",
        "code_challenge": pkce_challenge,
        "code_challenge_method": "S256",
    });
    let h_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header"));
    let c_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("claims"));
    let signing_input = format!("{h_b64}.{c_b64}");

    let ring_key = ring::signature::RsaKeyPair::from_pkcs8(pkcs8_bytes).expect("from_pkcs8");
    let mut sig = vec![0u8; ring_key.public().modulus_len()];
    ring_key
        .sign(
            &ring::signature::RSA_PKCS1_SHA256,
            &rng,
            signing_input.as_bytes(),
            &mut sig,
        )
        .expect("rsa sign");
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(&sig))
}

/// Parses a PKCS#1 `RSAPublicKey` DER blob (as emitted by `ring`'s
/// `RsaKeyPair::public().as_ref()`) and returns `(n_bytes, e_bytes)` with
/// the ASN.1 leading-zero sign byte stripped.
fn pkcs1_public_key_components(der: &[u8]) -> (Vec<u8>, Vec<u8>) {
    fn take(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
        let (t, rest) = input.split_first()?;
        if *t != tag {
            return None;
        }
        let (b0, rest) = rest.split_first()?;
        let (len, rest) = if *b0 & 0x80 == 0 {
            (usize::from(*b0), rest)
        } else {
            let n = usize::from(*b0 & 0x7F);
            if n == 0 || n > 4 || rest.len() < n {
                return None;
            }
            let mut l: usize = 0;
            for b in &rest[..n] {
                l = (l << 8) | usize::from(*b);
            }
            (l, &rest[n..])
        };
        if rest.len() < len {
            return None;
        }
        Some((&rest[..len], &rest[len..]))
    }
    fn strip(b: &[u8]) -> &[u8] {
        match b.split_first() {
            Some((0x00, rest)) if !rest.is_empty() => rest,
            _ => b,
        }
    }
    #[allow(clippy::unwrap_used)]
    let (body, _) = take(der, 0x30).unwrap();
    #[allow(clippy::unwrap_used)]
    let (n_raw, rest) = take(body, 0x02).unwrap();
    #[allow(clippy::unwrap_used)]
    let (e_raw, _) = take(rest, 0x02).unwrap();
    (strip(n_raw).to_vec(), strip(e_raw).to_vec())
}

// ── PS256 (RSA-PSS SHA-256) JAR helpers ──────────────────────────────────────

const PS256_KID: &str = "jar-test-rsa-pss-key";

/// Generates a fresh RSA-2048 key for PS256 signing.
///
/// The underlying RSA key structure is identical to RS256; the difference is
/// padding at signing time (`RSA_PSS_SHA256` vs `RSA_PKCS1_SHA256`).
fn generate_ps256() -> Rs256TestKey {
    let keypair = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).expect("rsa keygen");
    let pkcs8 = keypair.serialize_der();
    let ring_key = ring::signature::RsaKeyPair::from_pkcs8(&pkcs8).expect("ring from_pkcs8");
    let (n_bytes, e_bytes) = pkcs1_public_key_components(ring_key.public().as_ref());
    Rs256TestKey {
        pkcs8,
        n_b64: URL_SAFE_NO_PAD.encode(&n_bytes),
        e_b64: URL_SAFE_NO_PAD.encode(&e_bytes),
    }
}

/// Builds a JWKS JSON string with one RSA key advertising PS256.
fn jwks_json_ps256(n_b64: &str, e_b64: &str) -> String {
    format!(
        r#"{{"keys":[{{"kty":"RSA","alg":"PS256","kid":"{PS256_KID}","n":"{n_b64}","e":"{e_b64}"}}]}}"#
    )
}

/// Signs a JAR JWT using PS256 (RSA-PSS SHA-256).
fn sign_jar_ps256(pkcs8_bytes: &[u8], client_id: &str, issuer: &str, jti: &str) -> String {
    let rng = SystemRandom::new();
    let exp = EPOCH_MICROS / 1_000_000 + 3600;
    let iat = EPOCH_MICROS / 1_000_000;
    let pkce_challenge = {
        use data_encoding::BASE64URL_NOPAD;
        BASE64URL_NOPAD
            .encode(ring::digest::digest(&ring::digest::SHA256, PKCE_VERIFIER.as_bytes()).as_ref())
    };
    let header = serde_json::json!({"alg": "PS256", "kid": PS256_KID});
    let claims = serde_json::json!({
        "iss": client_id, "aud": issuer, "exp": exp, "iat": iat, "jti": jti,
        "client_id": client_id, "response_type": "code", "redirect_uri": REDIRECT_URI,
        "scope": "openid", "state": "test-state-ps256",
        "code_challenge": pkce_challenge,
        "code_challenge_method": "S256",
    });
    let h_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header"));
    let c_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("claims"));
    let signing_input = format!("{h_b64}.{c_b64}");

    let ring_key = ring::signature::RsaKeyPair::from_pkcs8(pkcs8_bytes).expect("from_pkcs8");
    let mut sig = vec![0u8; ring_key.public().modulus_len()];
    ring_key
        .sign(
            &ring::signature::RSA_PSS_SHA256,
            &rng,
            signing_input.as_bytes(),
            &mut sig,
        )
        .expect("rsa-pss sign");
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(&sig))
}

// ── Direct-path helpers ───────────────────────────────────────────────────────

/// Creates a test user in the given env.
fn create_test_user(env: &TestEnv) -> UserId {
    env.engine
        .create_user(
            &env.realm,
            &CreateUserRequest {
                email: format!("jar-direct-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "JAR Direct Test User".to_string(),
                ..CreateUserRequest::default()
            },
        )
        .expect("create test user")
        .id()
        .clone()
}

/// Calls `issue_authorization_code` with `jar_request = Some(jar_jwt)`.
/// Outer params are intentionally minimal — the JAR claims override them.
fn authorize_direct_with_jar(
    env: &TestEnv,
    user_id: &UserId,
    client_id: &ClientId,
    jar_jwt: String,
) -> Result<AuthorizationResponse, IdentityError> {
    env.engine.issue_authorization_code(
        &env.realm,
        user_id,
        client_id,
        REDIRECT_URI,
        "openid",
        "outer-state-ignored",
        None,
        None,
        None,
        vec![],
        None,
        Some(jar_jwt),
    )
}

// ── Direct-path tests (scenarios 10–16) ──────────────────────────────────────

/// Scenario 10 — direct authorize path: valid EdDSA JAR accepted.
#[test]
fn jar_direct_authorize_eddsa_accepted() {
    let env = setup();
    let (pkcs8, pub_bytes) = generate_ed25519();
    let jwks = jwks_json(&pub_bytes);
    let client = register_client_with_jwks(&env, &jwks);
    let client_id = client.client_id().clone();
    let cid_str = client_id.to_string();
    let user_id = create_test_user(&env);

    let jar = sign_jar(
        &pkcs8,
        &cid_str,
        &env.issuer,
        None,
        None,
        None,
        Some("jti-direct-eddsa-1"),
        None,
    );
    let resp = authorize_direct_with_jar(&env, &user_id, &client_id, jar)
        .expect("valid EdDSA JAR on direct path must succeed");

    assert!(
        !resp.code().is_empty(),
        "authorization code must be non-empty"
    );
    assert_eq!(
        resp.state(),
        "test-state-jar",
        "state must come from the JAR"
    );
}

/// Scenario 11 — direct authorize path: ES256 JAR accepted.
#[test]
fn jar_direct_authorize_es256_accepted() {
    let env = setup();
    let (pkcs8, x, y) = generate_es256();
    let jwks = jwks_json_es256(&x, &y);
    let client = register_client_with_jwks(&env, &jwks);
    let client_id = client.client_id().clone();
    let cid_str = client_id.to_string();
    let user_id = create_test_user(&env);

    let jar = sign_jar_es256(&pkcs8, &cid_str, &env.issuer, "jti-direct-es256-1");
    let resp = authorize_direct_with_jar(&env, &user_id, &client_id, jar)
        .expect("valid ES256 JAR on direct path must succeed");

    assert!(
        !resp.code().is_empty(),
        "authorization code must be non-empty"
    );
    assert_eq!(
        resp.state(),
        "test-state-es256",
        "state must come from the JAR"
    );
}

/// Scenario 12 — direct authorize path: RS256 JAR accepted.
#[test]
fn jar_direct_authorize_rs256_accepted() {
    let env = setup();
    let rs256 = generate_rs256();
    let jwks = jwks_json_rs256(&rs256.n_b64, &rs256.e_b64);
    let client = register_client_with_jwks(&env, &jwks);
    let client_id = client.client_id().clone();
    let cid_str = client_id.to_string();
    let user_id = create_test_user(&env);

    let jar = sign_jar_rs256(&rs256.pkcs8, &cid_str, &env.issuer, "jti-direct-rs256-1");
    let resp = authorize_direct_with_jar(&env, &user_id, &client_id, jar)
        .expect("valid RS256 JAR on direct path must succeed");

    assert!(
        !resp.code().is_empty(),
        "authorization code must be non-empty"
    );
    assert_eq!(
        resp.state(),
        "test-state-rs256",
        "state must come from the JAR"
    );
}

/// Scenario 13 — direct authorize path: `alg:none` JAR rejected.
#[test]
fn jar_direct_alg_none_rejected() {
    let env = setup();
    let (pkcs8, pub_bytes) = generate_ed25519();
    let jwks = jwks_json(&pub_bytes);
    let client = register_client_with_jwks(&env, &jwks);
    let client_id = client.client_id().clone();
    let cid_str = client_id.to_string();
    let user_id = create_test_user(&env);

    let jar = sign_jar(
        &pkcs8,
        &cid_str,
        &env.issuer,
        Some("none"),
        None,
        None,
        Some("jti-direct-none-1"),
        None,
    );
    let parts: Vec<&str> = jar.split('.').collect();
    let none_jwt = format!("{}.{}.", parts[0], parts[1]);

    let err = authorize_direct_with_jar(&env, &user_id, &client_id, none_jwt)
        .expect_err("alg:none on direct path must be rejected");

    assert!(
        matches!(err, IdentityError::InvalidJar { .. }),
        "expected InvalidJar for alg:none, got {err:?}"
    );
}

/// Scenario 14 — direct authorize path: expired JAR rejected.
#[test]
fn jar_direct_expired_rejected() {
    let env = setup();
    let (pkcs8, pub_bytes) = generate_ed25519();
    let jwks = jwks_json(&pub_bytes);
    let client = register_client_with_jwks(&env, &jwks);
    let client_id = client.client_id().clone();
    let cid_str = client_id.to_string();
    let user_id = create_test_user(&env);

    let past_exp = EPOCH_MICROS / 1_000_000 - 1;
    let jar = sign_jar(
        &pkcs8,
        &cid_str,
        &env.issuer,
        None,
        None,
        Some(past_exp),
        Some("jti-direct-exp-1"),
        None,
    );
    let err = authorize_direct_with_jar(&env, &user_id, &client_id, jar)
        .expect_err("expired JAR on direct path must be rejected");

    assert!(
        matches!(err, IdentityError::InvalidJar { .. }),
        "expected InvalidJar for expired token, got {err:?}"
    );
}

/// Scenario 15 — direct authorize path: JAR `client_id` claim mismatch rejected.
///
/// `iss` equals the outer `client_id` (passes `verify_jar`'s iss check), but
/// the `client_id` claim inside the JWT is a different value. `authorize()`
/// must detect the mismatch and reject.
#[test]
fn jar_direct_client_id_mismatch_rejected() {
    let env = setup();
    let (pkcs8, pub_bytes) = generate_ed25519();
    let jwks = jwks_json(&pub_bytes);
    let client = register_client_with_jwks(&env, &jwks);
    let client_id = client.client_id().clone();
    let outer_cid = client_id.to_string();
    let user_id = create_test_user(&env);

    // Build a JAR where iss == outer client_id (satisfies verify_jar) but
    // the client_id claim contains a different value (triggers mismatch in authorize).
    let exp = EPOCH_MICROS / 1_000_000 + 3600;
    let iat = EPOCH_MICROS / 1_000_000;
    let pkce_challenge = {
        use data_encoding::BASE64URL_NOPAD;
        BASE64URL_NOPAD
            .encode(ring::digest::digest(&ring::digest::SHA256, PKCE_VERIFIER.as_bytes()).as_ref())
    };
    let header = serde_json::json!({"alg": "EdDSA", "kid": TEST_KID});
    let claims = serde_json::json!({
        "iss": outer_cid,
        "aud": &env.issuer,
        "exp": exp, "iat": iat,
        "jti": "jti-direct-mismatch-1",
        "client_id": "client_that_does_not_match",
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": "openid",
        "state": "test-state-mismatch",
        "code_challenge": pkce_challenge,
        "code_challenge_method": "S256",
    });
    let h_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header"));
    let c_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("claims"));
    let signing_input = format!("{h_b64}.{c_b64}");
    let pair = Ed25519KeyPair::from_pkcs8(&pkcs8).expect("from_pkcs8");
    let sig = pair.sign(signing_input.as_bytes());
    let mismatch_jar = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()));

    let err = authorize_direct_with_jar(&env, &user_id, &client_id, mismatch_jar)
        .expect_err("JAR client_id claim mismatch must be rejected");

    assert!(
        matches!(err, IdentityError::InvalidJar { .. }),
        "expected InvalidJar for client_id mismatch, got {err:?}"
    );
}

/// Scenario 16 — direct authorize path: client without JWKS can't use JAR.
#[test]
fn jar_direct_missing_jwks_rejected() {
    let env = setup();
    let (pkcs8, pub_bytes) = generate_ed25519();
    // Register client without JWKS.
    let client = env
        .engine
        .register_client(
            &env.realm,
            &RegisterClientRequest {
                client_name: "No-JWKS Client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                jwks: None,
                ..Default::default()
            },
        )
        .expect("register client");
    let client_id = client.client_id().clone();
    let cid_str = client_id.to_string();
    let user_id = create_test_user(&env);

    let _ = pub_bytes; // unused — no JWKS registered for this client
    let jar = sign_jar(
        &pkcs8,
        &cid_str,
        &env.issuer,
        None,
        None,
        None,
        Some("jti-direct-nojwks-1"),
        None,
    );
    let err = authorize_direct_with_jar(&env, &user_id, &client_id, jar)
        .expect_err("JAR for client without JWKS must be rejected");

    assert!(
        matches!(err, IdentityError::InvalidJar { .. }),
        "expected InvalidJar for missing JWKS, got {err:?}"
    );
}

// ── PS256 tests (scenarios 17–19) ────────────────────────────────────────────

/// Scenario 17 — direct authorize path: PS256 JAR accepted.
///
/// Exercises the `PS256` branch in `verify_jar` (`RSA_PSS_2048_8192_SHA256`).
/// A future swap to `RSA_PKCS1_2048_8192_SHA256` would fail here immediately.
#[test]
fn jar_direct_authorize_ps256_accepted() {
    let env = setup();
    let ps256 = generate_ps256();
    let jwks = jwks_json_ps256(&ps256.n_b64, &ps256.e_b64);
    let client = register_client_with_jwks(&env, &jwks);
    let client_id = client.client_id().clone();
    let cid_str = client_id.to_string();
    let user_id = create_test_user(&env);

    let jar = sign_jar_ps256(&ps256.pkcs8, &cid_str, &env.issuer, "jti-direct-ps256-1");
    let resp = authorize_direct_with_jar(&env, &user_id, &client_id, jar)
        .expect("valid PS256 JAR on direct path must succeed");

    assert!(
        !resp.code().is_empty(),
        "authorization code must be non-empty"
    );
    assert_eq!(
        resp.state(),
        "test-state-ps256",
        "state must come from the JAR"
    );
}

/// Scenario 18 — PS256 JAR signed with the wrong RSA key is rejected.
///
/// Signs with `signing_key` but registers `registered_key` in the client JWKS.
/// The PS256 verifier must reject the mismatched signature with `InvalidJar`.
#[test]
fn jar_ps256_wrong_key_rejected() {
    let env = setup();
    let signing_key = generate_ps256();
    let registered_key = generate_ps256();
    let jwks = jwks_json_ps256(&registered_key.n_b64, &registered_key.e_b64);
    let client = register_client_with_jwks(&env, &jwks);
    let client_id = client.client_id().clone();
    let cid_str = client_id.to_string();
    let user_id = create_test_user(&env);

    let jar = sign_jar_ps256(
        &signing_key.pkcs8,
        &cid_str,
        &env.issuer,
        "jti-ps256-wrong-1",
    );
    let err = authorize_direct_with_jar(&env, &user_id, &client_id, jar)
        .expect_err("PS256 JAR signed with wrong key must be rejected");

    assert!(
        matches!(err, IdentityError::InvalidJar { .. }),
        "expected InvalidJar for wrong PS256 key, got {err:?}"
    );
}

/// Scenario 19 — PAR path: PS256 JAR accepted.
///
/// Mirrors Scenario 1 (PAR EdDSA) but with a PS256 key. Ensures the PS256
/// branch is reachable through `push_authorization_request`, not just the
/// direct authorize path.
#[test]
fn jar_par_ps256_accepted() {
    let env = setup();
    let ps256 = generate_ps256();
    let jwks = jwks_json_ps256(&ps256.n_b64, &ps256.e_b64);
    let client = register_client_with_jwks(&env, &jwks);
    let client_id = client.client_id().clone();
    let cid_str = client_id.to_string();

    let jar = sign_jar_ps256(&ps256.pkcs8, &cid_str, &env.issuer, "jti-par-ps256-1");
    let req = par_with_jar(client_id, jar);

    let resp = env
        .engine
        .push_authorization_request(&env.realm, &req)
        .expect("valid PS256 JAR on PAR path must succeed");

    assert!(
        resp.request_uri
            .starts_with("urn:ietf:params:oauth:request_uri:"),
        "request_uri must use the correct URN prefix"
    );
    assert_eq!(resp.expires_in, 90, "PAR TTL should be 90 s");
}
