#![allow(clippy::unwrap_used)]
//! Integration tests for DPoP (Demonstrating Proof-of-Possession — RFC 9449).
//!
//! Tests the token endpoint DPoP proof validation, `cnf.jkt` claim binding,
//! JTI replay rejection, and `DPoP-Nonce` header propagation.
//!
//! All tests use `tower::ServiceExt::oneshot` against a fully wired router.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use hearth::identity::{ClientTrustLevel, CreateRealmRequest, RegisterClientRequest};
use hearth::protocol::http::{router, AppState};
use ring::{
    rand::SystemRandom,
    signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING},
};
use tower::ServiceExt as _;

// ===== Key generation helpers =====

struct DPopKey {
    key_pair: EcdsaKeyPair,
    /// Public key bytes: `0x04 || x(32) || y(32)`
    pub_bytes: Vec<u8>,
}

impl DPopKey {
    fn generate() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap();
        let pub_bytes = key_pair.public_key().as_ref().to_vec();
        Self {
            key_pair,
            pub_bytes,
        }
    }

    /// Returns the public key as a JWK JSON object (lexicographically sorted keys per RFC 7638).
    fn public_jwk_json(&self) -> serde_json::Value {
        // Uncompressed: 0x04 || x(32) || y(32)
        let x = &self.pub_bytes[1..33];
        let y = &self.pub_bytes[33..65];
        let x_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x);
        let y_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(y);
        // RFC 7638: required members in lexicographic order for EC P-256
        serde_json::json!({"crv":"P-256","kty":"EC","x":x_b64,"y":y_b64})
    }

    /// Signs `data` with the private key and returns the raw r||s 64-byte signature.
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        let rng = SystemRandom::new();
        self.key_pair.sign(&rng, data).unwrap().as_ref().to_vec()
    }
}

/// Builds a DPoP proof JWT for the given method, URL, and optional nonce.
#[allow(clippy::similar_names)] // htm/htu are the canonical RFC 9449 DPoP claim names
fn make_dpop_proof(key: &DPopKey, htm: &str, htu: &str, nonce: Option<&str>) -> String {
    let jwk = key.public_jwk_json();
    let header = serde_json::json!({
        "alg": "ES256",
        "jwk": jwk,
        "typ": "dpop+jwt"
    });
    let iat = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let jti = uuid::Uuid::new_v4().to_string();
    let mut claims = serde_json::json!({
        "htm": htm,
        "htu": htu,
        "iat": iat,
        "jti": jti
    });
    if let Some(n) = nonce {
        claims["nonce"] = serde_json::Value::String(n.to_string());
    }

    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header_b64 = b64.encode(serde_json::to_string(&header).unwrap().as_bytes());
    let claims_b64 = b64.encode(serde_json::to_string(&claims).unwrap().as_bytes());
    let msg = format!("{header_b64}.{claims_b64}");
    let sig = key.sign(msg.as_bytes());
    let sig_b64 = b64.encode(&sig);
    format!("{header_b64}.{claims_b64}.{sig_b64}")
}

/// Builds the router with a deterministic DPoP nonce secret so nonces are predictable.
async fn build_app_with_key(harness: &common::TestHarness, nonce_secret: [u8; 32]) -> axum::Router {
    let state = AppState::new(
        harness.identity_arc(),
        harness.rbac_arc(),
        harness.audit_arc(),
    )
    .with_dpop_nonce_secret(nonce_secret);
    router(Arc::new(state))
}

/// Creates a test realm and registers a confidential client. Returns `(realm_id_str, client_id_str, client_secret)`.
async fn setup_realm_and_client(harness: &common::TestHarness) -> (String, String, String) {
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("dpop-test-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .unwrap();
    let realm_id = realm.id().as_uuid().to_string();
    let secret = "dpop-test-secret-123!".to_string();
    let client = harness
        .identity()
        .register_client(
            realm.id(),
            &RegisterClientRequest {
                client_name: "DPoP Test Client".to_string(),
                redirect_uris: vec![],
                client_secret: Some(secret.clone()),
                grant_types: vec!["client_credentials".to_string()],
                require_consent: false,
                client_logo_url: None,
                trust_level: ClientTrustLevel::FirstParty,
                ..Default::default()
            },
        )
        .unwrap();
    (realm_id, client.client_id().as_uuid().to_string(), secret)
}

// ===== Scenario DP-1: DPoP-bound client_credentials token =====

#[tokio::test]
async fn dpop_client_credentials_bound_token() {
    let h = common::TestHarness::embedded().await.unwrap();
    let (realm_id, client_id, client_secret) = setup_realm_and_client(&h).await;
    let state = Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()));

    let dpop_key = DPopKey::generate();
    let body = serde_json::json!({
        "grant_type": "client_credentials",
        "client_id": &client_id,
        "client_secret": &client_secret
    });

    // Step 1: send proof without nonce to get the server-issued nonce.
    let proof_no_nonce = make_dpop_proof(&dpop_key, "POST", "https://hearth.local/token", None);
    let nonce_resp = router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("X-Realm-ID", &realm_id)
                .header("Content-Type", "application/json")
                .header("DPoP", proof_no_nonce)
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let nonce = nonce_resp
        .headers()
        .get("DPoP-Nonce")
        .expect("401 must carry DPoP-Nonce")
        .to_str()
        .unwrap()
        .to_string();

    // Step 2: retry with the server-issued nonce.
    let proof = make_dpop_proof(
        &dpop_key,
        "POST",
        "https://hearth.local/token",
        Some(&nonce),
    );
    let resp = router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("X-Realm-ID", &realm_id)
                .header("Content-Type", "application/json")
                .header("DPoP", proof)
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK, "expected 200 with DPoP");

    // Response must include DPoP-Nonce header
    assert!(
        resp.headers().get("DPoP-Nonce").is_some(),
        "response must include DPoP-Nonce header"
    );

    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    // token_type must be DPoP, not Bearer
    assert_eq!(
        json["token_type"].as_str().unwrap(),
        "DPoP",
        "DPoP-bound token must have token_type=DPoP"
    );
    assert!(json["access_token"].as_str().is_some_and(|t| !t.is_empty()));
}

// ===== Scenario DP-2: cnf.jkt claim embedded in access token =====

#[tokio::test]
async fn dpop_access_token_carries_cnf_jkt() {
    let h = common::TestHarness::embedded().await.unwrap();
    let (realm_id, client_id, client_secret) = setup_realm_and_client(&h).await;
    let state = Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()));

    let dpop_key = DPopKey::generate();
    let body = serde_json::json!({
        "grant_type": "client_credentials",
        "client_id": &client_id,
        "client_secret": &client_secret
    });

    // Step 1: send proof without nonce to get the server-issued nonce.
    let proof_no_nonce = make_dpop_proof(&dpop_key, "POST", "https://hearth.local/token", None);
    let nonce_resp = router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("X-Realm-ID", &realm_id)
                .header("Content-Type", "application/json")
                .header("DPoP", proof_no_nonce)
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let nonce = nonce_resp
        .headers()
        .get("DPoP-Nonce")
        .expect("401 must carry DPoP-Nonce")
        .to_str()
        .unwrap()
        .to_string();

    // Step 2: retry with the server-issued nonce.
    let proof = make_dpop_proof(
        &dpop_key,
        "POST",
        "https://hearth.local/token",
        Some(&nonce),
    );
    let resp = router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("X-Realm-ID", &realm_id)
                .header("Content-Type", "application/json")
                .header("DPoP", proof)
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let access_token = json["access_token"].as_str().unwrap();

    // Decode the claims (without verification) and check cnf.jkt
    let claims = hearth::identity::decode_claims_unverified(access_token).unwrap();
    let cnf = claims.cnf.expect("access token must carry cnf claim");

    // Compute expected JKT from the key we used
    let jwk_json = dpop_key.public_jwk_json();
    let jwk_str = serde_json::to_string(&jwk_json).unwrap();
    let digest = ring::digest::digest(&ring::digest::SHA256, jwk_str.as_bytes());
    let expected_jkt = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.as_ref());

    assert_eq!(
        cnf.jkt, expected_jkt,
        "cnf.jkt must match the DPoP key thumbprint"
    );
}

// ===== Scenario DP-3: JTI replay rejection =====

#[tokio::test]
async fn dpop_replay_rejected() {
    let h = common::TestHarness::embedded().await.unwrap();
    let (realm_id, client_id, client_secret) = setup_realm_and_client(&h).await;
    // Share the same AppState (and JTI cache) across all requests.
    let state = Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()));

    let dpop_key = DPopKey::generate();
    let body_json = serde_json::json!({
        "grant_type": "client_credentials",
        "client_id": &client_id,
        "client_secret": &client_secret
    });

    let mk_req = |proof: &str| {
        Request::builder()
            .method("POST")
            .uri("/token")
            .header("X-Realm-ID", &realm_id)
            .header("Content-Type", "application/json")
            .header("DPoP", proof)
            .body(Body::from(serde_json::to_string(&body_json).unwrap()))
            .unwrap()
    };

    // Step 0: get the server-issued nonce (nonce grab).
    let proof_no_nonce = make_dpop_proof(&dpop_key, "POST", "https://hearth.local/token", None);
    let nonce_resp = router(Arc::clone(&state))
        .oneshot(mk_req(&proof_no_nonce))
        .await
        .unwrap();
    let nonce = nonce_resp
        .headers()
        .get("DPoP-Nonce")
        .expect("401 must carry DPoP-Nonce")
        .to_str()
        .unwrap()
        .to_string();

    // Use the same proof (same jti) for both replay-test requests to trigger replay rejection.
    let proof = make_dpop_proof(
        &dpop_key,
        "POST",
        "https://hearth.local/token",
        Some(&nonce),
    );

    let app1 = router(Arc::clone(&state));
    let app2 = router(Arc::clone(&state));

    // First request should succeed
    let resp1 = app1.oneshot(mk_req(&proof)).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::OK, "first request must succeed");

    // Second request with the same proof (same jti) must be rejected
    let resp2 = app2.oneshot(mk_req(&proof)).await.unwrap();
    assert_eq!(
        resp2.status(),
        StatusCode::UNAUTHORIZED,
        "replay must be rejected with 401"
    );
    let bytes = to_bytes(resp2.into_body(), 1024 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["error"].as_str().unwrap(), "use_dpop_nonce");
}

// ===== Scenario DP-4: Invalid DPoP proof rejected =====

#[tokio::test]
async fn dpop_invalid_proof_rejected() {
    let h = common::TestHarness::embedded().await.unwrap();
    let (realm_id, client_id, client_secret) = setup_realm_and_client(&h).await;
    let app = build_app_with_key(&h, [0u8; 32]).await;

    let body = serde_json::json!({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret
    });

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("X-Realm-ID", &realm_id)
                .header("Content-Type", "application/json")
                .header("DPoP", "not.a.valid.jwt")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "bad proof must be 401"
    );
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["error"].as_str().unwrap(), "invalid_dpop_proof");
}

// ===== Scenario DP-5: Without DPoP, token is plain Bearer but nonce is still returned =====

#[tokio::test]
async fn no_dpop_yields_bearer_token_with_nonce_header() {
    let h = common::TestHarness::embedded().await.unwrap();
    let (realm_id, client_id, client_secret) = setup_realm_and_client(&h).await;
    let app = build_app_with_key(&h, [0u8; 32]).await;

    let body = serde_json::json!({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret
    });

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("X-Realm-ID", &realm_id)
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    // Even without DPoP, the server must advertise a nonce for future use
    assert!(
        resp.headers().get("DPoP-Nonce").is_some(),
        "server must always return DPoP-Nonce header"
    );

    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["token_type"].as_str().unwrap(), "Bearer");

    // Access token must NOT carry a cnf claim
    let access_token = json["access_token"].as_str().unwrap();
    let claims = hearth::identity::decode_claims_unverified(access_token).unwrap();
    assert!(
        claims.cnf.is_none(),
        "plain Bearer token must not carry cnf claim"
    );
}

// ===== Scenario DP-nonce-required: missing nonce rejected =====

/// Server MUST reject a DPoP proof that omits the nonce (RFC 9449 §9.1).
///
/// Flow:
/// 1. Send DPoP proof without nonce → 401 `use_dpop_nonce` + `DPoP-Nonce` header.
/// 2. Retry with the nonce from the error response → 200 OK.
#[tokio::test]
async fn dpop_nonce_required_missing_nonce_rejected() {
    let nonce_secret = [0xAB_u8; 32];
    let h = common::TestHarness::embedded().await.unwrap();
    let (realm_id, client_id, client_secret) = setup_realm_and_client(&h).await;
    let state = Arc::new(
        AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc())
            .with_dpop_nonce_secret(nonce_secret),
    );
    let dpop_key = DPopKey::generate();
    let body_json = serde_json::json!({
        "grant_type": "client_credentials",
        "client_id": &client_id,
        "client_secret": &client_secret
    });
    // Step 1: proof without nonce → 401 + DPoP-Nonce
    let proof_no_nonce = make_dpop_proof(&dpop_key, "POST", "https://hearth.local/token", None);
    let app1 = router(Arc::clone(&state));
    let resp1 = app1
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("X-Realm-ID", &realm_id)
                .header("Content-Type", "application/json")
                .header("DPoP", &proof_no_nonce)
                .body(Body::from(serde_json::to_string(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp1.status(),
        StatusCode::UNAUTHORIZED,
        "DPoP without nonce must be 401"
    );
    let issued_nonce = resp1
        .headers()
        .get("DPoP-Nonce")
        .expect("401 response must contain DPoP-Nonce")
        .to_str()
        .unwrap()
        .to_string();
    let b1 = to_bytes(resp1.into_body(), 64 * 1024).await.unwrap();
    let j1: serde_json::Value = serde_json::from_slice(&b1).unwrap();
    assert_eq!(j1["error"].as_str().unwrap(), "use_dpop_nonce");
    // Step 2: retry with nonce → 200
    let proof_with_nonce = make_dpop_proof(
        &dpop_key,
        "POST",
        "https://hearth.local/token",
        Some(&issued_nonce),
    );
    let app2 = router(Arc::clone(&state));
    let resp2 = app2
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("X-Realm-ID", &realm_id)
                .header("Content-Type", "application/json")
                .header("DPoP", &proof_with_nonce)
                .body(Body::from(serde_json::to_string(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp2.status(),
        StatusCode::OK,
        "DPoP with nonce must succeed"
    );
    let b2 = to_bytes(resp2.into_body(), 1024 * 1024).await.unwrap();
    let j2: serde_json::Value = serde_json::from_slice(&b2).unwrap();
    assert_eq!(j2["token_type"].as_str().unwrap(), "DPoP");
}

// ===== Scenario DP-Config: dpop_nonce_secret wiring =====

/// `AppState::with_dpop_nonce_secret` must wire the correct secret into the DPoP processor.
///
/// Verified by checking that `current_nonce` returns the same value as computing the
/// nonce directly with the secret.
#[tokio::test]
async fn app_state_with_dpop_nonce_secret_stores_value() {
    let h = common::TestHarness::embedded().await.unwrap();
    let secret = [0xDE_u8; 32];
    let state =
        AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()).with_dpop_nonce_secret(secret);
    let now_secs = 0_i64;
    let expected = hearth::identity::dpop::current_dpop_nonce(&secret, now_secs);
    assert_eq!(state.dpop.current_nonce(now_secs), expected);
}

/// Hearth's per-realm DPoP nonce secret generator must never produce the zero
/// key and must be stable across calls for the same realm.
///
/// This drives the real `IdentityEngine::get_realm_dpop_nonce_secret` path
/// (CSPRNG generation + encrypted persistence + in-memory cache) rather than
/// exercising `ring::rand` in isolation. The zero-key guard and idempotence are
/// Hearth invariants: `current_dpop_nonce` uses the secret as an HMAC key, so a
/// zero or unstable secret would silently break DPoP-Nonce validation.
#[tokio::test]
async fn auto_generated_dpop_nonce_secret_is_nonzero() {
    let h = common::TestHarness::embedded().await.unwrap();
    let realm = h.create_realm();

    let secret1 = h.identity().get_realm_dpop_nonce_secret(&realm).unwrap();
    assert_ne!(
        secret1, [0u8; 32],
        "Hearth's auto-generated nonce secret must not be the zero key"
    );

    // Second call must return the identical secret (cache + persistence).
    let secret2 = h.identity().get_realm_dpop_nonce_secret(&realm).unwrap();
    assert_eq!(
        secret1, secret2,
        "the nonce secret for a realm must be stable across calls"
    );
}

/// The secret produced by Hearth is a working HMAC key for DPoP nonces and is
/// independently generated per realm.
///
/// The previous version decoded a fixed hex string with `u8::from_str_radix`,
/// asserting on `std` behaviour. This instead confirms that the secret Hearth
/// generates round-trips through Hearth's own `current_dpop_nonce` /
/// `is_valid_dpop_nonce`, and that two realms get distinct secrets (so nonces
/// from one realm do not validate against another).
#[tokio::test]
async fn dpop_nonce_secret_hex_decodes_correctly() {
    let h = common::TestHarness::embedded().await.unwrap();
    let realm_a = h.create_realm();
    let realm_b = h.create_realm();

    let secret_a = h.identity().get_realm_dpop_nonce_secret(&realm_a).unwrap();
    let secret_b = h.identity().get_realm_dpop_nonce_secret(&realm_b).unwrap();

    // Distinct realms must get independent secrets.
    assert_ne!(
        secret_a, secret_b,
        "each realm must receive an independent DPoP nonce secret"
    );

    // The secret must produce a nonce that Hearth validates as current.
    let now_secs = 1_700_000_000_i64;
    let nonce = hearth::identity::dpop::current_dpop_nonce(&secret_a, now_secs);
    assert!(
        hearth::identity::dpop::is_valid_dpop_nonce(&secret_a, &nonce, now_secs),
        "a nonce minted from realm A's secret must validate against realm A"
    );
    // A nonce from realm A must NOT validate against realm B's secret.
    assert!(
        !hearth::identity::dpop::is_valid_dpop_nonce(&secret_b, &nonce, now_secs),
        "realm A's nonce must not validate against realm B's independent secret"
    );
}

/// Builds a DPoP proof for a resource server request — includes the `ath` claim
/// (`BASE64URL(SHA-256(access_token))`) required by RFC 9449 §4.2 when the
/// proof accompanies an access token at a resource endpoint.
#[allow(clippy::similar_names)]
fn make_resource_dpop_proof(key: &DPopKey, htm: &str, htu: &str, access_token: &str) -> String {
    use ring::digest;
    let jwk = key.public_jwk_json();
    let header = serde_json::json!({"alg": "ES256", "jwk": jwk, "typ": "dpop+jwt"});
    let iat = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let jti = uuid::Uuid::new_v4().to_string();
    let ath_bytes = digest::digest(&digest::SHA256, access_token.as_bytes());
    let ath = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(ath_bytes.as_ref());
    let claims = serde_json::json!({"htm": htm, "htu": htu, "iat": iat, "jti": jti, "ath": ath});

    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header_b64 = b64.encode(serde_json::to_string(&header).unwrap().as_bytes());
    let claims_b64 = b64.encode(serde_json::to_string(&claims).unwrap().as_bytes());
    let msg = format!("{header_b64}.{claims_b64}");
    let sig = key.sign(msg.as_bytes());
    format!("{header_b64}.{claims_b64}.{}", b64.encode(&sig))
}

// ===== Scenario DP-7: cnf-bound token without DPoP proof at resource endpoint → 401 =====

/// Regression test for HEA-1465 / HEA-1462 F2.
///
/// A DPoP-bound access token presented as a plain Bearer token at a resource
/// endpoint MUST be rejected with 401 — not silently accepted.
#[tokio::test]
async fn dpop_cnf_bound_token_without_proof_at_resource_endpoint_is_401() {
    let h = common::TestHarness::embedded().await.unwrap();
    let (realm_id, client_id, client_secret) = setup_realm_and_client(&h).await;
    // Share AppState so the JTI cache is consistent across both legs.
    let state = Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()));
    let token_app = router(Arc::clone(&state));
    let resource_app = router(Arc::clone(&state));

    // Issue a DPoP-bound access token.
    let dpop_key = DPopKey::generate();
    let body = serde_json::json!({
        "grant_type": "client_credentials",
        "client_id": &client_id,
        "client_secret": &client_secret
    });

    // Step 0: get the server-issued nonce.
    let nonce_proof = make_dpop_proof(&dpop_key, "POST", "https://hearth.local/token", None);
    let nonce_resp = router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("X-Realm-ID", &realm_id)
                .header("Content-Type", "application/json")
                .header("DPoP", nonce_proof)
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let nonce = nonce_resp
        .headers()
        .get("DPoP-Nonce")
        .expect("401 must carry DPoP-Nonce")
        .to_str()
        .unwrap()
        .to_string();

    // Issue DPoP-bound token with the server-provided nonce.
    let token_proof = make_dpop_proof(
        &dpop_key,
        "POST",
        "https://hearth.local/token",
        Some(&nonce),
    );
    let token_resp = token_app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("X-Realm-ID", &realm_id)
                .header("Content-Type", "application/json")
                .header("DPoP", token_proof)
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        token_resp.status(),
        StatusCode::OK,
        "token issuance must succeed"
    );
    let bytes = to_bytes(token_resp.into_body(), 1024 * 1024).await.unwrap();
    let token_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let access_token = token_json["access_token"].as_str().unwrap().to_string();
    assert_eq!(token_json["token_type"].as_str().unwrap(), "DPoP");

    // Present the DPoP-bound token WITHOUT a DPoP proof header — must be rejected.
    let resp = resource_app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/oauth/consents")
                .header("X-Realm-ID", &realm_id)
                .header("Authorization", format!("Bearer {access_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "cnf-bound token without DPoP proof must be rejected with 401"
    );
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        json["error"].as_str().unwrap(),
        "invalid_token",
        "error body must be invalid_token"
    );
    // error_description confirms this is DPoP rejection, not sub-parsing failure.
    assert!(
        json["error_description"]
            .as_str()
            .is_some_and(|d| d.contains("DPoP")),
        "error_description must indicate DPoP proof was required; got: {json}"
    );
}

// ===== Scenario DP-8: cnf-bound token with valid DPoP proof at resource endpoint → auth passes =====

/// Positive case for HEA-1465: valid DPoP proof with `ath` at a resource
/// endpoint must NOT be rejected by DPoP enforcement. Any remaining failure
/// (e.g. sub parsing for a client-credentials token) is unrelated to DPoP.
#[tokio::test]
async fn dpop_cnf_bound_token_with_valid_proof_at_resource_endpoint_passes_auth() {
    let h = common::TestHarness::embedded().await.unwrap();
    let (realm_id, client_id, client_secret) = setup_realm_and_client(&h).await;
    let state = Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()));
    let token_app = router(Arc::clone(&state));
    let resource_app = router(Arc::clone(&state));

    // Issue a DPoP-bound access token via two-step nonce flow.
    let dpop_key = DPopKey::generate();
    let body = serde_json::json!({
        "grant_type": "client_credentials",
        "client_id": &client_id,
        "client_secret": &client_secret
    });

    // Step 0: get the server-issued nonce.
    let nonce_proof = make_dpop_proof(&dpop_key, "POST", "https://hearth.local/token", None);
    let nonce_resp = router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("X-Realm-ID", &realm_id)
                .header("Content-Type", "application/json")
                .header("DPoP", nonce_proof)
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let nonce = nonce_resp
        .headers()
        .get("DPoP-Nonce")
        .expect("401 must carry DPoP-Nonce")
        .to_str()
        .unwrap()
        .to_string();

    let token_proof = make_dpop_proof(
        &dpop_key,
        "POST",
        "https://hearth.local/token",
        Some(&nonce),
    );
    let token_resp = token_app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("X-Realm-ID", &realm_id)
                .header("Content-Type", "application/json")
                .header("DPoP", token_proof)
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(token_resp.status(), StatusCode::OK);
    let bytes = to_bytes(token_resp.into_body(), 1024 * 1024).await.unwrap();
    let token_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let access_token = token_json["access_token"].as_str().unwrap().to_string();

    // Present the token WITH a valid DPoP proof including the ath claim.
    let resource_proof = make_resource_dpop_proof(
        &dpop_key,
        "GET",
        "https://hearth.local/oauth/consents",
        &access_token,
    );
    let resp = resource_app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/oauth/consents")
                .header("X-Realm-ID", &realm_id)
                .header("Authorization", format!("Bearer {access_token}"))
                .header("DPoP", resource_proof)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // DPoP enforcement must not reject the request. If 401, it must NOT have
    // an error_description (which would indicate DPoP rejection). Sub-parsing
    // failure for client_credentials tokens is a separate, expected limitation.
    // Precondition: a client_credentials token has no `sub`, so authorization
    // at the resource endpoint fails with 401 for that *separate, expected*
    // reason. Assert it unconditionally so the branch below can never be
    // skipped (which would let the DPoP-rejection check pass vacuously).
    let status = resp.status();
    let body_bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "client_credentials token must reach the resource endpoint and 401 on sub-parsing; got {status}"
    );

    // Outcome: the 401 must NOT be a DPoP rejection. DPoP rejections carry an
    // `error_description` naming the DPoP failure; a bare 401 (no
    // `error_description`) proves the valid proof + `ath` passed DPoP enforcement.
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert!(
        json.get("error_description").is_none(),
        "valid DPoP proof must not be rejected by DPoP enforcement; got: {json}"
    );
}

// ===== Scenario DP-6: htm mismatch rejected =====

#[tokio::test]
async fn dpop_htm_mismatch_rejected() {
    let h = common::TestHarness::embedded().await.unwrap();
    let (realm_id, client_id, client_secret) = setup_realm_and_client(&h).await;
    let app = build_app_with_key(&h, [0u8; 32]).await;

    let dpop_key = DPopKey::generate();
    // proof says GET but actual request is POST
    let proof = make_dpop_proof(&dpop_key, "GET", "https://hearth.local/token", None);

    let body = serde_json::json!({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret
    });

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("X-Realm-ID", &realm_id)
                .header("Content-Type", "application/json")
                .header("DPoP", proof)
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["error"].as_str().unwrap(), "invalid_dpop_proof");
}
