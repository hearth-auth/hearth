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
    let mut state = AppState::new(
        harness.identity_arc(),
        harness.rbac_arc(),
        harness.audit_arc(),
    );
    state.dpop_nonce_secret = nonce_secret;
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
    let app = build_app_with_key(&h, [0u8; 32]).await;

    let dpop_key = DPopKey::generate();
    let proof = make_dpop_proof(&dpop_key, "POST", "https://hearth.local/token", None);

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
    let app = build_app_with_key(&h, [0u8; 32]).await;

    let dpop_key = DPopKey::generate();
    let proof = make_dpop_proof(&dpop_key, "POST", "https://hearth.local/token", None);

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
    // Share the same AppState (and JTI cache) across both requests
    let state = Arc::new({
        let mut s = AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc());
        s.dpop_nonce_secret = [0u8; 32];
        s
    });
    let app1 = router(Arc::clone(&state));
    let app2 = router(Arc::clone(&state));

    let dpop_key = DPopKey::generate();
    // Use the same proof for both requests (same jti)
    let proof = make_dpop_proof(&dpop_key, "POST", "https://hearth.local/token", None);

    let mk_req = |proof: &str| {
        let body = serde_json::json!({
            "grant_type": "client_credentials",
            "client_id": &client_id,
            "client_secret": &client_secret
        });
        Request::builder()
            .method("POST")
            .uri("/token")
            .header("X-Realm-ID", &realm_id)
            .header("Content-Type", "application/json")
            .header("DPoP", proof)
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap()
    };

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
