#![allow(clippy::unwrap_used)]
//! GA audit 2026-09-28 L7 — the magic-link grant answered `token_type: "DPoP"`
//! whenever the request carried a DPoP proof, but the tokens it issued carry
//! no `cnf` binding. A client told "DPoP" sends proofs a resource server never
//! checks and believes the token is sender-constrained when a thief can
//! replay it as a plain bearer. The grant must answer `Bearer` for an unbound
//! token.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use hearth::identity::{CreateRealmRequest, CreateUserRequest};
use hearth::protocol::http::{router, AppState};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use tower::ServiceExt as _;

/// Builds a token-endpoint DPoP proof (no `ath`) with a fresh ES256 key.
#[allow(clippy::similar_names)]
fn token_endpoint_proof(key: &EcdsaKeyPair, htu: &str, nonce: Option<&str>) -> String {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let public = key.public_key().as_ref();
    let jwk = serde_json::json!({
        "crv": "P-256",
        "kty": "EC",
        "x": b64.encode(&public[1..33]),
        "y": b64.encode(&public[33..65]),
    });
    let header = serde_json::json!({"alg": "ES256", "jwk": jwk, "typ": "dpop+jwt"});
    #[allow(clippy::cast_possible_wrap)]
    let iat = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mut claims = serde_json::json!({
        "htm": "POST", "htu": htu, "iat": iat, "jti": uuid::Uuid::new_v4().to_string(),
    });
    if let Some(n) = nonce {
        claims["nonce"] = serde_json::Value::String(n.to_string());
    }
    let msg = format!(
        "{}.{}",
        b64.encode(serde_json::to_vec(&header).unwrap()),
        b64.encode(serde_json::to_vec(&claims).unwrap())
    );
    let sig = key.sign(&SystemRandom::new(), msg.as_bytes()).unwrap();
    format!("{msg}.{}", b64.encode(sig.as_ref()))
}

#[tokio::test]
async fn magic_link_grant_answers_bearer_for_its_unbound_tokens() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("ml-type-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();
    h.identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "type@magic.test".into(),
                display_name: "Magic".into(),
                ..Default::default()
            },
        )
        .expect("create user");
    let minted = h
        .identity()
        .request_magic_link(&realm, "type@magic.test")
        .expect("mint magic link");

    let state = Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()));
    let htu = h.identity().oidc_discovery().token_endpoint;
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let body = serde_json::json!({
        "grant_type": "urn:hearth:grant-type:magic-link",
        "token": minted.token(),
    })
    .to_string();
    let send = |proof: String| {
        router(Arc::clone(&state)).oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("x-realm-id", realm.as_uuid().to_string())
                .header("content-type", "application/json")
                .header("dpop", proof)
                .body(Body::from(body.clone()))
                .unwrap(),
        )
    };

    // Step 1: the server issues its DPoP nonce (RFC 9449 §9) before any grant
    // runs, so the magic link is not consumed here.
    let first = send(token_endpoint_proof(&key, &htu, None)).await.unwrap();
    let nonce = first
        .headers()
        .get("DPoP-Nonce")
        .expect("DPoP-Nonce header")
        .to_str()
        .unwrap()
        .to_string();

    let resp = send(token_endpoint_proof(&key, &htu, Some(&nonce)))
        .await
        .unwrap();
    let status = resp.status();
    let json: serde_json::Value =
        serde_json::from_slice(&to_bytes(resp.into_body(), 1 << 20).await.unwrap()).unwrap();
    assert_eq!(status, StatusCode::OK, "magic-link grant; body {json}");

    let access = json["access_token"].as_str().expect("access_token");
    let claims = h.identity().validate_token(&realm, access).expect("valid");
    assert!(
        claims.cnf.is_none(),
        "precondition: the magic-link grant issues unbound tokens"
    );
    assert_eq!(
        json["token_type"].as_str(),
        Some("Bearer"),
        "an unbound token must be announced as Bearer, not DPoP; body {json}"
    );
}
