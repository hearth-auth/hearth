#![allow(clippy::unwrap_used)]
//! A-11 / task 26.20 — `/v1/tools/invoke` must check the DPoP key binding
//! **before** it burns the proof's JTI.
//!
//! `src/protocol/http/auth.rs` already gets this order right and
//! `src/identity/engine/approval.rs` wrote the rule down for capability tokens
//! ("this check MUST run before the JTI is burned. Spending the JTI on a failed
//! caller-binding lets any actor grief the legitimate caller").
//! `tool_invocation.rs` had the two statements inverted, so a proof that failed
//! `cnf.jkt` binding still consumed its one-shot replay slot — and because the
//! JTI store is durable and realm-wide, that slot was then spent for every
//! endpoint in the realm.

mod common;

use base64::Engine as _;
use hearth::identity::{
    ClientCredentialsRequest, ClientTrustLevel, CreateRealmRequest, IdentityError,
    RegisterClientRequest,
};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use sha2::{Digest, Sha256};

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// An ES256 key pair plus the JWK it advertises in a DPoP proof header.
struct DPopKey {
    key_pair: EcdsaKeyPair,
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

    fn public_jwk_json(&self) -> serde_json::Value {
        let x = B64.encode(&self.pub_bytes[1..33]);
        let y = B64.encode(&self.pub_bytes[33..65]);
        serde_json::json!({"crv":"P-256","kty":"EC","x":x,"y":y})
    }

    fn sign(&self, data: &[u8]) -> Vec<u8> {
        let rng = SystemRandom::new();
        self.key_pair.sign(&rng, data).unwrap().as_ref().to_vec()
    }
}

/// Builds a DPoP proof for `POST {htu}` carrying `ath = base64url(SHA-256(token))`
/// and the supplied `jti`.
#[allow(clippy::similar_names)] // htm/htu are the canonical RFC 9449 claim names
fn make_proof(key: &DPopKey, htu: &str, access_token: &str, jti: &str) -> String {
    let header = serde_json::json!({
        "alg": "ES256",
        "jwk": key.public_jwk_json(),
        "typ": "dpop+jwt",
    });
    let iat = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let ath = B64.encode(Sha256::digest(access_token.as_bytes()));
    let claims = serde_json::json!({
        "htm": "POST",
        "htu": htu,
        "iat": iat,
        "jti": jti,
        "ath": ath,
    });
    let header_b64 = B64.encode(serde_json::to_string(&header).unwrap().as_bytes());
    let claims_b64 = B64.encode(serde_json::to_string(&claims).unwrap().as_bytes());
    let msg = format!("{header_b64}.{claims_b64}");
    let sig_b64 = B64.encode(key.sign(msg.as_bytes()));
    format!("{msg}.{sig_b64}")
}

/// A DPoP proof rejected for key-binding mismatch must leave its JTI unspent.
///
/// The access token is bound to a thumbprint no real key can produce, so the
/// proof below always fails the `cnf.jkt` comparison. Afterwards the JTI is
/// offered to the realm's replay store directly: if the handler had already
/// recorded it, the store answers `DPopProofReplay` and the legitimate holder
/// of that proof has been griefed out of their own one-shot slot.
#[tokio::test]
async fn failed_dpop_binding_does_not_consume_the_proof_jti() {
    let h = common::TestHarness::server_with_agent_approval()
        .await
        .expect("harness");
    let base = h.base_url().expect("server mode").to_string();

    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("dpop-order-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();
    h.rbac().seed_realm(&realm).expect("seed realm");

    let client_secret = format!("dpop-order-secret-{}", uuid::Uuid::new_v4());
    let oauth_client = h
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "DPoP Order Client".to_string(),
                redirect_uris: vec![],
                client_secret: Some(client_secret.clone()),
                grant_types: vec!["client_credentials".to_string()],
                trust_level: ClientTrustLevel::ThirdParty,
                ..RegisterClientRequest::default()
            },
        )
        .expect("register client");

    // Bind the token to a thumbprint the proof key can never match, so the
    // request fails the binding check and nothing else.
    let cc = h
        .identity()
        .client_credentials_token(
            &realm,
            &ClientCredentialsRequest {
                client_id: oauth_client.client_id().clone(),
                client_secret: Some(client_secret),
                scope: Some("openid".to_string()),
                dpop_jkt: Some("not-a-real-thumbprint-AAAAAAAAAAAA".to_string()),
                client_assertion_type: None,
                client_assertion: None,
            },
        )
        .expect("client_credentials_token");
    let bound_token = cc.access_token().to_string();

    let issuer = h.identity().oidc_discovery().issuer.clone();
    let htu = format!("{issuer}/v1/tools/invoke");
    let key = DPopKey::generate();
    let jti = uuid::Uuid::new_v4().to_string();
    let proof = make_proof(&key, &htu, &bound_token, &jti);

    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/tools/invoke"))
        .header("Authorization", format!("Bearer {bound_token}"))
        .header("DPoP", proof)
        .header("X-Realm-ID", realm.as_uuid().to_string())
        .json(&serde_json::json!({"tool": "read_file", "action": "invoke"}))
        .send()
        .await
        .expect("request");

    assert_eq!(
        resp.status().as_u16(),
        401,
        "a proof whose key does not match cnf.jkt must be rejected"
    );

    // The load-bearing assertion: the JTI must still be spendable.
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let first_use = h
        .identity()
        .check_and_record_dpop_jti(&realm, &jti, now_secs);
    assert!(
        first_use.is_ok(),
        "the rejected proof must not have burned its JTI; got {first_use:?}"
    );

    // Sanity: the store really does detect a second use, so the assertion above
    // is not vacuously true for every JTI.
    let second_use = h
        .identity()
        .check_and_record_dpop_jti(&realm, &jti, now_secs);
    assert!(
        matches!(second_use, Err(IdentityError::DPopProofReplay)),
        "the replay store must reject a genuine second use; got {second_use:?}"
    );
}
