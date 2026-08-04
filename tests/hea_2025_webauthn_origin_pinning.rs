#![allow(clippy::unwrap_used)]
//! HEA-2025 regression: WebAuthn REST endpoints must pin `rp_id` and `origin`
//! server-side rather than trusting the request body.
//!
//! Before the fix, `webauthn_auth_begin` set `rp_id = body.rp_id` and
//! `webauthn_auth_complete` set `origin = body.origin`. Both are
//! attacker-controlled, so the two controls that make WebAuthn
//! phishing-resistant — the `clientDataJSON.origin` match and the
//! `authenticatorData.rpIdHash` match — were compared attacker-vs-attacker
//! (self-referential no-ops, CWE-346).
//!
//! The browser path pins both to the configured public origin
//! (`web/handlers.rs`, L5). These tests assert the REST path now does the same:
//!
//! 1. `auth/begin` echoes the server-pinned RP ID, never the client's.
//! 2. `auth/complete` rejects an otherwise-valid assertion whose
//!    `clientDataJSON.origin` is not the server's configured origin — even
//!    when the request body's `origin` field agrees with the forged CDJ.
//! 3. Positive control: an assertion carrying the server-pinned origin
//!    succeeds, proving the rejection in (2) is origin-specific.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::core::RealmId;
use hearth::identity::{CreateRealmRequest, CreateUserRequest, RegistrationOptions, User};
use hearth::protocol::http::{router, AppState};
use serde_json::{json, Value};
use tower::ServiceExt;

// The default OIDC issuer in the test config is `https://hearth.local`, so the
// server-pinned origin/RP ID are these constants.
const PINNED_ORIGIN: &str = "https://hearth.local";
const PINNED_RP_ID: &str = "hearth.local";

fn build_app(h: &common::TestHarness) -> axum::Router {
    router(Arc::new(AppState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
    )))
}

fn create_realm(h: &common::TestHarness) -> RealmId {
    h.identity()
        .create_realm(&CreateRealmRequest {
            name: format!("hea2025-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone()
}

fn create_user(h: &common::TestHarness, realm: &RealmId) -> User {
    h.identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("hea2025-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "HEA-2025 User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user")
}

// ── minimal mock authenticator (mirrors tests/webauthn.rs) ──────────────────
mod webauthn_helper {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use ring::rand::{SecureRandom, SystemRandom};
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

    const COSE_ALG_ES256: i64 = -7;

    pub struct TestAuthenticator {
        key_pair_pkcs8: Vec<u8>,
        pub credential_id: Vec<u8>,
        rp_id: String,
    }

    impl TestAuthenticator {
        pub fn new(rp_id: &str) -> Self {
            let rng = SystemRandom::new();
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .expect("generate P-256 key");
            let mut cred_id = vec![0u8; 32];
            rng.fill(&mut cred_id).expect("random cred id");
            Self {
                key_pair_pkcs8: pkcs8.as_ref().to_vec(),
                credential_id: cred_id,
                rp_id: rp_id.to_string(),
            }
        }

        fn cose_public_key(&self) -> Vec<u8> {
            let rng = SystemRandom::new();
            let key_pair = EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                &self.key_pair_pkcs8,
                &rng,
            )
            .expect("load key pair");
            let pub_bytes = key_pair.public_key().as_ref();
            let x = &pub_bytes[1..33];
            let y = &pub_bytes[33..65];
            let cose_map = ciborium::Value::Map(vec![
                (
                    ciborium::Value::Integer(1.into()),
                    ciborium::Value::Integer(2.into()),
                ),
                (
                    ciborium::Value::Integer(3.into()),
                    ciborium::Value::Integer(COSE_ALG_ES256.into()),
                ),
                (
                    ciborium::Value::Integer((-1).into()),
                    ciborium::Value::Integer(1.into()),
                ),
                (
                    ciborium::Value::Integer((-2).into()),
                    ciborium::Value::Bytes(x.to_vec()),
                ),
                (
                    ciborium::Value::Integer((-3).into()),
                    ciborium::Value::Bytes(y.to_vec()),
                ),
            ]);
            let mut buf = Vec::new();
            ciborium::into_writer(&cose_map, &mut buf).expect("encode COSE key");
            buf
        }

        #[allow(clippy::cast_possible_truncation)]
        fn build_auth_data(&self, sign_count: u32, include_credential: bool) -> Vec<u8> {
            let rp_id_hash = ring::digest::digest(&ring::digest::SHA256, self.rp_id.as_bytes());
            let mut data = Vec::new();
            data.extend_from_slice(rp_id_hash.as_ref());
            let flags: u8 = if include_credential { 0x41 } else { 0x01 };
            data.push(flags);
            data.extend_from_slice(&sign_count.to_be_bytes());
            if include_credential {
                data.extend_from_slice(&[0u8; 16]); // AAGUID
                data.extend_from_slice(&(self.credential_id.len() as u16).to_be_bytes());
                data.extend_from_slice(&self.credential_id);
                data.extend_from_slice(&self.cose_public_key());
            }
            data
        }

        fn build_client_data_json(ceremony_type: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
            let challenge_b64 = URL_SAFE_NO_PAD.encode(challenge);
            serde_json::to_vec(&serde_json::json!({
                "type": ceremony_type,
                "challenge": challenge_b64,
                "origin": origin,
            }))
            .expect("serialize clientDataJSON")
        }

        fn sign(&self, data: &[u8]) -> Vec<u8> {
            let rng = SystemRandom::new();
            let key_pair = EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                &self.key_pair_pkcs8,
                &rng,
            )
            .expect("load key pair");
            key_pair.sign(&rng, data).expect("sign").as_ref().to_vec()
        }

        /// Builds a registration response with "none" attestation.
        pub fn build_registration_response(
            &self,
            challenge: &[u8],
            origin: &str,
        ) -> (Vec<u8>, Vec<u8>) {
            let client_data_json =
                Self::build_client_data_json("webauthn.create", challenge, origin);
            let auth_data = self.build_auth_data(0, true);
            let att_obj = ciborium::Value::Map(vec![
                (
                    ciborium::Value::Text("fmt".to_string()),
                    ciborium::Value::Text("none".to_string()),
                ),
                (
                    ciborium::Value::Text("attStmt".to_string()),
                    ciborium::Value::Map(vec![]),
                ),
                (
                    ciborium::Value::Text("authData".to_string()),
                    ciborium::Value::Bytes(auth_data),
                ),
            ]);
            let mut att_bytes = Vec::new();
            ciborium::into_writer(&att_obj, &mut att_bytes).expect("encode attestation");
            (client_data_json, att_bytes)
        }

        /// Builds an authentication response (assertion) for the given origin.
        /// Returns `(clientDataJSON, authenticatorData, signature)`.
        pub fn build_authentication_response(
            &self,
            challenge: &[u8],
            origin: &str,
            sign_count: u32,
        ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
            let client_data_json = Self::build_client_data_json("webauthn.get", challenge, origin);
            let auth_data = self.build_auth_data(sign_count, false);
            let client_data_hash = ring::digest::digest(&ring::digest::SHA256, &client_data_json);
            let mut signed_data = auth_data.clone();
            signed_data.extend_from_slice(client_data_hash.as_ref());
            let sig = self.sign(&signed_data);
            (client_data_json, auth_data, sig)
        }
    }
}

fn b64(data: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    URL_SAFE_NO_PAD.encode(data)
}

fn b64_decode(s: &str) -> Vec<u8> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    URL_SAFE_NO_PAD.decode(s).expect("decode b64url")
}

async fn post_json(
    app: &axum::Router,
    path: &str,
    realm: &RealmId,
    body: Value,
) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(path)
        .header("X-Realm-ID", realm.as_uuid().to_string())
        .header("Content-Type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

/// (1) `auth/begin` must return the server-pinned RP ID, ignoring the client's.
#[tokio::test]
async fn auth_begin_ignores_client_rp_id() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm(&harness);
    let user = create_user(&harness, &realm);
    let app = build_app(&harness);

    let (status, body) = post_json(
        &app,
        "/webauthn/auth/begin",
        &realm,
        json!({ "rp_id": "evil.com", "user_id": user.id().as_uuid().to_string() }),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "begin should succeed: {body}");
    assert_eq!(
        body["rp_id"].as_str(),
        Some(PINNED_RP_ID),
        "RP ID must be pinned server-side, not taken from the request body"
    );
    assert_ne!(body["rp_id"].as_str(), Some("evil.com"));
}

/// (2) + (3) `auth/complete` rejects a forged origin and accepts the pinned one.
#[tokio::test]
async fn auth_complete_pins_origin_server_side() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm(&harness);
    let user = create_user(&harness, &realm);
    let app = build_app(&harness);

    // Register a credential bound to the server-pinned RP ID / origin, directly
    // through the engine (the registration REST path is covered elsewhere).
    let authenticator = webauthn_helper::TestAuthenticator::new(PINNED_RP_ID);
    let reg_challenge = harness
        .identity()
        .start_webauthn_registration(
            &realm,
            user.id(),
            &RegistrationOptions {
                rp_id: PINNED_RP_ID.to_string(),
                discoverable: false,
            },
        )
        .expect("start registration");
    let (reg_cdj, reg_att) =
        authenticator.build_registration_response(&reg_challenge, PINNED_ORIGIN);
    harness
        .identity()
        .complete_webauthn_registration(&realm, user.id(), &reg_cdj, &reg_att, PINNED_ORIGIN, false)
        .expect("complete registration");

    let cred_id_b64 = b64(&authenticator.credential_id);
    let uid = user.id().as_uuid().to_string();

    // ---- (2) Forged origin is rejected ------------------------------------
    let (begin_status, begin_body) = post_json(
        &app,
        "/webauthn/auth/begin",
        &realm,
        json!({ "user_id": uid }),
    )
    .await;
    assert_eq!(begin_status, StatusCode::OK, "begin: {begin_body}");
    let challenge = b64_decode(begin_body["challenge"].as_str().expect("challenge"));

    // The attacker forges the origin in BOTH the clientDataJSON and the request
    // body — pre-fix this passed the (attacker-vs-attacker) origin check.
    let (cdj, auth_data, sig) =
        authenticator.build_authentication_response(&challenge, "https://evil.com", 1);
    let (status, body) = post_json(
        &app,
        "/webauthn/auth/complete",
        &realm,
        json!({
            "credential_id": cred_id_b64,
            "client_data_json": b64(&cdj),
            "authenticator_data": b64(&auth_data),
            "signature": b64(&sig),
            "origin": "https://evil.com",
        }),
    )
    .await;
    assert_ne!(
        status,
        StatusCode::OK,
        "forged-origin assertion must be rejected, got 200: {body}"
    );

    // ---- (3) Positive control: the pinned origin succeeds ------------------
    let (begin_status, begin_body) = post_json(
        &app,
        "/webauthn/auth/begin",
        &realm,
        json!({ "user_id": uid }),
    )
    .await;
    assert_eq!(begin_status, StatusCode::OK, "begin: {begin_body}");
    let challenge = b64_decode(begin_body["challenge"].as_str().expect("challenge"));

    let (cdj, auth_data, sig) =
        authenticator.build_authentication_response(&challenge, PINNED_ORIGIN, 2);
    let (status, body) = post_json(
        &app,
        "/webauthn/auth/complete",
        &realm,
        json!({
            "credential_id": cred_id_b64,
            "client_data_json": b64(&cdj),
            "authenticator_data": b64(&auth_data),
            "signature": b64(&sig),
            "origin": PINNED_ORIGIN,
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "assertion carrying the server-pinned origin must succeed: {body}"
    );
    // `user_id` is the `UserId` Display form (`user_<uuid>`); confirm it carries
    // our user's UUID.
    assert!(
        body["user_id"].as_str().is_some_and(|s| s.contains(&uid)),
        "user_id {:?} should contain {uid}",
        body["user_id"]
    );
}
