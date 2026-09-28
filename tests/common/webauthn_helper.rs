//! Minimal WebAuthn test authenticator shared by the integration tests.
//!
//! Builds bit-accurate mock authenticator responses (CBOR attestation objects,
//! signed assertions) using ring for P-256 key generation/signing and ciborium
//! for CBOR encoding. Include it with
//! `#[path = "common/webauthn_helper.rs"] mod webauthn_helper;`.
#![allow(dead_code)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

/// COSE algorithm identifier for ES256.
const COSE_ALG_ES256: i64 = -7;

pub struct TestAuthenticator {
    key_pair_pkcs8: Vec<u8>,
    pub credential_id: Vec<u8>,
    rp_id: String,
}

/// Builds authenticator data (37 bytes) with a custom RP ID and no attested credential.
///
/// Used for RP-ID mismatch adversarial tests where the authenticator data
/// must claim a different RP than the server expects.
pub fn auth_data_for_rp(rp_id: &str, sign_count: u32) -> Vec<u8> {
    let rp_id_hash = ring::digest::digest(&ring::digest::SHA256, rp_id.as_bytes());
    let mut data = Vec::new();
    data.extend_from_slice(rp_id_hash.as_ref()); // 32-byte RP ID hash
    data.push(0x01); // UP flag set, no AT flag
    data.extend_from_slice(&sign_count.to_be_bytes()); // 4-byte counter
    data
}

/// Builds a `webauthn.get` clientDataJSON without signing anything.
///
/// Used to construct tampered CDJ payloads independently of the authenticator.
pub fn get_client_data_json(challenge: &[u8], origin: &str) -> Vec<u8> {
    let challenge_b64 = URL_SAFE_NO_PAD.encode(challenge);
    serde_json::to_vec(&serde_json::json!({
        "type": "webauthn.get",
        "challenge": challenge_b64,
        "origin": origin,
    }))
    .expect("serialize clientDataJSON")
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
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &self.key_pair_pkcs8, &rng)
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

    /// Builds authenticator data, optionally setting the UV (user
    /// verified, `0x04`) flag alongside UP (user present, `0x01`).
    #[allow(clippy::cast_possible_truncation)]
    fn build_auth_data_with_uv(
        &self,
        sign_count: u32,
        include_credential: bool,
        user_verified: bool,
    ) -> Vec<u8> {
        let rp_id_hash = ring::digest::digest(&ring::digest::SHA256, self.rp_id.as_bytes());
        let mut data = Vec::new();
        data.extend_from_slice(rp_id_hash.as_ref());
        let mut flags: u8 = if include_credential { 0x41 } else { 0x01 };
        if user_verified {
            flags |= 0x04;
        }
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
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &self.key_pair_pkcs8, &rng)
                .expect("load key pair");
        let sig = key_pair.sign(&rng, data).expect("sign");
        sig.as_ref().to_vec()
    }

    /// Builds a registration response with "none" attestation, proving
    /// user presence only.
    pub fn build_registration_response(
        &self,
        challenge: &[u8],
        origin: &str,
    ) -> (Vec<u8>, Vec<u8>) {
        self.build_registration(challenge, origin, false)
    }

    /// Builds a registration response whose authenticator also proved
    /// user verification (the UV flag).
    pub fn build_verified_registration_response(
        &self,
        challenge: &[u8],
        origin: &str,
    ) -> (Vec<u8>, Vec<u8>) {
        self.build_registration(challenge, origin, true)
    }

    fn build_registration(
        &self,
        challenge: &[u8],
        origin: &str,
        user_verified: bool,
    ) -> (Vec<u8>, Vec<u8>) {
        let client_data_json = Self::build_client_data_json("webauthn.create", challenge, origin);
        let auth_data = self.build_auth_data_with_uv(0, true, user_verified);

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

    /// Builds an authentication response (assertion) that proves user
    /// presence only — a touch, with no PIN and no biometric.
    pub fn build_authentication_response(
        &self,
        challenge: &[u8],
        origin: &str,
        sign_count: u32,
        user_handle: Option<&str>,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>) {
        self.build_assertion(challenge, origin, sign_count, user_handle, false)
    }

    /// Builds an assertion whose authenticator proved user verification
    /// (the UV flag) as well as user presence.
    pub fn build_verified_authentication_response(
        &self,
        challenge: &[u8],
        origin: &str,
        sign_count: u32,
        user_handle: Option<&str>,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>) {
        self.build_assertion(challenge, origin, sign_count, user_handle, true)
    }

    fn build_assertion(
        &self,
        challenge: &[u8],
        origin: &str,
        sign_count: u32,
        user_handle: Option<&str>,
        user_verified: bool,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>) {
        let client_data_json = Self::build_client_data_json("webauthn.get", challenge, origin);
        let auth_data = self.build_auth_data_with_uv(sign_count, false, user_verified);

        let client_data_hash = ring::digest::digest(&ring::digest::SHA256, &client_data_json);
        let mut signed_data = auth_data.clone();
        signed_data.extend_from_slice(client_data_hash.as_ref());
        let sig = self.sign(&signed_data);

        let handle = user_handle.map(|h| h.as_bytes().to_vec());
        (client_data_json, auth_data, sig, handle)
    }
}
