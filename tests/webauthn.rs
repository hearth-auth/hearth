//! Integration tests for `WebAuthn` / Passkeys (Step 24).
//!
//! Black box tests via `TestHarness` — exercises `WebAuthn` registration,
//! authentication, multi-credential management, and credential revocation
//! through the public `IdentityEngine` trait.

mod common;

use hearth::core::RealmId;
use hearth::identity::{
    AuthenticationOptions, CompleteAuthenticationParams, CreateRealmRequest, CreateUserRequest,
    IdentityError, RegistrationOptions, User,
};

/// Helper: creates a real realm with a signing key.
fn create_realm(harness: &common::TestHarness) -> RealmId {
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("webauthn-test-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");
    realm.id().clone()
}

/// Helper: creates a user with a unique email.
fn create_user(harness: &common::TestHarness, realm: &RealmId) -> User {
    harness
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("webauthn-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "WebAuthn Test User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user")
}

// ============================================================================
// Minimal WebAuthn test helper for integration tests.
//
// Builds bit-accurate mock authenticator responses (CBOR attestation objects,
// signed assertions) using ring for P-256 key generation/signing and ciborium
// for CBOR encoding. This mirrors the internal test_helper but is self-contained.
// ============================================================================

mod webauthn_helper {
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
            let key_pair = EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                &self.key_pair_pkcs8,
                &rng,
            )
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
            let client_data_json =
                Self::build_client_data_json("webauthn.create", challenge, origin);
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
}

// ===== Scenario D1: Full lifecycle via embedded API =====
//
// create realm → user → start registration → complete registration →
// start authentication → complete authentication → success

#[tokio::test]
async fn webauthn_full_lifecycle() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = create_realm(&harness);
    let user = create_user(&harness, &realm);
    let origin = "https://example.com";

    let authenticator = webauthn_helper::TestAuthenticator::new("example.com");

    // Start registration
    let challenge = harness
        .identity()
        .start_webauthn_registration(
            &realm,
            user.id(),
            &RegistrationOptions {
                rp_id: "example.com".to_string(),
                discoverable: false,
            },
        )
        .expect("start registration");

    // Build mock authenticator response
    let (client_data_json, attestation_object) =
        authenticator.build_registration_response(&challenge, origin);

    // Complete registration
    let cred_info = harness
        .identity()
        .complete_webauthn_registration(
            &realm,
            user.id(),
            &client_data_json,
            &attestation_object,
            origin,
            false,
        )
        .expect("complete registration");

    assert_eq!(cred_info.credential_id(), authenticator.credential_id);

    // Verify credential is listed
    let creds = harness
        .identity()
        .list_webauthn_credentials(&realm, user.id())
        .expect("list credentials");
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].credential_id(), authenticator.credential_id);

    // Start authentication
    let auth_challenge = harness
        .identity()
        .start_webauthn_authentication(
            &realm,
            Some(user.id()),
            &AuthenticationOptions {
                rp_id: "example.com".to_string(),
            },
        )
        .expect("start authentication");

    // Build mock assertion
    let (auth_cdj, auth_data, sig, _handle) =
        authenticator.build_authentication_response(&auth_challenge, origin, 1, None);

    // Complete authentication
    let auth_result = harness
        .identity()
        .complete_webauthn_authentication(
            &realm,
            &CompleteAuthenticationParams {
                credential_id: &authenticator.credential_id,
                client_data_json: &auth_cdj,
                authenticator_data: &auth_data,
                signature: &sig,
                user_handle: None,
                origin,
            },
        )
        .expect("complete authentication");

    assert_eq!(auth_result.user_id(), user.id());
    assert_eq!(auth_result.sign_count(), 1);
}

// ===== Scenario D2: Credential management =====
//
// register key1 → auth → register key2 → revoke key1 →
// list (only key2) → auth key2 ✓

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn webauthn_credential_management() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = create_realm(&harness);
    let user = create_user(&harness, &realm);
    let origin = "https://example.com";

    let auth1 = webauthn_helper::TestAuthenticator::new("example.com");
    let auth2 = webauthn_helper::TestAuthenticator::new("example.com");

    // Register key1
    let challenge1 = harness
        .identity()
        .start_webauthn_registration(
            &realm,
            user.id(),
            &RegistrationOptions {
                rp_id: "example.com".to_string(),
                discoverable: false,
            },
        )
        .expect("start reg1");

    let (cdj1, att1) = auth1.build_registration_response(&challenge1, origin);
    harness
        .identity()
        .complete_webauthn_registration(&realm, user.id(), &cdj1, &att1, origin, false)
        .expect("complete reg1");

    // Authenticate with key1
    let auth_challenge = harness
        .identity()
        .start_webauthn_authentication(
            &realm,
            Some(user.id()),
            &AuthenticationOptions {
                rp_id: "example.com".to_string(),
            },
        )
        .expect("start auth1");

    let (acdj, aad, asig, _) =
        auth1.build_authentication_response(&auth_challenge, origin, 1, None);
    harness
        .identity()
        .complete_webauthn_authentication(
            &realm,
            &CompleteAuthenticationParams {
                credential_id: &auth1.credential_id,
                client_data_json: &acdj,
                authenticator_data: &aad,
                signature: &asig,
                user_handle: None,
                origin,
            },
        )
        .expect("auth with key1");

    // Register key2
    let challenge2 = harness
        .identity()
        .start_webauthn_registration(
            &realm,
            user.id(),
            &RegistrationOptions {
                rp_id: "example.com".to_string(),
                discoverable: false,
            },
        )
        .expect("start reg2");

    let (cdj2, att2) = auth2.build_registration_response(&challenge2, origin);
    harness
        .identity()
        .complete_webauthn_registration(&realm, user.id(), &cdj2, &att2, origin, false)
        .expect("complete reg2");

    // Two credentials now
    let creds = harness
        .identity()
        .list_webauthn_credentials(&realm, user.id())
        .expect("list");
    assert_eq!(creds.len(), 2, "should have 2 credentials");

    // Revoke key1
    harness
        .identity()
        .revoke_webauthn_credential(&realm, user.id(), &auth1.credential_id)
        .expect("revoke key1");

    // Only key2 remains
    let creds_after = harness
        .identity()
        .list_webauthn_credentials(&realm, user.id())
        .expect("list after revoke");
    assert_eq!(
        creds_after.len(),
        1,
        "should have 1 credential after revoke"
    );
    assert_eq!(
        creds_after[0].credential_id(),
        auth2.credential_id,
        "remaining credential should be key2"
    );

    // Authenticate with key2
    let auth_challenge2 = harness
        .identity()
        .start_webauthn_authentication(
            &realm,
            Some(user.id()),
            &AuthenticationOptions {
                rp_id: "example.com".to_string(),
            },
        )
        .expect("start auth2");

    let (acdj2, aad2, asig2, _) =
        auth2.build_authentication_response(&auth_challenge2, origin, 1, None);
    let result = harness
        .identity()
        .complete_webauthn_authentication(
            &realm,
            &CompleteAuthenticationParams {
                credential_id: &auth2.credential_id,
                client_data_json: &acdj2,
                authenticator_data: &aad2,
                signature: &asig2,
                user_handle: None,
                origin,
            },
        )
        .expect("auth with key2");

    assert_eq!(result.user_id(), user.id());
}

// ===== Scenario D3: Credential naming and rename =====
//
// register → list (name=None) → rename → list (name=Some("...")) →
// rename to empty → list (name=None) → rename unknown cred → NotFound

#[tokio::test]
async fn webauthn_credential_naming() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = create_realm(&harness);
    let user = create_user(&harness, &realm);
    let origin = "https://example.com";

    let auth = webauthn_helper::TestAuthenticator::new("example.com");

    // Register
    let challenge = harness
        .identity()
        .start_webauthn_registration(
            &realm,
            user.id(),
            &RegistrationOptions {
                rp_id: "example.com".to_string(),
                discoverable: false,
            },
        )
        .expect("start registration");

    let (cdj, att) = auth.build_registration_response(&challenge, origin);
    let cred = harness
        .identity()
        .complete_webauthn_registration(&realm, user.id(), &cdj, &att, origin, false)
        .expect("complete registration");

    // Name is None after registration
    let creds = harness
        .identity()
        .list_webauthn_credentials(&realm, user.id())
        .expect("list");
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].name(), None, "name should start as None");

    // Rename
    harness
        .identity()
        .rename_webauthn_credential(&realm, user.id(), cred.credential_id(), "MacBook Touch ID")
        .expect("rename");

    let creds = harness
        .identity()
        .list_webauthn_credentials(&realm, user.id())
        .expect("list after rename");
    assert_eq!(creds[0].name(), Some("MacBook Touch ID"));

    // Rename to empty string clears the name
    harness
        .identity()
        .rename_webauthn_credential(&realm, user.id(), cred.credential_id(), "   ")
        .expect("rename to blank");

    let creds = harness
        .identity()
        .list_webauthn_credentials(&realm, user.id())
        .expect("list after blank rename");
    assert_eq!(creds[0].name(), None, "blank rename should clear name");

    // Rename with unknown credential ID returns NotFound
    let fake_id = vec![0xde, 0xad, 0xbe, 0xef];
    let err = harness
        .identity()
        .rename_webauthn_credential(&realm, user.id(), &fake_id, "Ghost")
        .expect_err("unknown credential should return error");
    assert!(
        matches!(err, IdentityError::WebAuthnCredentialNotFound),
        "expected WebAuthnCredentialNotFound, got: {err}"
    );
}

// ===== Scenario D4 (adversarial): Counter-replay rejection =====
//
// register → auth(sign_count=1) success → auth(sign_count=1) again → rejected
//
// Mirrors: src/identity/webauthn.rs tests::sign_counter_replay_rejected (inline unit test)

#[tokio::test]
async fn webauthn_counter_replay_rejected() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = create_realm(&harness);
    let user = create_user(&harness, &realm);
    let origin = "https://example.com";
    let authenticator = webauthn_helper::TestAuthenticator::new("example.com");

    // Register the credential
    let reg_challenge = harness
        .identity()
        .start_webauthn_registration(
            &realm,
            user.id(),
            &RegistrationOptions {
                rp_id: "example.com".to_string(),
                discoverable: false,
            },
        )
        .expect("start registration");
    let (reg_cdj, reg_att) = authenticator.build_registration_response(&reg_challenge, origin);
    harness
        .identity()
        .complete_webauthn_registration(&realm, user.id(), &reg_cdj, &reg_att, origin, false)
        .expect("complete registration");

    // First authentication with sign_count=1 — should succeed and store count=1
    let challenge1 = harness
        .identity()
        .start_webauthn_authentication(
            &realm,
            Some(user.id()),
            &AuthenticationOptions {
                rp_id: "example.com".to_string(),
            },
        )
        .expect("start auth1");
    let (auth_cdj1, auth_data1, sig1, _) =
        authenticator.build_authentication_response(&challenge1, origin, 1, None);
    harness
        .identity()
        .complete_webauthn_authentication(
            &realm,
            &CompleteAuthenticationParams {
                credential_id: &authenticator.credential_id,
                client_data_json: &auth_cdj1,
                authenticator_data: &auth_data1,
                signature: &sig1,
                user_handle: None,
                origin,
            },
        )
        .expect("first authentication should succeed");

    // Second authentication with same sign_count=1 — must be rejected (counter replay)
    let challenge2 = harness
        .identity()
        .start_webauthn_authentication(
            &realm,
            Some(user.id()),
            &AuthenticationOptions {
                rp_id: "example.com".to_string(),
            },
        )
        .expect("start auth2");
    let (auth_cdj2, auth_data2, sig2, _) =
        authenticator.build_authentication_response(&challenge2, origin, 1, None); // same counter
    let err = harness
        .identity()
        .complete_webauthn_authentication(
            &realm,
            &CompleteAuthenticationParams {
                credential_id: &authenticator.credential_id,
                client_data_json: &auth_cdj2,
                authenticator_data: &auth_data2,
                signature: &sig2,
                user_handle: None,
                origin,
            },
        )
        .expect_err("replayed counter should be rejected");
    assert!(
        matches!(err, IdentityError::InvalidAssertion { .. }),
        "expected InvalidAssertion, got: {err}"
    );
    assert!(
        err.to_string().contains("sign counter"),
        "expected sign-counter message, got: {err}"
    );
}

// ===== Scenario D5 (adversarial): RP-ID mismatch rejection =====
//
// register(rp_id=example.com) → authenticate with auth_data claiming evil.com → rejected
//
// Mirrors: src/identity/webauthn.rs tests::rp_id_mismatch_rejected_on_authentication

#[tokio::test]
async fn webauthn_rp_id_mismatch_rejected() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = create_realm(&harness);
    let user = create_user(&harness, &realm);
    let origin = "https://example.com";
    let authenticator = webauthn_helper::TestAuthenticator::new("example.com");

    // Register credential for example.com
    let reg_challenge = harness
        .identity()
        .start_webauthn_registration(
            &realm,
            user.id(),
            &RegistrationOptions {
                rp_id: "example.com".to_string(),
                discoverable: false,
            },
        )
        .expect("start registration");
    let (reg_cdj, reg_att) = authenticator.build_registration_response(&reg_challenge, origin);
    harness
        .identity()
        .complete_webauthn_registration(&realm, user.id(), &reg_cdj, &reg_att, origin, false)
        .expect("complete registration");

    // Start authentication — get a real challenge
    let auth_challenge = harness
        .identity()
        .start_webauthn_authentication(
            &realm,
            Some(user.id()),
            &AuthenticationOptions {
                rp_id: "example.com".to_string(),
            },
        )
        .expect("start authentication");

    // Build authenticator data with evil.com's RP-ID hash instead of example.com
    // RP-ID check happens before signature verification, so any signature bytes work.
    let evil_auth_data = webauthn_helper::auth_data_for_rp("evil.com", 1);
    let cdj = webauthn_helper::get_client_data_json(&auth_challenge, origin);
    let fake_sig = vec![0u8; 64]; // irrelevant — RP-ID check fires first

    let err = harness
        .identity()
        .complete_webauthn_authentication(
            &realm,
            &CompleteAuthenticationParams {
                credential_id: &authenticator.credential_id,
                client_data_json: &cdj,
                authenticator_data: &evil_auth_data,
                signature: &fake_sig,
                user_handle: None,
                origin,
            },
        )
        .expect_err("RP-ID mismatch should be rejected");
    assert!(
        matches!(err, IdentityError::InvalidAssertion { .. }),
        "expected InvalidAssertion, got: {err}"
    );
    assert!(
        err.to_string().contains("RP ID hash mismatch"),
        "expected RP ID mismatch message, got: {err}"
    );
}

// ===== Scenario D6 (adversarial): Tampered clientDataJSON rejection =====
//
// Attacker replaces the origin in clientDataJSON with evil.com.
// Origin is checked before RP-ID and signature, so the sig need not be valid.
//
// Mirrors: src/identity/webauthn.rs tests::tampered_origin_in_client_data_rejected

#[tokio::test]
async fn webauthn_tampered_client_data_json_rejected() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = create_realm(&harness);
    let user = create_user(&harness, &realm);
    let origin = "https://example.com";
    let authenticator = webauthn_helper::TestAuthenticator::new("example.com");

    // Register
    let reg_challenge = harness
        .identity()
        .start_webauthn_registration(
            &realm,
            user.id(),
            &RegistrationOptions {
                rp_id: "example.com".to_string(),
                discoverable: false,
            },
        )
        .expect("start registration");
    let (reg_cdj, reg_att) = authenticator.build_registration_response(&reg_challenge, origin);
    harness
        .identity()
        .complete_webauthn_registration(&realm, user.id(), &reg_cdj, &reg_att, origin, false)
        .expect("complete registration");

    // Get a real challenge then build a CDJ with the real challenge but wrong origin.
    // Engine parses challenge from CDJ to find the pending, so the challenge must be real.
    // Origin is checked inside complete_authentication before signature, so any sig works.
    let auth_challenge = harness
        .identity()
        .start_webauthn_authentication(
            &realm,
            Some(user.id()),
            &AuthenticationOptions {
                rp_id: "example.com".to_string(),
            },
        )
        .expect("start authentication");

    let tampered_cdj = webauthn_helper::get_client_data_json(&auth_challenge, "https://evil.com");
    let (_, auth_data, _, _) =
        authenticator.build_authentication_response(&auth_challenge, origin, 1, None);
    let fake_sig = vec![0u8; 64]; // origin check fires before signature verification

    let err = harness
        .identity()
        .complete_webauthn_authentication(
            &realm,
            &CompleteAuthenticationParams {
                credential_id: &authenticator.credential_id,
                client_data_json: &tampered_cdj,
                authenticator_data: &auth_data,
                signature: &fake_sig,
                user_handle: None,
                origin,
            },
        )
        .expect_err("tampered clientDataJSON origin should be rejected");
    assert!(
        matches!(err, IdentityError::InvalidAssertion { .. }),
        "expected InvalidAssertion, got: {err}"
    );
    assert!(
        err.to_string().contains("origin mismatch"),
        "expected origin mismatch message, got: {err}"
    );
}

// ===== Scenario D7 (adversarial): CBOR-malformed attestation object rejection =====
//
// Passes garbage bytes as the attestation_object during registration.
// parse_attestation_object (CBOR) must reject it cleanly, mirroring the fuzz target
// at src/identity/webauthn.rs::fuzz_parse_webauthn which exercises the same parser.
//
// Mirrors: src/identity/webauthn.rs::fuzz_parse_webauthn (fuzz coverage)

#[tokio::test]
async fn webauthn_cbor_malformed_auth_data_rejected() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = create_realm(&harness);
    let user = create_user(&harness, &realm);
    let origin = "https://example.com";
    let authenticator = webauthn_helper::TestAuthenticator::new("example.com");

    // Start registration to obtain a real challenge so the engine can find the pending.
    let reg_challenge = harness
        .identity()
        .start_webauthn_registration(
            &realm,
            user.id(),
            &RegistrationOptions {
                rp_id: "example.com".to_string(),
                discoverable: false,
            },
        )
        .expect("start registration");

    // Build a legitimate clientDataJSON (with the real challenge) but pass garbage CBOR
    // as the attestation object. parse_attestation_object must reject it.
    let (real_cdj, _) = authenticator.build_registration_response(&reg_challenge, origin);
    let garbage_attestation_object = b"\xff\x00\xde\xad\xbe\xef garbage not valid CBOR";

    let err = harness
        .identity()
        .complete_webauthn_registration(
            &realm,
            user.id(),
            &real_cdj,
            garbage_attestation_object,
            origin,
            false,
        )
        .expect_err("malformed CBOR attestation object should be rejected");
    assert!(
        matches!(err, IdentityError::InvalidInput { .. }),
        "expected InvalidInput for malformed CBOR, got: {err}"
    );
    assert!(
        err.to_string().contains("CBOR") || err.to_string().contains("attestation"),
        "expected CBOR/attestation error message, got: {err}"
    );
}

// ===== HEA-1720 regression: discoverable-login userHandle spoofing =====
//
// Attack: attacker holds a discoverable credential; submits a valid assertion
// but substitutes the victim's UUID into userHandle (which is unsigned). The
// server must reject the ceremony rather than issuing a session for the victim.

#[tokio::test]
async fn webauthn_discoverable_userhandle_spoofing_rejected() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = create_realm(&harness);
    let origin = "https://example.com";

    // Create attacker and victim accounts.
    let attacker = create_user(&harness, &realm);
    let victim = create_user(&harness, &realm);

    let attacker_authenticator = webauthn_helper::TestAuthenticator::new("example.com");

    // Register attacker's credential as discoverable (true → stored in discoverable index).
    let reg_challenge = harness
        .identity()
        .start_webauthn_registration(
            &realm,
            attacker.id(),
            &RegistrationOptions {
                rp_id: "example.com".to_string(),
                discoverable: true,
            },
        )
        .expect("start registration");

    let (reg_cdj, reg_att) =
        attacker_authenticator.build_registration_response(&reg_challenge, origin);
    harness
        .identity()
        .complete_webauthn_registration(
            &realm,
            attacker.id(),
            &reg_cdj,
            &reg_att,
            origin,
            true, // discoverable — writes credential_id → attacker into the index
        )
        .expect("complete registration");

    // Start discoverable authentication (no user_id supplied → discoverable flow).
    let auth_challenge = harness
        .identity()
        .start_webauthn_authentication(
            &realm,
            None, // discoverable: server does not commit to a user upfront
            &AuthenticationOptions {
                rp_id: "example.com".to_string(),
            },
        )
        .expect("start authentication");

    // Attacker builds a genuine assertion for their own credential …
    let (auth_cdj, auth_data, sig, _) =
        attacker_authenticator.build_authentication_response(&auth_challenge, origin, 1, None);

    // … but substitutes the victim's UUID into userHandle (the spoofing step).
    let victim_handle = victim.id().as_uuid().to_string();
    let spoofed_handle = victim_handle.as_bytes().to_vec();

    let err = harness
        .identity()
        .complete_webauthn_authentication(
            &realm,
            &CompleteAuthenticationParams {
                credential_id: &attacker_authenticator.credential_id,
                client_data_json: &auth_cdj,
                authenticator_data: &auth_data,
                signature: &sig,
                user_handle: Some(&spoofed_handle),
                origin,
            },
        )
        .expect_err("userHandle spoofing must be rejected");

    assert!(
        matches!(err, IdentityError::InvalidAssertion { .. }),
        "expected InvalidAssertion for spoofed userHandle, got: {err}"
    );
}

// ============================================================================
// B10 — user verification (audit 2026-08-28 §3 B10, §4.18#1)
// ============================================================================

/// Creates a realm with an explicit config.
fn create_realm_with_config(
    harness: &common::TestHarness,
    config: hearth::identity::RealmConfig,
) -> RealmId {
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("webauthn-uv-{}", uuid::Uuid::new_v4()),
            config: Some(config),
        })
        .expect("create realm");
    realm.id().clone()
}

/// Registers a discoverable credential for `user` and returns the
/// authenticator that owns it.
fn register_discoverable(
    harness: &common::TestHarness,
    realm: &RealmId,
    user: &User,
    rp_id: &str,
    origin: &str,
    user_verified: bool,
) -> webauthn_helper::TestAuthenticator {
    let authenticator = webauthn_helper::TestAuthenticator::new(rp_id);
    let challenge = harness
        .identity()
        .start_webauthn_registration(
            realm,
            user.id(),
            &RegistrationOptions {
                rp_id: rp_id.to_string(),
                discoverable: true,
            },
        )
        .expect("start registration");
    let (cdj, att) = if user_verified {
        authenticator.build_verified_registration_response(&challenge, origin)
    } else {
        authenticator.build_registration_response(&challenge, origin)
    };
    harness
        .identity()
        .complete_webauthn_registration(realm, user.id(), &cdj, &att, origin, true)
        .expect("complete registration");
    authenticator
}

/// A realm that sets `webauthn_user_verification: required` must refuse an
/// assertion whose authenticator never proved user verification. Today the
/// value only decorates the request options the browser receives; nothing
/// checks the response, so the knob is dead code.
#[tokio::test]
async fn realm_requiring_user_verification_refuses_an_unverified_assertion() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = create_realm_with_config(
        &harness,
        hearth::identity::RealmConfig {
            webauthn_user_verification: Some("required".to_string()),
            ..hearth::identity::RealmConfig::default()
        },
    );
    let user = create_user(&harness, &realm);
    let origin = "https://example.com";
    let authenticator = register_discoverable(&harness, &realm, &user, "example.com", origin, true);

    let challenge = harness
        .identity()
        .start_webauthn_authentication(
            &realm,
            Some(user.id()),
            &AuthenticationOptions {
                rp_id: "example.com".to_string(),
            },
        )
        .expect("start authentication");

    // The authenticator reports user presence only — a touch, no PIN and no
    // biometric.
    let (cdj, auth_data, sig, _) =
        authenticator.build_authentication_response(&challenge, origin, 1, None);

    let err = harness
        .identity()
        .complete_webauthn_authentication(
            &realm,
            &CompleteAuthenticationParams {
                credential_id: &authenticator.credential_id,
                client_data_json: &cdj,
                authenticator_data: &auth_data,
                signature: &sig,
                user_handle: None,
                origin,
            },
        )
        .expect_err("realm policy requires user verification");

    assert!(
        matches!(err, IdentityError::InvalidAssertion { .. }),
        "expected InvalidAssertion for a UV-less assertion under a required policy, got: {err}"
    );
}

/// The same realm accepts the assertion once the authenticator proves user
/// verification.
#[tokio::test]
async fn realm_requiring_user_verification_accepts_a_verified_assertion() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = create_realm_with_config(
        &harness,
        hearth::identity::RealmConfig {
            webauthn_user_verification: Some("required".to_string()),
            ..hearth::identity::RealmConfig::default()
        },
    );
    let user = create_user(&harness, &realm);
    let origin = "https://example.com";
    let authenticator = register_discoverable(&harness, &realm, &user, "example.com", origin, true);

    let challenge = harness
        .identity()
        .start_webauthn_authentication(
            &realm,
            Some(user.id()),
            &AuthenticationOptions {
                rp_id: "example.com".to_string(),
            },
        )
        .expect("start authentication");

    let (cdj, auth_data, sig, _) =
        authenticator.build_verified_authentication_response(&challenge, origin, 1, None);

    let result = harness
        .identity()
        .complete_webauthn_authentication(
            &realm,
            &CompleteAuthenticationParams {
                credential_id: &authenticator.credential_id,
                client_data_json: &cdj,
                authenticator_data: &auth_data,
                signature: &sig,
                user_handle: None,
                origin,
            },
        )
        .expect("a user-verified assertion satisfies a required policy");

    assert!(
        result.user_verified(),
        "the result must report that user verification was proven"
    );
    assert_eq!(result.user_id(), user.id());
}

// ---------------------------------------------------------------------------
// B10 end to end: a UV-less passkey must not satisfy `mfa_required`
// ---------------------------------------------------------------------------

/// Builds the `/ui` router over the harness's engines.
fn build_web_app(harness: &common::TestHarness) -> axum::Router {
    use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
    use hearth::identity::onboarding::OnboardingService;
    use hearth::protocol::web::{self, CookieSecret, WebState};
    use std::sync::Arc;

    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);

    let email = Arc::new(
        EmailService::new(
            Arc::new(LoggingEmailSender::new()),
            "Hearth".to_string(),
            None,
            EmailBranding::default(),
            String::new(),
            None,
        )
        .expect("email service"),
    );
    let onboarding = Arc::new(OnboardingService::new(
        harness.identity_arc(),
        harness.rbac_arc(),
        email,
        data_dir,
    ));
    let state = WebState::new(
        harness.identity_arc(),
        harness.rbac_arc(),
        harness.audit_arc(),
        onboarding,
        CookieSecret::from_bytes([7u8; 32]),
        None,
    )
    .with_dev_mode(true);
    web::router(state)
}

/// Computes a TOTP code from a base32 secret — mirrors `src/identity/totp.rs`.
fn compute_totp_code(secret_base32: &str, unix_secs: u64) -> String {
    let secret_bytes = data_encoding::BASE32_NOPAD
        .decode(secret_base32.as_bytes())
        .expect("decode base32");
    let step = unix_secs / 30;
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &secret_bytes);
    let tag = ring::hmac::sign(&key, &step.to_be_bytes());
    let hash = tag.as_ref();
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let binary = u32::from_be_bytes([
        hash[offset] & 0x7f,
        hash[offset + 1],
        hash[offset + 2],
        hash[offset + 3],
    ]);
    format!("{:06}", binary % 1_000_000)
}

/// Enrols and activates TOTP so `mfa_enabled` reports a second factor.
fn enroll_totp(harness: &common::TestHarness, realm: &RealmId, user: &User) {
    let enrollment = harness
        .identity()
        .enroll_totp(realm, user.id())
        .expect("enroll_totp");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("epoch")
        .as_secs();
    let code = compute_totp_code(&enrollment.secret_base32, now);
    harness
        .identity()
        .verify_totp_enrollment(realm, user.id(), &code)
        .expect("verify_totp_enrollment");
}

/// B10 — the blocker, end to end through the browser router.
///
/// The realm sets `mfa_required`. A passkey that proves user *presence*
/// only — a touch, no PIN and no biometric — is possession alone, so it is
/// one factor, not two. It must not produce a session.
#[tokio::test]
#[allow(clippy::too_many_lines)] // one linear browser flow; splitting it hides the sequence
async fn uv_less_passkey_does_not_satisfy_mfa_required() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use tower::ServiceExt as _;

    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm_id = create_realm_with_config(
        &harness,
        hearth::identity::RealmConfig {
            mfa_required: Some(true),
            ..hearth::identity::RealmConfig::default()
        },
    );
    let realm_name = harness
        .identity()
        .get_realm(&realm_id)
        .expect("get realm")
        .expect("realm exists")
        .name()
        .to_string();

    let user = create_user(&harness, &realm_id);
    harness
        .identity()
        .update_user(
            &realm_id,
            user.id(),
            &hearth::identity::UpdateUserRequest {
                status: Some(hearth::identity::UserStatus::Active),
                ..Default::default()
            },
        )
        .expect("activate user");
    enroll_totp(&harness, &realm_id, &user);

    let origin = "http://example.com";
    let authenticator =
        register_discoverable(&harness, &realm_id, &user, "example.com", origin, false);

    let app = build_web_app(&harness);

    // 1. Begin: the browser asks for a challenge.
    let begin = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/ui/realms/{realm_name}/login/passkey-begin"))
                .header("host", "example.com")
                .body(Body::empty())
                .expect("build begin request"),
        )
        .await
        .expect("begin response");
    assert_eq!(begin.status(), StatusCode::OK, "passkey-begin must succeed");
    let begin_bytes = axum::body::to_bytes(begin.into_body(), 64 * 1024)
        .await
        .expect("read begin body");
    let begin_json: serde_json::Value =
        serde_json::from_slice(&begin_bytes).expect("begin body is JSON");
    let challenge = URL_SAFE_NO_PAD
        .decode(
            begin_json["challenge"]
                .as_str()
                .expect("challenge in begin body"),
        )
        .expect("challenge is base64url");

    // 2. Complete: the authenticator signs with UP set and UV clear.
    let (cdj, auth_data, sig, _) = authenticator.build_authentication_response(
        &challenge,
        origin,
        1,
        Some(&user.id().as_uuid().to_string()),
    );
    let body = serde_json::json!({
        "credential_id": URL_SAFE_NO_PAD.encode(&authenticator.credential_id),
        "client_data_json": URL_SAFE_NO_PAD.encode(&cdj),
        "authenticator_data": URL_SAFE_NO_PAD.encode(&auth_data),
        "signature": URL_SAFE_NO_PAD.encode(&sig),
        "user_handle": URL_SAFE_NO_PAD.encode(user.id().as_uuid().to_string().as_bytes()),
    });
    let complete = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/realms/{realm_name}/login/passkey-complete"))
                .header("host", "example.com")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .expect("build complete request"),
        )
        .await
        .expect("complete response");

    let cookies: Vec<String> = complete
        .headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::to_string)
        .collect();
    let status = complete.status();
    let body_bytes = axum::body::to_bytes(complete.into_body(), 64 * 1024)
        .await
        .expect("read complete body");
    let body_text = String::from_utf8_lossy(&body_bytes).into_owned();

    let session_cookie = cookies
        .iter()
        .find(|c| c.starts_with("hearth_ui_session=") && !c.starts_with("hearth_ui_session=;"));
    assert!(
        session_cookie.is_none(),
        "a passkey that never proved user verification was issued a session under \
         mfa_required: status={status} cookie={session_cookie:?} body={body_text}"
    );
    assert!(
        body_text.contains("/ui/mfa-challenge"),
        "the response must direct the user to the MFA challenge, got: {body_text}"
    );
}

/// The counterpart: a passkey that *did* prove user verification is a
/// second factor, so the same realm issues a session. Without this the fix
/// above could pass by refusing every passkey.
#[tokio::test]
#[allow(clippy::too_many_lines)] // one linear browser flow; splitting it hides the sequence
async fn uv_proven_passkey_satisfies_mfa_required() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use tower::ServiceExt as _;

    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm_id = create_realm_with_config(
        &harness,
        hearth::identity::RealmConfig {
            mfa_required: Some(true),
            ..hearth::identity::RealmConfig::default()
        },
    );
    let realm_name = harness
        .identity()
        .get_realm(&realm_id)
        .expect("get realm")
        .expect("realm exists")
        .name()
        .to_string();

    let user = create_user(&harness, &realm_id);
    harness
        .identity()
        .update_user(
            &realm_id,
            user.id(),
            &hearth::identity::UpdateUserRequest {
                status: Some(hearth::identity::UserStatus::Active),
                ..Default::default()
            },
        )
        .expect("activate user");

    let origin = "http://example.com";
    let authenticator =
        register_discoverable(&harness, &realm_id, &user, "example.com", origin, false);
    let app = build_web_app(&harness);

    let begin = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/ui/realms/{realm_name}/login/passkey-begin"))
                .header("host", "example.com")
                .body(Body::empty())
                .expect("build begin request"),
        )
        .await
        .expect("begin response");
    assert_eq!(begin.status(), StatusCode::OK);
    let begin_bytes = axum::body::to_bytes(begin.into_body(), 64 * 1024)
        .await
        .expect("read begin body");
    let begin_json: serde_json::Value =
        serde_json::from_slice(&begin_bytes).expect("begin body is JSON");
    let challenge = URL_SAFE_NO_PAD
        .decode(begin_json["challenge"].as_str().expect("challenge"))
        .expect("challenge is base64url");

    let (cdj, auth_data, sig, _) = authenticator.build_verified_authentication_response(
        &challenge,
        origin,
        1,
        Some(&user.id().as_uuid().to_string()),
    );
    let body = serde_json::json!({
        "credential_id": URL_SAFE_NO_PAD.encode(&authenticator.credential_id),
        "client_data_json": URL_SAFE_NO_PAD.encode(&cdj),
        "authenticator_data": URL_SAFE_NO_PAD.encode(&auth_data),
        "signature": URL_SAFE_NO_PAD.encode(&sig),
        "user_handle": URL_SAFE_NO_PAD.encode(user.id().as_uuid().to_string().as_bytes()),
    });
    let complete = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/realms/{realm_name}/login/passkey-complete"))
                .header("host", "example.com")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .expect("build complete request"),
        )
        .await
        .expect("complete response");

    let cookies: Vec<String> = complete
        .headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::to_string)
        .collect();
    let body_bytes = axum::body::to_bytes(complete.into_body(), 64 * 1024)
        .await
        .expect("read complete body");
    let body_text = String::from_utf8_lossy(&body_bytes).into_owned();

    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("hearth_ui_session=") && !c.starts_with("hearth_ui_session=;")),
        "a user-verified passkey must produce a session: cookies={cookies:?} body={body_text}"
    );
}
