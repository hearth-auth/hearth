//! Regression tests for HEA-1724: MFA at-rest DEK decoupled from signing key.
//!
//! The critical invariant: TOTP verification and recovery-code redemption must
//! continue to work after signing-key rotation because the MFA DEK is now a
//! dedicated 32-byte random key independent of the signing key.
//!
//! These tests MUST fail on the old code (which derived the DEK via
//! HKDF-SHA256 from the signing key's PKCS#8 bytes).

#![allow(clippy::unwrap_used)]

mod common;

use hearth::identity::{CreateRealmRequest, CreateUserRequest};

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

/// enroll TOTP → rotate signing key → TOTP verify still succeeds.
///
/// This is the primary regression scenario for HEA-1724.  On the old code the
/// signing-key rotation would change the HKDF-derived DEK, making the stored
/// secret undecryptable and locking the user out of MFA permanently.
#[tokio::test]
async fn totp_verify_survives_signing_key_rotation() {
    let harness = common::TestHarness::embedded().await.unwrap();

    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("dek-test-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .unwrap()
        .id()
        .clone();

    let user = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("totp-dek-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "DEK Test User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .unwrap();

    // Step 1 — enroll TOTP.
    let enrollment = harness.identity().enroll_totp(&realm, user.id()).unwrap();
    let secret = enrollment.secret_base32.clone();

    // Step 2 — activate enrollment with current time step.
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let enroll_code = compute_totp_code(&secret, now_secs);
    harness
        .identity()
        .verify_totp_enrollment(&realm, user.id(), &enroll_code)
        .expect("verify_totp_enrollment before rotation");

    assert!(
        harness.identity().mfa_enabled(&realm, user.id()).unwrap(),
        "MFA must be enabled before testing rotation"
    );

    // Step 3 — rotate the signing key.
    harness
        .identity()
        .rotate_realm_signing_key(&realm, 86_400)
        .expect("rotate_realm_signing_key");

    // Step 4 — TOTP must still work after rotation.
    // Use a code from the NEXT 30-second step to avoid replay-protection.
    let post_rotation_secs = now_secs + 30;
    let verify_code = compute_totp_code(&secret, post_rotation_secs);
    harness
        .identity()
        .verify_totp(&realm, user.id(), &verify_code)
        .expect("verify_totp must succeed after signing-key rotation (HEA-1724)");
}

/// enroll TOTP → rotate signing key → recovery code still redeemable.
///
/// Recovery code hashes are Argon2id (not encrypted), so this mostly validates
/// that `load_mfa_state` can still read the blob after rotation.
#[tokio::test]
async fn recovery_code_survives_signing_key_rotation() {
    let harness = common::TestHarness::embedded().await.unwrap();

    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("dek-rc-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .unwrap()
        .id()
        .clone();

    let user = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("rc-dek-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "RC DEK User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .unwrap();

    let enrollment = harness.identity().enroll_totp(&realm, user.id()).unwrap();
    let secret = enrollment.secret_base32.clone();
    let recovery_code = enrollment.recovery_codes.as_slice()[0].clone();

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    harness
        .identity()
        .verify_totp_enrollment(&realm, user.id(), &compute_totp_code(&secret, now_secs))
        .expect("verify_totp_enrollment");

    // Rotate.
    harness
        .identity()
        .rotate_realm_signing_key(&realm, 86_400)
        .expect("rotate_realm_signing_key");

    // Recovery code must be redeemable post-rotation.
    harness
        .identity()
        .verify_recovery_code(&realm, user.id(), &recovery_code)
        .expect("verify_recovery_code must succeed after signing-key rotation (HEA-1724)");
}

/// Signing-key rotation is idempotent for MFA: multiple rotations must not
/// invalidate TOTP (each rotation migrates blobs to the same stable DEK).
#[tokio::test]
async fn totp_survives_multiple_signing_key_rotations() {
    let harness = common::TestHarness::embedded().await.unwrap();

    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("dek-multi-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .unwrap()
        .id()
        .clone();

    let user = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("multi-rot-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Multi Rotation User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .unwrap();

    let enrollment = harness.identity().enroll_totp(&realm, user.id()).unwrap();
    let secret = enrollment.secret_base32.clone();

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    harness
        .identity()
        .verify_totp_enrollment(&realm, user.id(), &compute_totp_code(&secret, now_secs))
        .expect("verify_totp_enrollment");

    // Three back-to-back rotations.
    harness
        .identity()
        .rotate_realm_signing_key(&realm, 86_400)
        .expect("rotation 1");
    harness
        .identity()
        .rotate_realm_signing_key(&realm, 86_400)
        .expect("rotation 2");
    harness
        .identity()
        .rotate_realm_signing_key(&realm, 86_400)
        .expect("rotation 3");

    // TOTP must still work using the next step (T+1) after the enrollment step (T).
    let post_secs = now_secs + 30;
    harness
        .identity()
        .verify_totp(&realm, user.id(), &compute_totp_code(&secret, post_secs))
        .expect("verify_totp after 3 rotations (HEA-1724)");
}
