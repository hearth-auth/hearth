//! Integration and adversarial tests for A-46: Argon2 pepper rotation.
//!
//! Tests the end-to-end flow of:
//! - Login succeeds with a peppered credential
//! - Login succeeds with a previous-pepper credential (grace window), and
//!   the credential is lazily re-hashed with the active pepper
//! - Legacy (non-peppered) credentials are lazily upgraded on login
//! - A closed grace window (unknown version) causes login failure
//! - Adversarial: a credential hashed with wrong pepper key is rejected

use hearth::identity::{
    hash_password, verify_password_with_pepper, CleartextPassword, CredentialConfig, PepperConfig,
    PepperKey, StoredCredential,
};

// ===== Unit: verify_password_with_pepper covers all branches =====

fn make_key(byte: u8) -> PepperKey {
    PepperKey::new(vec![byte; 32]).expect("valid key")
}

fn make_config_with_pepper(version: u32, byte: u8) -> CredentialConfig {
    CredentialConfig::fast_for_testing_with_pepper(version, make_key(byte))
}

/// A-46 — backward-compat: no pepper on either side.
#[test]
fn no_pepper_both_sides_verifies_unchanged() {
    let config = CredentialConfig::fast_for_testing();
    let pw = CleartextPassword::from_string("plain-legacy".to_string());
    let cred = hash_password(&pw, &config, 0).expect("hash");

    let (matches, needs_rehash) = verify_password_with_pepper(&pw, &cred, &config).expect("ok");
    assert!(matches);
    assert!(!needs_rehash, "no rehash needed when no pepper is involved");
}

/// A-46 — happy path: active pepper hashes and verifies correctly.
#[test]
fn active_pepper_hash_verify_roundtrip() {
    let config = make_config_with_pepper(1, 0xAA);
    let pw = CleartextPassword::from_string("peppered-password".to_string());
    let cred = hash_password(&pw, &config, 0).expect("hash");

    assert_eq!(cred.pepper_version, Some(1));

    let (matches, needs_rehash) = verify_password_with_pepper(&pw, &cred, &config).expect("ok");
    assert!(matches, "correct password must verify with active pepper");
    assert!(!needs_rehash, "up-to-date pepper requires no rehash");
}

/// A-46 — grace window: previous pepper is accepted, rehash is flagged.
#[test]
fn previous_pepper_accepted_flags_rehash() {
    // Hash with old pepper (version 1).
    let config_v1 = make_config_with_pepper(1, 0x11);
    let pw = CleartextPassword::from_string("my-password".to_string());
    let cred = hash_password(&pw, &config_v1, 0).expect("hash v1");
    assert_eq!(cred.pepper_version, Some(1));

    // Rotate to version 2 with grace window still open.
    let config_v2 = CredentialConfig {
        pepper: Some(PepperConfig {
            active_version: 2,
            active_key: make_key(0x22),
            previous_version: Some(1),
            previous_key: Some(make_key(0x11)),
        }),
        ..CredentialConfig::fast_for_testing()
    };

    let (matches, needs_rehash) = verify_password_with_pepper(&pw, &cred, &config_v2).expect("ok");
    assert!(matches, "previous pepper must verify during grace window");
    assert!(
        needs_rehash,
        "verified with previous pepper must trigger rehash"
    );
}

/// A-46 — grace window: wrong password against previous pepper does NOT flag rehash.
#[test]
fn previous_pepper_wrong_password_no_rehash() {
    let config_v1 = make_config_with_pepper(1, 0x11);
    let pw = CleartextPassword::from_string("my-password".to_string());
    let cred = hash_password(&pw, &config_v1, 0).expect("hash v1");

    let config_v2 = CredentialConfig {
        pepper: Some(PepperConfig {
            active_version: 2,
            active_key: make_key(0x22),
            previous_version: Some(1),
            previous_key: Some(make_key(0x11)),
        }),
        ..CredentialConfig::fast_for_testing()
    };

    let wrong = CleartextPassword::from_string("wrong".to_string());
    let (matches, needs_rehash) =
        verify_password_with_pepper(&wrong, &cred, &config_v2).expect("ok");
    assert!(!matches);
    assert!(!needs_rehash, "failed auth must not trigger rehash");
}

/// A-46 — closed grace window: unrecognised pepper version is rejected.
#[test]
fn closed_grace_window_rejects_old_pepper() {
    // Hash with version 1.
    let config_v1 = make_config_with_pepper(1, 0x11);
    let pw = CleartextPassword::from_string("old-password".to_string());
    let cred = hash_password(&pw, &config_v1, 0).expect("hash v1");

    // Operator removed previous pepper — version 1 no longer accepted.
    let config_v2 = make_config_with_pepper(2, 0x22);

    let (matches, needs_rehash) = verify_password_with_pepper(&pw, &cred, &config_v2).expect("ok");
    assert!(!matches, "expired pepper version must be rejected");
    assert!(!needs_rehash);
}

/// A-46 — legacy upgrade: credential without pepper_version is lazily upgraded.
#[test]
fn legacy_credential_flags_rehash_when_pepper_introduced() {
    let no_pepper_cfg = CredentialConfig::fast_for_testing();
    let pw = CleartextPassword::from_string("pre-pepper-password".to_string());
    let cred = hash_password(&pw, &no_pepper_cfg, 0).expect("hash");
    assert_eq!(cred.pepper_version, None);

    // Server now has pepper configured.
    let peppered_cfg = make_config_with_pepper(1, 0xBB);
    let (matches, needs_rehash) =
        verify_password_with_pepper(&pw, &cred, &peppered_cfg).expect("ok");
    assert!(
        matches,
        "legacy credential must still be valid after pepper introduction"
    );
    assert!(
        needs_rehash,
        "legacy credential must be scheduled for pepper rehash"
    );
}

// ===== Adversarial: wrong pepper key cannot forge verification =====

/// A-46 adversarial — different pepper key does not verify even with correct password.
#[test]
fn adversarial_different_pepper_key_rejected() {
    let config_a = make_config_with_pepper(1, 0xAA);
    let config_b = make_config_with_pepper(1, 0xBB); // same version, different key

    let pw = CleartextPassword::from_string("hunter2".to_string());
    let cred = hash_password(&pw, &config_a, 0).expect("hash with pepper A");

    let (matches, _) = verify_password_with_pepper(&pw, &cred, &config_b).expect("verify");
    assert!(
        !matches,
        "wrong pepper key must not verify correct password"
    );
}

/// A-46 adversarial — pepper prevents offline dictionary attacks:
/// same password with different peppers produces different PHC strings.
#[test]
fn adversarial_pepper_produces_unique_hashes_per_key() {
    let pw = CleartextPassword::from_string("common-password".to_string());

    let hashes: Vec<String> = (0u8..5)
        .map(|b| {
            let cfg = make_config_with_pepper(u32::from(b), b);
            hash_password(&pw, &cfg, 0).expect("hash").hash
        })
        .collect();

    // All hashes must be distinct — different peppers must diverge the PHC output.
    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len() {
            assert_ne!(
                hashes[i], hashes[j],
                "different pepper keys must produce different hashes"
            );
        }
    }
}

/// A-46 adversarial — setting pepper_version without the matching pepper key
/// cannot be used to forge a bypass (i.e., a credential from no-pepper config
/// does not verify against a config that expects pepper version 1).
#[test]
fn adversarial_forged_pepper_version_does_not_bypass() {
    // Hash with NO pepper.
    let cfg_no_pepper = CredentialConfig::fast_for_testing();
    let pw = CleartextPassword::from_string("secret".to_string());
    let cred = hash_password(&pw, &cfg_no_pepper, 0).expect("hash");

    // Manually forge pepper_version = 1.
    let forged = StoredCredential {
        pepper_version: Some(1),
        ..cred
    };

    // Server requires pepper version 1 with key 0xCC.
    let peppered_cfg = make_config_with_pepper(1, 0xCC);
    let (matches, _) = verify_password_with_pepper(&pw, &forged, &peppered_cfg).expect("verify");
    assert!(
        !matches,
        "forged pepper_version on unpeppered credential must not verify"
    );
}
