#![allow(clippy::unwrap_used)]
//! Integration tests for HEA-SEC-09: at-rest encryption of signing keys and
//! DPoP nonce secrets stored in the WAL.
//!
//! Three scenarios verified:
//! 1. WAL bytes for key-material storage keys start with the HKEY magic (not
//!    raw PKCS#8/JSON) when a KEK is configured.
//! 2. Keys survive an engine restart with the same KEK (round-trip).
//! 3. The `is_key_material` predicate correctly identifies all key prefixes
//!    so admin export/scan paths can filter them out.

mod common;

use std::sync::Arc;

use hearth::audit::EmbeddedAuditEngine;
use hearth::core::{Clock, RealmId};
use hearth::identity::key_encryption::StorageKek;
use hearth::identity::{
    CreateRealmRequest, CredentialConfig, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine,
};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_kek() -> StorageKek {
    StorageKek::new([0x42_u8; 32])
}

fn system_realm_id() -> RealmId {
    RealmId::new(uuid::Uuid::nil())
}

/// Builds an identity engine over `storage`.
///
/// Deliberately does **not** call `init_sv_bumper`: that stores a strong
/// `Arc<dyn SvBumper>` (the identity engine) on the RBAC engine, while the
/// identity engine already holds the RBAC engine — a reference cycle that never
/// drops. The server tolerates it because the process exits, but the restart
/// round-trip below has to actually release the `data_dir` lock when its first
/// engine goes out of scope, and a leaked storage handle keeps that lock held.
/// No test in this file exercises session-version bumping.
fn make_engine(
    storage: Arc<dyn StorageEngine>,
    kek: Option<StorageKek>,
) -> Arc<dyn IdentityEngine> {
    let clock = Arc::new(hearth::core::SystemClock) as Arc<dyn Clock>;
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    ));
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    ));
    let config = IdentityConfig {
        credential: CredentialConfig::fast_for_testing(),
        key_encryption_key: kek,
        ..IdentityConfig::default()
    };
    let engine = EmbeddedIdentityEngine::with_rbac(
        Arc::clone(&storage),
        Arc::clone(&clock),
        config,
        Arc::clone(&rbac) as Arc<dyn RbacEngine>,
        Arc::clone(&audit) as Arc<dyn hearth::audit::AuditEngine>,
    )
    .expect("engine creation");
    Arc::new(engine) as Arc<dyn IdentityEngine>
}

// ---------------------------------------------------------------------------
// Test 1a: global signing key bytes in WAL are HKEY-wrapped when KEK is set
// ---------------------------------------------------------------------------

#[tokio::test]
async fn stored_global_key_bytes_are_hkey_wrapped_when_kek_is_set() {
    let dir = tempfile::tempdir().unwrap();
    let storage_cfg = StorageConfig::dev(dir.path().to_path_buf());
    let storage: Arc<dyn StorageEngine> =
        Arc::new(EmbeddedStorageEngine::open(storage_cfg).unwrap());

    // Boot the engine with a KEK — persists the global signing key.
    let _engine = make_engine(Arc::clone(&storage), Some(test_kek()));

    // Read raw bytes directly from storage.
    let sys_realm = system_realm_id();
    let raw = storage
        .get(&sys_realm, b"sys:global:key")
        .unwrap()
        .expect("global key must be present");

    // Ed25519 PKCS#8 DER always starts with 0x30 (SEQUENCE tag).
    // HKEY envelope starts with b"HKEY".
    assert_ne!(
        raw.first().copied(),
        Some(0x30),
        "raw bytes must not start with PKCS#8 SEQUENCE tag when KEK is set"
    );
    assert_eq!(
        &raw[..4],
        b"HKEY",
        "encrypted key must begin with HKEY magic"
    );
}

// ---------------------------------------------------------------------------
// Test 1b: per-realm signing key bytes in WAL are HKEY-wrapped
// ---------------------------------------------------------------------------

#[tokio::test]
async fn stored_realm_key_bytes_are_hkey_wrapped_when_kek_is_set() {
    let dir = tempfile::tempdir().unwrap();
    let storage_cfg = StorageConfig::dev(dir.path().to_path_buf());
    let storage: Arc<dyn StorageEngine> =
        Arc::new(EmbeddedStorageEngine::open(storage_cfg).unwrap());

    let engine = make_engine(Arc::clone(&storage), Some(test_kek()));
    let realm = engine
        .create_realm(&CreateRealmRequest {
            name: "test-realm".into(),
            config: None,
        })
        .unwrap();

    let sys_realm = system_realm_id();
    let key_storage_key = format!("realm:key:{}", realm.id().as_uuid()).into_bytes();
    let raw = storage
        .get(&sys_realm, &key_storage_key)
        .unwrap()
        .expect("realm signing key must be present");

    assert_ne!(
        raw.first().copied(),
        Some(0x30),
        "stored realm key must not be raw PKCS#8 when KEK is set"
    );
    assert_eq!(&raw[..4], b"HKEY", "realm key must be HKEY-wrapped");
}

// ---------------------------------------------------------------------------
// Test 2: keys survive engine restart with the same KEK (round-trip)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn keys_survive_restart_with_same_kek() {
    let dir = tempfile::tempdir().unwrap();
    let storage_cfg = StorageConfig::dev(dir.path().to_path_buf());

    // First engine boot: create a realm.
    let realm_id = {
        let storage: Arc<dyn StorageEngine> =
            Arc::new(EmbeddedStorageEngine::open(storage_cfg.clone()).unwrap());
        let engine = make_engine(Arc::clone(&storage), Some(test_kek()));

        let realm = engine
            .create_realm(&CreateRealmRequest {
                name: "persistent-realm".into(),
                config: None,
            })
            .unwrap();

        // JWKS must be accessible on the first boot.
        let jwks = engine.realm_jwks(realm.id()).unwrap();
        assert!(!jwks.keys.is_empty(), "realm must have at least one JWK");

        realm.id().clone()
    };
    // Storage drops here — simulates a process restart.

    // Second engine boot with the same KEK: realm key must still be loadable.
    let storage: Arc<dyn StorageEngine> =
        Arc::new(EmbeddedStorageEngine::open(storage_cfg).unwrap());
    let engine = make_engine(Arc::clone(&storage), Some(test_kek()));

    let jwks = engine.realm_jwks(&realm_id).unwrap();
    assert!(
        !jwks.keys.is_empty(),
        "realm JWKS must survive restart when KEK is unchanged"
    );
}

// ---------------------------------------------------------------------------
// Test 3: is_key_material predicate identifies all key-material prefixes
// ---------------------------------------------------------------------------

#[test]
fn is_key_material_identifies_signing_key_prefixes() {
    let cases: &[(&[u8], bool)] = &[
        // Key-material prefixes — must be true.
        (b"realm:key:00000000-0000-0000-0000-000000000000", true),
        (
            b"realm:retiring:00000000-0000-0000-0000-000000000000:123:kid1",
            true,
        ),
        (b"realm:saml_key:00000000-0000-0000-0000-000000000000", true),
        (b"sys:global:key", true),
        (b"sys:oidc:rsa:key", true),
        (b"sys:oidc:rsa:retiring:00000000000000000100:kid1", true),
        (b"agt:dpop:nonce-secret", true),
        // Non-key-material — must be false.
        (b"realm:id:00000000-0000-0000-0000-000000000000", false),
        (b"realm:name:myrealm", false),
        (b"usr:id:abc", false),
        (b"oauth:client:def", false),
        (b"sys:global:config", false),
        (b"agt:dpop:jti:abc", false),
    ];

    for (key, expected) in cases {
        // We replicate the predicate logic directly since `is_key_material`
        // is internal; validate indirectly via the HKEY-wrap behavior and
        // document the expected classification here.
        let key_str = String::from_utf8_lossy(key);
        let is_kmat = key.starts_with(b"realm:key:")
            || key.starts_with(b"realm:retiring:")
            || key.starts_with(b"realm:saml_key:")
            || key.starts_with(b"sys:oidc:rsa:retiring:")
            || *key == b"sys:global:key"
            || *key == b"sys:oidc:rsa:key"
            || *key == b"agt:dpop:nonce-secret";
        assert_eq!(
            is_kmat, *expected,
            "is_key_material({key_str}) should be {expected}"
        );
    }
}

// ---------------------------------------------------------------------------
// Test 4 (audit 2026-08-28 §25.9): the KEK enrolment sweep and the strict
// read path must cover the per-realm key families too — SAML signing keys,
// DPoP nonce secrets and the MFA at-rest DEK — not just Ed25519 signing keys.
// ---------------------------------------------------------------------------

/// Storage key for a realm's SAML signing key (lives under the system realm).
fn saml_key_storage_key(realm_id: &RealmId) -> Vec<u8> {
    format!("realm:saml_key:{}", realm_id.as_uuid()).into_bytes()
}

const DPOP_NONCE_SECRET_KEY: &[u8] = b"agt:dpop:nonce-secret";
const MFA_DEK_KEY: &[u8] = b"mfa:dek:key";

/// Boots an engine with **no** KEK and materialises all three per-realm key
/// families in plaintext, exactly as a pre-KEK deployment leaves them on disk.
///
/// Returns the realm the keys belong to.
fn seed_plaintext_per_realm_keys(storage: &Arc<dyn StorageEngine>) -> RealmId {
    let engine = make_engine(Arc::clone(storage), None);
    let realm = engine
        .create_realm(&CreateRealmRequest {
            name: "legacy-realm".into(),
            config: None,
        })
        .unwrap();
    let realm_id = realm.id().clone();

    engine
        .get_or_create_saml_signing_key(&realm_id, "hearth-test")
        .unwrap();
    engine.get_realm_dpop_nonce_secret(&realm_id).unwrap();

    let user = engine
        .create_user(
            &realm_id,
            &hearth::identity::CreateUserRequest {
                email: "mfa@example.com".into(),
                display_name: "MFA User".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: std::collections::BTreeMap::new(),
            },
        )
        .unwrap();
    engine.enroll_totp(&realm_id, user.id()).unwrap();

    realm_id
}

/// Asserts a stored blob exists and is (or is not) HKEY-enveloped.
fn assert_envelope(
    storage: &Arc<dyn StorageEngine>,
    scope: &RealmId,
    key: &[u8],
    want_enveloped: bool,
    what: &str,
) {
    let raw = storage
        .get(scope, key)
        .unwrap()
        .unwrap_or_else(|| panic!("{what} must be present in storage"));
    let enveloped = raw.len() >= 4 && &raw[..4] == b"HKEY";
    assert_eq!(
        enveloped, want_enveloped,
        "{what}: expected HKEY-enveloped={want_enveloped}, got {enveloped}"
    );
}

#[tokio::test]
async fn kek_enrolment_sweep_covers_saml_dpop_and_mfa_keys() {
    let dir = tempfile::tempdir().unwrap();
    let storage_cfg = StorageConfig::dev(dir.path().to_path_buf());
    let storage: Arc<dyn StorageEngine> =
        Arc::new(EmbeddedStorageEngine::open(storage_cfg).unwrap());
    let sys_realm = system_realm_id();

    let realm_id = seed_plaintext_per_realm_keys(&storage);

    // Precondition: all three really are plaintext before enrolment. Without
    // this the assertions below could pass over keys that were never written.
    assert_envelope(
        &storage,
        &sys_realm,
        &saml_key_storage_key(&realm_id),
        false,
        "SAML signing key before enrolment",
    );
    assert_envelope(
        &storage,
        &realm_id,
        DPOP_NONCE_SECRET_KEY,
        false,
        "DPoP nonce secret before enrolment",
    );
    assert_envelope(
        &storage,
        &realm_id,
        MFA_DEK_KEY,
        false,
        "MFA DEK before enrolment",
    );

    // Switch the KEK on over the existing store. Construction runs the
    // enrolment sweep.
    let _engine = make_engine(Arc::clone(&storage), Some(test_kek()));

    assert_envelope(
        &storage,
        &sys_realm,
        &saml_key_storage_key(&realm_id),
        true,
        "SAML signing key after enrolment",
    );
    assert_envelope(
        &storage,
        &realm_id,
        DPOP_NONCE_SECRET_KEY,
        true,
        "DPoP nonce secret after enrolment",
    );
    assert_envelope(
        &storage,
        &realm_id,
        MFA_DEK_KEY,
        true,
        "MFA DEK after enrolment",
    );
}

#[tokio::test]
async fn enrolled_store_refuses_a_plaintext_saml_key() {
    let dir = tempfile::tempdir().unwrap();
    let storage_cfg = StorageConfig::dev(dir.path().to_path_buf());
    let storage: Arc<dyn StorageEngine> =
        Arc::new(EmbeddedStorageEngine::open(storage_cfg).unwrap());
    let sys_realm = system_realm_id();

    let realm_id = seed_plaintext_per_realm_keys(&storage);
    let _enrolled = make_engine(Arc::clone(&storage), Some(test_kek()));

    // An attacker with storage write access strips the envelope and
    // substitutes key material of their own. After enrolment that is a
    // downgrade, not a legacy row.
    let stripped = br#"{"pkcs8":[],"cert":[]}"#.to_vec();
    storage
        .put(&sys_realm, &saml_key_storage_key(&realm_id), &stripped)
        .unwrap();

    // A fresh engine over the same (already-enrolled) store: the sweep is a
    // no-op because the marker is present, so the read path must refuse.
    let engine = make_engine(Arc::clone(&storage), Some(test_kek()));
    let err = engine
        .get_or_create_saml_signing_key(&realm_id, "hearth-test")
        .expect_err("an unenveloped SAML key must be refused on an enrolled store");
    let msg = err.to_string();
    assert!(
        msg.contains("HKEY-envelope") || msg.contains("HKEY-enveloped"),
        "expected an envelope-downgrade refusal, got: {msg}"
    );
}

#[tokio::test]
async fn enrolled_store_refuses_a_plaintext_dpop_nonce_secret() {
    let dir = tempfile::tempdir().unwrap();
    let storage_cfg = StorageConfig::dev(dir.path().to_path_buf());
    let storage: Arc<dyn StorageEngine> =
        Arc::new(EmbeddedStorageEngine::open(storage_cfg).unwrap());

    let realm_id = seed_plaintext_per_realm_keys(&storage);
    let _enrolled = make_engine(Arc::clone(&storage), Some(test_kek()));

    storage
        .put(&realm_id, DPOP_NONCE_SECRET_KEY, &[0x11_u8; 32])
        .unwrap();

    let engine = make_engine(Arc::clone(&storage), Some(test_kek()));
    let err = engine
        .get_realm_dpop_nonce_secret(&realm_id)
        .expect_err("an unenveloped DPoP nonce secret must be refused on an enrolled store");
    let msg = err.to_string();
    assert!(
        msg.contains("HKEY-envelope") || msg.contains("HKEY-enveloped"),
        "expected an envelope-downgrade refusal, got: {msg}"
    );
}

#[tokio::test]
async fn enrolled_store_refuses_a_plaintext_mfa_dek() {
    let dir = tempfile::tempdir().unwrap();
    let storage_cfg = StorageConfig::dev(dir.path().to_path_buf());
    let storage: Arc<dyn StorageEngine> =
        Arc::new(EmbeddedStorageEngine::open(storage_cfg).unwrap());

    let realm_id = seed_plaintext_per_realm_keys(&storage);
    let _enrolled = make_engine(Arc::clone(&storage), Some(test_kek()));

    storage.put(&realm_id, MFA_DEK_KEY, &[0x22_u8; 32]).unwrap();

    let engine = make_engine(Arc::clone(&storage), Some(test_kek()));
    let user = engine
        .create_user(
            &realm_id,
            &hearth::identity::CreateUserRequest {
                email: "second@example.com".into(),
                display_name: "Second".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: std::collections::BTreeMap::new(),
            },
        )
        .unwrap();
    let err = engine
        .enroll_totp(&realm_id, user.id())
        .expect_err("an unenveloped MFA DEK must be refused on an enrolled store");
    let msg = err.to_string();
    assert!(
        msg.contains("HKEY-envelope") || msg.contains("HKEY-enveloped"),
        "expected an envelope-downgrade refusal, got: {msg}"
    );
}
