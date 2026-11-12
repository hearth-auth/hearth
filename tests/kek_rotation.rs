//! Rotation of the key-encryption key at a restart (#649).
//!
//! A store written under one KEK opens under a new KEK after one call of
//! `rotate_key_encryption_key` with the old KEK as the previous key. Every
//! stored key keeps its value: the same JWKS, SAML key, DPoP nonce secret
//! and TOTP data key.

use std::sync::Arc;

use hearth::audit::EmbeddedAuditEngine;
use hearth::core::{Clock, RealmId};
use hearth::identity::kek_rotation::rotate_key_encryption_key;
use hearth::identity::key_encryption::StorageKek;
use hearth::identity::{
    CreateRealmRequest, CreateUserRequest, CredentialConfig, EmbeddedIdentityEngine,
    IdentityConfig, IdentityEngine,
};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

fn old_kek() -> StorageKek {
    StorageKek::new([0x42_u8; 32])
}

fn new_kek() -> StorageKek {
    StorageKek::new([0x5a_u8; 32])
}

/// Builds the identity engine over `storage` with `kek`, as `serve` does:
/// the audit engine gets the same KEK. See `make_engine` in
/// `tests/key_encryption_at_rest.rs` for why there is no `init_sv_bumper`.
fn try_engine(
    storage: &Arc<dyn StorageEngine>,
    kek: &StorageKek,
) -> Result<Arc<dyn IdentityEngine>, hearth::identity::IdentityError> {
    let clock = Arc::new(hearth::core::SystemClock) as Arc<dyn Clock>;
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(storage),
        Arc::clone(&clock),
    ));
    let audit = Arc::new(
        EmbeddedAuditEngine::new(Arc::clone(storage), Arc::clone(&clock))
            .with_kek(Some(*kek.as_bytes())),
    );
    let config = IdentityConfig {
        credential: CredentialConfig::fast_for_testing(),
        key_encryption_key: Some(kek.clone()),
        ..IdentityConfig::default()
    };
    EmbeddedIdentityEngine::with_rbac(
        Arc::clone(storage),
        clock,
        config,
        Arc::clone(&rbac) as Arc<dyn RbacEngine>,
        audit as Arc<dyn hearth::audit::AuditEngine>,
    )
    .map(|engine| Arc::new(engine) as Arc<dyn IdentityEngine>)
}

fn open_storage(dir: &std::path::Path) -> Arc<dyn StorageEngine> {
    Arc::new(EmbeddedStorageEngine::open(StorageConfig::dev(dir.to_path_buf())).expect("storage"))
}

/// The values of the stored keys that a rotation must keep.
#[derive(Debug, PartialEq, Eq)]
struct KeyValues {
    jwks: String,
    saml_certificate: Vec<u8>,
    dpop_nonce_secret: [u8; 32],
}

fn key_values(engine: &Arc<dyn IdentityEngine>, realm: &RealmId) -> KeyValues {
    KeyValues {
        jwks: serde_json::to_string(&engine.realm_jwks(realm).expect("jwks")).expect("json"),
        saml_certificate: engine
            .get_or_create_saml_signing_key(realm, "hearth-test")
            .expect("saml key")
            .cert_der()
            .to_vec(),
        dpop_nonce_secret: engine
            .get_realm_dpop_nonce_secret(realm)
            .expect("dpop nonce secret"),
    }
}

/// Writes a store under the old KEK with every family of stored key: the
/// global and realm signing keys, a retiring key, a SAML key, the DPoP nonce
/// secret, the MFA data key and the audit chain key.
fn seed_store_under_old_kek(storage: &Arc<dyn StorageEngine>) -> (RealmId, KeyValues) {
    let engine = try_engine(storage, &old_kek()).expect("engine under the old KEK");
    let realm = engine
        .create_realm(&CreateRealmRequest {
            name: "rotated".into(),
            config: None,
        })
        .expect("realm")
        .id()
        .clone();
    engine
        .rotate_realm_signing_key(&realm, 3_600)
        .expect("a retiring key");
    let user = engine
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "mfa@example.com".into(),
                display_name: "MFA User".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: std::collections::BTreeMap::new(),
            },
        )
        .expect("user");
    engine.enroll_totp(&realm, user.id()).expect("totp");
    let values = key_values(&engine, &realm);
    (realm, values)
}

#[tokio::test]
async fn a_restart_with_the_previous_kek_rewraps_every_key_and_keeps_its_value() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = open_storage(dir.path());
    let (realm, before) = seed_store_under_old_kek(&storage);
    assert!(
        try_engine(&storage, &new_kek()).is_err(),
        "precondition: a store under the old KEK does not open under the new one"
    );

    let rewrapped =
        rotate_key_encryption_key(&storage, &new_kek(), Some(&old_kek())).expect("rotation");
    assert!(rewrapped > 0, "the rotation must write the stored keys");

    let engine = try_engine(&storage, &new_kek()).expect("the store opens under the new KEK");
    assert_eq!(
        key_values(&engine, &realm),
        before,
        "every key keeps its value"
    );
    assert!(
        try_engine(&storage, &old_kek()).is_err(),
        "after the rotation the old KEK opens nothing"
    );

    let again = rotate_key_encryption_key(&storage, &new_kek(), Some(&old_kek())).expect("again");
    assert_eq!(
        again, 0,
        "a second rotation (a restart with both keys) writes nothing"
    );
}

#[tokio::test]
async fn a_changed_kek_without_the_previous_kek_names_hearth_previous_kek() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = open_storage(dir.path());
    seed_store_under_old_kek(&storage);

    let err = rotate_key_encryption_key(&storage, &new_kek(), None)
        .expect_err("a store under another KEK must be refused");
    assert!(
        err.to_string().contains("HEARTH_PREVIOUS_KEK"),
        "the refusal must name HEARTH_PREVIOUS_KEK, got: {err}"
    );
}

#[tokio::test]
async fn a_wrong_previous_kek_is_refused_and_writes_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = open_storage(dir.path());
    let (realm, before) = seed_store_under_old_kek(&storage);

    let wrong = StorageKek::new([0x77_u8; 32]);
    let err = rotate_key_encryption_key(&storage, &new_kek(), Some(&wrong))
        .expect_err("a previous KEK that opens nothing must be refused");
    assert!(
        err.to_string().contains("HEARTH_PREVIOUS_KEK"),
        "the refusal must name HEARTH_PREVIOUS_KEK, got: {err}"
    );
    let engine = try_engine(&storage, &old_kek()).expect("the store still opens under the old KEK");
    assert_eq!(key_values(&engine, &realm), before);
}
