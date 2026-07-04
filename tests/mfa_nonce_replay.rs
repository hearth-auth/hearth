#![allow(clippy::unwrap_used)]
//! Regression tests for HEA-SEC-25 — MFA pending cookie nonce replay.
//!
//! Verifies:
//! 1. A nonce burned via `burn_mfa_nonce` is rejected by `is_mfa_nonce_burned`
//!    even after the identity engine is reconstructed from the same WAL storage
//!    (i.e. after a server restart). This is the core WAL-persistence regression.
//! 2. `burn_mfa_nonce` + `is_mfa_nonce_burned` are consistent within a single
//!    engine instance.
//! 3. A nonce that has never been burned is not reported as burned.

use std::sync::Arc;

use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{Clock, RealmId, SystemClock};
use hearth::identity::{
    CreateRealmRequest, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine,
};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Opens a storage engine at `data_dir` and builds an identity engine on top.
fn open_identity(data_dir: &std::path::Path) -> Arc<dyn IdentityEngine> {
    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.to_path_buf()))
            .expect("open storage"),
    );
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn AuditEngine>;
    Arc::new(
        EmbeddedIdentityEngine::new(
            Arc::clone(&storage) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
            IdentityConfig::default(),
            Arc::clone(&audit),
        )
        .expect("identity engine"),
    ) as Arc<dyn IdentityEngine>
}

/// Creates a realm in the given engine and returns its `RealmId`.
fn make_realm(identity: &dyn IdentityEngine) -> RealmId {
    identity
        .create_realm(&CreateRealmRequest {
            name: "test-realm".to_string(),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone()
}

// ── regression: WAL persistence ───────────────────────────────────────────────

/// A nonce burned before a simulated restart is still reported as burned after
/// reopening the same WAL storage. This is the core HEA-SEC-25 regression.
#[tokio::test]
async fn burned_nonce_survives_engine_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().to_path_buf();

    let nonce = "test-nonce-abc123";
    let exp_secs = u64::MAX; // far future — never stale

    // First engine lifetime: create realm, burn nonce.
    let realm_id = {
        let identity = open_identity(&data_dir);
        let realm_id = make_realm(identity.as_ref());
        identity
            .burn_mfa_nonce(&realm_id, nonce, exp_secs)
            .expect("burn_mfa_nonce");
        realm_id
    };
    // Engine dropped — all in-process state is gone.

    // Second engine lifetime: re-open same storage dir.
    let identity2 = open_identity(&data_dir);
    let burned = identity2
        .is_mfa_nonce_burned(&realm_id, nonce)
        .expect("is_mfa_nonce_burned");
    assert!(
        burned,
        "nonce must still be burned after engine restart (WAL must have persisted it)"
    );
}

// ── within-instance consistency ───────────────────────────────────────────────

/// Burning a nonce and then checking it returns `true` in the same instance.
#[tokio::test]
async fn burned_nonce_is_detected_same_instance() {
    let dir = tempfile::tempdir().expect("tempdir");
    let identity = open_identity(dir.path());
    let realm_id = make_realm(identity.as_ref());

    let nonce = "replay-me-if-you-can";
    let exp_secs = u64::MAX;

    identity
        .burn_mfa_nonce(&realm_id, nonce, exp_secs)
        .expect("burn_mfa_nonce");

    let burned = identity
        .is_mfa_nonce_burned(&realm_id, nonce)
        .expect("is_mfa_nonce_burned");
    assert!(
        burned,
        "nonce must be detected as burned immediately after burn"
    );
}

/// An unknown nonce is not reported as burned.
#[tokio::test]
async fn fresh_nonce_is_not_burned() {
    let dir = tempfile::tempdir().expect("tempdir");
    let identity = open_identity(dir.path());
    let realm_id = make_realm(identity.as_ref());

    let burned = identity
        .is_mfa_nonce_burned(&realm_id, "never-used-nonce")
        .expect("is_mfa_nonce_burned");
    assert!(
        !burned,
        "a nonce that was never burned must not be detected as burned"
    );
}

/// Two distinct nonces are tracked independently — burning one does not affect
/// the other.
#[tokio::test]
async fn burning_one_nonce_does_not_affect_another() {
    let dir = tempfile::tempdir().expect("tempdir");
    let identity = open_identity(dir.path());
    let realm_id = make_realm(identity.as_ref());

    let nonce_a = "nonce-aaaa";
    let nonce_b = "nonce-bbbb";
    let exp_secs = u64::MAX;

    identity
        .burn_mfa_nonce(&realm_id, nonce_a, exp_secs)
        .expect("burn nonce_a");

    assert!(
        identity
            .is_mfa_nonce_burned(&realm_id, nonce_a)
            .expect("check a"),
        "nonce_a must be burned"
    );
    assert!(
        !identity
            .is_mfa_nonce_burned(&realm_id, nonce_b)
            .expect("check b"),
        "nonce_b must not be burned"
    );
}

/// Nonces are realm-scoped: burning a nonce in realm A does not affect realm B.
#[tokio::test]
async fn burned_nonce_is_realm_scoped() {
    let dir = tempfile::tempdir().expect("tempdir");
    let identity = open_identity(dir.path());

    let realm_a = identity
        .create_realm(&CreateRealmRequest {
            name: "realm-a".to_string(),
            config: None,
        })
        .expect("create realm_a")
        .id()
        .clone();
    let realm_b = identity
        .create_realm(&CreateRealmRequest {
            name: "realm-b".to_string(),
            config: None,
        })
        .expect("create realm_b")
        .id()
        .clone();

    let nonce = "cross-realm-nonce";
    let exp_secs = u64::MAX;

    identity
        .burn_mfa_nonce(&realm_a, nonce, exp_secs)
        .expect("burn in realm_a");

    assert!(
        identity
            .is_mfa_nonce_burned(&realm_a, nonce)
            .expect("check realm_a"),
        "nonce burned in realm_a must be reported burned there"
    );
    assert!(
        !identity
            .is_mfa_nonce_burned(&realm_b, nonce)
            .expect("check realm_b"),
        "nonce burned in realm_a must NOT be reported burned in realm_b"
    );
}
