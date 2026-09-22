//! Signing-key and JWKS surface tests (audit 2026-08-28 §4.2#4, §4.15#3–#7).
//!
//! Each test here is the red half of one remediation task:
//!
//! - `jwks_publishes_only_algorithms_hearth_signs_with` — §4.15#5 / §4.2#4.
//! - `no_unencrypted_oidc_rsa_private_key_survives_in_storage` — §4.15#4.
//! - `config_driven_rotation_emits_an_audit_event` — §4.14#9.
//! - `config_driven_rotation_grace_covers_the_refresh_token_lifetime` — §4.15#3.
//! - `rotation_on_one_node_invalidates_a_second_nodes_key_cache` — §4.15#6.
//! - `unenveloped_signing_key_is_refused_when_a_kek_is_configured` and
//!   `enabling_the_kek_re_encrypts_already_stored_signing_keys` — §4.15#7.

#![allow(clippy::unwrap_used)]

mod common;

use std::sync::Arc;

use hearth::audit::{AuditAction, AuditEngine, AuditQuery, EmbeddedAuditEngine};
use hearth::config::{compute_diff, ConfigSnapshot, RealmYamlConfig};
use hearth::core::{Clock, FakeClock, RealmId, Timestamp};
use hearth::identity::key_encryption::StorageKek;
use hearth::identity::reconcile::apply_diff;
use hearth::identity::{
    CreateRealmRequest, CredentialConfig, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine,
    RealmConfig,
};
use hearth::rbac::EmbeddedRbacEngine;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

// ── Helpers ───────────────────────────────────────────────────────────────────

/// The nil-UUID system realm every signing-key blob is stored under.
fn system_realm() -> RealmId {
    RealmId::new(uuid::Uuid::nil())
}

/// Builds an identity engine on top of an already-open storage handle so a test
/// can stand up two engines over one store (the two-node shape of §4.15#6) or
/// re-open a store after seeding raw bytes into it.
fn engine_over(
    storage: &Arc<dyn StorageEngine>,
    clock: &Arc<FakeClock>,
    identity_config: IdentityConfig,
) -> Result<EmbeddedIdentityEngine, hearth::identity::IdentityError> {
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(storage),
        Arc::clone(clock) as Arc<dyn Clock>,
    ));
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(storage),
        Arc::clone(clock) as Arc<dyn Clock>,
    ));
    EmbeddedIdentityEngine::with_rbac(
        Arc::clone(storage),
        Arc::clone(clock) as Arc<dyn Clock>,
        identity_config,
        rbac as Arc<dyn hearth::rbac::RbacEngine>,
        audit as Arc<dyn AuditEngine>,
    )
}

fn fast_config() -> IdentityConfig {
    IdentityConfig {
        credential: CredentialConfig::fast_for_testing(),
        ..IdentityConfig::default()
    }
}

fn open_storage(dir: &tempfile::TempDir) -> Arc<dyn StorageEngine> {
    let config = StorageConfig::dev(dir.path().to_path_buf());
    Arc::new(EmbeddedStorageEngine::open(config).unwrap()) as Arc<dyn StorageEngine>
}

/// Scans a raw key prefix under the system realm and returns the entries.
fn scan_prefix(storage: &Arc<dyn StorageEngine>, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut end = prefix.to_vec();
    *end.last_mut().unwrap() += 1;
    storage
        .scan(&system_realm(), prefix, &end)
        .unwrap()
        .into_iter()
        .map(|e| (e.key, e.value))
        .collect()
}

// ── §4.15#5 / §4.2#4: publish only algorithms Hearth signs with ───────────────

/// Hearth signs every token it issues with Ed25519. The global JWKS also
/// advertised an RSA-2048 (`RS256`) key it never signs with and an EC P-256
/// (`ES256`) key whose private half was regenerated on every process start,
/// under a `max-age=3600` cache directive — so a relying party that picked the
/// ES256 entry verified against a key that no longer existed.
#[test]
fn jwks_publishes_only_algorithms_hearth_signs_with() {
    let dir = tempfile::tempdir().unwrap();
    let storage = open_storage(&dir);
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000_000_000)));
    let engine = engine_over(&storage, &clock, fast_config()).unwrap();

    let jwks = engine.jwks();
    assert!(!jwks.keys.is_empty(), "global JWKS must not be empty");

    let algs: Vec<&str> = jwks.keys.iter().map(|k| k.alg.as_str()).collect();
    assert!(
        jwks.keys.iter().all(|k| k.alg == "EdDSA"),
        "JWKS must publish only algorithms Hearth signs with; got {algs:?}"
    );
}

// ── §4.15#4: no unencrypted RSA private key at rest ──────────────────────────

/// The server-wide OIDC RSA-2048 keypair was serialised to
/// `sys:oidc:rsa:key` as plain JSON — PKCS#8 private key included — while
/// every other key family went through the HKEY envelope. Nothing signs with
/// it, so no plaintext private key may survive in storage.
#[test]
fn no_unencrypted_oidc_rsa_private_key_survives_in_storage() {
    let dir = tempfile::tempdir().unwrap();
    let storage = open_storage(&dir);
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000_000_000)));

    {
        let engine = engine_over(&storage, &clock, fast_config()).unwrap();
        // Touching the JWKS is what used to materialise and persist the key.
        let _ = engine.jwks();
    }

    let rows = scan_prefix(&storage, b"sys:oidc:rsa:");
    let keys: Vec<String> = rows
        .iter()
        .map(|(k, _)| String::from_utf8_lossy(k).into_owned())
        .collect();
    assert!(
        rows.is_empty(),
        "no OIDC RSA private-key row may remain in storage; found {keys:?}"
    );
}

/// A store written by an older build carries the plaintext row. Opening it
/// must remove it rather than leave an unencrypted private key at rest.
#[test]
fn a_preexisting_plaintext_oidc_rsa_row_is_purged_on_open() {
    let dir = tempfile::tempdir().unwrap();
    let storage = open_storage(&dir);
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000_000_000)));

    // Shape matches the legacy `StoredRsaKey` JSON envelope.
    let legacy = br#"{"pkcs8":[48,130,4,190],"cert":[48,130,3,120]}"#;
    storage
        .put(&system_realm(), b"sys:oidc:rsa:key", legacy)
        .unwrap();
    storage
        .put(
            &system_realm(),
            b"sys:oidc:rsa:retiring:00000000000099999999:legacy-kid",
            legacy,
        )
        .unwrap();

    let engine = engine_over(&storage, &clock, fast_config()).unwrap();
    let _ = engine.jwks();

    let rows = scan_prefix(&storage, b"sys:oidc:rsa:");
    assert!(
        rows.is_empty(),
        "legacy plaintext OIDC RSA rows must be purged, {} left",
        rows.len()
    );
}

// ── §4.14#9: config-driven rotation must be audited ──────────────────────────

/// `POST /admin/realms/{id}/rotate-signing-key` writes a `RealmUpdated` audit
/// event. The `rotate_signing_key: true` config path performed the identical
/// security-relevant operation and wrote nothing, so an operator reading the
/// audit log could not tell that the realm had been re-keyed.
#[tokio::test]
async fn config_driven_rotation_emits_an_audit_event() {
    let harness = common::TestHarness::embedded().await.unwrap();

    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: "tenant".to_string(),
            config: Some(RealmConfig::default()),
        })
        .unwrap();

    let realm_yaml = RealmYamlConfig {
        rotate_signing_key: Some(true),
        ..RealmYamlConfig::default()
    };
    let mut config = hearth::config::Config::default();
    let mut realms = std::collections::HashMap::new();
    realms.insert("tenant".to_string(), realm_yaml);
    config.realms = Some(realms);

    let old_snap = {
        let mut snap = ConfigSnapshot::from_config(&config);
        if let Some(realm_snaps) = snap.realms.as_mut() {
            if let Some(rs) = realm_snaps.get_mut("tenant") {
                rs.rotate_signing_key = false;
            }
        }
        snap
    };
    let diffs = compute_diff(&old_snap, &config);

    apply_diff(
        &diffs,
        &config,
        harness.identity(),
        harness.rbac(),
        harness.audit(),
    )
    .unwrap();

    let events = harness
        .audit()
        .query(&AuditQuery {
            realm_id: realm.id().clone(),
            start_time: None,
            end_time: None,
            actor: None,
            action: Some(AuditAction::RealmUpdated),
            limit: None,
            agent_id: None,
            tool: None,
        })
        .unwrap();

    let rotation = events.iter().find(|e| {
        e.metadata
            .as_ref()
            .and_then(|m| m.get("action"))
            .and_then(serde_json::Value::as_str)
            == Some("rotate_signing_key")
    });
    assert!(
        rotation.is_some(),
        "config-driven rotation must write an audit event; saw {} RealmUpdated events",
        events.len()
    );
}

// ── §4.15#3: grace window must relate to token lifetime ──────────────────────

/// The config-driven rotation used a hard-coded 24 h default while
/// `token.refresh_token_ttl` defaults to 7 d, so a planned rotation killed
/// every outstanding refresh token six days before its own `exp`. The default
/// must cover the longest refresh-token lifetime the realm can have issued.
#[test]
fn config_driven_rotation_grace_covers_the_refresh_token_lifetime() {
    let config = hearth::config::Config::default();
    let grace = hearth::identity::reconcile::config_rotation_grace_secs(&config);
    let refresh_ttl = hearth::identity::reconcile::config_refresh_ttl_secs(&config);

    assert!(
        grace >= refresh_ttl,
        "default rotation grace ({grace}s) must cover the refresh-token TTL ({refresh_ttl}s)"
    );
}

/// An operator who sets the key explicitly keeps control — the value is used
/// verbatim, including a deliberately short one.
#[test]
fn an_explicit_rotation_grace_is_honoured_verbatim() {
    let mut config = hearth::config::Config::default();
    config.token.signing_key_rotation_grace_period = Some("1h".to_string());
    assert_eq!(
        hearth::identity::reconcile::config_rotation_grace_secs(&config),
        3_600
    );
}

// ── §4.15#6: rotation must invalidate caches on every node ───────────────────

/// Two engines over one replicated store model two nodes. Rotating on the
/// first must stop the second publishing — and trusting — the pre-rotation
/// key. The signing-key caches were process-local with no cross-node signal.
#[test]
fn rotation_on_one_node_invalidates_a_second_nodes_key_cache() {
    let dir = tempfile::tempdir().unwrap();
    let storage = open_storage(&dir);
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000_000_000)));

    let node_a = engine_over(&storage, &clock, fast_config()).unwrap();
    let node_b = engine_over(&storage, &clock, fast_config()).unwrap();

    let realm = node_a
        .create_realm(&CreateRealmRequest {
            name: "acme".to_string(),
            config: Some(RealmConfig::default()),
        })
        .unwrap();

    // Node B warms its cache with the pre-rotation key.
    let before = node_b.realm_jwks(realm.id()).unwrap();
    assert_eq!(before.keys.len(), 1);
    let stale_kid = before.keys[0].kid.clone();

    // Node A performs a revoking rotation (grace 0 — the incident remedy).
    node_a.rotate_realm_signing_key(realm.id(), 0).unwrap();

    let after = node_b.realm_jwks(realm.id()).unwrap();
    let kids: Vec<&str> = after.keys.iter().map(|k| k.kid.as_str()).collect();
    assert!(
        !kids.contains(&stale_kid.as_str()),
        "node B must stop publishing the revoked kid {stale_kid}; got {kids:?}"
    );
}

// ── §4.15#7: KEK-configured deployments must fail closed ─────────────────────

/// `unwrap_key` passed any non-`HKEY` blob straight through, so on a
/// KEK-configured deployment an attacker with write access to the store could
/// strip the envelope and substitute a signing key of their own. A KEK
/// deployment must refuse unenveloped key material outright.
#[test]
fn unenveloped_signing_key_is_refused_when_a_kek_is_configured() {
    let dir = tempfile::tempdir().unwrap();
    let storage = open_storage(&dir);
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000_000_000)));

    let kek = StorageKek::new([0x5A; 32]);
    let engine = engine_over(
        &storage,
        &clock,
        IdentityConfig {
            key_encryption_key: Some(kek),
            ..fast_config()
        },
    )
    .unwrap();

    let realm = engine
        .create_realm(&CreateRealmRequest {
            name: "acme".to_string(),
            config: Some(RealmConfig::default()),
        })
        .unwrap();

    // An attacker substitutes their own unenveloped PKCS#8 key.
    let attacker = hearth::identity::tokens::SigningKey::generate().unwrap();
    let raw = attacker.pkcs8_bytes().to_vec();
    let key_path = format!("realm:key:{}", realm.id().as_uuid()).into_bytes();
    storage.put(&system_realm(), &key_path, &raw).unwrap();

    // A fresh engine must refuse the substituted key rather than adopt it.
    let reader = engine_over(
        &storage,
        &clock,
        IdentityConfig {
            key_encryption_key: Some(StorageKek::new([0x5A; 32])),
            ..fast_config()
        },
    )
    .unwrap();
    let result = reader.realm_jwks(realm.id());
    assert!(
        result.is_err(),
        "an unenveloped signing key must be refused on a KEK-configured deployment"
    );
}

/// Turning the KEK on for an existing data directory left every already-stored
/// key in plaintext until someone rotated it. Enabling the KEK must
/// re-encrypt what is already on disk.
#[test]
fn enabling_the_kek_re_encrypts_already_stored_signing_keys() {
    let dir = tempfile::tempdir().unwrap();
    let storage = open_storage(&dir);
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000_000_000)));

    // Boot 1: no KEK. Keys land in plaintext.
    let realm_id = {
        let engine = engine_over(&storage, &clock, fast_config()).unwrap();
        let realm = engine
            .create_realm(&CreateRealmRequest {
                name: "acme".to_string(),
                config: Some(RealmConfig::default()),
            })
            .unwrap();
        realm.id().clone()
    };

    let key_path = format!("realm:key:{}", realm_id.as_uuid()).into_bytes();
    let plain = storage.get(&system_realm(), &key_path).unwrap().unwrap();
    assert_ne!(&plain[..4], b"HKEY", "boot 1 must store plaintext");

    // Boot 2: KEK configured. The stored key must be re-encrypted in place.
    let engine = engine_over(
        &storage,
        &clock,
        IdentityConfig {
            key_encryption_key: Some(StorageKek::new([0x5A; 32])),
            ..fast_config()
        },
    )
    .unwrap();

    let stored = storage.get(&system_realm(), &key_path).unwrap().unwrap();
    assert_eq!(
        &stored[..4],
        b"HKEY",
        "enabling the KEK must re-encrypt the already-stored signing key"
    );

    // …and the realm still works afterwards.
    let jwks = engine.realm_jwks(&realm_id).unwrap();
    assert_eq!(jwks.keys.len(), 1);
}
