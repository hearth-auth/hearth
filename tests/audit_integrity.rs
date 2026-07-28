//! Integration tests for HEA-SEC-21: audit log integrity.
//!
//! Three scenarios:
//! 1. An `AuditLogPruned` event can be recorded before executing a prune and
//!    survives the pruning window (handler completeness).
//! 2. After a prune, no orphaned actor or action index entries remain (atomic
//!    delete via `write_batch`).
//! 3. `verify_integrity` fails after a storage-layer SHA-256 forgery attack
//!    (keyed HMAC chain cannot be forged without the per-realm key).

use hearth::audit::{AuditAction, AuditEngine, AuditQuery, CreateAuditEvent, EmbeddedAuditEngine};
use hearth::core::{Clock, FakeClock, RealmId, Timestamp};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use std::sync::Arc;

fn make_engine(
    clock: Arc<dyn Clock>,
) -> (
    Arc<EmbeddedAuditEngine>,
    Arc<dyn StorageEngine>,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = StorageConfig::dev(dir.path().to_path_buf());
    let storage =
        Arc::new(EmbeddedStorageEngine::open(cfg).expect("open")) as Arc<dyn StorageEngine>;
    let engine = Arc::new(EmbeddedAuditEngine::new(Arc::clone(&storage), clock));
    (engine, storage, dir)
}

fn append(
    engine: &dyn AuditEngine,
    realm: &RealmId,
    actor: &str,
    action: AuditAction,
    rid: &str,
) -> hearth::audit::AuditEvent {
    engine
        .append(&CreateAuditEvent {
            realm_id: realm.clone(),
            actor: actor.to_string(),
            action,
            resource_type: "test".to_string(),
            resource_id: rid.to_string(),
            metadata: None,
        })
        .expect("append")
}

// ---------------------------------------------------------------------------
// Scenario 1: prune is itself recorded in the audit log
// ---------------------------------------------------------------------------

/// The web handler records an `AuditLogPruned` event *before* calling
/// `prune_before`.  This test verifies that:
/// (a) `AuditLogPruned` is a valid appendable action, and
/// (b) the prune event, appended at or after the cutoff timestamp, is NOT
///     deleted by the subsequent `prune_before(cutoff)` call.
#[test]
fn audit_log_pruned_event_survives_prune() {
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
    let (engine, _storage, _dir) = make_engine(Arc::clone(&clock) as Arc<dyn Clock>);
    let realm = RealmId::generate();

    // Append 3 events at t=1s, 2s, 3s (all before the cutoff).
    for i in 0..3u32 {
        append(
            &*engine,
            &realm,
            "admin",
            AuditAction::UserCreated,
            &format!("u{i}"),
        );
        clock.advance(1_000_000);
    }
    // clock is now at t=4s; set cutoff = 4s so all three events are prunable.
    let cutoff = clock.now();

    // Append the prune sentinel AT or AFTER the cutoff (simulates the handler).
    let sentinel = engine
        .append(&CreateAuditEvent {
            realm_id: realm.clone(),
            actor: "admin-user-id".to_string(),
            action: AuditAction::AuditLogPruned,
            resource_type: "audit_log".to_string(),
            resource_id: realm.as_uuid().to_string(),
            metadata: Some(serde_json::json!({
                "cutoff_micros": cutoff.as_micros(),
                "retention_days": 30_u32,
            })),
        })
        .expect("append prune sentinel");

    // Execute the prune.
    let deleted = engine.prune_before(&realm, cutoff).expect("prune");
    assert_eq!(deleted, 3, "three UserCreated events should be pruned");

    // The AuditLogPruned sentinel must survive.
    let remaining = engine
        .query(&AuditQuery {
            realm_id: realm.clone(),
            action: Some(AuditAction::AuditLogPruned),
            ..AuditQuery::for_realm(realm.clone())
        })
        .expect("query by action");
    assert_eq!(
        remaining.len(),
        1,
        "AuditLogPruned must survive the prune window"
    );
    assert_eq!(remaining[0].id, sentinel.id);

    let meta = remaining[0].metadata.as_ref().expect("metadata");
    assert!(meta.get("cutoff_micros").is_some(), "must carry cutoff");
    assert!(
        meta.get("retention_days").is_some(),
        "must carry retention_days"
    );
}

// ---------------------------------------------------------------------------
// Scenario 2: no orphaned index entries after prune
// ---------------------------------------------------------------------------

/// After calling `prune_before`, neither the actor nor the action index may
/// contain entries pointing at deleted primary events.
///
/// Previously, three individual `delete` calls could be interrupted by a crash
/// after the primary-key delete but before the index deletes, leaving orphaned
/// rows.  `write_batch` makes each event's three-key deletion atomic.
#[test]
fn prune_leaves_no_orphaned_index_entries() {
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
    let (engine, _storage, _dir) = make_engine(Arc::clone(&clock) as Arc<dyn Clock>);
    let realm = RealmId::generate();

    // Append 5 events with distinct actors and advance the clock each time.
    for i in 0..5u32 {
        engine
            .append(&CreateAuditEvent {
                realm_id: realm.clone(),
                actor: format!("actor_{i}"),
                action: AuditAction::UserCreated,
                resource_type: "user".to_string(),
                resource_id: format!("u{i}"),
                metadata: None,
            })
            .expect("append");
        clock.advance(1_000_000);
    }

    // Prune all 5 events (cutoff is well past all event timestamps).
    let cutoff = Timestamp::from_micros(10_000_000);
    let deleted = engine.prune_before(&realm, cutoff).expect("prune");
    assert_eq!(deleted, 5, "all 5 events should be pruned");

    // Primary scan must be empty.
    let remaining = engine
        .query(&AuditQuery::for_realm(realm.clone()))
        .expect("query all");
    assert!(
        remaining.is_empty(),
        "primary index must be empty after full prune"
    );

    // Actor-index scan must also be empty for every actor.
    for i in 0..5u32 {
        let by_actor = engine
            .query(&AuditQuery {
                realm_id: realm.clone(),
                actor: Some(format!("actor_{i}")),
                ..AuditQuery::for_realm(realm.clone())
            })
            .expect("query by actor");
        assert!(
            by_actor.is_empty(),
            "actor_{i}: actor index must not have orphaned entries after prune"
        );
    }

    // Action-index scan must also be empty.
    let by_action = engine
        .query(&AuditQuery {
            realm_id: realm.clone(),
            action: Some(AuditAction::UserCreated),
            ..AuditQuery::for_realm(realm.clone())
        })
        .expect("query by action");
    assert!(
        by_action.is_empty(),
        "action index must not have orphaned entries after prune"
    );
}

// ---------------------------------------------------------------------------
// Scenario 3: HMAC chain rejects SHA-256 forgery
// ---------------------------------------------------------------------------

/// With the old unkeyed SHA-256 chain a storage-layer attacker who knows the
/// hash function can delete event E2 and forge E3's hash using the remaining
/// chain.  With HMAC-SHA256 the same forgery fails `verify_integrity` because
/// the attacker does not have the per-realm HMAC key.
///
/// Attack simulation:
/// 1. Append E1, E2, E3.
/// 2. Tamper with E2's `actor` and recompute its stored hash using raw
///    SHA-256 (as an attacker without the HMAC key would do).
/// 3. Write the tampered event back to storage, bypassing the engine.
/// 4. `verify_integrity` must return `false`.
#[test]
fn verify_integrity_rejects_sha256_forgery() {
    use ring::digest;

    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
    let (engine, storage, _dir) = make_engine(Arc::clone(&clock) as Arc<dyn Clock>);
    let realm = RealmId::generate();

    // Append three chained events.
    let e1 = append(&*engine, &realm, "alice", AuditAction::UserCreated, "u1");
    clock.advance(1_000_000);
    let e2 = append(&*engine, &realm, "alice", AuditAction::SessionCreated, "s1");
    clock.advance(1_000_000);
    let _e3 = append(&*engine, &realm, "alice", AuditAction::TokenIssued, "t1");

    // Baseline: chain is valid before any tampering.
    assert!(
        engine
            .verify_integrity(&realm, None, None)
            .expect("baseline verify"),
        "chain should be valid before tampering"
    );

    // ---- Attacker's forgery ----
    // Build the storage key for e2 (same encoding used by keys::encode_event_key).
    let e2_key: Vec<u8> = format!(
        "audit:evt:{:019}:{}",
        e2.timestamp.as_micros(),
        e2.id.as_uuid()
    )
    .into_bytes();

    // Modify e2: change actor to "attacker".
    let mut tampered = e2.clone();
    tampered.actor = "attacker".to_string();

    // Compute what a SHA-256-only attacker would put as the hash.
    // (They know e1's hash and can rebuild the hashable JSON, but not HMAC key.)
    let forged_hashable = serde_json::json!({
        "id": tampered.id,
        "realm_id": tampered.realm_id,
        "actor": tampered.actor,        // "attacker"
        "action": tampered.action,
        "resource_type": tampered.resource_type,
        "resource_id": tampered.resource_id,
        "timestamp": tampered.timestamp,
        "metadata": tampered.metadata,
    });
    let prev_hash = &e1.integrity_hash;
    let data = format!("{prev_hash}{forged_hashable}");
    let sha_tag = digest::digest(&digest::SHA256, data.as_bytes());
    let forged_hash: String = sha_tag.as_ref().iter().fold(String::new(), |mut acc, b| {
        use std::fmt::Write as _;
        let _ = write!(acc, "{b:02x}");
        acc
    });
    tampered.integrity_hash = forged_hash;

    // Write the tampered bytes directly to storage, bypassing the engine.
    // Must use encode_for_test so the bytes are in the correct postcard format
    // that decode_event expects (not JSON).
    let forged_bytes =
        EmbeddedAuditEngine::encode_for_test(&tampered).expect("encode tampered event");
    storage
        .put(&realm, &e2_key, &forged_bytes)
        .expect("put forged event");

    // The HMAC chain must detect the forgery.
    let valid = engine
        .verify_integrity(&realm, None, None)
        .expect("verify after tampering");
    assert!(
        !valid,
        "verify_integrity must detect SHA-256 forgery — HMAC tag will not match"
    );
}

// ---------------------------------------------------------------------------
// Scenario 4: byte-corrupted (non-decodable) record alarms, not Errs
// ---------------------------------------------------------------------------

/// A byte-corrupted audit record (one that fails postcard decoding entirely)
/// must be treated as a tamper signal: `verify_integrity` must return
/// `Ok(false)` and increment `audit_integrity_failures_total`.
///
/// Before HEA-1903 the `?` on `decode_event` propagated
/// `Err(Serialization)` to the caller instead of returning the alarm signal,
/// so dashboards keyed off `Ok(false)` / the metric would see nothing.
#[test]
fn verify_integrity_alarms_on_undecodable_record() {
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
    let (engine, storage, _dir) = make_engine(Arc::clone(&clock) as Arc<dyn Clock>);
    let realm = RealmId::generate();

    // Baseline delta counter before anything touches this global.
    let failures_before = hearth::metrics::metrics()
        .audit_integrity_failures_total
        .get();

    // Append one valid event so there is something in the chain to corrupt.
    append(&*engine, &realm, "alice", AuditAction::UserCreated, "u1");

    // Scan raw storage to locate the event key.
    let entries = storage
        .scan(&realm, b"audit:evt:", b"audit:evt;")
        .expect("scan audit event keys");
    assert!(!entries.is_empty(), "must have at least one event");

    // Overwrite the event bytes with garbage that will not deserialise.
    let garbage: Vec<u8> = vec![0xFF, 0xFE, 0x00, 0x01, 0x02, 0x03];
    storage
        .put(&realm, &entries[0].key, &garbage)
        .expect("write corrupted bytes");

    // verify_integrity must return Ok(false), not Err.
    let result = engine.verify_integrity(&realm, None, None);
    assert!(
        result.is_ok(),
        "verify_integrity must not propagate a decode error — got: {result:?}"
    );
    assert!(
        !result.expect("verify_integrity returned Err on undecodable record"),
        "verify_integrity must return false for an undecodable record"
    );

    // The integrity-failure counter must have been incremented.
    let failures_after = hearth::metrics::metrics()
        .audit_integrity_failures_total
        .get();
    assert!(
        failures_after > failures_before,
        "audit_integrity_failures_total must increment on undecodable record \
         (before={failures_before}, after={failures_after})"
    );
}
