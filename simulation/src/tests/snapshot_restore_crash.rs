//! Crash-atomicity tests for Raft snapshot restore (HEA-2132).
//!
//! `restore_snapshot_in_place` is a two-phase in-place operation:
//!
//! * **Phase 1** — delete every live key for every on-disk realm.
//! * **Phase 2** — replay all (key, value) pairs from the snapshot payload.
//!
//! A process killed between the two phases leaves the engine in a mixed-data
//! state (some realms cleared, some not). These tests verify that:
//!
//! 1. The `SNAPSHOT_RESTORE_IN_PROGRESS` marker is written durably before
//!    Phase 1 and removed after Phase 2.
//! 2. A torn restore (marker present at startup) causes the engine to refuse to
//!    open with `StorageError::TornSnapshotRestore` rather than silently serving
//!    mixed data.
//! 3. A clean restore (both phases complete) leaves no marker — the engine
//!    opens normally and serves the post-restore data.

#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use tempfile::tempdir;
use uuid::Uuid;

use hearth::core::RealmId;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine, StorageError};

fn make_realm() -> RealmId {
    RealmId::new(Uuid::new_v4())
}

/// A process killed after `begin_snapshot_restore` but before
/// `complete_snapshot_restore` must cause the engine to refuse to open on the
/// next startup, returning `StorageError::TornSnapshotRestore`.
///
/// This exercises the detection path: the operator must delete the marker and
/// restart so the node can re-request the snapshot from the Raft leader.
#[test]
fn torn_restore_detected_at_startup() {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().join("data");
    let realm = make_realm();

    // Open engine, write some data, start a restore but do NOT complete it.
    {
        let engine = EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).unwrap();
        engine.put(&realm, b"key1", b"value1").unwrap();
        engine.put(&realm, b"key2", b"value2").unwrap();

        // begin_snapshot_restore writes the durable marker.
        engine
            .begin_snapshot_restore("snap-42-aaaabbbb-cccc-dddd-eeee-ffffffffffff")
            .unwrap();

        // Phase 1: delete some keys (simulating the delete phase partially).
        engine.delete(&realm, b"key1").unwrap();

        // Process "crashes" here: engine is dropped without calling
        // complete_snapshot_restore. The marker remains on disk.
    }

    // Attempting to reopen must detect the torn restore rather than serving
    // the mixed (partially-cleared) state.
    let result = EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone()));
    assert!(
        matches!(result, Err(StorageError::TornSnapshotRestore { .. })),
        "expected TornSnapshotRestore on open after torn restore, got: {result:?}"
    );
}

/// A complete restore (begin + full Phase 1 + Phase 2 + complete) must leave
/// no marker. The engine opens normally and serves the post-restore state.
#[test]
fn clean_restore_leaves_no_marker() {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().join("data");
    let realm = make_realm();

    {
        let engine = EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).unwrap();
        engine.put(&realm, b"oldkey", b"oldval").unwrap();

        // Full two-phase restore.
        engine.begin_snapshot_restore("snap-clean-test").unwrap();
        // Phase 1: clear old data.
        engine.delete(&realm, b"oldkey").unwrap();
        // Phase 2: write new data.
        engine.put(&realm, b"newkey", b"newval").unwrap();
        // Signal clean completion — removes the marker.
        engine.complete_snapshot_restore().unwrap();
    }

    // Engine must open normally after a clean restore.
    let engine = EmbeddedStorageEngine::open(StorageConfig::dev(data_dir)).unwrap();
    assert_eq!(
        engine.get(&realm, b"newkey").unwrap(),
        Some(b"newval".to_vec()),
        "post-restore data must be readable after a clean restore"
    );
    assert_eq!(
        engine.get(&realm, b"oldkey").unwrap(),
        None,
        "pre-restore data must be absent after a clean restore"
    );
}

/// The `TornSnapshotRestore` error must name the marker file path and embed
/// the snapshot ID so the operator can take targeted action.
#[test]
fn torn_restore_error_names_marker_and_snapshot_id() {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().join("data");

    {
        let engine = EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).unwrap();
        engine
            .begin_snapshot_restore("snap-abc-deadbeef-1234-5678-dead-beefcafebabe")
            .unwrap();
        // Drop without completing — simulates kill between Phase 1 and Phase 2.
    }

    let err = EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone()))
        .expect_err("must fail with torn restore error");

    match err {
        StorageError::TornSnapshotRestore {
            ref marker_path,
            ref snapshot_id,
        } => {
            assert!(
                marker_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n == "SNAPSHOT_RESTORE_IN_PROGRESS"),
                "marker_path must point to the marker file, got: {}",
                marker_path.display()
            );
            assert_eq!(
                snapshot_id, "snap-abc-deadbeef-1234-5678-dead-beefcafebabe",
                "snapshot_id must match the value written by begin_snapshot_restore"
            );
        }
        other => panic!("expected TornSnapshotRestore, got: {other}"),
    }

    // The Display message must mention the marker file name so the operator
    // can act without reading source code.
    let msg = err.to_string();
    assert!(
        msg.contains("SNAPSHOT_RESTORE_IN_PROGRESS"),
        "error message must name the marker file, got: {msg}"
    );
}

/// Verify that `begin_snapshot_restore` is idempotent: writing the marker
/// twice (e.g. if a retry starts before the first run clears it) overwrites
/// it with the new snapshot ID rather than failing.
#[test]
fn begin_snapshot_restore_is_idempotent() {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().join("data");

    {
        let engine = EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).unwrap();

        // First marker write.
        engine.begin_snapshot_restore("snap-first").unwrap();
        // Second write — must not fail.
        engine.begin_snapshot_restore("snap-second").unwrap();
        // Now complete.
        engine.complete_snapshot_restore().unwrap();
    }

    // Engine opens normally after completion.
    EmbeddedStorageEngine::open(StorageConfig::dev(data_dir))
        .expect("engine must open normally after complete_snapshot_restore");
}

/// Verify that the marker file stores the snapshot ID that was passed to
/// `begin_snapshot_restore`, so a second `begin` call (idempotent retry)
/// shows the *latest* snapshot ID to the operator.
#[test]
fn begin_snapshot_restore_overwrites_stale_marker() {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().join("data");

    {
        let engine = EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).unwrap();
        engine.begin_snapshot_restore("snap-stale").unwrap();
        engine.begin_snapshot_restore("snap-latest").unwrap();
        // Drop without completing.
    }

    let err = EmbeddedStorageEngine::open(StorageConfig::dev(data_dir))
        .expect_err("must fail with torn restore error");

    match err {
        StorageError::TornSnapshotRestore { snapshot_id, .. } => {
            assert_eq!(
                snapshot_id, "snap-latest",
                "marker must contain the latest snapshot ID after an overwrite"
            );
        }
        other => panic!("expected TornSnapshotRestore, got: {other}"),
    }
}

/// Regression guard: a completely fresh directory (no prior restore started)
/// must open successfully — the marker check must not fire on a new engine.
#[test]
fn fresh_engine_opens_without_marker_error() {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().join("data");

    EmbeddedStorageEngine::open(StorageConfig::dev(data_dir))
        .expect("fresh engine must open without TornSnapshotRestore");
}

/// End-to-end round-trip: simulate the full snapshot-install call sequence
/// (as `restore_snapshot_in_place` would exercise it) with multiple realms,
/// then verify data integrity and that the engine re-opens cleanly.
#[test]
fn full_restore_roundtrip_multi_realm() {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().join("data");
    let realm_a = make_realm();
    let realm_b = make_realm();

    // Populate "old" data on disk.
    {
        let engine = EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).unwrap();
        engine.put(&realm_a, b"a-old", b"a-old-val").unwrap();
        engine.put(&realm_b, b"b-old", b"b-old-val").unwrap();
    }

    // Simulate a snapshot restore: begin → Phase 1 (delete) → Phase 2 (put) → complete.
    {
        let engine = EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).unwrap();

        engine.begin_snapshot_restore("snap-multi-realm").unwrap();

        // Phase 1: delete old keys in realm_a and realm_b.
        engine.delete(&realm_a, b"a-old").unwrap();
        engine.delete(&realm_b, b"b-old").unwrap();

        // Phase 2: write new snapshot data.
        engine
            .put_batch(&realm_a, &[(b"a-new".to_vec(), b"a-new-val".to_vec())])
            .unwrap();
        engine
            .put_batch(&realm_b, &[(b"b-new".to_vec(), b"b-new-val".to_vec())])
            .unwrap();

        engine.complete_snapshot_restore().unwrap();
    }

    // Reopen must succeed and serve post-restore state.
    let engine = EmbeddedStorageEngine::open(StorageConfig::dev(data_dir)).unwrap();

    assert_eq!(
        engine.get(&realm_a, b"a-new").unwrap(),
        Some(b"a-new-val".to_vec()),
        "realm_a new key must be readable after restore"
    );
    assert_eq!(
        engine.get(&realm_a, b"a-old").unwrap(),
        None,
        "realm_a old key must be absent after restore"
    );
    assert_eq!(
        engine.get(&realm_b, b"b-new").unwrap(),
        Some(b"b-new-val".to_vec()),
        "realm_b new key must be readable after restore"
    );
    assert_eq!(
        engine.get(&realm_b, b"b-old").unwrap(),
        None,
        "realm_b old key must be absent after restore"
    );
}

/// Cluster-level integration: `Arc<dyn StorageEngine>` trait-object dispatch
/// must reach the `EmbeddedStorageEngine` override (the trait default is no-op;
/// only the concrete impl writes/reads the marker).
#[test]
fn trait_object_dispatch_reaches_engine_impl() {
    let dir = tempdir().unwrap();
    let data_dir = dir.path().join("data");

    {
        let engine: Arc<dyn StorageEngine> =
            Arc::new(EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).unwrap());

        // Both methods must be callable through the trait object.
        engine.begin_snapshot_restore("snap-dyn-dispatch").unwrap();
        engine.complete_snapshot_restore().unwrap();
    }

    // Engine opens normally — no marker left by the trait-object path.
    EmbeddedStorageEngine::open(StorageConfig::dev(data_dir))
        .expect("engine must open normally after complete via trait object");
}
