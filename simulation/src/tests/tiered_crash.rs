//! Tiered storage crash-recovery simulation tests.
//!
//! Oracle invariant: tier transitions preserve all data. The hot tier
//! is purely in-memory, so crashes lose hot-tier state. Recovery must
//! re-populate from WAL + SST on first access.

use std::sync::Arc;

use hearth::core::RealmId;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Tier transitions preserve all data under concurrent read/write load.
#[test]
fn simulation_tier_transitions_concurrent() {
    let seed = 48u64;

    let dir = tempfile::tempdir().expect("tempdir");
    let realm = RealmId::generate();

    let config = StorageConfig::dev(dir.path().to_path_buf());
    let engine = Arc::new(EmbeddedStorageEngine::open(config).expect("open"));

    // Pre-populate 50 entries
    for i in 0u32..50 {
        let key = format!("conc-{i:04}");
        engine.put(&realm, key.as_bytes(), b"initial").expect("put");
    }

    // Concurrent operations from multiple threads
    let mut handles = Vec::new();

    // Reader threads
    for _ in 0..4 {
        let engine = Arc::clone(&engine);
        let t = realm.clone();
        handles.push(std::thread::spawn(move || {
            for i in 0u32..50 {
                let key = format!("conc-{i:04}");
                let val = engine.get(&t, key.as_bytes()).expect("get");
                if let Some(v) = val {
                    assert!(
                        v == b"initial" || v == b"updated",
                        "unexpected value for key {key}"
                    );
                }
            }
        }));
    }

    // Writer threads
    for batch in 0u32..4 {
        let engine = Arc::clone(&engine);
        let t = realm.clone();
        handles.push(std::thread::spawn(move || {
            for i in 0u32..10 {
                let key = format!("conc-{:04}", batch * 10 + i);
                engine.put(&t, key.as_bytes(), b"updated").expect("put");
            }
        }));
    }

    for handle in handles {
        handle.join().expect("thread panicked");
    }

    // Post-join accessibility check on the LIVE engine. With all threads
    // joined, the values are deterministic: writer batch b overwrote keys
    // b*10+i (i in 0..10) to "updated", so keys 0..40 read "updated" and keys
    // 40..50 keep "initial". This includes the volatile hot tier: a reader's
    // in-flight fill that overlaps a writer's put+invalidate is discarded by
    // the fill guard (audit 2026-08-28 §4.21#3), so the cache can never hold
    // the pre-write value once the writer has returned.
    for i in 0u32..50 {
        let key = format!("conc-{i:04}");
        let expected: &[u8] = if i < 40 { b"updated" } else { b"initial" };
        assert_eq!(
            engine.get(&realm, key.as_bytes()).expect("get").as_deref(),
            Some(expected),
            "key {key} must read its committed value on the live engine, \
             including through the hot tier (seed={seed})"
        );
    }

    // This is a `*_crash` file: its oracle is that tier transitions survive a
    // crash. Drop the engine (discarding the in-memory hot tier — the last Arc
    // ref, since all worker threads have joined) and reopen from disk. With a
    // cold cache, reads come straight from WAL + SST, so the committed values are
    // now deterministic: the writer threads overwrote keys 0..40 to "updated"
    // (batch b writes b*10+i for i in 0..10); keys 40..50 keep "initial".
    drop(engine);
    let reopened = EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf()))
        .expect("reopen after crash");
    let expected = |i: u32| -> &'static [u8] {
        if i < 40 {
            b"updated"
        } else {
            b"initial"
        }
    };
    for i in 0u32..50 {
        let key = format!("conc-{i:04}");
        assert_eq!(
            reopened
                .get(&realm, key.as_bytes())
                .expect("get")
                .as_deref(),
            Some(expected(i)),
            "key {key} must survive crash + recovery from WAL+SST with its \
             committed value (seed={seed})"
        );
    }
}

/// Crash during promotion: hot tier is in-memory, so a crash means
/// an empty tier on restart.
#[test]
fn simulation_crash_during_promotion() {
    let seed = 49u64;

    let dir = tempfile::tempdir().expect("tempdir");
    let realm = RealmId::generate();

    // Phase 1: Write data and access it
    {
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let engine = EmbeddedStorageEngine::open(config).expect("open");

        for i in 0u32..10 {
            let key = format!("hot-{i:04}");
            engine
                .put(&realm, key.as_bytes(), b"hot-value")
                .expect("put");
        }

        // Read to promote into hot tier
        for i in 0u32..10 {
            let key = format!("hot-{i:04}");
            let val = engine.get(&realm, key.as_bytes()).expect("get");
            assert_eq!(val, Some(b"hot-value".to_vec()));
        }
    }

    // Phase 2: Re-open — hot tier is empty
    {
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let engine = EmbeddedStorageEngine::open(config).expect("recovery");

        for i in 0u32..10 {
            let key = format!("hot-{i:04}");
            let val = engine.get(&realm, key.as_bytes()).expect("get");
            assert_eq!(
                val,
                Some(b"hot-value".to_vec()),
                "key {key} must be recoverable from WAL+SST after crash (seed={seed})"
            );
        }
    }
}
