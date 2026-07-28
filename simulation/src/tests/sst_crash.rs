//! SST crash-recovery simulation tests.
//!
//! Oracle invariant: after crash during flush or compaction, recovery
//! from WAL + valid SSTs produces correct state. Corrupt SSTs are
//! detected and skipped.

use std::io::Write;

use hearth::core::RealmId;
use hearth::storage::error::StorageError;
use hearth::storage::{CompactionConfig, EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Base (12) + encryption (76) header bytes at the front of every SST file.
/// Bytes at and beyond this offset are DEK-encrypted ciphertext. Mirrors
/// `sst::TOTAL_HEADER_SIZE`, which is `pub(crate)` and unreachable here.
const SST_TOTAL_HEADER_SIZE: usize = 88;

/// Crash during memtable flush: an SST whose KEK is not in the registry is
/// skipped under `allow_missing_keks` and WAL replay recovers all committed
/// data.
///
/// NOTE: the injected SST carries a garbage `kek_id`, so it is dropped via the
/// *missing-KEK* branch of `open()` — this test does NOT exercise ciphertext
/// corruption detection. See `simulation_crash_kek_present_body_corruption_fails`
/// for the KEK-valid body-corruption path that asserts `open()` → `Err`.
#[test]
fn simulation_crash_during_memtable_flush() {
    let seed = 45u64;

    let dir = tempfile::tempdir().expect("tempdir");
    let realm = RealmId::generate();

    // Write data through the engine (WAL is the durable copy)
    {
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let engine = EmbeddedStorageEngine::open(config).expect("open");
        engine.put(&realm, b"flush-key-1", b"val-1").expect("put");
        engine.put(&realm, b"flush-key-2", b"val-2").expect("put");
    }

    // Inject a corrupt SST file (new encrypted format: 88-byte header)
    {
        let corrupt_sst_path = dir.path().join("000001.sst");
        let mut file = std::fs::File::create(&corrupt_sst_path).expect("create corrupt sst");
        // Write a minimum-valid-sized file with garbage data.
        // Base header: magic + entry_count + crc (12 bytes)
        file.write_all(b"HSST").expect("magic");
        file.write_all(&2u32.to_le_bytes()).expect("count");
        file.write_all(&[0xAA; 4]).expect("crc");
        // Encryption header: 76 bytes of garbage
        file.write_all(&[0xDE; 76]).expect("enc header");
        // Corrupt data: not valid ciphertext
        file.write_all(&[0xAD; 16]).expect("bad data");
        file.sync_all().expect("sync");
    }

    // Re-open: engine should skip corrupt SST and recover from WAL
    {
        let mut config = StorageConfig::dev(dir.path().to_path_buf());
        config.allow_missing_keks = true;
        let engine = EmbeddedStorageEngine::open(config).expect("recovery");

        assert_eq!(
            engine.get(&realm, b"flush-key-1").expect("get"),
            Some(b"val-1".to_vec()),
            "data must survive crash during flush via WAL replay (seed={seed})"
        );
        assert_eq!(
            engine.get(&realm, b"flush-key-2").expect("get"),
            Some(b"val-2".to_vec()),
            "data must survive crash during flush via WAL replay (seed={seed})"
        );
    }
}

/// Crash during compaction: source SSTs remain intact when the
/// output SST has an unknown KEK.
///
/// As with `simulation_crash_during_memtable_flush`, the injected output SST
/// has a garbage `kek_id` and is dropped via the *missing-KEK* branch, not by
/// ciphertext-corruption detection.
#[test]
fn simulation_crash_during_compaction() {
    let seed = 46u64;

    let dir = tempfile::tempdir().expect("tempdir");
    let realm = RealmId::generate();

    // Write data in two phases
    {
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let engine = EmbeddedStorageEngine::open(config).expect("open");
        engine.put(&realm, b"key-a", b"val-a").expect("put");
        engine.put(&realm, b"key-b", b"val-b").expect("put");
    }

    {
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let engine = EmbeddedStorageEngine::open(config).expect("reopen");
        engine.put(&realm, b"key-c", b"val-c").expect("put");
        engine.put(&realm, b"key-d", b"val-d").expect("put");
    }

    // Simulate crash during compaction: create a corrupt output SST
    {
        let compacted_path = dir.path().join("999999.sst");
        let mut file = std::fs::File::create(&compacted_path).expect("create");
        // Write a minimum-valid-sized file with garbage data.
        // Base header: magic + entry_count + crc (12 bytes)
        file.write_all(b"HSST").expect("magic");
        file.write_all(&4u32.to_le_bytes()).expect("count");
        file.write_all(&[0xAA; 4]).expect("crc");
        // Encryption header: 76 bytes of garbage
        file.write_all(&[0xDE; 76]).expect("enc header");
        // Corrupt data: not valid ciphertext
        file.write_all(&[0xAD; 16]).expect("bad data");
        file.sync_all().expect("sync");
    }

    // Re-open: engine should skip corrupt SST and recover from WAL
    {
        let mut config = StorageConfig::dev(dir.path().to_path_buf());
        config.allow_missing_keks = true;
        let engine = EmbeddedStorageEngine::open(config).expect("recovery");
        assert_eq!(
            engine.get(&realm, b"key-a").expect("get"),
            Some(b"val-a".to_vec()),
            "data must survive crash during compaction (seed={seed})"
        );
        assert_eq!(
            engine.get(&realm, b"key-b").expect("get"),
            Some(b"val-b".to_vec()),
        );
        assert_eq!(
            engine.get(&realm, b"key-c").expect("get"),
            Some(b"val-c".to_vec()),
        );
        assert_eq!(
            engine.get(&realm, b"key-d").expect("get"),
            Some(b"val-d".to_vec()),
        );
    }
}

/// Power-loss simulation: WAL replay + SST recovery produces correct
/// state after simulated power loss that corrupts the WAL tail.
#[test]
fn simulation_power_loss() {
    let seed = 47u64;

    let dir = tempfile::tempdir().expect("tempdir");
    let realm = RealmId::generate();

    // Phase 1: Write data
    {
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let engine = EmbeddedStorageEngine::open(config).expect("open");

        for i in 0u32..10 {
            let key = format!("power-{i:04}");
            let val = format!("val-{i:04}");
            engine
                .put(&realm, key.as_bytes(), val.as_bytes())
                .expect("put");
        }
    }

    // Phase 2: Simulate power loss — corrupt the WAL tail
    {
        let wal_path = dir.path().join("hearth.wal");
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&wal_path)
            .expect("open wal for corruption");
        file.write_all(b"POWER_LOSS_GARBAGE_PARTIAL_RECORD")
            .expect("corrupt wal tail");
        file.sync_all().expect("sync");
    }

    // Phase 3: Recovery. Make the torn-tail *discard* load-bearing (it was
    // previously only implied by survival): after replay the recovered view must
    // be EXACTLY the 10 committed keys — no more (the garbage tail must not be
    // decoded into a phantom key) and no fewer.
    {
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let engine = EmbeddedStorageEngine::open(config).expect("recovery after power loss");

        for i in 0u32..10 {
            let key = format!("power-{i:04}");
            let expected = format!("val-{i:04}");
            let actual = engine.get(&realm, key.as_bytes()).expect("get");
            assert_eq!(
                actual,
                Some(expected.into_bytes()),
                "key {key} must survive power-loss recovery (seed={seed})"
            );
        }

        // The garbage tail must not have been decoded as a committed record: a
        // scan of the whole realm returns exactly the 10 keys, nothing more.
        let recovered = engine
            .scan(&realm, b"", &[0xFFu8; 8])
            .expect("scan after recovery");
        assert_eq!(
            recovered.len(),
            10,
            "torn tail must be discarded, not decoded into phantom keys: got {} entries (seed={seed})",
            recovered.len()
        );
    }

    // Phase 4: the corruption-then-crash *double fault* (HEA-1853). Write new
    // data against the recovered engine and drop it. Recovery truncates the
    // corrupt tail, so this append lands at the end of the valid record region
    // rather than behind the garbage.
    {
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let engine = EmbeddedStorageEngine::open(config).expect("reopen after recovery");
        engine
            .put(&realm, b"post-recovery", b"must-survive")
            .expect("put after recovery");
    }

    // Phase 5: replay again. Before HEA-1853 the post-recovery key was silently
    // lost here — replay halted at the still-present garbage that preceded it.
    {
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let engine = EmbeddedStorageEngine::open(config).expect("second recovery");

        assert_eq!(
            engine
                .get(&realm, b"post-recovery")
                .expect("get post-recovery key"),
            Some(b"must-survive".to_vec()),
            "a write made after corrupt-tail recovery must survive the next \
             restart (seed={seed})"
        );

        // The original committed prefix must still be intact alongside it.
        for i in 0u32..10 {
            let key = format!("power-{i:04}");
            let expected = format!("val-{i:04}");
            assert_eq!(
                engine.get(&realm, key.as_bytes()).expect("get"),
                Some(expected.into_bytes()),
                "key {key} must survive the double fault (seed={seed})"
            );
        }

        let recovered = engine
            .scan(&realm, b"", &[0xFFu8; 8])
            .expect("scan after double fault");
        assert_eq!(
            recovered.len(),
            11,
            "expected the 10 committed keys plus the post-recovery key, got {} (seed={seed})",
            recovered.len()
        );
    }
}

/// KEK-present body corruption: an SST whose `kek_id` resolves to a registered
/// KEK but whose ciphertext body is corrupt must make `open()` fail hard when
/// `allow_missing_keks` is false — the engine must NOT silently drop it.
///
/// This closes the gap left by the two tests above, which route corrupt SSTs
/// through the missing-KEK skip path and therefore never reach ciphertext
/// verification. Here the header (`kek_id` + wrapped DEK) is left intact so KEK
/// lookup and DEK unwrap both succeed; only the encrypted body is flipped, so
/// the failure can come from nothing but corruption detection.
#[test]
fn simulation_crash_kek_present_body_corruption_fails() {
    let seed = 48u64;

    let dir = tempfile::tempdir().expect("tempdir");
    let realm = RealmId::generate();

    // Phase 1: write enough data through a real engine to flush at least one
    // SST. A small `memtable_flush_bytes` forces flushes; `dev_mode` lets the
    // key registry auto-generate a realm KEK (persisted to hearth.keys), so the
    // flushed SST's kek_id references a KEK that survives a reopen.
    {
        let mut config = StorageConfig::production(
            dir.path().to_path_buf(),
            64 * 1024 * 1024, // wal_max_size_bytes
            50,               // memtable_flush_bytes: small → forces flushes
            100,              // hot_tier_capacity
        );
        config.compaction = CompactionConfig {
            enabled: false,
            interval_secs: 0,
            min_sst_count: 2,
        };
        config.dev_mode = true;
        let engine = EmbeddedStorageEngine::open(config).expect("open");
        for i in 0u32..30 {
            engine
                .put(
                    &realm,
                    format!("bc-{i:04}").as_bytes(),
                    format!("va-{i:04}").as_bytes(),
                )
                .expect("put");
        }
    }

    // Confirm the engine actually produced SST files (the KEK for `realm` is
    // registered in hearth.keys), then corrupt only the ciphertext body of each
    // — flipping the final byte lands inside the AES-GCM tag/ciphertext region,
    // leaving the 88-byte header (kek_id + wrapped DEK) untouched.
    let ssts: Vec<std::path::PathBuf> = std::fs::read_dir(dir.path())
        .expect("read_dir")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "sst"))
        .collect();
    assert!(
        !ssts.is_empty(),
        "engine must have flushed at least one SST to disk (seed={seed})"
    );
    for path in &ssts {
        let mut bytes = std::fs::read(path).expect("read sst");
        assert!(
            bytes.len() > SST_TOTAL_HEADER_SIZE,
            "SST must have a ciphertext body past the header (seed={seed})"
        );
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF; // corrupt inside the encrypted body
        std::fs::write(path, &bytes).expect("write corrupted sst");
    }

    // Reopen with allow_missing_keks = false (the StorageConfig::dev default).
    // KEK lookup + DEK unwrap succeed on the intact header, so the corrupt body
    // must surface as an error rather than a silent skip.
    let config = StorageConfig::dev(dir.path().to_path_buf());
    assert!(
        !config.allow_missing_keks,
        "dev config must reject missing/unreadable SSTs for this assertion (seed={seed})"
    );
    let result = EmbeddedStorageEngine::open(config);
    match result {
        Err(StorageError::Crypto { .. }) => {}
        Err(other) => panic!(
            "expected StorageError::Crypto from corrupt SST body, got {other:?} (seed={seed})"
        ),
        Ok(_) => panic!(
            "engine silently accepted a KEK-present SST with a corrupt body — \
             corruption detection is not load-bearing (seed={seed})"
        ),
    }
}
