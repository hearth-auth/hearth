//! SST compaction crash-recovery simulation tests.
//!
//! Oracle invariant: after crash during compaction (between rename and
//! old-file deletion), the engine recovers correctly with both old and
//! new SSTs on disk. Newer SST entries take priority.

use std::sync::Arc;

use hearth::core::RealmId;
use hearth::storage::{CompactionConfig, EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Crash after rename, before old-file deletion: both old and new SSTs
/// coexist on disk. Recovery must produce correct state — the newer
/// compacted SST takes priority for duplicate keys.
#[test]
fn simulation_compaction_leaked_files_after_crash() {
    let dir = tempfile::tempdir().expect("tempdir");
    let realm = RealmId::generate();

    // Phase 1: write data, generate >=2 SSTs, compact, then restore old
    // SSTs to simulate a crash between rename and old-file deletion.
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
            max_sst_count: 0,
            merge_min: 4,
        };
        // Allow key auto-generation in tests; HEARTH_MASTER_KEY is not set in CI.
        // This test exercises compaction + crash recovery, not master-key handling.
        config.dev_mode = true;
        let engine = EmbeddedStorageEngine::open(config).expect("open");

        for i in 0u32..30 {
            engine
                .put(
                    &realm,
                    format!("cr-{i:04}").as_bytes(),
                    format!("va-{i:04}").as_bytes(),
                )
                .expect("put");
        }

        // Verify we have >=2 SSTs before compaction
        let sst_count = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "sst"))
            .count();
        assert!(sst_count >= 2, "expected >=2 SSTs, got {sst_count}");

        // Save copies of SSTs before compaction deletes them
        let tmp_save = tempfile::tempdir().expect("tempdir for sst backups");
        for entry in std::fs::read_dir(dir.path()).expect("read_dir").flatten() {
            if entry.path().extension().is_some_and(|ext| ext == "sst") {
                let save_path = tmp_save.path().join(entry.file_name());
                std::fs::copy(entry.path(), &save_path).expect("copy sst backup");
            }
        }

        // Run compaction — this creates a merged SST and deletes old ones
        let compacted = engine.compact_ssts(2).expect("compact");
        assert!(compacted > 0, "compaction should have merged SSTs");

        // Simulate crash-after-rename: restore old SSTs alongside the new one
        for entry in std::fs::read_dir(tmp_save.path())
            .expect("read_dir")
            .flatten()
        {
            let restore_path = dir.path().join(entry.file_name());
            std::fs::copy(entry.path(), &restore_path).expect("restore old sst");
        }
    }

    // Phase 2: reopen with both old and new SSTs on disk
    {
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let engine = EmbeddedStorageEngine::open(config).expect("reopen after leaked files");

        // All keys must be readable — newer compacted SST wins for duplicates
        for i in 0u32..30 {
            let key = format!("cr-{i:04}");
            assert_eq!(
                engine.get(&realm, key.as_bytes()).expect("get"),
                Some(format!("va-{i:04}").into_bytes()),
                "key {key} must survive compaction crash with leaked SST files"
            );
        }
    }
}

/// C-4 resurrection: crash between partial-compaction rename and unlink.
///
/// When a partial compaction drops tombstones (`drop_tombstones = true`,
/// triggered when the run includes the oldest SST), it atomically renames the
/// merged output over the tombstone-bearing SST (the run's newest member, i.e.
/// `target_num`), then unlinks the older value-bearing members.  A crash
/// **between the rename and the first unlink** leaves both files on disk:
///
/// - `{target_num}.sst` — merged output (tombstone was dropped, key absent)
/// - `{older_num}.sst`  — original value-bearing SST (key present)
///
/// On recovery the engine loads both files. The merged SST is newer but has
/// no entry for the deleted key, so the lookup falls through to the orphan and
/// the deleted key reappears — a resurrection.
///
/// **This test FAILS at `af4edb59` (before W1-4 / HEA-1857 compaction
/// manifest lands).** A passing run means the fix is in place.
///
/// The `FaultFs` rename hook used here performs the actual OS rename on disk
/// (committing the filesystem change) then returns an error, recreating the
/// exact disk state a kill -9 between rename and unlink would leave.  The WAL
/// is removed before the second open to reproduce the case where the WAL had
/// already rotated before the crash, leaving only the SST layer authoritative.
#[test]
fn simulation_c4_partial_compaction_crash_resurrects_deleted_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let realm = RealmId::generate();

    // Phase 1: build two same-size SSTs and run partial compaction with a
    // rename fault that commits the rename on disk then returns an error.
    {
        let fault = Arc::new(crate::FaultFs::new());
        let mut config = StorageConfig::dev(dir.path().to_path_buf());
        // 1-byte flush threshold: every put/delete immediately flushes the
        // memtable to a new SST, giving us one entry per SST file.
        config.set_memtable_flush_bytes(1);
        // Disable background compaction; use merge_min=2 so two same-size SSTs
        // immediately form a compactable run.
        config.compaction = CompactionConfig {
            enabled: false,
            interval_secs: 0,
            min_sst_count: 2,
            max_sst_count: 0,
            merge_min: 2,
        };
        let engine = EmbeddedStorageEngine::open_with_fs(
            config,
            Arc::<crate::FaultFs>::clone(&fault) as Arc<dyn hearth::storage::fs::Fs>,
        )
        .expect("open engine");

        // SST0 (oldest): doomed="secret" — flush is automatic because the
        // 1-byte threshold is exceeded after the put.
        engine.put(&realm, b"doomed", b"secret").expect("put");

        // SST1 (newest): tombstone for doomed — automatic flush again.
        engine.delete(&realm, b"doomed").expect("delete");

        assert_eq!(
            engine.get(&realm, b"doomed").expect("pre-compact get"),
            None,
            "key must be deleted before compaction"
        );

        // compact_partial selects [SST1, SST0] as a same-size run reaching the
        // oldest SST => drop_tombstones=true.  It will:
        //   1. write merged output to SST1.partial.tmp (no entry for doomed)
        //   2. rename(SST1.partial.tmp → SST1)  ← our hook: rename commits on
        //      disk, then returns Err (post-rename crash simulation)
        //   3. remove_file(SST0) — never reached because step 2 returned Err
        //
        // Disk state after the injected "crash":
        //   SST1 = merged output (tombstone dropped, doomed absent)
        //   SST0 = value-bearing (doomed="secret", still present)
        fault.config.arm_rename_failure();
        let result = engine.compact_partial();
        assert!(
            result.is_err(),
            "compact_partial must propagate the injected rename error"
        );

        // Engine is dropped here — simulating process death after the rename.
    }

    // Remove the WAL so reopen starts with an empty memtable. In production
    // this corresponds to the WAL having rotated before the crash, leaving
    // only the SST layer as the authoritative source of truth.
    let wal_path = dir.path().join("hearth.wal");
    std::fs::remove_file(&wal_path).expect("remove WAL to simulate post-rotation crash");

    // Phase 2: reopen on real Fs; WAL is absent so the memtable starts empty
    // and every read resolves entirely through the SST layer.
    {
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let engine = EmbeddedStorageEngine::open(config).expect("reopen after crash");

        // BUG at af4edb59 (C-4): the merged SST1 has no entry for "doomed"
        // (tombstone was dropped), so the lookup falls through to the orphaned
        // SST0 and returns the deleted value "secret" — a resurrection.
        // After W1-4 / HEA-1857 this must return None.
        assert_eq!(
            engine.get(&realm, b"doomed").expect("get after crash"),
            None,
            "deleted key must not resurface after crash between rename and unlink (C-4)"
        );
    }
}
