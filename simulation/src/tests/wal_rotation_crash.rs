//! Crash recovery invariant: memtable is flushed to SST before WAL rotation.
//!
//! Regression test for HEA-1050: WAL rotation without a prior flush left
//! entries that existed only in the memtable unrecoverable after a crash.

use hearth::core::RealmId;
use hearth::storage::wal::{SyncMode, WalConfig};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Verifies that data written before a WAL rotation survives a simulated crash.
///
/// With the fix, `append_with_pre_rotate` flushes the memtable to an SST
/// before truncating the WAL file. Without it, entries in the memtable at
/// rotation time vanish after a crash because they are not in any WAL or SST.
#[test]
fn simulation_memtable_flushed_before_wal_rotation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let realm = RealmId::generate();

    // Phase 1: write entries that span a WAL rotation, then "crash" (drop).
    {
        let mut config = StorageConfig::dev(dir.path().to_path_buf());
        // Force rotation after ~4-5 entries (each entry is ~80 B on-disk).
        config.wal_config = WalConfig {
            max_size: 500,
            sync_mode: SyncMode::None,
        };
        // The default memtable threshold (4 MiB) is far above what the test
        // writes, so only the pre-rotation flush (not should_flush) saves
        // the data written before the first rotation.
        let engine = EmbeddedStorageEngine::open(config).expect("open");

        for i in 0u32..10 {
            let key = format!("rot-key-{i:04}");
            let val = format!("rot-val-{i:04}");
            engine
                .put(&realm, key.as_bytes(), val.as_bytes())
                .expect("put");
        }
        // Drop without explicit flush — simulates process kill after rotation.
    }

    // Phase 2: reopen and verify ALL 10 entries are readable.
    {
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let engine = EmbeddedStorageEngine::open(config).expect("reopen");

        for i in 0u32..10 {
            let key = format!("rot-key-{i:04}");
            let expected = format!("rot-val-{i:04}");
            assert_eq!(
                engine.get(&realm, key.as_bytes()).expect("get"),
                Some(expected.into_bytes()),
                "key {key} lost after WAL rotation — HEA-1050 regression"
            );
        }
    }
}
