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

        // A rotation must actually have occurred, otherwise all 10 entries would
        // still live in the single WAL and survive trivially — the flush-before-
        // rotate path this test guards would never be exercised. The pre-rotation
        // flush writes an SST, so at least one SST on disk is the proof that
        // rotation (and its flush) happened.
        let sst_count = std::fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(std::result::Result::ok)
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "sst"))
            .count();
        assert!(
            sst_count >= 1,
            "WAL rotation must have triggered a memtable flush to SST (found {sst_count} SSTs)"
        );
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

/// B4 (audit 2026-08-28 §3 B4, §4.11#1): a WAL rotation must not destroy a
/// write another thread has already been told is durable.
///
/// The interleaving needs no fault injection and no crash timing skill:
///
/// 1. Writer A appends its record and the WAL `fsync`s it. A is now entitled
///    to be told the write is durable.
/// 2. Before A applies its value to the memtable, writer B fills the segment
///    and triggers a rotation. Rotation flushes the memtable — which does not
///    contain A's value — and then truncates the segment, erasing A's record.
/// 3. A applies its value to the memtable, where it is the only copy.
/// 4. The process exits. A's acknowledged write is gone.
///
/// `CLAUDE.md` states the WAL is `fsync`'d before a write is acknowledged and
/// that acknowledged writes survive `kill -9`. Two concurrent writers are
/// enough to break that, with no crash at all.
#[test]
fn simulation_concurrent_writer_ack_survives_wal_rotation() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Condvar, Mutex};

    let dir = tempfile::tempdir().expect("tempdir");
    let realm = RealmId::generate();

    {
        let mut config = StorageConfig::dev(dir.path().to_path_buf());
        // Small segment so the filler writes below force several rotations,
        // and production sync semantics so "acknowledged" means fsync'd.
        config.wal_config = WalConfig {
            max_size: 4096,
            sync_mode: SyncMode::EveryWrite,
        };
        let engine = Arc::new(EmbeddedStorageEngine::open(config).expect("open"));

        // Rendezvous: `parked` fires when the writer reaches its
        // acknowledgement point; `release` lets it continue.
        let parked = Arc::new((Mutex::new(false), Condvar::new()));
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let armed = Arc::new(AtomicBool::new(true));

        {
            let parked = Arc::clone(&parked);
            let release = Arc::clone(&release);
            let armed = Arc::clone(&armed);
            engine.set_post_ack_hook(Arc::new(move || {
                // Only the first writer parks; the filler writes must run.
                if !armed.swap(false, Ordering::SeqCst) {
                    return;
                }
                {
                    let (lock, cv) = &*parked;
                    *lock.lock().expect("parked lock") = true;
                    cv.notify_all();
                }
                let (lock, cv) = &*release;
                let mut go = lock.lock().expect("release lock");
                while !*go {
                    go = cv.wait(go).expect("release wait");
                }
            }));
        }

        let writer = {
            let engine = Arc::clone(&engine);
            let realm = realm.clone();
            std::thread::spawn(move || {
                engine
                    .put(&realm, b"survivor", b"acknowledged-before-rotation")
                    .expect("the write is acknowledged");
            })
        };

        // Wait until the writer holds its acknowledgement.
        {
            let (lock, cv) = &*parked;
            let mut is_parked = lock.lock().expect("parked lock");
            while !*is_parked {
                is_parked = cv.wait(is_parked).expect("parked wait");
            }
        }

        // Drive rotations from this thread while the writer is parked.
        for i in 0u32..200 {
            let key = format!("filler-{i:04}");
            engine.put(&realm, key.as_bytes(), &[0u8; 64]).expect("put");
        }

        // A rotation must have happened, otherwise the test proves nothing:
        // the pre-rotation flush is what writes an SST.
        let sst_count = std::fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(std::result::Result::ok)
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "sst"))
            .count();
        assert!(
            sst_count >= 1,
            "the filler writes must have rotated the WAL (found {sst_count} SSTs)"
        );

        {
            let (lock, cv) = &*release;
            *lock.lock().expect("release lock") = true;
            cv.notify_all();
        }
        writer.join().expect("writer thread");
        // Exit without an explicit flush — the acknowledged write must not
        // depend on a clean shutdown.
    }

    let engine = EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf()))
        .expect("reopen after exit");
    let got = engine.get(&realm, b"survivor").expect("get");
    assert_eq!(
        got.as_deref(),
        Some(&b"acknowledged-before-rotation"[..]),
        "a write acknowledged before a concurrent rotation must survive it"
    );
}
