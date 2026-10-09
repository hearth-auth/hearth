//! `put_if_absent` acknowledges a claim only once it is durable (#442, #451).
//!
//! #442 moved `EmbeddedStorageEngine::put_if_absent`'s fsync wait outside its
//! engine-wide lock: the lock covers the existence check and the enqueue (which
//! applies the claim to the memtable), and the caller then waits for the group
//! commit's fsync like any other split-commit write. Two promises follow, and
//! these tests pin both with an injected fsync fault (the discriminator
//! `wal_fsync_before_ack` uses: a page-cache reopen cannot tell a synced write
//! from an unsynced one):
//!
//! - The claimer is told `Ok(true)` only after its fsync succeeded; when the
//!   fsync fails it gets an error and the WAL fences.
//! - A racing claimer that checks the key while the first claim is enqueued
//!   but not yet durable loses (`Ok(false)`), so when that fsync then fails
//!   nobody was told it won: the claim fails closed.
//!
//! Single-node only: in cluster mode a claim is a Raft `PutIfAbsent` that the
//! state machine applies with its own check-and-`write_batch`, never through
//! this method (`tests/cluster_follower_write_forwarding.rs` covers it).

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hearth::core::RealmId;
use hearth::storage::wal::{SyncMode, WalConfig};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

use crate::FaultFs;

/// Opens an engine on `fs` that fsyncs every write, as production does.
fn open_engine(dir: &std::path::Path, fs: &Arc<FaultFs>) -> Arc<EmbeddedStorageEngine> {
    let mut config = StorageConfig::dev(dir.to_path_buf());
    config.wal_config = WalConfig {
        max_size: 64 * 1024 * 1024,
        sync_mode: SyncMode::EveryWrite,
    };
    Arc::new(EmbeddedStorageEngine::open_with_fs(config, Arc::clone(fs) as _).expect("open"))
}

/// A claim whose fsync fails is not acknowledged, and the WAL fences so no
/// later write is acknowledged either. The first claim is the control: with a
/// healthy disk the same call wins, and only after an fsync.
#[test]
fn simulation_put_if_absent_is_refused_when_its_fsync_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fs = Arc::new(FaultFs::new());
    let engine = open_engine(dir.path(), &fs);
    let realm = RealmId::generate();

    let syncs_before = fs.config.datasync_count.load(Ordering::SeqCst);
    assert!(
        engine
            .put_if_absent(&realm, b"control", b"1")
            .expect("a claim on a healthy disk"),
        "the first claim of an absent key must win"
    );
    assert!(
        fs.config.datasync_count.load(Ordering::SeqCst) > syncs_before,
        "put_if_absent acknowledged a claim without an fsync"
    );
    assert!(!engine.is_write_fenced());

    fs.config.arm_sync_failure();
    let failed = engine.put_if_absent(&realm, b"unsynced", b"1");
    assert!(
        failed.is_err(),
        "put_if_absent acknowledged a claim whose fsync failed: {failed:?}"
    );
    assert!(
        engine.is_write_fenced(),
        "a failed claim fsync must fence the WAL"
    );
    assert!(
        engine.put_if_absent(&realm, b"after-fence", b"1").is_err(),
        "a fenced engine acknowledged a new claim"
    );
}

/// A claim racing a claim that is enqueued but not yet durable loses, and
/// returns without waiting for that fsync (the lock is free). When the first
/// claim's fsync then fails, its caller gets an error: no caller was told it
/// owns the key.
#[test]
fn simulation_a_claim_racing_an_unsynced_claim_loses_and_neither_wins_if_the_fsync_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fs = Arc::new(FaultFs::new());
    let engine = open_engine(dir.path(), &fs);
    let realm = RealmId::generate();

    // The next fsync stalls for 2 s, then fails.
    fs.config.set_latency(0, 0, 2_000_000, 0, 451);
    fs.config.arm_sync_failure();
    let first = {
        let engine = Arc::clone(&engine);
        let realm = realm.clone();
        std::thread::spawn(move || engine.put_if_absent(&realm, b"spent", b"first"))
    };

    // The enqueue applied the first claim to the memtable before the fsync.
    let deadline = Instant::now() + Duration::from_secs(10);
    while engine.get(&realm, b"spent").expect("get").is_none() {
        assert!(
            Instant::now() < deadline,
            "the first claim never reached the memtable"
        );
        std::thread::yield_now();
    }

    let second = engine.put_if_absent(&realm, b"spent", b"second");
    let first_still_waiting = !first.is_finished();
    fs.config.clear_latency();
    let first = first.join().expect("first claimer");

    assert!(
        matches!(second, Ok(false)),
        "a claim of a key already claimed must lose, durable or not: {second:?}"
    );
    assert!(
        first_still_waiting,
        "the racing claim waited for the first claim's fsync: put_if_absent holds its \
         lock across the fsync again"
    );
    assert!(
        first.is_err(),
        "the first claim was acknowledged although its fsync failed: {first:?}"
    );
    assert!(
        engine.is_write_fenced(),
        "a failed claim fsync must fence the WAL"
    );
}
