//! Task 24.2 (audit 2026-08-28 §4.11#11, §9 item 3) — prove `fsync`-before-ack,
//! not merely "the bytes came back".
//!
//! The WAL's durability claim is that an acknowledged write survives a
//! `kill -9`, which means the `fsync` must complete **before** `append`
//! returns. Nothing tested that. `wal_data_persists_across_reopen` says so in
//! its own doc comment — writer and reader share a process, so the bytes are
//! served from the page cache whether or not `fsync` was ever called — and it
//! pointed at "the `hearth-simulation` crate's `wal_crash` real-thread/tempfile
//! crash loop" for the real proof. There is no crash loop there. `wal_crash`
//! holds individual crash tests, and every one of them runs under
//! `SyncMode::None`, so none of them can distinguish the two.
//!
//! The discriminator used here is failure injection rather than counting: arm
//! the filesystem so the next sync fails, then append. A WAL that syncs before
//! acknowledging must surface that error. A WAL that acknowledges first — or
//! that calls `fsync` and ignores what it returns — answers `Ok` and has just
//! told the caller a lost write is durable.
//!
//! Each test carries its own control, so neither can pass because the WAL
//! happens to reject everything.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use hearth::core::{RealmId, Timestamp};
use hearth::storage::encryption;
use hearth::storage::wal::{SyncMode, Wal, WalConfig, WalEntry, WalOperation};

use crate::FaultFs;

fn test_kek() -> (encryption::KeyEncryptionKey, encryption::KekId) {
    let mut kek_bytes = [0u8; 32];
    for (i, b) in kek_bytes.iter_mut().enumerate() {
        *b = (i * 17 + 3) as u8;
    }
    (
        encryption::KeyEncryptionKey::from_bytes(kek_bytes),
        [0x55u8; encryption::KEK_ID_SIZE],
    )
}

fn open_wal(path: &std::path::Path, sync_mode: SyncMode, fs: Arc<FaultFs>) -> Wal {
    let (kek, kek_id) = test_kek();
    Wal::open_with_fs(
        path,
        WalConfig {
            max_size: u64::MAX,
            sync_mode,
        },
        fs,
        &kek,
        kek_id,
    )
    .expect("open wal")
}

fn make_entry(key: &[u8]) -> WalEntry {
    WalEntry {
        timestamp: Timestamp::from_micros(1_700_000_000_000_000),
        realm_id: RealmId::generate(),
        operation: WalOperation::Put,
        key: key.to_vec(),
        value: b"durable-value".to_vec(),
    }
}

/// An append whose `fsync` fails must NOT be acknowledged.
///
/// This is the whole durability invariant in one assertion. If the WAL returned
/// `Ok` here, every caller above it — the storage engine, the identity engine,
/// the HTTP handler — would have been told a write is durable when the kernel
/// never promised it, and a `kill -9` would lose it.
#[test]
fn simulation_append_is_refused_when_the_fsync_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    let wal_path = dir.path().join("fsync-before-ack.wal");
    let fault_fs = Arc::new(FaultFs::new());
    let wal = open_wal(&wal_path, SyncMode::EveryWrite, Arc::clone(&fault_fs));

    // Control: an unarmed append succeeds, so the assertion below cannot pass
    // merely because this WAL rejects everything.
    wal.append(&make_entry(b"control-key"))
        .expect("an unarmed append must succeed");

    let before = fault_fs.config.sync_count.load(Ordering::SeqCst);
    assert!(
        before > 0,
        "the control append must actually have synced, or arming the fault \
         below proves nothing"
    );

    fault_fs.config.arm_sync_failure();
    let result = wal.append(&make_entry(b"doomed-key"));

    assert!(
        result.is_err(),
        "an append whose fsync failed must not be acknowledged — returning Ok \
         here tells the caller a lost write is durable"
    );
}

/// The failure above must come from the sync, not from the write.
///
/// Under `SyncMode::None` the WAL never syncs on the append path, so arming the
/// same fault must leave the append untouched. Without this, the test above
/// would still pass if `arm_sync_failure` happened to break writes too, and it
/// would stop distinguishing fsync-before-ack from no fsync at all — which is
/// exactly the distinction task 24.2 asks for.
#[test]
fn simulation_sync_fault_does_not_bite_a_wal_that_never_syncs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let wal_path = dir.path().join("no-sync.wal");
    let fault_fs = Arc::new(FaultFs::new());
    let wal = open_wal(&wal_path, SyncMode::None, Arc::clone(&fault_fs));

    let before = fault_fs.config.sync_count.load(Ordering::SeqCst);
    fault_fs.config.arm_sync_failure();

    wal.append(&make_entry(b"unsynced-key"))
        .expect("SyncMode::None must not consult the fsync that just failed");

    assert_eq!(
        fault_fs.config.sync_count.load(Ordering::SeqCst),
        before,
        "SyncMode::None must not sync on the append path at all"
    );
}

/// `SyncMode::EveryWrite` must sync on EVERY append, not once at open.
///
/// A WAL that synced once and then acknowledged everything afterwards would
/// pass the failure-injection test above by luck of ordering. Counting pins it.
#[test]
fn simulation_every_write_syncs_once_per_append() {
    let dir = tempfile::tempdir().expect("tempdir");
    let wal_path = dir.path().join("count.wal");
    let fault_fs = Arc::new(FaultFs::new());
    let wal = open_wal(&wal_path, SyncMode::EveryWrite, Arc::clone(&fault_fs));

    let before = fault_fs.config.sync_count.load(Ordering::SeqCst);
    for i in 0..5u8 {
        wal.append(&make_entry(&[b'k', i])).expect("append");
    }
    let after = fault_fs.config.sync_count.load(Ordering::SeqCst);

    assert!(
        after - before >= 5,
        "EveryWrite must sync at least once per append; got {} syncs for 5 appends",
        after - before
    );
}
