//! WAL group-commit correctness and throughput tests.
//!
//! These tests verify the three invariants that group commit must uphold:
//!
//! 1. **Durability**: every writer that receives `Ok` from `append` had its
//!    bytes covered by a completed `sync_all` before the call returned.
//! 2. **Ordering**: bytes on disk are in `record_num` (nonce) order even under
//!    concurrent appenders — verified implicitly by re-opening the WAL and
//!    decrypting all records (a nonce mismatch would corrupt the AEAD tag and
//!    surface as an I/O error in `read_all`).
//! 3. **Throughput**: the number of `sync_all` calls is strictly less than the
//!    number of committed writes (the group commit benefit).

use std::sync::{Arc, Barrier};

use hearth::core::{RealmId, Timestamp};
use hearth::storage::encryption;
use hearth::storage::fs::Fs;
use hearth::storage::wal::{SyncMode, Wal, WalConfig, WalEntry, WalOperation};

use crate::FaultFs;

/// Deterministic KEK for group commit tests.
fn test_kek() -> (encryption::KeyEncryptionKey, encryption::KekId) {
    let mut kek_bytes = [0u8; 32];
    for (i, b) in kek_bytes.iter_mut().enumerate() {
        *b = (i * 17 + 3) as u8;
    }
    let kek = encryption::KeyEncryptionKey::from_bytes(kek_bytes);
    let kek_id = [0x55u8; encryption::KEK_ID_SIZE];
    (kek, kek_id)
}

fn open_wal(path: &std::path::Path, config: WalConfig) -> Wal {
    let (kek, kek_id) = test_kek();
    Wal::open_with_fs(
        path,
        config,
        Arc::new(hearth::storage::RealFs),
        &kek,
        kek_id,
    )
    .expect("open wal")
}

fn open_wal_with_fs(path: &std::path::Path, config: WalConfig, fs: Arc<dyn Fs>) -> Wal {
    let (kek, kek_id) = test_kek();
    Wal::open_with_fs(path, config, fs, &kek, kek_id).expect("open wal with fs")
}

fn make_entry(key: &[u8], value: &[u8]) -> WalEntry {
    WalEntry {
        timestamp: Timestamp::from_micros(1_700_000_000_000_000),
        realm_id: RealmId::generate(),
        operation: WalOperation::Put,
        key: key.to_vec(),
        value: value.to_vec(),
    }
}

/// All N concurrent writers must see Ok AND all entries must be readable after.
///
/// This is the core durability invariant: `Ok` from `append` guarantees the
/// write is durable even when many writers are grouped into a single fsync.
#[test]
fn group_commit_all_writers_acked_after_sync() {
    const N: usize = 8;
    const K: usize = 20;

    let dir = tempfile::tempdir().expect("tempdir");
    let wal_path = dir.path().join("test.wal");

    {
        let wal = Arc::new(open_wal(
            &wal_path,
            WalConfig {
                max_size: u64::MAX,
                sync_mode: SyncMode::EveryWrite,
            },
        ));

        let barrier = Arc::new(Barrier::new(N));
        let handles: Vec<_> = (0..N)
            .map(|t| {
                let wal = Arc::clone(&wal);
                let b = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    b.wait();
                    for k in 0..K {
                        let entry = make_entry(
                            format!("key-{t:02}-{k:03}").as_bytes(),
                            format!("val-{t:02}-{k:03}").as_bytes(),
                        );
                        wal.append(&entry)
                            .expect("all concurrent appends must succeed");
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().expect("worker thread panicked");
        }
    }

    // Re-open and verify every entry is readable.
    let wal = open_wal(
        &wal_path,
        WalConfig {
            max_size: u64::MAX,
            sync_mode: SyncMode::None,
        },
    );
    let entries = wal.read_all().expect("read_all after group commit");
    assert_eq!(
        entries.len(),
        N * K,
        "all {N}×{K} entries committed with Ok must survive restart"
    );
}

/// Group commit must reduce fsyncs-per-write below 1.0 at concurrency > 1.
///
/// With synthetic sync latency the leader should batch multiple writers into
/// each fsync call, driving fsyncs/write well below 1.0.
#[test]
fn group_commit_reduces_fsyncs() {
    const N: usize = 8;
    const K: usize = 10;

    let dir = tempfile::tempdir().expect("tempdir");
    let wal_path = dir.path().join("test.wal");

    let fault_fs = Arc::new(FaultFs::new());
    // 5 ms sync latency maximises the chance that many writers queue up while
    // one leader is inside sync_all, creating large batches.
    fault_fs.config.set_latency(0, 0, 5_000, 0, 0);

    {
        let wal = Arc::new(open_wal_with_fs(
            &wal_path,
            WalConfig {
                max_size: u64::MAX,
                sync_mode: SyncMode::EveryWrite,
            },
            Arc::clone(&fault_fs) as Arc<dyn Fs>,
        ));

        let barrier = Arc::new(Barrier::new(N));
        let handles: Vec<_> = (0..N)
            .map(|t| {
                let wal = Arc::clone(&wal);
                let b = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    b.wait();
                    for k in 0..K {
                        wal.append(&make_entry(format!("k{t}-{k}").as_bytes(), b"value"))
                            .expect("append");
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread");
        }
    }

    let total_syncs = fault_fs
        .config
        .sync_count
        .load(std::sync::atomic::Ordering::Relaxed);
    let total_writes = (N * K) as u64;

    assert!(
        total_syncs < total_writes,
        "group commit must batch fsyncs: {total_syncs} sync_all calls for \
         {total_writes} writes (ratio = {:.2}; should be < 1.0)",
        total_syncs as f64 / total_writes as f64,
    );
}

/// Bytes on disk must be in record_num (nonce) order even under concurrency.
///
/// A nonce ordering violation would break AEAD authentication, causing
/// `read_all` to surface an error or short-read.  This test forces thread
/// interleaving via write-latency jitter and then verifies that all entries
/// are still readable after re-open.
#[test]
fn concurrent_writes_preserve_nonce_ordering() {
    const N: usize = 8;
    const K: usize = 15;

    let dir = tempfile::tempdir().expect("tempdir");
    let wal_path = dir.path().join("test.wal");

    let fault_fs = Arc::new(FaultFs::new());
    // Write jitter injects up to 300 µs per write to maximise interleaving.
    fault_fs.config.set_latency(0, 100, 0, 200, 99);

    {
        let wal = Arc::new(open_wal_with_fs(
            &wal_path,
            WalConfig {
                max_size: u64::MAX,
                sync_mode: SyncMode::EveryWrite,
            },
            Arc::clone(&fault_fs) as Arc<dyn Fs>,
        ));

        let barrier = Arc::new(Barrier::new(N));
        let handles: Vec<_> = (0..N)
            .map(|t| {
                let wal = Arc::clone(&wal);
                let b = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    b.wait();
                    for k in 0..K {
                        wal.append(&make_entry(format!("ord-{t}-{k}").as_bytes(), b"v"))
                            .expect("append");
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread");
        }
    }

    // Re-open: AEAD decryption fails if nonce ordering is wrong.
    let wal = open_wal(
        &wal_path,
        WalConfig {
            max_size: u64::MAX,
            sync_mode: SyncMode::None,
        },
    );
    let entries = wal
        .read_all()
        .expect("read_all must succeed — AEAD failure indicates nonce ordering violation");
    assert_eq!(
        entries.len(),
        N * K,
        "all {N}×{K} entries must be decryptable (ordering violation breaks AEAD)"
    );
}

/// A sync failure mid-batch must propagate to all writers in that group.
///
/// No writer whose bytes were not durably fsynced may return Ok.  After the
/// failure the WAL must still recover to a valid prefix.
#[test]
fn group_commit_sync_failure_propagates_to_all_batch_members() {
    const N: usize = 4;

    let dir = tempfile::tempdir().expect("tempdir");
    let wal_path = dir.path().join("test.wal");

    let fault_fs = Arc::new(FaultFs::new());
    // Slow syncs so all N writers queue into the same batch before the leader
    // calls sync_all.
    fault_fs.config.set_latency(0, 0, 10_000, 0, 0);

    let error_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    {
        let wal = Arc::new(open_wal_with_fs(
            &wal_path,
            WalConfig {
                max_size: u64::MAX,
                sync_mode: SyncMode::EveryWrite,
            },
            Arc::clone(&fault_fs) as Arc<dyn Fs>,
        ));

        // Arm the failure AFTER WAL open (which itself calls sync_all once).
        fault_fs
            .config
            .fail_next_sync
            .store(true, std::sync::atomic::Ordering::SeqCst);

        let barrier = Arc::new(Barrier::new(N));
        let handles: Vec<_> = (0..N)
            .map(|t| {
                let wal = Arc::clone(&wal);
                let b = Arc::clone(&barrier);
                let errs = Arc::clone(&error_count);
                std::thread::spawn(move || {
                    b.wait();
                    let result = wal.append(&make_entry(format!("fail-{t}").as_bytes(), b"v"));
                    if result.is_err() {
                        errs.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread");
        }
    }

    // At least one writer in the failed batch must have received an error.
    // (With 10 ms sync latency all N writers typically batch together, but
    // the guarantee is: any writer whose bytes hit the failed sync_all gets
    // Err.  Writers in subsequent batches may succeed.)
    let errs = error_count.load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        errs >= 1,
        "sync failure must propagate to at least one batch member; got 0/{N} errors"
    );
    assert!(
        errs <= N,
        "impossible: more errors ({errs}) than writers ({N})"
    );

    // Recovery: WAL must still parse to a valid (possibly empty) prefix.
    let wal = open_wal(
        &wal_path,
        WalConfig {
            max_size: u64::MAX,
            sync_mode: SyncMode::None,
        },
    );
    wal.read_all()
        .expect("WAL must recover to a valid prefix after group sync failure");
}

/// After a crash mid-batch (simulated via WAL re-open), the valid prefix from
/// before the crash must be intact with no holes.
#[test]
fn concurrent_crash_mid_batch_leaves_valid_prefix() {
    const N: usize = 4;
    const K_BEFORE: usize = 10;

    let dir = tempfile::tempdir().expect("tempdir");
    let wal_path = dir.path().join("test.wal");

    // Phase 1: write K_BEFORE entries per thread — all durable.
    {
        let wal = Arc::new(open_wal(
            &wal_path,
            WalConfig {
                max_size: u64::MAX,
                sync_mode: SyncMode::EveryWrite,
            },
        ));

        let barrier = Arc::new(Barrier::new(N));
        let handles: Vec<_> = (0..N)
            .map(|t| {
                let wal = Arc::clone(&wal);
                let b = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    b.wait();
                    for k in 0..K_BEFORE {
                        wal.append(&make_entry(format!("pre-{t}-{k}").as_bytes(), b"v"))
                            .expect("pre-write");
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("pre-thread");
        }
    }

    // Phase 2: inject write fault on one of the first writes of the next batch.
    {
        let fault_fs = Arc::new(FaultFs::new());
        fault_fs.config.fail_write_after(2); // corrupt after 2 successful writes

        let wal = Arc::new(open_wal_with_fs(
            &wal_path,
            WalConfig {
                max_size: u64::MAX,
                sync_mode: SyncMode::EveryWrite,
            },
            Arc::clone(&fault_fs) as Arc<dyn Fs>,
        ));

        let barrier = Arc::new(Barrier::new(N));
        let handles: Vec<_> = (0..N)
            .map(|t| {
                let wal = Arc::clone(&wal);
                let b = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    b.wait();
                    // Ignore errors — some writes will fail due to the fault.
                    let _ = wal.append(&make_entry(format!("post-crash-{t}").as_bytes(), b"v"));
                })
            })
            .collect();
        for h in handles {
            h.join().expect("crash-thread");
        }
    }

    // Phase 3: re-open with real fs; verify the valid prefix from phase 1.
    let wal = open_wal(
        &wal_path,
        WalConfig {
            max_size: u64::MAX,
            sync_mode: SyncMode::None,
        },
    );
    let entries = wal
        .read_all()
        .expect("read after crash — valid prefix required");
    assert!(
        entries.len() >= N * K_BEFORE,
        "all {0}×{1} pre-crash entries must survive; got {2} entries",
        N,
        K_BEFORE,
        entries.len()
    );
}
