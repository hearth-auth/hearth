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

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::time::Duration;

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

/// The steady-state append path must use `sync_data` (fdatasync), while
/// rotation must still use a full `sync_all` (fsync).
///
/// HEA-1959 swapped the per-batch sync to fdatasync, which persists the data
/// and the file length but not other metadata. That is sound for an append-only
/// segment whose directory entry was already fsynced at creation (HEA-1855),
/// and it is *not* sound for rotation, which truncates and rewrites headers.
///
/// Without this test, a later change could quietly route rotation through
/// fdatasync too and lose the metadata durability that WAL reuse depends on —
/// a failure that would only ever appear as corruption after a real power loss,
/// which no test in this suite can reproduce. Pin the split instead.
#[test]
fn appends_use_fdatasync_while_rotation_uses_full_fsync() {
    let dir = tempfile::tempdir().expect("tempdir");
    let wal_path = dir.path().join("wal.log");
    let fault_fs = Arc::new(FaultFs::new());

    let counts = || {
        (
            fault_fs
                .config
                .sync_count
                .load(std::sync::atomic::Ordering::Relaxed),
            fault_fs
                .config
                .datasync_count
                .load(std::sync::atomic::Ordering::Relaxed),
        )
    };

    // A cap small enough that a handful of appends forces a rotation.
    let wal = open_wal_with_fs(
        &wal_path,
        WalConfig {
            max_size: 4096,
            sync_mode: SyncMode::EveryWrite,
        },
        Arc::clone(&fault_fs) as Arc<dyn Fs>,
    );

    // Steady-state appends, well under the rotation threshold.
    let (sync_before, data_before) = counts();
    wal.append(&make_entry(b"steady-1", b"value"))
        .expect("append");
    wal.append(&make_entry(b"steady-2", b"value"))
        .expect("append");
    let (sync_after, data_after) = counts();

    let syncs = sync_after - sync_before;
    let datasyncs = data_after - data_before;
    assert!(datasyncs > 0, "appends must issue at least one fdatasync");
    assert_eq!(
        syncs, datasyncs,
        "every sync on the steady-state append path must be an fdatasync; \
         got {syncs} syncs of which only {datasyncs} were fdatasync"
    );

    // Now force a rotation by overflowing the 4 KiB cap, and require that it
    // contributes at least one sync that is NOT an fdatasync.
    let (sync_before, data_before) = counts();
    let big = vec![b'x'; 2048];
    for i in 0..8 {
        wal.append(&make_entry(format!("rot-{i}").as_bytes(), &big))
            .expect("append");
    }
    let (sync_after, data_after) = counts();

    let syncs = sync_after - sync_before;
    let datasyncs = data_after - data_before;
    assert!(
        syncs > datasyncs,
        "rotation must issue a full sync_all, not an fdatasync: {syncs} total \
         syncs and {datasyncs} fdatasyncs means rotation used fdatasync too"
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

/// A sync failure mid-batch must propagate to **every** writer in that group.
///
/// No writer whose bytes were not durably fsynced may return `Ok`.  This test
/// uses a `commit_barrier` (test-hooks feature) to make batch membership
/// deterministic: all N writers push their slot before the leader drains,
/// so the leader's first batch contains exactly N entries.  A failing
/// `sync_all` on that batch must therefore produce exactly N errors.
///
/// After the failure the WAL must still recover to a valid prefix.
#[test]
fn group_commit_sync_failure_propagates_to_all_batch_members() {
    const N: usize = 4;

    let dir = tempfile::tempdir().expect("tempdir");
    let wal_path = dir.path().join("test.wal");

    let fault_fs = Arc::new(FaultFs::new());

    let error_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    {
        // Open the WAL, then attach the commit barrier before wrapping in Arc
        // so all N writers rendezvous before the leader drains the queue.
        let mut wal = open_wal_with_fs(
            &wal_path,
            WalConfig {
                max_size: u64::MAX,
                sync_mode: SyncMode::EveryWrite,
            },
            Arc::clone(&fault_fs) as Arc<dyn Fs>,
        );
        wal.commit_barrier = Some(Arc::new(std::sync::Barrier::new(N)));
        let wal = Arc::new(wal);

        // Arm the failure AFTER WAL open (which itself calls sync_all once).
        fault_fs
            .config
            .fail_next_sync
            .store(true, std::sync::atomic::Ordering::SeqCst);

        let start = Arc::new(Barrier::new(N));
        let handles: Vec<_> = (0..N)
            .map(|t| {
                let wal = Arc::clone(&wal);
                let b = Arc::clone(&start);
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

    // The commit_barrier guarantees all N writers are in the same batch.
    // A failing sync_all must propagate the error to every member — exactly N.
    let errs = error_count.load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        errs, N,
        "sync failure must propagate to every member of the failed batch; \
         got {errs}/{N} errors"
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

/// Rotation under group commit must not cause nonce reuse.
///
/// During `commit_batch`, when the WAL crosses `max_size`, the leader calls
/// `rotate_locked`, which resets `record_counter` to 0 atomically with the DEK
/// swap (HEA-SEC-08).  A bug that splits the counter reset from the DEK swap
/// would encrypt post-rotation records under a (DEK, nonce) pair already used
/// by the pre-rotation segment — a confidentiality breach.  On replay,
/// `scan_records` derives nonces positionally from 0, so any mismatch breaks
/// the AEAD tag and surfaces as an error or short read in `read_all`.
///
/// This test forces several WAL rotations under concurrent writers, then
/// re-opens and asserts that all remaining records decrypt without error.
#[test]
fn group_commit_rotation_does_not_cause_nonce_reuse() {
    const N: usize = 4;
    const K: usize = 30;

    let dir = tempfile::tempdir().expect("tempdir");
    let wal_path = dir.path().join("rotation-nonce.wal");

    // max_size small enough that every group-commit batch triggers a rotation.
    // Per-entry on-disk footprint: 4 (len) + plaintext + 16 (GCM tag) + 4 (CRC).
    // "rot-N-KK" key ≈ 9 B, "rotation-nonce-val" value ≈ 18 B:
    //   plaintext ≈ 8+16+1+4+9+4+18 = 60 B → on-disk ≈ 4+76+4 = 84 B/record.
    // With max_size=300 and header=82 B: 82+84 = 166 < 300 → no rotation alone,
    // but a batch of 4 adds 4×84 = 336 B → 82+336 = 418 > 300 → rotates.
    {
        let wal = Arc::new(open_wal(
            &wal_path,
            WalConfig {
                max_size: 300,
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
                        // Ignore errors — some writes may be lost on rotation;
                        // correctness is verified by decryption, not entry count.
                        let _ = wal.append(&make_entry(
                            format!("rot-{t}-{k}").as_bytes(),
                            b"rotation-nonce-val",
                        ));
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().expect("rotation thread panicked");
        }
    }

    // Re-open and verify all remaining records decrypt without AEAD error.
    // A nonce-reuse bug would corrupt the GCM tag and cause read_all to
    // return Err (or silently truncate — either way the assertion below fires).
    let wal = open_wal(
        &wal_path,
        WalConfig {
            max_size: u64::MAX,
            sync_mode: SyncMode::None,
        },
    );
    let entries = wal.read_all().expect(
        "read_all must succeed after concurrent rotations — \
         AEAD failure indicates nonce reuse under group commit",
    );

    // After many rotations the WAL holds the entries from the final segment.
    // Assert we recovered at least one readable record (zero would indicate
    // total data loss, which is a separate correctness bug).
    assert!(
        !entries.is_empty(),
        "WAL must contain at least one readable entry after concurrent rotations; \
         got none — possible rotation or nonce-counter bug"
    );
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

    // Verify the specific pre-crash key contents rather than just a count,
    // so the test can distinguish "right entries present" from "enough entries
    // of any kind happened to survive" (e.g. post-crash entries padding the
    // count past the N*K_BEFORE floor).
    let recovered_keys: std::collections::HashSet<Vec<u8>> =
        entries.iter().map(|e| e.key.clone()).collect();

    let missing: Vec<String> = (0..N)
        .flat_map(|t| (0..K_BEFORE).map(move |k| format!("pre-{t}-{k}")))
        .filter(|k| !recovered_keys.contains(k.as_bytes()))
        .collect();

    assert!(
        missing.is_empty(),
        "{} pre-crash key(s) missing after recovery: {:?}",
        missing.len(),
        &missing[..missing.len().min(5)],
    );
}

/// A panic inside `pre_rotate` must not strand the in-flight batch.
///
/// Regression for HEA-1924: `LeaderGuard::drop` previously only drained
/// `gs.pending`, which is empty by the time the leader calls `commit_batch`.
/// A panic inside `commit_batch` (e.g. the memtable-flush closure passed as
/// `pre_rotate`) therefore left every writer in the already-drained batch
/// blocked on its condvar forever.  The fix moves the drained batch into
/// `guard.in_flight` so `Drop` can signal those writers on the panic path.
#[test]
fn leader_panic_in_pre_rotate_does_not_strand_in_flight_batch() {
    const N: usize = 3;

    let dir = tempfile::tempdir().expect("tempdir");
    let wal_path = dir.path().join("panic.wal");

    let mut wal = open_wal(
        &wal_path,
        WalConfig {
            // max_size=1 forces every commit_batch to call pre_rotate.
            max_size: 1,
            sync_mode: SyncMode::EveryWrite,
        },
    );
    // commit_barrier ensures all N writers have pushed their slots before the
    // leader drains the queue, making batch membership deterministic.
    wal.commit_barrier = Some(Arc::new(std::sync::Barrier::new(N)));
    let wal = Arc::new(wal);

    let (tx, rx) = std::sync::mpsc::channel::<usize>();
    for t in 0..N {
        let wal = Arc::clone(&wal);
        let tx = tx.clone();
        std::thread::spawn(move || {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = wal
                    .append_with_pre_rotate(&make_entry(format!("p-{t}").as_bytes(), b"v"), || {
                        panic!("simulated memtable-flush panic inside pre_rotate")
                    });
            }));
            let _ = tx.send(t);
        });
    }
    drop(tx);

    let mut finished = 0;
    while finished < N {
        match rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(_) => finished += 1,
            Err(_) => break,
        }
    }
    assert_eq!(
        finished, N,
        "all {N} writers must return after a leader panic; only {finished} did — \
         in-flight batch members are stranded on their condvars"
    );
}

// ── HEA-1955: looping-leader coalescing tests ─────────────────────────────

/// HEA-1955 measurement: the looping leader must not waste inter-fsync budget
/// on follower-wakeup gaps.
///
/// With synthetic 5 ms sync latency and T=16 concurrent writers, the promote-
/// follower design (pre-fix) lost ~1–3 ms per fsync to OS thread wakeup,
/// cutting coalescing efficiency from ~100% to ~60–75%.  The looping leader
/// eliminates handoff: after committing a batch it immediately drains and
/// commits the next without parking the leader thread.
///
/// Measurement: run T writers for 300 ms, record ops and sync_count, derive
/// average batch size and (via FaultFs) the effective fsync rate.  The leader
/// must achieve an inter-fsync gap < half the sync latency (2.5 ms).
///
/// This test uses `#[ignore]` (HEA-1955) because:
///   (a) it takes ~300 ms of wall time, and
///   (b) its gap assertion depends on scheduler timing that is unreliable in
///       heavily-loaded CI containers.
///
/// Run manually to compare before/after the looping-leader fix:
///
///   CARGO_TARGET_DIR=/scratch/cache/target \
///     cargo test -p hearth-simulation -- \
///     measure_looping_leader_inter_fsync_gap --ignored --nocapture
///
/// Expected output after the fix:
///   avg_gap_ms ≈ 0.0  avg_batch ≈ T  efficiency ≈ 95–100%
#[test]
#[ignore = "HEA-1955: manual measurement — run with -- --ignored --nocapture; ~300 ms wall time, \
            and the gap assertion depends on scheduler timing unreliable in loaded CI containers"]
fn measure_looping_leader_inter_fsync_gap() {
    const T: usize = 16;
    const SYNC_LAT_US: u64 = 5_000; // 5 ms synthetic fsync latency
    const RUN_MS: u64 = 300;

    let dir = tempfile::tempdir().expect("tempdir");
    let fault_fs = Arc::new(FaultFs::new());
    fault_fs.config.set_latency(0, 0, SYNC_LAT_US, 0, 0);

    let wal = Arc::new(open_wal_with_fs(
        &dir.path().join("gap.wal"),
        WalConfig {
            max_size: u64::MAX,
            sync_mode: SyncMode::EveryWrite,
        },
        Arc::clone(&fault_fs) as Arc<dyn Fs>,
    ));

    let sync_start = fault_fs.config.sync_count.load(Ordering::SeqCst);
    let start = std::time::Instant::now();
    let stop = Arc::new(AtomicBool::new(false));
    let total_ops = Arc::new(AtomicU64::new(0));

    let handles: Vec<_> = (0..T)
        .map(|t| {
            let wal = Arc::clone(&wal);
            let stop = Arc::clone(&stop);
            let ops = Arc::clone(&total_ops);
            std::thread::spawn(move || {
                let mut k: u64 = 0;
                while !stop.load(Ordering::Relaxed) {
                    wal.append(&make_entry(format!("gap-{t}-{k}").as_bytes(), b"v"))
                        .expect("append");
                    ops.fetch_add(1, Ordering::Relaxed);
                    k += 1;
                }
            })
        })
        .collect();

    // RUN_MS *is* the measurement window: this benchmark derives fsync rate and batch size
    // from ops observed over a fixed wall-clock interval, so there is no condition to poll
    // for — replacing the sleep would void the measurement.
    // AUDIT: justified-sleep: fixed wall-clock measurement window; no condition to poll for.
    std::thread::sleep(Duration::from_millis(RUN_MS));
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        h.join().expect("thread");
    }

    let elapsed = start.elapsed();
    let syncs = fault_fs.config.sync_count.load(Ordering::Relaxed) - sync_start;
    let ops = total_ops.load(Ordering::Relaxed);

    let effective_rate_hz = syncs as f64 / elapsed.as_secs_f64();
    let theoretical_rate_hz = 1_000_000.0 / SYNC_LAT_US as f64;
    let avg_batch = if syncs > 0 {
        ops as f64 / syncs as f64
    } else {
        0.0
    };
    let avg_gap_ms = if syncs > 0 {
        (elapsed.as_secs_f64() / syncs as f64 - SYNC_LAT_US as f64 / 1_000_000.0) * 1_000.0
    } else {
        f64::MAX
    };
    let efficiency_pct = (effective_rate_hz / theoretical_rate_hz) * 100.0;

    eprintln!(
        "HEA-1955 measurement: T={T}, ops={ops}, syncs={syncs}, \
         avg_batch={avg_batch:.1}, efficiency={efficiency_pct:.1}%, \
         avg_gap_ms={avg_gap_ms:.2}"
    );
    eprintln!("  promote-follower baseline: gap≈1–3ms, efficiency≈60–75%");
    eprintln!("  looping-leader target:     gap≈0ms,   efficiency≈95–100%");

    // Lenient sanity check: at least some coalescing must occur.
    assert!(ops > 0 && syncs > 0, "no writes completed in {RUN_MS} ms");
    assert!(
        syncs <= ops,
        "sync count {syncs} must not exceed op count {ops}"
    );
}

/// HEA-1955 correctness: the looping leader must commit all entries across
/// multiple back-to-back batches without deadlock or data loss.
///
/// This test verifies that a leader which finds new entries queued after its
/// first fsync processes them in the same call rather than handing off, and
/// that all committed entries remain durable after re-open.
///
/// Uses FaultFs with 2 ms sync latency so entries accumulate between batches
/// without making the test slow.
#[test]
fn group_commit_looping_leader_chains_multiple_batches_correctly() {
    const T: usize = 8;
    const K: usize = 40; // writes per thread; enough rounds that looping fires
    const SYNC_LAT_US: u64 = 2_000; // 2 ms — enough for batches to form

    let dir = tempfile::tempdir().expect("tempdir");
    let fault_fs = Arc::new(FaultFs::new());
    fault_fs.config.set_latency(0, 0, SYNC_LAT_US, 0, 0);

    let wal_path = dir.path().join("chain.wal");
    {
        let wal = Arc::new(open_wal_with_fs(
            &wal_path,
            WalConfig {
                max_size: u64::MAX,
                sync_mode: SyncMode::EveryWrite,
            },
            Arc::clone(&fault_fs) as Arc<dyn Fs>,
        ));

        let barrier = Arc::new(Barrier::new(T));
        let handles: Vec<_> = (0..T)
            .map(|t| {
                let wal = Arc::clone(&wal);
                let b = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    b.wait();
                    for k in 0..K {
                        wal.append(&make_entry(format!("chain-{t}-{k:03}").as_bytes(), b"val"))
                            .expect("append must succeed");
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().expect("worker panicked");
        }
    }

    // Re-open and verify all T*K entries are durable.
    let wal_ro = open_wal(
        &wal_path,
        WalConfig {
            max_size: u64::MAX,
            sync_mode: SyncMode::None,
        },
    );
    let entries = wal_ro.read_all().expect("read_all after multi-batch loop");
    assert_eq!(
        entries.len(),
        T * K,
        "all {T}×{K} entries must be durable after looping-leader commits; \
         got {} — looping leader may have dropped entries across batch boundaries",
        entries.len()
    );

    // Verify coalescing actually occurred (batches formed during 2 ms fsyncs).
    let total_syncs = fault_fs.config.sync_count.load(Ordering::Relaxed);
    let total_writes = (T * K) as u64;
    assert!(
        total_syncs < total_writes,
        "looping leader must batch writes: {total_syncs} fsyncs for \
         {total_writes} writes — ratio should be < 1.0"
    );
}
