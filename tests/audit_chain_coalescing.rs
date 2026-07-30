//! HEA-1948 — proves that concurrent `EmbeddedAuditEngine::append` calls on the
//! same realm pipeline their WAL writes into a single group-commit fsync instead
//! of serialising them one-per-fsync behind the chain lock.
//!
//! ## Why this test exists
//!
//! Before HEA-1948, `append` held the per-realm chain lock across the whole
//! `put_batch` call — including the WAL `fsync` wait. This meant at most **one**
//! audit append per realm was ever in-flight, capping coalescing at exactly one
//! fsync per append regardless of thread count (measured: `fsyncs_per_write ≈ 1.0`).
//!
//! After HEA-1948 the lock covers only the hash-chain RMW and the WAL *enqueue*;
//! the fsync wait happens outside the lock. Concurrent appenders therefore all
//! enqueue within the fsync window of the first writer and coalesce into a single
//! `sync_all` call (`fsyncs_per_write << 1.0`).
//!
//! ## Tests
//!
//! 1. **`concurrent_appends_coalesce_fsyncs`** — proves coalescing.
//!    N threads each append one event to the same realm simultaneously. The WAL
//!    sync count must increase by strictly less than N (i.e. at least some fsyncs
//!    were shared).  With the old code the chain lock serialises appends so the
//!    count rises by exactly N; with the new code the fsync wait is off the lock
//!    and the writes coalesce.
//!
//! 2. **`concurrent_appends_preserve_chain_integrity`** — proves correctness.
//!    After M concurrent appenders finish, `verify_integrity` must return `true`:
//!    every `prev_hash` in the chain matches the preceding event's
//!    `integrity_hash`, the signed head's HMAC is valid, and no events are
//!    missing.

use std::path::PathBuf;
use std::sync::{Arc, Barrier};

use hearth::audit::{AuditAction, AuditEngine, AuditQuery, CreateAuditEvent, EmbeddedAuditEngine};
use hearth::core::{Clock, RealmId, SystemClock};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Build a production-mode storage engine (SyncMode::EveryWrite) in `tmp`.
///
/// `SyncMode::EveryWrite` is required here because that is the only mode where
/// one WAL append maps to one fsync, which makes `wal_sync_count()` a faithful
/// fsync counter. `dev_mode = true` auto-generates the host key so the engine
/// opens without the HEARTH_MASTER_KEY env var.
fn prod_storage(tmp: &tempfile::TempDir) -> Arc<EmbeddedStorageEngine> {
    let mut config = StorageConfig::production(
        PathBuf::from(tmp.path()),
        256 * 1024 * 1024,
        8 * 1024 * 1024,
        4_096,
    );
    config.dev_mode = true;
    Arc::new(EmbeddedStorageEngine::open(config).expect("open storage"))
}

fn make_request(realm_id: RealmId, i: usize) -> CreateAuditEvent {
    CreateAuditEvent {
        realm_id,
        actor: format!("actor-{i}"),
        action: AuditAction::UserCreated,
        resource_type: "test".to_string(),
        resource_id: format!("res-{i}"),
        metadata: None,
    }
}

// ---------------------------------------------------------------------------
// Test 1: concurrent appends must coalesce fsyncs
// ---------------------------------------------------------------------------

/// N threads each append one event to the **same realm** simultaneously.
///
/// With the pre-HEA-1948 code the chain lock is held across the WAL fsync wait,
/// so appends serialise and `wal_sync_count` rises by exactly N. With the fix
/// the lock is released before the fsync, enabling group-commit coalescing;
/// `wal_sync_count` must therefore rise by strictly less than N.
///
/// A thread start-barrier (`std::sync::Barrier::new(N)`) is used to ensure all
/// N threads enter `append` before any single-threaded fsync could complete,
/// making the coalescing observable even on fast-fsync systems.
#[test]
fn concurrent_appends_coalesce_fsyncs() {
    const N: usize = 8;

    let tmp = tempfile::tempdir().expect("tempdir");
    let storage_engine = prod_storage(&tmp);
    let storage = Arc::clone(&storage_engine) as Arc<dyn StorageEngine>;
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let audit = Arc::new(EmbeddedAuditEngine::new(Arc::clone(&storage), clock));

    let realm = RealmId::generate();
    // Warm up the realm (initialise the chain head) with a single sequential
    // append so the per-realm HMAC key and head are cached.
    audit
        .append(&make_request(realm.clone(), 0))
        .expect("warm-up append");

    // Synchronise all threads so they are truly concurrent.
    let start_barrier = Arc::new(Barrier::new(N));

    let sync_before = storage_engine.wal_sync_count();

    let handles: Vec<_> = (0..N)
        .map(|i| {
            let audit = Arc::clone(&audit);
            let realm = realm.clone();
            let b = Arc::clone(&start_barrier);
            std::thread::spawn(move || {
                b.wait(); // all N threads start simultaneously
                audit
                    .append(&make_request(realm, i + 1))
                    .expect("concurrent append")
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread panicked");
    }

    let sync_after = storage_engine.wal_sync_count();
    let fsyncs = sync_after - sync_before;

    assert!(
        fsyncs < N as u64,
        "expected WAL fsyncs to coalesce: got {fsyncs} for {N} concurrent appends. \
         With the chain lock released before the fsync wait, concurrent appenders \
         should share a single group-commit batch (fsyncs < N). \
         If fsyncs == N the chain lock is still held across the fsync wait (HEA-1948)."
    );
}

// ---------------------------------------------------------------------------
// Test 2: chain integrity survives concurrent appends
// ---------------------------------------------------------------------------

/// After M concurrent appenders all commit successfully, the audit hash chain
/// must be intact: every event's `prev_hash` must match the preceding event's
/// `integrity_hash` and the signed head's HMAC must verify.
///
/// This is the correctness companion to `concurrent_appends_coalesce_fsyncs`:
/// the optimistic cache update (which happens under the chain lock before the
/// lock is released) must not corrupt the ordering or hashes even when appends
/// interleave with each other's fsync waits.
#[test]
fn concurrent_appends_preserve_chain_integrity() {
    const M: usize = 16;

    let tmp = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(PathBuf::from(tmp.path())))
            .expect("open storage"),
    ) as Arc<dyn StorageEngine>;
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let audit = Arc::new(EmbeddedAuditEngine::new(Arc::clone(&storage), clock));

    let realm = RealmId::generate();
    // Warm-up so chain head is initialised.
    audit
        .append(&make_request(realm.clone(), 0))
        .expect("warm-up append");

    let start_barrier = Arc::new(Barrier::new(M));

    let handles: Vec<_> = (0..M)
        .map(|i| {
            let audit = Arc::clone(&audit);
            let realm = realm.clone();
            let b = Arc::clone(&start_barrier);
            std::thread::spawn(move || {
                b.wait();
                audit.append(&make_request(realm, i + 1)).expect("append")
            })
        })
        .collect();

    let events: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().expect("thread panicked"))
        .collect();

    assert_eq!(events.len(), M, "all {M} appends must succeed");

    // verify_integrity re-reads every event from storage, recomputes the HMAC
    // hash chain from the genesis, and checks the signed head.
    let valid = audit
        .verify_integrity(&realm, None, None)
        .expect("verify_integrity must not fail");

    assert!(
        valid,
        "audit chain must pass integrity verification after {M} concurrent appends. \
         A false result means the prev_hash sequence was corrupted — the optimistic \
         cache update or enqueue ordering is incorrect (HEA-1948)."
    );

    // Sanity: all M+1 events (warm-up + M concurrent) must be queryable.
    let all = audit
        .query(&AuditQuery::for_realm(realm.clone()))
        .expect("query all events");
    assert_eq!(
        all.len(),
        M + 1,
        "expected {} events in the audit log, found {}",
        M + 1,
        all.len()
    );
}
