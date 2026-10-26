//! A disk-write stall under steady load must not leave the server with
//! hundreds of extra threads (#596; #581 part 1).
//!
//! On a single node, the storage adapter runs a write inside
//! `tokio::task::block_in_place`, which hands the runtime worker's other tasks
//! to a blocking-pool thread. A handler that runs in `spawn_blocking` holds a
//! pool thread for its whole write. While the disk completes no sync, each
//! write that arrives waits and holds its own thread. After the stall, the
//! steady load wakes the pool's idle threads in turn, so no idle thread reaches
//! Tokio's 10 s keep-alive and the pool never shrinks: the steady-state memory
//! run 40124528097 went from 148 to 523 threads in one 9 s stall and kept them.
//!
//! The test runs the production write path (a single-node `ClusterEngine`
//! behind `ClusterStorageAdapter`, WAL fsync on every write) on `FaultFs`, under
//! an open-loop load shaped like the server's requests: half the writes on
//! runtime workers, half in `spawn_blocking`. It makes the syncs slow until
//! `STALL_WAITERS` writes wait, then counts the process's threads while the
//! load goes on.

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hearth::cluster::{ClusterEngine, ClusterStorageAdapter};
use hearth::core::RealmId;
use hearth::storage::wal::SyncMode;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

use crate::{FaultConfig, FaultFs};

/// Gap between two writes of the open-loop load: 400 writes per second.
const LOAD_INTERVAL: Duration = Duration::from_micros(2_500);
/// Length of each slow sync. About 300 writes arrive during the first one.
const STALL_SYNC_US: u64 = 750_000;
/// Writes waiting at the same time that end the stall: later syncs are fast.
const STALL_WAITERS: usize = 200;
/// A write that took at least this long waited for a slow sync.
const SLOW_WRITE: Duration = Duration::from_micros(STALL_SYNC_US / 2);
/// Threads more than the count before the stall that may stay after it.
const EXTRA_THREADS_ALLOWED: usize = 64;
/// Time after the stall for the thread count to come down: two of Tokio's
/// 10 s blocking-pool keep-alive periods.
const SETTLE_DEADLINE: Duration = Duration::from_secs(20);

/// Counters of the open-loop load.
#[derive(Default)]
struct Load {
    completed: AtomicU64,
    in_flight: AtomicUsize,
    slow: AtomicU64,
    failed: AtomicU64,
    stop: AtomicBool,
}

/// The storage stack that `serve` builds on a single node, on `fs`.
fn open_single_node_storage(dir: &Path, fs: Arc<FaultFs>) -> Arc<dyn StorageEngine> {
    let mut config = StorageConfig::dev(dir.to_path_buf());
    config.wal_config.sync_mode = SyncMode::EveryWrite;
    let inner = Arc::new(EmbeddedStorageEngine::open_with_fs(config, fs).expect("open storage"));
    Arc::new(ClusterStorageAdapter::new(Arc::new(
        ClusterEngine::single_node(inner),
    )))
}

/// The process's thread count, from `/proc/self/status`.
fn thread_count() -> usize {
    let status = std::fs::read_to_string("/proc/self/status").expect("read /proc/self/status");
    status
        .lines()
        .find_map(|line| line.strip_prefix("Threads:"))
        .and_then(|count| count.trim().parse().ok())
        .expect("a Threads: line in /proc/self/status")
}

/// Calls `done` until it returns true or `deadline` passes. Returns whether
/// it returned true.
fn wait_until(deadline: Duration, mut done: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + deadline;
    loop {
        if done() {
            return true;
        }
        if Instant::now() >= end {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10)); // AUDIT: justified-sleep: polling a thread count and load counters, which give no event to wait on
    }
}

/// Starts one write each `LOAD_INTERVAL` until `load.stop` is set, without
/// waiting for earlier writes: requests arrive whether or not the disk keeps
/// up. Even writes run on a runtime worker, odd ones in `spawn_blocking`.
async fn run_load(storage: Arc<dyn StorageEngine>, realm: RealmId, load: Arc<Load>) {
    let mut ticks = tokio::time::interval(LOAD_INTERVAL);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut n: u64 = 0;
    while !load.stop.load(Ordering::SeqCst) {
        ticks.tick().await;
        n += 1;
        let (storage, realm, load) = (Arc::clone(&storage), realm.clone(), Arc::clone(&load));
        let key = format!("stall:{n}").into_bytes();
        load.in_flight.fetch_add(1, Ordering::SeqCst);
        tokio::spawn(async move {
            let start = Instant::now();
            let write = move || storage.put(&realm, &key, b"v");
            let result = if n % 2 == 0 {
                write()
            } else {
                tokio::task::spawn_blocking(write)
                    .await
                    .expect("spawn_blocking write")
            };
            if result.is_err() {
                load.failed.fetch_add(1, Ordering::SeqCst);
            }
            if start.elapsed() >= SLOW_WRITE {
                load.slow.fetch_add(1, Ordering::SeqCst);
            }
            load.completed.fetch_add(1, Ordering::SeqCst);
            load.in_flight.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

#[test]
fn a_write_stall_does_not_leave_hundreds_of_extra_threads() {
    let dir = tempfile::tempdir().expect("tempdir");
    let faults = FaultConfig::default();
    let storage =
        open_single_node_storage(dir.path(), Arc::new(FaultFs::with_config(faults.clone())));
    let realm = RealmId::generate();
    let load = Arc::new(Load::default());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("runtime");
    runtime.spawn(run_load(
        Arc::clone(&storage),
        realm.clone(),
        Arc::clone(&load),
    ));

    // Before: the pool has the threads that the steady load needs.
    let warmed_up = wait_until(Duration::from_secs(30), || {
        load.completed.load(Ordering::SeqCst) >= 1_000
    });
    assert!(
        warmed_up,
        "the load completed fewer than 1,000 writes in 30 s"
    );
    let before = thread_count();

    // The stall: syncs are slow until STALL_WAITERS writes wait (or 3 s).
    let mut peak = before;
    faults
        .sync_latency_us
        .store(STALL_SYNC_US, Ordering::SeqCst);
    wait_until(Duration::from_secs(3), || {
        peak = peak.max(thread_count());
        load.in_flight.load(Ordering::SeqCst) >= STALL_WAITERS
    });
    faults.sync_latency_us.store(0, Ordering::SeqCst);
    let drained = wait_until(Duration::from_secs(30), || {
        peak = peak.max(thread_count());
        load.in_flight.load(Ordering::SeqCst) < 50
    });

    // After: the load goes on, and the thread count must come back down.
    let mut after = thread_count();
    let settled = wait_until(SETTLE_DEADLINE, || {
        after = thread_count();
        after <= before + EXTRA_THREADS_ALLOWED
    });

    load.stop.store(true, Ordering::SeqCst);
    wait_until(Duration::from_secs(30), || {
        load.in_flight.load(Ordering::SeqCst) == 0
    });
    let final_write = runtime.block_on(async move {
        tokio::spawn(async move { storage.put(&realm, b"after-the-stall", b"v") })
            .await
            .expect("final write task")
    });
    runtime.shutdown_timeout(Duration::from_secs(10));

    assert!(
        drained,
        "the writes that waited for the slow sync did not finish"
    );
    assert!(
        load.slow.load(Ordering::SeqCst) > 0,
        "no write waited for a slow sync, so the test did not stall the disk"
    );
    final_write.expect("a write after the stall must succeed");
    assert!(
        settled,
        "{after} threads {SETTLE_DEADLINE:?} after a write stall, {before} before it \
         (peak {peak}, {} failed writes): at most {EXTRA_THREADS_ALLOWED} extra threads \
         may stay (#596)",
        load.failed.load(Ordering::SeqCst)
    );
}
