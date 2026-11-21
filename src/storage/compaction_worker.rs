//! Count-triggered compaction for a store that no server runs (#912).
//!
//! `hearth serve` runs a background task that merges SSTs whenever a flush
//! leaves [`CompactionConfig::max_sst_count`](super::CompactionConfig) or
//! more of them. `hearth backup restore` opened the store without that task,
//! so a restore of 10M users left about 260 SSTs, and every write of a new key
//! probed all of them: the restore slowed down as the store grew. A
//! [`CompactionWorker`] runs the same partial compaction on its own thread
//! while an offline command writes.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use tokio::sync::Notify;

use super::{EmbeddedStorageEngine, StorageError};

/// Merges the SSTs of a store on a background thread whenever a flush asks
/// for it, until stopped.
///
/// The merge is the one the server's task runs ([`compact_partial`]): it
/// holds no lock that writers wait on except for its short commit, so the
/// writing thread goes on while the worker merges on another core. Dropping
/// a worker stops it too.
///
/// [`compact_partial`]: EmbeddedStorageEngine::compact_partial
pub struct CompactionWorker {
    /// Wakes the worker to stop.
    stop: Arc<Notify>,
    /// Set once the worker is to stop: it starts no further merge.
    stopping: Arc<AtomicBool>,
    thread: Option<JoinHandle<Result<usize, StorageError>>>,
}

impl CompactionWorker {
    /// Starts a worker for `engine` on a new thread.
    ///
    /// # Errors
    ///
    /// [`StorageError::Io`] when the thread cannot be started.
    pub fn start(engine: Arc<EmbeddedStorageEngine>) -> Result<Self, StorageError> {
        let stop = Arc::new(Notify::new());
        let stopping = Arc::new(AtomicBool::new(false));
        let thread = std::thread::Builder::new()
            .name("hearth-compact".to_string())
            .spawn({
                let stop = Arc::clone(&stop);
                let stopping = Arc::clone(&stopping);
                move || run(&engine, &stop, &stopping)
            })?;
        Ok(Self {
            stop,
            stopping,
            thread: Some(thread),
        })
    }

    /// Stops the worker once its current merge is done, and returns the
    /// SSTs it merged in all.
    ///
    /// # Errors
    ///
    /// The error of the merge that stopped the worker early. The store is
    /// still whole: a merge that fails changes nothing.
    pub fn stop(mut self) -> Result<usize, StorageError> {
        self.join()
    }

    fn join(&mut self) -> Result<usize, StorageError> {
        self.stopping.store(true, Ordering::Release);
        self.stop.notify_one();
        match self.thread.take() {
            Some(thread) => thread.join().unwrap_or_else(|_| {
                Err(StorageError::Io(std::io::Error::other(
                    "the compaction worker panicked",
                )))
            }),
            None => Ok(0),
        }
    }
}

impl Drop for CompactionWorker {
    fn drop(&mut self) {
        if let Err(e) = self.join() {
            tracing::warn!(error = %e, "background SST compaction failed");
        }
    }
}

/// The worker's loop: on each wake from a flush, merges until no size tier
/// has enough SSTs to merge, or the worker is to stop.
fn run(
    engine: &EmbeddedStorageEngine,
    stop: &Notify,
    stopping: &AtomicBool,
) -> Result<usize, StorageError> {
    let wake = engine.compaction_notify();
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    runtime.block_on(async {
        let mut merged = 0;
        loop {
            tokio::select! {
                biased;
                () = stop.notified() => return Ok(merged),
                () = wake.notified() => {}
            }
            while !stopping.load(Ordering::Acquire) {
                let n = engine.compact_partial()?;
                if n == 0 {
                    break;
                }
                merged += n;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::RealmId;
    use crate::storage::{CompactionConfig, StorageConfig, StorageEngine};

    fn sst_count(dir: &std::path::Path) -> usize {
        std::fs::read_dir(dir)
            .expect("read data dir")
            .filter(|e| {
                e.as_ref()
                    .is_ok_and(|e| e.path().extension().is_some_and(|x| x == "sst"))
            })
            .count()
    }

    /// A store with a small memtable and the default count trigger.
    fn open(dir: &std::path::Path) -> Arc<EmbeddedStorageEngine> {
        let mut config = StorageConfig::dev(dir.to_path_buf());
        config.set_memtable_flush_bytes(16 * 1024);
        config.compaction = CompactionConfig {
            interval_secs: 0,
            ..CompactionConfig::default()
        };
        Arc::new(EmbeddedStorageEngine::open(config).expect("open storage"))
    }

    /// Writes `rounds` memtables' worth of new keys into `realm`.
    fn bulk_write(engine: &EmbeddedStorageEngine, realm: &RealmId, rounds: u32) {
        for i in 0..rounds * 64 {
            let rows: Vec<(Vec<u8>, Vec<u8>)> = (0..4)
                .map(|j| (format!("k{i:08}-{j}").into_bytes(), vec![b'v'; 64]))
                .collect();
            engine.put_batch(realm, &rows).expect("write");
        }
    }

    /// Waits up to 30 s for `dir` to hold at most `bound` SSTs.
    fn wait_for_ssts_at_most(dir: &std::path::Path, bound: usize) -> usize {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let n = sst_count(dir);
            if n <= bound || std::time::Instant::now() > deadline {
                return n;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    /// Without a worker, an offline bulk write leaves one SST per flushed
    /// memtable; with one, the count stays near the trigger, and every key
    /// is still there.
    #[test]
    fn a_worker_keeps_the_sst_count_of_a_bulk_write_bounded() {
        let realm = RealmId::new(uuid::Uuid::from_u128(912));

        let control_dir = tempfile::tempdir().expect("tempdir");
        let control = open(control_dir.path());
        bulk_write(&control, &realm, 48);
        let without = sst_count(control_dir.path());
        assert!(without >= 40, "the control flushed {without} SSTs");

        let dir = tempfile::tempdir().expect("tempdir");
        let engine = open(dir.path());
        let worker = CompactionWorker::start(Arc::clone(&engine)).expect("start");
        bulk_write(&engine, &realm, 48);
        let with = wait_for_ssts_at_most(dir.path(), 16);
        let merged = worker.stop().expect("the worker's merges succeed");

        assert!(with <= 16, "{with} SSTs with a worker, {without} without");
        assert!(merged > 0, "the worker merged no SST");
        for i in (0..48 * 64).step_by(97) {
            let key = format!("k{i:08}-3").into_bytes();
            assert!(
                engine.get(&realm, &key).expect("get").is_some(),
                "key {i} is lost"
            );
        }
    }

    /// A worker of a store that is never written stops at once.
    #[test]
    fn a_worker_with_nothing_to_merge_stops() {
        let dir = tempfile::tempdir().expect("tempdir");
        let worker = CompactionWorker::start(open(dir.path())).expect("start");
        assert_eq!(worker.stop().expect("stop"), 0);
    }
}
