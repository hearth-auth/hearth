//! The memtable must apply writes in exactly the order the WAL records them,
//! and a record the WAL made durable must already be in the memtable
//! (audit GA 2026-09-28 M1, M2).
//!
//! Replay rebuilds the memtable from the WAL in WAL order. If two writers to
//! one key reach the memtable in one order and the WAL in the other, the node
//! serves one value until it restarts and the other after — for a session row
//! that is a revocation undone by a crash (M1).
//!
//! `enqueue_batch` used to queue its record for group commit *before* applying
//! it to the memtable. A looping leader could then make the record durable and
//! rotate the segment — flushing a memtable that did not yet hold it, then
//! truncating the only durable copy — before the enqueuing thread applied it.
//! The batch was acknowledged and lost at the next crash (M2).

use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use hearth::core::RealmId;
use hearth::storage::fs::{FileBacking, Fs, FsFile};
use hearth::storage::wal::{SyncMode, WalConfig};
use hearth::storage::{EmbeddedStorageEngine, RealFs, StorageConfig, StorageEngine};

/// A one-shot rendezvous: the parked thread signals `parked` and waits for
/// `release`.
struct Park {
    armed: AtomicBool,
    parked: Mutex<Option<mpsc::Sender<()>>>,
    release: (Mutex<bool>, Condvar),
}

impl Park {
    fn new() -> (Arc<Self>, mpsc::Receiver<()>) {
        let (tx, rx) = mpsc::channel();
        (
            Arc::new(Self {
                armed: AtomicBool::new(true),
                parked: Mutex::new(Some(tx)),
                release: (Mutex::new(false), Condvar::new()),
            }),
            rx,
        )
    }

    /// Parks the first caller only.
    fn hook(self: &Arc<Self>) -> Arc<dyn Fn() + Send + Sync> {
        let park = Arc::clone(self);
        Arc::new(move || {
            if !park.armed.swap(false, Ordering::SeqCst) {
                return;
            }
            if let Some(tx) = park.parked.lock().expect("parked").take() {
                let _ = tx.send(());
            }
            let (lock, cv) = &park.release;
            let mut go = lock.lock().expect("release");
            while !*go {
                go = cv.wait(go).expect("release wait");
            }
        })
    }

    fn release(&self) {
        let (lock, cv) = &self.release;
        *lock.lock().expect("release") = true;
        cv.notify_all();
    }
}

fn production_like_config(dir: &Path, wal_max: u64) -> StorageConfig {
    let mut config = StorageConfig::dev(dir.to_path_buf());
    config.wal_config = WalConfig {
        max_size: wal_max,
        sync_mode: SyncMode::EveryWrite,
    };
    config
}

/// Runs `first` on a thread that parks just before its record enters the WAL,
/// runs `second` to completion on this thread, releases `first`, then crashes
/// (drops the engine without a flush) and reopens. Returns the value served
/// before the crash and the value replay restored.
fn race_two_writers_to_one_key(
    first: impl FnOnce(&EmbeddedStorageEngine, &RealmId) + Send + 'static,
    second: impl FnOnce(&EmbeddedStorageEngine, &RealmId),
) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let realm = RealmId::generate();
    let live = {
        let engine = Arc::new(
            EmbeddedStorageEngine::open(production_like_config(dir.path(), 64 * 1024 * 1024))
                .expect("open"),
        );
        let (park, parked) = Park::new();
        engine.set_pre_wal_hook(park.hook());

        let writer = {
            let engine = Arc::clone(&engine);
            let realm = realm.clone();
            std::thread::spawn(move || first(&engine, &realm))
        };
        parked
            .recv_timeout(Duration::from_secs(10))
            .expect("the first writer never reached the WAL");

        second(&engine, &realm);
        park.release();
        writer.join().expect("first writer");

        engine.get(&realm, b"k").expect("get before the crash")
        // Dropped without a flush: only the WAL carries these writes.
    };

    let engine =
        EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf())).expect("reopen");
    let replayed = engine.get(&realm, b"k").expect("get after replay");
    (live, replayed)
}

#[test]
fn concurrent_puts_to_one_key_serve_the_same_value_before_and_after_a_crash() {
    let (live, replayed) = race_two_writers_to_one_key(
        |engine, realm| engine.put(realm, b"k", b"first").expect("put first"),
        |engine, realm| engine.put(realm, b"k", b"second").expect("put second"),
    );
    assert_eq!(
        live, replayed,
        "the node served {live:?} but replay restored {replayed:?}: the memtable and the WAL \
         ordered the two writes differently"
    );
}

#[test]
fn a_delete_racing_a_put_is_not_undone_by_a_crash() {
    // The revocation shape: a stale put and a delete of the same row.
    let (live, replayed) = race_two_writers_to_one_key(
        |engine, realm| engine.put(realm, b"k", b"stale").expect("put stale"),
        |engine, realm| engine.delete(realm, b"k").expect("delete"),
    );
    assert_eq!(
        live, replayed,
        "the node served {live:?} but replay restored {replayed:?}"
    );
}

// ── M2: enqueue_batch ─────────────────────────────────────────────────────────

/// Wraps [`RealFs`]; while the gate is closed, the first WAL `sync_data`
/// blocks (after signalling that it has started) until the gate opens.
struct GateFs {
    gate: Arc<Gate>,
}

struct Gate {
    closed: Mutex<bool>,
    cv: Condvar,
    entered: Mutex<Option<mpsc::Sender<()>>>,
}

impl Gate {
    fn open(&self) {
        *self.closed.lock().expect("gate") = false;
        self.cv.notify_all();
    }
}

struct GateFile {
    inner: Box<dyn FsFile>,
    gate: Arc<Gate>,
}

impl FsFile for GateFile {
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.inner.write_all(buf)
    }
    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        self.inner.read_to_end(buf)
    }
    fn sync_all(&self) -> io::Result<()> {
        self.inner.sync_all()
    }
    fn sync_data(&self) -> io::Result<()> {
        if let Some(tx) = self.gate.entered.lock().expect("entered").take() {
            let _ = tx.send(());
        }
        let mut closed = self.gate.closed.lock().expect("gate");
        while *closed {
            closed = self.gate.cv.wait(closed).expect("gate wait");
        }
        drop(closed);
        self.inner.sync_data()
    }
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
    fn set_len(&self, size: u64) -> io::Result<()> {
        self.inner.set_len(size)
    }
}

impl Fs for GateFs {
    fn open_append(&self, path: &Path) -> io::Result<Box<dyn FsFile>> {
        Ok(Box::new(GateFile {
            inner: RealFs.open_append(path)?,
            gate: Arc::clone(&self.gate),
        }))
    }
    fn create(&self, path: &Path) -> io::Result<Box<dyn FsFile>> {
        Ok(Box::new(GateFile {
            inner: RealFs.create(path)?,
            gate: Arc::clone(&self.gate),
        }))
    }
    fn open_read(&self, path: &Path) -> io::Result<Box<dyn FsFile>> {
        RealFs.open_read(path)
    }
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        RealFs.read(path)
    }
    fn read_prefix(&self, path: &Path, len: usize) -> io::Result<Vec<u8>> {
        RealFs.read_prefix(path, len)
    }
    fn map_readonly(&self, path: &Path) -> io::Result<FileBacking> {
        RealFs.map_readonly(path)
    }
    fn write(&self, path: &Path, data: &[u8]) -> io::Result<()> {
        RealFs.write(path, data)
    }
    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        RealFs.create_dir_all(path)
    }
    fn read_dir(&self, path: &Path) -> io::Result<Vec<std::path::PathBuf>> {
        RealFs.read_dir(path)
    }
    fn remove_file(&self, path: &Path) -> io::Result<()> {
        RealFs.remove_file(path)
    }
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        RealFs.rename(from, to)
    }
    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        RealFs.sync_dir(dir)
    }
}

/// M2: a follower's `enqueue_batch` record is committed by the looping leader
/// and a rotation truncates its segment while the follower is between its
/// enqueue and its memtable apply. The batch is then acknowledged — and must
/// survive a crash.
#[test]
fn an_acknowledged_enqueued_batch_survives_a_rotation_that_overtakes_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let realm = RealmId::generate();

    {
        let (entered_tx, entered_rx) = mpsc::channel();
        let gate = Arc::new(Gate {
            closed: Mutex::new(true),
            cv: Condvar::new(),
            entered: Mutex::new(Some(entered_tx)),
        });
        let engine = Arc::new(
            EmbeddedStorageEngine::open_with_fs(
                production_like_config(dir.path(), 4096),
                Arc::new(GateFs {
                    gate: Arc::clone(&gate),
                }),
            )
            .expect("open"),
        );
        let (park, parked) = Park::new();
        engine.set_post_enqueue_hook(park.hook());

        // 1. A leader is inside its fsync, so the next enqueue is a follower.
        let leader = {
            let engine = Arc::clone(&engine);
            let realm = realm.clone();
            std::thread::spawn(move || engine.put(&realm, b"leader", b"x").expect("leader put"))
        };
        entered_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the leader never reached its fsync");

        // 2. The follower enqueues its batch and parks before returning.
        let follower = {
            let engine = Arc::clone(&engine);
            let realm = realm.clone();
            std::thread::spawn(move || {
                let handle = engine
                    .enqueue_batch(&realm, &[(b"batch-key".to_vec(), b"acked".to_vec())])
                    .expect("enqueue");
                engine
                    .await_batch_durable(handle)
                    .expect("the batch is acknowledged");
            })
        };
        parked
            .recv_timeout(Duration::from_secs(10))
            .expect("the follower never enqueued");

        // 3. The looping leader commits the follower's record, then drains.
        gate.open();
        leader.join().expect("leader");

        // 4. Rotate the segment: a flush of the memtable, then a truncation of
        //    the segment that holds the follower's record.
        for i in 0u32..200 {
            engine
                .put(&realm, format!("filler-{i:04}").as_bytes(), &[0u8; 64])
                .expect("filler put");
        }
        let ssts = std::fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(Result::ok)
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "sst"))
            .count();
        assert!(ssts >= 1, "the filler writes must have rotated the WAL");

        // 5. The follower finishes and is acknowledged.
        park.release();
        follower.join().expect("follower");
        // Crash: no flush.
    }

    let engine =
        EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf())).expect("reopen");
    assert_eq!(
        engine.get(&realm, b"batch-key").expect("get"),
        Some(b"acked".to_vec()),
        "an acknowledged enqueue_batch record was lost: the rotation flushed a memtable \
         that did not yet hold it, then truncated its only durable copy"
    );
}
