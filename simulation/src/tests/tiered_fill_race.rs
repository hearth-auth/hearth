//! Hot-tier fill/invalidation race (audit 2026-08-28 §4.21#3).
//!
//! A cold read fills the hot tier *after* it reads the authoritative
//! memtable/SST value. A `delete` or `put` that lands between those two
//! steps invalidates the hot tier while the key is not yet cached — a
//! no-op — and the parked fill then installs the pre-delete value. Every
//! later `get` hits the hot tier, so the stale value is served for the
//! life of the process: a revoked credential stays readable until restart.
//!
//! The test parks a reader at exactly that point with the engine's
//! `pre_promote` test hook, drives the delete from the main thread, and
//! asserts the delete stays visible.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};

use hearth::core::RealmId;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

#[test]
fn simulation_delete_racing_hot_tier_fill_stays_deleted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let realm = RealmId::generate();

    let config = StorageConfig::dev(dir.path().to_path_buf());
    let engine = Arc::new(EmbeddedStorageEngine::open(config).expect("open"));

    // The credential exists and is not yet in the hot tier: writes only
    // invalidate, and nothing has read the key yet.
    engine.put(&realm, b"cred:token", b"live").expect("put");

    // Park the reader at the fill point: after it has read "live" from the
    // memtable, before it promotes into the hot tier. Only the first fill
    // parks; later fills pass through.
    let (parked_tx, parked_rx) = mpsc::channel::<()>();
    let (resume_tx, resume_rx) = mpsc::channel::<()>();
    let resume_rx = Mutex::new(resume_rx); // Receiver is !Sync; the hook is Fn
    let fired = AtomicBool::new(false);
    engine.set_pre_promote_hook(Arc::new(move || {
        if fired.swap(true, Ordering::SeqCst) {
            return;
        }
        parked_tx.send(()).expect("signal parked");
        let _ = resume_rx.lock().expect("resume rx lock").recv();
    }));

    // Reader: a cold read that will park mid-fill.
    let reader = {
        let engine = Arc::clone(&engine);
        let realm = realm.clone();
        std::thread::spawn(move || engine.get(&realm, b"cred:token").expect("get"))
    };

    parked_rx.recv().expect("reader reaches the fill point");

    // The delete lands while the reader sits between its memtable read and
    // its hot-tier fill.
    engine.delete(&realm, b"cred:token").expect("delete");

    resume_tx.send(()).expect("resume reader");
    let read_before_delete = reader.join().expect("reader thread");

    // The reader legitimately observed the pre-delete value.
    assert_eq!(read_before_delete.as_deref(), Some(b"live" as &[u8]));

    // The delete must be visible to every subsequent read for the life of
    // the process. Before the fix, the parked fill installed "live" into
    // the hot tier after the invalidation and it stayed readable forever.
    for attempt in 0..3 {
        assert_eq!(
            engine.get(&realm, b"cred:token").expect("get"),
            None,
            "deleted key served from a stale hot-tier fill on read {attempt} (audit §4.21#3)"
        );
    }
}

#[test]
fn simulation_update_racing_hot_tier_fill_serves_new_value() {
    let dir = tempfile::tempdir().expect("tempdir");
    let realm = RealmId::generate();

    let config = StorageConfig::dev(dir.path().to_path_buf());
    let engine = Arc::new(EmbeddedStorageEngine::open(config).expect("open"));

    engine.put(&realm, b"cred:token", b"v1").expect("put");

    let (parked_tx, parked_rx) = mpsc::channel::<()>();
    let (resume_tx, resume_rx) = mpsc::channel::<()>();
    let resume_rx = Mutex::new(resume_rx);
    let fired = AtomicBool::new(false);
    engine.set_pre_promote_hook(Arc::new(move || {
        if fired.swap(true, Ordering::SeqCst) {
            return;
        }
        parked_tx.send(()).expect("signal parked");
        let _ = resume_rx.lock().expect("resume rx lock").recv();
    }));

    let reader = {
        let engine = Arc::clone(&engine);
        let realm = realm.clone();
        std::thread::spawn(move || engine.get(&realm, b"cred:token").expect("get"))
    };

    parked_rx.recv().expect("reader reaches the fill point");

    // The update lands while the reader sits inside the fill window.
    engine.put(&realm, b"cred:token", b"v2").expect("put v2");

    resume_tx.send(()).expect("resume reader");
    let read_before_update = reader.join().expect("reader thread");
    assert_eq!(read_before_update.as_deref(), Some(b"v1" as &[u8]));

    // The stale fill must not shadow the newer value.
    for attempt in 0..3 {
        assert_eq!(
            engine.get(&realm, b"cred:token").expect("get").as_deref(),
            Some(b"v2" as &[u8]),
            "updated key served a stale hot-tier fill on read {attempt} (audit §4.21#3)"
        );
    }
}
