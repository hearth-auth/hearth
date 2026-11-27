//! The snapshot install fence (`cluster-consistency` R3, R4; tasks 3.1, 3.2).
//!
//! An install deletes every key (Phase 1), writes the snapshot (Phase 2) and
//! rebuilds node-local caches (`on_replicated_reset`). A read anywhere in
//! that window would see partial state, so the gate is closed before Phase 1
//! and reopens only through a contact after the install.
//!
//! The storage stub records whether the gate allowed a read when Phase 2
//! starts, which is the point between the two phases; the observer stub
//! records it when the cache rebuild runs, and what the store it is handed
//! holds then.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use openraft::storage::{RaftSnapshotBuilder as _, RaftStateMachine as _};
use openraft::{CommittedLeaderId, Entry, EntryPayload, LogId, Snapshot};
use tempfile::tempdir;
use uuid::Uuid;

use super::HearthStateMachine;
use crate::cluster::read_gate::{ReadGate, Refusal};
use crate::cluster::types::{HearthRaftConfig, RaftCommand};
use crate::cluster::ReplicatedWriteObserver;
use crate::core::RealmId;
use crate::storage::{
    EmbeddedStorageEngine, ScanEntry, StorageConfig, StorageDurabilityHandle, StorageEngine,
    StorageError,
};

/// Local storage that records the gate when Phase 2 starts, and can fail
/// there. Every call passes straight through otherwise.
struct PhaseStorage {
    inner: Arc<dyn StorageEngine>,
    gate: Arc<ReadGate>,
    /// Whether the gate allowed a read at each Phase 2 write.
    seen_between_phases: Mutex<Vec<bool>>,
    fail_phase_two: AtomicBool,
}

impl StorageEngine for PhaseStorage {
    fn get(&self, realm_id: &RealmId, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.get(realm_id, key)
    }

    fn put(&self, realm_id: &RealmId, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        self.inner.put(realm_id, key, value)
    }

    fn delete(&self, realm_id: &RealmId, key: &[u8]) -> Result<(), StorageError> {
        self.inner.delete(realm_id, key)
    }

    fn scan(
        &self,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
    ) -> Result<Vec<ScanEntry>, StorageError> {
        self.inner.scan(realm_id, start, end)
    }

    fn put_batch(
        &self,
        realm_id: &RealmId,
        entries: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<(), StorageError> {
        self.seen_between_phases
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(self.gate.allows());
        if self.fail_phase_two.load(Ordering::SeqCst) {
            return Err(StorageError::Io(std::io::Error::other("phase 2 fails")));
        }
        self.inner.put_batch(realm_id, entries)
    }

    fn write_batch(
        &self,
        realm_id: &RealmId,
        puts: &[(Vec<u8>, Vec<u8>)],
        deletes: &[Vec<u8>],
    ) -> Result<(), StorageError> {
        self.inner.write_batch(realm_id, puts, deletes)
    }

    fn put_if_absent(
        &self,
        realm_id: &RealmId,
        key: &[u8],
        value: &[u8],
    ) -> Result<bool, StorageError> {
        self.inner.put_if_absent(realm_id, key, value)
    }

    fn increment_u64(&self, realm_id: &RealmId, key: &[u8]) -> Result<u64, StorageError> {
        self.inner.increment_u64(realm_id, key)
    }

    fn enqueue_batch(
        &self,
        realm_id: &RealmId,
        entries: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<StorageDurabilityHandle, StorageError> {
        self.inner.enqueue_batch(realm_id, entries)
    }

    fn await_batch_durable(&self, handle: StorageDurabilityHandle) -> Result<(), StorageError> {
        self.inner.await_batch_durable(handle)
    }

    fn list_realms(&self) -> Result<Vec<RealmId>, StorageError> {
        self.inner.list_realms()
    }

    fn begin_snapshot_restore(&self, snapshot_id: &str) -> Result<(), StorageError> {
        self.inner.begin_snapshot_restore(snapshot_id)
    }

    fn complete_snapshot_restore(&self) -> Result<(), StorageError> {
        self.inner.complete_snapshot_restore()
    }
}

/// Records whether the gate allowed a read while caches were rebuilt, and
/// the snapshot's key as the store handed to the rebuild reads it. Fails
/// the rebuild while `fail` is set.
struct ResetObserver {
    gate: Arc<ReadGate>,
    seen_at_reset: Mutex<Vec<bool>>,
    read_at_reset: Mutex<Vec<Option<Vec<u8>>>>,
    fail: AtomicBool,
}

impl ReplicatedWriteObserver for ResetObserver {
    fn on_replicated_put(&self, _: &RealmId, _: &[u8], _: &[u8]) {}
    fn on_replicated_delete(&self, _: &RealmId, _: &[u8]) {}
    fn on_replicated_reset(
        &self,
        store: &dyn StorageEngine,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.seen_at_reset
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(self.gate.allows());
        let read = store.get(&RealmId::new(Uuid::from_u128(7)), b"new")?;
        self.read_at_reset
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(read);
        if self.fail.load(Ordering::SeqCst) {
            return Err("rebuild fails".into());
        }
        Ok(())
    }
    fn on_leadership_acquired(&self) {}
}

struct Fixture {
    dirs: [tempfile::TempDir; 2],
    gate: Arc<ReadGate>,
    storage: Arc<PhaseStorage>,
    observer: Arc<ResetObserver>,
    sm: HearthStateMachine,
}

/// A follower state machine with one applied key (so Phase 1 deletes
/// something), behind the stubs, and an open gate.
async fn fixture() -> Fixture {
    let dir = tempdir().expect("tempdir");
    let gate = Arc::new(ReadGate::new(60_000));
    let engine = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf())).expect("open"),
    );
    let observer = Arc::new(ResetObserver {
        gate: Arc::clone(&gate),
        seen_at_reset: Mutex::new(Vec::new()),
        read_at_reset: Mutex::new(Vec::new()),
        fail: AtomicBool::new(false),
    });
    let slot: Arc<OnceLock<Arc<dyn ReplicatedWriteObserver>>> = Arc::new(OnceLock::new());
    let _ = slot.set(Arc::clone(&observer) as Arc<dyn ReplicatedWriteObserver>);
    let mut sm = HearthStateMachine::with_observer_slot(engine, slot)
        .expect("state machine")
        .with_read_gate(Arc::clone(&gate));
    // The state machine opens its snapshot store from the concrete engine;
    // its reads and writes then go through the stub.
    let storage = Arc::new(PhaseStorage {
        inner: Arc::clone(&sm.engine),
        gate: Arc::clone(&gate),
        seen_between_phases: Mutex::new(Vec::new()),
        fail_phase_two: AtomicBool::new(false),
    });
    sm.engine = Arc::clone(&storage) as Arc<dyn StorageEngine>;
    sm.apply([put_entry(1, b"old")]).await.expect("apply");
    gate.record_contact_at(gate.now_ms());
    assert!(gate.allows(), "precondition: the follower is in contact");
    let source = tempdir().expect("tempdir");
    Fixture {
        dirs: [dir, source],
        gate,
        storage,
        observer,
        sm,
    }
}

fn put_entry(index: u64, key: &[u8]) -> Entry<HearthRaftConfig> {
    Entry {
        log_id: LogId::new(CommittedLeaderId::new(1, 0), index),
        payload: EntryPayload::Normal(RaftCommand::Put {
            leader_timestamp: 0,
            realm: RealmId::new(Uuid::from_u128(7)),
            key: key.to_vec(),
            value: b"v".to_vec(),
        }),
    }
}

/// A snapshot through log index 9 from another node.
async fn snapshot_from(dir: &std::path::Path) -> Snapshot<HearthRaftConfig> {
    let engine = EmbeddedStorageEngine::open(StorageConfig::dev(dir.to_path_buf())).expect("open");
    let mut source = HearthStateMachine::new(Arc::new(engine)).expect("state machine");
    source.apply([put_entry(9, b"new")]).await.expect("apply");
    source
        .get_snapshot_builder()
        .await
        .build_snapshot()
        .await
        .expect("snapshot")
}

fn seen(log: &Mutex<Vec<bool>>) -> Vec<bool> {
    log.lock().unwrap_or_else(PoisonError::into_inner).clone()
}

/// Tasks 3.1 and 3.2: the gate is closed between the phases and while
/// caches are rebuilt, stays closed after the install, drops the contact
/// waiting for its apply, and reopens on the next contact.
#[tokio::test]
async fn an_install_fences_reads_until_a_contact_after_it() {
    let mut f = fixture().await;
    let snap = snapshot_from(f.dirs[1].path()).await;
    // A contact waiting for commit index 9, which the snapshot reaches.
    f.gate.record_contact_once_applied(f.gate.now_ms(), Some(9));

    let snap = super::tests::transfer(&mut f.sm, snap).await;
    f.sm.install_snapshot(&snap.meta, snap.snapshot)
        .await
        .expect("install");

    assert_eq!(seen(&f.storage.seen_between_phases), [false]);
    assert_eq!(seen(&f.observer.seen_at_reset), [false]);
    assert_eq!(
        *f.observer
            .read_at_reset
            .lock()
            .unwrap_or_else(PoisonError::into_inner),
        [Some(b"v".to_vec())],
        "the rebuild reads the installed snapshot through the gate it closed"
    );
    assert!(!f.gate.allows(), "the end of an install opens nothing");
    assert_eq!(
        f.gate.refusal_at(f.gate.now_ms()),
        Some(Refusal::NotInContact)
    );
    f.gate.record_contact_once_applied(f.gate.now_ms(), Some(9));
    assert!(f.gate.allows(), "a contact after the install reopens it");
}

/// Task 3.2: a failed install leaves the gate closed.
#[tokio::test]
async fn a_failed_install_leaves_the_gate_closed() {
    let mut f = fixture().await;
    let snap = snapshot_from(f.dirs[1].path()).await;
    let snap = super::tests::transfer(&mut f.sm, snap).await;
    f.storage.fail_phase_two.store(true, Ordering::SeqCst);

    let result = f.sm.install_snapshot(&snap.meta, snap.snapshot).await;

    assert!(
        result.is_err_and(|e| e.to_string().contains("phase 2 fails")),
        "the stub fails Phase 2"
    );
    f.gate.record_contact_at(f.gate.now_ms());
    assert!(!f.gate.allows(), "no contact reopens a failed install");
    assert_eq!(
        f.gate.refusal_at(f.gate.now_ms()),
        Some(Refusal::InstallingSnapshot)
    );
}

/// `cluster-consistency` R4: a failed cache rebuild fails the install and
/// leaves the gate closed. A node that reopened then would serve credentials
/// from caches that predate the snapshot.
#[tokio::test]
async fn a_failed_cache_rebuild_fails_the_install_and_leaves_the_gate_closed() {
    let mut f = fixture().await;
    let snap = snapshot_from(f.dirs[1].path()).await;
    let snap = super::tests::transfer(&mut f.sm, snap).await;
    f.observer.fail.store(true, Ordering::SeqCst);

    let result = f.sm.install_snapshot(&snap.meta, snap.snapshot).await;

    assert!(
        result.is_err_and(|e| e.to_string().contains("rebuild fails")),
        "a failed rebuild fails the install"
    );
    f.gate.record_contact_at(f.gate.now_ms());
    assert!(!f.gate.allows(), "no contact reopens it");
    assert_eq!(
        f.gate.refusal_at(f.gate.now_ms()),
        Some(Refusal::InstallingSnapshot)
    );
}
