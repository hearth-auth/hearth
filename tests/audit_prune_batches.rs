//! #735: the audit prune deletes in bounded batches. It streams the events it
//! deletes instead of reading them all into memory, and no single atomic write
//! removes the whole pruned range. The chain still verifies after the prune and
//! after a later append.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use hearth::audit::{AuditAction, AuditEngine, CreateAuditEvent, EmbeddedAuditEngine};
use hearth::core::{RealmId, SystemClock, Timestamp};
use hearth::storage::{
    EmbeddedStorageEngine, EntryVisitor, ScanEntry, StorageConfig, StorageEngine, StorageError,
};

/// Events in the realm before the prune: more than two batches of 10 000.
const EVENTS: u64 = 25_000;

/// A pruned event is three keys (the event and its actor and action index
/// entries), and a batch is at most 10 000 events.
const MAX_KEYS_PER_BATCH: usize = 3 * 10_000;

/// Storage that, once armed, refuses a value scan of the audit events and
/// records the size of each atomic delete. Streaming walks pass through.
struct PruneProbe {
    inner: Arc<EmbeddedStorageEngine>,
    armed: AtomicBool,
    batches: AtomicUsize,
    max_batch_deletes: AtomicUsize,
}

impl StorageEngine for PruneProbe {
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
        if self.armed.load(Ordering::SeqCst) && start == b"audit:evt:" {
            return Err(StorageError::Io(std::io::Error::other(
                "a value scan that reads every pruned audit event into memory",
            )));
        }
        self.inner.scan(realm_id, start, end)
    }

    fn visit_keys(
        &self,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
        visit: &mut dyn FnMut(&[u8]) -> std::ops::ControlFlow<()>,
    ) -> Result<(), StorageError> {
        self.inner.visit_keys(realm_id, start, end, visit)
    }

    fn visit_entries(
        &self,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
        visit: &mut EntryVisitor<'_>,
    ) -> Result<(), StorageError> {
        self.inner.visit_entries(realm_id, start, end, visit)
    }

    fn write_batch(
        &self,
        realm_id: &RealmId,
        puts: &[(Vec<u8>, Vec<u8>)],
        deletes: &[Vec<u8>],
    ) -> Result<(), StorageError> {
        if self.armed.load(Ordering::SeqCst) {
            self.batches.fetch_add(1, Ordering::SeqCst);
            self.max_batch_deletes
                .fetch_max(deletes.len(), Ordering::SeqCst);
        }
        self.inner.write_batch(realm_id, puts, deletes)
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

fn append_one(audit: &dyn AuditEngine, realm: &RealmId) {
    audit
        .append(&CreateAuditEvent {
            realm_id: realm.clone(),
            actor: "system".to_string(),
            action: AuditAction::UserCreated,
            resource_type: "user".to_string(),
            resource_id: uuid::Uuid::new_v4().to_string(),
            metadata: None,
        })
        .expect("append");
}

/// An audit engine over a probe, with `EVENTS` events in a new realm.
fn filled(temp: &tempfile::TempDir) -> (EmbeddedAuditEngine, Arc<PruneProbe>, RealmId) {
    let probe = Arc::new(PruneProbe {
        inner: Arc::new(
            EmbeddedStorageEngine::open(StorageConfig::dev(temp.path().join("data")))
                .expect("open storage"),
        ),
        armed: AtomicBool::new(false),
        batches: AtomicUsize::new(0),
        max_batch_deletes: AtomicUsize::new(0),
    });
    let storage: Arc<dyn StorageEngine> = probe.clone();
    let audit = EmbeddedAuditEngine::new(storage, Arc::new(SystemClock));
    let realm = RealmId::generate();
    for _ in 0..EVENTS {
        append_one(&audit, &realm);
    }
    (audit, probe, realm)
}

/// Checks the batches the armed probe saw, then that the chain verifies now
/// and after one more append.
fn assert_batched_and_verified(audit: &EmbeddedAuditEngine, probe: &PruneProbe, realm: &RealmId) {
    probe.armed.store(false, Ordering::SeqCst);
    let max = probe.max_batch_deletes.load(Ordering::SeqCst);
    assert!(
        max <= MAX_KEYS_PER_BATCH,
        "one atomic write deleted {max} keys; a batch is at most {MAX_KEYS_PER_BATCH}"
    );
    assert!(
        probe.batches.load(Ordering::SeqCst) >= 3,
        "a prune of more than 20 000 events takes at least three batches"
    );
    assert!(
        audit.verify_integrity(realm, None, None).expect("verify"),
        "the retained chain verifies after a batched prune"
    );
    append_one(audit, realm);
    assert!(
        audit.verify_integrity(realm, None, None).expect("verify"),
        "the chain verifies after an append that follows the prune"
    );
}

#[test]
fn prune_oldest_deletes_in_bounded_batches_without_a_value_scan() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (audit, probe, realm) = filled(&temp);

    probe.armed.store(true, Ordering::SeqCst);
    let deleted = audit
        .prune_oldest(&realm, 23_000)
        .expect("prune_oldest must stream the events it deletes");

    assert_eq!(deleted, 23_000);
    assert_eq!(audit.count_events(&realm).expect("count"), 2_000);
    assert_batched_and_verified(&audit, &probe, &realm);
}

#[test]
fn prune_before_deletes_in_bounded_batches_without_a_value_scan() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (audit, probe, realm) = filled(&temp);
    // One second after the newest event, so the prune covers every event.
    let cutoff = Timestamp::now().add_micros(1_000_000);

    probe.armed.store(true, Ordering::SeqCst);
    let deleted = audit
        .prune_before(&realm, cutoff)
        .expect("prune_before must stream the events it deletes");

    assert_eq!(deleted, EVENTS);
    assert_eq!(audit.count_events(&realm).expect("count"), 0);
    assert_batched_and_verified(&audit, &probe, &realm);
}
