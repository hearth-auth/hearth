//! #630 part 2: `count_events` counts audit keys and reads no event value, so
//! the daily row-limit check costs no memory per event.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use hearth::audit::{AuditAction, AuditEngine, CreateAuditEvent, EmbeddedAuditEngine};
use hearth::core::{RealmId, SystemClock};
use hearth::storage::{
    EmbeddedStorageEngine, ScanEntry, StorageConfig, StorageEngine, StorageError,
};

/// Storage that, once armed, refuses a value scan of the audit events (the
/// scan a count does when it reads every event) and serves key walks. The
/// first append of a realm scans the events once to start the chain, so the
/// test arms it after the appends.
struct EventValueScanRefused {
    inner: Arc<EmbeddedStorageEngine>,
    armed: Arc<AtomicBool>,
}

impl StorageEngine for EventValueScanRefused {
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
                "a value scan of every audit event",
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

#[test]
fn count_events_reads_no_event_values() {
    let temp = tempfile::tempdir().expect("tempdir");
    let inner = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(temp.path().join("data")))
            .expect("open storage"),
    );
    let armed = Arc::new(AtomicBool::new(false));
    let audit = EmbeddedAuditEngine::new(
        Arc::new(EventValueScanRefused {
            inner,
            armed: Arc::clone(&armed),
        }),
        Arc::new(SystemClock),
    );
    let realm = RealmId::generate();
    for _ in 0..7 {
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

    armed.store(true, Ordering::SeqCst);
    let count = audit
        .count_events(&realm)
        .expect("count_events must not read the event values");
    assert_eq!(count, 7);
}
