//! A signing-key rotation lands in ONE atomic storage batch.
//!
//! A rotation writes the new key, the old key's retiring row, the purge of
//! closed (or, revoking, all) retiring rows, the record of every kid it
//! retires, the RSA ID-token half and the key-epoch bump. Written one by one,
//! a crash between them left a new key whose predecessor was not recorded
//! retired — and the record is what a backup restore consults to refuse an
//! archived key the realm rotated away from.

use super::*;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::storage::{ScanEntry, StorageDurabilityHandle, StorageError};

/// Counts the system-realm writes that are NOT part of one atomic batch.
struct CountingStorage {
    inner: Arc<dyn StorageEngine>,
    single_writes: AtomicUsize,
    batches: AtomicUsize,
}

impl CountingStorage {
    fn single(&self, realm_id: &RealmId) {
        if keys::is_system_realm(realm_id) {
            self.single_writes.fetch_add(1, Ordering::SeqCst);
        }
    }
}

impl StorageEngine for CountingStorage {
    fn get(&self, realm_id: &RealmId, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.get(realm_id, key)
    }

    fn put(&self, realm_id: &RealmId, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        self.single(realm_id);
        self.inner.put(realm_id, key, value)
    }

    fn delete(&self, realm_id: &RealmId, key: &[u8]) -> Result<(), StorageError> {
        self.single(realm_id);
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
        if keys::is_system_realm(realm_id) {
            self.batches.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.put_batch(realm_id, entries)
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

    fn put_if_absent(
        &self,
        realm_id: &RealmId,
        key: &[u8],
        value: &[u8],
    ) -> Result<bool, StorageError> {
        self.single(realm_id);
        self.inner.put_if_absent(realm_id, key, value)
    }

    fn increment_u64(&self, realm_id: &RealmId, key: &[u8]) -> Result<u64, StorageError> {
        self.single(realm_id);
        self.inner.increment_u64(realm_id, key)
    }

    fn write_batch(
        &self,
        realm_id: &RealmId,
        puts: &[(Vec<u8>, Vec<u8>)],
        deletes: &[Vec<u8>],
    ) -> Result<(), StorageError> {
        if keys::is_system_realm(realm_id) {
            self.batches.fetch_add(1, Ordering::SeqCst);
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

#[test]
fn a_rotation_writes_its_keys_and_retired_records_in_one_batch() {
    let dir = tempfile::tempdir().expect("tempdir");
    let inner = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf())).expect("open"),
    ) as Arc<dyn StorageEngine>;
    let counting = Arc::new(CountingStorage {
        inner,
        single_writes: AtomicUsize::new(0),
        batches: AtomicUsize::new(0),
    });
    let storage = Arc::clone(&counting) as Arc<dyn StorageEngine>;
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000_000)));
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock) as Arc<dyn Clock>,
    ));
    let engine = EmbeddedIdentityEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock) as Arc<dyn Clock>,
        IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        },
        audit as Arc<dyn AuditEngine>,
    )
    .expect("engine")
    .with_hibp_transport(Arc::new(NeverPwnedStub));

    let realm = create_test_realm(&engine);
    engine
        .ensure_realm_id_token_rsa_key(&realm)
        .expect("RSA ID-token key");

    for grace_secs in [3_600_u64, 0, 3_600] {
        counting.single_writes.store(0, Ordering::SeqCst);
        counting.batches.store(0, Ordering::SeqCst);
        engine
            .rotate_realm_signing_key(&realm, grace_secs)
            .expect("rotate");
        assert_eq!(
            (
                counting.single_writes.load(Ordering::SeqCst),
                counting.batches.load(Ordering::SeqCst)
            ),
            (0, 1),
            "grace {grace_secs}: every system-realm write of the rotation is in one batch"
        );
    }
}
