//! A user-list page reads about one page of user records, not the realm
//! (#644). The exact total comes from the count that the storage engine
//! keeps.

use super::*;

use std::ops::ControlFlow;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::storage::{EntryVisitor, ScanEntry, StorageError};

/// Counts the user records (`usr:id:` keys) that reads walk or return. Every
/// call goes through to the real engine, `count_prefix` included.
struct UserReadCountingStorage {
    inner: Arc<dyn StorageEngine>,
    user_reads: AtomicUsize,
}

impl UserReadCountingStorage {
    fn count(&self, key: &[u8]) {
        if key.starts_with(crate::core::USER_RECORD_KEY_PREFIX) {
            self.user_reads.fetch_add(1, Ordering::SeqCst);
        }
    }
}

impl StorageEngine for UserReadCountingStorage {
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
        let entries = self.inner.scan(realm_id, start, end)?;
        for entry in &entries {
            self.count(&entry.key);
        }
        Ok(entries)
    }

    fn scan_keys(
        &self,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
    ) -> Result<Vec<Vec<u8>>, StorageError> {
        let keys = self.inner.scan_keys(realm_id, start, end)?;
        for key in &keys {
            self.count(key);
        }
        Ok(keys)
    }

    fn visit_keys(
        &self,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
        visit: &mut dyn FnMut(&[u8]) -> ControlFlow<()>,
    ) -> Result<(), StorageError> {
        self.inner.visit_keys(realm_id, start, end, &mut |key| {
            self.count(key);
            visit(key)
        })
    }

    fn visit_entries(
        &self,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
        visit: &mut EntryVisitor<'_>,
    ) -> Result<(), StorageError> {
        self.inner
            .visit_entries(realm_id, start, end, &mut |key, value| {
                self.count(key);
                visit(key, value)
            })
    }

    fn count_prefix(
        &self,
        realm_id: &RealmId,
        prefix: &[u8],
        cap: u64,
    ) -> Result<u64, StorageError> {
        self.inner.count_prefix(realm_id, prefix, cap)
    }

    fn put_batch(
        &self,
        realm_id: &RealmId,
        entries: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<(), StorageError> {
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
fn a_first_user_page_reads_one_page_of_records_and_reports_the_exact_total() {
    const USERS: usize = 300;
    const PAGE: u32 = 20;

    let dir = tempfile::tempdir().expect("tempdir");
    let inner = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf())).expect("open"),
    ) as Arc<dyn StorageEngine>;
    let counting = Arc::new(UserReadCountingStorage {
        inner,
        user_reads: AtomicUsize::new(0),
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
    for i in 0..USERS {
        let request = CreateUserRequest {
            email: format!("user{i:04}@example.com"),
            display_name: format!("User {i:04}"),
            ..Default::default()
        };
        engine.create_user(&realm, &request).expect("create user");
    }

    counting.user_reads.store(0, Ordering::SeqCst);
    let page = engine
        .list_users(&realm, &crate::core::PageRequest::new(0, PAGE))
        .expect("list users");
    let reads = counting.user_reads.load(Ordering::SeqCst);

    assert_eq!(page.items.len(), PAGE as usize);
    assert_eq!(page.total, USERS as u64);
    // One page of keys for the window plus one page of records for the
    // values. A walk of the realm reads every user key at least once.
    assert!(
        reads <= 2 * PAGE as usize + 2,
        "a first page of {PAGE} read {reads} user keys or records"
    );
}
