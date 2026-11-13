//! The realm session list and the session-timeout sweep read the live
//! sessions, not every session record of the realm (#644).
//!
//! A revoked session record stays in storage until the cleanup sweep deletes
//! it after it expires. Before, the realm list read every record and dropped
//! the revoked ones in memory, and the session-timeout sweep called that list
//! once per page. Each write of a session now also keeps one `ses:live:` key
//! for each session that is not revoked, and the storage engine keeps the
//! count of those keys.

use super::*;

use std::collections::BTreeSet;
use std::ops::ControlFlow;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::storage::{EntryVisitor, ScanEntry, StorageError};

const SESSION_RECORD_PREFIX: &[u8] = b"ses:id:";
const LIVE_SESSION_PREFIX: &[u8] = b"ses:live:";

/// Counts the session records (`ses:id:` keys) that reads walk or return.
/// Every call goes through to the real engine.
struct SessionReadCountingStorage {
    inner: Arc<dyn StorageEngine>,
    session_reads: AtomicUsize,
}

impl SessionReadCountingStorage {
    fn count(&self, key: &[u8]) {
        if key.starts_with(SESSION_RECORD_PREFIX) {
            self.session_reads.fetch_add(1, Ordering::SeqCst);
        }
    }
}

impl StorageEngine for SessionReadCountingStorage {
    fn get(&self, realm_id: &RealmId, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.count(key);
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

/// An engine on a real store, with every session record read counted.
fn counting_engine() -> (
    tempfile::TempDir,
    Arc<SessionReadCountingStorage>,
    EmbeddedIdentityEngine,
    Arc<FakeClock>,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let inner = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf())).expect("open"),
    ) as Arc<dyn StorageEngine>;
    let counting = Arc::new(SessionReadCountingStorage {
        inner,
        session_reads: AtomicUsize::new(0),
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
    (dir, counting, engine, clock)
}

fn realm_with_absolute_timeout(engine: &EmbeddedIdentityEngine, secs: u32) -> RealmId {
    engine
        .create_realm(&CreateRealmRequest {
            name: format!("session-list-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                absolute_timeout_secs: Some(secs),
                ..RealmConfig::default()
            }),
        })
        .expect("create realm")
        .id()
        .clone()
}

/// The session ids after `prefix` in the keys under it.
fn ids_under(storage: &dyn StorageEngine, realm: &RealmId, prefix: &[u8]) -> BTreeSet<Vec<u8>> {
    storage
        .scan_keys(realm, prefix, &keys::prefix_end(prefix))
        .expect("scan keys")
        .into_iter()
        .map(|key| key[prefix.len()..].to_vec())
        .collect()
}

/// The live index holds exactly the session records that are not revoked,
/// and the kept count matches it.
fn assert_live_index_matches_records(storage: &dyn StorageEngine, realm: &RealmId, step: &str) {
    let live: BTreeSet<Vec<u8>> = storage
        .scan(
            realm,
            SESSION_RECORD_PREFIX,
            &keys::prefix_end(SESSION_RECORD_PREFIX),
        )
        .expect("scan sessions")
        .into_iter()
        .filter(|entry| {
            let session =
                EmbeddedIdentityEngine::deserialize_session(&entry.value).expect("decode session");
            !session.is_revoked()
        })
        .map(|entry| entry.key[SESSION_RECORD_PREFIX.len()..].to_vec())
        .collect();
    let indexed = ids_under(storage, realm, LIVE_SESSION_PREFIX);
    assert_eq!(
        indexed, live,
        "{step}: the live index must hold the sessions that are not revoked"
    );
    assert_eq!(
        storage
            .count_prefix(realm, LIVE_SESSION_PREFIX, 0)
            .expect("count"),
        live.len() as u64,
        "{step}: the kept count must match the live index"
    );
}

#[test]
fn a_first_session_page_reads_one_page_of_records_and_reports_the_live_total() {
    const SESSIONS: usize = 300;
    const REVOKED: usize = 10;
    const PAGE: u32 = 20;

    let (_dir, counting, engine, _clock) = counting_engine();
    let realm = create_test_realm(&engine);
    let user = create_test_user(&engine, &realm);
    let mut sessions = Vec::new();
    for _ in 0..SESSIONS {
        sessions.push(
            engine
                .create_session(&realm, user.id(), &SessionContext::default())
                .expect("create session"),
        );
    }
    for session in sessions.iter().take(REVOKED) {
        engine
            .revoke_session(&realm, session.id())
            .expect("revoke session");
    }

    counting.session_reads.store(0, Ordering::SeqCst);
    let page = engine
        .list_sessions_by_realm(&realm, &crate::core::PageRequest::new(0, PAGE))
        .expect("list sessions");
    let reads = counting.session_reads.load(Ordering::SeqCst);

    assert_eq!(page.items.len(), PAGE as usize);
    assert!(page.items.iter().all(|s| !s.is_revoked()));
    assert_eq!(page.total, (SESSIONS - REVOKED) as u64);
    assert!(
        reads <= PAGE as usize + 2,
        "a first page of {PAGE} read {reads} session records"
    );
}

#[test]
fn every_session_write_path_keeps_the_live_index() {
    let (_dir, counting, engine, clock) = counting_engine();
    let storage = counting.as_ref();
    let realm = realm_with_absolute_timeout(&engine, 600);
    let alice = create_test_user(&engine, &realm);
    let bob = create_test_user(&engine, &realm);

    let a1 = engine
        .create_session(&realm, alice.id(), &SessionContext::default())
        .expect("create");
    let a2 = engine
        .create_session(&realm, alice.id(), &SessionContext::default())
        .expect("create");
    let b1 = engine
        .create_session(&realm, bob.id(), &SessionContext::default())
        .expect("create");
    engine
        .create_session(&realm, bob.id(), &SessionContext::default())
        .expect("create");
    assert_live_index_matches_records(storage, &realm, "create");

    engine.refresh_session(&realm, a1.id()).expect("refresh");
    assert_live_index_matches_records(storage, &realm, "refresh");

    engine.revoke_session(&realm, a2.id()).expect("revoke");
    assert_live_index_matches_records(storage, &realm, "revoke");

    engine
        .revoke_all_user_sessions(&realm, bob.id(), Some(b1.id()))
        .expect("revoke all");
    assert_live_index_matches_records(storage, &realm, "revoke all but one");

    engine.delete_user(&realm, bob.id()).expect("delete user");
    assert_live_index_matches_records(storage, &realm, "user delete cascade");

    clock.advance(600 * 1_000_000);
    assert_eq!(engine.sweep_expired_sessions(&realm).expect("sweep"), 1);
    assert_live_index_matches_records(storage, &realm, "timeout eviction");

    let a3 = engine
        .create_session(&realm, alice.id(), &SessionContext::default())
        .expect("create");
    engine
        .update_realm(
            &realm,
            &UpdateRealmRequest {
                status: Some(RealmStatus::Suspended),
                ..UpdateRealmRequest::default()
            },
        )
        .expect("suspend realm");
    assert!(engine
        .get_session(&realm, a3.id())
        .expect("get")
        .map_or(true, |s| s.is_revoked()));
    assert_live_index_matches_records(storage, &realm, "realm suspend");

    clock.advance(400 * 24 * 3_600 * 1_000_000);
    engine.sweep_expired(&realm).expect("cleanup sweep");
    assert!(
        ids_under(storage, &realm, SESSION_RECORD_PREFIX).is_empty(),
        "the cleanup sweep must delete every expired session record"
    );
    assert_live_index_matches_records(storage, &realm, "cleanup sweep");
}

/// The session-timeout sweep reads each session record a bounded number of
/// times, not once per page for every page.
#[test]
fn the_timeout_sweep_reads_each_session_record_a_bounded_number_of_times() {
    const SESSIONS: usize = 1_000;

    let (_dir, counting, engine, clock) = counting_engine();
    let realm = realm_with_absolute_timeout(&engine, 600);
    let user = create_test_user(&engine, &realm);
    for _ in 0..SESSIONS {
        engine
            .create_session(&realm, user.id(), &SessionContext::default())
            .expect("create session");
    }

    clock.advance(600 * 1_000_000);
    counting.session_reads.store(0, Ordering::SeqCst);
    assert_eq!(
        engine.sweep_expired_sessions(&realm).expect("sweep"),
        SESSIONS as u64
    );
    let reads = counting.session_reads.load(Ordering::SeqCst);
    assert!(
        reads <= 4 * SESSIONS,
        "the sweep of {SESSIONS} sessions read {reads} session records"
    );
}
