//! A refresh-token grant is ONE durable write (#890).
//!
//! A refresh made four durable writes, one after the other: its
//! `TokenRefreshed` audit event, the session's sliding expiry, the presented
//! token's single-use claim and the grant family's new hash. Each waited for
//! its own WAL sync. A refresh held a place of `storage.max_writes_in_flight`
//! four times in a row, and the write limit refused refreshes near 900/s on a
//! c7i.large.
//!
//! The claim and the family write were also two writes. When the write limit
//! refused the family write, the claim was already durable: the client got a
//! retryable `503`, and its retry with the same token was refused as a replay,
//! which revoked the grant family and the session (`refresh:400` in the load
//! test).

use super::*;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use crate::audit::AuditQuery;
use crate::storage::wal::SyncMode;
use crate::storage::{ClusterUnavailableCause, ScanEntry, StorageDurabilityHandle, StorageError};

/// An identity engine over a storage engine that syncs every write, as in
/// production, so `wal_sync_count` counts the durable writes.
fn synced_engine() -> (
    tempfile::TempDir,
    EmbeddedIdentityEngine,
    Arc<EmbeddedStorageEngine>,
    Arc<EmbeddedAuditEngine>,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = StorageConfig::dev(dir.path().to_path_buf());
    config.wal_config.sync_mode = SyncMode::EveryWrite;
    let storage = Arc::new(EmbeddedStorageEngine::open(config).expect("open"));
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock) as Arc<dyn Clock>,
    ));
    let engine = EmbeddedIdentityEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        clock as Arc<dyn Clock>,
        IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        },
        Arc::clone(&audit) as Arc<dyn AuditEngine>,
    )
    .expect("engine")
    .with_hibp_transport(Arc::new(NeverPwnedStub));
    (dir, engine, storage, audit)
}

/// The `TokenRefreshed` events of `realm_id`.
fn refreshed_events(audit: &EmbeddedAuditEngine, realm_id: &RealmId) -> usize {
    audit
        .query(&AuditQuery {
            realm_id: realm_id.clone(),
            start_time: None,
            end_time: None,
            actor: None,
            action: Some(AuditAction::TokenRefreshed),
            limit: None,
            agent_id: None,
            tool: None,
        })
        .expect("audit query")
        .len()
}

/// One refresh is one WAL sync, and that one write holds everything the
/// refresh changes: the next token works, the session's expiry slides and
/// the `TokenRefreshed` event is recorded.
#[test]
fn a_refresh_makes_one_durable_write() {
    let (_dir, engine, storage, audit) = synced_engine();
    let realm_id = create_test_realm(&engine);
    let user = create_test_user(&engine, &realm_id);
    let session = engine
        .create_session(&realm_id, user.id(), &SessionContext::default())
        .expect("session");
    let first = engine
        .issue_tokens(&realm_id, user.id(), session.id())
        .expect("issue tokens");
    // The first refresh of a realm may write the audit chain's anchor once.
    let second = engine
        .refresh_tokens(&realm_id, first.refresh_token(), None, None)
        .expect("first refresh");
    let events_before = refreshed_events(&audit, &realm_id);
    let expiry_before = engine
        .get_session(&realm_id, session.id())
        .expect("read session")
        .expect("live session")
        .expires_at();

    let syncs_before = storage.wal_sync_count();
    let third = engine
        .refresh_tokens(&realm_id, second.refresh_token(), None, None)
        .expect("refresh");
    let syncs = storage.wal_sync_count() - syncs_before;

    assert_eq!(syncs, 1, "a refresh made {syncs} durable writes");
    assert_eq!(
        refreshed_events(&audit, &realm_id),
        events_before + 1,
        "the refresh records its TokenRefreshed event"
    );
    let expiry_after = engine
        .get_session(&realm_id, session.id())
        .expect("read session")
        .expect("live session")
        .expires_at();
    assert!(
        expiry_after >= expiry_before,
        "the session's sliding expiry is written with the rotation"
    );
    engine
        .refresh_tokens(&realm_id, third.refresh_token(), None, None)
        .expect("the rotated token is the family's current token");
    assert!(
        matches!(
            engine.refresh_tokens(&realm_id, second.refresh_token(), None, None),
            Err(IdentityError::TokenRevoked)
        ),
        "the spent token is still refused as a replay"
    );
}

/// Refuses, as a full write limit does, the first write that would rotate
/// the grant family `target`: before it starts, so nothing of it is written.
struct RefuseFamilyWrite {
    inner: Arc<dyn StorageEngine>,
    target: Mutex<Option<Vec<u8>>>,
    refused: AtomicBool,
}

impl RefuseFamilyWrite {
    /// The write-limit refusal for a write whose keys include the target.
    fn refuse<'k>(&self, mut keys: impl Iterator<Item = &'k [u8]>) -> Result<(), StorageError> {
        let mut target = self.target.lock().expect("target lock");
        let hit = target
            .as_deref()
            .is_some_and(|family| keys.any(|key| key == family));
        if !hit {
            return Ok(());
        }
        *target = None;
        self.refused.store(true, Ordering::SeqCst);
        Err(StorageError::ClusterUnavailable {
            cause: ClusterUnavailableCause::WriteLimit,
            reason: "test: the write limit is full".to_string(),
        })
    }
}

impl StorageEngine for RefuseFamilyWrite {
    fn get(&self, realm_id: &RealmId, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.get(realm_id, key)
    }

    fn put(&self, realm_id: &RealmId, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        self.refuse(std::iter::once(key))?;
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
        self.refuse(entries.iter().map(|(k, _)| k.as_slice()))?;
        self.inner.put_batch(realm_id, entries)
    }

    fn enqueue_batch(
        &self,
        realm_id: &RealmId,
        entries: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<StorageDurabilityHandle, StorageError> {
        self.refuse(entries.iter().map(|(k, _)| k.as_slice()))?;
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
        self.refuse(std::iter::once(key))?;
        self.inner.put_if_absent(realm_id, key, value)
    }

    fn enqueue_batch_if_absent(
        &self,
        realm_id: &RealmId,
        guard_key: &[u8],
        guard_value: &[u8],
        entries: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<Option<StorageDurabilityHandle>, StorageError> {
        self.refuse(std::iter::once(guard_key).chain(entries.iter().map(|(k, _)| k.as_slice())))?;
        self.inner
            .enqueue_batch_if_absent(realm_id, guard_key, guard_value, entries)
    }

    fn write_batch(
        &self,
        realm_id: &RealmId,
        puts: &[(Vec<u8>, Vec<u8>)],
        deletes: &[Vec<u8>],
    ) -> Result<(), StorageError> {
        self.refuse(puts.iter().map(|(k, _)| k.as_slice()))?;
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

/// A refresh that the write limit refuses (`503`, retry later) changes
/// nothing: its retry with the same token succeeds, and the grant family and
/// the session stay live. Before #890 the refusal could fall after the
/// token's single-use claim, so the retry was answered as a replay.
#[test]
fn a_refresh_refused_by_the_write_limit_leaves_its_token_redeemable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let inner = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf())).expect("open"),
    ) as Arc<dyn StorageEngine>;
    let storage = Arc::new(RefuseFamilyWrite {
        inner,
        target: Mutex::new(None),
        refused: AtomicBool::new(false),
    });
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock) as Arc<dyn Clock>,
    ));
    let engine = EmbeddedIdentityEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        clock as Arc<dyn Clock>,
        IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        },
        audit as Arc<dyn AuditEngine>,
    )
    .expect("engine")
    .with_hibp_transport(Arc::new(NeverPwnedStub));

    let realm_id = create_test_realm(&engine);
    let user = create_test_user(&engine, &realm_id);
    let session = engine
        .create_session(&realm_id, user.id(), &SessionContext::default())
        .expect("session");
    let pair = engine
        .issue_tokens(&realm_id, user.id(), session.id())
        .expect("issue tokens");
    let fid = crate::identity::tokens::decode_claims_unverified(pair.refresh_token())
        .expect("decode refresh")
        .fid
        .expect("a refresh token names its grant family");
    *storage.target.lock().expect("target lock") = Some(keys::encode_grant_family(&fid));

    let refused = engine.refresh_tokens(&realm_id, pair.refresh_token(), None, None);
    assert!(
        storage.refused.load(Ordering::SeqCst),
        "the test must refuse the family's rotation"
    );
    let Err(IdentityError::Storage(err)) = refused else {
        panic!("a refused rotation is a storage refusal: {refused:?}");
    };
    assert_eq!(
        StorageError::retry_class_of(err.as_ref()),
        Some(crate::storage::RetryClass::Unavailable),
        "the client is told to retry: {err}"
    );

    let retried = engine
        .refresh_tokens(&realm_id, pair.refresh_token(), None, None)
        .expect("the retry with the same token succeeds, it is not a replay");
    engine
        .refresh_tokens(&realm_id, retried.refresh_token(), None, None)
        .expect("the retry rotated the family: its token is the current one");
    assert!(
        engine
            .get_session(&realm_id, session.id())
            .expect("read session")
            .is_some(),
        "the session stays live"
    );
}
