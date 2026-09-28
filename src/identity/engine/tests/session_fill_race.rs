//! A session-cache fill must never resurrect a session revoked while it ran.
//!
//! `get_session_arc` answers a cache miss by reading the session row and
//! inserting it into the cache. A revocation that lands between that read and
//! that insert writes the revoked row and evicts the key — which is not in the
//! cache yet — and then the fill inserts the live session it read. Every later
//! validation hits the cache and accepts the token: `/revoke` answered 200 and
//! the token stays active until the process restarts or the cache is flushed.
//!
//! The race is driven deterministically: a storage double parks the fill's
//! read of the session row until the revocation has completed.

use super::*;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::storage::{ScanEntry, StorageDurabilityHandle, StorageError};

/// Parks the first `get` of an armed key, after it has read the row, until
/// released.
struct PausingStorage {
    inner: Arc<dyn StorageEngine>,
    armed: Mutex<Option<Vec<u8>>>,
    loaded: Mutex<Option<mpsc::Sender<()>>>,
    release: Mutex<Option<mpsc::Receiver<()>>>,
    paused: AtomicBool,
}

impl StorageEngine for PausingStorage {
    fn get(&self, realm_id: &RealmId, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let value = self.inner.get(realm_id, key);
        let hit = {
            let mut armed = self.armed.lock().expect("armed");
            if armed.as_deref() == Some(key) {
                *armed = None;
                true
            } else {
                false
            }
        };
        if hit {
            self.paused.store(true, Ordering::SeqCst);
            if let Some(loaded) = self.loaded.lock().expect("loaded").take() {
                let _ = loaded.send(());
            }
            if let Some(release) = self.release.lock().expect("release").take() {
                let _ = release.recv_timeout(Duration::from_secs(30));
            }
        }
        value
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
        self.inner.put_if_absent(realm_id, key, value)
    }

    fn increment_u64(&self, realm_id: &RealmId, key: &[u8]) -> Result<u64, StorageError> {
        self.inner.increment_u64(realm_id, key)
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
fn a_revocation_racing_a_session_cache_fill_is_not_undone() {
    let dir = tempfile::tempdir().expect("tempdir");
    let inner = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf())).expect("open"),
    ) as Arc<dyn StorageEngine>;
    let pausing = Arc::new(PausingStorage {
        inner,
        armed: Mutex::new(None),
        loaded: Mutex::new(None),
        release: Mutex::new(None),
        paused: AtomicBool::new(false),
    });
    let storage = Arc::clone(&pausing) as Arc<dyn StorageEngine>;
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock) as Arc<dyn Clock>,
    ));
    let engine = Arc::new(
        EmbeddedIdentityEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock) as Arc<dyn Clock>,
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                ..IdentityConfig::default()
            },
            audit as Arc<dyn AuditEngine>,
        )
        .expect("engine")
        .with_hibp_transport(Arc::new(NeverPwnedStub)),
    );

    let realm = create_test_realm(&engine);
    let user = engine
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "fill@example.com".to_string(),
                display_name: "Fill".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("user");
    let session = engine
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session");
    let token = engine
        .issue_tokens(&realm, user.id(), session.id())
        .expect("tokens")
        .access_token()
        .to_string();
    engine.validate_token(&realm, &token).expect("warm");

    // Cold session cache, so the next validation fills it from storage; park
    // that fill's read of the session row.
    engine.session_cache.store(Arc::new(HashMap::new()));
    let (loaded_tx, loaded_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    *pausing.loaded.lock().expect("loaded") = Some(loaded_tx);
    *pausing.release.lock().expect("release") = Some(release_rx);
    *pausing.armed.lock().expect("armed") = Some(keys::encode_session_id(session.id()));

    let filler = {
        let engine = Arc::clone(&engine);
        let realm = realm.clone();
        let token = token.clone();
        std::thread::spawn(move || engine.validate_token(&realm, &token).map(|_| ()))
    };
    loaded_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the validation never read the session row");

    // The fill has read the live row and not yet inserted it.
    engine
        .revoke_session(&realm, session.id())
        .expect("revoke the session");
    release_tx.send(()).expect("release the fill");
    // Linearised before the revocation, so this one validation may pass.
    let _ = filler.join().expect("filler thread");

    let after = engine.validate_token(&realm, &token);
    assert!(
        matches!(after, Err(IdentityError::InvalidToken)),
        "a session revoked while a cache fill was in flight is still accepted: the fill \
         re-inserted the live session it had read ({after:?})"
    );
}
