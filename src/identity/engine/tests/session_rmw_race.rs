//! A session revocation must never be undone by a racing write of the same
//! session row (audit GA 2026-09-28 B7).
//!
//! `refresh_session` and `revoke_session` both read, modify and write the one
//! session row. With nothing serialising them, a refresh that read the live row
//! before the revocation wrote it back un-revoked after — `/revoke` answered
//! 200 and the session stayed live in storage. Separately, a session write
//! re-inserted the session into the in-process cache *after* its storage write
//! with no generation check, so a revocation landing between the two left the
//! cache serving a session storage calls revoked.
//!
//! Each race is driven with a storage double that parks one operation at the
//! exact point of the interleaving until the revocation has run (or, once the
//! row is serialised, until it is provably blocked behind the parked writer).

use super::*;

use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::core::PageRequest;
use crate::storage::{ScanEntry, StorageDurabilityHandle, StorageError};

/// Where the storage double parks the next matching call.
#[derive(Default)]
struct Arms {
    /// Park after the first `get` of this key has read the row.
    get: Option<Vec<u8>>,
    /// Park after the first `put_batch` containing this key has written.
    put_batch_key: Option<Vec<u8>>,
    /// Park after the next `await_batch_durable` returns.
    durable: bool,
}

struct ParkingStorage {
    inner: Arc<dyn StorageEngine>,
    arms: Mutex<Arms>,
    parked: Mutex<Option<mpsc::Sender<()>>>,
    release: Mutex<Option<mpsc::Receiver<()>>>,
}

impl ParkingStorage {
    fn park(&self) {
        if let Some(parked) = self.parked.lock().expect("parked").take() {
            let _ = parked.send(());
        }
        if let Some(release) = self.release.lock().expect("release").take() {
            let _ = release.recv_timeout(Duration::from_secs(30));
        }
    }

    /// Arms the double and returns (parked signal, release handle).
    fn arm(&self, arms: Arms) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (parked_tx, parked_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        *self.parked.lock().expect("parked") = Some(parked_tx);
        *self.release.lock().expect("release") = Some(release_rx);
        *self.arms.lock().expect("arms") = arms;
        (parked_rx, release_tx)
    }
}

impl StorageEngine for ParkingStorage {
    fn get(&self, realm_id: &RealmId, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let value = self.inner.get(realm_id, key);
        let hit = {
            let mut arms = self.arms.lock().expect("arms");
            if arms.get.as_deref() == Some(key) {
                arms.get = None;
                true
            } else {
                false
            }
        };
        if hit {
            self.park();
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
        let result = self.inner.put_batch(realm_id, entries);
        let hit = {
            let mut arms = self.arms.lock().expect("arms");
            let armed = arms
                .put_batch_key
                .as_ref()
                .is_some_and(|key| entries.iter().any(|(k, _)| k == key));
            if armed {
                arms.put_batch_key = None;
            }
            armed
        };
        if hit {
            self.park();
        }
        result
    }

    fn enqueue_batch(
        &self,
        realm_id: &RealmId,
        entries: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<StorageDurabilityHandle, StorageError> {
        self.inner.enqueue_batch(realm_id, entries)
    }

    fn await_batch_durable(&self, handle: StorageDurabilityHandle) -> Result<(), StorageError> {
        let result = self.inner.await_batch_durable(handle);
        let hit = {
            let mut arms = self.arms.lock().expect("arms");
            std::mem::take(&mut arms.durable)
        };
        if hit {
            self.park();
        }
        result
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

struct Fixture {
    _dir: tempfile::TempDir,
    storage: Arc<ParkingStorage>,
    engine: Arc<EmbeddedIdentityEngine>,
    realm: RealmId,
    user: UserId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let inner = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf())).expect("open"),
    ) as Arc<dyn StorageEngine>;
    let parking = Arc::new(ParkingStorage {
        inner,
        arms: Mutex::new(Arms::default()),
        parked: Mutex::new(None),
        release: Mutex::new(None),
    });
    let storage = Arc::clone(&parking) as Arc<dyn StorageEngine>;
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
                email: "race@example.com".to_string(),
                display_name: "Race".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("user")
        .id()
        .clone();
    Fixture {
        _dir: dir,
        storage: parking,
        engine,
        realm,
        user,
    }
}

/// Runs `revoke_session` on its own thread and gives it `grace` to finish.
///
/// Before the fix it always finishes (nothing serialises it against the
/// parked writer); once the row is serialised it blocks behind the parked
/// writer until that writer is released. Either way the returned handle
/// joins it.
fn revoke_in_background(
    f: &Fixture,
    session: &SessionId,
    grace: Duration,
) -> std::thread::JoinHandle<Result<(), IdentityError>> {
    let (done_tx, done_rx) = mpsc::channel();
    let handle = {
        let engine = Arc::clone(&f.engine);
        let realm = f.realm.clone();
        let session = session.clone();
        std::thread::spawn(move || {
            let result = engine.revoke_session(&realm, &session);
            let _ = done_tx.send(());
            result
        })
    };
    let _ = done_rx.recv_timeout(grace);
    handle
}

/// Asserts the session is revoked both in storage and in what the node serves.
fn assert_revoked_everywhere(f: &Fixture, session: &SessionId, what: &str) {
    let now = f.engine.clock.now();
    let stored = f
        .engine
        .load_session_raw(&f.realm, session)
        .expect("load")
        .expect("the row exists");
    assert!(
        !stored.is_valid(now),
        "{what}: the stored session row is live again after revoke_session returned Ok"
    );
    let served = f
        .engine
        .get_session(&f.realm, session)
        .expect("get_session");
    assert!(
        served.is_none(),
        "{what}: storage says revoked but the node still serves the session from its cache"
    );
}

#[test]
fn a_revocation_racing_a_refresh_read_modify_write_is_not_undone() {
    let f = fixture();
    let session = f
        .engine
        .create_session(&f.realm, &f.user, &SessionContext::default())
        .expect("session");

    // Park the refresh right after it read the live row.
    let (parked, release) = f.storage.arm(Arms {
        get: Some(keys::encode_session_id(session.id())),
        ..Arms::default()
    });
    let refresher = {
        let engine = Arc::clone(&f.engine);
        let realm = f.realm.clone();
        let id = session.id().clone();
        std::thread::spawn(move || engine.refresh_session(&realm, &id).map(|_| ()))
    };
    parked
        .recv_timeout(Duration::from_secs(10))
        .expect("the refresh never read the session row");

    let revoker = revoke_in_background(&f, session.id(), Duration::from_millis(500));
    release.send(()).expect("release the refresh");
    // Linearised before the revocation, so the refresh itself may succeed.
    let _ = refresher.join().expect("refresher");
    revoker.join().expect("revoker").expect("revoke_session");

    assert_revoked_everywhere(&f, session.id(), "refresh read → revoke → refresh write");
}

#[test]
fn a_revocation_between_a_refresh_write_and_its_cache_insert_is_not_undone() {
    let f = fixture();
    let session = f
        .engine
        .create_session(&f.realm, &f.user, &SessionContext::default())
        .expect("session");

    // Park the refresh after its storage write, before its cache update.
    let (parked, release) = f.storage.arm(Arms {
        put_batch_key: Some(keys::encode_session_id(session.id())),
        ..Arms::default()
    });
    let refresher = {
        let engine = Arc::clone(&f.engine);
        let realm = f.realm.clone();
        let id = session.id().clone();
        std::thread::spawn(move || engine.refresh_session(&realm, &id).map(|_| ()))
    };
    parked
        .recv_timeout(Duration::from_secs(10))
        .expect("the refresh never wrote the session row");

    let revoker = revoke_in_background(&f, session.id(), Duration::from_millis(500));
    release.send(()).expect("release the refresh");
    let _ = refresher.join().expect("refresher");
    revoker.join().expect("revoker").expect("revoke_session");

    assert_revoked_everywhere(&f, session.id(), "refresh write → revoke → cache insert");
}

#[test]
fn a_revocation_between_a_session_create_and_its_cache_insert_is_not_undone() {
    let f = fixture();

    // Park the creation after its batch is durable, before its cache insert.
    let (parked, release) = f.storage.arm(Arms {
        durable: true,
        ..Arms::default()
    });
    let creator = {
        let engine = Arc::clone(&f.engine);
        let realm = f.realm.clone();
        let user = f.user.clone();
        std::thread::spawn(move || engine.create_session(&realm, &user, &SessionContext::default()))
    };
    parked
        .recv_timeout(Duration::from_secs(10))
        .expect("the session was never written");

    let written = f
        .engine
        .list_sessions_by_user(&f.realm, &f.user, &PageRequest::new(0, 10))
        .expect("list sessions");
    let id = written
        .items
        .first()
        .expect("the parked creation has written its row")
        .id()
        .clone();
    let revoker = revoke_in_background(&f, &id, Duration::from_millis(500));
    release.send(()).expect("release the creation");
    let created = creator.join().expect("creator").expect("create_session");
    assert_eq!(created.id(), &id);
    revoker.join().expect("revoker").expect("revoke_session");

    assert_revoked_everywhere(&f, &id, "create write → revoke → cache insert");
}
