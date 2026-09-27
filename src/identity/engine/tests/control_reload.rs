//! Control-cache reloads: off the validation path, ordered against writers,
//! retried on failure, and complete.
//!
//! Three caches decide a control on the validation path — the revoked-JTI
//! blocklist, the DPoP blocklist and realm statuses — and a node reloads them
//! from storage when another node asserts a control (the control epoch moves).
//! These tests pin the properties that reload must have:
//!
//! * validation never waits for it — no lock on the validation path, even
//!   when the epoch has moved (ARCHITECTURE.md §3.2 rule 3);
//! * a failed reload does not consume the epoch, so the control still binds
//!   once storage recovers (it used to fail open until the next bump);
//! * a replicated write is projected into the caches without any storage
//!   write — observers run on the Raft apply path, and a write there proposes
//!   and waits for its own apply (a self-deadlock on the leader);
//! * the system realm's revocations and DPoP blocks survive a reload;
//! * a local or replicated write racing a reload's scan is never lost.

use super::*;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::cluster::ReplicatedWriteObserver;
use crate::storage::{ScanEntry, StorageDurabilityHandle, StorageError};

/// Long enough for a background reload on a loaded CI runner, short enough
/// that a hang fails the test instead of the suite.
const CONVERGE: Duration = Duration::from_secs(10);

/// Storage double over a real engine: counts writes and can fail scans.
struct FaultStorage {
    inner: Arc<dyn StorageEngine>,
    fail_scans: AtomicBool,
    writes: AtomicUsize,
}

impl FaultStorage {
    fn over(inner: Arc<dyn StorageEngine>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            fail_scans: AtomicBool::new(false),
            writes: AtomicUsize::new(0),
        })
    }

    fn wrote(&self) {
        self.writes.fetch_add(1, Ordering::SeqCst);
    }
}

impl StorageEngine for FaultStorage {
    fn get(&self, realm_id: &RealmId, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.get(realm_id, key)
    }

    fn put(&self, realm_id: &RealmId, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        self.wrote();
        self.inner.put(realm_id, key, value)
    }

    fn delete(&self, realm_id: &RealmId, key: &[u8]) -> Result<(), StorageError> {
        self.wrote();
        self.inner.delete(realm_id, key)
    }

    fn scan(
        &self,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
    ) -> Result<Vec<ScanEntry>, StorageError> {
        if self.fail_scans.load(Ordering::SeqCst) {
            return Err(StorageError::Io(std::io::Error::other(
                "injected scan failure",
            )));
        }
        self.inner.scan(realm_id, start, end)
    }

    fn put_batch(
        &self,
        realm_id: &RealmId,
        entries: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<(), StorageError> {
        self.wrote();
        self.inner.put_batch(realm_id, entries)
    }

    fn enqueue_batch(
        &self,
        realm_id: &RealmId,
        entries: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<StorageDurabilityHandle, StorageError> {
        self.wrote();
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
        self.wrote();
        self.inner.put_if_absent(realm_id, key, value)
    }

    fn increment_u64(&self, realm_id: &RealmId, key: &[u8]) -> Result<u64, StorageError> {
        self.wrote();
        self.inner.increment_u64(realm_id, key)
    }

    fn write_batch(
        &self,
        realm_id: &RealmId,
        puts: &[(Vec<u8>, Vec<u8>)],
        deletes: &[Vec<u8>],
    ) -> Result<(), StorageError> {
        self.wrote();
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

fn open_storage(dir: &tempfile::TempDir) -> Arc<dyn StorageEngine> {
    Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf())).expect("open"),
    ) as Arc<dyn StorageEngine>
}

/// An engine over storage and a clock the caller owns, so two engines can
/// share both and stand in for two nodes of one cluster.
fn engine_over(storage: &Arc<dyn StorageEngine>, clock: &Arc<FakeClock>) -> EmbeddedIdentityEngine {
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(storage),
        Arc::clone(clock) as Arc<dyn Clock>,
    ));
    EmbeddedIdentityEngine::new(
        Arc::clone(storage),
        Arc::clone(clock) as Arc<dyn Clock>,
        IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        },
        audit as Arc<dyn AuditEngine>,
    )
    .expect("engine creation")
    .with_hibp_transport(Arc::new(NeverPwnedStub))
}

/// A realm, a user, a session, and a live access token bound to it.
fn seed_token(engine: &EmbeddedIdentityEngine) -> (RealmId, String) {
    let realm = engine
        .create_realm(&CreateRealmRequest {
            name: format!("reload-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();
    let user = engine
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "reload@example.com".to_string(),
                display_name: "Reload".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    let session = engine
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("create session");
    let pair = engine
        .issue_tokens(&realm, user.id(), session.id())
        .expect("issue tokens");
    (realm, pair.access_token().to_string())
}

fn suspend(engine: &EmbeddedIdentityEngine, realm: &RealmId) {
    engine
        .update_realm(
            realm,
            &UpdateRealmRequest {
                status: Some(RealmStatus::Suspended),
                ..Default::default()
            },
        )
        .expect("suspend the realm");
}

/// Polls `validate_token` until it answers `RealmSuspended` or [`CONVERGE`]
/// passes. The reload runs in the background, so the bind is eventual.
fn binds_suspension(engine: &EmbeddedIdentityEngine, realm: &RealmId, token: &str) -> bool {
    let deadline = Instant::now() + CONVERGE;
    while Instant::now() < deadline {
        if matches!(
            engine.validate_token(realm, token),
            Err(IdentityError::RealmSuspended)
        ) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

/// Rule 3 of the hot path: `validate_token` takes no lock, even on the branch
/// where it observes that another node moved the control epoch.
///
/// The test holds the lock that orders control writers against the reloader
/// and drives a validation down the epoch-moved branch. Before the fix that
/// branch took the same lock to run the reload inline, so the validation
/// blocked for as long as any writer or reload held it.
#[test]
fn validation_on_a_moved_epoch_takes_no_lock() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = open_storage(&dir);
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
    let engine = Arc::new(engine_over(&storage, &clock));
    let (realm, token) = seed_token(&engine);
    engine.validate_token(&realm, &token).expect("warm");

    // Another node asserted a control: the persisted epoch is now ahead.
    storage
        .increment_u64(&keys::system_realm_id(), &keys::encode_control_epoch())
        .expect("bump the persisted epoch");
    clock.advance(EPOCH_SYNC_INTERVAL_MICROS + 1);

    let guard = engine.control.lock_writers_for_test();
    let (tx, rx) = mpsc::channel();
    let validator = {
        let engine = Arc::clone(&engine);
        let realm = realm.clone();
        std::thread::spawn(move || {
            let outcome = engine.validate_token(&realm, &token).map(|_| ());
            let _ = tx.send(outcome);
        })
    };
    let outcome = rx.recv_timeout(Duration::from_secs(5));
    drop(guard);
    validator.join().expect("validator thread");
    assert!(
        matches!(outcome, Ok(Ok(()))),
        "validate_token did not complete while the control writer/reloader lock was held: \
         {outcome:?}"
    );
}

/// A reload that fails part-way must not record the epoch it was reloading
/// for. It used to record it first and ignore the repopulate errors, so one
/// failed scan left the caches stale — failing open — until the next bump.
#[test]
fn a_failed_reload_does_not_consume_the_epoch() {
    let dir = tempfile::tempdir().expect("tempdir");
    let shared = open_storage(&dir);
    let fault = FaultStorage::over(Arc::clone(&shared));
    let validator_storage = Arc::clone(&fault) as Arc<dyn StorageEngine>;
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));

    let other_node = engine_over(&shared, &clock);
    let (realm, token) = seed_token(&other_node);
    let validator = engine_over(&validator_storage, &clock);
    validator.validate_token(&realm, &token).expect("warm");

    fault.fail_scans.store(true, Ordering::SeqCst);
    suspend(&other_node, &realm);
    clock.advance(EPOCH_SYNC_INTERVAL_MICROS + 1);
    // Observes the moved epoch; the reload it causes fails.
    let _ = validator.validate_token(&realm, &token);
    std::thread::sleep(Duration::from_millis(300));

    fault.fail_scans.store(false, Ordering::SeqCst);
    clock.advance(EPOCH_SYNC_INTERVAL_MICROS + 1);
    assert!(
        binds_suspension(&validator, &realm, &token),
        "after one failed reload the validator never enforced a suspension asserted on another \
         node: the failed reload consumed the epoch"
    );
}

/// A replicated revoked-JTI row is projected into the cache and nothing else:
/// no storage write, so no epoch bump and no Raft proposal from inside the
/// state machine's own apply.
#[test]
fn a_replicated_revocation_is_projected_without_any_storage_write() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fault = FaultStorage::over(open_storage(&dir));
    let storage = Arc::clone(&fault) as Arc<dyn StorageEngine>;
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
    let engine = engine_over(&storage, &clock);
    let realm = RealmId::new(uuid::Uuid::new_v4());
    let exp: i64 = 10_000;

    let before = fault.writes.load(Ordering::SeqCst);
    engine.on_replicated_put(
        &realm,
        &keys::encode_revoked_jti("replicated-jti"),
        &exp.to_le_bytes(),
    );
    let writes = fault.writes.load(Ordering::SeqCst) - before;

    assert_eq!(
        writes, 0,
        "projecting a replicated revocation wrote to storage {writes} time(s); on a cluster \
         leader that write is a Raft proposal made from inside the state machine's own apply"
    );
    assert!(
        engine
            .revoked_jti_cache
            .contains_key(format!("{}:replicated-jti", realm.as_uuid()).as_str()),
        "the replicated revocation must still reach the projection"
    );
}

/// The system realm's revocations and DPoP blocks are control rows like any
/// other realm's. Every reload used to skip the system realm, so they were
/// dropped by the first reload and by every restart.
#[test]
fn system_realm_controls_survive_a_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
    let sys = keys::system_realm_id();
    let exp: i64 = 10_000;
    {
        let storage = open_storage(&dir);
        let engine = engine_over(&storage, &clock);
        storage
            .put(
                &sys,
                &keys::encode_revoked_jti("sys-jti"),
                &exp.to_le_bytes(),
            )
            .expect("revocation row");
        engine.insert_revoked_jti_cache(&sys, "sys-jti", exp);
        engine
            .block_dpop_jkt_inner(&sys, "sys-jkt")
            .expect("block a DPoP key in the system realm");
    }

    let storage = open_storage(&dir);
    let restarted = engine_over(&storage, &clock);
    assert!(
        restarted
            .revoked_jti_cache
            .contains_key(format!("{}:sys-jti", sys.as_uuid()).as_str()),
        "a JTI revoked in the system realm was dropped by the restart's reload"
    );
    assert!(
        restarted.blocked_dpop_jkt_cache.contains_key("sys-jkt"),
        "a DPoP key blocked in the system realm was dropped by the restart's reload"
    );
}

/// A reload held between its scan and its swap. `entered` fires when a reload
/// reaches the hook; the reload then waits until `release` is dropped or sent.
struct HeldReload {
    entered: mpsc::Receiver<()>,
    release: mpsc::Sender<()>,
}

fn hold_reloads(engine: &EmbeddedIdentityEngine) -> HeldReload {
    let (entered_tx, entered) = mpsc::channel();
    let (release, release_rx) = mpsc::channel::<()>();
    let entered_tx = std::sync::Mutex::new(entered_tx);
    let release_rx = std::sync::Mutex::new(release_rx);
    engine.control.set_scan_hook(Some(Arc::new(move || {
        let _ = entered_tx.lock().expect("hook lock").send(());
        let _ = release_rx
            .lock()
            .expect("hook lock")
            .recv_timeout(Duration::from_secs(30));
    })));
    HeldReload { entered, release }
}

/// Forces the engine's background reloader to start a reload: moves the
/// persisted epoch past it and lets a validation observe that.
fn start_background_reload(
    engine: &EmbeddedIdentityEngine,
    storage: &Arc<dyn StorageEngine>,
    clock: &FakeClock,
    realm: &RealmId,
    token: &str,
) {
    storage
        .increment_u64(&keys::system_realm_id(), &keys::encode_control_epoch())
        .expect("bump the persisted epoch");
    clock.advance(EPOCH_SYNC_INTERVAL_MICROS + 1);
    let _ = engine.validate_token(realm, token);
}

/// While a reload is in flight — scanned, not yet swapped — validations keep
/// completing on the caches they have. Nothing on the validation path waits
/// for the reload.
#[test]
fn validations_complete_while_a_reload_is_held_mid_flight() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = open_storage(&dir);
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
    let engine = engine_over(&storage, &clock);
    let (realm, token) = seed_token(&engine);
    engine.validate_token(&realm, &token).expect("warm");

    let held = hold_reloads(&engine);
    start_background_reload(&engine, &storage, &clock, &realm, &token);
    held.entered
        .recv_timeout(CONVERGE)
        .expect("the background reload never started");

    let started = Instant::now();
    for _ in 0..200 {
        engine
            .validate_token(&realm, &token)
            .expect("a validation during an in-flight reload");
    }
    let elapsed = started.elapsed();
    drop(held.release);
    assert!(
        elapsed < Duration::from_secs(2),
        "200 validations took {elapsed:?} while a reload was held mid-flight"
    );
}

/// A local control write and a replicated revocation delete that land after a
/// reload's scan but before its swap both survive the swap. Without the
/// journal the swap installed the scan: the local revocation was lost (the
/// token stayed valid after `/revoke` answered 200), and the replicated delete
/// was undone.
#[test]
fn writes_racing_a_reload_swap_are_not_lost() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = open_storage(&dir);
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
    let engine = engine_over(&storage, &clock);
    let (realm, token) = seed_token(&engine);
    engine.validate_token(&realm, &token).expect("warm");
    let exp: i64 = 10_000;

    // A replicated revocation that the reload's scan will see.
    let deleted_key = keys::encode_revoked_jti("deleted-later");
    storage
        .put(&realm, &deleted_key, &exp.to_le_bytes())
        .expect("row");
    engine.on_replicated_put(&realm, &deleted_key, &exp.to_le_bytes());

    let held = hold_reloads(&engine);
    start_background_reload(&engine, &storage, &clock, &realm, &token);
    held.entered
        .recv_timeout(CONVERGE)
        .expect("the background reload never started");

    // After the scan: a local revocation, a local DPoP block, and the
    // replicated delete of the row the scan saw.
    storage
        .put(
            &realm,
            &keys::encode_revoked_jti("revoked-mid-reload"),
            &exp.to_le_bytes(),
        )
        .expect("row");
    engine.insert_revoked_jti_cache(&realm, "revoked-mid-reload", exp);
    engine
        .block_dpop_jkt_inner(&realm, "jkt-mid-reload")
        .expect("block");
    storage.delete(&realm, &deleted_key).expect("delete row");
    engine.on_replicated_delete(&realm, &deleted_key);

    let reloaded_from = engine.control.applied_epoch();
    drop(held.release);
    let deadline = Instant::now() + CONVERGE;
    while engine.control.applied_epoch() == reloaded_from && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    engine.control.set_scan_hook(None);

    let key = |jti: &str| format!("{}:{jti}", realm.as_uuid());
    assert!(
        engine
            .revoked_jti_cache
            .contains_key(key("revoked-mid-reload").as_str()),
        "a revocation applied during the reload was overwritten by its swap"
    );
    assert!(
        engine.blocked_dpop_jkt_cache.contains_key("jkt-mid-reload"),
        "a DPoP block applied during the reload was overwritten by its swap"
    );
    assert!(
        !engine
            .revoked_jti_cache
            .contains_key(key("deleted-later").as_str()),
        "a replicated delete applied during the reload was undone by its swap"
    );
}

/// A snapshot install can LOWER the persisted control epoch — the leader's
/// count was behind this node's (the replay double-count this cluster used to
/// have, or any other divergence). The reload after the reset used to keep
/// `applied` at the old, higher value, so every later control whose epoch was
/// at or below it was ignored here: a realm suspended on another node stayed
/// active on this one until the counter caught up.
#[test]
fn a_control_after_a_snapshot_lowered_the_epoch_still_binds() {
    use crate::cluster::ReplicatedWriteObserver as _;

    let dir = tempfile::tempdir().expect("tempdir");
    let storage = open_storage(&dir);
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
    let node = engine_over(&storage, &clock);
    let (realm, token) = seed_token(&node);
    node.validate_token(&realm, &token).expect("warm");

    // This node's count ran ahead: ten bumps it reloaded for.
    let sys = keys::system_realm_id();
    let epoch_key = keys::encode_control_epoch();
    for _ in 0..10 {
        storage.increment_u64(&sys, &epoch_key).expect("bump");
    }
    node.control.reload().expect("reload at the high epoch");
    let high = node.control.applied_epoch();

    // A snapshot from a leader whose count is lower replaces the key space.
    storage
        .put(&sys, &epoch_key, &(high - 5).to_le_bytes())
        .expect("snapshot-installed epoch");
    node.on_replicated_reset();

    // Another node suspends the realm: one bump above the snapshot's epoch,
    // still below the old high-water mark.
    let other_node = engine_over(&storage, &clock);
    suspend(&other_node, &realm);
    clock.advance(EPOCH_SYNC_INTERVAL_MICROS + 1);
    assert!(
        binds_suspension(&node, &realm, &token),
        "a suspension asserted after a snapshot lowered the control epoch never bound here"
    );
}
