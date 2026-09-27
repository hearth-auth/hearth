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
    /// Refuse `increment_u64` (a control-epoch bump) while set.
    fail_increments: AtomicBool,
    /// Refuse `increment_u64` with the error cluster storage returns on a
    /// node that is not the Raft leader, while set.
    not_leader_increments: AtomicBool,
    /// Hold every `increment_u64` (block the caller) while set — a Raft
    /// proposal waiting out `write_timeout` on a leader that lost its quorum.
    hold_increments: AtomicBool,
    /// Panic in this many `increment_u64` calls (then behave normally) — a
    /// storage bug unwinding through the bump thread's `catch_unwind`.
    panic_increments: AtomicUsize,
    /// Every `increment_u64` call, refused or not.
    increment_attempts: AtomicUsize,
    /// Scans refused while `fail_scans` was set.
    failed_scans: AtomicUsize,
    writes: AtomicUsize,
    /// Runs after every successful `increment_u64`, with the new value,
    /// before the increment returns to its caller.
    on_increment: std::sync::Mutex<Option<IncrementHook>>,
}

/// See [`FaultStorage::on_increment`].
type IncrementHook = Arc<dyn Fn(u64) + Send + Sync>;

impl FaultStorage {
    fn over(inner: Arc<dyn StorageEngine>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            fail_scans: AtomicBool::new(false),
            fail_increments: AtomicBool::new(false),
            not_leader_increments: AtomicBool::new(false),
            hold_increments: AtomicBool::new(false),
            panic_increments: AtomicUsize::new(0),
            increment_attempts: AtomicUsize::new(0),
            failed_scans: AtomicUsize::new(0),
            writes: AtomicUsize::new(0),
            on_increment: std::sync::Mutex::new(None),
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
            self.failed_scans.fetch_add(1, Ordering::SeqCst);
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
        self.increment_attempts.fetch_add(1, Ordering::SeqCst);
        while self.hold_increments.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(5));
        }
        if self
            .panic_increments
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            panic!("injected panic in increment_u64");
        }
        if self.not_leader_increments.load(Ordering::SeqCst) {
            return Err(crate::cluster::engine::cluster_to_storage_err(
                crate::cluster::ClusterError::NotLeader {
                    leader_addr: "unknown".to_string(),
                },
            ));
        }
        if self.fail_increments.load(Ordering::SeqCst) {
            return Err(StorageError::Io(std::io::Error::other(
                "injected increment failure (e.g. a leader change between two proposals)",
            )));
        }
        self.wrote();
        let next = self.inner.increment_u64(realm_id, key)?;
        let hook = self.on_increment.lock().expect("hook lock").clone();
        if let Some(hook) = hook {
            hook(next);
        }
        Ok(next)
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
/// The test holds both control-plane locks — the one that orders control
/// writers against the reloader, and the one-reload-at-a-time lock — and
/// drives a validation down the epoch-moved branch. Before the fix that
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

    // Both locks the control plane has: writers/reloader, and one-reload-
    // at-a-time.
    let wakes_before = engine.control.wakes_for_test();
    let reload_guard = engine.control.lock_reload_for_test();
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
    drop(reload_guard);
    validator.join().expect("validator thread");
    assert!(
        matches!(outcome, Ok(Ok(()))),
        "validate_token did not complete while the control writer/reloader lock was held: \
         {outcome:?}"
    );
    assert_eq!(
        engine.control.wakes_for_test() - wakes_before,
        1,
        "the validation must have taken the moved-epoch branch (signalled the reloader)"
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
    let deadline = Instant::now() + CONVERGE;
    while fault.failed_scans.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        fault.failed_scans.load(Ordering::SeqCst) > 0,
        "the reload never ran into the injected scan failure, so this test proves nothing"
    );

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

    let wakes_before = engine.control.wakes_for_test();
    let started = Instant::now();
    for _ in 0..200 {
        // Another node asserts a control, and the debounce has elapsed: this
        // validation takes the moved-epoch branch while the reload (holding
        // the reload lock) is parked mid-flight.
        storage
            .increment_u64(&keys::system_realm_id(), &keys::encode_control_epoch())
            .expect("bump the persisted epoch");
        clock.advance(EPOCH_SYNC_INTERVAL_MICROS + 1);
        engine
            .validate_token(&realm, &token)
            .expect("a validation during an in-flight reload");
    }
    let elapsed = started.elapsed();
    let signalled = engine.control.wakes_for_test() - wakes_before;
    drop(held.release);
    assert!(
        elapsed < Duration::from_secs(2),
        "200 validations took {elapsed:?} while a reload was held mid-flight"
    );
    assert_eq!(
        signalled, 200,
        "every validation must have seen a moved epoch and signalled the reloader, or the loop \
         never exercised the branch that could wait on the reload"
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

/// Validation signals on every debounced sync that sees the persisted epoch
/// ahead; only a signal that raises the target should wake the reloader.
/// Every call used to `unpark` it, so a node trailing by one epoch woke its
/// reloader on every sync until the reload landed.
#[test]
fn only_a_signal_that_raises_the_target_wakes_the_reloader() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = open_storage(&dir);
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
    let engine = engine_over(&storage, &clock);
    let plane = &engine.control;
    let target = plane.applied_epoch() + 5;

    let before = plane.wakes_for_test();
    plane.signal(target);
    plane.signal(target);
    plane.signal(target - 1);
    assert_eq!(
        plane.wakes_for_test() - before,
        1,
        "repeating or lowering a signalled epoch must not wake the reloader again"
    );
    plane.signal(target + 1);
    assert_eq!(
        plane.wakes_for_test() - before,
        2,
        "a higher epoch wakes it"
    );
}

/// On a cluster leader the Raft observer sees this node's own epoch bump
/// replicate back and signals it BEFORE the writer that made the bump records
/// it. A writer slower than the reloader's settle delay (5 ms) used to lose
/// that race: the leader reloaded every control cache — and dropped its
/// session and token-claims caches — for a control it had applied itself.
/// Reloads now wait for this node's in-flight bumps to be recorded.
#[test]
fn a_node_does_not_reload_for_its_own_control() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fault = FaultStorage::over(open_storage(&dir));
    let storage = Arc::clone(&fault) as Arc<dyn StorageEngine>;
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
    let engine = engine_over(&storage, &clock);

    let reloads = Arc::new(AtomicUsize::new(0));
    {
        let reloads = Arc::clone(&reloads);
        engine.control.set_scan_hook(Some(Arc::new(move || {
            reloads.fetch_add(1, Ordering::SeqCst);
        })));
    }
    // The observer's signal lands first; the writer then takes 50 ms — ten
    // settle delays — to record the epoch its bump produced.
    {
        let plane = Arc::clone(&engine.control);
        *fault.on_increment.lock().expect("hook lock") = Some(Arc::new(move |epoch| {
            plane.signal(epoch);
            std::thread::sleep(Duration::from_millis(50));
        }));
    }

    engine.bump_control_epoch();
    let bumped = engine.control.applied_epoch();
    std::thread::sleep(Duration::from_millis(400));

    assert_eq!(
        reloads.load(Ordering::SeqCst),
        0,
        "the node reloaded its control caches for a control it applied itself"
    );
    assert_eq!(engine.control.applied_epoch(), bumped);
}

/// With no reloader running (its thread failed to start), nothing ever covers
/// the gaps between this node's own epochs, so the epochs parked above
/// `applied` must stay bounded instead of growing for the life of the process.
#[test]
fn parked_local_epochs_stay_bounded_without_a_reloader() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = open_storage(&dir);
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
    let plane = control::ControlPlane::new(
        storage,
        clock as Arc<dyn Clock>,
        control::ControlCaches::new(),
    );
    // Every other epoch is another node's: none is contiguous with `applied`.
    for epoch in (2..20_000_u64).step_by(2) {
        plane.apply(None, Some(epoch));
    }
    assert!(
        plane.parked_local_epochs_for_test() <= control::MAX_PARKED_LOCAL_EPOCHS,
        "parked local epochs grew to {}",
        plane.parked_local_epochs_for_test()
    );
}

/// Deleting a user removes its sessions, and every other node must stop
/// accepting them. The delete removed the session rows and evicted them from
/// the deleting node's cache only; it published no control, so a node that had
/// the session cached kept validating the deleted user's tokens (a cache hit
/// never consults storage) until something else moved the control epoch.
#[test]
fn deleting_a_user_on_another_node_ends_its_sessions_here() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = open_storage(&dir);
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
    let node = engine_over(&storage, &clock);
    let other_node = engine_over(&storage, &clock);
    let (realm, token) = seed_token(&node);
    let claims = node.validate_token(&realm, &token).expect("warm the cache");
    let user = UserId::new(
        uuid::Uuid::parse_str(claims.sub.strip_prefix("user_").unwrap_or(&claims.sub))
            .expect("user id in sub"),
    );

    other_node
        .delete_user(&realm, &user)
        .expect("delete the user");
    clock.advance(EPOCH_SYNC_INTERVAL_MICROS + 1);

    let deadline = Instant::now() + CONVERGE;
    let mut still_valid = true;
    while Instant::now() < deadline {
        if node.validate_token(&realm, &token).is_err() {
            still_valid = false;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        !still_valid,
        "a node that had the session cached kept accepting a deleted user's token"
    );
}

/// L1: after a reset reload the persisted epoch is re-read and signalled, so
/// a control replicated during the reset still causes a reload. A failed
/// re-read was discarded (`if let Ok(..)`): the reload reported success and
/// nothing re-queued it, so that control could stay unbound here until the
/// next one. A failed re-read now queues another reset reload.
#[test]
fn a_failed_epoch_reread_after_a_reset_requeues_the_reset() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = open_storage(&dir);
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
    let node = engine_over(&storage, &clock);
    let sys = keys::system_realm_id();
    let epoch_key = keys::encode_control_epoch();
    storage.increment_u64(&sys, &epoch_key).expect("bump");

    // The row goes bad after the scan read it, before the re-read.
    let corrupting = Arc::clone(&storage);
    let (sys_h, key_h) = (sys.clone(), epoch_key.clone());
    node.control.set_scan_hook(Some(Arc::new(move || {
        corrupting.put(&sys_h, &key_h, b"bad").expect("corrupt");
    })));
    assert!(!node.control.reset_reload_queued_for_test());
    let _ = node.control.reload_after_reset();
    node.control.set_scan_hook(None);
    assert!(
        node.control.reset_reload_queued_for_test(),
        "a failed epoch re-read after a reset must queue another reset reload"
    );
}

/// A control whose durable row committed but whose epoch bump failed (for
/// example a leader change between the two Raft proposals) must still reach
/// every other node. The bump used to be logged and counted and then
/// forgotten: the admin call succeeded and other nodes enforced the stale
/// control indefinitely — until some unrelated control bumped the epoch.
/// The owed bump is now retried by the reloader until it succeeds.
#[test]
fn a_failed_epoch_bump_is_retried_until_other_nodes_bind() {
    let dir = tempfile::tempdir().expect("tempdir");
    let shared = open_storage(&dir);
    let fault = FaultStorage::over(Arc::clone(&shared));
    let faulty_storage = Arc::clone(&fault) as Arc<dyn StorageEngine>;
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));

    let validator = engine_over(&shared, &clock);
    let (realm, token) = seed_token(&validator);
    let asserting_node = engine_over(&faulty_storage, &clock);
    validator.validate_token(&realm, &token).expect("warm");

    fault.fail_increments.store(true, Ordering::SeqCst);
    suspend(&asserting_node, &realm);
    assert_eq!(
        asserting_node.control.owed_bumps(),
        1,
        "the failed bump must be recorded as owed"
    );

    // The failure window: the row is written, the epoch did not move, so the
    // other node still accepts the token.
    clock.advance(EPOCH_SYNC_INTERVAL_MICROS + 1);
    validator
        .validate_token(&realm, &token)
        .expect("precondition: without the bump the other node has not reloaded");

    // The fault clears on this same node — a transient failure (a write
    // timeout, say) while it is still the leader — and the owed bump must go
    // out. A leader change is a different case: the node that owes the bump is
    // then a follower that can never make it, and the new leader's election
    // bump covers it instead
    // (`a_bump_refused_as_not_leader_is_dropped_not_retried` here, and the
    // real leader change in `tests/cluster_three_node_control_coherence.rs`).
    fault.fail_increments.store(false, Ordering::SeqCst);
    let deadline = Instant::now() + CONVERGE;
    let mut bound = false;
    while Instant::now() < deadline {
        clock.advance(EPOCH_SYNC_INTERVAL_MICROS + 1);
        if matches!(
            validator.validate_token(&realm, &token),
            Err(IdentityError::RealmSuspended)
        ) {
            bound = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        bound,
        "a suspension whose epoch bump failed never bound on another node after the fault \
         cleared: the owed bump was not retried"
    );
    assert_eq!(
        asserting_node.control.owed_bumps(),
        0,
        "a successful retry pays the owed bump"
    );
}

/// Cluster storage has no follower-to-leader write forwarding: once
/// leadership moved, every bump a node owes is refused as `NotLeader`, forever.
/// It used to be retried every 5 s for as long as the node lived. The node
/// now drops those bumps — the new leader bumps the epoch when it is elected,
/// and that bump orders after every control row the old leader committed —
/// and stops retrying.
#[test]
fn a_bump_refused_as_not_leader_is_dropped_not_retried() {
    let dir = tempfile::tempdir().expect("tempdir");
    let shared = open_storage(&dir);
    let fault = FaultStorage::over(Arc::clone(&shared));
    let faulty_storage = Arc::clone(&fault) as Arc<dyn StorageEngine>;
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
    let node = engine_over(&faulty_storage, &clock);
    let (realm, _token) = seed_token(&node);

    fault.not_leader_increments.store(true, Ordering::SeqCst);
    suspend(&node, &realm);

    let deadline = Instant::now() + CONVERGE;
    while node.control.owed_bumps() > 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        node.control.owed_bumps(),
        0,
        "a bump refused as NotLeader must be dropped, not owed forever"
    );
    // And not retried: nothing is owed any more, so no further increment.
    let attempts = fault.increment_attempts.load(Ordering::SeqCst);
    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(
        fault.increment_attempts.load(Ordering::SeqCst),
        attempts,
        "a dropped bump must not be retried"
    );
    #[allow(clippy::float_cmp)] // an integral count stored as f64
    {
        assert_eq!(
            crate::metrics::metrics().control_epoch_bumps_owed.get(),
            0.0,
            "the owed gauge must not keep counting a dropped bump"
        );
    }
}

/// A node that becomes the Raft leader bumps the control epoch once, so
/// every node — itself included — reloads and picks up any control row
/// committed under the previous leader whose own bump never went out.
#[test]
fn becoming_leader_bumps_the_epoch_once_and_every_node_reloads() {
    use crate::cluster::ReplicatedWriteObserver as _;
    let dir = tempfile::tempdir().expect("tempdir");
    let shared = open_storage(&dir);
    let fault = FaultStorage::over(Arc::clone(&shared));
    let faulty_storage = Arc::clone(&fault) as Arc<dyn StorageEngine>;
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));

    // The old leader: its row writes land, its bumps never do.
    let old_leader = engine_over(&faulty_storage, &clock);
    let (realm, token) = seed_token(&old_leader);
    let bystander = engine_over(&shared, &clock);
    let new_leader = engine_over(&shared, &clock);
    for node in [&bystander, &new_leader] {
        node.validate_token(&realm, &token).expect("warm");
    }
    fault.fail_increments.store(true, Ordering::SeqCst);
    suspend(&old_leader, &realm);
    clock.advance(EPOCH_SYNC_INTERVAL_MICROS + 1);
    for node in [&bystander, &new_leader] {
        node.validate_token(&realm, &token)
            .expect("precondition: the failed bump left the other nodes unaware");
    }

    let sys = keys::system_realm_id();
    let epoch_key = keys::encode_control_epoch();
    let read_epoch = || {
        crate::storage::decode_u64_counter(shared.get(&sys, &epoch_key).expect("get").as_deref())
            .expect("epoch")
    };
    let before = read_epoch();
    new_leader.on_leadership_acquired();

    for (name, node) in [("bystander", &bystander), ("new leader", &new_leader)] {
        let deadline = Instant::now() + CONVERGE;
        let mut bound = false;
        while Instant::now() < deadline {
            clock.advance(EPOCH_SYNC_INTERVAL_MICROS + 1);
            if matches!(
                node.validate_token(&realm, &token),
                Err(IdentityError::RealmSuspended)
            ) {
                bound = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            bound,
            "the {name} never bound a control committed under the previous leader: \
             becoming leader must bump the control epoch"
        );
    }
    assert_eq!(
        read_epoch(),
        before + 1,
        "one leadership acquisition is one epoch bump"
    );
}

/// The bump thread runs each attempt under `catch_unwind`. An election bump
/// clears its flag before the increment, and the flag used to be restored only
/// on an `Err` — so a panic in the increment lost a pure election bump for
/// good: nothing was owed, the flag was clear, and no node ever reloaded for
/// the controls the previous leader's lost bumps covered.
#[test]
fn a_panicking_election_bump_is_retried_not_lost() {
    let dir = tempfile::tempdir().expect("tempdir");
    let shared = open_storage(&dir);
    let fault = FaultStorage::over(Arc::clone(&shared));
    let faulty_storage = Arc::clone(&fault) as Arc<dyn StorageEngine>;
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
    let node = engine_over(&faulty_storage, &clock);

    let sys = keys::system_realm_id();
    let epoch_key = keys::encode_control_epoch();
    let read_epoch = || {
        crate::storage::decode_u64_counter(shared.get(&sys, &epoch_key).expect("get").as_deref())
            .unwrap_or(0)
    };
    let before = read_epoch();
    fault.panic_increments.store(1, Ordering::SeqCst);
    node.on_leadership_acquired();

    let deadline = Instant::now() + CONVERGE;
    while read_epoch() == before && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        fault.increment_attempts.load(Ordering::SeqCst) >= 2,
        "the panicking attempt must be followed by a retry"
    );
    assert_eq!(
        read_epoch(),
        before + 1,
        "an election bump whose first attempt panicked must still be made, exactly once"
    );
}

/// An owed bump retry can block for a whole `write_timeout` (10 s by
/// default) on a leader that lost its quorum. It used to run on the reloader
/// thread, so while it blocked this node reloaded for nothing: controls
/// asserted on other nodes went unenforced here. The retry now runs off the
/// reloader's path.
#[test]
fn a_blocked_bump_retry_does_not_hold_up_reloads() {
    let dir = tempfile::tempdir().expect("tempdir");
    let shared = open_storage(&dir);
    let fault = FaultStorage::over(Arc::clone(&shared));
    let faulty_storage = Arc::clone(&fault) as Arc<dyn StorageEngine>;
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));

    let other = engine_over(&shared, &clock);
    let (realm, token) = seed_token(&other);
    let node = engine_over(&faulty_storage, &clock);
    // Releases the held increment before `node` drops (locals drop in reverse
    // order), so its threads can be joined.
    struct Release(Arc<FaultStorage>);
    impl Drop for Release {
        fn drop(&mut self) {
            self.0.hold_increments.store(false, Ordering::SeqCst);
        }
    }
    let _release = Release(Arc::clone(&fault));
    node.validate_token(&realm, &token).expect("warm");

    // This node owes a bump, and its retry is now stuck inside the increment.
    let (own_realm, _) = seed_token(&node);
    fault.fail_increments.store(true, Ordering::SeqCst);
    suspend(&node, &own_realm);
    fault.fail_increments.store(false, Ordering::SeqCst);
    let attempts = fault.increment_attempts.load(Ordering::SeqCst);
    fault.hold_increments.store(true, Ordering::SeqCst);
    let deadline = Instant::now() + CONVERGE;
    while fault.increment_attempts.load(Ordering::SeqCst) == attempts {
        assert!(Instant::now() < deadline, "the owed bump was never retried");
        std::thread::sleep(Duration::from_millis(5));
    }

    // Another node asserts a control; this node must still reload for it.
    suspend(&other, &realm);
    clock.advance(EPOCH_SYNC_INTERVAL_MICROS + 1);
    assert!(
        binds_suspension(&node, &realm, &token),
        "a bump retry blocked in storage stopped this node reloading for a control \
         asserted elsewhere"
    );
}

/// `hearth_control_epoch_bumps_owed` is one process-wide gauge, and a process
/// can hold more than one identity engine. Each engine used to `set` its own
/// count, so the gauge showed whichever wrote last, and an engine dropped
/// while owing kept its count on the gauge. It is now the sum over live
/// engines.
#[test]
fn the_owed_gauge_sums_every_engine_and_forgets_a_dropped_one() {
    let owed_gauge = || crate::metrics::metrics().control_epoch_bumps_owed.get();
    let dir = tempfile::tempdir().expect("tempdir");
    let shared = open_storage(&dir);
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
    let fault_a = FaultStorage::over(Arc::clone(&shared));
    let fault_b = FaultStorage::over(Arc::clone(&shared));
    let a = engine_over(&(Arc::clone(&fault_a) as Arc<dyn StorageEngine>), &clock);
    let b = engine_over(&(Arc::clone(&fault_b) as Arc<dyn StorageEngine>), &clock);
    let (realm_a, _) = seed_token(&a);
    let (realm_b, _) = seed_token(&b);
    fault_a.fail_increments.store(true, Ordering::SeqCst);
    fault_b.fail_increments.store(true, Ordering::SeqCst);
    suspend(&a, &realm_a);
    suspend(&b, &realm_b);
    let owed = a.control.owed_bumps() + b.control.owed_bumps();
    assert!(owed >= 2, "precondition: both engines owe");
    #[allow(clippy::cast_precision_loss, clippy::float_cmp)]
    {
        assert_eq!(
            owed_gauge(),
            owed as f64,
            "the gauge is the sum over engines"
        );
        let b_owed = b.control.owed_bumps();
        drop(b);
        assert_eq!(
            owed_gauge(),
            (owed - b_owed) as f64,
            "a dropped engine's owed bumps leave the gauge"
        );
    }
}
