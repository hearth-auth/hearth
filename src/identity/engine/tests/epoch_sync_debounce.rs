//! Epoch reconciliation on the token-validation hot path.
//!
//! `validate_token` reconciles two cluster epochs before it consults the
//! token-claims cache: the control epoch (realm suspend, token revocation, DPoP
//! blocklist) and the realm signing-key epoch. Task 24.6 put both there
//! deliberately. A warm cache hit returns without ever reaching signature
//! verification, so a control asserted on another node would otherwise go
//! unobserved exactly when the token is most likely to be one an operator has
//! just revoked.
//!
//! Each reconciliation reads a row from storage, and each read allocates: the
//! encoded key, plus the `Vec<u8>` the value returns in. Running them per call
//! therefore broke two hot-path rules at once — the zero-allocation budget that
//! `benches/validate_token.rs` gates at `MAX_ALLOCS_PER_CALL = 0`, and the ban
//! on storage reads from the read path.
//!
//! The reconciliation is debounced rather than removed. Inside a window the hot
//! path reads the clock and one atomic and returns; once per
//! `EPOCH_SYNC_INTERVAL_MICROS` it pays for the two rows. Staleness becomes
//! bounded instead of zero — and it was *unbounded* before task 24.6, because a
//! warm hit consulted nothing at all.
//!
//! The cache-miss path keeps reconciling unconditionally: it is already paying
//! for an Ed25519 verify, so the rows cost it nothing in relative terms.

use super::*;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::storage::{ScanEntry, StorageDurabilityHandle, StorageError};

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// True for the two rows the hot-path epoch reconciliation reads.
fn is_epoch_row(key: &[u8]) -> bool {
    key == keys::encode_control_epoch().as_slice() || key.starts_with(b"realm:keygen:")
}

/// Storage double that counts reads of the epoch rows. Everything else — every
/// method, and every other key — passes straight through to the real engine.
struct EpochReadCountingStorage {
    inner: Arc<dyn StorageEngine>,
    epoch_reads: AtomicUsize,
}

impl EpochReadCountingStorage {
    fn new(inner: Arc<dyn StorageEngine>) -> Self {
        Self {
            inner,
            epoch_reads: AtomicUsize::new(0),
        }
    }

    fn reset(&self) {
        self.epoch_reads.store(0, Ordering::SeqCst);
    }

    fn epoch_reads(&self) -> usize {
        self.epoch_reads.load(Ordering::SeqCst)
    }
}

impl StorageEngine for EpochReadCountingStorage {
    fn get(&self, realm_id: &RealmId, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        if is_epoch_row(key) {
            self.epoch_reads.fetch_add(1, Ordering::SeqCst);
        }
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

/// Builds an engine over storage and a clock the caller owns, so two engines
/// can share both and stand in for two nodes of one cluster.
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

/// Creates a realm, a user and a session, and returns a live access token.
fn seed_token(engine: &EmbeddedIdentityEngine) -> (RealmId, String) {
    let realm = engine
        .create_realm(&CreateRealmRequest {
            name: format!("epoch-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();

    let user = engine
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "epoch@example.com".to_string(),
                display_name: "Epoch User".to_string(),
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

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

/// The hot path must not read the epoch rows on every call.
///
/// This is the storage-read half of the budget `benches/validate_token.rs`
/// gates. The benchmark counts allocations; this counts the reads that cause
/// them, which is the property that actually has to hold.
#[test]
fn the_epoch_rows_are_not_read_on_every_validation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let inner = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf())).expect("open"),
    ) as Arc<dyn StorageEngine>;
    let counting = Arc::new(EpochReadCountingStorage::new(inner));
    let storage = Arc::clone(&counting) as Arc<dyn StorageEngine>;
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
    let engine = engine_over(&storage, &clock);

    let (realm, token) = seed_token(&engine);

    // Warm every cache, and let this first call claim the debounce window.
    engine
        .validate_token(&realm, &token)
        .expect("warm validate");

    counting.reset();
    for _ in 0..64 {
        engine.validate_token(&realm, &token).expect("validate");
    }

    assert_eq!(
        counting.epoch_reads(),
        0,
        "validate_token read an epoch row {} times across 64 warm calls inside \
         one debounce window; the hot path must perform no storage read",
        counting.epoch_reads()
    );
}

/// A control asserted on another node still binds, within one window.
///
/// Two engines share one storage and one clock, which is the two-node case task
/// 24.6 exists for. The suspend is invisible to the validator until the window
/// closes, and unmissable afterwards. Both halves are asserted: without the
/// first the debounce is untested, without the second the security property is.
#[test]
fn a_control_asserted_on_another_node_binds_within_one_debounce_window() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf())).expect("open"),
    ) as Arc<dyn StorageEngine>;
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));

    let validator = engine_over(&storage, &clock);
    let other_node = engine_over(&storage, &clock);

    let (realm, token) = seed_token(&validator);
    validator
        .validate_token(&realm, &token)
        .expect("warm validate");

    other_node
        .update_realm(
            &realm,
            &UpdateRealmRequest {
                status: Some(RealmStatus::Suspended),
                ..Default::default()
            },
        )
        .expect("suspend the realm from the other node");

    // Inside the window the validator is deliberately, boundedly stale.
    let stale = validator
        .validate_token(&realm, &token)
        .expect("inside the debounce window the suspend is not yet observed");
    assert_eq!(
        stale.tid.parse::<RealmId>().expect("tid parses"),
        realm,
        "the stale validation returned claims for a different realm"
    );

    clock.advance(EPOCH_SYNC_INTERVAL_MICROS + 1);

    // Past the window the validator observes the moved epoch and signals its
    // background reloader; the reload does not run on the validating thread,
    // so the suspension binds a moment later rather than on this very call.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut bound = false;
    while std::time::Instant::now() < deadline {
        if matches!(
            validator.validate_token(&realm, &token),
            Err(IdentityError::RealmSuspended)
        ) {
            bound = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(
        bound,
        "past the debounce window the validator still honoured a realm that \
         another node suspended"
    );
}

/// Sets up two "nodes" over one storage and clock, two realms with a warm
/// token each, and a revoking rotation of realm B's signing key made on the
/// other node. Returns the validator, the clock and both (realm, token) pairs.
#[allow(clippy::type_complexity)]
fn two_realms_and_a_rotation_elsewhere() -> (
    tempfile::TempDir,
    EmbeddedIdentityEngine,
    Arc<FakeClock>,
    (RealmId, String),
    (RealmId, String),
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf())).expect("open"),
    ) as Arc<dyn StorageEngine>;
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
    let validator = engine_over(&storage, &clock);
    let other_node = engine_over(&storage, &clock);

    let busy = seed_token(&validator);
    // Two realms hashed into one debounce window share it by design; pick a
    // quiet realm with a window of its own so the test is deterministic.
    let quiet = std::iter::repeat_with(|| seed_token(&validator))
        .take(16)
        .find(|q| realm_epoch_window(&q.0) != realm_epoch_window(&busy.0))
        .expect("a realm in a different debounce window");
    validator.validate_token(&busy.0, &busy.1).expect("warm A");
    validator
        .validate_token(&quiet.0, &quiet.1)
        .expect("warm B");

    // A revoking rotation (no grace) of the quiet realm's key, elsewhere: the
    // remedy for a leaked key. Every token B signed before it must die.
    other_node
        .rotate_realm_signing_key(&quiet.0, 0)
        .expect("rotate B's key on the other node");
    (dir, validator, clock, busy, quiet)
}

/// Audit GA 2026-09-28 M5: one global debounce slot reconciled only the realm
/// of the request that won it. While realm A's traffic kept winning the slot,
/// a quiet realm B whose key another node had revoked stayed trusted from the
/// warm claims cache indefinitely — not for one window. Each realm must get
/// its own window.
#[test]
fn a_busy_realm_does_not_starve_a_quiet_realms_key_epoch_reconciliation() {
    let (_dir, validator, clock, busy, quiet) = two_realms_and_a_rotation_elsewhere();

    clock.advance(EPOCH_SYNC_INTERVAL_MICROS + 1);
    // Realm A's request arrives first and claims the window.
    validator
        .validate_token(&busy.0, &busy.1)
        .expect("A is unaffected by B's rotation");

    let after = validator.validate_token(&quiet.0, &quiet.1);
    assert!(
        matches!(after, Err(IdentityError::InvalidToken)),
        "past the debounce window a token signed by realm B's revoked key was still \
         accepted, because realm A's request had claimed the only reconciliation slot \
         (error: {:?})",
        after.as_ref().err()
    );
}

/// Audit GA 2026-09-28 M5, cluster half: the signing-key epoch had no
/// replicated-write observer, so a follower learned of a rotation only from
/// the debounced read. The replicated `realm:keygen:` row must invalidate the
/// realm's keys directly, inside the window.
#[test]
fn a_replicated_key_epoch_row_invalidates_the_realms_keys_at_once() {
    use crate::cluster::ReplicatedWriteObserver as _;

    let (_dir, validator, _clock, _busy, quiet) = two_realms_and_a_rotation_elsewhere();
    let sys_realm = keys::system_realm_id();
    let row = keys::encode_realm_key_epoch(&quiet.0);
    let value = validator
        .storage
        .get(&sys_realm, &row)
        .expect("read the epoch row")
        .expect("the rotation wrote the epoch row");

    validator.on_replicated_put(&sys_realm, &row, &value);

    let after = validator.validate_token(&quiet.0, &quiet.1);
    assert!(
        matches!(after, Err(IdentityError::InvalidToken)),
        "inside the debounce window, after the replicated key-epoch row was observed, a \
         token signed by the revoked key was still accepted (error: {:?})",
        after.as_ref().err()
    );
}
