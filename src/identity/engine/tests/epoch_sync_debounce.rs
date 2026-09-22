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

    assert!(
        matches!(
            validator.validate_token(&realm, &token),
            Err(IdentityError::RealmSuspended)
        ),
        "past the debounce window the validator still honoured a realm that \
         another node suspended"
    );
}
