//! A node out of contact accepts no credential (`cluster-consistency` V2).
//!
//! `validate_token` and the session lookup serve from in-memory caches, so
//! the storage-level read fence never sees them. They ask
//! [`StorageEngine::serves_reads`] first, and answer its error: the protocol
//! layer turns it into `503` with `HEARTH_CLUSTER_UNAVAILABLE`. The refresh
//! path asks too, so a refresh fails the same way whatever it reads first.

use super::*;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::storage::{
    ClusterUnavailableCause, RetryClass, ScanEntry, StorageDurabilityHandle, StorageError,
};

/// Storage whose read gate the test opens and closes. Every read and write
/// passes straight through: only `serves_reads` changes, so a refusal proves
/// the caller asked the gate, not that a storage read failed.
struct GatedStorage {
    inner: Arc<dyn StorageEngine>,
    open: AtomicBool,
}

impl GatedStorage {
    fn set_open(&self, open: bool) {
        self.open.store(open, Ordering::SeqCst);
    }
}

impl StorageEngine for GatedStorage {
    fn serves_reads(&self) -> Result<(), StorageError> {
        if self.open.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(StorageError::ClusterUnavailable {
                cause: ClusterUnavailableCause::NotInContact,
                reason: "test gate closed".to_string(),
            })
        }
    }

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
        self.inner.scan(realm_id, start, end)
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

/// An engine over open gated storage, a realm, a user, a session and its
/// tokens.
struct Fixture {
    _dir: tempfile::TempDir,
    storage: Arc<GatedStorage>,
    engine: EmbeddedIdentityEngine,
    realm: RealmId,
    session: SessionId,
    pair: TokenPair,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let inner = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf())).expect("open"),
    ) as Arc<dyn StorageEngine>;
    let storage = Arc::new(GatedStorage {
        inner,
        open: AtomicBool::new(true),
    });
    let dyn_storage = Arc::clone(&storage) as Arc<dyn StorageEngine>;
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000))) as Arc<dyn Clock>;
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&dyn_storage),
        Arc::clone(&clock),
    ));
    let engine = EmbeddedIdentityEngine::new(
        dyn_storage,
        clock,
        IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        },
        audit as Arc<dyn AuditEngine>,
    )
    .expect("engine creation")
    .with_hibp_transport(Arc::new(NeverPwnedStub));
    let realm = engine
        .create_realm(&CreateRealmRequest {
            name: format!("fence-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();
    let user = engine
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "fence@example.com".to_string(),
                display_name: "Fence User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    let session = engine
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("create session")
        .id()
        .clone();
    let pair = engine
        .issue_tokens(&realm, user.id(), &session)
        .expect("issue tokens");
    Fixture {
        _dir: dir,
        storage,
        engine,
        realm,
        session,
        pair,
    }
}

/// Whether `err` is the unavailable storage error the protocol layer answers
/// `503` `HEARTH_CLUSTER_UNAVAILABLE`.
fn is_unavailable(err: &IdentityError) -> bool {
    matches!(err, IdentityError::Storage(e)
        if StorageError::retry_class_of(&**e) == Some(RetryClass::Unavailable))
}

#[test]
fn a_closed_gate_refuses_a_token_the_claims_cache_holds() {
    let f = fixture();
    let token = f.pair.access_token();
    // Warm the claims cache and the session cache.
    let warm = f.engine.validate_token(&f.realm, token).expect("warm");

    f.storage.set_open(false);
    let err = f
        .engine
        .validate_token(&f.realm, token)
        .expect_err("a node out of contact accepts no access token");
    assert!(is_unavailable(&err), "{err:?}");

    f.storage.set_open(true);
    let reopened = f.engine.validate_token(&f.realm, token).expect("reopened");
    assert_eq!(reopened.sid, warm.sid, "the same token, accepted again");
}

#[test]
fn a_closed_gate_refuses_a_session_the_session_cache_holds() {
    let f = fixture();
    let warm = f.engine.get_session(&f.realm, &f.session).expect("warm");
    assert_eq!(warm.map(|s| s.id().clone()), Some(f.session.clone()));

    f.storage.set_open(false);
    let err = f
        .engine
        .get_session(&f.realm, &f.session)
        .expect_err("a node out of contact accepts no session");
    assert!(is_unavailable(&err), "{err:?}");
}

#[test]
fn a_closed_gate_refuses_a_refresh() {
    let f = fixture();
    f.storage.set_open(false);
    let err = f
        .engine
        .refresh_tokens(&f.realm, f.pair.refresh_token(), None, None)
        .expect_err("a node out of contact accepts no refresh token");
    assert!(is_unavailable(&err), "{err:?}");
}

/// Introspection and the permission decision answer an unchecked token
/// `active: false` / `allowed: false`. A closed gate is no such answer: the
/// token may be valid, so they return the unavailable error instead.
#[test]
fn a_closed_gate_refuses_introspection_and_a_permission_decision() {
    let f = fixture();
    let token = f.pair.access_token().to_string();
    f.storage.set_open(false);

    let err = f
        .engine
        .introspect_token(
            &f.realm,
            &crate::identity::oidc::TokenIntrospectionRequest {
                token: token.clone(),
                token_type_hint: None,
                introspecting_client_id: None,
            },
        )
        .expect_err("a node out of contact does not judge a token inactive");
    assert!(is_unavailable(&err), "{err:?}");

    let err = f
        .engine
        .decide_token_permission(
            &f.realm,
            &crate::identity::oidc::DecidePermissionRequest {
                token,
                permission: "docs.read".to_string(),
                organization_id: None,
                resource: None,
            },
        )
        .expect_err("a node out of contact does not deny a valid token");
    assert!(is_unavailable(&err), "{err:?}");
}
