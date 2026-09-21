//! A-4 / task 26.14 — the AAT revocation blocklist must fail **closed**.
//!
//! `parse_and_validate_aat` walks `claims.aat_chain` and asks storage whether
//! each JTI carries an `aat:rev:` tombstone. The pre-fix loop was
//! `if let Ok(Some(_)) = self.storage.get(…)`, which put a storage `Err` in the
//! same branch as "absent" and accepted the token. The fix `?`-propagates the
//! read; this file is the proof that it does, which the audit could not supply
//! because it looked only at `FaultFs` (which sits under the filesystem, not
//! under the `StorageEngine` trait the engine actually calls).
//!
//! The wrapper below fails **only** reads of the `aat:rev:` key family, so a
//! green control case on the same fixture rules out the vacuous reading where
//! the token is refused for some unrelated reason.

mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{Clock, RealmId, SystemClock};
use hearth::identity::{
    AgentOwner, CreateAgentRequest, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, IdentityError, IssueAatRequest,
};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{
    EmbeddedStorageEngine, ScanEntry, StorageConfig, StorageEngine, StorageError,
};

/// The `aat:rev:` key prefix, mirroring `identity::keys::AAT_REVOKED_JTI_PREFIX`
/// (crate-private, so the literal is restated here).
const AAT_REVOKED_PREFIX: &[u8] = b"aat:rev:";

/// Fails `get()` for the AAT revocation blocklist only, once armed.
struct RevocationReadFaultEngine {
    inner: Arc<EmbeddedStorageEngine>,
    armed: Arc<AtomicBool>,
}

impl StorageEngine for RevocationReadFaultEngine {
    fn get(&self, realm_id: &RealmId, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        if self.armed.load(Ordering::Relaxed) && key.starts_with(AAT_REVOKED_PREFIX) {
            return Err(StorageError::Io(std::io::Error::other(
                "injected revocation-blocklist read fault",
            )));
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

/// A live AAT plus the switch that breaks its revocation lookup.
struct Fixture {
    identity: Arc<dyn IdentityEngine>,
    realm: RealmId,
    aat: String,
    armed: Arc<AtomicBool>,
    _temp: tempfile::TempDir,
}

fn build_fixture() -> Fixture {
    let temp = tempfile::tempdir().expect("tempdir");
    let inner = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(temp.path().to_path_buf()))
            .expect("open storage"),
    );
    let armed = Arc::new(AtomicBool::new(false));
    let storage: Arc<dyn StorageEngine> = Arc::new(RevocationReadFaultEngine {
        inner,
        armed: Arc::clone(&armed),
    });
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    ));
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    ));
    let identity: Arc<dyn IdentityEngine> = Arc::new(
        EmbeddedIdentityEngine::with_rbac(
            Arc::clone(&storage),
            clock,
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                ..IdentityConfig::default()
            },
            Arc::clone(&rbac) as Arc<dyn RbacEngine>,
            Arc::clone(&audit) as Arc<dyn AuditEngine>,
        )
        .expect("identity engine"),
    );

    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: format!("aat-fault-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();
    let owner = identity
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("aat-fault-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "AAT Owner".to_string(),
                ..Default::default()
            },
        )
        .expect("create user")
        .id()
        .clone();
    let agent = identity
        .create_agent(
            &realm,
            &CreateAgentRequest {
                display_name: "aat-fault-agent".to_string(),
                description: None,
                owner: AgentOwner::User(owner),
                capabilities: vec![],
                max_delegation_depth: 5,
            },
            None,
        )
        .expect("create agent")
        .id()
        .clone();
    let aat = identity
        .issue_aat(
            &realm,
            &IssueAatRequest {
                agent_id: agent,
                tools: vec![],
                scope: vec!["mcp:tools:invoke".to_string()],
                aud: None,
                expires_in_secs: Some(3600),
            },
        )
        .expect("issue aat")
        .aat;

    Fixture {
        identity,
        realm,
        aat,
        armed,
        _temp: temp,
    }
}

/// Control: with the fault disarmed the very same AAT validates. Without this
/// the fault case below could pass for any reason at all.
#[tokio::test]
async fn aat_validates_when_the_revocation_blocklist_is_readable() {
    let fx = build_fixture();
    fx.identity
        .validate_aat(&fx.realm, &fx.aat, None)
        .expect("a live AAT must validate when the blocklist read succeeds");
}

/// The defect: a failed revocation-blocklist read must not be treated as
/// "not revoked". An I/O fault has to fail the validation, not wave the token
/// through.
#[tokio::test]
async fn aat_validation_fails_closed_when_the_revocation_read_errors() {
    let fx = build_fixture();
    fx.armed.store(true, Ordering::Relaxed);

    let err = fx
        .identity
        .validate_aat(&fx.realm, &fx.aat, None)
        .expect_err("a failed revocation lookup must fail the validation");
    assert!(
        matches!(err, IdentityError::Storage(_)),
        "expected the storage fault to surface, got {err:?}"
    );
}

/// The same fail-closed rule must hold on the derivation path: `derive_aat`
/// funnels through the same validator, so a broken blocklist must not let a
/// fresh child be minted from a parent whose revocation status is unknown.
#[tokio::test]
async fn aat_derivation_fails_closed_when_the_revocation_read_errors() {
    use hearth::identity::DeriveAatRequest;

    let fx = build_fixture();
    fx.armed.store(true, Ordering::Relaxed);

    let err = fx
        .identity
        .derive_aat(
            &fx.realm,
            &DeriveAatRequest {
                parent_aat: fx.aat.clone(),
                tools: vec![],
                scope: vec!["mcp:tools:invoke".to_string()],
                aud: None,
                expires_in_secs: Some(600),
            },
        )
        .expect_err("derivation must not proceed on an unreadable blocklist");
    assert!(
        matches!(err, IdentityError::Storage(_)),
        "expected the storage fault to surface, got {err:?}"
    );
}
