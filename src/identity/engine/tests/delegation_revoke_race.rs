//! A delegation revoked while a token exchange runs on its token cannot leave
//! the onward token alive (`delegation-chain-integrity` design §2).
//!
//! The revoke walk finds onward grants through the `dgrant:parent:` index. An
//! exchange that validated its subject token before the revoke, but writes its
//! index row after the revoke's scan, is not found by the walk. The exchange
//! therefore re-reads its parent's revoked-`jti` row after it stores its own
//! grant. `RevokeParentOnIndexWrite` puts a revoke exactly into that window: it
//! writes the parent's blocklist row the moment the exchange writes its index
//! row, as a revoke on another node would.

use super::*;

use crate::identity::Rfc8693Request;
use crate::storage::{ScanEntry, StorageDurabilityHandle, StorageError};

const PARENT_INDEX_PREFIX: &[u8] = b"dgrant:parent:";

/// Writes the parent token's revoked-`jti` row before forwarding the write of
/// a `dgrant:parent:{jti}:{id}` index row.
struct RevokeParentOnIndexWrite {
    inner: Arc<dyn StorageEngine>,
}

impl RevokeParentOnIndexWrite {
    fn revoke_parent_of(&self, realm_id: &RealmId, key: &[u8]) -> Result<(), StorageError> {
        let Some(rest) = key.strip_prefix(PARENT_INDEX_PREFIX) else {
            return Ok(());
        };
        let rest = String::from_utf8_lossy(rest);
        let Some((parent_jti, _)) = rest.split_once(':') else {
            return Ok(());
        };
        self.inner.put(
            realm_id,
            &keys::encode_revoked_jti(parent_jti),
            &i64::MAX.to_le_bytes(),
        )
    }
}

impl StorageEngine for RevokeParentOnIndexWrite {
    fn get(&self, realm_id: &RealmId, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.get(realm_id, key)
    }

    fn put(&self, realm_id: &RealmId, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        self.revoke_parent_of(realm_id, key)?;
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
        for (key, _) in entries {
            self.revoke_parent_of(realm_id, key)?;
        }
        self.inner.put_batch(realm_id, entries)
    }

    fn enqueue_batch(
        &self,
        realm_id: &RealmId,
        entries: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<StorageDurabilityHandle, StorageError> {
        for (key, _) in entries {
            self.revoke_parent_of(realm_id, key)?;
        }
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
        self.revoke_parent_of(realm_id, key)?;
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
        for (key, _) in puts {
            self.revoke_parent_of(realm_id, key)?;
        }
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
fn an_exchange_racing_a_revoke_of_its_parent_fails_and_leaves_no_live_grant() {
    let dir = tempfile::tempdir().expect("tempdir");
    let real = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf())).expect("open"),
    ) as Arc<dyn StorageEngine>;
    let storage = Arc::new(RevokeParentOnIndexWrite { inner: real }) as Arc<dyn StorageEngine>;
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock) as Arc<dyn Clock>,
    ));
    let engine = EmbeddedIdentityEngine::new(
        Arc::clone(&storage),
        clock as Arc<dyn Clock>,
        IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        },
        audit as Arc<dyn AuditEngine>,
    )
    .expect("engine")
    .with_hibp_transport(Arc::new(NeverPwnedStub));

    let realm = create_test_realm(&engine);
    declare_test_scopes(&engine, &realm, &["mcp:tools:invoke"]);
    let user = create_test_user(&engine, &realm);
    let session = engine
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("session");
    let subject_token = engine
        .issue_tokens_with_context(
            &realm,
            user.id(),
            session.id(),
            &crate::identity::TokenIssuanceContext {
                client_id: None,
                granted_scopes: std::iter::once("mcp:tools:invoke".to_string()).collect(),
                oid: None,
                resource: None,
                dpop_jkt: None,
            },
        )
        .expect("subject token")
        .access_token()
        .to_string();
    let client_id = engine
        .register_client(
            &realm,
            &crate::identity::RegisterClientRequest {
                client_name: "race-exchanger".to_string(),
                redirect_uris: vec!["https://client.example.com/cb".to_string()],
                client_secret: Some("race-exchanger-secret!".to_string()),
                grant_types: vec!["urn:ietf:params:oauth:grant-type:token-exchange".to_string()],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("register exchange client")
        .client_id()
        .clone();

    // The parent token is revoked between this exchange's validation of it
    // and the write of the onward grant's index row.
    let result = engine.rfc8693_token_exchange(
        &realm,
        &Rfc8693Request {
            client_id,
            subject_token,
            subject_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            scope: Some("mcp:tools:invoke".to_string()),
            resource: None,
            audience: None,
            dpop_jkt: None,
        },
    );
    assert!(
        matches!(
            result,
            Err(IdentityError::TokenExchangeRejected {
                oauth_error: "invalid_grant",
                ..
            })
        ),
        "an exchange whose parent was revoked mid-flight must fail, got: {result:?}"
    );
    assert_eq!(
        engine
            .list_delegation_grants(&realm, &user.id().to_string())
            .expect("list")
            .len(),
        0,
        "the onward grant stored before the re-check is revoked"
    );
}
