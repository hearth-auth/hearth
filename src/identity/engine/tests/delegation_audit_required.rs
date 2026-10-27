//! A delegated token is issued only when its `AgentDelegation` audit record is
//! written (spec `delegated-authorization`, "Every delegation is audited with
//! its chain"; #621).
//!
//! The exchange discarded the result of that write, and `AgentDelegation` was
//! `LogOnly`, so a failed write still handed out the token: a delegated token
//! with no record of the delegation.

use super::*;

use crate::audit::{AuditAction, AuditError};
use crate::identity::Rfc8693Request;

/// Fails every `AgentDelegation` append and forwards everything else.
struct FailsDelegationAudit {
    inner: Arc<EmbeddedAuditEngine>,
}

fn refuse_delegation(action: &AuditAction) -> Result<(), AuditError> {
    if *action == AuditAction::AgentDelegation {
        return Err(AuditError::Storage("audit store unavailable".into()));
    }
    Ok(())
}

impl AuditEngine for FailsDelegationAudit {
    fn append(
        &self,
        event: &crate::audit::CreateAuditEvent,
    ) -> Result<crate::audit::AuditEvent, AuditError> {
        refuse_delegation(&event.action)?;
        self.inner.append(event)
    }

    fn export_chain_material(
        &self,
        realm_id: &RealmId,
    ) -> Result<Option<crate::audit::AuditChainMaterial>, AuditError> {
        self.inner.export_chain_material(realm_id)
    }

    fn on_replicated_row(&self, realm_id: &RealmId, key: &[u8]) {
        self.inner.on_replicated_row(realm_id, key);
    }

    fn on_replicated_snapshot(&self) {
        self.inner.on_replicated_snapshot();
    }

    fn import_events(
        &self,
        realm_id: &RealmId,
        events: &[crate::audit::AuditEvent],
    ) -> Result<crate::audit::AuditImportOutcome, AuditError> {
        self.inner.import_events(realm_id, events)
    }

    fn query(
        &self,
        query: &crate::audit::AuditQuery,
    ) -> Result<Vec<crate::audit::AuditEvent>, AuditError> {
        self.inner.query(query)
    }

    fn verify_integrity(
        &self,
        realm_id: &RealmId,
        start: Option<Timestamp>,
        end: Option<Timestamp>,
    ) -> Result<bool, AuditError> {
        self.inner.verify_integrity(realm_id, start, end)
    }

    fn get_retention_config(
        &self,
        realm_id: &RealmId,
    ) -> Result<crate::audit::AuditRetentionConfig, AuditError> {
        self.inner.get_retention_config(realm_id)
    }

    fn set_retention_config(
        &self,
        realm_id: &RealmId,
        config: &crate::audit::AuditRetentionConfig,
    ) -> Result<(), AuditError> {
        self.inner.set_retention_config(realm_id, config)
    }

    fn prune_before(&self, realm_id: &RealmId, cutoff: Timestamp) -> Result<u64, AuditError> {
        self.inner.prune_before(realm_id, cutoff)
    }

    fn count_events(&self, realm_id: &RealmId) -> Result<u64, AuditError> {
        self.inner.count_events(realm_id)
    }

    fn prune_oldest(&self, realm_id: &RealmId, n: u64) -> Result<u64, AuditError> {
        self.inner.prune_oldest(realm_id, n)
    }

    fn with_pending_append(
        &self,
        request: &crate::audit::CreateAuditEvent,
        enqueue_fn: crate::audit::AuditEnqueueFn<'_>,
    ) -> Result<crate::audit::AuditPendingWrite, AuditError> {
        refuse_delegation(&request.action)?;
        self.inner.with_pending_append(request, enqueue_fn)
    }
}

#[test]
fn a_delegation_whose_audit_write_fails_issues_no_token() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf())).expect("open"),
    ) as Arc<dyn StorageEngine>;
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
    let audit = Arc::new(FailsDelegationAudit {
        inner: Arc::new(EmbeddedAuditEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock) as Arc<dyn Clock>,
        )),
    });
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
                client_name: "audited-exchanger".to_string(),
                redirect_uris: vec!["https://client.example.com/cb".to_string()],
                client_secret: Some("audited-exchanger-secret!".to_string()),
                grant_types: vec!["urn:ietf:params:oauth:grant-type:token-exchange".to_string()],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("register exchange client")
        .client_id()
        .clone();

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
        matches!(result, Err(IdentityError::AuditFailure { .. })),
        "a delegation that cannot be audited must not issue a token, got: {result:?}"
    );
    assert_eq!(
        engine
            .list_delegation_grants(&realm, &user.id().to_string())
            .expect("list")
            .len(),
        0,
        "no delegation grant is stored for a token that was not issued"
    );
}
