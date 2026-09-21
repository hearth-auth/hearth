//! Agent-identity hardening regressions from the 2026-09-21 orgs/agents
//! subsystem audit (`reports/subsystem-audit-orgs-agents-2026-09-21.md`).
//!
//! Covers:
//! - A-2 / task 26.12 — `delete_agent` must order its cascade so every
//!   dependent row is still addressable when it is removed, must propagate the
//!   failure of every step, and must leave no live credential behind.
//! - A-8 / task 26.18 — token exchange must refuse a `Suspended` agent, not
//!   only a `Revoked` one. `Suspended` is the state the abuse monitor applies
//!   automatically, so the automatic response to credential abuse used not to
//!   stop the abused agent from delegating.
//! - A-10 / task 26.19 — the MCP scope-format rule of AGENT_AUTH.md §2.6 must
//!   be enforced where a realm declares its MCP scope vocabulary.
//! - Task 26.28 — `suspend_agent` and `reactivate_agent` must observe the
//!   archived-realm freeze that `revoke_agent` already observes.

mod common;

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{AgentId, ClientId, Clock, RealmId, SystemClock, UserId};
use hearth::identity::{
    AgentOwner, AgentStatus, CreateAgentRequest, CreateRealmRequest, CreateUserRequest,
    CredentialConfig, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, IdentityError,
    IssueAatRequest, RealmStatus, RegisterProtectedResourceRequest, RegisterSpiffeIdRequest,
    Rfc8693Request, SessionContext, TokenIssuanceContext, UpdateProtectedResourceRequest,
    UpdateRealmRequest,
};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{
    EmbeddedStorageEngine, ScanEntry, StorageConfig, StorageEngine, StorageError,
};

// ── Fault-injectable storage wrapper ─────────────────────────────────────────

/// Delegates to a real engine, but once `armed` is set every `delete` — and
/// every `scan` whose start key — begins with `fail_prefix` returns an I/O
/// error.
///
/// Arming is deferred so the engine can be constructed and the fixture seeded
/// through the same wrapper before the fault appears. `FaultFs` sits under the
/// filesystem; this sits under the `StorageEngine` trait, which is the layer
/// `delete_agent`'s cascade actually talks to.
struct PrefixDeleteFaultEngine {
    inner: Arc<EmbeddedStorageEngine>,
    armed: Arc<AtomicBool>,
    fail_prefix: &'static [u8],
}

impl PrefixDeleteFaultEngine {
    fn should_fail(&self, key: &[u8]) -> bool {
        self.armed.load(Ordering::Relaxed) && key.starts_with(self.fail_prefix)
    }
}

impl StorageEngine for PrefixDeleteFaultEngine {
    fn get(&self, realm_id: &RealmId, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.get(realm_id, key)
    }

    fn put(&self, realm_id: &RealmId, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        self.inner.put(realm_id, key, value)
    }

    fn delete(&self, realm_id: &RealmId, key: &[u8]) -> Result<(), StorageError> {
        if self.should_fail(key) {
            return Err(StorageError::Io(std::io::Error::other(
                "injected delete fault",
            )));
        }
        self.inner.delete(realm_id, key)
    }

    fn scan(
        &self,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
    ) -> Result<Vec<ScanEntry>, StorageError> {
        if self.should_fail(start) {
            return Err(StorageError::Io(std::io::Error::other(
                "injected scan fault",
            )));
        }
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

/// An identity engine wired over a fault-injecting storage wrapper.
struct FaultFixture {
    identity: Arc<dyn IdentityEngine>,
    armed: Arc<AtomicBool>,
    _temp: tempfile::TempDir,
}

fn build_fault_fixture(fail_prefix: &'static [u8]) -> FaultFixture {
    let temp = tempfile::tempdir().expect("tempdir");
    let inner = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(temp.path().to_path_buf()))
            .expect("open storage"),
    );
    let armed = Arc::new(AtomicBool::new(false));
    let storage: Arc<dyn StorageEngine> = Arc::new(PrefixDeleteFaultEngine {
        inner,
        armed: Arc::clone(&armed),
        fail_prefix,
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
    let identity = EmbeddedIdentityEngine::with_rbac(
        Arc::clone(&storage),
        clock,
        IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        },
        Arc::clone(&rbac) as Arc<dyn RbacEngine>,
        Arc::clone(&audit) as Arc<dyn AuditEngine>,
    )
    .expect("identity engine");
    FaultFixture {
        identity: Arc::new(identity),
        armed,
        _temp: temp,
    }
}

// ── Shared fixture helpers ───────────────────────────────────────────────────

fn make_realm(identity: &dyn IdentityEngine, tag: &str) -> RealmId {
    identity
        .create_realm(&CreateRealmRequest {
            name: format!("{tag}-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone()
}

fn make_user(identity: &dyn IdentityEngine, realm_id: &RealmId) -> UserId {
    identity
        .create_user(
            realm_id,
            &CreateUserRequest {
                email: format!("owner-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Agent Owner".to_string(),
                ..Default::default()
            },
        )
        .expect("create user")
        .id()
        .clone()
}

fn make_agent(identity: &dyn IdentityEngine, realm_id: &RealmId, owner: &UserId) -> AgentId {
    identity
        .create_agent(
            realm_id,
            &CreateAgentRequest {
                display_name: "hardening-agent".to_string(),
                description: None,
                owner: AgentOwner::User(owner.clone()),
                capabilities: vec![],
                max_delegation_depth: 5,
            },
            None,
        )
        .expect("create agent")
        .id()
        .clone()
}

fn archive_realm(identity: &dyn IdentityEngine, realm_id: &RealmId) {
    identity
        .update_realm(
            realm_id,
            &UpdateRealmRequest {
                status: Some(RealmStatus::Archived),
                ..Default::default()
            },
        )
        .expect("archive realm");
}

/// Issues a real Ed25519-signed access token usable as an RFC 8693 subject
/// token.
fn make_subject_token(
    identity: &dyn IdentityEngine,
    realm_id: &RealmId,
    user_id: &UserId,
    scope: &str,
) -> String {
    let session = identity
        .create_session(realm_id, user_id, &SessionContext::default())
        .expect("create session");
    let granted_scopes: BTreeSet<String> = scope.split_whitespace().map(String::from).collect();
    identity
        .issue_tokens_with_context(
            realm_id,
            user_id,
            session.id(),
            &TokenIssuanceContext {
                client_id: None,
                granted_scopes,
                oid: None,
                resource: None,
            },
        )
        .expect("issue subject token")
        .access_token()
        .to_string()
}

// ──────────────────────────────────────────────────────────────────────────────
// 26.12 / A-2 — delete_agent cascade ordering and failure propagation
// ──────────────────────────────────────────────────────────────────────────────

/// The primary agent record MUST be the last row removed. If any earlier step
/// of the cascade fails, the record must still be there — otherwise the
/// remaining rows are keyed under a UUID nothing can resolve, and the operator
/// has no handle left to retry the delete with.
#[tokio::test]
async fn delete_agent_keeps_agent_addressable_when_owner_index_delete_fails() {
    // `agt:owner:` is the owner index — the step that used to run *after* the
    // primary delete, with its `Result` thrown away.
    let fx = build_fault_fixture(b"agt:owner:");
    let identity = fx.identity.as_ref();
    let realm = make_realm(identity, "cascade-order");
    let owner = make_user(identity, &realm);
    let agent = make_agent(identity, &realm, &owner);

    fx.armed.store(true, Ordering::Relaxed);

    let err = identity
        .delete_agent(&realm, &agent, None)
        .expect_err("a failed owner-index delete must not report success");
    assert!(
        matches!(
            err,
            IdentityError::Storage(_) | IdentityError::Internal { .. }
        ),
        "expected the storage failure to be propagated, got {err:?}"
    );

    fx.armed.store(false, Ordering::Relaxed);
    assert!(
        identity
            .get_agent(&realm, &agent)
            .expect("get after failed delete")
            .is_some(),
        "the primary record must survive a failed cascade so the delete stays retryable"
    );
}

/// A failing RBAC purge must fail the call. `purge_user_from_realm`'s `Result`
/// used to be discarded with `let _ =`, so a failed purge produced a `204 No
/// Content` over a surviving set of role assignments under a dangling UUID.
#[tokio::test]
async fn delete_agent_propagates_rbac_purge_failure() {
    // `rba:` is the RBAC key family; failing I/O under it makes
    // `purge_user_from_realm` (which scans `rba:` before deleting) fail
    // without disturbing the identity half of the cascade.
    let fx = build_fault_fixture(b"rba:");
    let identity = fx.identity.as_ref();
    let realm = make_realm(identity, "cascade-rbac");
    let owner = make_user(identity, &realm);
    let agent = make_agent(identity, &realm, &owner);

    fx.armed.store(true, Ordering::Relaxed);

    let err = identity
        .delete_agent(&realm, &agent, None)
        .expect_err("a failed RBAC purge must not report success");
    assert!(
        matches!(
            err,
            IdentityError::Internal { .. } | IdentityError::Storage(_)
        ),
        "expected the rbac cascade failure to be propagated, got {err:?}"
    );

    fx.armed.store(false, Ordering::Relaxed);
    assert!(
        identity
            .get_agent(&realm, &agent)
            .expect("get after failed delete")
            .is_some(),
        "the agent must remain addressable after a failed RBAC purge"
    );
}

/// AGENT_AUTH.md §1.2: deletion MUST delete all credentials. A SPIFFE mapping
/// is a live workload credential — the SVID keeps presenting and the mapping
/// keeps resolving to an agent UUID whose record is gone.
#[tokio::test]
async fn delete_agent_removes_the_spiffe_workload_mapping() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm = make_realm(identity, "cascade-spiffe");
    let owner = make_user(identity, &realm);
    let agent = make_agent(identity, &realm, &owner);

    let spiffe_id = format!("spiffe://example.org/agent/{}", agent.as_uuid());
    identity
        .register_spiffe_mapping(
            &realm,
            &RegisterSpiffeIdRequest {
                agent_id: agent.clone(),
                spiffe_id: spiffe_id.clone(),
                trust_bundle_pem: None,
            },
        )
        .expect("register spiffe mapping");
    assert!(
        identity
            .lookup_agent_by_spiffe_id(&realm, &spiffe_id)
            .expect("lookup before delete")
            .is_some(),
        "precondition: the SPIFFE mapping resolves"
    );

    identity.delete_agent(&realm, &agent, None).expect("delete");

    assert!(
        identity
            .lookup_agent_by_spiffe_id(&realm, &spiffe_id)
            .expect("lookup after delete")
            .is_none(),
        "the SPIFFE mapping is a credential and must not outlive the agent"
    );
}

/// AGENT_AUTH.md §1.2: deletion MUST revoke all active tokens. For AATs — the
/// agent's own token family — that guarantee is carried by the subject
/// resolution inside AAT validation. Assert it end to end so the sentence in
/// the spec is a tested property rather than prose.
#[tokio::test]
async fn delete_agent_invalidates_outstanding_aats() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm = make_realm(identity, "cascade-aat");
    let owner = make_user(identity, &realm);
    let agent = make_agent(identity, &realm, &owner);

    let aat = identity
        .issue_aat(
            &realm,
            &IssueAatRequest {
                agent_id: agent.clone(),
                tools: vec![],
                scope: vec!["mcp:tools:invoke".to_string()],
                aud: None,
                expires_in_secs: Some(3600),
            },
        )
        .expect("issue aat");
    identity
        .validate_aat(&realm, &aat.aat, None)
        .expect("precondition: the AAT validates while the agent lives");

    identity.delete_agent(&realm, &agent, None).expect("delete");

    let err = identity
        .validate_aat(&realm, &aat.aat, None)
        .expect_err("a deleted agent's outstanding AAT must stop validating");
    assert!(
        matches!(
            err,
            IdentityError::AgentNotFound | IdentityError::AgentRevoked
        ),
        "expected the AAT to be refused for a dead subject, got {err:?}"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// 26.28 — archived realms freeze suspend / reactivate
// ──────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn suspend_agent_is_frozen_on_an_archived_realm() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm = make_realm(identity, "freeze-suspend");
    let owner = make_user(identity, &realm);
    let agent = make_agent(identity, &realm, &owner);

    archive_realm(identity, &realm);

    let err = identity
        .suspend_agent(&realm, &agent, None)
        .expect_err("an archived realm must refuse agent mutations");
    assert!(
        matches!(err, IdentityError::RealmSuspended),
        "expected RealmSuspended, got {err:?}"
    );
    assert_eq!(
        identity
            .get_agent(&realm, &agent)
            .expect("get")
            .expect("agent")
            .status(),
        AgentStatus::Active,
        "a refused suspension must not have mutated the record"
    );
}

#[tokio::test]
async fn reactivate_agent_is_frozen_on_an_archived_realm() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm = make_realm(identity, "freeze-reactivate");
    let owner = make_user(identity, &realm);
    let agent = make_agent(identity, &realm, &owner);

    identity
        .suspend_agent(&realm, &agent, None)
        .expect("suspend while the realm is active");
    archive_realm(identity, &realm);

    let err = identity
        .reactivate_agent(&realm, &agent, None)
        .expect_err("an archived realm must refuse agent mutations");
    assert!(
        matches!(err, IdentityError::RealmSuspended),
        "expected RealmSuspended, got {err:?}"
    );
    assert_eq!(
        identity
            .get_agent(&realm, &agent)
            .expect("get")
            .expect("agent")
            .status(),
        AgentStatus::Suspended,
        "a refused reactivation must not have mutated the record"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// 26.18 / A-8 — token exchange refuses a Suspended agent, not just a Revoked one
// ──────────────────────────────────────────────────────────────────────────────

/// With no `actor_token`, the exchange's actor subject is the request's
/// `client_id`. Registering an agent under that same UUID makes the agent the
/// actor, which is exactly the shape the status gate was written for.
/// `Suspended` — the state the abuse monitor applies automatically on
/// credential stuffing — must block the exchange just as `Revoked` does.
#[tokio::test]
async fn token_exchange_refuses_a_suspended_agent_actor() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm = make_realm(identity, "exchange-suspended");
    let owner = make_user(identity, &realm);
    let agent = make_agent(identity, &realm, &owner);
    let subject = make_user(identity, &realm);

    let make_req = || Rfc8693Request {
        client_id: ClientId::new(*agent.as_uuid()),
        subject_token: make_subject_token(identity, &realm, &subject, "mcp:tools:invoke"),
        subject_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
        actor_token: None,
        actor_token_type: None,
        requested_token_type: None,
        scope: Some("mcp:tools:invoke".to_string()),
        resource: None,
        audience: None,
        dpop_jkt: None,
    };

    // Control: an Active agent may exchange.
    identity
        .rfc8693_token_exchange(&realm, &make_req())
        .expect("an active agent actor must be able to exchange");

    identity
        .suspend_agent(&realm, &agent, None)
        .expect("suspend agent");

    let err = identity
        .rfc8693_token_exchange(&realm, &make_req())
        .expect_err("a suspended agent must not perform token exchange");
    assert!(
        matches!(err, IdentityError::TokenExchangeRejected { .. }),
        "expected TokenExchangeRejected for a suspended actor, got {err:?}"
    );

    // Reactivation restores the capability — the state machine is reversible.
    identity
        .reactivate_agent(&realm, &agent, None)
        .expect("reactivate agent");
    identity
        .rfc8693_token_exchange(&realm, &make_req())
        .expect("a reactivated agent must be able to exchange again");
}

// ──────────────────────────────────────────────────────────────────────────────
// 26.19 / A-10 — AGENT_AUTH.md §2.6 MCP scope format is enforced
// ──────────────────────────────────────────────────────────────────────────────

/// §2.6: "Custom scopes MAY be registered per protected resource. Scope
/// strings MUST follow the pattern `{namespace}:{category}:{action}`."
/// Protected-resource registration is where a realm declares that vocabulary,
/// so it is where the MUST is enforced.
#[tokio::test]
async fn protected_resource_scope_vocabulary_enforces_mcp_format() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let realm = make_realm(identity, "mcp-scope-format");

    // Non-MCP scopes are untouched: §2.6's rule is about MCP scope strings,
    // and plain OAuth scopes such as `openid` are one component by design.
    identity
        .register_protected_resource(
            &realm,
            &RegisterProtectedResourceRequest {
                resource_uri: "https://api.example.com".to_string(),
                display_name: "Plain API".to_string(),
                scopes: vec!["openid".to_string(), "profile".to_string()],
                required_claims: vec![],
            },
        )
        .expect("plain OAuth scopes must still register");

    for bad in [
        "mcp:tools",
        "mcp:tools:invoke:extra",
        "mcp::invoke",
        "mcp:tools:invoke me",
    ] {
        let err = identity
            .register_protected_resource(
                &realm,
                &RegisterProtectedResourceRequest {
                    resource_uri: format!("https://mcp-{}.example.com", uuid::Uuid::new_v4()),
                    display_name: "MCP Server".to_string(),
                    scopes: vec![bad.to_string()],
                    required_claims: vec![],
                },
            )
            .err();
        assert!(
            matches!(err, Some(IdentityError::InvalidInput { .. })),
            "`{bad}` violates AGENT_AUTH.md §2.6 and must be refused; got {err:?}"
        );
    }

    // The same rule must hold on the update path, or the vocabulary can be
    // widened after the fact.
    let resource = identity
        .register_protected_resource(
            &realm,
            &RegisterProtectedResourceRequest {
                resource_uri: "https://mcp-good.example.com".to_string(),
                display_name: "MCP Server".to_string(),
                scopes: vec!["mcp:tools:invoke".to_string()],
                required_claims: vec![],
            },
        )
        .expect("well-formed MCP scope registers");

    let err = identity
        .update_protected_resource(
            &realm,
            &resource.id,
            &UpdateProtectedResourceRequest {
                scopes: Some(vec!["mcp:tools".to_string()]),
                ..Default::default()
            },
        )
        .err();
    assert!(
        matches!(err, Some(IdentityError::InvalidInput { .. })),
        "update must enforce §2.6 too; got {err:?}"
    );
}
