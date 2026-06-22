//! Transaction token single-use crash-recovery simulation tests.
//!
//! Oracle invariant:
//! - A transaction token consumed on one engine instance MUST NOT be consumable
//!   on a second instance that opens the same WAL after the first closes.
//!
//! This simulates a Raft-partitioned cluster scenario: node A consumes the
//! token and records the consumed marker to WAL; when node A crashes and node B
//! (or a restarted A) replays the WAL, the consumed marker is present and any
//! attempt to consume the same token again must return `TransactionTokenReplayed`.

use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{AgentId, Clock, FakeClock, RealmId, Timestamp};
use hearth::identity::{
    AgentOwner, CreateAgentRequest, CreateRealmRequest, CreateTransactionTokenRequest,
    CreateUserRequest, CredentialConfig, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine,
    IdentityError,
};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use std::sync::Arc;

// ── helpers ──────────────────────────────────────────────────────────────────

fn open_engine(dir: &std::path::Path) -> EmbeddedIdentityEngine {
    let config = StorageConfig::dev(dir.to_path_buf());
    let storage = Arc::new(EmbeddedStorageEngine::open(config).expect("open storage"));
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000_000)));
    let identity_config = IdentityConfig {
        credential: CredentialConfig::fast_for_testing(),
        ..IdentityConfig::default()
    };
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock) as Arc<dyn Clock>,
    )) as Arc<dyn AuditEngine>;
    EmbeddedIdentityEngine::new(
        storage as Arc<dyn StorageEngine>,
        clock as Arc<dyn Clock>,
        identity_config,
        audit,
    )
    .expect("engine init")
}

fn make_realm_and_agents(engine: &EmbeddedIdentityEngine) -> (RealmId, AgentId, AgentId) {
    let realm = engine
        .create_realm(&CreateRealmRequest {
            name: format!("sim-txn-su-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();

    let make_agent = |suffix: &str| {
        let owner = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: format!("txn-su-{suffix}-{}@sim.test", uuid::Uuid::new_v4()),
                    display_name: format!("TXN-SU {suffix}"),
                    ..Default::default()
                },
            )
            .expect("create owner user")
            .id()
            .clone();
        engine
            .create_agent(
                &realm,
                &CreateAgentRequest {
                    display_name: format!("sim-txn-su-{suffix}"),
                    description: None,
                    owner: AgentOwner::User(owner),
                    capabilities: vec![],
                    max_delegation_depth: 3,
                },
                None,
            )
            .expect("create agent")
            .id()
            .clone()
    };

    let agent_a = make_agent("caller");
    let agent_b = make_agent("target");
    (realm, agent_a, agent_b)
}

// ── Test 1: consumed token rejected after engine restart ──────────────────────

/// After engine A consumes a transaction token and WAL is fsynced, engine B
/// (same WAL directory, simulating a restarted or newly-caught-up Raft replica)
/// must reject a second consume attempt with `TransactionTokenReplayed`.
#[test]
fn simulation_txn_consumed_token_rejected_after_engine_restart() {
    let dir = tempfile::tempdir().expect("tempdir");

    // Phase 1: issue and consume on engine A.
    let (realm_id, token_str) = {
        let engine_a = open_engine(dir.path());
        let (realm_id, agent_a, agent_b) = make_realm_and_agents(&engine_a);
        let txn_id = uuid::Uuid::new_v4().to_string();

        let resp = engine_a
            .issue_transaction_token(
                &realm_id,
                &CreateTransactionTokenRequest {
                    requesting_agent_id: agent_a,
                    target_agent_id: agent_b,
                    txn_id,
                    delegation_context: None,
                },
            )
            .expect("issue transaction token on engine A");

        engine_a
            .consume_transaction_token(&realm_id, &resp.token)
            .expect("consume transaction token on engine A");

        (realm_id, resp.token)
        // engine_a drops here — WAL is fsynced before drop
    };

    // Phase 2: reopen WAL as engine B; the consumed marker is replayed into
    // the memtable at startup, mirroring Raft log replay on a recovered node.
    let engine_b = open_engine(dir.path());

    let err = engine_b
        .consume_transaction_token(&realm_id, &token_str)
        .expect_err("second consume after WAL-replay must be rejected");

    assert!(
        matches!(err, IdentityError::TransactionTokenReplayed),
        "expected TransactionTokenReplayed on second consume after engine restart, got {err:?}"
    );
}

// ── Test 2: issued txn_id cannot be reissued after engine restart ─────────────

/// After engine A records a `txn_id` issuance to WAL, engine B must reject a
/// second issuance of the same `txn_id` with `TransactionTokenReplayed`.
#[test]
fn simulation_txn_issued_id_cannot_be_reissued_after_engine_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let txn_id = uuid::Uuid::new_v4().to_string();

    // Phase 1: issue on engine A.
    let (realm_id, agent_a, agent_b) = {
        let engine_a = open_engine(dir.path());
        let (realm_id, agent_a, agent_b) = make_realm_and_agents(&engine_a);

        engine_a
            .issue_transaction_token(
                &realm_id,
                &CreateTransactionTokenRequest {
                    requesting_agent_id: agent_a.clone(),
                    target_agent_id: agent_b.clone(),
                    txn_id: txn_id.clone(),
                    delegation_context: None,
                },
            )
            .expect("issue transaction token on engine A");

        (realm_id, agent_a, agent_b)
        // engine_a drops here
    };

    // Phase 2: reopen as engine B and attempt re-issuance.
    let engine_b = open_engine(dir.path());

    let err = engine_b
        .issue_transaction_token(
            &realm_id,
            &CreateTransactionTokenRequest {
                requesting_agent_id: agent_a,
                target_agent_id: agent_b,
                txn_id: txn_id.clone(),
                delegation_context: None,
            },
        )
        .expect_err("re-issuance of same txn_id after engine restart must fail");

    assert!(
        matches!(err, IdentityError::TransactionTokenReplayed),
        "expected TransactionTokenReplayed on re-issuance after restart, got {err:?}"
    );
}
