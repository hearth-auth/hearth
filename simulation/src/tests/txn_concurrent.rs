//! Transaction token concurrency simulation tests.
//!
//! Oracle invariants:
//! - Two concurrent `issue_transaction_token` calls with the same `txn_id` must
//!   produce exactly one success and one `TransactionTokenReplayed` error.
//! - Two concurrent `consume_transaction_token` calls presenting the same token
//!   must produce exactly one success and one `TransactionTokenReplayed` error.
//!
//! Both invariants rely on the per-txn advisory lock in `txn_advisory_lock()`
//! that serializes the check+write inside each inner function.

use std::sync::Arc;
use std::thread;

use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{AgentId, Clock, FakeClock, RealmId, Timestamp};
use hearth::identity::{
    AgentOwner, CreateAgentRequest, CreateRealmRequest, CreateTransactionTokenRequest,
    CreateUserRequest, CredentialConfig, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine,
    IdentityError,
};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

// ── helpers ──────────────────────────────────────────────────────────────────

fn open_engine(dir: &std::path::Path) -> (Arc<EmbeddedStorageEngine>, EmbeddedIdentityEngine) {
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
    let engine = EmbeddedIdentityEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        clock as Arc<dyn Clock>,
        identity_config,
        audit,
    )
    .expect("engine init");
    (storage, engine)
}

/// Create a realm with two agents. Returns `(realm_id, agent_a, agent_b)`.
fn make_realm_and_agents(engine: &EmbeddedIdentityEngine) -> (RealmId, AgentId, AgentId) {
    let realm = engine
        .create_realm(&CreateRealmRequest {
            name: format!("sim-txn-{}", uuid::Uuid::new_v4()),
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
                    email: format!("txn-{suffix}-{}@sim.test", uuid::Uuid::new_v4()),
                    display_name: format!("TXN {suffix}"),
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
                    display_name: format!("sim-txn-{suffix}"),
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

    let agent_a = make_agent("a");
    let agent_b = make_agent("b");
    (realm, agent_a, agent_b)
}

// ── Test 1: concurrent issuance — exactly one winner ─────────────────────────

/// Two threads race to issue a transaction token with the same `txn_id`.
/// The per-txn advisory lock in `issue_transaction_token_inner` serializes
/// the guard read + guard write, so exactly one thread wins and the other
/// gets `TransactionTokenReplayed`.
#[test]
fn simulation_txn_issue_concurrent_exactly_one_wins() {
    let seed = 70u64;

    let dir = tempfile::tempdir().expect("tempdir");
    let (_storage, engine) = open_engine(dir.path());
    let (realm_id, agent_a, agent_b) = make_realm_and_agents(&engine);
    let txn_id = uuid::Uuid::new_v4().to_string();

    let engine = Arc::new(engine);

    let make_thread = |engine: Arc<EmbeddedIdentityEngine>,
                       realm: RealmId,
                       a: AgentId,
                       b: AgentId,
                       txn: String| {
        thread::spawn(move || {
            engine.issue_transaction_token(
                &realm,
                &CreateTransactionTokenRequest {
                    requesting_agent_id: a,
                    target_agent_id: b,
                    txn_id: txn,
                    delegation_context: None,
                },
            )
        })
    };

    let h1 = make_thread(
        Arc::clone(&engine),
        realm_id.clone(),
        agent_a.clone(),
        agent_b.clone(),
        txn_id.clone(),
    );
    let h2 = make_thread(
        Arc::clone(&engine),
        realm_id.clone(),
        agent_a.clone(),
        agent_b.clone(),
        txn_id.clone(),
    );

    let r1 = h1.join().expect("thread 1 panicked");
    let r2 = h2.join().expect("thread 2 panicked");

    let (successes, replayed): (u32, u32) =
        [r1, r2].into_iter().fold((0, 0), |(s, r), res| match res {
            Ok(_) => (s + 1, r),
            Err(IdentityError::TransactionTokenReplayed) => (s, r + 1),
            Err(e) => panic!("unexpected error in concurrent issuance: {e:?} (seed={seed})"),
        });

    assert_eq!(
        successes, 1,
        "exactly one concurrent issue_transaction_token must succeed (seed={seed})"
    );
    assert_eq!(
        replayed, 1,
        "the losing concurrent issue must return TransactionTokenReplayed (seed={seed})"
    );
}

// ── Test 2: concurrent consumption — exactly one winner ──────────────────────

/// Two threads race to consume the same transaction token.
/// The per-txn advisory lock in `consume_transaction_token_inner` serializes
/// the consumed-key check + write, so exactly one thread wins and the other
/// gets `TransactionTokenReplayed`.
#[test]
fn simulation_txn_consume_concurrent_exactly_one_wins() {
    let seed = 71u64;

    let dir = tempfile::tempdir().expect("tempdir");
    let (_storage, engine) = open_engine(dir.path());
    let (realm_id, agent_a, agent_b) = make_realm_and_agents(&engine);
    let txn_id = uuid::Uuid::new_v4().to_string();

    // Issue the token once before the concurrent consume race.
    let resp = engine
        .issue_transaction_token(
            &realm_id,
            &CreateTransactionTokenRequest {
                requesting_agent_id: agent_a,
                target_agent_id: agent_b,
                txn_id,
                delegation_context: None,
            },
        )
        .expect("issue transaction token");

    let engine = Arc::new(engine);
    let token = resp.token;

    let make_thread = |engine: Arc<EmbeddedIdentityEngine>, realm: RealmId, tok: String| {
        thread::spawn(move || engine.consume_transaction_token(&realm, &tok))
    };

    let h1 = make_thread(Arc::clone(&engine), realm_id.clone(), token.clone());
    let h2 = make_thread(Arc::clone(&engine), realm_id.clone(), token.clone());

    let r1 = h1.join().expect("thread 1 panicked");
    let r2 = h2.join().expect("thread 2 panicked");

    let (successes, replayed): (u32, u32) =
        [r1, r2].into_iter().fold((0, 0), |(s, r), res| match res {
            Ok(_) => (s + 1, r),
            Err(IdentityError::TransactionTokenReplayed) => (s, r + 1),
            Err(e) => panic!("unexpected error in concurrent consume: {e:?} (seed={seed})"),
        });

    assert_eq!(
        successes, 1,
        "exactly one concurrent consume_transaction_token must succeed (seed={seed})"
    );
    assert_eq!(
        replayed, 1,
        "the losing concurrent consume must return TransactionTokenReplayed (seed={seed})"
    );
}
