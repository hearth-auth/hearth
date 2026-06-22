//! Phase D.3 integration tests — transaction tokens.
//!
//! Covers:
//! - Single-use enforcement (replay prevention)
//! - 60-second expiry cap
//! - `txn` claim echoed in response
//! - Adversarial: replay of consumed token fails

mod common;

use std::sync::Arc;

use common::TestHarness;
use hearth::core::RealmId;
use hearth::identity::{
    AgentOwner, CreateAgentRequest, CreateRealmRequest, CreateTransactionTokenRequest,
    CreateUserRequest, IdentityError,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_realm(h: &TestHarness) -> RealmId {
    h.identity()
        .create_realm(&CreateRealmRequest {
            name: format!("txn-test-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone()
}

fn make_agent(h: &TestHarness, realm_id: &RealmId) -> hearth::core::AgentId {
    let owner = h
        .identity()
        .create_user(
            realm_id,
            &CreateUserRequest {
                email: format!("txn-owner-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "TXN Owner".to_string(),
                ..Default::default()
            },
        )
        .expect("create owner");
    h.identity()
        .create_agent(
            realm_id,
            &CreateAgentRequest {
                display_name: "txn-agent".to_string(),
                description: None,
                owner: AgentOwner::User(owner.id().clone()),
                capabilities: vec![],
                max_delegation_depth: 3,
            },
            None,
        )
        .expect("create agent")
        .id()
        .clone()
}

// ── D.3.1: Issue transaction token ───────────────────────────────────────────

#[tokio::test]
async fn issue_transaction_token_returns_signed_jwt() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_a = make_agent(&h, &realm_id);
    let agent_b = make_agent(&h, &realm_id);

    let txn_id = uuid::Uuid::new_v4().to_string();

    let resp = h
        .identity()
        .issue_transaction_token(
            &realm_id,
            &CreateTransactionTokenRequest {
                requesting_agent_id: agent_a.clone(),
                target_agent_id: agent_b.clone(),
                txn_id: txn_id.clone(),
                delegation_context: None,
            },
        )
        .expect("issue transaction token");

    assert_eq!(resp.txn_id, txn_id, "txn_id must be echoed");
    assert_eq!(
        resp.expires_in_secs, 60,
        "transaction tokens expire in 60 s"
    );

    let parts: Vec<&str> = resp.token.split('.').collect();
    assert_eq!(parts.len(), 3, "transaction token must be a valid JWT");
}

// ── D.3.2: Single-use — same txn_id cannot be reused ─────────────────────────

#[tokio::test]
async fn transaction_token_txn_id_is_single_use() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_a = make_agent(&h, &realm_id);
    let agent_b = make_agent(&h, &realm_id);

    let txn_id = uuid::Uuid::new_v4().to_string();

    // First issuance succeeds.
    h.identity()
        .issue_transaction_token(
            &realm_id,
            &CreateTransactionTokenRequest {
                requesting_agent_id: agent_a.clone(),
                target_agent_id: agent_b.clone(),
                txn_id: txn_id.clone(),
                delegation_context: None,
            },
        )
        .expect("first issuance must succeed");

    // Second issuance with the same txn_id must fail.
    let err = h
        .identity()
        .issue_transaction_token(
            &realm_id,
            &CreateTransactionTokenRequest {
                requesting_agent_id: agent_a,
                target_agent_id: agent_b,
                txn_id: txn_id.clone(),
                delegation_context: None,
            },
        )
        .expect_err("replay of same txn_id must be rejected");

    assert!(
        matches!(err, IdentityError::TransactionTokenReplayed),
        "expected TransactionTokenReplayed, got {err:?}"
    );
}

// ── D.3.3: Consume transaction token — first consume succeeds, replay fails ───

#[tokio::test]
async fn consume_transaction_token_is_single_use() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_a = make_agent(&h, &realm_id);
    let agent_b = make_agent(&h, &realm_id);

    let txn_id = uuid::Uuid::new_v4().to_string();

    let resp = h
        .identity()
        .issue_transaction_token(
            &realm_id,
            &CreateTransactionTokenRequest {
                requesting_agent_id: agent_a,
                target_agent_id: agent_b,
                txn_id: txn_id.clone(),
                delegation_context: None,
            },
        )
        .expect("issue token");

    // First consume succeeds.
    let claims = h
        .identity()
        .consume_transaction_token(&realm_id, &resp.token)
        .expect("first consume must succeed");

    assert_eq!(claims.txn, txn_id, "txn claim must match");

    // Second consume of the same token must fail.
    let err = h
        .identity()
        .consume_transaction_token(&realm_id, &resp.token)
        .expect_err("second consume must be rejected");

    assert!(
        matches!(err, IdentityError::TransactionTokenReplayed),
        "expected TransactionTokenReplayed on second consume, got {err:?}"
    );
}

// ── D.3.4: Different txn_ids are independent ─────────────────────────────────

#[tokio::test]
async fn different_txn_ids_are_independent() {
    let h = TestHarness::embedded().await.expect("harness init");
    let realm_id = make_realm(&h);
    let agent_a = make_agent(&h, &realm_id);
    let agent_b = make_agent(&h, &realm_id);

    for _ in 0..3 {
        let txn_id = uuid::Uuid::new_v4().to_string();
        h.identity()
            .issue_transaction_token(
                &realm_id,
                &CreateTransactionTokenRequest {
                    requesting_agent_id: agent_a.clone(),
                    target_agent_id: agent_b.clone(),
                    txn_id,
                    delegation_context: None,
                },
            )
            .expect("each unique txn_id must succeed");
    }
}

// ── D.3.5: Concurrent issuance — exactly one winner ──────────────────────────

/// N concurrent `issue_transaction_token` calls with the same `txn_id` must
/// result in exactly one success and N-1 `TransactionTokenReplayed` errors.
///
/// Regression test for the TOCTOU race fixed in HEA-1439: before the advisory
/// lock was added, two racing callers could both pass the guard read before
/// either wrote the used marker, yielding two valid tokens from one txn_id.
#[tokio::test]
async fn concurrent_issue_same_txn_id_exactly_one_wins() {
    let h = Arc::new(TestHarness::embedded().await.expect("harness init"));
    let realm_id = make_realm(&h);
    let agent_a = make_agent(&h, &realm_id);
    let agent_b = make_agent(&h, &realm_id);
    let txn_id = uuid::Uuid::new_v4().to_string();

    const N: usize = 8;

    let handles: Vec<_> = (0..N)
        .map(|_| {
            let identity = h.identity_arc();
            let realm_id = realm_id.clone();
            let agent_a = agent_a.clone();
            let agent_b = agent_b.clone();
            let txn_id = txn_id.clone();
            tokio::task::spawn_blocking(move || {
                identity.issue_transaction_token(
                    &realm_id,
                    &CreateTransactionTokenRequest {
                        requesting_agent_id: agent_a,
                        target_agent_id: agent_b,
                        txn_id,
                        delegation_context: None,
                    },
                )
            })
        })
        .collect();

    let mut successes = 0u32;
    let mut replayed = 0u32;
    for handle in handles {
        match handle.await.expect("task did not panic") {
            Ok(_) => successes += 1,
            Err(IdentityError::TransactionTokenReplayed) => replayed += 1,
            Err(e) => panic!("unexpected error from concurrent issue: {e:?}"),
        }
    }

    assert_eq!(
        successes, 1,
        "exactly one concurrent issue_transaction_token must succeed"
    );
    assert_eq!(
        replayed,
        (N as u32) - 1,
        "the remaining {N} - 1 must return TransactionTokenReplayed"
    );
}
