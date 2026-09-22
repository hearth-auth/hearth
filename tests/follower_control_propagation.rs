//! Task 24.6 (audit 2026-08-28 §4.1 objection, §4.16#5, §4.19#12, §9 item 5) —
//! a control asserted on one node must bind on every node, within one epoch
//! reconciliation window.
//!
//! `serve` always installs a `ClusterStorageAdapter`, so every storage write is
//! a Raft command that reaches every node. Three caches in the identity engine
//! are nonetheless **authoritative** on the token-validation path — a miss is
//! treated as a decision, not as a reason to consult storage — and each is
//! written only by the node that served the mutating request:
//!
//! * `realm_status_cache` — realm suspend and archive;
//! * `revoked_jti_cache` — token revocation;
//! * `blocked_dpop_jkt_cache` — the DPoP key blocklist.
//!
//! So a kill-switch thrown on node A did not bind on node B until node B was
//! restarted, while node B's own storage already held the row that says so.
//!
//! The enumeration behind these three is
//! `reports/follower-bypass-enumeration-2026-09-21.md`.
//!
//! Two engines over ONE storage stand in for two nodes: that is exactly what a
//! replicated store looks like from the engine's side, and it is the shape
//! `tests/signing_key_surface.rs` already uses for the signing-key epoch that
//! task 18.7 introduced.

#![allow(clippy::unwrap_used)]

mod common;

use std::sync::Arc;

use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{Clock, FakeClock, RealmId, Timestamp};
use hearth::identity::{
    CreateRealmRequest, CreateUserRequest, CredentialConfig, EmbeddedIdentityEngine,
    IdentityConfig, IdentityEngine, RealmConfig, SessionContext, UpdateRealmRequest,
};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// How far to move the clock so the validating node reconciles the epoch again.
///
/// The validation path debounces the two epoch reads, because it may perform no
/// storage read and no heap allocation — see `EPOCH_SYNC_INTERVAL_MICROS` in
/// `src/identity/engine/mod.rs`, which this must stay comfortably above. One
/// second against a 200 ms window leaves room for that constant to be retuned
/// without silently making these tests vacuous.
const PAST_THE_EPOCH_WINDOW_MICROS: i64 = 1_000_000;

fn open_storage(dir: &tempfile::TempDir) -> Arc<dyn StorageEngine> {
    let config = StorageConfig::dev(dir.path().to_path_buf());
    Arc::new(EmbeddedStorageEngine::open(config).unwrap()) as Arc<dyn StorageEngine>
}

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
    .unwrap()
}

/// Creates a realm with one user and a live session, and returns
/// `(realm_id, access_token)`.
fn realm_with_live_token(engine: &EmbeddedIdentityEngine, name: &str) -> (RealmId, String) {
    let realm = engine
        .create_realm(&CreateRealmRequest {
            name: name.to_string(),
            config: Some(RealmConfig::default()),
        })
        .unwrap();
    let user = engine
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("user@{name}.test"),
                display_name: "Node Test".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                ..Default::default()
            },
        )
        .unwrap();
    let session = engine
        .create_session(realm.id(), user.id(), &SessionContext::default())
        .unwrap();
    let tokens = engine
        .issue_tokens(realm.id(), user.id(), session.id())
        .unwrap();
    (realm.id().clone(), tokens.access_token().to_string())
}

/// B-1 — suspending a realm on one node must stop the other node validating
/// that realm's tokens.
///
/// `realm_status_cache` is filled once at start-up and thereafter only by the
/// node that served the status change. Its read comment said an absent entry
/// "fail-open matches the original behavior", so node B kept serving a
/// suspended tenant until it restarted.
#[test]
fn suspending_a_realm_on_one_node_binds_on_the_other() {
    let dir = tempfile::tempdir().unwrap();
    let storage = open_storage(&dir);
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000_000_000)));

    let node_a = engine_over(&storage, &clock);
    let node_b = engine_over(&storage, &clock);

    let (realm_id, token) = realm_with_live_token(&node_a, "suspendme");

    // Control: node B accepts the token while the realm is active, so the
    // assertion below cannot pass merely because node B rejects everything.
    assert!(
        node_b.validate_token(&realm_id, &token).is_ok(),
        "node B must accept the token before the realm is suspended"
    );

    node_a
        .update_realm(
            &realm_id,
            &UpdateRealmRequest {
                status: Some(hearth::identity::RealmStatus::Suspended),
                ..Default::default()
            },
        )
        .unwrap();

    // Node B reconciles the epoch at most once per window, so it is
    // deliberately stale until this point. Asserted rather than skipped past:
    // the bound is the cost of keeping the validation path free of storage
    // reads, and a test that hid it would let the window grow unnoticed.
    assert!(
        node_b.validate_token(&realm_id, &token).is_ok(),
        "node B is expected to be stale inside its reconciliation window"
    );

    clock.advance(PAST_THE_EPOCH_WINDOW_MICROS);

    assert!(
        node_b.validate_token(&realm_id, &token).is_err(),
        "a realm suspended on node A must stop node B validating its tokens"
    );
}

/// B-2 — revoking a token on one node must stop the other node accepting it.
///
/// `is_token_jti_revoked` reads only `revoked_jti_cache`; there is no storage
/// fallback on any branch. The blocklist row replicates and sits in node B's
/// own storage, unread until the next start-up scan.
#[test]
fn revoking_a_token_on_one_node_binds_on_the_other() {
    use hearth::identity::oidc::TokenRevocationRequest;

    let dir = tempfile::tempdir().unwrap();
    let storage = open_storage(&dir);
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000_000_000)));

    let node_a = engine_over(&storage, &clock);
    let node_b = engine_over(&storage, &clock);

    let (realm_id, token) = realm_with_live_token(&node_a, "revokeme");

    assert!(
        node_b.validate_token(&realm_id, &token).is_ok(),
        "node B must accept the token before it is revoked"
    );

    node_a
        .revoke_token(
            &realm_id,
            &TokenRevocationRequest {
                token: token.clone(),
                token_type_hint: None,
            },
        )
        .unwrap();

    assert!(
        node_b.validate_token(&realm_id, &token).is_ok(),
        "node B is expected to be stale inside its reconciliation window"
    );

    clock.advance(PAST_THE_EPOCH_WINDOW_MICROS);

    assert!(
        node_b.validate_token(&realm_id, &token).is_err(),
        "a token revoked on node A must stop validating on node B"
    );
}
