//! Approval request CAS crash-recovery and concurrency simulation tests.
//!
//! Oracle invariants:
//! - After a crash anywhere inside `create_approval_request`, recovery yields
//!   either a complete record (primary + list index + pending index + outbox) or
//!   nothing at all. No partial state leaks — the 4-key `put_batch` is one
//!   atomic WAL record.
//! - After a crash between `approve`'s `delete(pending_key)` and
//!   `put(primary_key, Approved)`, the primary record is still `Pending` and a
//!   second `approve` call completes successfully (idempotent recovery).
//! - The webhook outbox key is written atomically with the create batch: if the
//!   create survives a crash, so does the outbox entry.
//! - A concurrent approve + deny race returns exactly one success and one
//!   `ApprovalRequestNotPending` error.

use std::io::Write;
use std::sync::Arc;
use std::thread;

use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{AgentId, Clock, FakeClock, RealmId, Timestamp};
use hearth::identity::{
    AgentOwner, ApprovalRequestStatus, CreateAgentRequest, CreateApprovalRequestInput,
    CreateRealmRequest, CreateUserRequest, CredentialConfig, EmbeddedIdentityEngine,
    IdentityConfig, IdentityEngine,
};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

// ── helpers ─────────────────────────────────────────────────────────────────

/// Open (or reopen) an identity engine against a fixed storage directory.
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

/// Create a realm and a minimal agent inside it. Returns `(realm_id, agent_id)`.
fn make_realm_and_agent(engine: &EmbeddedIdentityEngine) -> (RealmId, AgentId) {
    let realm = engine
        .create_realm(&CreateRealmRequest {
            name: format!("sim-appr-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();

    let owner = engine
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("owner-{}@sim.test", uuid::Uuid::new_v4()),
                display_name: "Owner".to_string(),
                ..Default::default()
            },
        )
        .expect("create owner user")
        .id()
        .clone();

    let agent = engine
        .create_agent(
            &realm,
            &CreateAgentRequest {
                display_name: "sim-agent".to_string(),
                description: None,
                owner: AgentOwner::User(owner),
                capabilities: vec![],
                max_delegation_depth: 3,
            },
            None,
        )
        .expect("create agent")
        .id()
        .clone();

    (realm, agent)
}

/// Build a `CreateApprovalRequestInput` for use in tests.
fn make_request(agent_id: AgentId) -> CreateApprovalRequestInput {
    CreateApprovalRequestInput {
        agent_id,
        tool: "delete_file".to_string(),
        action: "invoke".to_string(),
        context: serde_json::json!({"file": "/tmp/test.log"}),
        delegation_chain: vec![],
        expires_in_secs: Some(3600),
    }
}

// ── Test 1: create crash ─────────────────────────────────────────────────────

/// A crash during `create_approval_request` must leave either a fully-intact
/// record (primary + list + pending + outbox in one atomic WAL batch) or nothing.
///
/// Why the orphan-header injection is a faithful proxy: `create_approval_request`
/// writes all four keys in a SINGLE `put_batch`, i.e. one WAL record. A crash
/// mid-create therefore produces one torn record, which fails CRC and is
/// discarded as a unit on replay — exactly the outcome an appended orphan length
/// header reproduces. There is no intermediate "some keys written, others not"
/// state to roll back, so trailing-record discard *is* the partial-create
/// rollback here.
///
/// Strategy:
/// 1. Create two complete approval requests.
/// 2. Inject an orphan WAL length header — the torn tail of a would-be third
///    create; WAL replay discards it.
/// 3. Reopen the engine. Verify exactly two requests exist and both are Pending,
///    and the pending index matches (no half-written index entries).
#[test]
fn simulation_approval_cas_create_crash_discards_partial_record() {
    let seed = 60u64;

    let dir = tempfile::tempdir().expect("tempdir");
    let mut request_ids = Vec::new();
    let realm_id;

    // Phase 1: two successful creates.
    {
        let (_storage, engine) = open_engine(dir.path());
        let (realm, agent) = make_realm_and_agent(&engine);
        realm_id = realm;

        for _ in 0..2 {
            let created = engine
                .create_approval_request(&realm_id, &make_request(agent.clone()))
                .expect("create approval request");
            request_ids.push(created.request_id);
        }
    }

    // Phase 2: append an orphan length header to the WAL to simulate a crash
    // mid-write of a third create. The replay will see a record header (4 KiB
    // claimed) with no following payload — it discards it.
    {
        let wal_path = dir.path().join("hearth.wal");
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&wal_path)
            .expect("open wal for corruption");
        file.write_all(&4096u32.to_le_bytes())
            .expect("write orphan length header");
        file.sync_all().expect("sync");
    }

    // Phase 3: reopen and verify invariant.
    {
        let (_storage, engine) = open_engine(dir.path());

        let page = engine
            .list_approval_requests(&realm_id, None, None, 100)
            .expect("list after crash");
        assert_eq!(
            page.items.len(),
            2,
            "crashed create must be rolled back entirely — no partial record (seed={seed})"
        );

        // Both survived requests must still be individually readable and Pending.
        for rid in &request_ids {
            let req = engine
                .get_approval_request(&realm_id, rid)
                .expect("get survived request");
            assert_eq!(
                req.status,
                ApprovalRequestStatus::Pending,
                "survived request {rid} must remain Pending after crash (seed={seed})"
            );
        }

        // The pending index must also be consistent (no phantom entries).
        let pending_page = engine
            .list_approval_requests(&realm_id, Some(ApprovalRequestStatus::Pending), None, 100)
            .expect("list pending after crash");
        assert_eq!(
            pending_page.items.len(),
            2,
            "pending index must match total count after crash rollback (seed={seed})"
        );
    }
}

// ── Test 2: crash mid-transition leaves idempotent recoverable state ──────────

/// A crash between `approve`'s two writes (delete pending key / put approved
/// primary) must leave a recoverable state: the primary record still reads
/// `Pending` and a subsequent `approve` call completes successfully.
///
/// The `approve_approval_request_inner` does two separate storage operations:
///   1. `delete(pending_key)` — WAL record N   (committed before the crash)
///   2. `put(primary_key, Approved)` — WAL record N+1 (lost to crash)
///
/// We simulate this by manually executing only the first write (via the raw
/// storage layer) and then cleanly reopening the engine — a proxy for a crash
/// between the two writes rather than an injected fault. This is sound because
/// the reopen reconstructs the *exact* intermediate durable state a real crash
/// would leave (primary still Pending, pending-index entry deleted); the
/// recovery path can't tell the difference. The primary record is still
/// Pending; the pending index entry is gone.
///
/// After reopening, `approve_approval_request` must succeed because:
/// - It reads the primary (Pending) and passes the CAS check.
/// - `delete(pending_key)` is idempotent — the WAL tombstone is harmless.
/// - `put(primary_key, Approved)` completes the transition.
#[test]
fn simulation_approval_cas_transition_crash_leaves_recoverable_state() {
    let seed = 61u64;

    let dir = tempfile::tempdir().expect("tempdir");
    let realm_id;
    let request_id;

    // Phase 1: create one approval request, then drop engine.
    {
        let (_storage, engine) = open_engine(dir.path());
        let (realm, agent) = make_realm_and_agent(&engine);
        realm_id = realm;

        let created = engine
            .create_approval_request(&realm_id, &make_request(agent))
            .expect("create approval request");
        request_id = created.request_id;
    }

    // Phase 2: simulate "crash after delete(pending_key) but before
    // put(primary_key, Approved)" by opening the raw storage and deleting just
    // the pending index key — the same first write approve would make — then
    // closing cleanly.
    //
    // The pending key format is `appreq:pending:{request_id}`.
    {
        let config = StorageConfig::dev(dir.path().to_path_buf());
        let storage = Arc::new(EmbeddedStorageEngine::open(config).expect("reopen storage"));
        let pending_key = format!("appreq:pending:{request_id}").into_bytes();
        storage
            .delete(&realm_id, &pending_key)
            .expect("delete pending key (simulating first half of approve)");
        // Drop storage — clean shutdown durably commits the delete.
    }

    // Phase 3: reopen the engine and verify the partially-approved state.
    {
        let (_storage, engine) = open_engine(dir.path());

        // Primary record must still say Pending (put(primary, Approved) was lost).
        let req = engine
            .get_approval_request(&realm_id, &request_id)
            .expect("get request after partial approve crash");
        assert_eq!(
            req.status,
            ApprovalRequestStatus::Pending,
            "primary record must remain Pending after crash before put(Approved) (seed={seed})"
        );

        // Pending index is gone — listing pending returns empty.
        let pending_page = engine
            .list_approval_requests(&realm_id, Some(ApprovalRequestStatus::Pending), None, 100)
            .expect("list pending after partial approve");
        assert_eq!(
            pending_page.items.len(),
            0,
            "pending index must be empty after the delete half of approve survived crash (seed={seed})"
        );

        // A second approve call must succeed — the per-request advisory lock
        // is fresh and the primary still reads Pending.
        let response = engine
            .approve_approval_request(&realm_id, &request_id, None)
            .expect("second approve must succeed after crash (idempotent recovery)");
        assert_eq!(
            response.status,
            ApprovalRequestStatus::Approved,
            "approve must transition to Approved on idempotent recovery (seed={seed})"
        );
        assert!(
            response.capability_token.is_some(),
            "approved request must yield a capability token on recovery (seed={seed})"
        );

        // Final state: primary reads Approved.
        let final_req = engine
            .get_approval_request(&realm_id, &request_id)
            .expect("get after recovery approve");
        assert_eq!(
            final_req.status,
            ApprovalRequestStatus::Approved,
            "request must be Approved in storage after recovery (seed={seed})"
        );
    }
}

// ── Test 3: webhook outbox WAL durability ─────────────────────────────────────

/// The webhook outbox entry is written in the same `put_batch` as the approval
/// request primary record. It must survive a crash that occurs before webhook
/// delivery fires — i.e., a crash-and-reopen without delivery must still find
/// the outbox entry ready for re-delivery.
///
/// Strategy:
/// 1. Create an approval request (no webhook configured → delivery skipped,
///    but the outbox key is still written atomically with the create batch).
/// 2. Drop the engine immediately — simulating a crash or restart before the
///    background outbox scanner runs.
/// 3. Append an orphan WAL length header to simulate a crash mid-write of a
///    second request. Replay must discard that incomplete record and keep the
///    first request's batch intact.
/// 4. Reopen the engine and scan for the outbox key.
///
/// Invariant: the outbox entry for the first request must still be present —
/// it was written atomically with the create batch and not yet deleted by a
/// successful delivery.
#[test]
fn simulation_approval_webhook_outbox_survives_crash_before_delivery() {
    let seed = 62u64;

    let dir = tempfile::tempdir().expect("tempdir");
    let realm_id;
    let request_id;

    // Phase 1: create one approval request.
    {
        let (_storage, engine) = open_engine(dir.path());
        let (realm, agent) = make_realm_and_agent(&engine);
        realm_id = realm;

        let created = engine
            .create_approval_request(&realm_id, &make_request(agent))
            .expect("create approval request");
        request_id = created.request_id;
    }
    // Engine dropped here — no webhook was delivered (no webhook configured).

    // Phase 2: inject an orphan WAL length header to simulate a crash mid-write
    // of a subsequent operation. Replay discards this truncated record but keeps
    // everything before it.
    {
        let wal_path = dir.path().join("hearth.wal");
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&wal_path)
            .expect("open wal for corruption");
        file.write_all(&4096u32.to_le_bytes())
            .expect("write orphan length header");
        file.sync_all().expect("sync");
    }

    // Phase 3: reopen and verify the outbox entry survived.
    {
        let (storage, engine) = open_engine(dir.path());

        // The request itself must survive.
        let req = engine
            .get_approval_request(&realm_id, &request_id)
            .expect("get request after crash");
        assert_eq!(
            req.status,
            ApprovalRequestStatus::Pending,
            "request must survive crash-before-delivery reopen (seed={seed})"
        );

        // The outbox key must also survive — it was in the same WAL batch.
        // Outbox prefix: `appreq:outbox:` (see keys::APPROVAL_WEBHOOK_OUTBOX_PREFIX).
        let outbox_prefix = b"appreq:outbox:".to_vec();
        let outbox_end = {
            let mut end = outbox_prefix.clone();
            *end.last_mut().expect("non-empty") += 1;
            end
        };

        let outbox_entries = storage
            .scan(&realm_id, &outbox_prefix, &outbox_end)
            .expect("scan outbox");
        assert_eq!(
            outbox_entries.len(),
            1,
            "outbox entry must survive crash-before-delivery — written atomically with the create batch (seed={seed})"
        );

        let outbox_key_str = String::from_utf8_lossy(&outbox_entries[0].key);
        assert!(
            outbox_key_str.ends_with(&request_id),
            "outbox entry must be for the created request (seed={seed}); got key={outbox_key_str}"
        );
    }
}

// ── Test 4: concurrent approve + deny race ───────────────────────────────────

/// A concurrent approve and deny racing on the same Pending request must
/// produce exactly one success and one `ApprovalRequestNotPending` error.
///
/// The per-request advisory lock inside `approve_approval_request_inner` /
/// `deny_approval_request_inner` serializes the two callers. The first to
/// acquire the lock completes the CAS transition; the second reads the
/// already-resolved status and returns the error.
#[test]
fn simulation_approval_cas_concurrent_approve_deny_exactly_one_wins() {
    let seed = 63u64;

    let dir = tempfile::tempdir().expect("tempdir");

    let (storage, engine) = open_engine(dir.path());
    let (realm_id, agent_id) = make_realm_and_agent(&engine);

    let created = engine
        .create_approval_request(&realm_id, &make_request(agent_id))
        .expect("create approval request");
    let request_id = created.request_id;

    // Wrap engine in Arc so both threads can hold a reference.
    drop(storage);
    let engine = Arc::new(engine);

    let rid_approve = request_id.clone();
    let realm_approve = realm_id.clone();
    let engine_approve = Arc::clone(&engine);

    let rid_deny = request_id.clone();
    let realm_deny = realm_id.clone();
    let engine_deny = Arc::clone(&engine);

    let handle_approve = thread::spawn(move || {
        engine_approve.approve_approval_request(&realm_approve, &rid_approve, None)
    });

    let handle_deny = thread::spawn(move || {
        engine_deny.deny_approval_request(
            &realm_deny,
            &rid_deny,
            Some("concurrent test".to_string()),
        )
    });

    let result_approve = handle_approve.join().expect("approve thread panicked");
    let result_deny = handle_deny.join().expect("deny thread panicked");

    // Exactly one must succeed; the other must fail with NotPending.
    let (winner_status, loser_err) = match (&result_approve, &result_deny) {
        (Ok(r), Err(e)) => (r.status.clone(), e),
        (Err(e), Ok(r)) => (r.status.clone(), e),
        (Ok(_), Ok(_)) => panic!(
            "both approve and deny succeeded on the same Pending request — CAS violated (seed={seed})"
        ),
        (Err(e1), Err(e2)) => panic!(
            "both approve and deny failed — one must succeed; approve={e1:?} deny={e2:?} (seed={seed})"
        ),
    };

    assert!(
        winner_status == ApprovalRequestStatus::Approved
            || winner_status == ApprovalRequestStatus::Denied,
        "winning transition must land in Approved or Denied (seed={seed})"
    );

    // The loser must get ApprovalRequestNotPending.
    assert!(
        matches!(
            loser_err,
            hearth::identity::IdentityError::ApprovalRequestNotPending { .. }
        ),
        "losing transition must return ApprovalRequestNotPending, got {loser_err:?} (seed={seed})"
    );

    // Storage must reflect the winner's terminal state.
    let final_req = engine
        .get_approval_request(&realm_id, &request_id)
        .expect("get final state");
    assert_eq!(
        final_req.status, winner_status,
        "storage must match the winner's transition (seed={seed})"
    );
    assert!(
        final_req.status != ApprovalRequestStatus::Pending,
        "request must not remain Pending after a race (seed={seed})"
    );
}
