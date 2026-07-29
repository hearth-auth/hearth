//! HEA-1945 / HEA-1954 — pins how many durable WAL records `create_session` costs.
//!
//! `session_create` is fsync-bound. C7-v2 measured 111 ops/s at 1 thread with
//! **3.0 fsyncs per write**, on a host whose device sustains only ~330–500
//! fsyncs/s. On the durable path throughput is therefore
//!
//! ```text
//! ops/s  ≈  device_fsync_rate / (wal_records_per_op / batch_coalescing_factor)
//! ```
//!
//! The engine does not control the device rate, and it only controls the
//! coalescing factor indirectly (via how many writers can be in flight at
//! once). The one term it controls outright is **WAL records per operation** —
//! every avoidable record is a directly proportional throughput loss.
//!
//! `create_session` previously wrote two separate records: the session body +
//! user→session index entry (collapsed in HEA-1945), and the `SessionCreated`
//! audit event. HEA-1954 merges all three into a single atomic `put_batch` via
//! `AuditEngine::with_pending_append`, halving the fsync cost on the hot path.
//!
//! This test pins the resulting count at 1 so a later refactor cannot silently
//! re-split the batch and regress write performance without anyone noticing.
//! The second test verifies crash atomicity: a torn/CRC-failed WAL record leaves
//! neither the session nor the audit event, proving the crash window that
//! existed between the two separate records is now impossible by construction.

use std::io::{Seek, SeekFrom, Write as IoWrite};
use std::path::PathBuf;
use std::sync::Arc;

use hearth::audit::{AuditEngine, AuditQuery, EmbeddedAuditEngine};
use hearth::core::{Clock, SystemClock};
use hearth::identity::{
    CreateRealmRequest, CreateUserRequest, CredentialConfig, EmbeddedIdentityEngine,
    IdentityConfig, IdentityEngine, SessionContext,
};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// WAL records a single `create_session` is allowed to emit in steady state
/// on `EmbeddedAuditEngine`.  HEA-1954 merged session body + user→session
/// index + `SessionCreated` audit event into one atomic batch.
const EXPECTED_WAL_RECORDS_PER_SESSION_CREATE: u64 = 1;

fn open_engine(
    dir: &std::path::Path,
) -> (
    Arc<EmbeddedStorageEngine>,
    EmbeddedIdentityEngine,
    Arc<dyn AuditEngine>,
) {
    let mut config = StorageConfig::production(
        PathBuf::from(dir),
        256 * 1024 * 1024,
        8 * 1024 * 1024,
        4_096,
    );
    config.dev_mode = true;

    let storage_engine = Arc::new(EmbeddedStorageEngine::open(config).expect("open storage"));
    let storage = Arc::clone(&storage_engine) as Arc<dyn StorageEngine>;
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    )) as Arc<dyn AuditEngine>;
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    )) as Arc<dyn RbacEngine>;
    let engine = EmbeddedIdentityEngine::with_rbac(
        storage,
        Arc::clone(&clock),
        IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        },
        rbac,
        Arc::clone(&audit),
    )
    .expect("build identity engine");

    (storage_engine, engine, audit)
}

#[test]
fn create_session_costs_one_wal_record() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // `production()` is the only constructor that guarantees
    // `SyncMode::EveryWrite`, which is what makes one WAL append == one fsync
    // and therefore makes `wal_sync_count()` a faithful record counter here.
    let (storage_engine, engine, _audit) = open_engine(tmp.path());

    let realm = engine
        .create_realm(&CreateRealmRequest {
            name: format!("hea1945-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();

    let user = engine
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("wal-amp-{}@hea1945.test", uuid::Uuid::new_v4()),
                display_name: "wal amp".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let ctx = SessionContext::default();

    // First call may absorb one-time per-realm initialisation (e.g. loading the
    // audit chain head). Measure it separately so a one-time cost can never be
    // mistaken for steady-state write amplification.
    let before_first = storage_engine.wal_sync_count();
    engine
        .create_session(&realm, user.id(), &ctx)
        .expect("first create_session");
    let first = storage_engine.wal_sync_count() - before_first;

    let before_steady = storage_engine.wal_sync_count();
    engine
        .create_session(&realm, user.id(), &ctx)
        .expect("steady create_session");
    let steady = storage_engine.wal_sync_count() - before_steady;

    assert_eq!(
        steady, EXPECTED_WAL_RECORDS_PER_SESSION_CREATE,
        "create_session emitted {steady} WAL records (fsyncs) in steady state, expected \
         {EXPECTED_WAL_RECORDS_PER_SESSION_CREATE}. Each extra record divides durable write \
         throughput by the device fsync rate again (HEA-1945/HEA-1954)."
    );
    assert_eq!(
        first, steady,
        "first create_session cost {first} WAL records vs {steady} in steady state — a \
         per-realm one-time write is hiding inside the session write path"
    );
}

/// A torn (CRC-failed) WAL record must leave **neither** the session nor the
/// `SessionCreated` audit event.  Before HEA-1954 there were two separate
/// records, creating a crash window where the session could be written but the
/// audit event lost.  After HEA-1954 the two are one atomic batch — a partial
/// write discards both, proving the crash window is closed by construction.
#[test]
fn create_session_torn_wal_record_leaves_neither_session_nor_audit_event() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let realm_name = format!("hea1954-{}", uuid::Uuid::new_v4());
    let realm_id;

    // Phase 1: set up realm and user so subsequent create_session costs exactly
    // one WAL record (steady state).
    let user_id = {
        let (_, engine, _) = open_engine(tmp.path());

        let realm = engine
            .create_realm(&CreateRealmRequest {
                name: realm_name.clone(),
                config: None,
            })
            .expect("create realm");
        realm_id = realm.id().clone();

        let user = engine
            .create_user(
                &realm_id,
                &CreateUserRequest {
                    email: format!("torn-{}@hea1954.test", uuid::Uuid::new_v4()),
                    display_name: "torn test".to_string(),
                    first_name: String::new(),
                    last_name: String::new(),
                    attributes: Default::default(),
                },
            )
            .expect("create user");

        // Warm the audit chain head so the next create_session is steady-state
        // (no one-time initialisation record).
        engine
            .create_session(&realm_id, user.id(), &SessionContext::default())
            .expect("warm-up session");

        user.id().clone()
    };

    // Phase 2: open fresh, create one session, then corrupt the WAL record
    // before reopening — simulating a crash / torn write on the merged record.
    {
        let (_, engine, _) = open_engine(tmp.path());

        engine
            .create_session(&realm_id, &user_id, &SessionContext::default())
            .expect("session to be torn");
    }

    // Flip the last 4 bytes of the WAL file (the CRC of the most recent record).
    // WAL replay stops at the first bad CRC and discards everything after it.
    {
        let wal_path = tmp.path().join("hearth.wal");
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&wal_path)
            .expect("open WAL for corruption");
        let len = file.seek(SeekFrom::End(0)).expect("seek end");
        assert!(len >= 4, "WAL too short to corrupt");
        file.seek(SeekFrom::End(-4)).expect("seek -4");
        let mut crc_bytes = [0u8; 4];
        std::io::Read::read_exact(&mut file, &mut crc_bytes).expect("read CRC");
        // XOR all bits to guarantee the CRC is invalid regardless of original value.
        let corrupt = u32::from_le_bytes(crc_bytes) ^ 0xFFFF_FFFF;
        file.seek(SeekFrom::End(-4)).expect("seek -4 again");
        file.write_all(&corrupt.to_le_bytes()).expect("write corrupt CRC");
        file.sync_all().expect("sync");
    }

    // Phase 3: reopen and verify that BOTH the session and the audit event were
    // discarded — the merged write is atomic.
    {
        let (_, engine, audit) = open_engine(tmp.path());

        // The warm-up session (from phase 1) should still exist.
        // The torn session (from phase 2) must not.
        let sessions = engine
            .list_sessions_by_user(
                &realm_id,
                &user_id,
                &hearth::core::PageRequest::new(0, 100),
            )
            .expect("list sessions");

        // Phase 1 warm-up session + phase 2 create (NOT committed → must be 1).
        assert_eq!(
            sessions.total, 1,
            "torn WAL record must leave no session: found {} sessions (expected 1 from warm-up)",
            sessions.total
        );

        // Audit event count: warm-up (1 session) + user create + realm create, but
        // specifically the SessionCreated from the torn write must be absent.
        // Count the SessionCreated events: exactly 1 (warm-up), not 2.
        let events = audit
            .query(&AuditQuery::for_realm(realm_id.clone()))
            .expect("query audit");
        let session_created_count = events
            .iter()
            .filter(|e| e.action == hearth::audit::AuditAction::SessionCreated)
            .count();
        assert_eq!(
            session_created_count, 1,
            "torn WAL record must leave no SessionCreated audit event: \
             found {session_created_count} (expected 1 from warm-up)"
        );

        // Integrity chain must still verify cleanly.
        let valid = audit
            .verify_integrity(&realm_id, None, None)
            .expect("verify chain");
        assert!(valid, "audit chain integrity must survive a torn merged record");
    }
}
