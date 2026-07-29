//! HEA-1945 — pins how many durable WAL records `create_session` costs.
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
//! `create_session` wrote three separate records: the session body, the
//! user→session index entry, and the audit event. The first two describe a
//! single logical fact and are now written as one atomic `put_batch`, which
//! also closes a crash window that could strand an index entry pointing at a
//! session that was never persisted.
//!
//! This test pins the resulting count so a later refactor cannot silently
//! re-split the batch back into separate `put` calls and regress the write
//! path without anyone noticing.

use std::path::PathBuf;
use std::sync::Arc;

use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{Clock, SystemClock};
use hearth::identity::{
    CreateRealmRequest, CreateUserRequest, CredentialConfig, EmbeddedIdentityEngine,
    IdentityConfig, IdentityEngine, SessionContext,
};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// WAL records a single `create_session` is allowed to emit:
///   1. session body + user→session index (one atomic `put_batch`)
///   2. the `SessionCreated` audit event (`AuditEngine::append`'s `put_batch`)
///
/// Lowering this further means coalescing the audit event into the same
/// record, which requires splitting the audit chain lock off the durability
/// wait — tracked separately, not by this test.
const EXPECTED_WAL_RECORDS_PER_SESSION_CREATE: u64 = 2;

#[test]
fn create_session_costs_two_wal_records() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // `production()` is the only constructor that guarantees
    // `SyncMode::EveryWrite`, which is what makes one WAL append == one fsync
    // and therefore makes `wal_sync_count()` a faithful record counter here.
    let mut config = StorageConfig::production(
        PathBuf::from(tmp.path()),
        256 * 1024 * 1024,
        8 * 1024 * 1024,
        4_096,
    );
    // Auto-generates the host key for the temp dir; does not relax durability.
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
        clock,
        IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        },
        rbac,
        audit,
    )
    .expect("build identity engine");

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
         throughput by the device fsync rate again (HEA-1945)."
    );
    assert_eq!(
        first, steady,
        "first create_session cost {first} WAL records vs {steady} in steady state — a \
         per-realm one-time write is hiding inside the session write path"
    );
}
