//! #645: the audit pruner runs its first sweep soon after startup, then once
//! per day. A server that restarts more often than once per day must still
//! prune.
//!
//! The tests run on paused Tokio time: the runtime moves the clock forward
//! when every task waits, so a day of schedule takes no real time.

mod common;

use std::sync::Arc;
use std::time::Duration;

use hearth::audit::{AuditAction, AuditEngine, CreateAuditEvent};
use hearth::core::{Clock, RealmId, SystemClock};
use hearth::identity::audit_prune::{run_audit_pruner, PruneSchedule};
use hearth::identity::{CreateRealmRequest, Realm, RealmConfig, RealmQuotaConfig};

/// The latest time after startup at which the first sweep must have run.
const FIRST_SWEEP_BOUND: Duration = Duration::from_secs(5 * 60);

/// The row limit of the test realm.
const ROW_LIMIT: u64 = 10;

fn append_events(audit: &dyn AuditEngine, realm: &RealmId, n: u64) {
    for _ in 0..n {
        audit
            .append(&CreateAuditEvent {
                realm_id: realm.clone(),
                actor: "system".to_string(),
                action: AuditAction::UserCreated,
                resource_type: "user".to_string(),
                resource_id: uuid::Uuid::new_v4().to_string(),
                metadata: None,
            })
            .expect("append");
    }
}

fn realm_with_row_limit(h: &common::TestHarness) -> Realm {
    h.identity()
        .create_realm(&CreateRealmRequest {
            name: format!("audit-schedule-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                quotas: Some(RealmQuotaConfig {
                    max_audit_rows: Some(ROW_LIMIT),
                    ..RealmQuotaConfig::default()
                }),
                ..RealmConfig::default()
            }),
        })
        .expect("create realm with a row limit")
}

/// Waits on paused time until `realm` holds `ROW_LIMIT` events or `bound` has
/// gone by. Returns the time it waited, or `None` at the bound.
async fn wait_for_trim(
    audit: &dyn AuditEngine,
    realm: &RealmId,
    bound: Duration,
) -> Option<Duration> {
    let start = tokio::time::Instant::now();
    while start.elapsed() <= bound {
        if audit.count_events(realm).expect("count") == ROW_LIMIT {
            return Some(start.elapsed());
        }
        // Move the paused clock 10 s; the pruner task runs while this yields.
        tokio::time::advance(Duration::from_secs(10)).await;
        tokio::task::yield_now().await;
    }
    None
}

fn spawn_pruner(h: &common::TestHarness) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run_audit_pruner(
        h.audit_arc(),
        h.identity_arc(),
        h.storage_arc(),
        Arc::new(SystemClock) as Arc<dyn Clock>,
        PruneSchedule::default(),
    ))
}

/// Regression for #645: the first sweep ran 24 h after startup, so a server
/// that restarted every day never pruned.
#[tokio::test(start_paused = true)]
async fn the_first_prune_runs_soon_after_startup() {
    let h = common::TestHarness::in_process().await.expect("setup");
    let realm = realm_with_row_limit(&h);
    append_events(h.audit(), realm.id(), ROW_LIMIT + 5);

    let pruner = spawn_pruner(&h);
    let waited = wait_for_trim(h.audit(), realm.id(), FIRST_SWEEP_BOUND).await;
    pruner.abort();

    assert!(
        waited.is_some(),
        "no prune in the first {FIRST_SWEEP_BOUND:?} after startup: the realm still holds {} \
         events, the row limit is {ROW_LIMIT}",
        h.audit().count_events(realm.id()).expect("count")
    );
}

/// After the first sweep, the pruner sweeps again once per day.
#[tokio::test(start_paused = true)]
async fn the_prune_repeats_daily() {
    let h = common::TestHarness::in_process().await.expect("setup");
    let realm = realm_with_row_limit(&h);
    append_events(h.audit(), realm.id(), ROW_LIMIT + 5);

    let pruner = spawn_pruner(&h);
    let day = Duration::from_secs(24 * 60 * 60);
    assert!(
        wait_for_trim(h.audit(), realm.id(), day + FIRST_SWEEP_BOUND)
            .await
            .is_some(),
        "the first sweep did not run"
    );

    append_events(h.audit(), realm.id(), 5);
    let waited = wait_for_trim(h.audit(), realm.id(), day + Duration::from_secs(60)).await;
    pruner.abort();

    let waited = waited.expect("no second sweep within a day of the first");
    assert!(
        waited > day.saturating_sub(FIRST_SWEEP_BOUND),
        "the second sweep ran {waited:?} after the first, not about a day"
    );
}
