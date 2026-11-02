//! #630 part 2 (OpenSpec `fix-spec-drift-defects` task 1.4): the daily audit
//! pruner enforces the realm quota `max_audit_rows` (A-24), and its counts and
//! disk sample read no record values.

mod common;

use hearth::audit::{AuditAction, AuditEngine, AuditRetentionConfig, CreateAuditEvent};
use hearth::core::{RealmId, Timestamp};
use hearth::identity::audit_prune::prune_realm_audit;
use hearth::identity::{CreateRealmRequest, Realm, RealmConfig, RealmQuotaConfig};
use hearth::storage::{ScanEntry, StorageEngine, StorageError};

/// Appends events to `realm` until it holds `total` audit events.
fn fill_to(audit: &dyn AuditEngine, realm: &RealmId, total: u64) {
    let have = audit.count_events(realm).expect("count before fill");
    assert!(have <= total, "the realm already holds {have} events");
    for _ in have..total {
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

fn realm_with_quota(h: &common::TestHarness, quota: RealmQuotaConfig) -> Realm {
    h.identity()
        .create_realm(&CreateRealmRequest {
            name: format!("audit-rows-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                quotas: Some(quota),
                ..RealmConfig::default()
            }),
        })
        .expect("create realm with quota")
}

/// Scenario "Regression — audit row quota is enforced": a realm with
/// `max_audit_rows: 1000` that holds 1 500 events loses its oldest 500 at the
/// daily prune.
#[tokio::test]
async fn a24_the_daily_prune_enforces_max_audit_rows() {
    let h = common::TestHarness::in_process().await.expect("setup");
    let realm = realm_with_quota(
        &h,
        RealmQuotaConfig {
            max_audit_rows: Some(1000),
            ..RealmQuotaConfig::default()
        },
    );
    fill_to(h.audit(), realm.id(), 1500);

    let report = prune_realm_audit(h.audit(), h.storage(), &realm, Timestamp::now());

    assert_eq!(report.row_limit, Some(1000));
    assert_eq!(report.deleted_by_rows, 500, "the oldest 500 events go");
    assert_eq!(h.audit().count_events(realm.id()).expect("count"), 1000);
}

/// The audit `max_rows` and the quota `max_audit_rows` both cap the log, so the
/// prune applies the lower of the two, whichever setting holds it.
#[tokio::test]
async fn a24_the_lower_row_limit_wins() {
    let h = common::TestHarness::in_process().await.expect("setup");
    for (max_rows, max_audit_rows) in [(12, 10), (10, 12)] {
        let realm = realm_with_quota(
            &h,
            RealmQuotaConfig {
                max_audit_rows: Some(max_audit_rows),
                ..RealmQuotaConfig::default()
            },
        );
        h.audit()
            .set_retention_config(
                realm.id(),
                &AuditRetentionConfig {
                    retention_days: 90,
                    max_rows: Some(max_rows),
                },
            )
            .expect("set retention");
        fill_to(h.audit(), realm.id(), 15);

        let report = prune_realm_audit(h.audit(), h.storage(), &realm, Timestamp::now());

        assert_eq!(
            report.row_limit,
            Some(10),
            "max_rows {max_rows}, max_audit_rows {max_audit_rows}"
        );
        assert_eq!(h.audit().count_events(realm.id()).expect("count"), 10);
    }
}

/// With no row limit set, the prune deletes nothing by row count.
#[tokio::test]
async fn a24_no_row_limit_prunes_no_rows() {
    let h = common::TestHarness::in_process().await.expect("setup");
    let realm = realm_with_quota(&h, RealmQuotaConfig::default());
    fill_to(h.audit(), realm.id(), 20);

    let report = prune_realm_audit(h.audit(), h.storage(), &realm, Timestamp::now());

    assert_eq!(report.row_limit, None);
    assert_eq!(report.deleted_by_rows, 0);
    assert_eq!(h.audit().count_events(realm.id()).expect("count"), 20);
}

/// Storage that refuses a value scan of the whole realm (the scan the disk
/// sample did) and serves everything else.
struct WholeRealmValueScanRefused<'a> {
    inner: &'a dyn StorageEngine,
}

impl StorageEngine for WholeRealmValueScanRefused<'_> {
    fn get(&self, realm_id: &RealmId, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.get(realm_id, key)
    }

    fn put(&self, realm_id: &RealmId, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        self.inner.put(realm_id, key, value)
    }

    fn delete(&self, realm_id: &RealmId, key: &[u8]) -> Result<(), StorageError> {
        self.inner.delete(realm_id, key)
    }

    fn scan(
        &self,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
    ) -> Result<Vec<ScanEntry>, StorageError> {
        if start.is_empty() {
            return Err(StorageError::Io(std::io::Error::other(
                "a value scan of the whole realm",
            )));
        }
        self.inner.scan(realm_id, start, end)
    }

    fn visit_entries(
        &self,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
        visit: &mut hearth::storage::EntryVisitor<'_>,
    ) -> Result<(), StorageError> {
        self.inner.visit_entries(realm_id, start, end, visit)
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

/// The `max_disk_bytes` sample walks the realm one entry at a time: with a
/// value scan of the whole realm refused, it still measures the realm.
#[tokio::test]
async fn a24_the_disk_sample_streams_the_realm() {
    let h = common::TestHarness::in_process().await.expect("setup");
    let realm = realm_with_quota(
        &h,
        RealmQuotaConfig {
            max_disk_bytes: Some(1),
            ..RealmQuotaConfig::default()
        },
    );
    fill_to(h.audit(), realm.id(), 5);
    let storage = WholeRealmValueScanRefused { inner: h.storage() };

    let report = prune_realm_audit(h.audit(), &storage, &realm, Timestamp::now());

    let usage = report
        .usage_bytes
        .expect("the sample must measure the realm without a whole-realm value scan");
    assert!(usage > 0, "a realm with 5 events uses some bytes");
}
