//! The daily audit prune of one realm: A-25 `retention_days` and `max_rows`,
//! and the A-24 quotas `max_audit_rows` and `max_disk_bytes`.
//!
//! The server runs [`prune_realm_audit`] for every realm once per day.

use std::ops::ControlFlow;

use tracing::{info, warn};

use crate::audit::AuditEngine;
use crate::core::Timestamp;
use crate::identity::Realm;
use crate::storage::StorageEngine;

/// What one realm's daily audit prune did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuditPruneReport {
    /// Events deleted because they were older than `retention_days`.
    pub deleted_by_age: u64,
    /// Events deleted because the realm held more than `row_limit` events.
    pub deleted_by_rows: u64,
    /// The row limit applied: the lower of the audit `max_rows` and the realm
    /// quota `max_audit_rows`. `None` when neither is set.
    pub row_limit: Option<u64>,
    /// The realm's storage use in bytes (keys plus values). `None` when
    /// `max_disk_bytes` is not set or the sample failed.
    pub usage_bytes: Option<u64>,
}

/// Runs the daily audit prune for `realm` at `now`:
///
/// 1. Deletes the events older than the audit `retention_days` (`0` = off).
/// 2. Deletes the oldest events above the row limit, the lower of the audit
///    `max_rows` and the quota `max_audit_rows` (#630).
/// 3. When the quota `max_disk_bytes` is set, measures the realm's storage
///    and warns at or above it. It never blocks a write.
///
/// A failed step is logged at `warn`, and the later steps still run. Counting
/// and measuring read no more than one entry at a time.
pub fn prune_realm_audit(
    audit: &dyn AuditEngine,
    storage: &dyn StorageEngine,
    realm: &Realm,
    now: Timestamp,
) -> AuditPruneReport {
    let mut report = AuditPruneReport::default();
    let quotas = realm.config().quotas.as_ref();
    let retention = match audit.get_retention_config(realm.id()) {
        Ok(config) => Some(config),
        Err(e) => {
            warn!(realm = %realm.name(), error = %e, "audit prune: config fetch failed");
            None
        }
    };

    if let Some(days) = retention
        .as_ref()
        .map(|r| r.retention_days)
        .filter(|d| *d > 0)
    {
        let window_micros = i64::from(days) * 86_400 * 1_000_000;
        let cutoff = Timestamp::from_micros(now.as_micros().saturating_sub(window_micros));
        match audit.prune_before(realm.id(), cutoff) {
            Ok(0) => {}
            Ok(n) => {
                report.deleted_by_age = n;
                info!(realm = %realm.name(), deleted = n, "audit prune: pruned old events");
            }
            Err(e) => warn!(realm = %realm.name(), error = %e, "audit prune: prune failed"),
        }
    }

    report.row_limit = match (
        retention.as_ref().and_then(|r| r.max_rows),
        quotas.and_then(|q| q.max_audit_rows),
    ) {
        (Some(max_rows), Some(max_audit_rows)) => Some(max_rows.min(max_audit_rows)),
        (max_rows, max_audit_rows) => max_rows.or(max_audit_rows),
    };
    if let Some(max_rows) = report.row_limit {
        match audit.count_events(realm.id()) {
            Ok(count) if count > max_rows => {
                match audit.prune_oldest(realm.id(), count - max_rows) {
                    Ok(0) => {}
                    Ok(n) => {
                        report.deleted_by_rows = n;
                        info!(
                            realm = %realm.name(),
                            deleted = n,
                            max_rows,
                            "audit prune: row limit trimmed oldest events"
                        );
                    }
                    Err(e) => {
                        warn!(realm = %realm.name(), error = %e, "audit prune: row trim failed");
                    }
                }
            }
            Ok(_) => {}
            Err(e) => warn!(realm = %realm.name(), error = %e, "audit prune: count_events failed"),
        }
    }

    if let Some(limit) = quotas.and_then(|q| q.max_disk_bytes) {
        // Walk every entry of the realm one at a time (#630): a value scan of
        // the whole realm held all of it in memory at once.
        let mut usage: u64 = 0;
        let walk = storage.visit_entries(realm.id(), b"", &[0xFF; 256], &mut |key, value| {
            usage = usage.saturating_add((key.len() + value.len()) as u64);
            ControlFlow::Continue(())
        });
        match walk {
            Ok(()) => {
                report.usage_bytes = Some(usage);
                if usage >= limit {
                    warn!(
                        realm = %realm.name(),
                        usage_bytes = usage,
                        limit_bytes = limit,
                        "disk pressure: realm storage usage at or above configured max_disk_bytes"
                    );
                }
            }
            Err(e) => warn!(realm = %realm.name(), error = %e, "audit prune: disk sample failed"),
        }
    }

    report
}
