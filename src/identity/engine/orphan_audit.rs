//! Audit of registry references that permission resolution skipped.
//!
//! `rbac` resolution skips a reference to a registry entry that `hearth.yaml`
//! no longer defines and returns it in [`ResolvedPermissions::orphans`]. The
//! identity layer writes one `OrphanedReferenceSkipped` audit event per realm
//! and reference per hour (custom-permissions "Registry reload is lazy and
//! non-destructive"). The window is kept per node: a cluster-wide window would
//! put a replicated write on the token path.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::audit::{Actor, AuditAction, AuditContext};
use crate::core::{RealmId, Timestamp};
use crate::rbac::{OrphanKind, OrphanRef};

use super::EmbeddedIdentityEngine;

/// One event per `(realm, reference)` per hour.
const ORPHAN_AUDIT_WINDOW_MICROS: i64 = 3_600 * 1_000_000;

/// Upper bound on remembered keys. When full, expired keys are evicted; when
/// it is still full, the event is not written, so memory stays bounded however
/// many distinct orphans exist.
const ORPHAN_AUDIT_MAX_KEYS: usize = 10_000;

/// Per-node rate limiter for `OrphanedReferenceSkipped` audit events.
pub(super) struct OrphanAuditLimiter {
    last_written: Mutex<HashMap<(RealmId, OrphanRef), Timestamp>>,
}

impl OrphanAuditLimiter {
    pub(super) fn new() -> Self {
        Self {
            last_written: Mutex::new(HashMap::new()),
        }
    }

    /// Returns `true`, and records `now`, when an event for `orphan` in
    /// `realm_id` may be written at `now`.
    fn admit(&self, realm_id: &RealmId, orphan: &OrphanRef, now: Timestamp) -> bool {
        let mut last = self
            .last_written
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = (realm_id.clone(), orphan.clone());
        let fresh = |at: &Timestamp| now.as_micros() - at.as_micros() < ORPHAN_AUDIT_WINDOW_MICROS;
        if last.get(&key).is_some_and(fresh) {
            return false;
        }
        if last.len() >= ORPHAN_AUDIT_MAX_KEYS && !last.contains_key(&key) {
            last.retain(|_, at| fresh(at));
            if last.len() >= ORPHAN_AUDIT_MAX_KEYS {
                return false;
            }
        }
        last.insert(key, now);
        true
    }
}

fn kind_label(kind: OrphanKind) -> &'static str {
    match kind {
        OrphanKind::Permission => "permission",
        OrphanKind::Role => "role",
        OrphanKind::RoleName => "role_name",
    }
}

impl EmbeddedIdentityEngine {
    /// Writes `OrphanedReferenceSkipped` for each skipped reference, at most
    /// once per realm and reference per hour on this node. An audit failure
    /// never fails the issuance that found the orphan.
    pub(super) fn audit_orphans(&self, realm_id: &RealmId, orphans: &[OrphanRef]) {
        if orphans.is_empty() {
            return;
        }
        let now = self.clock.now();
        for orphan in orphans {
            if !self.orphan_audit.admit(realm_id, orphan, now) {
                continue;
            }
            tracing::warn!(
                realm_id = %realm_id,
                kind = kind_label(orphan.kind),
                reference = %orphan.reference,
                action = "orphaned_reference_skipped",
                "registry reference skipped during permission resolution"
            );
            let ctx = AuditContext {
                actor: Actor::System,
                metadata: Some(serde_json::json!({
                    "kind": kind_label(orphan.kind),
                    "reference": orphan.reference,
                })),
            };
            if let Err(e) = self.record_audit(
                realm_id,
                Some(&ctx),
                AuditAction::OrphanedReferenceSkipped,
                "rbac_reference",
                &orphan.reference,
            ) {
                tracing::warn!(error = %e, "OrphanedReferenceSkipped audit not written");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn orphan(name: &str) -> OrphanRef {
        OrphanRef {
            kind: OrphanKind::Permission,
            reference: name.to_string(),
        }
    }

    #[test]
    fn one_admission_per_key_per_window() {
        let limiter = OrphanAuditLimiter::new();
        let realm = RealmId::generate();
        let t0 = Timestamp::from_micros(1_000_000_000);
        assert!(limiter.admit(&realm, &orphan("docs.archive"), t0));
        assert!(!limiter.admit(&realm, &orphan("docs.archive"), t0.add_micros(1)));
        assert!(
            limiter.admit(&realm, &orphan("docs.purge"), t0),
            "another reference"
        );
        assert!(
            limiter.admit(&RealmId::generate(), &orphan("docs.archive"), t0),
            "another realm"
        );
        assert!(
            limiter.admit(
                &realm,
                &orphan("docs.archive"),
                t0.add_micros(ORPHAN_AUDIT_WINDOW_MICROS)
            ),
            "the window has passed"
        );
    }

    #[test]
    fn a_full_limiter_evicts_expired_keys_and_stays_bounded() {
        let limiter = OrphanAuditLimiter::new();
        let realm = RealmId::generate();
        let t0 = Timestamp::from_micros(1_000_000_000);
        for i in 0..ORPHAN_AUDIT_MAX_KEYS {
            assert!(limiter.admit(&realm, &orphan(&format!("p.{i}")), t0));
        }
        assert!(
            !limiter.admit(&realm, &orphan("p.new"), t0.add_micros(1)),
            "full of live keys: the new key is not admitted"
        );
        let later = t0.add_micros(ORPHAN_AUDIT_WINDOW_MICROS);
        assert!(
            limiter.admit(&realm, &orphan("p.new"), later),
            "expired keys are evicted"
        );
        let len = limiter.last_written.lock().map(|m| m.len()).unwrap_or(0);
        assert_eq!(len, 1);
    }
}
