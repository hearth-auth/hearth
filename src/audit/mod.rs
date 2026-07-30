//! Audit logging: append-only, tamper-evident event log.
//!
//! Cross-cutting infrastructure for recording security-critical mutations.
//! All events are realm-scoped and linked via a SHA-256 hash chain for
//! tamper detection.
//!
//! # Public API
//!
//! The [`AuditEngine`] trait defines the interface. [`EmbeddedAuditEngine`]
//! is the storage-backed implementation.
//!
//! Events are **append-only**: the trait exposes no update or delete
//! operations. This is enforced at the type level. The sole exception is
//! [`AuditEngine::prune_before`], an explicit administrative deletion used
//! for compliance-driven retention (e.g., COPPA data deletion).

pub mod context;
mod engine;
pub mod error;
pub(crate) mod keys;
mod types;

pub use context::{Actor, AuditContext};
pub use engine::EmbeddedAuditEngine;
pub use error::AuditError;
pub use types::{
    AuditAction, AuditEvent, AuditFailurePolicy, AuditQuery, AuditRetentionConfig, CreateAuditEvent,
};

use crate::core::{RealmId, Timestamp};
use crate::storage::{StorageDurabilityHandle, StorageError};

/// Outcome of a successful [`AuditEngine::with_pending_append`] call.
///
/// The caller must:
/// 1. Call [`crate::storage::StorageEngine::await_batch_durable`] on `handle`.
/// 2. On success: call `on_success()` (e.g. to broadcast the event to webhook listeners).
/// 3. On failure: call `on_failure()` to invalidate the audit chain cache so the next
///    [`AuditEngine::append`] re-reads the last-good head from storage.
pub struct AuditPendingWrite {
    /// The computed audit event (for use in responses or further processing).
    pub event: AuditEvent,
    /// Durability handle for the combined (caller + audit) WAL batch.
    pub handle: StorageDurabilityHandle,
    /// Invalidates the audit chain cache. Call this if `await_batch_durable` fails.
    pub on_failure: Box<dyn FnOnce() + Send>,
    /// Post-durability hook. Call this after a successful `await_batch_durable`.
    pub on_success: Box<dyn FnOnce() + Send>,
}

/// Caller-supplied WAL enqueue closure for the merged audit-write path.
///
/// Receives the audit KV pairs computed under the chain lock (primary event
/// record + two index entries + chain-head update) and is expected to combine
/// them with the caller's own KV pairs into a single
/// [`StorageEngine::enqueue_batch`] call — one WAL record, one fsync
/// (`W` 2 → 1, HEA-1954).
///
/// [`StorageEngine::enqueue_batch`]: crate::storage::StorageEngine::enqueue_batch
pub type AuditEnqueueFn<'a> =
    Box<dyn FnOnce(&[(Vec<u8>, Vec<u8>)]) -> Result<StorageDurabilityHandle, StorageError> + 'a>;

/// Trait defining the audit engine interface.
///
/// Events are append-only by design to maintain the tamper-evident hash chain.
/// The only administrative deletion path is [`prune_before`], which is
/// intentional and explicitly breaks the chain for the pruned window.
pub trait AuditEngine: Send + Sync {
    /// Appends a new audit event to the log.
    ///
    /// The engine assigns the event ID, timestamp, and integrity hash.
    /// Returns the complete event including computed fields.
    fn append(&self, event: &CreateAuditEvent) -> Result<AuditEvent, AuditError>;

    /// Queries audit events matching the given criteria.
    ///
    /// Results are returned in chronological order. All filters are
    /// combined with AND semantics.
    fn query(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>, AuditError>;

    /// Verifies the integrity of the audit log hash chain.
    ///
    /// Walks the event chain for the given realm and time range,
    /// recomputing hashes and comparing against stored values.
    /// Returns `true` if the chain is valid, `false` if tampered.
    fn verify_integrity(
        &self,
        realm_id: &RealmId,
        start: Option<Timestamp>,
        end: Option<Timestamp>,
    ) -> Result<bool, AuditError>;

    /// Returns the retention configuration for a realm.
    ///
    /// Returns the default config (90 days) if none has been set.
    fn get_retention_config(&self, realm_id: &RealmId) -> Result<AuditRetentionConfig, AuditError>;

    /// Updates the retention configuration for a realm.
    fn set_retention_config(
        &self,
        realm_id: &RealmId,
        config: &AuditRetentionConfig,
    ) -> Result<(), AuditError>;

    /// Deletes all audit events strictly older than `cutoff`.
    ///
    /// This is an intentional administrative operation for compliance-driven
    /// retention (e.g., COPPA). It breaks the hash chain for the pruned
    /// window — integrity verification should only be run against the
    /// retained window after pruning.
    ///
    /// Returns the number of primary events deleted.
    fn prune_before(&self, realm_id: &RealmId, cutoff: Timestamp) -> Result<u64, AuditError>;

    /// Returns the total number of audit events stored for this realm (A-25).
    ///
    /// Used by the background pruner to enforce the `max_rows` backstop.
    fn count_events(&self, realm_id: &RealmId) -> Result<u64, AuditError>;

    /// Deletes the oldest `n` audit events for this realm (A-25 max_rows backstop).
    ///
    /// Returns the number of primary events actually deleted (may be less than
    /// `n` if the realm has fewer events).
    fn prune_oldest(&self, realm_id: &RealmId, n: u64) -> Result<u64, AuditError>;

    /// Merged-write variant: builds the audit KV pairs under the chain lock and
    /// delegates the WAL enqueue to the caller's closure, so the caller can merge
    /// the audit event into its own `put_batch` — one fsync for caller data + audit
    /// event (W 2 → 1, HEA-1954).
    ///
    /// The chain lock is held while `enqueue_fn` executes, guaranteeing that
    /// audit-chain ordering matches WAL ordering. The closure receives the computed
    /// audit KV pairs (primary event record + two index entries + chain-head update);
    /// it should combine them with its own KV pairs and call
    /// `storage.enqueue_batch(...)`, returning the resulting handle.
    ///
    /// The caller must call [`StorageEngine::await_batch_durable`] on
    /// `AuditPendingWrite::handle`, then call `on_success` (durability confirmed)
    /// or `on_failure` (durability failed).
    ///
    /// Implementations that do not support the merged path return
    /// `Err(AuditError::MergedAppendNotSupported)`. The caller must then fall back
    /// to a separate storage write followed by [`append`][AuditEngine::append].
    ///
    /// [`StorageEngine::await_batch_durable`]: crate::storage::StorageEngine::await_batch_durable
    fn with_pending_append(
        &self,
        request: &CreateAuditEvent,
        enqueue_fn: AuditEnqueueFn<'_>,
    ) -> Result<AuditPendingWrite, AuditError> {
        let _ = (request, enqueue_fn);
        Err(AuditError::MergedAppendNotSupported)
    }
}
