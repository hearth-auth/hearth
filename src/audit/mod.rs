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
pub use engine::{first_broken_link, ChainVerifier, EmbeddedAuditEngine};
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
/// The material a restore needs to verify an exported audit chain.
///
/// Carried in a backup archive next to `audit.ndjson`, encrypted with the
/// archive DEK exactly like the realm's signing key.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditChainMaterial {
    /// The realm's HMAC-SHA256 chain key, base64 (standard alphabet).
    pub chain_key_b64: String,
    /// The chain's anchor hash — `GENESIS_HASH` unless the chain was pruned.
    pub anchor: String,
}

impl std::fmt::Debug for AuditChainMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditChainMaterial")
            .field("chain_key_b64", &"[REDACTED]")
            .field("anchor", &self.anchor)
            .finish()
    }
}

/// What [`AuditEngine::import_events`] did with an archive's events.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuditImportOutcome {
    /// Events written into the destination chain.
    pub imported: u64,
    /// Events skipped because the realm already holds an event with that id.
    pub duplicates: u64,
    /// Whether the imported events were stamped with the import time (the
    /// realm already held events) rather than keeping their original times.
    pub restamped: bool,
}

/// What an audit import must know about the whole run of archived events
/// before it writes the first one, so that it can take the events one at a
/// time (#867).
///
/// Events keep their original timestamps only when the whole run is in
/// ascending time and none is in the future. A restore learns this when it
/// checks the archive's chain, before it imports: [`observe`](Self::observe)
/// each event in order, then pass the plan to
/// [`AuditEngine::import_event_stream`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuditImportPlan {
    /// The timestamp of the last event observed.
    last: Option<Timestamp>,
    /// The newest timestamp observed.
    newest: Option<Timestamp>,
    /// An event was older than the one before it.
    descending: bool,
}

impl AuditImportPlan {
    /// The plan for the run `events`.
    pub fn of(events: &[AuditEvent]) -> Self {
        let mut plan = Self::default();
        for event in events {
            plan.observe(event);
        }
        plan
    }

    /// Adds `event`, the next event of the run.
    pub fn observe(&mut self, event: &AuditEvent) {
        if self.last.is_some_and(|last| event.timestamp < last) {
            self.descending = true;
        }
        self.last = Some(event.timestamp);
        self.newest = self.newest.max(Some(event.timestamp));
    }

    /// Whether the events observed are in ascending time.
    pub fn ascending(&self) -> bool {
        !self.descending
    }

    /// The newest timestamp observed, `None` for an empty run.
    pub fn newest(&self) -> Option<Timestamp> {
        self.newest
    }
}

pub trait AuditEngine: Send + Sync {
    /// A read-only copy of this engine that reads `storage`, a storage
    /// snapshot, or `None` if this engine cannot make one (#643). A backup
    /// export reads through it while writes continue on the live engine.
    ///
    /// The default returns `None`: correct for test doubles.
    fn read_view(
        &self,
        _storage: std::sync::Arc<dyn crate::storage::StorageEngine>,
    ) -> Option<std::sync::Arc<dyn AuditEngine>> {
        None
    }
    /// Appends a new audit event to the log.
    ///
    /// The engine assigns the event ID, timestamp, and integrity hash.
    /// Returns the complete event including computed fields.
    fn append(&self, event: &CreateAuditEvent) -> Result<AuditEvent, AuditError>;

    /// Restores audit events from a backup archive into `realm_id`'s chain
    /// (HEA-2160).
    ///
    /// `events` are the archive's events in their source chain order (the
    /// caller has already checked them against the archive's own chain). Each
    /// keeps its `id`, `actor`, `action`, resource fields and metadata, gains
    /// an explicit `backup_restore` marker in its metadata recording its
    /// original timestamp, and is re-chained under the destination realm's
    /// HMAC key (the source key is not portable) **at the end of the
    /// destination chain** — imported history never slots in before, or is
    /// re-signed together with, events the destination already holds:
    ///
    /// - Into a realm whose chain holds no event, events keep their original
    ///   timestamps (a rebuilt data directory keeps its history's times).
    /// - Into a realm that already holds events, each is stamped with the
    ///   import time — the original stays in the marker — so storage order
    ///   stays chain order and the realm keeps verifying.
    ///
    /// - Once any other event is in the chain — before the import, or a live
    ///   append landing between two chunks — the remaining events are stamped
    ///   no earlier than it, for the same reason.
    ///
    /// An event whose `id` the realm already holds is skipped, so re-importing
    /// an archive adds nothing. Events are written in atomic chunks, each
    /// advancing the signed chain head with it; the realm's chain lock is held
    /// per chunk (never across a chunk's fsync or the whole import), so live
    /// audit writes to the realm wait at most for one chunk. A chunk that fails
    /// leaves the chunks before it durable, chained and anchored.
    ///
    /// The slice form of [`import_event_stream`](Self::import_event_stream).
    fn import_events(
        &self,
        realm_id: &RealmId,
        events: &[AuditEvent],
    ) -> Result<AuditImportOutcome, AuditError> {
        self.import_event_stream(
            realm_id,
            &AuditImportPlan::of(events),
            &mut events.iter().cloned(),
        )
    }

    /// [`import_events`](Self::import_events) for a run of events that the
    /// caller passes one at a time, so that an import does not hold the run
    /// in memory (#867).
    ///
    /// `plan` describes the whole run of `events` (see [`AuditImportPlan`]).
    /// If the run does not match it — an event older than the one before it,
    /// or one in the future, where the plan said there is none — the
    /// remaining events are stamped no earlier than every event written
    /// before them, so storage order stays chain order.
    ///
    /// The duplicate check is against the events the realm holds when the
    /// import starts.
    fn import_event_stream(
        &self,
        realm_id: &RealmId,
        plan: &AuditImportPlan,
        events: &mut dyn Iterator<Item = AuditEvent>,
    ) -> Result<AuditImportOutcome, AuditError>;

    /// Returns the material a restore needs to verify an exported chain.
    ///
    /// `Ok(None)` means this realm has no audit chain — there is nothing to
    /// export. `Ok(Some(..))` carries the realm's HMAC chain key and the
    /// chain's current anchor, which is `GENESIS_HASH` on an un-pruned chain
    /// and the last-pruned event's hash after a retention prune.
    ///
    /// Restore re-signs every imported event under the destination realm's key,
    /// so without this the source hashes are discarded unchecked and a tampered
    /// archive restores into a chain that verifies clean (audit 2026-08-28
    /// §4.14#5). There is deliberately no default implementation: one that
    /// answered `None` would silently reinstate that.
    fn export_chain_material(
        &self,
        realm_id: &RealmId,
    ) -> Result<Option<AuditChainMaterial>, AuditError>;

    /// Queries audit events matching the given criteria.
    ///
    /// Results are returned in chronological order. All filters are
    /// combined with AND semantics.
    fn query(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>, AuditError>;

    /// Passes every event of `realm_id` to `visit`, oldest first, one at a
    /// time, for backup export (#866). The order is the chain order, as for
    /// [`query`](Self::query).
    ///
    /// The default collects [`query`](Self::query) first, so its memory grows
    /// with the log: correct for test doubles.
    fn export_events(
        &self,
        realm_id: &RealmId,
        visit: &mut crate::core::ExportVisitor<'_, AuditEvent>,
    ) -> Result<(), AuditError> {
        for event in self.query(&AuditQuery::for_realm(realm_id.clone()))? {
            if visit(event).is_break() {
                break;
            }
        }
        Ok(())
    }

    /// Returns the newest events that match `query`, newest first (#644).
    ///
    /// `query.limit` caps the number of events. `query.end_time` is the
    /// exclusive upper bound, or the current time when it is `None`.
    /// `query.start_time` is the inclusive lower bound, or the start of the
    /// log when it is `None`.
    ///
    /// The engine reads back from the upper bound in growing time windows
    /// (1 hour, 1 day, 7 days, 30 days, 365 days, then the remaining log). It
    /// stops after the first window that holds `limit` matching events, so a
    /// busy realm reads only its recent events. A quiet realm can read its
    /// whole log, once.
    fn recent(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>, AuditError>;

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

    /// A replicated row was applied on this node for `realm_id` (task 26.47).
    ///
    /// The append path caches each realm's signed [`chain head`](AuditEvent)
    /// and prefers it over the persisted one, so a node that has appended for
    /// a realm never re-reads the head. Leadership flapping then forks the
    /// chain: node A leads and reaches sequence N, leadership moves to B which
    /// advances the persisted head to N+50, leadership returns to A — whose
    /// cache still says N — and A chains its next event off a stale
    /// `prev_hash` while re-using sequence numbers that are already taken.
    ///
    /// The cache is dropped when the head row arrives from another node, so
    /// the next append reloads it. There is deliberately no default
    /// implementation: one that did nothing would silently reinstate the fork.
    fn on_replicated_row(&self, realm_id: &RealmId, key: &[u8]);

    /// The whole key-space was replaced (snapshot install). Implementors MUST
    /// drop every cached chain head.
    fn on_replicated_snapshot(&self);

    /// The realm was deleted: its stored audit rows, HMAC key and chain anchor
    /// are gone. Implementors MUST drop all in-memory state they keep for
    /// `realm_id` (#609).
    ///
    /// The identity engine calls this after the realm-delete cascade. There is
    /// deliberately no default implementation: a wrapper that did nothing
    /// would keep the inner engine's state for every deleted realm.
    fn forget_realm(&self, realm_id: &RealmId);

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
    /// The events go in atomic batches of bounded size, oldest first, and the
    /// realm's chain lock is held for one batch at a time (#735). If a batch
    /// fails, the batches before it stay deleted and the error is returned.
    ///
    /// Returns the number of primary events deleted.
    fn prune_before(&self, realm_id: &RealmId, cutoff: Timestamp) -> Result<u64, AuditError>;

    /// Returns the total number of audit events stored for this realm (A-25).
    ///
    /// Used by the background pruner to enforce the `max_rows` backstop.
    fn count_events(&self, realm_id: &RealmId) -> Result<u64, AuditError>;

    /// Deletes the oldest `n` audit events for this realm (A-25 max_rows backstop).
    ///
    /// Deletes in atomic batches of bounded size, as
    /// [`prune_before`](Self::prune_before) does.
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
