//! Storage engine: WAL, memtable, SSTs, and tiered hot/cold storage.
//!
//! The leaf layer. Pure data persistence with no knowledge of identity,
//! auth, or authorization concepts.
//!
//! # Public API
//!
//! The [`StorageEngine`] trait defines the interface for upper layers.
//! [`EmbeddedStorageEngine`] is the default implementation composing
//! WAL, memtable, SST, and hot tier components.

pub mod auto_size;
#[allow(dead_code)]
pub(crate) mod block_cache;
pub mod encryption;
mod engine;
pub mod error;
pub mod fs;
mod key_merge;
#[allow(dead_code)]
pub(crate) mod key_registry;
#[allow(dead_code)]
pub(crate) mod memtable;
pub mod migrations;
mod paging;
#[allow(dead_code)]
pub(crate) mod sst;
#[allow(dead_code)]
mod tiered;
pub mod wal;

pub use engine::{CompactionConfig, EmbeddedStorageEngine, StorageConfig};
pub use error::{ClusterUnavailableCause, RetryClass, StorageError};
pub use fs::{Fs, FsFile, RealFs};
pub use key_merge::EntryVisitor;

use crate::core::RealmId;

/// A single key-value entry returned from a scan operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanEntry {
    /// The raw key bytes (without realm prefix).
    pub key: Vec<u8>,
    /// The value bytes.
    pub value: Vec<u8>,
}

/// Returns an exclusive end bound for a prefix scan (increments last byte).
///
/// Used alongside [`StorageEngine::scan`] to bound a scan to a given key
/// prefix: `scan(realm, prefix, &prefix_scan_end(prefix))`.
///
/// Panics if `prefix` is empty.
pub fn prefix_scan_end(prefix: &[u8]) -> Vec<u8> {
    let mut end = prefix.to_vec();
    if let Some(last) = end.last_mut() {
        *last = last.saturating_add(1);
    }
    end
}

/// Decodes a counter written by [`StorageEngine::increment_u64`]: an absent
/// value is `0`, and anything but exactly eight little-endian bytes is an error.
///
/// # Errors
///
/// [`StorageError::DeserializationFailed`] when `raw` is present but not eight
/// bytes long.
pub fn decode_u64_counter(raw: Option<&[u8]>) -> Result<u64, StorageError> {
    match raw {
        None => Ok(0),
        Some(bytes) => <[u8; 8]>::try_from(bytes)
            .map(u64::from_le_bytes)
            .map_err(|_| StorageError::DeserializationFailed {
                reason: format!("u64 counter is {} bytes, expected 8", bytes.len()),
            }),
    }
}

/// Opaque handle returned by [`StorageEngine::enqueue_batch`].
///
/// Pass to [`StorageEngine::await_batch_durable`] to block until all entries in
/// the batch are guaranteed durable (covered by a WAL `fsync`). The caller must
/// NOT treat the data as durable until after `await_batch_durable` returns `Ok`.
///
/// This type is intentionally opaque: the inner representation is
/// implementation-specific.
pub struct StorageDurabilityHandle(pub(crate) StorageDurabilityHandleKind);

/// Inner representation of a [`StorageDurabilityHandle`].
pub(crate) enum StorageDurabilityHandleKind {
    /// Batch already written synchronously. `await_batch_durable` is a no-op.
    Immediate,
    /// Batch is pending in the WAL group-commit queue.
    Pending(crate::storage::engine::PendingBatchHandle),
}

/// Trait defining the public storage engine interface.
///
/// Synchronous for Phase 0 — callers should use `spawn_blocking` for async
/// contexts. All operations require a `RealmId` for multi-realm isolation.
pub trait StorageEngine: Send + Sync {
    /// Retrieves a value by realm and key. Returns `None` if not found.
    fn get(&self, realm_id: &RealmId, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError>;

    /// Reads a key like [`get`](Self::get), without caching what it reads.
    ///
    /// A cold read through `get` promotes the row into the hot tier and puts
    /// its SST block in the block cache. A background walk that reads each
    /// row once, such as the cleanup sweep's grant-family check, would fill
    /// both caches with rows no request reads (#445); it reads through this
    /// instead. The answer is the same as `get`'s.
    ///
    /// The default implementation is `get`. [`EmbeddedStorageEngine`]
    /// overrides it.
    fn get_uncached(
        &self,
        realm_id: &RealmId,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, StorageError> {
        self.get(realm_id, key)
    }

    /// Inserts or updates a key-value pair for the given realm.
    fn put(&self, realm_id: &RealmId, key: &[u8], value: &[u8]) -> Result<(), StorageError>;

    /// Deletes a key for the given realm.
    fn delete(&self, realm_id: &RealmId, key: &[u8]) -> Result<(), StorageError>;

    /// Whether this handle proposes writes itself right now: always for
    /// local storage, hence the `true` default; in cluster mode only on the
    /// current Raft leader. A follower's writes still succeed — they are
    /// forwarded to the leader — but start-up paths that would otherwise
    /// write on a cold data directory consult this so the write set runs on
    /// exactly one node; see
    /// [`crate::identity::EmbeddedIdentityEngine::await_cold_start_window`].
    ///
    /// This is advisory, not a lock: the leader can change between the check
    /// and the write. It exists so start-up does not *begin* a write set that
    /// cannot possibly succeed, not to make writes infallible.
    fn accepts_writes(&self) -> bool {
        true
    }

    /// Writes a row that belongs to **this node only** and must not replicate.
    ///
    /// Defaults to [`Self::put`], which is correct for local storage: there is
    /// exactly one node. In cluster mode the cluster adapter overrides it to
    /// write straight to the node's own engine instead of proposing through
    /// Raft.
    ///
    /// Use it only for state that is per-node *by design* — the rehydration
    /// rows behind the in-memory rate-limit trackers are the case this exists
    /// for. Proposing those through Raft would replicate one node's counts to
    /// every node (and, before follower write forwarding, failed with
    /// `NotLeader` on every follower): a failure a follower counted was never
    /// persisted, and a lockout row the leader replicated could never be
    /// cleared by the follower that later saw the successful attempt.
    fn put_node_local(
        &self,
        realm_id: &RealmId,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), StorageError> {
        self.put(realm_id, key, value)
    }

    /// Deletes a row written by [`Self::put_node_local`]. Same contract.
    fn delete_node_local(&self, realm_id: &RealmId, key: &[u8]) -> Result<(), StorageError> {
        self.delete(realm_id, key)
    }

    /// Scans a range of keys for the given realm (half-open interval `[start, end)`).
    ///
    /// Returns entries sorted by key. Merges data across memtable and SST layers.
    fn scan(
        &self,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
    ) -> Result<Vec<ScanEntry>, StorageError>;

    /// Atomically writes a batch of `(key, value)` pairs for a single realm.
    ///
    /// All entries land durably or none do: a crash or I/O fault mid-way
    /// leaves either the empty pre-batch state or the fully-applied
    /// post-batch state. This is the primitive upper layers should use
    /// whenever two or more writes must be visible together after recovery
    /// (e.g., a primary record plus its secondary indexes).
    ///
    /// The default implementation falls back to sequential `put()` calls,
    /// which does NOT provide atomicity — implementers that care must
    /// override.
    fn put_batch(
        &self,
        realm_id: &RealmId,
        entries: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<(), StorageError> {
        for (key, value) in entries {
            self.put(realm_id, key, value)?;
        }
        Ok(())
    }

    /// Enqueue an atomic batch write without blocking for the WAL fsync.
    ///
    /// Returns a [`StorageDurabilityHandle`] that the caller must pass to
    /// [`await_batch_durable`] before treating the data as durable. This
    /// split allows callers to release any serialising lock (e.g. an audit
    /// chain lock) between the enqueue and the fsync wait, enabling concurrent
    /// writers to coalesce into a single group-commit `sync_all`.
    ///
    /// **Ordering guarantee**: entries pushed by the *same caller* via sequential
    /// `enqueue_batch` calls appear in the WAL in call order. Callers that need
    /// cross-writer ordering must hold an external serialising lock *across the
    /// enqueue call* (not across the fsync wait).
    ///
    /// The default implementation calls [`put_batch`] synchronously and returns
    /// an `Immediate` handle (correct for non-group-commit implementations).
    fn enqueue_batch(
        &self,
        realm_id: &RealmId,
        entries: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<StorageDurabilityHandle, StorageError> {
        self.put_batch(realm_id, entries)?;
        Ok(StorageDurabilityHandle(
            StorageDurabilityHandleKind::Immediate,
        ))
    }

    /// Block until the batch write represented by `handle` is durable.
    ///
    /// For `Immediate` handles (from the default impl or `SyncMode::None`),
    /// this is a no-op. For `Pending` handles, waits for the WAL group-commit
    /// `sync_all` that covers the batch.
    ///
    /// Returns the same error semantics as [`put_batch`]: `Ok(())` means the
    /// data is on disk and recoverable after a crash; `Err` means the write
    /// failed and the data must be considered lost.
    fn await_batch_durable(&self, _handle: StorageDurabilityHandle) -> Result<(), StorageError> {
        Ok(())
    }

    /// Inserts a key-value pair only if the key is currently absent.
    ///
    /// Returns `true` if the write was performed (key was absent), or `false`
    /// if the key already existed (write was skipped).
    ///
    /// In cluster mode this call is routed through Raft as a `PutIfAbsent`
    /// command via [`ClusterStorageAdapter`], making the check-and-write
    /// atomic across all nodes — there is no TOCTOU window between the
    /// existence check and the write.
    ///
    /// The default implementation falls back to a non-atomic `get` + `put`
    /// and is only correct for single-node usage where callers already hold
    /// an external advisory lock serialising concurrent access to the key.
    fn put_if_absent(
        &self,
        realm_id: &RealmId,
        key: &[u8],
        value: &[u8],
    ) -> Result<bool, StorageError> {
        if self.get(realm_id, key)?.is_some() {
            return Ok(false);
        }
        self.put(realm_id, key, value)?;
        Ok(true)
    }

    /// Atomically increments the little-endian `u64` counter stored at `key`
    /// and returns the new value. An absent key counts as `0`, so the first
    /// increment returns `1`.
    ///
    /// Concurrent increments never lose one another and the stored value never
    /// moves backwards: N increments move it by exactly N. A read-then-write by
    /// the caller cannot promise that — two callers that read the same value
    /// both write its successor, and a slow one can overwrite a faster one's
    /// higher value (the control-epoch regression this exists for).
    ///
    /// In cluster mode [`ClusterStorageAdapter`](crate::cluster::ClusterStorageAdapter)
    /// routes this through Raft as one command whose old + 1 is computed at
    /// apply time, so the increment is atomic across nodes, not only within
    /// one process.
    ///
    /// The default implementation serialises every increment in this process
    /// behind one lock around a `get` + `put`, which is atomic for any
    /// implementor whose storage this process alone writes. Implementors that
    /// can do better (a single-key lock, a replicated command) override it.
    ///
    /// # Errors
    ///
    /// Any error from the underlying read or write, or
    /// [`StorageError::DeserializationFailed`] when the stored value is not
    /// exactly eight bytes — a corrupted counter is reported, never reset, so
    /// it cannot silently restart below values already handed out. (In a
    /// cluster the Raft state machine instead repairs it to the incrementing
    /// entry's log index, which is above every value ever handed out.)
    fn increment_u64(&self, realm_id: &RealmId, key: &[u8]) -> Result<u64, StorageError> {
        static DEFAULT_INCREMENT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = DEFAULT_INCREMENT_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let next = decode_u64_counter(self.get(realm_id, key)?.as_deref())?.saturating_add(1);
        self.put(realm_id, key, &next.to_le_bytes())?;
        Ok(next)
    }

    /// Scans a range of keys returning only key bytes (no values).
    ///
    /// Semantics mirror [`scan`] but omit value materialisation. Use this when
    /// only the key list or count is needed — avoids allocating value bytes for
    /// every entry in large prefixes.
    ///
    /// The default implementation falls back to [`scan`] and discards values.
    /// [`EmbeddedStorageEngine`] overrides this with a true key-only merge that
    /// never allocates value bytes.
    fn scan_keys(
        &self,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
    ) -> Result<Vec<Vec<u8>>, StorageError> {
        let entries = self.scan(realm_id, start, end)?;
        Ok(entries.into_iter().map(|e| e.key).collect())
    }

    /// Visits, in key order, every live key in `[start, end)` for the given
    /// realm, one at a time, until the range ends or `visit` breaks.
    ///
    /// Unlike [`scan_keys`](Self::scan_keys), nothing is collected: a walk over
    /// a million keys holds one key at a time. `count_prefix` and
    /// `scan_prefix_paged` are built on it, so an admin list page costs memory
    /// for the page it serves, not for every record in the realm (#447).
    ///
    /// The default implementation collects the range with `scan_keys` and then
    /// visits it, so its memory still grows with the range.
    /// [`EmbeddedStorageEngine`] overrides it with a streaming merge of the
    /// memtable and the SSTs.
    fn visit_keys(
        &self,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
        visit: &mut dyn FnMut(&[u8]) -> std::ops::ControlFlow<()>,
    ) -> Result<(), StorageError> {
        paging::visit_collected_keys(self, realm_id, start, end, visit)
    }

    /// Visits, in key order, every live entry in `[start, end)` for the given
    /// realm, one at a time, until the range ends or `visit` breaks.
    ///
    /// The value form of [`visit_keys`](Self::visit_keys): nothing is
    /// collected, so a walk over a million rows holds one at a time. The
    /// periodic cleanup sweep reads every expiring row of a realm this way
    /// (#445). The walk reads each block once and does not put it in the
    /// shared block cache, where it would only evict the query path's working
    /// set.
    ///
    /// The default implementation collects the range with [`scan`](Self::scan)
    /// and then visits it, so its memory still grows with the range.
    /// [`EmbeddedStorageEngine`] overrides it with a streaming merge of the
    /// memtable and the SSTs.
    fn visit_entries(
        &self,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
        visit: &mut EntryVisitor<'_>,
    ) -> Result<(), StorageError> {
        for entry in self.scan(realm_id, start, end)? {
            if visit(&entry.key, &entry.value).is_break() {
                break;
            }
        }
        Ok(())
    }

    /// Counts entries whose key starts with `prefix` for the given realm.
    ///
    /// A `cap` of `0` means **no ceiling** — return the exact count. A non-zero
    /// `cap` truncates the reported count to `cap` (callers may then display
    /// e.g. "N+" to make the ceiling visible), and the walk stops there.
    ///
    /// Walks the keys with [`visit_keys`](Self::visit_keys) without keeping
    /// them or reading any value.
    fn count_prefix(
        &self,
        realm_id: &RealmId,
        prefix: &[u8],
        cap: u64,
    ) -> Result<u64, StorageError> {
        paging::count_prefix(self, realm_id, prefix, cap)
    }

    /// Scans a key prefix with offset-based pagination, returning the items
    /// window and the total count.
    ///
    /// Returns `(window, total)` where:
    /// - `window` — up to `limit` entries starting at zero-based `offset`.
    /// - `total` — count of all prefix entries. A `cap` of `0` means **no
    ///   ceiling** (report the exact total so admin UIs can page through the
    ///   whole result set); a non-zero `cap` truncates the reported total.
    ///
    /// The item window is always exact. Only the reported `total` is subject to
    /// `cap`.
    ///
    /// One [`visit_keys`](Self::visit_keys) walk counts the total and finds the
    /// window's bounds without keeping the other keys; a value scan then reads
    /// only the window. Memory follows `limit`, not the prefix (#447).
    fn scan_prefix_paged(
        &self,
        realm_id: &RealmId,
        prefix: &[u8],
        offset: u64,
        limit: u32,
        cap: u64,
    ) -> Result<(Vec<ScanEntry>, u64), StorageError> {
        paging::scan_prefix_paged(self, realm_id, prefix, offset, limit, cap)
    }

    /// Atomically writes a batch of puts and deletes for a single realm.
    ///
    /// All mutations (inserts/updates and removals) land durably together
    /// or none do. Use this when both puts and deletes must be crash-safe
    /// as a unit (e.g., invitation acceptance updates the record and removes
    /// the dedup sentinel).
    ///
    /// The default implementation falls back to sequential `put`/`delete`
    /// calls without atomicity — implementers that care must override.
    fn write_batch(
        &self,
        realm_id: &RealmId,
        puts: &[(Vec<u8>, Vec<u8>)],
        deletes: &[Vec<u8>],
    ) -> Result<(), StorageError> {
        for (key, value) in puts {
            self.put(realm_id, key, value)?;
        }
        for key in deletes {
            self.delete(realm_id, key)?;
        }
        Ok(())
    }

    /// Enumerates the distinct realm IDs present in this storage engine.
    ///
    /// Returns all realm IDs that have at least one entry (live or tombstoned)
    /// in any storage layer (memtable, SST files, etc.).  Used by the cluster
    /// snapshot install path to discover which realms must be cleared before
    /// replaying a new snapshot — without this, a restarted follower whose
    /// in-memory `known_realms` set is empty would skip Phase 1 entirely and
    /// leave stale on-disk data in place (HEA-2131).
    ///
    /// The cluster snapshot **build** path enumerates realms through this same
    /// call.  Build and install must agree on which realms exist: install
    /// clears every realm this call reports and then replays only the realms
    /// the payload carries, so a realm the build path omits is deleted from
    /// every follower (audit 2026-08-28 §4.9#3).
    ///
    /// Implementors that do not support multi-realm enumeration (e.g. test
    /// doubles) should return `Ok(vec![])` explicitly.  There is no silent
    /// default: a missing override that returns empty would silently skip the
    /// Phase 1 clear on the snapshot-install path (HEA-2133).
    fn list_realms(&self) -> Result<Vec<RealmId>, StorageError>;

    /// Write a durable "snapshot restore in progress" marker before the
    /// two-phase snapshot restore begins (HEA-2132).
    ///
    /// Called by the cluster snapshot install path immediately before Phase 1
    /// (delete all keys).  A process killed after this point but before
    /// [`complete_snapshot_restore`](Self::complete_snapshot_restore) leaves
    /// the marker on disk.  The engine detects the marker at next startup and
    /// returns [`StorageError::TornSnapshotRestore`] rather than silently
    /// serving mixed data from two different snapshot epochs.
    ///
    /// [`EmbeddedStorageEngine`] writes and `fsync`s the marker file and its
    /// parent directory.  Wrappers must delegate to their inner engine.
    /// Test doubles that have no persistent marker should return `Ok(())`
    /// explicitly — there is no silent default: a missing override would
    /// silently skip crash detection on the snapshot-install path (HEA-2135).
    fn begin_snapshot_restore(&self, snapshot_id: &str) -> Result<(), StorageError>;

    /// Remove the "snapshot restore in progress" marker after Phase 2 completes
    /// successfully (HEA-2132).
    ///
    /// Called after all snapshot data has been replayed.  Removing the marker
    /// signals that the restore finished cleanly — the engine will start
    /// normally on the next open.
    ///
    /// [`EmbeddedStorageEngine`] unlinks the marker and `fsync`s the parent
    /// directory.  Wrappers must delegate to their inner engine.  Test doubles
    /// that have no persistent marker should return `Ok(())` explicitly —
    /// there is no silent default (HEA-2135).
    fn complete_snapshot_restore(&self) -> Result<(), StorageError>;

    /// Returns the process-wide backup-consistency barrier, or `None` if this
    /// engine does not support consistent snapshots (HEA-2167).
    ///
    /// A backup export acquires the returned lock in **write** mode and holds
    /// it across its per-entity read pass. While held, every mutating
    /// operation (`put`, `delete`, `put_batch`, `write_batch`,
    /// `enqueue_batch`, `await_batch_durable`) blocks, so the export observes a
    /// single point-in-time view and cannot capture a *torn* archive — e.g. a
    /// group membership referencing a user the archive omits. Reads
    /// (`get`/`scan`) are never blocked, so the hot path and the export's own
    /// scans proceed freely.
    ///
    /// **Write-availability impact**: while an export holds the barrier, writes
    /// to this node block until the export's read pass completes. Operators
    /// scheduling backups against a live server must account for this window.
    ///
    /// The default returns `None` (no barrier) — correct for test doubles and
    /// wrappers that do not provide snapshot isolation; callers that receive
    /// `None` fall back to a non-isolated export. [`EmbeddedStorageEngine`]
    /// overrides this with a real reader-writer barrier.
    fn backup_barrier(&self) -> Option<std::sync::Arc<std::sync::RwLock<()>>> {
        None
    }

    /// Writes the in-memory write buffer out to a durable file.
    ///
    /// Called on the graceful-shutdown path. Durability does **not** depend on
    /// it: every acknowledged write is in the WAL before it is acknowledged,
    /// and recovery replays the WAL on the next open. Flushing on shutdown
    /// shortens that replay and leaves the data directory in a state a file
    /// copy can read without one (audit 2026-08-28 §3 B4, §4.11#1).
    ///
    /// The default is a no-op — correct for test doubles and for wrappers with
    /// no buffer of their own. [`EmbeddedStorageEngine`] overrides it.
    ///
    /// # Errors
    ///
    /// Reports whether the write-ahead log has fenced writes after a write
    /// fault (audit 2026-08-28 §4.11#8).
    ///
    /// A fenced engine refuses every write for the life of the process, while
    /// reads keep working. `/readyz` reads this so a fenced node stops
    /// receiving traffic it cannot accept; restart it to clear the fence.
    ///
    /// The default returns `false`, which is correct for engines with no WAL.
    fn is_write_fenced(&self) -> bool {
        false
    }

    /// Returns any error from writing the SST.
    fn flush_memtable(&self) -> Result<(), StorageError> {
        Ok(())
    }
}
