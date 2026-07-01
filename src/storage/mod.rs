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
pub(crate) mod breach_corpus;
pub mod encryption;
mod engine;
pub mod error;
pub mod fs;
#[allow(dead_code)]
pub(crate) mod key_registry;
#[allow(dead_code)]
pub(crate) mod memtable;
pub mod migrations;
#[allow(dead_code)]
pub(crate) mod sst;
#[allow(dead_code)]
mod tiered;
pub mod wal;

pub use engine::{CompactionConfig, EmbeddedStorageEngine, StorageConfig};
pub use error::StorageError;
pub use fs::{Fs, FsFile, RealFs};

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

/// Trait defining the public storage engine interface.
///
/// Synchronous for Phase 0 — callers should use `spawn_blocking` for async
/// contexts. All operations require a `RealmId` for multi-realm isolation.
pub trait StorageEngine: Send + Sync {
    /// Retrieves a value by realm and key. Returns `None` if not found.
    fn get(&self, realm_id: &RealmId, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError>;

    /// Inserts or updates a key-value pair for the given realm.
    fn put(&self, realm_id: &RealmId, key: &[u8], value: &[u8]) -> Result<(), StorageError>;

    /// Deletes a key for the given realm.
    fn delete(&self, realm_id: &RealmId, key: &[u8]) -> Result<(), StorageError>;

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

    /// Counts entries whose key starts with `prefix` for the given realm.
    ///
    /// A `cap` of `0` means **no ceiling** — return the exact count. A non-zero
    /// `cap` truncates the reported count to `cap` (callers may then display
    /// e.g. "N+" to make the ceiling visible). The full prefix scan runs
    /// regardless; the cap only bounds the reported number.
    ///
    /// Uses a key-only scan to avoid materialising value bytes.
    fn count_prefix(
        &self,
        realm_id: &RealmId,
        prefix: &[u8],
        cap: u64,
    ) -> Result<u64, StorageError> {
        if prefix.is_empty() {
            return Ok(0);
        }
        let end = prefix_scan_end(prefix);
        let keys = self.scan_keys(realm_id, prefix, &end)?;
        let n = keys.len() as u64;
        Ok(if cap == 0 { n } else { n.min(cap) })
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
    /// Two-phase implementation: key-only scan for the total (no value bytes
    /// allocated for out-of-window entries), then a bounded value scan covering
    /// only the `limit` window entries.
    fn scan_prefix_paged(
        &self,
        realm_id: &RealmId,
        prefix: &[u8],
        offset: u64,
        limit: u32,
        cap: u64,
    ) -> Result<(Vec<ScanEntry>, u64), StorageError> {
        if prefix.is_empty() {
            return Ok((vec![], 0));
        }
        let prefix_end = prefix_scan_end(prefix);

        // Phase 1: key-only scan for total (no value bytes allocated).
        let all_keys = self.scan_keys(realm_id, prefix, &prefix_end)?;
        let n = all_keys.len() as u64;
        let total = if cap == 0 { n } else { n.min(cap) };

        // Phase 2: bounded value scan for the window only.
        let start_idx = (offset as usize).min(all_keys.len());
        let end_idx = (start_idx + limit as usize).min(all_keys.len());

        if start_idx >= end_idx {
            return Ok((vec![], total));
        }

        // Bound the scan to exactly the window keys. `win_end` is either the
        // key immediately after the window (exclusive) or the prefix sentinel.
        let win_start = &all_keys[start_idx];
        let win_end: Vec<u8> = if end_idx < all_keys.len() {
            all_keys[end_idx].clone()
        } else {
            prefix_end
        };

        // This scan processes only O(limit) entries instead of O(N).
        let window = self.scan(realm_id, win_start, &win_end)?;
        Ok((window, total))
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
}
