//! In-memory sorted key-value store for recent writes.
//!
//! The memtable accepts writes and provides lock-free reads. It is backed by a
//! `crossbeam_skiplist::SkipMap` — a lock-free, ordered, concurrent map — held
//! behind an `ArcSwap` so a flush can atomically reset the map to empty. When it
//! reaches its configured size threshold, it signals readiness for flushing to
//! an SST (Step 5).
//!
//! ## Why a skiplist, not a copy-on-write `Arc<BTreeMap>` (HEA-1897)
//!
//! The original design cloned the *entire* backing `BTreeMap` on every `put`
//! (`current.clone()` → mutate → `ArcSwap::store`). That made each write O(N) in
//! the number of resident entries: at the 64 MiB default flush threshold, ~160k
//! entries were reallocated on every single put, and because two full copies are
//! live at once (and `arc_swap` defers freeing the old one) the glibc arena
//! high-water grew and RSS never returned it. HEA-1867's record-size trace
//! attributed ~22 of the observed 24 KB/user resident cost to exactly this
//! clone, and the C0 seed ladder's rising ms/user (2.63 → 7.76) is its
//! write-throughput signature.
//!
//! `SkipMap` inserts in O(log N) with no whole-map copy, so per-put cost is
//! independent of occupancy. It preserves the storage hot-path contract
//! (CLAUDE.md): **reads take no lock** (`SkipMap::get`/`range` are lock-free,
//! epoch-reclaimed) and **do not yield**. Writes still hold a `Mutex` — not to
//! protect the map (the skiplist is internally concurrent) but to keep the
//! read-old-size / insert / size-delta sequence atomic against other writers and
//! to give [`flush_streaming`](Memtable::flush_streaming) a barrier so its
//! atomic swap-to-empty can never drop a concurrent put. Writes are off the hot
//! path, so serializing them is acceptable; the defect was the O(N) clone under
//! that lock, not the lock itself.
//!
//! ## Streaming flush without a full copy (HEA-1908)
//!
//! [`flush_streaming`](Memtable::flush_streaming) holds the write lock only for
//! an O(1) swap: it parks the full map in an immutable `flushing` slot and
//! installs a fresh empty active map, then streams the parked map to the SST
//! **outside** the lock. Two wins over the previous "materialise a `Vec` copy and
//! `write_sst` under the lock" shape: no ~64 MiB duplicate of the memtable is
//! live during a flush, and concurrent writers are not blocked for the SST
//! encrypt+`fsync`. Reads consult the active map first, then the `flushing` slot,
//! so a key mid-flush is always visible from one or the other; on SST-write
//! failure the parked map is folded back into the active map so no acknowledged
//! write is dropped (the HEA-1897 no-loss property).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use arc_swap::{ArcSwap, ArcSwapOption};
use crossbeam_skiplist::SkipMap;

use crate::core::RealmId;
use crate::storage::error::StorageError;
use crate::storage::wal::{WalEntry, WalOperation};

/// Composite key combining realm identity with a data key.
///
/// Ordered by realm UUID bytes first, then by key bytes (lexicographic).
/// This ensures realm-scoped ordering and makes cross-realm reads
/// structurally impossible without providing a different `RealmId`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct CompositeKey {
    /// The realm that owns this key.
    realm_id: RealmId,
    /// The raw key bytes.
    key: Vec<u8>,
}

impl CompositeKey {
    /// Creates a new composite key from a realm ID and raw key bytes.
    pub(crate) fn new(realm_id: RealmId, key: Vec<u8>) -> Self {
        Self { realm_id, key }
    }

    /// Returns a reference to the realm ID.
    pub(crate) fn realm_id(&self) -> &RealmId {
        &self.realm_id
    }

    /// Returns a reference to the raw key bytes.
    pub(crate) fn key(&self) -> &[u8] {
        &self.key
    }
}

/// Value stored in the memtable, supporting tombstone markers for deletes.
///
/// Tombstones are preserved until SST flush and compaction (Step 5+).
/// The `get()` method returns `None` for both absent keys and tombstones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MemtableValue {
    /// A live key-value entry.
    Data(Vec<u8>),
    /// A deletion marker.
    Tombstone,
}

/// Configuration for the memtable.
#[derive(Debug, Clone)]
pub(crate) struct MemtableConfig {
    /// Byte threshold at which the memtable signals readiness for flush.
    pub flush_threshold_bytes: usize,
}

impl Default for MemtableConfig {
    fn default() -> Self {
        Self {
            flush_threshold_bytes: 4 * 1024 * 1024, // 4 MiB
        }
    }
}

/// In-memory sorted key-value store with lock-free reads.
///
/// Backed by a lock-free `SkipMap` so writes insert in O(log N) with no
/// whole-map copy (HEA-1897); the map lives behind an `ArcSwap` purely so a
/// flush can atomically replace it with a fresh empty map. A `Mutex` serializes
/// writers (see the module docs) — reads never take it.
pub(crate) struct Memtable {
    /// The sorted key-value data. The skiplist itself is concurrently mutable;
    /// the `ArcSwap` wrapper exists only so [`flush_streaming`](Self::flush_streaming)
    /// and [`clear`](Self::clear) can atomically swap in an empty map.
    data: ArcSwap<SkipMap<CompositeKey, MemtableValue>>,
    /// The immutable map currently being streamed to an SST, if a flush is in
    /// progress (`None` otherwise). Parked here by [`flush_streaming`](Self::flush_streaming)
    /// so its keys stay readable while the SST is written *outside* the write
    /// lock. Only ever one at a time — the engine's flush lock serializes flushes.
    flushing: ArcSwapOption<SkipMap<CompositeKey, MemtableValue>>,
    /// Serializes write operations (put, delete, clear) so size accounting and
    /// the flush swap-to-empty are race-free. Reads never acquire it.
    write_lock: Mutex<()>,
    /// Approximate total byte size of all entries in the **active** map. The
    /// map parked in `flushing` is excluded — it is on its way to an SST and
    /// must not keep re-triggering the size-based flush.
    approximate_size: AtomicUsize,
    /// Configuration (flush threshold).
    config: MemtableConfig,
}

impl Memtable {
    /// Creates a new empty memtable with the given configuration.
    pub(crate) fn new(config: MemtableConfig) -> Self {
        Self {
            data: ArcSwap::from_pointee(SkipMap::new()),
            flushing: ArcSwapOption::empty(),
            write_lock: Mutex::new(()),
            approximate_size: AtomicUsize::new(0),
            config,
        }
    }

    /// Inserts or updates a key-value pair for the given realm.
    ///
    /// If the key already exists, its value is overwritten. Size tracking
    /// is updated to reflect the delta.
    pub(crate) fn put(
        &self,
        realm_id: &RealmId,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), StorageError> {
        let composite = CompositeKey {
            realm_id: realm_id.clone(),
            key: key.to_vec(),
        };
        let new_value = MemtableValue::Data(value.to_vec());

        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| StorageError::Io(std::io::Error::other("memtable mutex poisoned")))?;

        let map = self.data.load();

        let new_entry_size = Self::entry_size(key, &new_value);
        let old_entry_size = map
            .get(&composite)
            .map_or(0, |old| Self::entry_size(key, old.value()));

        map.insert(composite, new_value);

        self.update_size(old_entry_size, new_entry_size);

        Ok(())
    }

    /// Inserts or updates many key-value pairs under a single write-lock hold.
    ///
    /// Equivalent to calling [`put`](Self::put) once per entry — same final map
    /// contents and same `approximate_size` — but acquires the write lock once
    /// for the whole batch instead of once per entry. Each individual insert is
    /// O(log N) into the lock-free skiplist (HEA-1897), so a bulk insert of `B`
    /// entries is O(B · log N) with no whole-map copy, which is essential for
    /// large bulk loads (e.g. the demo seeder writing millions of rows).
    pub(crate) fn put_batch(
        &self,
        realm_id: &RealmId,
        entries: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<(), StorageError> {
        if entries.is_empty() {
            return Ok(());
        }

        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| StorageError::Io(std::io::Error::other("memtable mutex poisoned")))?;

        let map = self.data.load();

        let mut old_total: usize = 0;
        let mut new_total: usize = 0;
        for (key, value) in entries {
            let composite = CompositeKey {
                realm_id: realm_id.clone(),
                key: key.clone(),
            };
            let new_value = MemtableValue::Data(value.clone());

            new_total += Self::entry_size(key, &new_value);
            old_total += map
                .get(&composite)
                .map_or(0, |old| Self::entry_size(key, old.value()));

            map.insert(composite, new_value);
        }

        self.update_size(old_total, new_total);

        Ok(())
    }

    /// Flushes the memtable to an SST by **streaming** its backing map, holding
    /// the write lock only for an O(1) swap rather than across the SST write.
    ///
    /// Two phases:
    ///
    /// 1. **Under the write lock (O(1)):** park the current map in the `flushing`
    ///    slot, install a fresh empty active map, and reset the active size to
    ///    zero. Writers block only for this swap — microseconds — not for the SST
    ///    encrypt+`fsync` below.
    /// 2. **Outside the write lock:** run the caller-supplied `write_sst`, which
    ///    receives the parked map and streams it to the SST (and registers it).
    ///    Concurrent `put`/`put_batch` proceed against the fresh active map.
    ///
    /// **No-loss property (HEA-1897, pinned by
    /// `concurrent_writes_during_flush_are_not_lost`):** a write racing the flush
    /// either lands in the parked map before the swap — captured in the SST — or
    /// in the fresh active map after it. It is never dropped. And because reads
    /// consult the active map *then* the `flushing` slot, a key is always visible
    /// from one or the other while the SST is being written.
    ///
    /// If `write_sst` returns `Err`, the parked map is folded back into the
    /// active map (active wins on any key re-written during the flush window), so
    /// no acknowledged write is dropped on a failed flush. Returns `Ok(false)`
    /// when the memtable was empty (nothing flushed).
    ///
    /// `write_sst` receives the map sorted by composite key: iterate it with
    /// `.iter()` (entries are yielded in key order) and size it with `.len()`.
    pub(crate) fn flush_streaming<F>(&self, write_sst: F) -> Result<bool, StorageError>
    where
        F: FnOnce(&SkipMap<CompositeKey, MemtableValue>) -> Result<(), StorageError>,
    {
        // Phase 1 — O(1) swap under the write lock.
        let parked = {
            let _guard = self
                .write_lock
                .lock()
                .map_err(|_| StorageError::Io(std::io::Error::other("memtable mutex poisoned")))?;

            let current = self.data.load_full();
            if current.is_empty() {
                return Ok(false);
            }

            // Install a fresh empty active map and park the old one so reads keep
            // seeing its keys while the SST is written.
            self.data.store(Arc::new(SkipMap::new()));
            self.approximate_size.store(0, Ordering::Relaxed);
            self.flushing.store(Some(Arc::clone(&current)));
            current
        };

        // Phase 2 — stream the parked map to the SST *without* the write lock.
        match write_sst(&parked) {
            Ok(()) => {
                // Persisted + registered by the closure; drop the parked copy.
                self.flushing.store(None);
                Ok(true)
            }
            Err(e) => {
                // Persist failed: fold the parked entries back so nothing is
                // dropped, then clear the flushing slot.
                self.reabsorb(&parked)?;
                self.flushing.store(None);
                Err(e)
            }
        }
    }

    /// Folds a parked (failed-flush) map back into the active map under the write
    /// lock, inserting only keys the active map does not already hold — a write
    /// that raced the flush is newer and must win — and restoring their size.
    fn reabsorb(&self, parked: &SkipMap<CompositeKey, MemtableValue>) -> Result<(), StorageError> {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| StorageError::Io(std::io::Error::other("memtable mutex poisoned")))?;

        let active = self.data.load();
        let mut restored: usize = 0;
        for entry in parked.iter() {
            if active.get(entry.key()).is_none() {
                restored += Self::entry_size(entry.key().key(), entry.value());
                active.insert(entry.key().clone(), entry.value().clone());
            }
        }
        self.approximate_size.fetch_add(restored, Ordering::Relaxed);
        Ok(())
    }

    /// Inserts a tombstone for the given key, marking it as deleted.
    ///
    /// Subsequent `get()` calls return `None`. The tombstone is preserved
    /// for SST flush so downstream compaction can remove the key.
    pub(crate) fn delete(&self, realm_id: &RealmId, key: &[u8]) -> Result<(), StorageError> {
        let composite = CompositeKey {
            realm_id: realm_id.clone(),
            key: key.to_vec(),
        };
        let new_value = MemtableValue::Tombstone;

        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| StorageError::Io(std::io::Error::other("memtable mutex poisoned")))?;

        let map = self.data.load();

        let new_entry_size = Self::entry_size(key, &new_value);
        let old_entry_size = map
            .get(&composite)
            .map_or(0, |old| Self::entry_size(key, old.value()));

        map.insert(composite, new_value);

        self.update_size(old_entry_size, new_entry_size);

        Ok(())
    }

    /// Retrieves a value by realm and key. Returns `None` for both
    /// absent keys and tombstones. This is a lock-free read.
    pub(crate) fn get(&self, realm_id: &RealmId, key: &[u8]) -> Option<Vec<u8>> {
        match self.get_entry(realm_id, key) {
            Some(MemtableValue::Data(v)) => Some(v),
            Some(MemtableValue::Tombstone) | None => None,
        }
    }

    /// Looks up the raw memtable entry for a key via the backing `SkipMap`.
    ///
    /// Returns `Some(Data)`, `Some(Tombstone)`, or `None` (absent). Unlike
    /// [`get`](Self::get) this distinguishes a tombstone from an absent key, so
    /// the storage engine can stop searching deeper layers on a delete without
    /// materialising the realm's entries. O(log n) lock-free read.
    ///
    /// Consults the active map first, then the map parked for flushing (if a
    /// flush is in progress): the active map holds any newer write for the key,
    /// and the parked map holds a value still on its way to an SST (HEA-1908).
    pub(crate) fn get_entry(&self, realm_id: &RealmId, key: &[u8]) -> Option<MemtableValue> {
        let composite = CompositeKey {
            realm_id: realm_id.clone(),
            key: key.to_vec(),
        };
        if let Some(v) = self.data.load().get(&composite).map(|e| e.value().clone()) {
            return Some(v);
        }
        // Fall back to the map being streamed to an SST, if any.
        self.flushing
            .load()
            .as_ref()
            .and_then(|parked| parked.get(&composite).map(|e| e.value().clone()))
    }

    /// Returns whether the memtable has reached its flush threshold.
    pub(crate) fn should_flush(&self) -> bool {
        self.approximate_size.load(Ordering::Relaxed) >= self.config.flush_threshold_bytes
    }

    /// Returns the approximate byte size of all entries in the memtable.
    pub(crate) fn approximate_size(&self) -> usize {
        self.approximate_size.load(Ordering::Relaxed)
    }

    /// Returns all entries for a given realm, sorted by key.
    ///
    /// Includes tombstones. The returned keys are the raw data keys
    /// (without the realm prefix).
    pub(crate) fn iter_realm(&self, realm_id: &RealmId) -> Vec<(Vec<u8>, MemtableValue)> {
        let active = self.data.load();
        let flushing = self.flushing.load();
        let Some(parked) = flushing.as_ref() else {
            // Common case — no flush in progress: scan the active map directly,
            // no merge allocation.
            return Self::scan_realm(&active, realm_id);
        };
        // A flush is in progress: merge the parked (older) map under the active
        // (newer) one, active winning on any re-written key.
        let mut merged: BTreeMap<Vec<u8>, MemtableValue> = BTreeMap::new();
        for (k, v) in Self::scan_realm(parked, realm_id) {
            merged.insert(k, v);
        }
        for (k, v) in Self::scan_realm(&active, realm_id) {
            merged.insert(k, v);
        }
        merged.into_iter().collect()
    }

    /// Realm-scoped full scan of a single backing map, sorted by key.
    fn scan_realm(
        map: &SkipMap<CompositeKey, MemtableValue>,
        realm_id: &RealmId,
    ) -> Vec<(Vec<u8>, MemtableValue)> {
        let start = CompositeKey {
            realm_id: realm_id.clone(),
            key: vec![],
        };
        map.range(start..)
            .take_while(|entry| entry.key().realm_id == *realm_id)
            .map(|entry| (entry.key().key.clone(), entry.value().clone()))
            .collect()
    }

    /// Key-only range scan within a realm — returns `(key, is_alive)` pairs
    /// without cloning value bytes.
    ///
    /// Used by the key-only scan path to avoid allocating value bytes for
    /// count/total queries on large prefixes.
    pub(crate) fn iter_realm_range_keys(
        &self,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
    ) -> Vec<(Vec<u8>, bool)> {
        let active = self.data.load();
        let flushing = self.flushing.load();
        let Some(parked) = flushing.as_ref() else {
            // Common case — no flush in progress: scan the active map directly.
            return Self::scan_realm_range_keys(&active, realm_id, start, end);
        };
        // A flush is in progress: merge parked (older) under active (newer).
        let mut merged: BTreeMap<Vec<u8>, bool> = BTreeMap::new();
        for (k, alive) in Self::scan_realm_range_keys(parked, realm_id, start, end) {
            merged.insert(k, alive);
        }
        for (k, alive) in Self::scan_realm_range_keys(&active, realm_id, start, end) {
            merged.insert(k, alive);
        }
        merged.into_iter().collect()
    }

    /// Realm-scoped key-only range scan of a single backing map — `(key, alive)`
    /// pairs for `start <= key < end`, sorted by key.
    fn scan_realm_range_keys(
        map: &SkipMap<CompositeKey, MemtableValue>,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
    ) -> Vec<(Vec<u8>, bool)> {
        let start_key = CompositeKey {
            realm_id: realm_id.clone(),
            key: start.to_vec(),
        };
        map.range(start_key..)
            .take_while(|entry| {
                entry.key().realm_id == *realm_id && entry.key().key.as_slice() < end
            })
            .map(|entry| {
                (
                    entry.key().key.clone(),
                    matches!(entry.value(), MemtableValue::Data(_)),
                )
            })
            .collect()
    }

    /// Returns all entries across all realms, sorted by composite key.
    ///
    /// Used for flushing to SST files. Includes tombstones.
    pub(crate) fn iter_all(&self) -> Vec<(CompositeKey, MemtableValue)> {
        let active = self.data.load();
        let flushing = self.flushing.load();
        let Some(parked) = flushing.as_ref() else {
            return active
                .iter()
                .map(|entry| (entry.key().clone(), entry.value().clone()))
                .collect();
        };
        // Merge parked (older) under active (newer), active winning per key.
        let mut merged: BTreeMap<CompositeKey, MemtableValue> = BTreeMap::new();
        for entry in parked.iter() {
            merged.insert(entry.key().clone(), entry.value().clone());
        }
        for entry in active.iter() {
            merged.insert(entry.key().clone(), entry.value().clone());
        }
        merged.into_iter().collect()
    }

    /// Applies a WAL entry to the memtable (for crash recovery replay).
    pub(crate) fn apply_wal_entry(&self, entry: &WalEntry) -> Result<(), StorageError> {
        match entry.operation {
            WalOperation::Put => self.put(&entry.realm_id, &entry.key, &entry.value),
            WalOperation::Delete => self.delete(&entry.realm_id, &entry.key),
            WalOperation::Batch => {
                // The outer record's CRC already guarantees atomicity — a
                // corrupt or truncated batch is dropped by the reader before
                // reaching here. If decoding still fails, treat it as a
                // malformed record and stop replay rather than applying a
                // partial batch.
                let sub_entries = crate::storage::wal::decode_batch_payload(&entry.value)?;
                // Apply runs of consecutive puts via `put_batch` (one map clone
                // per run) instead of one clone per entry, so replaying a large
                // WAL segment of bulk writes stays O(N) rather than O(N²). A
                // delete flushes the pending put-run first to preserve the
                // encoded order, then applies as a tombstone.
                let mut put_run: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
                for sub in &sub_entries {
                    match sub.operation {
                        WalOperation::Put => {
                            put_run.push((sub.key.clone(), sub.value.clone()));
                        }
                        WalOperation::Delete => {
                            if !put_run.is_empty() {
                                self.put_batch(&entry.realm_id, &put_run)?;
                                put_run.clear();
                            }
                            self.delete(&entry.realm_id, &sub.key)?;
                        }
                        WalOperation::Batch => {
                            return Err(StorageError::DeserializationFailed {
                                reason: "nested batch in WAL replay".to_string(),
                            });
                        }
                    }
                }
                if !put_run.is_empty() {
                    self.put_batch(&entry.realm_id, &put_run)?;
                }
                Ok(())
            }
        }
    }

    /// Clears all data and resets size tracking. Used after flushing to SST.
    pub(crate) fn clear(&self) -> Result<(), StorageError> {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| StorageError::Io(std::io::Error::other("memtable mutex poisoned")))?;

        self.data.store(Arc::new(SkipMap::new()));
        self.flushing.store(None);
        self.approximate_size.store(0, Ordering::Relaxed);

        Ok(())
    }

    /// Estimates the byte size of a single entry.
    ///
    /// Accounts for 16 bytes of UUID, key length, and value length.
    fn entry_size(key: &[u8], value: &MemtableValue) -> usize {
        16 + key.len()
            + match value {
                MemtableValue::Data(v) => v.len(),
                MemtableValue::Tombstone => 0,
            }
    }

    /// Updates the approximate size atomically given old and new entry sizes.
    fn update_size(&self, old_size: usize, new_size: usize) {
        if new_size >= old_size {
            self.approximate_size
                .fetch_add(new_size - old_size, Ordering::Relaxed);
        } else {
            self.approximate_size
                .fetch_sub(old_size - new_size, Ordering::Relaxed);
        }
    }
}

impl std::fmt::Debug for Memtable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Memtable")
            .field(
                "approximate_size",
                &self.approximate_size.load(Ordering::Relaxed),
            )
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{RealmId, Timestamp};
    use std::collections::{HashMap, HashSet};
    use std::sync::atomic::AtomicBool;

    // ===== Phase A: P0 Fast Unit Tests =====
    // TEST_SCENARIOS.md: "Insert and retrieve key-value pairs (single and multiple)"

    #[test]
    fn insert_and_retrieve_single_key() {
        let mt = Memtable::new(MemtableConfig::default());
        let realm = RealmId::generate();

        mt.put(&realm, b"key1", b"value1").expect("put");

        assert_eq!(mt.get(&realm, b"key1"), Some(b"value1".to_vec()));
    }

    #[test]
    fn insert_and_retrieve_multiple_keys() {
        let mt = Memtable::new(MemtableConfig::default());
        let realm = RealmId::generate();

        mt.put(&realm, b"key1", b"val1").expect("put 1");
        mt.put(&realm, b"key2", b"val2").expect("put 2");
        mt.put(&realm, b"key3", b"val3").expect("put 3");

        assert_eq!(mt.get(&realm, b"key1"), Some(b"val1".to_vec()));
        assert_eq!(mt.get(&realm, b"key2"), Some(b"val2".to_vec()));
        assert_eq!(mt.get(&realm, b"key3"), Some(b"val3".to_vec()));
    }

    #[test]
    fn get_nonexistent_key_returns_none() {
        let mt = Memtable::new(MemtableConfig::default());
        let realm = RealmId::generate();

        assert_eq!(mt.get(&realm, b"missing"), None);
    }

    // `get_entry` powers the storage engine's O(log n) point lookup: it must
    // distinguish a live value, a tombstone, and an absent key so the engine
    // can stop descending into SSTs on a delete without an O(N) realm scan
    // (HEA-1614 user-detail slowness).
    #[test]
    fn get_entry_distinguishes_data_tombstone_and_absent() {
        let mt = Memtable::new(MemtableConfig::default());
        let realm = RealmId::generate();

        mt.put(&realm, b"live", b"v").expect("put");
        mt.delete(&realm, b"dead").expect("delete");

        assert!(
            matches!(mt.get_entry(&realm, b"live"), Some(MemtableValue::Data(v)) if v == b"v"),
            "live key returns Data"
        );
        assert!(
            matches!(
                mt.get_entry(&realm, b"dead"),
                Some(MemtableValue::Tombstone)
            ),
            "deleted key returns Tombstone, not None"
        );
        assert!(
            mt.get_entry(&realm, b"absent").is_none(),
            "absent key returns None"
        );
    }

    // `put_batch` must be observationally identical to N sequential `put`s:
    // same final values AND same approximate_size. This is the invariant that
    // lets the storage engine batch the memtable update for bulk loads
    // (clone-once-per-batch instead of clone-per-entry) without changing
    // semantics. Includes an overwrite so the old-size accounting is exercised.
    #[test]
    fn put_batch_matches_sequential_puts() {
        let realm = RealmId::generate();
        let entries: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (b"key1".to_vec(), b"value-one".to_vec()),
            (b"key2".to_vec(), b"v2".to_vec()),
            (b"key3".to_vec(), b"value-three-longer".to_vec()),
            // Overwrite of key1 within the same batch — last write wins, and the
            // first key1's size must not leak into approximate_size.
            (b"key1".to_vec(), b"value-one-updated".to_vec()),
        ];

        // Reference: apply sequentially via `put`.
        let seq = Memtable::new(MemtableConfig::default());
        for (k, v) in &entries {
            seq.put(&realm, k, v).expect("put");
        }

        // Subject: apply as one batch.
        let batch = Memtable::new(MemtableConfig::default());
        batch.put_batch(&realm, &entries).expect("put_batch");

        for key in [b"key1".as_slice(), b"key2".as_slice(), b"key3".as_slice()] {
            assert_eq!(
                batch.get(&realm, key),
                seq.get(&realm, key),
                "batch and sequential disagree on {key:?}"
            );
        }
        assert_eq!(
            batch.get(&realm, b"key1"),
            Some(b"value-one-updated".to_vec())
        );
        assert_eq!(
            batch.approximate_size(),
            seq.approximate_size(),
            "put_batch must track the same approximate_size as sequential puts"
        );
    }

    #[test]
    fn put_batch_empty_is_noop() {
        let mt = Memtable::new(MemtableConfig::default());
        let realm = RealmId::generate();
        mt.put_batch(&realm, &[]).expect("empty put_batch");
        assert_eq!(mt.approximate_size(), 0);
    }

    // `flush_streaming` hands the closure the full parked map, then empties the
    // active map once the closure succeeds. (Concurrency — that a write racing
    // the flush is never lost — is covered by an integration test.)
    #[test]
    fn flush_streaming_snapshots_then_empties() {
        let mt = Memtable::new(MemtableConfig::default());
        let realm = RealmId::generate();
        mt.put(&realm, b"k1", b"v1").expect("put 1");
        mt.put(&realm, b"k2", b"v2").expect("put 2");

        let mut captured: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        let flushed = mt
            .flush_streaming(|map| {
                for entry in map.iter() {
                    if let MemtableValue::Data(bytes) = entry.value() {
                        captured.push((entry.key().key().to_vec(), bytes.clone()));
                    }
                }
                Ok(())
            })
            .expect("flush");

        assert!(flushed, "non-empty memtable must report a flush");
        assert_eq!(captured.len(), 2, "closure must see the full parked map");
        assert!(
            mt.iter_all().is_empty(),
            "memtable must be empty after a successful flush"
        );
        assert_eq!(mt.approximate_size(), 0);
    }

    #[test]
    fn flush_streaming_empty_is_noop() {
        let mt = Memtable::new(MemtableConfig::default());
        let mut called = false;
        let flushed = mt
            .flush_streaming(|_| {
                called = true;
                Ok(())
            })
            .expect("flush");
        assert!(!flushed, "empty memtable reports no flush");
        assert!(!called, "closure must not run for an empty memtable");
    }

    // A key parked for flushing MUST stay readable while the SST is being
    // written — reads fall through the active map to the parked map. This is
    // what closes the read gap the streaming flush would otherwise open between
    // emptying the active map and registering the SST (HEA-1908).
    #[test]
    fn flush_streaming_parked_keys_readable_mid_flush() {
        let mt = Memtable::new(MemtableConfig::default());
        let realm = RealmId::generate();
        mt.put(&realm, b"parked", b"old").expect("put");

        let flushed = mt
            .flush_streaming(|map| {
                // Inside the closure the active map is already empty, but the
                // parked key must resolve from the flushing slot.
                assert_eq!(
                    mt.get(&realm, b"parked"),
                    Some(b"old".to_vec()),
                    "parked key must be readable during the flush"
                );
                assert!(matches!(
                    mt.get_entry(&realm, b"parked"),
                    Some(MemtableValue::Data(_))
                ));
                // And a concurrent write to the fresh active map must win over
                // the parked value when the same key is re-written.
                mt.put(&realm, b"parked", b"new").expect("racing put");
                assert_eq!(mt.get(&realm, b"parked"), Some(b"new".to_vec()));
                // The parked map is untouched (still holds the old value).
                assert_eq!(map.len(), 1);
                Ok(())
            })
            .expect("flush");

        assert!(flushed);
        // After the flush the racing write survives and the flushing slot is gone.
        assert_eq!(mt.get(&realm, b"parked"), Some(b"new".to_vec()));
    }

    #[test]
    fn flush_streaming_preserves_data_on_error() {
        let mt = Memtable::new(MemtableConfig::default());
        let realm = RealmId::generate();
        mt.put(&realm, b"k1", b"v1").expect("put");
        mt.put(&realm, b"k2", b"v2").expect("put");
        let before = mt.approximate_size();

        let res = mt.flush_streaming(|_| {
            Err(StorageError::Io(std::io::Error::other(
                "simulated SST failure",
            )))
        });

        assert!(res.is_err(), "flush must surface the SST write error");
        // Critical: a failed flush must NOT drop the data — it is folded back
        // into the active map, and the size accounting is restored exactly.
        assert_eq!(mt.get(&realm, b"k1"), Some(b"v1".to_vec()));
        assert_eq!(mt.get(&realm, b"k2"), Some(b"v2".to_vec()));
        assert_eq!(mt.approximate_size(), before);
        // The flushing slot must be cleared so a subsequent flush is clean.
        assert!(mt.flushing.load().is_none());
    }

    // On a failed flush, a key re-written to the fresh active map during the
    // flush window MUST win over the parked (older) copy the reabsorb folds
    // back — reabsorb inserts only keys the active map does not already hold.
    #[test]
    fn flush_streaming_error_reabsorb_active_wins() {
        let mt = Memtable::new(MemtableConfig::default());
        let realm = RealmId::generate();
        mt.put(&realm, b"shared", b"old").expect("put");

        let res = mt.flush_streaming(|_| {
            // Racing write of the same key to the fresh active map, then fail.
            mt.put(&realm, b"shared", b"new").expect("racing put");
            Err(StorageError::Io(std::io::Error::other("boom")))
        });

        assert!(res.is_err());
        // The newer active value must survive the reabsorb, not be clobbered by
        // the parked "old".
        assert_eq!(mt.get(&realm, b"shared"), Some(b"new".to_vec()));
        assert!(mt.flushing.load().is_none());
    }

    // DoD (HEA-1908): writers MUST NOT be blocked for the full SST write. The
    // streaming flush holds the write lock only for the O(1) swap, then runs the
    // SST write outside it — so a concurrent `put` completes promptly even while
    // a slow "SST write" is in flight.
    #[test]
    fn flush_streaming_does_not_block_writers_for_sst_write() {
        use std::sync::mpsc;
        use std::time::{Duration, Instant};

        let mt = Arc::new(Memtable::new(MemtableConfig::default()));
        let realm = RealmId::generate();
        mt.put(&realm, b"flushme", b"v").expect("put");

        let (started_tx, started_rx) = mpsc::channel::<()>();
        let flush_dur = Duration::from_millis(400);

        let mt_flush = Arc::clone(&mt);
        let handle = std::thread::spawn(move || {
            mt_flush
                .flush_streaming(|_map| {
                    // Signal that we are inside the SST write, then simulate a
                    // slow encrypt+fsync while NOT holding the write lock.
                    started_tx.send(()).expect("signal");
                    std::thread::sleep(flush_dur);
                    Ok(())
                })
                .expect("flush");
        });

        // Wait until the flush is inside its slow "SST write".
        started_rx.recv().expect("flush started");

        // A concurrent writer must complete well before the slow flush finishes.
        let start = Instant::now();
        mt.put(&realm, b"concurrent", b"w").expect("concurrent put");
        let elapsed = start.elapsed();
        assert!(
            elapsed < flush_dur / 2,
            "writer blocked for {elapsed:?} during a {flush_dur:?} flush — the SST \
             write must not hold the write lock"
        );

        handle.join().expect("flush thread");
        // The concurrent write (to the fresh active map) survives the flush. The
        // parked "flushme" was handed to the no-op closure and not persisted here
        // — engine-level durability is covered by
        // `concurrent_writes_during_flush_are_not_lost`.
        assert_eq!(mt.get(&realm, b"concurrent"), Some(b"w".to_vec()));
    }

    // TEST_SCENARIOS.md: "Update existing key overwrites value"

    #[test]
    fn update_overwrites_value() {
        let mt = Memtable::new(MemtableConfig::default());
        let realm = RealmId::generate();

        mt.put(&realm, b"key1", b"original").expect("put 1");
        assert_eq!(mt.get(&realm, b"key1"), Some(b"original".to_vec()));

        mt.put(&realm, b"key1", b"updated").expect("put 2");
        assert_eq!(mt.get(&realm, b"key1"), Some(b"updated".to_vec()));
    }

    // TEST_SCENARIOS.md: "Delete key removes entry; subsequent lookup returns None"

    #[test]
    fn delete_key_returns_none_on_lookup() {
        let mt = Memtable::new(MemtableConfig::default());
        let realm = RealmId::generate();

        mt.put(&realm, b"key1", b"value1").expect("put");
        assert_eq!(mt.get(&realm, b"key1"), Some(b"value1".to_vec()));

        mt.delete(&realm, b"key1").expect("delete");
        assert_eq!(mt.get(&realm, b"key1"), None);
    }

    #[test]
    fn delete_nonexistent_key_succeeds() {
        let mt = Memtable::new(MemtableConfig::default());
        let realm = RealmId::generate();

        mt.delete(&realm, b"missing").expect("delete");
        assert_eq!(mt.get(&realm, b"missing"), None);
    }

    #[test]
    fn delete_inserts_tombstone_visible_in_iterator() {
        let mt = Memtable::new(MemtableConfig::default());
        let realm = RealmId::generate();

        mt.put(&realm, b"key1", b"value1").expect("put");
        mt.delete(&realm, b"key1").expect("delete");

        let entries = mt.iter_realm(&realm);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], (b"key1".to_vec(), MemtableValue::Tombstone));
    }

    // TEST_SCENARIOS.md: "Flush threshold triggers when memtable reaches configured byte size"

    #[test]
    fn flush_threshold_triggers_at_configured_size() {
        let config = MemtableConfig {
            flush_threshold_bytes: 100,
        };
        let mt = Memtable::new(config);
        let realm = RealmId::generate();

        assert!(!mt.should_flush());
        assert_eq!(mt.approximate_size(), 0);

        // Each entry: 16 (UUID) + key.len() + value.len()
        // First put: 16 + 4 + 32 = 52
        mt.put(&realm, b"key1", &[0u8; 32]).expect("put 1");
        assert!(!mt.should_flush());

        // Second put: 16 + 4 + 32 = 52, total ~104 > 100
        mt.put(&realm, b"key2", &[0u8; 32]).expect("put 2");
        assert!(mt.should_flush());
    }

    #[test]
    fn size_tracking_accounts_for_updates() {
        let mt = Memtable::new(MemtableConfig::default());
        let realm = RealmId::generate();

        mt.put(&realm, b"key1", &[0u8; 100]).expect("put large");
        let size_after_large = mt.approximate_size();

        // Overwrite with smaller value — size should decrease
        mt.put(&realm, b"key1", &[0u8; 10]).expect("put small");
        let size_after_small = mt.approximate_size();

        assert!(
            size_after_small < size_after_large,
            "size should decrease on smaller update: {size_after_small} vs {size_after_large}"
        );
    }

    // TEST_SCENARIOS.md: "Iterator returns entries in sorted key order"

    #[test]
    fn iterator_returns_sorted_key_order() {
        let mt = Memtable::new(MemtableConfig::default());
        let realm = RealmId::generate();

        // Insert in non-sorted order
        mt.put(&realm, b"charlie", b"3").expect("put");
        mt.put(&realm, b"alpha", b"1").expect("put");
        mt.put(&realm, b"delta", b"4").expect("put");
        mt.put(&realm, b"bravo", b"2").expect("put");

        let entries = mt.iter_realm(&realm);
        let keys: Vec<&[u8]> = entries.iter().map(|(k, _)| k.as_slice()).collect();
        assert_eq!(
            keys,
            vec![
                b"alpha".as_slice(),
                b"bravo".as_slice(),
                b"charlie".as_slice(),
                b"delta".as_slice(),
            ]
        );
    }

    // ===== Supplementary Unit Tests (architecture requirements) =====

    #[test]
    fn realm_isolation_no_cross_realm_reads() {
        let mt = Memtable::new(MemtableConfig::default());
        let realm_a = RealmId::generate();
        let realm_b = RealmId::generate();

        mt.put(&realm_a, b"shared_key", b"value-a").expect("put a");
        mt.put(&realm_b, b"shared_key", b"value-b").expect("put b");
        mt.put(&realm_a, b"only-a", b"exclusive").expect("put a2");

        // Each realm sees only their own data
        assert_eq!(mt.get(&realm_a, b"shared_key"), Some(b"value-a".to_vec()));
        assert_eq!(mt.get(&realm_b, b"shared_key"), Some(b"value-b".to_vec()));
        assert_eq!(mt.get(&realm_b, b"only-a"), None);

        // Realm iterators are scoped
        let entries_a = mt.iter_realm(&realm_a);
        assert_eq!(entries_a.len(), 2);
        let entries_b = mt.iter_realm(&realm_b);
        assert_eq!(entries_b.len(), 1);
    }

    #[test]
    fn apply_wal_entry_put_and_delete() {
        let mt = Memtable::new(MemtableConfig::default());
        let realm = RealmId::generate();

        let put_entry = WalEntry {
            timestamp: Timestamp::from_micros(1_000_000),
            realm_id: realm.clone(),
            operation: WalOperation::Put,
            key: b"key1".to_vec(),
            value: b"value1".to_vec(),
        };
        mt.apply_wal_entry(&put_entry).expect("apply put");
        assert_eq!(mt.get(&realm, b"key1"), Some(b"value1".to_vec()));

        let delete_entry = WalEntry {
            timestamp: Timestamp::from_micros(2_000_000),
            realm_id: realm.clone(),
            operation: WalOperation::Delete,
            key: b"key1".to_vec(),
            value: vec![],
        };
        mt.apply_wal_entry(&delete_entry).expect("apply delete");
        assert_eq!(mt.get(&realm, b"key1"), None);
    }

    #[test]
    fn clear_resets_data_and_size() {
        let mt = Memtable::new(MemtableConfig::default());
        let realm = RealmId::generate();

        mt.put(&realm, b"key1", b"value1").expect("put 1");
        mt.put(&realm, b"key2", b"value2").expect("put 2");
        assert!(mt.approximate_size() > 0);

        mt.clear().expect("clear");

        assert_eq!(mt.get(&realm, b"key1"), None);
        assert_eq!(mt.get(&realm, b"key2"), None);
        assert_eq!(mt.approximate_size(), 0);
        assert!(mt.iter_realm(&realm).is_empty());
        assert!(mt.iter_all().is_empty());
    }

    #[test]
    fn iter_all_returns_entries_across_realms() {
        let mt = Memtable::new(MemtableConfig::default());
        let realm_a = RealmId::generate();
        let realm_b = RealmId::generate();

        mt.put(&realm_a, b"a1", b"va1").expect("put");
        mt.put(&realm_b, b"b1", b"vb1").expect("put");

        let all = mt.iter_all();
        assert_eq!(all.len(), 2);

        // All entries should be sorted by CompositeKey
        assert!(all[0].0 < all[1].0, "iter_all should return sorted entries");
    }

    #[test]
    fn memtable_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Memtable>();
    }

    // ===== HEA-1897: put cost must not scale with memtable occupancy =====

    /// Averages the wall-clock cost of a batch of `probe` distinct-key puts made
    /// into a memtable already holding `prefill` distinct entries. The prefill
    /// puts are **not** timed — only the probe batch is measured — so the return
    /// value isolates the marginal cost of one put at the given occupancy.
    fn avg_put_nanos(realm: &RealmId, prefill: u32, probe: u32) -> f64 {
        use std::time::Instant;
        let mt = Memtable::new(MemtableConfig {
            // Large threshold so no flush fires mid-measurement and skews it.
            flush_threshold_bytes: usize::MAX,
        });
        // Untimed prefill to establish occupancy.
        let value = [0u8; 256];
        for i in 0..prefill {
            mt.put(realm, &i.to_be_bytes(), &value)
                .expect("prefill put");
        }
        // Timed probe: fresh keys above the prefill range so every put is an
        // insert (not an overwrite), matching the create-user write pattern.
        let start = Instant::now();
        for i in prefill..(prefill + probe) {
            mt.put(realm, &i.to_be_bytes(), &value).expect("probe put");
        }
        let elapsed = start.elapsed();
        #[allow(clippy::cast_precision_loss)]
        let nanos = elapsed.as_nanos() as f64 / f64::from(probe);
        nanos
    }

    /// TEST_SCENARIOS / HEA-1897: the marginal cost of a `put` MUST be
    /// (approximately) independent of how many entries the memtable already
    /// holds. The old copy-on-write `Arc<BTreeMap>` cloned the entire map on
    /// every put, making per-put cost O(N) — an 8× larger memtable made each put
    /// ~8× more expensive. A structure with sub-linear inserts holds the ratio
    /// near constant. We assert the 8×-occupancy batch stays within 4× of the
    /// baseline batch, which the O(N) clone cannot satisfy but O(log N) inserts
    /// comfortably do (a generous bound chosen to avoid timing flakiness).
    #[test]
    fn put_cost_does_not_scale_with_occupancy() {
        let realm = RealmId::generate();
        const PROBE: u32 = 2_000;
        const LOW_OCCUPANCY: u32 = 2_000;
        const HIGH_OCCUPANCY: u32 = 16_000; // 8× the low mark

        // Warm up allocator/caches so the first measured batch isn't penalised.
        let _ = avg_put_nanos(&realm, 256, 256);

        let low = avg_put_nanos(&realm, LOW_OCCUPANCY, PROBE);
        let high = avg_put_nanos(&realm, HIGH_OCCUPANCY, PROBE);

        assert!(
            high < low * 4.0,
            "put cost scales with occupancy: {high:.0} ns/put at {HIGH_OCCUPANCY} entries \
             vs {low:.0} ns/put at {LOW_OCCUPANCY} entries (ratio {:.1}×, expected < 4×). \
             This indicates an O(N)-per-put copy of the backing map.",
            high / low
        );
    }

    // ===== Phase B: P0 Extended Property Tests =====

    use proptest::prelude::*;

    #[derive(Debug, Clone)]
    enum TestOp {
        Put(Vec<u8>, Vec<u8>),
        Delete(Vec<u8>),
    }

    fn arb_test_op() -> impl Strategy<Value = TestOp> {
        prop_oneof![
            (
                prop::collection::vec(any::<u8>(), 1..32),
                prop::collection::vec(any::<u8>(), 0..64),
            )
                .prop_map(|(k, v)| TestOp::Put(k, v)),
            prop::collection::vec(any::<u8>(), 1..32).prop_map(TestOp::Delete),
        ]
    }

    proptest! {
        /// TEST_SCENARIOS.md: "Random insert/update/delete sequences maintain correct key set"
        #[test]
        fn proptest_random_ops_maintain_correct_key_set(
            ops in prop::collection::vec(arb_test_op(), 1..200)
        ) {
            let mt = Memtable::new(MemtableConfig::default());
            let realm = RealmId::generate();
            let mut oracle: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();

            for op in &ops {
                match op {
                    TestOp::Put(key, value) => {
                        mt.put(&realm, key, value).expect("put");
                        oracle.insert(key.clone(), value.clone());
                    }
                    TestOp::Delete(key) => {
                        mt.delete(&realm, key).expect("delete");
                        oracle.remove(key);
                    }
                }
            }

            // Verify all oracle entries exist in memtable
            for (key, expected) in &oracle {
                let actual = mt.get(&realm, key);
                prop_assert_eq!(
                    actual.as_deref(),
                    Some(expected.as_slice()),
                    "key {:?} mismatch",
                    key
                );
            }

            // Verify memtable has no extra live entries
            let entries = mt.iter_realm(&realm);
            let live_entries: Vec<_> = entries
                .into_iter()
                .filter(|(_, v)| matches!(v, MemtableValue::Data(_)))
                .collect();
            let memtable_keys: HashSet<Vec<u8>> =
                live_entries.iter().map(|(k, _)| k.clone()).collect();
            let oracle_keys: HashSet<Vec<u8>> = oracle.keys().cloned().collect();
            prop_assert_eq!(memtable_keys, oracle_keys);
        }
    }

    /// `TEST_SCENARIOS.md`: "Concurrent reads during writes see consistent snapshots"
    ///
    /// A start [`Barrier`](std::sync::Barrier) rendezvouses all four readers with
    /// the writer before the first put, and each reader takes its snapshot
    /// *before* re-checking `done`. Both are load-bearing: since HEA-1897 replaced
    /// the O(N)-per-put clone with a skiplist insert, the writer can retire all
    /// 1000 puts and set `done` before a reader thread is ever scheduled, which
    /// made the `iterations > 0` liveness assert fail intermittently. Gating on
    /// the barrier (readers are running before any write lands) plus the
    /// do-while shape guarantees the overlap the test claims to exercise instead
    /// of leaving it to the scheduler.
    #[test]
    fn concurrent_reads_during_writes_see_consistent_snapshots() {
        const READERS: usize = 4;

        let mt = Arc::new(Memtable::new(MemtableConfig::default()));
        let realm = RealmId::generate();
        let done = Arc::new(AtomicBool::new(false));
        // READERS + the writer.
        let start = Arc::new(std::sync::Barrier::new(READERS + 1));

        std::thread::scope(|s| {
            // Writer: inserts keys 0..1000
            let mt_w = &mt;
            let t_w = &realm;
            let done_w = &done;
            let start_w = &start;
            s.spawn(move || {
                start_w.wait();
                for i in 0u32..1000 {
                    mt_w.put(t_w, &i.to_be_bytes(), &i.to_be_bytes())
                        .expect("put");
                }
                done_w.store(true, Ordering::Release);
            });

            // Readers: continuously snapshot and verify sorted order
            for _ in 0..READERS {
                let mt_r = &mt;
                let t_r = &realm;
                let done_r = &done;
                let start_r = &start;
                s.spawn(move || {
                    start_r.wait();
                    let mut iterations = 0u64;
                    // Do-while: always take at least one snapshot, however fast
                    // the writer retires its puts.
                    loop {
                        let entries = mt_r.iter_realm(t_r);
                        // Every snapshot must be sorted
                        for window in entries.windows(2) {
                            assert!(
                                window[0].0 <= window[1].0,
                                "snapshot not sorted at iteration {iterations}"
                            );
                        }
                        iterations += 1;
                        if done_r.load(Ordering::Acquire) {
                            break;
                        }
                    }
                    // Ensure readers actually ran
                    assert!(iterations > 0, "reader thread never ran");
                });
            }
        });

        // Final consistency check: all 1000 keys should be present
        for i in 0u32..1000 {
            assert_eq!(
                mt.get(&realm, &i.to_be_bytes()),
                Some(i.to_be_bytes().to_vec()),
                "key {i} missing after concurrent writes"
            );
        }
    }
}
