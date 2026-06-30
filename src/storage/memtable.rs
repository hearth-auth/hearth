//! In-memory sorted key-value store for recent writes.
//!
//! The memtable accepts writes and provides lock-free reads via `ArcSwap`.
//! When it reaches its configured size threshold, it signals readiness for
//! flushing to an SST (Step 5). Writes are serialized behind a `Mutex`;
//! reads are wait-free through `ArcSwap::load()`.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;

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
/// Uses `ArcSwap<BTreeMap>` for wait-free read access and a `Mutex`
/// to serialize writes (clone-mutate-swap pattern). Writes are off the
/// hot path, so the allocation from cloning is acceptable.
pub(crate) struct Memtable {
    /// The sorted key-value data, swapped atomically on writes.
    data: ArcSwap<BTreeMap<CompositeKey, MemtableValue>>,
    /// Serializes write operations (put, delete, clear).
    write_lock: Mutex<()>,
    /// Approximate total byte size of all entries.
    approximate_size: AtomicUsize,
    /// Configuration (flush threshold).
    config: MemtableConfig,
}

impl Memtable {
    /// Creates a new empty memtable with the given configuration.
    pub(crate) fn new(config: MemtableConfig) -> Self {
        Self {
            data: ArcSwap::from_pointee(BTreeMap::new()),
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

        let current = self.data.load_full();
        let mut new_map = (*current).clone();

        let new_entry_size = Self::entry_size(key, &new_value);
        let old_entry_size = new_map
            .get(&composite)
            .map_or(0, |old_val| Self::entry_size(key, old_val));

        new_map.insert(composite, new_value);
        self.data.store(Arc::new(new_map));

        self.update_size(old_entry_size, new_entry_size);

        Ok(())
    }

    /// Inserts or updates many key-value pairs in a single copy-on-write cycle.
    ///
    /// Equivalent to calling [`put`](Self::put) once per entry — same final map
    /// contents and same `approximate_size` — but clones the backing `BTreeMap`
    /// **once** for the whole batch instead of once per entry. This turns a bulk
    /// insert of `B` entries from O(B · N) into O(N + B), which is essential for
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

        let current = self.data.load_full();
        let mut new_map = (*current).clone();

        let mut old_total: usize = 0;
        let mut new_total: usize = 0;
        for (key, value) in entries {
            let composite = CompositeKey {
                realm_id: realm_id.clone(),
                key: key.clone(),
            };
            let new_value = MemtableValue::Data(value.clone());

            new_total += Self::entry_size(key, &new_value);
            old_total += new_map
                .get(&composite)
                .map_or(0, |old_val| Self::entry_size(key, old_val));

            new_map.insert(composite, new_value);
        }

        self.data.store(Arc::new(new_map));
        self.update_size(old_total, new_total);

        Ok(())
    }

    /// Atomically flushes the memtable to an SST and resets it to empty.
    ///
    /// Holds the write lock for the **entire** operation — snapshot, the
    /// caller-supplied `write_sst` (which writes and registers the SST), and the
    /// reset to empty all happen in one critical section. This is what makes a
    /// flush safe against concurrent writers: a `put`/`put_batch` racing with a
    /// flush either completes *before* the snapshot (and is captured in the SST)
    /// or *after* the reset (and stays in the fresh map) — it can never land in a
    /// window where it is wiped without being persisted (the bug in the old
    /// lock-free `iter_all()` + later `clear()` pair).
    ///
    /// Reads are unaffected: they never take the write lock, and `write_sst`
    /// registers the new SST *before* this method empties the in-memory map, so
    /// a just-flushed key is always readable from one tier or the other.
    ///
    /// `write_sst` receives the entries sorted by composite key. If it returns
    /// `Err`, the memtable is left untouched (no data is dropped). Returns
    /// `Ok(false)` when the memtable was empty (nothing flushed).
    pub(crate) fn flush_under_lock<F>(&self, write_sst: F) -> Result<bool, StorageError>
    where
        F: FnOnce(&[(CompositeKey, MemtableValue)]) -> Result<(), StorageError>,
    {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| StorageError::Io(std::io::Error::other("memtable mutex poisoned")))?;

        let current = self.data.load_full();
        if current.is_empty() {
            return Ok(false);
        }

        let entries: Vec<(CompositeKey, MemtableValue)> = current
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        // Persist + register the SST while still holding the write lock. On
        // failure we return without resetting, so nothing is lost.
        write_sst(&entries)?;

        self.data.store(Arc::new(BTreeMap::new()));
        self.approximate_size.store(0, Ordering::Relaxed);

        Ok(true)
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

        let current = self.data.load_full();
        let mut new_map = (*current).clone();

        let new_entry_size = Self::entry_size(key, &new_value);
        let old_entry_size = new_map
            .get(&composite)
            .map_or(0, |old_val| Self::entry_size(key, old_val));

        new_map.insert(composite, new_value);
        self.data.store(Arc::new(new_map));

        self.update_size(old_entry_size, new_entry_size);

        Ok(())
    }

    /// Retrieves a value by realm and key. Returns `None` for both
    /// absent keys and tombstones. This is a lock-free read.
    pub(crate) fn get(&self, realm_id: &RealmId, key: &[u8]) -> Option<Vec<u8>> {
        let composite = CompositeKey {
            realm_id: realm_id.clone(),
            key: key.to_vec(),
        };
        let snapshot = self.data.load();
        match snapshot.get(&composite) {
            Some(MemtableValue::Data(v)) => Some(v.clone()),
            Some(MemtableValue::Tombstone) | None => None,
        }
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
        let snapshot = self.data.load();
        let start = CompositeKey {
            realm_id: realm_id.clone(),
            key: vec![],
        };
        snapshot
            .range(start..)
            .take_while(|(k, _)| k.realm_id == *realm_id)
            .map(|(k, v)| (k.key.clone(), v.clone()))
            .collect()
    }

    /// Returns all entries across all realms, sorted by composite key.
    ///
    /// Used for flushing to SST files. Includes tombstones.
    pub(crate) fn iter_all(&self) -> Vec<(CompositeKey, MemtableValue)> {
        let snapshot = self.data.load();
        snapshot
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
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

        self.data.store(Arc::new(BTreeMap::new()));
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

    // `flush_under_lock` hands the closure the full snapshot, then empties the
    // memtable only after the closure succeeds. (Concurrency — that a write
    // racing the flush is never lost — is covered by an integration test, since
    // a same-thread write inside the closure would deadlock on the write lock.)
    #[test]
    fn flush_under_lock_snapshots_then_empties() {
        let mt = Memtable::new(MemtableConfig::default());
        let realm = RealmId::generate();
        mt.put(&realm, b"k1", b"v1").expect("put 1");
        mt.put(&realm, b"k2", b"v2").expect("put 2");

        let mut captured: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        let flushed = mt
            .flush_under_lock(|entries| {
                for (k, v) in entries {
                    if let MemtableValue::Data(bytes) = v {
                        captured.push((k.key().to_vec(), bytes.clone()));
                    }
                }
                Ok(())
            })
            .expect("flush");

        assert!(flushed, "non-empty memtable must report a flush");
        assert_eq!(captured.len(), 2, "closure must see the full snapshot");
        assert!(
            mt.iter_all().is_empty(),
            "memtable must be empty after flush"
        );
        assert_eq!(mt.approximate_size(), 0);
    }

    #[test]
    fn flush_under_lock_empty_is_noop() {
        let mt = Memtable::new(MemtableConfig::default());
        let mut called = false;
        let flushed = mt
            .flush_under_lock(|_| {
                called = true;
                Ok(())
            })
            .expect("flush");
        assert!(!flushed, "empty memtable reports no flush");
        assert!(!called, "closure must not run for an empty memtable");
    }

    #[test]
    fn flush_under_lock_preserves_data_on_error() {
        let mt = Memtable::new(MemtableConfig::default());
        let realm = RealmId::generate();
        mt.put(&realm, b"k1", b"v1").expect("put");
        let before = mt.approximate_size();

        let res = mt.flush_under_lock(|_| {
            Err(StorageError::Io(std::io::Error::other(
                "simulated SST failure",
            )))
        });

        assert!(res.is_err(), "flush must surface the SST write error");
        // Critical: a failed flush must NOT drop the data.
        assert_eq!(mt.get(&realm, b"k1"), Some(b"v1".to_vec()));
        assert_eq!(mt.approximate_size(), before);
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
    #[test]
    fn concurrent_reads_during_writes_see_consistent_snapshots() {
        let mt = Arc::new(Memtable::new(MemtableConfig::default()));
        let realm = RealmId::generate();
        let done = Arc::new(AtomicBool::new(false));

        std::thread::scope(|s| {
            // Writer: inserts keys 0..1000
            let mt_w = &mt;
            let t_w = &realm;
            let done_w = &done;
            s.spawn(move || {
                for i in 0u32..1000 {
                    mt_w.put(t_w, &i.to_be_bytes(), &i.to_be_bytes())
                        .expect("put");
                }
                done_w.store(true, Ordering::Release);
            });

            // Readers: continuously snapshot and verify sorted order
            for _ in 0..4 {
                let mt_r = &mt;
                let t_r = &realm;
                let done_r = &done;
                s.spawn(move || {
                    let mut iterations = 0u64;
                    while !done_r.load(Ordering::Acquire) {
                        let entries = mt_r.iter_realm(t_r);
                        // Every snapshot must be sorted
                        for window in entries.windows(2) {
                            assert!(
                                window[0].0 <= window[1].0,
                                "snapshot not sorted at iteration {iterations}"
                            );
                        }
                        iterations += 1;
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
