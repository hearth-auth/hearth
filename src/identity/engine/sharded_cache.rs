//! Sharded, lock-free concurrent cache used by the identity-engine hot path.
//!
//! Wraps a fixed array of [`EpochCell`]-backed `HashMap` shards. Reads take a
//! single epoch-pinned `load()` on the shard selected by the key's hash — no
//! lock, no syscall, and no allocation beyond the epoch collector's amortised
//! bookkeeping (see [`EpochCell::load`]) — preserving the O(1) hot-path read
//! the revocation and signing-key caches depend on.
//!
//! The win over a single cell holding the whole map (HEA-1772, C-3) is on the
//! write path: an insert or remove `rcu()`s only the one shard the key maps to,
//! so a write clones roughly `1/N` of the entries instead of the entire map.
//! This collapses the previous `O(m)` per-insert full-map clone — which churned
//! badly under revocation storms and many-realm workloads — to `O(m/N)` while
//! leaving the read path byte-for-byte equivalent.
//!
//! The shards were `ArcSwap` until task 26.5; `arc-swap` 1.9.2 corrupts the
//! heap under exactly this `load` + `rcu` pattern (see
//! `https://github.com/hearth-auth/hearth/blob/4d9dda1f5b514891e90dadeffb03d1a026af4e51/reports/arc-swap-use-after-free-2026-09-21.md`).

use std::borrow::Borrow;
use std::collections::HashMap;
use std::hash::{BuildHasher, Hash};
use std::sync::Arc;

use crate::core::EpochCell;

/// Number of independent shards.
///
/// A power of two so the shard index is a cheap mask of the key hash. 64 keeps
/// per-shard clone cost at ~`1/64` of the map while the fixed per-shard
/// overhead (64 empty `Arc<HashMap>` pointers) stays negligible.
const SHARD_COUNT: usize = 64;

/// A concurrent map partitioned into [`SHARD_COUNT`] `EpochCell<HashMap>`
/// shards.
///
/// Reads are lock-free; writes clone only the affected shard. Intended for
/// hot-path projections (JTI revocation, DPoP blocklist, per-realm signing
/// keys) where reads dominate and writes must not clone the full map.
pub(crate) struct ShardedEpochMap<K, V> {
    shards: Box<[EpochCell<HashMap<K, V>>]>,
    /// Fixed per-instance hasher used *only* for shard selection. Kept separate
    /// from each shard's internal `RandomState` so a key always resolves to the
    /// same shard for the life of the map.
    hasher: std::collections::hash_map::RandomState,
}

impl<K, V> ShardedEpochMap<K, V>
where
    K: Hash + Eq + Clone,
    V: Clone,
{
    /// Creates an empty sharded map.
    pub(crate) fn new() -> Self {
        let shards = (0..SHARD_COUNT)
            .map(|_| EpochCell::from_pointee(HashMap::new()))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            shards,
            hasher: std::collections::hash_map::RandomState::new(),
        }
    }

    #[inline]
    fn shard_index<Q>(&self, key: &Q) -> usize
    where
        Q: Hash + ?Sized,
    {
        // SHARD_COUNT is a power of two, so the mask is exact.
        (self.hasher.hash_one(key) as usize) & (SHARD_COUNT - 1)
    }

    #[inline]
    fn shard<Q>(&self, key: &Q) -> &EpochCell<HashMap<K, V>>
    where
        Q: Hash + ?Sized,
    {
        &self.shards[self.shard_index(key)]
    }

    /// Lock-free membership test. A single epoch-pinned `load()` on the key's
    /// shard — no lock, no syscall, and what `EpochCell::load` allocates:
    /// nothing but the collector's amortised bookkeeping.
    #[inline]
    pub(crate) fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.shard(key).load().contains_key(key)
    }

    /// Lock-free lookup returning a clone of the value. A single epoch-pinned
    /// `load()`; for `V = Arc<_>` the clone is just a reference-count bump.
    #[inline]
    pub(crate) fn get<Q>(&self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.shard(key).load().get(key).cloned()
    }

    /// Inserts `(key, value)`, cloning only the target shard.
    pub(crate) fn insert(&self, key: K, value: V) {
        self.shard(&key).rcu(|old| {
            let mut next = HashMap::clone(old);
            next.insert(key.clone(), value.clone());
            next
        });
    }

    /// Inserts `(key, value)` into its shard while dropping any existing entry
    /// for which `retain` returns `false`.
    ///
    /// Used by the JTI revocation cache to evict expired entries as a side
    /// effect of each write. Because only the target shard is swept, eviction
    /// is lazy per shard rather than global — harmless, since an expired token
    /// is rejected by the `exp` claim check before the cache is consulted.
    pub(crate) fn insert_retaining<F>(&self, key: K, value: V, mut retain: F)
    where
        F: FnMut(&K, &V) -> bool,
    {
        self.shard(&key).rcu(|old| {
            let mut next: HashMap<K, V> = old
                .iter()
                .filter(|(k, v)| retain(k, v))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            next.insert(key.clone(), value.clone());
            next
        });
    }

    /// Removes `key` from its shard, cloning only that shard.
    pub(crate) fn remove<Q>(&self, key: &Q)
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.shard(key).rcu(|old| {
            let mut next = HashMap::clone(old);
            next.remove(key);
            next
        });
    }

    /// Distributes `entries` into per-shard maps without publishing them.
    ///
    /// Together with [`Self::prepared_insert`], [`Self::prepared_remove`] and
    /// [`Self::install`] this splits a rebuild into an expensive part that
    /// needs no coordination (hashing every entry into its shard) and a cheap
    /// part a caller can run under a lock that orders it against concurrent
    /// writers: replaying their changes and swapping one pointer per shard.
    pub(crate) fn prepare<I>(&self, entries: I) -> PreparedShards<K, V>
    where
        I: IntoIterator<Item = (K, V)>,
    {
        let mut buckets: Vec<HashMap<K, V>> = (0..SHARD_COUNT).map(|_| HashMap::new()).collect();
        for (k, v) in entries {
            let idx = self.shard_index(&k);
            buckets[idx].insert(k, v);
        }
        PreparedShards { buckets }
    }

    /// Inserts into a [`PreparedShards`] built by this map.
    pub(crate) fn prepared_insert(&self, prepared: &mut PreparedShards<K, V>, key: K, value: V) {
        let idx = self.shard_index(&key);
        prepared.buckets[idx].insert(key, value);
    }

    /// Removes from a [`PreparedShards`] built by this map.
    pub(crate) fn prepared_remove<Q>(&self, prepared: &mut PreparedShards<K, V>, key: &Q)
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let idx = self.shard_index(key);
        prepared.buckets[idx].remove(key);
    }

    /// Publishes a [`PreparedShards`], one pointer store per shard.
    pub(crate) fn install(&self, prepared: PreparedShards<K, V>) {
        for (shard, bucket) in self.shards.iter().zip(prepared.buckets) {
            shard.store(Arc::new(bucket));
        }
    }
}

/// Shard contents built by [`ShardedEpochMap::prepare`] and not yet published.
pub(crate) struct PreparedShards<K, V> {
    buckets: Vec<HashMap<K, V>>,
}

impl<K, V> Default for ShardedEpochMap<K, V>
where
    K: Hash + Eq + Clone,
    V: Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Captures the current `Arc` pointer of every shard so a later snapshot can
    /// prove which shards a mutation actually cloned.
    fn shard_ptrs<K, V>(map: &ShardedEpochMap<K, V>) -> Vec<*const HashMap<K, V>> {
        map.shards
            .iter()
            .map(|s| Arc::as_ptr(&s.load_full()))
            .collect()
    }

    #[test]
    fn insert_clones_only_one_shard() {
        // Regression for HEA-1772 C-3: an insert must NOT clone the full map.
        // We prove it by showing every shard except the one the key hashes to
        // keeps its exact same backing `Arc` after the write.
        let map: ShardedEpochMap<String, i64> = ShardedEpochMap::new();
        for i in 0..1_000 {
            map.insert(format!("seed:{i}"), i);
        }

        let before = shard_ptrs(&map);
        map.insert("new-key".to_string(), 42);
        let after = shard_ptrs(&map);

        let changed = before.iter().zip(&after).filter(|(a, b)| a != b).count();
        assert_eq!(
            changed, 1,
            "exactly one shard should be re-published per insert; \
             a full-map clone would touch every shard"
        );
        assert_eq!(map.get("new-key"), Some(42));
    }

    #[test]
    fn remove_clones_only_one_shard() {
        let map: ShardedEpochMap<String, i64> = ShardedEpochMap::new();
        for i in 0..1_000 {
            map.insert(format!("seed:{i}"), i);
        }
        assert!(map.contains_key("seed:500"));

        let before = shard_ptrs(&map);
        map.remove("seed:500");
        let after = shard_ptrs(&map);

        let changed = before.iter().zip(&after).filter(|(a, b)| a != b).count();
        assert_eq!(changed, 1, "remove must not clone the full map");
        assert!(!map.contains_key("seed:500"));
    }

    #[test]
    fn read_path_reflects_writes() {
        let map: ShardedEpochMap<String, i64> = ShardedEpochMap::new();
        assert!(!map.contains_key("absent"));
        assert_eq!(map.get("absent"), None);

        map.insert("a".to_string(), 1);
        map.insert("b".to_string(), 2);
        assert!(map.contains_key("a"));
        assert_eq!(map.get("b"), Some(2));

        map.remove("a");
        assert!(!map.contains_key("a"));
        assert!(map.contains_key("b"));
    }

    #[test]
    fn insert_retaining_evicts_and_inserts() {
        let map: ShardedEpochMap<String, i64> = ShardedEpochMap::new();
        // Force these into the same shard is not required; retain runs per
        // shard, so seed keys that land in the target shard should be swept.
        for i in 0..100 {
            map.insert(format!("k:{i}"), 0); // value 0 == "expired"
        }
        // Insert a live entry, retaining only non-zero (non-expired) values.
        map.insert_retaining("live".to_string(), 1, |_, &v| v != 0);

        assert_eq!(map.get("live"), Some(1));
        // Every expired entry that shared the "live" shard must be gone; entries
        // in other shards are untouched (lazy per-shard eviction).
        let live_shard = map.shard_index(&"live".to_string());
        for i in 0..100 {
            let key = format!("k:{i}");
            if map.shard_index(&key) == live_shard {
                assert!(!map.contains_key(&key), "{key} should be evicted");
            }
        }
    }

    #[test]
    fn prepare_and_install_rebuild_contents() {
        let map: ShardedEpochMap<String, i64> = ShardedEpochMap::new();
        map.insert("stale".to_string(), 9);

        let mut prepared = map.prepare((0..50).map(|i| (format!("r:{i}"), i)));
        map.prepared_insert(&mut prepared, "late".to_string(), 99);
        map.prepared_remove(&mut prepared, "r:49");
        map.install(prepared);
        assert_eq!(map.get("late"), Some(99));
        assert!(!map.contains_key("r:49"));

        assert!(!map.contains_key("stale"));
        assert_eq!(map.get("r:25"), Some(25));
        assert!(map.contains_key("r:0"));
    }

    #[test]
    fn works_as_a_set_projection() {
        // The DPoP blocklist is modelled as a `ShardedEpochMap<String, ()>`.
        let set: ShardedEpochMap<String, ()> = ShardedEpochMap::new();
        set.insert("jkt-1".to_string(), ());
        assert!(set.contains_key("jkt-1"));
        assert!(!set.contains_key("jkt-2"));
        set.remove("jkt-1");
        assert!(!set.contains_key("jkt-1"));
    }

    /// Writers racing on ONE shard — every write an `rcu` of the same cell —
    /// must not lose an insert or a remove, and readers must only ever see a
    /// key with the value that was written for it. This is the revocation
    /// projection's contract: a JTI revoked concurrently with another
    /// revocation in the same shard must still be revoked afterwards.
    #[test]
    fn concurrent_writers_on_one_shard_never_lose_an_update() {
        const WRITERS: usize = 4;
        const PER_WRITER: usize = 150;

        let map: Arc<ShardedEpochMap<String, u64>> = Arc::new(ShardedEpochMap::new());
        let target = map.shard_index("anchor");
        // Every key lands in the same shard, so every write contends.
        let keys: Vec<String> = (0_u64..)
            .map(|i| format!("jti:{i}"))
            .filter(|k| map.shard_index(k.as_str()) == target)
            .take(WRITERS * PER_WRITER)
            .collect();
        let keys = Arc::new(keys);
        let stop = Arc::new(AtomicBool::new(false));

        let readers: Vec<_> = (0..3)
            .map(|_| {
                let map = Arc::clone(&map);
                let keys = Arc::clone(&keys);
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        for (i, key) in keys.iter().enumerate() {
                            if let Some(v) = map.get(key.as_str()) {
                                assert_eq!(v, i as u64, "{key} read back a foreign value");
                            }
                        }
                    }
                })
            })
            .collect();

        let writers: Vec<_> = (0..WRITERS)
            .map(|w| {
                let map = Arc::clone(&map);
                let keys = Arc::clone(&keys);
                std::thread::spawn(move || {
                    let mine = w * PER_WRITER..(w + 1) * PER_WRITER;
                    for i in mine.clone() {
                        map.insert(keys[i].clone(), i as u64);
                    }
                    // Remove every other key again: a lost remove leaves it
                    // behind, a remove that clobbers a neighbour's insert
                    // loses that neighbour.
                    for i in mine.step_by(2) {
                        map.remove(keys[i].as_str());
                    }
                })
            })
            .collect();

        for w in writers {
            w.join().expect("writer thread");
        }
        stop.store(true, Ordering::Relaxed);
        for r in readers {
            r.join().expect("reader thread");
        }

        for (i, key) in keys.iter().enumerate() {
            let expect_present = (i % PER_WRITER) % 2 == 1;
            assert_eq!(
                map.get(key.as_str()),
                expect_present.then_some(i as u64),
                "{key}: an insert or a remove was lost"
            );
        }
    }
}
