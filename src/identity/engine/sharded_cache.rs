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
use crate::identity::tokens::TokenClaims;

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

/// One [`ClaimsCache`] shard's map.
type ClaimsMap = HashMap<[u8; 32], Arc<TokenClaims>>;

/// Entries per [`ClaimsCache`] shard that the shard count aims for. An insert
/// into a full shard sweeps and rebuilds it, so this bounds the work of one
/// insert.
const CLAIMS_ENTRIES_PER_SHARD: usize = 1_024;

/// The verified token-claims cache: claims keyed by the SHA-256 of the raw JWT,
/// in up to [`SHARD_COUNT`] shards.
///
/// Reads are lock-free (one epoch-pinned `load()` and an `Arc` reference-count
/// bump). An insert clones the shard it changes, and a full shard is also swept
/// for expired entries and trimmed, so an insert costs time in proportion to
/// one shard. With one map for the whole cache, every insert into a full
/// 65,536-entry cache copied and swept all of it, and a server that validated
/// ~40 new tokens a second spent all its CPU there (#445).
///
/// The shard is the key's first byte masked by the shard count: a SHA-256 byte
/// is uniform. The shard count is the largest power of two, at most
/// [`SHARD_COUNT`], that gives each shard at least
/// [`CLAIMS_ENTRIES_PER_SHARD`] entries; each shard holds `max / count`, so the
/// cache never holds more than `max`. A cache smaller than
/// `2 * CLAIMS_ENTRIES_PER_SHARD` is one shard and keeps the exact bound.
pub(crate) struct ClaimsCache {
    shards: Box<[EpochCell<ClaimsMap>]>,
    /// The most entries one shard holds.
    shard_max: usize,
}

impl ClaimsCache {
    /// Creates an empty cache that holds at most `max` entries.
    pub(crate) fn new(max: usize) -> Self {
        let max = max.max(1);
        let wanted = max / CLAIMS_ENTRIES_PER_SHARD;
        let count = if wanted == 0 {
            1
        } else {
            (1usize << wanted.ilog2()).min(SHARD_COUNT)
        };
        let shards = (0..count)
            .map(|_| EpochCell::from_pointee(HashMap::new()))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            shards,
            shard_max: max / count,
        }
    }

    #[inline]
    fn shard(&self, key: &[u8; 32]) -> &EpochCell<ClaimsMap> {
        // The shard count is a power of two of at most 64, so the mask of one
        // byte is exact.
        &self.shards[usize::from(key[0]) & (self.shards.len() - 1)]
    }

    /// Lock-free lookup: one epoch-pinned `load()` and an `Arc` reference-count
    /// bump.
    #[inline]
    pub(crate) fn get(&self, key: &[u8; 32]) -> Option<Arc<TokenClaims>> {
        self.shard(key).load().get(key).cloned()
    }

    /// Inserts `claims` under `key`, unless `still_valid` returns `false`.
    ///
    /// `still_valid` runs inside the copy-on-write update, again on every
    /// retry, so a flush that lands while the update runs always wins.
    ///
    /// A full shard first drops every entry whose `exp` is at or before
    /// `now_secs`. If it is still full, the entries closest to expiry go: they
    /// have the least life left and are the least likely to be validated
    /// again. A full shard therefore replaces entries instead of refusing new
    /// ones.
    pub(crate) fn insert(
        &self,
        key: [u8; 32],
        claims: Arc<TokenClaims>,
        now_secs: i64,
        still_valid: impl Fn() -> bool,
    ) {
        let max = self.shard_max;
        self.shard(&key).rcu(|map| {
            if !still_valid() {
                return HashMap::clone(map);
            }

            // Room to spare, or an update of an existing key.
            if map.len() < max || map.contains_key(&key) {
                let mut m = HashMap::clone(map);
                m.insert(key, Arc::clone(&claims));
                return m;
            }

            // Full: rebuild without expired entries.
            let mut m: ClaimsMap = map
                .iter()
                .filter(|(_, v)| v.exp > now_secs)
                .map(|(k, v)| (*k, Arc::clone(v)))
                .collect();

            // Still full: evict the entries closest to expiry.
            if m.len() >= max {
                let overflow = m.len() - max + 1;
                let mut exps: Vec<i64> = m.values().map(|v| v.exp).collect();
                // `overflow <= m.len()`, so `overflow - 1` is a valid index.
                exps.select_nth_unstable(overflow - 1);
                let threshold = exps[overflow - 1];
                let mut removed = 0usize;
                m.retain(|_, v| {
                    if removed < overflow && v.exp <= threshold {
                        removed += 1;
                        false
                    } else {
                        true
                    }
                });
            }

            m.insert(key, Arc::clone(&claims));
            m
        });
    }

    /// Drops every entry.
    pub(crate) fn clear(&self) {
        for shard in &*self.shards {
            shard.store(Arc::new(HashMap::new()));
        }
    }

    /// The number of shards.
    #[cfg(test)]
    pub(crate) fn shard_count(&self) -> usize {
        self.shards.len()
    }

    /// The most entries one shard holds.
    #[cfg(test)]
    pub(crate) fn shard_max(&self) -> usize {
        self.shard_max
    }

    /// The number of entries in every shard together.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.shards.iter().map(|s| s.load().len()).sum()
    }

    /// Whether the cache holds no entry.
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether the cache holds `key`.
    #[cfg(test)]
    pub(crate) fn contains_key(&self, key: &[u8; 32]) -> bool {
        self.shard(key).load().contains_key(key)
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

    fn claims_expiring_at(exp: i64) -> Arc<TokenClaims> {
        Arc::new(TokenClaims {
            sub: "user".to_string(),
            iss: "hearth".to_string(),
            aud: crate::identity::tokens::Audience::single("hearth"),
            exp,
            iat: 0,
            nbf: None,
            sid: "session".to_string(),
            tid: "realm".to_string(),
            oid: None,
            token_type: "access".to_string(),
            jti: None,
            fid: None,
            scope: None,
            nonce: None,
            azp: None,
            cnf: None,
            roles: Vec::new(),
            groups: Vec::new(),
            org_groups: Vec::new(),
            permissions: Vec::new(),
            custom: std::collections::BTreeMap::new(),
            act: None,
            amr: Vec::new(),
            sv: None,
        })
    }

    /// A cache key whose first byte, which picks the shard, is `first`.
    fn claims_key(first: u8, rest: u8) -> [u8; 32] {
        let mut key = [rest; 32];
        key[0] = first;
        key
    }

    fn claims_shard_ptrs(cache: &ClaimsCache) -> Vec<*const ClaimsMap> {
        cache
            .shards
            .iter()
            .map(|s| Arc::as_ptr(&s.load_full()))
            .collect()
    }

    #[test]
    fn a_default_claims_cache_has_64_shards_of_1024_entries() {
        let cache = ClaimsCache::new(65_536);
        assert_eq!((cache.shard_count(), cache.shard_max()), (64, 1_024));
    }

    #[test]
    fn a_small_claims_cache_keeps_its_exact_bound() {
        let cache = ClaimsCache::new(4);
        assert_eq!((cache.shard_count(), cache.shard_max()), (1, 4));
        let cache = ClaimsCache::new(3_000);
        assert_eq!((cache.shard_count(), cache.shard_max()), (2, 1_500));
        let cache = ClaimsCache::new(1_000_000);
        assert_eq!((cache.shard_count(), cache.shard_max()), (64, 15_625));
    }

    /// #445: a full 65,536-entry cache that copied and swept the whole map on
    /// every insert used all CPU on a server validating ~40 new tokens a
    /// second. An insert must copy only the shard of its key.
    #[test]
    fn a_claims_insert_copies_only_the_shard_of_its_key() {
        let cache = ClaimsCache::new(65_536);
        for first in 0..=255u8 {
            cache.insert(claims_key(first, 1), claims_expiring_at(100), 0, || true);
        }
        let before = claims_shard_ptrs(&cache);
        cache.insert(claims_key(5, 2), claims_expiring_at(100), 0, || true);
        let after = claims_shard_ptrs(&cache);
        let changed: Vec<usize> = (0..before.len())
            .filter(|&i| before[i] != after[i])
            .collect();
        assert_eq!(changed, vec![5]);
        assert!(cache.contains_key(&claims_key(5, 2)));
    }

    #[test]
    fn a_full_claims_shard_drops_expired_entries_first() {
        let cache = ClaimsCache::new(4);
        for n in 0..4u8 {
            let exp = if n < 2 { 50 } else { 500 };
            cache.insert(claims_key(0, n), claims_expiring_at(exp), 0, || true);
        }
        cache.insert(claims_key(0, 9), claims_expiring_at(500), 100, || true);
        assert_eq!(cache.len(), 3);
        assert!(cache.contains_key(&claims_key(0, 9)));
        assert!(!cache.contains_key(&claims_key(0, 0)));
        assert!(!cache.contains_key(&claims_key(0, 1)));
    }

    #[test]
    fn a_full_claims_shard_of_live_entries_evicts_the_closest_to_expiry() {
        let cache = ClaimsCache::new(4);
        for n in 0..4u8 {
            cache.insert(
                claims_key(0, n),
                claims_expiring_at(200 + i64::from(n)),
                0,
                || true,
            );
        }
        cache.insert(claims_key(0, 9), claims_expiring_at(900), 100, || true);
        assert_eq!(cache.len(), 4);
        assert!(cache.contains_key(&claims_key(0, 9)));
        assert!(!cache.contains_key(&claims_key(0, 0)));
    }

    #[test]
    fn a_claims_insert_that_is_no_longer_valid_changes_nothing() {
        let cache = ClaimsCache::new(4);
        cache.insert(claims_key(0, 1), claims_expiring_at(100), 0, || false);
        assert!(cache.is_empty());
    }

    #[test]
    fn clearing_the_claims_cache_empties_every_shard() {
        let cache = ClaimsCache::new(65_536);
        for first in 0..=255u8 {
            cache.insert(claims_key(first, 1), claims_expiring_at(100), 0, || true);
        }
        assert_eq!(cache.len(), 256);
        cache.clear();
        assert!(cache.is_empty());
    }
}
