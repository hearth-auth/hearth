//! Hot tier with clock-based LRU eviction for frequently accessed data.
//!
//! Provides lock-free reads via `ArcSwap<HashMap>`. Writes (promote, invalidate,
//! evict) are serialized behind a `Mutex` and use clone-mutate-swap — acceptable
//! because they are off the hot path.
//!
//! A fill (`promote`) is guarded against racing an invalidation: the caller
//! opens a [`FillGuard`] before its authoritative memtable/SST read, and a
//! fill whose window saw an invalidation is discarded. Without the guard, a
//! delete or update overlapping an in-flight read left the stale value
//! cached for the life of the process (audit 2026-08-28 §4.21#3).
//!
//! The clock algorithm approximates LRU:
//! - Each entry has an `AtomicBool` reference bit.
//! - On read hit: set `reference_bit` = true (atomic store, no lock).
//! - Clock hand sweeps entries: `ref_bit`=0 → evict; `ref_bit`=1 → clear, advance.

use std::hash::{BuildHasher, Hash, Hasher};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use hashbrown::HashMap;

use arc_swap::ArcSwap;

use crate::core::RealmId;
use crate::storage::memtable::CompositeKey;

/// A single entry in the hot tier.
pub(crate) struct HotEntry {
    /// The cached value bytes — shared cheaply via Arc on cache hits.
    value: Arc<[u8]>,
    /// Clock reference bit: set on access, cleared during sweep.
    reference_bit: AtomicBool,
}

impl HotEntry {
    /// Creates a new hot entry with the reference bit set (just accessed).
    fn new(value: Arc<[u8]>) -> Self {
        Self {
            value,
            reference_bit: AtomicBool::new(true),
        }
    }
}

// Manual Clone needed because AtomicBool doesn't derive Clone.
impl Clone for HotEntry {
    fn clone(&self) -> Self {
        Self {
            value: Arc::clone(&self.value),
            reference_bit: AtomicBool::new(self.reference_bit.load(Ordering::Relaxed)),
        }
    }
}

/// Proof that a hot-tier fill began before any conflicting invalidation.
///
/// Captured with [`HotTier::begin_fill`] *before* the caller reads the
/// authoritative memtable/SST value it intends to cache. [`HotTier::promote`]
/// discards the fill when any invalidation ran after the guard was taken, so
/// a delete or update that overlaps an in-flight read is never shadowed by
/// the stale value (audit 2026-08-28 §4.21#3).
#[derive(Clone, Copy)]
pub(crate) struct FillGuard {
    /// The invalidation epoch observed when the fill window opened.
    epoch: u64,
}

/// Production promotion sample rate: admit 1-in-N cold promotions to bound
/// write-lock acquisition and O(capacity) map-clone churn under
/// cold-read-heavy load. Genuinely hot keys are read repeatedly and so are
/// sampled in quickly; correctness is unaffected because an unadmitted record
/// is still servable from the memtable/SST layers (HEA-1775).
pub(crate) const PRODUCTION_PROMOTE_SAMPLE_RATE: u32 = 4;

/// Configuration for the hot tier.
#[derive(Debug, Clone)]
pub(crate) struct TieredConfig {
    /// Maximum number of entries in the hot tier.
    pub hot_tier_capacity: usize,
    /// Number of entries to scan per clock sweep step.
    pub eviction_batch_size: usize,
    /// Probabilistic-admission divisor for [`HotTier::promote`]: admit only
    /// 1-in-`N` promotions to the hot tier, where `N` is this value.
    ///
    /// Each admitted promotion acquires the write lock and clones the whole
    /// map (`O(capacity)`), so under cold-read-heavy load promoting on every
    /// memtable/SST hit dominates. A value `> 1` amortizes that churn; `1`
    /// admits every promotion (immediate, deterministic caching).
    pub promote_sample_rate: u32,
}

impl Default for TieredConfig {
    fn default() -> Self {
        Self {
            hot_tier_capacity: 100_000,
            eviction_batch_size: 64,
            // Admit every promotion by default — deterministic caching for
            // dev/embedded use. Production opts into sampling explicitly via
            // `PRODUCTION_PROMOTE_SAMPLE_RATE`.
            promote_sample_rate: 1,
        }
    }
}

/// Lock-free read, serialized-write hot tier with clock-based LRU eviction.
pub(crate) struct HotTier {
    /// The cached data, swapped atomically on mutations.
    data: ArcSwap<HashMap<CompositeKey, HotEntry>>,
    /// Maximum entries before eviction is triggered.
    capacity: usize,
    /// Clock hand position for sweep (indexes into a snapshot of keys).
    clock_hand: AtomicUsize,
    /// Serializes write operations (promote, invalidate, evict).
    write_lock: Mutex<()>,
    /// Monotonic counter of `promote` calls, used by the probabilistic-admission
    /// sampler to decide which promotions to admit. Wraps harmlessly.
    promote_counter: AtomicU64,
    /// Count of promotions actually admitted (took the write lock + cloned the
    /// map). Compared against total calls to measure sampler effectiveness.
    admitted_promotions: AtomicU64,
    /// Monotonic count of invalidations. `promote` admits a fill only when
    /// the epoch still matches its [`FillGuard`], which proves no delete or
    /// update landed between the caller's authoritative read and the fill.
    invalidation_epoch: AtomicU64,
    /// Configuration.
    config: TieredConfig,
}

impl HotTier {
    /// Creates a new empty hot tier with the given configuration.
    pub(crate) fn new(config: TieredConfig) -> Self {
        let capacity = config.hot_tier_capacity;
        Self {
            data: ArcSwap::from_pointee(HashMap::new()),
            capacity,
            clock_hand: AtomicUsize::new(0),
            write_lock: Mutex::new(()),
            promote_counter: AtomicU64::new(0),
            admitted_promotions: AtomicU64::new(0),
            invalidation_epoch: AtomicU64::new(0),
            config,
        }
    }

    /// Opens a fill window for a later [`HotTier::promote`].
    ///
    /// Call this *before* reading the authoritative memtable/SST value. The
    /// guard captures the invalidation epoch; `promote` discards the fill
    /// when the epoch has moved, so a value read before a concurrent delete
    /// or update cannot be installed after that write's invalidation
    /// (audit 2026-08-28 §4.21#3).
    pub(crate) fn begin_fill(&self) -> FillGuard {
        FillGuard {
            epoch: self.invalidation_epoch.load(Ordering::SeqCst),
        }
    }

    /// Lock-free read from the hot tier. Returns `None` if not cached.
    ///
    /// On hit, sets the reference bit to protect the entry from eviction.
    /// Returns `Arc<[u8]>` so callers avoid a heap allocation on every cache
    /// hit — Arc clone is an atomic refcount increment with no malloc.
    pub(crate) fn get(&self, realm_id: &RealmId, key: &[u8]) -> Option<Arc<[u8]>> {
        let snapshot = self.data.load();

        // Build the hash that matches CompositeKey's derived Hash impl
        // (fields hashed in declaration order: realm_id then key).
        // This avoids allocating a CompositeKey just for the lookup.
        let hash = {
            let mut hasher = snapshot.hasher().build_hasher();
            realm_id.hash(&mut hasher);
            key.hash(&mut hasher);
            hasher.finish()
        };

        snapshot
            .raw_entry()
            .from_hash(hash, |k| k.realm_id() == realm_id && k.key() == key)
            .map(|(_, entry)| {
                // Mark as recently accessed — protects from next sweep
                entry.reference_bit.store(true, Ordering::Relaxed);
                Arc::clone(&entry.value)
            })
    }

    /// Promotes a key-value pair into the hot tier.
    ///
    /// If the tier is at capacity, runs clock sweep to evict entries first.
    /// This is a write operation (off hot path) — acquires the write lock.
    ///
    /// The `guard` must come from a [`HotTier::begin_fill`] call made before
    /// the caller read `value` from the authoritative layers. A fill whose
    /// guard epoch is stale — an invalidation ran inside the fill window — is
    /// discarded, because `value` may predate a delete or update
    /// (audit 2026-08-28 §4.21#3). The record stays servable from the
    /// memtable/SST layers.
    ///
    /// Promotion is *probabilistically admitted*: only 1-in-`promote_sample_rate`
    /// calls proceed to take the write lock and clone the map. On cold-read-heavy
    /// workloads this bounds write-lock contention and O(capacity) map clones
    /// without changing which records are servable — an unadmitted record is
    /// still returned from the memtable/SST layers, and repeatedly-read (hot)
    /// keys are admitted quickly (HEA-1775).
    pub(crate) fn promote(&self, guard: FillGuard, realm_id: &RealmId, key: &[u8], value: &[u8]) {
        // Probabilistic admission gate — cheap atomic, evaluated before any
        // allocation (CompositeKey) or lock acquisition so skipped promotions
        // cost almost nothing. Counter starts at 0, so the first promotion is
        // always admitted.
        let sample_rate = self.config.promote_sample_rate;
        if sample_rate > 1 {
            let n = self.promote_counter.fetch_add(1, Ordering::Relaxed);
            if !n.is_multiple_of(u64::from(sample_rate)) {
                return;
            }
        }

        let composite = CompositeKey::new(realm_id.clone(), key.to_vec());

        let Ok(_lock) = self.write_lock.lock() else {
            return; // Poisoned mutex — silently skip promotion
        };

        // An invalidation ran inside the fill window: the value in hand may
        // predate a delete or update, and installing it would serve the stale
        // value for the life of the process. Discard the fill
        // (audit 2026-08-28 §4.21#3).
        if self.invalidation_epoch.load(Ordering::SeqCst) != guard.epoch {
            crate::metrics::metrics()
                .storage_hot_tier_stale_fills_discarded_total
                .inc();
            return;
        }

        // Admitted: this call takes the write lock and clones the map below.
        self.admitted_promotions.fetch_add(1, Ordering::Relaxed);
        crate::metrics::metrics()
            .storage_hot_tier_promotions_total
            .inc();

        let current = self.data.load_full();

        // If already present, just update the value and set ref bit
        if current.contains_key(&composite) {
            let mut new_map = (*current).clone();
            new_map.insert(composite, HotEntry::new(Arc::from(value)));
            self.data.store(Arc::new(new_map));
            return;
        }

        // Evict if at capacity
        let mut new_map = (*current).clone();
        if new_map.len() >= self.capacity {
            self.evict_locked(&mut new_map);
        }

        new_map.insert(composite, HotEntry::new(Arc::from(value)));
        self.data.store(Arc::new(new_map));
    }

    /// Invalidates (removes) an entry from the hot tier.
    ///
    /// Called on writes/deletes to ensure stale data isn't served.
    pub(crate) fn invalidate(&self, realm_id: &RealmId, key: &[u8]) {
        // Bump the epoch before anything else — including when the key is
        // not (yet) cached. An in-flight fill for this key is invisible
        // here; the epoch is what stops it landing after we return
        // (audit 2026-08-28 §4.21#3).
        self.invalidation_epoch.fetch_add(1, Ordering::SeqCst);

        let composite = CompositeKey::new(realm_id.clone(), key.to_vec());

        let Ok(_guard) = self.write_lock.lock() else {
            return;
        };

        let current = self.data.load_full();
        if !current.contains_key(&composite) {
            return;
        }

        let mut new_map = (*current).clone();
        new_map.remove(&composite);
        self.data.store(Arc::new(new_map));
    }

    /// Performs one clock sweep step, returning the evicted key (if any).
    ///
    /// Scans up to `min(eviction_batch_size, len)` distinct entries. For each:
    /// - If `reference_bit` is false → evict (remove and return key).
    /// - If `reference_bit` is true → clear to false, advance.
    ///
    /// The sweep never wraps past all entries in a single call — this ensures
    /// that clearing a reference bit and evicting are separate sweep passes.
    ///
    /// Acquires the write lock.
    pub(crate) fn clock_sweep_step(&self) -> Option<CompositeKey> {
        let Ok(_guard) = self.write_lock.lock() else {
            return None;
        };

        let current = self.data.load_full();
        if current.is_empty() {
            return None;
        }

        // Collect keys for indexed access (deterministic order via sorted keys)
        let mut keys: Vec<CompositeKey> = current.keys().cloned().collect();
        keys.sort();

        let len = keys.len();
        // Never scan more entries than exist — prevents wrapping in one call
        let scan_count = self.config.eviction_batch_size.min(len);
        let mut hand = self.clock_hand.load(Ordering::Relaxed) % len;

        for _ in 0..scan_count {
            let key = &keys[hand];

            if let Some(entry) = current.get(key) {
                if !entry.reference_bit.load(Ordering::Relaxed) {
                    // Evict this entry
                    let evicted_key = key.clone();
                    let mut new_map = (*current).clone();
                    new_map.remove(&evicted_key);
                    self.data.store(Arc::new(new_map));
                    crate::metrics::metrics()
                        .storage_hot_tier_evictions_total
                        .inc();
                    hand = (hand + 1) % len;
                    self.clock_hand.store(hand, Ordering::Relaxed);
                    return Some(evicted_key);
                }
                // Clear reference bit — give it a second chance
                entry.reference_bit.store(false, Ordering::Relaxed);
            }

            hand = (hand + 1) % len;
        }

        self.clock_hand.store(hand, Ordering::Relaxed);
        None
    }

    /// Returns the number of entries currently in the hot tier.
    pub(crate) fn len(&self) -> usize {
        self.data.load().len()
    }

    /// Returns whether the hot tier contains the given key.
    pub(crate) fn contains(&self, realm_id: &RealmId, key: &[u8]) -> bool {
        let composite = CompositeKey::new(realm_id.clone(), key.to_vec());
        self.data.load().contains_key(&composite)
    }

    /// Number of promotions that were *admitted* — i.e. actually acquired the
    /// write lock and cloned the map. Compare against the total number of
    /// `promote` calls to quantify how much the probabilistic-admission sampler
    /// cut write-lock/clone churn.
    #[cfg(test)]
    pub(crate) fn admitted_promotions(&self) -> u64 {
        self.admitted_promotions.load(Ordering::Relaxed)
    }

    /// Test convenience: a fill with no interleaved invalidation — the guard
    /// is taken immediately before the promote.
    #[cfg(test)]
    pub(crate) fn promote_now(&self, realm_id: &RealmId, key: &[u8], value: &[u8]) {
        self.promote(self.begin_fill(), realm_id, key, value);
    }

    /// Runs clock sweep eviction on the mutable map (write lock must be held).
    ///
    /// First pass: scan all entries, clear ref bits, evict first unreferenced.
    /// Second pass (if first pass only cleared bits): scan again to evict.
    /// Force-evict at hand position if both passes fail (guarantees progress).
    fn evict_locked(&self, map: &mut HashMap<CompositeKey, HotEntry>) {
        if map.is_empty() {
            return;
        }

        let mut keys: Vec<CompositeKey> = map.keys().cloned().collect();
        keys.sort();

        let len = keys.len();
        let mut hand = self.clock_hand.load(Ordering::Relaxed) % len;

        // Two full passes: first clears ref bits, second evicts
        for _ in 0..len * 2 {
            let key = &keys[hand];

            if let Some(entry) = map.get(key) {
                if !entry.reference_bit.load(Ordering::Relaxed) {
                    let evicted = key.clone();
                    map.remove(&evicted);
                    crate::metrics::metrics()
                        .storage_hot_tier_evictions_total
                        .inc();
                    hand = (hand + 1) % len;
                    self.clock_hand.store(hand, Ordering::Relaxed);
                    return;
                }
                entry.reference_bit.store(false, Ordering::Relaxed);
            }

            hand = (hand + 1) % len;
        }

        self.clock_hand.store(hand, Ordering::Relaxed);

        // If we still couldn't evict (shouldn't happen after 2 passes, but be safe),
        // force-evict at current hand position.
        let key = keys[hand % len].clone();
        map.remove(&key);
        crate::metrics::metrics()
            .storage_hot_tier_evictions_total
            .inc();
    }
}

impl std::fmt::Debug for HotTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HotTier")
            .field("len", &self.len())
            .field("capacity", &self.capacity)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::RealmId;

    // ===== Phase A: P0 Fast Unit Tests =====

    // TEST_SCENARIOS.md: "Recently accessed records remain in hot tier across subsequent reads"

    #[test]
    fn hot_tier_recently_accessed_remains_hot() {
        let config = TieredConfig {
            hot_tier_capacity: 10,
            eviction_batch_size: 10,
            promote_sample_rate: 1,
        };
        let tier = HotTier::new(config);
        let realm = RealmId::generate();

        // Promote an entry
        tier.promote_now(&realm, b"key1", b"value1");
        assert!(tier.contains(&realm, b"key1"));

        // Read it (sets reference bit)
        let val = tier.get(&realm, b"key1");
        assert_eq!(val.as_deref(), Some(b"value1" as &[u8]));

        // Sweep — should NOT evict because reference bit is set
        let evicted = tier.clock_sweep_step();
        // The sweep clears the bit but doesn't evict on first pass
        // Second read should still find the entry
        let val = tier.get(&realm, b"key1");
        assert_eq!(
            val.as_deref(),
            Some(b"value1" as &[u8]),
            "entry should survive sweep after read"
        );

        // If eviction occurred, it shouldn't have been our key
        if let Some(ref key) = evicted {
            assert_ne!(
                key.key(),
                b"key1",
                "recently accessed key should not be evicted"
            );
        }
    }

    // TEST_SCENARIOS.md: "Records not accessed within eviction window are demoted to cold tier"

    #[test]
    fn hot_tier_unaccessed_evicted() {
        let config = TieredConfig {
            hot_tier_capacity: 10,
            eviction_batch_size: 10,
            promote_sample_rate: 1,
        };
        let tier = HotTier::new(config);
        let realm = RealmId::generate();

        // Promote an entry
        tier.promote_now(&realm, b"lonely", b"value");
        assert!(tier.contains(&realm, b"lonely"));

        // First sweep: clears the reference bit (was set on promote)
        let _ = tier.clock_sweep_step();

        // Second sweep: reference bit is now false → evict
        let evicted = tier.clock_sweep_step();
        assert!(evicted.is_some(), "unaccessed entry should be evicted");
        assert!(
            !tier.contains(&realm, b"lonely"),
            "evicted entry should not be in tier"
        );
        assert_eq!(tier.get(&realm, b"lonely"), None);
    }

    // TEST_SCENARIOS.md: "Clock-based LRU approximation evicts least-recently-used records correctly"

    #[test]
    fn clock_lru_evicts_least_recently_used() {
        let config = TieredConfig {
            hot_tier_capacity: 3,
            eviction_batch_size: 10,
            promote_sample_rate: 1,
        };
        let tier = HotTier::new(config);
        let realm = RealmId::generate();

        // Fill to capacity (all entries get ref_bit=true from promote)
        tier.promote_now(&realm, b"key1", b"v1");
        tier.promote_now(&realm, b"key2", b"v2");
        tier.promote_now(&realm, b"key3", b"v3");
        assert_eq!(tier.len(), 3);

        // ONE sweep pass clears all reference bits (no eviction since all were true)
        let evicted = tier.clock_sweep_step();
        assert!(
            evicted.is_none(),
            "first sweep should only clear bits, not evict"
        );

        // Now access key1 and key3 — sets their ref bits back to true
        assert!(tier.get(&realm, b"key1").is_some());
        assert!(tier.get(&realm, b"key3").is_some());
        // key2 NOT accessed — its ref_bit remains false

        // Promote a new key (triggers eviction since at capacity)
        // evict_locked will find key2 with ref_bit=false and evict it
        tier.promote_now(&realm, b"key4", b"v4");

        // key2 should have been evicted (unaccessed), others survive
        assert!(
            tier.contains(&realm, b"key1"),
            "accessed key1 should survive"
        );
        assert!(
            !tier.contains(&realm, b"key2"),
            "unaccessed key2 should be evicted"
        );
        assert!(
            tier.contains(&realm, b"key3"),
            "accessed key3 should survive"
        );
        assert!(
            tier.contains(&realm, b"key4"),
            "newly promoted key4 should exist"
        );
    }

    // TEST_SCENARIOS.md: "Hot tier auto-sizes based on available system memory / cgroup memory limit"

    #[test]
    fn hot_tier_config_accepts_custom_capacity() {
        let config = TieredConfig {
            hot_tier_capacity: 500_000,
            eviction_batch_size: 128,
            promote_sample_rate: 1,
        };
        let tier = HotTier::new(config);
        assert_eq!(tier.capacity, 500_000);
    }

    // ===== Supplementary Unit Tests =====

    #[test]
    fn promote_updates_existing_entry() {
        let config = TieredConfig {
            hot_tier_capacity: 10,
            eviction_batch_size: 10,
            promote_sample_rate: 1,
        };
        let tier = HotTier::new(config);
        let realm = RealmId::generate();

        tier.promote_now(&realm, b"key1", b"old");
        assert_eq!(tier.get(&realm, b"key1").as_deref(), Some(b"old" as &[u8]));

        tier.promote_now(&realm, b"key1", b"new");
        assert_eq!(tier.get(&realm, b"key1").as_deref(), Some(b"new" as &[u8]));
        assert_eq!(tier.len(), 1, "update should not add a second entry");
    }

    #[test]
    fn invalidate_removes_entry() {
        let config = TieredConfig {
            hot_tier_capacity: 10,
            eviction_batch_size: 10,
            promote_sample_rate: 1,
        };
        let tier = HotTier::new(config);
        let realm = RealmId::generate();

        tier.promote_now(&realm, b"key1", b"value1");
        assert!(tier.contains(&realm, b"key1"));

        tier.invalidate(&realm, b"key1");
        assert!(!tier.contains(&realm, b"key1"));
        assert_eq!(tier.get(&realm, b"key1"), None);
    }

    #[test]
    fn invalidate_nonexistent_is_noop() {
        let config = TieredConfig::default();
        let tier = HotTier::new(config);
        let realm = RealmId::generate();

        tier.invalidate(&realm, b"missing");
        assert_eq!(tier.len(), 0);
    }

    // ===== Audit 2026-08-28 §4.21#3: fill/invalidation race =====

    // Models the engine's `get`/`delete` interleaving: the reader opens its
    // fill window, reads the pre-delete value from the store, the delete's
    // invalidation lands, and the fill completes last. The stale fill must
    // be discarded — before the guard existed it was installed permanently.
    #[test]
    fn stale_fill_after_invalidate_is_discarded() {
        let tier = HotTier::new(TieredConfig::default());
        let realm = RealmId::generate();

        let fill = tier.begin_fill();
        tier.invalidate(&realm, b"cred"); // the concurrent delete wins the race
        tier.promote(fill, &realm, b"cred", b"stale");

        assert_eq!(
            tier.get(&realm, b"cred"),
            None,
            "a fill whose window saw an invalidation must be discarded"
        );
    }

    // The guard must fire even when the invalidated key was never cached —
    // the old `invalidate` early-returned on an absent key, which is exactly
    // how the in-flight fill slipped past it.
    #[test]
    fn invalidate_of_uncached_key_still_blocks_stale_fill() {
        let tier = HotTier::new(TieredConfig::default());
        let realm = RealmId::generate();
        assert!(!tier.contains(&realm, b"cred"), "key must start uncached");

        let fill = tier.begin_fill();
        tier.invalidate(&realm, b"cred");
        tier.promote(fill, &realm, b"cred", b"stale");

        assert_eq!(tier.get(&realm, b"cred"), None);
    }

    // A fill window opened after the invalidation is clean and must land.
    #[test]
    fn fresh_fill_after_invalidate_is_admitted() {
        let tier = HotTier::new(TieredConfig::default());
        let realm = RealmId::generate();

        tier.invalidate(&realm, b"cred");
        let fill = tier.begin_fill();
        tier.promote(fill, &realm, b"cred", b"current");

        assert_eq!(
            tier.get(&realm, b"cred").as_deref(),
            Some(b"current" as &[u8]),
            "a fill that began after the invalidation is not stale"
        );
    }

    #[test]
    fn realm_isolation() {
        let config = TieredConfig::default();
        let tier = HotTier::new(config);
        let realm_a = RealmId::generate();
        let realm_b = RealmId::generate();

        tier.promote_now(&realm_a, b"shared_key", b"value-a");
        tier.promote_now(&realm_b, b"shared_key", b"value-b");

        assert_eq!(
            tier.get(&realm_a, b"shared_key").as_deref(),
            Some(b"value-a" as &[u8])
        );
        assert_eq!(
            tier.get(&realm_b, b"shared_key").as_deref(),
            Some(b"value-b" as &[u8])
        );
        assert_eq!(tier.len(), 2);
    }

    #[test]
    fn sweep_on_empty_tier_returns_none() {
        let config = TieredConfig::default();
        let tier = HotTier::new(config);
        assert_eq!(tier.clock_sweep_step(), None);
    }

    #[test]
    fn hot_tier_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<HotTier>();
    }

    // ===== HEA-1775: Promote write-lock / clone churn (probabilistic admission) =====

    fn sampling_config(promote_sample_rate: u32) -> TieredConfig {
        TieredConfig {
            // Large capacity so eviction never masks the admission behaviour.
            hot_tier_capacity: 100_000,
            eviction_batch_size: 64,
            promote_sample_rate,
        }
    }

    // Bench-style assertion: under cold-read-heavy load (many distinct keys,
    // each promoted once) a sampler with rate N takes the write lock and clones
    // the map only ~1/N as often as rate=1, cutting promote-path contention.
    #[test]
    fn promote_sampling_cuts_lock_and_clone_rate() {
        let realm = RealmId::generate();
        let n = 800u32;

        let always = HotTier::new(sampling_config(1));
        let sampled = HotTier::new(sampling_config(8));

        for i in 0..n {
            let key = i.to_be_bytes();
            always.promote_now(&realm, &key, b"v");
            sampled.promote_now(&realm, &key, b"v");
        }

        // rate=1 must admit (write-lock + clone) every single promotion.
        assert_eq!(
            always.admitted_promotions(),
            u64::from(n),
            "rate=1 must clone on every promote"
        );

        // rate=8 admits indices 0,8,16,... => exactly n/8 = 100 admissions.
        assert_eq!(
            sampled.admitted_promotions(),
            u64::from(n) / 8,
            "rate=8 must admit ~1/8 of promotions"
        );

        // Concretely: the sampler cut write-lock/clone churn by >4x.
        assert!(
            sampled.admitted_promotions() * 4 < always.admitted_promotions(),
            "sampler should sharply reduce admitted promotions: {} vs {}",
            sampled.admitted_promotions(),
            always.admitted_promotions()
        );
    }

    // Guardrail: sampling must not change which records are servable — a hot key
    // read repeatedly is still admitted, and the first promotion is always
    // admitted (counter starts at 0) so callers get deterministic warm-up.
    #[test]
    fn promote_sampling_admits_first_and_repeated_keys() {
        let realm = RealmId::generate();
        let tier = HotTier::new(sampling_config(4));

        // First promotion is always admitted.
        tier.promote_now(&realm, b"first", b"v");
        assert!(
            tier.contains(&realm, b"first"),
            "first promotion must be admitted deterministically"
        );

        // A repeatedly-promoted (hot) key is admitted within a bounded number
        // of attempts even under sampling.
        for _ in 0..4 {
            tier.promote_now(&realm, b"hot", b"v");
        }
        assert!(
            tier.contains(&realm, b"hot"),
            "a repeatedly promoted hot key must be admitted under sampling"
        );
    }

    // Production opts into sampling (compile-time invariant).
    const _: () = assert!(PRODUCTION_PROMOTE_SAMPLE_RATE > 1);

    #[test]
    fn default_config_admits_every_promotion() {
        // Dev/embedded default keeps deterministic immediate caching.
        assert_eq!(TieredConfig::default().promote_sample_rate, 1);

        // Exercise the contract the name claims: under the default config a
        // single promotion is admitted immediately (no sampling gate), unlike
        // the sampled production config where a lone promote may be skipped.
        let tier = HotTier::new(TieredConfig::default());
        let realm = RealmId::generate();
        tier.promote_now(&realm, b"once", b"v");
        assert!(
            tier.contains(&realm, b"once"),
            "default (sample_rate=1) config must admit every single promotion"
        );
    }

    // ===== Phase B: P0 Extended Property Tests =====

    use proptest::prelude::*;

    #[derive(Debug, Clone)]
    enum TierOp {
        Promote(Vec<u8>, Vec<u8>),
        Get(Vec<u8>),
        Invalidate(Vec<u8>),
        Sweep,
    }

    fn arb_tier_op() -> impl Strategy<Value = TierOp> {
        prop_oneof![
            (
                prop::collection::vec(any::<u8>(), 1..16),
                prop::collection::vec(any::<u8>(), 1..32),
            )
                .prop_map(|(k, v)| TierOp::Promote(k, v)),
            prop::collection::vec(any::<u8>(), 1..16).prop_map(TierOp::Get),
            prop::collection::vec(any::<u8>(), 1..16).prop_map(TierOp::Invalidate),
            Just(TierOp::Sweep),
        ]
    }

    // TEST_SCENARIOS.md: "Random access patterns produce correct eviction and promotion behavior"
    proptest! {
        #[test]
        fn proptest_random_access_correct_eviction(
            ops in prop::collection::vec(arb_tier_op(), 1..200)
        ) {
            let config = TieredConfig {
                hot_tier_capacity: 20,
                eviction_batch_size: 5,
                promote_sample_rate: 1,
            };
            let tier = HotTier::new(config);
            let realm = RealmId::generate();
            let mut oracle: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();

            for op in &ops {
                match op {
                    TierOp::Promote(k, v) => {
                        tier.promote_now(&realm, k, v);
                        oracle.insert(k.clone(), v.clone());
                    }
                    TierOp::Get(k) => {
                        let tier_val = tier.get(&realm, k);
                        if let Some(val) = &tier_val {
                            // If hot tier returns a value, it must match oracle
                            if let Some(oracle_val) = oracle.get(k) {
                                prop_assert_eq!(val.as_ref(), oracle_val.as_slice(),
                                    "hot tier returned wrong value for key {:?}", k);
                            }
                        }
                        // It's OK for hot tier to return None even if oracle has it
                        // (entry may have been evicted)
                    }
                    TierOp::Invalidate(k) => {
                        tier.invalidate(&realm, k);
                        oracle.remove(k);
                    }
                    TierOp::Sweep => {
                        if let Some(evicted) = tier.clock_sweep_step() {
                            oracle.remove(evicted.key());
                        }
                    }
                }
            }

            // Invariant 1: capacity is never exceeded regardless of op sequence.
            prop_assert!(tier.len() <= 20, "hot tier exceeded capacity: {}", tier.len());

            // Invariant 2 (eviction *correctness*, not just count): every key that
            // survived in the tier must still read back its most-recently-promoted
            // value. Eviction may drop a key (→ None, allowed), but it must never
            // corrupt a surviving entry or resurrect a stale value. The oracle holds
            // the latest value written per still-live key.
            for (k, expected) in &oracle {
                if let Some(got) = tier.get(&realm, k) {
                    prop_assert_eq!(
                        got.as_ref(),
                        expected.as_slice(),
                        "surviving key {:?} must read its latest promoted value", k
                    );
                }
            }
        }
    }

    // TEST_SCENARIOS.md: "Power-law access distribution: hot tier converges to active working set"
    proptest! {
        #[test]
        fn proptest_power_law_converges(seed in any::<u64>()) {
            const CAPACITY: usize = 10;
            let config = TieredConfig {
                hot_tier_capacity: CAPACITY,
                eviction_batch_size: 5,
                promote_sample_rate: 1,
            };
            let tier = HotTier::new(config);
            let realm = RealmId::generate();

            // Create 50 keys but only access 5 of them frequently (Zipfian-like)
            let hot_keys: Vec<Vec<u8>> = (0..5u8).map(|i| vec![i]).collect();
            let cold_keys: Vec<Vec<u8>> = (5..50u8).map(|i| vec![i]).collect();

            // Simple deterministic PRNG for reproducibility
            let mut rng_state = seed;
            let next_u64 = |state: &mut u64| -> u64 {
                *state = state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                *state
            };

            // Simulate Zipfian: 80% of accesses go to hot_keys, 20% to cold_keys
            // On cache miss, promote the entry (simulates cold read → promote flow)
            for _ in 0..500 {
                let r = next_u64(&mut rng_state);
                #[allow(clippy::cast_possible_truncation)]
                let idx = (r as usize) / 10;
                let key = if r % 10 < 8 {
                    &hot_keys[idx % hot_keys.len()]
                } else {
                    &cold_keys[idx % cold_keys.len()]
                };

                // Try to read; if miss, promote (simulates cold path promotion)
                if tier.get(&realm, key).is_none() {
                    tier.promote_now(&realm, key, &[42u8; 8]);
                }

                // Occasional sweep
                if r % 5 == 0 {
                    let _ = tier.clock_sweep_step();
                }
            }

            // Convergence to the active working set, asserted as *retention under
            // cold-stream pressure*.
            //
            // Two earlier framings of this assertion were both bad, and both are
            // worth recording so they are not reintroduced:
            //
            //   * `hot_in_tier >= 1` after the Zipfian phase was random-chance
            //     level (hot keys are 10% of the keyspace and capacity is 10, so
            //     ≈1 resident is expected with no locality at all).
            //   * "touch each hot key once, then require all 5 resident" is not a
            //     property CLOCK provides and failed for ~1 seed in N. Entering
            //     that round the tier holds reference bits left by the Zipfian
            //     phase, and each promotion's `evict_locked` clears bits as it
            //     scans, so a key promoted early in the round can be evicted by a
            //     later promotion in the same round. That is second-chance
            //     behaviour working as designed, not a defect.
            //
            // Measured on this workload, hot-vs-cold *hit rate* after the Zipfian
            // phase (≈0.91 vs ≈0.10) does not discriminate either: because every
            // miss re-promotes, the numbers are identical whether eviction honours
            // the reference bit, ignores it, or inverts it. So the assertion below
            // instead drives the case eviction policy actually decides — a working
            // set that is *being used* while new cold data streams in:
            //
            //   for each cold entry still resident: re-read all 5 hot keys (sets
            //   their reference bits), then promote one never-seen intruder key.
            //
            // The tier is at capacity, so each intruder forces an eviction, and a
            // tier with locality must spend those evictions on the cold/intruder
            // entries rather than on the working set.
            //
            // Residency is averaged over the rounds rather than asserted per round:
            // when *every* resident entry is referenced, CLOCK legitimately falls
            // back to evicting at the hand, which can take a hot key for one round.
            // Averaging tolerates that without tolerating a policy that keeps doing
            // it. Measured discrimination, threshold 0.90:
            //
            //   as-shipped CLOCK                              residency 1.000 (pass)
            //   evict *referenced* entries (locality inverted) residency 0.800 (fail)
            //   evict at the hand, ignoring the reference bit  residency ≥0.90 (pass)
            //
            // So this catches a tier that actively works against locality; it does
            // not claim to separate CLOCK from FIFO — with promote-on-miss and a
            // working set half the capacity, FIFO retains it too. Do not read a
            // pass here as evidence the reference bit is honoured; the dedicated
            // unit tests (`hot_tier_recently_accessed_remains_hot`,
            // `clock_lru_evicts_least_recently_used`) cover that.
            // Intruder keys are outside both hot_keys (0..5) and cold_keys (5..50),
            // so every one of them is a genuine first-touch admission.
            const ROUNDS: usize = 40;
            let mut resident_total = 0usize;
            for i in 0..ROUNDS {
                for key in &hot_keys {
                    if tier.get(&realm, key).is_none() {
                        tier.promote_now(&realm, key, &[42u8; 8]);
                    }
                }
                #[allow(clippy::cast_possible_truncation)]
                tier.promote_now(&realm, &[200u8, i as u8], &[7u8; 8]);
                resident_total += hot_keys.iter().filter(|k| tier.contains(&realm, k)).count();
            }
            #[allow(clippy::cast_precision_loss)]
            let residency = resident_total as f64 / (ROUNDS * hot_keys.len()) as f64;
            prop_assert!(
                residency >= 0.90,
                "actively-used working set residency {:.3} < 0.90 over {} rounds of \
                 cold-stream pressure at capacity {}",
                residency, ROUNDS, CAPACITY,
            );
        }
    }

    // ===== Phase C: Simulation tests — see simulation/ crate =====
    // ===== Phase D: Benchmarks — see benches/tiered_storage.rs =====
}
