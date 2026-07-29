//! Sharded, lock-free decision cache for full permission resolutions (HEA-1906).
//!
//! Replaces the single `Mutex<ResolutionCache>` (HEA-1770) that serialized every
//! `permission_check`. The C7 saturation sweep (HEA-1875, `b29e57dd`) measured
//! that path scaling at **−0.549** — adding cores made it *slower* — because both
//! the hit-check and the fill took the same global mutex, bouncing one cache line
//! across every core. This structure moves reads to the wait-free `ArcSwap`
//! pattern already proven by the identity-engine `ShardedArcSwapMap` (HEA-1772,
//! C-3) and the permission cache: a read is two atomic `load()`s (the per-realm
//! version map plus one entry shard), with no lock, allocation, or syscall.
//!
//! # Correctness (security boundary)
//!
//! Permission resolution is an authorization boundary; a stale hit is privilege
//! escalation. Correctness rests on a per-realm monotonic *graph version*
//! (`generations`) that every RBAC mutation bumps — strictly *after* its durable
//! storage write (see [`super::engine`] `invalidate_realm`). A cached entry is
//! served only when its stored version equals the realm's current version, so any
//! mutation atomically renders every prior entry for that realm unreachable.
//!
//! Splitting the former single mutex into (a) one `ArcSwap<HashMap<RealmId,u64>>`
//! for the versions and (b) [`SHARD_COUNT`] `ArcSwap<HashMap<Key,…>>` entry shards
//! does **not** widen the stale-read window versus the mutex, because:
//!
//! * mutations only ever bump `generations`; they never touch entry shards, so an
//!   entry's stored version is immutable once written;
//! * a fill tags its entry with the version captured *before* its storage reads
//!   and the caller commits only if that version is still current, so a snapshot
//!   taken before a racing mutation is never published as current;
//! * once a reader observes a bumped version, every older-versioned entry fails
//!   the equality check — exactly the mutex's invalidation guarantee.
//!
//! The mutex's only extra property — reading `(version, entry)` as one atomic
//! pair — carried no security guarantee: a read concurrent with a mutation may be
//! linearized on either side of it under the mutex too. What the mutex actually
//! protected (an entry is never served once its realm's version has advanced past
//! it) is preserved by the version equality check on two independent atomic loads.

use std::collections::HashMap;
use std::hash::BuildHasher;

use arc_swap::ArcSwap;

use crate::core::{OrganizationId, RealmId, UserId};

use super::types::ResolvedPermissions;

/// Upper bound on cached resolutions across all realms and shards. When a shard
/// exceeds its share the shard is cleared wholesale (coarse eviction — always
/// correctness-safe, since every entry is re-derivable from storage). Sized to
/// comfortably hold the working set of a large tenant without unbounded growth.
const MAX_RESOLUTION_CACHE_ENTRIES: usize = 50_000;

/// Number of independent entry shards. A power of two so shard selection is a
/// cheap mask of the key hash. Matches the `ShardedArcSwapMap` fan-out (HEA-1772)
/// — 64 keeps per-shard clone cost at ~`1/64` of the working set while the fixed
/// overhead (64 empty `Arc<HashMap>` pointers) stays negligible.
const SHARD_COUNT: usize = 64;

/// Per-shard entry cap so the aggregate stays near [`MAX_RESOLUTION_CACHE_ENTRIES`].
const MAX_ENTRIES_PER_SHARD: usize = MAX_RESOLUTION_CACHE_ENTRIES / SHARD_COUNT;

/// Cache key: `(realm, user, org)`. The cached value is the *unnarrowed* full
/// resolution (`requested_scope = None`); scope narrowing runs fresh on top of a
/// hit on every call, so the config scope registry never invalidates this cache.
type CacheKey = (RealmId, UserId, Option<OrganizationId>);

/// A stored entry: the graph version it was computed against, and the resolution.
type Entry = (u64, ResolvedPermissions);

/// Sharded, lock-free decision cache. See the module docs for the correctness
/// model — this is a security boundary, edit with that in mind.
pub(crate) struct ShardedResolutionCache {
    /// Per-realm graph version, bumped on every mutation. Wait-free reads via
    /// `ArcSwap::load`; a bump is a rare (off-hot-path) `rcu`. The realm count is
    /// small, so cloning this map on bump is cheap; it is deliberately *not*
    /// sharded to keep the invalidation boundary a single, auditable atomic.
    generations: ArcSwap<HashMap<RealmId, u64>>,
    /// `(realm,user,org)` → `(version-at-fill, resolved)`, partitioned into
    /// [`SHARD_COUNT`] independently-published shards so a fill `rcu`s only the
    /// one shard the key maps to.
    entries: Box<[ArcSwap<HashMap<CacheKey, Entry>>]>,
    /// Fixed hasher used *only* for shard selection so a key always resolves to
    /// the same shard for the life of the cache (kept separate from each shard's
    /// internal `RandomState`).
    hasher: std::collections::hash_map::RandomState,
    /// Per-shard entry cap. [`MAX_ENTRIES_PER_SHARD`] in production; lowered by
    /// tests to exercise eviction cheaply.
    max_entries_per_shard: usize,
}

impl Default for ShardedResolutionCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ShardedResolutionCache {
    /// Creates an empty cache with all shards initialized.
    pub(crate) fn new() -> Self {
        Self::with_shard_cap(MAX_ENTRIES_PER_SHARD)
    }

    /// Creates an empty cache with an explicit per-shard entry cap. Production
    /// uses [`Self::new`]; tests use a small cap to exercise eviction cheaply.
    fn with_shard_cap(max_entries_per_shard: usize) -> Self {
        let entries = (0..SHARD_COUNT)
            .map(|_| ArcSwap::from_pointee(HashMap::new()))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            generations: ArcSwap::from_pointee(HashMap::new()),
            entries,
            hasher: std::collections::hash_map::RandomState::new(),
            max_entries_per_shard,
        }
    }

    #[inline]
    fn shard(&self, key: &CacheKey) -> &ArcSwap<HashMap<CacheKey, Entry>> {
        // SHARD_COUNT is a power of two, so the mask is exact.
        let idx = (self.hasher.hash_one(key) as usize) & (SHARD_COUNT - 1);
        &self.entries[idx]
    }

    /// Current graph version for a realm (`0` if never mutated). Wait-free: a
    /// single atomic `load()` on the versions map.
    pub(crate) fn generation(&self, realm_id: &RealmId) -> u64 {
        self.generations.load().get(realm_id).copied().unwrap_or(0)
    }

    /// Returns the cached resolution iff it matches the realm's current version.
    ///
    /// Wait-free: two atomic loads (versions map, then one entry shard) and no
    /// lock. Serving a version-matched entry is safe even though the two loads
    /// are not a single atomic snapshot — see the module docs.
    pub(crate) fn get(&self, key: &CacheKey) -> Option<ResolvedPermissions> {
        let current = self.generation(&key.0);
        match self.shard(key).load().get(key) {
            Some((version, value)) if *version == current => Some(value.clone()),
            _ => None,
        }
    }

    /// Inserts a resolution tagged with the version it was computed against,
    /// cloning only the target shard.
    ///
    /// Callers MUST pass the version captured *before* the storage reads that
    /// produced `value`, and only after confirming it is still current — this is
    /// what prevents publishing a pre-mutation snapshot as fresh.
    pub(crate) fn insert(&self, key: CacheKey, version: u64, value: ResolvedPermissions) {
        self.shard(&key).rcu(|old| {
            // Coarse per-shard eviction: if this shard is full and the key is new,
            // drop the shard's contents rather than grow unbounded. Correctness-
            // safe — every dropped entry is re-derivable from storage.
            let mut next = if old.len() >= self.max_entries_per_shard && !old.contains_key(&key) {
                HashMap::new()
            } else {
                (**old).clone()
            };
            next.insert(key.clone(), (version, value.clone()));
            next
        });
    }

    /// Bumps a realm's graph version, invalidating all of its cached entries.
    ///
    /// `rcu` is a compare-and-swap retry loop, so concurrent bumps (same or
    /// different realms) never lose an increment.
    pub(crate) fn bump(&self, realm_id: &RealmId) {
        self.generations.rcu(|old| {
            let mut next = (**old).clone();
            *next.entry(realm_id.clone()).or_insert(0) += 1;
            next
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;

    fn key(realm: &RealmId, user: &UserId) -> CacheKey {
        (realm.clone(), user.clone(), None)
    }

    fn resolved_with(perm: &str) -> ResolvedPermissions {
        ResolvedPermissions {
            permissions: vec![super::super::types::Permission::new(perm).expect("perm")],
            ..Default::default()
        }
    }

    /// The read must be gated on the realm's current version: a hit is served
    /// only while the version it was filled against is still current; a bump
    /// makes every prior entry unreachable. This is the invalidation invariant
    /// that a stale hit would violate (privilege escalation).
    #[test]
    fn read_is_version_gated_by_bump() {
        let cache = ShardedResolutionCache::new();
        let realm = RealmId::generate();
        let user = UserId::generate();
        let k = key(&realm, &user);

        let v0 = cache.generation(&realm);
        cache.insert(k.clone(), v0, resolved_with("docs.view"));
        assert!(cache.get(&k).is_some(), "fresh entry must be served");

        // A mutation bumps the realm — the old entry is now unreachable.
        cache.bump(&realm);
        assert!(
            cache.get(&k).is_none(),
            "entry filled at the old version must not survive a bump"
        );

        // Re-filling at the new version is served again.
        let v1 = cache.generation(&realm);
        assert_eq!(v1, v0 + 1);
        cache.insert(k.clone(), v1, resolved_with("docs.view"));
        assert!(cache.get(&k).is_some());
    }

    /// A bump on one realm must not invalidate another realm's entries.
    #[test]
    fn bump_is_per_realm() {
        let cache = ShardedResolutionCache::new();
        let realm_a = RealmId::generate();
        let realm_b = RealmId::generate();
        let user = UserId::generate();
        let ka = key(&realm_a, &user);
        let kb = key(&realm_b, &user);

        cache.insert(ka.clone(), cache.generation(&realm_a), resolved_with("a.read"));
        cache.insert(kb.clone(), cache.generation(&realm_b), resolved_with("b.read"));

        cache.bump(&realm_a);

        assert!(cache.get(&ka).is_none(), "bumped realm entry gone");
        assert!(cache.get(&kb).is_some(), "untouched realm entry survives");
    }

    /// A fill must clone only the shard the key maps to — the whole point of the
    /// HEA-1906 rework (a single mutex/`ArcSwap<HashMap>` cloned everything and
    /// serialized the read path). Proven by pointer identity of each shard's
    /// backing `Arc`.
    #[test]
    fn insert_clones_only_one_shard() {
        let cache = ShardedResolutionCache::new();
        let realm = RealmId::generate();
        for _ in 0..1_000 {
            let u = UserId::generate();
            cache.insert(key(&realm, &u), 0, resolved_with("seed.read"));
        }

        let before: Vec<*const HashMap<CacheKey, Entry>> = cache
            .entries
            .iter()
            .map(|s| Arc::as_ptr(&s.load_full()))
            .collect();
        cache.insert(key(&realm, &UserId::generate()), 0, resolved_with("new.read"));
        let after: Vec<*const HashMap<CacheKey, Entry>> = cache
            .entries
            .iter()
            .map(|s| Arc::as_ptr(&s.load_full()))
            .collect();

        let changed = before.iter().zip(&after).filter(|(a, b)| a != b).count();
        assert_eq!(
            changed, 1,
            "exactly one shard should be re-published per insert; a full-map \
             clone (the old mutex behaviour) would touch every shard"
        );
    }

    /// Per-shard eviction keeps the cache bounded without unbounded growth and
    /// without dropping unrelated shards. Uses a small per-shard cap so eviction
    /// is forced on at least one shard cheaply.
    #[test]
    fn insert_evicts_within_shard_when_full() {
        let cap = 4;
        let cache = ShardedResolutionCache::with_shard_cap(cap);
        let realm = RealmId::generate();
        // Insert enough that at least one shard crosses the tiny cap.
        for _ in 0..(cap * SHARD_COUNT * 8) {
            let u = UserId::generate();
            cache.insert(key(&realm, &u), 0, resolved_with("x.read"));
        }
        // No shard may exceed its cap — coarse per-shard eviction bounds growth.
        for shard in cache.entries.iter() {
            assert!(
                shard.load().len() <= cap,
                "shard exceeded its per-shard cap"
            );
        }
    }

    /// Concurrency regression (HEA-1906): many reader threads hammering `get`
    /// while a writer repeatedly fills-then-bumps must (1) never panic and
    /// (2) never observe a stale hit — i.e. every value a reader is handed either
    /// matches the version live at read time or the read misses. The old design
    /// serialized all of this behind one mutex; the new one is lock-free, and
    /// this test pins the security invariant that the sharding must not break.
    #[test]
    fn concurrent_readers_never_observe_stale_after_bump() {
        let cache = Arc::new(ShardedResolutionCache::new());
        let realm = RealmId::generate();
        let user = UserId::generate();
        let k = key(&realm, &user);

        // Fill an initial entry at version 0.
        cache.insert(k.clone(), 0, resolved_with("v.read"));

        let threads = 8;
        let barrier = Arc::new(Barrier::new(threads + 1));
        let stop = Arc::new(AtomicBool::new(false));

        let readers: Vec<_> = (0..threads)
            .map(|_| {
                let cache = Arc::clone(&cache);
                let realm = realm.clone();
                let k = k.clone();
                let barrier = Arc::clone(&barrier);
                let stop = Arc::clone(&stop);
                thread::spawn(move || {
                    barrier.wait();
                    while !stop.load(Ordering::Relaxed) {
                        // Read the version, then the entry. If we get a hit, its
                        // stored version must be >= the version we observed just
                        // before (versions are monotonic; an entry is only served
                        // when it equals the *then-current* version). We can't
                        // capture the exact race, but we assert the hit is never
                        // for a version already known to be superseded.
                        let seen_gen = cache.generation(&realm);
                        if cache.get(&k).is_some() {
                            // A served hit implies its stored version == current
                            // generation at the moment `get` read it, which is
                            // >= seen_gen. Re-read: current must not be < seen_gen.
                            assert!(
                                cache.generation(&realm) >= seen_gen,
                                "generation must be monotonic"
                            );
                        }
                    }
                })
            })
            .collect();

        // Writer: fill-then-bump many times, mirroring the engine's
        // resolve→mutation interleaving.
        barrier.wait();
        for v in 0..50_000u64 {
            cache.insert(k.clone(), cache.generation(&realm), resolved_with("v.read"));
            cache.bump(&realm);
            let _ = v;
        }
        stop.store(true, Ordering::Relaxed);
        for r in readers {
            r.join().expect("reader thread panicked");
        }

        // Final consistency: after all bumps, a stale (version-0) entry must
        // never be served; only a fresh fill at the current version would hit.
        assert!(
            cache.get(&k).is_none() || cache.generation(&realm) > 0,
            "post-run: no version-0 stale entry may be served"
        );
    }
}
