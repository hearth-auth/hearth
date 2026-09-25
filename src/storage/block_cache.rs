//! Bounded, sharded cache of decrypted SST data blocks (HEA-1914).
//!
//! The v3 SST reader keeps only a small footer index resident and decrypts
//! individual ~4 KiB data blocks on demand. Without a bound on decrypted-block
//! residency the working set would still grow with the corpus, so decrypted
//! blocks live here behind a fixed byte budget shared by every reader in the
//! process.
//!
//! ## Concurrency
//!
//! Cold-tier reads are **not** the hot path, but the cache still must not
//! serialize every read through a single lock (CLAUDE.md). Lookups are
//! therefore lock-free: each shard's map is an [`EpochCell`], so a cache **hit**
//! only loads the map pointer, clones an `Arc`, and sets a relaxed atomic
//! reference bit — no mutex. A per-shard `Mutex` is taken only on a **miss**
//! insert / eviction, which already pays for a decrypt and is off the hot path.
//!
//! Eviction is CLOCK (second-chance): each cached block carries a `referenced`
//! bit set on every hit and cleared by the eviction sweep, approximating LRU
//! without touching the shard lock on reads.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::core::EpochCell;
use crate::storage::memtable::{CompositeKey, MemtableValue};

/// Number of independent shards. A power of two so the index mask is a cheap
/// bitwise AND.
const SHARD_COUNT: usize = 16;

/// Identifies one decrypted block: the owning reader's unique open id plus the
/// block's ordinal position within that file.
///
/// The key is the per-open `reader_id`, **not** the SST file number, because
/// partial compaction reuses a run's file number for its rewritten output
/// (HEA-1885). Keying by file number would let a freshly compacted file read a
/// stale, differently-laid-out block from the pre-compaction file. Each
/// physical open gets a fresh monotonic `reader_id`, so no such collision is
/// possible; orphaned blocks from a replaced reader simply age out via CLOCK.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) struct BlockId {
    /// Unique id assigned when the owning `SstReader` was opened.
    pub reader_id: u64,
    /// Zero-based index of the block within the SST's data section.
    pub block_index: u32,
}

/// A decrypted, parsed SST data block held in the cache.
pub(crate) struct CachedBlock {
    /// Entries decoded from the block plaintext, sorted by `CompositeKey`.
    pub entries: Vec<(CompositeKey, MemtableValue)>,
    /// Plaintext byte weight used for cache-budget accounting.
    pub weight: usize,
    /// CLOCK reference bit — set on every cache hit (lock-free) and cleared by
    /// the eviction sweep. Lets hits avoid taking the shard lock.
    referenced: AtomicBool,
}

impl CachedBlock {
    /// Builds a cache entry from decoded block entries, weighted by the block's
    /// decrypted plaintext length.
    pub(crate) fn new(entries: Vec<(CompositeKey, MemtableValue)>, plaintext_len: usize) -> Self {
        Self {
            entries,
            weight: plaintext_len,
            referenced: AtomicBool::new(true),
        }
    }

    /// Records a hit on this block (lock-free; CLOCK reference bit).
    fn mark_referenced(&self) {
        self.referenced.store(true, Ordering::Relaxed);
    }
}

/// One shard of the block cache.
struct Shard {
    /// Lock-free read map. Rebuilt-and-swapped on every insert/eviction.
    map: EpochCell<HashMap<BlockId, Arc<CachedBlock>>>,
    /// Eviction bookkeeping — touched only on miss-insert, never on a hit.
    inner: Mutex<ShardInner>,
}

/// Per-shard eviction state, guarded by the shard mutex.
struct ShardInner {
    /// CLOCK hand order of resident block ids.
    clock: VecDeque<BlockId>,
    /// Current resident weight (sum of cached block plaintext lengths).
    bytes: usize,
}

/// A process-wide, byte-bounded cache of decrypted SST blocks.
pub(crate) struct BlockCache {
    shards: Vec<Shard>,
    /// Per-shard byte budget (`total_budget / SHARD_COUNT`, at least one block).
    shard_cap_bytes: usize,
}

impl BlockCache {
    /// Creates a cache with the given total byte budget, split evenly across
    /// shards. A budget of zero still admits at least a minimal per-shard cap so
    /// point lookups make progress (blocks are inserted then immediately
    /// eligible for eviction).
    pub(crate) fn new(total_budget_bytes: usize) -> Self {
        let shard_cap_bytes = (total_budget_bytes / SHARD_COUNT).max(1);
        let shards = (0..SHARD_COUNT)
            .map(|_| Shard {
                map: EpochCell::from_pointee(HashMap::new()),
                inner: Mutex::new(ShardInner {
                    clock: VecDeque::new(),
                    bytes: 0,
                }),
            })
            .collect();
        Self {
            shards,
            shard_cap_bytes,
        }
    }

    /// Selects the shard for a block id via a cheap integer mix.
    fn shard_idx(&self, id: BlockId) -> usize {
        // Mix the reader id and block index; SHARD_COUNT is a power of two.
        let h = id
            .reader_id
            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
            .wrapping_add(u64::from(id.block_index).wrapping_mul(0x0000_0100_0000_01b3));
        (h as usize) & (SHARD_COUNT - 1)
    }

    /// Looks up a cached block. Lock-free; sets the CLOCK reference bit on a hit.
    pub(crate) fn get(&self, id: BlockId) -> Option<Arc<CachedBlock>> {
        let shard = &self.shards[self.shard_idx(id)];
        let map = shard.map.load();
        map.get(&id).map(|block| {
            block.mark_referenced();
            Arc::clone(block)
        })
    }

    /// Inserts a freshly decrypted block, evicting via CLOCK to stay within the
    /// per-shard byte budget. A concurrent insert of the same id is a no-op.
    pub(crate) fn insert(&self, id: BlockId, block: Arc<CachedBlock>) {
        let shard = &self.shards[self.shard_idx(id)];
        let Ok(mut inner) = shard.inner.lock() else {
            // A poisoned shard lock only disables caching for that shard; the
            // caller already holds the decrypted block, so correctness is
            // unaffected. Skip the insert rather than panic on the read path.
            return;
        };

        let current = shard.map.load_full();
        if current.contains_key(&id) {
            return;
        }
        let mut new_map = HashMap::clone(&current);

        // CLOCK eviction. Bound the scan so a storm of concurrent hits
        // continually re-setting reference bits cannot spin forever; on the
        // bound we simply admit the block slightly over budget.
        let mut scans = 0usize;
        let scan_limit = inner.clock.len().saturating_mul(2).saturating_add(1);
        while inner.bytes + block.weight > self.shard_cap_bytes
            && !inner.clock.is_empty()
            && scans < scan_limit
        {
            scans += 1;
            let Some(victim) = inner.clock.pop_front() else {
                break;
            };
            let Some(victim_block) = new_map.get(&victim) else {
                continue; // already gone
            };
            if victim_block.referenced.swap(false, Ordering::Relaxed) {
                inner.clock.push_back(victim); // second chance
                continue;
            }
            let freed = victim_block.weight;
            new_map.remove(&victim);
            inner.bytes = inner.bytes.saturating_sub(freed);
        }

        new_map.insert(id, Arc::clone(&block));
        inner.bytes += block.weight;
        inner.clock.push_back(id);
        shard.map.store(Arc::new(new_map));
    }

    /// Total resident decrypted-block bytes across all shards (test/metrics).
    pub(crate) fn resident_bytes(&self) -> usize {
        self.shards
            .iter()
            .filter_map(|s| s.inner.lock().ok().map(|i| i.bytes))
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::RealmId;

    fn block(realm: &RealmId, key: &[u8], weight: usize) -> Arc<CachedBlock> {
        let entries = vec![(
            CompositeKey::new(realm.clone(), key.to_vec()),
            MemtableValue::Data(vec![0u8; 8]),
        )];
        Arc::new(CachedBlock::new(entries, weight))
    }

    #[test]
    fn insert_then_get_returns_block() {
        let cache = BlockCache::new(1 << 20);
        let realm = RealmId::generate();
        let id = BlockId {
            reader_id: 1,
            block_index: 0,
        };
        cache.insert(id, block(&realm, b"k", 64));
        assert!(cache.get(id).is_some());
        assert!(cache
            .get(BlockId {
                reader_id: 1,
                block_index: 99
            })
            .is_none());
    }

    #[test]
    fn eviction_keeps_resident_bytes_bounded() {
        // Small budget; insert far more block-bytes than fit.
        let budget = SHARD_COUNT * 4096;
        let cache = BlockCache::new(budget);
        let realm = RealmId::generate();
        for i in 0..10_000u32 {
            let id = BlockId {
                reader_id: 7,
                block_index: i,
            };
            cache.insert(id, block(&realm, format!("k{i}").as_bytes(), 512));
        }
        // Resident must never blow past the budget by more than one block per
        // shard of slack (the over-admit bound).
        let slack = SHARD_COUNT * 512;
        assert!(
            cache.resident_bytes() <= budget + slack,
            "resident {} exceeds budget {} + slack {}",
            cache.resident_bytes(),
            budget,
            slack
        );
    }

    /// A hit loads its shard's map with no lock while inserts rebuild and
    /// replace it (an `ArcSwap` until task 26.5, an `EpochCell` now). Readers
    /// racing evicting inserts on one shard must only ever get back the block
    /// cached under the id they asked for. Run several copies at once with
    /// glibc's heap checking on (`MALLOC_CHECK_=3` with `libc_malloc_debug.so`
    /// preloaded, plus `MALLOC_PERTURB_=165`) and a use-after-free in the cell
    /// aborts (task 26.1).
    #[test]
    fn concurrent_hits_only_return_the_block_cached_under_their_id() {
        const IDS: usize = 24;
        const ROUNDS: usize = 150;
        const WEIGHT: usize = 64;

        // Room for four blocks per shard, and every id below lands in the same
        // shard, so nearly every insert evicts another id's block.
        let cache = Arc::new(BlockCache::new(SHARD_COUNT * WEIGHT * 4));
        let target = cache.shard_idx(BlockId {
            reader_id: 9,
            block_index: 0,
        });
        let ids: Arc<Vec<BlockId>> = Arc::new(
            (0_u32..)
                .map(|block_index| BlockId {
                    reader_id: 9,
                    block_index,
                })
                .filter(|id| cache.shard_idx(*id) == target)
                .take(IDS)
                .collect(),
        );
        let key_of = |id: BlockId| format!("{}:{}", id.reader_id, id.block_index).into_bytes();
        let realm = RealmId::generate();
        let stop = Arc::new(AtomicBool::new(false));

        let readers: Vec<_> = (0..4)
            .map(|_| {
                let (cache, ids, stop) = (Arc::clone(&cache), Arc::clone(&ids), Arc::clone(&stop));
                std::thread::spawn(move || {
                    let mut hits = 0_u64;
                    while !stop.load(Ordering::Relaxed) {
                        for id in ids.iter() {
                            if let Some(block) = cache.get(*id) {
                                hits += 1;
                                assert_eq!(
                                    block.entries[0].0.key(),
                                    key_of(*id).as_slice(),
                                    "a hit returned another id's block"
                                );
                            }
                        }
                    }
                    hits
                })
            })
            .collect();

        let writers: Vec<_> = (0..2)
            .map(|w| {
                let (cache, ids, realm) = (Arc::clone(&cache), Arc::clone(&ids), realm.clone());
                std::thread::spawn(move || {
                    for _ in 0..ROUNDS {
                        for id in ids.iter().skip(w).step_by(2) {
                            cache.insert(*id, block(&realm, &key_of(*id), WEIGHT));
                        }
                    }
                })
            })
            .collect();

        for w in writers {
            w.join().expect("writer thread");
        }
        stop.store(true, Ordering::Relaxed);
        let hits: u64 = readers
            .into_iter()
            .map(|r| r.join().expect("reader thread"))
            .sum();
        assert!(hits > 0, "the readers never hit: nothing was checked");

        // Settled: an insert of an evicted id publishes again.
        let last = ids[IDS - 1];
        cache.insert(last, block(&realm, &key_of(last), WEIGHT));
        assert_eq!(
            cache.get(last).map(|b| b.entries[0].0.key().to_vec()),
            Some(key_of(last)),
            "an insert after the storm did not publish"
        );
    }

    #[test]
    fn zero_budget_still_admits_and_stays_tiny() {
        let cache = BlockCache::new(0);
        let realm = RealmId::generate();
        for i in 0..100u32 {
            cache.insert(
                BlockId {
                    reader_id: 1,
                    block_index: i,
                },
                block(&realm, b"k", 128),
            );
        }
        // With a ~1-byte-per-shard cap every insert evicts almost immediately;
        // residency stays minuscule regardless of how many blocks pass through.
        assert!(cache.resident_bytes() <= SHARD_COUNT * 128);
    }
}
