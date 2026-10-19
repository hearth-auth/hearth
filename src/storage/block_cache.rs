//! Bounded, sharded cache of decrypted SST blocks (HEA-1914, #445).
//!
//! An SST reader decrypts individual ~4 KiB data blocks on demand, and a v4
//! reader also its index and filter blocks. Without a bound on decrypted-block
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
//! Eviction is CLOCK: each cached block carries a count of chances, reset on
//! every hit and lowered by the eviction sweep, which evicts a block with no
//! chance left. This approximates LRU without touching the shard lock on
//! reads. An index or filter block gets [`METADATA_CHANCES`] chances and a data
//! block one: every lookup in a partition's range reads its index and filter
//! blocks, so a stream of data blocks read once must not push them out.
//!
//! Each insert copies its shard's map, so the shard count grows with the
//! budget: a shard holds about [`SHARD_TARGET_BYTES`] of blocks, a few hundred
//! of them, and an insert copies only those.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use crate::core::EpochCell;
use crate::storage::sst::Block;

/// The fewest shards a cache has, whatever its budget.
const MIN_SHARDS: usize = 16;

/// The most shards a cache has.
const MAX_SHARDS: usize = 256;

/// The budget of one shard that the shard count aims at.
const SHARD_TARGET_BYTES: usize = 1 << 20;

/// The chances an index or filter block gets before eviction; a data block
/// gets one.
const METADATA_CHANCES: u8 = 3;

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

/// A decrypted SST block held in the cache.
pub(crate) struct CachedBlock {
    /// The decoded block.
    pub block: Block,
    /// The heap this block holds while it is cached, charged against the
    /// budget: its buffers plus [`ENTRY_OVERHEAD`].
    pub weight: usize,
    /// The chances this block gets after a hit: [`METADATA_CHANCES`] for an
    /// index or filter block, 1 for a data block.
    max_chances: u8,
    /// CLOCK chances left — reset on every cache hit (lock-free) and lowered
    /// by the eviction sweep. Lets hits avoid taking the shard lock.
    chances: AtomicU8,
}

/// The heap the cache holds for each block besides the block's buffers: the
/// `Arc` allocation of the [`CachedBlock`], its slot in the shard map, and its
/// place in the CLOCK queue.
const ENTRY_OVERHEAD: usize = 2 * std::mem::size_of::<usize>()
    + std::mem::size_of::<CachedBlock>()
    + std::mem::size_of::<(BlockId, Arc<CachedBlock>)>()
    + std::mem::size_of::<BlockId>();

impl CachedBlock {
    /// Builds a cache entry, weighted by the heap the block holds (#445).
    pub(crate) fn new(block: Block) -> Self {
        let weight = block.heap_bytes() + ENTRY_OVERHEAD;
        Self::with_weight(block, weight)
    }

    /// Builds a cache entry with a chosen weight.
    fn with_weight(block: Block, weight: usize) -> Self {
        let max_chances = if block.is_metadata() {
            METADATA_CHANCES
        } else {
            1
        };
        Self {
            block,
            weight,
            max_chances,
            chances: AtomicU8::new(max_chances),
        }
    }

    /// Records a hit on this block (lock-free; resets its CLOCK chances).
    fn mark_referenced(&self) {
        self.chances.store(self.max_chances, Ordering::Relaxed);
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
    /// Current resident weight (the sum of the cached blocks' weights).
    bytes: usize,
}

/// A process-wide, byte-bounded cache of decrypted SST blocks.
pub(crate) struct BlockCache {
    /// A power of two in `[MIN_SHARDS, MAX_SHARDS]`.
    shards: Vec<Shard>,
    /// Per-shard byte budget (`total_budget / shards.len()`, at least 1).
    shard_cap_bytes: usize,
}

impl BlockCache {
    /// Creates a cache with the given total byte budget, split evenly across
    /// shards. A budget of zero still admits at least a minimal per-shard cap so
    /// point lookups make progress (blocks are inserted then immediately
    /// eligible for eviction).
    pub(crate) fn new(total_budget_bytes: usize) -> Self {
        let wanted = (total_budget_bytes / SHARD_TARGET_BYTES).clamp(MIN_SHARDS, MAX_SHARDS);
        // The largest power of two at or below `wanted`.
        let shard_count = 1usize << wanted.ilog2();
        let shard_cap_bytes = (total_budget_bytes / shard_count).max(1);
        let shards = (0..shard_count)
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
        // Mix the reader id and block index; the shard count is a power of two.
        let h = id
            .reader_id
            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
            .wrapping_add(u64::from(id.block_index).wrapping_mul(0x0000_0100_0000_01b3));
        (h as usize) & (self.shards.len() - 1)
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
        // continually resetting chances cannot spin forever; on the bound we
        // simply admit the block slightly over budget.
        let mut scans = 0usize;
        let scan_limit = inner
            .clock
            .len()
            .saturating_mul(usize::from(METADATA_CHANCES) + 1)
            .saturating_add(1);
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
            let chances = victim_block.chances.load(Ordering::Relaxed);
            if chances > 0 {
                victim_block.chances.store(chances - 1, Ordering::Relaxed);
                inner.clock.push_back(victim); // another chance
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

    use crate::storage::memtable::{CompositeKey, MemtableValue};
    use crate::storage::sst::DataBlock;
    use std::sync::atomic::AtomicBool;

    fn data_block(realm: &RealmId, key: &[u8]) -> Block {
        let entries = vec![(
            CompositeKey::new(realm.clone(), key.to_vec()),
            MemtableValue::Data(vec![0u8; 8]),
        )];
        Block::Data(DataBlock::from_entries(&entries))
    }

    fn block(realm: &RealmId, key: &[u8], weight: usize) -> Arc<CachedBlock> {
        Arc::new(CachedBlock::with_weight(data_block(realm, key), weight))
    }

    /// Ids of `count` blocks of reader `reader_id` that all land in one shard.
    fn ids_in_one_shard(cache: &BlockCache, reader_id: u64, count: usize) -> Vec<BlockId> {
        let target = cache.shard_idx(BlockId {
            reader_id,
            block_index: 0,
        });
        (0_u32..)
            .map(|block_index| BlockId {
                reader_id,
                block_index,
            })
            .filter(|id| cache.shard_idx(*id) == target)
            .take(count)
            .collect()
    }

    /// Every lookup in a partition's range reads its index and filter blocks,
    /// while a scan or a spread of cold lookups reads each data block once. An
    /// index or filter block must outlive data blocks that arrive after it,
    /// even if neither is read again (#445).
    #[test]
    fn a_metadata_block_outlives_data_blocks_inserted_after_it() {
        const WEIGHT: usize = 64;
        // Room for four blocks in each shard.
        let cache = BlockCache::new(MIN_SHARDS * WEIGHT * 4);
        let realm = RealmId::generate();
        let ids = ids_in_one_shard(&cache, 3, 7);
        let filter = Block::Filter(crate::storage::sst::BloomFilter::for_test());
        cache.insert(ids[0], Arc::new(CachedBlock::with_weight(filter, WEIGHT)));
        cache.insert(ids[1], block(&realm, b"first data", WEIGHT));
        // Five more data blocks: a one-chance CLOCK evicts the oldest block, the
        // filter block, at the fourth of them.
        for id in &ids[2..] {
            cache.insert(*id, block(&realm, b"later data", WEIGHT));
        }
        assert!(
            cache.get(ids[0]).is_some(),
            "five data blocks pushed out the filter block"
        );
        assert!(
            cache.get(ids[1]).is_none(),
            "the data block inserted after the filter block was not pushed out"
        );
    }

    #[test]
    fn the_shard_count_grows_with_the_budget() {
        assert_eq!(BlockCache::new(0).shards.len(), MIN_SHARDS);
        assert_eq!(BlockCache::new(32 << 20).shards.len(), 32);
        assert_eq!(BlockCache::new(48 << 20).shards.len(), 32, "a power of two");
        assert_eq!(BlockCache::new(256 << 20).shards.len(), 256);
        assert_eq!(BlockCache::new(1 << 40).shards.len(), MAX_SHARDS);
    }

    #[test]
    fn a_block_is_charged_at_least_the_heap_of_its_buffers() {
        let realm = RealmId::generate();
        let entries: Vec<_> = (0..30)
            .map(|i| {
                (
                    CompositeKey::new(realm.clone(), format!("key-{i:04}").into_bytes()),
                    MemtableValue::Data(vec![b'v'; 64]),
                )
            })
            .collect();
        let block = Block::Data(DataBlock::from_entries(&entries));
        let heap = block.heap_bytes();
        assert!(
            heap >= 30 * (25 + 8 + 64),
            "the plaintext alone is that long"
        );
        assert!(CachedBlock::new(block).weight > heap);
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
        let budget = MIN_SHARDS * 4096;
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
        let slack = MIN_SHARDS * 512;
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
    /// aborts (task 26.1). `make heap-check` runs it that way (CI: the
    /// `quality` job).
    #[test]
    fn concurrent_hits_only_return_the_block_cached_under_their_id() {
        const IDS: usize = 24;
        const ROUNDS: usize = 150;
        const WEIGHT: usize = 64;

        // Room for four blocks per shard, and every id below lands in the same
        // shard, so nearly every insert evicts another id's block.
        let cache = Arc::new(BlockCache::new(MIN_SHARDS * WEIGHT * 4));
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
                                    block
                                        .block
                                        .data()
                                        .ok()
                                        .and_then(|b| b.entry(0))
                                        .map(|e| e.key().to_vec()),
                                    Some(key_of(*id)),
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
            cache.get(last).and_then(|b| {
                b.block
                    .data()
                    .ok()
                    .and_then(|d| d.entry(0))
                    .map(|e| e.key().to_vec())
            }),
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
        assert!(cache.resident_bytes() <= MIN_SHARDS * 128);
    }

    /// `hearth_storage_block_cache_bytes` is the bytes the cache charges
    /// against its budget. It follows inserts and evictions, and a dropped
    /// cache takes its bytes out of it (#445).
    #[test]
    #[allow(clippy::cast_precision_loss)] // test sizes are far below 2^52
    fn the_bytes_gauge_follows_inserts_and_evictions() {
        const WEIGHT: usize = 100;
        let gauge = || crate::metrics::metrics().storage_block_cache_bytes.get();
        let base = gauge();
        // Room for four blocks in each shard.
        let cache = BlockCache::new(MIN_SHARDS * WEIGHT * 4);
        let realm = RealmId::generate();
        let ids = ids_in_one_shard(&cache, 5, 10);

        for (n, id) in ids.iter().enumerate() {
            cache.insert(*id, block(&realm, b"k", WEIGHT));
            assert_eq!(
                gauge() - base,
                cache.resident_bytes() as f64,
                "after insert {n}"
            );
        }
        assert_eq!(
            cache.resident_bytes(),
            4 * WEIGHT,
            "evictions kept the shard at its budget"
        );

        cache.insert(ids[9], block(&realm, b"k", WEIGHT));
        assert_eq!(gauge() - base, (4 * WEIGHT) as f64, "a repeat insert");

        let other_shard = (0_u32..)
            .map(|block_index| BlockId {
                reader_id: 6,
                block_index,
            })
            .find(|id| cache.shard_idx(*id) != cache.shard_idx(ids[0]))
            .expect("the cache has more than one shard");
        cache.insert(other_shard, block(&realm, b"k", 3 * WEIGHT));
        assert_eq!(gauge() - base, cache.resident_bytes() as f64);
        assert_eq!(cache.resident_bytes(), 7 * WEIGHT, "a second shard");

        drop(cache);
        assert_eq!(gauge() - base, 0.0);
    }
}
