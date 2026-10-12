//! The block cache holds no more heap than `storage.block_cache_bytes` (#445).
//!
//! The cache charged each decrypted block at its plaintext length, but it kept
//! the block's entries decoded: a key buffer and a value buffer for each entry,
//! plus the list of entries. For small rows that is about 1.7 times the
//! plaintext. A heaptrack run of a 12-hour soak with a 32 MiB cache found
//! 57.6 MB of blocks in it.
//!
//! The test writes several times the cache size to an SST file, reads every key
//! once so that the cache fills, and measures the live heap that the reads
//! leave behind.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};

use hearth::core::RealmId;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

// ── Live heap of the whole process ───────────────────────────────────────────

/// Live heap bytes allocated through [`LiveAllocator`].
static LIVE: AtomicIsize = AtomicIsize::new(0);

/// A `System`-backed allocator that tracks the live heap of every thread.
struct LiveAllocator;

// SAFETY: every method forwards to `System` with the same `Layout`; the only
// added work is relaxed atomic bookkeeping, which cannot affect the pointers.
unsafe impl GlobalAlloc for LiveAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarding unchanged to the system allocator.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            LIVE.fetch_add(layout.size().cast_signed(), Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarding unchanged to the system allocator.
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size().cast_signed(), Ordering::Relaxed);
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarding unchanged to the system allocator.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            LIVE.fetch_add(layout.size().cast_signed(), Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: forwarding unchanged to the system allocator.
        let new = unsafe { System.realloc(ptr, layout, new_size) };
        if !new.is_null() {
            LIVE.fetch_add(
                new_size.cast_signed() - layout.size().cast_signed(),
                Ordering::Relaxed,
            );
        }
        new
    }
}

#[global_allocator]
static ALLOCATOR: LiveAllocator = LiveAllocator;

// ── Workload ─────────────────────────────────────────────────────────────────

/// The block cache budget of this test.
const CACHE_BYTES: usize = 4 * 1024 * 1024;
/// A small row, as most of Hearth's rows are: about 120 bytes in the SST.
const VALUE_BYTES: usize = 64;
/// About 7 MB of rows: several times the cache.
const ROWS: usize = 60_000;
/// Entries per `put_batch`.
const BATCH: usize = 1_000;

fn key(i: usize) -> Vec<u8> {
    format!("user:{i:012}").into_bytes()
}

#[test]
#[allow(clippy::cast_precision_loss)] // the ratio in the failure message only
fn the_block_cache_holds_no_more_heap_than_its_budget() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = StorageConfig::dev(dir.path().to_path_buf());
    config.compaction.enabled = false;
    config.block_cache_bytes = CACHE_BYTES;
    // Reads promote rows into the hot tier; keep it too small to matter.
    config.set_hot_tier_capacity(16);
    let engine = EmbeddedStorageEngine::open(config).expect("open engine");
    let realm = RealmId::generate();

    let value = vec![b'v'; VALUE_BYTES];
    for start in (0..ROWS).step_by(BATCH) {
        let batch: Vec<(Vec<u8>, Vec<u8>)> = (start..start + BATCH)
            .map(|i| (key(i), value.clone()))
            .collect();
        engine.put_batch(&realm, &batch).expect("put_batch");
    }
    engine.flush_memtable().expect("flush");

    let before = LIVE.load(Ordering::Relaxed);
    for i in 0..ROWS {
        let row = engine.get(&realm, &key(i)).expect("get");
        assert_eq!(row.as_deref(), Some(value.as_slice()), "row {i}");
    }
    let held = LIVE.load(Ordering::Relaxed) - before;

    // The cache may admit one block over its budget in each of its shards.
    let limit = (CACHE_BYTES + CACHE_BYTES / 10).cast_signed();
    assert!(
        held <= limit,
        "a full {CACHE_BYTES}-byte block cache held {held} bytes of heap ({:.2}x its budget)",
        held as f64 / CACHE_BYTES as f64
    );
    // The reads must have filled the cache, or the check above proves nothing.
    assert!(
        held > (CACHE_BYTES / 2).cast_signed(),
        "the reads left only {held} bytes in a {CACHE_BYTES}-byte cache"
    );
}
