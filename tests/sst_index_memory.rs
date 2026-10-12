//! The heap of open SST files does not grow with the data they hold (#445).
//!
//! Each open SST file kept its whole block index (one entry per ~4 KiB block)
//! and its whole Bloom filter (10 bits per row) on the heap. So the heap grew
//! with every row ever stored: about 21 MiB an hour at 120 sign-in journeys a
//! second, for as long as the rows are kept. The filters and the block index
//! are now stored in pieces in the file and load through the block cache. Only
//! a small top-level index stays on the heap.
//!
//! The test flushes about 4 MB of rows, then about 12 MB more, and measures the
//! live heap after each flush.

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

/// A small row, as most of Hearth's rows are: about 140 bytes in the SST.
const VALUE_BYTES: usize = 100;
/// About 4 MB of rows.
const FIRST_ROWS: usize = 28_000;
/// About 12 MB more.
const SECOND_ROWS: usize = 84_000;
/// Entries per `put_batch`.
const BATCH: usize = 1_000;

fn key(i: usize) -> Vec<u8> {
    format!("audit:evt:{i:012}").into_bytes()
}

fn write_rows(engine: &EmbeddedStorageEngine, realm: &RealmId, rows: std::ops::Range<usize>) {
    let value = vec![b'v'; VALUE_BYTES];
    for start in rows.clone().step_by(BATCH) {
        let batch: Vec<(Vec<u8>, Vec<u8>)> = (start..(start + BATCH).min(rows.end))
            .map(|i| (key(i), value.clone()))
            .collect();
        engine.put_batch(realm, &batch).expect("put_batch");
    }
}

fn sst_bytes(dir: &std::path::Path) -> u64 {
    std::fs::read_dir(dir)
        .expect("read data dir")
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "sst"))
        .map(|e| e.metadata().expect("metadata").len())
        .sum()
}

#[test]
fn the_heap_of_open_sst_files_does_not_grow_with_their_data() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = StorageConfig::dev(dir.path().to_path_buf());
    config.compaction.enabled = false;
    config.set_memtable_flush_bytes(256 * 1024 * 1024);
    config.set_hot_tier_capacity(16);
    let engine = EmbeddedStorageEngine::open(config).expect("open engine");
    let realm = RealmId::generate();
    let base = LIVE.load(Ordering::Relaxed);

    write_rows(&engine, &realm, 0..FIRST_ROWS);
    engine.flush_memtable().expect("first flush");
    let after_first = LIVE.load(Ordering::Relaxed) - base;
    let first_bytes = sst_bytes(dir.path());

    write_rows(&engine, &realm, FIRST_ROWS..FIRST_ROWS + SECOND_ROWS);
    engine.flush_memtable().expect("second flush");
    let after_second = LIVE.load(Ordering::Relaxed) - base;
    let added_bytes = sst_bytes(dir.path()) - first_bytes;

    assert!(
        added_bytes > 2 * first_bytes,
        "precondition: the second flush wrote {added_bytes} bytes, the first {first_bytes}"
    );
    // The second file adds one reader and its top-level index: a few hundred
    // bytes. A block index and Bloom filter on the heap for the added rows took
    // about 2.7 % of the added bytes, here about 340 KB.
    let grown = after_second - after_first;
    assert!(
        grown < 64 * 1024,
        "{added_bytes} more bytes of SST data took {grown} more bytes of heap \
         (heap after the first flush: {after_first}, after the second: {after_second})"
    );
}
