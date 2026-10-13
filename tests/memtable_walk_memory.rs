//! A walk over the memtable does not keep the rows it passes alive (#445).
//!
//! The range iterator of crossbeam-skiplist 0.1.3 keeps one reference on each
//! entry it passes and never gives it back. So a row that a walk passed was
//! never freed when a later write replaced it (an overwrite or a delete). The
//! cleanup sweep walks expiring rows and then deletes them, and the memtable
//! leaked about 9 MB an hour under sign-in load.
//!
//! Each test writes the same rows again and again. After each write it walks
//! the rows with one storage API, then measures the live heap.

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

/// Rows written, and then walked, in each round.
const ROWS: usize = 2_000;
/// A small row, as most of Hearth's rows are.
const VALUE_BYTES: usize = 100;
/// Entries per `put_batch`.
const BATCH: usize = 500;
/// Rounds of write-then-walk.
const ROUNDS: usize = 12;
/// Rounds before the first measurement: the first rounds size the engine's
/// buffers.
const WARM_UP: usize = 2;
/// A leaked row holds about 250 bytes, so the defect leaks about 500 KB each
/// round. The bound is a fifth of one round's leak.
const MAX_GROWTH_BYTES: isize = 100 * 1024;

/// The key range every walk covers: exactly the rows the test writes.
const START: &[u8] = b"row:";
const END: &[u8] = b"row;";

fn key(i: usize) -> Vec<u8> {
    format!("row:{i:06}").into_bytes()
}

/// An engine that keeps every write in the memtable: no flush, no compaction.
fn open(dir: &std::path::Path) -> EmbeddedStorageEngine {
    let mut config = StorageConfig::dev(dir.to_path_buf());
    config.compaction.enabled = false;
    config.set_memtable_flush_bytes(1 << 30);
    config.set_hot_tier_capacity(16);
    EmbeddedStorageEngine::open(config).expect("open storage engine")
}

/// Frees the skiplist nodes that writes replaced. crossbeam-skiplist defers
/// each free to the default epoch collector; each `flush` moves this thread's
/// deferred frees to the collector and runs those whose epoch is past.
fn collect_replaced_nodes() {
    for _ in 0..256 {
        crossbeam_epoch::pin().flush();
    }
}

/// Writes all rows `ROUNDS` times and walks them with `walk` after each
/// write. Returns how much the live heap grew after the warm-up.
fn heap_growth_with(walk: impl Fn(&EmbeddedStorageEngine, &RealmId)) -> isize {
    let dir = tempfile::tempdir().expect("tempdir");
    let engine = open(dir.path());
    let realm = RealmId::generate();
    let value = vec![b'v'; VALUE_BYTES];
    let rows: Vec<usize> = (0..ROWS).collect();
    let mut live = Vec::with_capacity(ROUNDS);
    for _ in 0..ROUNDS {
        for chunk in rows.chunks(BATCH) {
            let batch: Vec<(Vec<u8>, Vec<u8>)> =
                chunk.iter().map(|&i| (key(i), value.clone())).collect();
            engine.put_batch(&realm, &batch).expect("put_batch");
        }
        walk(&engine, &realm);
        collect_replaced_nodes();
        live.push(LIVE.load(Ordering::Relaxed));
    }
    live[ROUNDS - 1] - live[WARM_UP]
}

fn assert_no_growth(api: &str, growth: isize) {
    assert!(
        growth < MAX_GROWTH_BYTES,
        "the live heap grew {growth} bytes over {} rounds of write-then-{api}; \
         the bound is {MAX_GROWTH_BYTES} bytes",
        ROUNDS - 1 - WARM_UP,
    );
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[test]
fn count_prefix_does_not_keep_the_rows_it_passes_alive() {
    let growth = heap_growth_with(|engine, realm| {
        let count = engine.count_prefix(realm, START, 0).expect("count_prefix");
        assert_eq!(count, ROWS as u64);
    });
    assert_no_growth("count_prefix", growth);
}

#[test]
fn scan_does_not_keep_the_rows_it_passes_alive() {
    let growth = heap_growth_with(|engine, realm| {
        let rows = engine.scan(realm, START, END).expect("scan");
        assert_eq!(rows.len(), ROWS);
    });
    assert_no_growth("scan", growth);
}

#[test]
fn scan_keys_does_not_keep_the_rows_it_passes_alive() {
    let growth = heap_growth_with(|engine, realm| {
        let keys = engine.scan_keys(realm, START, END).expect("scan_keys");
        assert_eq!(keys.len(), ROWS);
    });
    assert_no_growth("scan_keys", growth);
}
