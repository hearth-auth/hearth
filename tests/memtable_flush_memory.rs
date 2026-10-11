//! A memtable flush writes its SST without a copy of the file in memory (#445).
//!
//! When the memtable reaches `memtable_flush_bytes`, the engine writes it to a
//! new SST. The flush streams the entries off the memtable without a copy
//! (HEA-1908), but the SST writer then kept every encrypted block in one
//! buffer and copied the whole file into a second buffer before the write:
//! about 3.4 times the flushed bytes of extra heap. A heaptrack run of the
//! server under load found 217 MB of extra heap at each 64 MiB flush.
//! Compaction already writes each block to the file when it is sealed
//! (HEA-1922).
//!
//! This test fills the memtable to just below its flush threshold, writes
//! past the threshold, and measures the highest heap the process holds above
//! the level before the flush.

use std::alloc::{GlobalAlloc, Layout, System};
use std::path::Path;
use std::sync::atomic::{AtomicIsize, Ordering};

use hearth::core::RealmId;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

// ── Live and peak heap of the whole process ──────────────────────────────────

/// Live heap bytes allocated through [`PeakAllocator`].
static LIVE: AtomicIsize = AtomicIsize::new(0);
/// The highest `LIVE` since the last [`reset_peak`].
static PEAK: AtomicIsize = AtomicIsize::new(0);

/// A `System`-backed allocator that tracks live and peak heap bytes. The flush
/// can run on any writer thread, so it counts every thread.
struct PeakAllocator;

fn note(delta: isize) {
    let now = LIVE.fetch_add(delta, Ordering::Relaxed) + delta;
    PEAK.fetch_max(now, Ordering::Relaxed);
}

// SAFETY: every method forwards to `System` with the same `Layout`; the only
// added work is relaxed atomic bookkeeping, which cannot affect the pointers.
unsafe impl GlobalAlloc for PeakAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarding unchanged to the system allocator.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            note(layout.size().cast_signed());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarding unchanged to the system allocator.
        unsafe { System.dealloc(ptr, layout) };
        note(-layout.size().cast_signed());
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarding unchanged to the system allocator.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            note(layout.size().cast_signed());
        }
        ptr
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: forwarding unchanged to the system allocator.
        let new = unsafe { System.realloc(ptr, layout, new_size) };
        if !new.is_null() {
            note(new_size.cast_signed() - layout.size().cast_signed());
        }
        new
    }
}

#[global_allocator]
static ALLOCATOR: PeakAllocator = PeakAllocator;

/// Starts a new peak window at the current live heap and returns that level.
fn reset_peak() -> isize {
    let live = LIVE.load(Ordering::Relaxed);
    PEAK.store(live, Ordering::Relaxed);
    live
}

// ── Workload ─────────────────────────────────────────────────────────────────

/// The flush threshold of this test. Large enough that the SST dwarfs the
/// fixed costs of a flush, small enough for a debug build.
const FLUSH_BYTES: usize = 16 * 1024 * 1024;
/// A serialized user record, as in the HEA-1908 harness.
const VALUE_BYTES: usize = 300;
/// Entries per `put_batch`.
const BATCH: usize = 500;

fn key(prefix: &str, i: usize) -> Vec<u8> {
    format!("{prefix}:{i:012}").into_bytes()
}

/// The memtable's accounting of one entry (`Memtable::entry_size`).
fn logical_bytes(key: &[u8]) -> usize {
    16 + key.len() + VALUE_BYTES
}

fn sst_files(dir: &Path) -> usize {
    let mut count = 0;
    let mut pending = vec![dir.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).expect("read data dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|ext| ext == "sst") {
                count += 1;
            }
        }
    }
    count
}

#[test]
#[allow(clippy::cast_precision_loss)] // the ratio in the failure message only
fn a_memtable_flush_holds_no_copy_of_the_sst_in_memory() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = StorageConfig::dev(dir.path().to_path_buf());
    config.set_memtable_flush_bytes(FLUSH_BYTES);
    config.compaction.enabled = false;
    let engine = EmbeddedStorageEngine::open(config).expect("open engine");
    let realm = RealmId::generate();
    let value = vec![b'v'; VALUE_BYTES];

    // Fill to 95% of the threshold: no flush yet.
    let mut logical = 0;
    let mut i = 0;
    while logical < FLUSH_BYTES * 95 / 100 {
        let batch: Vec<(Vec<u8>, Vec<u8>)> = (i..i + BATCH)
            .map(|n| (key("user", n), value.clone()))
            .collect();
        logical += batch.iter().map(|(k, _)| logical_bytes(k)).sum::<usize>();
        engine.put_batch(&realm, &batch).expect("put_batch");
        i += BATCH;
    }
    assert_eq!(sst_files(dir.path()), 0, "no flush below the threshold");

    // Write past the threshold until the flush has written its SST.
    let before = reset_peak();
    let mut burst = 0;
    while sst_files(dir.path()) == 0 {
        assert!(
            burst < FLUSH_BYTES / logical_bytes(&key("burst", 0)),
            "no SST after writing past the flush threshold"
        );
        let batch: Vec<(Vec<u8>, Vec<u8>)> = (burst..burst + 100)
            .map(|n| (key("burst", n), value.clone()))
            .collect();
        engine.put_batch(&realm, &batch).expect("put_batch");
        burst += 100;
    }
    let transient = PEAK.load(Ordering::Relaxed) - before;

    // The writer holds one block, one write chunk, the block index and the
    // Bloom filter. With the entries written past the threshold and the new
    // SST's reader, this measured 0.18x; the buffered writer measured 3.39x.
    // One copy of the file in memory is about 1x.
    let flushed = logical.cast_signed();
    assert!(
        transient < flushed / 2,
        "the flush held {transient} bytes of extra heap for {flushed} flushed bytes \
         ({:.2}x); a copy of the SST in memory is about 1x",
        transient as f64 / flushed as f64
    );
}
