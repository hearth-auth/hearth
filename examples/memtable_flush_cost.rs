//! HEA-1908 · flush-time transient memory of a memtable flush.
//!
//! ## Why this exists
//!
//! Before HEA-1908, `Memtable::flush` held the write lock across the whole SST
//! encrypt+`fsync`, and — even after the lock-hold was fixed — both flush
//! callsites still materialised the **entire** parked map into an owned
//! `Vec<(CompositeKey, MemtableValue)>` (a full deep copy of every key and value)
//! before handing it to the SST writer. At the default flush threshold that meant
//! a duplicate of the memtable was live for the whole flush, on top of the SST
//! serialization buffers.
//!
//! HEA-1908 (this child, HEA-1944) inverts the SST writer to a **sink-driven
//! feeder**: the flush pushes each `crossbeam_skiplist::Entry` guard's borrowed
//! key/value into the writer per entry, so nothing accumulates and the duplicate
//! `Vec` is gone entirely.
//!
//! ## What this harness proves
//!
//! A behavioural test that passes against both the old and new code does not pin a
//! memory property (HEA-1926 area-4). So this harness measures the property
//! directly: a **counting global allocator** records peak live heap bytes across a
//! single flush, and the binary *asserts* that the peak transient stays below the
//! band the eliminated `Vec` copy would have pushed it into. Reintroducing the
//! full-map copy at either callsite fails the assertion.
//!
//! Run:  `cargo run --release --example memtable_flush_cost`

// Example/measurement binary: casts are for reporting math on small magnitudes.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use hearth::core::RealmId;
use hearth::storage::{CompactionConfig, EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Live heap bytes currently allocated through [`CountingAlloc`].
static LIVE: AtomicUsize = AtomicUsize::new(0);
/// High-water mark of `LIVE` since it was last reset via [`peak_reset`].
static PEAK: AtomicUsize = AtomicUsize::new(0);

/// A `System`-backed global allocator that tracks live and peak heap bytes.
///
/// `realloc` falls through to the `GlobalAlloc` default (alloc + copy + dealloc),
/// so `Vec` growth is captured on both the alloc and the dealloc side and the
/// accounting stays balanced.
struct CountingAlloc;

// SAFETY: every method forwards to the corresponding `System` allocator method
// with an unchanged `Layout`; the only added work is relaxed atomic bookkeeping,
// which cannot affect the returned pointer's validity.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            let now = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(now, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc_zeroed(layout);
        if !ptr.is_null() {
            let now = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(now, Ordering::Relaxed);
        }
        ptr
    }
}

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

/// Resets the peak high-water mark to the current live total, so the next
/// measured window's peak is a clean delta.
fn peak_reset() {
    PEAK.store(LIVE.load(Ordering::Relaxed), Ordering::Relaxed);
}

/// Representative serialized `User` value size (per HEA-1867 finding 3).
const RECORD_VALUE_BYTES: usize = 300;

/// Flush threshold for this run: a single flush moves ~this many bytes.
const FLUSH_THRESHOLD_BYTES: u64 = 32 * 1024 * 1024;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("HEA-1908 · memtable flush-time transient memory\n");
    println!(
        "record value bytes = {RECORD_VALUE_BYTES}, flush threshold = {} MiB\n",
        FLUSH_THRESHOLD_BYTES / (1024 * 1024)
    );

    let tmp = tempfile::tempdir()?;
    let wal_max = 256 * 1024 * 1024;
    let hot_capacity = 100;
    let mut config = StorageConfig::production(
        PathBuf::from(tmp.path()),
        wal_max,
        FLUSH_THRESHOLD_BYTES,
        hot_capacity,
    );
    config.dev_mode = true;
    // No compaction — isolate the memtable flush.
    config.compaction = CompactionConfig {
        enabled: false,
        interval_secs: 0,
        min_sst_count: 2,
        max_sst_count: 0,
        merge_min: 4,
    };
    let engine = EmbeddedStorageEngine::open(config)?;
    let realm = RealmId::generate();
    let value = vec![b'x'; RECORD_VALUE_BYTES];

    // Per-entry logical bytes: key ("user:{i:012}") + value + realm/len overhead
    // matching `Memtable::entry_size` (16 + key + value).
    let key_bytes = "user:000000000000".len();
    let per_entry_logical = 16 + key_bytes + RECORD_VALUE_BYTES;
    // Seed to ~95% of the threshold so a small burst crosses it exactly once and
    // the flush-time transient dominates the measured window (the burst itself
    // adds only ~5% of corpus in permanent live data, not transient).
    let target_entries = (FLUSH_THRESHOLD_BYTES as usize * 95 / 100) / per_entry_logical;

    for i in 0..target_entries {
        engine.put(
            &realm,
            format!("user:{i:012}").into_bytes().as_slice(),
            &value,
        )?;
    }

    let logical_flushed = target_entries * per_entry_logical;

    // Baseline the allocator right before the flush window: the ~1× parked map is
    // already live and counts as baseline, so PEAK - baseline isolates the NEW
    // transient the flush allocates (SST writer buffers, and — pre-HEA-1908 — the
    // eliminated full-map Vec copy on top of them).
    let live_before = LIVE.load(Ordering::Relaxed);
    peak_reset();

    // Burst just past the threshold — one of these puts triggers an inline flush.
    // Keep it small (~8% of corpus) so it does not itself dominate the window.
    let burst = target_entries / 12 + 1;
    for i in 0..burst {
        engine.put(
            &realm,
            format!("burst:{i:012}").into_bytes().as_slice(),
            &value,
        )?;
    }

    let peak = PEAK.load(Ordering::Relaxed);
    let peak_transient = peak.saturating_sub(live_before);

    let mib = |b: usize| b as f64 / (1024.0 * 1024.0);
    let ratio = peak_transient as f64 / logical_flushed.max(1) as f64;
    println!("entries flushed          : {target_entries}");
    println!("logical bytes flushed    : {:.2} MiB", mib(logical_flushed));
    println!("live heap before flush   : {:.2} MiB", mib(live_before));
    println!("peak live heap in flush  : {:.2} MiB", mib(peak));
    println!(
        "peak flush transient     : {:.2} MiB  ({ratio:.2}× logical flushed)",
        mib(peak_transient)
    );
    println!(
        "\nStreaming (HEA-1908): measured transient ≈ 3.4× logical (the eager SST\n\
         writer's block buffer + assembled output buffer + realloc growth). Reintro-\n\
         ducing the full-map Vec copy at a flush callsite measures ≈ 4.7×; the extra\n\
         ~1.3× (≈ the memtable size) is exactly what this change eliminates. The\n\
         {THRESHOLD_RATIO_NUM}/{THRESHOLD_RATIO_DEN}× guard below sits between the two."
    );

    // Property assertion (HEA-1926 area-4): the peak transient must stay in the
    // streaming band. Measured on this harness: streaming ≈ 3.4× logical flushed,
    // the reintroduced full-map Vec copy ≈ 4.7× (verified by temporarily
    // materialising the map at the trigger_flush callsite). The guard sits at the
    // 4× midpoint — it fails if either flush callsite regresses to copying the map,
    // with ~0.6× headroom on each side for allocator run-to-run noise.
    let bound = logical_flushed * THRESHOLD_RATIO_NUM / THRESHOLD_RATIO_DEN;
    assert!(
        peak_transient < bound,
        "peak flush transient {:.2} MiB ({ratio:.2}× logical) exceeds the {THRESHOLD_RATIO_NUM}/{THRESHOLD_RATIO_DEN}× guard \
         ({:.2} MiB) — a full-map Vec copy has been reintroduced at a flush callsite (HEA-1908)",
        mib(peak_transient),
        mib(bound)
    );
    println!("\nPASS: peak flush transient is within the streaming (no-copy) band.");

    Ok(())
}

/// Numerator of the peak-transient guard ratio (peak < NUM/DEN × logical flushed).
const THRESHOLD_RATIO_NUM: usize = 4;
/// Denominator of the peak-transient guard ratio.
const THRESHOLD_RATIO_DEN: usize = 1;
