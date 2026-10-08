//! Cost of one hot-tier promotion as the tier fills, and once it is full.
//!
//! ## Why this exists
//!
//! A 50-minute live soak (2026-10-08, 2-vCPU `c-2`, 1,000,000 users) promoted
//! ~300,000 entries and evicted none; resident memory rose ~1.5 KB per
//! promotion. Every admitted promotion cloned its shard's map, keys included,
//! and an eviction also cloned and sorted every key in the shard. Both costs
//! grew with the shard, so they grew as the tier filled. This harness measures
//! them through the public storage engine:
//!
//! * live heap bytes per cached entry;
//! * allocations and wall time of the one read that admits an entry, at each
//!   tenth of fill, and on a full tier where every admission evicts.
//!
//! Measured 2026-10-08 (1,474,140 entries, 300-byte values, laptop):
//!
//! | tier fill | before: µs / allocs per promote | after: µs / allocs |
//! |-----------|---------------------------------|--------------------|
//! | 0–10%     | 90 / 1,161                      | 2.9 / 9            |
//! | 50–60%    | 1,809 / 12,677                  | 25.3 / 9           |
//! | 90–100%   | —                               | 47.4 / 9           |
//! | full      | —                               | 46.2 / 9           |
//!
//! "Before" cloned every key on each shard-map copy, at 64 shards (~23,000
//! entries each when full). "After" shares keys behind an `Arc` and sizes the
//! shard count so a shard stays at most 2,048 entries. A cached entry costs 437
//! live heap bytes at this value size. The binary asserts that allocations per
//! promote stay constant, so a return of per-key copies fails it.
//!
//! Run: `cargo run --release --example hot_tier_cost -- [capacity] [value_bytes]`
//! (defaults: 1,474,140 entries — the live `c-2`'s auto-sized tier — and 300 bytes).
// Example/measurement binary: casts are for reporting math on small magnitudes.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use hearth::core::RealmId;
use hearth::storage::{CompactionConfig, EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Live heap bytes currently allocated through [`CountingAlloc`].
static LIVE: AtomicUsize = AtomicUsize::new(0);
/// Number of allocations made through [`CountingAlloc`].
static ALLOCS: AtomicUsize = AtomicUsize::new(0);

/// A `System`-backed global allocator that counts allocations and live bytes.
struct CountingAlloc;

// SAFETY: every method forwards to the corresponding `System` allocator method
// with an unchanged `Layout`; the only added work is relaxed atomic bookkeeping,
// which cannot affect the returned pointer's validity.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            LIVE.fetch_add(layout.size(), Ordering::Relaxed);
            ALLOCS.fetch_add(1, Ordering::Relaxed);
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
            LIVE.fetch_add(layout.size(), Ordering::Relaxed);
            ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        ptr
    }
}

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

/// Admitted promotions so far (process-wide counter).
fn promotions() -> u64 {
    hearth::metrics::metrics()
        .storage_hot_tier_promotions_total
        .get() as u64
}

/// Totals for the admitting reads in one measured window.
/// Most allocations one admitted promote may make. The measured value is 9
/// at every fill level; a per-key copy of the shard map adds one per entry.
const MAX_ALLOCS_PER_PROMOTE: f64 = 32.0;

#[derive(Default)]
struct Window {
    admitted: u64,
    allocs: usize,
    time: Duration,
    worst: Duration,
}

impl Window {
    fn allocs_per_promote(&self) -> f64 {
        self.allocs as f64 / self.admitted.max(1) as f64
    }

    fn report(&self, label: &str) {
        let n = self.admitted.max(1);
        println!(
            "{label:>14}  {:>9.1} µs/promote  worst {:>9.1} µs  {:>9.0} allocs/promote",
            self.time.as_secs_f64() * 1e6 / n as f64,
            self.worst.as_secs_f64() * 1e6,
            self.allocs_per_promote(),
        );
        assert!(
            self.allocs_per_promote() <= MAX_ALLOCS_PER_PROMOTE,
            "{label}: {:.0} allocations per promote; the limit is {MAX_ALLOCS_PER_PROMOTE}",
            self.allocs_per_promote()
        );
    }
}

/// Reads `key` until the hot tier admits it (production admits 1 in 4 misses),
/// and adds the admitting read's cost to `window`.
fn promote(engine: &EmbeddedStorageEngine, realm: &RealmId, key: &[u8], window: &mut Window) {
    for _ in 0..16 {
        let before = promotions();
        let allocs = ALLOCS.load(Ordering::Relaxed);
        let start = Instant::now();
        let value = engine.get(realm, key).expect("get");
        let took = start.elapsed();
        assert!(value.is_some(), "every measured key was written");
        if promotions() > before {
            window.admitted += 1;
            window.allocs += ALLOCS.load(Ordering::Relaxed) - allocs;
            window.time += took;
            window.worst = window.worst.max(took);
            return;
        }
    }
    panic!("key was not admitted after 16 misses");
}

fn key(prefix: &str, i: usize) -> Vec<u8> {
    format!("{prefix}:{i:012}").into_bytes()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let capacity: usize = args.next().map_or(Ok(1_474_140), |a| a.parse())?;
    let value_bytes: usize = args.next().map_or(Ok(300), |a| a.parse())?;
    let full_tier_promotes = 4_000;
    println!("hot tier: capacity {capacity} entries, value {value_bytes} bytes\n");

    let tmp = tempfile::tempdir()?;
    // A memtable large enough that nothing flushes: every read is a memtable
    // hit that promotes, and no flush allocation lands in a window.
    let mut config = StorageConfig::production(
        PathBuf::from(tmp.path()),
        8 * 1024 * 1024 * 1024,
        4 * 1024 * 1024 * 1024,
        capacity,
    );
    config.dev_mode = true;
    // The harness measures the hot tier, not durability: without this, loading
    // 1.5 M keys waits on one fsync per put.
    config.wal_config.sync_mode = hearth::storage::wal::SyncMode::None;
    config.set_hot_tier_per_realm_metrics(false);
    config.compaction = CompactionConfig {
        enabled: false,
        interval_secs: 0,
        min_sst_count: 2,
        max_sst_count: 0,
        merge_min: 4,
    };
    let engine = EmbeddedStorageEngine::open(config)?;
    let realm = RealmId::generate();
    let value = vec![b'x'; value_bytes];

    for i in 0..capacity {
        engine.put(&realm, &key("sess", i), &value)?;
    }
    for i in 0..full_tier_promotes {
        engine.put(&realm, &key("late", i), &value)?;
    }

    let live_before = LIVE.load(Ordering::Relaxed);
    let tenth = capacity / 10;
    for step in 0..10 {
        let mut window = Window::default();
        for i in step * tenth..(step + 1) * tenth {
            promote(&engine, &realm, &key("sess", i), &mut window);
        }
        window.report(&format!("{}–{}% full", step * 10, step * 10 + 10));
    }
    let cached = promotions();
    let live_after = LIVE.load(Ordering::Relaxed);
    println!(
        "\nlive heap per cached entry: {:.0} bytes ({} entries, {:.1} MiB)",
        (live_after - live_before) as f64 / cached.max(1) as f64,
        cached,
        (live_after - live_before) as f64 / (1024.0 * 1024.0)
    );

    let mut window = Window::default();
    for i in 0..full_tier_promotes {
        promote(&engine, &realm, &key("late", i), &mut window);
    }
    window.report("full (evicts)");
    Ok(())
}
