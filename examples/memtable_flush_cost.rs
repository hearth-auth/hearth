//! HEA-1908 · flush-time transient memory of a memtable flush.
//!
//! ## Why this exists
//!
//! Before HEA-1908, `Memtable::flush` materialised the **entire** memtable into a
//! `Vec<(CompositeKey, MemtableValue)>` — a full deep copy of every key and value
//! — and held the write lock across the SST encrypt+`fsync`. At the 64 MiB
//! default flush threshold that meant a ~64 MiB duplicate of the memtable was live
//! for the whole flush, a live candidate for part of the gap between the C0
//! re-measurement (9,960 B/user, `124aeee2`) and the 1–2 KB Layer-B estimate.
//!
//! HEA-1908 streams the SST writer directly off the lock-free `SkipMap`, so no
//! duplicate `Vec` is allocated. This harness makes the eliminated transient
//! concrete: it fills a realm to just under a flush threshold, then triggers a
//! single flush while a background thread samples RSS, and reports
//!
//!   * the logical bytes flushed (what the pre-HEA-1908 copy duplicated),
//!   * the analytic size of the eliminated `Vec` copy (backbone + key/value
//!     heap), and
//!   * the empirically observed peak-RSS delta across the flush (post-fix).
//!
//! Run:  `cargo run --release --example memtable_flush_cost`

// Example/measurement binary: casts are for reporting math on small magnitudes.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hearth::core::RealmId;
use hearth::storage::{CompactionConfig, EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Representative serialized `User` value size (per HEA-1867 finding 3).
const RECORD_VALUE_BYTES: usize = 300;

/// Flush threshold for this run: a single flush moves ~this many bytes.
const FLUSH_THRESHOLD_BYTES: u64 = 32 * 1024 * 1024;

/// Sizeof one `(CompositeKey, MemtableValue)` tuple's *inline* footprint — the
/// per-entry backbone the old flush `Vec` allocated on top of the key/value heap
/// bytes: `RealmId` (16) + `Vec<u8>` key handle (24) + `MemtableValue` (32,
/// tagged `Vec<u8>`), rounded to the tuple's 8-byte alignment.
const TUPLE_BACKBONE_BYTES: usize = 72;

/// Reads this process's resident set size in bytes from `/proc/self/statm`.
/// Returns 0 on non-Linux / read failure (the analytic figure is the headline).
fn rss_bytes() -> usize {
    let Ok(statm) = std::fs::read_to_string("/proc/self/statm") else {
        return 0;
    };
    // Field 2 (0-indexed 1) is resident pages.
    let resident_pages: usize = statm
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    resident_pages * 4096
}

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
    // Seed to ~90% of the threshold so the next burst crosses it exactly once.
    let target_entries = (FLUSH_THRESHOLD_BYTES as usize * 9 / 10) / per_entry_logical;

    for i in 0..target_entries {
        engine.put(
            &realm,
            format!("user:{i:012}").into_bytes().as_slice(),
            &value,
        )?;
    }

    let logical_flushed = target_entries * per_entry_logical;
    let eliminated_copy = target_entries * (TUPLE_BACKBONE_BYTES + key_bytes + RECORD_VALUE_BYTES);

    // Background RSS sampler captures the peak across the flush window.
    let stop = Arc::new(AtomicBool::new(false));
    let peak = Arc::new(AtomicUsize::new(0));
    let sampler = {
        let stop = Arc::clone(&stop);
        let peak = Arc::clone(&peak);
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let r = rss_bytes();
                peak.fetch_max(r, Ordering::Relaxed);
                std::thread::sleep(Duration::from_micros(200));
            }
        })
    };

    let rss_before = rss_bytes();
    peak.fetch_max(rss_before, Ordering::Relaxed);

    // Burst across the threshold — one of these puts triggers an inline flush.
    for i in 0..(target_entries / 4) {
        engine.put(
            &realm,
            format!("burst:{i:012}").into_bytes().as_slice(),
            &value,
        )?;
    }

    stop.store(true, Ordering::Relaxed);
    sampler.join().ok();
    let rss_peak = peak.load(Ordering::Relaxed);
    let rss_after = rss_bytes();

    let mib = |b: usize| b as f64 / (1024.0 * 1024.0);
    println!("entries flushed          : {target_entries}");
    println!("logical bytes flushed    : {:.2} MiB", mib(logical_flushed));
    println!(
        "eliminated Vec copy      : {:.2} MiB  ← HEA-1908 no longer allocates this",
        mib(eliminated_copy)
    );
    println!(
        "per-user eliminated      : {} B/user",
        eliminated_copy / target_entries.max(1)
    );
    if rss_before > 0 {
        println!("\nRSS before burst         : {:.2} MiB", mib(rss_before));
        println!("RSS peak during burst    : {:.2} MiB", mib(rss_peak));
        println!("RSS after burst          : {:.2} MiB", mib(rss_after));
        println!(
            "peak-RSS delta over flush: {:.2} MiB",
            mib(rss_peak.saturating_sub(rss_before))
        );
        println!(
            "\nWith the pre-HEA-1908 flush the peak-RSS delta would include the ~{:.0} MiB \
             duplicate\nabove; streaming keeps only the SST serialization buffers.",
            mib(eliminated_copy)
        );
    }
    Ok(())
}
