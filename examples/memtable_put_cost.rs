//! HEA-1897 · Layer B — memtable put cost vs occupancy.
//!
//! Demonstrates that the marginal cost of a single `put` is (approximately)
//! independent of how many entries the memtable already holds, through the
//! public `EmbeddedStorageEngine` write path.
//!
//! ## Why this exists
//!
//! Before HEA-1897 the memtable was an `ArcSwap<BTreeMap>` that cloned the
//! *entire* backing map on every `put` (`current.clone()` → mutate → store).
//! That made per-put cost **O(N)** in resident-entry count: at the 64 MiB
//! default flush threshold, ~160k entries were reallocated on every write, two
//! full copies were live at once, and `arc_swap` deferred the free — so the
//! glibc arena high-water grew and RSS never came back. HEA-1867's record-size
//! trace attributed ~22 of the observed 24 KB/user resident cost to exactly this
//! clone, and the C0 seed ladder's rising ms/user (2.63 → 7.76) was its
//! write-throughput signature.
//!
//! The fix replaces the CoW `BTreeMap` with a lock-free `crossbeam_skiplist`
//! `SkipMap`: inserts are O(log N) with no whole-map copy. This harness makes the
//! difference observable end-to-end — with the fix the ns/put column stays flat
//! across an 8× growth in occupancy; before it, it grew roughly linearly.
//!
//! Run:  `cargo run --release --example memtable_put_cost`
//!
//! The flush threshold is set very large so no SST flush fires mid-measurement:
//! every probe put lands in a memtable that already holds the full occupancy, so
//! the timed cost is the marginal put cost at that occupancy.

// Example/measurement binary: casts are for reporting math on small magnitudes.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::path::PathBuf;
use std::time::Instant;

use hearth::core::RealmId;
use hearth::storage::{CompactionConfig, EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Representative serialized `User` value size (per HEA-1867 finding 3).
const RECORD_VALUE_BYTES: usize = 300;

/// Flush threshold held very high (2 GiB) so the memtable never flushes during
/// the measurement — occupancy grows monotonically with cumulative puts.
const NO_FLUSH_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Number of timed probe puts at each occupancy checkpoint.
const PROBE: usize = 2_000;

/// Occupancy checkpoints (resident entries in the memtable before the probe).
/// Geometric 8× span so O(N) scaling is unmistakable if present.
const LADDER: &[usize] = &[2_000, 4_000, 8_000, 16_000];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("HEA-1897 · Layer B — memtable put cost vs occupancy\n");
    println!(
        "record value bytes = {RECORD_VALUE_BYTES}, probe batch = {PROBE} puts, \
         flush = OFF (threshold {} GiB)\n",
        NO_FLUSH_BYTES / (1024 * 1024 * 1024)
    );

    let tmp = tempfile::tempdir()?;
    let wal_max = 256 * 1024 * 1024;
    let hot_capacity = 100;
    let mut config = StorageConfig::production(
        PathBuf::from(tmp.path()),
        wal_max,
        NO_FLUSH_BYTES,
        hot_capacity,
    );
    config.dev_mode = true;
    // No compaction: we only care about the in-memory memtable put path.
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

    // Warm up allocator/caches so the first checkpoint isn't penalised.
    for i in 0..PROBE {
        engine.put(
            &realm,
            format!("warm:{i:012}").into_bytes().as_slice(),
            &value,
        )?;
    }

    let mut baseline_ns = 0.0_f64;
    println!("{:>10}  {:>12}  {:>10}", "occupancy", "ns/put", "vs base");
    println!("{}", "-".repeat(36));

    let mut seeded = 0usize;
    for (idx, &target) in LADDER.iter().enumerate() {
        // Seed (untimed) up to the target occupancy with distinct keys.
        while seeded < target {
            engine.put(
                &realm,
                format!("seed:{seeded:012}").into_bytes().as_slice(),
                &value,
            )?;
            seeded += 1;
        }

        // Timed probe: fresh keys so every put is an insert, not an overwrite.
        let start = Instant::now();
        for i in 0..PROBE {
            engine.put(
                &realm,
                format!("probe:{idx}:{i:012}").into_bytes().as_slice(),
                &value,
            )?;
            seeded += 1;
        }
        let ns_per_put = start.elapsed().as_nanos() as f64 / PROBE as f64;
        if idx == 0 {
            baseline_ns = ns_per_put;
        }
        println!(
            "{target:>10}  {ns_per_put:>12.0}  {:>9.2}x",
            ns_per_put / baseline_ns
        );
    }

    println!(
        "\nExpected with the skiplist fix: the `vs base` column stays near 1x across the 8x \
         occupancy span.\nWith the old copy-on-write BTreeMap it grew roughly linearly (~8x)."
    );
    Ok(())
}
