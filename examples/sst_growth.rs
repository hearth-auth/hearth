//! HEA-1870 · C2 — SST-count growth vs corpus size (settles finding 5).
//!
//! Measures how the on-disk SST **file count** — the exact quantity the cold
//! read path fans out over (`EmbeddedStorageEngine::get`, `src/storage/engine.rs`,
//! linear scan of the flat `sst_readers` Vec) — grows as a function of corpus
//! size, both **immediately post-seed** (before any compaction) and
//! **post-compaction**, then fits `log(count)` on `log(n)` and reports the
//! empirical exponent.
//!
//! This is a pure storage-engine experiment: SST count is a deterministic
//! function of bytes written, the memtable flush threshold, and the compaction
//! policy. It does **not** depend on request concurrency or the HTTP harness, so
//! there is no generator-ceiling attribution risk (per the HEA-1867 grading
//! rules). The only hardware-dependent figure it emits is wall-clock seed time,
//! which is labelled as such.
//!
//! Run:  `cargo run --release --example sst_growth`
//!
//! The measurement holds the memtable flush threshold at a scaled-down value so
//! that a modest corpus produces a countable number of SSTs; it then projects
//! the fitted relationship onto the production default flush threshold
//! (64 MiB, `StorageSection::default_memtable_flush_bytes`).

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

/// Representative serialized size of a `User` record value, in bytes.
///
/// Per HEA-1867 finding 3, a `User` (`src/identity/types/user.rs`) serializes to
/// a few hundred bytes. We use a fixed 300-byte value so the bytes-per-record
/// term in the SST-count relationship is explicit and reproducible.
const RECORD_VALUE_BYTES: usize = 300;

/// Scaled-down memtable flush threshold used for the measurement (256 KiB).
///
/// Small enough that the corpus ladder below produces tens-to-hundreds of SSTs
/// (so the fit has signal), while remaining large relative to a single record.
const MEASURE_FLUSH_BYTES: u64 = 256 * 1024;

/// Production default memtable flush threshold (64 MiB), used only for the
/// projection table. Mirrors `StorageSection::default_memtable_flush_bytes`.
const PROD_FLUSH_BYTES: u64 = 64 * 1024 * 1024;

/// Corpus-size ladder (record counts). Geometric so the log-log fit is evenly
/// spaced.
const LADDER: &[usize] = &[10_000, 20_000, 40_000, 80_000, 160_000, 320_000];

/// One measured rung.
struct Rung {
    n: usize,
    ssts_post_seed: usize,
    ssts_post_compaction: usize,
    seed_secs: f64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("HEA-1870 · C2 — SST-count growth vs corpus size\n");
    println!(
        "record value bytes = {RECORD_VALUE_BYTES}, measurement flush threshold = {} KiB, \
         compaction periodic sweep = OFF (manual)\n",
        MEASURE_FLUSH_BYTES / 1024
    );

    let mut rungs: Vec<Rung> = Vec::with_capacity(LADDER.len());
    for &n in LADDER {
        rungs.push(measure_rung(n)?);
    }

    print_table(&rungs);
    print_fits(&rungs);
    print_projection(&rungs);
    Ok(())
}

/// Seeds `n` records into a fresh engine (compaction sweep disabled), counts
/// SST files on disk, then runs a manual full compaction and counts again.
fn measure_rung(n: usize) -> Result<Rung, Box<dyn std::error::Error>> {
    let tmp = tempfile::tempdir()?;
    // `production()` is the only public constructor that lets us set the
    // memtable flush threshold directly. It defaults to `dev_mode = false`
    // (requires HEARTH_MASTER_KEY); we flip `dev_mode = true` so the host key
    // auto-generates for this throwaway measurement dir.
    let wal_max = 256 * 1024 * 1024;
    let hot_capacity = 100;
    let mut config = StorageConfig::production(
        PathBuf::from(tmp.path()),
        wal_max,
        MEASURE_FLUSH_BYTES,
        hot_capacity,
    );
    config.dev_mode = true;
    // Manual control: no periodic sweep, no count trigger. We compact explicitly.
    config.compaction = CompactionConfig {
        enabled: false,
        interval_secs: 0,
        min_sst_count: 2,
    };
    let engine = EmbeddedStorageEngine::open(config)?;
    let realm = RealmId::generate();

    let value = vec![b'x'; RECORD_VALUE_BYTES];
    // Seed via `put_batch` to amortize the production `SyncMode::EveryWrite`
    // fsync (one WAL fsync per batch instead of per record). The chunk size is
    // deliberately kept *below* the memtable flush threshold in bytes so the
    // tail-of-batch flush check still fires at threshold granularity — i.e. the
    // resulting SST count matches per-`put` behavior, only faster to seed.
    const CHUNK: usize = 500;
    let start = Instant::now();
    let mut i = 0usize;
    while i < n {
        let end = (i + CHUNK).min(n);
        let batch: Vec<(Vec<u8>, Vec<u8>)> = (i..end)
            .map(|j| (format!("user:{j:012}").into_bytes(), value.clone()))
            .collect();
        engine.put_batch(&realm, &batch)?;
        i = end;
    }
    let seed_secs = start.elapsed().as_secs_f64();

    let ssts_post_seed = count_ssts(tmp.path())?;
    // Full compaction collapses every SST into one (engine.rs `compact_ssts`).
    engine.compact_ssts(2)?;
    let ssts_post_compaction = count_ssts(tmp.path())?;

    Ok(Rung {
        n,
        ssts_post_seed,
        ssts_post_compaction,
        seed_secs,
    })
}

/// Counts `*.sst` files in `dir` (ignores `.sst.tmp`).
fn count_ssts(dir: &std::path::Path) -> Result<usize, std::io::Error> {
    let count = std::fs::read_dir(dir)?
        .filter_map(std::result::Result::ok)
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "sst"))
        .count();
    Ok(count)
}

fn print_table(rungs: &[Rung]) {
    println!("corpus (n) | SSTs post-seed | SSTs post-compaction | seed wall-clock (s)");
    println!("-----------+----------------+----------------------+--------------------");
    for r in rungs {
        println!(
            "{:>10} | {:>14} | {:>20} | {:>18.2}",
            r.n, r.ssts_post_seed, r.ssts_post_compaction, r.seed_secs
        );
    }
    println!();
}

/// Least-squares slope and R² of `y` on `x`.
fn linreg(xs: &[f64], ys: &[f64]) -> (f64, f64) {
    let m = xs.len() as f64;
    let sx: f64 = xs.iter().sum();
    let sy: f64 = ys.iter().sum();
    let mean_x = sx / m;
    let mean_y = sy / m;
    let mut sxx = 0.0;
    let mut sxy = 0.0;
    let mut syy = 0.0;
    for (&x, &y) in xs.iter().zip(ys) {
        sxx += (x - mean_x) * (x - mean_x);
        sxy += (x - mean_x) * (y - mean_y);
        syy += (y - mean_y) * (y - mean_y);
    }
    let slope = if sxx == 0.0 { 0.0 } else { sxy / sxx };
    let r2 = if sxx == 0.0 || syy == 0.0 {
        1.0
    } else {
        (sxy * sxy) / (sxx * syy)
    };
    (slope, r2)
}

fn print_fits(rungs: &[Rung]) {
    let log_n: Vec<f64> = rungs.iter().map(|r| (r.n as f64).ln()).collect();
    let log_seed: Vec<f64> = rungs
        .iter()
        .map(|r| (r.ssts_post_seed.max(1) as f64).ln())
        .collect();

    let (slope, r2) = linreg(&log_n, &log_seed);
    println!("Fit: log(SSTs post-seed) = slope * log(n) + c");
    println!("  post-seed exponent  = {slope:.4}  (R^2 = {r2:.4})");

    let all_one = rungs.iter().all(|r| r.ssts_post_compaction == 1);
    println!(
        "  post-compaction     = {} (constant) => cold-path fan-out O(1)\n",
        if all_one {
            "1".to_string()
        } else {
            format!(
                "{:?}",
                rungs
                    .iter()
                    .map(|r| r.ssts_post_compaction)
                    .collect::<Vec<_>>()
            )
        }
    );
}

/// Projects the measured bytes-per-SST onto the production flush threshold.
fn print_projection(rungs: &[Rung]) {
    // Bytes per SST at production flush size, using the same 300-byte record.
    let records_per_sst = PROD_FLUSH_BYTES as f64 / RECORD_VALUE_BYTES as f64;
    println!(
        "Projection to production flush threshold ({} MiB, {RECORD_VALUE_BYTES}B records):",
        PROD_FLUSH_BYTES / (1024 * 1024)
    );
    println!("  ~{records_per_sst:.0} records per SST");
    println!("  corpus (n) | projected SSTs post-seed (pre-compaction)");
    println!("  -----------+------------------------------------------");
    for &n in &[1_000_000usize, 10_000_000, 100_000_000] {
        let ssts = (n as f64 / records_per_sst).ceil();
        println!("  {n:>10} | {ssts:>8.0}");
    }
    // Silence unused warning if the ladder ever shrinks to empty.
    let _ = rungs.len();
}
