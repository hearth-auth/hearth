//! HEA-1905 · E4 re-run — SST-count growth with partial compaction ENABLED.
//!
//! Companion to `examples/sst_growth.rs` (HEA-1870/C2, baseline, exponent 1.0000)
//! and `examples/sst_partial_compaction.rs` (HEA-1885, max_sst_count=12).
//!
//! This sweep measures three configurations on the same corpus ladder and
//! hardware:
//!
//! | Config | max_sst_count | Description |
//! |--------|--------------|-------------|
//! | C (control) | 0  | Time-triggered only — the HEA-1870/C2 baseline. |
//! | T8          | 8  | Count trigger fires when live SST count ≥ 8.  |
//! | T16         | 16 | Count trigger fires when live SST count ≥ 16. |
//!
//! For each trigger value the harness drives `compact_partial()` deterministically
//! whenever the live SST count reaches the threshold, matching what the production
//! background task does — without the background-task non-determinism.
//!
//! Reports:
//!  1. Fitted `log(peak fan-out)` on `log(n)` exponent + R² — the DoD primary ask.
//!  2. Write amplification per trigger value vs. the O(log n) bar.
//!  3. Per-merge write-stall (p50 / p99 / max) for each enabled configuration.
//!  4. Recommendation on whether the default should flip from 0.
//!
//! Run:  `cargo run --release --example sst_growth_e4_rerun`

// Example/measurement binary: casts are for reporting math on small magnitudes.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use hearth::core::RealmId;
use hearth::storage::{CompactionConfig, EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Representative serialized `User` record value, bytes — matches `sst_growth.rs`.
const RECORD_VALUE_BYTES: usize = 300;

/// Scaled-down memtable flush threshold (256 KiB) — same as `sst_growth.rs` and
/// `sst_partial_compaction.rs`; keeps the two baselines directly comparable.
const MEASURE_FLUSH_BYTES: u64 = 256 * 1024;

/// Per-tier fan-in for partial compaction (`storage.compaction.merge_min`).
const MERGE_MIN: usize = 4;

/// Corpus-size ladder.  Geometric so the log-log fit is evenly spaced.
const LADDER: &[usize] = &[10_000, 20_000, 40_000, 80_000, 160_000, 320_000];

/// Trigger values to sweep.  0 = control (disabled), 8, 12 (new default from
/// HEA-1931), and 16 are the settings requested by HEA-1905/HEA-1936.
const TRIGGERS: &[usize] = &[0, 8, 12, 16];

// ─── per-rung measurements ──────────────────────────────────────────────────

struct Rung {
    n: usize,
    /// Peak live SST count observed at any point during seeding.
    /// For control (trigger=0) this equals `ssts_post_seed`.
    peak_ssts: usize,
    /// Live SST files when seeding is done (after draining residual tiers).
    live_ssts: usize,
    /// SSTs after a full `compact_ssts` — only tracked for the control run.
    ssts_post_full_compact: Option<usize>,
    /// Total bytes written to `.sst` files (flushes + merges).
    bytes_written: u64,
    /// Write amplification = bytes_written / corpus bytes.
    write_amp: f64,
    /// Per-merge stall wall-clock samples, milliseconds (trigger > 0 only).
    merge_ms: Vec<f64>,
    seed_secs: f64,
}

// ─── measurement ────────────────────────────────────────────────────────────

fn measure_rung(n: usize, max_sst_count: usize) -> Result<Rung, Box<dyn std::error::Error>> {
    let tmp = tempfile::tempdir()?;
    let wal_max = 256 * 1024 * 1024;
    let hot_capacity = 100;
    let mut config = StorageConfig::production(
        PathBuf::from(tmp.path()),
        wal_max,
        MEASURE_FLUSH_BYTES,
        hot_capacity,
    );
    config.dev_mode = true;

    if max_sst_count == 0 {
        // Control: periodic sweep disabled, count trigger disabled.
        // Matches the HEA-1870/C2 baseline exactly.
        config.compaction = CompactionConfig {
            enabled: false,
            interval_secs: 0,
            min_sst_count: 2,
            max_sst_count: 0,
            merge_min: MERGE_MIN,
        };
    } else {
        // Trigger ON: count trigger drives partial compaction; interval_secs=0
        // so only the count trigger fires (no background sweep in the example).
        config.compaction = CompactionConfig {
            enabled: true,
            interval_secs: 0,
            min_sst_count: 2,
            max_sst_count,
            merge_min: MERGE_MIN,
        };
    }

    let engine = EmbeddedStorageEngine::open(config)?;
    let realm = RealmId::generate();

    let value = vec![b'x'; RECORD_VALUE_BYTES];
    let mut seen_sizes: HashMap<u64, u64> = HashMap::new();
    let mut bytes_written: u64 = 0;
    let mut peak_ssts: usize = 0;
    let mut merge_ms: Vec<f64> = Vec::new();

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

        bytes_written += new_sst_bytes(tmp.path(), &mut seen_sizes)?;

        if max_sst_count > 0 {
            // Service the count trigger deterministically.
            while count_ssts(tmp.path())? >= max_sst_count {
                let t0 = Instant::now();
                let merged = engine.compact_partial()?;
                if merged == 0 {
                    break;
                }
                merge_ms.push(t0.elapsed().as_secs_f64() * 1000.0);
                bytes_written += new_sst_bytes(tmp.path(), &mut seen_sizes)?;
            }
        }
        peak_ssts = peak_ssts.max(count_ssts(tmp.path())?);
    }
    let seed_secs = start.elapsed().as_secs_f64();

    // Drain any tiers left above min_threshold (trigger-ON runs only).
    let mut ssts_post_full_compact = None;
    if max_sst_count > 0 {
        loop {
            let merged = engine.compact_partial()?;
            if merged == 0 {
                break;
            }
            bytes_written += new_sst_bytes(tmp.path(), &mut seen_sizes)?;
        }
    } else {
        // Control: do the same full compaction as HEA-1870/C2 so the post-seed
        // count and post-full-compact count are both visible.
        engine.compact_ssts(2)?;
        ssts_post_full_compact = Some(count_ssts(tmp.path())?);
    }

    let live_ssts = count_ssts(tmp.path())?;
    let corpus_bytes = (n * RECORD_VALUE_BYTES) as f64;
    let write_amp = bytes_written as f64 / corpus_bytes;

    Ok(Rung {
        n,
        peak_ssts,
        live_ssts,
        ssts_post_full_compact,
        bytes_written,
        write_amp,
        merge_ms,
        seed_secs,
    })
}

// ─── helpers ────────────────────────────────────────────────────────────────

fn new_sst_bytes(dir: &Path, seen: &mut HashMap<u64, u64>) -> Result<u64, std::io::Error> {
    let mut written = 0u64;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_none_or(|ext| ext != "sst") {
            continue;
        }
        let Some(num) = path
            .file_stem()
            .and_then(|s| s.to_str())
            .and_then(|s| s.parse::<u64>().ok())
        else {
            continue;
        };
        let size = entry.metadata()?.len();
        if seen.get(&num).copied() != Some(size) {
            written += size;
            seen.insert(num, size);
        }
    }
    Ok(written)
}

fn count_ssts(dir: &Path) -> Result<usize, std::io::Error> {
    Ok(std::fs::read_dir(dir)?
        .filter_map(std::result::Result::ok)
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "sst"))
        .count())
}

/// Least-squares slope and R² of y on x.
fn linreg(xs: &[f64], ys: &[f64]) -> (f64, f64) {
    let m = xs.len() as f64;
    let mean_x = xs.iter().sum::<f64>() / m;
    let mean_y = ys.iter().sum::<f64>() / m;
    let (mut sxx, mut sxy, mut syy) = (0.0, 0.0, 0.0);
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

// ─── reporting ───────────────────────────────────────────────────────────────

fn print_config_results(label: &str, max_sst_count: usize, rungs: &[Rung]) {
    println!("### Config {label} (max_sst_count = {max_sst_count})\n");

    if max_sst_count == 0 {
        println!("corpus (n) | SSTs post-seed | SSTs post-full-compact | write-amp | seed (s)");
        println!("-----------+----------------+------------------------+-----------+---------");
        for r in rungs {
            println!(
                "{:>10} | {:>14} | {:>22} | {:>8.2}x | {:>7.2}",
                r.n,
                r.peak_ssts,
                r.ssts_post_full_compact.unwrap_or(0),
                r.write_amp,
                r.seed_secs
            );
        }
    } else {
        println!("corpus (n) | live SSTs | peak SSTs | bytes written | write-amp | seed (s)");
        println!("-----------+-----------+-----------+---------------+-----------+---------");
        for r in rungs {
            println!(
                "{:>10} | {:>9} | {:>9} | {:>13} | {:>8.2}x | {:>7.2}",
                r.n, r.live_ssts, r.peak_ssts, r.bytes_written, r.write_amp, r.seed_secs
            );
        }
    }
    println!();

    // Fit
    let log_n: Vec<f64> = rungs.iter().map(|r| (r.n as f64).ln()).collect();
    let log_peak: Vec<f64> = rungs
        .iter()
        .map(|r| (r.peak_ssts.max(1) as f64).ln())
        .collect();
    let (slope, r2) = linreg(&log_n, &log_peak);
    let verdict = if max_sst_count == 0 || slope > 0.3 {
        "MISS (super-logarithmic)"
    } else {
        "PASS (capped, O(1) fan-out)"
    };
    println!("Fit: log(peak fan-out) = {slope:.4} * log(n) + c   R² = {r2:.4}");
    println!("Verdict: {verdict}");
    println!();

    // Write amp
    if max_sst_count > 0 {
        let max_amp = rungs.iter().map(|r| r.write_amp).fold(0.0_f64, f64::max);
        println!("Write amplification: max across ladder = {max_amp:.2}x");
        println!();

        // Stall
        let mut all: Vec<f64> = rungs
            .iter()
            .flat_map(|r| r.merge_ms.iter().copied())
            .collect();
        if !all.is_empty() {
            all.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let p = |q: f64| all[((all.len() as f64 - 1.0) * q).round() as usize];
            let mean = all.iter().sum::<f64>() / all.len() as f64;
            println!(
                "Per-merge stall (flush_lock hold): merges={}, mean={:.1}ms, p50={:.1}ms, p99={:.1}ms, max={:.1}ms",
                all.len(),
                mean,
                p(0.50),
                p(0.99),
                all[all.len() - 1]
            );
        } else {
            println!("Per-merge stall: no merges fired.");
        }
        println!();
    }
}

// ─── main ────────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_lines)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Admissibility check
    let mem_avail_kb = std::fs::read_to_string("/proc/meminfo")
        .unwrap_or_default()
        .lines()
        .find(|l| l.starts_with("MemAvailable:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    let swap_used_kb = {
        let info = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
        let total: u64 = info
            .lines()
            .find(|l| l.starts_with("SwapTotal:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        let free: u64 = info
            .lines()
            .find(|l| l.starts_with("SwapFree:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        total.saturating_sub(free)
    };

    println!("═══════════════════════════════════════════════════════════════");
    println!(" HEA-1905 · E4 re-run: SST-count growth, three trigger values");
    println!("═══════════════════════════════════════════════════════════════\n");
    println!(
        "Record value bytes      = {RECORD_VALUE_BYTES}\n\
         Measurement flush bytes = {} KiB\n\
         merge_min               = {MERGE_MIN}\n\
         Trigger values swept    = {:?}\n",
        MEASURE_FLUSH_BYTES / 1024,
        TRIGGERS
    );
    println!("Admissibility check:");
    println!("  MemAvailable = {} GiB", mem_avail_kb / (1024 * 1024));
    println!("  Swap used    = {} MiB", swap_used_kb / 1024);
    println!();

    let mut results: Vec<(usize, Vec<Rung>)> = Vec::new();

    for &trigger in TRIGGERS {
        let label = if trigger == 0 {
            "C (control)".to_string()
        } else {
            format!("T{trigger}")
        };
        println!(
            "▶ Running config {label} (max_sst_count={trigger}, {} rungs) …",
            LADDER.len()
        );
        let rungs: Vec<Rung> = LADDER
            .iter()
            .map(|&n| measure_rung(n, trigger))
            .collect::<Result<_, _>>()?;
        results.push((trigger, rungs));
        println!("  done.\n");
    }

    println!("\n═══════════════════════════════════════════════════════════════");
    println!(" Results");
    println!("═══════════════════════════════════════════════════════════════\n");

    for (trigger, rungs) in &results {
        let label = if *trigger == 0 {
            "C (control)".to_string()
        } else {
            format!("T{trigger}")
        };
        print_config_results(&label, *trigger, rungs);
        println!("───────────────────────────────────────────────────────────────\n");
    }

    // Summary comparison table
    println!("## Summary — fitted exponents across configurations\n");
    println!(
        "{:<20} | {:>15} | {:>8} | {:>12} | verdict",
        "config", "peak-fan-out exp", "R²", "max write-amp"
    );
    println!(
        "{:<20}-+-{:->15}-+-{:->8}-+-{:->12}-+---------------",
        "", "", "", ""
    );
    for (trigger, rungs) in &results {
        let label = if *trigger == 0 {
            "C max_sst_count=0".to_string()
        } else {
            format!("T max_sst_count={trigger}")
        };
        let log_n: Vec<f64> = rungs.iter().map(|r| (r.n as f64).ln()).collect();
        let log_peak: Vec<f64> = rungs
            .iter()
            .map(|r| (r.peak_ssts.max(1) as f64).ln())
            .collect();
        let (slope, r2) = linreg(&log_n, &log_peak);
        let max_amp = rungs.iter().map(|r| r.write_amp).fold(0.0_f64, f64::max);
        let verdict = if *trigger == 0 || slope > 0.3 {
            "MISS"
        } else {
            "PASS (capped)"
        };
        println!(
            "{label:<20} | {:>15.4} | {:>8.4} | {:>11.2}x | {verdict}",
            slope, r2, max_amp
        );
    }
    println!();

    println!("## Recommendation\n");
    let slope_for = |trigger: usize| -> f64 {
        let (_, rungs) = results
            .iter()
            .find(|(t, _)| *t == trigger)
            .unwrap_or_else(|| panic!("T{trigger} result missing"));
        let log_n: Vec<f64> = rungs.iter().map(|r| (r.n as f64).ln()).collect();
        let log_peak: Vec<f64> = rungs
            .iter()
            .map(|r| (r.peak_ssts.max(1) as f64).ln())
            .collect();
        linreg(&log_n, &log_peak).0
    };
    let t8_slope = slope_for(8);
    let t12_slope = slope_for(12);
    let t16_slope = slope_for(16);

    // HEA-1936: the acceptance criterion for the HEA-1931 flipped default is
    // T12 exponent ≤ 0.20.
    if t12_slope <= 0.20 {
        println!(
            "HEA-1931 AC PASS — T12 (max_sst_count=12, the new default) exponent={t12_slope:.4} ≤ 0.20.\n\
             T8 exp={t8_slope:.4}  T16 exp={t16_slope:.4}"
        );
    } else {
        println!(
            "HEA-1931 AC MISS — T12 exponent={t12_slope:.4} > 0.20. The new default may need tuning.\n\
             T8 exp={t8_slope:.4}  T16 exp={t16_slope:.4}\n\
             Review results; consider a lower max_sst_count or tuned merge_min."
        );
    }

    Ok(())
}
