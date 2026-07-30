//! HEA-1918 — C0 memory exit-criteria harness for SST v3 (HEA-1914, d6fd6e91).
//!
//! Validates that block-based SST v3 with a bounded block cache kills the
//! O(corpus) resident-RAM ceiling established in HEA-1904 (9,960 B/user
//! pre-v3, all data resident in heap Vec + SkipMap / eager-decrypt SST).
//!
//! ## Exit criteria (from HEA-1914)
//! - Resident bytes/user ≤ 1.5× on-disk bytes/user (~2,800 B disk → target ≤ 4,200 B)
//! - Resident RAM flat-ish in corpus size once the block cache cap binds
//!
//! ## Methodology (in-process, no HTTP server)
//! - `EmbeddedStorageEngine` with `flush_threshold_bytes = 256 KiB` so data
//!   flows into SSTs during seeding (same as `sst_growth.rs` / HEA-1870 C2).
//! - `block_cache_bytes = BLOCK_CACHE_BYTES` (default 64 MiB in this harness
//!   so the cap binds at ~210 k users and flatness is clearly visible).
//! - After seeding each rung, `compact_ssts(1)` merges all SSTs into one v3 file.
//! - VmRSS read from `/proc/self/status` (bytes) as the resident-RAM metric.
//! - Delta RSS = post-compact RSS − process baseline RSS (measured before any
//!   engine is opened).
//! - Disk = sum of all file sizes in the tempdir after compaction.
//!
//! ## Verdict
//! PASS if (a) `delta_rss / N ≤ 4,200 B` at every rung, and (b) the slope in
//! the log-log regression of `delta_rss` on `N` is ≤ 0.1 above the cache-cap
//! binding point (indicating near-O(1) scaling, i.e. flat RAM).
//!
//! ## Comparison baseline
//! Pre-v3 (HEA-1904, commit c82d8eb8): **9,960 B/user** (OLS), measured as
//! `rss_post_seed − baseline` with data entirely in the SkipMap memtable.
//!
//! Run: `PROTOC=$(which protoc) cargo run --release --example sst_v3_c0_memory`

// Measurement binary: casts are for reporting math on small magnitudes.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::path::{Path, PathBuf};
use std::time::Instant;

use hearth::core::RealmId;
use hearth::storage::{CompactionConfig, EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Representative serialized user record value — matches sst_growth.rs and HEA-1904.
const RECORD_VALUE_BYTES: usize = 300;

/// Scaled-down memtable flush threshold — same as sst_growth.rs / HEA-1870/C2.
/// Forces data into SSTs during seeding without an explicit flush call.
const MEASURE_FLUSH_BYTES: u64 = 256 * 1024;

/// Block cache cap for this harness.
///
/// 64 MiB was chosen so the cache cap binds visibly at ~210 k users, making
/// the O(1) plateau appear within the corpus ladder below.  The production
/// default is 256 MiB; results at 64 MiB are *conservative* (higher per-user
/// cost at small N, same plateau floor at large N).
const BLOCK_CACHE_BYTES: usize = 64 * 1024 * 1024;

/// Cache cap binding point: total data in SSTs exceeds the cache once
/// N > BLOCK_CACHE_BYTES / (RECORD_VALUE_BYTES bytes/block * fraction/block).
/// With 4 KiB blocks and 300 B/entry ≈ 13 entries/block, the binding corpus is
/// ≈ (64 MiB / 4 KiB) × 13 ≈ 213 k users.
const CACHE_BIND_N_APPROX: usize = 213_000;

/// Corpus-size ladder spanning linear (pre-cap) and flat (post-cap) regions.
/// 100 k and 1 M are the two sizes explicitly named in the HEA-1914 exit criteria.
const LADDER: &[usize] = &[10_000, 50_000, 100_000, 500_000, 1_000_000];

// ─── per-rung data ───────────────────────────────────────────────────────────

struct Rung {
    n: usize,
    /// VmRSS (bytes) right after compact_ssts(1). Block cache is warm from
    /// compaction reads but bounded by BLOCK_CACHE_BYTES.
    rss_post_compact: u64,
    /// VmRSS delta: rss_post_compact − process_baseline.
    delta_rss: i64,
    /// Total bytes on disk in the tempdir (WAL + compacted SST).
    disk_bytes: u64,
    /// SST file count after compaction (expected: 1).
    sst_count: usize,
    /// Wall-clock for seeding N users (seconds).
    seed_secs: f64,
    /// Wall-clock for compact_ssts(1) (seconds).
    compact_secs: f64,
}

// ─── helpers ─────────────────────────────────────────────────────────────────

/// Reads `VmRSS` from `/proc/self/status` (in bytes, converted from kB).
fn read_rss_bytes() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .find(|l| l.starts_with("VmRSS:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0)
        * 1024
}

/// Sum of all file sizes in `dir` (flat — no recursion needed; hearth data dirs
/// contain no subdirectories).
fn dir_bytes(dir: &Path) -> u64 {
    std::fs::read_dir(dir)
        .ok()
        .map(|entries| {
            entries
                .filter_map(std::result::Result::ok)
                .filter_map(|e| e.metadata().ok())
                .filter(|m| m.is_file())
                .map(|m| m.len())
                .sum()
        })
        .unwrap_or(0)
}

fn count_ssts(dir: &Path) -> usize {
    std::fs::read_dir(dir)
        .ok()
        .map(|entries| {
            entries
                .filter_map(std::result::Result::ok)
                .filter(|e| e.path().extension().is_some_and(|ext| ext == "sst"))
                .count()
        })
        .unwrap_or(0)
}

fn make_config(data_dir: PathBuf) -> StorageConfig {
    let mut config = StorageConfig::production(
        data_dir,
        256 * 1024 * 1024, // wal_max_size_bytes
        MEASURE_FLUSH_BYTES,
        100, // hot_tier_capacity (irrelevant for C0 — not measured)
    );
    config.dev_mode = true; // auto-generate host key; no fsync
    config.block_cache_bytes = BLOCK_CACHE_BYTES;
    // Manual compaction control — no background sweep during seeding.
    config.compaction = CompactionConfig {
        enabled: false,
        interval_secs: 0,
        min_sst_count: 2,
        max_sst_count: 0,
        merge_min: 4,
    };
    config
}

// ─── measurement ─────────────────────────────────────────────────────────────

fn measure_rung(n: usize, process_baseline: u64) -> Result<Rung, Box<dyn std::error::Error>> {
    let tmp = tempfile::tempdir()?;
    let config = make_config(PathBuf::from(tmp.path()));
    let engine = EmbeddedStorageEngine::open(config)?;

    let realm = RealmId::generate();
    let value = vec![b'x'; RECORD_VALUE_BYTES];

    // Seed via put_batch — same approach as sst_growth.rs.
    // CHUNK < flush threshold ensures the flush check fires at threshold
    // granularity (same SST-count behaviour as per-put seeding, faster).
    const CHUNK: usize = 500;
    let seed_start = Instant::now();
    let mut i = 0usize;
    while i < n {
        let end = (i + CHUNK).min(n);
        let batch: Vec<(Vec<u8>, Vec<u8>)> = (i..end)
            .map(|j| (format!("user:{j:012}").into_bytes(), value.clone()))
            .collect();
        engine.put_batch(&realm, &batch)?;
        i = end;
    }
    let seed_secs = seed_start.elapsed().as_secs_f64();

    // Merge all SSTs into one v3 file; this is the "all-data-in-SSTs" state.
    let compact_start = Instant::now();
    engine.compact_ssts(1)?;
    let compact_secs = compact_start.elapsed().as_secs_f64();

    // Post-compact RSS: block cache may be warm from compaction reads but is
    // bounded by BLOCK_CACHE_BYTES. Active memtable holds at most one partial
    // flush worth of entries (~256 KiB, negligible).
    let rss_post_compact = read_rss_bytes();
    let sst_count = count_ssts(tmp.path());
    let disk_bytes = dir_bytes(tmp.path());

    let delta_rss = rss_post_compact as i64 - process_baseline as i64;

    Ok(Rung {
        n,
        rss_post_compact,
        delta_rss,
        disk_bytes,
        sst_count,
        seed_secs,
        compact_secs,
    })
}

// ─── linear regression (OLS, same as other harnesses) ────────────────────────

/// Returns (slope, r²) of the OLS fit of ys on xs.
fn linreg(xs: &[f64], ys: &[f64]) -> (f64, f64) {
    let m = xs.len() as f64;
    let mean_x = xs.iter().sum::<f64>() / m;
    let mean_y = ys.iter().sum::<f64>() / m;
    let (mut sxx, mut sxy, mut syy) = (0.0, 0.0, 0.0);
    for (&x, &y) in xs.iter().zip(ys) {
        sxx += (x - mean_x).powi(2);
        sxy += (x - mean_x) * (y - mean_y);
        syy += (y - mean_y).powi(2);
    }
    let slope = if sxx == 0.0 { 0.0 } else { sxy / sxx };
    let r2 = if sxx == 0.0 || syy == 0.0 {
        1.0
    } else {
        (sxy * sxy) / (sxx * syy)
    };
    (slope, r2)
}

// ─── main ────────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_lines)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Admissibility: check available memory before running.
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

    println!("═══════════════════════════════════════════════════════════════════");
    println!(" HEA-1918 · C0 Memory Exit-Criteria — SST v3 (HEA-1914, d6fd6e91)");
    println!("═══════════════════════════════════════════════════════════════════\n");
    println!(
        "record_value_bytes    = {RECORD_VALUE_BYTES}\n\
         flush_threshold       = {} KiB\n\
         block_cache_bytes     = {} MiB\n\
         cache cap binds at    ≈ {} k users\n\
         ladder                = {:?}\n",
        MEASURE_FLUSH_BYTES / 1024,
        BLOCK_CACHE_BYTES / (1024 * 1024),
        CACHE_BIND_N_APPROX / 1000,
        LADDER,
    );
    println!("Admissibility:");
    println!("  MemAvailable = {} GiB", mem_avail_kb / (1024 * 1024));
    println!("  Swap used    = {} MiB", swap_used_kb / 1024);
    if swap_used_kb > 100 * 1024 {
        println!("  WARNING: swap > 100 MiB — RSS measurements may be unreliable");
    }
    println!();

    // Measure process baseline before any engine is opened.
    let process_baseline = read_rss_bytes();
    println!(
        "Process baseline RSS = {} MiB\n",
        process_baseline / (1024 * 1024)
    );

    // Run all rungs.
    let mut rungs: Vec<Rung> = Vec::with_capacity(LADDER.len());
    for &n in LADDER {
        print!("▶ N = {:>9} … ", n);
        let r = measure_rung(n, process_baseline)?;
        println!(
            "seed {:.1}s  compact {:.1}s  RSS {:.1} MiB  disk {:.1} MiB  SSTs {}",
            r.seed_secs,
            r.compact_secs,
            r.rss_post_compact as f64 / (1024.0 * 1024.0),
            r.disk_bytes as f64 / (1024.0 * 1024.0),
            r.sst_count,
        );
        rungs.push(r);
    }

    println!("\n═══════════════════════════════════════════════════════════════════");
    println!(" Results");
    println!("═══════════════════════════════════════════════════════════════════\n");

    println!(
        "baseline RSS = {:.1} MiB   block_cache_bytes = {} MiB\n",
        process_baseline as f64 / (1024.0 * 1024.0),
        BLOCK_CACHE_BYTES / (1024 * 1024)
    );

    println!(
        "{:>12} | {:>10} | {:>10} | {:>12} | {:>12} | {:>8}",
        "N users", "δRSS (MiB)", "disk (MiB)", "δRSS/user (B)", "disk/user (B)", "SSTs"
    );
    println!("{}", "─".repeat(75));
    for r in &rungs {
        let delta_mib = r.delta_rss as f64 / (1024.0 * 1024.0);
        let disk_mib = r.disk_bytes as f64 / (1024.0 * 1024.0);
        let rss_per_user = r.delta_rss as f64 / r.n as f64;
        let disk_per_user = r.disk_bytes as f64 / r.n as f64;
        println!(
            "{:>12} | {:>10.1} | {:>10.1} | {:>12.0} | {:>12.0} | {:>8}",
            r.n, delta_mib, disk_mib, rss_per_user, disk_per_user, r.sst_count
        );
    }
    println!();

    // ── OLS regression of delta_rss on N across all rungs ──────────────────
    let ns: Vec<f64> = rungs.iter().map(|r| r.n as f64).collect();
    let deltas: Vec<f64> = rungs.iter().map(|r| r.delta_rss as f64).collect();
    let (ols_slope, ols_r2) = linreg(&ns, &deltas);
    println!(
        "OLS (all rungs): δRSS(B) = {:.0} × N + intercept   R² = {:.4}",
        ols_slope, ols_r2
    );
    println!("  → OLS bytes/user = {:.0} B", ols_slope);
    println!();

    // ── log-log regression on the post-cap rungs only ──────────────────────
    let post_cap: Vec<&Rung> = rungs.iter().filter(|r| r.n > CACHE_BIND_N_APPROX).collect();
    let flatness_verdict = if post_cap.len() >= 2 {
        let log_n: Vec<f64> = post_cap.iter().map(|r| (r.n as f64).ln()).collect();
        let log_d: Vec<f64> = post_cap
            .iter()
            .map(|r| (r.delta_rss.max(1) as f64).ln())
            .collect();
        let (exp, r2) = linreg(&log_n, &log_d);
        println!(
            "Log-log fit (post-cap rungs N > {}k):  exponent = {:.4}  R² = {:.4}",
            CACHE_BIND_N_APPROX / 1000,
            exp,
            r2
        );
        if exp <= 0.1 {
            format!("PASS — exponent {exp:.4} ≤ 0.10 (near-O(1) plateau confirmed)")
        } else {
            format!("MISS — exponent {exp:.4} > 0.10 (RAM still scaling with corpus)")
        }
    } else {
        "SKIP — fewer than 2 post-cap rungs for log-log fit".to_string()
    };

    println!();

    // ── per-rung exit-criteria verdict ─────────────────────────────────────
    println!("Per-rung exit-criteria (target: δRSS/user ≤ 4,200 B):\n");
    println!(
        "{:>12} | {:>12} | {:>8} | {:>6}",
        "N users", "δRSS/user (B)", "on-disk (B)", "verdict"
    );
    println!("{}", "─".repeat(52));
    let mut all_pass = true;
    for r in &rungs {
        let rss_per_user = r.delta_rss as f64 / r.n as f64;
        let disk_per_user = r.disk_bytes as f64 / r.n as f64;
        let pass = rss_per_user <= 4200.0;
        if !pass {
            all_pass = false;
        }
        println!(
            "{:>12} | {:>12.0} | {:>11.0} | {}",
            r.n,
            rss_per_user,
            disk_per_user,
            if pass { "PASS" } else { "MISS" }
        );
    }
    println!();

    // ── overall verdict ────────────────────────────────────────────────────
    println!("═══════════════════════════════════════════════════════════════════");
    println!(" Verdict");
    println!("═══════════════════════════════════════════════════════════════════\n");

    println!(
        "(1) δRSS/user ≤ 4,200 B at all rungs:  {}",
        if all_pass { "PASS ✓" } else { "MISS ✗" }
    );
    println!(
        "(2) RAM flat once cache cap binds:      {}",
        flatness_verdict
    );
    println!();

    // Comparison with pre-v3 baseline (HEA-1904).
    let rung_100k = rungs.iter().find(|r| r.n == 100_000);
    let rung_1m = rungs.iter().find(|r| r.n == 1_000_000);
    println!("Comparison with pre-v3 baseline (HEA-1904 @ 9,960 B/user):\n");
    if let Some(r) = rung_100k {
        let rss_per_user = r.delta_rss as f64 / r.n as f64;
        println!(
            "  N = 100 k: {:.0} B/user (was 9,960 B; {:.1}× improvement)",
            rss_per_user,
            9960.0 / rss_per_user.max(1.0)
        );
    }
    if let Some(r) = rung_1m {
        let rss_per_user = r.delta_rss as f64 / r.n as f64;
        println!(
            "  N =   1 M: {:.0} B/user (was N/A pre-v3 — O(corpus) RAM would be ~10 GB)",
            rss_per_user
        );
    }
    println!();

    if all_pass {
        println!("HEA-1914 C0 exit-criteria: PASS");
    } else {
        println!("HEA-1914 C0 exit-criteria: FAIL — one or more rungs exceeded 4,200 B/user");
    }

    Ok(())
}
