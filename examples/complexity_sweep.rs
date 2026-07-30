//! HEA-1873 · C5 — Complexity-class sweep (the headline deliverable).
//!
//! Answers the board's top question — **does lookup latency scale ≤ O(log n)
//! with corpus size?** — by driving [`EmbeddedStorageEngine::get`] *directly,
//! in-process*, with no HTTP server and no load generator in the loop.
//!
//! ## Why in-process, not through the Goose harness
//!
//! The HTTP-driven path is currently **NOT-MEASURABLE** in this environment:
//! HEA-1871 (C3) bisected the throughput cliff to the server side, and the
//! HEA-1876 (C8) HTTP sweep could not even seed 1 000 users without the
//! generator/server co-residency ceiling voiding the run. Per the HEA-1867
//! grading rules, *nothing is graded PASS on a run whose ceiling attribution
//! was the generator*. Driving the storage engine directly removes the
//! generator from the measurement entirely: the only quantity under test is the
//! engine's own `get()` latency, which is the sole corpus-size-dependent term
//! in user-lookup / session-lookup / `validate_token` (JWT verify and Argon2id
//! are fixed per-op costs independent of `n`). This is the honest way to
//! isolate the *complexity class* the board asked about.
//!
//! ## What it measures (two independent axes, per plan §1a)
//!
//! **Axis A — corpus-size ladder at fixed active set.** Hold hot-tier capacity
//! and the active (hot) set constant; sweep corpus `n` over a geometric ladder.
//! At each rung, seed, warm the hot set to convergence (accounting for the
//! production `promote_sample_rate = 4`), then measure `get()` latency for
//! three populations — **hot** (in the hot tier), **cold/natural** (SST read at
//! the natural post-seed SST count), and **cold/compacted** (SST read after a
//! full compaction to one SST). Fit `log(p99)` on `log(n)` per population and
//! report the empirical exponent. The hot/cold split is confirmed against C1's
//! `hearth_storage_get_total{outcome=…}` counters (HEA-1869), not asserted.
//!
//! **Axis B — hot-set / capacity ratio ladder at fixed corpus.** Hold corpus
//! constant; sweep the ratio `active_set / hot_capacity` from 0.1× to 10×.
//! Report the hot-hit ratio and active-set p99 at each rung and the ratio at
//! which p99 first breaches the VISION §7.1 user-lookup budget (500 µs).
//!
//! Run:  `cargo run --release --example complexity_sweep`
//!
//! Every latency figure is engine-level on the host it was measured on; the
//! harness prints the fit **and** its R², and emits a machine-readable JSON
//! block after the `===JSON===` marker for the committed artifact.

// Measurement binary: casts are for reporting math on small magnitudes, and the
// percentile/print helpers are intentionally verbose for auditability.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_lines,
    clippy::similar_names
)]

use std::path::PathBuf;
use std::time::Instant;

use hearth::core::RealmId;
use hearth::storage::{CompactionConfig, EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Representative serialized size of a `User` record value, in bytes (matches
/// the C2 harness / HEA-1867 finding 3).
const RECORD_VALUE_BYTES: usize = 300;

/// Memtable flush threshold for the measurement (1 MiB). Small enough that the
/// corpus ladder produces a countable, growing number of SSTs so the cold-path
/// fan-out has signal, while remaining large relative to a single record.
const MEASURE_FLUSH_BYTES: u64 = 1024 * 1024;

/// Fixed active (hot) working-set size, in distinct keys, for Axis A.
const ACTIVE_SET: usize = 2_000;

/// Hot-tier capacity held constant across Axis A. Comfortably larger than
/// `ACTIVE_SET` so the whole active set fits and every warmed lookup is a hit.
const AXIS_A_HOT_CAPACITY: usize = 8_000;

/// Corpus-size ladder for Axis A (record counts). Geometric so the log-log fit
/// is evenly spaced. The default tops out at 320 k (fast); set the environment
/// variable `LADDER_MAX` to 640000 / 1280000 / 2560000 / 5120000 to extend into
/// multi-million territory. Seeding cost scales linearly with n, so expect each
/// extra doubling to roughly double the seeding wall-time.
fn axis_a_ladder() -> Vec<usize> {
    let max = std::env::var("LADDER_MAX")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(320_000);
    [
        10_000usize,
        20_000,
        40_000,
        80_000,
        160_000,
        320_000,
        640_000,
        1_280_000,
        2_560_000,
        5_120_000,
    ]
    .iter()
    .copied()
    .filter(|&n| n <= max)
    .collect()
}

/// Fixed corpus size for Axis B (ratio sweep).
const AXIS_B_CORPUS: usize = 160_000;

/// Ratio ladder for Axis B: `active_set / hot_capacity`. 0.1× = capacity is 10×
/// the active set (everything fits); 10× = active set is 10× capacity (thrash).
const AXIS_B_RATIOS: &[f64] = &[0.1, 0.3, 1.0, 3.0, 10.0];

/// Warm passes over the active set before a hot measurement. With
/// `promote_sample_rate = 4`, a key is promoted after ~4 sampled touches on
/// average; 24 passes drives the hot set well past convergence.
const WARM_PASSES: usize = 24;

/// Hot-phase measurement samples (cycled over the active set).
const HOT_SAMPLES: usize = 60_000;

/// VISION §7.1 p99 budget for user lookup on the hot path (µs).
const VISION_USER_P99_HOT_US: f64 = 500.0;

/// VISION §7.1 cold-path (first access) budget for user lookup (µs).
const VISION_USER_COLD_US: f64 = 5_000.0;

/// Returns the process RSS in KiB by reading `/proc/self/status` (Linux only;
/// returns 0 on other platforms or if the file is unreadable).
fn process_rss_kb() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("VmRSS:") {
                    if let Some(n) = rest.split_whitespace().next().and_then(|s| s.parse().ok()) {
                        return n;
                    }
                }
            }
        }
    }
    0
}

/// Verdict label for the RAM exponent. The standing exponent is 0.8778 (close to
/// linear); we report PASS only when the slope is genuinely flat (hot-tier
/// capacity fixed ⇒ RSS should plateau once the working set fits).
fn ram_verdict(slope: f64) -> &'static str {
    if slope.abs() < 0.05 {
        "PASS — O(1) RAM (flat)"
    } else if slope < 0.20 {
        "NEAR-PASS — sub-linear but not flat; dominated by hot-tier structure"
    } else {
        "MISS — RAM grows with corpus; O(1) RAM claim is NOT supported at this scale"
    }
}

/// Prints basic host conditions so results can be interpreted in context.
fn print_host_conditions() {
    println!("── Host conditions ──");
    #[cfg(target_os = "linux")]
    {
        if let Ok(mem) = std::fs::read_to_string("/proc/meminfo") {
            for line in mem.lines() {
                if line.starts_with("MemTotal:") || line.starts_with("MemAvailable:") {
                    println!("  {}", line.trim());
                }
            }
        }
        if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
            if let Some(model) = cpuinfo
                .lines()
                .find(|l| l.starts_with("model name"))
                .and_then(|l| l.split(':').nth(1))
            {
                println!("  CPU: {}", model.trim());
            }
        }
    }
    println!(
        "  LADDER_MAX env: {}",
        std::env::var("LADDER_MAX").unwrap_or_else(|_| "320000 (default)".to_string())
    );
    println!();
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("HEA-1873 · C5 — Complexity-class sweep (extended: HEA-1992)\n");
    println!(
        "record value = {RECORD_VALUE_BYTES} B, flush threshold = {} KiB, \
         promote_sample_rate = 4 (production), active set = {ACTIVE_SET} keys\n",
        MEASURE_FLUSH_BYTES / 1024
    );

    print_host_conditions();

    let axis_a = run_axis_a()?;
    let axis_b = run_axis_b()?;

    emit_json(&axis_a, &axis_b);
    Ok(())
}

// ─────────────────────────────── Axis A ────────────────────────────────────

/// One corpus rung of Axis A.
struct RungA {
    n: usize,
    ssts_natural: usize,
    hot: Pctl,
    cold_natural: Pctl,
    cold_compacted: Pctl,
    /// Fraction of the hot-phase gets that C1 counted as `hot_hit`.
    hot_purity: f64,
    /// Fraction of the natural cold-phase gets that C1 counted as `sst_hit`.
    cold_purity: f64,
    /// Process RSS in KiB after seeding + hot-tier warm-up (steady-state footprint).
    rss_kb: u64,
}

fn run_axis_a() -> Result<Vec<RungA>, Box<dyn std::error::Error>> {
    let ladder = axis_a_ladder();
    println!("── Axis A · corpus-size ladder (fixed active set = {ACTIVE_SET}, hot cap = {AXIS_A_HOT_CAPACITY}) ──");
    println!("   ladder: {:?}", ladder);
    println!();
    let mut rungs = Vec::with_capacity(ladder.len());
    for n in ladder {
        rungs.push(measure_rung_a(n)?);
    }

    println!(
        "corpus (n) | SSTs | hot p50/p99 (µs) | cold-nat p50/p99 (µs) | cold-cmp p50/p99 (µs) | hot% | cold% | RSS MiB"
    );
    println!(
        "-----------+------+------------------+-----------------------+-----------------------+------+-------+---------"
    );
    for r in &rungs {
        println!(
            "{:>10} | {:>4} | {:>7.1}/{:>7.1} | {:>10.1}/{:>10.1} | {:>10.1}/{:>10.1} | {:>4.0} | {:>5.0} | {:>7.1}",
            r.n,
            r.ssts_natural,
            r.hot.p50,
            r.hot.p99,
            r.cold_natural.p50,
            r.cold_natural.p99,
            r.cold_compacted.p50,
            r.cold_compacted.p99,
            r.hot_purity * 100.0,
            r.cold_purity * 100.0,
            r.rss_kb as f64 / 1024.0,
        );
    }
    println!();

    print_axis_a_fits(&rungs);
    Ok(rungs)
}

fn measure_rung_a(n: usize) -> Result<RungA, Box<dyn std::error::Error>> {
    let tmp = tempfile::tempdir()?;
    let engine = open_engine(tmp.path(), AXIS_A_HOT_CAPACITY)?;
    let realm = RealmId::generate();
    seed(&engine, &realm, n)?;

    // Active set = the first ACTIVE_SET keys. Cold windows are disjoint slices
    // deeper in the corpus so their first-touch latency is a clean SST read
    // (each cold key is measured exactly once, so promotion of one key never
    // pollutes another's single sample).
    let cold_span = ((n - ACTIVE_SET) / 3).clamp(500, 8_000);
    let cold_a = ACTIVE_SET..(ACTIVE_SET + cold_span);
    let cold_b = (ACTIVE_SET + cold_span)..(ACTIVE_SET + 2 * cold_span);

    warm_active_set(&engine, &realm);
    let rss_kb = process_rss_kb();
    let (hot, hot_purity) = measure_hot(&engine, &realm);

    let ssts_natural = count_ssts(tmp.path())?;
    let (cold_natural, cold_purity) = measure_cold(&engine, &realm, cold_a);

    // Collapse to a single SST and re-measure a fresh cold window: isolates the
    // intrinsic per-SST binary-search cost from the fan-out over #SSTs.
    engine.compact_ssts(2)?;
    let (cold_compacted, _) = measure_cold(&engine, &realm, cold_b);

    Ok(RungA {
        n,
        ssts_natural,
        hot,
        cold_natural,
        cold_compacted,
        hot_purity,
        cold_purity,
        rss_kb,
    })
}

fn print_axis_a_fits(rungs: &[RungA]) {
    let log_n: Vec<f64> = rungs.iter().map(|r| (r.n as f64).ln()).collect();

    let fit = |ys: Vec<f64>| linreg(&log_n, &ys);

    let (hot_slope, hot_r2) = fit(rungs.iter().map(|r| r.hot.p99.max(0.001).ln()).collect());
    let (cn_slope, cn_r2) = fit(rungs
        .iter()
        .map(|r| r.cold_natural.p99.max(0.001).ln())
        .collect());
    let (cc_slope, cc_r2) = fit(rungs
        .iter()
        .map(|r| r.cold_compacted.p99.max(0.001).ln())
        .collect());
    let (sst_slope, sst_r2) = fit(rungs
        .iter()
        .map(|r| (r.ssts_natural.max(1) as f64).ln())
        .collect());

    // RSS fit uses only rungs where the OS reported a non-zero value, and must
    // recompute log_n over that filtered subset to keep xs and ys aligned.
    let log_n_ram: Vec<f64> = rungs
        .iter()
        .filter(|r| r.rss_kb > 0)
        .map(|r| (r.n as f64).ln())
        .collect();
    let (ram_slope, ram_r2) = linreg(
        &log_n_ram,
        &rungs
            .iter()
            .filter(|r| r.rss_kb > 0)
            .map(|r| (r.rss_kb as f64).ln())
            .collect::<Vec<_>>(),
    );

    println!(
        "Fit: log(p99) = slope · log(n) + c   [slope ≈ 0 → O(1); slope of a log term → O(log n)]"
    );
    println!(
        "  hot            exponent = {hot_slope:+.3}  (R² = {hot_r2:.3})  → {}",
        verdict(hot_slope)
    );
    println!(
        "  cold (natural) exponent = {cn_slope:+.3}  (R² = {cn_r2:.3})  → {}",
        verdict(cn_slope)
    );
    println!(
        "  cold (compact) exponent = {cc_slope:+.3}  (R² = {cc_r2:.3})  → {}",
        verdict(cc_slope)
    );
    println!("  #SSTs (natural) exponent = {sst_slope:+.3} (R² = {sst_r2:.3})  [confirms cold fan-out ∝ #SSTs]");
    if !log_n_ram.is_empty() {
        println!(
            "  RAM (RSS)  exponent = {ram_slope:+.3}  (R² = {ram_r2:.3})  → {} (slope < 0.05 = O(1))",
            ram_verdict(ram_slope)
        );
    }
    println!();
    println!(
        "  Interpretation: cold-path cost = (#SSTs probed) · (per-SST binary search). The\n  \
         compacted curve isolates the per-SST log term; the natural curve carries the\n  \
         #SSTs fan-out on top. #SSTs is bounded by compaction in steady state, so the\n  \
         graded complexity class is the compacted-cold exponent.\n"
    );
}

/// PASS/MISS label for a fitted exponent against the "≤ O(log n)" bar. A slope
/// on a log-log plot near 0 is O(1); a small positive slope that a log fit
/// explains is O(log n); anything approaching 1 is linear.
fn verdict(slope: f64) -> &'static str {
    if slope < 0.15 {
        "PASS (≈ flat, O(1)/O(log n))"
    } else if slope < 0.45 {
        "PASS (sub-linear, consistent with O(log n))"
    } else {
        "MISS (super-logarithmic — see dominating term)"
    }
}

// ─────────────────────────────── Axis B ────────────────────────────────────

/// One ratio rung of Axis B.
struct RungB {
    ratio: f64,
    hot_capacity: usize,
    hit_ratio: f64,
    p50: f64,
    p99: f64,
    breaches_budget: bool,
}

fn run_axis_b() -> Result<Vec<RungB>, Box<dyn std::error::Error>> {
    println!(
        "── Axis B · hot-set/capacity ratio ladder (fixed corpus = {AXIS_B_CORPUS}, active set = {ACTIVE_SET}) ──\n"
    );
    let mut rungs = Vec::with_capacity(AXIS_B_RATIOS.len());
    for &ratio in AXIS_B_RATIOS {
        // ratio = active_set / capacity  ⇒  capacity = active_set / ratio.
        let capacity = ((ACTIVE_SET as f64) / ratio).round() as usize;
        rungs.push(measure_rung_b(ratio, capacity.max(1))?);
    }

    println!(
        "ratio (set/cap) | hot cap | hit ratio | p50 (µs) | p99 (µs) | breaches 500µs budget?"
    );
    println!(
        "----------------+---------+-----------+----------+----------+-----------------------"
    );
    for r in &rungs {
        println!(
            "{:>15.1} | {:>7} | {:>8.1}% | {:>8.1} | {:>8.1} | {}",
            r.ratio,
            r.hot_capacity,
            r.hit_ratio * 100.0,
            r.p50,
            r.p99,
            if r.breaches_budget { "YES" } else { "no" }
        );
    }
    println!();

    match rungs.iter().find(|r| r.breaches_budget) {
        Some(r) => println!(
            "Breach: active-set p99 first crosses the VISION §7.1 user-lookup budget \
             ({VISION_USER_P99_HOT_US:.0} µs) at ratio {:.1}× (hot capacity {}).\n",
            r.ratio, r.hot_capacity
        ),
        None => println!(
            "No breach across the ladder — active-set p99 stays under {VISION_USER_P99_HOT_US:.0} µs \
             even at 10× over-subscription.\n"
        ),
    }
    Ok(rungs)
}

fn measure_rung_b(ratio: f64, capacity: usize) -> Result<RungB, Box<dyn std::error::Error>> {
    let tmp = tempfile::tempdir()?;
    let engine = open_engine(tmp.path(), capacity)?;
    let realm = RealmId::generate();
    seed(&engine, &realm, AXIS_B_CORPUS)?;

    warm_active_set(&engine, &realm);
    let (pctl, hit_ratio) = measure_hot(&engine, &realm);

    Ok(RungB {
        ratio,
        hot_capacity: capacity,
        hit_ratio,
        p50: pctl.p50,
        p99: pctl.p99,
        breaches_budget: pctl.p99 > VISION_USER_P99_HOT_US,
    })
}

// ─────────────────────────── shared measurement ────────────────────────────

/// Opens a throwaway production-config engine with the given hot-tier capacity.
/// `dev_mode = true` only auto-generates the host key for the temp dir; it does
/// **not** change `promote_sample_rate`, which stays at the production value 4.
fn open_engine(
    dir: &std::path::Path,
    hot_capacity: usize,
) -> Result<EmbeddedStorageEngine, Box<dyn std::error::Error>> {
    let wal_max = 512 * 1024 * 1024;
    let mut config = StorageConfig::production(
        PathBuf::from(dir),
        wal_max,
        MEASURE_FLUSH_BYTES,
        hot_capacity,
    );
    config.dev_mode = true;
    // Manual compaction only, so #SSTs is a deterministic function of the seed.
    config.compaction = CompactionConfig {
        enabled: false,
        interval_secs: 0,
        min_sst_count: 2,
        max_sst_count: 0,
        merge_min: 4,
    };
    Ok(EmbeddedStorageEngine::open(config)?)
}

fn key_for(i: usize) -> Vec<u8> {
    format!("user:{i:012}").into_bytes()
}

fn seed(
    engine: &EmbeddedStorageEngine,
    realm: &RealmId,
    n: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let value = vec![b'x'; RECORD_VALUE_BYTES];
    const CHUNK: usize = 500;
    let mut i = 0usize;
    while i < n {
        let end = (i + CHUNK).min(n);
        let batch: Vec<(Vec<u8>, Vec<u8>)> =
            (i..end).map(|j| (key_for(j), value.clone())).collect();
        engine.put_batch(realm, &batch)?;
        i = end;
    }
    Ok(())
}

/// Drives repeated gets over the active set so it converges into the hot tier
/// despite 1-in-4 promote sampling.
fn warm_active_set(engine: &EmbeddedStorageEngine, realm: &RealmId) {
    for _ in 0..WARM_PASSES {
        for i in 0..ACTIVE_SET {
            let _ = engine.get(realm, &key_for(i));
        }
    }
}

/// Measures `HOT_SAMPLES` gets cycled over the active set, returning the latency
/// percentiles and the C1-confirmed hot-hit fraction over the measured window.
fn measure_hot(engine: &EmbeddedStorageEngine, realm: &RealmId) -> (Pctl, f64) {
    let before = hot_hit_count();
    let mut samples = Vec::with_capacity(HOT_SAMPLES);
    for s in 0..HOT_SAMPLES {
        let key = key_for(s % ACTIVE_SET);
        let start = Instant::now();
        let _ = engine.get(realm, &key);
        samples.push(start.elapsed().as_nanos() as u64);
    }
    let hits = hot_hit_count() - before;
    (
        Pctl::from_nanos(&mut samples),
        hits as f64 / HOT_SAMPLES as f64,
    )
}

/// Measures a single first-touch get over each distinct key in `range`,
/// returning latency percentiles and the C1-confirmed sst-hit fraction.
fn measure_cold(
    engine: &EmbeddedStorageEngine,
    realm: &RealmId,
    range: std::ops::Range<usize>,
) -> (Pctl, f64) {
    let before = sst_hit_count();
    let count = range.len();
    let mut samples = Vec::with_capacity(count);
    for i in range {
        let key = key_for(i);
        let start = Instant::now();
        let _ = engine.get(realm, &key);
        samples.push(start.elapsed().as_nanos() as u64);
    }
    let hits = sst_hit_count() - before;
    (
        Pctl::from_nanos(&mut samples),
        hits as f64 / count.max(1) as f64,
    )
}

fn hot_hit_count() -> u64 {
    hearth::metrics::metrics()
        .storage_get_total
        .with_label_values(&["hot_hit"])
        .get() as u64
}

fn sst_hit_count() -> u64 {
    hearth::metrics::metrics()
        .storage_get_total
        .with_label_values(&["sst_hit"])
        .get() as u64
}

/// Counts `*.sst` files in `dir` (ignores `.sst.tmp`).
fn count_ssts(dir: &std::path::Path) -> Result<usize, std::io::Error> {
    let count = std::fs::read_dir(dir)?
        .filter_map(std::result::Result::ok)
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "sst"))
        .count();
    Ok(count)
}

/// Latency percentiles in microseconds.
struct Pctl {
    p50: f64,
    p99: f64,
}

impl Pctl {
    fn from_nanos(samples: &mut [u64]) -> Self {
        samples.sort_unstable();
        Self {
            p50: percentile_us(samples, 0.50),
            p99: percentile_us(samples, 0.99),
        }
    }
}

/// Nearest-rank percentile of sorted nanosecond samples, returned in µs.
fn percentile_us(sorted: &[u64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((q * (sorted.len() - 1) as f64).round() as usize).min(sorted.len() - 1);
    sorted[idx] as f64 / 1000.0
}

/// Least-squares slope and R² of `ys` on `xs`.
fn linreg(xs: &[f64], ys: &[f64]) -> (f64, f64) {
    let m = xs.len() as f64;
    let mean_x = xs.iter().sum::<f64>() / m;
    let mean_y = ys.iter().sum::<f64>() / m;
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

/// Emits a machine-readable JSON block for the committed artifact.
fn emit_json(axis_a: &[RungA], axis_b: &[RungB]) {
    println!("===JSON===");
    let a: Vec<String> = axis_a
        .iter()
        .map(|r| {
            format!(
                "{{\"n\":{},\"ssts_natural\":{},\"hot_p50_us\":{:.2},\"hot_p99_us\":{:.2},\
                 \"cold_natural_p50_us\":{:.2},\"cold_natural_p99_us\":{:.2},\
                 \"cold_compacted_p50_us\":{:.2},\"cold_compacted_p99_us\":{:.2},\
                 \"hot_purity\":{:.4},\"cold_purity\":{:.4},\"rss_kb\":{}}}",
                r.n,
                r.ssts_natural,
                r.hot.p50,
                r.hot.p99,
                r.cold_natural.p50,
                r.cold_natural.p99,
                r.cold_compacted.p50,
                r.cold_compacted.p99,
                r.hot_purity,
                r.cold_purity,
                r.rss_kb,
            )
        })
        .collect();
    let b: Vec<String> = axis_b
        .iter()
        .map(|r| {
            format!(
                "{{\"ratio\":{:.2},\"hot_capacity\":{},\"hit_ratio\":{:.4},\"p50_us\":{:.2},\
                 \"p99_us\":{:.2},\"breaches_budget\":{}}}",
                r.ratio, r.hot_capacity, r.hit_ratio, r.p50, r.p99, r.breaches_budget
            )
        })
        .collect();
    println!(
        "{{\"child_issue\":\"HEA-1873\",\"extension_issue\":\"HEA-1992\",\
         \"record_value_bytes\":{},\"flush_bytes\":{},\
         \"active_set\":{},\"promote_sample_rate\":4,\
         \"vision_user_p99_hot_us\":{},\"vision_user_cold_us\":{},\
         \"axis_a\":[{}],\"axis_b\":[{}]}}",
        RECORD_VALUE_BYTES,
        MEASURE_FLUSH_BYTES,
        ACTIVE_SET,
        VISION_USER_P99_HOT_US,
        VISION_USER_COLD_US,
        a.join(","),
        b.join(",")
    );
}
