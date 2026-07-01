//! Point-lookup latency guard bench for the storage engine.
//!
//! TDD regression guard authored in HEA-1625 (Phase 1) for the HEA-1624
//! lookup-performance fix track.
//!
//! Two scenarios × three realm sizes (10 k / 100 k / 500 k users):
//!   (a) **hot-tier hit** — key already promoted to the ArcSwap hot tier;
//!       exercises the lock-free O(1) read path only.
//!   (b) **cold random** — key not present in hot tier; exercises the
//!       memtable BTreeMap O(log n) + SST binary-search O(k · log n) path.
//!
//! ## Flat-latency gate
//!
//! The `gate_flat_latency()` function runs before Criterion sampling and
//! panics (→ non-zero exit) if any of the following invariants are violated:
//!
//! | Invariant | Limit |
//! |-----------|-------|
//! | Hot-tier p99, any realm size | ≤ 100 µs |
//! | Cold-path p99, any realm size | ≤ 5 ms |
//! | Cold p99 growth (500 k / 10 k) | ≤ 20 × |
//!
//! A failing gate is the "red" signal that Phase 2 (production fix) must
//! address. A passing gate confirms the O(log n) guarantee holds at scale.

use std::time::{Duration, Instant};

use criterion::{black_box, criterion_group, Criterion};

use hearth::core::RealmId;
use hearth::storage::wal::SyncMode;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Hot tier capacity used for the hot-hit scenario (matches production default).
const HOT_TIER_CAPACITY: usize = 100_000;

/// Number of keys pre-warmed into the hot tier before hot-hit measurement.
///
/// Hot-tier lookup is O(1) regardless of how many entries are in the tier,
/// so warming a small fixed count is sufficient to measure the ArcSwap path.
/// Warming the full `HOT_TIER_CAPACITY` (100 k) would require O(N²) HashMap
/// clone-swap operations in `promote()` — 5 billion malloc calls for 100 k
/// entries — making bench setup impractically slow. A fixed 1 k warm is enough
/// to exercise the hot path while keeping setup ≤ 1 second.
const HOT_WARM_COUNT: usize = 1_000;

/// Intentionally tiny hot tier for the cold-path scenario so nearly every
/// bench read falls through to the memtable / SST layers.
const COLD_HOT_TIER_CAPACITY: usize = 1_000;

/// Approximate byte size of a realistic serialised user record.
const VALUE_SIZE: usize = 256;

/// Raw timed reads collected per measurement phase for p50/p99 estimation.
const SAMPLES: usize = 5_000;

/// Discarded warm-up iterations before timed measurement begins.
const WARMUP: usize = 200;

/// p99 ceiling for hot-tier hit reads, any realm size.
///
/// The hot tier is a lock-free `ArcSwap` load + atomic `reference_bit` set.
/// Sub-microsecond in practice; 100 µs is very generous to tolerate CI noise.
const HOT_P99_CEILING: Duration = Duration::from_micros(100);

/// p99 ceiling for cold (SST) reads at any realm size.
///
/// With bloom filters (HEA-1626 Phase 2): at 500 k users (~35 SSTs), a cold
/// read probes 7 CRC32 hash positions per SST for fast rejection (~70 ns/SST)
/// then binary-searches the single matching SST (~1 µs). Total ≈ 34 × 70 ns
/// + 1 µs ≈ 3.4 µs — well within this 5 ms ceiling.
const COLD_P99_CEILING: Duration = Duration::from_millis(5);

/// Maximum allowed ratio of cold p99 at the largest realm vs the smallest.
///
/// Without bloom filters: O(k·log n) fan-out grows ~47× from 10 k to 500 k
/// users (1 → 35 SSTs), exceeding this limit.
/// With bloom filters: O(k·hash_count) per rejected SST grows only ~4–5× over
/// the same range (constant hash cost vs growing binary-search fan-out), easily
/// clearing the 20× gate.
const COLD_SCALE_LIMIT: f64 = 20.0;

/// Chunk size for batched seeder writes via `put_batch`.
///
/// `populate()` previously called `engine.put()` once per entry, which clones
/// the entire memtable BTreeMap per write — O(N²) per flush cycle.
/// Using `put_batch` with chunks clones the map once per chunk instead of once
/// per entry: O(N + chunk_size) per batch. At 500 k users this is the
/// difference between ~150 s and ~2 s of setup time.
const SEED_BATCH_SIZE: usize = 5_000;

/// Realm sizes exercised by the bench (restored to original spec: 10k/100k/500k).
///
/// Previously limited to [1k/10k/50k] because `populate()` used per-entry
/// `engine.put()` causing O(N²) BTreeMap clone work in the memtable.
/// HEA-1626 Phase 2 fixes this by seeding via `engine.put_batch()` (one map
/// clone per chunk instead of one per entry), and adds per-SST bloom filters
/// so the O(k·log n) SST fan-out at 500 k users stays within the 20× gate.
const REALM_SIZES: [usize; 3] = [10_000, 100_000, 500_000];

// ── Engine factory ────────────────────────────────────────────────────────────

/// Opens a fresh storage engine in a temporary directory.
///
/// Uses the **default 4 MiB memtable flush threshold** so that the bulk-write
/// setup phase stays within O(flush_cycle²) instead of O(total_writes²).
/// Every `put()` clones the entire memtable BTreeMap; with a 64 MiB threshold
/// the memtable accumulates ~238 k entries before flushing, making 100 k
/// writes take ~150 s. With 4 MiB (≈ 14 k entries/cycle) the same 100 k
/// writes complete in ~22 s (6–7 cycles × ~3.3 s each).
///
/// `SyncMode::None` eliminates per-write fsync; durability does not matter
/// for read-latency measurement.  Compaction is disabled for a deterministic
/// SST count during reads.
fn open_engine(hot_capacity: usize) -> (tempfile::TempDir, EmbeddedStorageEngine, RealmId) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = StorageConfig::production(
        dir.path().to_path_buf(),
        64 * 1024 * 1024, // 64 MiB WAL
        4 * 1024 * 1024,  // 4 MiB memtable (default) — limits O(N²) clone cycles
        hot_capacity,
    );
    config.dev_mode = true;
    // No fsync needed for read-latency benchmarks.
    config.wal_config.sync_mode = SyncMode::None;
    config.compaction.enabled = false;
    let engine = EmbeddedStorageEngine::open(config).expect("open");
    let realm = RealmId::generate();
    (dir, engine, realm)
}

// ── Key / value helpers ───────────────────────────────────────────────────────

fn make_key(i: usize) -> Vec<u8> {
    format!("usr:{i:016}").into_bytes()
}

fn pre_gen_keys(count: usize) -> Vec<Vec<u8>> {
    (0..count).map(make_key).collect()
}

fn make_value() -> Vec<u8> {
    vec![0x42u8; VALUE_SIZE]
}

/// Seeds `count` key-value pairs into `engine` using batched writes.
///
/// Calling `engine.put()` per entry clones the entire memtable BTreeMap on
/// every write — O(N²) per flush cycle.  `engine.put_batch()` clones the map
/// once per `SEED_BATCH_SIZE` entries instead, reducing setup to O(N).
fn populate(engine: &EmbeddedStorageEngine, realm: &RealmId, count: usize) {
    let value = make_value();
    let entries: Vec<(Vec<u8>, Vec<u8>)> =
        (0..count).map(|i| (make_key(i), value.clone())).collect();
    for chunk in entries.chunks(SEED_BATCH_SIZE) {
        engine.put_batch(realm, chunk).expect("put_batch");
    }
}

/// Reads each key once to promote it into the hot tier.
fn warm_hot_tier(engine: &EmbeddedStorageEngine, realm: &RealmId, keys: &[Vec<u8>]) {
    for key in keys {
        let _ = engine.get(realm, key);
    }
}

// ── Measurement helpers ───────────────────────────────────────────────────────

/// Runs warmup iterations then collects `samples` timed reads, cycling
/// through `keys` to avoid aliasing with warm-up.
fn measure(
    engine: &EmbeddedStorageEngine,
    realm: &RealmId,
    keys: &[Vec<u8>],
    samples: usize,
) -> Vec<Duration> {
    let n = keys.len();
    for i in 0..WARMUP {
        let _ = black_box(engine.get(realm, black_box(&keys[i % n])).expect("get"));
    }
    let mut times = Vec::with_capacity(samples);
    for i in 0..samples {
        let key = &keys[i % n];
        let t = Instant::now();
        let _ = black_box(engine.get(realm, black_box(key)).expect("get"));
        times.push(t.elapsed());
    }
    times
}

fn p50_p99(mut samples: Vec<Duration>) -> (Duration, Duration) {
    samples.sort_unstable();
    let p50 = samples[samples.len() / 2];
    let p99 = samples[samples.len() * 99 / 100];
    (p50, p99)
}

// ── Gate ──────────────────────────────────────────────────────────────────────

/// Flat-latency gate: panics with a descriptive message if any invariant
/// is violated. Called from `main()` before Criterion sampling begins.
#[allow(clippy::too_many_lines)]
fn gate_flat_latency() {
    println!("=== point_lookup gate: measuring hot-tier hit latency ===");

    // ── Hot-tier hit ──────────────────────────────────────────────────────────
    // Each realm is fully populated but only a fixed 1 k subset is warmed into
    // the hot tier. The hot-tier path is O(1) ArcSwap regardless of realm size,
    // so p99 must stay flat across all three realm sizes.

    let mut hot_p99s: Vec<(usize, Duration)> = Vec::new();

    for &user_count in &REALM_SIZES {
        let (_dir, engine, realm) = open_engine(HOT_TIER_CAPACITY);
        populate(&engine, &realm, user_count);
        // Warm a fixed 1 k subset — see HOT_WARM_COUNT for why a small fixed
        // count is correct and faster than warming the full tier.
        let warm_keys = pre_gen_keys(HOT_WARM_COUNT);
        warm_hot_tier(&engine, &realm, &warm_keys);

        let times = measure(&engine, &realm, &warm_keys, SAMPLES);
        let (p50, p99) = p50_p99(times);
        println!(
            "  hot-tier hit {:>7}k users  p50={p50:?}  p99={p99:?}",
            user_count / 1_000,
        );

        assert!(
            p99 <= HOT_P99_CEILING,
            "hot-tier p99 {p99:?} at {user_count} users exceeds ceiling {HOT_P99_CEILING:?} — \
             expected O(1) ArcSwap read; see benches/point_lookup.rs for threshold rationale"
        );
        hot_p99s.push((user_count, p99));
    }

    // ── Cold random read ──────────────────────────────────────────────────────
    // Hot tier capacity = COLD_HOT_TIER_CAPACITY (1 k), so reads cycling through
    // all `user_count` keys are almost always cold (hit rate ≤ 1 k / user_count).
    // This exercises the memtable BTreeMap + SST binary-search fan-out path.

    println!("=== point_lookup gate: measuring cold (SST) read latency ===");

    let mut cold_p99s: Vec<(usize, Duration)> = Vec::new();

    for &user_count in &REALM_SIZES {
        let (_dir, engine, realm) = open_engine(COLD_HOT_TIER_CAPACITY);
        populate(&engine, &realm, user_count);
        let keys = pre_gen_keys(user_count);

        let times = measure(&engine, &realm, &keys, SAMPLES);
        let (p50, p99) = p50_p99(times);
        println!(
            "  cold random  {:>7}k users  p50={p50:?}  p99={p99:?}",
            user_count / 1_000,
        );

        assert!(
            p99 <= COLD_P99_CEILING,
            "cold-read p99 {p99:?} at {user_count} users exceeds ceiling {COLD_P99_CEILING:?} — \
             expected O(k·log n) SST fan-out; see benches/point_lookup.rs for threshold rationale"
        );
        cold_p99s.push((user_count, p99));
    }

    // ── Flatness check (cold path) ─────────────────────────────────────────────
    // p99 at 500 k must not exceed p99 at 10 k by more than COLD_SCALE_LIMIT.
    // A ratio beyond this signals an O(N) regression rather than O(log n) growth.

    let cold_p99_small = cold_p99s[0].1; // smallest realm (1 k)
    let cold_p99_large = cold_p99s[2].1; // largest realm (50 k)
    let small_size = cold_p99s[0].0;
    let large_size = cold_p99s[2].0;

    // Guard against division by zero (would only happen if p99 = 0, i.e. no-op
    // reads). In that case, there is clearly no regression.
    if cold_p99_small > Duration::ZERO {
        let ratio = cold_p99_large.as_secs_f64() / cold_p99_small.as_secs_f64();
        println!(
            "  scale ratio {large_size}/{small_size}: {ratio:.2}× (limit {COLD_SCALE_LIMIT}×)  \
             p99_{small_size}={cold_p99_small:?}  p99_{large_size}={cold_p99_large:?}"
        );
        assert!(
            ratio <= COLD_SCALE_LIMIT,
            "cold-read p99 grew {ratio:.2}× from {small_size} to {large_size} users \
             (limit {COLD_SCALE_LIMIT}×) — possible O(N) regression; \
             pre-HEA-1614 linear scan produced ~3 000×; \
             see benches/point_lookup.rs for threshold rationale"
        );
    }

    println!("=== point_lookup gate: PASSED ===");
}

// ── Criterion benchmarks ──────────────────────────────────────────────────────
//
// These run after the gate and provide Criterion's HTML timeline / comparison.
// We use a parametric helper to avoid code duplication across the three sizes.

fn bench_hot_hit(c: &mut Criterion, user_count: usize) {
    let (_dir, engine, realm) = open_engine(HOT_TIER_CAPACITY);
    populate(&engine, &realm, user_count);
    let warm_keys = pre_gen_keys(HOT_WARM_COUNT);
    warm_hot_tier(&engine, &realm, &warm_keys);

    let label = format!("hot_hit_{}", user_count / 1_000);
    let mut group = c.benchmark_group("point_lookup");
    group.bench_function(label, |b| {
        let mut i = 0usize;
        b.iter(|| {
            let _ = black_box(
                engine
                    .get(&realm, black_box(&warm_keys[i % HOT_WARM_COUNT]))
                    .expect("get"),
            );
            i += 1;
        });
    });
    group.finish();
}

fn bench_cold_random(c: &mut Criterion, user_count: usize) {
    let (_dir, engine, realm) = open_engine(COLD_HOT_TIER_CAPACITY);
    populate(&engine, &realm, user_count);
    let keys = pre_gen_keys(user_count);

    let label = format!("cold_random_{}", user_count / 1_000);
    let mut group = c.benchmark_group("point_lookup");
    group.bench_function(label, |b| {
        let mut i = 0usize;
        b.iter(|| {
            let _ = black_box(
                engine
                    .get(&realm, black_box(&keys[i % user_count]))
                    .expect("get"),
            );
            i += 1;
        });
    });
    group.finish();
}

// ── Criterion group wrappers (one per variant) ────────────────────────────────

fn bench_hot_hit_10k(c: &mut Criterion) {
    bench_hot_hit(c, 10_000);
}
fn bench_hot_hit_100k(c: &mut Criterion) {
    bench_hot_hit(c, 100_000);
}
fn bench_hot_hit_500k(c: &mut Criterion) {
    bench_hot_hit(c, 500_000);
}
fn bench_cold_random_10k(c: &mut Criterion) {
    bench_cold_random(c, 10_000);
}
fn bench_cold_random_100k(c: &mut Criterion) {
    bench_cold_random(c, 100_000);
}
fn bench_cold_random_500k(c: &mut Criterion) {
    bench_cold_random(c, 500_000);
}

criterion_group!(
    benches,
    bench_hot_hit_10k,
    bench_hot_hit_100k,
    bench_hot_hit_500k,
    bench_cold_random_10k,
    bench_cold_random_100k,
    bench_cold_random_500k,
);

// ── Custom main: gate first, then Criterion ───────────────────────────────────

fn main() {
    gate_flat_latency();
    benches();
}
