//! Sub-millisecond per-journey latency extremes (HEA-1796 follow-up).
//!
//! Goose aggregates response times in **whole milliseconds**, so its reported
//! min/max round sub-ms samples to the nearest ms — a 0.1 ms request shows as
//! `0` or `1`. Hearth targets sub-ms p99, so that resolution hides exactly the
//! signal these tests exist to measure.
//!
//! This module measures each request's wall-clock latency in the load generator
//! itself and tracks a lock-free per-journey **microsecond** min/max, which the
//! report ([`crate::report`]) surfaces alongside Goose's ms-granular
//! percentiles. Recording is a pair of relaxed atomic `fetch_min`/`fetch_max`
//! per request — cheap enough not to perturb the generator.
//!
//! The generator drives full HTTP round-trips, so the microsecond figures
//! include the client's own request/response overhead; they are a
//! higher-resolution view of the *same* measurement Goose rounds, not a
//! separate engine-level probe.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

/// Request names tracked, matching the Goose transaction names set in
/// [`crate::scenarios`]. A name absent here is silently ignored by [`record`],
/// so adding a journey without registering it degrades gracefully (no min/max)
/// rather than panicking the run.
const JOURNEY_NAMES: [&str; 9] = [
    "validate",
    "session_lookup",
    "user_lookup",
    "issuance",
    "revoke_mint",
    "revoke",
    "revoke_revalidate",
    // Tier-miss lookup profile (HEA-1801): resident hot working set vs uniform
    // cold draw, so the report can split hot-tier-hit from cold/SST-miss tails.
    "lookup_hot",
    "lookup_cold",
];

/// Number of microsecond-exact buckets: samples in `0..US_EXACT` µs land in a
/// per-µs bucket, so the sub-millisecond hot-path journeys (validate, session /
/// user lookup) get exact-µs percentiles — the resolution Goose throws away.
const US_EXACT: usize = 4096;
/// Number of 1-ms buckets above [`US_EXACT`]: covers `4 ms ..= 60_004 ms`, so the
/// Argon2id-bound journeys (issuance, revoke — hundreds of ms to seconds) still
/// get whole-ms percentiles, where sub-ms precision is irrelevant anyway.
const MS_BUCKETS: usize = 60_000;
/// Total histogram width. ~64 k `AtomicU64` per journey (~0.5 MB × 9 ≈ 4.6 MB) —
/// trivial for the load *client* (this is not the Hearth server hot path).
const TOTAL_BUCKETS: usize = US_EXACT + MS_BUCKETS;

/// Bucket index for a microsecond sample: µs-exact below [`US_EXACT`], then 1-ms
/// buckets, saturating into the final bucket for very slow (multi-minute) samples.
fn bucket_of(us: u64) -> usize {
    if us < US_EXACT as u64 {
        us as usize
    } else {
        let ms = (us / 1000) as usize; // >= 4 in this branch
        (US_EXACT + ms.saturating_sub(4)).min(TOTAL_BUCKETS - 1)
    }
}

/// Representative microsecond value for a bucket index (its lower edge). Exact in
/// the µs-exact range; the ms-bucket lower edge (±1 ms) above it.
fn bucket_repr_us(idx: usize) -> u64 {
    if idx < US_EXACT {
        idx as u64
    } else {
        ((idx - US_EXACT) as u64 + 4) * 1000
    }
}

/// Computes the reported percentiles from a per-bucket count slice and the exact
/// `max_us`. Returns `None` when no samples were recorded. Mirrors Goose's own
/// cumulative-count rule: the first bucket whose running total reaches the target
/// rank. `p100` uses the exact recorded max rather than a bucket edge.
fn percentiles_from_counts(counts: &[u64], max_us: u64) -> Option<LatencyPercentiles> {
    let total: u64 = counts.iter().sum();
    if total == 0 {
        return None;
    }
    let at = |fraction: f64| -> u64 {
        #[allow(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss
        )]
        let rank = ((fraction * total as f64).ceil() as u64).max(1);
        let mut cum = 0u64;
        for (idx, &count) in counts.iter().enumerate() {
            cum += count;
            if cum >= rank {
                return bucket_repr_us(idx);
            }
        }
        max_us
    };
    Some(LatencyPercentiles {
        p50_us: at(0.50),
        p60_us: at(0.60),
        p70_us: at(0.70),
        p80_us: at(0.80),
        p90_us: at(0.90),
        p95_us: at(0.95),
        p99_us: at(0.99),
        p100_us: max_us,
    })
}

/// Lock-free microsecond min/max + histogram accumulator for one journey.
///
/// `min_us` starts at `u64::MAX` and `max_us` at `0`; a journey with no recorded
/// sample is therefore distinguishable (`min_us == u64::MAX`) from one whose
/// fastest request was 0 µs.
struct JourneyLatency {
    min_us: AtomicU64,
    max_us: AtomicU64,
    buckets: Box<[AtomicU64]>,
}

impl JourneyLatency {
    fn new() -> Self {
        Self {
            min_us: AtomicU64::new(u64::MAX),
            max_us: AtomicU64::new(0),
            buckets: (0..TOTAL_BUCKETS)
                .map(|_| AtomicU64::new(0))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        }
    }

    fn reset(&self) {
        self.min_us.store(u64::MAX, Ordering::Relaxed);
        self.max_us.store(0, Ordering::Relaxed);
        for bucket in &self.buckets {
            bucket.store(0, Ordering::Relaxed);
        }
    }

    fn record(&self, us: u64) {
        self.min_us.fetch_min(us, Ordering::Relaxed);
        self.max_us.fetch_max(us, Ordering::Relaxed);
        self.buckets[bucket_of(us)].fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> Option<LatencyExtremes> {
        let min_us = self.min_us.load(Ordering::Relaxed);
        if min_us == u64::MAX {
            return None; // no samples recorded this run
        }
        Some(LatencyExtremes {
            min_us,
            max_us: self.max_us.load(Ordering::Relaxed),
        })
    }

    /// Reads this journey's bucket counts into an owned slice (relaxed loads).
    fn bucket_counts(&self) -> Vec<u64> {
        self.buckets
            .iter()
            .map(|b| b.load(Ordering::Relaxed))
            .collect()
    }
}

/// Microsecond latency extremes for a single journey over one attack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LatencyExtremes {
    /// Fastest observed request latency (µs).
    pub min_us: u64,
    /// Slowest observed request latency (µs).
    pub max_us: u64,
}

/// Microsecond-resolution response-time percentiles for a single journey (or the
/// merged aggregate), matching the columns Goose renders — 50/60/70/80/90/95/99
/// plus p100 (the exact max). Goose computes these from a **whole-millisecond**
/// histogram, so its sub-ms journeys render every percentile as `1`; these are
/// measured by the generator at microsecond resolution instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LatencyPercentiles {
    /// 50th-percentile latency (µs).
    pub p50_us: u64,
    /// 60th-percentile latency (µs).
    pub p60_us: u64,
    /// 70th-percentile latency (µs).
    pub p70_us: u64,
    /// 80th-percentile latency (µs).
    pub p80_us: u64,
    /// 90th-percentile latency (µs).
    pub p90_us: u64,
    /// 95th-percentile latency (µs).
    pub p95_us: u64,
    /// 99th-percentile latency (µs).
    pub p99_us: u64,
    /// 100th-percentile latency (µs) — the exact recorded max.
    pub p100_us: u64,
}

/// A point-in-time percentile snapshot: per-journey percentiles plus the
/// bucket-merged `aggregate` across every recorded journey (the report's
/// `Aggregated` row). `aggregate` is `None` when no journey recorded a sample.
#[derive(Debug, Clone)]
pub struct PercentileSnapshot {
    /// Per-journey percentiles, keyed by request name.
    pub per_journey: HashMap<&'static str, LatencyPercentiles>,
    /// Percentiles over the histogram merged across all journeys.
    pub aggregate: Option<LatencyPercentiles>,
}

/// Per-journey registry keyed by request name, lazily initialized on first use.
static REGISTRY: OnceLock<HashMap<&'static str, JourneyLatency>> = OnceLock::new();

fn registry() -> &'static HashMap<&'static str, JourneyLatency> {
    REGISTRY.get_or_init(|| {
        JOURNEY_NAMES
            .iter()
            .map(|&name| (name, JourneyLatency::new()))
            .collect()
    })
}

/// Records one request's latency under `name`. Names not in [`JOURNEY_NAMES`]
/// are ignored.
pub fn record(name: &str, elapsed: Duration) {
    if let Some(journey) = registry().get(name) {
        let us = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        journey.record(us);
    }
}

/// Clears every journey's extremes. Call before each attack so a per-step report
/// reflects only that sub-run — ramp and soak modes run several attacks and must
/// not carry min/max across steps.
pub fn reset() {
    for journey in registry().values() {
        journey.reset();
    }
}

/// Snapshots the current per-journey extremes. Only journeys with at least one
/// recorded sample appear. Call after an attack completes (no transactions are
/// in flight then), so the read is a consistent point-in-time view.
#[must_use]
pub fn snapshot() -> HashMap<&'static str, LatencyExtremes> {
    registry()
        .iter()
        .filter_map(|(&name, journey)| journey.snapshot().map(|e| (name, e)))
        .collect()
}

/// Snapshots per-journey microsecond percentiles plus the merged aggregate. Only
/// journeys with at least one recorded sample appear in `per_journey`; the
/// aggregate is the sum of every journey's histogram. Call after an attack
/// completes (no transactions in flight) so the read is consistent.
#[must_use]
pub fn snapshot_percentiles() -> PercentileSnapshot {
    let mut per_journey = HashMap::new();
    let mut merged = vec![0u64; TOTAL_BUCKETS];
    let mut merged_max = 0u64;
    let mut any = false;
    for (&name, journey) in registry() {
        let counts = journey.bucket_counts();
        let max_us = journey.max_us.load(Ordering::Relaxed);
        if let Some(pct) = percentiles_from_counts(&counts, max_us) {
            per_journey.insert(name, pct);
            for (slot, &count) in merged.iter_mut().zip(&counts) {
                *slot += count;
            }
            merged_max = merged_max.max(max_us);
            any = true;
        }
    }
    let aggregate = if any {
        percentiles_from_counts(&merged, merged_max)
    } else {
        None
    };
    PercentileSnapshot {
        per_journey,
        aggregate,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests share the process-global registry, so they cannot assert on a
    // clean slate concurrently. Each seeds its own journey and resets first;
    // `reset()` + distinct journey names keep them independent.

    #[test]
    fn record_tracks_microsecond_min_and_max() {
        reset();
        record("validate", Duration::from_micros(120));
        record("validate", Duration::from_micros(40));
        record("validate", Duration::from_micros(900));
        let snap = snapshot();
        let ext = snap.get("validate").copied().expect("recorded journey");
        // Sub-ms precision: 40 µs would round to 0 ms in Goose, 900 µs to 1 ms.
        assert_eq!(ext.min_us, 40);
        assert_eq!(ext.max_us, 900);
    }

    #[test]
    fn reset_clears_prior_samples() {
        record("issuance", Duration::from_micros(500));
        reset();
        assert!(
            !snapshot().contains_key("issuance"),
            "reset must drop journeys with no post-reset samples"
        );
    }

    #[test]
    fn unknown_journey_is_ignored() {
        reset();
        record("not_a_journey", Duration::from_micros(10));
        assert!(!snapshot().contains_key("not_a_journey"));
    }

    #[test]
    fn tier_miss_journeys_are_tracked() {
        // Regression (HEA-1801): the hot/cold tier lookups must be recordable so
        // the report can surface their microsecond extremes per tier.
        reset();
        record("lookup_hot", Duration::from_micros(80));
        record("lookup_cold", Duration::from_micros(2_400));
        let snap = snapshot();
        assert_eq!(snap.get("lookup_hot").map(|e| e.min_us), Some(80));
        assert_eq!(snap.get("lookup_cold").map(|e| e.max_us), Some(2_400));
    }

    #[test]
    fn journey_with_no_samples_is_absent() {
        reset();
        record("user_lookup", Duration::from_micros(200));
        let snap = snapshot();
        // Only the recorded journey appears; untouched ones are omitted, not 0.
        assert!(snap.contains_key("user_lookup"));
        assert!(!snap.contains_key("session_lookup"));
    }

    #[test]
    fn bucket_scheme_is_exact_sub_ms_and_ms_above() {
        // Sub-US_EXACT samples map to their own µs bucket (exact round-trip);
        // above it, samples collapse to 1-ms buckets.
        assert_eq!(bucket_repr_us(bucket_of(37)), 37);
        assert_eq!(bucket_repr_us(bucket_of(4095)), 4095);
        // 4096 µs → first ms bucket, lower edge 4 ms.
        assert_eq!(bucket_repr_us(bucket_of(4096)), 4000);
        // 12_500 µs → 12-ms bucket lower edge.
        assert_eq!(bucket_repr_us(bucket_of(12_500)), 12_000);
    }

    #[test]
    fn percentiles_are_microsecond_accurate_for_sub_ms_journey() {
        // Regression (board follow-up HEA-1788): Goose renders a journey whose
        // p50..p99 are all tens/hundreds of µs as a flat `1` ms. Our histogram
        // must recover the real µs percentiles.
        reset();
        for us in 1..=100u64 {
            // 100 samples at 1,2,...,100 µs — all well under 1 ms.
            record("validate", Duration::from_micros(us));
        }
        let snap = snapshot_percentiles();
        let p = snap
            .per_journey
            .get("validate")
            .copied()
            .expect("recorded journey");
        // Every percentile stays sub-millisecond, not rounded to 1000 µs.
        assert!(p.p50_us <= 60, "p50 {} µs should be ~50 µs", p.p50_us);
        assert!(p.p99_us < 1000, "p99 {} µs must stay sub-ms", p.p99_us);
        assert_eq!(p.p100_us, 100, "p100 is the exact max");
    }

    #[test]
    fn aggregate_merges_journey_histograms() {
        reset();
        record("validate", Duration::from_micros(10));
        record("session_lookup", Duration::from_micros(20));
        record("issuance", Duration::from_millis(500));
        let snap = snapshot_percentiles();
        let agg = snap.aggregate.expect("aggregate present with samples");
        // p100 across the merged set is the slowest journey's max.
        assert_eq!(agg.p100_us, 500_000);
    }

    #[test]
    fn aggregate_absent_without_samples() {
        reset();
        assert!(snapshot_percentiles().aggregate.is_none());
    }
}
