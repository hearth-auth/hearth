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

/// Lock-free microsecond min/max accumulator for one journey.
///
/// `min_us` starts at `u64::MAX` and `max_us` at `0`; a journey with no recorded
/// sample is therefore distinguishable (`min_us == u64::MAX`) from one whose
/// fastest request was 0 µs.
struct JourneyLatency {
    min_us: AtomicU64,
    max_us: AtomicU64,
}

impl JourneyLatency {
    fn new() -> Self {
        Self {
            min_us: AtomicU64::new(u64::MAX),
            max_us: AtomicU64::new(0),
        }
    }

    fn reset(&self) {
        self.min_us.store(u64::MAX, Ordering::Relaxed);
        self.max_us.store(0, Ordering::Relaxed);
    }

    fn record(&self, us: u64) {
        self.min_us.fetch_min(us, Ordering::Relaxed);
        self.max_us.fetch_max(us, Ordering::Relaxed);
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
}

/// Microsecond latency extremes for a single journey over one attack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LatencyExtremes {
    /// Fastest observed request latency (µs).
    pub min_us: u64,
    /// Slowest observed request latency (µs).
    pub max_us: u64,
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
}
