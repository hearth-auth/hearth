//! Machine-readable JSON report + percentile extraction (HEA-1791).
//!
//! Goose already emits an HTML report; this module adds the versioned
//! (`"schema": 1`) JSON baseline the plan (HEA-1787 §7) requires: run metadata,
//! a per-journey percentile table (p50/p95/p99/p999), the ramp saturation knee,
//! soak latency drift, and pass/fail against the sourced HTTP budgets
//! ([`crate::budget`]). A future nightly CI job can diff this JSON against a
//! committed baseline to flag regressions — schema versioning is what makes
//! that diff safe.
//!
//! Percentiles are read from Goose's per-request timing histogram
//! (`GooseRequestMetricTimingData::times`, response time in whole ms → count),
//! using the same cumulative-count algorithm Goose reports with, plus p999
//! which Goose does not surface directly.

use std::collections::HashMap;

use goose::metrics::{GooseRequestMetricTimingData, GooseRequestMetrics};
use serde::Serialize;

use crate::budget::{self, Budget};
use crate::latency::LatencyExtremes;
use crate::resources::ResourceReport;

/// Report schema version. Bump on any breaking shape change so a nightly diff
/// job can refuse to compare across incompatible schemas.
///
/// * `3` — added the optional `resources` block (server RSS/CPU, HEA-1811).
pub const SCHEMA_VERSION: u32 = 3;

/// Run metadata stamped into every report header.
#[derive(Debug, Clone, Serialize)]
pub struct RunMetadata {
    /// Git commit the harness was built from (`"unknown"` if undetectable).
    pub git_sha: String,
    /// Unix epoch seconds when the report was produced.
    pub timestamp_unix: u64,
    /// Run mode (`steady` / `ramp` / `soak`).
    pub mode: String,
    /// Base URL the load was driven against.
    pub host: String,
    /// Deterministic seed the corpus was derived from.
    pub seed: u64,
    /// Human-readable dataset shape (mirrors the seed handle).
    pub dataset_shape: String,
    /// Concurrent Goose users configured.
    pub users: usize,
    /// Per-step steady duration (Goose timespan).
    pub run_time: String,
    /// Ramp-up hatch rate.
    pub hatch_rate: String,
}

/// One journey's measured percentiles and its verdict against the sourced
/// HTTP budget.
#[derive(Debug, Clone, Serialize)]
pub struct JourneyRow {
    /// Goose transaction/request name (e.g. `"validate"`).
    pub journey: String,
    /// HTTP method (`"GET"` / `"POST"`).
    pub method: String,
    /// Total requests recorded for this journey.
    pub requests: usize,
    /// Requests that returned a non-2xx / errored.
    pub failures: usize,
    /// Failure fraction in `[0.0, 1.0]` — surfaced so a fast-but-erroring
    /// journey is visibly unhealthy, not a silent pass.
    pub failure_rate: f64,
    /// p50 response time (ms).
    pub p50_ms: usize,
    /// p95 response time (ms).
    pub p95_ms: usize,
    /// p99 response time (ms).
    pub p99_ms: usize,
    /// p999 response time (ms).
    pub p999_ms: usize,
    /// Fastest observed request latency (µs), measured by the generator at
    /// microsecond resolution — Goose's own min rounds sub-ms samples to whole
    /// ms (a 0.1 ms request reads as `0`). `None` if no sample was recorded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_us: Option<u64>,
    /// Slowest observed request latency (µs), microsecond resolution. `None` if
    /// no sample was recorded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_us: Option<u64>,
    /// In-process engine p99 target (µs), if this journey maps to one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spec_engine_p99_us: Option<u64>,
    /// HTTP p99 budget (µs) asserted against, if this journey has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_budget_p99_us: Option<u64>,
    /// `Some(true)`/`Some(false)` pass/fail vs the HTTP budget; `None` for
    /// journeys with no atomic budget (the compound revoke journey).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pass: Option<bool>,
}

/// One ramp step: the achieved throughput and whether any budgeted journey
/// breached its HTTP p99 budget at that load.
#[derive(Debug, Clone, Serialize)]
pub struct RampStep {
    /// Configured concurrent users for the step.
    pub users: usize,
    /// Achieved requests-per-second across all journeys (total / duration).
    pub rps: f64,
    /// Whether any budgeted journey's p99 breached its HTTP budget here.
    pub breached: bool,
    /// Per-journey rows measured at this step.
    pub journeys: Vec<JourneyRow>,
}

/// One soak time-bucket: per-journey percentiles over a slice of the run, so
/// latency drift across the soak is visible even though Goose only aggregates.
#[derive(Debug, Clone, Serialize)]
pub struct SoakBucket {
    /// 0-based bucket index (chronological).
    pub bucket: usize,
    /// Per-journey rows measured during this bucket.
    pub journeys: Vec<JourneyRow>,
}

/// Attribution of the observed throughput ceiling — the DoD (HEA-1796 §4)
/// requires the report to state, explicitly and honestly, whether the run was
/// limited by the server under test or by the load generator itself.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Ceiling {
    /// A budgeted journey's p99 breached its HTTP budget: server latency is the
    /// limiter, so the observed ceiling is the server under test.
    Server,
    /// No budgeted journey breached and failures were negligible: the server
    /// sustained the offered load, so the run did not reach the server's
    /// ceiling. The limit is the load generator (or simply untested headroom —
    /// raise `--users` to push further).
    LoadGeneratorOrHeadroom,
    /// Elevated failure rate without a latency breach — the offered load
    /// exceeded what the generator/host could faithfully drive (ephemeral-port
    /// exhaustion, `ulimit -n`, `TIME_WAIT`). Tune the generator (README
    /// "Driving high concurrency") and re-run before trusting the numbers.
    GeneratorSaturated,
    /// A latency breach was observed but the server resource data needed to
    /// confirm it was absent (`--server-pid` not supplied, or fewer than two
    /// samples were gathered). Cannot distinguish server saturation from
    /// generator collapse — the run is inadmissible for grading
    /// (`PERFORMANCE_REPORT_1_0.md §7`).
    Unknown,
}

/// Aggregate run summary: achieved concurrency + throughput and the ceiling
/// attribution, so a reader can tell the single-node ceiling from a generator
/// bottleneck at a glance (HEA-1796 §4).
#[derive(Debug, Clone, Serialize)]
pub struct RunSummary {
    /// Peak concurrent Goose users the run reached.
    pub achieved_users: usize,
    /// Achieved aggregate requests-per-second (all journeys, total / duration).
    pub achieved_rps: f64,
    /// Total requests recorded across all journeys.
    pub total_requests: usize,
    /// Total failed requests across all journeys.
    pub total_failures: usize,
    /// Aggregate failure fraction in `[0.0, 1.0]`.
    pub failure_rate: f64,
    /// Attribution of the observed throughput ceiling.
    pub ceiling: Ceiling,
    /// Human-readable rationale for the [`Ceiling`] verdict.
    pub ceiling_reason: String,
}

/// Failure fraction above which, absent a latency breach, we suspect the load
/// generator rather than the server (connection resets from port/fd exhaustion
/// show up as request failures, not slow-but-successful responses).
const GENERATOR_SATURATION_FAILURE_RATE: f64 = 0.02;

/// Mean server CPU below this floor during a run that produced a latency breach
/// indicates the server was not the active bottleneck. Client-observed timeouts
/// with an idle server are connection-level failures (ephemeral-port exhaustion,
/// TIME_WAIT backpressure) rather than server processing failures.
const SERVER_CPU_FLOOR_MEAN_PCT: f64 = 5.0;

/// Peak server CPU below this floor (combined with the mean floor) confirms the
/// server never meaningfully spun up during the measurement window, ruling out
/// a brief saturation spike that subsequently collapsed the load generator.
const SERVER_CPU_FLOOR_PEAK_PCT: f64 = 10.0;

/// Builds the aggregate [`RunSummary`] + ceiling attribution from the primary
/// journey rows and the achieved concurrency/throughput.
#[must_use]
pub fn summarize(rows: &[JourneyRow], achieved_users: usize, achieved_rps: f64) -> RunSummary {
    let total_requests: usize = rows.iter().map(|r| r.requests).sum();
    let total_failures: usize = rows.iter().map(|r| r.failures).sum();
    let failure_rate = if total_requests == 0 {
        0.0
    } else {
        #[allow(clippy::cast_precision_loss)]
        {
            total_failures as f64 / total_requests as f64
        }
    };

    let (ceiling, ceiling_reason) = if any_breach(rows) {
        (
            Ceiling::Server,
            "a budgeted journey's p99 breached its HTTP budget — server latency is the limiter; \
             the observed ceiling is the server under test"
                .to_string(),
        )
    } else if failure_rate > GENERATOR_SATURATION_FAILURE_RATE {
        (
            Ceiling::GeneratorSaturated,
            format!(
                "failure rate {:.2}% exceeds {:.0}% with no latency breach — suspect load-generator \
                 saturation (ephemeral ports, ulimit -n, TIME_WAIT); tune the generator and re-run",
                failure_rate * 100.0,
                GENERATOR_SATURATION_FAILURE_RATE * 100.0,
            ),
        )
    } else {
        (
            Ceiling::LoadGeneratorOrHeadroom,
            "no budgeted journey breached and failures were negligible — the server sustained the \
             offered load; the ceiling is the load generator or untested headroom. Raise --users \
             to push further"
                .to_string(),
        )
    };

    RunSummary {
        achieved_users,
        achieved_rps,
        total_requests,
        total_failures,
        failure_rate,
        ceiling,
        ceiling_reason,
    }
}

/// Corrects [`RunSummary::ceiling`] after server resource data becomes available.
///
/// `summarize` is called before the resource sampler stops (the sampler spans
/// the full run and stops in the outer `run_load` after all sub-runs complete),
/// so the initial attribution cannot see CPU/RSS figures. This function applies
/// two post-hoc rules:
///
/// 1. **No samples → `Unknown`**: a `Server` verdict without resource evidence is
///    inadmissible. The generator may have saturated before the server was ever
///    meaningfully stressed; without CPU data we cannot tell the two apart.
///    Programme rule 3 (`PERFORMANCE_REPORT_1_0.md §7`) rejects any row whose
///    `ceiling.attribution` resolves to this variant.
///
/// 2. **Idle server → `GeneratorSaturated`**: when the server's mean and peak CPU
///    are both below their respective floors ([`SERVER_CPU_FLOOR_MEAN_PCT`] /
///    [`SERVER_CPU_FLOOR_PEAK_PCT`]), the server was demonstrably idle while
///    request failures accumulated. Client timeouts at 30 s with 0 % server CPU
///    are connection-level failures driven by port exhaustion or `TIME_WAIT`
///    backpressure on the generator host — not server processing failures.
///
/// Only `Server` attributions are affected; `GeneratorSaturated` and
/// `LoadGeneratorOrHeadroom` are derived from failure-rate patterns that remain
/// valid regardless of resource data.
pub fn correct_ceiling_with_resources(
    summary: &mut RunSummary,
    resources: Option<&ResourceReport>,
) {
    if summary.ceiling != Ceiling::Server {
        return;
    }
    match resources {
        None => {
            summary.ceiling = Ceiling::Unknown;
            summary.ceiling_reason =
                "a latency breach was observed but no server resource samples were collected \
                 (--server-pid not supplied, or fewer than two samples gathered); cannot \
                 distinguish server saturation from generator collapse — this run is \
                 inadmissible for grading (PERFORMANCE_REPORT_1_0.md §7)"
                    .to_string();
        }
        Some(res)
            if res.cpu_mean_pct < SERVER_CPU_FLOOR_MEAN_PCT
                && res.cpu_peak_pct < SERVER_CPU_FLOOR_PEAK_PCT =>
        {
            summary.ceiling = Ceiling::GeneratorSaturated;
            summary.ceiling_reason = format!(
                "latency breach observed but server CPU mean {:.1}% and peak {:.1}% are both \
                 below their utilisation floors ({:.0}% mean / {:.0}% peak) — the server was \
                 idle while request failures accumulated; the bottleneck was the load generator \
                 (ephemeral-port exhaustion, ulimit -n, TIME_WAIT backpressure), not the server \
                 under test. Tune the generator (loadtest/README.md §\"Driving high \
                 concurrency\") and re-run.",
                res.cpu_mean_pct,
                res.cpu_peak_pct,
                SERVER_CPU_FLOOR_MEAN_PCT,
                SERVER_CPU_FLOOR_PEAK_PCT,
            );
        }
        Some(_) => {} // server CPU data confirms the server was active; attribution stands
    }
}

/// Per-tier lookup latency split for the tier-miss profile (HEA-1801).
///
/// Additive, back-compat report block: present only for `tier-miss` runs and
/// omitted otherwise, so existing `report.json` consumers stay unaffected. The
/// corpus-scale proof is the **hot-vs-cold p99 delta**: a hot working set that
/// stays resident in the size-capped hot tier vs a uniform draw across the whole
/// corpus that mostly falls through to the cold/SST read path. If lookup latency
/// is corpus-size independent, the per-tier percentiles stay flat as the corpus
/// grows across a `10k → 100k → 1M` sweep.
///
/// Read the hot-vs-cold delta at **p50/p95**, not p99: every request pays a full
/// ROPC Argon2id verify, so the sub-ms storage delta is only a small slice of the
/// total, and the p99 tail can invert under Argon2id hot-set lock contention when
/// many concurrent users hash the same small resident set (HEA-1804). p50/p95
/// keep the correct ordering; the tail is reported for completeness.
#[derive(Debug, Clone, Serialize)]
pub struct TierMissReport {
    /// Total addressable corpus the cold draw spanned (`1..=corpus_size`).
    pub corpus_size: u64,
    /// Size of the resident hot working set the hot draw spanned
    /// (`1..=hot_working_set_size`).
    pub hot_working_set_size: u64,
    /// Configured hot-tier capacity (entries) the instance was booted with, if
    /// the operator supplied it. Sizing this below the corpus is what forces the
    /// cold draw through the SST tier (`storage.hot_tier_capacity`, HEA-1800).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hot_tier_capacity: Option<u64>,
    /// Fraction of requests drawn from the hot working set, by construction
    /// (`hot_weight / (hot_weight + cold_weight)`).
    pub hot_request_fraction: f64,
    /// Expected fraction of a uniform cold draw that misses the hot tier, by
    /// construction: `1 - min(1, hot_tier_capacity / corpus_size)`. `None` when
    /// no hot-tier capacity was supplied (cannot be estimated). This is a
    /// by-construction estimate, not a server-observed counter — the HTTP client
    /// cannot see which tier served a given lookup.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_cold_miss_rate: Option<f64>,
    /// Hot-tier-hit p50 (ms), from the `lookup_hot` journey. `None` if the hot
    /// journey recorded no requests. Both tiers pay a full ROPC Argon2id verify,
    /// so the storage-tier delta is clearest at p50/p95 — the tail (p99) can
    /// invert under Argon2id hot-set contention (HEA-1804); read the delta here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hot_p50_ms: Option<usize>,
    /// Cold/SST-miss p50 (ms), from the `lookup_cold` journey. `None` if the
    /// cold journey recorded no requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cold_p50_ms: Option<usize>,
    /// Hot-tier-hit p95 (ms), from the `lookup_hot` journey. `None` if the hot
    /// journey recorded no requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hot_p95_ms: Option<usize>,
    /// Cold/SST-miss p95 (ms), from the `lookup_cold` journey. `None` if the
    /// cold journey recorded no requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cold_p95_ms: Option<usize>,
    /// Hot-tier-hit p99 (ms), from the `lookup_hot` journey. `None` if the hot
    /// journey recorded no requests. See the p50/p95 caveat above: at p99 the
    /// hot/cold ordering can invert under Argon2id hot-set lock contention.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hot_p99_ms: Option<usize>,
    /// Cold/SST-miss p99 (ms), from the `lookup_cold` journey. `None` if the
    /// cold journey recorded no requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cold_p99_ms: Option<usize>,
    /// Hot-tier-hit slowest observed latency (µs), microsecond resolution.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hot_max_us: Option<u64>,
    /// Cold/SST-miss slowest observed latency (µs), microsecond resolution.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cold_max_us: Option<u64>,
}

/// Builds the [`TierMissReport`] from the measured hot/cold journey rows.
///
/// `rows` are the tier-miss run's journey rows (containing `lookup_hot` /
/// `lookup_cold`); `hot_tier_capacity` is the operator-supplied capacity the
/// instance was booted with (informational); `hot_weight`/`cold_weight` are the
/// configured Goose weights the hot-request fraction is derived from.
#[must_use]
pub fn tier_miss_report(
    rows: &[JourneyRow],
    corpus_size: u64,
    hot_working_set_size: u64,
    hot_tier_capacity: Option<u64>,
    hot_weight: usize,
    cold_weight: usize,
) -> TierMissReport {
    let find = |name: &str| rows.iter().find(|r| r.journey == name);
    let hot = find("lookup_hot");
    let cold = find("lookup_cold");

    let total_weight = hot_weight + cold_weight;
    let hot_request_fraction = if total_weight == 0 {
        0.0
    } else {
        #[allow(clippy::cast_precision_loss)]
        {
            hot_weight as f64 / total_weight as f64
        }
    };

    let expected_cold_miss_rate = hot_tier_capacity.map(|cap| {
        if corpus_size == 0 {
            0.0
        } else {
            #[allow(clippy::cast_precision_loss)]
            let resident = (cap as f64 / corpus_size as f64).min(1.0);
            1.0 - resident
        }
    });

    TierMissReport {
        corpus_size,
        hot_working_set_size,
        hot_tier_capacity,
        hot_request_fraction,
        expected_cold_miss_rate,
        // A journey with no recorded requests reports None rather than a bogus 0.
        hot_p50_ms: hot.filter(|r| r.requests > 0).map(|r| r.p50_ms),
        cold_p50_ms: cold.filter(|r| r.requests > 0).map(|r| r.p50_ms),
        hot_p95_ms: hot.filter(|r| r.requests > 0).map(|r| r.p95_ms),
        cold_p95_ms: cold.filter(|r| r.requests > 0).map(|r| r.p95_ms),
        hot_p99_ms: hot.filter(|r| r.requests > 0).map(|r| r.p99_ms),
        cold_p99_ms: cold.filter(|r| r.requests > 0).map(|r| r.p99_ms),
        hot_max_us: hot.and_then(|r| r.max_us),
        cold_max_us: cold.and_then(|r| r.max_us),
    }
}

/// The full report serialized to `report.json`.
#[derive(Debug, Clone, Serialize)]
pub struct LoadReport {
    /// Schema version (always [`SCHEMA_VERSION`]).
    pub schema: u32,
    /// Run metadata header.
    pub metadata: RunMetadata,
    /// Aggregate summary: achieved concurrency/RPS + ceiling attribution.
    pub summary: RunSummary,
    /// Primary per-journey percentile table (the final/aggregate step).
    pub journeys: Vec<JourneyRow>,
    /// Ramp steps + saturation knee (ramp mode only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ramp_steps: Option<Vec<RampStep>>,
    /// Saturation knee RPS: the achieved RPS at the first ramp step where a
    /// budgeted journey's p99 breached its HTTP budget. `None` if no step
    /// breached (or not ramp mode).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub knee_rps: Option<f64>,
    /// Soak time-buckets for drift inspection (soak mode only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub soak_buckets: Option<Vec<SoakBucket>>,
    /// Per-tier lookup latency split (tier-miss mode only, HEA-1801). Additive:
    /// omitted for every other mode so existing consumers are unaffected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier_miss: Option<TierMissReport>,
    /// Server resource consumption (peak/mean RSS + CPU%) sampled during the
    /// run (HEA-1811). Additive and optional: present only when `--server-pid`
    /// was supplied and at least two samples were gathered, so a report can
    /// state "p99 in budget **and** the server was not resource-starved".
    /// Omitted for every run that did not sample, leaving existing consumers
    /// unaffected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceReport>,
    /// Overall pass: every budgeted journey stayed within its HTTP budget.
    pub pass: bool,
}

/// The percentile of a Goose timing histogram, in whole ms.
///
/// Mirrors Goose's own cumulative-count percentile: walk the histogram in
/// ascending response-time order, summing counts until the cumulative count
/// reaches `percent` of the total, clamped to the observed min/max.
#[must_use]
pub fn percentile_ms(timing: &GooseRequestMetricTimingData, percent: f32) -> usize {
    if timing.counter == 0 {
        return 0;
    }
    #[allow(clippy::cast_precision_loss, clippy::cast_sign_loss)]
    let target = ((timing.counter as f32) * percent).round() as usize;
    let mut cumulative = 0usize;
    for (&value, &count) in &timing.times {
        cumulative += count;
        if cumulative >= target {
            return value.clamp(timing.minimum_time, timing.maximum_time);
        }
    }
    timing.maximum_time
}

/// Builds the per-journey rows from Goose's request metrics.
///
/// The metrics map is keyed `"METHOD name"` (e.g. `"POST validate"`); the name
/// after the first space is the Goose transaction name we set, which maps to a
/// sourced budget via [`budget::budget_for`]. `latency` is the generator's own
/// microsecond min/max keyed by the same journey name (see [`crate::latency`]);
/// a journey absent from it simply carries `None` min/max. Rows are sorted by
/// journey name for stable, diff-friendly output.
#[must_use]
pub fn journey_rows(
    requests: &GooseRequestMetrics,
    latency: &HashMap<&'static str, LatencyExtremes>,
) -> Vec<JourneyRow> {
    let mut rows: Vec<JourneyRow> = requests
        .iter()
        .map(|(key, agg)| {
            let name = key.split_once(' ').map_or(key.as_str(), |(_, n)| n);
            let t = &agg.raw_data;
            let p99 = percentile_ms(t, 0.99);
            let budget: Option<Budget> = budget::budget_for(name);
            let pass = budget.map(|b| budget::passes(p99, agg.fail_count, t.counter, b));
            let extremes = latency.get(name);
            JourneyRow {
                journey: name.to_string(),
                method: agg.method.to_string(),
                requests: t.counter,
                failures: agg.fail_count,
                failure_rate: budget::failure_rate(agg.fail_count, t.counter),
                p50_ms: percentile_ms(t, 0.5),
                p95_ms: percentile_ms(t, 0.95),
                p99_ms: p99,
                p999_ms: percentile_ms(t, 0.999),
                min_us: extremes.map(|e| e.min_us),
                max_us: extremes.map(|e| e.max_us),
                spec_engine_p99_us: budget.map(|b| b.spec_engine_p99_us),
                http_budget_p99_us: budget.map(|b| b.http_p99_us),
                pass,
            }
        })
        .collect();
    rows.sort_by(|a, b| a.journey.cmp(&b.journey));
    rows
}

/// Whether every journey that has a budget stayed within it. Journeys with no
/// budget (revoke) do not affect the verdict. An all-unbudgeted set passes
/// vacuously.
#[must_use]
pub fn overall_pass(rows: &[JourneyRow]) -> bool {
    rows.iter().all(|r| r.pass.unwrap_or(true))
}

/// Whether any budgeted journey in `rows` breached its HTTP p99 budget.
#[must_use]
pub fn any_breach(rows: &[JourneyRow]) -> bool {
    rows.iter().any(|r| r.pass == Some(false))
}

/// The saturation knee: the achieved RPS of the first ramp step (in order) that
/// breached a budget. `None` if no step breached.
#[must_use]
pub fn find_knee(steps: &[RampStep]) -> Option<f64> {
    steps.iter().find(|s| s.breached).map(|s| s.rps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use goose::goose::GooseMethod;
    use goose::metrics::GooseRequestMetricAggregate;
    use std::collections::BTreeMap;

    fn timing(samples: &[(usize, usize)]) -> GooseRequestMetricTimingData {
        let times: BTreeMap<usize, usize> = samples.iter().copied().collect();
        let counter: usize = samples.iter().map(|(_, c)| c).sum();
        let minimum_time = samples.iter().map(|(v, _)| *v).min().unwrap_or(0);
        let maximum_time = samples.iter().map(|(v, _)| *v).max().unwrap_or(0);
        let total_time: usize = samples.iter().map(|(v, c)| v * c).sum();
        GooseRequestMetricTimingData {
            times,
            minimum_time,
            maximum_time,
            total_time,
            counter,
        }
    }

    fn agg(
        name: &str,
        method: GooseMethod,
        t: GooseRequestMetricTimingData,
    ) -> (String, GooseRequestMetricAggregate) {
        let key = format!("{method} {name}");
        let success = t.counter;
        (
            key.clone(),
            GooseRequestMetricAggregate {
                path: format!("/{name}"),
                method,
                raw_data: t,
                coordinated_omission_data: None,
                status_code_counts: std::collections::HashMap::new(),
                success_count: success,
                fail_count: 0,
                load_test_hash: 0,
            },
        )
    }

    #[test]
    fn percentile_walks_the_histogram() {
        // 100 samples: 90 at 1 ms, 9 at 2 ms, 1 at 50 ms.
        let t = timing(&[(1, 90), (2, 9), (50, 1)]);
        assert_eq!(percentile_ms(&t, 0.5), 1);
        assert_eq!(percentile_ms(&t, 0.95), 2);
        // p99 = 99th of 100 → still in the 2 ms bucket (cumulative 99).
        assert_eq!(percentile_ms(&t, 0.99), 2);
        // p999 rounds to the 100th sample → the 50 ms tail.
        assert_eq!(percentile_ms(&t, 0.999), 50);
    }

    #[test]
    fn percentile_of_empty_is_zero() {
        let t = timing(&[]);
        assert_eq!(percentile_ms(&t, 0.99), 0);
    }

    #[test]
    fn rows_map_names_to_budgets_and_verdicts() {
        let mut requests: GooseRequestMetrics = std::collections::HashMap::new();
        // validate: p99 in the 1 ms bucket → within the 1.5 ms budget → pass.
        let (k, v) = agg("validate", GooseMethod::Post, timing(&[(1, 100)]));
        requests.insert(k, v);
        // session_lookup: p99 at 3 ms → over the 1.1 ms budget → fail.
        let (k, v) = agg("session_lookup", GooseMethod::Get, timing(&[(3, 100)]));
        requests.insert(k, v);
        // revoke: compound, no budget → pass=None.
        let (k, v) = agg("revoke", GooseMethod::Post, timing(&[(9, 100)]));
        requests.insert(k, v);

        let rows = journey_rows(&requests, &HashMap::new());
        assert_eq!(rows.len(), 3);
        // Sorted by name: revoke, session_lookup, validate.
        assert_eq!(rows[0].journey, "revoke");
        assert_eq!(rows[0].pass, None);
        assert_eq!(rows[1].journey, "session_lookup");
        assert_eq!(rows[1].pass, Some(false));
        assert_eq!(rows[2].journey, "validate");
        assert_eq!(rows[2].pass, Some(true));
        assert_eq!(rows[2].http_budget_p99_us, Some(1_500));

        // Overall fails because session_lookup breached.
        assert!(!overall_pass(&rows));
        assert!(any_breach(&rows));
    }

    #[test]
    fn fast_but_all_failing_journey_does_not_pass() {
        // Regression: a journey that responds in 1 ms (within budget) but every
        // request errored must report pass=false, not a silent latency pass.
        let mut requests: GooseRequestMetrics = std::collections::HashMap::new();
        let (key, mut v) = agg("validate", GooseMethod::Post, timing(&[(1, 1000)]));
        v.success_count = 0;
        v.fail_count = 1000;
        requests.insert(key, v);
        let rows = journey_rows(&requests, &HashMap::new());
        assert_eq!(rows[0].failures, 1000);
        assert!((rows[0].failure_rate - 1.0).abs() < f64::EPSILON);
        assert_eq!(rows[0].pass, Some(false), "all-erroring journey must fail");
        assert!(!overall_pass(&rows));
    }

    #[test]
    fn all_within_budget_passes_overall() {
        let mut requests: GooseRequestMetrics = std::collections::HashMap::new();
        let (k, v) = agg("validate", GooseMethod::Post, timing(&[(1, 100)]));
        requests.insert(k, v);
        let (k, v) = agg("issuance", GooseMethod::Post, timing(&[(4, 100)]));
        requests.insert(k, v);
        let rows = journey_rows(&requests, &HashMap::new());
        assert!(overall_pass(&rows));
        assert!(!any_breach(&rows));
    }

    #[test]
    fn rows_carry_submillisecond_min_max_from_the_latency_snapshot() {
        // Regression (HEA-1796 board comment): min/max must be reported at
        // microsecond resolution, not rounded to Goose's whole-ms grid.
        let mut requests: GooseRequestMetrics = std::collections::HashMap::new();
        let (k, v) = agg("validate", GooseMethod::Post, timing(&[(1, 100)]));
        requests.insert(k, v);

        let mut latency: HashMap<&'static str, LatencyExtremes> = HashMap::new();
        latency.insert(
            "validate",
            LatencyExtremes {
                min_us: 90, // 0.09 ms — rounds to 0 ms in Goose
                max_us: 1_450,
            },
        );

        let rows = journey_rows(&requests, &latency);
        assert_eq!(rows[0].journey, "validate");
        assert_eq!(rows[0].min_us, Some(90));
        assert_eq!(rows[0].max_us, Some(1_450));

        // A journey with no latency sample carries None, not a bogus 0.
        let (k, v) = agg("session_lookup", GooseMethod::Get, timing(&[(2, 10)]));
        requests.insert(k, v);
        let rows = journey_rows(&requests, &latency);
        let session = rows.iter().find(|r| r.journey == "session_lookup").unwrap();
        assert_eq!(session.min_us, None);
        assert_eq!(session.max_us, None);
    }

    /// Minimal [`JourneyRow`] for summary tests: only the fields `summarize`
    /// reads (requests, failures, pass) are meaningful.
    fn row(journey: &str, requests: usize, failures: usize, pass: Option<bool>) -> JourneyRow {
        JourneyRow {
            journey: journey.to_string(),
            method: "POST".to_string(),
            requests,
            failures,
            failure_rate: budget::failure_rate(failures, requests),
            p50_ms: 0,
            p95_ms: 0,
            p99_ms: 0,
            p999_ms: 0,
            min_us: None,
            max_us: None,
            spec_engine_p99_us: None,
            http_budget_p99_us: None,
            pass,
        }
    }

    #[test]
    fn ceiling_is_server_when_a_budget_breaches() {
        let rows = vec![
            row("validate", 10_000, 0, Some(true)),
            row("session_lookup", 5_000, 0, Some(false)), // breach
        ];
        let s = summarize(&rows, 10_000, 42_000.0);
        assert_eq!(s.ceiling, Ceiling::Server);
        assert_eq!(s.achieved_users, 10_000);
        assert_eq!(s.total_requests, 15_000);
    }

    #[test]
    fn ceiling_is_generator_or_headroom_when_clean() {
        // No breach, negligible failures → the server kept up; ceiling is the
        // generator or untested headroom, not the server.
        let rows = vec![row("validate", 100_000, 0, Some(true))];
        let s = summarize(&rows, 10_000, 55_000.0);
        assert_eq!(s.ceiling, Ceiling::LoadGeneratorOrHeadroom);
        assert!((s.failure_rate - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn ceiling_is_generator_saturated_on_high_failures_without_breach() {
        // 5% failures but every journey within its latency budget → the failures
        // are connection-level (generator saturation), not server latency.
        let rows = vec![row("validate", 100_000, 5_000, Some(true))];
        let s = summarize(&rows, 10_000, 30_000.0);
        assert_eq!(s.ceiling, Ceiling::GeneratorSaturated);
        assert!(s.failure_rate > GENERATOR_SATURATION_FAILURE_RATE);
    }

    #[test]
    fn knee_is_first_breaching_step() {
        let steps = vec![
            RampStep {
                users: 10,
                rps: 100.0,
                breached: false,
                journeys: vec![],
            },
            RampStep {
                users: 20,
                rps: 200.0,
                breached: false,
                journeys: vec![],
            },
            RampStep {
                users: 30,
                rps: 280.0,
                breached: true,
                journeys: vec![],
            },
            RampStep {
                users: 40,
                rps: 300.0,
                breached: true,
                journeys: vec![],
            },
        ];
        assert_eq!(find_knee(&steps), Some(280.0));
    }

    #[test]
    fn knee_none_when_no_step_breaches() {
        let steps = vec![
            RampStep {
                users: 10,
                rps: 100.0,
                breached: false,
                journeys: vec![],
            },
            RampStep {
                users: 20,
                rps: 200.0,
                breached: false,
                journeys: vec![],
            },
        ];
        assert_eq!(find_knee(&steps), None);
    }

    #[test]
    fn report_serializes_with_schema_and_skips_empty_mode_fields() {
        let report = LoadReport {
            schema: SCHEMA_VERSION,
            metadata: RunMetadata {
                git_sha: "abc123".into(),
                timestamp_unix: 1_700_000_000,
                mode: "steady".into(),
                host: "http://127.0.0.1:8420".into(),
                seed: 1,
                dataset_shape: "realms=1".into(),
                users: 50,
                run_time: "60s".into(),
                hatch_rate: "5".into(),
            },
            summary: summarize(&[], 50, 0.0),
            journeys: vec![],
            ramp_steps: None,
            knee_rps: None,
            soak_buckets: None,
            tier_miss: None,
            resources: None,
            pass: true,
        };
        let json = serde_json::to_string(&report).expect("serialize");
        assert!(json.contains("\"schema\":3"));
        assert!(json.contains("\"git_sha\":\"abc123\""));
        assert!(json.contains("\"summary\""));
        assert!(json.contains("\"pass\":true"));
        // steady-mode report omits ramp/soak/tier-only fields.
        assert!(!json.contains("knee_rps"));
        assert!(!json.contains("ramp_steps"));
        assert!(!json.contains("soak_buckets"));
        assert!(!json.contains("tier_miss"));
        // no sampling → the resources block is omitted, not null.
        assert!(!json.contains("resources"));
    }

    #[test]
    fn ramp_report_includes_knee() {
        let report = LoadReport {
            schema: SCHEMA_VERSION,
            metadata: RunMetadata {
                git_sha: "deadbeef".into(),
                timestamp_unix: 1,
                mode: "ramp".into(),
                host: "h".into(),
                seed: 1,
                dataset_shape: "s".into(),
                users: 10,
                run_time: "30s".into(),
                hatch_rate: "5".into(),
            },
            summary: summarize(&[], 10, 123.5),
            journeys: vec![],
            ramp_steps: Some(vec![RampStep {
                users: 10,
                rps: 123.5,
                breached: true,
                journeys: vec![],
            }]),
            knee_rps: Some(123.5),
            soak_buckets: None,
            tier_miss: None,
            resources: None,
            pass: false,
        };
        let json = serde_json::to_string(&report).expect("serialize");
        assert!(json.contains("\"knee_rps\":123.5"));
        assert!(json.contains("\"mode\":\"ramp\""));
    }

    #[test]
    fn tier_miss_report_splits_hot_and_cold_percentiles() {
        // The corpus-scale proof: hot working set resident (fast) vs uniform cold
        // draw through the SST tier (slow). The per-tier delta is the signal, read
        // at p50/p95 (the tail can invert under Argon2id contention, HEA-1804).
        let mut requests: GooseRequestMetrics = std::collections::HashMap::new();
        let (k, v) = agg("lookup_hot", GooseMethod::Post, timing(&[(2, 100)]));
        requests.insert(k, v);
        let (k, v) = agg("lookup_cold", GooseMethod::Post, timing(&[(9, 100)]));
        requests.insert(k, v);

        let mut latency: HashMap<&'static str, LatencyExtremes> = HashMap::new();
        latency.insert(
            "lookup_hot",
            LatencyExtremes {
                min_us: 800,
                max_us: 2_100,
            },
        );
        latency.insert(
            "lookup_cold",
            LatencyExtremes {
                min_us: 3_000,
                max_us: 9_400,
            },
        );

        let rows = journey_rows(&requests, &latency);
        let tm = tier_miss_report(&rows, 1_000_000, 1_000, Some(100_000), 50, 50);

        assert_eq!(tm.corpus_size, 1_000_000);
        assert_eq!(tm.hot_working_set_size, 1_000);
        assert_eq!(tm.hot_tier_capacity, Some(100_000));
        assert!((tm.hot_request_fraction - 0.5).abs() < f64::EPSILON);
        // 100k resident of 1M → 90% of a uniform cold draw misses.
        assert!((tm.expected_cold_miss_rate.unwrap() - 0.9).abs() < 1e-9);
        // p50/p95 are the primary read: a single timing bucket per tier makes all
        // percentiles resolve to that bucket, so the hot < cold ordering holds at
        // every percentile the report surfaces.
        assert_eq!(tm.hot_p50_ms, Some(2));
        assert_eq!(tm.cold_p50_ms, Some(9));
        assert_eq!(tm.hot_p95_ms, Some(2));
        assert_eq!(tm.cold_p95_ms, Some(9));
        assert_eq!(tm.hot_p99_ms, Some(2));
        assert_eq!(tm.cold_p99_ms, Some(9));
        assert_eq!(tm.hot_max_us, Some(2_100));
        assert_eq!(tm.cold_max_us, Some(9_400));
    }

    #[test]
    fn tier_miss_report_without_capacity_omits_miss_rate() {
        let rows = journey_rows(&std::collections::HashMap::new(), &HashMap::new());
        let tm = tier_miss_report(&rows, 10_000, 500, None, 30, 70);
        assert_eq!(tm.expected_cold_miss_rate, None);
        // No journeys recorded → every per-tier percentile is absent, not a bogus 0.
        assert_eq!(tm.hot_p50_ms, None);
        assert_eq!(tm.cold_p50_ms, None);
        assert_eq!(tm.hot_p95_ms, None);
        assert_eq!(tm.cold_p95_ms, None);
        assert_eq!(tm.hot_p99_ms, None);
        assert_eq!(tm.cold_p99_ms, None);
        assert!((tm.hot_request_fraction - 0.3).abs() < f64::EPSILON);
    }

    fn resource_report(cpu_mean: f64, cpu_peak: f64) -> ResourceReport {
        ResourceReport {
            pid: 1,
            samples: 63,
            interval_ms: 1000,
            rss_peak_bytes: 1024 * 1024,
            rss_mean_bytes: 1024 * 1024,
            cpu_peak_pct: cpu_peak,
            cpu_mean_pct: cpu_mean,
        }
    }

    // --- correct_ceiling_with_resources regression tests (HEA-1880) ---

    #[test]
    fn server_ceiling_without_resource_data_becomes_unknown() {
        // A run with a latency breach but no --server-pid cannot claim server
        // attribution — 0% CPU and 30-second client timeouts both look the same
        // without evidence. Pin to Unknown (inadmissible for grading).
        let rows = vec![row("session_lookup", 1_357, 1_357, Some(false))]; // breach
        let mut s = summarize(&rows, 700, 30.0);
        assert_eq!(
            s.ceiling,
            Ceiling::Server,
            "pre-condition: initial attribution"
        );
        correct_ceiling_with_resources(&mut s, None);
        assert_eq!(s.ceiling, Ceiling::Unknown);
        assert!(s.ceiling_reason.contains("inadmissible"));
    }

    #[test]
    fn server_ceiling_with_zero_cpu_becomes_generator_saturated() {
        // Reproduces steady-700u through steady-2000u from HEA-1812: 100% failure
        // rate, latency breach (30 s timeout), server CPU mean=0.0% peak=0.0%.
        // The server did no work — the generator saturated (port exhaustion /
        // TIME_WAIT), not the server.
        let rows = vec![row("session_lookup", 1_357, 1_357, Some(false))]; // breach
        let mut s = summarize(&rows, 700, 30.0);
        assert_eq!(
            s.ceiling,
            Ceiling::Server,
            "pre-condition: initial attribution"
        );
        let res = resource_report(0.0, 0.0);
        correct_ceiling_with_resources(&mut s, Some(&res));
        assert_eq!(s.ceiling, Ceiling::GeneratorSaturated);
        assert!(
            s.ceiling_reason.contains("idle"),
            "reason should mention idle server: {}",
            s.ceiling_reason
        );
    }

    #[test]
    fn server_ceiling_with_high_cpu_stays_server() {
        // Reproduces steady-500u from HEA-1812: high CPU, legitimate breach.
        // cpu_mean=178%, cpu_peak=292% — the server was the bottleneck.
        let rows = vec![row("validate", 10_000, 0, Some(false))]; // breach
        let mut s = summarize(&rows, 500, 1678.0);
        assert_eq!(s.ceiling, Ceiling::Server, "pre-condition");
        let res = resource_report(178.0, 292.0);
        correct_ceiling_with_resources(&mut s, Some(&res));
        assert_eq!(s.ceiling, Ceiling::Server, "high-CPU run must stay Server");
    }

    #[test]
    fn non_server_ceiling_is_not_changed_by_correction() {
        // GeneratorSaturated is derived from failure rate; resource data cannot
        // promote it to Server, and Unknown only applies to Server attributions.
        let rows = vec![row("validate", 100_000, 5_001, Some(true))]; // high failure, no breach
        let mut s = summarize(&rows, 10_000, 30_000.0);
        assert_eq!(
            s.ceiling,
            Ceiling::GeneratorSaturated,
            "pre-condition: high failure without breach"
        );
        // Calling with None should NOT change a non-Server ceiling.
        correct_ceiling_with_resources(&mut s, None);
        assert_eq!(
            s.ceiling,
            Ceiling::GeneratorSaturated,
            "correction must not mutate non-Server ceilings"
        );
    }

    #[test]
    fn cpu_just_above_floor_stays_server() {
        // cpu_peak_pct=15% exceeds SERVER_CPU_FLOOR_PEAK_PCT (10%) so the override
        // does not fire — we cannot rule out a brief server spike that collapsed the
        // generator after a short burst.
        let rows = vec![row("validate", 1_000, 1_000, Some(false))]; // breach
        let mut s = summarize(&rows, 100, 10.0);
        assert_eq!(s.ceiling, Ceiling::Server, "pre-condition");
        let res = resource_report(3.0, 15.0); // mean below floor, peak above
        correct_ceiling_with_resources(&mut s, Some(&res));
        assert_eq!(
            s.ceiling,
            Ceiling::Server,
            "peak above floor must prevent the generator-saturated override"
        );
    }
}
