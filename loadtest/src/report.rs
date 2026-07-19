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

use goose::metrics::{GooseRequestMetricTimingData, GooseRequestMetrics};
use serde::Serialize;

use crate::budget::{self, Budget};

/// Report schema version. Bump on any breaking shape change so a nightly diff
/// job can refuse to compare across incompatible schemas.
pub const SCHEMA_VERSION: u32 = 1;

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

/// The full report serialized to `report.json`.
#[derive(Debug, Clone, Serialize)]
pub struct LoadReport {
    /// Schema version (always [`SCHEMA_VERSION`]).
    pub schema: u32,
    /// Run metadata header.
    pub metadata: RunMetadata,
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
/// sourced budget via [`budget::budget_for`]. Rows are sorted by journey name
/// for stable, diff-friendly output.
#[must_use]
pub fn journey_rows(requests: &GooseRequestMetrics) -> Vec<JourneyRow> {
    let mut rows: Vec<JourneyRow> = requests
        .iter()
        .map(|(key, agg)| {
            let name = key.split_once(' ').map_or(key.as_str(), |(_, n)| n);
            let t = &agg.raw_data;
            let p99 = percentile_ms(t, 0.99);
            let budget: Option<Budget> = budget::budget_for(name);
            let pass = budget.map(|b| budget::passes(p99, agg.fail_count, t.counter, b));
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

        let rows = journey_rows(&requests);
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
        let rows = journey_rows(&requests);
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
        let rows = journey_rows(&requests);
        assert!(overall_pass(&rows));
        assert!(!any_breach(&rows));
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
            journeys: vec![],
            ramp_steps: None,
            knee_rps: None,
            soak_buckets: None,
            pass: true,
        };
        let json = serde_json::to_string(&report).expect("serialize");
        assert!(json.contains("\"schema\":1"));
        assert!(json.contains("\"git_sha\":\"abc123\""));
        assert!(json.contains("\"pass\":true"));
        // steady-mode report omits ramp/soak-only fields.
        assert!(!json.contains("knee_rps"));
        assert!(!json.contains("ramp_steps"));
        assert!(!json.contains("soak_buckets"));
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
            journeys: vec![],
            ramp_steps: Some(vec![RampStep {
                users: 10,
                rps: 123.5,
                breached: true,
                journeys: vec![],
            }]),
            knee_rps: Some(123.5),
            soak_buckets: None,
            pass: false,
        };
        let json = serde_json::to_string(&report).expect("serialize");
        assert!(json.contains("\"knee_rps\":123.5"));
        assert!(json.contains("\"mode\":\"ramp\""));
    }
}
