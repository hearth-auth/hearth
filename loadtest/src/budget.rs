//! Sourced latency budgets and the pass/fail comparison (HEA-1791).
//!
//! Two constant sets, per the HEA-1787 plan §3/§6:
//!
//! * `SPEC_P99_ENGINE_*_US` — the **in-process engine** p99 targets, cited
//!   verbatim from `docs/specs/TESTING.md` lines 143–152 ("Benchmark targets
//!   and thresholds, from vision doc §7.1"). These are the physics floor: raw
//!   op latency with no wire overhead. They are NOT what this harness measures.
//! * `HTTP_BUDGET_P99_*_US` — the HTTP-level p99 budgets this harness asserts
//!   against. Each is its engine target **plus a documented loopback
//!   envelope**: the extra cost of `loopback → axum → handler → engine →
//!   response` (framing, serialization, syscalls). The envelope value and the
//!   "engine target + loopback allowance" approach were signed off by the CTO
//!   in the approved HEA-1787 plan (§6 proposal, §9 decision 3). No budget here
//!   is invented — DoD requirement.
//!
//! We deliberately do NOT assert the raw engine numbers over HTTP: a 500 µs
//! engine target is physically unreachable through the full request stack, so
//! asserting it would fail every run and prove nothing.

/// Engine p99 — token validation (JWT verify + session lookup).
/// Source: `docs/specs/TESTING.md:147` (`< 500 us`).
pub const SPEC_P99_ENGINE_TOKEN_VALIDATION_US: u64 = 500;

/// Engine p99 — session lookup by ID.
/// Source: `docs/specs/TESTING.md:148` (`< 100 us`).
pub const SPEC_P99_ENGINE_SESSION_LOOKUP_US: u64 = 100;

/// Engine p99 — permission check (direct relationship). Not a load journey
/// (authorization is off the hot path — permissions are baked into the JWT at
/// issue time), cited for completeness of the sourced set.
/// Source: `docs/specs/TESTING.md:149` (`< 200 us`).
// Not mapped to a load journey (authorization is off the hot path), but cited
// so the sourced-budget set is complete and the guard test below covers it.
#[allow(dead_code)]
pub const SPEC_P99_ENGINE_PERMISSION_CHECK_US: u64 = 200;

/// Engine p99 — user lookup by email/ID.
/// Source: `docs/specs/TESTING.md:151` (`< 200 us`).
pub const SPEC_P99_ENGINE_USER_LOOKUP_US: u64 = 200;

/// Engine p99 — token issuance (full OAuth2 flow).
/// Source: `docs/specs/TESTING.md:152` (`< 5 ms`).
pub const SPEC_P99_ENGINE_TOKEN_ISSUANCE_US: u64 = 5_000;

/// Loopback envelope added to every engine target to form the HTTP budget.
///
/// The engine numbers are in-process; this harness drives real HTTP over
/// loopback. `~1 ms` covers axum routing, request/response (de)serialization,
/// and loopback syscall overhead. CTO-approved in the HEA-1787 plan (§6
/// proposal "engine target + ~1 ms loopback allowance"; §9 decision 3).
pub const LOOPBACK_ENVELOPE_P99_US: u64 = 1_000;

/// HTTP p99 budget — validate journey (`POST /introspect`).
pub const HTTP_BUDGET_P99_VALIDATE_US: u64 =
    SPEC_P99_ENGINE_TOKEN_VALIDATION_US + LOOPBACK_ENVELOPE_P99_US;

/// HTTP p99 budget — session-lookup journey (`GET /userinfo`).
pub const HTTP_BUDGET_P99_SESSION_US: u64 =
    SPEC_P99_ENGINE_SESSION_LOOKUP_US + LOOPBACK_ENVELOPE_P99_US;

/// HTTP p99 budget — user-lookup journey (`GET /admin/users/{id}`).
pub const HTTP_BUDGET_P99_USER_US: u64 = SPEC_P99_ENGINE_USER_LOOKUP_US + LOOPBACK_ENVELOPE_P99_US;

/// HTTP p99 budget — issuance journey (`POST /token`).
pub const HTTP_BUDGET_P99_ISSUANCE_US: u64 =
    SPEC_P99_ENGINE_TOKEN_ISSUANCE_US + LOOPBACK_ENVELOPE_P99_US;

/// The sourced budget for one journey: its engine floor and HTTP budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    /// In-process engine p99 target (µs) — the physics floor, informational.
    pub spec_engine_p99_us: u64,
    /// HTTP p99 budget (µs) this harness asserts against.
    pub http_p99_us: u64,
}

/// The sourced budget for `journey_name`, or `None` for journeys with no
/// single spec operation to compare against (the compound revoke journey mints,
/// revokes, then re-validates — no atomic engine target maps to it).
///
/// `journey_name` is the Goose transaction/request name (e.g. `"validate"`,
/// `"session_lookup"`; the compound revoke sub-requests are `"revoke_mint"`,
/// `"revoke"`, `"revoke_revalidate"`).
#[must_use]
pub fn budget_for(journey_name: &str) -> Option<Budget> {
    let (engine, http) = match journey_name {
        "validate" => (
            SPEC_P99_ENGINE_TOKEN_VALIDATION_US,
            HTTP_BUDGET_P99_VALIDATE_US,
        ),
        "session_lookup" => (
            SPEC_P99_ENGINE_SESSION_LOOKUP_US,
            HTTP_BUDGET_P99_SESSION_US,
        ),
        "user_lookup" => (SPEC_P99_ENGINE_USER_LOOKUP_US, HTTP_BUDGET_P99_USER_US),
        "issuance" => (
            SPEC_P99_ENGINE_TOKEN_ISSUANCE_US,
            HTTP_BUDGET_P99_ISSUANCE_US,
        ),
        // revoke_mint / revoke / revoke_revalidate: compound, no atomic target.
        _ => return None,
    };
    Some(Budget {
        spec_engine_p99_us: engine,
        http_p99_us: http,
    })
}

/// Maximum fraction of failed (non-2xx / errored) requests a journey may have
/// and still be eligible to pass its budget.
///
/// A latency budget is meaningless if the requests aren't actually succeeding:
/// a journey that 100%-errors but responds in 1 ms must NOT read as a pass. We
/// therefore gate the pass on a low failure rate as well as latency. 5% mirrors
/// a conventional load-test error-budget; a run above it is reported as failing
/// regardless of how fast the errors came back.
pub const MAX_FAILURE_RATE: f64 = 0.05;

/// Whether an observed HTTP p99 (in whole ms, as Goose records) is within
/// `budget`. Goose stores response times in integer milliseconds, so the
/// observed value is scaled to µs before comparison to keep sub-ms budgets
/// meaningful. A p99 exactly equal to the budget passes.
#[must_use]
pub fn within_budget(observed_p99_ms: usize, budget: Budget) -> bool {
    (observed_p99_ms as u64) * 1_000 <= budget.http_p99_us
}

/// The pass/fail verdict for a journey: it must be **both** within its latency
/// budget **and** succeeding (failure rate at or below [`MAX_FAILURE_RATE`]).
/// A fast-but-all-erroring journey fails.
#[must_use]
pub fn passes(observed_p99_ms: usize, failures: usize, requests: usize, budget: Budget) -> bool {
    within_budget(observed_p99_ms, budget) && failure_rate(failures, requests) <= MAX_FAILURE_RATE
}

/// Failure fraction in `[0.0, 1.0]`. Zero requests → `0.0` (nothing failed).
#[must_use]
pub fn failure_rate(failures: usize, requests: usize) -> f64 {
    if requests == 0 {
        0.0
    } else {
        #[allow(clippy::cast_precision_loss)]
        {
            failures as f64 / requests as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_constants_match_testing_md() {
        // Guards against a silent edit drifting away from TESTING.md:143-152.
        assert_eq!(SPEC_P99_ENGINE_TOKEN_VALIDATION_US, 500);
        assert_eq!(SPEC_P99_ENGINE_SESSION_LOOKUP_US, 100);
        assert_eq!(SPEC_P99_ENGINE_PERMISSION_CHECK_US, 200);
        assert_eq!(SPEC_P99_ENGINE_USER_LOOKUP_US, 200);
        assert_eq!(SPEC_P99_ENGINE_TOKEN_ISSUANCE_US, 5_000);
    }

    #[test]
    fn http_budget_is_engine_plus_documented_envelope() {
        // The CTO-approved formula: HTTP budget = engine target + loopback envelope.
        assert_eq!(
            HTTP_BUDGET_P99_VALIDATE_US,
            SPEC_P99_ENGINE_TOKEN_VALIDATION_US + LOOPBACK_ENVELOPE_P99_US
        );
        assert_eq!(HTTP_BUDGET_P99_VALIDATE_US, 1_500);
        assert_eq!(HTTP_BUDGET_P99_SESSION_US, 1_100);
        assert_eq!(HTTP_BUDGET_P99_USER_US, 1_200);
        assert_eq!(HTTP_BUDGET_P99_ISSUANCE_US, 6_000);
    }

    #[test]
    fn budget_lookup_maps_each_journey() {
        assert_eq!(
            budget_for("validate").unwrap().http_p99_us,
            HTTP_BUDGET_P99_VALIDATE_US
        );
        assert_eq!(
            budget_for("session_lookup").unwrap().spec_engine_p99_us,
            SPEC_P99_ENGINE_SESSION_LOOKUP_US
        );
        assert!(budget_for("user_lookup").is_some());
        assert!(budget_for("issuance").is_some());
    }

    #[test]
    fn compound_revoke_journey_has_no_atomic_budget() {
        assert!(budget_for("revoke").is_none());
        assert!(budget_for("revoke_mint").is_none());
        assert!(budget_for("revoke_revalidate").is_none());
        assert!(budget_for("something_unknown").is_none());
    }

    #[test]
    fn within_budget_passes_under_and_at_the_line() {
        let b = budget_for("validate").unwrap(); // 1500 µs = 1.5 ms
        assert!(within_budget(0, b));
        assert!(within_budget(1, b)); // 1 ms = 1000 µs <= 1500
        assert!(!within_budget(2, b)); // 2 ms = 2000 µs > 1500 → breach
    }

    #[test]
    fn passes_requires_both_latency_and_low_failure_rate() {
        let b = budget_for("validate").unwrap(); // 1.5 ms budget
                                                 // Fast + all successful → pass.
        assert!(passes(1, 0, 1000, b));
        // Fast but every request failed → must NOT pass.
        assert!(!passes(1, 1000, 1000, b));
        // Within the 5% error budget → still passes.
        assert!(passes(1, 40, 1000, b));
        // Just over 5% → fails despite fast latency.
        assert!(!passes(1, 60, 1000, b));
        // Slow but successful → fails on latency.
        assert!(!passes(5, 0, 1000, b));
    }

    #[test]
    fn failure_rate_handles_zero_requests() {
        assert_eq!(failure_rate(0, 0), 0.0);
        assert_eq!(failure_rate(5, 10), 0.5);
        assert_eq!(failure_rate(0, 10), 0.0);
    }

    #[test]
    fn within_budget_at_exact_line_passes() {
        // Session budget is 1100 µs; 1 ms (1000 µs) is under, 2 ms breaches.
        let b = budget_for("session_lookup").unwrap();
        assert!(within_budget(1, b));
        assert!(!within_budget(2, b));
        // Issuance budget is 6000 µs = 6 ms; exactly 6 ms passes.
        let iss = budget_for("issuance").unwrap();
        assert!(within_budget(6, iss));
        assert!(!within_budget(7, iss));
    }
}
