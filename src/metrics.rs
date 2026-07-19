//! Prometheus metrics registry and metric definitions for Hearth.
//!
//! All metrics are registered into a dedicated [`Registry`] (not the
//! process-global default) so the namespace is clean and the registry can
//! be exercised in unit tests without global state pollution.
//!
//! # Usage
//!
//! Increment counters and observe histograms directly on the [`Metrics`]
//! instance returned by [`metrics()`]:
//!
//! ```text
//! metrics()
//!     .tokens_issued_total
//!     .with_label_values(&["my-realm", "authorization_code"])
//!     .inc();
//! ```
//!
//! Render the current snapshot for the `/metrics` scrape endpoint via
//! [`Metrics::render`].

use std::sync::OnceLock;

use prometheus::{
    Counter, CounterVec, Gauge, GaugeVec, HistogramOpts, HistogramVec, Opts, Registry,
};

/// HTTP request latency histogram buckets (seconds).
///
/// Range: 1 ms → 2.5 s, covering sub-millisecond hot-path responses
/// through the occasional slow admin or federation request.
const HTTP_BUCKETS: &[f64] = &[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5];

/// Storage operation latency histogram buckets (seconds).
///
/// Range: 50 µs → 100 ms, covering WAL flush and SST scan latencies.
/// Does not apply to hot-tier reads, which bypass storage instrumentation
/// to avoid syscall overhead on the hot path.
const STORAGE_BUCKETS: &[f64] = &[
    0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1,
];

/// All Prometheus metrics collected by the Hearth server.
///
/// Obtain the process-global singleton via [`metrics()`].
pub struct Metrics {
    /// Prometheus registry backing all metrics in this struct.
    ///
    /// Exposed so the `/metrics` handler can call
    /// `registry.gather()` without another layer of indirection.
    registry: Registry,

    /// HTTP request latency histogram in seconds.
    ///
    /// Labels: `method` (HTTP verb), `route` (matched path pattern),
    /// `status` (HTTP status code as string).
    pub http_request_duration_seconds: HistogramVec,

    /// Total authentication attempts, by outcome.
    ///
    /// Labels: `realm` (realm UUID string), `outcome` (`success` | `failure`).
    pub auth_attempts_total: CounterVec,

    /// Total tokens issued, by grant type.
    ///
    /// Labels: `realm` (realm UUID string), `grant_type`
    /// (`authorization_code` | `refresh_token` | `client_credentials` |
    /// `urn:ietf:params:oauth:grant-type:device_code`).
    pub tokens_issued_total: CounterVec,

    /// Instantaneous count of active sessions across all realms.
    ///
    /// Incremented on `create_session`; decremented on `revoke_session`.
    pub active_sessions: Gauge,

    /// Storage write and scan operation latency in seconds.
    ///
    /// Labels: `operation` (`put` | `delete` | `put_batch` | `scan`).
    /// `get` is intentionally excluded — hot-tier reads bypass this layer
    /// and adding `Instant::now()` to every `get` would violate the
    /// zero-syscall hot-path contract.
    pub storage_operation_duration_seconds: HistogramVec,

    /// Total number of audit chain integrity verification failures.
    ///
    /// Incremented each time `verify_integrity` detects a hash mismatch in
    /// the append-only audit log. A non-zero value indicates either log
    /// tampering or storage corruption and SHOULD trigger an alert.
    pub audit_integrity_failures_total: Counter,

    /// Total device-fingerprint entries evicted by the background sweeper.
    ///
    /// Monotonically increasing. Each increment represents one expired
    /// `dfp:user:*` storage entry deleted by the proactive TTL sweeper.
    pub dfp_sweeper_evicted_total: Counter,

    /// Active (non-expired) device-fingerprint entries as of the last sweep.
    ///
    /// Sampled once per sweep pass across all realms. Useful for capacity
    /// planning and detecting abnormal fingerprint accumulation.
    pub dfp_keys_active: Gauge,

    // ── Agent Auth (Phase A–D) ──────────────────────────────────────────────
    /// Total agent delegation token exchanges completed.
    ///
    /// Labels: `realm` (realm UUID), `outcome` (`success` | `failure`).
    pub agent_delegation_total: CounterVec,

    /// Total approval request state transitions.
    ///
    /// Labels: `realm` (realm UUID), `transition` (`requested` | `granted` | `denied` | `expired`).
    pub agent_approval_total: CounterVec,

    /// Total Attenuating Authorization Tokens issued or derived.
    ///
    /// Labels: `realm` (realm UUID), `kind` (`root` | `derived`).
    pub agent_aat_issued_total: CounterVec,

    /// Total AAT revocations.
    ///
    /// Labels: `realm` (realm UUID).
    pub agent_aat_revoked_total: CounterVec,

    /// Total transaction token operations.
    ///
    /// Labels: `realm` (realm UUID), `op` (`issued` | `consumed` | `replayed`).
    pub agent_txn_token_total: CounterVec,

    /// Runtime signal that request-rate limiters are globally disabled.
    ///
    /// Label: `reason` (currently only `load_test`). Set to `1` at boot when
    /// the `security.load_test_unthrottled` escape hatch resolves to `Enabled`
    /// (HEA-1799). The time series is **absent** during normal operation —
    /// its mere presence on a live scrape means brute-force / abuse protection
    /// is off, so dashboards and alerts can detect the state even if the
    /// boot-time WARN log has scrolled past.
    pub rate_limiters_disabled: GaugeVec,
}

impl Metrics {
    #[allow(clippy::too_many_lines)]
    fn new() -> Self {
        let registry = Registry::new();

        let http_request_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "hearth_http_request_duration_seconds",
                "HTTP request latency in seconds",
            )
            .buckets(HTTP_BUCKETS.to_vec()),
            &["method", "route", "status"],
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(http_request_duration_seconds.clone()))
            .expect("metric registration succeeds on a fresh registry");

        let auth_attempts_total = CounterVec::new(
            Opts::new(
                "hearth_auth_attempts_total",
                "Total authentication attempts, labelled by outcome",
            ),
            &["realm", "outcome"],
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(auth_attempts_total.clone()))
            .expect("metric registration succeeds on a fresh registry");

        let tokens_issued_total = CounterVec::new(
            Opts::new(
                "hearth_tokens_issued_total",
                "Total tokens issued, labelled by grant type",
            ),
            &["realm", "grant_type"],
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(tokens_issued_total.clone()))
            .expect("metric registration succeeds on a fresh registry");

        let active_sessions = Gauge::new(
            "hearth_active_sessions",
            "Instantaneous count of active sessions across all realms",
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(active_sessions.clone()))
            .expect("metric registration succeeds on a fresh registry");

        let storage_operation_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "hearth_storage_operation_duration_seconds",
                "Storage write and scan operation latency in seconds",
            )
            .buckets(STORAGE_BUCKETS.to_vec()),
            &["operation"],
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(storage_operation_duration_seconds.clone()))
            .expect("metric registration succeeds on a fresh registry");

        let audit_integrity_failures_total = Counter::new(
            "hearth_audit_integrity_failures_total",
            "Total audit chain integrity verification failures detected",
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(audit_integrity_failures_total.clone()))
            .expect("metric registration succeeds on a fresh registry");

        let dfp_sweeper_evicted_total = Counter::new(
            "hearth_dfp_sweeper_evicted_total",
            "Total device-fingerprint entries evicted by the background sweeper",
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(dfp_sweeper_evicted_total.clone()))
            .expect("metric registration succeeds on a fresh registry");

        let dfp_keys_active = Gauge::new(
            "hearth_dfp_keys_active",
            "Active (non-expired) device-fingerprint entries as of the last sweep",
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(dfp_keys_active.clone()))
            .expect("metric registration succeeds on a fresh registry");

        let agent_delegation_total = CounterVec::new(
            Opts::new(
                "hearth_agent_delegation_total",
                "Total agent delegation token exchanges",
            ),
            &["realm", "outcome"],
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(agent_delegation_total.clone()))
            .expect("metric registration succeeds on a fresh registry");

        let agent_approval_total = CounterVec::new(
            Opts::new(
                "hearth_agent_approval_total",
                "Total approval request state transitions",
            ),
            &["realm", "transition"],
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(agent_approval_total.clone()))
            .expect("metric registration succeeds on a fresh registry");

        let agent_aat_issued_total = CounterVec::new(
            Opts::new(
                "hearth_agent_aat_issued_total",
                "Total Attenuating Authorization Tokens issued or derived",
            ),
            &["realm", "kind"],
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(agent_aat_issued_total.clone()))
            .expect("metric registration succeeds on a fresh registry");

        let agent_aat_revoked_total = CounterVec::new(
            Opts::new("hearth_agent_aat_revoked_total", "Total AAT revocations"),
            &["realm"],
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(agent_aat_revoked_total.clone()))
            .expect("metric registration succeeds on a fresh registry");

        let agent_txn_token_total = CounterVec::new(
            Opts::new(
                "hearth_agent_txn_token_total",
                "Total transaction token operations",
            ),
            &["realm", "op"],
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(agent_txn_token_total.clone()))
            .expect("metric registration succeeds on a fresh registry");

        let rate_limiters_disabled = GaugeVec::new(
            Opts::new(
                "hearth_rate_limiters_disabled",
                "Set to 1 when all request-rate limiters are disabled (load-test escape hatch)",
            ),
            &["reason"],
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(rate_limiters_disabled.clone()))
            .expect("metric registration succeeds on a fresh registry");

        Self {
            registry,
            http_request_duration_seconds,
            auth_attempts_total,
            tokens_issued_total,
            active_sessions,
            storage_operation_duration_seconds,
            audit_integrity_failures_total,
            dfp_sweeper_evicted_total,
            dfp_keys_active,
            agent_delegation_total,
            agent_approval_total,
            agent_aat_issued_total,
            agent_aat_revoked_total,
            agent_txn_token_total,
            rate_limiters_disabled,
        }
    }

    /// Marks the `hearth_rate_limiters_disabled{reason=…}` gauge as active (`1`).
    ///
    /// Call once at boot when the load-test unthrottle escape hatch resolves to
    /// `Enabled`. Before the first call the time series is absent from scrapes,
    /// so `reason` only ever appears when limiters are genuinely off.
    pub fn mark_rate_limiters_disabled(&self, reason: &str) {
        self.rate_limiters_disabled
            .with_label_values(&[reason])
            .set(1.0);
    }

    /// Renders all collected metrics in Prometheus text exposition format.
    ///
    /// The returned string is ready to serve verbatim from the `/metrics`
    /// endpoint with `Content-Type: text/plain; version=0.0.4`.
    pub fn render(&self) -> String {
        use prometheus::Encoder as _;
        let encoder = prometheus::TextEncoder::new();
        let families = self.registry.gather();
        let mut buf = Vec::new();
        if let Err(e) = encoder.encode(&families, &mut buf) {
            tracing::error!(error = %e, "failed to encode Prometheus metrics");
            return String::new();
        }
        // Prometheus text format is always valid UTF-8.
        String::from_utf8(buf).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::Metrics;

    /// HEA-1799: the `hearth_rate_limiters_disabled` time series is absent from
    /// a scrape during normal operation and appears (set to `1`) only after the
    /// load-test escape hatch marks it.
    #[test]
    fn rate_limiters_disabled_gauge_absent_until_marked() {
        let metrics = Metrics::new();

        // Off (never marked) — the family must not appear in the render output,
        // so a scrape cannot false-positive during normal operation.
        let before = metrics.render();
        assert!(
            !before.contains("hearth_rate_limiters_disabled"),
            "gauge must be absent before the escape hatch marks it, got:\n{before}"
        );

        // Enabled — mark it, then the labelled series must be present at value 1.
        metrics.mark_rate_limiters_disabled("load_test");
        let after = metrics.render();
        assert!(
            after.contains("hearth_rate_limiters_disabled{reason=\"load_test\"} 1"),
            "gauge must read 1 for reason=load_test once marked, got:\n{after}"
        );
    }
}

/// Process-global [`Metrics`] singleton backing storage.
static INSTANCE: OnceLock<Metrics> = OnceLock::new();

/// Returns the process-global [`Metrics`] singleton, initialising it on first call.
///
/// Uses [`OnceLock`] (not `lazy_static!`) per the project policy.
pub fn metrics() -> &'static Metrics {
    INSTANCE.get_or_init(Metrics::new)
}
