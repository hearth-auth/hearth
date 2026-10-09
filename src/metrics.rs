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
    Counter, CounterVec, Gauge, GaugeVec, Histogram, HistogramOpts, HistogramVec, Opts, Registry,
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

/// Storage `get`-path latency histogram buckets (seconds), for the tier
/// fall-through path only (memtable / SST / miss).
///
/// Range: 500 ns → 10 ms. Finer at the sub-microsecond end than
/// [`STORAGE_BUCKETS`] so a memtable hit (hundreds of ns) is distinguishable
/// from an SST probe (µs–ms). Hot-tier hits are **not** timed — see
/// [`Metrics::inc_get_hot_hit`] — so this histogram never observes them.
const GET_BUCKETS: &[f64] = &[
    0.000_000_5,
    0.000_001,
    0.000_002_5,
    0.000_005,
    0.000_01,
    0.000_025,
    0.000_05,
    0.000_1,
    0.000_25,
    0.000_5,
    0.001,
    0.002_5,
    0.005,
    0.01,
];

/// Buckets for the "SST files probed per fall-through get" histogram.
///
/// A cold lookup fans out across every live SST newest-first (HEA-1800), so the
/// probe count is the linear factor behind cold-tier latency. Powers of two up
/// to 64 capture the tail without over-bucketing the common 0–2 probe case.
const SST_PROBE_BUCKETS: &[f64] = &[0.0, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0];

/// KDF **queue-wait** histogram buckets (seconds) for the bounded Argon2id
/// admission gate (HEA-1887 / R1).
///
/// Range: 100 µs → 1 s. A well-provisioned gate keeps the mass near zero (a
/// permit is free); a saturated one pushes toward the configured
/// `max_queue_wait` ceiling just before it sheds. The shape of this histogram
/// is the direct, previously-invisible evidence of the Little's-Law queue that
/// C9/HEA-1879 inferred only from end-to-end p99.
const KDF_QUEUE_WAIT_BUCKETS: &[f64] = &[
    0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0,
];

/// KDF **compute-time** histogram buckets (seconds) for one Argon2id operation.
///
/// Range: 5 ms → 2 s. Centred on the measured OWASP-parameter cost
/// (≈12–120 ms on `dev-ryzen-7840hs`, C9/HEA-1879 §2) so the compute floor is
/// separable from queue wait — the two histograms together decompose the tail
/// that was a single opaque number before this change.
const KDF_COMPUTE_BUCKETS: &[f64] = &[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0];

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

    /// Set to `1` when the WAL write fence engages, labelled by the fault that
    /// engaged it (audit 2026-08-28 §4.11#8).
    ///
    /// The fence rejects every subsequent write for the life of the process,
    /// because bytes written after a torn record are discarded on replay. Reads
    /// keep working, so nothing else in a scrape distinguishes a fenced node
    /// from a healthy one. The time series is **absent** during normal
    /// operation: its presence on a live scrape means the node accepts no
    /// writes and must be restarted.
    pub wal_write_fenced: GaugeVec,

    // ── Hot-tier / storage `get` observability (HEA-1869) ───────────────────
    /// Total storage `get` operations, labelled by the tier that satisfied
    /// (or failed to satisfy) the read.
    ///
    /// Labels: `outcome` (`hot_hit` | `memtable_hit` | `sst_hit` | `miss`).
    /// The ratio `hot_hit / sum(all)` is the **observed** hot-tier hit ratio —
    /// tier-miss load profiles report this instead of an arithmetic estimate
    /// (HEA-1800). The `hot_hit` series is incremented on the hot path via a
    /// pre-resolved child handle ([`Metrics::inc_get_hot_hit`]); the other three
    /// are incremented off the hot path via [`Metrics::record_get_fallthrough`].
    pub storage_get_total: CounterVec,

    /// Pre-resolved `storage_get_total{outcome="hot_hit"}` child handle.
    ///
    /// Held so the hot path can do a lock-free atomic increment without the
    /// `CounterVec` label-map read lock that `with_label_values` takes —
    /// preserving the "no locks on read path" hot-path rule.
    storage_get_hot_hit: Counter,

    /// `get`-path latency in seconds for the tier **fall-through** path.
    ///
    /// Labels: `outcome` (`memtable_hit` | `sst_hit` | `miss`). Hot-tier hits
    /// are deliberately excluded: timing them would require an `Instant::now()`
    /// clock read on the zero-syscall hot path (and regress `bench-gate`). Their
    /// latency is instead covered by the `storage_hot_tier` benchmark gate.
    pub storage_get_duration_seconds: HistogramVec,

    /// Number of SST files probed per fall-through `get`.
    ///
    /// Observed once per read that misses the hot tier and the memtable. A
    /// rising distribution here is the signature of the O(#SST) cold-lookup
    /// fan-out (HEA-1800); `storage_sst_files` bounds its worst case.
    pub storage_get_ssts_probed: Histogram,

    /// Total hot-tier evictions (clock-sweep + capacity-driven).
    pub storage_hot_tier_evictions_total: Counter,

    /// Total hot-tier promotions **admitted** (took the write lock and inserted).
    ///
    /// Under production sampling (HEA-1775) this counts admitted promotions, not
    /// promotion attempts, so it tracks real map-clone churn.
    pub storage_hot_tier_promotions_total: Counter,

    /// Hot-tier evictions broken down by the realm that owned the evicted key.
    ///
    /// Labels: `realm` (the realm's UUID). The hot tier is one shared cache
    /// across every tenant, so the unlabelled total above cannot say which
    /// realm is being evicted or which realm is doing the evicting
    /// (audit 2026-08-28 §4.9#6). Series appear only while
    /// `storage.hot_tier_per_realm_metrics` is on; turn it off on deployments
    /// where the realm count makes the label's cardinality too expensive.
    pub storage_hot_tier_evictions_by_realm_total: CounterVec,

    /// Hot-tier promotions **admitted**, broken down by realm.
    ///
    /// Labels: `realm` (the realm's UUID). Pairs with
    /// `storage_hot_tier_evictions_by_realm_total`: together they show which
    /// tenant's working set the shared hot tier is actually holding
    /// (audit 2026-08-28 §4.9#6). Gated by the same config knob.
    pub storage_hot_tier_promotions_by_realm_total: CounterVec,

    /// Hot-tier fills discarded because an invalidation raced the fill.
    ///
    /// Incremented when a cold read's promote is dropped because a delete or
    /// update invalidated the tier between the read and the fill
    /// (audit 2026-08-28 §4.21#3). A nonzero rate is normal under write
    /// contention; the discarded record stays servable from memtable/SST.
    pub storage_hot_tier_stale_fills_discarded_total: Counter,

    /// Live SST file count backing the storage engine.
    ///
    /// Updated off the hot path whenever the SST reader set is swapped (flush,
    /// WAL-rotation flush, compaction). Bounds the worst-case probe fan-out of a
    /// cold `get`.
    pub storage_sst_files: Gauge,

    // ── Storage size gauges (#450) ──────────────────────────────────────────
    /// Entries held by the storage memtable, by state.
    ///
    /// Labels: `state` — see [`MemtableStateLabel`]: `active` (the map taking
    /// writes) and `flushing` (the map parked while it streams to an SST; `0`
    /// between flushes). Tombstones count as entries. Both series are present
    /// at 0 from the first scrape. Updated off the hot path, under the
    /// memtable's write lock, on every write, flush and clear — never on a
    /// read. Summed over the process's storage engines (a server runs one).
    pub storage_memtable_entries: GaugeVec,

    /// Bytes held by the storage memtable, by state, as the memtable's own
    /// size estimate (key + value bytes + 16 per entry) — the figure that
    /// triggers a flush, not allocator overhead.
    ///
    /// Labels: `state` (`active` | `flushing`), as for
    /// `storage_memtable_entries`, and updated at the same points.
    pub storage_memtable_bytes: GaugeVec,

    /// Pre-resolved `storage_memtable_entries` children, indexed by
    /// [`MemtableStateLabel::index`], so a write adjusts a plain atomic gauge
    /// without the `GaugeVec` label-map lock.
    memtable_entries_by_state: [Gauge; 2],

    /// Pre-resolved `storage_memtable_bytes` children, indexed like
    /// `memtable_entries_by_state`.
    memtable_bytes_by_state: [Gauge; 2],

    /// Live hot-tier entry count.
    ///
    /// Updated off the hot path, under the shard write lock, whenever a
    /// promotion, invalidation or eviction changes a shard — never on a
    /// hot-tier hit. Summed over the process's storage engines (a server runs one).
    pub storage_hot_tier_entries: Gauge,

    // ── KDF admission control (HEA-1887 / R1) ───────────────────────────────
    /// Argon2id operations currently executing on the **shared** blocking pool
    /// (holding a shared-gate permit). Bounded above by `hearth_kdf_permits`; if
    /// it sits pinned at the permit ceiling the shared gate is saturated and
    /// `hearth_kdf_queue_wait_seconds` / `hearth_kdf_shed_total` show the
    /// resulting back-pressure. The admin-reserved pool (HEA-1892 / F2) is
    /// tracked separately by `hearth_kdf_admin_in_flight` so this gauge never
    /// exceeds its own `hearth_kdf_permits` ceiling.
    pub kdf_in_flight: Gauge,

    /// Argon2id operations currently executing on the **admin-reserved** pool
    /// (HEA-1894). Bounded above by `hearth_kdf_admin_permits`. Split out from
    /// `hearth_kdf_in_flight` so shared-pool saturation alerts shaped
    /// `kdf_in_flight >= kdf_permits` do not misfire on admin traffic.
    pub kdf_admin_in_flight: Gauge,

    /// Configured maximum concurrent Argon2id operations (permit count).
    ///
    /// Set once at boot from `security.password.kdf.max_in_flight` (default =
    /// available parallelism / core count). Exported so a scrape can compute
    /// `kdf_in_flight / kdf_permits` saturation without knowing the config.
    pub kdf_permits: Gauge,

    /// Configured maximum concurrent Argon2id operations reserved for the
    /// **admin** login gate (HEA-1892 / F2).
    ///
    /// Admin login runs under a separate, small permit pool so a flood against a
    /// tenant realm's login form cannot exhaust the shared gate and lock the
    /// operator out of the admin console. Exported separately so a scrape can
    /// reason about admin capacity independently of the shared realm pool.
    pub kdf_admin_permits: Gauge,

    /// Time a request waited to acquire a KDF permit before its Argon2id op ran,
    /// in seconds. Only successful (non-shed) acquisitions are observed.
    pub kdf_queue_wait_seconds: Histogram,

    /// Wall-clock cost of a single Argon2id operation (verify or hash), in
    /// seconds — measured around the `spawn_blocking` body, excluding queue wait.
    pub kdf_compute_seconds: Histogram,

    /// Total Argon2id operations shed (rejected with `503`/`Retry-After`) because
    /// no permit became free within the configured `max_queue_wait` budget.
    ///
    /// A non-zero and rising value means the KDF path is overloaded and honest
    /// back-pressure is engaging instead of the unbounded queueing that produced
    /// the multi-second p99 tail in C9/HEA-1879. Counts **shared-pool** sheds
    /// only; admin-pool sheds are tracked by `hearth_kdf_admin_shed_total`.
    pub kdf_shed_total: Counter,

    /// Total Argon2id operations shed on the **admin-reserved** pool (HEA-1894).
    ///
    /// Split out from `hearth_kdf_shed_total` so operators can alert on the
    /// exact condition the F2 isolation exists to prevent — the admin console
    /// shedding — without conflating it with tenant-realm login sheds.
    pub kdf_admin_shed_total: Counter,

    /// Total control-epoch bumps that could not be persisted.
    ///
    /// A control (token or session revocation, DPoP key block, realm status
    /// change) is applied on the node that served it and announced to the
    /// others by bumping the replicated control epoch. A failed bump means the
    /// other nodes do not reload for it until the next successful bump (which
    /// reloads everything), so any increase is worth an alert in a cluster.
    pub control_epoch_bump_failures_total: Counter,
    /// Controls whose epoch bump failed and is still owed, summed over every
    /// identity engine in the process: a background thread retries the bump
    /// (with bounded backoff) until it succeeds, and a node refused as
    /// `NotLeader` — no leader reachable to forward it to — drops it (the new
    /// leader's election bump covers it); then
    /// this returns to 0. Non-zero for long means a node that believes it
    /// leads cannot commit, and other nodes are enforcing stale controls —
    /// alert on it staying above 0.
    pub control_epoch_bumps_owed: Gauge,

    // ── Cluster write forwarding (H-3) ──────────────────────────────────────
    /// Writes a follower forwarded to the Raft leader, by outcome.
    ///
    /// Labels: `outcome` — a closed set, see [`ForwardedWriteOutcomeLabel`]:
    /// `committed` (applied here too), `not_applied_locally` (committed, not
    /// yet applied on this node within the bound), `not_leader` (the peer was
    /// no longer the leader; retried once), `unreachable` (the leader could
    /// not be connected to; retried once), `busy` (the leader was at its
    /// forwarded-write limit), `rejected` (too large, undecodable, or an older
    /// build), `outcome_unknown` (the answer was lost after the request was
    /// sent). Every series is present at 0 from the first scrape.
    pub cluster_forwarded_writes_total: CounterVec,
}

/// The `outcome` label of `hearth_cluster_forwarded_writes_total`. A closed
/// set: the label never carries a value derived from a request or a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardedWriteOutcomeLabel {
    /// Committed by the leader and applied on the forwarding node.
    Committed,
    /// Committed, but not applied on the forwarding node within the bound.
    NotAppliedLocally,
    /// The peer answered that it is not the leader; nothing was proposed.
    NotLeader,
    /// The leader could not be connected to; nothing was sent.
    Unreachable,
    /// The leader was at its forwarded-write concurrency limit.
    Busy,
    /// Refused for a reason a retry does not cure.
    Rejected,
    /// The answer was lost after the request was sent.
    OutcomeUnknown,
}

impl ForwardedWriteOutcomeLabel {
    /// Every label value, for pre-creating the series.
    pub const ALL: [Self; 7] = [
        Self::Committed,
        Self::NotAppliedLocally,
        Self::NotLeader,
        Self::Unreachable,
        Self::Busy,
        Self::Rejected,
        Self::OutcomeUnknown,
    ];

    /// The Prometheus label value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::NotAppliedLocally => "not_applied_locally",
            Self::NotLeader => "not_leader",
            Self::Unreachable => "unreachable",
            Self::Busy => "busy",
            Self::Rejected => "rejected",
            Self::OutcomeUnknown => "outcome_unknown",
        }
    }
}

/// The `state` label of `hearth_storage_memtable_entries` and
/// `hearth_storage_memtable_bytes`. A closed set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemtableStateLabel {
    /// The map taking writes.
    Active,
    /// The map parked while it streams to an SST.
    Flushing,
}

impl MemtableStateLabel {
    /// Every label value, for pre-creating the series.
    pub const ALL: [Self; 2] = [Self::Active, Self::Flushing];

    /// The Prometheus label value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Flushing => "flushing",
        }
    }

    /// Position of this state in [`Self::ALL`].
    fn index(self) -> usize {
        match self {
            Self::Active => 0,
            Self::Flushing => 1,
        }
    }
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

        let wal_write_fenced = GaugeVec::new(
            Opts::new(
                "hearth_wal_write_fenced",
                "Set to 1 when the WAL write fence is engaged and every write is refused",
            ),
            &["reason"],
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(wal_write_fenced.clone()))
            .expect("metric registration succeeds on a fresh registry");

        let storage_get_total = CounterVec::new(
            Opts::new(
                "hearth_storage_get_total",
                "Total storage get operations, labelled by satisfying tier",
            ),
            &["outcome"],
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(storage_get_total.clone()))
            .expect("metric registration succeeds on a fresh registry");
        // Pre-create every outcome child so all four series are present (at 0)
        // on the first scrape — dashboards can compute a hit ratio before any
        // traffic. `hot_hit` is retained as a handle for lock-free hot-path inc.
        let storage_get_hot_hit = storage_get_total.with_label_values(&["hot_hit"]);
        let _ = storage_get_total.with_label_values(&["memtable_hit"]);
        let _ = storage_get_total.with_label_values(&["sst_hit"]);
        let _ = storage_get_total.with_label_values(&["miss"]);

        let storage_get_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "hearth_storage_get_duration_seconds",
                "Storage get fall-through latency in seconds (excludes hot-tier hits)",
            )
            .buckets(GET_BUCKETS.to_vec()),
            &["outcome"],
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(storage_get_duration_seconds.clone()))
            .expect("metric registration succeeds on a fresh registry");

        let storage_get_ssts_probed = Histogram::with_opts(
            HistogramOpts::new(
                "hearth_storage_get_ssts_probed",
                "Number of SST files probed per fall-through get",
            )
            .buckets(SST_PROBE_BUCKETS.to_vec()),
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(storage_get_ssts_probed.clone()))
            .expect("metric registration succeeds on a fresh registry");

        let storage_hot_tier_evictions_total = Counter::new(
            "hearth_storage_hot_tier_evictions_total",
            "Total hot-tier evictions (clock-sweep and capacity-driven)",
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(storage_hot_tier_evictions_total.clone()))
            .expect("metric registration succeeds on a fresh registry");

        let storage_hot_tier_promotions_total = Counter::new(
            "hearth_storage_hot_tier_promotions_total",
            "Total hot-tier promotions admitted (write lock taken and entry inserted)",
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(storage_hot_tier_promotions_total.clone()))
            .expect("metric registration succeeds on a fresh registry");

        let storage_hot_tier_evictions_by_realm_total = CounterVec::new(
            Opts::new(
                "hearth_storage_hot_tier_evictions_by_realm_total",
                "Hot-tier evictions, labelled by the realm that owned the evicted key",
            ),
            &["realm"],
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(storage_hot_tier_evictions_by_realm_total.clone()))
            .expect("metric registration succeeds on a fresh registry");

        let storage_hot_tier_promotions_by_realm_total = CounterVec::new(
            Opts::new(
                "hearth_storage_hot_tier_promotions_by_realm_total",
                "Hot-tier promotions admitted, labelled by realm",
            ),
            &["realm"],
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(storage_hot_tier_promotions_by_realm_total.clone()))
            .expect("metric registration succeeds on a fresh registry");

        let storage_hot_tier_stale_fills_discarded_total = Counter::new(
            "hearth_storage_hot_tier_stale_fills_discarded_total",
            "Hot-tier fills discarded because a delete or update invalidated \
             the tier between the authoritative read and the fill",
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(
                storage_hot_tier_stale_fills_discarded_total.clone(),
            ))
            .expect("metric registration succeeds on a fresh registry");

        let storage_sst_files = Gauge::new(
            "hearth_storage_sst_files",
            "Live SST file count backing the storage engine",
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(storage_sst_files.clone()))
            .expect("metric registration succeeds on a fresh registry");

        let storage_memtable_entries = GaugeVec::new(
            Opts::new(
                "hearth_storage_memtable_entries",
                "Entries held by the storage memtable (active map, or the map flushing to an SST)",
            ),
            &["state"],
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(storage_memtable_entries.clone()))
            .expect("metric registration succeeds on a fresh registry");
        let memtable_entries_by_state = MemtableStateLabel::ALL
            .map(|state| storage_memtable_entries.with_label_values(&[state.as_str()]));

        let storage_memtable_bytes = GaugeVec::new(
            Opts::new(
                "hearth_storage_memtable_bytes",
                "Estimated bytes held by the storage memtable (active map, or the map flushing \
                 to an SST)",
            ),
            &["state"],
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(storage_memtable_bytes.clone()))
            .expect("metric registration succeeds on a fresh registry");
        let memtable_bytes_by_state = MemtableStateLabel::ALL
            .map(|state| storage_memtable_bytes.with_label_values(&[state.as_str()]));

        let storage_hot_tier_entries = Gauge::new(
            "hearth_storage_hot_tier_entries",
            "Live hot-tier entry count",
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(storage_hot_tier_entries.clone()))
            .expect("metric registration succeeds on a fresh registry");

        let kdf_in_flight = Gauge::new(
            "hearth_kdf_in_flight",
            "Argon2id operations currently executing (holding an admission permit)",
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(kdf_in_flight.clone()))
            .expect("metric registration succeeds on a fresh registry");

        let kdf_admin_in_flight = Gauge::new(
            "hearth_kdf_admin_in_flight",
            "Argon2id operations currently executing on the admin-reserved pool",
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(kdf_admin_in_flight.clone()))
            .expect("metric registration succeeds on a fresh registry");

        let kdf_permits = Gauge::new(
            "hearth_kdf_permits",
            "Configured maximum concurrent Argon2id operations (permit count)",
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(kdf_permits.clone()))
            .expect("metric registration succeeds on a fresh registry");

        let kdf_admin_permits = Gauge::new(
            "hearth_kdf_admin_permits",
            "Configured maximum concurrent Argon2id operations reserved for admin login",
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(kdf_admin_permits.clone()))
            .expect("metric registration succeeds on a fresh registry");

        let kdf_queue_wait_seconds = Histogram::with_opts(
            HistogramOpts::new(
                "hearth_kdf_queue_wait_seconds",
                "Seconds spent waiting for a KDF admission permit (successful acquisitions only)",
            )
            .buckets(KDF_QUEUE_WAIT_BUCKETS.to_vec()),
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(kdf_queue_wait_seconds.clone()))
            .expect("metric registration succeeds on a fresh registry");

        let kdf_compute_seconds = Histogram::with_opts(
            HistogramOpts::new(
                "hearth_kdf_compute_seconds",
                "Wall-clock seconds for one Argon2id operation (excludes queue wait)",
            )
            .buckets(KDF_COMPUTE_BUCKETS.to_vec()),
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(kdf_compute_seconds.clone()))
            .expect("metric registration succeeds on a fresh registry");

        let kdf_shed_total = Counter::new(
            "hearth_kdf_shed_total",
            "Total Argon2id operations shed (503/Retry-After) due to a full KDF queue",
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(kdf_shed_total.clone()))
            .expect("metric registration succeeds on a fresh registry");

        let kdf_admin_shed_total = Counter::new(
            "hearth_kdf_admin_shed_total",
            "Total Argon2id operations shed (503/Retry-After) on the admin-reserved KDF pool",
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(kdf_admin_shed_total.clone()))
            .expect("metric registration succeeds on a fresh registry");

        let control_epoch_bump_failures_total = Counter::new(
            "hearth_control_epoch_bump_failures_total",
            "Control-epoch bumps that could not be persisted (other nodes miss the control \
             until the next successful bump)",
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(control_epoch_bump_failures_total.clone()))
            .expect("metric registration succeeds on a fresh registry");

        let control_epoch_bumps_owed = Gauge::new(
            "hearth_control_epoch_bumps_owed",
            "Controls whose control-epoch bump failed and is being retried; other nodes do \
             not enforce them until it succeeds",
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(control_epoch_bumps_owed.clone()))
            .expect("metric registration succeeds on a fresh registry");

        let cluster_forwarded_writes_total = CounterVec::new(
            Opts::new(
                "hearth_cluster_forwarded_writes_total",
                "Writes a cluster follower forwarded to the Raft leader, by outcome",
            ),
            &["outcome"],
        )
        .expect("metric descriptor is valid");
        registry
            .register(Box::new(cluster_forwarded_writes_total.clone()))
            .expect("metric registration succeeds on a fresh registry");
        for label in ForwardedWriteOutcomeLabel::ALL {
            let _ = cluster_forwarded_writes_total.with_label_values(&[label.as_str()]);
        }

        Self {
            registry,
            http_request_duration_seconds,
            auth_attempts_total,
            tokens_issued_total,
            active_sessions,
            storage_operation_duration_seconds,
            audit_integrity_failures_total,
            agent_delegation_total,
            agent_approval_total,
            agent_aat_issued_total,
            agent_aat_revoked_total,
            agent_txn_token_total,
            rate_limiters_disabled,
            wal_write_fenced,
            storage_get_total,
            storage_get_hot_hit,
            storage_get_duration_seconds,
            storage_get_ssts_probed,
            storage_hot_tier_evictions_total,
            storage_hot_tier_promotions_total,
            storage_hot_tier_evictions_by_realm_total,
            storage_hot_tier_promotions_by_realm_total,
            storage_hot_tier_stale_fills_discarded_total,
            storage_sst_files,
            storage_memtable_entries,
            storage_memtable_bytes,
            memtable_entries_by_state,
            memtable_bytes_by_state,
            storage_hot_tier_entries,
            kdf_in_flight,
            kdf_admin_in_flight,
            kdf_permits,
            kdf_admin_permits,
            kdf_queue_wait_seconds,
            kdf_compute_seconds,
            kdf_shed_total,
            kdf_admin_shed_total,
            control_epoch_bump_failures_total,
            control_epoch_bumps_owed,
            cluster_forwarded_writes_total,
        }
    }

    /// Counts one forwarded write's outcome
    /// (`hearth_cluster_forwarded_writes_total{outcome}`).
    pub fn record_forwarded_write(&self, outcome: ForwardedWriteOutcomeLabel) {
        self.cluster_forwarded_writes_total
            .with_label_values(&[outcome.as_str()])
            .inc();
    }

    /// The current count for one outcome (tests, diagnostics).
    #[must_use]
    pub fn forwarded_writes(&self, outcome: ForwardedWriteOutcomeLabel) -> u64 {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let n = self
            .cluster_forwarded_writes_total
            .with_label_values(&[outcome.as_str()])
            .get() as u64;
        n
    }

    /// Records a hot-tier `get` hit — a single lock-free atomic increment.
    ///
    /// This is the only metric touched on the storage hot path. It uses a
    /// pre-resolved child counter (no `CounterVec` label-map lock, no heap
    /// allocation, no syscall), so it honours all four hot-path rules and does
    /// not regress `bench-gate`.
    #[inline]
    pub fn inc_get_hot_hit(&self) {
        self.storage_get_hot_hit.inc();
    }

    /// Adds `entries` and `bytes` (either may be negative) to the memtable
    /// size gauges for `state`.
    ///
    /// Off the hot path: the memtable calls it under its write lock, after a
    /// write, flush or clear has changed its size. Each gauge is a lock-free
    /// atomic add on a pre-resolved child.
    pub fn adjust_memtable_size(&self, state: MemtableStateLabel, entries: f64, bytes: f64) {
        let i = state.index();
        if entries != 0.0 {
            self.memtable_entries_by_state[i].add(entries);
        }
        if bytes != 0.0 {
            self.memtable_bytes_by_state[i].add(bytes);
        }
    }

    /// The current `hearth_storage_memtable_entries{state}` value (tests,
    /// diagnostics).
    #[must_use]
    pub fn memtable_entries(&self, state: MemtableStateLabel) -> f64 {
        self.memtable_entries_by_state[state.index()].get()
    }

    /// The current `hearth_storage_memtable_bytes{state}` value (tests,
    /// diagnostics).
    #[must_use]
    pub fn memtable_bytes(&self, state: MemtableStateLabel) -> f64 {
        self.memtable_bytes_by_state[state.index()].get()
    }

    /// Records a tier fall-through `get` outcome (off the hot path).
    ///
    /// Increments the `outcome` counter, observes the elapsed latency under that
    /// outcome, and records how many SST files were probed. `outcome` must be
    /// one of `memtable_hit`, `sst_hit`, or `miss`.
    pub fn record_get_fallthrough(
        &self,
        outcome: &str,
        elapsed: std::time::Duration,
        ssts_probed: u64,
    ) {
        self.storage_get_total.with_label_values(&[outcome]).inc();
        self.storage_get_duration_seconds
            .with_label_values(&[outcome])
            .observe(elapsed.as_secs_f64());
        #[allow(clippy::cast_precision_loss)]
        self.storage_get_ssts_probed.observe(ssts_probed as f64);
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

    /// Marks the `hearth_wal_write_fenced{reason=…}` gauge as active (`1`).
    ///
    /// Called by the WAL when a write fault fences it. Before the first call
    /// the time series is absent from scrapes, so `reason` only ever appears
    /// when the node is genuinely refusing writes.
    pub fn mark_wal_write_fenced(&self, reason: &str) {
        self.wal_write_fenced.with_label_values(&[reason]).set(1.0);
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

/// Process-global [`Metrics`] singleton backing storage.
static INSTANCE: OnceLock<Metrics> = OnceLock::new();

/// Returns the process-global [`Metrics`] singleton, initialising it on first call.
///
/// Uses [`OnceLock`] (not `lazy_static!`) per the project policy.
pub fn metrics() -> &'static Metrics {
    INSTANCE.get_or_init(Metrics::new)
}

#[cfg(test)]
mod tests {
    use super::{ForwardedWriteOutcomeLabel, MemtableStateLabel, Metrics};

    /// Every forwarded-write outcome is scraped from the start (at 0), and
    /// recording one moves only its own series.
    #[test]
    fn forwarded_write_outcomes_are_a_closed_pre_created_set() {
        let metrics = Metrics::new();
        let rendered = metrics.render();
        for label in ForwardedWriteOutcomeLabel::ALL {
            let series = format!(
                "hearth_cluster_forwarded_writes_total{{outcome=\"{}\"}} 0",
                label.as_str()
            );
            assert!(
                rendered.contains(&series),
                "missing {series} in:\n{rendered}"
            );
        }
        metrics.record_forwarded_write(ForwardedWriteOutcomeLabel::OutcomeUnknown);
        metrics.record_forwarded_write(ForwardedWriteOutcomeLabel::OutcomeUnknown);
        assert_eq!(
            metrics.forwarded_writes(ForwardedWriteOutcomeLabel::OutcomeUnknown),
            2
        );
        assert_eq!(
            metrics.forwarded_writes(ForwardedWriteOutcomeLabel::Committed),
            0
        );
    }

    /// #450: the storage size gauges are scraped from the start (at 0), and
    /// adjusting one memtable state moves only that state's series.
    #[test]
    fn storage_size_gauges_are_pre_created_and_move_per_state() {
        let metrics = Metrics::new();
        let rendered = metrics.render();
        for state in MemtableStateLabel::ALL {
            for family in [
                "hearth_storage_memtable_entries",
                "hearth_storage_memtable_bytes",
            ] {
                let series = format!("{family}{{state=\"{}\"}} 0", state.as_str());
                assert!(
                    rendered.contains(&series),
                    "missing {series} in:\n{rendered}"
                );
            }
        }
        assert!(
            rendered.contains("\nhearth_storage_hot_tier_entries 0"),
            "missing hearth_storage_hot_tier_entries in:\n{rendered}"
        );

        metrics.adjust_memtable_size(MemtableStateLabel::Flushing, 3.0, 120.0);
        metrics.adjust_memtable_size(MemtableStateLabel::Flushing, -1.0, -40.0);
        assert_eq!(
            (
                metrics.memtable_entries(MemtableStateLabel::Flushing),
                metrics.memtable_bytes(MemtableStateLabel::Flushing),
            ),
            (2.0, 80.0)
        );
        assert_eq!(
            (
                metrics.memtable_entries(MemtableStateLabel::Active),
                metrics.memtable_bytes(MemtableStateLabel::Active),
            ),
            (0.0, 0.0)
        );
    }

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
