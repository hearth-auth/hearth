//! Bounded admission control for the Argon2id KDF path (HEA-1887 / R1).
//!
//! # Why this exists
//!
//! Password hashing runs on Tokio's default 512-thread blocking pool. With no
//! bound, offered concurrency translates 1:1 into oversubscription of a
//! machine's handful of cores — and, because each OWASP-parameter Argon2id op
//! allocates ~19 MiB, into memory/swap pressure. C9/HEA-1879 confirmed that the
//! ~7 s token-issuance p99 in the baseline was **queueing under this
//! oversubscription, not Argon2id compute** (`throughput_scaling_past_cores =
//! 1.02×` while `latency_growth_past_cores = 2.50×`). See
//! `docs/perf/HEA-1879-C9-issuance-triage.md`.
//!
//! # What it does
//!
//! [`KdfGate::run`] acquires an **async** semaphore permit *before* it calls
//! [`tokio::task::spawn_blocking`], so a request waiting for capacity holds
//! neither a blocking-pool thread nor a 19 MiB Argon2 allocation. Waits are
//! **bounded**: if no permit frees within `max_queue_wait`, the op is **shed**
//! ([`KdfGateError::Overloaded`]) so the caller can return `503 Retry-After`
//! rather than pile onto an unbounded queue. This converts a multi-second
//! thrash into `compute floor + short bounded queue` and collapses peak
//! resident memory from `offered × 19 MiB` to `permits × 19 MiB`.
//!
//! Every op is instrumented (`hearth_kdf_*`): in-flight gauge, queue-wait and
//! compute-time histograms, and a shed counter — the telemetry whose absence
//! made the C9 tail invisible.
//!
//! # Default bound
//!
//! `max_in_flight` defaults to [`std::thread::available_parallelism`] (the
//! core count). This is the principled Little's-Law starting point: throughput
//! saturates at the core count, so permits beyond it buy no throughput and only
//! add queue latency. The *calibrated production default* is refined by the
//! C7/HEA-1875 saturation sweep.

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;

/// Configuration for the [`KdfGate`].
///
/// Resolved from `security.password.kdf.*` at boot (see `main.rs`). Held as
/// plain primitives so the identity layer does not depend on the config crate.
#[derive(Debug, Clone, Copy)]
pub struct KdfGateConfig {
    /// Maximum concurrent Argon2id operations (semaphore permits).
    ///
    /// Defaults to the core count via [`Self::default`]. MUST be `>= 1`;
    /// callers are responsible for rejecting `0` at config-validation time.
    pub max_in_flight: usize,
    /// Maximum time a request waits for a permit before being shed.
    pub max_queue_wait: Duration,
    /// `Retry-After` hint advertised to shed callers.
    pub retry_after: Duration,
}

impl Default for KdfGateConfig {
    fn default() -> Self {
        let cores = std::thread::available_parallelism()
            .map(std::num::NonZeroUsize::get)
            .unwrap_or(1);
        Self {
            max_in_flight: cores,
            max_queue_wait: Duration::from_millis(250),
            retry_after: Duration::from_secs(1),
        }
    }
}

/// Failure modes of [`KdfGate::run`].
#[derive(Debug)]
#[non_exhaustive]
pub enum KdfGateError {
    /// No permit became free within `max_queue_wait`. The KDF path is
    /// overloaded; the caller SHOULD return `503` with the carried
    /// `Retry-After` hint instead of executing the operation.
    Overloaded {
        /// Suggested `Retry-After` duration for the client.
        retry_after: Duration,
    },
    /// The blocking Argon2id task panicked or was cancelled.
    Join(tokio::task::JoinError),
}

impl std::fmt::Display for KdfGateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Overloaded { .. } => f.write_str("KDF admission gate overloaded — shed"),
            Self::Join(e) => write!(f, "KDF blocking task failed: {e}"),
        }
    }
}

impl std::error::Error for KdfGateError {}

/// Bounded admission gate for Argon2id operations.
///
/// Cheap to clone conceptually via the process-global [`gate`]; typically there
/// is exactly one instance for the whole server.
pub struct KdfGate {
    semaphore: Semaphore,
    max_queue_wait: Duration,
    retry_after: Duration,
    permits: usize,
}

impl KdfGate {
    /// Builds a gate from resolved configuration and publishes the permit count
    /// to the `hearth_kdf_permits` gauge.
    ///
    /// A `max_in_flight` of `0` is clamped to `1` defensively — a gate that can
    /// never admit is a self-inflicted total outage, which is never the intent.
    #[must_use]
    pub fn new(config: KdfGateConfig) -> Self {
        let permits = config.max_in_flight.max(1);
        #[allow(clippy::cast_precision_loss)]
        crate::metrics::metrics().kdf_permits.set(permits as f64);
        Self {
            semaphore: Semaphore::new(permits),
            max_queue_wait: config.max_queue_wait,
            retry_after: config.retry_after,
            permits,
        }
    }

    /// The configured permit ceiling (for tests / introspection).
    #[must_use]
    pub fn permits(&self) -> usize {
        self.permits
    }

    /// Permits currently available (for tests / introspection).
    #[must_use]
    pub fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }

    /// Runs one Argon2id operation under the admission bound.
    ///
    /// Acquires a permit (waiting at most `max_queue_wait`), then executes `f`
    /// on the blocking pool. Records queue-wait, compute-time, in-flight, and —
    /// on timeout — the shed counter.
    ///
    /// # Errors
    ///
    /// - [`KdfGateError::Overloaded`] if no permit frees within `max_queue_wait`
    ///   (the op is **not** executed).
    /// - [`KdfGateError::Join`] if the blocking task panics or is cancelled.
    pub async fn run<F, T>(&self, f: F) -> Result<T, KdfGateError>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let metrics = crate::metrics::metrics();

        // Bounded wait for a permit. Past the budget we shed instead of queueing
        // unboundedly — the crux of R1.
        let wait_start = Instant::now();
        let permit = match tokio::time::timeout(self.max_queue_wait, self.semaphore.acquire()).await
        {
            Ok(Ok(permit)) => permit,
            // Semaphore closed — only happens on shutdown; treat as overload so
            // the caller sheds cleanly rather than panicking mid-auth.
            Ok(Err(_closed)) => {
                metrics.kdf_shed_total.inc();
                return Err(KdfGateError::Overloaded {
                    retry_after: self.retry_after,
                });
            }
            Err(_elapsed) => {
                metrics.kdf_shed_total.inc();
                return Err(KdfGateError::Overloaded {
                    retry_after: self.retry_after,
                });
            }
        };
        metrics
            .kdf_queue_wait_seconds
            .observe(wait_start.elapsed().as_secs_f64());

        // Permit held for the duration of the compute; released on drop after
        // the blocking task joins.
        metrics.kdf_in_flight.inc();
        let compute_start = Instant::now();
        let result = tokio::task::spawn_blocking(f).await;
        metrics
            .kdf_compute_seconds
            .observe(compute_start.elapsed().as_secs_f64());
        metrics.kdf_in_flight.dec();
        drop(permit);

        result.map_err(KdfGateError::Join)
    }
}

/// Process-global gate singleton.
static GATE: OnceLock<KdfGate> = OnceLock::new();

/// Installs the process-global [`KdfGate`] from resolved config. First call
/// wins; subsequent calls are ignored (returns `false`). Call once at boot,
/// before serving.
///
/// If never called (e.g. an embedded test that bypasses server boot), [`gate`]
/// lazily materialises a [`KdfGateConfig::default`] gate so the KDF path is
/// always bounded.
pub fn init_gate(config: KdfGateConfig) -> bool {
    GATE.set(KdfGate::new(config)).is_ok()
}

/// Returns the process-global [`KdfGate`], initialising a default-bounded gate
/// on first use if [`init_gate`] was never called.
pub fn gate() -> &'static KdfGate {
    GATE.get_or_init(|| KdfGate::new(KdfGateConfig::default()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R1 core property: once every permit is held, an offered operation past
    /// the bound is **shed** (fast `Overloaded`) rather than queued unboundedly
    /// (which is what inflated p99 to seconds in C9). We hold both permits of a
    /// 2-permit gate with slow blocking work and a tiny `max_queue_wait`, then
    /// assert the third op sheds promptly.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn offered_concurrency_past_bound_is_shed_not_queued() {
        let gate = std::sync::Arc::new(KdfGate::new(KdfGateConfig {
            max_in_flight: 2,
            max_queue_wait: Duration::from_millis(20),
            retry_after: Duration::from_secs(3),
        }));

        // Saturate both permits with work that outlives the queue-wait budget.
        let mut holders = Vec::new();
        for _ in 0..2 {
            let g = gate.clone();
            holders.push(tokio::spawn(async move {
                g.run(|| std::thread::sleep(Duration::from_millis(300)))
                    .await
            }));
        }
        // Let the holders acquire their permits before we probe.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            gate.available_permits(),
            0,
            "both permits should be held by the saturating ops"
        );

        // The probe cannot get a permit within 20 ms → must shed quickly, well
        // before a permit would free (~250 ms out).
        let probe_start = Instant::now();
        let outcome = gate.run(|| 42_u32).await;
        let elapsed = probe_start.elapsed();

        assert!(
            matches!(outcome, Err(KdfGateError::Overloaded { retry_after }) if retry_after == Duration::from_secs(3)),
            "past-bound op must shed with Overloaded + Retry-After, got {outcome:?}"
        );
        assert!(
            elapsed < Duration::from_millis(150),
            "shed must be fast (bounded by max_queue_wait), took {elapsed:?}"
        );

        // The holders still complete successfully — shedding the excess did not
        // break admitted work.
        for h in holders {
            assert!(h.await.expect("task joins").is_ok());
        }
    }

    /// Under the bound, operations run and return their value; the permit is
    /// released so subsequent ops proceed (no permit leak on the success path).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn admitted_op_runs_and_releases_permit() {
        let gate = KdfGate::new(KdfGateConfig {
            max_in_flight: 1,
            max_queue_wait: Duration::from_millis(500),
            retry_after: Duration::from_secs(1),
        });

        let first = gate.run(|| 7_u32 * 6).await.expect("admitted");
        assert_eq!(first, 42);
        assert_eq!(
            gate.available_permits(),
            1,
            "permit must be returned after the op completes"
        );
        // A second sequential op also succeeds, proving the permit was freed.
        assert_eq!(gate.run(|| 1_u32 + 1).await.expect("admitted"), 2);
    }

    /// A `max_in_flight` of 0 is clamped to 1 rather than producing a gate that
    /// can never admit (which would be a self-inflicted outage).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn zero_permits_is_clamped_to_one() {
        let gate = KdfGate::new(KdfGateConfig {
            max_in_flight: 0,
            max_queue_wait: Duration::from_millis(500),
            retry_after: Duration::from_secs(1),
        });
        assert_eq!(gate.permits(), 1);
        assert_eq!(gate.run(|| 5_u32).await.expect("admitted"), 5);
    }
}
