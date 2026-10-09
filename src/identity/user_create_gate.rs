//! Admission limit for user creation (#446).
//!
//! # Why this exists
//!
//! Creating a user hashes no password, so it does not take a KDF permit
//! ([`super::kdf_gate`], #439). It still runs on Tokio's blocking pool, which
//! it shares with every Argon2id hash (logins) and with blocking storage
//! writes. Without a bound of its own, a large provisioning job or a SCIM sync
//! puts every create it sends into that pool at once: under overload the
//! creates queue for blocking threads instead of failing fast, and sign-in
//! slows for everyone (2026-10-08: mean create latency 567 ms, 10 s client
//! timeouts, no `503`).
//!
//! # What it does
//!
//! [`UserCreateGate::admit`] takes an **async** semaphore permit, waiting at
//! most `max_queue_wait`. A waiting create holds no blocking-pool thread. When
//! no permit frees in time, the create is **shed**
//! ([`UserCreateGateError::Overloaded`]) and the caller answers `503` with
//! `Retry-After`. [`UserCreateGate::run`] admits, then runs the create on the
//! blocking pool with the permit held until the closure returns.
//!
//! # Default bound
//!
//! The bound is a queue depth, not a core count: a create spends most of its
//! time waiting for an fsync, not on a CPU. It caps how many creates may sit in
//! the blocking pool at once. [`DEFAULT_USER_CREATE_MAX_IN_FLIGHT`] (64) keeps
//! creates to an eighth of Tokio's 512 blocking threads. By Little's law 64
//! permits sustain 600 creates/s (the rate measured on a 2-vCPU host) until a
//! create takes 107 ms, nine times the measured p99 (11.7 ms at 800/s).

use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;

/// Default permit count for the user-create gate when
/// `operational.user_create.max_in_flight` is unset. See the module docs.
pub const DEFAULT_USER_CREATE_MAX_IN_FLIGHT: usize = 64;

/// Default queue wait (milliseconds) for the user-create gate when
/// `operational.user_create.max_queue_wait_ms` is unset. The same budget as
/// the shared KDF gate: a healthy create waits about one create latency
/// (milliseconds) for a permit, so only real overload reaches it.
pub const DEFAULT_USER_CREATE_MAX_QUEUE_WAIT_MS: u64 = 250;

/// Configuration for the [`UserCreateGate`].
///
/// Resolved from `operational.user_create.*` at boot (see `main.rs`). Held as
/// plain primitives so the identity layer does not depend on the config crate.
#[derive(Debug, Clone, Copy)]
pub struct UserCreateGateConfig {
    /// Maximum concurrent user creates (semaphore permits). MUST be `>= 1`;
    /// config validation rejects `0`, and the gate clamps it defensively.
    pub max_in_flight: usize,
    /// Maximum time a create waits for a permit before it is shed.
    pub max_queue_wait: Duration,
    /// `Retry-After` hint advertised to shed callers.
    pub retry_after: Duration,
}

impl Default for UserCreateGateConfig {
    fn default() -> Self {
        Self {
            max_in_flight: DEFAULT_USER_CREATE_MAX_IN_FLIGHT,
            max_queue_wait: Duration::from_millis(DEFAULT_USER_CREATE_MAX_QUEUE_WAIT_MS),
            retry_after: Duration::from_secs(1),
        }
    }
}

/// Failure modes of [`UserCreateGate::admit`] and [`UserCreateGate::run`].
#[derive(Debug)]
#[non_exhaustive]
pub enum UserCreateGateError {
    /// No permit became free within `max_queue_wait`. The caller SHOULD answer
    /// `503` with the carried `Retry-After` hint; the create did not run.
    Overloaded {
        /// Suggested `Retry-After` duration for the client.
        retry_after: Duration,
    },
    /// The blocking create task panicked or was cancelled.
    Join(tokio::task::JoinError),
}

impl std::fmt::Display for UserCreateGateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Overloaded { .. } => f.write_str("user-create admission limit full — shed"),
            Self::Join(e) => write!(f, "user-create blocking task failed: {e}"),
        }
    }
}

impl std::error::Error for UserCreateGateError {}

/// Bounded admission gate for user creation. There is one process-global
/// instance ([`user_create_gate`]).
pub struct UserCreateGate {
    semaphore: Arc<Semaphore>,
    max_queue_wait: Duration,
    retry_after: Duration,
    permits: usize,
}

impl UserCreateGate {
    /// Builds a gate from resolved configuration and publishes the permit
    /// count to `hearth_user_create_permits`. A `max_in_flight` of `0` is
    /// clamped to `1`: a gate that never admits would refuse every create.
    #[must_use]
    pub fn new(config: UserCreateGateConfig) -> Self {
        let permits = config.max_in_flight.max(1);
        #[allow(clippy::cast_precision_loss)]
        crate::metrics::metrics()
            .user_create_permits
            .set(permits as f64);
        Self {
            semaphore: Arc::new(Semaphore::new(permits)),
            max_queue_wait: config.max_queue_wait,
            retry_after: config.retry_after,
            permits,
        }
    }

    /// The configured permit ceiling.
    #[must_use]
    pub fn permits(&self) -> usize {
        self.permits
    }

    /// Permits currently available.
    #[must_use]
    pub fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }

    /// Waits at most `max_queue_wait` for a permit. The wait is async: the
    /// caller holds no blocking-pool thread while it waits. The permit is
    /// released when the returned [`UserCreatePermit`] drops, so a caller that
    /// runs its create elsewhere (inside a KDF-gated closure, for example)
    /// moves the permit there.
    ///
    /// # Errors
    ///
    /// [`UserCreateGateError::Overloaded`] when no permit frees in time.
    pub async fn admit(&self) -> Result<UserCreatePermit, UserCreateGateError> {
        let wait_start = Instant::now();
        let permit = match tokio::time::timeout(
            self.max_queue_wait,
            Arc::clone(&self.semaphore).acquire_owned(),
        )
        .await
        {
            Ok(Ok(permit)) => permit,
            // A closed semaphore (never closed today) sheds like a timeout.
            Ok(Err(_)) | Err(_) => return Err(self.shed()),
        };
        let metrics = crate::metrics::metrics();
        metrics
            .user_create_queue_wait_seconds
            .observe(wait_start.elapsed().as_secs_f64());
        metrics.user_create_in_flight.inc();
        Ok(UserCreatePermit { _permit: permit })
    }

    /// Admits one create, then runs `f` on the blocking pool with the permit
    /// held until `f` returns (or panics, or the caller is dropped mid-run).
    ///
    /// # Errors
    ///
    /// - [`UserCreateGateError::Overloaded`] when no permit frees within
    ///   `max_queue_wait` (`f` did not run).
    /// - [`UserCreateGateError::Join`] when the blocking task panics or is
    ///   cancelled.
    pub async fn run<F, T>(&self, f: F) -> Result<T, UserCreateGateError>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let permit = self.admit().await?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            f()
        })
        .await
        .map_err(UserCreateGateError::Join)
    }

    /// Counts a shed and builds the error.
    fn shed(&self) -> UserCreateGateError {
        crate::metrics::metrics().user_create_shed_total.inc();
        UserCreateGateError::Overloaded {
            retry_after: self.retry_after,
        }
    }
}

/// One admitted user create. Holds its permit and counts itself in
/// `hearth_user_create_in_flight` until dropped.
pub struct UserCreatePermit {
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl Drop for UserCreatePermit {
    fn drop(&mut self) {
        crate::metrics::metrics().user_create_in_flight.dec();
    }
}

/// Process-global gate singleton.
static GATE: OnceLock<UserCreateGate> = OnceLock::new();

/// Installs the process-global [`UserCreateGate`] from resolved config. The
/// first call wins; later calls return `false`. Call once at boot, before
/// serving. If never called, [`user_create_gate`] builds a default gate.
pub fn init_user_create_gate(config: UserCreateGateConfig) -> bool {
    GATE.set(UserCreateGate::new(config)).is_ok()
}

/// Returns the process-global [`UserCreateGate`], building one from
/// [`UserCreateGateConfig::default`] if [`init_user_create_gate`] never ran.
pub fn user_create_gate() -> &'static UserCreateGate {
    GATE.get_or_init(|| UserCreateGate::new(UserCreateGateConfig::default()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate(max_in_flight: usize, wait_ms: u64, retry_secs: u64) -> Arc<UserCreateGate> {
        Arc::new(UserCreateGate::new(UserCreateGateConfig {
            max_in_flight,
            max_queue_wait: Duration::from_millis(wait_ms),
            retry_after: Duration::from_secs(retry_secs),
        }))
    }

    /// With every permit held, the next create is shed with the configured
    /// `Retry-After` once the queue wait passes — not served late, and not
    /// queued without bound.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_full_gate_sheds_the_next_create_within_the_queue_wait() {
        let gate = gate(1, 50, 3);
        let held = gate.admit().await.expect("the first create is admitted");

        let start = Instant::now();
        let outcome = gate.run(|| 7_u32).await;
        let elapsed = start.elapsed();

        assert!(
            matches!(
                outcome,
                Err(UserCreateGateError::Overloaded { retry_after })
                    if retry_after == Duration::from_secs(3)
            ),
            "a create past the limit must be shed with Retry-After, got {outcome:?}"
        );
        assert!(
            elapsed >= Duration::from_millis(50),
            "the create waited the queue wait before it was shed, took {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "the shed is bounded by the queue wait, took {elapsed:?}"
        );
        drop(held);
    }

    /// A create that waits for a permit is admitted as soon as one frees
    /// inside the queue wait.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_permit_freed_inside_the_queue_wait_admits_the_waiter() {
        let gate = gate(1, 2_000, 1);
        let held = gate.admit().await.expect("the first create is admitted");
        let releaser = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            drop(held);
        });

        assert_eq!(gate.run(|| 7_u32).await.expect("admitted"), 7);
        releaser.await.expect("releaser joins");
    }

    /// `run` releases its permit when the closure returns and when it panics.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_releases_its_permit_on_return_and_on_panic() {
        let gate = gate(1, 50, 1);
        assert_eq!(gate.run(|| 1_u32).await.expect("admitted"), 1);
        assert_eq!(gate.available_permits(), 1);

        let outcome = gate.run(|| -> u32 { panic!("create failed") }).await;
        assert!(matches!(outcome, Err(UserCreateGateError::Join(_))));
        assert_eq!(
            gate.available_permits(),
            1,
            "a panic must not leak the permit"
        );
    }

    /// A configured `0` is clamped: the gate always admits something.
    #[test]
    fn zero_permits_clamp_to_one() {
        assert_eq!(gate(0, 50, 1).permits(), 1);
    }

    /// The default is a queue depth well above the creates a 2-vCPU host
    /// keeps in flight at 600/s, independent of the core count.
    #[test]
    fn the_default_bound_does_not_depend_on_the_core_count() {
        let config = UserCreateGateConfig::default();
        assert_eq!(config.max_in_flight, DEFAULT_USER_CREATE_MAX_IN_FLIGHT);
        assert_eq!(
            config.max_queue_wait,
            Duration::from_millis(DEFAULT_USER_CREATE_MAX_QUEUE_WAIT_MS)
        );
    }
}
