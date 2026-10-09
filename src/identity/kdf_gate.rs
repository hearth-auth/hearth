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
//! `https://github.com/hearth-auth/hearth/blob/4d9dda1f5b514891e90dadeffb03d1a026af4e51/docs/perf/HEA-1879-C9-issuance-triage.md`.
//!
//! # What it does
//!
//! [`KdfGate::run`] acquires an **async** semaphore permit *before* it calls
//! [`tokio::task::spawn_blocking`], so a request waiting for capacity holds
//! neither a blocking-pool thread nor a 19 MiB Argon2 allocation. Waits are
//! **bounded**: if no permit frees within `max_queue_wait`, the op is **shed**
//! ([`KdfGateError::Overloaded`]) so the caller can return `503 Retry-After`
//! rather than pile onto an unbounded queue. This converts a multi-second
//! thrash into `compute floor + short bounded queue`.
//!
//! # Scope of the memory bound (HEA-1891 / HEA-1889 F3)
//!
//! The `offered × 19 MiB → permits × 19 MiB` collapse only holds if **every**
//! Argon2id caller shares this one process-global gate. The original R1 change
//! (`b851ae1a`) gated only the three login handlers, leaving registration,
//! password-reset confirm, change-password, MFA step-up, and the REST
//! `create_user` paths free to independently oversubscribe the blocking pool —
//! a `/ui/register` flood alone re-introduced the unbounded `offered × 19 MiB`
//! blowup. Peak was really `(permits + concurrent registrations + resets + …)
//! × 19 MiB`. As of HEA-1891 all of those callers route through this gate
//! (`run_kdf_gated` for UI `Response` handlers; engine-side callers such as
//! client authentication map a shed to `IdentityError::KdfOverloaded`), so the
//! `permits × 19 MiB` ceiling is now server-wide. REST `create_user` is not a
//! caller: its request carries no password, and gating it only limited
//! concurrent creates to the permit count (2026-10-08 stress run).
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
//!
//! # Reused Argon2 block buffers (#445)
//!
//! Each gate keeps up to `permits` Argon2 block buffers in a [`BlockPool`]. An
//! admitted closure that runs Argon2 through [`with_argon2_blocks`] checks a
//! buffer out, and gives it back zeroed when the hash ends. A hash at the
//! default cost therefore no longer maps, faults in and frees 19 MiB: in 4 KiB
//! pages that cost 35–40% more CPU per hash once glibc's mmap threshold was
//! fixed at 128 KiB, and before that, glibc's dynamic threshold rose to 19 MiB
//! after the first freed buffer and pulled every mid-size allocation into its
//! arenas. A buffer grows to the largest cost it has served and stays that
//! size, so a gate holds at most `permits × largest memory cost` bytes.

use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use argon2::Block;
use tokio::sync::Semaphore;
use zeroize::Zeroize;

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

/// Which permit pool a [`KdfGate`] instance represents (HEA-1894).
///
/// The shared and admin-reserved gates are distinct semaphores with distinct
/// telemetry: the shared pool writes `hearth_kdf_{in_flight,shed_total}`, the
/// admin pool writes `hearth_kdf_admin_{in_flight,shed_total}`. Without this
/// discriminant both pools wrote the shared counters, making admin sheds
/// invisible and letting `hearth_kdf_in_flight` exceed `hearth_kdf_permits`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pool {
    /// The shared realm-login gate.
    Shared,
    /// The admin-reserved gate (HEA-1892 / F2).
    Admin,
}

/// Bounded admission gate for Argon2id operations.
///
/// Cheap to clone conceptually via the process-global [`gate`]; typically there
/// is exactly one instance for the whole server.
pub struct KdfGate {
    semaphore: std::sync::Arc<Semaphore>,
    max_queue_wait: Duration,
    retry_after: Duration,
    permits: usize,
    pool: Pool,
    /// Argon2 block buffers for the closures this gate admits, at most one
    /// per permit.
    blocks: Arc<BlockPool>,
}

impl KdfGate {
    /// Builds a gate from resolved configuration and publishes the permit count
    /// to the `hearth_kdf_permits` gauge.
    ///
    /// A `max_in_flight` of `0` is clamped to `1` defensively — a gate that can
    /// never admit is a self-inflicted total outage, which is never the intent.
    #[must_use]
    pub fn new(config: KdfGateConfig) -> Self {
        let gate = Self::build(config, Pool::Shared);
        #[allow(clippy::cast_precision_loss)]
        crate::metrics::metrics()
            .kdf_permits
            .set(gate.permits as f64);
        gate
    }

    /// Builds the **admin-reserved** gate (HEA-1892 / F2), publishing its permit
    /// count to `hearth_kdf_admin_permits` instead of `hearth_kdf_permits`.
    ///
    /// Admin login uses this separate pool so a flood against a tenant realm's
    /// login form cannot consume every shared permit and lock the operator out
    /// of the admin console. Same clamp semantics as [`Self::new`].
    #[must_use]
    pub fn new_admin(config: KdfGateConfig) -> Self {
        let gate = Self::build(config, Pool::Admin);
        #[allow(clippy::cast_precision_loss)]
        crate::metrics::metrics()
            .kdf_admin_permits
            .set(gate.permits as f64);
        gate
    }

    /// Shared constructor: clamps permits to `>= 1`, wires the semaphore, and
    /// records the `pool` discriminant so [`Self::run`] routes telemetry to the
    /// right counters. Metric publication is left to the role-specific
    /// [`Self::new`] / [`Self::new_admin`] so the two pools report distinct
    /// gauges.
    fn build(config: KdfGateConfig, pool: Pool) -> Self {
        let permits = config.max_in_flight.max(1);
        Self {
            semaphore: std::sync::Arc::new(Semaphore::new(permits)),
            max_queue_wait: config.max_queue_wait,
            retry_after: config.retry_after,
            permits,
            pool,
            blocks: Arc::new(BlockPool::new(permits)),
        }
    }

    /// The configured permit ceiling (for tests / introspection).
    #[must_use]
    pub fn permits(&self) -> usize {
        self.permits
    }

    /// The Argon2 block buffers this gate keeps for reuse.
    #[cfg_attr(not(test), allow(dead_code))] // introspection for tests
    pub(crate) fn block_pool(&self) -> &BlockPool {
        &self.blocks
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
        // unboundedly — the crux of R1. The wait is ASYNC: a waiter holds no
        // blocking-pool thread and no worker, so any number of waiters can
        // queue without starving the runtime, and the shed timer always runs.
        let wait_start = Instant::now();
        let permit = match tokio::time::timeout(
            self.max_queue_wait,
            std::sync::Arc::clone(&self.semaphore).acquire_owned(),
        )
        .await
        {
            Ok(Ok(permit)) => permit,
            // Semaphore closed — only happens on shutdown; treat as overload so
            // the caller sheds cleanly rather than panicking mid-auth.
            Ok(Err(_)) | Err(_) => return Err(self.shed()),
        };
        metrics
            .kdf_queue_wait_seconds
            .observe(wait_start.elapsed().as_secs_f64());

        // Permit and in-flight gauge are both RAII and live INSIDE the blocking
        // task: they are released when the Argon2id run actually ends — on
        // success, on panic, and when the caller is dropped mid-run (a
        // disconnected client), which must neither leak the gauge nor free the
        // permit while the run still holds its memory.
        let in_flight = InFlight::enter(self, permit);
        let blocks = Arc::clone(&self.blocks);
        let compute_start = Instant::now();
        let result = tokio::task::spawn_blocking(move || {
            let _in_flight = in_flight;
            let _admitted = Admitted::enter(blocks);
            f()
        })
        .await;
        metrics
            .kdf_compute_seconds
            .observe(compute_start.elapsed().as_secs_f64());

        result.map_err(KdfGateError::Join)
    }

    /// Runs `f` on the CALLING thread under a permit taken without waiting.
    ///
    /// For synchronous code that finds it must run Argon2id and has no way to
    /// wait asynchronously (an engine method called directly rather than
    /// through an async entry point that routes it via [`Self::run`]). It
    /// NEVER waits: when no permit is free right now, the op is shed at once.
    /// Waiting here would either block a runtime worker on a permit another
    /// task must be polled to release, or — with `block_in_place` — consume a
    /// blocking-pool thread per waiter, which deadlocks a runtime once the
    /// waiters outnumber the pool. Taking a permit keeps the process-wide
    /// `permits × memory` bound.
    ///
    /// Inside a closure this gate already admitted, `f` runs directly: taking a
    /// second permit while holding one could exhaust the pool.
    ///
    /// # Errors
    ///
    /// [`KdfGateError::Overloaded`] when no permit is free (`f` did not run).
    pub fn try_run_inline<F, T>(&self, f: F) -> Result<T, KdfGateError>
    where
        F: FnOnce() -> T,
    {
        if ADMITTED_BY.with_borrow(Option::is_some) {
            return Ok(f());
        }
        let Ok(permit) = std::sync::Arc::clone(&self.semaphore).try_acquire_owned() else {
            return Err(self.shed());
        };
        crate::metrics::metrics()
            .kdf_queue_wait_seconds
            .observe(0.0);
        let _in_flight = InFlight::enter(self, permit);
        let compute_start = Instant::now();
        let out = {
            let _admitted = Admitted::enter(Arc::clone(&self.blocks));
            f()
        };
        crate::metrics::metrics()
            .kdf_compute_seconds
            .observe(compute_start.elapsed().as_secs_f64());
        Ok(out)
    }

    /// Counts a shed on this gate's pool and builds the error.
    fn shed(&self) -> KdfGateError {
        let metrics = crate::metrics::metrics();
        match self.pool {
            Pool::Shared => metrics.kdf_shed_total.inc(),
            Pool::Admin => metrics.kdf_admin_shed_total.inc(),
        }
        KdfGateError::Overloaded {
            retry_after: self.retry_after,
        }
    }

    /// This gate's in-flight gauge. Routed per pool so admin sheds are
    /// alertable and each `*_in_flight` gauge stays bounded by its own permit
    /// ceiling (HEA-1894).
    fn in_flight_gauge(&self) -> &'static prometheus::Gauge {
        let metrics = crate::metrics::metrics();
        match self.pool {
            Pool::Shared => &metrics.kdf_in_flight,
            Pool::Admin => &metrics.kdf_admin_in_flight,
        }
    }
}

/// One admitted op: holds its permit and counts itself in the pool's
/// in-flight gauge until dropped — on success, panic, or cancellation alike.
struct InFlight {
    gauge: &'static prometheus::Gauge,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl InFlight {
    fn enter(gate: &KdfGate, permit: tokio::sync::OwnedSemaphorePermit) -> Self {
        let gauge = gate.in_flight_gauge();
        gauge.inc();
        Self {
            gauge,
            _permit: permit,
        }
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.gauge.dec();
    }
}

thread_local! {
    /// While this thread runs a closure a [`KdfGate`] admitted: that gate's
    /// block buffers. `None` outside any admitted closure.
    static ADMITTED_BY: RefCell<Option<Arc<BlockPool>>> = const { RefCell::new(None) };
}

/// Marks the current thread as running a closure admitted by the gate that
/// owns `blocks`, until dropped.
struct Admitted(Option<Arc<BlockPool>>);

impl Admitted {
    fn enter(blocks: Arc<BlockPool>) -> Self {
        Self(ADMITTED_BY.replace(Some(blocks)))
    }
}

impl Drop for Admitted {
    fn drop(&mut self) {
        ADMITTED_BY.set(self.0.take());
    }
}

/// Argon2 block buffers one [`KdfGate`] keeps for reuse (#445).
///
/// Holds at most `capacity` (the gate's permit count) buffers, every one of
/// them all zeros. Off the hot path: a `Mutex` guards the list, held only to
/// pop or push one buffer and never across an `.await`.
pub(crate) struct BlockPool {
    buffers: Mutex<Vec<Vec<Block>>>,
    capacity: usize,
    /// Buffers this pool had to allocate because none it held was large
    /// enough (or it held none).
    fresh_allocations: AtomicU64,
}

impl BlockPool {
    /// An empty pool that keeps at most `capacity` buffers.
    fn new(capacity: usize) -> Self {
        Self {
            buffers: Mutex::new(Vec::new()),
            capacity,
            fresh_allocations: AtomicU64::new(0),
        }
    }

    /// The most buffers this pool keeps: its gate's permit count.
    #[cfg_attr(not(test), allow(dead_code))] // introspection for tests
    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }

    /// Buffers held right now (not checked out).
    #[cfg_attr(not(test), allow(dead_code))] // introspection for tests
    pub(crate) fn pooled(&self) -> usize {
        self.lock().len()
    }

    /// Bytes held right now in buffers that are not checked out.
    #[cfg_attr(not(test), allow(dead_code))] // introspection for tests
    pub(crate) fn pooled_bytes(&self) -> usize {
        self.lock().iter().map(|b| b.len() * Block::SIZE).sum()
    }

    /// Buffers this pool has allocated since it was built.
    #[cfg_attr(not(test), allow(dead_code))] // introspection for tests
    pub(crate) fn fresh_allocations(&self) -> u64 {
        self.fresh_allocations.load(Ordering::Relaxed)
    }

    /// The buffer list. A panic while it was held cannot leave it
    /// inconsistent (every operation is one push or pop), so a poisoned lock
    /// is taken as is.
    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Vec<Block>>> {
        self.buffers.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A zeroed buffer of at least `blocks` blocks: a pooled one that is large
    /// enough, or else a fresh one.
    ///
    /// When every pooled buffer is too small, one of them is dropped: the
    /// fresh, larger buffer takes its place when it comes back, so the pool
    /// keeps the larger size instead of holding both.
    fn take(&self, blocks: usize) -> Vec<Block> {
        let (fits, outgrown) = {
            let mut buffers = self.lock();
            match buffers.iter().position(|b| b.len() >= blocks) {
                Some(i) => (Some(buffers.swap_remove(i)), None),
                None => (None, buffers.pop()),
            }
        };
        // Freed outside the lock: unmapping a large buffer is a syscall.
        drop(outgrown);
        if let Some(buffer) = fits {
            return buffer;
        }
        self.fresh_allocations.fetch_add(1, Ordering::Relaxed);
        vec![Block::new(); blocks]
    }

    /// Takes back a zeroed buffer, or drops it when the pool already holds
    /// `capacity` buffers (more than `capacity` can be out at once only when
    /// an admitted closure runs Argon2 inside another Argon2 run).
    fn give_back(&self, buffer: Vec<Block>) {
        if buffer.is_empty() {
            return;
        }
        let rejected = {
            let mut buffers = self.lock();
            if buffers.len() < self.capacity {
                buffers.push(buffer);
                None
            } else {
                Some(buffer)
            }
        };
        drop(rejected);
    }
}

/// A buffer checked out for one Argon2 run. Dropping it zeroes the blocks the
/// run used and gives the buffer back to its pool, on success and on panic.
struct BlockLease {
    blocks: Vec<Block>,
    used: usize,
    pool: Option<Arc<BlockPool>>,
}

impl Drop for BlockLease {
    fn drop(&mut self) {
        for block in self.blocks.iter_mut().take(self.used) {
            block.as_mut().zeroize();
        }
        if let Some(pool) = self.pool.take() {
            pool.give_back(std::mem::take(&mut self.blocks));
        }
    }
}

/// Runs `f` with an Argon2 block buffer of exactly `blocks` blocks
/// (`Params::block_count`), all zeros on entry.
///
/// Inside a closure a [`KdfGate`] admitted, the buffer comes from that gate's
/// [`BlockPool`] and goes back to it when `f` returns: a hash at an unchanged
/// cost allocates nothing. Elsewhere (start-up, tests, a caller outside the
/// gate) the buffer is allocated for this call and freed after it. Either
/// way the blocks are zeroed when `f` returns, so the memory-hard state of a
/// password hash does not outlive it.
pub(crate) fn with_argon2_blocks<R>(blocks: usize, f: impl FnOnce(&mut [Block]) -> R) -> R {
    let pool = ADMITTED_BY.with_borrow(Option::clone);
    let buffer = match &pool {
        Some(pool) => pool.take(blocks),
        None => vec![Block::new(); blocks],
    };
    let mut lease = BlockLease {
        blocks: buffer,
        used: blocks,
        pool,
    };
    f(&mut lease.blocks[..blocks])
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

/// Default permit count for the admin-reserved gate (HEA-1892 / F2) when
/// `security.password.kdf.admin_max_in_flight` is unset.
///
/// Deliberately small and fixed: admin login is inherently low-volume, and a
/// tiny reserved pool is all that's needed to keep the operator console
/// reachable while the shared gate sheds a realm-login flood.
pub const DEFAULT_ADMIN_MAX_IN_FLIGHT: usize = 2;

/// Default queue-wait (milliseconds) for the admin-reserved gate (HEA-1895)
/// when `security.password.kdf.admin_max_queue_wait_ms` is unset.
///
/// Deliberately far longer than the shared gate's 250 ms shed threshold: admin
/// login is the one auth surface where **queueing beats shedding**. Its latency
/// budget is seconds, not milliseconds, and its volume is inherently low, so a
/// distributed flood that occupies the tiny [`DEFAULT_ADMIN_MAX_IN_FLIGHT`]-permit
/// pool can no longer hold the console in steady-state `503` — genuine operator
/// logins queue for a slot instead. The pool is only a couple of permits, so a
/// longer wait cannot grow the queue's memory footprint unboundedly.
pub const DEFAULT_ADMIN_MAX_QUEUE_WAIT_MS: u64 = 2_500;

/// Builds the default admin gate config: [`DEFAULT_ADMIN_MAX_IN_FLIGHT`] permits
/// with the longer [`DEFAULT_ADMIN_MAX_QUEUE_WAIT_MS`] queue-wait (prefer
/// queueing over shedding on admin login), sharing the retry-after hint.
fn admin_default_config() -> KdfGateConfig {
    KdfGateConfig {
        max_in_flight: DEFAULT_ADMIN_MAX_IN_FLIGHT,
        max_queue_wait: Duration::from_millis(DEFAULT_ADMIN_MAX_QUEUE_WAIT_MS),
        ..KdfGateConfig::default()
    }
}

/// Process-global admin-reserved gate singleton (HEA-1892 / F2).
static ADMIN_GATE: OnceLock<KdfGate> = OnceLock::new();

/// Installs the process-global admin [`KdfGate`] from resolved config. First
/// call wins; subsequent calls are ignored (returns `false`). Call once at boot,
/// alongside [`init_gate`].
///
/// If never called, [`admin_gate`] lazily materialises a small default pool so
/// admin login is always isolated from the shared realm-login gate.
pub fn init_admin_gate(config: KdfGateConfig) -> bool {
    ADMIN_GATE.set(KdfGate::new_admin(config)).is_ok()
}

/// Returns the process-global admin-reserved [`KdfGate`], initialising a small
/// default-bounded pool on first use if [`init_admin_gate`] was never called.
///
/// This is a **separate** semaphore from [`gate`]: exhausting one never starves
/// the other, so a tenant-realm login flood cannot lock out the admin console.
pub fn admin_gate() -> &'static KdfGate {
    ADMIN_GATE.get_or_init(|| KdfGate::new_admin(admin_default_config()))
}

/// The gate a credential check for an account in `realm_id` runs on: the
/// admin-reserved [`admin_gate`] for the system realm (operators), the shared
/// [`gate`] for every tenant realm. One choice for every surface an operator
/// proves a credential on (console login, step-ups, account page), so a
/// tenant-login flood cannot shed any of them (HEA-1892 / F2; GA sweep 4).
pub fn gate_for_realm(realm_id: &crate::core::RealmId) -> &'static KdfGate {
    if realm_id.as_uuid().is_nil() {
        admin_gate()
    } else {
        gate()
    }
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
        // 250 ms is still before either permit can free (~300 ms), so the
        // bound proves the probe was shed, not served late, with headroom for
        // a loaded CI runner.
        assert!(
            elapsed < Duration::from_millis(250),
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

    /// The synchronous path never waits: with the only permit held it sheds
    /// at once, and the op does not run.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn try_run_inline_sheds_at_once_when_no_permit_is_free() {
        let gate = std::sync::Arc::new(KdfGate::new(KdfGateConfig {
            max_in_flight: 1,
            max_queue_wait: Duration::from_secs(30),
            retry_after: Duration::from_secs(4),
        }));
        let (held_tx, held_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let holder = {
            let g = gate.clone();
            tokio::spawn(async move {
                g.run(move || {
                    let _ = held_tx.send(());
                    let _ = release_rx.recv_timeout(Duration::from_secs(30));
                })
                .await
            })
        };
        held_rx.await.expect("holder admitted");

        let started = Instant::now();
        let mut ran = false;
        let outcome = gate.try_run_inline(|| ran = true);
        assert!(
            matches!(outcome, Err(KdfGateError::Overloaded { retry_after }) if retry_after == Duration::from_secs(4)),
            "no free permit must shed, got {outcome:?}"
        );
        assert!(!ran, "a shed op must not run");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "the synchronous path must not wait out the 30 s queue budget"
        );

        release_tx.send(()).expect("release");
        assert!(holder.await.expect("joins").is_ok());
        assert_eq!(gate.try_run_inline(|| 9_u8).expect("admitted"), 9);
        assert_eq!(gate.available_permits(), 1, "the inline permit is returned");
    }

    /// A panicking inline op releases its permit and its in-flight count.
    /// (The first synchronous path decremented the gauge only after `f`
    /// returned, so a panic leaked it for the life of the process.)
    #[test]
    #[allow(clippy::float_cmp)]
    fn a_panicking_inline_op_releases_its_permit_and_gauge() {
        let gate = KdfGate::new_admin(KdfGateConfig {
            max_in_flight: 1,
            max_queue_wait: Duration::from_millis(10),
            retry_after: Duration::from_secs(1),
        });
        let before = crate::metrics::metrics().kdf_admin_in_flight.get();
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = gate.try_run_inline(|| panic!("argon2 blew up"));
        }));
        assert!(panicked.is_err(), "the op's panic propagates");
        assert_eq!(gate.available_permits(), 1, "permit returned after a panic");
        assert_eq!(
            crate::metrics::metrics().kdf_admin_in_flight.get(),
            before,
            "in-flight gauge restored after a panic"
        );
    }

    /// A caller dropped mid-run (a disconnected client) keeps its permit until
    /// the blocking op really ends, then releases permit and gauge.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::float_cmp)]
    async fn a_cancelled_run_holds_its_permit_until_the_op_ends() {
        let gate = std::sync::Arc::new(KdfGate::new_admin(KdfGateConfig {
            max_in_flight: 1,
            max_queue_wait: Duration::from_millis(10),
            retry_after: Duration::from_secs(1),
        }));
        let before = crate::metrics::metrics().kdf_admin_in_flight.get();
        let (held_tx, held_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let caller = {
            let g = gate.clone();
            tokio::spawn(async move {
                g.run(move || {
                    let _ = held_tx.send(());
                    let _ = release_rx.recv_timeout(Duration::from_secs(30));
                    let _ = done_tx.send(());
                })
                .await
            })
        };
        held_rx.await.expect("admitted");
        caller.abort();
        let _ = caller.await;
        assert_eq!(
            gate.available_permits(),
            0,
            "the op still runs, so its permit is still held"
        );
        release_tx.send(()).expect("release");
        done_rx.await.expect("op finished");
        // The guard drops right after the closure returns on the blocking
        // thread; wait for that deterministically via the permit.
        let permit = tokio::time::timeout(Duration::from_secs(5), gate.semaphore.acquire())
            .await
            .expect("permit released once the op ended")
            .expect("open");
        drop(permit);
        assert_eq!(
            crate::metrics::metrics().kdf_admin_in_flight.get(),
            before,
            "in-flight gauge restored after a cancelled caller"
        );
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

    /// F2 isolation property: the admin-reserved gate is a **separate**
    /// semaphore. Saturating a realm gate to zero available permits must leave
    /// an independent admin gate fully able to admit — one realm's login flood
    /// cannot lock out the admin console.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn admin_gate_is_isolated_from_saturated_shared_gate() {
        let shared = std::sync::Arc::new(KdfGate::new(KdfGateConfig {
            max_in_flight: 1,
            max_queue_wait: Duration::from_millis(20),
            retry_after: Duration::from_secs(1),
        }));
        let admin = KdfGate::new_admin(KdfGateConfig {
            max_in_flight: 2,
            max_queue_wait: Duration::from_millis(20),
            retry_after: Duration::from_secs(1),
        });

        // Peg the shared gate: hold its only permit, then confirm a second
        // shared op sheds (the flood).
        let holder = {
            let g = shared.clone();
            tokio::spawn(async move {
                g.run(|| std::thread::sleep(Duration::from_millis(300)))
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            shared.available_permits(),
            0,
            "shared gate should be fully saturated"
        );
        assert!(
            matches!(
                shared.run(|| 0_u32).await,
                Err(KdfGateError::Overloaded { .. })
            ),
            "a second shared-gate op must shed while the flood holds the permit"
        );

        // The admin gate, though sharing no permits with `shared`, still admits
        // immediately — the operator console stays reachable.
        assert_eq!(admin.available_permits(), 2);
        assert_eq!(admin.run(|| 42_u32).await.expect("admin admitted"), 42);
        assert_eq!(
            admin.available_permits(),
            2,
            "admin permit returned after the op"
        );

        assert!(holder.await.expect("holder joins").is_ok());
    }

    /// The admin default pool is small and non-zero — a reserved lane, not the
    /// full core count — and its queue-wait is the *longer* admin default
    /// (HEA-1895): admin login prefers queueing over shedding.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn admin_default_config_is_small_and_nonzero() {
        let cfg = admin_default_config();
        let admin = KdfGate::new_admin(cfg);
        assert_eq!(admin.permits(), DEFAULT_ADMIN_MAX_IN_FLIGHT);
        assert!(admin.permits() >= 1);
        assert_eq!(
            cfg.max_queue_wait,
            Duration::from_millis(DEFAULT_ADMIN_MAX_QUEUE_WAIT_MS)
        );
        // Must strictly exceed the shared gate's shed threshold.
        assert!(cfg.max_queue_wait > KdfGateConfig::default().max_queue_wait);
    }

    /// HEA-1894: a shed on the **admin** gate must increment the admin shed
    /// counter and leave the shared shed counter untouched. Before the pool
    /// discriminant, `KdfGate::run` wrote the shared counters unconditionally,
    /// so admin sheds were invisible in telemetry — the exact operator-console
    /// shedding the F2 isolation exists to make alertable. We measure deltas
    /// because the metrics singleton is process-global.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[allow(clippy::float_cmp)]
    async fn admin_shed_increments_admin_counter_not_shared() {
        let metrics = crate::metrics::metrics();
        let shared_before = metrics.kdf_shed_total.get();
        let admin_before = metrics.kdf_admin_shed_total.get();
        let admin_in_flight_before = metrics.kdf_admin_in_flight.get();

        let admin = std::sync::Arc::new(KdfGate::new_admin(KdfGateConfig {
            max_in_flight: 1,
            max_queue_wait: Duration::from_millis(20),
            retry_after: Duration::from_secs(1),
        }));

        // Peg the admin gate's only permit with work that outlives the queue
        // wait, then offer a second op that must shed.
        let holder = {
            let g = admin.clone();
            tokio::spawn(async move {
                g.run(|| std::thread::sleep(Duration::from_millis(300)))
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            admin.available_permits(),
            0,
            "admin gate should be saturated by the holder"
        );

        assert!(
            matches!(
                admin.run(|| 0_u32).await,
                Err(KdfGateError::Overloaded { .. })
            ),
            "the offered admin op must shed while the permit is held"
        );

        // The admin shed counter advanced; the shared shed counter did not.
        assert_eq!(
            metrics.kdf_admin_shed_total.get() - admin_before,
            1.0,
            "admin shed must increment hearth_kdf_admin_shed_total"
        );
        assert_eq!(
            metrics.kdf_shed_total.get(),
            shared_before,
            "admin shed must NOT touch the shared hearth_kdf_shed_total"
        );

        assert!(holder.await.expect("holder joins").is_ok());
        // The admin in-flight gauge returns to its starting level (holder done).
        assert_eq!(
            metrics.kdf_admin_in_flight.get(),
            admin_in_flight_before,
            "admin in-flight gauge must settle back after the op completes"
        );
    }

    // ── Argon2 block buffers (#445) ─────────────────────────────────────

    fn pool_gate(permits: usize) -> KdfGate {
        KdfGate::new(KdfGateConfig {
            max_in_flight: permits,
            max_queue_wait: Duration::from_secs(5),
            retry_after: Duration::from_secs(1),
        })
    }

    /// Whether every word of `blocks` is zero.
    fn all_zero(blocks: &[Block]) -> bool {
        blocks.iter().all(|b| b.as_ref().iter().all(|w| *w == 0))
    }

    /// The point of the pool: a second hash at the same cost through the same
    /// gate takes the buffer the first one gave back instead of mapping,
    /// faulting in and freeing a fresh one.
    #[test]
    fn a_hash_through_the_gate_reuses_the_pooled_buffer() {
        let gate = pool_gate(1);
        for _ in 0..3 {
            let len = gate
                .try_run_inline(|| with_argon2_blocks(64, |b| b.len()))
                .expect("admitted");
            assert_eq!(len, 64, "the closure gets exactly the blocks it asked for");
        }
        assert_eq!(
            gate.block_pool().fresh_allocations(),
            1,
            "only the first hash allocates; the others reuse its buffer"
        );
        assert_eq!(gate.block_pool().pooled(), 1);
        assert_eq!(gate.block_pool().pooled_bytes(), 64 * Block::SIZE);
    }

    /// The async path (`run`, on the blocking pool) reuses the buffer too,
    /// whichever blocking thread runs the closure.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_async_path_reuses_the_pooled_buffer() {
        let gate = pool_gate(1);
        for _ in 0..3 {
            gate.run(|| with_argon2_blocks(64, |b| b.len()))
                .await
                .expect("admitted");
        }
        assert_eq!(gate.block_pool().fresh_allocations(), 1);
        assert_eq!(gate.block_pool().pooled(), 1);
    }

    /// A realm with a higher memory cost (or a stored hash with a larger `m`)
    /// grows the buffer, and the pool keeps the larger one: a smaller cost
    /// afterwards runs in it without allocating.
    #[test]
    fn a_larger_cost_grows_the_buffer_and_the_pool_keeps_it() {
        let gate = pool_gate(1);
        for blocks in [64, 256, 64, 256] {
            let len = gate
                .try_run_inline(|| with_argon2_blocks(blocks, |b| b.len()))
                .expect("admitted");
            assert_eq!(
                len, blocks,
                "a larger pooled buffer is handed out at the asked size"
            );
        }
        assert_eq!(
            gate.block_pool().fresh_allocations(),
            2,
            "one allocation at 64 blocks, one when the cost grew to 256"
        );
        assert_eq!(gate.block_pool().pooled(), 1);
        assert_eq!(gate.block_pool().pooled_bytes(), 256 * Block::SIZE);
    }

    /// The pool's memory bound is `permits × buffer size`: even when more
    /// buffers are out at once than there are permits (a nested Argon2 run
    /// inside an admitted closure), it keeps at most `permits` of them.
    #[test]
    fn the_pool_never_holds_more_buffers_than_permits() {
        let gate = pool_gate(2);
        assert_eq!(gate.block_pool().capacity(), 2);
        gate.try_run_inline(|| {
            with_argon2_blocks(16, |_| {
                with_argon2_blocks(16, |_| with_argon2_blocks(16, |_| ()));
            });
        })
        .expect("admitted");
        assert_eq!(gate.block_pool().fresh_allocations(), 3);
        assert_eq!(
            gate.block_pool().pooled(),
            2,
            "three buffers came back; a 2-permit pool keeps two"
        );
    }

    /// Concurrent hashes through a saturated gate never leave more than
    /// `permits` buffers behind, and once warm allocate nothing more.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_hashes_stay_within_the_pool_bound() {
        let gate = Arc::new(pool_gate(2));
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let gate = Arc::clone(&gate);
            tasks.push(tokio::spawn(async move {
                gate.run(|| {
                    with_argon2_blocks(32, |_| std::thread::sleep(Duration::from_millis(5)));
                })
                .await
            }));
        }
        for task in tasks {
            task.await.expect("joins").expect("admitted");
        }
        let pool = gate.block_pool();
        assert!(pool.pooled() <= 2, "pool holds {} buffers", pool.pooled());
        assert!(
            pool.fresh_allocations() <= 2,
            "16 hashes with 2 permits need at most 2 buffers, allocated {}",
            pool.fresh_allocations()
        );
    }

    /// The blocks a hash leaves behind are memory-hard state derived from the
    /// password; with them, a guess costs one Blake2b instead of a full
    /// Argon2 run. A buffer is zeroed before anyone else can take it.
    #[test]
    fn a_buffer_is_zeroed_before_it_is_reused() {
        let gate = pool_gate(1);
        gate.try_run_inline(|| {
            with_argon2_blocks(64, |blocks| {
                for block in blocks.iter_mut() {
                    block.as_mut().fill(0xA5A5_A5A5_A5A5_A5A5);
                }
            });
        })
        .expect("admitted");
        let zero = gate
            .try_run_inline(|| with_argon2_blocks(64, |blocks| all_zero(blocks)))
            .expect("admitted");
        assert_eq!(gate.block_pool().fresh_allocations(), 1, "the same buffer");
        assert!(
            zero,
            "the reused buffer still held the previous hash's blocks"
        );
    }

    /// The blocks are zeroed even when the Argon2 run panics.
    #[test]
    fn a_panicking_hash_still_zeroes_and_returns_its_buffer() {
        let gate = pool_gate(1);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            gate.try_run_inline(|| {
                with_argon2_blocks(64, |blocks| {
                    blocks[0].as_mut().fill(u64::MAX);
                    panic!("argon2 run panicked");
                });
            })
        }));
        assert!(outcome.is_err(), "the panic propagates");
        assert_eq!(gate.block_pool().pooled(), 1, "the buffer came back");
        let zero = gate
            .try_run_inline(|| with_argon2_blocks(64, |blocks| all_zero(blocks)))
            .expect("admitted");
        assert!(zero, "a panicking run left its blocks behind");
        assert_eq!(gate.block_pool().fresh_allocations(), 1);
    }

    /// Outside an admitted closure there is no pool to draw from: the call
    /// still gets a zeroed buffer of the asked size, and no gate's pool
    /// changes.
    #[test]
    fn outside_the_gate_a_buffer_is_allocated_and_not_pooled() {
        let gate = pool_gate(1);
        let (len, zero) = with_argon2_blocks(48, |blocks| (blocks.len(), all_zero(blocks)));
        assert_eq!((len, zero), (48, true));
        assert_eq!(gate.block_pool().fresh_allocations(), 0);
        assert_eq!(gate.block_pool().pooled(), 0);
    }
}
