//! Criterion benchmarks and CI threshold gates for session management (E2).
//!
//! Covers `TEST_SCENARIOS.md` § Session Management — Benchmark:
//! 1. Session lookup by ID: p50 < 10 μs, p99 < 100 μs
//! 2. Session creation throughput: > 50,000 ops/sec/core
//!
//! # CI Threshold Gates (HEA-1776)
//!
//! Two hard gates run at binary startup (before Criterion sampling), mirroring
//! the allocation-gate pattern established in `benches/validate_token.rs`. A
//! panic causes a non-zero exit, which fails `make bench-gate` and therefore
//! `make ci-standard`.
//!
//! | Gate | Metric | Limit | Source |
//! |------|--------|-------|--------|
//! | `session_lookup_latency` | p99 | ≤ 1 ms (CI) | TEST_SCENARIOS.md (p99 < 100 µs prod) |
//! | `session_lookup_allocs`  | allocs / call | ≤ [`MAX_ALLOCS_PER_CALL`] (0) | see below |
//!
//! This locks the §2 Big-O baseline for the E2 `lookup_session` endpoint so
//! that a re-introduced read-path syscall, `format!()`, or deep clone is caught
//! automatically rather than slipping through review.
//!
//! ## Latency ceiling (informational vs blocking)
//!
//! TEST_SCENARIOS.md targets p50 < 10 µs and p99 < 100 µs on production
//! hardware (informational). Shared GitHub Actions runners add 2–4× overhead
//! and scheduler jitter, so the **blocking** CI gate is 1 ms — strict enough to
//! catch multi-ms regressions (e.g. an accidental storage read on the hot path)
//! while avoiding false positives from runner noise. This matches the
//! `validate_token` latency gate rationale.
//!
//! ## Allocation ceiling rationale
//!
//! On a **warm** cache hit `get_session` performs a single ArcSwap `load()`
//! (thread-local debt slots, no allocation single-thread) and clones the cached
//! `Session` body. The gate fixture uses [`SessionContext::default()`] — a
//! browserless session whose `ip_address`, `user_agent_raw`, and `device_label`
//! fields are all `None` and whose remaining fields are `Copy` — so the clone
//! bumps no heap. The warm read path therefore performs **zero heap
//! allocations**, and [`MAX_ALLOCS_PER_CALL`] is `0`: any allocation on the
//! warm path — a re-introduced eviction storage write (C-5 regression), a stray
//! `format!()`, a `Vec`/`Box`, or a `Session` field that starts heap-allocating
//! on clone — trips the gate.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use criterion::{black_box, criterion_group, Criterion};

use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{Clock, RealmId, SessionId, SystemClock, UserId};
use hearth::identity::{
    CreateRealmRequest, CreateUserRequest, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine,
    SessionContext,
};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

// ── Counting allocator ────────────────────────────────────────────────────────

/// Counting wrapper around the system allocator.
///
/// Enabled only during the `gate_session_lookup_allocs` measurement loop;
/// disabled during engine setup, warmup, and Criterion sampling so we do not
/// measure allocator activity unrelated to the hot path.
struct CountingAllocator;

/// Total heap allocations recorded while [`COUNTING`] is `true`.
static ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Guards counting: `true` only during the allocation gate measurement loop.
static COUNTING: AtomicBool = AtomicBool::new(false);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: forwarding unchanged to the system allocator.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarding unchanged to the system allocator.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: forwarding unchanged to the system allocator.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: forwarding unchanged to the system allocator.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

// ── Threshold constants ───────────────────────────────────────────────────────

/// Hard p99 limit for `get_session` on CI runners.
///
/// TEST_SCENARIOS.md targets p99 < 100 µs on production hardware; the CI gate
/// uses 1 ms to accommodate shared-runner overhead while still catching
/// multi-ms regressions (e.g. an accidental cold storage read).
const SESSION_LOOKUP_P99: Duration = Duration::from_millis(1);

/// Maximum heap allocations per warm `get_session` invocation.
///
/// See the module-level "Allocation ceiling rationale": the warm read path over
/// a browserless (`SessionContext::default()`) session performs zero heap
/// allocations, so the ceiling is `0` — a hard zero-allocation proof for E2.
const MAX_ALLOCS_PER_CALL: usize = 0;

/// Samples collected for the latency gate.
const GATE_SAMPLES: usize = 10_000;

/// Warm-up iterations discarded before gate measurement begins.
const GATE_WARMUP: usize = 500;

/// Rounds used to amortize per-call allocation counting noise.
const ALLOC_ROUNDS: usize = 200;

// ── Shared setup ──────────────────────────────────────────────────────────────

struct BenchState {
    /// Kept alive so the storage directory is not deleted during the bench.
    _dir: tempfile::TempDir,
    engine: EmbeddedIdentityEngine,
    realm: RealmId,
    session_id: SessionId,
    user_id: UserId,
}

/// Sets up an identity engine with a user and a warmed, hot-tier session.
fn make_bench_state() -> BenchState {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = StorageConfig::dev(dir.path().to_path_buf());
    let storage =
        Arc::new(EmbeddedStorageEngine::open(config).expect("open")) as Arc<dyn StorageEngine>;
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    )) as Arc<dyn AuditEngine>;
    let engine = EmbeddedIdentityEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
        IdentityConfig::default(),
        Arc::clone(&audit),
    )
    .expect("engine creation");

    let realm = engine
        .create_realm(&CreateRealmRequest {
            name: format!("bench-session-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();

    let user = engine
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "bench-session@example.com".to_string(),
                display_name: "Bench Session User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let session = engine
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("create session");

    // Prime the session hot tier so gates measure steady-state warm reads.
    for _ in 0..GATE_WARMUP {
        black_box(
            engine
                .get_session(&realm, session.id())
                .expect("warmup get_session"),
        );
    }

    BenchState {
        _dir: dir,
        engine,
        realm,
        session_id: session.id().clone(),
        user_id: user.id().clone(),
    }
}

// ── Percentile helper ─────────────────────────────────────────────────────────

/// Sort `samples`, then panic if p99 exceeds the limit.
fn assert_p99(samples: &mut [Duration], gate: &str, p99_limit: Duration) {
    samples.sort_unstable();
    let p99 = samples[samples.len() * 99 / 100];
    assert!(
        p99 <= p99_limit,
        "{gate} p99 {p99:?} exceeds CI limit {p99_limit:?} \
         — see benches/session_lookup.rs and TEST_SCENARIOS.md § Session Management"
    );
}

// ── Gate functions ────────────────────────────────────────────────────────────

/// Assert `get_session` p99 ≤ [`SESSION_LOOKUP_P99`] on the warm hot tier.
fn gate_session_lookup_latency(state: &BenchState) {
    let mut samples = Vec::with_capacity(GATE_SAMPLES);
    for _ in 0..GATE_SAMPLES {
        let start = Instant::now();
        black_box(
            state
                .engine
                .get_session(&state.realm, black_box(&state.session_id))
                .expect("get_session"),
        );
        samples.push(start.elapsed());
    }
    assert_p99(&mut samples, "session_lookup", SESSION_LOOKUP_P99);
}

/// Assert warm `get_session` allocates ≤ [`MAX_ALLOCS_PER_CALL`] per invocation.
fn gate_session_lookup_allocs(state: &BenchState) {
    ALLOC_COUNT.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::SeqCst);

    for _ in 0..ALLOC_ROUNDS {
        black_box(
            state
                .engine
                .get_session(&state.realm, black_box(&state.session_id))
                .expect("get_session"),
        );
    }

    COUNTING.store(false, Ordering::SeqCst);
    let total = ALLOC_COUNT.load(Ordering::Relaxed);
    // Ceiling division: round up so a single extra allocation is always visible.
    let per_call = total.div_ceil(ALLOC_ROUNDS);

    assert!(
        per_call <= MAX_ALLOCS_PER_CALL,
        "session_lookup averaged {per_call} heap allocations per call \
         (limit: {MAX_ALLOCS_PER_CALL}). \
         A new format!(), clone(), read-path syscall, or boxing was added to the \
         session lookup hot path. \
         See benches/session_lookup.rs § allocation ceiling rationale."
    );
}

// ── Criterion benchmarks ──────────────────────────────────────────────────────

/// Benchmarks session lookup by ID (hot path).
fn bench_session_lookup_by_id(c: &mut Criterion) {
    let state = make_bench_state();
    c.bench_function("session_lookup_by_id", |b| {
        b.iter(|| {
            let result = state
                .engine
                .get_session(&state.realm, &state.session_id)
                .expect("get");
            assert!(result.is_some());
        });
    });
}

/// Benchmarks session creation throughput.
fn bench_session_creation(c: &mut Criterion) {
    let state = make_bench_state();
    c.bench_function("session_creation", |b| {
        b.iter(|| {
            let result = state.engine.create_session(
                &state.realm,
                &state.user_id,
                &SessionContext::default(),
            );
            assert!(result.is_ok());
        });
    });
}

criterion_group!(benches, bench_session_lookup_by_id, bench_session_creation);

// Custom main: run hard threshold gates before Criterion sampling.
// Panicking here causes non-zero exit, which fails `make bench-gate`.
fn main() {
    let state = make_bench_state();
    gate_session_lookup_latency(&state);
    gate_session_lookup_allocs(&state);
    benches();
}
