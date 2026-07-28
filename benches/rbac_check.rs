//! Criterion benchmarks and CI threshold gates for claims-based RBAC checks.
//!
//! Covers the hot-path authorization pattern: client and server
//! authorization decisions are JWT claim lookups, never network calls.
//!
//! # CI Threshold Gates
//!
//! Two hard gates run at binary startup (before Criterion sampling).
//! The bench binary exits non-zero if either limit is breached, which
//! causes `make bench-gate` — and therefore `make ci-standard` — to fail.
//!
//! | Gate | Limit | Regression delta |
//! |------|-------|-----------------|
//! | `resolve_permissions` (JWT decode + HashSet lookup) | p99 ≤ 1 ms | 0% (hard limit) |
//! | `hasPermission` (pre-parsed `HashSet::contains`)    | p99 ≤ 1 µs | 0% (hard limit) |
//! | `hasPermission` allocations                         | ≤ [`MAX_ALLOCS_PER_CALL`] (0) | 0% (hard limit) |
//!
//! Gates collect [`GATE_SAMPLES`] measurements after [`GATE_WARMUP`]
//! discard iterations, then assert `samples[samples.len() * 99 / 100]`.
//!
//! ## Allocation ceiling rationale (HEA-1776)
//!
//! The steady-state server authorization path (E7) is a single
//! `HashSet<String>::contains(&str)` over the pre-materialized claim set. That
//! borrows the probe key and never allocates, so [`MAX_ALLOCS_PER_CALL`] is `0`
//! — a hard zero-allocation proof that trips if a `format!()`, `to_string()`,
//! or owned-key construction is re-introduced into the per-check path. This
//! mirrors the allocation-gate pattern in `benches/validate_token.rs` and locks
//! the §2 E7 baseline in CI. (The cold client-side `do_jwt_lookup` path — split
//! + base64 decode + JSON parse — allocates by construction and is covered by
//! the latency gate only, not the allocation gate.)
//!
//! Thresholds derive from `docs/specs/TESTING.md` (Standard CI tier) and
//! `docs/specs/AUTHORIZATION.md` § 10. These checks intentionally use
//! hard thresholds to prevent drift on the two P0 RBAC latency scenarios.
//!
//! Aspirational design targets (tighter, not enforced in CI):
//! - JWT decode + permission lookup: p99 < 1 µs
//! - `HashSet::contains` over claim set: p99 < 100 ns

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use criterion::{black_box, criterion_group, BenchmarkId, Criterion};

// ── Counting allocator ────────────────────────────────────────────────────────

/// Counting wrapper around the system allocator.
///
/// Enabled only during the `gate_has_permission_allocs` measurement loop;
/// disabled during warmup and Criterion sampling so we do not measure allocator
/// activity unrelated to the steady-state authorization check.
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

/// Maximum heap allocations per steady-state `hasPermission` invocation.
///
/// See the module-level "Allocation ceiling rationale": `HashSet::contains`
/// borrows the probe key and never allocates, so the ceiling is `0`.
const MAX_ALLOCS_PER_CALL: usize = 0;

/// Rounds used to amortize per-call allocation counting noise.
const ALLOC_ROUNDS: usize = 200;

/// Hard p99 limit for `resolve_permissions` (full JWT decode + lookup path).
const RESOLVE_PERMISSIONS_P99_LIMIT: Duration = Duration::from_millis(1);

/// Hard p99 limit for `hasPermission` (pre-parsed `HashSet::contains` only).
const HAS_PERMISSION_P99_LIMIT: Duration = Duration::from_micros(1);

/// Number of raw samples collected per gate for p99 estimation.
const GATE_SAMPLES: usize = 10_000;

/// Warm-up iterations discarded before gate measurement begins.
const GATE_WARMUP: usize = 200;

// ── Token forge helper ────────────────────────────────────────────────────────

/// Build a JWT payload segment containing `n` permissions plus a fixed
/// set of RBAC-relevant claims. The signature segment is arbitrary —
/// nothing in these benchmarks verifies it.
fn forge_token(permission_count: usize) -> String {
    let perms: Vec<String> = (0..permission_count)
        .map(|i| format!("namespace.resource.action_{i:04}"))
        .collect();
    let roles = vec!["admin".to_string(), "editor".to_string()];
    let groups = vec!["engineering".to_string(), "security".to_string()];
    let claims = serde_json::json!({
        "sub": "user_abc123",
        "iss": "https://hearth.example.com",
        "aud": "hearth",
        "exp": 2_000_000_000i64,
        "iat": 1_700_000_000i64,
        "sid": "sid_1",
        "tid": "tid_1",
        "oid": "org_42",
        "token_type": "access",
        "roles": roles,
        "groups": groups,
        "permissions": perms,
    });
    let header = serde_json::json!({"alg": "EdDSA", "typ": "JWT", "kid": "k1"});
    let hb = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header"));
    let cb = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("claims"));
    let sig = URL_SAFE_NO_PAD.encode(b"not-a-real-signature");
    format!("{hb}.{cb}.{sig}")
}

// ── Inner hot-path helpers (shared by gates and Criterion) ───────────────────

/// JWT decode + linear permission scan — the `resolve_permissions` path.
#[inline]
fn do_jwt_lookup(token: &str, target: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    let payload = URL_SAFE_NO_PAD.decode(parts[1]).expect("base64 decode");
    let claims: serde_json::Value = serde_json::from_slice(&payload).expect("json parse");
    claims
        .get("permissions")
        .and_then(|p| p.as_array())
        .is_some_and(|arr| arr.iter().any(|v| v.as_str() == Some(target)))
}

/// Pre-parsed `HashSet::contains` — the `hasPermission` server hot path.
#[inline]
fn do_hashset_contains(set: &HashSet<String>, target: &str) -> bool {
    set.contains(target)
}

// ── Threshold gate functions ──────────────────────────────────────────────────

/// Assert `resolve_permissions` p99 ≤ [`RESOLVE_PERMISSIONS_P99_LIMIT`].
///
/// Uses the worst-case fixture: 100 permissions, target is the last one
/// (maximises the linear scan in `do_jwt_lookup`).
fn gate_resolve_permissions_p99() {
    let token = forge_token(100);
    let target = format!("namespace.resource.action_{:04}", 99);

    for _ in 0..GATE_WARMUP {
        black_box(do_jwt_lookup(black_box(&token), black_box(&target)));
    }

    let mut samples: Vec<Duration> = Vec::with_capacity(GATE_SAMPLES);
    for _ in 0..GATE_SAMPLES {
        let start = Instant::now();
        black_box(do_jwt_lookup(black_box(&token), black_box(&target)));
        samples.push(start.elapsed());
    }

    samples.sort_unstable();
    let p99 = samples[GATE_SAMPLES * 99 / 100];

    assert!(
        p99 <= RESOLVE_PERMISSIONS_P99_LIMIT,
        "resolve_permissions p99 {p99:?} exceeds CI limit {RESOLVE_PERMISSIONS_P99_LIMIT:?} \
         — see benches/rbac_check.rs for threshold rationale"
    );
}

/// Assert `hasPermission` p99 ≤ [`HAS_PERMISSION_P99_LIMIT`].
///
/// Uses a 100-element set; target is the worst-case hash bucket.
fn gate_has_permission_p99() {
    let set: HashSet<String> = (0..100usize)
        .map(|i| format!("namespace.resource.action_{i:04}"))
        .collect();
    let target = format!("namespace.resource.action_{:04}", 99);

    for _ in 0..GATE_WARMUP {
        black_box(do_hashset_contains(black_box(&set), black_box(&target)));
    }

    let mut samples: Vec<Duration> = Vec::with_capacity(GATE_SAMPLES);
    for _ in 0..GATE_SAMPLES {
        let start = Instant::now();
        black_box(do_hashset_contains(black_box(&set), black_box(&target)));
        samples.push(start.elapsed());
    }

    samples.sort_unstable();
    let p99 = samples[GATE_SAMPLES * 99 / 100];

    assert!(
        p99 <= HAS_PERMISSION_P99_LIMIT,
        "hasPermission p99 {p99:?} exceeds CI limit {HAS_PERMISSION_P99_LIMIT:?} \
         — see benches/rbac_check.rs for threshold rationale"
    );
}

/// Assert steady-state `hasPermission` allocates ≤ [`MAX_ALLOCS_PER_CALL`].
///
/// Uses a 100-element set and probes the worst-case member. `HashSet::contains`
/// borrows the `&str` probe key, so the warm path must perform zero heap
/// allocations. Any `format!()`/`to_string()`/owned-key construction added to
/// the per-check path trips this gate.
fn gate_has_permission_allocs() {
    let set: HashSet<String> = (0..100usize)
        .map(|i| format!("namespace.resource.action_{i:04}"))
        .collect();
    let target = format!("namespace.resource.action_{:04}", 99);

    for _ in 0..GATE_WARMUP {
        black_box(do_hashset_contains(black_box(&set), black_box(&target)));
    }

    ALLOC_COUNT.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::SeqCst);

    for _ in 0..ALLOC_ROUNDS {
        black_box(do_hashset_contains(black_box(&set), black_box(&target)));
    }

    COUNTING.store(false, Ordering::SeqCst);
    let total = ALLOC_COUNT.load(Ordering::Relaxed);
    // Ceiling division: round up so a single extra allocation is always visible.
    let per_call = total.div_ceil(ALLOC_ROUNDS);

    assert!(
        per_call == MAX_ALLOCS_PER_CALL,
        "hasPermission averaged {per_call} heap allocations per call \
         (limit: {MAX_ALLOCS_PER_CALL}). \
         A new format!(), to_string(), or owned-key construction was added to \
         the authorization hot path. \
         See benches/rbac_check.rs § allocation ceiling rationale."
    );
}

// ── Criterion benchmark groups ────────────────────────────────────────────────

/// Benchmarks the end-to-end "client-side claim lookup" pattern:
/// split the JWT, base64url-decode the payload segment, parse JSON,
/// then test membership.
///
/// This is what a web app does on every render when it calls
/// `hearth.hasPermission(...)`.
fn bench_jwt_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("rbac_jwt_lookup");
    for size in [10usize, 50, 100] {
        let token = forge_token(size);
        let target = format!("namespace.resource.action_{:04}", size - 1);
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                black_box(do_jwt_lookup(
                    black_box(token.as_str()),
                    black_box(target.as_str()),
                ))
            });
        });
    }
    group.finish();
}

/// Benchmarks server-side authorization: given a pre-materialized
/// `HashSet<String>` of the claim set (as a middleware would build once
/// per request after verifying the token), check membership.
///
/// This is the steady-state hot path — after the per-request
/// verification cost has been amortized over however many permission
/// checks the handler performs.
fn bench_hashset_contains(c: &mut Criterion) {
    let mut group = c.benchmark_group("rbac_hashset_contains");
    for size in [10usize, 50, 100] {
        let set: HashSet<String> = (0..size)
            .map(|i| format!("namespace.resource.action_{i:04}"))
            .collect();
        let target = format!("namespace.resource.action_{:04}", size - 1);
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                black_box(do_hashset_contains(
                    black_box(&set),
                    black_box(target.as_str()),
                ))
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_jwt_lookup, bench_hashset_contains);

// Custom main: run hard threshold gates before Criterion sampling.
// Panicking here causes non-zero exit, which fails `make bench-gate`.
fn main() {
    gate_resolve_permissions_p99();
    gate_has_permission_p99();
    gate_has_permission_allocs();

    // `benches()` is generated by criterion_group! and owns its Criterion instance.
    benches();
}
