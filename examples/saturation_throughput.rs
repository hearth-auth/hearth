//! HEA-1875 · C7 — Saturation-throughput benches for VISION §7.2.
//!
//! Answers the board's throughput questions for the identity hot path by
//! driving the **real** engine operations in-process — no HTTP server, no axum,
//! no tokio, no load generator in the loop — swept across 1/2/4/8/16 OS threads:
//!
//!   * `validate_token`  (hot: token-claims-cache hit; miss: full Ed25519 verify)
//!   * `session_lookup`  (`get_session`; hot-tier hit vs forced miss)
//!   * `user_lookup`     (`get_user`;    hot-tier hit vs forced miss)
//!   * `permission_check`(`RbacEngine::resolve_permissions`, HEA-1770 cache)
//!   * `session_create`  (`create_session`; WAL-`fsync` write path)
//!
//! ## Why in-process, not through the Goose/HTTP harness
//!
//! The HTTP-driven path is **NOT-MEASURABLE** in this environment: HEA-1871 (C3)
//! bisected the throughput cliff to the server side, and the HEA-1876 (C8) HTTP
//! sweep could not seed the corpus without the generator/server co-residency
//! ceiling voiding the run. Per the HEA-1867 grading rules, *nothing is graded
//! PASS on a run whose ceiling attribution was the generator*. Driving the engine
//! operations directly removes the generator entirely: the only quantity under
//! test is the engine's own per-op cost and how it scales with core count. This
//! is the honest way to isolate the **engine cost** the VISION §7.2 budgets
//! (engine target + a 1 ms loopback envelope) are far too coarse to validate.
//!
//! ## What "hot-hit" and "forced-miss" mean here
//!
//! * `user_lookup` / `session_lookup`: **hot** = the record is resident in the
//!   hot tier (warmed to convergence past the production `promote_sample_rate`);
//!   **miss** = a random, never-inserted id, so the read falls through the tier
//!   and returns `None` — the corpus-size-dependent path.
//! * `validate_token`: **hot** = the raw-JWT SHA-256 is resident in the 2048-slot
//!   token-claims cache, so the Ed25519 verify + `serde` parse are skipped;
//!   **miss** = a token whose hash is *not* cached (the cache is pre-saturated
//!   with a disjoint warm set, and inserts silently no-op at capacity), so every
//!   call pays the full verify. Both still run every semantic check and the
//!   session-validity `get_session`.
//! * `permission_check` / `session_create` have no meaningful tier-miss beyond
//!   their own internal cache / the WAL, so they are measured once.
//!
//! ## Output
//!
//! For every operation: aggregate ops/s and **per-core** ops/s at each thread
//! count, the fitted **scaling exponent** (slope of `log(agg ops/s)` on
//! `log(threads)`; 1.0 = perfect linear scaling, 0.0 = fully serialized), whether
//! single-thread per-core throughput clears the **200 k ops/s/core** VISION §7.2
//! bar, and a scales-vs-contends verdict from the 1→16-thread efficiency. Every
//! figure is engine-level on the host it was measured on (printed in the header);
//! a machine-readable JSON block follows the `===JSON===` marker for the artifact.
//!
//! Run:  `cargo run --release --example saturation_throughput`

// Measurement binary: casts are for reporting math on small magnitudes, and the
// setup/print helpers are intentionally verbose for auditability.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::needless_range_loop
)]

use std::path::PathBuf;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{Clock, RealmId, SessionId, SystemClock, UserId};
use hearth::identity::{
    CreateRealmRequest, CreateUserRequest, CredentialConfig, EmbeddedIdentityEngine,
    IdentityConfig, IdentityEngine, SessionContext,
};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Thread counts swept for every operation (VISION §7.2 ladder).
const THREADS: &[usize] = &[1, 2, 4, 8, 16];

/// Wall-clock measurement window per (operation, thread-count) cell.
const MEASURE: Duration = Duration::from_secs(2);

/// Ops between deadline checks — amortizes `Instant::now()` over sub-µs reads
/// without materially overshooting the window.
const BATCH: u64 = 64;

/// Distinct users seeded (user_lookup pool + token subjects).
const USERS: usize = 1_000;

/// Warm session pool (session_lookup hot + validate-hot token subjects). Sized
/// to exactly saturate the 2048-slot token-claims cache with warm tokens.
const SESSIONS: usize = 2_048;

/// Dedicated sessions backing the validate-**miss** token pool — kept disjoint
/// from the warm set so their tokens never land in the (already-full) cache.
const MISS_SESSIONS: usize = 512;

/// Warm passes over a hot pool before measuring — drives promotion past the
/// production `promote_sample_rate` to convergence.
const WARM_PASSES: usize = 24;

/// Hot-tier capacity: comfortably larger than every warm working set combined
/// (user records + email indexes + session records + session indexes) so a
/// warmed pool stays fully resident across its whole thread sweep.
const HOT_CAPACITY: usize = 40_000;

/// VISION §7.2 per-core throughput bar.
const VISION_OPS_PER_CORE: f64 = 200_000.0;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cores = thread::available_parallelism().map_or(0, std::num::NonZeroUsize::get);
    println!("HEA-1875 · C7 — Saturation-throughput benches (VISION §7.2)\n");
    println!(
        "host: {} logical cores | measure window = {:?}/cell | users = {USERS}, \
         warm sessions = {SESSIONS}, miss sessions = {MISS_SESSIONS}",
        cores, MEASURE
    );
    println!("in-process engine drive — no HTTP / axum / tokio / load generator in the loop\n");

    let fixture = Fixture::build()?;
    let results = fixture.run_all();

    print_tables(&results, cores);
    emit_json(&results, cores);
    Ok(())
}

// ───────────────────────────── fixture / setup ─────────────────────────────

/// Everything the operations read from, built once up front.
struct Fixture {
    engine: EmbeddedIdentityEngine,
    /// Shared handle to the same RBAC engine wired into `engine`, so the
    /// permission-check bench can call `resolve_permissions` directly.
    rbac: Arc<dyn RbacEngine>,
    realm: RealmId,
    users: Vec<UserId>,
    /// Warm sessions — `session_lookup` hot pool.
    sessions: Vec<SessionId>,
    /// Warm access tokens whose hashes fill the claims cache (`validate` hot).
    warm_tokens: Vec<String>,
    /// Access tokens whose hashes are *not* cached (`validate` miss).
    miss_tokens: Vec<String>,
    /// Random, never-inserted user ids (`user_lookup` miss).
    miss_user_ids: Vec<UserId>,
    /// Random, never-inserted session ids (`session_lookup` miss).
    miss_session_ids: Vec<SessionId>,
    /// Kept alive for the lifetime of the run so the data dir is not reaped.
    _tmp: tempfile::TempDir,
}

impl Fixture {
    fn build() -> Result<Self, Box<dyn std::error::Error>> {
        let tmp = tempfile::tempdir()?;
        let mut config = StorageConfig::production(
            PathBuf::from(tmp.path()),
            2 * 1024 * 1024 * 1024, // 2 GiB WAL ceiling — the write bench churns sessions.
            8 * 1024 * 1024,        // 8 MiB memtable flush.
            HOT_CAPACITY,
        );
        // dev_mode only auto-generates the host key for the temp dir; it does not
        // relax promote_sample_rate, which stays at the production value.
        config.dev_mode = true;

        let storage = Arc::new(EmbeddedStorageEngine::open(config)?) as Arc<dyn StorageEngine>;
        let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
        let audit = Arc::new(EmbeddedAuditEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock),
        )) as Arc<dyn AuditEngine>;
        let rbac = Arc::new(EmbeddedRbacEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock),
        )) as Arc<dyn RbacEngine>;
        let rbac_handle = Arc::clone(&rbac);
        let engine = EmbeddedIdentityEngine::with_rbac(
            storage,
            clock,
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                ..IdentityConfig::default()
            },
            rbac,
            audit,
        )?;

        let realm = engine
            .create_realm(&CreateRealmRequest {
                name: format!("c7-sat-{}", uuid::Uuid::new_v4()),
                config: None,
            })?
            .id()
            .clone();

        println!("seeding {USERS} users …");
        let mut users = Vec::with_capacity(USERS);
        for i in 0..USERS {
            let user = engine.create_user(
                &realm,
                &CreateUserRequest {
                    email: format!("u{i}-{}@c7.test", uuid::Uuid::new_v4()),
                    display_name: format!("user {i}"),
                    first_name: String::new(),
                    last_name: String::new(),
                    attributes: Default::default(),
                },
            )?;
            users.push(user.id().clone());
        }

        let ctx = SessionContext::default();

        println!("creating {SESSIONS} warm sessions + minting warm tokens …");
        let mut sessions = Vec::with_capacity(SESSIONS);
        let mut warm_tokens = Vec::with_capacity(SESSIONS);
        for i in 0..SESSIONS {
            let uid = &users[i % USERS];
            let session = engine.create_session(&realm, uid, &ctx)?;
            let sid = session.id().clone();
            let pair = engine.issue_tokens(&realm, uid, &sid)?;
            warm_tokens.push(pair.access_token().to_string());
            sessions.push(sid);
        }

        println!("creating {MISS_SESSIONS} sessions + minting miss tokens …");
        let mut miss_tokens = Vec::with_capacity(MISS_SESSIONS);
        for i in 0..MISS_SESSIONS {
            let uid = &users[i % USERS];
            let session = engine.create_session(&realm, uid, &ctx)?;
            let pair = engine.issue_tokens(&realm, uid, session.id())?;
            miss_tokens.push(pair.access_token().to_string());
        }

        // Random ids that were never written — guaranteed lookup misses.
        let miss_user_ids: Vec<UserId> = (0..4_096).map(|_| UserId::generate()).collect();
        let miss_session_ids: Vec<SessionId> = (0..4_096).map(|_| SessionId::generate()).collect();

        let fixture = Self {
            engine,
            rbac: rbac_handle,
            realm,
            users,
            sessions,
            warm_tokens,
            miss_tokens,
            miss_user_ids,
            miss_session_ids,
            _tmp: tmp,
        };

        fixture.warm();
        Ok(fixture)
    }

    /// Warms the hot pools and saturates the token-claims cache.
    ///
    /// Saturating the cache with the warm-token set (≥ its 2048 capacity) is
    /// what makes the `validate` **miss** measurement honest: once full, inserts
    /// silently no-op, so the disjoint miss tokens can never become resident and
    /// every miss call pays the full Ed25519 verify.
    fn warm(&self) {
        println!("warming hot tier ({WARM_PASSES} passes) + saturating claims cache …\n");
        for _ in 0..WARM_PASSES {
            for u in &self.users {
                let _ = self.engine.get_user(&self.realm, u);
            }
            for s in &self.sessions {
                let _ = self.engine.get_session(&self.realm, s);
            }
        }
        // Fill the 2048-slot claims cache with the warm tokens (validate hot),
        // and warm the miss tokens' sessions so a miss pays *only* the extra
        // verify/parse relative to a hit — not a cold session read on top.
        for t in &self.warm_tokens {
            let _ = self.engine.validate_token(&self.realm, t);
        }
        for t in &self.miss_tokens {
            let _ = self.engine.validate_token(&self.realm, t);
        }
    }

    /// Runs every operation's full thread sweep.
    fn run_all(&self) -> Vec<OpResult> {
        vec![
            self.sweep_op("validate_token", "hot", |tid, n| {
                let i = mix(tid, n) % self.warm_tokens.len();
                let _ = self
                    .engine
                    .validate_token(&self.realm, &self.warm_tokens[i]);
            }),
            self.sweep_op("validate_token", "miss", |tid, n| {
                let i = mix(tid, n) % self.miss_tokens.len();
                let _ = self
                    .engine
                    .validate_token(&self.realm, &self.miss_tokens[i]);
            }),
            self.sweep_op("session_lookup", "hot", |tid, n| {
                let i = mix(tid, n) % self.sessions.len();
                let _ = self.engine.get_session(&self.realm, &self.sessions[i]);
            }),
            self.sweep_op("session_lookup", "miss", |tid, n| {
                let i = mix(tid, n) % self.miss_session_ids.len();
                let _ = self
                    .engine
                    .get_session(&self.realm, &self.miss_session_ids[i]);
            }),
            self.sweep_op("user_lookup", "hot", |tid, n| {
                let i = mix(tid, n) % self.users.len();
                let _ = self.engine.get_user(&self.realm, &self.users[i]);
            }),
            self.sweep_op("user_lookup", "miss", |tid, n| {
                let i = mix(tid, n) % self.miss_user_ids.len();
                let _ = self.engine.get_user(&self.realm, &self.miss_user_ids[i]);
            }),
            self.sweep_op("permission_check", "hot", |tid, n| {
                let i = mix(tid, n) % self.users.len();
                let _ = self
                    .rbac
                    .resolve_permissions(&self.users[i], &self.realm, None, None);
            }),
            self.sweep_op("session_create", "write", |tid, n| {
                let i = mix(tid, n) % self.users.len();
                let _ = self.engine.create_session(
                    &self.realm,
                    &self.users[i],
                    &SessionContext::default(),
                );
            }),
        ]
    }

    /// Runs one operation across the whole thread ladder.
    fn sweep_op<F>(&self, op: &str, state: &str, body: F) -> OpResult
    where
        F: Fn(usize, u64) + Sync + Send + Copy,
    {
        let points: Vec<Point> = THREADS.iter().map(|&t| measure_cell(t, body)).collect();
        OpResult {
            op: op.to_string(),
            state: state.to_string(),
            points,
        }
    }
}

// ───────────────────────────── measurement core ────────────────────────────

/// One (operation, thread-count) measurement.
struct Point {
    threads: usize,
    ops: u64,
    elapsed_s: f64,
    agg_ops_s: f64,
    per_core_ops_s: f64,
}

/// One operation's full sweep across the thread ladder.
struct OpResult {
    op: String,
    state: String,
    points: Vec<Point>,
}

impl OpResult {
    fn label(&self) -> String {
        format!("{} [{}]", self.op, self.state)
    }

    fn point(&self, threads: usize) -> Option<&Point> {
        self.points.iter().find(|p| p.threads == threads)
    }

    /// Scaling exponent: slope of `log(agg ops/s)` on `log(threads)`.
    fn scaling_exponent(&self) -> (f64, f64) {
        let xs: Vec<f64> = self
            .points
            .iter()
            .map(|p| (p.threads as f64).ln())
            .collect();
        let ys: Vec<f64> = self
            .points
            .iter()
            .map(|p| p.agg_ops_s.max(1.0).ln())
            .collect();
        linreg(&xs, &ys)
    }

    /// Parallel efficiency at the top of the ladder: per-core@max ÷ per-core@1.
    fn efficiency(&self) -> f64 {
        let base = self.points.first().map_or(0.0, |p| p.per_core_ops_s);
        let top = self.points.last().map_or(0.0, |p| p.per_core_ops_s);
        if base <= 0.0 {
            0.0
        } else {
            top / base
        }
    }

    fn meets_200k_single_core(&self) -> bool {
        self.point(1)
            .is_some_and(|p| p.per_core_ops_s >= VISION_OPS_PER_CORE)
    }
}

/// Runs `body` on `threads` threads for [`MEASURE`], returning aggregate and
/// per-core throughput. Threads start together on a barrier; each counts its own
/// completed ops until a shared-shaped deadline.
fn measure_cell<F>(threads: usize, body: F) -> Point
where
    F: Fn(usize, u64) + Sync + Send + Copy,
{
    let barrier = Barrier::new(threads);
    let start = Instant::now(); // placeholder; real start captured post-barrier
    let (total, elapsed) = thread::scope(|scope| {
        let handles: Vec<_> = (0..threads)
            .map(|tid| {
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    let t0 = Instant::now();
                    let deadline = t0 + MEASURE;
                    let mut n = 0u64;
                    loop {
                        for _ in 0..BATCH {
                            body(tid, n);
                            n += 1;
                        }
                        if Instant::now() >= deadline {
                            break;
                        }
                    }
                    (n, t0.elapsed())
                })
            })
            .collect();
        let mut total = 0u64;
        let mut max_elapsed = Duration::ZERO;
        for h in handles {
            let (n, e) = h.join().expect("worker thread panicked");
            total += n;
            max_elapsed = max_elapsed.max(e);
        }
        (total, max_elapsed)
    });
    let _ = start;
    let elapsed_s = elapsed.as_secs_f64().max(f64::MIN_POSITIVE);
    let agg = total as f64 / elapsed_s;
    Point {
        threads,
        ops: total,
        elapsed_s,
        agg_ops_s: agg,
        per_core_ops_s: agg / threads as f64,
    }
}

/// Spreads keys across threads so no two threads pin the same index in lockstep
/// (which would flatter shared-cache behaviour) while staying deterministic.
fn mix(tid: usize, n: u64) -> usize {
    (tid.wrapping_mul(0x9E37_79B9) as u64).wrapping_add(n.wrapping_mul(2_654_435_761)) as usize
}

// ─────────────────────────────── reporting ─────────────────────────────────

fn print_tables(results: &[OpResult], cores: usize) {
    for r in results {
        println!("── {} ──", r.label());
        println!("threads | aggregate ops/s | per-core ops/s | scaling eff (vs 1T)");
        println!("--------+-----------------+----------------+--------------------");
        let base = r.points.first().map_or(0.0, |p| p.per_core_ops_s);
        for p in &r.points {
            let eff = if base > 0.0 {
                p.per_core_ops_s / base
            } else {
                0.0
            };
            println!(
                "{:>7} | {:>15.0} | {:>14.0} | {:>17.2}×",
                p.threads, p.agg_ops_s, p.per_core_ops_s, eff
            );
        }
        let (slope, r2) = r.scaling_exponent();
        println!(
            "  scaling exponent = {slope:+.3} (R² = {r2:.3})  [1.0 = linear, 0.0 = serialized] → {}",
            scaling_verdict(slope, r.efficiency())
        );
        println!(
            "  single-core throughput = {:.0} ops/s → 200 k/core bar: {}",
            r.point(1).map_or(0.0, |p| p.per_core_ops_s),
            if r.meets_200k_single_core() {
                "MET"
            } else {
                "MISS"
            }
        );
        let single_us = r
            .point(1)
            .map(|p| 1_000_000.0 / p.per_core_ops_s.max(f64::MIN_POSITIVE));
        if let Some(us) = single_us {
            println!("  ⇒ engine cost ≈ {us:.3} µs/op (single thread, {cores}-core host)");
        }
        println!();
    }

    print_summary(results);
}

fn print_summary(results: &[OpResult]) {
    println!("═══ Summary ═══\n");
    println!("op [state]              | 1T/core ops/s | 16T agg ops/s | scaling | eff | 200k/core | verdict");
    println!("------------------------+---------------+---------------+---------+-----+-----------+--------");
    for r in results {
        let (slope, _) = r.scaling_exponent();
        let top = r
            .points
            .iter()
            .max_by_key(|p| p.threads)
            .map_or(0.0, |p| p.agg_ops_s);
        println!(
            "{:<23} | {:>13.0} | {:>13.0} | {:>+7.3} | {:>3.2} | {:>9} | {}",
            r.label(),
            r.point(1).map_or(0.0, |p| p.per_core_ops_s),
            top,
            slope,
            r.efficiency(),
            if r.meets_200k_single_core() {
                "MET"
            } else {
                "MISS"
            },
            scaling_verdict(slope, r.efficiency()),
        );
    }
    println!();
    println!(
        "Engine-cost floor only. The HTTP/axum/tokio delta on top is NOT-MEASURABLE in this\n\
         environment (HEA-1871 C3 / HEA-1876 C8: the generator, not the server, is the ceiling).\n\
         Reads are lock-free hot-path (epoch-reclaimed, ArcSwap caches) and are expected to scale;\n\
         session_create is WAL-fsync-serialized and is expected to contend."
    );
}

/// Scales-vs-contends verdict from the fitted exponent and 1→16T efficiency.
fn scaling_verdict(slope: f64, efficiency: f64) -> &'static str {
    if slope >= 0.85 && efficiency >= 0.80 {
        "SCALES (near-linear)"
    } else if slope >= 0.5 && efficiency >= 0.4 {
        "PARTIAL (some contention)"
    } else {
        "CONTENDS (serialized/shared bottleneck)"
    }
}

/// Least-squares slope and R² of `ys` on `xs`.
fn linreg(xs: &[f64], ys: &[f64]) -> (f64, f64) {
    let m = xs.len() as f64;
    let mean_x = xs.iter().sum::<f64>() / m;
    let mean_y = ys.iter().sum::<f64>() / m;
    let (mut sxx, mut sxy, mut syy) = (0.0, 0.0, 0.0);
    for (&x, &y) in xs.iter().zip(ys) {
        sxx += (x - mean_x) * (x - mean_x);
        sxy += (x - mean_x) * (y - mean_y);
        syy += (y - mean_y) * (y - mean_y);
    }
    let slope = if sxx == 0.0 { 0.0 } else { sxy / sxx };
    let r2 = if sxx == 0.0 || syy == 0.0 {
        1.0
    } else {
        (sxy * sxy) / (sxx * syy)
    };
    (slope, r2)
}

fn emit_json(results: &[OpResult], cores: usize) {
    println!("===JSON===");
    let ops: Vec<String> = results
        .iter()
        .map(|r| {
            let (slope, r2) = r.scaling_exponent();
            let pts: Vec<String> = r
                .points
                .iter()
                .map(|p| {
                    format!(
                        "{{\"threads\":{},\"ops\":{},\"elapsed_s\":{:.4},\
                         \"agg_ops_s\":{:.1},\"per_core_ops_s\":{:.1}}}",
                        p.threads, p.ops, p.elapsed_s, p.agg_ops_s, p.per_core_ops_s
                    )
                })
                .collect();
            format!(
                "{{\"op\":\"{}\",\"state\":\"{}\",\"scaling_exponent\":{:.4},\
                 \"scaling_r2\":{:.4},\"efficiency_1_to_16\":{:.4},\
                 \"meets_200k_single_core\":{},\"points\":[{}]}}",
                r.op,
                r.state,
                slope,
                r2,
                r.efficiency(),
                r.meets_200k_single_core(),
                pts.join(",")
            )
        })
        .collect();
    println!(
        "{{\"child_issue\":\"HEA-1875\",\"host_logical_cores\":{},\"measure_secs\":{},\
         \"users\":{},\"warm_sessions\":{},\"miss_sessions\":{},\
         \"vision_ops_per_core\":{},\"http_split\":\"NOT-MEASURABLE (HEA-1871/HEA-1876)\",\
         \"operations\":[{}]}}",
        cores,
        MEASURE.as_secs(),
        USERS,
        SESSIONS,
        MISS_SESSIONS,
        VISION_OPS_PER_CORE,
        ops.join(",")
    );
}
