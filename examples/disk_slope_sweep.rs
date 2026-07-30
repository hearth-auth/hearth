//! HEA-1951 · C0 disk-slope sweep — WAL/SST split across N
//!
//! Re-runs the C0 disk-slope measurement across a range of corpus sizes,
//! separating WAL bytes from SST bytes at each checkpoint to demonstrate WAL
//! rotation and the asymptotic SST/user slope that determines the K7 verdict.
//!
//! ## Why this exists
//!
//! The HEA-1904 C0 run measured at N=12,000 and reported 2,840 B/user, of which
//! 59% was WAL. WAL disk is hard-bounded at `max_size` (64 MiB default) — O(1),
//! not O(N). That 59% disappears once the WAL has rotated.
//!
//! At N=60,000 the WAL first rotated and disk/user fell to 1,738 B with SST/user
//! at 1,192 B. This sweep extends that single data point to a range (default
//! 5k → 200k) to confirm SST/user stays flat as N grows, and to fit an OLS
//! line to the SST bytes as the authoritative K7 slope.
//!
//! ## Code state
//!
//! Commit `abf179ba` (feature/perf-updates-7-28-26). The duplicate-`UserCreated`
//! bug (HEA-1946 §3.3) is **not yet fixed** in this code state — every user
//! carries one extra audit-event chain from the identity layer. The probe
//! therefore includes the second audit event explicitly (mirroring what
//! `admin_create_user` in `src/protocol/http/admin.rs` also emits), and the
//! reported SST/user reflects the current unfixed state. A re-run is expected
//! after the fix lands.
//!
//! ## Method
//!
//! 1. Seed through `EmbeddedIdentityEngine::create_user` (same path as the load
//!    test that produced the 2,840 B/user baseline), plus a second `UserCreated`
//!    audit event per user as `admin_create_user` does.
//! 2. Stop at each checkpoint N and stat the data directory.
//! 3. Partition files into WAL (`*.wal` / contains "wal") and SST (`.sst`).
//! 4. Fit OLS: `sst_bytes = m × N + b`. Slope m is the asymptotic SST/user.
//! 5. Report PASS/MISS against the K7 budget (200 GiB @ 100M users = 2,147 B/user).
//!
//! Run:  `cargo run --release --example disk_slope_sweep [N1 N2 ...]`
//! Default checkpoints: 5000 20000 60000 100000 150000 200000

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_lines
)]

use hearth::audit::{AuditAction, AuditEngine, CreateAuditEvent, EmbeddedAuditEngine};
use hearth::core::{Clock, RealmId, SystemClock};
use hearth::identity::{
    CreateRealmRequest, CreateUserRequest, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine,
};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

/// K7 budget: 200 GiB @ 100M users → 2,147 B/user.
const K7_BUDGET_BYTES_PER_USER: f64 = 2147.0;

/// Default sweep checkpoints (user counts at which disk is measured).
const DEFAULT_CHECKPOINTS: &[usize] = &[5_000, 20_000, 60_000, 100_000, 150_000, 200_000];

/// Commit SHA measured. Embedded at compile time if set; otherwise informational.
const COMMIT_SHA: &str = "abf179ba (duplicate-UserCreated NOT yet fixed)";

/// Recursively sums file bytes in `dir`, partitioned into (WAL, SST, other).
fn disk_usage(dir: &Path) -> (u64, u64, u64) {
    let (mut wal, mut sst, mut other) = (0u64, 0u64, 0u64);
    let mut stack = vec![dir.to_path_buf()];
    while let Some(p) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&p) else {
            continue;
        };
        for entry in rd.flatten() {
            let path = entry.path();
            let Ok(md) = entry.metadata() else { continue };
            if md.is_dir() {
                stack.push(path);
            } else if md.is_file() {
                let name = path.to_string_lossy().to_lowercase();
                let len = md.len();
                if name.contains("wal") {
                    wal += len;
                } else if Path::new(&*name)
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("sst"))
                {
                    sst += len;
                } else {
                    other += len;
                }
            }
        }
    }
    (wal, sst, other)
}

/// Ordinary-least-squares fit: `y = m·x + b`.
///
/// Returns `(slope, intercept, r_squared)`.
fn ols(xs: &[f64], ys: &[f64]) -> (f64, f64, f64) {
    assert_eq!(xs.len(), ys.len());
    let n = xs.len() as f64;
    let sx: f64 = xs.iter().sum();
    let sy: f64 = ys.iter().sum();
    let sxx: f64 = xs.iter().map(|x| x * x).sum();
    let sxy: f64 = xs.iter().zip(ys).map(|(x, y)| x * y).sum();
    let m = (n * sxy - sx * sy) / (n * sxx - sx * sx);
    let b = (sy - m * sx) / n;
    let mean_y = sy / n;
    let ss_tot: f64 = ys.iter().map(|y| (y - mean_y).powi(2)).sum();
    let ss_res: f64 = xs
        .iter()
        .zip(ys)
        .map(|(x, y)| (y - (m * x + b)).powi(2))
        .sum();
    let r_sq = 1.0 - ss_res / ss_tot.max(1e-12);
    (m, b, r_sq)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut checkpoints: Vec<usize> = if args.len() > 1 {
        args[1..].iter().filter_map(|s| s.parse().ok()).collect()
    } else {
        DEFAULT_CHECKPOINTS.to_vec()
    };
    checkpoints.sort_unstable();
    checkpoints.dedup();
    let max_n = *checkpoints.last().expect("at least one checkpoint");

    println!("HEA-1951 · C0 disk-slope sweep — WAL/SST split across N");
    println!("Commit:         {COMMIT_SHA}");
    println!("Checkpoints:    {checkpoints:?}");
    println!("Max N:          {max_n}");
    println!("WAL max_size:   64 MiB (StorageConfig::dev default)");
    println!("Rotation at ~N: ~22,600 users (64 MiB ÷ 2,840 B/user)");
    println!();

    // -------------------------------------------------------------- engine setup
    // StorageConfig::dev() uses 64 MiB WAL — identical to the production default
    // and to the --dev server used in the HEA-1904 C0 baseline.
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf()))
            .expect("open storage"),
    ) as Arc<dyn StorageEngine>;
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    )) as Arc<dyn AuditEngine>;
    let identity = EmbeddedIdentityEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
        IdentityConfig::default(),
        Arc::clone(&audit),
    )
    .expect("identity engine");

    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: "slope-sweep".to_string(),
            config: None,
        })
        .expect("create realm");
    let realm_id: RealmId = realm.id().clone();

    // -------------------------------------------------------------- sweep table
    println!(
        "{:>9} | {:>13} | {:>13} | {:>9} | {:>9} | {:>9} | rot",
        "N", "WAL bytes", "SST bytes", "WAL/user", "SST/user", "tot/user"
    );
    println!("{}", "-".repeat(82));

    // Measurements: (N, wal_bytes, sst_bytes) at each checkpoint.
    let mut meas: Vec<(f64, f64, f64)> = Vec::new();
    let mut prev_wal: u64 = 0;
    let mut rotation_count: usize = 0;

    let mut cp_iter = checkpoints.iter().peekable();
    let mut next_cp = *cp_iter.next().expect("checkpoints must be non-empty");

    let sweep_start = Instant::now();

    for i in 0..max_n {
        // Create user i.  Email pattern matches loadtest/src/params.rs so the
        // per-user record shape is identical to the C0 baseline corpus.
        let email = format!("loaduser-1-r0-u{i}@loadtest.test");
        let user = identity
            .create_user(
                &realm_id,
                &CreateUserRequest {
                    email,
                    display_name: "Load Test User".to_string(),
                    first_name: String::new(),
                    last_name: String::new(),
                    attributes: Default::default(),
                },
            )
            .expect("create_user");

        // Second audit event: mirrors admin_create_user in
        // src/protocol/http/admin.rs exactly. This is the pair that produced
        // the 2,840 B/user baseline.
        audit
            .append(&CreateAuditEvent {
                realm_id: realm_id.clone(),
                actor: user.id().as_uuid().to_string(),
                action: AuditAction::UserCreated,
                resource_type: "user".to_string(),
                resource_id: user.id().as_uuid().to_string(),
                metadata: Some(serde_json::json!({"via": "admin_api"})),
            })
            .expect("audit append");

        // Measure after creating the (i+1)-th user.
        let n_done = i + 1;
        if n_done == next_cp {
            let (wal_b, sst_b, _other) = disk_usage(dir.path());
            let n = n_done as f64;
            let wal_per = wal_b as f64 / n;
            let sst_per = sst_b as f64 / n;
            let tot_per = (wal_b + sst_b) as f64 / n;

            // Rotation detected when WAL file shrinks (set_len(0) after flush).
            let rotated = if wal_b < prev_wal {
                rotation_count += 1;
                true
            } else {
                false
            };
            prev_wal = wal_b;

            let rot_label = if rotated {
                format!("#{rotation_count}")
            } else {
                String::new()
            };

            println!(
                "{:>9} | {:>13} | {:>13} | {:>9.0} | {:>9.0} | {:>9.0} | {}",
                n_done, wal_b, sst_b, wal_per, sst_per, tot_per, rot_label
            );

            meas.push((n, wal_b as f64, sst_b as f64));

            match cp_iter.next() {
                Some(&cp) => next_cp = cp,
                None => break,
            }
        }
    }

    let sweep_secs = sweep_start.elapsed().as_secs_f64();
    println!();
    println!(
        "Sweep time: {sweep_secs:.1} s  ({:.3} ms/user)",
        sweep_secs * 1000.0 / max_n as f64
    );
    println!("WAL rotations detected: {rotation_count}");
    println!();

    // ------------------------------------------------------------ OLS analysis
    // Use only post-rotation checkpoints (WAL has flattened ≈ max_size / N → 0).
    // The first WAL rotation occurs at ~22,600 users; use N >= 60,000 as a
    // conservative post-rotation threshold that guarantees at least 2 rotations.
    let post_rot: Vec<(f64, f64)> = meas
        .iter()
        .filter(|(n, _, _)| *n >= 60_000.0)
        .map(|(n, _, sst)| (*n, *sst))
        .collect();

    println!("=== OLS fit — SST bytes vs N (post-rotation, N >= 60k) ===");

    if post_rot.len() < 2 {
        println!("INSUFFICIENT DATA: need at least 2 post-rotation checkpoints.");
        println!("Re-run with N >= 120,000 (e.g. 60000 100000 150000).");
        return;
    }

    let xs: Vec<f64> = post_rot.iter().map(|(n, _)| *n).collect();
    let ys: Vec<f64> = post_rot.iter().map(|(_, s)| *s).collect();
    let (m, b, r_sq) = ols(&xs, &ys);

    println!("  SST_bytes = {m:.2} × N  +  {b:.0}");
    println!("  R²         = {r_sq:.6}  (1.0 = perfect linear fit)");
    println!();

    // SST/user residuals at each post-rotation checkpoint.
    println!(
        "  {:>9}  {:>9}  {:>9}  {:>9}",
        "N", "SST/user", "fitted", "residual"
    );
    println!("  {}", "-".repeat(45));
    for (n, sst) in &post_rot {
        let measured = sst / n;
        let fitted = (m * n + b) / n;
        let residual = measured - fitted;
        println!(
            "  {:>9.0}  {:>9.1}  {:>9.1}  {:>+9.1}",
            n, measured, fitted, residual
        );
    }
    println!();

    let gib_100m = m * 100_000_000.0 / (1024.0_f64.powi(3));
    let headroom = K7_BUDGET_BYTES_PER_USER / m;
    let verdict = if m < K7_BUDGET_BYTES_PER_USER {
        "PASS"
    } else {
        "MISS"
    };

    println!("=== K7 verdict ===");
    println!("  OLS SST/user slope : {m:.1} B/user");
    println!("  K7 budget          : {K7_BUDGET_BYTES_PER_USER:.0} B/user  (200 GiB @ 100M)");
    println!("  Projected @ 100M   : {gib_100m:.1} GiB");
    println!("  Headroom           : {headroom:.2}×");
    println!("  K7 VERDICT         : {verdict}");
    println!();

    if verdict == "PASS" {
        println!("  The WAL term is O(1) (max 64 MiB, confirmed by {rotation_count} rotations).");
        println!("  Asymptotically disk/user → SST/user = {m:.1} B, which extrapolates to");
        println!("  {gib_100m:.1} GiB @100M — {headroom:.2}× inside the 200 GiB K7 budget.");
        println!("  The K7 MISS in PERFORMANCE_REPORT v2 was a small-N measurement artifact.");
        if COMMIT_SHA.contains("duplicate-UserCreated NOT") {
            println!();
            println!(
                "  NOTE: measured on code with the duplicate-UserCreated bug (HEA-1946 §3.3)."
            );
            println!(
                "  After that fix lands, SST/user is expected to drop by ~39.5% → ~{:.0} B/user.",
                m * 0.605
            );
            println!("  Re-run this sweep after the fix to update the K7 projection.");
        }
    } else {
        println!("  SST/user ({m:.1} B) exceeds the K7 budget ({K7_BUDGET_BYTES_PER_USER:.0} B).");
        println!("  Compression (Option A) or the duplicate-UserCreated fix is required.");
    }
}
