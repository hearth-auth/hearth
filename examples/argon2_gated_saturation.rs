//! HEA-1887 · R1 — Argon2id saturation **with** the bounded KDF admission gate.
//!
//! Companion to `argon2_saturation.rs` (C9/HEA-1879), which measured the
//! *ungated* path and confirmed the multi-second p99 was queueing under
//! `spawn_blocking` oversubscription, not Argon2id compute. This harness runs
//! the same offered-concurrency ladder **through [`hearth::identity::KdfGate`]**
//! and reports, per rung:
//!
//! - `admitted p99` — latency of the ops that ran (queue-wait + compute), which
//!   should stay near `compute_floor + short bounded queue` instead of growing
//!   with offered depth, and
//! - `shed` — how many ops past the bound were rejected fast (`Overloaded`)
//!   rather than piling onto the queue and inflating the tail.
//!
//! The mechanism is proved deterministically by the `identity::kdf_gate` unit
//! tests; this example demonstrates it under the real Argon2id cost so the delta
//! can be appended to `docs/perf/HEA-1879-C9-issuance-triage.md`.
//!
//! Run (permits default to the core count, matching the shipped default):
//! `cargo run --release --example argon2_gated_saturation -- \
//!    $(git rev-parse --short HEAD) $(date -u +%Y-%m-%dT%H:%M:%SZ)`
//!
//! Optional 3rd arg overrides the permit count (else = core count).
//!
//! ## Admissibility
//!
//! Same `/proc/vmstat` swap accounting and `void` rule as the C9 harness: this
//! host swaps continuously, so a rung with > 512 swap-in pages is flagged
//! `void`. An isolated host (C3/HEA-1871) is required for a citable absolute p99.

// Measurement binary: casts are for reporting math on small magnitudes.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::fs;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hearth::identity::{
    hash_password, CleartextPassword, CredentialConfig, KdfGate, KdfGateConfig, KdfGateError,
};

/// Offered-concurrency ladder — the number of hash *requests* fired at once.
/// Spans below, at, and well past the core count so the gate's admitted-latency
/// plateau and the onset of shedding are both visible.
const OFFERED_LADDER: &[usize] = &[1, 2, 4, 8, 16, 32, 64];

/// Bounded queue-wait before an offered op sheds. Matches the shipped default.
const MAX_QUEUE_WAIT: Duration = Duration::from_millis(250);

/// Warm-up hashes discarded before measurement (allocator / page-cache warmup).
const WARMUP_HASHES: usize = 3;

/// Swap-in pages above which a rung is treated as swap-affected (see C9 harness).
const VOID_SWAP_PAGE_THRESHOLD: u64 = 512;

/// Reads a named counter from `/proc/vmstat` (0 if unavailable).
fn vmstat(key: &str) -> u64 {
    fs::read_to_string("/proc/vmstat")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with(key))
                .and_then(|l| l.split_whitespace().nth(1).map(str::to_owned))
        })
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// Reads the cpu0 scaling governor.
fn governor() -> String {
    fs::read_to_string("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
        .map(|s| s.trim().to_owned())
        .unwrap_or_else(|_| "unknown".to_owned())
}

/// Percentile (nearest-rank) over a sorted slice of microsecond samples.
fn pct(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = ((p / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[rank.min(sorted.len() - 1)]
}

/// One measured rung of the gated ladder.
struct GatedRung {
    offered: usize,
    admitted: usize,
    shed: usize,
    p50_us: u64,
    p99_us: u64,
    max_us: u64,
    swap_in_pages: u64,
    void_due_to_swap: bool,
}

/// Fires `offered` concurrent hash requests through the shared gate and records
/// the admitted-op latency distribution and the shed count.
async fn measure_gated_rung(gate: Arc<KdfGate>, offered: usize) -> GatedRung {
    let cfg = CredentialConfig::default(); // production: 19 MiB, t=2, p=1
    let now_micros: i64 = 1_753_660_800_000_000;

    let swp_in_0 = vmstat("pswpin");

    let mut handles = Vec::with_capacity(offered);
    for w in 0..offered {
        let gate = gate.clone();
        let cfg = cfg.clone();
        handles.push(tokio::spawn(async move {
            let t0 = Instant::now();
            let outcome = gate
                .run(move || {
                    let pw =
                        CleartextPassword::from_string(format!("correct horse battery staple {w}"));
                    hash_password(&pw, &cfg, now_micros).map(|_| ())
                })
                .await;
            // Total request latency = queue wait + compute (or shed detection).
            let elapsed = t0.elapsed().as_micros() as u64;
            match outcome {
                Ok(Ok(())) => (Some(elapsed), false),
                Ok(Err(_hash_err)) => (None, false),
                Err(KdfGateError::Overloaded { .. }) => (None, true),
                // KdfGateError is #[non_exhaustive]; Join and any future variant
                // are neither admitted-latency samples nor sheds.
                Err(_) => (None, false),
            }
        }));
    }

    let mut admitted_us: Vec<u64> = Vec::with_capacity(offered);
    let mut shed = 0usize;
    for h in handles {
        if let Ok((sample, was_shed)) = h.await {
            if let Some(us) = sample {
                admitted_us.push(us);
            }
            if was_shed {
                shed += 1;
            }
        }
    }
    admitted_us.sort_unstable();

    let swap_in = vmstat("pswpin").saturating_sub(swp_in_0);
    GatedRung {
        offered,
        admitted: admitted_us.len(),
        shed,
        p50_us: pct(&admitted_us, 50.0),
        p99_us: pct(&admitted_us, 99.0),
        max_us: admitted_us.last().copied().unwrap_or(0),
        swap_in_pages: swap_in,
        void_due_to_swap: swap_in > VOID_SWAP_PAGE_THRESHOLD,
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let git_sha = args.get(1).cloned().unwrap_or_else(|| "UNKNOWN".to_owned());
    let timestamp = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_owned());

    let cores = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    let permits = args
        .get(3)
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|p| *p >= 1)
        .unwrap_or(cores);
    let gov = governor();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        // Warm up on a single blocking thread.
        {
            let cfg = CredentialConfig::default();
            let pw = CleartextPassword::from_string("warmup".to_owned());
            for _ in 0..WARMUP_HASHES {
                let _ = hash_password(&pw, &cfg, 0);
            }
        }

        let gate = Arc::new(KdfGate::new(KdfGateConfig {
            max_in_flight: permits,
            max_queue_wait: MAX_QUEUE_WAIT,
            retry_after: Duration::from_secs(1),
        }));

        let mut rungs = Vec::new();
        for &offered in OFFERED_LADDER {
            rungs.push(measure_gated_rung(gate.clone(), offered).await);
        }

        println!("# HEA-1887 R1 — gated Argon2id saturation");
        println!(
            "# git_sha={git_sha} ts={timestamp} cores={cores} permits={permits} \
             max_queue_wait_ms={} governor={gov}",
            MAX_QUEUE_WAIT.as_millis()
        );
        println!("# offered | admitted | shed | p50_ms | p99_ms | max_ms | swap_in | void");
        for r in &rungs {
            println!(
                "{:>7} | {:>8} | {:>4} | {:>6.1} | {:>6.1} | {:>6.1} | {:>7} | {}",
                r.offered,
                r.admitted,
                r.shed,
                r.p50_us as f64 / 1000.0,
                r.p99_us as f64 / 1000.0,
                r.max_us as f64 / 1000.0,
                r.swap_in_pages,
                r.void_due_to_swap
            );
        }
        println!(
            "# Interpretation: admitted p99 stays near compute_floor + bounded queue \
             (<= ~{permits}x compute) instead of growing with offered depth; ops past \
             the bound show up as `shed`, not as p99 inflation."
        );
    });
    Ok(())
}
