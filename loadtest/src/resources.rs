//! Server-side resource sampling (HEA-1811).
//!
//! Goose measures only client-observed latency/throughput/response codes — it
//! has no visibility into the Hearth server's own resource use. A run whose p99
//! is in budget but whose server is pinned at 100% CPU or climbing toward an OOM
//! is *not* healthy, and the client-side report cannot tell the difference. This
//! module samples the server process (`RSS` + `CPU%`) on a low-frequency
//! interval so a "saturation" verdict means "p99 in budget **and** the server is
//! not resource-starved."
//!
//! Sampling is Linux-only (reads `/proc/<pid>/stat` + `/proc/<pid>/status`). On
//! any other platform, or when the pid is unknown/unreadable, no samples are
//! collected and no `resources` block is emitted — the rest of the report is
//! unaffected. Polling at 1 s keeps the sampler off the hot path entirely.
//!
//! The parsing ([`parse_vm_rss_bytes`], [`parse_cpu_ticks`]) and aggregation
//! ([`summarize`]) are pure so every branch is unit-testable without a live
//! process.

use std::time::{Duration, Instant};

use serde::Serialize;

/// Default poll interval — low enough that sampling cannot perturb the hot path.
const DEFAULT_INTERVAL_MS: u64 = 1000;

/// Kernel `USER_HZ`: `utime`/`stime` in `/proc/<pid>/stat` are counted in clock
/// ticks, and CPU% derives from ticks-per-wall-second. `USER_HZ` is a fixed
/// kernel ABI constant, effectively always `100` on Linux (`getconf CLK_TCK`);
/// we assume that rather than pull in `libc` for one `sysconf` call.
const USER_HZ: f64 = 100.0;

/// Folded server resource-consumption figures for a run, serialized as the JSON
/// report's `resources` block (schema ≥ 3) and rendered into the HTML report.
///
/// `None` peaks are impossible here: the block is only emitted when at least two
/// samples were collected (CPU% needs a delta), so every field is populated.
#[derive(Debug, Clone, Serialize)]
pub struct ResourceReport {
    /// PID that was sampled.
    pub pid: u32,
    /// Number of samples folded into these figures.
    pub samples: usize,
    /// Poll interval used, in milliseconds.
    pub interval_ms: u64,
    /// Peak resident set size observed, in bytes.
    pub rss_peak_bytes: u64,
    /// Mean resident set size across all samples, in bytes.
    pub rss_mean_bytes: u64,
    /// Peak CPU utilisation across any single sample interval, as a percentage
    /// of one core (a multi-threaded server can exceed `100`).
    pub cpu_peak_pct: f64,
    /// Mean CPU utilisation across the whole sampled window, as a percentage of
    /// one core.
    pub cpu_mean_pct: f64,
}

/// One point-in-time reading of the sampled process.
#[derive(Debug, Clone, Copy)]
struct Sample {
    /// Seconds elapsed since sampling began (monotonic).
    elapsed_secs: f64,
    /// Resident set size in bytes at this instant.
    rss_bytes: u64,
    /// Cumulative CPU time (`utime + stime`) in clock ticks at this instant.
    cpu_ticks: u64,
}

/// Parses `VmRSS` (in bytes) from the contents of `/proc/<pid>/status`.
///
/// The line reads `VmRSS:\t   12345 kB`; the kB value is scaled to bytes.
/// `None` if the field is absent or malformed.
#[must_use]
fn parse_vm_rss_bytes(status: &str) -> Option<u64> {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

/// Parses cumulative CPU ticks (`utime + stime`) from `/proc/<pid>/stat`.
///
/// The `comm` field (2nd) is parenthesised and may itself contain spaces and
/// parens, so fields are counted from **after the last `)`**: the first token
/// there is field 3 (`state`), making `utime` (field 14) index 11 and `stime`
/// (field 15) index 12. `None` if the layout is unexpected.
#[must_use]
fn parse_cpu_ticks(stat: &str) -> Option<u64> {
    let rparen = stat.rfind(')')?;
    let fields: Vec<&str> = stat[rparen + 1..].split_whitespace().collect();
    let utime: u64 = fields.get(11)?.parse().ok()?;
    let stime: u64 = fields.get(12)?.parse().ok()?;
    Some(utime.saturating_add(stime))
}

/// Rounds a percentage to two decimals so the JSON stays tidy.
fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}

/// Folds a sample series into peak/mean RSS and peak/mean CPU%.
///
/// Returns `None` when fewer than two samples were collected — CPU% is a
/// tick-delta over a wall-clock delta and is undefined for a single point.
#[must_use]
#[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
fn summarize(samples: &[Sample], pid: u32, interval_ms: u64) -> Option<ResourceReport> {
    if samples.len() < 2 {
        return None;
    }
    let n = samples.len();

    let rss_peak_bytes = samples.iter().map(|s| s.rss_bytes).max()?;
    let rss_sum: u128 = samples.iter().map(|s| u128::from(s.rss_bytes)).sum();
    let rss_mean_bytes = (rss_sum / n as u128) as u64;

    // Peak CPU% over any single inter-sample interval.
    let mut cpu_peak_pct = 0.0_f64;
    for w in samples.windows(2) {
        let dt = w[1].elapsed_secs - w[0].elapsed_secs;
        if dt <= 0.0 {
            continue;
        }
        let dticks = w[1].cpu_ticks.saturating_sub(w[0].cpu_ticks) as f64;
        let pct = (dticks / USER_HZ) / dt * 100.0;
        if pct > cpu_peak_pct {
            cpu_peak_pct = pct;
        }
    }

    // Mean CPU% across the whole sampled window.
    let total_dt = samples[n - 1].elapsed_secs - samples[0].elapsed_secs;
    let cpu_mean_pct = if total_dt > 0.0 {
        let dticks = samples[n - 1]
            .cpu_ticks
            .saturating_sub(samples[0].cpu_ticks) as f64;
        (dticks / USER_HZ) / total_dt * 100.0
    } else {
        0.0
    };

    Some(ResourceReport {
        pid,
        samples: n,
        interval_ms,
        rss_peak_bytes,
        rss_mean_bytes,
        cpu_peak_pct: round2(cpu_peak_pct),
        cpu_mean_pct: round2(cpu_mean_pct),
    })
}

/// Reads one sample for `pid` from `/proc`. `None` on any read/parse failure
/// (process gone, non-Linux, unexpected layout) so a transient miss is simply
/// skipped rather than aborting the run.
fn sample_proc(pid: u32, started: Instant) -> Option<Sample> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    Some(Sample {
        elapsed_secs: started.elapsed().as_secs_f64(),
        rss_bytes: parse_vm_rss_bytes(&status)?,
        cpu_ticks: parse_cpu_ticks(&stat)?,
    })
}

/// A background sampler polling a server process for RSS/CPU during a run.
///
/// [`start`](Self::start) spawns a Tokio task that reads `/proc/<pid>` every
/// [`DEFAULT_INTERVAL_MS`]; [`stop`](Self::stop) signals it, awaits the samples,
/// and folds them into a [`ResourceReport`]. Sampling runs on the same runtime
/// as the attack but does no hot-path work — a `/proc` read once per second.
pub struct ResourceSampler {
    pid: u32,
    interval_ms: u64,
    stop_tx: tokio::sync::oneshot::Sender<()>,
    handle: tokio::task::JoinHandle<Vec<Sample>>,
}

impl ResourceSampler {
    /// Starts sampling `pid` at the default interval on the current runtime.
    #[must_use]
    pub fn start(pid: u32) -> Self {
        let interval_ms = DEFAULT_INTERVAL_MS;
        let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(async move {
            let started = Instant::now();
            let mut samples: Vec<Sample> = Vec::new();
            let mut ticker = tokio::time::interval(Duration::from_millis(interval_ms));
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        if let Some(s) = sample_proc(pid, started) {
                            samples.push(s);
                        }
                    }
                    _ = &mut stop_rx => break,
                }
            }
            samples
        });
        Self {
            pid,
            interval_ms,
            stop_tx,
            handle,
        }
    }

    /// Stops sampling and folds the collected series into a report. `None` when
    /// fewer than two samples were gathered (a very short run, or a pid that was
    /// never readable — e.g. off Linux).
    pub async fn stop(self) -> Option<ResourceReport> {
        // Best-effort: if the task already ended, the send just fails.
        let _ = self.stop_tx.send(());
        let samples = self.handle.await.unwrap_or_default();
        summarize(&samples, self.pid, self.interval_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_vm_rss_scales_kb_to_bytes() {
        let status = "Name:\thearth\nVmPeak:\t  204800 kB\nVmRSS:\t   12345 kB\nThreads:\t8\n";
        assert_eq!(parse_vm_rss_bytes(status), Some(12345 * 1024));
    }

    #[test]
    fn parse_vm_rss_absent_is_none() {
        assert_eq!(parse_vm_rss_bytes("Name:\thearth\nThreads:\t8\n"), None);
    }

    #[test]
    fn parse_cpu_ticks_handles_comm_with_spaces_and_parens() {
        // comm = "(weird )name)" — spaces and an inner ')' must not confuse the
        // field split, which keys off the LAST ')'. Fields 3.. after it:
        // state=R ppid=1 ... utime(14)=500 stime(15)=123.
        let stat = "42 (weird )name) R 1 1 1 0 -1 0 0 0 0 0 500 123 0 0 20 0 8 0 999";
        assert_eq!(parse_cpu_ticks(stat), Some(500 + 123));
    }

    #[test]
    fn parse_cpu_ticks_truncated_is_none() {
        assert_eq!(parse_cpu_ticks("42 (hearth) R 1 1"), None);
    }

    fn sample(elapsed_secs: f64, rss_bytes: u64, cpu_ticks: u64) -> Sample {
        Sample {
            elapsed_secs,
            rss_bytes,
            cpu_ticks,
        }
    }

    #[test]
    fn summarize_needs_two_samples() {
        assert!(summarize(&[], 1, 1000).is_none());
        assert!(summarize(&[sample(0.0, 100, 0)], 1, 1000).is_none());
    }

    #[test]
    fn summarize_folds_peak_and_mean() {
        // 3 samples, 1 s apart. RSS: 100, 300, 200 → peak 300, mean 200.
        // CPU ticks: 0, 100, 130. USER_HZ=100 ⇒ 1 tick = 10 ms.
        //   interval 0→1: 100 ticks / 1 s = 100% peak.
        //   interval 1→2: 30 ticks / 1 s = 30%.
        //   mean over 2 s: 130 ticks / 2 s = 65%.
        let samples = [
            sample(0.0, 100, 0),
            sample(1.0, 300, 100),
            sample(2.0, 200, 130),
        ];
        let r = summarize(&samples, 4242, 1000).expect("two+ samples fold");
        assert_eq!(r.pid, 4242);
        assert_eq!(r.samples, 3);
        assert_eq!(r.rss_peak_bytes, 300);
        assert_eq!(r.rss_mean_bytes, 200);
        assert!(
            (r.cpu_peak_pct - 100.0).abs() < 1e-6,
            "peak {}",
            r.cpu_peak_pct
        );
        assert!(
            (r.cpu_mean_pct - 65.0).abs() < 1e-6,
            "mean {}",
            r.cpu_mean_pct
        );
    }

    #[test]
    fn summarize_ignores_nonpositive_intervals() {
        // A duplicate timestamp (dt=0) must not divide-by-zero or spike the peak.
        let samples = [
            sample(0.0, 100, 0),
            sample(0.0, 100, 50),
            sample(1.0, 100, 100),
        ];
        let r = summarize(&samples, 1, 1000).expect("folds");
        // The dt=0 window is skipped (no div-by-zero, no spike). The only valid
        // window spans 50→100 ticks over 1 s ⇒ 50%. Mean over the 0→1 s total
        // window is 100 ticks / 1 s = 100%.
        assert!(
            (r.cpu_peak_pct - 50.0).abs() < 1e-6,
            "peak {}",
            r.cpu_peak_pct
        );
        assert!(
            (r.cpu_mean_pct - 100.0).abs() < 1e-6,
            "mean {}",
            r.cpu_mean_pct
        );
    }
}
