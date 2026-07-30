//! Host-environment capture and the **quiescence gate** for perf harnesses.
//!
//! # Why this exists
//!
//! HEA-1967 re-ran the C11 `http_delta` harness and got HTTP-plane numbers up to
//! **4.8× worse** than the 2.1a run — while the *engine* phase out of the same
//! binary, in the same run, got **25% better**. No code path produces that. The
//! measured cause was host contention: `load average 16.45` on a 16-thread part
//! with a browser, an IDE and an agent harness resident. The HTTP phase is the
//! only phase that must sustain a request generator *and* a server on contended
//! cores, so it is the phase that collapses first.
//!
//! The lesson, per HEA-1974 AC1: **a run on a contended box is not a result.**
//! Quiescence therefore has to be enforced by the harness and recorded in the
//! artifact, not asserted in prose by whoever happened to run it.
//!
//! # What this module does
//!
//! * Captures a [`HostProfile`] — CPU model, topology, scaling governor, CPU
//!   isolation, chassis class, thermal state.
//! * Captures a [`LoadSnapshot`] + [`ProcessCensus`] before and after a run.
//! * Applies a [`Gate`] that decides whether the resulting numbers may be
//!   published, and records *why not* when they may not.
//!
//! # The escape hatch is deliberately lossy
//!
//! `--allow-contended-host` lets a run proceed on a box that fails the gate, but
//! it stamps `publishable: false` into the artifact along with every violation.
//! You cannot get a clean artifact off a dirty host. That is the point: the
//! failure mode being designed against is a contended run being *mistaken* for a
//! quiesced one six weeks later, which is exactly what happened to 2.1a.

// Measurement support code: reporting math on small magnitudes, and the capture
// helpers are intentionally verbose for auditability.
#![allow(
    dead_code,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::collections::HashMap;
use std::fmt::Write as _;
use std::time::Duration;

// ── Thresholds ────────────────────────────────────────────────────────────────

/// Maximum tolerated pre-run 1-minute load average, **per visible CPU**.
///
/// Foreign load must be under 5% of host capacity before a measurement window
/// opens. On a 16-thread part that is `load1 <= 0.80`. For reference, the run
/// that produced the unreproducible HEA-1967 HTTP figures sat at `16.45`, or
/// `1.03` per core — twenty times this bar.
pub const MAX_PRERUN_LOAD_PER_CPU: f64 = 0.05;

/// Maximum tolerated CPU share of any single foreign process, in percent of one
/// core, sampled over [`CENSUS_INTERVAL`].
///
/// A low aggregate load average can still hide one busy neighbour that lands on
/// the same core as the generator, so the aggregate bar is not sufficient alone.
pub const MAX_FOREIGN_PROC_CPU_PCT: f64 = 5.0;

/// Sampling interval for per-process CPU attribution.
pub const CENSUS_INTERVAL: Duration = Duration::from_millis(750);

/// How many top CPU consumers to record in the artifact.
pub const CENSUS_TOP_N: usize = 15;

// ── Host profile ──────────────────────────────────────────────────────────────

/// Static-ish properties of the machine the measurement ran on.
pub struct HostProfile {
    /// `model name` from `/proc/cpuinfo`.
    pub cpu_model: String,
    /// Logical CPUs visible to the process.
    pub cpus: usize,
    /// `scaling_governor` of cpu0, if exposed.
    pub governor: Option<String>,
    /// Whether turbo/boost is enabled, if exposed.
    pub boost: Option<bool>,
    /// Contents of `/sys/devices/system/cpu/isolated`; empty means no isolation.
    pub isolated_cpus: String,
    /// True when a battery is present — i.e. this is a laptop, not a server.
    pub has_battery: bool,
    /// Peak package temperature in °C at capture time, if exposed.
    pub temp_c: Option<f64>,
}

impl HostProfile {
    /// Reads the host profile from `/proc` and `/sys`.
    pub fn capture() -> Self {
        let cpu_model = read_to_string("/proc/cpuinfo")
            .lines()
            .find(|l| l.starts_with("model name"))
            .and_then(|l| l.split_once(':'))
            .map_or_else(|| "unknown".to_string(), |(_, v)| v.trim().to_string());

        let governor = read_opt("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor");
        let boost = read_opt("/sys/devices/system/cpu/cpufreq/boost").map(|s| s == "1");
        let isolated_cpus = read_opt("/sys/devices/system/cpu/isolated").unwrap_or_default();
        let has_battery = std::fs::read_dir("/sys/class/power_supply")
            .map(|d| {
                d.flatten().any(|e| {
                    read_opt(&format!("{}/type", e.path().display()))
                        .is_some_and(|t| t.eq_ignore_ascii_case("Battery"))
                })
            })
            .unwrap_or(false);

        Self {
            cpu_model,
            cpus: std::thread::available_parallelism().map_or(0, std::num::NonZeroUsize::get),
            governor,
            boost,
            isolated_cpus,
            has_battery,
            temp_c: hottest_zone_c(),
        }
    }

    /// Reasons this host is not server-class for publishable competitive work.
    ///
    /// These are *host-class* objections, distinct from transient contention:
    /// quiescing the box does not fix any of them. Every competitor figure we
    /// compare against was taken on a server-class instance with a fixed clock,
    /// so a mobile part under DVFS is not a like-for-like denominator.
    pub fn non_server_class_reasons(&self) -> Vec<String> {
        let mut v = Vec::new();
        if self.has_battery {
            v.push(format!(
                "mobile chassis: battery present, CPU is '{}' — a laptop part with \
                 thermal- and power-limited sustained clocks",
                self.cpu_model
            ));
        }
        match self.governor.as_deref() {
            Some("performance") => {}
            Some(g) => v.push(format!(
                "scaling governor is '{g}', not 'performance' — clocks vary during the \
                 measurement window, so throughput is not attributable to the code"
            )),
            None => v.push("scaling governor not exposed; clock stability unverifiable".into()),
        }
        if self.isolated_cpus.trim().is_empty() {
            v.push(
                "no isolated CPUs (`isolcpus=` unset) — the generator, the server and every \
                 foreign process share the same schedulable set"
                    .into(),
            );
        }
        v
    }

    /// Renders the profile as JSON.
    pub fn to_json(&self) -> serde_json::Value {
        let reasons = self.non_server_class_reasons();
        serde_json::json!({
            "cpu_model": self.cpu_model,
            "logical_cpus": self.cpus,
            "scaling_governor": self.governor,
            "boost_enabled": self.boost,
            "isolated_cpus": self.isolated_cpus,
            "battery_present": self.has_battery,
            "package_temp_c": self.temp_c,
            "server_class": reasons.is_empty(),
            "non_server_class_reasons": reasons,
        })
    }
}

// ── Load + census ─────────────────────────────────────────────────────────────

/// A `/proc/loadavg` reading.
#[derive(Clone, Copy)]
pub struct LoadSnapshot {
    pub load1: f64,
    pub load5: f64,
    pub load15: f64,
    /// Currently-runnable kernel scheduling entities.
    pub running: u64,
}

impl LoadSnapshot {
    /// Reads `/proc/loadavg`.
    pub fn capture() -> Self {
        let s = read_to_string("/proc/loadavg");
        let f: Vec<&str> = s.split_whitespace().collect();
        let num = |i: usize| f.get(i).and_then(|v| v.parse().ok()).unwrap_or(f64::NAN);
        Self {
            load1: num(0),
            load5: num(1),
            load15: num(2),
            running: f
                .get(3)
                .and_then(|v| v.split_once('/'))
                .and_then(|(r, _)| r.parse().ok())
                .unwrap_or(0),
        }
    }

    /// Load average per visible CPU — the scale-free contention figure.
    pub fn per_cpu(&self, cpus: usize) -> f64 {
        if cpus == 0 {
            f64::NAN
        } else {
            self.load1 / cpus as f64
        }
    }

    /// Renders the snapshot as JSON. Takes `self` by value — this type is `Copy`.
    pub fn to_json(self, cpus: usize) -> serde_json::Value {
        serde_json::json!({
            "load1": self.load1,
            "load5": self.load5,
            "load15": self.load15,
            "runnable": self.running,
            "load1_per_cpu": self.per_cpu(cpus),
        })
    }
}

/// One process's CPU attribution over the census interval.
pub struct ProcSample {
    pub pid: u32,
    pub comm: String,
    /// CPU used, in percent of a single core.
    pub cpu_pct: f64,
    /// Resident set size in KiB.
    pub rss_kib: u64,
}

/// Top foreign CPU consumers, sampled over [`CENSUS_INTERVAL`].
pub struct ProcessCensus {
    pub procs: Vec<ProcSample>,
    /// Total non-idle CPU across all cores, in percent of one core.
    pub total_busy_pct: f64,
}

impl ProcessCensus {
    /// Samples `/proc/[pid]/stat` twice over [`CENSUS_INTERVAL`] and attributes
    /// CPU by jiffy delta.
    ///
    /// CPU share is computed against the *total* jiffy delta from `/proc/stat`
    /// rather than against a hardcoded `CLK_TCK`, so the result does not depend
    /// on the kernel's tick rate.
    pub fn capture(exclude_pid: u32) -> Self {
        let first = sample_procs();
        let cpu_first = total_cpu_jiffies();
        std::thread::sleep(CENSUS_INTERVAL);
        let second = sample_procs();
        let cpu_second = total_cpu_jiffies();

        // Total jiffies elapsed across all cores. One core's worth is this
        // divided by the CPU count, which is the denominator for "percent of
        // one core".
        let (busy_d, total_d) = (
            (cpu_second.0 - cpu_first.0) as f64,
            (cpu_second.1 - cpu_first.1) as f64,
        );
        let cpus = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
        let per_core_jiffies = if total_d > 0.0 {
            total_d / cpus as f64
        } else {
            f64::NAN
        };

        let mut procs: Vec<ProcSample> = second
            .into_iter()
            .filter(|(pid, _)| *pid != exclude_pid)
            .filter_map(|(pid, (comm, jiffies, rss))| {
                let prev = first.get(&pid).map_or(0, |p| p.1);
                let delta = jiffies.saturating_sub(prev) as f64;
                let cpu_pct = 100.0 * delta / per_core_jiffies;
                (cpu_pct >= 0.5).then_some(ProcSample {
                    pid,
                    comm,
                    cpu_pct,
                    rss_kib: rss,
                })
            })
            .collect();
        procs.sort_by(|a, b| b.cpu_pct.total_cmp(&a.cpu_pct));
        procs.truncate(CENSUS_TOP_N);

        Self {
            procs,
            total_busy_pct: 100.0 * busy_d / per_core_jiffies,
        }
    }

    /// The busiest foreign process, if any.
    pub fn worst(&self) -> Option<&ProcSample> {
        self.procs.first()
    }

    /// Renders the census as JSON.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "interval_ms": CENSUS_INTERVAL.as_millis(),
            "total_busy_pct_of_one_core": self.total_busy_pct,
            "top": self.procs.iter().map(|p| serde_json::json!({
                "pid": p.pid,
                "comm": p.comm,
                "cpu_pct_of_one_core": p.cpu_pct,
                "rss_kib": p.rss_kib,
            })).collect::<Vec<_>>(),
        })
    }
}

// ── The gate ──────────────────────────────────────────────────────────────────

/// A pre-run quiescence + host-class decision.
pub struct Verdict {
    /// True only when every gate passed. Stamped into the artifact.
    pub publishable: bool,
    /// Transient contention objections — quiescing the host clears these.
    pub contention: Vec<String>,
    /// Host-class objections — quiescing the host does **not** clear these.
    pub host_class: Vec<String>,
}

impl Verdict {
    /// True when nothing but transient contention stands in the way.
    pub fn only_contention(&self) -> bool {
        self.host_class.is_empty() && !self.contention.is_empty()
    }

    /// Human-readable multi-line explanation.
    pub fn explain(&self) -> String {
        let mut s = String::new();
        if !self.host_class.is_empty() {
            let _ = writeln!(s, "  host-class objections (NOT fixable by quiescing):");
            for r in &self.host_class {
                let _ = writeln!(s, "    ✗ {r}");
            }
        }
        if !self.contention.is_empty() {
            let _ = writeln!(s, "  contention objections (fixable by quiescing):");
            for r in &self.contention {
                let _ = writeln!(s, "    ✗ {r}");
            }
        }
        s
    }

    /// Renders the verdict as JSON.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "publishable": self.publishable,
            "contention_objections": self.contention,
            "host_class_objections": self.host_class,
            "thresholds": {
                "max_prerun_load_per_cpu": MAX_PRERUN_LOAD_PER_CPU,
                "max_foreign_proc_cpu_pct": MAX_FOREIGN_PROC_CPU_PCT,
            },
        })
    }
}

/// Evaluates quiescence and host class against the thresholds in this module.
pub fn evaluate(host: &HostProfile, load: &LoadSnapshot, census: &ProcessCensus) -> Verdict {
    let mut contention = Vec::new();

    let bar = MAX_PRERUN_LOAD_PER_CPU * host.cpus as f64;
    // Fail closed: an unparseable load average comes through as NaN, which is
    // incomparable, and an unknown load must block publication rather than
    // sail through a `>` test that NaN would quietly fail.
    let within_bar = matches!(
        load.load1.partial_cmp(&bar),
        Some(std::cmp::Ordering::Less | std::cmp::Ordering::Equal)
    );
    if !within_bar {
        contention.push(format!(
            "pre-run load average {:.2} exceeds the bar of {:.2} ({:.0}% of {} CPUs; \
             measured {:.1}% of capacity)",
            load.load1,
            bar,
            MAX_PRERUN_LOAD_PER_CPU * 100.0,
            host.cpus,
            100.0 * load.per_cpu(host.cpus),
        ));
    }
    for p in census
        .procs
        .iter()
        .filter(|p| p.cpu_pct > MAX_FOREIGN_PROC_CPU_PCT)
    {
        contention.push(format!(
            "foreign process '{}' (pid {}) is using {:.1}% of a core, over the {:.1}% bar",
            p.comm, p.pid, p.cpu_pct, MAX_FOREIGN_PROC_CPU_PCT
        ));
    }

    let host_class = host.non_server_class_reasons();
    Verdict {
        publishable: contention.is_empty() && host_class.is_empty(),
        contention,
        host_class,
    }
}

// ── /proc plumbing ────────────────────────────────────────────────────────────

fn read_to_string(p: &str) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

fn read_opt(p: &str) -> Option<String> {
    std::fs::read_to_string(p)
        .ok()
        .map(|s| s.trim().to_string())
}

/// Returns `(busy_jiffies, total_jiffies)` summed across all cores.
fn total_cpu_jiffies() -> (u64, u64) {
    let s = read_to_string("/proc/stat");
    let Some(line) = s.lines().next().filter(|l| l.starts_with("cpu ")) else {
        return (0, 0);
    };
    let vals: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .filter_map(|v| v.parse().ok())
        .collect();
    let total: u64 = vals.iter().sum();
    // Fields 4 and 5 are idle and iowait.
    let idle: u64 = vals.iter().skip(3).take(2).sum();
    (total.saturating_sub(idle), total)
}

/// `pid -> (comm, utime+stime jiffies, rss_kib)` for every readable process.
fn sample_procs() -> HashMap<u32, (String, u64, u64)> {
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return HashMap::new();
    };
    let mut out = HashMap::new();
    for entry in dir.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            continue;
        };
        // `comm` is parenthesised and may itself contain spaces or ')', so the
        // field split has to start after the *last* ')'.
        let Some(close) = stat.rfind(')') else {
            continue;
        };
        let comm = stat
            .get(..close)
            .and_then(|s| s.find('(').map(|o| stat[o + 1..close].to_string()))
            .unwrap_or_default();
        let rest: Vec<&str> = stat[close + 1..].split_whitespace().collect();
        // After `state`, offsets are: utime=11, stime=12, rss(pages)=21.
        let jiffies = rest
            .get(11)
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0)
            + rest
                .get(12)
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
        let rss_kib = rest
            .get(21)
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0)
            * 4;
        out.insert(pid, (comm, jiffies, rss_kib));
    }
    out
}

/// Hottest `thermal_zone*` reading in °C, if `/sys` exposes any.
fn hottest_zone_c() -> Option<f64> {
    let dir = std::fs::read_dir("/sys/class/thermal").ok()?;
    dir.flatten()
        .filter_map(|e| read_opt(&format!("{}/temp", e.path().display())))
        .filter_map(|t| t.parse::<f64>().ok())
        .map(|t| t / 1000.0)
        .filter(|t| *t > 0.0 && *t < 150.0)
        .max_by(f64::total_cmp)
}
