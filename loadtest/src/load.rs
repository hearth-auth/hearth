//! Load-run orchestration (HEA-1790, modes + reporters HEA-1791).
//!
//! Parses the CLI knobs for a Goose run, loads the seed-handle corpus, wires it
//! into [`crate::scenarios`], and drives the attack. Journey weighting is fully
//! parameterized (defaults mirror the plan, HEA-1787 §4): `validation >> lookup
//! >> issuance >> revoke`.
//!
//! Three run modes (HEA-1787 §7):
//! * `steady` — a single fixed-user attack for `--run-time`; the primary report.
//! * `ramp` — a user ladder run step-by-step, recording the **saturation knee**:
//!   the achieved RPS at the first step where a budgeted journey's p99 breaches
//!   its HTTP budget ([`crate::budget`]).
//! * `soak` — a sequence of fixed-user buckets over a long window, surfacing
//!   latency drift bucket-to-bucket (Goose only aggregates, so per-bucket
//!   sub-runs are how drift becomes visible).
//!
//! Every mode emits a Goose HTML report per sub-run plus one versioned
//! machine-readable `report.json` ([`crate::report`]).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, ValueEnum};
use goose::config::GooseConfiguration;
use goose::metrics::GooseMetrics;
use goose::prelude::*;

use crate::handle::SeedHandle;
use crate::latency::{self, LatencyExtremes};
use crate::report::{self, LoadReport, RampStep, RunMetadata, SoakBucket, SCHEMA_VERSION};
use crate::scenarios::{self, ContextError, LoadContext, TierMissContext, Weights};
use crate::seed::{DEV_ADMIN_EMAIL, DEV_ADMIN_PASSWORD};

/// Run mode selecting the load profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Mode {
    /// Fixed users for `--run-time` (primary report).
    Steady,
    /// Step the user ladder upward, recording the saturation knee.
    Ramp,
    /// Long fixed-user run in buckets, surfacing latency drift.
    Soak,
    /// Corpus-scale `lookup_user` sweep with tier-attributed hot/cold draws,
    /// proving lookup latency stays flat as the corpus grows (HEA-1801).
    TierMiss,
}

impl Mode {
    /// Lowercase name stamped into the report metadata.
    fn as_str(self) -> &'static str {
        match self {
            Self::Steady => "steady",
            Self::Ramp => "ramp",
            Self::Soak => "soak",
            Self::TierMiss => "tier-miss",
        }
    }
}

/// Parameters for a Goose load run.
///
/// Every per-journey weight has a CLI flag and an env fallback; a weight of `0`
/// drops that journey. Standard load knobs (`--users`, `--run-time`,
/// `--hatch-rate`) map onto Goose's own configuration.
///
/// Holds the tier-miss corpus password (`tier_miss_password`), so no `Debug` —
/// parity with [`TierMissContext`] and the `SeedParams` redaction (HEA-1795).
#[derive(Clone, Args)]
pub struct LoadParams {
    /// Path to the JSON seed-handle produced by the `seed` step.
    #[arg(
        long,
        env = "HEARTH_LOADTEST_SEED_OUT",
        default_value = "loadtest/reports/seed-handle.json"
    )]
    pub seed_handle: String,

    /// Base URL to drive load against. Defaults to the seed-handle's
    /// `target_host` (the instance the corpus was seeded on), or the loopback
    /// dev address in `tier-miss` mode.
    #[arg(long, env = "HEARTH_LOADTEST_TARGET_HOST")]
    pub host: Option<String>,

    /// Allow a non-loopback `--host` (HEA-1807).
    ///
    /// A load run drives sustained traffic at its target, so by default `run`
    /// refuses any host that is not loopback (`127.0.0.0/8`, `::1`, or the
    /// literal `localhost`) — the same failure-closed guard the `seed` step
    /// applies (HEA-1794). Set this flag only for an isolated lab instance you
    /// control; never for a shared or production host.
    #[arg(
        long,
        env = "HEARTH_LOADTEST_ALLOW_REMOTE_TARGET",
        default_value_t = false
    )]
    pub allow_remote_target: bool,

    /// Run mode: `steady` (fixed users), `ramp` (saturation knee), `soak`
    /// (long-window drift), or `tier-miss` (corpus-scale lookup with per-tier
    /// hot/cold latency split).
    #[arg(long, env = "HEARTH_LOADTEST_MODE", value_enum, default_value_t = Mode::Steady)]
    pub mode: Mode,

    /// Directory for the HTML + JSON reports. Created if absent.
    #[arg(
        long,
        env = "HEARTH_LOADTEST_REPORT_DIR",
        default_value = "loadtest/reports"
    )]
    pub report_dir: String,

    /// Total users resident in the server's storage engine for this run, if
    /// known (the `make loadtest` large corpus; HEA-1787 §2).
    ///
    /// This is **not** the concurrency (`--users`) and **not** the seed-handle
    /// token pool: it is the size of the demo corpus the server was booted with
    /// so the hot path is exercised against a realistically-large store. When
    /// set it is appended to the report's `dataset_shape` (`resident_corpus=N`)
    /// so a report can never be misread as "only N users seeded" when N is the
    /// load-generator concurrency. Omitted (`None`) for a bare seed-handle run
    /// against an instance whose corpus size the harness does not know.
    #[arg(long, env = "HEARTH_LOADTEST_RESIDENT_CORPUS_SIZE")]
    pub resident_corpus_size: Option<u64>,

    /// Concurrent Goose users (steady + soak; ramp uses its own ladder).
    #[arg(long, env = "HEARTH_LOADTEST_USERS", default_value_t = 50)]
    pub users: usize,

    /// Per-step steady duration (Goose timespan, e.g. `60s`, `5m`). In `soak`
    /// mode this is the duration of each bucket.
    #[arg(long, env = "HEARTH_LOADTEST_RUN_TIME", default_value = "60s")]
    pub run_time: String,

    /// Users spawned per second during ramp-up.
    #[arg(long, env = "HEARTH_LOADTEST_HATCH_RATE", default_value = "5")]
    pub hatch_rate: String,

    /// Cap total requests per second across all users (`0` = unthrottled).
    ///
    /// Useful against an instance with per-client rate limits, where an
    /// unthrottled run is dominated by `429`s rather than the hot path.
    #[arg(long, env = "HEARTH_LOADTEST_THROTTLE", default_value_t = 0)]
    pub throttle: usize,

    /// `ramp` mode: users at the first ladder step.
    #[arg(long, env = "HEARTH_LOADTEST_RAMP_START_USERS", default_value_t = 10)]
    pub ramp_start_users: usize,

    /// `ramp` mode: users added at each subsequent ladder step.
    #[arg(long, env = "HEARTH_LOADTEST_RAMP_STEP_USERS", default_value_t = 10)]
    pub ramp_step_users: usize,

    /// `ramp` mode: maximum number of ladder steps (the ramp stops early once a
    /// budgeted journey breaches — the knee is recorded then).
    #[arg(long, env = "HEARTH_LOADTEST_RAMP_STEPS", default_value_t = 8)]
    pub ramp_steps: usize,

    /// `soak` mode: number of equal-length buckets. Total soak time is
    /// `soak_buckets * run_time` (e.g. `--run-time 3m --soak-buckets 6` ≈ 18m).
    #[arg(long, env = "HEARTH_LOADTEST_SOAK_BUCKETS", default_value_t = 6)]
    pub soak_buckets: usize,

    /// Weight of journey 1 — validate (`POST /introspect`).
    #[arg(long, env = "HEARTH_LOADTEST_WEIGHT_VALIDATE", default_value_t = 70)]
    pub weight_validate: usize,

    /// Weight of journey 2 — session lookup (`GET /userinfo`).
    #[arg(long, env = "HEARTH_LOADTEST_WEIGHT_SESSION", default_value_t = 12)]
    pub weight_session: usize,

    /// Weight of journey 3 — user lookup (`GET /admin/users/{id}`).
    #[arg(long, env = "HEARTH_LOADTEST_WEIGHT_USER", default_value_t = 8)]
    pub weight_user: usize,

    /// Weight of journey 4 — issuance (`POST /token`).
    #[arg(long, env = "HEARTH_LOADTEST_WEIGHT_ISSUANCE", default_value_t = 8)]
    pub weight_issuance: usize,

    /// Weight of journey 5 — revoke → re-validate.
    #[arg(long, env = "HEARTH_LOADTEST_WEIGHT_REVOKE", default_value_t = 2)]
    pub weight_revoke: usize,

    // ── Tier-miss profile (HEA-1801) — only used when `--mode tier-miss`. ──
    /// `tier-miss` mode: realm UUID of the bulk demo corpus (`X-Realm-ID`).
    ///
    /// Config-declared realms get a **random** v4 UUID at first boot (unlike
    /// deterministic client IDs), so it cannot be defaulted — obtain it once
    /// after boot (see the README "tier-miss" section) and pass it here.
    /// Required in tier-miss mode.
    #[arg(long, env = "HEARTH_LOADTEST_TIER_REALM_ID")]
    pub tier_miss_realm_id: Option<String>,

    /// `tier-miss` mode: public OAuth client owning the bulk corpus's ROPC
    /// password grant. Deterministic per `(realm_name, app_key)`; for
    /// `examples/large-scale-demo/hearth-tier-miss.yaml` this is the `bulk-app`
    /// client. Required in tier-miss mode.
    #[arg(long, env = "HEARTH_LOADTEST_TIER_CLIENT_ID")]
    pub tier_miss_client_id: Option<String>,

    /// `tier-miss` mode: email domain of the bulk corpus (`user<idx>@<domain>`).
    #[arg(
        long,
        env = "HEARTH_LOADTEST_TIER_EMAIL_DOMAIN",
        default_value = "bulk.demo"
    )]
    pub tier_miss_email_domain: String,

    /// `tier-miss` mode: shared password every bulk user authenticates with
    /// (`demo.password`).
    ///
    /// Prefer sourcing this from the `HEARTH_LOADTEST_TIER_PASSWORD` env var
    /// rather than the `--tier-miss-password` flag, so the corpus credential
    /// does not land in shell history (HEA-1807). The flag default is the demo
    /// config's well-known value purely so a zero-arg dev run works; override it
    /// via the env var for any non-default corpus. The value holder has no
    /// `Debug`, so it never spills to logs regardless.
    #[arg(
        long,
        env = "HEARTH_LOADTEST_TIER_PASSWORD",
        default_value = "DemoPassw0rd!"
    )]
    pub tier_miss_password: String,

    /// `tier-miss` mode: total addressable corpus size. The cold draw spans
    /// `1..=corpus_size`. Sweep this (`10000 → 100000 → 1000000`) to prove the
    /// per-tier tail stays flat as the corpus grows.
    #[arg(
        long,
        env = "HEARTH_LOADTEST_TIER_CORPUS_SIZE",
        default_value_t = 1_000_000
    )]
    pub tier_miss_corpus_size: u64,

    /// `tier-miss` mode: size of the resident hot working set. Hot draws span
    /// `1..=hot_set_size`, hit repeatedly so they stay in the hot tier. Defaults
    /// to `10_000`: a set that is too small concentrates every concurrent ROPC
    /// user onto the same few accounts, and the Argon2id verify contention on
    /// those accounts inflates the hot-tier tail above the cold tail (HEA-1804).
    /// Keep this comfortably above `--users` so hot draws spread across accounts.
    #[arg(
        long,
        env = "HEARTH_LOADTEST_TIER_HOT_SET_SIZE",
        default_value_t = 10_000
    )]
    pub tier_miss_hot_set_size: u64,

    /// `tier-miss` mode: hot-tier capacity (entries) the instance was booted
    /// with (`storage.hot_tier_capacity`). Informational — recorded in the
    /// report and used to estimate the expected cold miss rate. Optional.
    #[arg(long, env = "HEARTH_LOADTEST_TIER_HOT_TIER_CAPACITY")]
    pub tier_miss_hot_tier_capacity: Option<u64>,

    /// `tier-miss` mode: Goose weight of the hot-tier lookup tier.
    #[arg(long, env = "HEARTH_LOADTEST_TIER_WEIGHT_HOT", default_value_t = 50)]
    pub tier_miss_weight_hot: usize,

    /// `tier-miss` mode: Goose weight of the cold/SST-miss lookup tier.
    #[arg(long, env = "HEARTH_LOADTEST_TIER_WEIGHT_COLD", default_value_t = 50)]
    pub tier_miss_weight_cold: usize,
}

/// Errors from preparing or running a load run.
#[derive(Debug)]
pub enum LoadError {
    /// The seed-handle could not be read.
    Io(std::io::Error),
    /// The seed-handle JSON could not be parsed.
    Parse(serde_json::Error),
    /// The corpus in the handle is unusable for the journeys.
    Context(ContextError),
    /// Goose rejected the configuration or scenario, or the attack failed.
    Goose(GooseError),
    /// The JSON report could not be serialized or written.
    Report(std::io::Error),
    /// A tier-miss run was misconfigured (missing/invalid required knob).
    TierMissConfig(String),
    /// The resolved `--host` failed the loopback guard (HEA-1807).
    HostGuard(String),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "reading seed handle: {e}"),
            Self::Parse(e) => write!(f, "parsing seed handle: {e}"),
            Self::Context(e) => write!(f, "seed corpus unusable: {e}"),
            Self::Goose(e) => write!(f, "goose: {e}"),
            Self::Report(e) => write!(f, "writing report: {e}"),
            Self::TierMissConfig(m) => write!(f, "tier-miss configuration: {m}"),
            Self::HostGuard(m) => write!(f, "host guard: {m}"),
        }
    }
}

impl std::error::Error for LoadError {}

impl From<GooseError> for LoadError {
    fn from(e: GooseError) -> Self {
        Self::Goose(e)
    }
}

impl LoadParams {
    /// The per-journey weights this run requests.
    #[must_use]
    pub fn weights(&self) -> Weights {
        Weights {
            validate: self.weight_validate,
            session: self.weight_session,
            user: self.weight_user,
            issuance: self.weight_issuance,
            revoke: self.weight_revoke,
        }
    }

    /// The user ladder for `ramp` mode: `ramp_steps` steps starting at
    /// `ramp_start_users`, each adding `ramp_step_users`.
    #[must_use]
    pub fn ramp_ladder(&self) -> Vec<usize> {
        (0..self.ramp_steps.max(1))
            .map(|i| self.ramp_start_users + i * self.ramp_step_users)
            .collect()
    }
}

/// Loads the seed-handle, wires the corpus into the journeys, and runs the
/// selected mode, writing HTML + JSON reports.
///
/// # Errors
/// Returns a [`LoadError`] if the seed-handle is missing/invalid, its corpus is
/// unusable, Goose fails to configure or run an attack, or the report cannot be
/// written.
pub async fn run_load(params: &LoadParams) -> Result<(), LoadError> {
    let report_dir = PathBuf::from(&params.report_dir);
    std::fs::create_dir_all(&report_dir).map_err(LoadError::Report)?;

    // The tier-miss profile addresses a server-seeded bulk corpus by index, so
    // it needs no seed-handle; every other mode draws its corpus from one.
    let report = if params.mode == Mode::TierMiss {
        run_tier_miss(params, &report_dir).await?
    } else {
        run_journey_modes(params, &report_dir).await?
    };

    let json_path = report_dir.join("report.json");
    let json = serde_json::to_string_pretty(&report)
        .map_err(|e| LoadError::Report(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
    std::fs::write(&json_path, json).map_err(LoadError::Report)?;
    println!("  report: {} (pass={})", json_path.display(), report.pass);
    Ok(())
}

/// Failure-closed loopback guard on a resolved run target (HEA-1807).
///
/// Mirrors the `seed` guard (HEA-1794): a `run` against a non-loopback host is
/// a deliberate opt-in (`--allow-remote-target`), never the silent default, so
/// a stray remote target does not drive sustained load at a shared instance.
/// Pure (no I/O) so every branch is unit-testable.
///
/// # Errors
/// Returns [`LoadError::HostGuard`] if `host` is not a valid http(s) URL, or is
/// non-loopback and `allow_remote` was not set.
fn guard_run_host(host: &str, allow_remote: bool) -> Result<(), LoadError> {
    match crate::params::host_is_loopback(host) {
        Ok(crate::params::HostClass::Loopback) => Ok(()),
        Ok(crate::params::HostClass::Remote(_)) if allow_remote => Ok(()),
        Ok(crate::params::HostClass::Remote(h)) => Err(LoadError::HostGuard(format!(
            "run target {h} is not loopback; a load run drives sustained traffic, so \
             remote targets require the explicit --allow-remote-target opt-in \
             (isolated lab instances only)"
        ))),
        Err(()) => Err(LoadError::HostGuard(format!(
            "run target {host} is not a valid http(s) URL"
        ))),
    }
}

/// Runs one of the seed-handle-backed journey modes (`steady` / `ramp` /
/// `soak`), loading the corpus from the seed-handle first.
async fn run_journey_modes(
    params: &LoadParams,
    report_dir: &Path,
) -> Result<LoadReport, LoadError> {
    let raw = std::fs::read_to_string(&params.seed_handle).map_err(LoadError::Io)?;
    let handle: SeedHandle = serde_json::from_str(&raw).map_err(LoadError::Parse)?;

    let host = params
        .host
        .clone()
        .unwrap_or_else(|| handle.target_host.clone());
    guard_run_host(&host, params.allow_remote_target)?;

    let context = LoadContext::from_handle(&handle, DEV_ADMIN_EMAIL, DEV_ADMIN_PASSWORD)
        .map_err(LoadError::Context)?;
    scenarios::set_context(Arc::new(context));

    let weights = params.weights();

    println!(
        "hearth-loadtest run: mode={} host={host} run_time={} hatch_rate={} (corpus: {})",
        params.mode.as_str(),
        params.run_time,
        params.hatch_rate,
        handle.dataset_shape,
    );
    println!(
        "  weights: validate={} session={} user={} issuance={} revoke={}",
        weights.validate, weights.session, weights.user, weights.issuance, weights.revoke,
    );

    match params.mode {
        Mode::Steady => run_steady(params, &host, &weights, &handle, report_dir).await,
        Mode::Ramp => run_ramp(params, &host, &weights, &handle, report_dir).await,
        Mode::Soak => run_soak(params, &host, &weights, &handle, report_dir).await,
        // TierMiss is dispatched before this function is reached.
        Mode::TierMiss => unreachable!("tier-miss is handled in run_load"),
    }
}

/// Runs a single fixed-user attack and returns its metrics plus the generator's
/// microsecond per-journey latency extremes ([`crate::latency`]). `html` is the
/// Goose HTML report path for this sub-run.
///
/// The latency registry is reset before the attack so a per-step report (ramp /
/// soak run several attacks) reflects only its own sub-run, and snapshotted
/// after `execute` returns — at which point no transactions are in flight.
async fn run_attack(
    params: &LoadParams,
    host: &str,
    weights: &Weights,
    users: usize,
    html: &Path,
) -> Result<(GooseMetrics, HashMap<&'static str, LatencyExtremes>), LoadError> {
    let scenario = scenarios::build_scenario(weights)?;
    let config = build_config(params, host.to_string(), users, html);
    latency::reset();
    let metrics = GooseAttack::initialize_with_config(config)?
        .register_scenario(scenario)
        .execute()
        .await?;
    let latency = latency::snapshot();
    let percentiles = latency::snapshot_percentiles();
    rewrite_html_extremes(html, &latency, &percentiles, params.resident_corpus_size)?;
    Ok((metrics, latency))
}

/// Rewrites the whole-ms cells of the Goose HTML report at `html` with our
/// microsecond-resolution figures (HEA-1788 board follow-up): the Request
/// Metrics `Min`/`Max` columns from `latency`, and the Response Time Metrics
/// percentile table from `percentiles`. Goose measures response times in whole
/// ms, so without this both tables render Hearth's sub-ms hot path as `1`. Also
/// relabels the overview `Users:` line (Goose's load-generator concurrency) and,
/// when `resident_corpus_size` is known, states the seeded population under test
/// so the top-of-report number can no longer be misread as "only N users".
/// Best-effort on the read: if Goose wrote no report (e.g. an attack recorded
/// zero requests) the file is simply absent and there is nothing to fix. A
/// failed write is a real I/O error and is propagated.
fn rewrite_html_extremes(
    html: &Path,
    latency: &HashMap<&'static str, LatencyExtremes>,
    percentiles: &latency::PercentileSnapshot,
    resident_corpus_size: Option<u64>,
) -> Result<(), LoadError> {
    let Ok(original) = std::fs::read_to_string(html) else {
        return Ok(());
    };
    let rewritten = crate::html::rewrite_request_extremes(&original, latency);
    let rewritten = crate::html::rewrite_response_percentiles(&rewritten, percentiles);
    let rewritten = crate::html::rewrite_users_label(&rewritten, resident_corpus_size);
    if rewritten != original {
        std::fs::write(html, rewritten).map_err(LoadError::Report)?;
    }
    Ok(())
}

/// Steady mode: one attack, one HTML, primary percentile table.
async fn run_steady(
    params: &LoadParams,
    host: &str,
    weights: &Weights,
    handle: &SeedHandle,
    report_dir: &Path,
) -> Result<LoadReport, LoadError> {
    let (metrics, latency) = run_attack(
        params,
        host,
        weights,
        params.users,
        &report_dir.join("steady.html"),
    )
    .await?;
    let journeys = report::journey_rows(&metrics.requests, &latency);
    let pass = report::overall_pass(&journeys);
    let summary = report::summarize(&journeys, params.users, requests_per_second(&metrics));
    Ok(LoadReport {
        schema: SCHEMA_VERSION,
        metadata: metadata(params, host, Mode::Steady, handle),
        summary,
        journeys,
        ramp_steps: None,
        knee_rps: None,
        soak_buckets: None,
        tier_miss: None,
        pass,
    })
}

/// Ramp mode: walk the user ladder, stop at the first budget breach, record the
/// saturation knee.
async fn run_ramp(
    params: &LoadParams,
    host: &str,
    weights: &Weights,
    handle: &SeedHandle,
    report_dir: &Path,
) -> Result<LoadReport, LoadError> {
    let mut steps: Vec<RampStep> = Vec::new();
    for users in params.ramp_ladder() {
        let html = report_dir.join(format!("ramp-{users}u.html"));
        let (metrics, latency) = run_attack(params, host, weights, users, &html).await?;
        let journeys = report::journey_rows(&metrics.requests, &latency);
        let rps = requests_per_second(&metrics);
        let breached = report::any_breach(&journeys);
        println!("  ramp step: users={users} rps={rps:.1} breached={breached}");
        steps.push(RampStep {
            users,
            rps,
            breached,
            journeys,
        });
        if breached {
            break; // knee found — no need to push further.
        }
    }

    let knee_rps = report::find_knee(&steps);
    // Primary step = the knee step if any breached, else the final (highest) step.
    let primary_step = steps.iter().find(|s| s.breached).or_else(|| steps.last());
    let primary = primary_step.map(|s| s.journeys.clone()).unwrap_or_default();
    let summary = report::summarize(
        &primary,
        primary_step.map_or(0, |s| s.users),
        primary_step.map_or(0.0, |s| s.rps),
    );
    let pass = knee_rps.is_none();
    Ok(LoadReport {
        schema: SCHEMA_VERSION,
        metadata: metadata(params, host, Mode::Ramp, handle),
        summary,
        journeys: primary,
        ramp_steps: Some(steps),
        knee_rps,
        soak_buckets: None,
        tier_miss: None,
        pass,
    })
}

/// Soak mode: fixed users across N buckets; per-bucket tables surface drift.
async fn run_soak(
    params: &LoadParams,
    host: &str,
    weights: &Weights,
    handle: &SeedHandle,
    report_dir: &Path,
) -> Result<LoadReport, LoadError> {
    let mut buckets: Vec<SoakBucket> = Vec::new();
    let mut all_pass = true;
    let mut last_rps = 0.0;
    for bucket in 0..params.soak_buckets.max(1) {
        let html = report_dir.join(format!("soak-bucket-{bucket}.html"));
        let (metrics, latency) = run_attack(params, host, weights, params.users, &html).await?;
        let journeys = report::journey_rows(&metrics.requests, &latency);
        last_rps = requests_per_second(&metrics);
        all_pass &= report::overall_pass(&journeys);
        println!(
            "  soak bucket {bucket}: validate p99={} ms",
            journeys
                .iter()
                .find(|r| r.journey == "validate")
                .map_or(0, |r| r.p99_ms)
        );
        buckets.push(SoakBucket { bucket, journeys });
    }

    let primary = buckets
        .last()
        .map(|b| b.journeys.clone())
        .unwrap_or_default();
    let summary = report::summarize(&primary, params.users, last_rps);
    Ok(LoadReport {
        schema: SCHEMA_VERSION,
        metadata: metadata(params, host, Mode::Soak, handle),
        summary,
        journeys: primary,
        ramp_steps: None,
        knee_rps: None,
        soak_buckets: Some(buckets),
        tier_miss: None,
        pass: all_pass,
    })
}

/// The validated inputs a tier-miss run needs, resolved from [`LoadParams`].
struct TierMissPlan {
    realm_id: String,
    client_id: String,
    corpus_size: u64,
    hot_set_size: u64,
    hot_w: usize,
    cold_w: usize,
    host: String,
}

/// Validates and resolves the tier-miss knobs from `params`. Pure (no I/O) so
/// the validation branches are unit-testable without a running server.
///
/// # Errors
/// Returns [`LoadError::TierMissConfig`] naming the first invalid/missing knob.
fn tier_miss_plan(params: &LoadParams) -> Result<TierMissPlan, LoadError> {
    let realm_id = params.tier_miss_realm_id.clone().ok_or_else(|| {
        LoadError::TierMissConfig(
            "--tier-miss-realm-id (or HEARTH_LOADTEST_TIER_REALM_ID) is required in tier-miss mode"
                .to_string(),
        )
    })?;
    let client_id = params.tier_miss_client_id.clone().ok_or_else(|| {
        LoadError::TierMissConfig(
            "--tier-miss-client-id (or HEARTH_LOADTEST_TIER_CLIENT_ID) is required in tier-miss mode"
                .to_string(),
        )
    })?;
    let corpus_size = params.tier_miss_corpus_size;
    let hot_set_size = params.tier_miss_hot_set_size;
    if corpus_size == 0 {
        return Err(LoadError::TierMissConfig(
            "--tier-miss-corpus-size must be at least 1".to_string(),
        ));
    }
    if hot_set_size == 0 || hot_set_size > corpus_size {
        return Err(LoadError::TierMissConfig(format!(
            "--tier-miss-hot-set-size ({hot_set_size}) must be in 1..=corpus-size ({corpus_size})"
        )));
    }
    let (hot_w, cold_w) = (params.tier_miss_weight_hot, params.tier_miss_weight_cold);
    if hot_w + cold_w == 0 {
        return Err(LoadError::TierMissConfig(
            "at least one of --tier-miss-weight-hot / --tier-miss-weight-cold must be >= 1"
                .to_string(),
        ));
    }
    let host = params
        .host
        .clone()
        .unwrap_or_else(|| "http://127.0.0.1:8420".to_string());
    guard_run_host(&host, params.allow_remote_target)?;
    Ok(TierMissPlan {
        realm_id,
        client_id,
        corpus_size,
        hot_set_size,
        hot_w,
        cold_w,
        host,
    })
}

/// Tier-miss mode: a corpus-scale `lookup_user` sweep split into a resident hot
/// working set and a uniform cold draw, so `report.json` can split hot-tier-hit
/// from cold/SST-miss tail latency (HEA-1801). No seed-handle — the bulk corpus
/// is addressed by index against a server-seeded demo instance.
async fn run_tier_miss(params: &LoadParams, report_dir: &Path) -> Result<LoadReport, LoadError> {
    let plan = tier_miss_plan(params)?;
    let TierMissPlan {
        realm_id,
        client_id,
        corpus_size,
        hot_set_size,
        hot_w,
        cold_w,
        host,
    } = plan;

    println!(
        "hearth-loadtest tier-miss: host={host} corpus={corpus_size} hot_set={hot_set_size} \
         hot_tier_capacity={:?} weights(hot={hot_w} cold={cold_w}) run_time={} users={}",
        params.tier_miss_hot_tier_capacity, params.run_time, params.users,
    );

    let ctx = TierMissContext::new(
        realm_id,
        client_id,
        params.tier_miss_email_domain.clone(),
        params.tier_miss_password.clone(),
        corpus_size,
        hot_set_size,
    );
    scenarios::set_tier_context(Arc::new(ctx));

    let scenario = scenarios::build_tier_scenario(hot_w, cold_w)?;
    let html = report_dir.join("tier-miss.html");
    let config = build_config(params, host.clone(), params.users, &html);
    latency::reset();
    let metrics = GooseAttack::initialize_with_config(config)?
        .register_scenario(scenario)
        .execute()
        .await?;
    let latency = latency::snapshot();
    let percentiles = latency::snapshot_percentiles();
    // Tier-miss has no seed-handle; the resident population under test is the
    // bulk corpus itself, so surface it as the report's corpus figure.
    rewrite_html_extremes(&html, &latency, &percentiles, Some(corpus_size))?;

    let journeys = report::journey_rows(&metrics.requests, &latency);
    let rps = requests_per_second(&metrics);
    let pass = report::overall_pass(&journeys);
    let summary = report::summarize(&journeys, params.users, rps);
    let tier_miss = report::tier_miss_report(
        &journeys,
        corpus_size,
        hot_set_size,
        params.tier_miss_hot_tier_capacity,
        hot_w,
        cold_w,
    );

    Ok(LoadReport {
        schema: SCHEMA_VERSION,
        metadata: tier_metadata(params, &host, corpus_size, hot_set_size),
        summary,
        journeys,
        ramp_steps: None,
        knee_rps: None,
        soak_buckets: None,
        tier_miss: Some(tier_miss),
        pass,
    })
}

/// Achieved requests-per-second: total recorded requests / run duration.
fn requests_per_second(metrics: &GooseMetrics) -> f64 {
    let total: usize = metrics.requests.values().map(|r| r.raw_data.counter).sum();
    if metrics.duration == 0 {
        0.0
    } else {
        #[allow(clippy::cast_precision_loss)]
        {
            total as f64 / metrics.duration as f64
        }
    }
}

/// Composes the report's `dataset_shape` from the seed-handle's token-pool
/// description plus, when known, the resident large-corpus size.
///
/// The seed-handle describes only the small token pool the journeys log in as;
/// on a `make loadtest` run the server is separately booted with a much larger
/// demo corpus. Appending `resident_corpus=N` keeps the report from being
/// misread as "only <pool> users" when the hot path was actually driven against
/// N resident records (HEA-1787 §2 — the board's "why 200 users?" follow-up).
fn compose_dataset_shape(base: &str, resident_corpus_size: Option<u64>) -> String {
    match resident_corpus_size {
        Some(n) => format!("{base} resident_corpus={n}"),
        None => base.to_string(),
    }
}

/// Builds the report metadata header, capturing git SHA + wall-clock timestamp.
fn metadata(params: &LoadParams, host: &str, mode: Mode, handle: &SeedHandle) -> RunMetadata {
    RunMetadata {
        git_sha: git_sha(),
        timestamp_unix: now_unix(),
        mode: mode.as_str().to_string(),
        host: host.to_string(),
        seed: handle.seed,
        dataset_shape: compose_dataset_shape(&handle.dataset_shape, params.resident_corpus_size),
        users: params.users,
        run_time: params.run_time.clone(),
        hatch_rate: params.hatch_rate.clone(),
    }
}

/// Report metadata for a tier-miss run. There is no seed-handle, so `seed` is
/// `0` and `dataset_shape` describes the corpus/tier construction instead.
fn tier_metadata(
    params: &LoadParams,
    host: &str,
    corpus_size: u64,
    hot_set_size: u64,
) -> RunMetadata {
    RunMetadata {
        git_sha: git_sha(),
        timestamp_unix: now_unix(),
        mode: Mode::TierMiss.as_str().to_string(),
        host: host.to_string(),
        seed: 0,
        dataset_shape: format!(
            "tier-miss corpus={corpus_size} hot_set={hot_set_size} domain={}",
            params.tier_miss_email_domain,
        ),
        users: params.users,
        run_time: params.run_time.clone(),
        hatch_rate: params.hatch_rate.clone(),
    }
}

/// The short git SHA of the build, or `"unknown"`. Prefers the
/// `HEARTH_GIT_SHA` env override (set by CI where `git` may be unavailable).
fn git_sha() -> String {
    if let Ok(sha) = std::env::var("HEARTH_GIT_SHA") {
        let sha = sha.trim().to_string();
        if !sha.is_empty() {
            return sha;
        }
    }
    Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Wall-clock time as Unix epoch seconds (0 if the clock is before the epoch).
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Builds a Goose configuration from the CLI params for one attack.
///
/// Starts from `GooseConfiguration::default()` (all Goose flags at their
/// defaults) and overrides only the run knobs. The telnet/websocket controllers
/// are disabled — this is a one-shot headless run, not an interactive session.
/// `html` is written as the Goose HTML report for this sub-run.
// GooseConfiguration exposes no builder, so we reassign fields on a default.
#[allow(clippy::field_reassign_with_default)]
fn build_config(
    params: &LoadParams,
    host: String,
    users: usize,
    html: &Path,
) -> GooseConfiguration {
    let mut config = GooseConfiguration::default();
    config.host = host;
    config.users = Some(users);
    config.run_time = params.run_time.clone();
    config.hatch_rate = Some(params.hatch_rate.clone());
    config.throttle_requests = params.throttle;
    config.report_file = vec![html.to_string_lossy().into_owned()];
    config.no_telnet = true;
    config.no_websocket = true;
    config
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        params: LoadParams,
    }

    fn parse(args: &[&str]) -> LoadParams {
        let mut argv = vec!["hearth-loadtest"];
        argv.extend_from_slice(args);
        TestCli::parse_from(argv).params
    }

    #[test]
    fn default_weights_mirror_the_plan() {
        let p = parse(&[]);
        let w = p.weights();
        assert_eq!(w.validate, 70);
        assert_eq!(w.session, 12);
        assert_eq!(w.user, 8);
        assert_eq!(w.issuance, 8);
        assert_eq!(w.revoke, 2);
        // The mix is validation >> lookup >> issuance >> revoke.
        assert!(w.validate > w.session);
        assert!(w.session > w.user);
        assert!(w.issuance >= w.user);
        assert!(w.issuance > w.revoke);
    }

    #[test]
    fn weight_flags_override_defaults() {
        let p = parse(&[
            "--weight-validate",
            "40",
            "--weight-session",
            "30",
            "--weight-user",
            "20",
            "--weight-issuance",
            "5",
            "--weight-revoke",
            "5",
        ]);
        let w = p.weights();
        assert_eq!(w.total(), 100);
        let scenario = scenarios::build_scenario(&w).expect("scenario");
        assert_eq!(scenario.transactions.len(), 5);
    }

    #[test]
    fn zero_weight_override_drops_a_journey() {
        let p = parse(&["--weight-revoke", "0", "--weight-issuance", "0"]);
        let w = p.weights();
        let scenario = scenarios::build_scenario(&w).expect("scenario");
        assert_eq!(scenario.transactions.len(), 3);
    }

    #[test]
    fn mode_defaults_to_steady_and_parses_variants() {
        assert_eq!(parse(&[]).mode, Mode::Steady);
        assert_eq!(parse(&["--mode", "ramp"]).mode, Mode::Ramp);
        assert_eq!(parse(&["--mode", "soak"]).mode, Mode::Soak);
        assert_eq!(parse(&["--mode", "tier-miss"]).mode, Mode::TierMiss);
    }

    #[test]
    fn resident_corpus_size_is_optional_and_parses() {
        // Omitted by default — a bare seed-handle run does not know the corpus.
        assert_eq!(parse(&[]).resident_corpus_size, None);
        let p = parse(&["--resident-corpus-size", "1200000"]);
        assert_eq!(p.resident_corpus_size, Some(1_200_000));
    }

    #[test]
    fn dataset_shape_surfaces_resident_corpus_when_known() {
        // The seed-handle only ever describes the small token pool; the report
        // must additionally state the resident corpus so "users=200" (Goose
        // concurrency) is never mistaken for the seeded population.
        let base = "realms=1 users/realm=80 sessions/realm=40";
        assert_eq!(
            compose_dataset_shape(base, Some(1_200_000)),
            "realms=1 users/realm=80 sessions/realm=40 resident_corpus=1200000"
        );
        // Unknown corpus → unchanged shape (no misleading zero).
        assert_eq!(compose_dataset_shape(base, None), base);
    }

    fn tier_args() -> Vec<&'static str> {
        vec![
            "--mode",
            "tier-miss",
            "--tier-miss-realm-id",
            "11111111-1111-1111-1111-111111111111",
            "--tier-miss-client-id",
            "bulk-app",
        ]
    }

    #[test]
    fn tier_miss_defaults_and_plan_resolve() {
        let p = parse(&tier_args());
        assert_eq!(p.tier_miss_corpus_size, 1_000_000);
        assert_eq!(p.tier_miss_hot_set_size, 10_000);
        assert_eq!(p.tier_miss_email_domain, "bulk.demo");
        assert_eq!(p.tier_miss_password, "DemoPassw0rd!");
        let plan = tier_miss_plan(&p).expect("valid tier-miss plan");
        assert_eq!(plan.corpus_size, 1_000_000);
        assert_eq!(plan.client_id, "bulk-app");
        // No --host → the loopback dev default.
        assert_eq!(plan.host, "http://127.0.0.1:8420");
    }

    #[test]
    fn tier_miss_requires_realm_and_client() {
        let no_realm = parse(&["--mode", "tier-miss", "--tier-miss-client-id", "bulk-app"]);
        assert!(matches!(
            tier_miss_plan(&no_realm),
            Err(LoadError::TierMissConfig(_))
        ));
        let no_client = parse(&[
            "--mode",
            "tier-miss",
            "--tier-miss-realm-id",
            "11111111-1111-1111-1111-111111111111",
        ]);
        assert!(matches!(
            tier_miss_plan(&no_client),
            Err(LoadError::TierMissConfig(_))
        ));
    }

    #[test]
    fn tier_miss_rejects_hot_set_larger_than_corpus() {
        let mut args = tier_args();
        args.extend_from_slice(&[
            "--tier-miss-corpus-size",
            "1000",
            "--tier-miss-hot-set-size",
            "5000",
        ]);
        let p = parse(&args);
        assert!(matches!(
            tier_miss_plan(&p),
            Err(LoadError::TierMissConfig(_))
        ));
    }

    #[test]
    fn tier_miss_rejects_all_zero_weights() {
        let mut args = tier_args();
        args.extend_from_slice(&[
            "--tier-miss-weight-hot",
            "0",
            "--tier-miss-weight-cold",
            "0",
        ]);
        let p = parse(&args);
        assert!(matches!(
            tier_miss_plan(&p),
            Err(LoadError::TierMissConfig(_))
        ));
    }

    #[test]
    fn tier_miss_hot_tier_capacity_is_optional_and_parses() {
        let p = parse(&tier_args());
        assert_eq!(p.tier_miss_hot_tier_capacity, None);
        let mut args = tier_args();
        args.extend_from_slice(&["--tier-miss-hot-tier-capacity", "100000"]);
        let p = parse(&args);
        assert_eq!(p.tier_miss_hot_tier_capacity, Some(100_000));
    }

    /// Regression (HEA-1807): the `run` loopback guard mirrors the seed guard —
    /// loopback hosts pass, remote hosts are rejected unless `--allow-remote-target`
    /// is set, and a malformed URL is rejected outright.
    #[test]
    fn run_host_guard_accepts_loopback_and_rejects_remote() {
        for host in [
            "http://127.0.0.1:8420",
            "http://localhost:9999",
            "http://[::1]:8420",
            "https://127.0.0.53",
        ] {
            guard_run_host(host, false)
                .unwrap_or_else(|e| panic!("loopback host {host} must pass the guard: {e}"));
        }
        for host in [
            "http://10.0.0.5:8420",
            "https://hearth.example.com",
            // Userinfo trick: the connect host is evil.example, not 127.0.0.1.
            "http://127.0.0.1@evil.example:8420",
        ] {
            assert!(
                matches!(guard_run_host(host, false), Err(LoadError::HostGuard(_))),
                "remote host {host} must be rejected without opt-in"
            );
            guard_run_host(host, true)
                .unwrap_or_else(|e| panic!("explicit opt-in must pass for {host}: {e}"));
        }
        // Malformed / non-http targets are rejected even with the opt-in.
        for host in ["not a url", "ftp://127.0.0.1", ""] {
            assert!(
                matches!(guard_run_host(host, true), Err(LoadError::HostGuard(_))),
                "invalid target {host:?} must be rejected"
            );
        }
    }

    /// The tier-miss plan runs the loopback guard on the resolved host: a
    /// non-loopback `--host` is rejected unless `--allow-remote-target` is set.
    #[test]
    fn tier_miss_plan_enforces_loopback_guard() {
        let mut args = tier_args();
        args.extend_from_slice(&["--host", "http://10.0.0.5:8420"]);
        let p = parse(&args);
        assert!(matches!(tier_miss_plan(&p), Err(LoadError::HostGuard(_))));

        let mut args = tier_args();
        args.extend_from_slice(&["--host", "http://10.0.0.5:8420", "--allow-remote-target"]);
        let p = parse(&args);
        assert_eq!(
            tier_miss_plan(&p).expect("opt-in must pass").host,
            "http://10.0.0.5:8420"
        );
    }

    #[test]
    fn report_dir_has_a_default_and_overrides() {
        assert_eq!(parse(&[]).report_dir, "loadtest/reports");
        assert_eq!(parse(&["--report-dir", "/tmp/lt"]).report_dir, "/tmp/lt");
    }

    #[test]
    fn ramp_ladder_steps_upward() {
        let p = parse(&[
            "--ramp-start-users",
            "10",
            "--ramp-step-users",
            "20",
            "--ramp-steps",
            "4",
        ]);
        assert_eq!(p.ramp_ladder(), vec![10, 30, 50, 70]);
    }

    #[test]
    fn ramp_ladder_never_empty() {
        let p = parse(&["--ramp-steps", "0"]);
        assert_eq!(p.ramp_ladder(), vec![10]);
    }

    #[test]
    fn run_knobs_parse_into_config() {
        let p = parse(&[
            "--users",
            "100",
            "--run-time",
            "5m",
            "--hatch-rate",
            "10",
            "--throttle",
            "25",
            "--host",
            "http://127.0.0.1:9999",
        ]);
        let config = build_config(
            &p,
            "http://127.0.0.1:9999".to_string(),
            100,
            Path::new("/tmp/r.html"),
        );
        assert_eq!(config.users, Some(100));
        assert_eq!(config.run_time, "5m");
        assert_eq!(config.hatch_rate.as_deref(), Some("10"));
        assert_eq!(config.throttle_requests, 25);
        assert_eq!(config.report_file, vec!["/tmp/r.html".to_string()]);
        assert!(config.no_telnet);
        assert!(config.no_websocket);
    }
}
