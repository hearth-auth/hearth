//! Load-run orchestration (HEA-1790).
//!
//! Parses the CLI knobs for a Goose run, loads the seed-handle corpus, wires it
//! into [`crate::scenarios`], and drives the attack. Journey weighting is fully
//! parameterized (defaults mirror the plan, HEA-1787 §4): `validation >> lookup
//! >> issuance >> revoke`.
//!
//! Modes (steady/ramp/soak) and the JSON/HTML reporters are a follow-up
//! (HEA-1791); this module keeps the run config minimal — host, users, run-time,
//! ramp — so the five journeys can be exercised green against a seeded instance.

use std::sync::Arc;

use clap::Args;
use goose::config::GooseConfiguration;
use goose::prelude::*;

use crate::handle::SeedHandle;
use crate::scenarios::{self, ContextError, LoadContext, Weights};
use crate::seed::{DEV_ADMIN_EMAIL, DEV_ADMIN_PASSWORD};

/// Parameters for a Goose load run.
///
/// Every per-journey weight has a CLI flag and an env fallback; a weight of `0`
/// drops that journey. Standard load knobs (`--users`, `--run-time`,
/// `--hatch-rate`) map onto Goose's own configuration.
#[derive(Debug, Clone, Args)]
pub struct LoadParams {
    /// Path to the JSON seed-handle produced by the `seed` step.
    #[arg(
        long,
        env = "HEARTH_LOADTEST_SEED_OUT",
        default_value = "loadtest/reports/seed-handle.json"
    )]
    pub seed_handle: String,

    /// Base URL to drive load against. Defaults to the seed-handle's
    /// `target_host` (the instance the corpus was seeded on).
    #[arg(long, env = "HEARTH_LOADTEST_TARGET_HOST")]
    pub host: Option<String>,

    /// Concurrent Goose users.
    #[arg(long, env = "HEARTH_LOADTEST_USERS", default_value_t = 50)]
    pub users: usize,

    /// Steady-state duration (Goose timespan, e.g. `60s`, `5m`).
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
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "reading seed handle: {e}"),
            Self::Parse(e) => write!(f, "parsing seed handle: {e}"),
            Self::Context(e) => write!(f, "seed corpus unusable: {e}"),
            Self::Goose(e) => write!(f, "goose: {e}"),
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
}

/// Loads the seed-handle, wires the corpus into the journeys, and runs Goose.
///
/// # Errors
/// Returns a [`LoadError`] if the seed-handle is missing/invalid, its corpus is
/// unusable, or Goose fails to configure or run the attack.
pub async fn run_load(params: &LoadParams) -> Result<(), LoadError> {
    let raw = std::fs::read_to_string(&params.seed_handle).map_err(LoadError::Io)?;
    let handle: SeedHandle = serde_json::from_str(&raw).map_err(LoadError::Parse)?;

    let host = params
        .host
        .clone()
        .unwrap_or_else(|| handle.target_host.clone());

    let context = LoadContext::from_handle(&handle, DEV_ADMIN_EMAIL, DEV_ADMIN_PASSWORD)
        .map_err(LoadError::Context)?;
    scenarios::set_context(Arc::new(context));

    let weights = params.weights();
    let scenario = scenarios::build_scenario(&weights)?;

    println!(
        "hearth-loadtest run: host={host} users={} run_time={} hatch_rate={}",
        params.users, params.run_time, params.hatch_rate
    );
    println!(
        "  weights: validate={} session={} user={} issuance={} revoke={} (corpus: {})",
        weights.validate,
        weights.session,
        weights.user,
        weights.issuance,
        weights.revoke,
        handle.dataset_shape,
    );

    let config = build_config(params, host);
    GooseAttack::initialize_with_config(config)?
        .register_scenario(scenario)
        .execute()
        .await?;
    Ok(())
}

/// Builds a Goose configuration from the CLI params.
///
/// Starts from `GooseConfiguration::default()` (all Goose flags at their
/// defaults) and overrides only the run knobs. The telnet/websocket controllers
/// are disabled — this is a one-shot headless run, not an interactive session.
// GooseConfiguration exposes no builder, so we reassign fields on a default.
#[allow(clippy::field_reassign_with_default)]
fn build_config(params: &LoadParams, host: String) -> GooseConfiguration {
    let mut config = GooseConfiguration::default();
    config.host = host;
    config.users = Some(params.users);
    config.run_time = params.run_time.clone();
    config.hatch_rate = Some(params.hatch_rate.clone());
    config.throttle_requests = params.throttle;
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
        assert!(w.issuance >= w.user || w.issuance == w.user);
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
        assert_eq!(w.validate, 40);
        assert_eq!(w.session, 30);
        assert_eq!(w.user, 20);
        assert_eq!(w.issuance, 5);
        assert_eq!(w.revoke, 5);
        assert_eq!(w.total(), 100);
        // A fully-weighted override still builds all five journeys.
        let scenario = scenarios::build_scenario(&w).expect("scenario");
        assert_eq!(scenario.transactions.len(), 5);
    }

    #[test]
    fn zero_weight_override_drops_a_journey() {
        let p = parse(&["--weight-revoke", "0", "--weight-issuance", "0"]);
        let w = p.weights();
        assert_eq!(w.issuance, 0);
        assert_eq!(w.revoke, 0);
        let scenario = scenarios::build_scenario(&w).expect("scenario");
        assert_eq!(
            scenario.transactions.len(),
            3,
            "issuance + revoke dropped, three journeys remain"
        );
    }

    #[test]
    fn run_knobs_parse() {
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
        assert_eq!(p.users, 100);
        assert_eq!(p.run_time, "5m");
        assert_eq!(p.hatch_rate, "10");
        assert_eq!(p.throttle, 25);
        assert_eq!(p.host.as_deref(), Some("http://127.0.0.1:9999"));
        let config = build_config(&p, "http://127.0.0.1:9999".to_string());
        assert_eq!(config.users, Some(100));
        assert_eq!(config.run_time, "5m");
        assert_eq!(config.hatch_rate.as_deref(), Some("10"));
        assert_eq!(config.throttle_requests, 25);
        assert!(config.no_telnet);
        assert!(config.no_websocket);
    }
}
