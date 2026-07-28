//! Open-loop saturation driver (C4, HEA-1872).
//!
//! Drives `N` concurrent TCP connections against a single read-only hot-path
//! journey, **decoupling connection concurrency from the session-token pool
//! size**: 10 000 connections can cycle through 1 000 tokens because multiple
//! connections share tokens. Each connection is a Tokio task in a tight
//! request/response loop — no Goose overhead per task; only reqwest + tokio
//! machinery.
//!
//! The exit criterion (HEA-1872): a ≥10 000-concurrent-client run whose
//! `ceiling_attribution` is `server`, not `generator_saturated`. The existing
//! [`crate::report::Ceiling`] logic drives the verdict — a server-bound run
//! shows latency breach; a generator-bound run shows elevated errors without a
//! latency breach. An additional generator CPU% sample augments the verdict when
//! the CPU exceeds 80%.
//!
//! ## OS tuning for high connection counts
//!
//! ```text
//! ulimit -n 16384                # raise file-descriptor limit (per shell)
//! sysctl net.ipv4.tcp_tw_reuse=1 # allow TIME_WAIT reuse (if needed)
//! ```
//!
//! See the README "Driving high concurrency" section for persistent tuning.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::Client;

use crate::budget;
use crate::handle::SeedHandle;
use crate::latency;
use crate::load::{LoadError, LoadParams, Mode, SaturateJourney};
use crate::report::{self, JourneyRow, LoadReport, RunMetadata, SCHEMA_VERSION};
use crate::scenarios::LoadContext;

/// Runs the open-loop saturation driver against a seed-handle-backed corpus.
///
/// Spawns `params.saturate_connections` Tokio tasks, each maintaining one TCP
/// connection (a private `reqwest::Client` with `pool_max_idle_per_host=1`).
/// Requests fire in a tight loop for the configured `run_time`; token selection
/// round-robins the live-token pool independently from the connection index, so
/// `N` connections can share `K < N` tokens.
///
/// # Errors
/// Returns [`LoadError::Saturate`] if the reqwest client fails to build, or
/// [`LoadError::Report`] if the JSON report cannot be written.
pub async fn run_saturate(
    params: &LoadParams,
    host: &str,
    ctx: Arc<LoadContext>,
    handle: &SeedHandle,
    _report_dir: &std::path::Path,
) -> Result<LoadReport, LoadError> {
    let connections = params.saturate_connections;
    let journey = params.saturate_journey;
    let run_duration = parse_duration(&params.run_time);
    let token_count = ctx.live_tokens_len();

    if connections == 0 {
        return Err(LoadError::Saturate(
            "--saturate-connections must be at least 1".to_string(),
        ));
    }

    println!(
        "hearth-loadtest saturate: host={host} connections={connections} \
         journey={} run_time={} token_pool={token_count}",
        journey.journey_name(),
        params.run_time,
    );
    if connections > token_count {
        #[allow(clippy::cast_precision_loss)]
        let reuse = connections as f64 / token_count.max(1) as f64;
        println!(
            "  note: {connections} connections × {token_count} tokens \
             ({reuse:.1}× reuse) — connections > sessions is the C4 design point"
        );
    }

    latency::reset();
    let gen_cpu_before = proc_self_jiffies();

    let total_requests = Arc::new(AtomicU64::new(0));
    let total_errors = Arc::new(AtomicU64::new(0));

    // One shared client with a large idle-connection pool.  Active connections
    // are never subject to `pool_max_idle_per_host`; the cap only controls
    // how many idle connections to keep after responses complete.  At 10 k
    // concurrent tasks all immediately re-sending, the pool stays hot.
    let client = Arc::new(
        Client::builder()
            .pool_max_idle_per_host(connections.min(4_096))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| LoadError::Saturate(format!("reqwest client build: {e}")))?,
    );

    let host_arc = Arc::new(host.to_string());
    let deadline = Instant::now() + run_duration;
    let run_start = Instant::now();

    let mut task_handles = Vec::with_capacity(connections);
    for _ in 0..connections {
        let reqs = Arc::clone(&total_requests);
        let errs = Arc::clone(&total_errors);
        let client = Arc::clone(&client);
        let ctx = Arc::clone(&ctx);
        let host = Arc::clone(&host_arc);

        task_handles.push(tokio::spawn(async move {
            // Compute once per task (these don't change between requests).
            let realm_id = ctx.realm_id().to_string();
            let client_id_val = ctx.client_id().to_string();

            loop {
                if Instant::now() >= deadline {
                    break;
                }

                // Owned Strings so they don't borrow across the await point.
                let token = ctx.live_token_cloned();

                let start = Instant::now();
                let ok = match journey {
                    SaturateJourney::Validate => {
                        fire_validate(&client, &host, &realm_id, &client_id_val, &token).await
                    }
                    SaturateJourney::Session => {
                        fire_session(&client, &host, &realm_id, &token).await
                    }
                    SaturateJourney::User => {
                        let uid = ctx.user_id_cloned();
                        fire_user(&client, &host, &realm_id, &uid, &token).await
                    }
                };
                let elapsed = start.elapsed();

                reqs.fetch_add(1, Ordering::Relaxed);
                if ok {
                    latency::record(journey.journey_name(), elapsed);
                } else {
                    errs.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }

    for task in task_handles {
        let _ = task.await;
    }
    let elapsed = run_start.elapsed();

    let gen_cpu_after = proc_self_jiffies();
    let gen_cpu_pct = cpu_pct(gen_cpu_before, gen_cpu_after, elapsed);

    let total_req = total_requests.load(Ordering::Relaxed);
    let total_err = total_errors.load(Ordering::Relaxed);
    #[allow(clippy::cast_precision_loss)]
    let achieved_rps = total_req as f64 / elapsed.as_secs_f64().max(0.001);

    let percentiles = latency::snapshot_percentiles();
    let extremes = latency::snapshot();
    let journey_name = journey.journey_name();
    let pct_data = percentiles.per_journey.get(journey_name);

    let p50_us = pct_data.map_or(0, |p| p.p50_us);
    let p95_us = pct_data.map_or(0, |p| p.p95_us);
    let p99_us = pct_data.map_or(0, |p| p.p99_us);
    let p100_us = pct_data.map_or(0, |p| p.p100_us);
    let ext = extremes.get(journey_name);

    #[allow(clippy::cast_possible_truncation)]
    let reqs_usize = total_req.min(usize::MAX as u64) as usize;
    #[allow(clippy::cast_possible_truncation)]
    let errs_usize = total_err.min(usize::MAX as u64) as usize;
    let fail_rate = budget::failure_rate(errs_usize, reqs_usize);
    let budget_opt = budget::budget_for(journey_name);

    // µs-resolution pass verdict — more accurate than the whole-ms rounding
    // used by the Goose-based modes (e.g. 1.4 ms p99 vs a 1.5 ms budget).
    let pass = budget_opt.map(|b| p99_us <= b.http_p99_us && fail_rate <= budget::MAX_FAILURE_RATE);

    let row = JourneyRow {
        journey: journey_name.to_string(),
        method: journey.http_method().to_string(),
        requests: reqs_usize,
        failures: errs_usize,
        failure_rate: fail_rate,
        #[allow(clippy::cast_possible_truncation)]
        p50_ms: (p50_us / 1_000) as usize,
        #[allow(clippy::cast_possible_truncation)]
        p95_ms: (p95_us / 1_000) as usize,
        #[allow(clippy::cast_possible_truncation)]
        p99_ms: (p99_us / 1_000) as usize,
        #[allow(clippy::cast_possible_truncation)]
        p999_ms: (p100_us / 1_000) as usize,
        min_us: ext.map(|e| e.min_us),
        max_us: ext.map(|e| e.max_us),
        spec_engine_p99_us: budget_opt.map(|b| b.spec_engine_p99_us),
        http_budget_p99_us: budget_opt.map(|b| b.http_p99_us),
        pass,
    };

    let rows = vec![row];
    let mut summary = report::summarize(&rows, connections, achieved_rps);

    // Augment with generator CPU% when available: CPU > 80% with no server
    // latency breach means the generator itself is the bottleneck.
    if let Some(cpu) = gen_cpu_pct {
        if cpu > 80.0 && summary.ceiling != report::Ceiling::Server {
            summary.ceiling = report::Ceiling::GeneratorSaturated;
            summary.ceiling_reason = format!(
                "generator CPU {cpu:.1}% > 80% with no server latency breach — \
                 the load generator is CPU-bound; move the driver to a dedicated \
                 host or reduce --saturate-connections (README 'Driving high \
                 concurrency')"
            );
        }
    }

    println!(
        "  done: connections={connections} rps={achieved_rps:.0} \
         p99={p99_us}µs errors={total_err}/{total_req} ceiling={:?} gen_cpu={}",
        summary.ceiling,
        gen_cpu_pct.map_or_else(|| "unavailable".to_string(), |c| format!("{c:.1}%")),
    );

    let meta = saturate_metadata(params, host, connections, handle);
    let pass_overall = report::overall_pass(&rows);

    Ok(LoadReport {
        schema: SCHEMA_VERSION,
        metadata: meta,
        summary,
        journeys: rows,
        ramp_steps: None,
        knee_rps: None,
        soak_buckets: None,
        tier_miss: None,
        resources: None,
        pass: pass_overall,
    })
}

// ── HTTP request helpers ─────────────────────────────────────────────────────

/// `POST /introspect {token, client_id}` — returns `true` on HTTP 2xx.
async fn fire_validate(
    client: &Client,
    host: &str,
    realm_id: &str,
    client_id: &str,
    token: &str,
) -> bool {
    match client
        .post(format!("{host}/introspect"))
        .header("X-Realm-ID", realm_id)
        .json(&serde_json::json!({"token": token, "client_id": client_id}))
        .send()
        .await
    {
        Err(_) => false,
        Ok(resp) => {
            let ok = resp.status().is_success();
            // Consume the body so the TCP connection returns to the pool
            // promptly for the next request on this task.
            let _ = resp.bytes().await;
            ok
        }
    }
}

/// `GET /userinfo` with Bearer token — returns `true` on HTTP 2xx.
async fn fire_session(client: &Client, host: &str, realm_id: &str, token: &str) -> bool {
    match client
        .get(format!("{host}/userinfo"))
        .header("X-Realm-ID", realm_id)
        .bearer_auth(token)
        .send()
        .await
    {
        Err(_) => false,
        Ok(resp) => {
            let ok = resp.status().is_success();
            let _ = resp.bytes().await;
            ok
        }
    }
}

/// `GET /admin/users/{user_id}` with Bearer token — returns `true` on HTTP 2xx.
async fn fire_user(
    client: &Client,
    host: &str,
    realm_id: &str,
    user_id: &str,
    token: &str,
) -> bool {
    match client
        .get(format!("{host}/admin/users/{user_id}"))
        .header("X-Realm-ID", realm_id)
        .bearer_auth(token)
        .send()
        .await
    {
        Err(_) => false,
        Ok(resp) => {
            let ok = resp.status().is_success();
            let _ = resp.bytes().await;
            ok
        }
    }
}

// ── Generator CPU measurement ────────────────────────────────────────────────

/// Reads the generator process's cumulative CPU jiffies from `/proc/self/stat`
/// (fields 14 + 15: utime + stime). Returns `None` on any parse error or if
/// `/proc/self/stat` is unavailable (non-Linux).
fn proc_self_jiffies() -> Option<u64> {
    let content = std::fs::read_to_string("/proc/self/stat").ok()?;
    let parts: Vec<&str> = content.split_whitespace().collect();
    let utime: u64 = parts.get(13)?.parse().ok()?;
    let stime: u64 = parts.get(14)?.parse().ok()?;
    Some(utime + stime)
}

/// Computes the generator's CPU utilisation as a percentage of all available
/// cores over `elapsed`. Returns `None` if either jiffy sample is unavailable.
///
/// Linux jiffies tick at `CONFIG_HZ` (typically 100 Hz). `delta / 100` = CPU
/// seconds used; divided by `elapsed × num_cpus` gives a [0, 1] fraction.
fn cpu_pct(before: Option<u64>, after: Option<u64>, elapsed: Duration) -> Option<f64> {
    let delta = after?.checked_sub(before?)?;
    let num_cpus = std::thread::available_parallelism()
        .map(|n| n.get() as f64)
        .unwrap_or(1.0);
    let elapsed_secs = elapsed.as_secs_f64();
    if elapsed_secs <= 0.0 || num_cpus <= 0.0 {
        return None;
    }
    #[allow(clippy::cast_precision_loss)]
    let cpu_secs = delta as f64 / 100.0; // 100 Hz jiffy clock
    Some((cpu_secs / (elapsed_secs * num_cpus)) * 100.0)
}

// ── Utilities ────────────────────────────────────────────────────────────────

/// Parses a Goose-style duration string (`"60s"`, `"5m"`, `"1h"`, or a bare
/// number of seconds). Falls back to 60 s on any parse error.
pub(crate) fn parse_duration(s: &str) -> Duration {
    if let Some(n) = s.strip_suffix('h').and_then(|n| n.parse::<u64>().ok()) {
        return Duration::from_secs(n * 3_600);
    }
    if let Some(n) = s.strip_suffix('m').and_then(|n| n.parse::<u64>().ok()) {
        return Duration::from_secs(n * 60);
    }
    if let Some(n) = s.strip_suffix('s').and_then(|n| n.parse::<u64>().ok()) {
        return Duration::from_secs(n);
    }
    if let Ok(n) = s.parse::<u64>() {
        return Duration::from_secs(n);
    }
    Duration::from_secs(60)
}

/// Builds the report metadata header for a saturate run.
fn saturate_metadata(
    params: &LoadParams,
    host: &str,
    connections: usize,
    handle: &SeedHandle,
) -> RunMetadata {
    RunMetadata {
        git_sha: crate::load::git_sha(),
        timestamp_unix: crate::load::now_unix(),
        mode: Mode::Saturate.as_str().to_string(),
        host: host.to_string(),
        seed: handle.seed,
        dataset_shape: handle.dataset_shape.clone(),
        // `users` maps to connections in saturate mode: the concurrency knob.
        users: connections,
        run_time: params.run_time.clone(),
        hatch_rate: "instantaneous (open-loop)".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_handles_suffixes() {
        assert_eq!(parse_duration("60s"), Duration::from_secs(60));
        assert_eq!(parse_duration("5m"), Duration::from_secs(300));
        assert_eq!(parse_duration("2h"), Duration::from_secs(7_200));
        assert_eq!(parse_duration("120"), Duration::from_secs(120));
    }

    #[test]
    fn parse_duration_fallback_on_garbage() {
        assert_eq!(parse_duration("bogus"), Duration::from_secs(60));
        assert_eq!(parse_duration(""), Duration::from_secs(60));
    }

    #[test]
    fn saturate_journey_names_and_methods() {
        assert_eq!(SaturateJourney::Validate.journey_name(), "validate");
        assert_eq!(SaturateJourney::Session.journey_name(), "session_lookup");
        assert_eq!(SaturateJourney::User.journey_name(), "user_lookup");

        assert_eq!(SaturateJourney::Validate.http_method(), "POST");
        assert_eq!(SaturateJourney::Session.http_method(), "GET");
        assert_eq!(SaturateJourney::User.http_method(), "GET");
    }

    #[test]
    fn cpu_pct_computes_correctly() {
        let num_cpus = std::thread::available_parallelism()
            .map(|n| n.get() as f64)
            .unwrap_or(1.0);

        // `num_cpus × 100` jiffies in 1 s = 100% across all cores.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let jiffies = (num_cpus * 100.0).round() as u64;
        let pct = cpu_pct(Some(0), Some(jiffies), Duration::from_secs(1));
        assert!(
            (pct.unwrap() - 100.0).abs() < 0.5,
            "expected ~100%: {pct:?}"
        );

        // 0 delta → 0%.
        let zero = cpu_pct(Some(50), Some(50), Duration::from_secs(1));
        assert!(zero.unwrap().abs() < 0.1);

        // Missing samples → None.
        assert!(cpu_pct(None, Some(100), Duration::from_secs(1)).is_none());
        assert!(cpu_pct(Some(0), None, Duration::from_secs(1)).is_none());
    }
}
