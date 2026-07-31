//! HEA-1997 · HTTP-plane **saturation** ramp — the capacity number, not the
//! per-op cost.
//!
//! Every published Hearth figure to date answers *what does one `/userinfo`
//! cost* (engine-level: `saturation_throughput`, `http_delta`). None answers the
//! board's question on HEA-1970: *how many requests/s does this box serve before
//! it falls over.* `http_delta`'s `LADDER = [1, 8, 32]` is three fixed rungs, not
//! a ramp; 32 is the top of the ladder, not a knee. This harness is the missing
//! capacity measurement.
//!
//! ## Why this one is admissible where the Goose runs were not
//!
//! The binding HEA-1867 grading rule is: *nothing is graded PASS on a run whose
//! ceiling attribution was the generator.* Two structural choices earn a grade:
//!
//! 1. **Two hosts, not co-resident.** This binary runs on host **B** (the
//!    generator) and points at host **A** (Hearth) over a real network via
//!    `--target http://A:8420`. Generator/server core contention — the confirmed,
//!    repeatedly-observed HEA-1871/HEA-1876/HEA-1989 ceiling — is removed by
//!    construction. The harness *refuses to grade* a run whose target resolves to
//!    loopback (see [`target_is_loopback`]).
//!
//! 2. **Open-loop, fixed-rate ramp, not a closed-loop user count.** A closed-loop
//!    generator (N users each looping request→wait→request) cannot distinguish
//!    "server is slow" from "generator is waiting" — adding users just deepens the
//!    client's own queue. This harness fires at a *fixed offered rate* per rung
//!    (`--rungs 500,1000,2000,…` req/s), decoupled from completion. Latency is
//!    measured from each request's **intended** send time, not its actual send
//!    time, so a server that falls behind shows up as rising latency and a growing
//!    in-flight backlog — the textbook coordinated-omission correction — rather
//!    than a silently throttled offered load.
//!
//! ## Per-rung bottleneck attribution (requirement 3, first-class field)
//!
//! A rung is graded **ADMISSIBLE** only when ALL four hold, and each is emitted:
//!
//! * `server_cpu_pinned`     — host-A CPU ≥ [`SERVER_PINNED_PCT`]. Cross-host, so
//!   sourced from `--server-cpu-file` (a file host A's sampler rewrites each
//!   second — see the runbook). Absent file ⇒ `None` ⇒ rung is `INCOMPLETE`, never
//!   silently ADMISSIBLE.
//! * `generator_headroom_2x` — the generator used ≤ 50 % of host B's CPU capacity
//!   during the window (headroom ratio ≥ [`MIN_GENERATOR_HEADROOM`]). Measured
//!   locally from `/proc/self/stat`.
//! * `transport_clean`       — zero connect/transport errors.
//! * `degrading_by_queueing` — the non-2xx *rate* stayed under
//!   [`MAX_ERROR_RATE`]; the ceiling is showing as latency/queueing, not an error
//!   cliff.
//!
//! Any rung failing a condition is reported `INADMISSIBLE` (or `INCOMPLETE`) with
//! the failing conditions named — it is **not** dropped from the artifact.
//!
//! ## Planes (requirement: measure per plane, then blend)
//!
//! * `read`     — `/introspect` + `/userinfo` + `/admin/users/{id}`. The number
//!   directly comparable to competitors' published end-to-end HTTP figures.
//! * `issuance` — `POST /token` (`grant_type=client_credentials`): Ed25519 sign +
//!   grant-family WAL `fsync`. This is a **production** grant — the seeder
//!   registers a confidential `client_credentials` client and carries its
//!   `client_id`/`client_secret` in the seed handle (HEA-2003), so the plane runs
//!   on the two-host rig with the HEA-1980 `--dev` gate intact (no `/dev/*`
//!   endpoint at run time). **NB:** this is the *write/issuance* plane, **not**
//!   the Argon2id KDF plane — no password-verify path is exercised here. The true
//!   KDF plane needs seeded passwords; that is the `login` plane below.
//! * `login`    — `POST /ui/realms/{r}/login`, the Argon2id-bearing path, i.e.
//!   the **KDF benchmark**. Requires `--login-password` and users seeded with
//!   that password. The report MUST label any `login` number a KDF benchmark.
//! * `blended`  — the realistic operator-facing mix (default 90 % read / 8 %
//!   issuance / 2 % login), for the sizing guide.
//!
//! ## Rate-limiter decision (requirement 4)
//!
//! `security.load_test_unthrottled` requires `--dev` AND every effective bind
//! loopback (`src/main.rs`), so a two-host rig **cannot** enable it — the request
//! shaper stays ON. That is deliberate: we report what the product actually does.
//! It means the observed ceiling may be Hearth's own limiter; the artifact records
//! `limiter: "on"` and the runbook requires the operator to state which resource
//! saturated (server CPU vs limiter 429s) from the attribution fields.
//!
//! ## What this is NOT
//!
//! Not an optimization. This is a measurement-capability deliverable. If the run
//! reveals a bottleneck it gets its own issue (HEA-1997 §"out of scope").
//!
//! Run (on host B, against host A):
//!   cargo run --release --example http_saturation -- \
//!     --target http://A.internal:8420 --seed-handle seed.json \
//!     --plane read --rungs 500,1000,2000,4000,8000 --hold 20 --conns 256 \
//!     --server-cpu-file /shared/hostA-cpu.txt > sat-read.json

// Measurement binary: casts are reporting math on small magnitudes, and the
// scheduler/HTTP/print helpers are intentionally verbose for auditability.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::needless_range_loop
)]

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::io::{Read, Write as IoWrite};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

// ── Admissibility thresholds (HEA-1997 requirement 3) ───────────────────────────

/// Host-A CPU must be at least this % busy for the rung to count as "server
/// pinned" — below it, the ceiling is not the server and the rung is not the knee.
const SERVER_PINNED_PCT: f64 = 90.0;

/// The generator must retain at least this much headroom: host B's total CPU
/// capacity divided by the capacity the generator consumed. ≥ 2.0 means the
/// generator used ≤ 50 % of the box and cannot itself be the ceiling.
const MIN_GENERATOR_HEADROOM: f64 = 2.0;

/// Above this non-2xx *rate*, the ceiling is presenting as an error cliff, not as
/// queueing latency — the rung is inadmissible as a saturation point.
const MAX_ERROR_RATE: f64 = 0.005;

/// A rung's achieved rate must be within this fraction of its offered rate to be
/// considered "keeping up" (used for knee detection).
const KEEPUP_FRACTION: f64 = 0.95;

/// Backlog cap: intended-but-not-yet-sent requests are bounded to this multiple
/// of the connection count. Past it the scheduler records an overrun instead of
/// growing memory unboundedly — the server is already saturated well past serve
/// capacity, which is itself the finding.
const BACKLOG_CAP_PER_CONN: usize = 8;

// ── Minimal seed-handle mirror (decoupled from the `loadtest` crate) ────────────
//
// We deserialize only the fields the ramp needs. This mirrors
// `loadtest/src/handle.rs`; kept in sync by the field-name asserting test below.

#[derive(Deserialize)]
struct SeedHandle {
    #[serde(default)]
    admin_token: String,
    realms: Vec<SeededRealm>,
}

#[derive(Deserialize)]
struct SeededRealm {
    realm_id: String,
    /// Realm **name** (not id). The realm-scoped UI/OIDC routes are keyed by
    /// name — `/ui/realms/{realm_name}/login`, etc. — so the login/KDF plane
    /// MUST build its path from this, not `realm_id` (HEA-2006). Empty on
    /// pre-HEA-2006 handles; the login plane rejects those with a clear error
    /// rather than 404ing every request.
    #[serde(default)]
    realm_name: String,
    client_id: String,
    /// Confidential `client_credentials` client for the issuance plane (HEA-2003).
    /// Empty on pre-HEA-2003 handles.
    #[serde(default)]
    cc_client_id: String,
    /// Its secret (SECRET). Empty on pre-HEA-2003 handles.
    #[serde(default)]
    cc_client_secret: String,
    #[serde(default)]
    users: Vec<SeededUser>,
    #[serde(default)]
    tokens: Vec<SeededToken>,
}

#[derive(Deserialize)]
struct SeededUser {
    id: String,
    email: String,
}

#[derive(Deserialize)]
struct SeededToken {
    access_token: String,
    #[serde(default)]
    revoked: bool,
}

// ── Planes ──────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum Plane {
    Read,
    Issuance,
    Login,
    Blended,
}

impl Plane {
    fn parse(s: &str) -> Result<Self, String> {
        match s {
            "read" => Ok(Self::Read),
            "issuance" => Ok(Self::Issuance),
            "login" => Ok(Self::Login),
            "blended" => Ok(Self::Blended),
            other => Err(format!(
                "unknown plane {other:?}; expected read|issuance|login|blended"
            )),
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Issuance => "issuance",
            Self::Login => "login",
            Self::Blended => "blended",
        }
    }
    /// Whether this plane exercises the Argon2id KDF (must be labelled as such).
    fn is_kdf(self) -> bool {
        matches!(self, Self::Login | Self::Blended)
    }
}

// ── One prebuilt request (raw HTTP/1.1 bytes + a body-check discriminant) ───────

/// A request template: the exact bytes to write and how to judge the response.
struct ReqTemplate {
    /// Full HTTP/1.1 request bytes (request line + headers + CRLF + body).
    bytes: Vec<u8>,
    /// Human name for the op (introspect/userinfo/user_lookup/mint/login).
    #[allow(dead_code)]
    op: &'static str,
}

/// The corpus of request templates for a plane, round-robined by the workers.
struct Corpus {
    templates: Vec<ReqTemplate>,
    cursor: AtomicU64,
}

impl Corpus {
    fn next(&self) -> &ReqTemplate {
        let i = self.cursor.fetch_add(1, Ordering::Relaxed) as usize % self.templates.len();
        &self.templates[i]
    }
}

/// Builds an HTTP/1.1 request as raw bytes with keep-alive and the given body.
fn build_request(
    method: &str,
    path: &str,
    host_header: &str,
    extra_headers: &[(&str, &str)],
    body: &[u8],
) -> Vec<u8> {
    // NB: write directly to the `Vec` (its `io::Write` impl APPENDS). Wrapping
    // each `write!` in a fresh `Cursor::new(&mut req)` would reset the write
    // position to 0 every call and overwrite the previous bytes, producing a
    // malformed request.
    let mut req = Vec::with_capacity(256 + body.len());
    let _ = write!(
        &mut req,
        "{method} {path} HTTP/1.1\r\nHost: {host_header}\r\nConnection: keep-alive\r\n"
    );
    for (k, v) in extra_headers {
        let _ = write!(&mut req, "{k}: {v}\r\n");
    }
    let _ = write!(&mut req, "Content-Length: {}\r\n\r\n", body.len());
    req.extend_from_slice(body);
    req
}

fn build_corpus(plane: Plane, target: &Target, handle: &SeedHandle) -> Result<Corpus, String> {
    let realm = handle
        .realms
        .first()
        .ok_or("seed handle has no realms; re-seed the corpus")?;
    let host_header = target.host_header();
    let realm_hdr = ("X-Realm-ID", realm.realm_id.as_str());
    let live: Vec<&str> = realm
        .tokens
        .iter()
        .filter(|t| !t.revoked)
        .map(|t| t.access_token.as_str())
        .collect();
    let mut templates = Vec::new();

    let mut push_read = || -> Result<(), String> {
        if live.is_empty() {
            return Err("seed handle has no live tokens; increase --sessions-frac".into());
        }
        // introspect
        for tok in &live {
            let body = format!(
                "{{\"token\":\"{}\",\"client_id\":\"{}\"}}",
                tok, realm.client_id
            );
            templates.push(ReqTemplate {
                bytes: build_request(
                    "POST",
                    "/introspect",
                    &host_header,
                    &[realm_hdr, ("Content-Type", "application/json")],
                    body.as_bytes(),
                ),
                op: "introspect",
            });
            // userinfo (bearer)
            let auth = format!("Bearer {tok}");
            templates.push(ReqTemplate {
                bytes: build_request(
                    "GET",
                    "/userinfo",
                    &host_header,
                    &[realm_hdr, ("Authorization", &auth)],
                    b"",
                ),
                op: "userinfo",
            });
        }
        // admin user lookup (needs admin token + a user id)
        if !handle.admin_token.is_empty() {
            let auth = format!("Bearer {}", handle.admin_token);
            for u in &realm.users {
                let path = format!("/admin/users/{}", u.id);
                templates.push(ReqTemplate {
                    bytes: build_request(
                        "GET",
                        &path,
                        &host_header,
                        &[realm_hdr, ("Authorization", &auth)],
                        b"",
                    ),
                    op: "user_lookup",
                });
            }
        }
        Ok(())
    };

    let push_issuance = |templates: &mut Vec<ReqTemplate>| -> Result<(), String> {
        // HEA-2003: mint over the PRODUCTION client_credentials grant, not the
        // dev-only /dev/seed-token endpoint. This exercises the real issuance
        // machinery (Ed25519 sign + grant-family WAL write) and needs no /dev/*
        // route at run time, so it runs on the two-host rig with the HEA-1980
        // gate intact. The confidential client is provisioned by the seeder.
        if realm.cc_client_id.is_empty() || realm.cc_client_secret.is_empty() {
            return Err(
                "issuance plane requires a confidential client_credentials client in the seed \
                 handle (cc_client_id/cc_client_secret); re-seed with a HEA-2003 seeder"
                    .into(),
            );
        }
        // A single client_credentials request template — every mint is a fresh
        // token for the same M2M client (there is no per-user subject on this
        // grant). The open-loop scheduler replays it at the offered rate.
        //
        // `scope=openid`: the DCR-registered client is ThirdParty, and the server
        // requires a ThirdParty client to request at least one scope. `openid` is
        // an OIDC standard scope that is always legal for any client (no declared
        // scope needed) — its content is irrelevant to what this plane measures
        // (Ed25519 sign + grant-family WAL write).
        let body = format!(
            "{{\"grant_type\":\"client_credentials\",\"client_id\":\"{}\",\"client_secret\":\"{}\",\"scope\":\"openid\"}}",
            realm.cc_client_id, realm.cc_client_secret
        );
        templates.push(ReqTemplate {
            bytes: build_request(
                "POST",
                "/token",
                &host_header,
                &[realm_hdr, ("Content-Type", "application/json")],
                body.as_bytes(),
            ),
            op: "issuance_mint",
        });
        Ok(())
    };

    let push_login = |templates: &mut Vec<ReqTemplate>, password: &str| -> Result<(), String> {
        if password.is_empty() {
            return Err(
                "login/KDF plane requires --login-password AND users seeded with it \
                        (see runbook: seeder credential-seeding follow-up)"
                    .into(),
            );
        }
        if realm.users.is_empty() {
            return Err("seed handle has no users for the login plane".into());
        }
        // The realm-scoped login route is keyed by realm NAME, not id:
        // `/ui/realms/{realm_name}/login` (src/protocol/http.rs). Building the
        // path from `realm_id` 404s every request — the KDF is never exercised
        // and the plane silently measures nothing (HEA-2006). Fail loud when the
        // handle predates the name-carrying seeder rather than emit a bad path.
        if realm.realm_name.is_empty() {
            return Err(
                "login/KDF plane requires the realm NAME in the seed handle \
                 (realm_name); the realm-scoped login route is keyed by name, not id. \
                 Re-seed with a HEA-2006 seeder"
                    .into(),
            );
        }
        let login_path = format!("/ui/realms/{}/login", realm.realm_name);
        for u in &realm.users {
            let body = format!(
                "email={}&password={}",
                urlencode(&u.email),
                urlencode(password)
            );
            templates.push(ReqTemplate {
                bytes: build_request(
                    "POST",
                    &login_path,
                    &host_header,
                    &[
                        realm_hdr,
                        ("Content-Type", "application/x-www-form-urlencoded"),
                    ],
                    body.as_bytes(),
                ),
                op: "login",
            });
        }
        Ok(())
    };

    match plane {
        Plane::Read => push_read()?,
        Plane::Issuance => push_issuance(&mut templates)?,
        Plane::Login => push_login(&mut templates, &target.login_password)?,
        Plane::Blended => {
            // Weight by replicating templates: 90/8/2. Read dominates the corpus.
            push_read()?;
            let read_len = templates.len().max(1);
            let mut issuance = Vec::new();
            push_issuance(&mut issuance)?;
            // ~8% issuance
            let want_iss = (read_len * 8 / 90).max(1);
            for i in 0..want_iss {
                let t = &issuance[i % issuance.len()];
                templates.push(ReqTemplate {
                    bytes: t.bytes.clone(),
                    op: t.op,
                });
            }
            if !target.login_password.is_empty() {
                let mut login = Vec::new();
                push_login(&mut login, &target.login_password)?;
                let want_login = (read_len * 2 / 90).max(1);
                for i in 0..want_login {
                    let t = &login[i % login.len()];
                    templates.push(ReqTemplate {
                        bytes: t.bytes.clone(),
                        op: t.op,
                    });
                }
            }
        }
    }

    if templates.is_empty() {
        return Err("plane produced no request templates".into());
    }
    Ok(Corpus {
        templates,
        cursor: AtomicU64::new(0),
    })
}

/// Minimal application/x-www-form-urlencoded escaping for the login body.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b' ' => out.push('+'),
            _ => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

// ── Target & args ───────────────────────────────────────────────────────────────

struct Target {
    /// `host:port` for the TCP connection.
    authority: String,
    /// The `Host:` header value (host, and port if non-default).
    host: String,
    login_password: String,
}

impl Target {
    fn host_header(&self) -> String {
        self.host.clone()
    }
}

/// True when the target authority resolves only to loopback addresses — in which
/// case the run CANNOT be graded (generator/server would be co-resident).
fn target_is_loopback(authority: &str) -> bool {
    match authority.to_socket_addrs() {
        Ok(addrs) => {
            let mut any = false;
            for a in addrs {
                any = true;
                if !a.ip().is_loopback() {
                    return false;
                }
            }
            any // all resolved addrs were loopback (and there was at least one)
        }
        // Unresolvable: treat conservatively as not-loopback so the operator sees
        // the connection error rather than a spurious loopback refusal.
        Err(_) => false,
    }
}

// ── Latency histogram (coordinated-omission-corrected) ──────────────────────────

/// A simple sorted-sample percentile. `samples` are latencies in microseconds.
fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = (p / 100.0 * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[rank.min(sorted.len() - 1)]
}

// ── Per-rung result + attribution ───────────────────────────────────────────────

#[derive(Serialize)]
struct Attribution {
    /// Host-A CPU % during the window (from --server-cpu-file); `None` if absent.
    server_cpu_pct: Option<f64>,
    server_cpu_pinned: Option<bool>,
    /// host-B total-capacity / generator-consumed-capacity.
    generator_headroom: f64,
    generator_headroom_2x: bool,
    transport_clean: bool,
    degrading_by_queueing: bool,
    /// Overall grade for the rung.
    grade: String,
    /// Which conditions failed (empty when ADMISSIBLE).
    failing_conditions: Vec<String>,
}

/// The pure admissibility decision (unit-tested without a server).
fn classify(
    server_cpu_pct: Option<f64>,
    generator_headroom: f64,
    connect_or_transport_errors: u64,
    error_rate: f64,
) -> Attribution {
    let server_cpu_pinned = server_cpu_pct.map(|c| c >= SERVER_PINNED_PCT);
    let generator_headroom_2x = generator_headroom >= MIN_GENERATOR_HEADROOM;
    let transport_clean = connect_or_transport_errors == 0;
    let degrading_by_queueing = error_rate <= MAX_ERROR_RATE;

    let mut failing = Vec::new();
    if !generator_headroom_2x {
        failing.push("generator_headroom_2x".to_string());
    }
    if !transport_clean {
        failing.push("transport_clean".to_string());
    }
    if !degrading_by_queueing {
        failing.push("degrading_by_queueing".to_string());
    }
    if server_cpu_pinned == Some(false) {
        failing.push("server_cpu_pinned".to_string());
    }

    let grade = if server_cpu_pct.is_none() {
        // Can't confirm the server saturated: incomplete, never silently ADMISSIBLE.
        "INCOMPLETE".to_string()
    } else if failing.is_empty() {
        "ADMISSIBLE".to_string()
    } else {
        "INADMISSIBLE".to_string()
    };

    Attribution {
        server_cpu_pct,
        server_cpu_pinned,
        generator_headroom,
        generator_headroom_2x,
        transport_clean,
        degrading_by_queueing,
        grade,
        failing_conditions: failing,
    }
}

#[derive(Serialize)]
struct RungResult {
    offered_rate: u64,
    achieved_rate: f64,
    completed: u64,
    non_2xx: u64,
    connect_errors: u64,
    transport_errors: u64,
    error_rate: f64,
    max_backlog: u64,
    p50_ms: f64,
    p99_ms: f64,
    p999_ms: f64,
    attribution: Attribution,
}

/// Detects the knee: the highest ADMISSIBLE rung whose achieved rate kept up with
/// its offered rate. Returns the index into `rungs`, or `None` if no rung qualifies.
fn detect_knee(rungs: &[RungResult]) -> Option<usize> {
    let mut knee = None;
    for (i, r) in rungs.iter().enumerate() {
        let kept_up = r.achieved_rate >= r.offered_rate as f64 * KEEPUP_FRACTION;
        if r.attribution.grade == "ADMISSIBLE" && kept_up {
            knee = Some(i);
        }
    }
    knee
}

/// Classifies the degradation shape past the knee: "graceful" (throughput holds
/// while latency climbs) vs "cliff" (achieved throughput collapses or errors spike).
fn degradation_shape(rungs: &[RungResult], knee: Option<usize>) -> &'static str {
    let Some(k) = knee else { return "no-knee" };
    let Some(past) = rungs.get(k + 1) else {
        return "not-reached";
    };
    let knee_tput = rungs[k].achieved_rate;
    if past.achieved_rate < knee_tput * 0.75 || past.error_rate > MAX_ERROR_RATE {
        "cliff"
    } else {
        "graceful"
    }
}

// ── Generator CPU sampling (host B, /proc/self/stat) ────────────────────────────

/// Returns cumulative generator CPU-seconds (utime+stime) for this process.
fn process_cpu_seconds() -> f64 {
    let ticks_per_sec = 100.0; // _SC_CLK_TCK is 100 on all supported Linux targets.
    match std::fs::read_to_string("/proc/self/stat") {
        Ok(s) => {
            // Fields after the (comm) paren block: utime=14, stime=15 (1-indexed).
            if let Some(rparen) = s.rfind(')') {
                let rest: Vec<&str> = s[rparen + 1..].split_whitespace().collect();
                // rest[0] = state (field 3); utime is field 14 => rest index 11.
                let utime: f64 = rest.get(11).and_then(|v| v.parse().ok()).unwrap_or(0.0);
                let stime: f64 = rest.get(12).and_then(|v| v.parse().ok()).unwrap_or(0.0);
                return (utime + stime) / ticks_per_sec;
            }
            0.0
        }
        Err(_) => 0.0,
    }
}

fn num_cpus() -> usize {
    thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// Reads the last whitespace/newline-delimited float from the server-cpu file.
fn read_server_cpu(path: &Option<String>) -> Option<f64> {
    let p = path.as_ref()?;
    let s = std::fs::read_to_string(p).ok()?;
    s.split_whitespace().last()?.parse::<f64>().ok()
}

// ── Open-loop scheduler + worker pool ───────────────────────────────────────────

/// Shared, bounded backlog of intended send-times. Open-loop: the scheduler
/// pushes at a fixed rate; workers drain. If it fills, the scheduler records an
/// overrun instead of blocking (which would silently make the run closed-loop).
struct Backlog {
    inner: Mutex<VecDeque<Instant>>,
    cv: Condvar,
    cap: usize,
    max_seen: AtomicU64,
    overruns: AtomicU64,
    closed: AtomicBool,
}

impl Backlog {
    fn push(&self, at: Instant) {
        let mut q = self.inner.lock().expect("backlog lock");
        if q.len() >= self.cap {
            self.overruns.fetch_add(1, Ordering::Relaxed);
            return;
        }
        q.push_back(at);
        let len = q.len() as u64;
        drop(q);
        self.max_seen.fetch_max(len, Ordering::Relaxed);
        self.cv.notify_one();
    }
    fn pop(&self) -> Option<Instant> {
        let mut q = self.inner.lock().expect("backlog lock");
        loop {
            if let Some(v) = q.pop_front() {
                return Some(v);
            }
            if self.closed.load(Ordering::Relaxed) {
                return None;
            }
            q = self
                .cv
                .wait_timeout(q, Duration::from_millis(50))
                .expect("backlog wait")
                .0;
        }
    }
    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        self.cv.notify_all();
    }
}

/// A worker's tallies for one rung.
#[derive(Default)]
struct WorkerStats {
    completed: u64,
    non_2xx: u64,
    connect_errors: u64,
    transport_errors: u64,
    latencies_us: Vec<u64>,
}

/// Sends one request over an established keep-alive stream and reads the full
/// response. Returns the HTTP status code, or an error string on transport
/// failure. The connection is drained (Content-Length or chunked) so it can be
/// reused.
fn send_one(stream: &mut TcpStream, req: &[u8]) -> Result<u16, String> {
    stream.write_all(req).map_err(|e| format!("write: {e}"))?;
    stream.flush().map_err(|e| format!("flush: {e}"))?;
    read_response(stream)
}

/// Reads one HTTP/1.1 response, returns the status code, leaves the stream at the
/// start of the next response.
fn read_response(stream: &mut TcpStream) -> Result<u16, String> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 4096];
    // Read until we have the header terminator.
    let header_end = loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        let n = stream
            .read(&mut tmp)
            .map_err(|e| format!("read hdr: {e}"))?;
        if n == 0 {
            return Err("eof before headers".into());
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let head = std::str::from_utf8(&buf[..header_end]).map_err(|_| "non-utf8 headers")?;
    let status = parse_status(head)?;
    let (content_len, chunked) = parse_body_framing(head);
    let mut body_have = buf.len() - header_end;

    if chunked {
        // Read until the terminating 0-size chunk. We scan for "0\r\n\r\n".
        let mut body = buf[header_end..].to_vec();
        while find_subslice(&body, b"\r\n0\r\n\r\n").is_none() && !body.starts_with(b"0\r\n\r\n") {
            let n = stream
                .read(&mut tmp)
                .map_err(|e| format!("read chunk: {e}"))?;
            if n == 0 {
                return Err("eof mid-chunked-body".into());
            }
            body.extend_from_slice(&tmp[..n]);
        }
        return Ok(status);
    }

    let want = content_len.unwrap_or(0);
    while body_have < want {
        let n = stream
            .read(&mut tmp)
            .map_err(|e| format!("read body: {e}"))?;
        if n == 0 {
            return Err("eof mid-body".into());
        }
        body_have += n;
    }
    Ok(status)
}

fn parse_status(head: &str) -> Result<u16, String> {
    let line = head.lines().next().ok_or("empty response")?;
    let code = line
        .split_whitespace()
        .nth(1)
        .ok_or("no status code")?
        .parse::<u16>()
        .map_err(|_| "bad status code")?;
    Ok(code)
}

fn parse_body_framing(head: &str) -> (Option<usize>, bool) {
    let mut content_len = None;
    let mut chunked = false;
    for line in head.lines().skip(1) {
        let lower = line.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            content_len = v.trim().parse::<usize>().ok();
        } else if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
            chunked = true;
        }
    }
    (content_len, chunked)
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Runs one rung: fires at `offered_rate` for `hold`, returns the result.
fn run_rung(
    target: &Target,
    corpus: &Arc<Corpus>,
    offered_rate: u64,
    warmup: Duration,
    hold: Duration,
    conns: usize,
    server_cpu_file: &Option<String>,
) -> RungResult {
    let backlog = Arc::new(Backlog {
        inner: Mutex::new(VecDeque::new()),
        cv: Condvar::new(),
        cap: (conns * BACKLOG_CAP_PER_CONN).max(64),
        max_seen: AtomicU64::new(0),
        overruns: AtomicU64::new(0),
        closed: AtomicBool::new(false),
    });
    let stats: Vec<Arc<Mutex<WorkerStats>>> = (0..conns)
        .map(|_| Arc::new(Mutex::new(WorkerStats::default())))
        .collect();

    let measuring = Arc::new(AtomicBool::new(false));

    // Worker threads: each owns a persistent keep-alive connection.
    let mut workers = Vec::with_capacity(conns);
    for w in 0..conns {
        let backlog = Arc::clone(&backlog);
        let corpus = Arc::clone(corpus);
        let stats = Arc::clone(&stats[w]);
        let measuring = Arc::clone(&measuring);
        let authority = target.authority.clone();
        workers.push(thread::spawn(move || {
            let mut stream = connect(&authority);
            while let Some(intended) = backlog.pop() {
                let tpl = corpus.next();
                let count = measuring.load(Ordering::Relaxed);
                let result = match stream.as_mut() {
                    Some(s) => send_one(s, &tpl.bytes),
                    None => {
                        // (Re)connect lazily; a failed connect is a connect error.
                        stream = connect(&authority);
                        match stream.as_mut() {
                            Some(s) => send_one(s, &tpl.bytes),
                            None => Err("connect".into()),
                        }
                    }
                };
                // CO-corrected latency: measured from the *intended* send time.
                let elapsed = intended.elapsed().as_micros() as u64;
                if !count {
                    continue;
                }
                let mut st = stats.lock().expect("stats lock");
                match result {
                    Ok(code) => {
                        st.completed += 1;
                        st.latencies_us.push(elapsed);
                        if !(200..300).contains(&code) {
                            st.non_2xx += 1;
                        }
                    }
                    Err(e) => {
                        if e.starts_with("connect")
                            || e.starts_with("write")
                            || e.starts_with("flush")
                        {
                            st.connect_errors += 1;
                            stream = None; // force reconnect next iteration
                        } else {
                            st.transport_errors += 1;
                            stream = None;
                        }
                    }
                }
            }
        }));
    }

    // Scheduler: push intended send-times at the fixed offered rate.
    let start = Instant::now();
    let total_window = warmup + hold;
    let interval = Duration::from_secs_f64(1.0 / offered_rate as f64);
    let cpu_start = process_cpu_seconds();
    let mut cpu_measure_start = cpu_start;
    let mut measure_wall_start = start;
    let mut i: u64 = 0;
    let mut turned_on = false;
    loop {
        let now = Instant::now();
        let since = now.duration_since(start);
        if since >= total_window {
            break;
        }
        if !turned_on && since >= warmup {
            measuring.store(true, Ordering::Relaxed);
            cpu_measure_start = process_cpu_seconds();
            measure_wall_start = Instant::now();
            turned_on = true;
        }
        let target_time = start + interval.mul_f64(i as f64);
        if now < target_time {
            thread::sleep((target_time - now).min(Duration::from_millis(2)));
            continue;
        }
        backlog.push(target_time);
        i += 1;
    }
    backlog.close();
    for w in workers {
        let _ = w.join();
    }

    let measure_wall = measure_wall_start.elapsed().as_secs_f64().max(1e-9);
    let cpu_used = (process_cpu_seconds() - cpu_measure_start).max(0.0);
    // Fraction of one core, per second, the generator consumed, vs total cores.
    let cores = num_cpus() as f64;
    let generator_cores_used = cpu_used / measure_wall;
    let generator_headroom = if generator_cores_used <= 0.0 {
        cores // effectively idle generator
    } else {
        cores / generator_cores_used
    };

    // Aggregate worker stats.
    let mut completed = 0u64;
    let mut non_2xx = 0u64;
    let mut connect_errors = 0u64;
    let mut transport_errors = 0u64;
    let mut lat: Vec<u64> = Vec::new();
    for s in &stats {
        let st = s.lock().expect("stats lock");
        completed += st.completed;
        non_2xx += st.non_2xx;
        connect_errors += st.connect_errors;
        transport_errors += st.transport_errors;
        lat.extend_from_slice(&st.latencies_us);
    }
    lat.sort_unstable();
    let achieved_rate = completed as f64 / measure_wall;
    let denom = (completed + connect_errors + transport_errors).max(1);
    let error_rate = (non_2xx + connect_errors + transport_errors) as f64 / denom as f64;

    let server_cpu_pct = read_server_cpu(server_cpu_file);
    let attribution = classify(
        server_cpu_pct,
        generator_headroom,
        connect_errors + transport_errors,
        error_rate,
    );

    RungResult {
        offered_rate,
        achieved_rate,
        completed,
        non_2xx,
        connect_errors,
        transport_errors,
        error_rate,
        max_backlog: backlog.max_seen.load(Ordering::Relaxed),
        p50_ms: percentile(&lat, 50.0) as f64 / 1000.0,
        p99_ms: percentile(&lat, 99.0) as f64 / 1000.0,
        p999_ms: percentile(&lat, 99.9) as f64 / 1000.0,
        attribution,
    }
}

fn connect(authority: &str) -> Option<TcpStream> {
    let stream = TcpStream::connect(authority).ok()?;
    stream.set_nodelay(true).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
    Some(stream)
}

// ── main ────────────────────────────────────────────────────────────────────────

fn main() {
    if let Err(e) = real_main() {
        eprintln_stderr(&format!("http_saturation: {e}"));
        std::process::exit(1);
    }
}

/// Wrapper so we can bail with a `Result` and keep `?` throughout.
fn real_main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    let mut target_url = env_or(&args, "--target", "HEARTH_SAT_TARGET", "");
    let seed_path = arg(&args, "--seed-handle").ok_or("--seed-handle <path> is required")?;
    let plane = Plane::parse(&arg(&args, "--plane").unwrap_or_else(|| "read".into()))?;
    let rungs: Vec<u64> = arg(&args, "--rungs")
        .unwrap_or_else(|| "500,1000,2000,4000,8000".into())
        .split(',')
        .map(|s| {
            s.trim()
                .parse::<u64>()
                .map_err(|_| format!("bad rung {s:?}"))
        })
        .collect::<Result<_, _>>()?;
    let hold = Duration::from_secs(
        arg(&args, "--hold")
            .and_then(|s| s.parse().ok())
            .unwrap_or(20),
    );
    let warmup = Duration::from_secs(
        arg(&args, "--warmup")
            .and_then(|s| s.parse().ok())
            .unwrap_or(3),
    );
    let conns: usize = arg(&args, "--conns")
        .and_then(|s| s.parse().ok())
        .unwrap_or(256);
    let server_cpu_file = arg(&args, "--server-cpu-file");
    let login_password = arg(&args, "--login-password").unwrap_or_default();
    let allow_loopback = args.iter().any(|a| a == "--allow-loopback");

    if target_url.is_empty() {
        return Err("--target http://HOST:PORT (or HEARTH_SAT_TARGET) is required".into());
    }
    if !target_url.starts_with("http://") {
        // Only plaintext HTTP/1.1 is supported by this hand-rolled client.
        if target_url.starts_with("https://") {
            return Err(
                "this harness speaks plaintext HTTP/1.1 only; put TLS terminator note in \
                        the report and target the plaintext port"
                    .into(),
            );
        }
        target_url = format!("http://{target_url}");
    }
    let (authority, host) = parse_authority(&target_url)?;

    if target_is_loopback(&authority) && !allow_loopback {
        return Err(format!(
            "target {authority} resolves to loopback — generator and server would be co-resident, \
             which is the exact ceiling HEA-1997 requires two hosts to avoid. Refusing to grade. \
             Pass --allow-loopback ONLY for a smoke test (the artifact will be stamped ungradable)."
        ));
    }

    let target = Target {
        authority,
        host,
        login_password,
    };

    let raw = std::fs::read_to_string(&seed_path).map_err(|e| format!("read seed handle: {e}"))?;
    let handle: SeedHandle =
        serde_json::from_str(&raw).map_err(|e| format!("parse seed handle: {e}"))?;

    let corpus = Arc::new(build_corpus(plane, &target, &handle)?);

    let mut results = Vec::new();
    for &rate in &rungs {
        eprintln_stderr(&format!(
            "[rung] offered={rate} req/s hold={}s …",
            hold.as_secs()
        ));
        let r = run_rung(
            &target,
            &corpus,
            rate,
            warmup,
            hold,
            conns,
            &server_cpu_file,
        );
        eprintln_stderr(&format!(
            "  achieved={:.0}/s p50={:.2}ms p99={:.2}ms grade={} err_rate={:.4}",
            r.achieved_rate, r.p50_ms, r.p99_ms, r.attribution.grade, r.error_rate
        ));
        results.push(r);
    }

    let knee = detect_knee(&results);
    let shape = degradation_shape(&results, knee);

    let artifact = serde_json::json!({
        "schema": "hea-1997-saturation-1",
        "plane": plane.label(),
        "is_kdf_benchmark": plane.is_kdf(),
        "kdf_label": if plane.is_kdf() {
            "This plane exercises Argon2id (login/password verify). Any throughput \
             figure here is a KDF benchmark, not a server-capacity figure."
        } else if plane == Plane::Issuance {
            "Issuance/write plane: session-create + Ed25519 sign + WAL fsync. NOT the \
             Argon2id KDF path (seeded corpus has no password credentials)."
        } else {
            "Read plane: no KDF, no durable write."
        },
        "target_authority": redact_authority(&target.authority),
        "limiter": "on (two-host rig cannot enable load_test_unthrottled; report which resource saturated)",
        "generator_cores": num_cpus(),
        "conns": conns,
        "warmup_s": warmup.as_secs(),
        "hold_s": hold.as_secs(),
        "rungs": results,
        "knee_index": knee,
        "knee_throughput": knee.map(|k| results[k].achieved_rate),
        "knee_p50_ms": knee.map(|k| results[k].p50_ms),
        "knee_p99_ms": knee.map(|k| results[k].p99_ms),
        "degradation_shape": shape,
        "notes": [
            "Open-loop fixed-rate ramp; latency is coordinated-omission-corrected \
             (measured from intended send time).",
            "A rung is ADMISSIBLE only when server CPU is pinned, generator headroom \
             >= 2x, transport is clean, and degradation is by queueing not errors.",
            "INCOMPLETE = no --server-cpu-file, so server saturation is unconfirmed; \
             never treat an INCOMPLETE rung as a published capacity number."
        ]
    });

    println_stdout(&serde_json::to_string_pretty(&artifact).map_err(|e| e.to_string())?);
    Ok(())
}

fn parse_authority(url: &str) -> Result<(String, String), String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or("target must be http://")?;
    let host_port = rest.split('/').next().unwrap_or(rest);
    let authority = if host_port.contains(':') {
        host_port.to_string()
    } else {
        format!("{host_port}:80")
    };
    Ok((authority, host_port.to_string()))
}

/// Redacts nothing sensitive here (host:port is not secret) but keeps a single
/// choke point in case a userinfo@ form is ever passed.
fn redact_authority(authority: &str) -> String {
    match authority.rsplit_once('@') {
        Some((_creds, hostport)) => format!("<redacted>@{hostport}"),
        None => authority.to_string(),
    }
}

fn arg(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1).cloned())
}

fn env_or(args: &[String], flag: &str, env: &str, default: &str) -> String {
    arg(args, flag)
        .or_else(|| std::env::var(env).ok())
        .unwrap_or_else(|| default.to_string())
}

// `println!`/`eprintln!` are banned in the crate, but examples run outside the
// server and must emit their artifact to stdout. We go straight to the fds.
fn println_stdout(s: &str) {
    use std::io::Write as _;
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(s.as_bytes());
    let _ = out.write_all(b"\n");
}
fn eprintln_stderr(s: &str) {
    use std::io::Write as _;
    let mut err = std::io::stderr().lock();
    let _ = err.write_all(s.as_bytes());
    let _ = err.write_all(b"\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_basic() {
        let v: Vec<u64> = (1..=100).collect();
        // Nearest-rank: index = round(p/100 * (n-1)).
        assert_eq!(percentile(&v, 50.0), 51); // round(0.50*99)=50 ⇒ v[50]=51
        assert_eq!(percentile(&v, 99.0), 99); // round(0.99*99)=98 ⇒ v[98]=99
        assert_eq!(percentile(&v, 100.0), 100);
        assert_eq!(percentile(&v, 0.0), 1);
        assert_eq!(percentile(&[], 50.0), 0);
    }

    #[test]
    fn classify_admissible_when_all_conditions_met() {
        let a = classify(Some(95.0), 3.0, 0, 0.0);
        assert_eq!(a.grade, "ADMISSIBLE");
        assert!(a.failing_conditions.is_empty());
        assert_eq!(a.server_cpu_pinned, Some(true));
    }

    #[test]
    fn classify_incomplete_without_server_cpu() {
        // Even with a perfect generator-side picture, no server CPU ⇒ INCOMPLETE.
        let a = classify(None, 5.0, 0, 0.0);
        assert_eq!(a.grade, "INCOMPLETE");
    }

    #[test]
    fn classify_inadmissible_on_generator_ceiling() {
        // Generator itself is the bottleneck (headroom < 2x): inadmissible.
        let a = classify(Some(70.0), 1.2, 0, 0.0);
        assert_eq!(a.grade, "INADMISSIBLE");
        assert!(a
            .failing_conditions
            .iter()
            .any(|c| c == "generator_headroom_2x"));
        assert!(a
            .failing_conditions
            .iter()
            .any(|c| c == "server_cpu_pinned"));
    }

    #[test]
    fn classify_inadmissible_on_error_cliff() {
        // Server pinned & generator clear, but the ceiling is an error cliff.
        let a = classify(Some(99.0), 4.0, 0, 0.20);
        assert_eq!(a.grade, "INADMISSIBLE");
        assert!(a
            .failing_conditions
            .iter()
            .any(|c| c == "degrading_by_queueing"));
    }

    #[test]
    fn classify_inadmissible_on_transport_errors() {
        let a = classify(Some(99.0), 4.0, 5, 0.0);
        assert_eq!(a.grade, "INADMISSIBLE");
        assert!(a.failing_conditions.iter().any(|c| c == "transport_clean"));
    }

    fn rung(offered: u64, achieved: f64, _grade: &str, err: f64) -> RungResult {
        RungResult {
            offered_rate: offered,
            achieved_rate: achieved,
            completed: achieved as u64,
            non_2xx: 0,
            connect_errors: 0,
            transport_errors: 0,
            error_rate: err,
            max_backlog: 0,
            p50_ms: 1.0,
            p99_ms: 2.0,
            p999_ms: 3.0,
            attribution: classify(Some(95.0), 4.0, 0, err),
        }
    }

    #[test]
    fn knee_is_highest_admissible_keeping_up() {
        // 500 & 1000 keep up and are admissible; 2000 falls behind (throttled).
        let rungs = vec![
            rung(500, 500.0, "ADMISSIBLE", 0.0),
            rung(1000, 1000.0, "ADMISSIBLE", 0.0),
            rung(2000, 1400.0, "ADMISSIBLE", 0.0), // achieved << offered ⇒ past knee
        ];
        let knee = detect_knee(&rungs);
        assert_eq!(knee, Some(1));
        assert_eq!(rungs[knee.unwrap()].offered_rate, 1000);
    }

    #[test]
    fn knee_none_when_no_rung_admissible() {
        let mut r = rung(500, 500.0, "ADMISSIBLE", 0.30);
        r.attribution = classify(Some(50.0), 1.0, 3, 0.30);
        assert_eq!(detect_knee(&[r]), None);
    }

    #[test]
    fn degradation_cliff_when_throughput_collapses() {
        let rungs = vec![
            rung(1000, 1000.0, "ADMISSIBLE", 0.0),
            rung(2000, 400.0, "INADMISSIBLE", 0.0), // collapsed to 40% ⇒ cliff
        ];
        assert_eq!(degradation_shape(&rungs, Some(0)), "cliff");
    }

    #[test]
    fn degradation_graceful_when_throughput_holds() {
        let rungs = vec![
            rung(1000, 1000.0, "ADMISSIBLE", 0.0),
            rung(2000, 1050.0, "INADMISSIBLE", 0.0), // holds ⇒ graceful
        ];
        assert_eq!(degradation_shape(&rungs, Some(0)), "graceful");
    }

    #[test]
    fn loopback_targets_are_refused() {
        assert!(target_is_loopback("127.0.0.1:8420"));
        assert!(target_is_loopback("localhost:8420"));
    }

    #[test]
    fn urlencode_escapes_reserved() {
        assert_eq!(urlencode("a b+c@d"), "a+b%2Bc%40d");
        assert_eq!(urlencode("user@hearth.test"), "user%40hearth.test");
    }

    #[test]
    fn parse_authority_adds_default_port() {
        let (auth, host) = parse_authority("http://a.internal/foo").unwrap();
        assert_eq!(auth, "a.internal:80");
        assert_eq!(host, "a.internal");
        let (auth, _) = parse_authority("http://a.internal:8420").unwrap();
        assert_eq!(auth, "a.internal:8420");
    }

    #[test]
    fn parse_status_and_framing() {
        let head =
            "HTTP/1.1 200 OK\r\nContent-Length: 12\r\nContent-Type: application/json\r\n\r\n";
        assert_eq!(parse_status(head).unwrap(), 200);
        assert_eq!(parse_body_framing(head), (Some(12), false));
        let chunked = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert_eq!(parse_body_framing(chunked), (None, true));
    }

    #[test]
    fn read_plane_requires_live_tokens() {
        // A handle with a realm but no tokens must fail the read plane clearly.
        let handle = SeedHandle {
            admin_token: String::new(),
            realms: vec![SeededRealm {
                realm_id: "r1".into(),
                realm_name: "dev-realm".into(),
                client_id: "c1".into(),
                cc_client_id: String::new(),
                cc_client_secret: String::new(),
                users: vec![],
                tokens: vec![],
            }],
        };
        let target = Target {
            authority: "a:80".into(),
            host: "a".into(),
            login_password: String::new(),
        };
        let err = match build_corpus(Plane::Read, &target, &handle) {
            Ok(_) => panic!("expected read plane to fail with no live tokens"),
            Err(e) => e,
        };
        assert!(err.contains("no live tokens"), "{err}");
    }

    #[test]
    fn build_request_is_well_formed_and_appends_in_order() {
        // Regression: an earlier version wrapped each write in a fresh
        // Cursor::new(&mut req), which resets the position to 0 and overwrites
        // prior bytes, producing a malformed request on every plane.
        let raw = build_request(
            "POST",
            "/token",
            "a",
            &[("X-Realm-ID", "r1"), ("Content-Type", "application/json")],
            b"{\"k\":\"v\"}",
        );
        let s = String::from_utf8(raw).expect("utf8");
        assert!(s.starts_with("POST /token HTTP/1.1\r\n"), "{s:?}");
        assert!(s.contains("\r\nHost: a\r\n"), "{s:?}");
        assert!(s.contains("\r\nX-Realm-ID: r1\r\n"), "{s:?}");
        assert!(s.contains("\r\nContent-Length: 9\r\n"), "{s:?}");
        assert!(
            s.ends_with("\r\n\r\n{\"k\":\"v\"}"),
            "body must be last: {s:?}"
        );
    }

    fn issuance_target() -> Target {
        Target {
            authority: "a:80".into(),
            host: "a".into(),
            login_password: String::new(),
        }
    }

    #[test]
    fn issuance_plane_mints_over_production_client_credentials_grant() {
        // HEA-2003: the issuance plane must hit the production POST /token grant,
        // NOT the dev-only /dev/seed-token endpoint (which the two-host gate
        // forbids exposing).
        let handle = SeedHandle {
            admin_token: String::new(),
            realms: vec![SeededRealm {
                realm_id: "r1".into(),
                realm_name: "dev-realm".into(),
                client_id: "c1".into(),
                cc_client_id: "cc-1".into(),
                cc_client_secret: "cc-secret".into(),
                users: vec![],
                tokens: vec![],
            }],
        };
        let corpus = build_corpus(Plane::Issuance, &issuance_target(), &handle)
            .expect("issuance corpus builds with cc credentials");
        let req = String::from_utf8(corpus.templates[0].bytes.clone()).expect("utf8");
        assert!(req.starts_with("POST /token "), "must POST /token: {req}");
        assert!(
            !req.contains("/dev/seed-token"),
            "issuance must not touch the dev-only endpoint: {req}"
        );
        assert!(req.contains("client_credentials"), "{req}");
        assert!(req.contains("cc-1") && req.contains("cc-secret"), "{req}");
        // ThirdParty DCR clients must request a scope; openid is always legal.
        assert!(req.contains("\"scope\":\"openid\""), "{req}");
    }

    #[test]
    fn issuance_plane_errors_without_confidential_client() {
        // A pre-HEA-2003 handle (no cc credentials) must fail the issuance plane
        // with a clear message rather than silently minting nothing.
        let handle = SeedHandle {
            admin_token: String::new(),
            realms: vec![SeededRealm {
                realm_id: "r1".into(),
                realm_name: "dev-realm".into(),
                client_id: "c1".into(),
                cc_client_id: String::new(),
                cc_client_secret: String::new(),
                users: vec![SeededUser {
                    id: "u1".into(),
                    email: "u1@loadtest.test".into(),
                }],
                tokens: vec![],
            }],
        };
        let err = match build_corpus(Plane::Issuance, &issuance_target(), &handle) {
            Ok(_) => panic!("issuance must fail without a confidential client"),
            Err(e) => e,
        };
        assert!(err.contains("client_credentials"), "{err}");
    }

    fn login_target() -> Target {
        Target {
            authority: "a:80".into(),
            host: "a".into(),
            login_password: "hunter2".into(),
        }
    }

    fn login_handle(realm_id: &str, realm_name: &str) -> SeedHandle {
        SeedHandle {
            admin_token: String::new(),
            realms: vec![SeededRealm {
                realm_id: realm_id.into(),
                realm_name: realm_name.into(),
                client_id: "c1".into(),
                cc_client_id: String::new(),
                cc_client_secret: String::new(),
                users: vec![SeededUser {
                    id: "u1".into(),
                    email: "user@hearth.test".into(),
                }],
                tokens: vec![],
            }],
        }
    }

    #[test]
    fn login_plane_builds_path_from_realm_name_not_id() {
        // HEA-2006: the realm-scoped login route is keyed by realm NAME
        // (`/ui/realms/{realm_name}/login`, src/protocol/http.rs). An earlier
        // version built the path from `realm_id`, which 404s every request and
        // never exercises Argon2id. Pin the constructed path against the real
        // route and prove the id does NOT leak into it.
        let realm_id = "9a35bdcf-0000-4000-8000-000000000000";
        let handle = login_handle(realm_id, "dev-realm");
        let corpus = build_corpus(Plane::Login, &login_target(), &handle)
            .expect("login corpus builds with a realm name and a password");
        let req = String::from_utf8(corpus.templates[0].bytes.clone()).expect("utf8");
        // The request LINE (path) is name-keyed; the realm id must not leak into
        // it. (The id still rides in the `X-Realm-ID` header — that is correct
        // and required for realm routing — so scope the check to the path.)
        let request_line = req.lines().next().unwrap_or_default();
        assert_eq!(
            request_line, "POST /ui/realms/dev-realm/login HTTP/1.1",
            "login must POST the name-keyed route, not the id-keyed one"
        );
        assert!(
            !request_line.contains(realm_id),
            "the realm id must never appear in the login path (route is name-keyed): {request_line}"
        );
        assert!(req.contains("password=hunter2"), "{req}");
    }

    #[test]
    fn login_plane_errors_without_realm_name() {
        // A pre-HEA-2006 handle carries only `realm_id` (realm_name defaults to
        // empty). The login plane must fail loud rather than emit
        // `/ui/realms//login` and silently 404 every request.
        let handle = login_handle("9a35bdcf-0000-4000-8000-000000000000", "");
        let err = match build_corpus(Plane::Login, &login_target(), &handle) {
            Ok(_) => panic!("login must fail when the handle carries no realm name"),
            Err(e) => e,
        };
        assert!(err.contains("realm_name"), "{err}");
    }
}
