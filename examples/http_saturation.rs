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
//! * `rate_limited_shed`     — **zero** HTTP 429s. A single 429 means the request
//!   shaper shed offered load, so the ceiling measured is Hearth's own limiter,
//!   not the server. This is a hard INADMISSIBLE independent of the error-rate
//!   threshold and of whether a server-CPU sample is present — it outranks
//!   `INCOMPLETE`, so a shed rung can never be a knee (HEA-2007).
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
//! Because the shipped shaper defaults (`ip_rps: 100`, `realm_rps: 1000`) would
//! shed every rung the runbook fires from a single generator IP, the measured host
//! MUST pin `security.request_shaper` above the top rung (HEA-2007). The chosen
//! setting is captured in the artifact via `--limiter-note`, and the harness voids
//! any rung that still 429s (see `rate_limited_shed` above) so a limiter-shed rung
//! is never mistaken for the server's knee.
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

use std::collections::{BTreeMap, VecDeque};
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

fn build_corpus(
    plane: Plane,
    target: &Target,
    handle: &SeedHandle,
    login_csrf_token: Option<&str>,
) -> Result<Corpus, String> {
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

    let push_login = |templates: &mut Vec<ReqTemplate>,
                      password: &str,
                      csrf_token: Option<&str>|
     -> Result<(), String> {
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
        // HEA-2015: production mode enforces a double-submit CSRF check on
        // POST /ui/realms/{name}/login. The token is pre-fetched once per
        // corpus build and embedded in every login template as both a Cookie
        // header and a `_csrf` body field. Without both, the server returns
        // 422 before reaching Argon2id (p50 ≈ 0.39 ms, no KDF exercised).
        let cookie_hdr_val = csrf_token.map(|t| format!("hearth_ui_csrf={t}"));
        let csrf_suffix = csrf_token.map(|t| format!("&_csrf={}", urlencode(t)));
        for u in &realm.users {
            let body = format!(
                "email={}&password={}{}",
                urlencode(&u.email),
                urlencode(password),
                csrf_suffix.as_deref().unwrap_or(""),
            );
            let mut headers = vec![
                realm_hdr,
                ("Content-Type", "application/x-www-form-urlencoded"),
            ];
            if let Some(c) = &cookie_hdr_val {
                headers.push(("Cookie", c.as_str()));
            }
            templates.push(ReqTemplate {
                bytes: build_request("POST", &login_path, &host_header, &headers, body.as_bytes()),
                op: "login",
            });
        }
        Ok(())
    };

    match plane {
        Plane::Read => push_read()?,
        Plane::Issuance => push_issuance(&mut templates)?,
        Plane::Login => push_login(&mut templates, &target.login_password, login_csrf_token)?,
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
                push_login(&mut login, &target.login_password, login_csrf_token)?;
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

/// Issues a `GET` to the login page and extracts the CSRF token from the
/// `Set-Cookie: hearth_ui_csrf=TOKEN` response header (double-submit pattern).
///
/// Called once per `build_corpus` invocation for the login/blended planes. One
/// GET per corpus build (≤100 users standard corpus) adds negligible overhead.
/// On failure (server down, no cookie set) the harness aborts before firing any
/// load — a missing token means every login request would 422 immediately.
fn fetch_csrf_token(
    authority: &str,
    host_header: &str,
    login_path: &str,
) -> Result<String, String> {
    let mut stream = TcpStream::connect(authority)
        .map_err(|e| format!("csrf prefetch connect({authority}): {e}"))?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

    let req =
        format!("GET {login_path} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("csrf prefetch write: {e}"))?;
    stream
        .flush()
        .map_err(|e| format!("csrf prefetch flush: {e}"))?;

    // Read until the header terminator — body is not needed.
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        let n = stream
            .read(&mut tmp)
            .map_err(|e| format!("csrf prefetch read: {e}"))?;
        if n == 0 {
            if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
                break pos + 4;
            }
            return Err("csrf prefetch: EOF before header terminator".into());
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 64 * 1024 {
            return Err("csrf prefetch: response headers too large".into());
        }
    };

    let head = std::str::from_utf8(&buf[..header_end])
        .map_err(|_| "csrf prefetch: non-UTF-8 response headers")?;

    // Scan for:  Set-Cookie: hearth_ui_csrf=TOKEN[; directives...]
    for line in head.lines() {
        let lower = line.to_ascii_lowercase();
        if !lower.starts_with("set-cookie:") {
            continue;
        }
        let val = line["set-cookie:".len()..].trim();
        // cookie-string = name=value[; directives...]
        let cookie_pair = val.split(';').next().unwrap_or(val);
        if let Some(token) = cookie_pair.strip_prefix("hearth_ui_csrf=") {
            let token = token.trim();
            if !token.is_empty() {
                return Ok(token.to_string());
            }
        }
    }

    Err(format!(
        "csrf prefetch: server did not set the hearth_ui_csrf cookie on GET {login_path}; \
         verify the server is running in production mode (not --dev)"
    ))
}

/// Pre-fetches the CSRF token for the login/blended planes from the server.
///
/// Returns `None` when no password is configured (login templates will be
/// skipped; `push_login` will surface the real error if the plane needs one)
/// or the realm name is not yet known (push_login will also error there).
fn prefetch_login_csrf(target: &Target, handle: &SeedHandle) -> Result<Option<String>, String> {
    if target.login_password.is_empty() {
        return Ok(None);
    }
    let realm = handle
        .realms
        .first()
        .ok_or("seed handle has no realms; re-seed the corpus")?;
    if realm.realm_name.is_empty() {
        return Ok(None); // push_login will emit the clear "realm_name" error
    }
    let login_path = format!("/ui/realms/{}/login", realm.realm_name);
    eprintln_stderr(&format!(
        "[csrf] pre-fetching CSRF token from GET {login_path} …"
    ));
    let token = fetch_csrf_token(&target.authority, &target.host_header(), &login_path)?;
    eprintln_stderr("[csrf] CSRF token obtained");
    Ok(Some(token))
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
    /// True when the rung saw ≥1 HTTP 429 — the request shaper shed load, so the
    /// ceiling measured is Hearth's own limiter, not the server (HEA-2007).
    rate_limited_shed: bool,
    // ── Generator NIC accounting (HEA-2014) ─────────────────────────────────
    /// Kernel packets dropped at the generator NIC (softnet column 1 delta).
    /// Non-zero ⇒ the NIC, not Hearth, was the bottleneck — INADMISSIBLE.
    generator_softnet_dropped: u64,
    /// Softnet `time_squeeze` events on the generator (CPU ran out of NAPI quota).
    generator_softnet_time_squeeze: u64,
    /// Generator NIC receive packets/s during the measurement window.
    generator_rx_pps: f64,
    /// Generator NIC transmit packets/s during the measurement window.
    generator_tx_pps: f64,
    /// TIME_WAIT socket count on the generator at rung end.
    generator_time_wait: u64,
    /// True when no packets were dropped at the generator NIC.
    softnet_drops_zero: bool,
    /// True when TIME_WAIT count is below 95 % of the ephemeral port range.
    /// Exhaustion looks exactly like a server-side latency cliff.
    generator_ephemeral_ports_ok: bool,
    // ────────────────────────────────────────────────────────────────────────
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
    rate_limited: u64,
    net: &NetDelta,
) -> Attribution {
    let server_cpu_pinned = server_cpu_pct.map(|c| c >= SERVER_PINNED_PCT);
    let generator_headroom_2x = generator_headroom >= MIN_GENERATOR_HEADROOM;
    let transport_clean = connect_or_transport_errors == 0;
    let degrading_by_queueing = error_rate <= MAX_ERROR_RATE;
    // A single 429 means the request shaper shed offered load: the ceiling we would
    // report is Hearth's own rate limiter, not the server. That contaminates the
    // measurement outright, so it is a hard-fail condition independent of the
    // error-rate threshold and of whether a server-CPU sample is present (HEA-2007).
    let rate_limited_shed = rate_limited > 0;

    // HEA-2014: generator-side NIC accounting.
    // Any softnet drops mean the kernel discarded packets at the NIC — the ceiling
    // is the generator's NIC, not Hearth. Hard-INADMISSIBLE independent of server
    // CPU (outranks INCOMPLETE, same as rate_limited_shed).
    let softnet_drops_zero = net.softnet_dropped == 0;
    // TIME_WAIT exhaustion looks exactly like a server-side latency cliff. Gate at
    // 95 % of the ephemeral port range. Fail-open when the range is unreadable
    // (port_range_size == u64::MAX).
    let generator_ephemeral_ports_ok =
        net.port_range_size == u64::MAX || net.time_wait < net.port_range_size * 95 / 100;

    let mut failing = Vec::new();
    if rate_limited_shed {
        failing.push("rate_limited".to_string());
    }
    if !softnet_drops_zero {
        failing.push("generator_softnet_drops".to_string());
    }
    if !generator_ephemeral_ports_ok {
        failing.push("generator_ephemeral_ports".to_string());
    }
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

    let grade = if rate_limited_shed {
        // Rate-limited: the limiter, not the server, is the ceiling. Hard
        // INADMISSIBLE even without a server-CPU sample (so it outranks
        // INCOMPLETE) — a shed rung can therefore never be a knee (HEA-2007).
        "INADMISSIBLE".to_string()
    } else if !softnet_drops_zero || !generator_ephemeral_ports_ok {
        // Generator NIC or port exhaustion is the ceiling — rig-bound. Hard
        // INADMISSIBLE: we know the generator is the bottleneck independent of
        // whether the server CPU sample is present (HEA-2014).
        "INADMISSIBLE".to_string()
    } else if server_cpu_pct.is_none() {
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
        rate_limited_shed,
        generator_softnet_dropped: net.softnet_dropped,
        generator_softnet_time_squeeze: net.softnet_time_squeeze,
        generator_rx_pps: net.rx_pps,
        generator_tx_pps: net.tx_pps,
        generator_time_wait: net.time_wait,
        softnet_drops_zero,
        generator_ephemeral_ports_ok,
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
    /// Subset of `non_2xx` that were HTTP 429 (a limiter shed load). Any non-zero
    /// value forces the rung INADMISSIBLE with reason `rate_limited` (HEA-2007).
    rate_limited: u64,
    /// `rate_limited` attributed to the limiter that shed it, keyed by the
    /// server's `limiter` tag (HEA-2010). Zero-count limiters are omitted.
    /// `unattributed` counts 429s whose body carried no recognised tag.
    rate_limited_by: BTreeMap<String, u64>,
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

// ── Generator network accounting (host B, /proc and /sys) ────────────────────

/// Raw network counters on the generator host, captured at a single instant.
struct NetSnapshot {
    softnet_dropped: u64,
    softnet_time_squeeze: u64,
    rx_packets: u64,
    tx_packets: u64,
    time_wait: u64,
}

impl NetSnapshot {
    fn capture(dev: &str) -> Self {
        let (softnet_dropped, softnet_time_squeeze) = read_softnet_stat();
        Self {
            softnet_dropped,
            softnet_time_squeeze,
            rx_packets: read_net_stat(dev, "rx_packets"),
            tx_packets: read_net_stat(dev, "tx_packets"),
            time_wait: read_time_wait(),
        }
    }
}

/// Generator-side network accounting derived over the measurement window.
///
/// `Default` is provided for unit tests and environments where `/proc` is absent.
/// In production, these values are always computed from real snapshots.
struct NetDelta {
    softnet_dropped: u64,
    softnet_time_squeeze: u64,
    /// Receive packets/s on the generator NIC during this rung.
    rx_pps: f64,
    /// Transmit packets/s on the generator NIC during this rung.
    tx_pps: f64,
    time_wait: u64,
    /// Ephemeral port range size; `u64::MAX` when unreadable (fails open).
    port_range_size: u64,
}

impl Default for NetDelta {
    fn default() -> Self {
        Self {
            softnet_dropped: 0,
            softnet_time_squeeze: 0,
            rx_pps: 0.0,
            tx_pps: 0.0,
            time_wait: 0,
            port_range_size: u64::MAX,
        }
    }
}

/// Reads `/proc/net/softnet_stat`, returning `(total_dropped, total_time_squeeze)`
/// summed across all CPUs.
///
/// `/proc/net/softnet_stat` format (hex values, one row per CPU):
/// column 0 = total frames received, column 1 = dropped (NIC ring-buffer overflow),
/// column 2 = time_squeeze (kernel ran out of NAPI quota). Non-zero dropped means
/// the kernel discarded packets at the NIC layer — the rung is measuring the NIC
/// ceiling, not Hearth's.
fn read_softnet_stat() -> (u64, u64) {
    let s = match std::fs::read_to_string("/proc/net/softnet_stat") {
        Ok(s) => s,
        Err(_) => return (0, 0),
    };
    let mut dropped = 0u64;
    let mut time_squeeze = 0u64;
    for line in s.lines() {
        let mut cols = line.split_whitespace();
        cols.next(); // column 0: total (skip)
        if let Some(d) = cols.next().and_then(|v| u64::from_str_radix(v, 16).ok()) {
            dropped += d;
        }
        if let Some(t) = cols.next().and_then(|v| u64::from_str_radix(v, 16).ok()) {
            time_squeeze += t;
        }
    }
    (dropped, time_squeeze)
}

/// Reads `/sys/class/net/<dev>/statistics/<stat>`.
fn read_net_stat(dev: &str, stat: &str) -> u64 {
    let path = format!("/sys/class/net/{dev}/statistics/{stat}");
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

/// Returns the primary network interface name (the one carrying the default route).
///
/// Reads `/proc/net/route` and returns the interface whose destination is
/// `00000000` (the default route). Falls back to `"eth0"` if unreadable.
fn primary_net_dev() -> String {
    let route = std::fs::read_to_string("/proc/net/route").unwrap_or_default();
    for line in route.lines().skip(1) {
        let mut f = line.split_whitespace();
        let Some(iface) = f.next() else { continue };
        let Some(dest) = f.next() else { continue };
        if dest == "00000000" {
            return iface.to_string();
        }
    }
    "eth0".to_string()
}

/// Returns the current TIME_WAIT socket count from `/proc/net/sockstat`.
///
/// FORMAT: `TCP: inuse N orphan N tw N alloc N mem N`
fn read_time_wait() -> u64 {
    let s = std::fs::read_to_string("/proc/net/sockstat").unwrap_or_default();
    for line in s.lines() {
        if !line.starts_with("TCP:") {
            continue;
        }
        let mut parts = line.split_whitespace();
        while let Some(key) = parts.next() {
            if key == "tw" {
                if let Some(val) = parts.next().and_then(|v| v.parse::<u64>().ok()) {
                    return val;
                }
            }
        }
    }
    0
}

/// Returns the number of ports in the ephemeral range from
/// `/proc/sys/net/ipv4/ip_local_port_range`.
fn read_ephemeral_port_range_size() -> u64 {
    let s = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range").unwrap_or_default();
    let mut parts = s.split_whitespace();
    let low: u64 = parts.next().and_then(|v| v.parse().ok()).unwrap_or(32768);
    let high: u64 = parts.next().and_then(|v| v.parse().ok()).unwrap_or(60999);
    high.saturating_sub(low) + 1
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
    /// Subset of `non_2xx` that were HTTP 429 (a limiter shed load).
    rate_limited: u64,
    /// `rate_limited` split by which limiter shed the request (HEA-2010).
    rate_limited_by: LimiterCounts,
    connect_errors: u64,
    transport_errors: u64,
    latencies_us: Vec<u64>,
}

/// Server-side rate-limiter identifiers, as emitted in the `limiter` field of a
/// `429` body (HEA-2010). Order matches [`LIMITER_IDS`] and the per-rung
/// `rate_limited_by` histogram.
const LIMITER_IDS: [&str; 5] = ["shaper", "admin", "token", "export", "login_ip"];

/// Bucket index for a 429 whose body carried no recognised `limiter` field —
/// an older server, or a 429 emitted by a path that is not yet tagged.
const LIMITER_UNATTRIBUTED: usize = LIMITER_IDS.len();

/// One counter per known limiter, plus a trailing `unattributed` bucket.
type LimiterCounts = [u64; LIMITER_IDS.len() + 1];

/// Extracts the `limiter` tag from a `429` body and maps it to its bucket index.
///
/// Deliberately a substring scan rather than a JSON parse: this runs on the
/// generator's hot loop and must not allocate.
fn limiter_bucket(body: &[u8]) -> usize {
    let Some(pos) = find_subslice(body, b"\"limiter\"") else {
        return LIMITER_UNATTRIBUTED;
    };
    let tail = &body[pos + b"\"limiter\"".len()..];
    for (idx, id) in LIMITER_IDS.iter().enumerate() {
        // The value follows within a few bytes (`: "admin"`); bound the scan so
        // an unrelated later field cannot be mistaken for the value.
        let window = &tail[..tail.len().min(id.len() + 8)];
        if find_subslice(window, id.as_bytes()).is_some() {
            return idx;
        }
    }
    LIMITER_UNATTRIBUTED
}

/// Renders the per-limiter 429 counters as a named map, dropping zero buckets so
/// the artifact names only the limiters that actually shed.
fn limiter_histogram(counts: &LimiterCounts) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    for (idx, n) in counts.iter().enumerate() {
        if *n == 0 {
            continue;
        }
        let name = LIMITER_IDS.get(idx).copied().unwrap_or("unattributed");
        out.insert(name.to_string(), *n);
    }
    out
}

/// The limiter that shed the most requests in a rung, for the operator-facing
/// diagnosis. `None` when nothing was shed.
fn dominant_limiter(hist: &BTreeMap<String, u64>) -> Option<(&str, u64)> {
    hist.iter()
        .max_by_key(|(_, n)| **n)
        .map(|(k, n)| (k.as_str(), *n))
}

/// Sends one request over an established keep-alive stream and reads the full
/// response. Returns the HTTP status code, the shedding-limiter bucket index on
/// a `429`, and the `location` header value on a 3xx, or an error string on
/// transport failure. The connection is drained (Content-Length or chunked) so
/// it can be reused.
fn send_one(
    stream: &mut TcpStream,
    req: &[u8],
) -> Result<(u16, Option<usize>, Option<String>), String> {
    stream.write_all(req).map_err(|e| format!("write: {e}"))?;
    stream.flush().map_err(|e| format!("flush: {e}"))?;
    read_response(stream)
}

/// Reads one HTTP/1.1 response, returns the status code, the shedding-limiter
/// bucket index on a `429`, and the `location` header value on a 3xx. Leaves
/// the stream at the start of the next response.
fn read_response(stream: &mut TcpStream) -> Result<(u16, Option<usize>, Option<String>), String> {
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
    let location = if (300..400).contains(&status) {
        parse_location(head)
    } else {
        None
    };
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
        let bucket = (status == 429).then(|| limiter_bucket(&body));
        return Ok((status, bucket, location));
    }

    let want = content_len.unwrap_or(0);
    // Only a 429 body is retained — on every other status the bytes are counted
    // and dropped, so the generator's hot loop keeps its zero-copy drain.
    let keep_body = status == 429;
    let mut body: Vec<u8> = if keep_body {
        buf[header_end..].to_vec()
    } else {
        Vec::new()
    };
    while body_have < want {
        let n = stream
            .read(&mut tmp)
            .map_err(|e| format!("read body: {e}"))?;
        if n == 0 {
            return Err("eof mid-body".into());
        }
        if keep_body {
            body.extend_from_slice(&tmp[..n]);
        }
        body_have += n;
    }
    let bucket = keep_body.then(|| limiter_bucket(&body));
    Ok((status, bucket, location))
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

/// Extracts the `location` header value from a raw response head, or `None`.
fn parse_location(head: &str) -> Option<String> {
    for line in head.lines().skip(1) {
        if line.len() >= 9 && line[..9].eq_ignore_ascii_case("location:") {
            return Some(line[9..].trim().to_string());
        }
    }
    None
}

/// Returns true when the response counts as success for the given op.
///
/// Login ops treat a 303 (or 302) redirect to `/ui` as success — that is the
/// normal post-login redirect. A redirect back to the login page is a failed
/// login rendered as a redirect; blanket-accepting 3xx would grade a
/// 100%-wrong-password run green. Every other op requires a 2xx.
fn is_response_success(op: &str, code: u16, location: Option<&str>) -> bool {
    if op == "login" && matches!(code, 302 | 303) {
        return location == Some("/ui");
    }
    (200..300).contains(&code)
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
    net_dev: &str,
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
                    Ok((code, limiter, location)) => {
                        st.completed += 1;
                        st.latencies_us.push(elapsed);
                        if !is_response_success(tpl.op, code, location.as_deref()) {
                            st.non_2xx += 1;
                            if code == 429 {
                                st.rate_limited += 1;
                                st.rate_limited_by[limiter.unwrap_or(LIMITER_UNATTRIBUTED)] += 1;
                            }
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
    // HEA-2014: network snapshot taken at measurement start, delta computed at end.
    let mut net_snapshot_start: Option<NetSnapshot> = None;
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
            net_snapshot_start = Some(NetSnapshot::capture(net_dev));
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
    let mut rate_limited = 0u64;
    let mut rate_limited_by: LimiterCounts = [0; LIMITER_IDS.len() + 1];
    let mut connect_errors = 0u64;
    let mut transport_errors = 0u64;
    let mut lat: Vec<u64> = Vec::new();
    for s in &stats {
        let st = s.lock().expect("stats lock");
        completed += st.completed;
        non_2xx += st.non_2xx;
        rate_limited += st.rate_limited;
        for (agg, w) in rate_limited_by.iter_mut().zip(st.rate_limited_by.iter()) {
            *agg += *w;
        }
        connect_errors += st.connect_errors;
        transport_errors += st.transport_errors;
        lat.extend_from_slice(&st.latencies_us);
    }
    lat.sort_unstable();
    let achieved_rate = completed as f64 / measure_wall;
    let denom = (completed + connect_errors + transport_errors).max(1);
    let error_rate = (non_2xx + connect_errors + transport_errors) as f64 / denom as f64;

    // HEA-2014: compute generator NIC delta over the measurement window.
    let net_delta = match net_snapshot_start {
        Some(start_snap) => {
            let end_snap = NetSnapshot::capture(net_dev);
            NetDelta {
                softnet_dropped: end_snap
                    .softnet_dropped
                    .saturating_sub(start_snap.softnet_dropped),
                softnet_time_squeeze: end_snap
                    .softnet_time_squeeze
                    .saturating_sub(start_snap.softnet_time_squeeze),
                rx_pps: end_snap.rx_packets.saturating_sub(start_snap.rx_packets) as f64
                    / measure_wall,
                tx_pps: end_snap.tx_packets.saturating_sub(start_snap.tx_packets) as f64
                    / measure_wall,
                time_wait: end_snap.time_wait,
                port_range_size: read_ephemeral_port_range_size(),
            }
        }
        None => NetDelta::default(),
    };

    let server_cpu_pct = read_server_cpu(server_cpu_file);
    let attribution = classify(
        server_cpu_pct,
        generator_headroom,
        connect_errors + transport_errors,
        error_rate,
        rate_limited,
        &net_delta,
    );

    RungResult {
        offered_rate,
        achieved_rate,
        completed,
        non_2xx,
        rate_limited,
        rate_limited_by: limiter_histogram(&rate_limited_by),
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
    // HEA-2014: loopback control run — measures the read plane over loopback on
    // the server droplet before the 2-host sweep. Same binary, same config. The
    // delta between the loopback number and the two-host number attributes the
    // difference to 'real wire + slower cores' vs 'co-residency', breaking the
    // confound that changing two variables (machine class AND network transport)
    // would otherwise leave.
    let loopback_control = args.iter().any(|a| a == "--loopback-control");
    // Operator-supplied record of the measured host's shaper setting (HEA-2007):
    // e.g. `--limiter-note "request_shaper ip_rps=200000 realm_rps=200000"`. Echoed
    // verbatim into the artifact so the chosen setting is captured alongside the run.
    // Advisory only — the `rate_limited` gate is what actually voids a shed rung.
    let limiter_note = arg(&args, "--limiter-note");

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

    if target_is_loopback(&authority) && !allow_loopback && !loopback_control {
        return Err(format!(
            "target {authority} resolves to loopback — generator and server would be co-resident, \
             which is the exact ceiling HEA-1997 requires two hosts to avoid. Refusing to grade. \
             Pass --loopback-control to run the loopback baseline (stamped run_type=loopback_control), \
             or --allow-loopback for a smoke test (stamped run_type=loopback_smoke, ungradable)."
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

    // HEA-2015: login/blended planes require a CSRF token pre-fetched before the
    // corpus is built. Fetch it once here; the corpus builder embeds it in each
    // login template. Fails fast so the operator sees the blocker before any
    // load is fired.
    let login_csrf_token: Option<String> = match plane {
        Plane::Login | Plane::Blended => prefetch_login_csrf(&target, &handle)?,
        _ => None,
    };
    let corpus = Arc::new(build_corpus(
        plane,
        &target,
        &handle,
        login_csrf_token.as_deref(),
    )?);

    // HEA-2014: detect the generator's primary NIC once; reused across rungs.
    let net_dev = primary_net_dev();
    eprintln_stderr(&format!("[net] generator primary NIC: {net_dev}"));

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
            &net_dev,
            &server_cpu_file,
        );
        // Name the shedding limiter inline: the operator's next action is to
        // raise *that* limit, and printing only a 429 count sends them to
        // `security.request_shaper` by default (HEA-2010).
        let shed_by = match dominant_limiter(&r.rate_limited_by) {
            Some((name, n)) => format!(" shed_by={name}({n})"),
            None => String::new(),
        };
        eprintln_stderr(&format!(
            "  achieved={:.0}/s p50={:.2}ms p99={:.2}ms grade={} err_rate={:.4} 429={}{shed_by}",
            r.achieved_rate, r.p50_ms, r.p99_ms, r.attribution.grade, r.error_rate, r.rate_limited
        ));
        results.push(r);
    }

    let knee = detect_knee(&results);
    let shape = degradation_shape(&results, knee);

    // HEA-2010: which limiter actually shed, summed across every rung.
    let mut rate_limited_by_total: BTreeMap<String, u64> = BTreeMap::new();
    for r in &results {
        for (k, n) in &r.rate_limited_by {
            *rate_limited_by_total.entry(k.clone()).or_default() += n;
        }
    }

    let run_type = if loopback_control {
        "loopback_control"
    } else if allow_loopback {
        "loopback_smoke"
    } else {
        "two_host"
    };

    let artifact = serde_json::json!({
        "schema": "hea-1997-saturation-1",
        // HEA-2014: two_host = normal 2-host rig run; loopback_control = baseline
        // measured over loopback on the server droplet (same binary, same config,
        // same rungs) to attribute the delta between the loopback and 2-host numbers.
        "run_type": run_type,
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
        // HEA-2007: the measured host must pin `security.request_shaper` above the
        // top rung so the shaper does not shed offered load; the operator records
        // that setting here. Any rung that still sees a 429 is graded INADMISSIBLE
        // (reason `rate_limited`) so a shaper-shed rung can never be reported as a knee.
        "limiter_setting": limiter_note,
        "rungs_rate_limited": results.iter().any(|r| r.rate_limited > 0),
        // HEA-2010: which limiter actually shed, summed across every rung. The
        // shaper is only one of five; before this the artifact implied it was
        // always the cause and sent operators to re-pin a limit that was already
        // 200x above the top rung.
        "rate_limited_by_total": rate_limited_by_total,
        "generator_cores": num_cpus(),
        // HEA-2014: the NIC whose softnet/pps counters appear in each rung's attribution.
        "generator_net_dev": net_dev,
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
             >= 2x, softnet drops are zero, ephemeral ports are not exhausted, \
             transport is clean, and degradation is by queueing not errors.",
            "INCOMPLETE = no --server-cpu-file, so server saturation is unconfirmed; \
             never treat an INCOMPLETE rung as a published capacity number.",
            "Any rung with a 429 is INADMISSIBLE (reason `rate_limited`): a limiter \
             shed load, so the ceiling is Hearth's limiter, not the server (HEA-2007).",
            "`rate_limited_by` / `rate_limited_by_total` name WHICH limiter shed \
             (HEA-2010). Raise that one, not the shaper by reflex: `shaper` = \
             security.request_shaper, `admin` = security.rate_limiting.admin_per_minute, \
             `token` = security.rate_limiting.token_per_minute, `export` = \
             security.backup.export_rate_limit. `unattributed` means the server \
             predates the tagging — upgrade it before trusting the split.",
            "HEA-2014 NIC accounting: `attribution.generator_softnet_dropped` is \
             the kernel drop count at the generator NIC during the rung. Non-zero \
             ⇒ INADMISSIBLE (reason `generator_softnet_drops`): the NIC, not Hearth, \
             was the bottleneck. `generator_rx_pps`/`generator_tx_pps` give pps \
             context. `generator_time_wait` near the port range ⇒ TIME_WAIT \
             exhaustion: INADMISSIBLE (reason `generator_ephemeral_ports`).",
            "run_type: two_host = 2-host rig (gradable); loopback_control = loopback \
             baseline on the server droplet (for attribution only, never a knee); \
             loopback_smoke = --allow-loopback smoke test (ungradable)."
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
        let a = classify(Some(95.0), 3.0, 0, 0.0, 0, &NetDelta::default());
        assert_eq!(a.grade, "ADMISSIBLE");
        assert!(a.failing_conditions.is_empty());
        assert_eq!(a.server_cpu_pinned, Some(true));
    }

    #[test]
    fn classify_incomplete_without_server_cpu() {
        // Even with a perfect generator-side picture, no server CPU ⇒ INCOMPLETE.
        let a = classify(None, 5.0, 0, 0.0, 0, &NetDelta::default());
        assert_eq!(a.grade, "INCOMPLETE");
    }

    #[test]
    fn classify_inadmissible_on_generator_ceiling() {
        // Generator itself is the bottleneck (headroom < 2x): inadmissible.
        let a = classify(Some(70.0), 1.2, 0, 0.0, 0, &NetDelta::default());
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
        let a = classify(Some(99.0), 4.0, 0, 0.20, 0, &NetDelta::default());
        assert_eq!(a.grade, "INADMISSIBLE");
        assert!(a
            .failing_conditions
            .iter()
            .any(|c| c == "degrading_by_queueing"));
    }

    #[test]
    fn classify_inadmissible_on_transport_errors() {
        let a = classify(Some(99.0), 4.0, 5, 0.0, 0, &NetDelta::default());
        assert_eq!(a.grade, "INADMISSIBLE");
        assert!(a.failing_conditions.iter().any(|c| c == "transport_clean"));
    }

    #[test]
    fn classify_inadmissible_on_any_429_even_below_error_threshold() {
        // A perfectly-attributed rung (server pinned, generator clear, transport
        // clean) with a single 429 whose error rate is *under* MAX_ERROR_RATE must
        // still be INADMISSIBLE — the shaper shed load, so it measured the limiter.
        let a = classify(
            Some(99.0),
            4.0,
            0,
            MAX_ERROR_RATE / 2.0,
            1,
            &NetDelta::default(),
        );
        assert_eq!(a.grade, "INADMISSIBLE");
        assert!(a.rate_limited_shed);
        assert!(a.failing_conditions.iter().any(|c| c == "rate_limited"));
    }

    #[test]
    fn classify_inadmissible_on_softnet_drops() {
        // Non-zero softnet drops: the generator NIC is the bottleneck — hard INADMISSIBLE.
        let net = NetDelta {
            softnet_dropped: 42,
            softnet_time_squeeze: 0,
            rx_pps: 15_000.0,
            tx_pps: 15_000.0,
            time_wait: 100,
            port_range_size: 28_232,
        };
        let a = classify(Some(99.0), 4.0, 0, 0.0, 0, &net);
        assert_eq!(a.grade, "INADMISSIBLE");
        assert!(
            a.failing_conditions
                .iter()
                .any(|c| c == "generator_softnet_drops"),
            "expected generator_softnet_drops in {:?}",
            a.failing_conditions
        );
        assert!(!a.softnet_drops_zero);
    }

    #[test]
    fn classify_inadmissible_on_ephemeral_port_exhaustion() {
        // TIME_WAIT at 96% of the port range: exhaustion is the ceiling.
        let range_size = 28_232u64;
        let net = NetDelta {
            softnet_dropped: 0,
            softnet_time_squeeze: 0,
            rx_pps: 10_000.0,
            tx_pps: 10_000.0,
            time_wait: range_size * 96 / 100 + 1,
            port_range_size: range_size,
        };
        let a = classify(Some(99.0), 4.0, 0, 0.0, 0, &net);
        assert_eq!(a.grade, "INADMISSIBLE");
        assert!(
            a.failing_conditions
                .iter()
                .any(|c| c == "generator_ephemeral_ports"),
            "expected generator_ephemeral_ports in {:?}",
            a.failing_conditions
        );
        assert!(!a.generator_ephemeral_ports_ok);
    }

    #[test]
    fn classify_softnet_inadmissible_outranks_incomplete() {
        // Softnet drops hard-INADMISSIBLE even without a server-CPU sample —
        // the generator NIC is the ceiling regardless of server state.
        let net = NetDelta {
            softnet_dropped: 1,
            ..NetDelta::default()
        };
        let a = classify(None, 5.0, 0, 0.0, 0, &net);
        assert_eq!(a.grade, "INADMISSIBLE");
        assert!(a
            .failing_conditions
            .iter()
            .any(|c| c == "generator_softnet_drops"));
    }

    #[test]
    fn classify_ephemeral_ports_fail_open_when_range_unknown() {
        // port_range_size == u64::MAX means we could not read the range — must not
        // penalise the rung for something we cannot measure.
        let net = NetDelta {
            time_wait: 50_000,
            port_range_size: u64::MAX,
            ..NetDelta::default()
        };
        let a = classify(Some(95.0), 3.0, 0, 0.0, 0, &net);
        assert_eq!(a.grade, "ADMISSIBLE");
        assert!(a.generator_ephemeral_ports_ok);
    }

    // ── 429 attribution (HEA-2010) ───────────────────────────────────────────
    //
    // The HEA-1970 dry-run voided all five rungs and the artifact pointed the
    // operator at `security.request_shaper`, which had already been pinned 200x
    // above the top rung. The actual sheds came from the admin and token
    // limiters. A 429 must name its own source.

    #[test]
    fn attributes_429_to_the_admin_limiter() {
        let body = br#"{"error":"too_many_requests","error_description":"rate limit exceeded","limiter":"admin"}"#;
        assert_eq!(LIMITER_IDS[limiter_bucket(body)], "admin");
    }

    #[test]
    fn attributes_429_to_the_shaper() {
        let body = br#"{"error":"too_many_requests","error_description":"rate limit exceeded","limiter":"shaper"}"#;
        assert_eq!(LIMITER_IDS[limiter_bucket(body)], "shaper");
    }

    #[test]
    fn attributes_export_429_despite_a_different_error_code() {
        let body = br#"{"error":"export_rate_limit_exceeded","error_description":"export rate limit exceeded; maximum exports per hour reached","limiter":"export"}"#;
        assert_eq!(LIMITER_IDS[limiter_bucket(body)], "export");
    }

    #[test]
    fn untagged_429_is_unattributed_not_silently_blamed_on_the_shaper() {
        // An older server emits no `limiter` field. Guessing "shaper" here is
        // exactly the misdiagnosis this change exists to remove.
        let body = br#"{"error":"too_many_requests"}"#;
        assert_eq!(limiter_bucket(body), LIMITER_UNATTRIBUTED);
        let hist = limiter_histogram(&{
            let mut c: LimiterCounts = [0; LIMITER_IDS.len() + 1];
            c[LIMITER_UNATTRIBUTED] = 7;
            c
        });
        assert_eq!(hist.get("unattributed"), Some(&7));
        assert!(!hist.contains_key("shaper"));
    }

    #[test]
    fn a_later_unrelated_field_is_not_mistaken_for_the_limiter_value() {
        // `admin` appears in the body but far past the `limiter` value, which is
        // `token`. A greedy scan would report the wrong limiter.
        let body = br#"{"limiter":"token","path":"/admin/users/1"}"#;
        assert_eq!(LIMITER_IDS[limiter_bucket(body)], "token");
    }

    #[test]
    fn histogram_omits_zero_buckets_and_dominant_names_the_worst_offender() {
        let mut c: LimiterCounts = [0; LIMITER_IDS.len() + 1];
        c[1] = 900; // admin
        c[2] = 12; // token
        let hist = limiter_histogram(&c);
        assert_eq!(hist.len(), 2, "zero buckets must not appear: {hist:?}");
        assert_eq!(dominant_limiter(&hist), Some(("admin", 900)));
        assert_eq!(dominant_limiter(&BTreeMap::new()), None);
    }

    // ── login 303 scorer (HEA-2016) ─────────────────────────────────────────

    #[test]
    fn login_303_to_ui_counts_as_success() {
        // A successful browser login returns 303 to /ui. The old scorer treated
        // every non-2xx as an error, making every login request appear to fail.
        assert!(is_response_success("login", 303, Some("/ui")));
    }

    #[test]
    fn login_303_back_to_login_page_counts_as_non_2xx() {
        // A failed login is rendered as a 303 redirect back to the login page.
        // Blanket-accepting 3xx would grade a 100%-wrong-password run green;
        // only a redirect to /ui (the post-login target) counts as success.
        assert!(!is_response_success(
            "login",
            303,
            Some("/ui/realms/dev/login")
        ));
        assert!(!is_response_success(
            "login",
            302,
            Some("/ui/realms/dev/login")
        ));
    }

    #[test]
    fn read_op_303_counts_as_non_2xx() {
        // Non-login ops must not inherit the login 3xx carve-out.
        assert!(!is_response_success("introspect", 303, Some("/ui")));
        assert!(!is_response_success("mint", 303, Some("/ui")));
    }

    #[test]
    fn login_429_is_not_success_so_rate_limited_path_fires() {
        // 429s must not be swallowed by the login-success check so that the
        // rate_limited / rate_limited_by attribution counters still increment.
        assert!(!is_response_success("login", 429, None));
    }

    #[test]
    fn classify_429_outranks_incomplete_without_server_cpu() {
        // No server-CPU sample would normally give INCOMPLETE, but a 429 is a hard
        // INADMISSIBLE — otherwise a shed rung could sneak past as "not yet graded".
        let a = classify(None, 5.0, 0, 0.0, 3, &NetDelta::default());
        assert_eq!(a.grade, "INADMISSIBLE");
        assert!(a.failing_conditions.iter().any(|c| c == "rate_limited"));
    }

    fn rung(offered: u64, achieved: f64, _grade: &str, err: f64) -> RungResult {
        RungResult {
            offered_rate: offered,
            achieved_rate: achieved,
            completed: achieved as u64,
            non_2xx: 0,
            rate_limited: 0,
            rate_limited_by: BTreeMap::new(),
            connect_errors: 0,
            transport_errors: 0,
            error_rate: err,
            max_backlog: 0,
            p50_ms: 1.0,
            p99_ms: 2.0,
            p999_ms: 3.0,
            attribution: classify(Some(95.0), 4.0, 0, err, 0, &NetDelta::default()),
        }
    }

    #[test]
    fn rate_limited_rung_is_never_a_knee() {
        // A rung that keeps up and would otherwise be the knee, but saw 429s, must
        // be excluded from knee detection (HEA-2007 AC: shed rung never ADMISSIBLE).
        let mut shed = rung(1000, 1000.0, "ADMISSIBLE", 0.0);
        shed.rate_limited = 42;
        shed.attribution = classify(Some(99.0), 4.0, 0, 0.0, 42, &NetDelta::default());
        let rungs = vec![rung(500, 500.0, "ADMISSIBLE", 0.0), shed];
        // The only keeping-up rung with a valid grade is index 0, not the shed rung.
        assert_eq!(detect_knee(&rungs), Some(0));
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
        r.attribution = classify(Some(50.0), 1.0, 3, 0.30, 0, &NetDelta::default());
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
        let err = match build_corpus(Plane::Read, &target, &handle, None) {
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
        let corpus = build_corpus(Plane::Issuance, &issuance_target(), &handle, None)
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
        let err = match build_corpus(Plane::Issuance, &issuance_target(), &handle, None) {
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
        // HEA-2015: pass a pre-fetched CSRF token so the template is realistic;
        // the network call (fetch_csrf_token) is exercised separately.
        let corpus = build_corpus(
            Plane::Login,
            &login_target(),
            &handle,
            Some("csrf-test-token"),
        )
        .expect("login corpus builds with a realm name, password, and csrf token");
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
        // CSRF fields must be embedded (HEA-2015).
        assert!(
            req.contains("Cookie: hearth_ui_csrf=csrf-test-token\r\n"),
            "Cookie header with CSRF token missing: {req}"
        );
        assert!(
            req.contains("_csrf=csrf-test-token"),
            "_csrf body field missing: {req}"
        );
    }

    #[test]
    fn login_plane_errors_without_realm_name() {
        // A pre-HEA-2006 handle carries only `realm_id` (realm_name defaults to
        // empty). The login plane must fail loud rather than emit
        // `/ui/realms//login` and silently 404 every request.
        let handle = login_handle("9a35bdcf-0000-4000-8000-000000000000", "");
        let err = match build_corpus(Plane::Login, &login_target(), &handle, None) {
            Ok(_) => panic!("login must fail when the handle carries no realm name"),
            Err(e) => e,
        };
        assert!(err.contains("realm_name"), "{err}");
    }

    #[test]
    fn login_plane_embeds_csrf_token_and_cookie_header() {
        // HEA-2015: when a CSRF token is pre-fetched and provided, every login
        // template must carry both the `Cookie: hearth_ui_csrf=TOKEN` header and
        // the `_csrf=TOKEN` body field. Without both the production-mode server
        // returns 422 before reaching Argon2id — the KDF plane measures nothing.
        let handle = login_handle("r1", "dev-realm");
        let corpus = build_corpus(Plane::Login, &login_target(), &handle, Some("tok-abc-123"))
            .expect("login corpus with csrf token");
        let req = String::from_utf8(corpus.templates[0].bytes.clone()).expect("utf8");
        assert!(
            req.contains("Cookie: hearth_ui_csrf=tok-abc-123\r\n"),
            "Cookie header with CSRF token missing: {req}"
        );
        assert!(
            req.contains("_csrf=tok-abc-123"),
            "_csrf body field missing: {req}"
        );
    }

    #[test]
    fn login_plane_omits_csrf_fields_when_no_token_provided() {
        // When login_csrf_token is None (e.g. --dev bypass or future stateless
        // mode), no CSRF cookie or body field must be injected.
        let handle = login_handle("r1", "dev-realm");
        let corpus = build_corpus(Plane::Login, &login_target(), &handle, None)
            .expect("login corpus without csrf token");
        let req = String::from_utf8(corpus.templates[0].bytes.clone()).expect("utf8");
        assert!(!req.contains("Cookie:"), "unexpected Cookie header: {req}");
        assert!(!req.contains("_csrf="), "unexpected _csrf field: {req}");
    }
}
