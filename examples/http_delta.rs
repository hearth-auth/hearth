//! HEA-1957 · C11 — the end-to-end **HTTP delta**.
//!
//! Every Hearth number published so far (`PERFORMANCE_REPORT` 1.0 → 2.1) is
//! **engine-level**: measured by calling `IdentityEngine` methods in-process
//! with no HTTP server, no axum, no tokio, no sockets. Every competitor number
//! we compare against (`docs/perf/HEA-1867-COMPETITIVE-COMPARISON.md`) is
//! **end-to-end HTTP under load**. Comparing the two is not a comparison, and
//! 2.0/2.1 correctly record the HTTP layer as `NOT-MEASURABLE`
//! (HEA-1871 / HEA-1876).
//!
//! This harness measures the missing quantity: for the same operation, on the
//! same host, in the **same process and the same run**, how much throughput and
//! latency does the HTTP surface cost relative to the engine call underneath it?
//!
//! The deliverable is the **delta ratio** — `engine ops/s ÷ HTTP ops/s` — per
//! operation, not the absolute numbers.
//!
//! ## Why this run is admissible where HEA-1871/HEA-1876 were not
//!
//! The binding grading rule from `docs/perf/HEA-1867-PLAN.md` is: *nothing is
//! graded PASS on a run whose ceiling attribution was the generator.* The Goose
//! runs failed that rule — the generator and the server shared cores and Goose's
//! own I/O loop consumed them first, so the measured ceiling was Goose's, not
//! Hearth's. Two changes make this run gradable:
//!
//! 1. **A generator that costs almost nothing.** The client here is a
//!    hand-rolled, closed-loop HTTP/1.1 driver over a persistent `TcpStream`
//!    with pre-built request bytes: no TLS, no connection churn, no async
//!    runtime, no per-request allocation, no response parsing beyond
//!    `Content-Length`.
//! 2. **A measured generator ceiling** (`null` op). Before touching Hearth, the
//!    same generator threads are pointed at a bare TCP echo server in this
//!    process that replies with a canned, fixed `200 OK`. That number is the
//!    ceiling this generator can produce on this host at this concurrency. Every
//!    Hearth op is then reported alongside its **generator headroom** =
//!    `null_ops_s / op_ops_s`. A result with headroom ≥ 2× is generator-clear by
//!    construction; anything below that is marked inadmissible in the output
//!    rather than silently published.
//!
//! ## Operation ladder — each HTTP op is paired with its engine counterpart
//!
//! | HTTP op | Endpoint | Engine counterpart |
//! |---|---|---|
//! | `null` | canned-response TCP server | — (generator calibration) |
//! | `healthz` | `GET /healthz` | — (axum/tokio/TCP envelope floor, no engine work) |
//! | `introspect` | `POST /realms/{r}/introspect` | `introspect_token` |
//! | `userinfo` | `GET /realms/{r}/userinfo` | `validate_token` + `get_user` |
//! | `login` | `POST /ui/realms/{r}/login` | `verify_password` + `create_session` |
//!
//! `introspect` is the direct comparator for Ory Hydra's published
//! introspection figure — same operation, same wire shape, both end-to-end.
//! `healthz` is the load-bearing control: it is the *same* HTTP stack with the
//! engine removed, so `1/healthz_ops_s` is the per-request envelope cost that
//! every other row pays before its engine call starts.
//!
//! `login` is the only Hearth HTTP surface that creates a **durable** session
//! (`create_session` → WAL `fsync`), and it necessarily performs an Argon2id
//! verify first — there is no KDF-free session-create endpoint. Its Argon2id
//! parameters are therefore emitted as first-class fields: competitors publish
//! login throughput without disclosing their KDF cost, which makes their numbers
//! unfalsifiable. Ours is stated.
//!
//! ## What is *not* included, and must be disclosed with any published number
//!
//! * **No TLS.** Loopback plaintext HTTP/1.1. A TLS terminator adds handshake
//!   cost (amortised by keep-alive) and per-record symmetric crypto.
//! * **No physical network.** Loopback only — no NIC, no switch, no RTT.
//! * **Client and server are co-resident** on the same host and share cores.
//!   The `null` calibration bounds the error this introduces; it does not
//!   remove it.
//!
//! These make the measured HTTP number an **upper bound on Hearth's HTTP
//! throughput** and hence the delta ratio a **lower bound**. Real deployments
//! behind TLS on a real network will show a larger delta, never a smaller one.
//!
//! Run: `cargo run --release --example http_delta`

// Measurement binary: casts are reporting math on small magnitudes, and the
// setup/print helpers are intentionally verbose for auditability.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::needless_range_loop
)]

use std::io::{Read, Write as IoWrite};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{Clock, RealmId, SystemClock, UserId};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, SessionContext,
    TokenIntrospectionRequest,
};
use hearth::protocol::http::AppState;
use hearth::protocol::web::{CookieSecret, WebState};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

#[path = "support/hostenv.rs"]
mod hostenv;

/// Concurrency ladder. Both the engine phase and the HTTP phase are measured at
/// every rung, so the ratio at each rung compares like with like.
const LADDER: &[usize] = &[1, 8, 32];

/// Concurrency ladder for the KDF-bearing `login` op. Argon2id verify is
/// ~10–30 ms of CPU behind a bounded admission gate, so a 32-deep read ladder
/// would spend the whole window queued. Kept short and shallow deliberately.
const LOGIN_LADDER: &[usize] = &[1, 8];

/// Measurement window per (op, concurrency) cell.
const MEASURE: Duration = Duration::from_secs(3);

/// Warm-up window per cell, discarded. Lets the accept loop, the connection
/// pool and the CPU frequency governor settle before the timed window opens.
const WARMUP: Duration = Duration::from_millis(400);

/// Seeded users. Small on purpose: this harness measures *per-operation* cost,
/// not corpus-scale behaviour (that is C5/C8's job).
const USERS: usize = 256;

/// Warm sessions + access tokens minted against them.
const SESSIONS: usize = 1_024;

/// Users provisioned with a real Argon2id password credential, one per
/// `login` generator thread, so concurrent logins do not serialize on a single
/// user's session index and measure lock contention instead of the login path.
const LOGIN_USERS: usize = 32;

/// The password every login user shares. Not a secret — this is a throwaway
/// in-process fixture whose data dir is deleted when the run ends.
const LOGIN_PASSWORD: &str = "correct-horse-battery-staple-1957";

/// Hot-tier capacity for the fixture's storage engine.
const HOT_CAPACITY: usize = 40_000;

/// Tokio worker threads for the axum server under test.
const SERVER_WORKERS: usize = 8;

/// Default number of independent samples of the full measurement.
///
/// HEA-1974 AC3: "a figure without a spread is not publishable — that is the
/// lesson from L5's 236% spread." Three is the floor, not a target.
const DEFAULT_SAMPLES: usize = 3;

/// One complete pass over all three phases. Repeated `--samples` times so the
/// artifact carries run-to-run spread rather than a single point.
struct Sample {
    null: Vec<Cell>,
    engine: Vec<OpResult>,
    http: Vec<OpResult>,
}

/// Parsed command line.
struct Args {
    samples: usize,
    allow_contended: bool,
    out: PathBuf,
}

impl Args {
    fn parse() -> Result<Self, Box<dyn std::error::Error>> {
        let mut a = Self {
            samples: DEFAULT_SAMPLES,
            allow_contended: false,
            out: PathBuf::from("docs/perf/artifacts/c11-http-delta-raw.json"),
        };
        let mut it = std::env::args().skip(1);
        while let Some(arg) = it.next() {
            match arg.as_str() {
                "--samples" => {
                    a.samples = it
                        .next()
                        .ok_or("--samples needs a value")?
                        .parse::<usize>()?
                        .max(1);
                }
                "--allow-contended-host" => a.allow_contended = true,
                "--out" => a.out = PathBuf::from(it.next().ok_or("--out needs a value")?),
                "--help" | "-h" => {
                    println!(
                        "usage: http_delta [--samples N] [--out PATH] [--allow-contended-host]\n\n\
                         --samples N               independent passes (default {DEFAULT_SAMPLES}, minimum 1)\n\
                         --out PATH                raw artifact destination\n\
                         --allow-contended-host    run anyway on a host that fails the quiescence\n\
                         \x20                         gate, stamping publishable:false in the artifact"
                    );
                    std::process::exit(0);
                }
                other => return Err(format!("unknown argument: {other}").into()),
            }
        }
        Ok(a)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse()?;
    println!(
        "HEA-1974 · C11 — end-to-end HTTP delta ({} samples)\n",
        args.samples
    );

    // ── Quiescence preflight (HEA-1974 AC1) ──────────────────────────────────
    // This runs *before* the fixture is built so a doomed run costs seconds, not
    // the full Argon2id corpus seed.
    let host = hostenv::HostProfile::capture();
    let load_pre = hostenv::LoadSnapshot::capture();
    println!("── preflight: host profile + quiescence gate ──\n");
    println!(
        "  cpu            {} ({} logical)",
        host.cpu_model, host.cpus
    );
    println!(
        "  governor       {}   boost {}   isolated '{}'",
        host.governor.as_deref().unwrap_or("?"),
        host.boost.map_or("?", |b| if b { "on" } else { "off" }),
        host.isolated_cpus
    );
    println!(
        "  battery        {}   package temp {}",
        if host.has_battery {
            "present"
        } else {
            "absent"
        },
        host.temp_c
            .map_or_else(|| "?".to_string(), |t| format!("{t:.1}°C"))
    );
    println!(
        "  load average   {:.2} {:.2} {:.2}   ({:.1}% of {} CPUs)",
        load_pre.load1,
        load_pre.load5,
        load_pre.load15,
        100.0 * load_pre.per_cpu(host.cpus),
        host.cpus
    );

    let census_pre = hostenv::ProcessCensus::capture(std::process::id());
    println!(
        "  foreign CPU    {:.0}% of one core across the host; top consumers:",
        census_pre.total_busy_pct
    );
    for p in census_pre.procs.iter().take(8) {
        println!(
            "                   {:>6.1}%  {:<24} pid {:<8} rss {:>8} MiB",
            p.cpu_pct,
            p.comm,
            p.pid,
            p.rss_kib / 1024
        );
    }

    let verdict = hostenv::evaluate(&host, &load_pre, &census_pre);
    println!();
    if verdict.publishable {
        println!("  ✅ QUIESCENCE GATE PASSED — this run's figures are publishable.\n");
    } else {
        println!("  ❌ QUIESCENCE GATE FAILED\n{}", verdict.explain());
        if !args.allow_contended {
            eprintln!(
                "refusing to measure: a run on a contended or non-server-class box is not a \
                 result (HEA-1974 AC1/AC6).\n\
                 \x20 · If the objections are contention-only, quiesce the host and re-run.\n\
                 \x20 · If any objection is host-class, this box cannot produce publishable\n\
                 \x20   competitive figures at all — escalate for a server-class host.\n\
                 \x20 · To collect non-publishable diagnostic data anyway, pass\n\
                 \x20   --allow-contended-host (the artifact will be stamped publishable:false)."
            );
            std::process::exit(2);
        }
        println!(
            "  ⚠️  --allow-contended-host set: continuing, but this artifact is stamped\n\
             \x20     publishable:false and MUST NOT be cited in any competitive comparison.\n"
        );
    }

    // ── Measurement ──────────────────────────────────────────────────────────
    let fixture = Fixture::build()?;
    let null_addr = spawn_null_server()?;
    let servers = fixture.spawn_servers()?;

    let mut samples = Vec::new();
    for s in 1..=args.samples {
        println!("\n════ sample {s}/{} ════", args.samples);

        println!("\n── phase 1/3: generator calibration (null TCP server) ──\n");
        let mut null = Vec::new();
        for &t in LADDER {
            let r = drive_http("null", null_addr, t, &fixture.null_requests(t));
            println!(
                "  null   T={t:<3}  {:>12.0} ops/s   p50 {:>8.1} µs",
                r.ops_s, r.p50_us
            );
            null.push(r);
        }

        println!("\n── phase 2/3: engine-direct (no HTTP) ──\n");
        let engine = fixture.measure_engine();

        println!("\n── phase 3/3: end-to-end HTTP ──\n");
        let http = fixture.measure_http(&servers);

        samples.push(Sample { null, engine, http });
    }

    let load_post = hostenv::LoadSnapshot::capture();
    let census_post = hostenv::ProcessCensus::capture(std::process::id());

    // INVARIANT: the loop above pushes at least one sample (`Args::parse` clamps
    // `samples` to a minimum of 1), so `last()` is always `Some`.
    #[allow(clippy::unwrap_used)]
    let last = samples.last().unwrap();
    print_report(&fixture, &last.null, &last.engine, &last.http);
    print_spread(&samples);
    emit_json(
        &fixture,
        &args,
        &samples,
        &host,
        (&load_pre, &census_pre),
        (&load_post, &census_post),
        &verdict,
    )?;
    Ok(())
}

// ── Fixture ───────────────────────────────────────────────────────────────────

/// Engines, corpus and credentials shared by the engine phase and the HTTP
/// phase. Both phases run against **this** state, in this process, so the ratio
/// is not confounded by a different build, host, corpus or page cache.
struct Fixture {
    engine: Arc<EmbeddedIdentityEngine>,
    rbac: Arc<dyn RbacEngine>,
    audit: Arc<dyn AuditEngine>,
    realm: RealmId,
    realm_name: String,
    /// Warm access tokens whose hashes are resident in the claims cache.
    warm_tokens: Vec<String>,
    /// `warm_tokens[i]`'s subject, so the engine counterpart of `GET /userinfo`
    /// can do `validate_token` + `get_user` without re-parsing the subject —
    /// the handler resolves it from the claims, which is not a measurable cost.
    warm_token_users: Vec<UserId>,
    /// Emails of the Argon2id-credentialed login users.
    login_emails: Vec<String>,
    /// Argon2id parameters actually in force for `verify_password` / `login`.
    argon2: (u32, u32, u32),
    data_dir: PathBuf,
    _tmp: tempfile::TempDir,
}

impl Fixture {
    fn build() -> Result<Self, Box<dyn std::error::Error>> {
        let tmp = tempfile::tempdir()?;
        let data_dir = tmp.path().to_path_buf();
        let mut config = StorageConfig::production(
            data_dir.clone(),
            2 * 1024 * 1024 * 1024, // 2 GiB WAL ceiling — the login op churns sessions.
            8 * 1024 * 1024,        // 8 MiB memtable flush.
            HOT_CAPACITY,
        );
        config.dev_mode = true; // only auto-generates the host key for the temp dir

        let storage_engine = Arc::new(EmbeddedStorageEngine::open(config)?);
        let storage = Arc::clone(&storage_engine) as Arc<dyn StorageEngine>;
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

        // PRODUCTION credential parameters — deliberately *not*
        // `CredentialConfig::fast_for_testing()` (which C7 uses, because C7
        // never touches a KDF). The whole point of the `login` row is to publish
        // a password-login number with its real Argon2id cost disclosed.
        let credential = CredentialConfig::default();
        let argon2 = (
            credential.memory_cost_kib,
            credential.time_cost,
            credential.parallelism,
        );
        println!(
            "Argon2id (production defaults): m = {} KiB, t = {}, p = {}",
            argon2.0, argon2.1, argon2.2
        );

        let engine = Arc::new(EmbeddedIdentityEngine::with_rbac(
            storage,
            clock,
            IdentityConfig {
                credential,
                ..IdentityConfig::default()
            },
            Arc::clone(&rbac),
            Arc::clone(&audit),
        )?);

        let realm_name = format!("c11-http-{}", uuid::Uuid::new_v4().simple());
        let realm = engine
            .create_realm(&CreateRealmRequest {
                name: realm_name.clone(),
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
                    email: format!("u{i}-{}@c11.test", uuid::Uuid::new_v4().simple()),
                    display_name: format!("user {i}"),
                    first_name: String::new(),
                    last_name: String::new(),
                    attributes: Default::default(),
                },
            )?;
            users.push(user.id().clone());
        }

        let ctx = SessionContext::default();
        println!("creating {SESSIONS} warm sessions + minting access tokens …");
        let mut warm_tokens = Vec::with_capacity(SESSIONS);
        let mut warm_token_users = Vec::with_capacity(SESSIONS);
        for i in 0..SESSIONS {
            let uid = &users[i % USERS];
            let session = engine.create_session(&realm, uid, &ctx)?;
            let pair = engine.issue_tokens(&realm, uid, session.id())?;
            warm_tokens.push(pair.access_token().to_string());
            warm_token_users.push(uid.clone());
        }

        println!(
            "provisioning {LOGIN_USERS} Argon2id password credentials \
             (m={} KiB — this is slow by design) …",
            argon2.0
        );
        let mut login_emails = Vec::with_capacity(LOGIN_USERS);
        for i in 0..LOGIN_USERS {
            let email = format!("login{i}-{}@c11.test", uuid::Uuid::new_v4().simple());
            let user = engine.create_user(
                &realm,
                &CreateUserRequest {
                    email: email.clone(),
                    display_name: format!("login user {i}"),
                    first_name: String::new(),
                    last_name: String::new(),
                    attributes: Default::default(),
                },
            )?;
            engine.set_password(
                &realm,
                user.id(),
                &CleartextPassword::from_string(LOGIN_PASSWORD.to_string()),
            )?;
            login_emails.push(email);
        }

        let fixture = Self {
            engine,
            rbac: rbac_handle,
            audit,
            realm,
            realm_name,
            warm_tokens,
            warm_token_users,
            login_emails,
            argon2,
            data_dir,
            _tmp: tmp,
        };
        fixture.warm(&users);
        Ok(fixture)
    }

    /// Warms the hot tier and saturates the token-claims cache so the
    /// `introspect` / `userinfo` rows measure the *hot* path — the same state
    /// C7 measured its `validate_token` hot number in.
    fn warm(&self, users: &[UserId]) {
        println!("warming hot tier + saturating the claims cache …");
        for _ in 0..8 {
            for u in users {
                let _ = self.engine.get_user(&self.realm, u);
            }
        }
        for t in &self.warm_tokens {
            let _ = self.engine.validate_token(&self.realm, t);
        }
    }

    // ── phase 2: engine-direct ────────────────────────────────────────────────

    fn measure_engine(&self) -> Vec<OpResult> {
        let mut out = Vec::new();

        out.push(self.sweep_engine("introspect_token", LADDER, |tid, n| {
            let tok = &self.warm_tokens[(tid * 7919 + n as usize) % self.warm_tokens.len()];
            let req = TokenIntrospectionRequest {
                token: tok.clone(),
                token_type_hint: None,
                introspecting_client_id: None,
            };
            self.engine.introspect_token(&self.realm, &req).is_ok()
        }));

        out.push(
            self.sweep_engine("validate_token+get_user", LADDER, |tid, n| {
                let i = (tid * 7919 + n as usize) % self.warm_tokens.len();
                match self
                    .engine
                    .validate_token(&self.realm, &self.warm_tokens[i])
                {
                    Ok(_) => self
                        .engine
                        .get_user(&self.realm, &self.warm_token_users[i])
                        .is_ok_and(|u| u.is_some()),
                    Err(_) => false,
                }
            }),
        );

        out.push(
            self.sweep_engine("verify_password+create_session", LOGIN_LADDER, |tid, n| {
                let email = &self.login_emails[(tid + n as usize) % self.login_emails.len()];
                let Ok(Some(user)) = self.engine.get_user_by_email(&self.realm, email) else {
                    return false;
                };
                let secret = CleartextPassword::from_string(LOGIN_PASSWORD.to_string());
                if self
                    .engine
                    .verify_password(&self.realm, user.id(), &secret)
                    .is_err()
                {
                    return false;
                }
                self.engine
                    .create_session(&self.realm, user.id(), &SessionContext::default())
                    .is_ok()
            }),
        );

        out
    }

    fn sweep_engine<F>(&self, op: &str, ladder: &[usize], body: F) -> OpResult
    where
        F: Fn(usize, u64) -> bool + Sync,
    {
        let mut cells = Vec::new();
        for &t in ladder {
            let c = measure_engine_cell(t, &body);
            println!(
                "  {op:<30} T={t:<3}  {:>12.0} ops/s   p50 {:>8.1} µs   p99 {:>9.1} µs   ok {:.1}%",
                c.ops_s,
                c.p50_us,
                c.p99_us,
                c.ok_pct()
            );
            cells.push(c);
        }
        OpResult {
            op: op.to_string(),
            cells,
        }
    }

    // ── phase 3: end-to-end HTTP ──────────────────────────────────────────────

    /// Boots the **real** axum routers on real loopback TCP listeners.
    ///
    /// The API router (`protocol::http::router`) and the web router
    /// (`protocol::web::router`) are served on **separate** listeners rather
    /// than merged, so a route-path collision between the two cannot silently
    /// change what is under test.
    fn spawn_servers(&self) -> Result<Servers, Box<dyn std::error::Error>> {
        // Abuse controls OFF for the measurement, and this is a disclosure, not
        // a footnote. The shipped defaults are `security.request_shaper.ip_rps
        // = 100` and `realm_rps = 1000` (`ShaperConfig::default`). Every request
        // this generator makes originates from 127.0.0.1, so with the shaper on,
        // the harness measures the 429 rejection path at 100 rps and nothing
        // else — the first run of this harness did exactly that, and the
        // admissibility gate caught it (`ok 0.1%`, `429 x 580882`).
        //
        // Those limits bound what ONE client IP may draw, not what the server
        // can serve; a real deployment fields many source IPs. Measuring server
        // capacity therefore requires them off. Any published throughput number
        // from this harness MUST carry the note that a single source IP is
        // capped at 100 rps by default.
        let app_state = Arc::new(
            AppState::new_dev(
                Arc::clone(&self.engine) as Arc<dyn IdentityEngine>,
                Arc::clone(&self.rbac),
                Arc::clone(&self.audit),
            )
            .with_request_shaper(Arc::new(hearth::abuse::shaper::RequestShaper::disabled()))
            .with_rate_limiters_disabled(true),
        );
        let api_router = hearth::protocol::http::router(app_state);

        let email = Arc::new(EmailService::new(
            Arc::new(LoggingEmailSender::new()),
            "Hearth".to_string(),
            None,
            EmailBranding::default(),
            String::new(),
            None,
        )?);
        let onboarding = Arc::new(OnboardingService::new(
            Arc::clone(&self.engine) as Arc<dyn IdentityEngine>,
            Arc::clone(&self.rbac),
            email,
            self.data_dir.clone(),
        ));
        let web_state = WebState::new(
            Arc::clone(&self.engine) as Arc<dyn IdentityEngine>,
            Arc::clone(&self.rbac),
            Arc::clone(&self.audit),
            onboarding,
            CookieSecret::from_bytes([9u8; 32]),
            None,
        )
        // Allows the generator to POST the login form without first doing a GET
        // to pick up the CSRF cookie. This changes only the *pre-auth CSRF
        // cookie* check; the Argon2id verify and the durable session create —
        // the two things being measured — are untouched.
        .with_dev_mode(true);
        let web_router = hearth::protocol::web::router(web_state);

        let api_listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let web_listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let api_addr = api_listener.local_addr()?;
        let web_addr = web_listener.local_addr()?;
        api_listener.set_nonblocking(true)?;
        web_listener.set_nonblocking(true)?;

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(SERVER_WORKERS)
            .enable_all()
            .build()?;
        rt.spawn(async move {
            let l = tokio::net::TcpListener::from_std(api_listener).expect("api listener");
            let _ = axum::serve(l, api_router).await;
        });
        rt.spawn(async move {
            let l = tokio::net::TcpListener::from_std(web_listener).expect("web listener");
            let _ = axum::serve(l, web_router).await;
        });

        // Block until both listeners answer, so no measurement window includes
        // server start-up.
        for addr in [api_addr, web_addr] {
            let deadline = Instant::now() + Duration::from_secs(10);
            while TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_err() {
                assert!(Instant::now() < deadline, "server at {addr} never came up");
            }
        }
        println!("  api  listening on {api_addr}\n  web  listening on {web_addr}");

        Ok(Servers {
            api_addr,
            web_addr,
            _rt: rt,
        })
    }

    fn measure_http(&self, s: &Servers) -> Vec<OpResult> {
        let mut out = Vec::new();

        out.push(self.sweep_http("healthz", s.api_addr, LADDER, |_t| {
            (0..1)
                .map(|_| {
                    format!("GET /healthz HTTP/1.1\r\nHost: h\r\nConnection: keep-alive\r\n\r\n")
                        .into_bytes()
                })
                .collect()
        }));

        out.push(self.sweep_http("introspect", s.api_addr, LADDER, |_t| {
            self.warm_tokens
                .iter()
                .take(256)
                .map(|tok| {
                    let body = format!("{{\"token\":\"{tok}\"}}");
                    format!(
                        "POST /realms/{}/introspect HTTP/1.1\r\nHost: h\r\n\
                         Content-Type: application/json\r\nContent-Length: {}\r\n\
                         Connection: keep-alive\r\n\r\n{body}",
                        self.realm_name,
                        body.len()
                    )
                    .into_bytes()
                })
                .collect()
        }));

        out.push(self.sweep_http("userinfo", s.api_addr, LADDER, |_t| {
            self.warm_tokens
                .iter()
                .take(256)
                .map(|tok| {
                    format!(
                        "GET /realms/{}/userinfo HTTP/1.1\r\nHost: h\r\n\
                         Authorization: Bearer {tok}\r\nConnection: keep-alive\r\n\r\n",
                        self.realm_name
                    )
                    .into_bytes()
                })
                .collect()
        }));

        out.push(self.sweep_http("login", s.web_addr, LOGIN_LADDER, |t| {
            (0..LOGIN_USERS.max(t))
                .map(|i| {
                    let email = &self.login_emails[i % self.login_emails.len()];
                    let body = format!(
                        "email={}&password={}",
                        urlencode(email),
                        urlencode(LOGIN_PASSWORD)
                    );
                    format!(
                        "POST /ui/realms/{}/login HTTP/1.1\r\nHost: h\r\n\
                         Content-Type: application/x-www-form-urlencoded\r\n\
                         Content-Length: {}\r\nConnection: keep-alive\r\n\r\n{body}",
                        self.realm_name,
                        body.len()
                    )
                    .into_bytes()
                })
                .collect()
        }));

        out
    }

    fn sweep_http<F>(&self, op: &str, addr: SocketAddr, ladder: &[usize], build: F) -> OpResult
    where
        F: Fn(usize) -> Vec<Vec<u8>>,
    {
        let mut cells = Vec::new();
        for &t in ladder {
            let reqs = build(t);
            let c = drive_http(op, addr, t, &reqs);
            println!(
                "  {op:<30} T={t:<3}  {:>12.0} ops/s   p50 {:>8.1} µs   p99 {:>9.1} µs   ok {:.1}%  statuses {}",
                c.ops_s,
                c.p50_us,
                c.p99_us,
                c.ok_pct(),
                c.status_summary()
            );
            cells.push(c);
        }
        OpResult {
            op: op.to_string(),
            cells,
        }
    }

    /// Trivial `GET /` requests aimed at the calibration server.
    fn null_requests(&self, _t: usize) -> Vec<Vec<u8>> {
        vec![b"GET / HTTP/1.1\r\nHost: h\r\nConnection: keep-alive\r\n\r\n".to_vec()]
    }
}

/// Handles for the running axum servers. Dropping this stops the runtime.
struct Servers {
    api_addr: SocketAddr,
    web_addr: SocketAddr,
    _rt: tokio::runtime::Runtime,
}

// ── Measurement primitives ────────────────────────────────────────────────────

/// One (op, concurrency) measurement.
struct Cell {
    threads: usize,
    ops_s: f64,
    p50_us: f64,
    p99_us: f64,
    ok: u64,
    total: u64,
    /// `status -> count`, sorted by status. Empty for engine cells.
    statuses: Vec<(u16, u64)>,
}

impl Cell {
    fn ok_pct(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            100.0 * self.ok as f64 / self.total as f64
        }
    }

    fn status_summary(&self) -> String {
        self.statuses
            .iter()
            .map(|(s, n)| format!("{s}×{n}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Every concurrency rung for a single operation.
struct OpResult {
    op: String,
    cells: Vec<Cell>,
}

impl OpResult {
    fn cell(&self, threads: usize) -> Option<&Cell> {
        self.cells.iter().find(|c| c.threads == threads)
    }
}

/// Runs `body` on `threads` OS threads for [`MEASURE`], after a [`WARMUP`]
/// window whose samples are discarded.
fn measure_engine_cell<F>(threads: usize, body: &F) -> Cell
where
    F: Fn(usize, u64) -> bool + Sync,
{
    let barrier = Arc::new(Barrier::new(threads + 1));
    let stop = Arc::new(AtomicBool::new(false));

    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(threads);
        for tid in 0..threads {
            let barrier = Arc::clone(&barrier);
            let stop = Arc::clone(&stop);
            handles.push(scope.spawn(move || {
                let mut lat = Vec::with_capacity(1 << 16);
                let mut ok: u64 = 0;
                let mut n: u64 = 0;

                let warm_end = Instant::now() + WARMUP;
                while Instant::now() < warm_end {
                    let _ = body(tid, n);
                    n += 1;
                }

                barrier.wait(); // all threads warm → open the timed window
                while !stop.load(Ordering::Relaxed) {
                    let t0 = Instant::now();
                    let good = body(tid, n);
                    lat.push(t0.elapsed().as_nanos() as u64);
                    ok += u64::from(good);
                    n += 1;
                }
                (lat, ok)
            }));
        }

        barrier.wait();
        let t0 = Instant::now();
        thread::sleep(MEASURE);
        stop.store(true, Ordering::Relaxed);
        let elapsed = t0.elapsed();

        let mut lat = Vec::new();
        let mut ok = 0u64;
        for h in handles {
            let (l, o) = h.join().expect("engine measurement thread panicked");
            lat.extend(l);
            ok += o;
        }
        let mut cell = finish_cell(threads, lat, Vec::new(), elapsed, |_| true);
        cell.ok = ok;
        cell
    })
}

/// Drives `threads` closed-loop HTTP clients against `addr`, cycling through
/// `requests`. One persistent connection per thread, `TCP_NODELAY` set.
fn drive_http(_op: &str, addr: SocketAddr, threads: usize, requests: &[Vec<u8>]) -> Cell {
    let barrier = Arc::new(Barrier::new(threads + 1));
    let stop = Arc::new(AtomicBool::new(false));

    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(threads);
        for tid in 0..threads {
            let barrier = Arc::clone(&barrier);
            let stop = Arc::clone(&stop);
            handles.push(scope.spawn(move || {
                let mut conn = HttpConn::connect(addr).expect("connect to server under test");
                let mut lat = Vec::with_capacity(1 << 16);
                let mut statuses: Vec<(u16, u64)> = Vec::new();
                let mut n: u64 = 0;

                // Warm-up: same work, samples discarded.
                let warm_end = Instant::now() + WARMUP;
                while Instant::now() < warm_end {
                    let req = &requests[(tid + n as usize) % requests.len()];
                    let _ = conn.round_trip(req);
                    n += 1;
                }

                barrier.wait(); // all threads warm → open the timed window
                while !stop.load(Ordering::Relaxed) {
                    let req = &requests[(tid + n as usize) % requests.len()];
                    let t0 = Instant::now();
                    let status = conn.round_trip(req).unwrap_or(0);
                    lat.push(t0.elapsed().as_nanos() as u64);
                    match statuses.iter_mut().find(|(s, _)| *s == status) {
                        Some(e) => e.1 += 1,
                        None => statuses.push((status, 1)),
                    }
                    n += 1;
                }
                (lat, statuses)
            }));
        }

        barrier.wait();
        let t0 = Instant::now();
        thread::sleep(MEASURE);
        stop.store(true, Ordering::Relaxed);
        let elapsed = t0.elapsed();

        let mut lat = Vec::new();
        let mut statuses: Vec<(u16, u64)> = Vec::new();
        for h in handles {
            let (l, s) = h.join().expect("generator thread panicked");
            lat.extend(l);
            for (code, count) in s {
                match statuses.iter_mut().find(|(c, _)| *c == code) {
                    Some(e) => e.1 += count,
                    None => statuses.push((code, count)),
                }
            }
        }
        statuses.sort_unstable();
        finish_cell(threads, lat, statuses, elapsed, |s| (200..400).contains(&s))
    })
}

/// Builds a [`Cell`] from raw latency samples and a status histogram.
fn finish_cell<P: Fn(u16) -> bool>(
    threads: usize,
    mut lat: Vec<u64>,
    statuses: Vec<(u16, u64)>,
    elapsed: Duration,
    is_ok: P,
) -> Cell {
    let total: u64 = lat.len() as u64;
    let ok: u64 = statuses
        .iter()
        .filter(|(s, _)| is_ok(*s))
        .map(|(_, n)| *n)
        .sum();
    lat.sort_unstable();
    let pct = |p: f64| -> f64 {
        if lat.is_empty() {
            return 0.0;
        }
        let idx = ((lat.len() as f64 - 1.0) * p).round() as usize;
        lat[idx] as f64 / 1_000.0
    };
    Cell {
        threads,
        ops_s: total as f64 / elapsed.as_secs_f64(),
        p50_us: pct(0.50),
        p99_us: pct(0.99),
        ok: if statuses.is_empty() { total } else { ok },
        total,
        statuses,
    }
}

/// A persistent, closed-loop HTTP/1.1 connection.
///
/// Deliberately minimal: no request building at measurement time (the byte
/// buffers are pre-rendered), no header map, no allocation per round trip. The
/// only parsing is the status line and `Content-Length`, which is all that is
/// needed to know when a response has been fully consumed.
struct HttpConn {
    stream: TcpStream,
    buf: Vec<u8>,
}

impl HttpConn {
    fn connect(addr: SocketAddr) -> std::io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        Ok(Self {
            stream,
            buf: vec![0u8; 1 << 16],
        })
    }

    /// Writes `req` and consumes exactly one response. Returns the status code.
    fn round_trip(&mut self, req: &[u8]) -> std::io::Result<u16> {
        self.stream.write_all(req)?;

        let mut filled = 0usize;
        let mut header_end = None;
        // Read until the header terminator is in the buffer.
        while header_end.is_none() {
            let n = self.stream.read(&mut self.buf[filled..])?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "server closed the connection mid-response",
                ));
            }
            filled += n;
            header_end = find_header_end(&self.buf[..filled]);
        }
        let hend = header_end.expect("loop exits only once the terminator is found");
        let head = &self.buf[..hend];
        let status = parse_status(head);
        let want = hend + content_length(head);

        while filled < want {
            let n = self.stream.read(&mut self.buf[filled..])?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "server closed the connection before the body was complete",
                ));
            }
            filled += n;
        }
        Ok(status)
    }
}

/// Index just past the `\r\n\r\n` that ends the response head, if present.
fn find_header_end(b: &[u8]) -> Option<usize> {
    b.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// Parses the status code out of `HTTP/1.1 NNN ...`.
fn parse_status(head: &[u8]) -> u16 {
    head.split(|&c| c == b' ')
        .nth(1)
        .and_then(|s| std::str::from_utf8(s).ok())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// Parses `Content-Length` from a response head. Absent header ⇒ 0.
fn content_length(head: &[u8]) -> usize {
    let text = String::from_utf8_lossy(head).to_ascii_lowercase();
    for line in text.split("\r\n") {
        if let Some(v) = line.strip_prefix("content-length:") {
            return v.trim().parse().unwrap_or(0);
        }
    }
    0
}

/// Minimal `application/x-www-form-urlencoded` escaping for the login body.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Spawns a bare TCP server that answers every request with a fixed `200 OK`.
///
/// This is the generator's calibration target: whatever throughput the driver
/// reaches against it is the most this driver can produce on this host, so it
/// bounds how much of any Hearth number is really the generator.
fn spawn_null_server() -> std::io::Result<SocketAddr> {
    const CANNED: &[u8] =
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n\
          {\"status\":\"ok\"}";
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let _ = s.set_nodelay(true);
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(_) => {
                            if s.write_all(CANNED).is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    Ok(addr)
}

// ── Reporting ─────────────────────────────────────────────────────────────────

/// Engine op ↔ HTTP op pairing. The left column is what `measure_engine`
/// labels its rows; the right is what `measure_http` labels its rows.
const PAIRS: &[(&str, &str)] = &[
    ("introspect_token", "introspect"),
    ("validate_token+get_user", "userinfo"),
    ("verify_password+create_session", "login"),
];

/// A run is only gradable where the generator was demonstrably not the ceiling.
/// 2× headroom against the measured `null` ceiling is the bar.
const MIN_GENERATOR_HEADROOM: f64 = 2.0;

fn print_report(f: &Fixture, null_cal: &[Cell], engine: &[OpResult], http: &[OpResult]) {
    let find =
        |set: &[OpResult], name: &str| -> Option<usize> { set.iter().position(|o| o.op == name) };

    println!("\n════════ HTTP DELTA ════════\n");
    println!(
        "Argon2id in force: m = {} KiB, t = {}, p = {}   (production defaults, not fast_for_testing)",
        f.argon2.0, f.argon2.1, f.argon2.2
    );

    if let Some(hz) = find(http, "healthz").and_then(|i| http[i].cell(1)) {
        println!(
            "\nHTTP envelope floor (GET /healthz, no engine work): {:.0} ops/s 1T, p50 {:.1} µs\n\
             → every engine-backed row below pays ≈ {:.1} µs of axum/tokio/TCP before its engine call starts.",
            hz.ops_s, hz.p50_us, hz.p50_us
        );
    }

    println!(
        "\n{:<32} {:>4} {:>13} {:>13} {:>8} {:>10} {:>10} {:>9} verdict",
        "operation",
        "T",
        "engine ops/s",
        "http ops/s",
        "ratio",
        "eng p50µs",
        "http p50µs",
        "headroom"
    );
    println!("{}", "─".repeat(122));

    for (eng_name, http_name) in PAIRS {
        let (Some(ei), Some(hi)) = (find(engine, eng_name), find(http, http_name)) else {
            continue;
        };
        for hc in &http[hi].cells {
            let Some(ec) = engine[ei].cell(hc.threads) else {
                continue;
            };
            let null_ops = null_cal
                .iter()
                .find(|c| c.threads == hc.threads)
                .map_or(f64::NAN, |c| c.ops_s);
            let headroom = null_ops / hc.ops_s;
            let ratio = ec.ops_s / hc.ops_s;
            let verdict = grade(hc, headroom);
            println!(
                "{:<32} {:>4} {:>13.0} {:>13.0} {:>7.1}× {:>10.2} {:>10.2} {:>8.1}× {verdict}",
                format!("{eng_name} → /{http_name}"),
                hc.threads,
                ec.ops_s,
                hc.ops_s,
                ratio,
                ec.p50_us,
                hc.p50_us,
                headroom
            );
        }
    }

    println!("\nGenerator calibration (null TCP server — the driver's own ceiling):");
    for c in null_cal {
        println!(
            "  T={:<3} {:>12.0} ops/s   p50 {:>7.2} µs",
            c.threads, c.ops_s, c.p50_us
        );
    }
    println!(
        "\nA row is ADMISSIBLE only when generator headroom ≥ {MIN_GENERATOR_HEADROOM:.1}× and \
         success ≥ 99%%.\nExcluded from every number above: TLS, physical network, \
         client/server core isolation.\nThe HTTP figures are therefore an UPPER bound and the \
         ratios a LOWER bound."
    );
}

/// Grades one HTTP cell against the two admissibility gates.
fn grade(c: &Cell, headroom: f64) -> &'static str {
    if c.ok_pct() < 99.0 {
        "INADMISSIBLE (errors)"
    } else if headroom < MIN_GENERATOR_HEADROOM {
        "INADMISSIBLE (generator-bound)"
    } else {
        "ADMISSIBLE"
    }
}

// ── Run-to-run spread (HEA-1974 AC3) ──────────────────────────────────────────

/// Min / median / max of one metric across samples, plus the relative spread.
struct Spread {
    min: f64,
    median: f64,
    max: f64,
    /// `(max - min) / min`, in percent. L5 was withdrawn at 236%.
    pct: f64,
}

impl Spread {
    fn of(mut v: Vec<f64>) -> Self {
        v.sort_by(f64::total_cmp);
        let (min, max) = (
            v.first().copied().unwrap_or(f64::NAN),
            v.last().copied().unwrap_or(f64::NAN),
        );
        Self {
            min,
            median: v.get(v.len() / 2).copied().unwrap_or(f64::NAN),
            max,
            pct: if min > 0.0 {
                100.0 * (max - min) / min
            } else {
                f64::NAN
            },
        }
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "min": self.min, "median": self.median, "max": self.max,
            "spread_pct": self.pct,
        })
    }
}

/// Every `(plane, op, threads)` coordinate present in the first sample.
fn coordinates(samples: &[Sample]) -> Vec<(&'static str, String, usize)> {
    let mut out = Vec::new();
    let Some(first) = samples.first() else {
        return out;
    };
    for c in &first.null {
        out.push(("null", "null".to_string(), c.threads));
    }
    for (plane, set) in [("engine", &first.engine), ("http", &first.http)] {
        for op in set {
            for c in &op.cells {
                out.push((plane, op.op.clone(), c.threads));
            }
        }
    }
    out
}

/// Pulls one cell's metrics from every sample at a given coordinate.
fn series(samples: &[Sample], plane: &str, op: &str, threads: usize) -> (Vec<f64>, Vec<f64>) {
    let mut ops = Vec::new();
    let mut p50 = Vec::new();
    for s in samples {
        let cell = match plane {
            "null" => s.null.iter().find(|c| c.threads == threads),
            "engine" => s
                .engine
                .iter()
                .find(|o| o.op == op)
                .and_then(|o| o.cell(threads)),
            _ => s
                .http
                .iter()
                .find(|o| o.op == op)
                .and_then(|o| o.cell(threads)),
        };
        if let Some(c) = cell {
            ops.push(c.ops_s);
            p50.push(c.p50_us);
        }
    }
    (ops, p50)
}

/// Prints the run-to-run spread table. A figure without a spread is not
/// publishable, so this table — not the single-sample report above it — is what
/// any published number must be sourced from.
fn print_spread(samples: &[Sample]) {
    println!(
        "\n── run-to-run spread across {} samples ──\n",
        samples.len()
    );
    println!(
        "  {:<7} {:<22} {:>4}  {:>12} {:>12} {:>8}   {:>9} {:>8}",
        "plane", "op", "T", "ops/s min", "ops/s max", "spread", "p50 med", "spread"
    );
    for (plane, op, threads) in coordinates(samples) {
        let (ops, p50) = series(samples, plane, &op, threads);
        if ops.len() < 2 {
            continue;
        }
        let (so, sp) = (Spread::of(ops), Spread::of(p50));
        let flag = if so.pct > 25.0 { " ⚠" } else { "" };
        println!(
            "  {:<7} {:<22} {:>4}  {:>12.0} {:>12.0} {:>7.1}%   {:>8.1}µ {:>7.1}%{}",
            plane, op, threads, so.min, so.max, so.pct, sp.median, sp.pct, flag
        );
    }
    println!("\n  ⚠ marks >25% throughput spread — treat as not publishable without explanation.");
}

fn emit_json(
    f: &Fixture,
    args: &Args,
    samples: &[Sample],
    host: &hostenv::HostProfile,
    pre: (&hostenv::LoadSnapshot, &hostenv::ProcessCensus),
    post: (&hostenv::LoadSnapshot, &hostenv::ProcessCensus),
    verdict: &hostenv::Verdict,
) -> Result<(), Box<dyn std::error::Error>> {
    let cell_json = |c: &Cell| {
        serde_json::json!({
            "threads": c.threads,
            "ops_per_sec": c.ops_s,
            "p50_us": c.p50_us,
            "p99_us": c.p99_us,
            "samples": c.total,
            "ok": c.ok,
            "ok_pct": c.ok_pct(),
            "statuses": c.statuses.iter()
                .map(|(s, n)| serde_json::json!({"status": s, "count": n}))
                .collect::<Vec<_>>(),
        })
    };
    let ops_json = |set: &[OpResult]| {
        set.iter()
            .map(|o| {
                serde_json::json!({
                    "op": o.op,
                    "cells": o.cells.iter().map(cell_json).collect::<Vec<_>>(),
                })
            })
            .collect::<Vec<_>>()
    };

    let deltas_for = |s: &Sample| {
        let mut deltas = Vec::new();
        for (eng_name, http_name) in PAIRS {
            let (Some(e), Some(h)) = (
                s.engine.iter().find(|o| o.op == *eng_name),
                s.http.iter().find(|o| o.op == *http_name),
            ) else {
                continue;
            };
            for hc in &h.cells {
                let Some(ec) = e.cell(hc.threads) else {
                    continue;
                };
                let null_ops = s
                    .null
                    .iter()
                    .find(|c| c.threads == hc.threads)
                    .map_or(f64::NAN, |c| c.ops_s);
                let headroom = null_ops / hc.ops_s;
                deltas.push(serde_json::json!({
                    "engine_op": eng_name,
                    "http_op": http_name,
                    "threads": hc.threads,
                    "engine_ops_per_sec": ec.ops_s,
                    "http_ops_per_sec": hc.ops_s,
                    "throughput_delta_ratio": ec.ops_s / hc.ops_s,
                    "engine_p50_us": ec.p50_us,
                    "http_p50_us": hc.p50_us,
                    "engine_p99_us": ec.p99_us,
                    "http_p99_us": hc.p99_us,
                    "added_latency_p50_us": hc.p50_us - ec.p50_us,
                    "generator_headroom": headroom,
                    "verdict": grade(hc, headroom),
                }));
            }
        }
        deltas
    };

    let sample_json: Vec<_> = samples
        .iter()
        .enumerate()
        .map(|(i, s)| {
            serde_json::json!({
                "sample": i + 1,
                "generator_calibration_null": s.null.iter().map(cell_json).collect::<Vec<_>>(),
                "engine": ops_json(&s.engine),
                "http": ops_json(&s.http),
                "deltas": deltas_for(s),
            })
        })
        .collect();

    // AC3: every coordinate carries its run-to-run spread. A single-sample
    // figure is not publishable, so this is the block a published number cites.
    let spread_json: Vec<_> = coordinates(samples)
        .into_iter()
        .filter_map(|(plane, op, threads)| {
            let (ops, p50) = series(samples, plane, &op, threads);
            (ops.len() >= 2).then(|| {
                serde_json::json!({
                    "plane": plane,
                    "op": op,
                    "threads": threads,
                    "n_samples": ops.len(),
                    "ops_per_sec": Spread::of(ops).to_json(),
                    "p50_us": Spread::of(p50).to_json(),
                })
            })
        })
        .collect();

    let doc = serde_json::json!({
        "issue": "HEA-1974",
        "supersedes": "HEA-1957 / HEA-1967 single-sample runs",
        "axis": "C11 — end-to-end HTTP delta",
        "harness": "examples/http_delta.rs",
        "samples_requested": args.samples,
        "samples_collected": samples.len(),

        // Provenance first: whether these numbers may be cited at all.
        "publishable": verdict.publishable,
        "quiescence": {
            "verdict": verdict.to_json(),
            "host": host.to_json(),
            "pre_run": {
                "load": pre.0.to_json(host.cpus),
                "process_census": pre.1.to_json(),
            },
            "post_run": {
                "load": post.0.to_json(host.cpus),
                "process_census": post.1.to_json(),
            },
            "allow_contended_host_override": args.allow_contended,
        },
        // AC4: state co-residency explicitly rather than leaving it to be
        // inferred from the module docs.
        "load_generator_co_resident_with_server": true,
        "co_residency_note":
            "The request generator and the server under test run as threads of THIS process on \
             THIS host and share the same cores. The null-server calibration bounds the error \
             this introduces but does not remove it. Co-residency is the leading suspect for the \
             HEA-1967 HTTP-plane collapse: the HTTP phase is the only one that must sustain a \
             generator and a server simultaneously, so it degrades first and worst under \
             foreign load.",
        "measure_window_secs": MEASURE.as_secs(),
        "warmup_ms": WARMUP.as_millis(),
        "server_tokio_worker_threads": SERVER_WORKERS,
        "physical_cores_visible": std::thread::available_parallelism().map(std::num::NonZeroUsize::get).unwrap_or(0),
        "corpus": {"users": USERS, "warm_sessions": SESSIONS, "login_users": LOGIN_USERS},
        "argon2id": {
            "memory_cost_kib": f.argon2.0,
            "time_cost": f.argon2.1,
            "parallelism": f.argon2.2,
            "note": "production CredentialConfig::default(), NOT fast_for_testing()"
        },
        "excluded_from_measurement": [
            "TLS termination",
            "physical network / NIC / RTT (loopback only)",
            "client-server core isolation (co-resident, bounded by the null calibration)"
        ],
        "admissibility": {
            "min_generator_headroom": MIN_GENERATOR_HEADROOM,
            "min_ok_pct": 99.0,
            "rule": "nothing graded on a run whose ceiling attribution was the generator"
        },
        "samples": sample_json,
        "spread": spread_json,
    });

    let path = args.out.clone();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut file = std::fs::File::create(&path)?;
    file.write_all(serde_json::to_string_pretty(&doc)?.as_bytes())?;
    file.write_all(b"\n")?;
    println!("\nraw artifact → {}", path.display());
    Ok(())
}
