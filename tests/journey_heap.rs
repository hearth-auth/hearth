//! The heap does not grow with the journeys the server serves (#445).
//!
//! A 12-hour soak on AWS cannot see a leak smaller than about 2 MiB an hour,
//! because the resident memory moves by about 20 MiB from hour to hour. At
//! 120 journeys a second, 2 MiB an hour is about 5 bytes a journey. This test
//! counts every allocation of the process instead, so it sees much less.
//!
//! The test sends the soak's journey mix through the HTTP router in-process:
//! refresh 65, sign-in 15 (hosted login form, authorization code, PKCE),
//! userinfo 15, admin lookup 5. Each client signs in again after 20 refreshes,
//! as the soak does, or when its access token is near its expiry (here, once
//! a round). After each round, a fake clock moves past every token,
//! session and marker lifetime, and the test runs the work the server runs in
//! the background: the cleanup sweep, a memtable flush and, every fourth
//! round, a compaction. The sweep thus walks the round's rows and deletes
//! them while they are still in the memtable, as it does in the server. The
//! caches are small, so they are full after the warm-up. From then on, the
//! live heap must stay level: [`MAX_BYTES_PER_JOURNEY`].
//!
//! With the `SkipMap::range` leak of #445 put back (before #498), the heap
//! grew 307 bytes a journey here.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, Response, StatusCode};
use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{Clock, FakeClock, RealmId, Timestamp, UserId};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::hibp::{HibpError, HibpTransport};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CleartextPassword, ClientTrustLevel, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, RealmConfig, RegisterClientRequest,
    SessionContext, UpdateUserRequest, UserStatus,
};
use hearth::protocol::http::{router_with, AppState};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{AssignRoleRequest, EmbeddedRbacEngine, RbacEngine, Scope, Subject, SvBumper};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use tower::ServiceExt as _;

// ── Live heap of the whole process ───────────────────────────────────────────

/// Live heap bytes allocated through [`LiveAllocator`].
static LIVE: AtomicIsize = AtomicIsize::new(0);

/// A `System`-backed allocator that tracks the live heap of every thread.
struct LiveAllocator;

// SAFETY: every method forwards to `System` with the same `Layout`; the only
// added work is relaxed atomic bookkeeping, which cannot affect the pointers.
unsafe impl GlobalAlloc for LiveAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarding unchanged to the system allocator.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            LIVE.fetch_add(layout.size().cast_signed(), Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarding unchanged to the system allocator.
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size().cast_signed(), Ordering::Relaxed);
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarding unchanged to the system allocator.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            LIVE.fetch_add(layout.size().cast_signed(), Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: forwarding unchanged to the system allocator.
        let new = unsafe { System.realloc(ptr, layout, new_size) };
        if !new.is_null() {
            LIVE.fetch_add(
                new_size.cast_signed() - layout.size().cast_signed(),
                Ordering::Relaxed,
            );
        }
        new
    }
}

#[global_allocator]
static ALLOCATOR: LiveAllocator = LiveAllocator;

// ── Workload ─────────────────────────────────────────────────────────────────

/// Journeys in one round.
const ROUND_JOURNEYS: usize = 500;
/// Rounds in all.
const ROUNDS: usize = 72;
/// Rounds before the first measurement. The live heap rises for about 20
/// rounds while the caches and maps fill to their size limits; from then on
/// it is level in every run of the fixed code.
const WARM_UP: usize = 24;
/// Simulated seconds that pass after each round: more than the longest
/// lifetime below (120 s) plus the 60 s grace of a single-use marker, so each
/// round's rows expire before the next round. Inside a round the clock stands
/// still.
const ROUND_SECS: i64 = 200;
/// The largest growth of the live heap the test accepts, in bytes a journey:
/// about 1.2 MiB an hour at 120 journeys a second. The live heap moves by
/// about 22 KiB from round to round (caches, and replaced values that wait
/// for the next write to their cell), so one slope has a standard error of
/// about 0.5 bytes a journey. In 8 runs of the fixed code the slope was
/// between -0.4 and +1.1. A leak of 5 bytes a journey (2 MiB an hour at 120
/// journeys a second) is 4 standard errors above the bound.
const MAX_BYTES_PER_JOURNEY: f64 = 3.0;

/// Users that sign in.
const USERS: usize = 64;
/// Clients, each with its own refresh-token chain.
const CLIENTS: usize = 32;
/// Concurrent workers; each drives its own share of the clients.
const WORKERS: usize = 4;
/// Refreshes after which a client signs in again (the soak's CHAIN_REFRESHES).
const CHAIN_REFRESHES: u32 = 20;

/// Token and session lifetimes, short so that they expire in the test.
const ACCESS_TOKEN_SECS: i64 = 60;
const REFRESH_TOKEN_SECS: i64 = 120;
const SESSION_SECS: i64 = 120;
/// A client gets a new access token when this much of its life has passed.
const RENEW_AFTER_SECS: i64 = 45;

const REDIRECT: &str = "https://app.example.com/cb";
const REDIRECT_ENCODED: &str = "https%3A%2F%2Fapp.example.com%2Fcb";
const PKCE_VERIFIER: &str = "journey-heap-verifier-journey-heap-verifier";
const PASSWORD: &str = "journey-heap-pass-phrase";

/// HIBP stub: never "pwned", no network.
struct NotPwned;
impl HibpTransport for NotPwned {
    fn get_range(&self, _prefix: &str, _api_key: Option<&str>) -> Result<String, HibpError> {
        Ok(String::new())
    }
}

/// The server under test and what the journeys need.
struct Rig {
    app: axum::Router,
    clock: Arc<FakeClock>,
    storage: Arc<EmbeddedStorageEngine>,
    identity: Arc<dyn IdentityEngine>,
    realm_id: RealmId,
    realm_name: String,
    client_id: String,
    authorize_uri: String,
    emails: Vec<String>,
    user_ids: Vec<UserId>,
    admin_id: UserId,
    _dirs: (tempfile::TempDir, tempfile::TempDir),
}

/// A client's refresh-token chain.
struct Chain {
    access: String,
    refresh: String,
    refreshes: u32,
    issued_at: i64,
}

/// The realm admin's access token.
struct AdminToken {
    access: String,
    issued_at: i64,
}

fn now_secs(clock: &FakeClock) -> i64 {
    clock.now().as_micros() / 1_000_000
}

/// Builds the server: storage, engines, realm, client, users and router.
#[allow(clippy::too_many_lines)] // one linear setup, read top to bottom
fn rig() -> Rig {
    let storage_dir = tempfile::tempdir().expect("tempdir");
    let mut config = StorageConfig::dev(storage_dir.path().to_path_buf());
    // The test flushes and compacts after each round itself.
    config.compaction.enabled = false;
    config.set_memtable_flush_bytes(256 << 20);
    config.set_hot_tier_capacity(64);
    config.set_hot_tier_per_realm_metrics(false);
    config.block_cache_bytes = 256 << 10;
    let storage = Arc::new(EmbeddedStorageEngine::open(config).expect("storage"));

    let clock = Arc::new(FakeClock::new(Timestamp::now()));
    let dyn_clock = Arc::clone(&clock) as Arc<dyn Clock>;
    let dyn_storage = Arc::clone(&storage) as Arc<dyn StorageEngine>;
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&dyn_storage),
        Arc::clone(&dyn_clock),
    ));
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&dyn_storage),
        Arc::clone(&dyn_clock),
    ));
    let mut identity_config = IdentityConfig {
        credential: CredentialConfig::fast_for_testing(),
        ..IdentityConfig::default()
    };
    identity_config.session.ttl_micros = SESSION_SECS * 1_000_000;
    identity_config.token.access_token_ttl_secs = ACCESS_TOKEN_SECS;
    identity_config.token.refresh_token_ttl_secs = REFRESH_TOKEN_SECS;
    identity_config.token.claims_cache_max = 64;
    let identity = Arc::new(
        EmbeddedIdentityEngine::with_rbac(
            Arc::clone(&dyn_storage),
            Arc::clone(&dyn_clock),
            identity_config,
            Arc::clone(&rbac) as Arc<dyn RbacEngine>,
            Arc::clone(&audit) as Arc<dyn AuditEngine>,
        )
        .expect("identity engine")
        .with_hibp_transport(Arc::new(NotPwned)),
    );
    rbac.init_sv_bumper(Arc::clone(&identity) as Arc<dyn SvBumper>);
    let identity_dyn = Arc::clone(&identity) as Arc<dyn IdentityEngine>;
    let rbac_dyn = Arc::clone(&rbac) as Arc<dyn RbacEngine>;
    let audit_dyn = Arc::clone(&audit) as Arc<dyn AuditEngine>;

    let realm_name = format!("journey-heap-{}", uuid::Uuid::new_v4());
    let realm = identity_dyn
        .create_realm(&CreateRealmRequest {
            name: realm_name.clone(),
            config: Some(RealmConfig::default()),
        })
        .expect("realm");
    let realm_id = realm.id().clone();
    rbac_dyn.seed_realm(&realm_id).expect("seed realm roles");

    let client = identity_dyn
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "Journey heap app".to_string(),
                redirect_uris: vec![REDIRECT.to_string()],
                grant_types: vec![
                    "authorization_code".to_string(),
                    "refresh_token".to_string(),
                ],
                trust_level: ClientTrustLevel::FirstParty,
                ..Default::default()
            },
        )
        .expect("register client");
    let client_id = client.client_id().as_uuid().to_string();
    let challenge = data_encoding::BASE64URL_NOPAD
        .encode(ring::digest::digest(&ring::digest::SHA256, PKCE_VERIFIER.as_bytes()).as_ref());
    let authorize_uri = format!(
        "/ui/oauth/authorize?client_id={client_id}&redirect_uri={REDIRECT_ENCODED}\
         &response_type=code&scope=openid&state=journey&code_challenge={challenge}\
         &code_challenge_method=S256"
    );

    let mut emails = Vec::with_capacity(USERS);
    let mut user_ids = Vec::with_capacity(USERS);
    for i in 0..USERS {
        let email = format!("user-{i:03}@journey-heap.test");
        let user = active_user(identity_dyn.as_ref(), &realm_id, &email);
        emails.push(email);
        user_ids.push(user);
    }
    let admin_id = active_user(identity_dyn.as_ref(), &realm_id, "admin@journey-heap.test");
    let role = rbac_dyn
        .get_role_by_name(&realm_id, "realm.admin")
        .expect("role lookup")
        .expect("realm.admin seeded");
    rbac_dyn
        .assign_role(
            &realm_id,
            &AssignRoleRequest {
                subject: Subject::User(admin_id.clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign realm.admin");

    let web_dir = tempfile::tempdir().expect("tempdir");
    let email_service = Arc::new(
        EmailService::new(
            Arc::new(LoggingEmailSender::new()),
            "Hearth".to_string(),
            None,
            EmailBranding::default(),
            String::new(),
            None,
        )
        .expect("email service"),
    );
    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&identity_dyn),
        Arc::clone(&rbac_dyn),
        Arc::clone(&email_service),
        web_dir.path().to_path_buf(),
    ));
    let web_state = WebState::new(
        Arc::clone(&identity_dyn),
        Arc::clone(&rbac_dyn),
        Arc::clone(&audit_dyn),
        onboarding,
        CookieSecret::random(),
        Some(email_service),
    )
    .with_default_realm(Some(realm_name.clone()));
    // Every in-process request comes from the same peer; the per-IP limits
    // would refuse the load, as they would refuse one busy client.
    let app_state = AppState::new(
        Arc::clone(&identity_dyn),
        Arc::clone(&rbac_dyn),
        Arc::clone(&audit_dyn),
    )
    .with_rate_limiters_disabled(true)
    .with_request_shaper(Arc::new(hearth::abuse::shaper::RequestShaper::disabled()));
    let app = router_with(Arc::new(app_state), web::router(web_state));

    Rig {
        app,
        clock,
        storage,
        identity: identity_dyn,
        realm_id,
        realm_name,
        client_id,
        authorize_uri,
        emails,
        user_ids,
        admin_id,
        _dirs: (storage_dir, web_dir),
    }
}

fn active_user(identity: &dyn IdentityEngine, realm_id: &RealmId, email: &str) -> UserId {
    let user = identity
        .create_user(
            realm_id,
            &CreateUserRequest {
                email: email.to_string(),
                display_name: "Journey".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    identity
        .set_password(
            realm_id,
            user.id(),
            &CleartextPassword::from_string(PASSWORD.to_string()),
        )
        .expect("set password");
    identity
        .update_user(
            realm_id,
            user.id(),
            &UpdateUserRequest {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .expect("activate user");
    user.id().clone()
}

// ── HTTP helpers ─────────────────────────────────────────────────────────────

async fn send(rig: &Rig, request: Request<Body>) -> Response<Body> {
    rig.app.clone().oneshot(request).await.expect("router")
}

fn get(uri: &str, cookies: &str) -> Request<Body> {
    let mut request = Request::builder().uri(uri);
    if !cookies.is_empty() {
        request = request.header(header::COOKIE, cookies);
    }
    request.body(Body::empty()).expect("build GET")
}

fn post_form(uri: &str, cookies: &str, body: String) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if !cookies.is_empty() {
        request = request.header(header::COOKIE, cookies);
    }
    request.body(Body::from(body)).expect("build POST")
}

async fn body_text(response: Response<Body>) -> String {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    String::from_utf8_lossy(&bytes).into_owned()
}

/// `name=value` of the cookie `name` that `response` sets.
fn cookie_pair(response: &Response<Body>, name: &str) -> Option<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with(&format!("{name}=")) && !v.contains("Max-Age=0"))
        .map(|v| v.split(';').next().unwrap_or("").to_string())
}

/// Where the browser goes next: `Location`, or a continue page's `Refresh`.
fn location(response: &Response<Body>) -> String {
    let value = |name| response.headers().get(name).and_then(|v| v.to_str().ok());
    value(header::LOCATION)
        .or_else(|| value(header::REFRESH).and_then(|v| v.split_once(";url=").map(|(_, u)| u)))
        .unwrap_or_default()
        .to_string()
}

fn query_param(location: &str, name: &str) -> Option<String> {
    let query = location.split('#').next()?.split_once('?')?.1;
    form_urlencoded::parse(query.as_bytes())
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

/// The access and refresh tokens of a token response.
async fn tokens(response: Response<Body>, what: &str) -> (String, String) {
    let status = response.status();
    let text = body_text(response).await;
    assert_eq!(status, StatusCode::OK, "{what}: {text}");
    let json: serde_json::Value = serde_json::from_str(&text).expect("token JSON");
    let field = |name: &str| {
        json[name]
            .as_str()
            .unwrap_or_else(|| panic!("{what}: no {name} in {text}"))
            .to_string()
    };
    (field("access_token"), field("refresh_token"))
}

// ── Journeys ─────────────────────────────────────────────────────────────────

/// Signs `user` in as a browser does: the login form, the authorization
/// request with PKCE, and the code exchange.
async fn sign_in(rig: &Rig, user: usize) -> Chain {
    let page = send(rig, get("/ui/login", "")).await;
    let csrf_cookie = cookie_pair(&page, "hearth_ui_csrf").expect("CSRF cookie");
    let html = body_text(page).await;
    let marker = r#"name="_csrf" value=""#;
    let start = html.find(marker).expect("_csrf field") + marker.len();
    let end = start + html[start..].find('"').expect("end of _csrf");
    let csrf = &html[start..end];

    let email: String = form_urlencoded::byte_serialize(rig.emails[user].as_bytes()).collect();
    let posted = send(
        rig,
        post_form(
            "/ui/login",
            &csrf_cookie,
            format!("email={email}&password={PASSWORD}&_csrf={csrf}"),
        ),
    )
    .await;
    let session = cookie_pair(&posted, "hearth_ui_session").unwrap_or_else(|| {
        panic!(
            "sign-in of user {user} set no session cookie: {}",
            posted.status()
        )
    });

    let authorized = send(
        rig,
        get(&rig.authorize_uri, &format!("{session}; {csrf_cookie}")),
    )
    .await;
    let target = location(&authorized);
    let code = query_param(&target, "code")
        .unwrap_or_else(|| panic!("authorize gave no code: {} {target}", authorized.status()));

    let exchanged = send(
        rig,
        post_form(
            &format!("/realms/{}/token", rig.realm_name),
            "",
            format!(
                "grant_type=authorization_code&code={code}&redirect_uri={REDIRECT_ENCODED}\
                 &client_id={}&code_verifier={PKCE_VERIFIER}",
                rig.client_id
            ),
        ),
    )
    .await;
    let (access, refresh) = tokens(exchanged, "code exchange").await;
    Chain {
        access,
        refresh,
        refreshes: 0,
        issued_at: now_secs(&rig.clock),
    }
}

/// Rotates `chain`'s refresh token.
async fn refresh(rig: &Rig, chain: &mut Chain) {
    let response = send(
        rig,
        post_form(
            &format!("/realms/{}/token", rig.realm_name),
            "",
            format!(
                "grant_type=refresh_token&refresh_token={}&client_id={}",
                chain.refresh, rig.client_id
            ),
        ),
    )
    .await;
    let (access, refresh) = tokens(response, "refresh").await;
    chain.access = access;
    chain.refresh = refresh;
    chain.refreshes += 1;
    chain.issued_at = now_secs(&rig.clock);
}

async fn userinfo(rig: &Rig, access: &str) {
    let response = send(
        rig,
        Request::builder()
            .uri(format!("/realms/{}/userinfo", rig.realm_name))
            .header(header::AUTHORIZATION, format!("Bearer {access}"))
            .body(Body::empty())
            .expect("build userinfo"),
    )
    .await;
    let status = response.status();
    assert_eq!(
        status,
        StatusCode::OK,
        "userinfo: {}",
        body_text(response).await
    );
}

async fn admin_lookup(rig: &Rig, admin: &str, user: &UserId) {
    let response = send(
        rig,
        Request::builder()
            .uri(format!("/admin/users/{}", user.as_uuid()))
            .header(header::AUTHORIZATION, format!("Bearer {admin}"))
            .header("X-Realm-ID", rig.realm_id.as_uuid().to_string())
            .body(Body::empty())
            .expect("build admin lookup"),
    )
    .await;
    let status = response.status();
    assert_eq!(
        status,
        StatusCode::OK,
        "admin lookup: {}",
        body_text(response).await
    );
}

fn admin_token(rig: &Rig) -> AdminToken {
    let session = rig
        .identity
        .create_session(&rig.realm_id, &rig.admin_id, &SessionContext::default())
        .expect("admin session");
    let access = rig
        .identity
        .issue_tokens(&rig.realm_id, &rig.admin_id, session.id())
        .expect("admin tokens")
        .access_token()
        .to_string();
    AdminToken {
        access,
        issued_at: now_secs(&rig.clock),
    }
}

/// A client's chain, after a new sign-in when the soak would sign in again:
/// no chain yet, 20 refreshes done, or an access token near its expiry.
async fn live_chain<'a>(
    rig: &Rig,
    chains: &'a mut [Option<Chain>],
    client: usize,
    user: usize,
) -> &'a mut Chain {
    let now = now_secs(&rig.clock);
    let stale = chains[client]
        .as_ref()
        .is_none_or(|c| c.refreshes >= CHAIN_REFRESHES || now - c.issued_at >= RENEW_AFTER_SECS);
    if stale {
        chains[client] = Some(sign_in(rig, user).await);
    }
    chains[client].as_mut().expect("chain")
}

/// A small deterministic random sequence (a 64-bit LCG).
struct Lcg(u64);
impl Lcg {
    fn next(&mut self, n: usize) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        ((self.0 >> 33) % n as u64) as usize
    }
}

/// One worker's share of the clients: their refresh-token chains, its admin
/// token and its random sequence. Each client belongs to one worker, so no
/// two workers present the same refresh token.
struct Worker {
    index: usize,
    rng: Lcg,
    chains: Vec<Option<Chain>>,
    admin: AdminToken,
}

/// One worker's share of a round of the soak's mix.
async fn worker_round(rig: Arc<Rig>, mut worker: Worker) -> Worker {
    let rig = rig.as_ref();
    for _ in 0..ROUND_JOURNEYS / WORKERS {
        let client = worker.rng.next(CLIENTS / WORKERS);
        let user = (worker.index * CLIENTS / WORKERS + client) % USERS;
        match worker.rng.next(100) {
            0..65 => {
                let chain = live_chain(rig, &mut worker.chains, client, user).await;
                refresh(rig, chain).await;
            }
            65..80 => {
                let user = worker.rng.next(USERS);
                drop(sign_in(rig, user).await);
            }
            80..95 => {
                let chain = live_chain(rig, &mut worker.chains, client, user).await;
                let access = chain.access.clone();
                userinfo(rig, &access).await;
            }
            _ => {
                if now_secs(&rig.clock) - worker.admin.issued_at >= RENEW_AFTER_SECS {
                    worker.admin = admin_token(rig);
                }
                let user = &rig.user_ids[worker.rng.next(USERS)];
                admin_lookup(rig, &worker.admin.access, user).await;
            }
        }
    }
    worker
}

/// The work the server runs in the background, then the deferred frees.
///
/// The clock first moves past every token, session and marker lifetime, so
/// the sweep finds the round's own rows expired while they are still in the
/// memtable: it walks them, then deletes them. In the server the memtable
/// lives longer than these lifetimes and than the sweep interval, so the
/// sweep does this all the time. Then the memtable flushes; every fourth
/// round also compacts. Returns how many expired rows the sweep deleted.
fn background_work(rig: &Rig, round: usize) -> u64 {
    rig.clock.advance(ROUND_SECS * 1_000_000);
    let swept = rig
        .identity
        .sweep_expired(&rig.realm_id)
        .expect("cleanup sweep");
    rig.storage.flush_memtable().expect("flush");
    if round % 4 == 3 {
        rig.storage.compact_ssts(2).expect("compaction");
    }

    // crossbeam-skiplist defers each freed node to the default epoch
    // collector; each `flush` runs the frees whose epoch is past.
    for _ in 0..256 {
        crossbeam_epoch::pin().flush();
    }
    swept.consumed_markers_deleted + swept.grant_families_deleted + swept.auth_codes_deleted
}

/// The least-squares slope of `ys` against `xs`.
#[allow(clippy::cast_precision_loss)] // n is a count of rounds
fn slope(xs: &[f64], ys: &[f64]) -> f64 {
    let n = xs.len() as f64;
    let mx = xs.iter().sum::<f64>() / n;
    let my = ys.iter().sum::<f64>() / n;
    let sxy: f64 = xs.iter().zip(ys).map(|(x, y)| (x - mx) * (y - my)).sum();
    let sxx: f64 = xs.iter().map(|x| (x - mx) * (x - mx)).sum();
    sxy / sxx
}

#[test]
#[allow(clippy::cast_precision_loss)] // journey counts and heap sizes far below 2^52
fn the_live_heap_stays_level_under_the_soak_mix() {
    // The threads live for the whole test, so their own state is part of the
    // level the heap reaches in the warm-up.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(WORKERS)
        .max_blocking_threads(WORKERS)
        .thread_keep_alive(Duration::from_secs(3600))
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let rig = Arc::new(rig());
        let mut workers: Vec<Worker> = (0..WORKERS)
            .map(|index| Worker {
                index,
                rng: Lcg(445 + index as u64),
                chains: (0..CLIENTS / WORKERS).map(|_| None).collect(),
                admin: admin_token(&rig),
            })
            .collect();
        let mut live = Vec::with_capacity(ROUNDS);
        for r in 0..ROUNDS {
            let running: Vec<_> = workers
                .drain(..)
                .map(|worker| tokio::spawn(worker_round(Arc::clone(&rig), worker)))
                .collect();
            for worker in running {
                workers.push(worker.await.expect("worker"));
            }
            let deleted = background_work(&rig, r);
            // Without this the test could pass without the pattern that
            // leaked: a walk over memtable rows, then their deletion.
            assert!(
                deleted >= (ROUND_JOURNEYS / 4) as u64,
                "round {r}: the sweep deleted only {deleted} expired rows"
            );
            live.push(LIVE.load(Ordering::Relaxed));
        }

        let measured = &live[WARM_UP..];
        let xs: Vec<f64> = (0..measured.len())
            .map(|i| (i * ROUND_JOURNEYS) as f64)
            .collect();
        let ys: Vec<f64> = measured.iter().map(|&b| b as f64).collect();
        let per_journey = slope(&xs, &ys);
        let kib: Vec<String> = live.iter().map(|b| format!("{}", b / 1024)).collect();
        assert!(
            per_journey < MAX_BYTES_PER_JOURNEY,
            "the live heap grew {per_journey:.2} bytes a journey over {} journeys \
             (bound {MAX_BYTES_PER_JOURNEY}); live heap after each round (KiB): {}",
            measured.len() * ROUND_JOURNEYS,
            kib.join(" "),
        );
    });
}
