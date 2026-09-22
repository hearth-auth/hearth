#![allow(clippy::unwrap_used)]
//! Task 21.1 — the browser router must sit *under* the API router's guard
//! stack, not beside it.
//!
//! Before this change `main.rs` composed the tree as
//! `http::router(state).merge(web::router(web_state))`. `Router::layer` only
//! wraps the routes registered **before** it, so every guard installed by
//! `http::router` — the `Host` allowlist, the per-IP request shaper, the JSON
//! parse-bomb depth guard, the 1 MiB body limit and the
//! `hearth_http_request_duration_seconds` histogram — stopped at the API
//! surface. `/ui/*`, the SAML ACS and `begin` endpoints, and the pre-auth
//! recovery pages were all served with none of them.
//!
//! Each test here drives the *composed* tree and asserts that one guard now
//! reaches a browser route. Every test carries a control assertion so a
//! blanket failure cannot make it pass vacuously.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hearth::abuse::shaper::{RequestShaper, ShaperConfig};
use hearth::audit::EmbeddedAuditEngine;
use hearth::core::SystemClock;
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CreateRealmRequest, CredentialConfig, EmbeddedIdentityEngine, IdentityConfig,
};
use hearth::protocol::http::{router_with, AppState};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::EmbeddedRbacEngine;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig};
use tower::ServiceExt as _;

// ---------------------------------------------------------------------------
// Rig
// ---------------------------------------------------------------------------

fn null_email_service() -> Arc<EmailService> {
    Arc::new(
        EmailService::new(
            Arc::new(LoggingEmailSender::new()),
            "Hearth".to_string(),
            None,
            EmailBranding::default(),
            String::new(),
            None,
        )
        .expect("email service"),
    )
}

/// Builds the composed tree exactly as `main.rs` does: one set of engines, an
/// API `AppState` and a browser `WebState` over them, merged into a single
/// router. `tune` configures the `AppState` so each test can arm one guard.
fn app(tune: impl FnOnce(AppState) -> AppState) -> axum::Router {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    // Held for the lifetime of the test process.
    std::mem::forget(temp);

    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).expect("storage"),
    ) as Arc<dyn hearth::storage::StorageEngine>;
    let clock = Arc::new(SystemClock) as Arc<dyn hearth::core::Clock>;
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    )) as Arc<dyn hearth::audit::AuditEngine>;
    let identity = Arc::new(
        EmbeddedIdentityEngine::new(
            Arc::clone(&storage),
            Arc::clone(&clock),
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                ..IdentityConfig::default()
            },
            Arc::clone(&audit),
        )
        .expect("identity"),
    ) as Arc<dyn hearth::identity::IdentityEngine>;
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    )) as Arc<dyn hearth::rbac::RbacEngine>;

    identity
        .create_realm(&CreateRealmRequest {
            name: "default".to_string(),
            config: None,
        })
        .expect("seed default realm");

    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&identity),
        Arc::clone(&rbac),
        null_email_service(),
        data_dir,
    ));

    let web_state = WebState::new(
        Arc::clone(&identity),
        Arc::clone(&rbac),
        Arc::clone(&audit),
        onboarding,
        CookieSecret::random(),
        None,
    )
    .with_dev_mode(true);

    let app_state = tune(AppState::new(
        Arc::clone(&identity),
        Arc::clone(&rbac),
        Arc::clone(&audit),
    ));

    router_with(Arc::new(app_state), web::router(web_state))
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

fn get_with_host(uri: &str, host: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("host", host)
        .body(Body::empty())
        .unwrap()
}

fn form_post(uri: &str, body: String) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap()
}

fn json_post(uri: &str, body: String) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

async fn text_of(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn shaper_of_one() -> Arc<RequestShaper> {
    Arc::new(RequestShaper::with_config(ShaperConfig {
        ip_rps: Some(1),
        realm_rps: None,
    }))
}

// ---------------------------------------------------------------------------
// §4.5#1 — Host allowlist
// ---------------------------------------------------------------------------

/// A `Host` outside `security.allowed_hosts` must be refused on `/ui/*`.
#[tokio::test]
async fn host_allowlist_reaches_ui_routes() {
    let denied = app(|s| s.with_allowed_hosts(vec!["allowed.example.com".to_string()]))
        .oneshot(get_with_host("/ui/login", "evil.example.com"))
        .await
        .unwrap();
    assert_eq!(
        denied.status(),
        StatusCode::BAD_REQUEST,
        "a Host outside security.allowed_hosts must be refused on /ui/*"
    );

    let allowed = app(|s| s.with_allowed_hosts(vec!["allowed.example.com".to_string()]))
        .oneshot(get_with_host("/ui/login", "allowed.example.com"))
        .await
        .unwrap();
    assert_ne!(
        allowed.status(),
        StatusCode::BAD_REQUEST,
        "control: a listed Host must still be served"
    );

    let open = app(|s| s)
        .oneshot(get_with_host("/ui/login", "anything.example.com"))
        .await
        .unwrap();
    assert_ne!(
        open.status(),
        StatusCode::BAD_REQUEST,
        "control: an empty allowlist stays fail-open"
    );
}

/// The widened allowlist must not lock an operator out of the documented dev
/// origins when `--dev` is in force.
#[tokio::test]
async fn host_allowlist_admits_loopback_in_dev_mode() {
    let resp = app(|mut s| {
        s.dev_mode = true;
        s.with_allowed_hosts(vec!["auth.example.com".to_string()])
    })
    .oneshot(get_with_host("/ui/login", "127.0.0.1:8420"))
    .await
    .unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "`make dev` must keep working when hearth.yaml also sets allowed_hosts"
    );

    // Control: the dev grace is loopback-only, not "allow everything".
    let denied = app(|mut s| {
        s.dev_mode = true;
        s.with_allowed_hosts(vec!["auth.example.com".to_string()])
    })
    .oneshot(get_with_host("/ui/login", "evil.example.com"))
    .await
    .unwrap();
    assert_eq!(
        denied.status(),
        StatusCode::BAD_REQUEST,
        "control: dev mode must not open the allowlist to arbitrary hosts"
    );
}

// ---------------------------------------------------------------------------
// §4.5#2 — per-IP request shaper
// ---------------------------------------------------------------------------

/// A flood against a `/ui/*` route must eventually be shed with 429.
#[tokio::test]
async fn rate_cap_reaches_ui_routes() {
    let app = app(|s| s.with_request_shaper(shaper_of_one()));

    let first = app.clone().oneshot(get("/ui/login")).await.unwrap();
    assert_ne!(
        first.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "control: the first request inside the window must pass"
    );

    let second = app.oneshot(get("/ui/login")).await.unwrap();
    assert_eq!(
        second.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "the per-IP cap must shed a /ui/* flood"
    );
}

/// Static assets are served from the binary with `no-cache` + `ETag`, so one
/// page navigation re-validates several of them. They must not spend the
/// caller's per-IP budget.
#[tokio::test]
async fn rate_cap_exempts_ui_static_assets() {
    let app = app(|s| s.with_request_shaper(shaper_of_one()));

    for i in 0..8 {
        let resp = app
            .clone()
            .oneshot(get("/ui/static/app.css"))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "static asset request {i} must not be shed by the per-IP cap"
        );
    }

    // Control: the exemption is path-scoped, not a disabled shaper. The eight
    // static requests above spent none of the budget, so the first page request
    // still passes and only the second is shed.
    let first_page = app.clone().oneshot(get("/ui/login")).await.unwrap();
    assert_ne!(
        first_page.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "static requests must not have consumed the per-IP budget"
    );
    let shed = app.oneshot(get("/ui/login")).await.unwrap();
    assert_eq!(
        shed.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "the exemption must not disable the cap for real pages"
    );
}

// ---------------------------------------------------------------------------
// §4.5#3 — JSON parse-bomb depth guard
// ---------------------------------------------------------------------------

/// An over-deep JSON body posted at a `/ui/*` route must be refused by the
/// depth guard before any handler runs.
#[tokio::test]
async fn json_depth_guard_reaches_ui_routes() {
    let app = app(|s| s);

    let depth = hearth::abuse::guards::MAX_JSON_DEPTH + 8;
    let bomb = format!("{}{}", "[".repeat(depth), "]".repeat(depth));

    let resp = app
        .clone()
        .oneshot(json_post("/ui/login", bomb))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "an over-deep JSON body must be refused on /ui/*"
    );
    let text = text_of(resp).await;
    assert!(
        text.contains("nesting depth"),
        "the 400 must come from the depth guard, got: {text}"
    );

    // Control: a shallow body of the same shape does not trip the guard.
    let ok = app
        .oneshot(json_post("/ui/login", "[[1]]".to_string()))
        .await
        .unwrap();
    let ok_text = text_of(ok).await;
    assert!(
        !ok_text.contains("nesting depth"),
        "control: a shallow JSON body must not trip the depth guard"
    );
}

// ---------------------------------------------------------------------------
// §4.5#4 — body limit
// ---------------------------------------------------------------------------

/// A form POST larger than the 1 MiB default must be refused on `/ui/*`.
///
/// The size is chosen between Hearth's 1 MiB limit and axum's own 2 MB
/// `DefaultBodyLimit`, so a pass cannot be attributed to the framework default.
#[tokio::test]
async fn body_limit_reaches_ui_routes() {
    let app = app(|s| s);

    let oversize = format!("email={}", "a".repeat(1_500_000));
    let resp = app
        .clone()
        .oneshot(form_post("/ui/login", oversize))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "a 1.5 MiB form POST must be refused on /ui/*"
    );

    // Control: a small body of the same shape is not refused for its size.
    let small = app
        .oneshot(form_post(
            "/ui/login",
            "email=a@b.test&password=x".to_string(),
        ))
        .await
        .unwrap();
    assert_ne!(
        small.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "control: a normal login form post must not be refused for its size"
    );
}

/// The SAML assertion consumer receives a base64-inflated signed XML document
/// with embedded certificates and attribute statements, so it gets a wider
/// limit than the JSON default.
#[tokio::test]
async fn saml_acs_keeps_a_wider_body_limit() {
    let resp = app(|s| s)
        .oneshot(form_post(
            "/ui/realms/default/federation/saml/acs",
            format!("SAMLResponse={}", "A".repeat(1_500_000)),
        ))
        .await
        .unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "the SAML ACS must accept a body larger than the 1 MiB form default"
    );
}

// ---------------------------------------------------------------------------
// §4.10#8 / §4.24#8 — request-duration metric
// ---------------------------------------------------------------------------

/// `hearth_http_request_duration_seconds` must observe a `/ui/*` request,
/// labelled with the matched path template rather than the raw URI.
#[tokio::test]
async fn request_duration_metric_records_ui_routes() {
    let before = hearth::metrics::metrics().render();
    assert!(
        !before.contains("route=\"/ui/login\""),
        "control: the histogram must not already carry the /ui/login label"
    );

    let resp = app(|s| s).oneshot(get("/ui/login")).await.unwrap();
    assert_ne!(resp.status(), StatusCode::NOT_FOUND, "/ui/login must exist");

    let after = hearth::metrics::metrics().render();
    assert!(
        after.contains("hearth_http_request_duration_seconds"),
        "the histogram must be registered"
    );
    assert!(
        after.contains("route=\"/ui/login\""),
        "the request-duration histogram must record /ui/* requests"
    );
}

// ---------------------------------------------------------------------------
// §4.23#10 / task 21.11 — the tenant-existence oracle is rate-limited
// ---------------------------------------------------------------------------

/// The audit's §4.23#10 finding has two halves: a real and a non-existent realm
/// are distinguishable across the pre-auth `/ui/realms/{r}/*` shapes, and there
/// is **no rate limit on the oracle**. Task 21.1 moved the browser tree under
/// the API guard stack, so the per-IP request shaper now reaches those routes.
/// This pins the second half: probing realm names is budgeted like every other
/// `/ui/*` request, so enumeration cannot be driven at line rate.
///
/// The first half — byte-identity between a real and a fabricated realm — is
/// measured by `tests/tenant_enumeration_oracle.rs`.
#[tokio::test]
async fn rate_cap_reaches_realm_scoped_pre_auth_probes() {
    let app = app(|s| s.with_request_shaper(shaper_of_one()));

    let first = app
        .clone()
        .oneshot(get("/ui/realms/does-not-exist/login"))
        .await
        .unwrap();
    assert_ne!(
        first.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "control: the first probe inside the window must pass"
    );

    // A different fabricated name — an enumerator never repeats a guess, so the
    // cap has to be per-IP, not per-path.
    let second = app
        .oneshot(get("/ui/realms/also-not-real/login"))
        .await
        .unwrap();
    assert_eq!(
        second.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "realm-name probes must spend the per-IP budget regardless of the name guessed"
    );
}
