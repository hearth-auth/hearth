//! Integration tests for HEA-502 Security Phase B acceptance criteria.
//!
//! Covers:
//! - F-03: Security response headers on UI routes (X-Frame-Options, CSP, etc.)
//! - F-04: `Secure` cookie attribute when TLS is active
//! - F-05: CORS preflight and response headers on OAuth token endpoints
//! - F-06: Per-`(realm, client)` token endpoint rate limiting (429 + Retry-After)
//! - HEA-1318: Login CSRF — Origin header validation on login endpoints

mod common;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hearth::audit::EmbeddedAuditEngine;
use hearth::core::{ClientId, RealmId, SessionId};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, RegisterClientRequest, UpdateUserRequest, UserStatus,
};
use hearth::protocol::admin_auth::TOKEN_RATE_LIMIT;
use hearth::protocol::http::{router as http_router, AppState};
use hearth::protocol::web::auth::{issue_auth_cookies, CookieSecret};
use hearth::protocol::web::{self, WebState};
use hearth::rbac::EmbeddedRbacEngine;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig};
use tower::ServiceExt;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helpers
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

/// Builds a `WebState` for UI-layer tests with a seeded "default" realm.
fn make_web_state() -> WebState {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);

    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).expect("storage"),
    );
    let clock = Arc::new(hearth::core::SystemClock) as Arc<dyn hearth::core::Clock>;
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn hearth::storage::StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn hearth::audit::AuditEngine>;
    let identity = Arc::new(
        EmbeddedIdentityEngine::new(
            Arc::clone(&storage) as Arc<dyn hearth::storage::StorageEngine>,
            Arc::clone(&clock),
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                ..IdentityConfig::default()
            },
            Arc::clone(&audit),
        )
        .expect("identity"),
    ) as Arc<dyn hearth::identity::IdentityEngine>;
    let authz = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as Arc<dyn hearth::storage::StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn hearth::rbac::RbacEngine>;
    identity
        .create_realm(&CreateRealmRequest {
            name: "default".to_string(),
            config: None,
        })
        .expect("seed default realm");

    let email = null_email_service();
    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&identity),
        Arc::clone(&authz),
        email,
        data_dir,
    ));

    WebState::new(
        identity,
        authz,
        audit,
        onboarding,
        CookieSecret::random(),
        None,
    )
    .with_dev_mode(true)
}

/// Builds an `AppState` for HTTP-layer tests.  Returns both state and the
/// seeded realm id so callers can register clients against it.
fn make_app_state() -> (Arc<AppState>, RealmId) {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);

    let storage =
        Arc::new(EmbeddedStorageEngine::open(StorageConfig::dev(data_dir)).expect("storage"));
    let clock = Arc::new(hearth::core::SystemClock) as Arc<dyn hearth::core::Clock>;
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn hearth::storage::StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn hearth::audit::AuditEngine>;
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as Arc<dyn hearth::storage::StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn hearth::rbac::RbacEngine>;
    let identity = Arc::new(
        EmbeddedIdentityEngine::with_rbac(
            Arc::clone(&storage) as Arc<dyn hearth::storage::StorageEngine>,
            Arc::clone(&clock),
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                ..IdentityConfig::default()
            },
            Arc::clone(&rbac),
            Arc::clone(&audit),
        )
        .expect("identity"),
    ) as Arc<dyn hearth::identity::IdentityEngine>;

    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: format!("sec-test-{}", Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");
    let realm_id = realm.id().clone();

    let state = Arc::new(AppState::new(identity, rbac, audit));
    (state, realm_id)
}

// ---------------------------------------------------------------------------
// F-03: Security headers
// ---------------------------------------------------------------------------

/// Security headers are injected on every UI response, including the login page.
#[tokio::test]
async fn security_headers_present_on_ui_route() {
    let app = web::router(make_web_state());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/ui/login")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    let h = resp.headers();
    assert_eq!(
        h["x-frame-options"], "DENY",
        "X-Frame-Options should be DENY",
    );
    assert_eq!(
        h["x-content-type-options"], "nosniff",
        "X-Content-Type-Options should be nosniff"
    );
    assert!(
        h.contains_key("referrer-policy"),
        "Referrer-Policy header must be present"
    );
    assert!(
        h.contains_key("content-security-policy"),
        "Content-Security-Policy header must be present"
    );
    assert!(
        !h.contains_key("strict-transport-security"),
        "HSTS must NOT be set when TLS is disabled"
    );
}

/// HSTS header is emitted only when `tls_enabled = true`.
#[tokio::test]
async fn hsts_header_present_when_tls_enabled() {
    let app = web::router(make_web_state().with_tls_enabled(true));
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/ui/login")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert!(
        resp.headers().contains_key("strict-transport-security"),
        "HSTS header must be present when TLS is enabled"
    );
}

/// CSP must contain neither 'unsafe-eval' nor 'unsafe-inline' (Alpine removed, HEA-850)
/// and must have no third-party origins (HEA-630).
#[tokio::test]
async fn csp_no_unsafe_eval_no_unsafe_inline_no_third_party() {
    let app = web::router(make_web_state());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/ui/login")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    let csp = resp
        .headers()
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .expect("CSP header");

    assert!(
        !csp.contains("'unsafe-eval'"),
        "CSP must not allow unsafe-eval after Alpine removal: {csp}"
    );
    assert!(
        !csp.contains("'unsafe-inline'"),
        "CSP must not allow unsafe-inline after Alpine removal: {csp}"
    );
    assert!(
        !csp.contains("cdn.jsdelivr.net"),
        "CSP must not reference cdn.jsdelivr.net: {csp}"
    );
    assert!(
        !csp.contains("fonts.googleapis.com"),
        "CSP must not reference fonts.googleapis.com: {csp}"
    );
    assert!(
        !csp.contains("fonts.gstatic.com"),
        "CSP must not reference fonts.gstatic.com: {csp}"
    );
    assert!(
        csp.contains("base-uri 'self'"),
        "CSP must restrict base-uri to self: {csp}"
    );
}

// ---------------------------------------------------------------------------
// F-04: Secure cookie flag
// ---------------------------------------------------------------------------

/// When `secure = true`, both session and CSRF cookies carry `; Secure`.
#[test]
fn session_cookie_has_secure_flag_when_tls_on() {
    let secret = CookieSecret::random();
    let realm_id = RealmId::new(Uuid::new_v4());
    let session_id = SessionId::new(Uuid::new_v4());

    let cookies = issue_auth_cookies(&secret, &realm_id, &session_id, true);

    assert!(
        cookies.session_cookie.contains("; Secure"),
        "session cookie must have Secure flag: {}",
        cookies.session_cookie
    );
    assert!(
        cookies.csrf_cookie.contains("; Secure"),
        "CSRF cookie must have Secure flag: {}",
        cookies.csrf_cookie
    );
}

/// When `secure = false` (plain HTTP), neither cookie carries `; Secure`.
#[test]
fn session_cookie_no_secure_flag_when_tls_off() {
    let secret = CookieSecret::random();
    let realm_id = RealmId::new(Uuid::new_v4());
    let session_id = SessionId::new(Uuid::new_v4());

    let cookies = issue_auth_cookies(&secret, &realm_id, &session_id, false);

    assert!(
        !cookies.session_cookie.contains("; Secure"),
        "session cookie must NOT have Secure flag over plain HTTP: {}",
        cookies.session_cookie
    );
    assert!(
        !cookies.csrf_cookie.contains("; Secure"),
        "CSRF cookie must NOT have Secure flag over plain HTTP: {}",
        cookies.csrf_cookie
    );
}

// ---------------------------------------------------------------------------
// F-05: CORS
// ---------------------------------------------------------------------------

/// Helper: registers a confidential client with a known redirect URI and
/// returns the registered `ClientId`.
fn register_cors_client(state: &AppState, realm_id: &RealmId) -> ClientId {
    let client = state
        .identity
        .register_client(
            realm_id,
            &RegisterClientRequest {
                client_name: "CORS Test Client".to_string(),
                redirect_uris: vec!["https://app.example.com/callback".to_string()],
                cors_origins: vec!["https://app.example.com".to_string()],
                client_secret: Some("cors-test-secret-1234".to_string()),
                grant_types: vec!["client_credentials".to_string()],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("register CORS test client");
    client.client_id().clone()
}

/// OPTIONS `/token` from a registered origin → 204 with CORS headers.
#[tokio::test]
async fn cors_preflight_allowed_origin_returns_headers() {
    let (state, realm_id) = make_app_state();
    register_cors_client(&state, &realm_id);
    let app = http_router(Arc::clone(&state));

    let resp = app
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/token")
                .header("x-realm-id", realm_id.as_uuid().to_string())
                .header("origin", "https://app.example.com")
                .header("access-control-request-method", "POST")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "preflight should be 204"
    );
    assert_eq!(
        resp.headers()["access-control-allow-origin"],
        "https://app.example.com",
        "allowed origin must be echoed back"
    );
    assert!(
        resp.headers().contains_key("access-control-allow-methods"),
        "access-control-allow-methods must be present"
    );
}

/// POST `/token` from an unregistered origin → response has NO CORS headers.
///
/// HEA-SEC-28: the OPTIONS preflight now echoes any origin uniformly (closing
/// the CORS-oracle leak), so the real security boundary is the POST response.
/// An origin not in `cors_origins` must NOT appear in `Access-Control-Allow-Origin`
/// on the actual token response.
#[tokio::test]
async fn cors_preflight_unregistered_origin_no_cors_headers() {
    let (state, realm_id) = make_app_state();
    let client_id = register_cors_client(&state, &realm_id);
    let app = http_router(Arc::clone(&state));

    let body = serde_json::json!({
        "grant_type": "client_credentials",
        "client_id": client_id.as_uuid().to_string(),
        "client_secret": "cors-test-secret-1234",
        "scope": null,
    });

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("content-type", "application/json")
                .header("x-realm-id", realm_id.as_uuid().to_string())
                .header("origin", "https://evil.com")
                .body(Body::from(serde_json::to_vec(&body).expect("serialize")))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert!(
        !resp.headers().contains_key("access-control-allow-origin"),
        "unregistered origin must NOT get CORS header on POST /token response"
    );
}

/// POST `/token` with `Origin` from a registered domain → response has
/// `Access-Control-Allow-Origin` echoing that origin.
#[tokio::test]
async fn token_response_includes_cors_header_for_registered_origin() {
    let (state, realm_id) = make_app_state();
    let client_id = register_cors_client(&state, &realm_id);
    let app = http_router(Arc::clone(&state));

    let body = serde_json::json!({
        "grant_type": "client_credentials",
        "client_id": client_id.as_uuid().to_string(),
        "client_secret": "cors-test-secret-1234",
        "scope": null,
    });

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("content-type", "application/json")
                .header("x-realm-id", realm_id.as_uuid().to_string())
                .header("origin", "https://app.example.com")
                .body(Body::from(serde_json::to_vec(&body).expect("serialize")))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        resp.headers()["access-control-allow-origin"],
        "https://app.example.com",
        "token response must echo allowed origin"
    );
}

// ---------------------------------------------------------------------------
// F-06: Token rate limiting
// ---------------------------------------------------------------------------

/// After exceeding `TOKEN_RATE_LIMIT` requests per window, the next request
/// receives `429 Too Many Requests` with a `Retry-After` header.
#[tokio::test]
async fn token_rate_limit_returns_429_with_retry_after() {
    let (state, realm_id) = make_app_state();
    let client = state
        .identity
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "Rate Limit Test Client".to_string(),
                redirect_uris: vec![],
                client_secret: Some("rl-secret-xyz".to_string()),
                grant_types: vec!["client_credentials".to_string()],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("register client");
    let client_id = client.client_id().clone();

    // Pre-exhaust the rate window by calling the limiter directly (fast path).
    #[allow(clippy::cast_possible_truncation)]
    let now_micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as i64;
    for _ in 0..TOKEN_RATE_LIMIT {
        state
            .token_rate_limiter
            .check(&realm_id, &client_id, now_micros);
    }

    // The next request via HTTP should be rejected with 429.
    let app = http_router(Arc::clone(&state));
    let body = serde_json::json!({
        "grant_type": "client_credentials",
        "client_id": client_id.as_uuid().to_string(),
        "client_secret": "rl-secret-xyz",
    });

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("content-type", "application/json")
                .header("x-realm-id", realm_id.as_uuid().to_string())
                .body(Body::from(serde_json::to_vec(&body).expect("serialize")))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "should return 429 after exhausting rate window"
    );
    assert!(
        resp.headers().contains_key("retry-after"),
        "429 response must include Retry-After header"
    );
}

// ---------------------------------------------------------------------------
// HEA-1318: Login CSRF — Origin header validation
// ---------------------------------------------------------------------------

const CSRF_TEST_EMAIL: &str = "csrf-test@hearth.test";
const CSRF_TEST_PASSWORD: &str = "CsrfTest123!";

/// Seeds a user in the "default" realm (sole realm in `make_web_state`).
/// Returns the realm's id so callers can target it if needed.
fn seed_login_user(state: &WebState) {
    // The sole realm resolves automatically (sole-realm shortcut in the resolver).
    let realm = state
        .identity
        .get_realm_by_name("default")
        .expect("get realm")
        .expect("default realm must exist");

    let user = state
        .identity
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: CSRF_TEST_EMAIL.to_string(),
                display_name: "CSRF Test".to_string(),
                first_name: "CSRF".to_string(),
                last_name: "Test".to_string(),
                attributes: Default::default(),
            },
        )
        .expect("create test user");

    state
        .identity
        .set_password(
            realm.id(),
            user.id(),
            &CleartextPassword::from_string(CSRF_TEST_PASSWORD.to_string()),
        )
        .expect("set password");

    state
        .identity
        .update_user(
            realm.id(),
            user.id(),
            &UpdateUserRequest {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .expect("activate user");
}

/// Seeds an admin user in the system realm for admin-login CSRF tests.
fn seed_admin_login_user(state: &WebState) {
    let user = state
        .identity
        .create_admin_user(&CreateUserRequest {
            email: "csrf-admin@hearth.test".to_string(),
            display_name: "CSRF Admin".to_string(),
            first_name: "CSRF".to_string(),
            last_name: "Admin".to_string(),
            attributes: Default::default(),
        })
        .expect("create admin user");

    let system_realm = RealmId::new(Uuid::nil());

    state
        .identity
        .set_password(
            &system_realm,
            user.id(),
            &CleartextPassword::from_string(CSRF_TEST_PASSWORD.to_string()),
        )
        .expect("set admin password");

    state
        .identity
        .update_user(
            &system_realm,
            user.id(),
            &UpdateUserRequest {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .expect("activate admin user");
}

/// Cross-origin POST to `/ui/login` with valid credentials must be rejected
/// (must NOT return `303 See Other` to the dashboard).
///
/// Fails against pre-fix code where the login succeeds regardless of Origin.
#[tokio::test]
async fn login_csrf_cross_origin_rejected() {
    let state = make_web_state();
    seed_login_user(&state);
    let app = web::router(state);

    let body = format!("email={}&password={}", CSRF_TEST_EMAIL, CSRF_TEST_PASSWORD);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/login")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("host", "localhost")
                .header("origin", "https://evil.example.com")
                .body(Body::from(body))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_ne!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "cross-origin login must NOT redirect to dashboard (CSRF rejected)"
    );
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "cross-origin login must return 401 via generic_error()"
    );
}

/// POST to `/ui/login` with no `Origin` header and valid credentials must
/// succeed (same-site form submission; CSRF guard must not fire).
#[tokio::test]
async fn login_csrf_same_origin_no_header_accepted() {
    let state = make_web_state();
    seed_login_user(&state);
    let app = web::router(state);

    let body = format!("email={}&password={}", CSRF_TEST_EMAIL, CSRF_TEST_PASSWORD);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/login")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("host", "localhost")
                .body(Body::from(body))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "login without Origin header must succeed (same-site flow)"
    );
}

/// Cross-origin POST to `/ui/admin/login` with valid credentials must be
/// rejected (must NOT return `303 See Other`).
///
/// Fails against pre-fix code where the admin login succeeds regardless of Origin.
#[tokio::test]
async fn admin_login_csrf_cross_origin_rejected() {
    let state = make_web_state();
    seed_admin_login_user(&state);
    let app = web::router(state);

    let body = format!(
        "email={}&password={}",
        "csrf-admin@hearth.test", CSRF_TEST_PASSWORD
    );

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/admin/login")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("host", "localhost")
                .header("origin", "https://evil.example.com")
                .body(Body::from(body))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_ne!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "cross-origin admin login must NOT redirect (CSRF rejected)"
    );
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "cross-origin admin login must return 401 via generic_error()"
    );
}

// ---------------------------------------------------------------------------
// HEA-1321: CSRF form-field double-submit verification on login
// ---------------------------------------------------------------------------

/// POST to `/ui/admin/login` with a `hearth_ui_csrf` cookie present but a
/// mismatched `_csrf` form field must show a CSRF-specific error (not silently
/// log the user in). Before the fix, valid credentials + wrong `_csrf` field
/// returned 303 See Other — the silent redirect described in the issue.
#[tokio::test]
async fn admin_login_mismatched_csrf_token_shows_error() {
    let state = make_web_state();
    seed_admin_login_user(&state);
    let app = web::router(state);

    // Cookie claims one token; form field submits a different one.
    let body = format!(
        "email={}&password={}&_csrf=intentionally-wrong-token",
        "csrf-admin@hearth.test", CSRF_TEST_PASSWORD
    );

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/admin/login")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("host", "localhost")
                .header("cookie", "hearth_ui_csrf=correct-cookie-value")
                .body(Body::from(body))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_ne!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "mismatched CSRF token must NOT redirect to the dashboard"
    );
    assert_eq!(
        resp.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "mismatched CSRF token must return 422"
    );

    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body bytes");
    let body_str = std::str::from_utf8(&body_bytes).expect("body is utf-8");
    assert!(
        body_str.contains("Invalid security token"),
        "response must contain the CSRF-specific error message"
    );
}

/// POST to `/ui/login` with a matching `hearth_ui_csrf` cookie + `_csrf` form
/// field must succeed (303 redirect) — the CSRF guard must not fire for a
/// correct double-submit pair.
#[tokio::test]
async fn login_matching_csrf_token_accepted() {
    let state = make_web_state();
    seed_login_user(&state);
    let app = web::router(state);

    let shared_token = "shared-csrf-token-abc123";
    let body = format!(
        "email={}&password={}&_csrf={}",
        CSRF_TEST_EMAIL, CSRF_TEST_PASSWORD, shared_token
    );

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/login")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("host", "localhost")
                // Cookie and form field both carry the same value.
                .header("cookie", format!("hearth_ui_csrf={shared_token}"))
                .body(Body::from(body))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "login with matching CSRF cookie+field must succeed (303)"
    );
}
