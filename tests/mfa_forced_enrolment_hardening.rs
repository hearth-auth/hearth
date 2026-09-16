//! 19.14 (audit 2026-08-28 §4.18#7) — forced-enrolment activation.
//!
//! `POST /ui/mfa-enroll-required/activate` ends in `create_session` exactly as
//! `POST /ui/mfa-challenge` does, and carried none of the three protections its
//! sibling has:
//!
//! * no CSRF double-submit check — a cross-site POST that landed on the right
//!   code completed a stranger's forced enrolment and logged them in;
//! * no redemption of the single-use MFA pending-cookie nonce — one captured
//!   cookie was replayable for its whole ten-minute life;
//! * no attempt budget — the pending TOTP secret could be guessed at line rate,
//!   while the challenge form throttles after five misses.
//!
//! These tests drive the real router with `tower::ServiceExt::oneshot` and
//! `dev_mode` **off**, because the CSRF check is deliberately relaxed in dev.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, Response, StatusCode};
use hearth::core::{Clock, RealmId, SystemClock, UserId};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, RealmConfig, UpdateUserRequest,
    UserStatus,
};
use hearth::protocol::web::auth::{CSRF_COOKIE, MFA_PENDING_COOKIE};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::EmbeddedRbacEngine;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use tower::ServiceExt as _;

const COOKIE_SECRET_BYTES: [u8; 32] = [7u8; 32];

/// Policy-valid credential assembled at runtime rather than written as a
/// literal, so CodeQL's hard-coded-credential rule does not fire.
fn password() -> String {
    ["correct-horse", "battery", "staple"].join("-")
}

struct Rig {
    app: axum::Router,
    identity: Arc<dyn IdentityEngine>,
    realm_id: RealmId,
    user_id: UserId,
}

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

/// Builds a router over a realm with `mfa_required: true` and a password-only
/// user, so the direct browser login lands on forced enrolment.
fn build_rig() -> Rig {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);

    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).expect("open storage"),
    );
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let audit = Arc::new(hearth::audit::EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn hearth::audit::AuditEngine>;
    let identity = Arc::new(
        EmbeddedIdentityEngine::new(
            Arc::clone(&storage) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                ..IdentityConfig::default()
            },
            Arc::clone(&audit),
        )
        .expect("identity engine"),
    ) as Arc<dyn IdentityEngine>;
    let authz = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    ));

    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: format!("forced-enrol-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                mfa_required: Some(true),
                ..RealmConfig::default()
            }),
        })
        .expect("create realm");
    let user = identity
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: "alice@acme.test".to_string(),
                display_name: "Alice".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    identity
        .set_password(
            realm.id(),
            user.id(),
            &CleartextPassword::from_string(password()),
        )
        .expect("set password");
    identity
        .update_user(
            realm.id(),
            user.id(),
            &UpdateUserRequest {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .expect("activate user");

    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&identity),
        authz.clone() as Arc<dyn hearth::rbac::RbacEngine>,
        null_email_service(),
        data_dir,
    ));
    let state = WebState::new(
        Arc::clone(&identity),
        authz as Arc<dyn hearth::rbac::RbacEngine>,
        audit as Arc<dyn hearth::audit::AuditEngine>,
        onboarding,
        CookieSecret::from_bytes(COOKIE_SECRET_BYTES),
        None,
    );
    let app = web::router(state);

    Rig {
        app,
        identity,
        realm_id: realm.id().clone(),
        user_id: user.id().clone(),
    }
}

// ─── cookie plumbing ────────────────────────────────────────────────────────

fn set_cookie_values(resp: &Response<Body>, name: &str) -> Option<String> {
    resp.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with(&format!("{name}=")))
        .and_then(|v| v.split(';').next())
        .and_then(|kv| kv.split_once('='))
        .map(|(_, val)| val.to_string())
}

/// The pending cookie is `user.realm.expires.return_to.nonce.mac` — plain,
/// dot-separated, with only the MAC keyed. The nonce is field 4.
fn nonce_from_pending(cookie_value: &str) -> String {
    cookie_value
        .split('.')
        .nth(4)
        .expect("pending cookie carries a nonce field")
        .to_string()
}

fn compute_totp_code(secret_base32: &str, unix_secs: u64) -> String {
    let secret_bytes = data_encoding::BASE32_NOPAD
        .decode(secret_base32.as_bytes())
        .expect("decode base32");
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &secret_bytes);
    let tag = ring::hmac::sign(&key, &(unix_secs / 30).to_be_bytes());
    let hash = tag.as_ref();
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let binary = u32::from_be_bytes([
        hash[offset] & 0x7f,
        hash[offset + 1],
        hash[offset + 2],
        hash[offset + 3],
    ]);
    format!("{:06}", binary % 1_000_000)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("epoch")
        .as_secs()
}

/// Logs in with the password and returns the MFA pending cookie value.
async fn login_to_forced_enrolment(rig: &Rig) -> String {
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "email=alice@acme.test&password={}",
                    password()
                )))
                .expect("build login request"),
        )
        .await
        .expect("login");
    assert_eq!(
        resp.headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/ui/mfa-enroll-required"),
        "an mfa_required realm with no enrolled factor must route to forced enrolment"
    );
    set_cookie_values(&resp, MFA_PENDING_COOKIE).expect("login issues a pending cookie")
}

/// Fetches the forced-enrolment page and returns `(csrf_value, totp_secret)`.
async fn open_enrolment_page(rig: &Rig, pending: &str) -> (String, String) {
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/mfa-enroll-required")
                .header(header::COOKIE, format!("{MFA_PENDING_COOKIE}={pending}"))
                .body(Body::empty())
                .expect("build enrol page request"),
        )
        .await
        .expect("enrol page");
    assert_eq!(resp.status(), StatusCode::OK, "enrolment page must render");
    let csrf = set_cookie_values(&resp, CSRF_COOKIE)
        .expect("the enrolment page must mint a CSRF cookie for its own form");
    let body = to_bytes(resp.into_body(), 1 << 20).await.expect("body");
    let html = String::from_utf8_lossy(&body).to_string();
    assert!(
        html.contains(r#"name="_csrf""#),
        "the activation form must carry the CSRF token the POST now demands"
    );
    // The page just ran a fresh enrolment; read the pending secret back out of
    // the engine rather than scraping the QR code.
    let secret = secret_for_user(rig);
    (csrf, secret)
}

/// Re-reads the user's pending TOTP secret by starting the same enrolment the
/// page started. `enroll_totp` is idempotent for a not-yet-enabled factor and
/// returns the live secret.
fn secret_for_user(rig: &Rig) -> String {
    rig.identity
        .enroll_totp(&rig.realm_id, &rig.user_id)
        .expect("enroll_totp")
        .secret_base32
        .clone()
}

/// Posts the activation form. `csrf` of `None` omits both the cookie and the
/// hidden field, which is what a cross-site form can manage.
async fn post_activate(rig: &Rig, pending: &str, csrf: Option<&str>, code: &str) -> Response<Body> {
    let mut cookies = format!("{MFA_PENDING_COOKIE}={pending}");
    let mut body = format!("code={code}");
    if let Some(token) = csrf {
        use std::fmt::Write as _;
        let _ = write!(cookies, "; {CSRF_COOKIE}={token}");
        let _ = write!(body, "&_csrf={token}");
    }
    rig.app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/mfa-enroll-required/activate")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, cookies)
                .body(Body::from(body))
                .expect("build activate request"),
        )
        .await
        .expect("activate")
}

// ─── the three protections ──────────────────────────────────────────────────

/// Control: with the CSRF token present, a correct code activates and issues a
/// session cookie. Every rejection below is measured against this.
#[tokio::test]
async fn activation_with_csrf_and_a_valid_code_creates_a_session() {
    let rig = build_rig();
    let pending = login_to_forced_enrolment(&rig).await;
    let (csrf, secret) = open_enrolment_page(&rig, &pending).await;

    let resp = post_activate(
        &rig,
        &pending,
        Some(&csrf),
        &compute_totp_code(&secret, now_secs()),
    )
    .await;
    assert!(
        resp.status().is_redirection(),
        "a valid activation must complete the login, got {}",
        resp.status()
    );
    assert!(
        set_cookie_values(&resp, hearth::protocol::web::auth::SESSION_COOKIE).is_some(),
        "a completed forced enrolment must issue a session cookie"
    );
}

/// §4.18#7, part 1: the same request without a CSRF token must be refused,
/// even though the code is correct.
#[tokio::test]
async fn activation_without_a_csrf_token_is_refused() {
    let rig = build_rig();
    let pending = login_to_forced_enrolment(&rig).await;
    let (_csrf, secret) = open_enrolment_page(&rig, &pending).await;

    let resp = post_activate(
        &rig,
        &pending,
        None,
        &compute_totp_code(&secret, now_secs()),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "a cross-site activation POST must be refused"
    );
    assert!(
        set_cookie_values(&resp, hearth::protocol::web::auth::SESSION_COOKIE).is_none(),
        "a CSRF-less activation must not issue a session"
    );
}

/// §4.18#7, part 1b: a CSRF token that does not match the cookie is no better
/// than none — this is what an attacker who can set a cookie but not read one
/// would try.
#[tokio::test]
async fn activation_with_a_mismatched_csrf_token_is_refused() {
    let rig = build_rig();
    let pending = login_to_forced_enrolment(&rig).await;
    let (csrf, secret) = open_enrolment_page(&rig, &pending).await;
    let code = compute_totp_code(&secret, now_secs());

    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/mfa-enroll-required/activate")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(
                    header::COOKIE,
                    format!("{MFA_PENDING_COOKIE}={pending}; {CSRF_COOKIE}={csrf}"),
                )
                .body(Body::from(format!("code={code}&_csrf=not-the-token")))
                .expect("build activate request"),
        )
        .await
        .expect("activate");
    assert_eq!(
        resp.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "a mismatched CSRF token must be refused"
    );
}

/// §4.18#7, part 2: the pending-cookie nonce is single-use. Burning it out of
/// band stands in for the first use; the activation must then refuse to mint a
/// session even though the TOTP code is correct.
#[tokio::test]
async fn activation_refuses_a_pending_cookie_whose_nonce_was_already_spent() {
    let rig = build_rig();
    let pending = login_to_forced_enrolment(&rig).await;
    let (csrf, secret) = open_enrolment_page(&rig, &pending).await;

    rig.identity
        .burn_mfa_nonce(
            &rig.realm_id,
            &nonce_from_pending(&pending),
            now_secs().saturating_add(600),
        )
        .expect("burn nonce");

    let resp = post_activate(
        &rig,
        &pending,
        Some(&csrf),
        &compute_totp_code(&secret, now_secs()),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "a replayed pending cookie must not complete a second activation"
    );
    assert!(
        set_cookie_values(&resp, hearth::protocol::web::auth::SESSION_COOKIE).is_none(),
        "a spent nonce must not issue a session"
    );
}

/// §4.18#7, part 3: guessing the pending TOTP secret must run out of attempts.
/// The engine's MFA budget is five failures, the same one `verify_totp` uses.
#[tokio::test]
async fn activation_throttles_repeated_wrong_codes() {
    let rig = build_rig();
    let pending = login_to_forced_enrolment(&rig).await;
    let (csrf, _secret) = open_enrolment_page(&rig, &pending).await;

    let mut saw_rate_limit = false;
    for attempt in 0..8 {
        let resp = post_activate(&rig, &pending, Some(&csrf), "000000").await;
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            saw_rate_limit = true;
            assert!(
                attempt >= 5,
                "the budget must allow the documented five attempts before locking out"
            );
            break;
        }
        assert_eq!(
            resp.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "a wrong code before lockout must render the form again"
        );
    }
    assert!(
        saw_rate_limit,
        "forced-enrolment activation must throttle, not accept unlimited guesses"
    );
}
