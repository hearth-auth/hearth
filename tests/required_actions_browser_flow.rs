//! Integration tests for the browser-login required-action gate (HEA-797).
//!
//! Covers:
//! * Browser login with `UPDATE_PASSWORD` pending → redirect to interstitial,
//!   no session cookie issued.
//! * Completing `UPDATE_PASSWORD` creates a session and redirects to `/ui`.
//! * Completing `UPDATE_PASSWORD` with `return_to` redirects to original dest.
//! * Browser login with `VERIFY_EMAIL` pending → redirect to interstitial.
//! * Resend (`GET /required-action/VERIFY_EMAIL`) with RA cookie dispatches
//!   a transport call (verified via a capturing sender).

use std::sync::{Arc, Mutex};

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use hearth::audit::EmbeddedAuditEngine;
use hearth::core::{Clock, RealmId, SystemClock};
use hearth::identity::email::{EmailBranding, EmailError, EmailMessage, EmailSender, EmailService};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, RealmConfig, RequiredAction,
    UpdateUserRequest, UserStatus,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::EmbeddedRbacEngine;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig};
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const COOKIE_SECRET: [u8; 32] = [13u8; 32];
const PASSWORD: &str = "correct-horse-battery-staple-97";
const NEW_PASSWORD: &str = "new-password-after-required-action-99";

// ---------------------------------------------------------------------------
// Capturing email sender — collects every sent message for assertions.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct CapturingEmailSender {
    sent: Mutex<Vec<EmailMessage>>,
}

impl CapturingEmailSender {
    fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn sent_count(&self) -> usize {
        self.sent.lock().unwrap_or_else(|p| p.into_inner()).len()
    }
}

impl EmailSender for CapturingEmailSender {
    fn send(&self, message: &EmailMessage) -> Result<(), EmailError> {
        self.sent
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(message.clone());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

struct Rig {
    app: axum::Router,
    identity: Arc<dyn IdentityEngine>,
    realm_name: String,
    realm_id: RealmId,
    email_sender: Arc<CapturingEmailSender>,
}

fn build_rig(default_actions: Vec<RequiredAction>) -> Rig {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);

    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).expect("storage"),
    );
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage) as _,
        Arc::clone(&clock),
    ));
    let identity = Arc::new(
        EmbeddedIdentityEngine::new(
            Arc::clone(&storage) as _,
            Arc::clone(&clock),
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                ..IdentityConfig::default()
            },
            Arc::clone(&audit) as _,
        )
        .expect("identity engine"),
    ) as Arc<dyn IdentityEngine>;
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as _,
        Arc::clone(&clock),
    )) as Arc<dyn hearth::rbac::RbacEngine>;

    let realm_name = format!("ra-browser-{}", uuid::Uuid::new_v4());
    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: realm_name.clone(),
            config: Some(RealmConfig {
                default_required_actions: default_actions,
                ..Default::default()
            }),
        })
        .expect("create realm");

    let email_sender = CapturingEmailSender::new();
    let email_svc = Arc::new(
        EmailService::new(
            Arc::clone(&email_sender) as _,
            "Hearth".to_string(),
            None,
            EmailBranding::default(),
            String::new(),
            None,
        )
        .expect("email service"),
    );

    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&identity),
        Arc::clone(&rbac),
        Arc::clone(&email_svc),
        data_dir,
    ));

    let state = WebState::new(
        Arc::clone(&identity),
        rbac,
        Arc::clone(&audit) as _,
        onboarding,
        CookieSecret::from_bytes(COOKIE_SECRET),
        Some(email_svc),
    );

    Rig {
        app: web::router(state),
        identity,
        realm_name,
        realm_id: realm.id().clone(),
        email_sender,
    }
}

/// Creates an active user with the given email, sets their password, and
/// activates their account. The user inherits whatever required actions the
/// realm defaults specify.
fn create_user(rig: &Rig, email: &str) {
    let user = rig
        .identity
        .create_user(
            &rig.realm_id,
            &CreateUserRequest {
                email: email.to_string(),
                display_name: "Test User".to_string(),
                first_name: "T".to_string(),
                last_name: "U".to_string(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    rig.identity
        .set_password(
            &rig.realm_id,
            user.id(),
            &CleartextPassword::from_string(PASSWORD.to_string()),
        )
        .expect("set password");

    rig.identity
        .update_user(
            &rig.realm_id,
            user.id(),
            &UpdateUserRequest {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .expect("activate user");
}

/// Submits the realm-scoped login form and returns the response.
async fn post_login(rig: &Rig, email: &str, return_to: Option<&str>) -> axum::response::Response {
    let mut body = format!(
        "email={}&password={}",
        url_encode(email),
        url_encode(PASSWORD),
    );
    if let Some(r) = return_to {
        use std::fmt::Write;
        let _ = write!(body, "&return_to={}", url_encode(r));
    }
    rig.app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/realms/{}/login", rig.realm_name))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .expect("build request"),
        )
        .await
        .expect("oneshot")
}

/// Extracts all Set-Cookie values from a response.
fn set_cookies(resp: &axum::response::Response) -> Vec<String> {
    resp.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(str::to_string))
        .collect()
}

/// Extracts the Location header from a redirect response.
fn location_of(resp: &axum::response::Response) -> Option<String> {
    resp.headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// Finds the value of a named cookie from a Set-Cookie header list.
fn find_cookie(cookies: &[String], name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    cookies.iter().find(|c| c.starts_with(&prefix)).map(|c| {
        c.split(';')
            .next()
            .unwrap_or("")
            .trim_start_matches(&prefix)
            .to_string()
    })
}

async fn body_text(resp: axum::response::Response) -> String {
    let bytes = to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .expect("body bytes");
    String::from_utf8_lossy(&bytes).into_owned()
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                use std::fmt::Write as _;
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

// ===========================================================================
// Tests: UPDATE_PASSWORD browser flow
// ===========================================================================

#[tokio::test]
async fn login_with_update_password_pending_redirects_to_interstitial() {
    let rig = build_rig(vec![RequiredAction::UpdatePassword]);
    create_user(&rig, "upw@ra-browser.test");

    let resp = post_login(&rig, "upw@ra-browser.test", None).await;

    // Must redirect to the RA action page, not to /ui.
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "expected 303 redirect, got {}",
        resp.status()
    );
    assert_eq!(
        location_of(&resp).as_deref(),
        Some("/required-action/UPDATE_PASSWORD"),
        "must redirect to UPDATE_PASSWORD interstitial"
    );

    let cookies = set_cookies(&resp);

    // RA session cookie MUST be set.
    assert!(
        find_cookie(&cookies, "hearth_ra_session").is_some(),
        "RA session cookie must be set: {cookies:?}"
    );

    // Session cookie must NOT be set — the user has no authenticated session yet.
    assert!(
        find_cookie(&cookies, "hearth_ui_session").is_none(),
        "session cookie must NOT be set before required action completes: {cookies:?}"
    );
}

#[tokio::test]
async fn update_password_completion_issues_session_and_redirects_to_ui() {
    let rig = build_rig(vec![RequiredAction::UpdatePassword]);
    create_user(&rig, "upw-complete@ra-browser.test");

    // 1. Login → intercepted, RA cookie set.
    let login_resp = post_login(&rig, "upw-complete@ra-browser.test", None).await;
    assert_eq!(login_resp.status(), StatusCode::SEE_OTHER);
    let ra_cookie_val = find_cookie(&set_cookies(&login_resp), "hearth_ra_session")
        .expect("RA session cookie must be set after login intercept");

    // 2. POST /required-action/UPDATE_PASSWORD with the new password.
    let body = format!(
        "new_password={}&confirm_password={}",
        url_encode(NEW_PASSWORD),
        url_encode(NEW_PASSWORD),
    );
    let complete_resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/required-action/UPDATE_PASSWORD")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, format!("hearth_ra_session={ra_cookie_val}"))
                .body(Body::from(body))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        complete_resp.status(),
        StatusCode::SEE_OTHER,
        "expected redirect after completing UPDATE_PASSWORD, got {}",
        complete_resp.status()
    );

    let completion_cookies = set_cookies(&complete_resp);

    // Session cookie MUST now be set.
    assert!(
        find_cookie(&completion_cookies, "hearth_ui_session").is_some(),
        "session cookie must be set after completing UPDATE_PASSWORD: {completion_cookies:?}"
    );

    // CSRF cookie MUST also be set.
    assert!(
        find_cookie(&completion_cookies, "hearth_ui_csrf").is_some(),
        "CSRF cookie must be set: {completion_cookies:?}"
    );

    // RA cookie must be cleared (Max-Age=0).
    let ra_cleared = completion_cookies
        .iter()
        .any(|c| c.starts_with("hearth_ra_session=") && c.contains("Max-Age=0"));
    assert!(
        ra_cleared,
        "RA cookie must be cleared: {completion_cookies:?}"
    );

    // Must redirect to /ui (default when no return_to was given).
    assert_eq!(
        location_of(&complete_resp).as_deref(),
        Some("/ui"),
        "must redirect to /ui after completing required action"
    );
}

#[tokio::test]
async fn update_password_completion_with_return_to_redirects_to_original_dest() {
    let rig = build_rig(vec![RequiredAction::UpdatePassword]);
    create_user(&rig, "upw-returnto@ra-browser.test");

    // Login with a return_to that should be honored after completion.
    let login_resp = post_login(&rig, "upw-returnto@ra-browser.test", Some("/ui/account")).await;
    assert_eq!(login_resp.status(), StatusCode::SEE_OTHER);
    let ra_cookie_val = find_cookie(&set_cookies(&login_resp), "hearth_ra_session")
        .expect("RA session cookie must be set");

    // Complete the required action.
    let body = format!(
        "new_password={}&confirm_password={}",
        url_encode(NEW_PASSWORD),
        url_encode(NEW_PASSWORD),
    );
    let complete_resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/required-action/UPDATE_PASSWORD")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, format!("hearth_ra_session={ra_cookie_val}"))
                .body(Body::from(body))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(complete_resp.status(), StatusCode::SEE_OTHER);

    // Must redirect to the original return_to, not /ui.
    assert_eq!(
        location_of(&complete_resp).as_deref(),
        Some("/ui/account"),
        "must redirect to return_to after completing required action"
    );

    // Session cookie must be set.
    assert!(
        find_cookie(&set_cookies(&complete_resp), "hearth_ui_session").is_some(),
        "session cookie must be set"
    );
}

// ===========================================================================
// Tests: VERIFY_EMAIL browser flow
// ===========================================================================

#[tokio::test]
async fn login_with_verify_email_pending_redirects_to_interstitial() {
    let rig = build_rig(vec![RequiredAction::VerifyEmail]);
    create_user(&rig, "ve@ra-browser.test");

    let resp = post_login(&rig, "ve@ra-browser.test", None).await;

    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "expected 303 redirect, got {}",
        resp.status()
    );
    assert_eq!(
        location_of(&resp).as_deref(),
        Some("/required-action/VERIFY_EMAIL"),
        "must redirect to VERIFY_EMAIL interstitial"
    );

    let cookies = set_cookies(&resp);
    assert!(
        find_cookie(&cookies, "hearth_ra_session").is_some(),
        "RA session cookie must be set: {cookies:?}"
    );
    assert!(
        find_cookie(&cookies, "hearth_ui_session").is_none(),
        "session cookie must NOT be set before VERIFY_EMAIL completes: {cookies:?}"
    );
}

#[tokio::test]
async fn verify_email_resend_with_ra_cookie_dispatches_transport_call() {
    let rig = build_rig(vec![RequiredAction::VerifyEmail]);
    create_user(&rig, "ve-resend@ra-browser.test");

    // Login → RA intercept. The initial verify_email_page GET also sends an email.
    let login_resp = post_login(&rig, "ve-resend@ra-browser.test", None).await;
    assert_eq!(login_resp.status(), StatusCode::SEE_OTHER);
    let ra_cookie_val = find_cookie(&set_cookies(&login_resp), "hearth_ra_session")
        .expect("RA session cookie must be set");

    // GET /required-action/VERIFY_EMAIL (the "Send again" link) with RA cookie.
    // This is the resend path — verify it sends an email via the transport.
    let sent_before = rig.email_sender.sent_count();
    let resend_resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/required-action/VERIFY_EMAIL")
                .header(header::COOKIE, format!("hearth_ra_session={ra_cookie_val}"))
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        resend_resp.status(),
        StatusCode::OK,
        "resend page must return 200 (not 400 'no active session'): {}",
        resend_resp.status()
    );

    // The "check your email" page body must be rendered.
    let body = body_text(resend_resp).await;
    assert!(
        body.contains("check your email")
            || body.contains("Check your email")
            || body.contains("verification"),
        "resend page must show email-sent confirmation: snippet = {body:.200}"
    );

    // The email transport must have been called at least once since login.
    assert!(
        rig.email_sender.sent_count() > sent_before,
        "resend must dispatch a transport call (sent_before={sent_before}, now={})",
        rig.email_sender.sent_count()
    );
}

// ===========================================================================
// Regression: no required actions → normal session issued immediately
// ===========================================================================

#[tokio::test]
async fn login_with_no_required_actions_issues_session_immediately() {
    let rig = build_rig(vec![]); // no default required actions
    create_user(&rig, "clean@ra-browser.test");

    let resp = post_login(&rig, "clean@ra-browser.test", None).await;

    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "expected 303 redirect, got {}",
        resp.status()
    );
    assert_eq!(location_of(&resp).as_deref(), Some("/ui"));

    let cookies = set_cookies(&resp);
    assert!(
        find_cookie(&cookies, "hearth_ui_session").is_some(),
        "session cookie must be set for clean user: {cookies:?}"
    );
    assert!(
        find_cookie(&cookies, "hearth_ra_session").is_none(),
        "RA cookie must NOT be set for clean user: {cookies:?}"
    );
}
