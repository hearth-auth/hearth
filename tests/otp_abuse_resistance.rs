//! Abuse resistance of the emailed second factor and the magic-link request
//! (GA audit 2026-09-28, findings M12 and L17).
//!
//! * Every `GET /ui/mfa-otp-challenge` used to mint and mail a fresh email OTP,
//!   `issue_email_otp` had no resend throttle (SMS has one), and the submit
//!   handler never touched the per-user MFA budget. Each code allowed five
//!   guesses, so a password holder could keep asking for codes and guess
//!   without limit — and flood the victim's inbox doing it.
//! * `POST /v1/{realm}/auth/magic-link` only *checked* the per-IP limiter and
//!   never recorded to it, so it never tripped, and it mailed a link to any
//!   address — an unauthenticated relay.

mod common;

use std::sync::{Arc, Mutex};

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use hearth::core::RealmId;
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, EmailBranding, EmailError,
    EmailMessage, EmailSender, EmailService, IdentityError, RealmConfig, RegistrationPolicy,
    UpdateUserRequest, User, UserStatus,
};
use tower::ServiceExt as _;

/// Records every message so a test can count sends and read the codes.
#[derive(Default)]
struct CapturingEmailSender {
    messages: Mutex<Vec<EmailMessage>>,
}

impl CapturingEmailSender {
    fn count(&self) -> usize {
        self.messages.lock().expect("lock").len()
    }

    fn recipients(&self) -> Vec<String> {
        self.messages
            .lock()
            .expect("lock")
            .iter()
            .map(|m| m.to.clone())
            .collect()
    }

    /// The 6-digit code in the most recent message.
    fn last_code(&self) -> String {
        let guard = self.messages.lock().expect("lock");
        let body = guard.last().expect("a message was sent").text_body.clone();
        body.split(|c: char| !c.is_ascii_digit())
            .find(|run| run.len() == 6)
            .expect("a 6-digit code in the message")
            .to_string()
    }
}

impl EmailSender for CapturingEmailSender {
    fn send(&self, message: &EmailMessage) -> Result<(), EmailError> {
        self.messages.lock().expect("lock").push(message.clone());
        Ok(())
    }
}

fn email_service(sender: &Arc<CapturingEmailSender>) -> Arc<EmailService> {
    Arc::new(
        EmailService::new(
            Arc::clone(sender) as Arc<dyn EmailSender>,
            "Hearth".to_string(),
            None,
            EmailBranding::default(),
            String::new(),
            None,
        )
        .expect("email service"),
    )
}

fn password() -> String {
    ["otp", "abuse", "horse", "staple"].join("-")
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("epoch")
        .as_secs()
}

fn create_realm(h: &common::TestHarness, config: RealmConfig) -> (RealmId, String) {
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("otp-{}", uuid::Uuid::new_v4().simple()),
            config: Some(config),
        })
        .expect("create realm");
    (realm.id().clone(), realm.name().to_string())
}

/// An active user with a password and email OTP enrolled.
fn email_otp_user(h: &common::TestHarness, realm: &RealmId) -> User {
    let user = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("otp-{}@example.com", uuid::Uuid::new_v4().simple()),
                display_name: "OTP User".to_string(),
                ..Default::default()
            },
        )
        .expect("create user");
    h.identity()
        .set_password(
            realm,
            user.id(),
            &CleartextPassword::from_string(password()),
        )
        .expect("set password");
    h.identity()
        .update_user(
            realm,
            user.id(),
            &UpdateUserRequest {
                status: Some(UserStatus::Active),
                email_otp_enabled: Some(true),
                ..Default::default()
            },
        )
        .expect("activate user and enrol email OTP");
    h.identity()
        .get_user(realm, user.id())
        .expect("get user")
        .expect("user exists")
}

fn build_web_app(h: &common::TestHarness, email: Arc<EmailService>) -> axum::Router {
    use hearth::identity::onboarding::OnboardingService;
    use hearth::protocol::web::{self, CookieSecret, WebState};

    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);
    let onboarding = Arc::new(OnboardingService::new(
        h.identity_arc(),
        h.rbac_arc(),
        Arc::clone(&email),
        data_dir,
    ));
    let state = WebState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
        onboarding,
        CookieSecret::from_bytes([5u8; 32]),
        Some(email),
    )
    .with_dev_mode(true);
    web::router(state)
}

fn cookie_pairs(response: &axum::response::Response) -> Vec<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter(|c| !c.contains("Max-Age=0"))
        .filter_map(|c| c.split(';').next().map(str::to_string))
        .collect()
}

fn find(pairs: &[String], name: &str) -> Option<String> {
    pairs
        .iter()
        .find(|p| p.starts_with(&format!("{name}=")))
        .cloned()
}

async fn send(app: &axum::Router, req: Request<Body>) -> axum::response::Response {
    app.clone().oneshot(req).await.expect("oneshot")
}

/// Signs in with the password and returns the MFA pending cookie.
async fn pending_cookie(app: &axum::Router, realm_name: &str, user: &User) -> String {
    let body = format!(
        "email={}&password={}",
        user.email().replace('@', "%40"),
        password()
    );
    let response = send(
        app,
        Request::builder()
            .method("POST")
            .uri(format!("/ui/realms/{realm_name}/login"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .expect("build login"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/ui/mfa-otp-challenge")
    );
    find(&cookie_pairs(&response), "hearth_ui_mfa_pending").expect("pending cookie")
}

/// `GET /ui/mfa-otp-challenge[?resend=1]`; returns the challenge cookie it set.
async fn challenge_page(app: &axum::Router, cookies: &str, resend: bool) -> Option<String> {
    let uri = if resend {
        "/ui/mfa-otp-challenge?resend=1"
    } else {
        "/ui/mfa-otp-challenge"
    };
    let response = send(
        app,
        Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::COOKIE, cookies)
            .body(Body::empty())
            .expect("build GET"),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the challenge page renders"
    );
    find(&cookie_pairs(&response), "hearth_ui_mfa_otp")
}

async fn submit_code(app: &axum::Router, cookies: &str, code: &str) -> axum::response::Response {
    send(
        app,
        Request::builder()
            .method("POST")
            .uri("/ui/mfa-otp-challenge")
            .header(header::COOKIE, cookies)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!("code={code}")))
            .expect("build POST"),
    )
    .await
}

// ─── M12 ────────────────────────────────────────────────────────────────────

/// `issue_email_otp` must throttle resends per address, as `issue_sms_otp`
/// does per phone.
#[tokio::test]
async fn email_otp_issuance_is_throttled_per_address() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let (realm, _) = create_realm(&h, RealmConfig::default());
    let sender = Arc::new(CapturingEmailSender::default());
    let service = email_service(&sender);
    let key = b"otp-abuse-test-hmac-key";

    let mut refused = None;
    for attempt in 0..10 {
        match h.identity().issue_email_otp(
            &realm,
            "victim@example.com",
            key,
            &service,
            None,
            now_secs(),
        ) {
            Ok(_) => {}
            Err(e) => {
                refused = Some((attempt, e));
                break;
            }
        }
    }
    let (attempt, err) = refused.expect("a resend limit must stop the issuance");
    assert!(matches!(err, IdentityError::RateLimited), "got {err:?}");
    assert!(
        attempt <= 5,
        "at most five codes per window, refused at {attempt}"
    );
    assert_eq!(sender.count(), attempt, "a refused issuance sends nothing");
}

/// Re-rendering the challenge page must not mint and mail a new code while
/// the one it already issued is outstanding. An explicit resend does.
#[tokio::test]
async fn revisiting_the_otp_challenge_reuses_the_outstanding_code() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let (realm, realm_name) = create_realm(&h, RealmConfig::default());
    let user = email_otp_user(&h, &realm);
    let sender = Arc::new(CapturingEmailSender::default());
    let app = build_web_app(&h, email_service(&sender));

    let pending = pending_cookie(&app, &realm_name, &user).await;
    let challenge = challenge_page(&app, &pending, false)
        .await
        .expect("the first render binds a challenge");
    assert_eq!(sender.count(), 1, "the first render sends one code");

    let both = format!("{pending}; {challenge}");
    let again = challenge_page(&app, &both, false).await;
    assert!(
        again.is_none(),
        "a re-render must keep the outstanding challenge"
    );
    assert_eq!(sender.count(), 1, "a re-render must not send another code");

    let resent = challenge_page(&app, &both, true).await;
    assert!(resent.is_some(), "an explicit resend binds a new challenge");
    assert_eq!(sender.count(), 2, "an explicit resend sends a new code");
}

/// Wrong codes spread across several issued codes share one per-user budget:
/// once it is spent, even the right code is refused.
#[tokio::test]
async fn otp_failures_across_codes_spend_one_per_user_budget() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let (realm, realm_name) = create_realm(&h, RealmConfig::default());
    let user = email_otp_user(&h, &realm);
    let sender = Arc::new(CapturingEmailSender::default());
    let app = build_web_app(&h, email_service(&sender));
    let pending = pending_cookie(&app, &realm_name, &user).await;

    // Three wrong guesses against the first code.
    let first = challenge_page(&app, &pending, false)
        .await
        .expect("challenge");
    let cookies = format!("{pending}; {first}");
    for _ in 0..3 {
        let r = submit_code(&app, &cookies, "000000").await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    }
    // A fresh code, and two more wrong guesses: each code alone allows five.
    let second = challenge_page(&app, &cookies, true).await.expect("resend");
    let cookies = format!("{pending}; {second}");
    for _ in 0..2 {
        let r = submit_code(&app, &cookies, "000000").await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    }

    // Five failures in all: the budget is spent, so the right code is refused.
    let right = sender.last_code();
    let r = submit_code(&app, &cookies, &right).await;
    let status = r.status();
    let set = cookie_pairs(&r);
    let text = String::from_utf8_lossy(&to_bytes(r.into_body(), 1 << 20).await.expect("body"))
        .into_owned();
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "body: {text}");
    assert!(
        find(&set, "hearth_ui_session").is_none(),
        "no session: {set:?}"
    );
}

// ─── L17 ────────────────────────────────────────────────────────────────────

fn rest_app(h: &common::TestHarness, email: Arc<EmailService>) -> axum::Router {
    use hearth::protocol::http::{router, AppState};
    router(Arc::new(
        AppState::new_dev(h.identity_arc(), h.rbac_arc(), h.audit_arc()).with_email(Some(email)),
    ))
}

async fn request_link(app: &axum::Router, realm_name: &str, email: &str) -> StatusCode {
    send(
        app,
        Request::builder()
            .method("POST")
            .uri(format!("/v1/{realm_name}/auth/magic-link"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({ "email": email }).to_string(),
            ))
            .expect("build POST"),
    )
    .await
    .status()
}

/// Every magic-link request counts against the caller's IP, so a flood trips
/// the limiter instead of mailing without end.
#[tokio::test]
async fn magic_link_requests_count_against_the_ip_limit() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let (_, realm_name) = create_realm(&h, RealmConfig::default());
    let sender = Arc::new(CapturingEmailSender::default());
    let app = rest_app(&h, email_service(&sender));

    let mut limited = false;
    for i in 0..50 {
        let status = request_link(&app, &realm_name, &format!("x{i}@example.com")).await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            limited = true;
            break;
        }
        assert_eq!(status, StatusCode::ACCEPTED);
    }
    assert!(
        limited,
        "fifty requests from one address must trip the IP limiter"
    );
}

/// On a realm that cannot create an account from a magic link, a link for an
/// address with no account is not mailed: the endpoint is not a relay.
#[tokio::test]
async fn magic_link_is_not_mailed_to_an_address_that_cannot_sign_in() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let (realm, realm_name) = create_realm(
        &h,
        RealmConfig {
            registration_policy: Some(RegistrationPolicy::Disabled),
            ..RealmConfig::default()
        },
    );
    let known = email_otp_user(&h, &realm);
    let sender = Arc::new(CapturingEmailSender::default());
    let app = rest_app(&h, email_service(&sender));

    assert_eq!(
        request_link(&app, &realm_name, "stranger@example.net").await,
        StatusCode::ACCEPTED,
        "the answer is the same either way"
    );
    assert_eq!(
        request_link(&app, &realm_name, known.email()).await,
        StatusCode::ACCEPTED
    );
    // Delivery runs off the request path; wait for the known address's link.
    for _ in 0..200 {
        if sender.recipients().iter().any(|r| r == known.email()) {
            break;
        }
        tokio::task::yield_now().await;
        std::thread::sleep(std::time::Duration::from_millis(5)); // AUDIT: justified-sleep: delivery runs on the blocking pool; poll for it with a bounded wait
    }
    let recipients = sender.recipients();
    assert!(
        recipients.iter().any(|r| r == known.email()),
        "the account holder gets the link: {recipients:?}"
    );
    assert!(
        !recipients.iter().any(|r| r == "stranger@example.net"),
        "no link may be mailed to an address that cannot sign in: {recipients:?}"
    );
}

// ─── L21: a delivery failure does not carry the recipient into logs ─────────

/// A transport whose rejection names the recipient, as an SMTP server's does.
struct RejectingSender;

impl EmailSender for RejectingSender {
    fn send(&self, message: &EmailMessage) -> Result<(), EmailError> {
        Err(EmailError::Transport {
            reason: format!("550 5.1.1 <{}>: recipient rejected", message.to),
        })
    }
}

/// The error an email-OTP delivery failure returns is logged by every
/// caller, so it must not repeat the full address the server named.
#[tokio::test]
async fn an_email_otp_delivery_failure_masks_the_recipient() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let (realm, _) = create_realm(&h, RealmConfig::default());
    let service = EmailService::new(
        Arc::new(RejectingSender),
        "Hearth".to_string(),
        None,
        EmailBranding::default(),
        String::new(),
        None,
    )
    .expect("email service");
    let err = h
        .identity()
        .issue_email_otp(
            &realm,
            "victim.person@example.com",
            b"otp-abuse-test-hmac-key",
            &service,
            None,
            now_secs(),
        )
        .expect_err("a rejected send fails the issuance");
    let text = err.to_string();
    assert!(
        !text.contains("victim.person@example.com"),
        "the logged error must not carry the full address: {text}"
    );
}
