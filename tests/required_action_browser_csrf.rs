//! Every `/required-action/*` form completes in a real browser outside
//! `--dev`, and refuses a forged cross-site `POST`.
//!
//! These tests never hand-build a `Cookie:` header. They drive each flow
//! through a cookie jar that sends only the cookies a browser would send to
//! the requested path (see `support/browser.rs`). Hand-built headers hid a
//! production bug: `POST /required-action/UPDATE_PASSWORD` demanded the
//! `hearth_ui_csrf` double-submit cookie, which is scoped to `Path=/ui`, so a
//! browser never sent it there and the form could never be submitted.
//!
//! The forms under `/required-action/*` now carry a per-page token bound to
//! the required-action session cookie (an HMAC of it under the cookie
//! secret) in their `_csrf` field. The page can embed it; a cross-site
//! attacker, who can neither read the HttpOnly cookie nor compute the MAC,
//! cannot.

#[path = "support/browser.rs"]
mod browser;

use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use browser::{body_text, hidden_fields, location, Browser};
use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{Clock, RealmId, SystemClock, UserId};
use hearth::identity::email::{EmailBranding, EmailError, EmailMessage, EmailSender, EmailService};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CleartextPassword, ClientTrustLevel, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, OAuthClient, RealmConfig,
    RegisterClientRequest, RequiredAction, SessionContext, SmsError, SmsMessage, SmsSender,
    UpdateUserRequest, UserStatus,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig};

const COOKIE_SECRET: [u8; 32] = [31u8; 32];
const PASSWORD: &str = "browser-jar-password-1";
const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const CALLBACK: &str = "https://app.example.com/cb";

// ── Capturing transports ─────────────────────────────────────────────────────

#[derive(Default)]
struct Outbox {
    sms: Mutex<Vec<String>>,
    mail: Mutex<Vec<String>>,
}

struct CapturingSms(Arc<Outbox>);
impl SmsSender for CapturingSms {
    fn send(&self, message: &SmsMessage) -> Result<(), SmsError> {
        #[allow(clippy::unwrap_used)] // INVARIANT: test-only mutex, never poisoned.
        self.0.sms.lock().unwrap().push(message.body.clone());
        Ok(())
    }
}

struct CapturingMail(Arc<Outbox>);
impl EmailSender for CapturingMail {
    fn send(&self, message: &EmailMessage) -> Result<(), EmailError> {
        #[allow(clippy::unwrap_used)] // INVARIANT: test-only mutex, never poisoned.
        self.0
            .mail
            .lock()
            .unwrap()
            .push(format!("{}\n{}", message.text_body, message.html_body));
        Ok(())
    }
}

impl Outbox {
    fn last_sms(&self) -> String {
        #[allow(clippy::unwrap_used)] // INVARIANT: test-only mutex, never poisoned.
        self.sms
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("an SMS was sent")
    }
    fn last_mail(&self) -> String {
        #[allow(clippy::unwrap_used)] // INVARIANT: test-only mutex, never poisoned.
        self.mail
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("an email was sent")
    }
}

/// The first run of exactly six digits in `text`.
fn six_digit_code(text: &str) -> String {
    let bytes = text.as_bytes();
    (0..bytes.len().saturating_sub(5))
        .find(|&i| {
            bytes[i..i + 6].iter().all(u8::is_ascii_digit)
                && (i == 0 || !bytes[i - 1].is_ascii_digit())
                && bytes.get(i + 6).is_none_or(|b| !b.is_ascii_digit())
        })
        .map(|i| text[i..i + 6].to_string())
        .expect("a six-digit code in the message")
}

// ── Rig ──────────────────────────────────────────────────────────────────────

struct Rig {
    app: axum::Router,
    identity: Arc<dyn IdentityEngine>,
    realm_id: RealmId,
    client: OAuthClient,
    outbox: Arc<Outbox>,
}

/// A production-mode (`dev_mode = false`) web router over plain HTTP, in a
/// realm offering the second factors `mfa_methods` (each offered factor the
/// user lacks is enrolled as an extra required action, so a test offers only
/// the one it drives).
fn build_rig(mfa_methods: &[&str]) -> Rig {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);
    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).expect("storage"),
    );
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let audit: Arc<dyn AuditEngine> = Arc::new(EmbeddedAuditEngine::new(
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
    )) as Arc<dyn RbacEngine>;
    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: format!("ra-jar-{}", uuid::Uuid::new_v4().simple()),
            config: Some(RealmConfig {
                mfa_methods: (!mfa_methods.is_empty())
                    .then(|| mfa_methods.iter().map(|m| (*m).to_string()).collect()),
                ..Default::default()
            }),
        })
        .expect("create realm");
    let client = identity
        .register_client(
            realm.id(),
            &RegisterClientRequest {
                client_name: "Browser Jar App".to_string(),
                redirect_uris: vec![CALLBACK.to_string()],
                require_consent: false,
                grant_types: vec!["authorization_code".to_string()],
                trust_level: ClientTrustLevel::FirstParty,
                ..Default::default()
            },
        )
        .expect("register client");
    let outbox = Arc::new(Outbox::default());
    let email = Arc::new(
        EmailService::new(
            Arc::new(CapturingMail(Arc::clone(&outbox))),
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
        Arc::clone(&email),
        data_dir,
    ));
    let state = WebState::new(
        Arc::clone(&identity),
        rbac,
        audit,
        onboarding,
        CookieSecret::from_bytes(COOKIE_SECRET),
        Some(email),
    )
    .with_dev_mode(false)
    .with_sms(
        Arc::new(CapturingSms(Arc::clone(&outbox))) as _,
        Some(b"browser-jar-sms-key".to_vec()),
    );
    Rig {
        app: web::router(state),
        identity,
        realm_id: realm.id().clone(),
        client,
        outbox,
    }
}

/// Creates an active user with `actions` pending and a browser holding the
/// session cookies the login form would have set (their real `Set-Cookie`
/// lines, so the jar applies their `Path`).
fn signed_in_browser(rig: &Rig, email: &str, actions: Vec<RequiredAction>) -> (Browser, UserId) {
    let user = rig
        .identity
        .create_user(
            &rig.realm_id,
            &CreateUserRequest {
                email: email.to_string(),
                display_name: "Jar User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
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
                required_actions: Some(actions),
                ..Default::default()
            },
        )
        .expect("activate");
    let session = rig
        .identity
        .create_session(&rig.realm_id, user.id(), &SessionContext::default())
        .expect("session");
    let issued = web::auth::issue_auth_cookies(
        &CookieSecret::from_bytes(COOKIE_SECRET),
        &rig.realm_id,
        session.id(),
        false,
    );
    let mut browser = Browser::new(rig.app.clone());
    browser.accept_set_cookie(&issued.session_cookie, "/ui/login");
    browser.accept_set_cookie(&issued.csrf_cookie, "/ui/login");
    (browser, user.id().clone())
}

fn authorize_uri(rig: &Rig) -> String {
    format!(
        "/ui/oauth/authorize?client_id={}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb\
         &response_type=code&scope=openid&state=s&code_challenge={PKCE_CHALLENGE}\
         &code_challenge_method=S256",
        rig.client.client_id().as_uuid()
    )
}

/// Starts the authorization flow and follows it to the first required-action
/// page, returning that page's path.
async fn start_flow(rig: &Rig, browser: &mut Browser) -> String {
    let resp = browser.get(&authorize_uri(rig)).await;
    assert!(
        resp.status().is_redirection(),
        "authorize: {}",
        resp.status()
    );
    let next = location(&resp).expect("Location");
    assert!(
        next.starts_with("/required-action/"),
        "unexpected redirect: {next}"
    );
    next
}

/// GETs `page` and returns its HTML.
async fn open(browser: &mut Browser, page: &str) -> String {
    let resp = browser.get(page).await;
    assert_eq!(resp.status(), StatusCode::OK, "GET {page}");
    body_text(resp).await
}

/// Submits the form posting to `action` on `html`: its hidden fields plus
/// `typed`, the fields a user fills in.
async fn submit(
    browser: &mut Browser,
    html: &str,
    action: &str,
    typed: &[(&str, &str)],
) -> axum::response::Response {
    let mut fields = hidden_fields(html, action);
    fields.extend(
        typed
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string())),
    );
    browser.post_form(action, &fields).await
}

/// Same as [`submit`], but drops the `_csrf` field — the shape of a forged
/// cross-site POST that rides the victim's cookies.
async fn submit_forged(
    browser: &mut Browser,
    html: &str,
    action: &str,
    typed: &[(&str, &str)],
) -> axum::response::Response {
    let mut fields = hidden_fields(html, action);
    fields.retain(|(k, _)| k != "_csrf");
    fields.extend(
        typed
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string())),
    );
    browser.post_form(action, &fields).await
}

/// The action completed: the browser is redirected out of the
/// required-action flow — back to the client with a code, or on to the
/// login's remaining step (an enrolled SMS factor is challenged next).
fn assert_flow_finished(resp: &axum::response::Response) {
    assert!(
        resp.status().is_redirection(),
        "the action must complete, got {}",
        resp.status()
    );
    let next = location(resp).expect("Location");
    assert!(
        next.starts_with(CALLBACK) || next.starts_with("/ui/"),
        "completing the last action leaves the required-action flow, got {next}"
    );
}

fn assert_refused(resp: &axum::response::Response) {
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a POST without the page's token must be refused"
    );
}

// ── UPDATE_PASSWORD ─────────────────────────────────────────────────────────

#[tokio::test]
async fn update_password_completes_in_a_real_browser() {
    let rig = build_rig(&[]);
    let (mut browser, user) = signed_in_browser(
        &rig,
        "jar-pw@example.com",
        vec![RequiredAction::UpdatePassword],
    );
    let page = start_flow(&rig, &mut browser).await;
    assert_eq!(page, "/required-action/UPDATE_PASSWORD");
    let html = open(&mut browser, &page).await;
    let new = "jar-new-password-2";
    let resp = submit(
        &mut browser,
        &html,
        &page,
        &[
            ("current_password", PASSWORD),
            ("new_password", new),
            ("confirm_password", new),
        ],
    )
    .await;
    assert_flow_finished(&resp);
    assert!(rig
        .identity
        .verify_password(
            &rig.realm_id,
            &user,
            &CleartextPassword::from_string(new.to_string())
        )
        .expect("verify"));
}

#[tokio::test]
async fn update_password_refuses_a_forged_post() {
    let rig = build_rig(&[]);
    let (mut browser, user) = signed_in_browser(
        &rig,
        "jar-pw-csrf@example.com",
        vec![RequiredAction::UpdatePassword],
    );
    let page = start_flow(&rig, &mut browser).await;
    let html = open(&mut browser, &page).await;
    let resp = submit_forged(
        &mut browser,
        &html,
        &page,
        &[
            ("current_password", PASSWORD),
            ("new_password", "attacker-password-9"),
            ("confirm_password", "attacker-password-9"),
        ],
    )
    .await;
    assert_refused(&resp);
    assert!(rig
        .identity
        .verify_password(
            &rig.realm_id,
            &user,
            &CleartextPassword::from_string(PASSWORD.to_string())
        )
        .expect("verify"));
}

// ── ENROLL_PHONE_OTP ────────────────────────────────────────────────────────

#[tokio::test]
async fn phone_enrolment_completes_in_a_real_browser() {
    let rig = build_rig(&["sms"]);
    let (mut browser, _user) = signed_in_browser(
        &rig,
        "jar-phone@example.com",
        vec![RequiredAction::EnrollPhoneOtp],
    );
    let page = start_flow(&rig, &mut browser).await;
    assert_eq!(page, "/required-action/ENROLL_PHONE_OTP");
    let html = open(&mut browser, &page).await;
    let send = "/required-action/ENROLL_PHONE_OTP/send";
    let resp = submit(&mut browser, &html, send, &[("phone", "+15555550142")]).await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the send step renders the code form"
    );
    let html = body_text(resp).await;
    let code = six_digit_code(&rig.outbox.last_sms());
    let resp = submit(
        &mut browser,
        &html,
        "/required-action/ENROLL_PHONE_OTP/verify",
        &[("code", &code)],
    )
    .await;
    assert_flow_finished(&resp);
}

#[tokio::test]
async fn phone_enrolment_refuses_forged_posts() {
    let rig = build_rig(&["sms"]);
    let (mut browser, _user) = signed_in_browser(
        &rig,
        "jar-phone-csrf@example.com",
        vec![RequiredAction::EnrollPhoneOtp],
    );
    let page = start_flow(&rig, &mut browser).await;
    let html = open(&mut browser, &page).await;
    let send = "/required-action/ENROLL_PHONE_OTP/send";
    let forged = submit_forged(&mut browser, &html, send, &[("phone", "+15555550143")]).await;
    assert_refused(&forged);
    #[allow(clippy::unwrap_used)] // INVARIANT: test-only mutex, never poisoned.
    let sms_count = rig.outbox.sms.lock().unwrap().len();
    assert_eq!(sms_count, 0, "a forged send must not cost the realm an SMS");

    let resp = submit(&mut browser, &html, send, &[("phone", "+15555550143")]).await;
    let html = body_text(resp).await;
    let code = six_digit_code(&rig.outbox.last_sms());
    let forged = submit_forged(
        &mut browser,
        &html,
        "/required-action/ENROLL_PHONE_OTP/verify",
        &[("code", &code)],
    )
    .await;
    assert_refused(&forged);
}

// ── ENROLL_EMAIL_OTP ────────────────────────────────────────────────────────

#[tokio::test]
async fn email_otp_enrolment_completes_in_a_real_browser() {
    let rig = build_rig(&["email_otp"]);
    let (mut browser, _user) = signed_in_browser(
        &rig,
        "jar-emailotp@example.com",
        vec![RequiredAction::EnrollEmailOtp],
    );
    let page = start_flow(&rig, &mut browser).await;
    assert_eq!(page, "/required-action/ENROLL_EMAIL_OTP");
    let html = open(&mut browser, &page).await;
    let send = "/required-action/ENROLL_EMAIL_OTP/send";
    let resp = submit(&mut browser, &html, send, &[]).await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the send step renders the code form"
    );
    let html = body_text(resp).await;
    let code = six_digit_code(&rig.outbox.last_mail());
    let resp = submit(
        &mut browser,
        &html,
        "/required-action/ENROLL_EMAIL_OTP/verify",
        &[("code", &code)],
    )
    .await;
    assert_flow_finished(&resp);
}

#[tokio::test]
async fn email_otp_enrolment_refuses_forged_posts() {
    let rig = build_rig(&["email_otp"]);
    let (mut browser, _user) = signed_in_browser(
        &rig,
        "jar-emailotp-csrf@example.com",
        vec![RequiredAction::EnrollEmailOtp],
    );
    let page = start_flow(&rig, &mut browser).await;
    let html = open(&mut browser, &page).await;
    let send = "/required-action/ENROLL_EMAIL_OTP/send";
    assert_refused(&submit_forged(&mut browser, &html, send, &[]).await);
    #[allow(clippy::unwrap_used)] // INVARIANT: test-only mutex, never poisoned.
    let mail_count = rig.outbox.mail.lock().unwrap().len();
    assert_eq!(mail_count, 0, "a forged send must not send an email");

    let resp = submit(&mut browser, &html, send, &[]).await;
    let html = body_text(resp).await;
    let code = six_digit_code(&rig.outbox.last_mail());
    let forged = submit_forged(
        &mut browser,
        &html,
        "/required-action/ENROLL_EMAIL_OTP/verify",
        &[("code", &code)],
    )
    .await;
    assert_refused(&forged);
}

// ── enroll-mfa (TOTP) ───────────────────────────────────────────────────────

/// RFC 6238 TOTP (SHA-1, 6 digits, 30 s) for the current time step.
fn totp_now(secret_base32: &str) -> String {
    let secret = data_encoding::BASE32_NOPAD
        .decode(secret_base32.trim_end_matches('=').as_bytes())
        .expect("base32 secret");
    let step = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
        / 30;
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &secret);
    let tag = ring::hmac::sign(&key, &step.to_be_bytes());
    let hash = tag.as_ref();
    let offset = usize::from(hash[hash.len() - 1] & 0x0f);
    let binary = u32::from_be_bytes([
        hash[offset] & 0x7f,
        hash[offset + 1],
        hash[offset + 2],
        hash[offset + 3],
    ]);
    format!("{:06}", binary % 1_000_000)
}

#[tokio::test]
async fn totp_enrolment_completes_in_a_real_browser() {
    let rig = build_rig(&["totp"]);
    let (mut browser, user) = signed_in_browser(
        &rig,
        "jar-totp@example.com",
        vec![RequiredAction::EnrollMfa],
    );
    let page = start_flow(&rig, &mut browser).await;
    assert_eq!(page, "/required-action/enroll-mfa");
    let html = open(&mut browser, &page).await;
    let secret = rig
        .identity
        .load_pending_totp_secret(&rig.realm_id, &user)
        .expect("load secret")
        .expect("a pending enrolment");
    let resp = submit(&mut browser, &html, &page, &[("code", &totp_now(&secret))]).await;
    assert_flow_finished(&resp);
}

#[tokio::test]
async fn totp_enrolment_refuses_a_forged_post() {
    let rig = build_rig(&["totp"]);
    let (mut browser, user) = signed_in_browser(
        &rig,
        "jar-totp-csrf@example.com",
        vec![RequiredAction::EnrollMfa],
    );
    let page = start_flow(&rig, &mut browser).await;
    let html = open(&mut browser, &page).await;
    let secret = rig
        .identity
        .load_pending_totp_secret(&rig.realm_id, &user)
        .expect("load secret")
        .expect("a pending enrolment");
    let forged = submit_forged(&mut browser, &html, &page, &[("code", &totp_now(&secret))]).await;
    assert_refused(&forged);
}

// ── VERIFY_EMAIL (emailed link) ─────────────────────────────────────────────

#[tokio::test]
async fn email_verification_completes_in_a_real_browser() {
    let rig = build_rig(&[]);
    let (mut browser, _user) = signed_in_browser(
        &rig,
        "jar-verify@example.com",
        vec![RequiredAction::VerifyEmail],
    );
    let page = start_flow(&rig, &mut browser).await;
    assert_eq!(page, "/required-action/VERIFY_EMAIL");
    open(&mut browser, &page).await;
    // Follow the emailed link: the first hop moves the token into a cookie.
    let mail = rig.outbox.last_mail();
    let start = mail
        .find("/required-action/VERIFY_EMAIL/confirm?token=")
        .expect("a confirm link in the email");
    let link: String = mail[start..]
        .chars()
        .take_while(|c| !c.is_whitespace() && *c != '"' && *c != '<')
        .collect();
    let hop = browser.get(&link).await;
    assert_eq!(hop.status(), StatusCode::SEE_OTHER);
    let confirm = location(&hop).expect("Location");
    let html = open(&mut browser, &confirm).await;
    let resp = submit(&mut browser, &html, &confirm, &[]).await;
    assert_flow_finished(&resp);
}

// ── The generic `/required-action/{action}` route ───────────────────────────

/// A POST straight to an action's page path must not mark the action done
/// without doing it.
#[tokio::test]
async fn an_action_cannot_be_skipped_by_posting_to_its_page() {
    for (methods, email, action, path) in [
        (
            &[][..],
            "jar-skip-verify@example.com",
            RequiredAction::VerifyEmail,
            "/required-action/VERIFY_EMAIL",
        ),
        (
            &["sms"][..],
            "jar-skip-phone@example.com",
            RequiredAction::EnrollPhoneOtp,
            "/required-action/ENROLL_PHONE_OTP",
        ),
        (
            &["email_otp"][..],
            "jar-skip-emailotp@example.com",
            RequiredAction::EnrollEmailOtp,
            "/required-action/ENROLL_EMAIL_OTP",
        ),
    ] {
        let rig = build_rig(methods);
        let (mut browser, _user) = signed_in_browser(&rig, email, vec![action]);
        let page = start_flow(&rig, &mut browser).await;
        assert_eq!(page, path);
        let html = open(&mut browser, &page).await;
        // Carry the page's own token when it offers one, to be generous to
        // the attacker.
        let token = html
            .split("name=\"_csrf\" value=\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .unwrap_or_default()
            .to_string();
        let resp = browser
            .post_form(path, &[("_csrf".to_string(), token)])
            .await;
        let skipped = location(&resp).is_some_and(|l| l.starts_with(CALLBACK));
        assert!(
            !skipped,
            "POST {path} completed {action:?} without doing it"
        );
    }
}
