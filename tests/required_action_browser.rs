//! Required-action flows driven through a real-browser cookie jar outside
//! `--dev`:
//!
//! * every `/required-action/*` form completes, and refuses a forged
//!   cross-site `POST`;
//! * an enrolment or verification action the user has already satisfied is
//!   cleared and the login continues — the page never redirects to itself.
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
#[path = "common/webauthn_helper.rs"]
mod webauthn_helper;

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
    audit: Arc<dyn AuditEngine>,
    realm_name: String,
}

/// A production-mode (`dev_mode = false`) web router over plain HTTP, in a
/// realm offering the second factors `mfa_methods` (each offered factor the
/// user lacks is enrolled as an extra required action, so a test offers only
/// the one it drives).
fn build_rig(mfa_methods: &[&str]) -> Rig {
    build_rig_with(mfa_methods, false)
}

/// [`build_rig`], optionally in a realm that requires a passkey
/// (`webauthn_required`).
fn build_rig_with(mfa_methods: &[&str], webauthn_required: bool) -> Rig {
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
    let realm_name = format!("ra-jar-{}", uuid::Uuid::new_v4().simple());
    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: realm_name.clone(),
            config: Some(RealmConfig {
                mfa_methods: (!mfa_methods.is_empty())
                    .then(|| mfa_methods.iter().map(|m| (*m).to_string()).collect()),
                webauthn_required: webauthn_required.then_some(true),
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
        Arc::clone(&audit),
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
        audit,
        realm_name,
    }
}

/// Creates an active user with `actions` pending and a browser holding the
/// session cookies the login form would have set (their real `Set-Cookie`
/// lines, so the jar applies their `Path`).
fn signed_in_browser(rig: &Rig, email: &str, actions: Vec<RequiredAction>) -> (Browser, UserId) {
    signed_in_browser_with(rig, email, actions, hearth::identity::MfaProof::Proved)
}

/// [`signed_in_browser`] with the login's MFA proof spelled out.
fn signed_in_browser_with(
    rig: &Rig,
    email: &str,
    actions: Vec<RequiredAction>,
    mfa_proof: hearth::identity::MfaProof,
) -> (Browser, UserId) {
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
        .create_session(
            &rig.realm_id,
            user.id(),
            // A signed-in browser: the login proved whatever factors the realm
            // demands (a passkey-requiring realm refuses a session otherwise).
            &SessionContext {
                mfa_proof,
                ..SessionContext::default()
            },
        )
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

// ── Already-satisfied actions never loop ────────────────────────────────────
//
// A pending enrolment or verification action can already be satisfied when
// the page is reached: an operator put it on an account that holds the
// factor, or the user completed it in another tab. `/required-action/enroll-mfa`
// used to redirect to itself in that case — a loop the browser gives up on.
// Each such page now records the action as completed, clears it from the
// account, and continues the login.

/// Enrols TOTP for `user` through the engine, as the account page would.
fn enrol_totp(rig: &Rig, user: &UserId) {
    let enrolment = rig
        .identity
        .enroll_totp(&rig.realm_id, user)
        .expect("start TOTP enrolment");
    rig.identity
        .verify_totp_enrollment(&rig.realm_id, user, &totp_now(&enrolment.secret_base32))
        .expect("confirm TOTP enrolment");
}

fn pending_on_account(rig: &Rig, user: &UserId) -> Vec<RequiredAction> {
    rig.identity
        .get_user(&rig.realm_id, user)
        .expect("lookup")
        .expect("user")
        .required_actions()
        .to_vec()
}

fn auto_cleared_events(rig: &Rig) -> Vec<hearth::audit::AuditEvent> {
    rig.audit
        .query(&hearth::audit::AuditQuery {
            action: Some(hearth::audit::AuditAction::RequiredActionAutoCleared),
            ..hearth::audit::AuditQuery::for_realm(rig.realm_id.clone())
        })
        .expect("audit query")
}

/// GETs the page `page` and asserts it did not answer with a redirect back to
/// itself; returns the response.
async fn get_without_self_redirect(browser: &mut Browser, page: &str) -> axum::response::Response {
    let resp = browser.get(page).await;
    assert_ne!(
        location(&resp).as_deref(),
        Some(page),
        "{page} redirected to itself"
    );
    resp
}

#[tokio::test]
async fn a_totp_holder_with_a_pending_enrol_mfa_continues_the_login() {
    let rig = build_rig(&["totp"]);
    let (mut browser, user) = signed_in_browser(
        &rig,
        "sat-totp@example.com",
        vec![RequiredAction::EnrollMfa],
    );
    enrol_totp(&rig, &user);
    let page = start_flow(&rig, &mut browser).await;
    assert_eq!(page, "/required-action/enroll-mfa");

    let resp = get_without_self_redirect(&mut browser, &page).await;
    assert_flow_finished(&resp);
    assert!(
        !pending_on_account(&rig, &user).contains(&RequiredAction::EnrollMfa),
        "the satisfied action is cleared from the account"
    );
    assert_eq!(
        auto_cleared_events(&rig).len(),
        1,
        "and recorded as completed"
    );
}

#[tokio::test]
async fn a_satisfied_enrol_mfa_hands_over_to_the_next_pending_action() {
    let rig = build_rig(&["totp", "email_otp"]);
    let (mut browser, user) = signed_in_browser(
        &rig,
        "sat-totp-next@example.com",
        vec![RequiredAction::EnrollMfa, RequiredAction::EnrollEmailOtp],
    );
    enrol_totp(&rig, &user);
    let page = start_flow(&rig, &mut browser).await;
    assert_eq!(page, "/required-action/enroll-mfa");

    let resp = get_without_self_redirect(&mut browser, &page).await;
    assert!(resp.status().is_redirection(), "got {}", resp.status());
    let next = "/required-action/ENROLL_EMAIL_OTP";
    assert_eq!(location(&resp).as_deref(), Some(next));

    // The next action works with the cookie the hand-over set.
    let html = open(&mut browser, next).await;
    let resp = submit(
        &mut browser,
        &html,
        "/required-action/ENROLL_EMAIL_OTP/send",
        &[],
    )
    .await;
    let html = body_text(resp).await;
    let code = six_digit_code(&rig.outbox.last_mail());
    let done = submit(
        &mut browser,
        &html,
        "/required-action/ENROLL_EMAIL_OTP/verify",
        &[("code", &code)],
    )
    .await;
    assert_flow_finished(&done);
    assert!(!pending_on_account(&rig, &user).contains(&RequiredAction::EnrollMfa));
}

#[tokio::test]
async fn completing_enrol_mfa_clears_it_from_the_account() {
    let rig = build_rig(&["totp"]);
    let (mut browser, user) = signed_in_browser(
        &rig,
        "sat-totp-clear@example.com",
        vec![RequiredAction::EnrollMfa],
    );
    let page = start_flow(&rig, &mut browser).await;
    let html = open(&mut browser, &page).await;
    let secret = rig
        .identity
        .load_pending_totp_secret(&rig.realm_id, &user)
        .expect("load secret")
        .expect("a pending enrolment");
    let resp = submit(&mut browser, &html, &page, &[("code", &totp_now(&secret))]).await;
    assert_flow_finished(&resp);
    assert!(
        !pending_on_account(&rig, &user).contains(&RequiredAction::EnrollMfa),
        "an enrolled user must not be sent back to enrolment on the next login"
    );
}

#[tokio::test]
async fn a_verified_phone_with_a_pending_phone_enrolment_continues_the_login() {
    let rig = build_rig(&["sms"]);
    let (mut browser, user) = signed_in_browser(
        &rig,
        "sat-phone@example.com",
        vec![RequiredAction::EnrollPhoneOtp],
    );
    rig.identity
        .update_user(
            &rig.realm_id,
            &user,
            &UpdateUserRequest {
                phone_number: Some(Some("+15555550177".to_string())),
                phone_verified: Some(true),
                ..Default::default()
            },
        )
        .expect("verified phone");
    let page = start_flow(&rig, &mut browser).await;
    assert_eq!(page, "/required-action/ENROLL_PHONE_OTP");

    let resp = get_without_self_redirect(&mut browser, &page).await;
    assert_flow_finished(&resp);
    assert!(!pending_on_account(&rig, &user).contains(&RequiredAction::EnrollPhoneOtp));
    assert_eq!(auto_cleared_events(&rig).len(), 1);
}

#[tokio::test]
async fn an_email_otp_holder_with_a_pending_email_otp_enrolment_continues_the_login() {
    let rig = build_rig(&["email_otp"]);
    let (mut browser, user) = signed_in_browser(
        &rig,
        "sat-emailotp@example.com",
        vec![RequiredAction::EnrollEmailOtp],
    );
    rig.identity
        .update_user(
            &rig.realm_id,
            &user,
            &UpdateUserRequest {
                email_otp_enabled: Some(true),
                ..Default::default()
            },
        )
        .expect("email OTP enabled");
    let page = start_flow(&rig, &mut browser).await;
    assert_eq!(page, "/required-action/ENROLL_EMAIL_OTP");

    let resp = get_without_self_redirect(&mut browser, &page).await;
    assert_flow_finished(&resp);
    assert!(!pending_on_account(&rig, &user).contains(&RequiredAction::EnrollEmailOtp));
    assert_eq!(auto_cleared_events(&rig).len(), 1);
    #[allow(clippy::unwrap_used)] // INVARIANT: test-only mutex, never poisoned.
    let mail_count = rig.outbox.mail.lock().unwrap().len();
    assert_eq!(
        mail_count, 0,
        "no enrolment code is sent to an enrolled user"
    );
}

#[tokio::test]
async fn a_verified_email_with_a_pending_verification_continues_the_login() {
    let rig = build_rig(&[]);
    let (mut browser, user) = signed_in_browser(
        &rig,
        "sat-verify@example.com",
        vec![RequiredAction::VerifyEmail],
    );
    let token = rig
        .identity
        .issue_email_verification_token(&rig.realm_id, &user)
        .expect("token");
    rig.identity
        .verify_email_token(&rig.realm_id, &token)
        .expect("verify");
    rig.identity
        .update_user(
            &rig.realm_id,
            &user,
            &UpdateUserRequest {
                required_actions: Some(vec![RequiredAction::VerifyEmail]),
                ..Default::default()
            },
        )
        .expect("re-add the action");
    let page = start_flow(&rig, &mut browser).await;
    assert_eq!(page, "/required-action/VERIFY_EMAIL");

    let resp = get_without_self_redirect(&mut browser, &page).await;
    assert_flow_finished(&resp);
    assert!(!pending_on_account(&rig, &user).contains(&RequiredAction::VerifyEmail));
}

// ── Passkey enrolment during login ──────────────────────────────────────────
//
// A realm that requires a passkey (`webauthn_required`) used to answer a user
// without one with a dead-end 409. The login now registers one: after the
// password (and any existing second factor), `/required-action/enroll-mfa`
// runs a WebAuthn registration with user verification REQUIRED, bound to the
// required-action session, and the session created at the end records
// `ProvedWebAuthn`.

/// The origin and RP ID the server derives for a request with no `Host`.
const ORIGIN: &str = "http://localhost";
const RP_ID: &str = "localhost";
const PASSKEY_PAGE: &str = "/required-action/enroll-mfa";
const PASSKEY_BEGIN: &str = "/required-action/enroll-mfa/passkey/begin";
const PASSKEY_COMPLETE: &str = "/required-action/enroll-mfa/passkey/complete";

/// Creates an active user with a password and nothing else.
fn password_only_user(rig: &Rig, email: &str) -> UserId {
    let user = rig
        .identity
        .create_user(
            &rig.realm_id,
            &CreateUserRequest {
                email: email.to_string(),
                display_name: "Passkey User".to_string(),
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
                ..Default::default()
            },
        )
        .expect("activate");
    user.id().clone()
}

/// Signs in through the realm's login form (CSRF cookie and field, password)
/// and returns the browser and where the login sent it.
async fn log_in(rig: &Rig, email: &str) -> (Browser, String) {
    let mut browser = Browser::new(rig.app.clone());
    let login = format!("/ui/realms/{}/login", rig.realm_name);
    let html = open(&mut browser, &login).await;
    let resp = submit(
        &mut browser,
        &html,
        &login,
        &[("email", email), ("password", PASSWORD)],
    )
    .await;
    assert!(resp.status().is_redirection(), "login: {}", resp.status());
    let next = location(&resp).expect("Location");
    (browser, next)
}

/// The `<meta name="csrf">` token the page's script sends as `X-CSRF-Token`.
fn page_csrf(html: &str) -> String {
    html.split("<meta name=\"csrf\" content=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("the page carries a CSRF token for its script")
        .to_string()
}

fn b64(bytes: &[u8]) -> String {
    data_encoding::BASE64URL_NOPAD.encode(bytes)
}

/// Starts a registration and returns the challenge the server issued.
async fn begin_registration(browser: &mut Browser, csrf: &str) -> Vec<u8> {
    let resp = browser
        .post_json(
            PASSKEY_BEGIN,
            &serde_json::json!({}),
            &[("x-csrf-token", csrf)],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK, "begin");
    let opts: serde_json::Value =
        serde_json::from_str(&body_text(resp).await).expect("options JSON");
    assert_eq!(opts["rp"]["id"], RP_ID, "the RP ID is pinned: {opts}");
    assert_eq!(
        opts["authenticatorSelection"]["userVerification"], "required",
        "a login-time passkey must prove user verification: {opts}"
    );
    data_encoding::BASE64URL_NOPAD
        .decode(opts["challenge"].as_str().expect("challenge").as_bytes())
        .expect("b64 challenge")
}

async fn complete_registration(
    browser: &mut Browser,
    csrf: &str,
    response: &(Vec<u8>, Vec<u8>),
) -> axum::response::Response {
    browser
        .post_json(
            PASSKEY_COMPLETE,
            &serde_json::json!({
                "client_data_json": b64(&response.0),
                "attestation_object": b64(&response.1),
            }),
            &[("x-csrf-token", csrf)],
        )
        .await
}

fn passkeys(rig: &Rig, user: &UserId) -> usize {
    rig.identity
        .list_webauthn_credentials(&rig.realm_id, user)
        .expect("list passkeys")
        .len()
}

/// The `mfa_proof` of the browser session the jar now holds.
fn session_proof(rig: &Rig, browser: &Browser) -> hearth::identity::MfaProof {
    let cookie = browser
        .cookie("hearth_ui_session")
        .expect("a session cookie");
    let session_id = cookie.split('.').next().expect("session id");
    let session_id = hearth::core::SessionId::new(session_id.parse().expect("uuid"));
    rig.identity
        .get_session(&rig.realm_id, &session_id)
        .expect("lookup")
        .expect("session")
        .mfa_proof()
}

#[tokio::test]
async fn a_password_only_user_enrols_a_passkey_during_login() {
    let rig = build_rig_with(&["webauthn"], true);
    let user = password_only_user(&rig, "pk-enrol@example.com");
    let (mut browser, next) = log_in(&rig, "pk-enrol@example.com").await;
    assert_eq!(next, PASSKEY_PAGE, "the login detours to passkey enrolment");

    let html = open(&mut browser, PASSKEY_PAGE).await;
    assert!(
        html.contains("data-ra-passkey"),
        "the page runs the registration"
    );
    let csrf = page_csrf(&html);
    let challenge = begin_registration(&mut browser, &csrf).await;
    let authenticator = webauthn_helper::TestAuthenticator::new(RP_ID);
    let registration = authenticator.build_verified_registration_response(&challenge, ORIGIN);
    let resp = complete_registration(&mut browser, &csrf, &registration).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_str(&body_text(resp).await).expect("completion JSON");
    assert_eq!(
        body["next"], "/ui",
        "the login lands on its destination: {body}"
    );

    assert_eq!(passkeys(&rig, &user), 1, "the passkey is registered");
    assert!(!pending_on_account(&rig, &user).contains(&RequiredAction::EnrollMfa));
    assert!(
        !browser.has_cookie("hearth_ra_session"),
        "the RA session is over"
    );
    assert_eq!(
        session_proof(&rig, &browser),
        hearth::identity::MfaProof::ProvedWebAuthn,
        "the session proved a user-verified passkey"
    );
}

#[tokio::test]
async fn a_totp_holder_in_a_passkey_realm_enrols_a_passkey_too() {
    let rig = build_rig_with(&["totp", "webauthn"], true);
    let (mut browser, user) = signed_in_browser_with(
        &rig,
        "pk-totp@example.com",
        vec![],
        hearth::identity::MfaProof::ProvedWebAuthn,
    );
    enrol_totp(&rig, &user);
    let page = start_flow(&rig, &mut browser).await;
    assert_eq!(page, PASSKEY_PAGE);
    let resp = get_without_self_redirect(&mut browser, &page).await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "TOTP does not satisfy the realm"
    );
    let html = body_text(resp).await;
    let csrf = page_csrf(&html);
    let challenge = begin_registration(&mut browser, &csrf).await;
    let registration = webauthn_helper::TestAuthenticator::new(RP_ID)
        .build_verified_registration_response(&challenge, ORIGIN);
    let resp = complete_registration(&mut browser, &csrf, &registration).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_str(&body_text(resp).await).expect("completion JSON");
    assert!(
        body["next"]
            .as_str()
            .is_some_and(|n| n.starts_with(CALLBACK)),
        "the authorization resumes: {body}"
    );
    assert_eq!(passkeys(&rig, &user), 1);
}

#[tokio::test]
async fn passkey_registration_refuses_requests_without_the_page_token() {
    let rig = build_rig_with(&["webauthn"], true);
    let user = password_only_user(&rig, "pk-csrf@example.com");
    let (mut browser, _) = log_in(&rig, "pk-csrf@example.com").await;
    let html = open(&mut browser, PASSKEY_PAGE).await;
    let csrf = page_csrf(&html);

    let forged = browser
        .post_json(PASSKEY_BEGIN, &serde_json::json!({}), &[])
        .await;
    assert_eq!(
        forged.status(),
        StatusCode::FORBIDDEN,
        "begin without the token"
    );

    let challenge = begin_registration(&mut browser, &csrf).await;
    let registration = webauthn_helper::TestAuthenticator::new(RP_ID)
        .build_verified_registration_response(&challenge, ORIGIN);
    let forged = browser
        .post_json(
            PASSKEY_COMPLETE,
            &serde_json::json!({
                "client_data_json": b64(&registration.0),
                "attestation_object": b64(&registration.1),
            }),
            &[("x-csrf-token", "forged")],
        )
        .await;
    assert_eq!(
        forged.status(),
        StatusCode::FORBIDDEN,
        "complete with a forged token"
    );
    assert_eq!(passkeys(&rig, &user), 0, "nothing was registered");
}

#[tokio::test]
async fn a_passkey_that_does_not_prove_user_verification_is_refused() {
    let rig = build_rig_with(&["webauthn"], true);
    let user = password_only_user(&rig, "pk-uv@example.com");
    let (mut browser, _) = log_in(&rig, "pk-uv@example.com").await;
    let html = open(&mut browser, PASSKEY_PAGE).await;
    let csrf = page_csrf(&html);
    let challenge = begin_registration(&mut browser, &csrf).await;
    // User presence only: a touch, no PIN, no biometric.
    let touch_only = webauthn_helper::TestAuthenticator::new(RP_ID)
        .build_registration_response(&challenge, ORIGIN);
    let resp = complete_registration(&mut browser, &csrf, &touch_only).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(passkeys(&rig, &user), 0);
    assert!(
        browser.has_cookie("hearth_ra_session"),
        "the enrolment is still pending"
    );
}

#[tokio::test]
async fn a_registration_challenge_is_single_use() {
    let rig = build_rig_with(&["webauthn"], true);
    let user = password_only_user(&rig, "pk-replay@example.com");
    let (mut browser, _) = log_in(&rig, "pk-replay@example.com").await;
    let html = open(&mut browser, PASSKEY_PAGE).await;
    let csrf = page_csrf(&html);
    let challenge = begin_registration(&mut browser, &csrf).await;
    let authenticator = webauthn_helper::TestAuthenticator::new(RP_ID);

    // First use of the challenge (refused: presence only) spends it.
    let first = complete_registration(
        &mut browser,
        &csrf,
        &authenticator.build_registration_response(&challenge, ORIGIN),
    )
    .await;
    assert_eq!(first.status(), StatusCode::BAD_REQUEST);
    // Replaying the same challenge, even with a good response, is refused.
    let replay = complete_registration(
        &mut browser,
        &csrf,
        &authenticator.build_verified_registration_response(&challenge, ORIGIN),
    )
    .await;
    assert_eq!(
        replay.status(),
        StatusCode::BAD_REQUEST,
        "a spent challenge"
    );
    assert_eq!(passkeys(&rig, &user), 0);

    // A fresh challenge works.
    let challenge = begin_registration(&mut browser, &csrf).await;
    let ok = complete_registration(
        &mut browser,
        &csrf,
        &authenticator.build_verified_registration_response(&challenge, ORIGIN),
    )
    .await;
    assert_eq!(ok.status(), StatusCode::OK);
    assert_eq!(passkeys(&rig, &user), 1);
}

#[tokio::test]
async fn a_challenge_from_another_required_action_session_is_refused() {
    let rig = build_rig_with(&["webauthn"], true);
    let victim = password_only_user(&rig, "pk-victim@example.com");
    let _attacker = password_only_user(&rig, "pk-attacker@example.com");
    let (mut victim_browser, _) = log_in(&rig, "pk-victim@example.com").await;
    let (mut attacker_browser, _) = log_in(&rig, "pk-attacker@example.com").await;

    let victim_html = open(&mut victim_browser, PASSKEY_PAGE).await;
    let victim_csrf = page_csrf(&victim_html);
    let attacker_html = open(&mut attacker_browser, PASSKEY_PAGE).await;
    let attacker_csrf = page_csrf(&attacker_html);

    // The attacker's challenge, answered in the victim's session.
    let challenge = begin_registration(&mut attacker_browser, &attacker_csrf).await;
    let registration = webauthn_helper::TestAuthenticator::new(RP_ID)
        .build_verified_registration_response(&challenge, ORIGIN);
    let resp = complete_registration(&mut victim_browser, &victim_csrf, &registration).await;
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "bound to the RA session"
    );
    assert_eq!(passkeys(&rig, &victim), 0);
}

/// A realm that requires a passkey but does not offer the `webauthn` method
/// cannot register one: say so plainly, never loop.
#[tokio::test]
async fn a_passkey_realm_that_does_not_offer_passkeys_says_so() {
    let rig = build_rig_with(&["totp"], true);
    let (mut browser, user) = signed_in_browser_with(
        &rig,
        "pk-misconfigured@example.com",
        vec![],
        hearth::identity::MfaProof::ProvedWebAuthn,
    );
    enrol_totp(&rig, &user);
    let page = start_flow(&rig, &mut browser).await;
    let resp = get_without_self_redirect(&mut browser, &page).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let html = body_text(resp).await;
    assert!(
        html.contains("passkey"),
        "the page names what is required: {html}"
    );
    assert_eq!(
        auto_cleared_events(&rig),
        [] as [hearth::audit::AuditEvent; 0]
    );
}

// ── ENROLL_EMAIL_OTP after a magic link (GA sweep 4 round 2) ────────────────

/// The `mfa_proof` of the browser session the jar now holds.
fn jar_session_proof(rig: &Rig, browser: &Browser) -> hearth::identity::MfaProof {
    let cookie = browser
        .cookie("hearth_ui_session")
        .expect("a session cookie");
    let session_id = cookie.split('.').next().expect("session id");
    rig.identity
        .get_session(
            &rig.realm_id,
            &hearth::core::SessionId::new(session_id.parse().expect("uuid")),
        )
        .expect("lookup")
        .expect("session")
        .mfa_proof()
}

/// An active user with `actions` pending and no session.
fn user_with_actions(rig: &Rig, email: &str, actions: Vec<RequiredAction>) {
    let (_unused_browser, user) =
        signed_in_browser_with(rig, email, actions, hearth::identity::MfaProof::None);
    rig.identity
        .revoke_all_user_sessions(&rig.realm_id, &user, None)
        .expect("sign the setup session out");
}

/// Completes the pending `ENROLL_EMAIL_OTP` page the browser was sent to.
async fn enrol_email_otp(rig: &Rig, browser: &mut Browser, page: &str) -> axum::response::Response {
    assert_eq!(page, "/required-action/ENROLL_EMAIL_OTP");
    let html = open(browser, page).await;
    let resp = submit(
        browser,
        &html,
        "/required-action/ENROLL_EMAIL_OTP/send",
        &[],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "the send step");
    let html = body_text(resp).await;
    let code = six_digit_code(&rig.outbox.last_mail());
    submit(
        browser,
        &html,
        "/required-action/ENROLL_EMAIL_OTP/verify",
        &[("code", &code)],
    )
    .await
}

/// A magic link proves the inbox. Enrolling email OTP in the required-action
/// detour that follows proves the same inbox again: one factor, not two —
/// the rule a magic-link login already applies to an email-OTP second factor
/// (D-4). The enrolment used to raise the session to `Proved`.
///
/// Once enrolled, email OTP is a factor the account holds and a magic-link
/// login cannot prove it — exactly where a magic-link login of a user who
/// already holds email OTP stands — so the flow ends without a session.
#[tokio::test]
async fn an_email_otp_enrolled_after_a_magic_link_is_not_a_second_factor() {
    let rig = build_rig(&["email_otp"]);
    let email = "jar-magic-emailotp@example.com";
    user_with_actions(&rig, email, vec![RequiredAction::EnrollEmailOtp]);
    let minted = rig
        .identity
        .request_magic_link(&rig.realm_id, email)
        .expect("mint magic link");

    let mut browser = Browser::new(rig.app.clone());
    let redeem = format!("/ui/realms/{}/magic-link", rig.realm_name);
    browser.accept_set_cookie(
        &format!("hearth_link_token={}; Path=/ui", minted.token()),
        &redeem,
    );
    let binding =
        web::link_token::link_binding(&CookieSecret::from_bytes(COOKIE_SECRET), minted.token());
    browser.accept_set_cookie("hearth_ui_csrf=magic-csrf; Path=/ui", &redeem);
    let resp = browser
        .post_form(
            &redeem,
            &[
                ("link_binding".to_string(), binding),
                ("_csrf".to_string(), "magic-csrf".to_string()),
            ],
        )
        .await;
    let page = location(&resp).expect("the link redirects");
    let resp = enrol_email_otp(&rig, &mut browser, &page).await;

    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a magic link plus an email OTP from the same inbox is one factor: no session"
    );
    assert!(
        !browser.has_cookie("hearth_ui_session"),
        "no session was opened on the strength of the same inbox twice"
    );
}

/// The control: after a password login the same enrolment is a second
/// factor, as it always was.
#[tokio::test]
async fn an_email_otp_enrolled_after_a_password_login_is_a_second_factor() {
    let rig = build_rig(&["email_otp"]);
    let email = "jar-password-emailotp@example.com";
    user_with_actions(&rig, email, vec![RequiredAction::EnrollEmailOtp]);

    let mut browser = Browser::new(rig.app.clone());
    let login = format!("/ui/realms/{}/login", rig.realm_name);
    let html = open(&mut browser, &login).await;
    let mut fields = hidden_fields(&html, &login);
    fields.push(("email".to_string(), email.to_string()));
    fields.push(("password".to_string(), PASSWORD.to_string()));
    let resp = browser.post_form(&login, &fields).await;
    let page = location(&resp).expect("the login redirects");
    let resp = enrol_email_otp(&rig, &mut browser, &page).await;
    assert_eq!(
        location(&resp).as_deref(),
        Some("/ui"),
        "the flow ends in a session"
    );

    assert_eq!(
        jar_session_proof(&rig, &browser),
        hearth::identity::MfaProof::Proved
    );
}
