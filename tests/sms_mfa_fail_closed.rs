//! SMS MFA must fail closed (GA hardening, "fix/ga-sms").
//!
//! Four defects chained into an OTP leak plus an MFA skip:
//!
//! 1. The default `sms.transport` is `log`, which delivers nothing.
//! 2. YAML validation refused `sms` MFA on the `log` transport, but the two
//!    runtime surfaces that write `mfa_methods` — the JSON admin API
//!    (`PATCH /admin/realms/{id}/config`) and the admin console
//!    (`PATCH /ui/admin/realms/{realm}/config`) — accepted it, and did not
//!    check the method names at all.
//! 3. `LoggingSmsSender` logged the whole body, OTP included, at WARN.
//! 4. With no `HEARTH_SMS_OTP_HMAC_KEY` the handlers HMAC'd codes under an
//!    all-zero key, and a missing transport made the challenge step return
//!    "no challenge needed", so the login went through without the factor.
//!
//! These tests drive the public HTTP surfaces and the authorize intercept.

mod common;

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{header, Request, Response, StatusCode};
use hearth::audit::AuditEngine;
use hearth::config::SmsTransport;
use hearth::core::{Clock, RealmId, SessionId, SystemClock, Timestamp, UserId};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, RealmConfig, SessionContext, SmsError,
    SmsMessage, SmsSender, UpdateUserRequest, UserStatus,
};
use hearth::protocol::http::{router, AppState};
use hearth::protocol::web::auth::{MFA_OTP_COOKIE, MFA_PENDING_COOKIE, SESSION_COOKIE};
use hearth::protocol::web::oauth_consent::AuthorizeQuery;
use hearth::protocol::web::sms_challenge::sms_mfa_challenge_check;
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{AssignRoleRequest, EmbeddedRbacEngine, RbacEngine, Scope, Subject};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use tower::ServiceExt as _;

const COOKIE_SECRET: [u8; 32] = [57u8; 32];
const CSRF: &str = "sms-fail-closed-csrf";
const USER_EMAIL: &str = "sms-user@fail-closed.test";
const PHONE: &str = "+15555550142";

fn password() -> String {
    ["sms", "fail", "closed", "pass"].join("-")
}

// ---------------------------------------------------------------------------
// Capturing SMS sender
// ---------------------------------------------------------------------------

struct CapturingSms {
    messages: Mutex<Vec<SmsMessage>>,
}

impl CapturingSms {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            messages: Mutex::new(Vec::new()),
        })
    }

    fn sent(&self) -> usize {
        #[allow(clippy::unwrap_used)]
        self.messages.lock().unwrap().len()
    }

    /// The 6-digit code in the most recent message.
    fn last_code(&self) -> String {
        #[allow(clippy::unwrap_used)]
        let guard = self.messages.lock().unwrap();
        let body = guard.last().expect("an SMS was sent").body.clone();
        let (_, code) = body.rsplit_once(": ").expect("code in body");
        code.trim().to_string()
    }
}

impl SmsSender for CapturingSms {
    fn send(&self, message: &SmsMessage) -> Result<(), SmsError> {
        #[allow(clippy::unwrap_used)]
        self.messages.lock().unwrap().push(message.clone());
        Ok(())
    }
}

fn null_email() -> Arc<EmailService> {
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

// ===========================================================================
// JSON admin API — PATCH /admin/realms/{id}/config
// ===========================================================================

async fn json_admin_token(h: &common::TestHarness, realm: &RealmId) -> String {
    let user = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: "admin@sms-guard.test".into(),
                display_name: "Admin".into(),
                first_name: "Admin".into(),
                last_name: "User".into(),
                attributes: Default::default(),
            },
        )
        .expect("create admin");
    let role = h
        .rbac()
        .get_role_by_name(realm, "realm.admin")
        .expect("lookup role")
        .expect("realm.admin seeded");
    h.rbac()
        .assign_role(
            realm,
            &AssignRoleRequest {
                subject: Subject::User(user.id().clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign admin role");
    let session = h
        .identity()
        .create_session(realm, user.id(), &SessionContext::default())
        .expect("session");
    h.identity()
        .issue_tokens(realm, user.id(), session.id())
        .expect("issue tokens")
        .access_token()
        .to_string()
}

async fn json_patch_mfa(
    state: AppState,
    h: &common::TestHarness,
    body: &str,
) -> (StatusCode, RealmId) {
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = json_admin_token(h, &realm).await;
    let realm_uuid = realm.as_uuid().to_string();
    let resp = router(Arc::new(state))
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/admin/realms/{realm_uuid}/config"))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm_uuid)
                .header("Content-Type", "application/json")
                .body(Body::from(body.to_string()))
                .expect("build request"),
        )
        .await
        .expect("oneshot");
    (resp.status(), realm)
}

fn stored_mfa_methods(h: &common::TestHarness, realm: &RealmId) -> Option<Vec<String>> {
    h.identity()
        .get_realm(realm)
        .expect("get_realm")
        .expect("realm exists")
        .config()
        .mfa_methods
        .clone()
}

/// A production server on the `log` transport cannot deliver a code, so the
/// JSON admin API must refuse to turn SMS MFA on — exactly as the YAML
/// validator already does.
#[tokio::test]
async fn json_admin_api_refuses_sms_mfa_on_the_log_transport_outside_dev() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let state = AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc());
    let (status, realm) = json_patch_mfa(state, &h, r#"{"mfa_methods":["totp","sms"]}"#).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "enabling sms MFA with no deliverable transport must be a 4xx"
    );
    assert_eq!(
        stored_mfa_methods(&h, &realm),
        None,
        "a refused PATCH must not have written mfa_methods"
    );
}

/// Unknown method names were stored verbatim by the JSON admin API.
#[tokio::test]
async fn json_admin_api_refuses_an_unknown_mfa_method() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let state = AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc())
        .with_sms_transport(SmsTransport::Twilio);
    let (status, realm) =
        json_patch_mfa(state, &h, r#"{"mfa_methods":["totp","carrier_pigeon"]}"#).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(stored_mfa_methods(&h, &realm), None);
}

/// Control: a real transport makes SMS MFA deliverable, so the same PATCH is
/// accepted — the refusal above is about the transport, not about `sms`.
#[tokio::test]
async fn json_admin_api_accepts_sms_mfa_with_a_real_transport() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let state = AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc())
        .with_sms_transport(SmsTransport::Twilio);
    let (status, realm) = json_patch_mfa(state, &h, r#"{"mfa_methods":["totp","sms"]}"#).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        stored_mfa_methods(&h, &realm),
        Some(vec!["totp".to_string(), "sms".to_string()])
    );
}

/// Dev mode logs the full SMS body, so the `log` transport *does* deliver
/// the code to the developer there.
#[tokio::test]
async fn json_admin_api_accepts_sms_mfa_on_the_log_transport_in_dev() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let state = AppState::new_dev(h.identity_arc(), h.rbac_arc(), h.audit_arc());
    let (status, _) = json_patch_mfa(state, &h, r#"{"mfa_methods":["sms"]}"#).await;
    assert_eq!(status, StatusCode::OK);
}

// ===========================================================================
// Admin console — PATCH /ui/admin/realms/{realm}/config
// ===========================================================================

struct Engines {
    identity: Arc<dyn IdentityEngine>,
    rbac: Arc<dyn RbacEngine>,
    audit: Arc<dyn AuditEngine>,
    data_dir: std::path::PathBuf,
}

fn engines() -> Engines {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);
    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).expect("storage"),
    );
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let audit = Arc::new(hearth::audit::EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn AuditEngine>;
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
        .expect("identity"),
    ) as Arc<dyn IdentityEngine>;
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn RbacEngine>;
    Engines {
        identity,
        rbac,
        audit,
        data_dir,
    }
}

fn web_state(e: &Engines) -> WebState {
    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&e.identity),
        Arc::clone(&e.rbac),
        null_email(),
        e.data_dir.clone(),
    ));
    WebState::new(
        Arc::clone(&e.identity),
        Arc::clone(&e.rbac),
        Arc::clone(&e.audit),
        onboarding,
        CookieSecret::from_bytes(COOKIE_SECRET),
        Some(null_email()),
    )
}

/// Seeds a system-realm admin and a tenant realm; returns the admin cookie
/// header and the tenant realm id.
fn console_admin(e: &Engines, tenant_name: &str) -> (String, RealmId) {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let system_realm_id = RealmId::new(uuid::Uuid::nil());
    e.rbac.seed_realm(&system_realm_id).expect("seed system");
    let admin = e
        .identity
        .create_admin_user(&CreateUserRequest {
            email: "console-admin@sms-guard.test".to_string(),
            display_name: "ConsoleAdmin".to_string(),
            first_name: String::new(),
            last_name: String::new(),
            attributes: Default::default(),
        })
        .expect("create admin");
    e.identity
        .update_user(
            &system_realm_id,
            admin.id(),
            &UpdateUserRequest {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .expect("activate");
    let role = e
        .rbac
        .get_role_by_name(&system_realm_id, "realm.admin")
        .expect("lookup")
        .expect("seeded");
    e.rbac
        .assign_role(
            &system_realm_id,
            &AssignRoleRequest {
                subject: Subject::User(admin.id().clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign");
    let session = e
        .identity
        .create_session(&system_realm_id, admin.id(), &SessionContext::default())
        .expect("session");
    let session_id: SessionId = session.id().clone();

    let tenant = e
        .identity
        .create_realm(&CreateRealmRequest {
            name: tenant_name.to_string(),
            config: None,
        })
        .expect("realm");

    let mut mac = <Hmac<Sha256>>::new_from_slice(&COOKIE_SECRET).expect("key");
    mac.update(session_id.as_uuid().as_bytes());
    mac.update(b"|");
    mac.update(system_realm_id.as_uuid().as_bytes());
    let tag = data_encoding::BASE64URL_NOPAD.encode(&mac.finalize().into_bytes());
    let cookie = format!(
        "hearth_ui_session={}.{}.{}; hearth_ui_csrf={CSRF}",
        session_id.as_uuid(),
        system_realm_id.as_uuid(),
        tag,
    );
    (cookie, tenant.id().clone())
}

async fn console_patch_mfa(
    configure: impl FnOnce(WebState) -> WebState,
    body: &str,
) -> (StatusCode, Option<Vec<String>>) {
    let e = engines();
    let tenant_name = "smsguard";
    let (cookie, tenant_id) = console_admin(&e, tenant_name);
    let app = web::router(configure(web_state(&e)));
    let resp = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/ui/admin/realms/{tenant_name}/config"))
                .header(header::COOKIE, cookie)
                .header("x-csrf-token", CSRF)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .expect("build"),
        )
        .await
        .expect("oneshot");
    let stored = e
        .identity
        .get_realm(&tenant_id)
        .expect("get_realm")
        .expect("realm")
        .config()
        .mfa_methods
        .clone();
    (resp.status(), stored)
}

#[tokio::test]
async fn admin_console_refuses_sms_mfa_on_the_log_transport_outside_dev() {
    let (status, stored) = console_patch_mfa(|s| s, r#"{"mfa_methods":["sms"]}"#).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the console must refuse sms MFA that cannot be delivered"
    );
    assert_eq!(stored, None, "a refused PATCH must not write mfa_methods");
}

#[tokio::test]
async fn admin_console_refuses_an_unknown_mfa_method() {
    let (status, stored) = console_patch_mfa(
        |s| s.with_sms_transport(SmsTransport::Twilio),
        r#"{"mfa_methods":["totp","carrier_pigeon"]}"#,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(stored, None);
}

#[tokio::test]
async fn admin_console_accepts_sms_mfa_with_a_real_transport() {
    let (status, stored) = console_patch_mfa(
        |s| s.with_sms_transport(SmsTransport::Twilio),
        r#"{"mfa_methods":["sms"]}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(stored, Some(vec!["sms".to_string()]));
}

#[tokio::test]
async fn admin_console_accepts_sms_mfa_on_the_log_transport_in_dev() {
    let (status, _) =
        console_patch_mfa(|s| s.with_dev_mode(true), r#"{"mfa_methods":["sms"]}"#).await;
    assert_eq!(status, StatusCode::OK);
}

// ===========================================================================
// Browser login — the SMS factor must not be skipped
// ===========================================================================

struct LoginRig {
    app: axum::Router,
    state: Arc<WebState>,
    realm_id: RealmId,
    user_id: UserId,
    sms: Arc<CapturingSms>,
}

/// A realm offering only `sms` and a user with a verified phone and no TOTP.
/// `configure` decides what SMS wiring the web tier gets.
fn login_rig(configure: impl FnOnce(WebState, Arc<CapturingSms>) -> WebState) -> LoginRig {
    login_rig_with_mfa(Some(vec!["sms".to_string()]), configure)
}

/// [`login_rig`] with the realm's `mfa_methods` chosen by the caller (`None`
/// = the realm restricts nothing and requires no SMS factor).
fn login_rig_with_mfa(
    mfa_methods: Option<Vec<String>>,
    configure: impl FnOnce(WebState, Arc<CapturingSms>) -> WebState,
) -> LoginRig {
    let e = engines();
    let realm = e
        .identity
        .create_realm(&CreateRealmRequest {
            name: format!("sms-fc-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                mfa_methods,
                ..RealmConfig::default()
            }),
        })
        .expect("realm");
    let user = e
        .identity
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: USER_EMAIL.to_string(),
                display_name: "Sam".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("user");
    e.identity
        .set_password(
            realm.id(),
            user.id(),
            &CleartextPassword::from_string(password()),
        )
        .expect("password");
    e.identity
        .update_user(
            realm.id(),
            user.id(),
            &UpdateUserRequest {
                status: Some(UserStatus::Active),
                phone_number: Some(Some(PHONE.to_string())),
                phone_verified: Some(true),
                ..Default::default()
            },
        )
        .expect("verify phone");

    let sms = CapturingSms::new();
    let state = configure(web_state(&e), Arc::clone(&sms))
        .with_default_realm(Some(realm.name().to_string()));
    let app = web::router(state.clone());
    LoginRig {
        app,
        state: Arc::new(state),
        realm_id: realm.id().clone(),
        user_id: user.id().clone(),
        sms,
    }
}

fn has_cookie(resp: &Response<Body>, name: &str) -> bool {
    resp.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.starts_with(&format!("{name}=")) && !v.contains("Max-Age=0"))
}

fn cookie_pair(resp: &Response<Body>, name: &str) -> Option<String> {
    resp.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with(&format!("{name}=")))
        .map(|v| v.split(';').next().unwrap_or("").to_string())
}

async fn post_login(rig: &LoginRig) -> Response<Body> {
    post_login_as(rig, USER_EMAIL).await
}

async fn post_login_as(rig: &LoginRig, email: &str) -> Response<Body> {
    let page = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/login")
                .body(Body::empty())
                .expect("build login GET"),
        )
        .await
        .expect("login page");
    let csrf_cookie = cookie_pair(&page, "hearth_ui_csrf").expect("csrf cookie");
    let html = String::from_utf8_lossy(
        &axum::body::to_bytes(page.into_body(), 1 << 20)
            .await
            .expect("body"),
    )
    .into_owned();
    let marker = r#"name="_csrf" value=""#;
    let start = html.find(marker).expect("_csrf field") + marker.len();
    let end = start + html[start..].find('"').expect("unterminated _csrf");
    let csrf_field = &html[start..end];

    rig.app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, csrf_cookie)
                .body(Body::from(format!(
                    "email={email}&password={}&_csrf={csrf_field}",
                    password()
                )))
                .expect("build login POST"),
        )
        .await
        .expect("login")
}

/// With no SMS transport wired, the login used to treat the enrolled SMS
/// factor as absent and issue the session — a password-only login for a user
/// who had enrolled a second factor. It must route to the challenge instead.
#[tokio::test]
async fn login_without_an_sms_transport_does_not_skip_the_enrolled_sms_factor() {
    let rig = login_rig(|s, _| s);
    let resp = post_login(&rig).await;
    assert!(
        !has_cookie(&resp, SESSION_COOKIE),
        "a user with an enrolled SMS factor must not get a session on the password alone"
    );
    assert_eq!(
        resp.headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/ui/mfa-otp-challenge"),
        "the SMS factor must still be challenged (and fail closed there)"
    );
}

/// With a transport but no `HEARTH_SMS_OTP_HMAC_KEY`, the challenge used to
/// HMAC the code under an all-zero key. It must now refuse to issue a code.
#[tokio::test]
async fn login_otp_challenge_without_an_hmac_key_sends_no_code_and_no_session() {
    let rig = login_rig(|s, sms| s.with_sms(sms as _, None));
    let resp = post_login(&rig).await;
    assert!(!has_cookie(&resp, SESSION_COOKIE));
    let pending = cookie_pair(&resp, MFA_PENDING_COOKIE).expect("pending cookie");

    let challenge = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/mfa-otp-challenge")
                .header(header::COOKIE, pending)
                .body(Body::empty())
                .expect("build challenge GET"),
        )
        .await
        .expect("challenge");
    assert!(!has_cookie(&challenge, SESSION_COOKIE));
    assert_eq!(
        rig.sms.sent(),
        0,
        "no OTP may be issued under a missing (formerly all-zero) HMAC key"
    );
}

/// Control: with a key configured the same challenge does send a code, so the
/// zero above is the missing key and not a broken rig.
#[tokio::test]
async fn login_otp_challenge_with_an_hmac_key_sends_a_code() {
    let rig = login_rig(|s, sms| {
        s.with_sms(sms as _, Some(b"0123456789abcdef0123456789abcdef".to_vec()))
    });
    let resp = post_login(&rig).await;
    let pending = cookie_pair(&resp, MFA_PENDING_COOKIE).expect("pending cookie");
    let _ = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/mfa-otp-challenge")
                .header(header::COOKIE, pending)
                .body(Body::empty())
                .expect("build challenge GET"),
        )
        .await
        .expect("challenge");
    assert_eq!(rig.sms.sent(), 1);
}

// ===========================================================================
// Authorize intercept — sms_mfa_challenge_check
// ===========================================================================

fn authorize_query() -> AuthorizeQuery {
    serde_json::from_value(serde_json::json!({
        "client_id": uuid::Uuid::new_v4().to_string(),
        "redirect_uri": "https://app.example.com/cb",
        "response_type": "code",
        "scope": "openid",
        "state": "st",
    }))
    .expect("query")
}

fn assert_denied(resp: Option<axum::response::Response>, what: &str) {
    let Some(resp) = resp else {
        panic!("{what}: `None` means \"no challenge needed\" — the SMS factor was skipped");
    };
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        !loc.starts_with("https://app.example.com/cb"),
        "{what}: must not return to the client with a code; got {loc}"
    );
    assert_ne!(
        loc, "/ui/sms-challenge",
        "{what}: must not start a challenge it cannot back with a keyed OTP"
    );
}

#[tokio::test]
async fn authorize_intercept_without_an_hmac_key_denies() {
    let rig = login_rig(|s, sms| s.with_sms(sms as _, None));
    let resp = sms_mfa_challenge_check(
        &rig.state,
        &rig.realm_id,
        &rig.user_id,
        &authorize_query(),
        &axum::http::HeaderMap::new(),
        Timestamp::from_micros(0),
        false,
    );
    assert_denied(resp, "missing HMAC key");
    assert_eq!(rig.sms.sent(), 0, "no OTP may be sent without a key");
}

#[tokio::test]
async fn authorize_intercept_without_an_sms_transport_denies() {
    let rig = login_rig(|s, _| s);
    let resp = sms_mfa_challenge_check(
        &rig.state,
        &rig.realm_id,
        &rig.user_id,
        &authorize_query(),
        &axum::http::HeaderMap::new(),
        Timestamp::from_micros(0),
        false,
    );
    assert_denied(resp, "missing SMS transport");
}

/// Control: fully wired, the intercept starts the challenge.
#[tokio::test]
async fn authorize_intercept_with_key_and_transport_starts_the_challenge() {
    let rig = login_rig(|s, sms| {
        s.with_sms(sms as _, Some(b"0123456789abcdef0123456789abcdef".to_vec()))
    });
    let resp = sms_mfa_challenge_check(
        &rig.state,
        &rig.realm_id,
        &rig.user_id,
        &authorize_query(),
        &axum::http::HeaderMap::new(),
        Timestamp::from_micros(0),
        false,
    )
    .expect("the intercept must fire");
    assert_eq!(
        resp.headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/ui/sms-challenge")
    );
    assert_eq!(rig.sms.sent(), 1);
}

// ===========================================================================
// JSON admin API — shape errors in `mfa_methods`
// ===========================================================================

/// A non-string entry used to be dropped silently, so the stored list was not
/// the list the operator sent. It is refused — even on a real transport, so
/// the refusal is about the shape and nothing else.
#[tokio::test]
async fn json_admin_api_refuses_a_non_string_mfa_method_entry() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let state = AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc())
        .with_sms_transport(SmsTransport::Twilio);
    let (status, realm) = json_patch_mfa(state, &h, r#"{"mfa_methods":["totp",5]}"#).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(stored_mfa_methods(&h, &realm), None);
}

/// A scalar where a list belongs used to be ignored (the PATCH answered 200
/// and changed nothing). It is refused.
#[tokio::test]
async fn json_admin_api_refuses_a_non_array_mfa_methods() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let state = AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc())
        .with_sms_transport(SmsTransport::Twilio);
    let (status, realm) = json_patch_mfa(state, &h, r#"{"mfa_methods":"sms"}"#).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(stored_mfa_methods(&h, &realm), None);
}

// ===========================================================================
// Shared helpers for the OTP surfaces below
// ===========================================================================

const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";
/// The key the handlers used to substitute when none was loaded.
const OLD_ZERO_KEY: [u8; 32] = [0u8; 32];
const OTHER_EMAIL: &str = "other-user@fail-closed.test";
const OTHER_PHONE: &str = "+15555550199";
const REDIRECT: &str = "https://app.example.com/cb";

/// S256 challenge for a fixed verifier — the test clients are public, and a
/// public client must use PKCE.
fn pkce_challenge() -> String {
    data_encoding::BASE64URL_NOPAD.encode(
        ring::digest::digest(
            &ring::digest::SHA256,
            b"verifier-verifier-verifier-verifier-4",
        )
        .as_ref(),
    )
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Adds a second active user with its own verified phone to the rig's realm.
fn add_sms_user(rig: &LoginRig, email: &str, phone: &str) -> UserId {
    let user = rig
        .state
        .identity
        .create_user(
            &rig.realm_id,
            &CreateUserRequest {
                email: email.to_string(),
                display_name: "Other".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("user");
    rig.state
        .identity
        .set_password(
            &rig.realm_id,
            user.id(),
            &CleartextPassword::from_string(password()),
        )
        .expect("password");
    rig.state
        .identity
        .update_user(
            &rig.realm_id,
            user.id(),
            &UpdateUserRequest {
                status: Some(UserStatus::Active),
                phone_number: Some(Some(phone.to_string())),
                phone_verified: Some(true),
                ..Default::default()
            },
        )
        .expect("verify phone");
    user.id().clone()
}

fn html_field(html: &str, name: &str) -> String {
    let marker = format!(r#"name="{name}" value=""#);
    let start = html.find(&marker).unwrap_or_else(|| panic!("{name} field")) + marker.len();
    let end = start + html[start..].find('"').expect("unterminated value");
    html[start..end].to_string()
}

async fn body_string(resp: Response<Body>) -> String {
    String::from_utf8_lossy(
        &axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("body"),
    )
    .into_owned()
}

/// Password step for `email`, then the challenge page; returns the pending
/// cookie pair and the challenge cookie pair the page set.
async fn start_otp_login(rig: &LoginRig, email: &str) -> (String, String) {
    let resp = post_login_as(rig, email).await;
    let pending = cookie_pair(&resp, MFA_PENDING_COOKIE).expect("pending cookie");
    let page = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ui/mfa-otp-challenge")
                .header(header::COOKIE, pending.clone())
                .body(Body::empty())
                .expect("build challenge GET"),
        )
        .await
        .expect("challenge");
    assert_eq!(page.status(), StatusCode::OK, "challenge page renders");
    let otp = cookie_pair(&page, MFA_OTP_COOKIE)
        .expect("the challenge page must bind the OTP it issued to a server-signed cookie");
    let html = body_string(page).await;
    assert!(
        !html.contains(r#"name="otp_nonce""#) && !html.contains(r#"name="factor""#),
        "the OTP handle and factor must not round-trip through the form"
    );
    (pending, otp)
}

/// POSTs the OTP challenge form. `cookies` is the cookie header minus the
/// CSRF cookie; `extra` is appended to the form body verbatim — client-chosen
/// fields the server must ignore.
async fn submit_login_otp(
    rig: &LoginRig,
    cookies: &str,
    code: &str,
    extra: &str,
) -> Response<Body> {
    rig.app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/mfa-otp-challenge")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, format!("{cookies}; hearth_ui_csrf={CSRF}"))
                .body(Body::from(format!("code={code}&_csrf={CSRF}{extra}")))
                .expect("build challenge POST"),
        )
        .await
        .expect("challenge submit")
}

/// The login OTP challenge cookie, MAC'd exactly as the challenge page does.
/// Only for a test that needs an OTP the page itself would refuse to issue.
fn forge_mfa_otp_cookie(pending_pair: &str, factor: &str, otp_nonce: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let (_, value) = pending_pair.split_once('=').expect("cookie pair");
    let parts: Vec<&str> = value.split('.').collect();
    let user = uuid::Uuid::parse_str(parts[0]).expect("user uuid");
    let realm = uuid::Uuid::parse_str(parts[1]).expect("realm uuid");
    let pending_nonce = parts[4];
    let mut mac = <Hmac<Sha256>>::new_from_slice(&COOKIE_SECRET).expect("key");
    mac.update(b"hearth-mfa-otp|");
    mac.update(user.as_bytes());
    mac.update(b"|");
    mac.update(realm.as_bytes());
    mac.update(b"|");
    mac.update(pending_nonce.as_bytes());
    mac.update(b"|");
    mac.update(factor.as_bytes());
    mac.update(b"|");
    mac.update(otp_nonce.as_bytes());
    let tag = data_encoding::BASE64URL_NOPAD.encode(&mac.finalize().into_bytes());
    format!("{MFA_OTP_COOKIE}={factor}.{otp_nonce}.{tag}")
}

fn clears_cookie(resp: &Response<Body>, name: &str) -> bool {
    resp.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.starts_with(&format!("{name}=;")) && v.contains("Max-Age=0"))
}

// ===========================================================================
// Login OTP — the code proves the PENDING user's factor, via server state
// ===========================================================================

/// Someone who knows the victim's password and holds their own account in the
/// same realm obtains a genuine code for THEMSELVES, then presents it — with
/// their own challenge cookie — on the victim's pending login. Neither the OTP
/// record nor the form named the victim, so it verified as the victim.
#[tokio::test]
async fn login_otp_issued_to_another_user_does_not_pass_the_victims_challenge() {
    let rig = login_rig(|s, sms| s.with_sms(sms as _, Some(KEY.to_vec())));
    add_sms_user(&rig, OTHER_EMAIL, OTHER_PHONE);

    // Attacker: their own login, their own genuine code.
    let (_own_pending, own_otp) = start_otp_login(&rig, OTHER_EMAIL).await;
    let own_code = rig.sms.last_code();

    // Victim: password step only (the attacker knows the password).
    let victim = post_login_as(&rig, USER_EMAIL).await;
    let victim_pending = cookie_pair(&victim, MFA_PENDING_COOKIE).expect("pending cookie");

    let resp = submit_login_otp(
        &rig,
        &format!("{victim_pending}; {own_otp}"),
        &own_code,
        "&factor=sms",
    )
    .await;
    assert!(
        !has_cookie(&resp, SESSION_COOKIE),
        "an OTP sent to another user's phone must not prove the victim's factor"
    );
}

/// Control: the user's own code completes the login with nothing but the code
/// in the form, and the challenge cookie is cleared with the pending one.
#[tokio::test]
async fn login_otp_issued_to_the_user_completes_the_login() {
    let rig = login_rig(|s, sms| s.with_sms(sms as _, Some(KEY.to_vec())));
    let (pending, otp) = start_otp_login(&rig, USER_EMAIL).await;
    let code = rig.sms.last_code();
    let resp = submit_login_otp(&rig, &format!("{pending}; {otp}"), &code, "").await;
    assert!(has_cookie(&resp, SESSION_COOKIE), "own code must log in");
    assert!(
        clears_cookie(&resp, MFA_OTP_COOKIE),
        "the spent challenge cookie must be cleared"
    );
}

/// The form used to name the pending OTP record (`otp_nonce`), so the client
/// chose which record the typed code was checked against. A code obtained for
/// the same phone by any other route then passed the login challenge. The
/// record must come from the server-signed challenge cookie only.
#[tokio::test]
async fn login_otp_submit_ignores_a_form_supplied_nonce() {
    let rig = login_rig(|s, sms| s.with_sms(sms as _, Some(KEY.to_vec())));
    let (pending, otp) = start_otp_login(&rig, USER_EMAIL).await;
    let challenge_code = rig.sms.last_code();

    // A second, genuine OTP for the same phone that the challenge never issued.
    let other_nonce = rig
        .state
        .identity
        .issue_sms_otp(&rig.realm_id, PHONE, KEY, rig.sms.as_ref(), now_secs())
        .expect("issue a second OTP");
    let other_code = rig.sms.last_code();
    let cookies = format!("{pending}; {otp}");

    let resp = submit_login_otp(
        &rig,
        &cookies,
        &other_code,
        &format!("&factor=sms&otp_nonce={other_nonce}"),
    )
    .await;
    assert!(
        !has_cookie(&resp, SESSION_COOKIE),
        "a client-chosen OTP record must not complete the challenge"
    );

    // The record the challenge bound still verifies its own code.
    let resp = submit_login_otp(
        &rig,
        &cookies,
        &challenge_code,
        &format!("&otp_nonce={other_nonce}"),
    )
    .await;
    assert!(
        has_cookie(&resp, SESSION_COOKIE),
        "the server-bound OTP record must be the one checked"
    );
}

/// The form used to name the factor too. The server-side factor wins: the
/// user is challenged on SMS, so SMS is verified whatever the form claims.
#[tokio::test]
async fn login_otp_submit_ignores_a_form_supplied_factor() {
    let rig = login_rig(|s, sms| s.with_sms(sms as _, Some(KEY.to_vec())));
    let (pending, otp) = start_otp_login(&rig, USER_EMAIL).await;
    let code = rig.sms.last_code();
    let resp = submit_login_otp(
        &rig,
        &format!("{pending}; {otp}"),
        &code,
        "&factor=email_otp",
    )
    .await;
    assert!(
        has_cookie(&resp, SESSION_COOKIE),
        "the factor is the one the server challenged, not the form's"
    );
}

/// Without the challenge cookie there is no server-issued OTP to check, so a
/// genuine code for the user's phone — issued outside this challenge — is
/// refused.
#[tokio::test]
async fn login_otp_submit_without_the_challenge_cookie_is_refused() {
    let rig = login_rig(|s, sms| s.with_sms(sms as _, Some(KEY.to_vec())));
    let victim = post_login_as(&rig, USER_EMAIL).await;
    let pending = cookie_pair(&victim, MFA_PENDING_COOKIE).expect("pending cookie");
    let nonce = rig
        .state
        .identity
        .issue_sms_otp(&rig.realm_id, PHONE, KEY, rig.sms.as_ref(), now_secs())
        .expect("issue");
    let code = rig.sms.last_code();

    let resp = submit_login_otp(
        &rig,
        &pending,
        &code,
        &format!("&factor=sms&otp_nonce={nonce}"),
    )
    .await;
    assert!(!has_cookie(&resp, SESSION_COOKIE));
}

/// With no key loaded, a code HMAC'd under the old all-zero key must not
/// verify, even with a correctly signed challenge cookie naming it: the
/// submit path used the zero key too, so reinstating that fallback would make
/// this pass.
#[tokio::test]
async fn login_otp_submit_without_an_hmac_key_refuses_a_zero_key_code() {
    let rig = login_rig(|s, sms| s.with_sms(sms as _, None));
    let nonce = rig
        .state
        .identity
        .issue_sms_otp(
            &rig.realm_id,
            PHONE,
            &OLD_ZERO_KEY,
            rig.sms.as_ref(),
            now_secs(),
        )
        .expect("issue under the old zero key");
    let code = rig.sms.last_code();
    let victim = post_login_as(&rig, USER_EMAIL).await;
    let pending = cookie_pair(&victim, MFA_PENDING_COOKIE).expect("pending cookie");
    let otp = forge_mfa_otp_cookie(&pending, "sms", &nonce);

    let resp = submit_login_otp(&rig, &format!("{pending}; {otp}"), &code, "").await;
    assert!(!has_cookie(&resp, SESSION_COOKIE));
}

/// Control for the forged cookie above: the same forgery under a loaded key
/// does complete the login, so the refusal is the missing key and not a
/// cookie the handler would never accept.
#[tokio::test]
async fn login_otp_forged_challenge_cookie_matches_the_server_format() {
    let rig = login_rig(|s, sms| s.with_sms(sms as _, Some(KEY.to_vec())));
    let nonce = rig
        .state
        .identity
        .issue_sms_otp(&rig.realm_id, PHONE, KEY, rig.sms.as_ref(), now_secs())
        .expect("issue");
    let code = rig.sms.last_code();
    let victim = post_login_as(&rig, USER_EMAIL).await;
    let pending = cookie_pair(&victim, MFA_PENDING_COOKIE).expect("pending cookie");
    let otp = forge_mfa_otp_cookie(&pending, "sms", &nonce);

    let resp = submit_login_otp(&rig, &format!("{pending}; {otp}"), &code, "").await;
    assert!(has_cookie(&resp, SESSION_COOKIE));
}

// ===========================================================================
// /ui/sms-challenge (authorize intercept) — no key refuses
// ===========================================================================

fn register_client(rig: &LoginRig) -> hearth::identity::OAuthClient {
    rig.state
        .identity
        .register_client(
            &rig.realm_id,
            &hearth::identity::RegisterClientRequest {
                client_name: "SMS fail-closed app".to_string(),
                redirect_uris: vec![REDIRECT.to_string()],
                require_consent: false,
                grant_types: vec!["authorization_code".to_string()],
                trust_level: hearth::identity::ClientTrustLevel::FirstParty,
                ..Default::default()
            },
        )
        .expect("register client")
}

/// A signed UI session cookie (plus the CSRF cookie) for `user_id`.
fn ui_session_cookie(rig: &LoginRig, user_id: &UserId) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let session = rig
        .state
        .identity
        .create_session(&rig.realm_id, user_id, &SessionContext::default())
        .expect("session");
    let mut mac = <Hmac<Sha256>>::new_from_slice(&COOKIE_SECRET).expect("key");
    mac.update(session.id().as_uuid().as_bytes());
    mac.update(b"|");
    mac.update(rig.realm_id.as_uuid().as_bytes());
    let tag = data_encoding::BASE64URL_NOPAD.encode(&mac.finalize().into_bytes());
    format!(
        "hearth_ui_session={}.{}.{}; hearth_ui_csrf={CSRF}",
        session.id().as_uuid(),
        rig.realm_id.as_uuid(),
        tag,
    )
}

/// The `/ui/sms-challenge` pending cookie, MAC'd the way the intercept does.
fn sms_mfa_cookie(rig: &LoginRig, client_id: &str, otp_nonce: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let payload = serde_json::json!({
        "realm_id": rig.realm_id.as_uuid().to_string(),
        "user_id": rig.user_id.as_uuid().to_string(),
        "otp_nonce": otp_nonce,
        "masked_phone": "+1•••0142",
        "client_id": client_id,
        "redirect_uri": REDIRECT,
        "scope": "openid",
        "oauth_state": "st",
        "code_challenge": pkce_challenge(),
        "code_challenge_method": "S256",
        "response_type": "code",
        "via_par": false,
    });
    let b64 = data_encoding::BASE64URL_NOPAD
        .encode(serde_json::to_string(&payload).expect("json").as_bytes());
    let mut mac = <Hmac<Sha256>>::new_from_slice(&COOKIE_SECRET).expect("key");
    mac.update(rig.user_id.as_uuid().as_bytes());
    mac.update(b"|");
    mac.update(b64.as_bytes());
    let tag = data_encoding::BASE64URL_NOPAD.encode(&mac.finalize().into_bytes());
    format!("hearth_ui_sms_mfa={b64}.{tag}")
}

async fn post_sms_challenge(rig: &LoginRig, issue_key: &[u8]) -> Response<Body> {
    let client = register_client(rig);
    let nonce = rig
        .state
        .identity
        .issue_sms_otp(
            &rig.realm_id,
            PHONE,
            issue_key,
            rig.sms.as_ref(),
            now_secs(),
        )
        .expect("issue");
    let code = rig.sms.last_code();
    let cookies = format!(
        "{}; {}",
        ui_session_cookie(rig, &rig.user_id),
        sms_mfa_cookie(rig, &client.client_id().as_uuid().to_string(), &nonce)
    );
    rig.app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/sms-challenge")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, cookies)
                .body(Body::from(format!("code={code}&_csrf={CSRF}")))
                .expect("build sms-challenge POST"),
        )
        .await
        .expect("sms-challenge")
}

fn location(resp: &Response<Body>) -> String {
    resp.headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

#[tokio::test]
async fn sms_challenge_post_without_an_hmac_key_refuses_a_zero_key_code() {
    let rig = login_rig(|s, sms| s.with_sms(sms as _, None));
    let resp = post_sms_challenge(&rig, &OLD_ZERO_KEY).await;
    assert!(
        !location(&resp).starts_with(REDIRECT),
        "no authorization code may be issued without a loaded OTP key; got {}",
        location(&resp)
    );
}

/// Control: with the key the same POST issues the code.
#[tokio::test]
async fn sms_challenge_post_with_the_hmac_key_issues_the_code() {
    let rig = login_rig(|s, sms| s.with_sms(sms as _, Some(KEY.to_vec())));
    let resp = post_sms_challenge(&rig, KEY).await;
    assert!(
        location(&resp).starts_with(REDIRECT),
        "rig sanity: the right code under the right key completes; got {} ({})",
        location(&resp),
        resp.status()
    );
}

// ===========================================================================
// Phone enrolment (ENROLL_PHONE_OTP required action)
// ===========================================================================

const ENROLL_EMAIL: &str = "enrol@fail-closed.test";
const ENROLL_PHONE: &str = "+15555550177";

/// Creates a user who must enrol a phone, drives the authorize intercept, and
/// returns `(user_id, ra_cookie)`.
async fn enrolment_ra_cookie(rig: &LoginRig) -> (UserId, String) {
    let client = register_client(rig);
    let user = rig
        .state
        .identity
        .create_user(
            &rig.realm_id,
            &CreateUserRequest {
                email: ENROLL_EMAIL.to_string(),
                display_name: "Enrol".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("user");
    rig.state
        .identity
        .update_user(
            &rig.realm_id,
            user.id(),
            &UpdateUserRequest {
                status: Some(UserStatus::Active),
                required_actions: Some(vec![hearth::identity::RequiredAction::EnrollPhoneOtp]),
                ..Default::default()
            },
        )
        .expect("require phone enrolment");
    let challenge = pkce_challenge();
    let uri = format!(
        "/ui/oauth/authorize?client_id={}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb\
         &response_type=code&scope=openid&state=st&code_challenge={challenge}\
         &code_challenge_method=S256",
        client.client_id().as_uuid()
    );
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header(header::COOKIE, ui_session_cookie(rig, user.id()))
                .body(Body::empty())
                .expect("build authorize"),
        )
        .await
        .expect("authorize");
    let ra = resp
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|v| v.strip_prefix("hearth_ra_session="))
        .and_then(|rest| rest.split(';').next())
        .map(|t| format!("hearth_ra_session={t}"))
        .expect("RA cookie from the intercept");
    (user.id().clone(), ra)
}

async fn enroll_post(rig: &LoginRig, ra: &str, path: &str, body: String) -> Response<Body> {
    rig.app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, ra)
                .body(Body::from(body))
                .expect("build enrol POST"),
        )
        .await
        .expect("enrol")
}

fn phone_verified(rig: &LoginRig, user: &UserId) -> (Option<String>, bool) {
    let u = rig
        .state
        .identity
        .get_user(&rig.realm_id, user)
        .expect("get_user")
        .expect("user exists");
    (u.phone_number().map(str::to_string), u.phone_verified())
}

#[tokio::test]
async fn enroll_phone_send_without_an_hmac_key_sends_nothing() {
    let rig = login_rig(|s, sms| s.with_sms(sms as _, None));
    let (_, ra) = enrolment_ra_cookie(&rig).await;
    let resp = enroll_post(
        &rig,
        &ra,
        "/required-action/ENROLL_PHONE_OTP/send",
        "phone=%2B15555550177".to_string(),
    )
    .await;
    let html = body_string(resp).await;
    assert!(
        html.contains("SMS delivery is not configured"),
        "the page must say why no code was sent"
    );
    assert_eq!(rig.sms.sent(), 0, "no code may be issued without a key");
}

#[tokio::test]
async fn enroll_phone_verify_without_an_hmac_key_refuses_a_zero_key_code() {
    let rig = login_rig(|s, sms| s.with_sms(sms as _, None));
    let (user, ra) = enrolment_ra_cookie(&rig).await;
    let nonce = rig
        .state
        .identity
        .issue_sms_otp(
            &rig.realm_id,
            ENROLL_PHONE,
            &OLD_ZERO_KEY,
            rig.sms.as_ref(),
            now_secs(),
        )
        .expect("issue under the old zero key");
    let code = rig.sms.last_code();
    let _ = enroll_post(
        &rig,
        &ra,
        "/required-action/ENROLL_PHONE_OTP/verify",
        format!("nonce={nonce}&phone=%2B15555550177&code={code}"),
    )
    .await;
    assert_eq!(
        phone_verified(&rig, &user),
        (None, false),
        "no phone may be verified without a loaded OTP key"
    );
}

/// A code sent to the enrolling user's OWN phone must not verify a different
/// number: the form carries the phone, and the OTP named no recipient, so any
/// number could be marked verified with a code received elsewhere.
#[tokio::test]
async fn enroll_phone_verify_refuses_a_code_sent_to_a_different_number() {
    let rig = login_rig(|s, sms| s.with_sms(sms as _, Some(KEY.to_vec())));
    let (user, ra) = enrolment_ra_cookie(&rig).await;
    let resp = enroll_post(
        &rig,
        &ra,
        "/required-action/ENROLL_PHONE_OTP/send",
        "phone=%2B15555550177".to_string(),
    )
    .await;
    let nonce = html_field(&body_string(resp).await, "nonce");
    let code = rig.sms.last_code();
    let _ = enroll_post(
        &rig,
        &ra,
        "/required-action/ENROLL_PHONE_OTP/verify",
        format!("nonce={nonce}&phone=%2B15555550100&code={code}"),
    )
    .await;
    assert_eq!(
        phone_verified(&rig, &user),
        (None, false),
        "+15555550100 never received a code and must not become verified"
    );
}

/// Control: the number the code went to does verify.
#[tokio::test]
async fn enroll_phone_verify_accepts_the_number_the_code_was_sent_to() {
    let rig = login_rig(|s, sms| s.with_sms(sms as _, Some(KEY.to_vec())));
    let (user, ra) = enrolment_ra_cookie(&rig).await;
    let resp = enroll_post(
        &rig,
        &ra,
        "/required-action/ENROLL_PHONE_OTP/send",
        "phone=%2B15555550177".to_string(),
    )
    .await;
    let nonce = html_field(&body_string(resp).await, "nonce");
    let code = rig.sms.last_code();
    let resp = enroll_post(
        &rig,
        &ra,
        "/required-action/ENROLL_PHONE_OTP/verify",
        format!("nonce={nonce}&phone=%2B15555550177&code={code}"),
    )
    .await;
    assert_eq!(
        phone_verified(&rig, &user),
        (Some(ENROLL_PHONE.to_string()), true)
    );
    // The resumed authorize still runs the SMS challenge (documented in the
    // SMS MFA deployment guide): a second code, no authorization code yet.
    assert_eq!(location(&resp), "/ui/sms-challenge");
    assert_eq!(
        rig.sms.sent(),
        2,
        "enrolment code, then the sign-in challenge code"
    );
}

// ===========================================================================
// Authorize with a signed request object (JAR) — intercepts still run
// ===========================================================================

const JAR_KID: &str = "sms-fc-jar-key";

/// Registers a JWKS client and signs a JAR for it; returns the authorize URI.
fn jar_authorize_uri(rig: &LoginRig) -> String {
    jar_authorize_uri_with(rig, &serde_json::json!({})).0
}

/// [`jar_authorize_uri`] with `overrides` merged into the request object's
/// claims (a `null` value removes the claim). Returns the authorize URI and
/// the client id.
#[allow(clippy::too_many_lines)]
fn jar_authorize_uri_with(rig: &LoginRig, overrides: &serde_json::Value) -> (String, String) {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use ring::signature::KeyPair;

    let pair = jar_key();
    let x = URL_SAFE_NO_PAD.encode(pair.public_key().as_ref());
    let jwks = format!(
        r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","kid":"{JAR_KID}","x":"{x}"}}]}}"#
    );
    let client = rig
        .state
        .identity
        .register_client(
            &rig.realm_id,
            &hearth::identity::RegisterClientRequest {
                client_name: "JAR app".to_string(),
                redirect_uris: vec![REDIRECT.to_string()],
                require_consent: false,
                grant_types: vec!["authorization_code".to_string()],
                trust_level: hearth::identity::ClientTrustLevel::FirstParty,
                jwks: Some(jwks),
                ..Default::default()
            },
        )
        .expect("register JAR client");
    let cid = client.client_id().to_string();
    let realm_name = rig
        .state
        .identity
        .get_realm(&rig.realm_id)
        .expect("get_realm")
        .expect("realm")
        .name()
        .to_string();
    let now = i64::try_from(now_secs()).expect("now");
    let challenge = pkce_challenge();
    let header = serde_json::json!({ "alg": "EdDSA", "kid": JAR_KID });
    let mut claims = serde_json::json!({
        "iss": cid,
        "aud": format!("https://hearth.local/realms/{realm_name}"),
        "exp": now + 600,
        "iat": now,
        "jti": uuid::Uuid::new_v4().to_string(),
        "client_id": cid,
        "response_type": "code",
        "redirect_uri": REDIRECT,
        "scope": "openid",
        "state": "jar-state",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    });
    if let (Some(claims), Some(overrides)) = (claims.as_object_mut(), overrides.as_object()) {
        for (k, v) in overrides {
            if v.is_null() {
                claims.remove(k);
            } else {
                claims.insert(k.clone(), v.clone());
            }
        }
    }
    let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header"));
    let c = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("claims"));
    let input = format!("{h}.{c}");
    let sig = URL_SAFE_NO_PAD.encode(pair.sign(input.as_bytes()).as_ref());
    (
        format!(
            "/ui/oauth/authorize?client_id={}&request={input}.{sig}",
            client.client_id().as_uuid()
        ),
        client.client_id().as_uuid().to_string(),
    )
}

async fn jar_authorize(rig: &LoginRig) -> Response<Body> {
    let uri = jar_authorize_uri(rig);
    rig.app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header(header::COOKIE, ui_session_cookie(rig, &rig.user_id))
                .body(Body::empty())
                .expect("build JAR authorize"),
        )
        .await
        .expect("JAR authorize")
}

/// The JAR branch returned a code before the SMS intercept ever ran, so a
/// session made without the SMS factor got a code on an `sms` realm.
#[tokio::test]
async fn jar_authorize_runs_the_sms_challenge() {
    let rig = login_rig(|s, sms| s.with_sms(sms as _, Some(KEY.to_vec())));
    let resp = jar_authorize(&rig).await;
    assert_eq!(
        location(&resp),
        "/ui/sms-challenge",
        "a JAR authorize on an sms realm must be challenged, not issued a code"
    );
    assert_eq!(rig.sms.sent(), 1);
}

/// And with no transport the JAR branch fails closed like the others.
#[tokio::test]
async fn jar_authorize_without_an_sms_transport_issues_no_code() {
    let rig = login_rig(|s, _| s);
    let resp = jar_authorize(&rig).await;
    assert!(
        !location(&resp).starts_with(REDIRECT),
        "no code without the SMS factor; got {}",
        location(&resp)
    );
}

/// The JAR's pending required actions are enforced too.
#[tokio::test]
async fn jar_authorize_runs_the_required_action_intercept() {
    let rig = login_rig(|s, sms| s.with_sms(sms as _, Some(KEY.to_vec())));
    rig.state
        .identity
        .update_user(
            &rig.realm_id,
            &rig.user_id,
            &UpdateUserRequest {
                required_actions: Some(vec![hearth::identity::RequiredAction::UpdatePassword]),
                ..Default::default()
            },
        )
        .expect("require an action");
    let resp = jar_authorize(&rig).await;
    assert!(
        !location(&resp).starts_with(REDIRECT),
        "pending required actions must be completed first; got {}",
        location(&resp)
    );
    assert!(
        resp.headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .any(|v| v.starts_with("hearth_ra_session=")),
        "the RA intercept must have started"
    );
}

// ===========================================================================
// Required-action resume — the SMS intercept still runs
// ===========================================================================

/// A plain (non-PAR, non-JAR) authorize for `user`, with a UI session made
/// without any second factor.
async fn plain_authorize(rig: &LoginRig, user: &UserId) -> Response<Body> {
    let client = register_client(rig);
    let uri = format!(
        "/ui/oauth/authorize?client_id={}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb\
         &response_type=code&scope=openid&state=st&code_challenge={}\
         &code_challenge_method=S256",
        client.client_id().as_uuid(),
        pkce_challenge()
    );
    rig.app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header(header::COOKIE, ui_session_cookie(rig, user))
                .body(Body::empty())
                .expect("build authorize"),
        )
        .await
        .expect("authorize")
}

/// The RA intercept runs before the SMS intercept and returns first, so a
/// user with any pending required action reached `resume_oidc_flow` — which
/// issued the authorization code directly. The SMS intercept never ran: a
/// session made without the SMS factor got a code on an `sms` realm just by
/// having (or being given) a required action.
#[tokio::test]
async fn completing_a_required_action_does_not_skip_the_sms_challenge() {
    let rig = login_rig(|s, sms| s.with_sms(sms as _, Some(KEY.to_vec())));
    rig.state
        .identity
        .update_user(
            &rig.realm_id,
            &rig.user_id,
            &UpdateUserRequest {
                required_actions: Some(vec![hearth::identity::RequiredAction::UpdatePassword]),
                ..Default::default()
            },
        )
        .expect("require a password update");

    let resp = plain_authorize(&rig, &rig.user_id).await;
    let ra = cookie_pair(&resp, "hearth_ra_session").expect("RA cookie from the intercept");
    assert_eq!(rig.sms.sent(), 0, "the RA intercept runs first");

    let new_password = ["a", "brand", "new", "sms", "passphrase", "9"].join("-");
    let resp = enroll_post(
        &rig,
        &format!("{ra}; hearth_ui_csrf={CSRF}"),
        "/required-action/UPDATE_PASSWORD",
        format!(
            "current_password={}&new_password={new_password}&confirm_password={new_password}\
             &_csrf={CSRF}",
            password()
        ),
    )
    .await;
    assert!(
        !location(&resp).starts_with(REDIRECT),
        "no authorization code before the SMS factor is proved; got {}",
        location(&resp)
    );
    assert_eq!(
        location(&resp),
        "/ui/sms-challenge",
        "completing the last required action must lead to the SMS challenge"
    );
    assert_eq!(rig.sms.sent(), 1, "the SMS challenge sends its code");
}

/// And without an SMS transport the resume fails closed instead of issuing.
#[tokio::test]
async fn completing_a_required_action_without_an_sms_transport_issues_no_code() {
    let rig = login_rig(|s, _| s);
    rig.state
        .identity
        .update_user(
            &rig.realm_id,
            &rig.user_id,
            &UpdateUserRequest {
                required_actions: Some(vec![hearth::identity::RequiredAction::UpdatePassword]),
                ..Default::default()
            },
        )
        .expect("require a password update");
    let resp = plain_authorize(&rig, &rig.user_id).await;
    let ra = cookie_pair(&resp, "hearth_ra_session").expect("RA cookie from the intercept");

    let new_password = ["a", "brand", "new", "sms", "passphrase", "9"].join("-");
    let resp = enroll_post(
        &rig,
        &format!("{ra}; hearth_ui_csrf={CSRF}"),
        "/required-action/UPDATE_PASSWORD",
        format!(
            "current_password={}&new_password={new_password}&confirm_password={new_password}\
             &_csrf={CSRF}",
            password()
        ),
    )
    .await;
    assert!(
        !location(&resp).starts_with(REDIRECT),
        "no authorization code without the SMS factor; got {} ({})",
        location(&resp),
        resp.status()
    );
    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "the password page must not simply re-render"
    );
}

// ===========================================================================
// Email OTP — the HMAC key is never a public constant
// ===========================================================================

/// The key email OTP codes used to be HMAC'd under whenever no SMS OTP key was
/// loaded — every production deployment on the `log` SMS transport. It is in
/// the public source, so every stored digest was brute-forceable offline.
const OLD_PUBLIC_EMAIL_KEY: &[u8] = b"hearth-dev-email-otp-key-not-for-production";

struct CapturingEmail {
    messages: Mutex<Vec<hearth::identity::EmailMessage>>,
}

impl CapturingEmail {
    fn last_code(&self) -> String {
        #[allow(clippy::unwrap_used)]
        let guard = self.messages.lock().unwrap();
        let body = guard.last().expect("an email was sent").text_body.clone();
        let (_, rest) = body.rsplit_once(": ").expect("code in body");
        rest.trim().chars().take(6).collect()
    }
}

impl hearth::identity::EmailSender for CapturingEmail {
    fn send(
        &self,
        message: &hearth::identity::EmailMessage,
    ) -> Result<(), hearth::identity::EmailError> {
        #[allow(clippy::unwrap_used)]
        self.messages.lock().unwrap().push(message.clone());
        Ok(())
    }
}

struct EmailRig {
    login: LoginRig,
    mail: Arc<CapturingEmail>,
    service: Arc<EmailService>,
}

/// A realm offering only `email_otp`, a user enrolled in it, a capturing mail
/// transport and NO SMS OTP key — the production shape that used to fall
/// back to the public constant.
fn email_rig() -> EmailRig {
    let e = engines();
    let realm = e
        .identity
        .create_realm(&CreateRealmRequest {
            name: format!("email-fc-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                mfa_methods: Some(vec!["email_otp".to_string()]),
                ..RealmConfig::default()
            }),
        })
        .expect("realm");
    let user = e
        .identity
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: USER_EMAIL.to_string(),
                display_name: "Em".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("user");
    e.identity
        .set_password(
            realm.id(),
            user.id(),
            &CleartextPassword::from_string(password()),
        )
        .expect("password");
    e.identity
        .update_user(
            realm.id(),
            user.id(),
            &UpdateUserRequest {
                status: Some(UserStatus::Active),
                email_otp_enabled: Some(true),
                ..Default::default()
            },
        )
        .expect("enrol email otp");

    let mail = Arc::new(CapturingEmail {
        messages: Mutex::new(Vec::new()),
    });
    let service = Arc::new(
        EmailService::new(
            Arc::clone(&mail) as _,
            "Hearth".to_string(),
            None,
            EmailBranding::default(),
            String::new(),
            None,
        )
        .expect("email service"),
    );
    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&e.identity),
        Arc::clone(&e.rbac),
        null_email(),
        e.data_dir.clone(),
    ));
    let state = WebState::new(
        Arc::clone(&e.identity),
        Arc::clone(&e.rbac),
        Arc::clone(&e.audit),
        onboarding,
        CookieSecret::from_bytes(COOKIE_SECRET),
        Some(Arc::clone(&service)),
    )
    .with_default_realm(Some(realm.name().to_string()));
    let app = web::router(state.clone());
    EmailRig {
        login: LoginRig {
            app,
            state: Arc::new(state),
            realm_id: realm.id().clone(),
            user_id: user.id().clone(),
            sms: CapturingSms::new(),
        },
        mail,
        service,
    }
}

/// A code HMAC'd under the old public constant must not complete an email OTP
/// login: that would mean the handler still keys email OTPs with it.
#[tokio::test]
async fn email_otp_login_refuses_a_code_keyed_with_the_old_public_constant() {
    let rig = email_rig();
    let nonce = rig
        .login
        .state
        .identity
        .issue_email_otp(
            &rig.login.realm_id,
            USER_EMAIL,
            OLD_PUBLIC_EMAIL_KEY,
            &rig.service,
            None,
            now_secs(),
        )
        .expect("issue under the old public key");
    let code = rig.mail.last_code();
    let login = post_login(&rig.login).await;
    let pending = cookie_pair(&login, MFA_PENDING_COOKIE).expect("pending cookie");
    let otp = forge_mfa_otp_cookie(&pending, "email_otp", &nonce);

    let resp = submit_login_otp(&rig.login, &format!("{pending}; {otp}"), &code, "").await;
    assert!(
        !has_cookie(&resp, SESSION_COOKIE),
        "an email OTP keyed with the public constant must not verify"
    );
}

/// Control: with no SMS key loaded, email OTP still works end to end — the
/// key is a secret derived per process, not missing — so the refusal above is
/// the key and not a broken email flow.
#[tokio::test]
async fn email_otp_login_works_without_an_sms_key() {
    let rig = email_rig();
    let (pending, otp) = start_otp_login(&rig.login, USER_EMAIL).await;
    assert!(otp.contains("email_otp."), "the email factor is challenged");
    let code = rig.mail.last_code();
    let resp = submit_login_otp(&rig.login, &format!("{pending}; {otp}"), &code, "").await;
    assert!(
        has_cookie(&resp, SESSION_COOKIE),
        "own email code must log in"
    );
}

// ===========================================================================
// JAR authorize — the request object's own parameters are honoured
// ===========================================================================

/// An RFC 8707 resource indicator for the JAR / PAR audience tests.
const RESOURCE: &str = "https://api.example.com/v1";
const PKCE_VERIFIER: &str = "verifier-verifier-verifier-verifier-4";

async fn jar_authorize_with(
    rig: &LoginRig,
    user: &UserId,
    overrides: &serde_json::Value,
) -> (Response<Body>, String) {
    let (uri, client_id) = jar_authorize_uri_with(rig, overrides);
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header(header::COOKIE, ui_session_cookie(rig, user))
                .body(Body::empty())
                .expect("build JAR authorize"),
        )
        .await
        .expect("JAR authorize");
    (resp, client_id)
}

/// The value of query parameter `name` in a redirect `location`.
fn query_param(location: &str, name: &str) -> Option<String> {
    let (_, query) = location.split_once('?')?;
    form_urlencoded::parse(query.as_bytes())
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

/// The JAR clients' signing key (one per test process). A client that
/// registers a JWKS is confidential, so it also signs its `private_key_jwt`
/// assertions with this key.
fn jar_key() -> &'static ring::signature::Ed25519KeyPair {
    static KEY: std::sync::OnceLock<ring::signature::Ed25519KeyPair> = std::sync::OnceLock::new();
    KEY.get_or_init(|| {
        let pkcs8 =
            ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
                .expect("keygen");
        ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("pair")
    })
}

/// A `private_key_jwt` assertion for the JAR client `client_id` (bare UUID).
fn jar_client_assertion(rig: &LoginRig, client_id: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    let cid =
        hearth::core::ClientId::new(uuid::Uuid::parse_str(client_id).expect("uuid")).to_string();
    let realm_name = rig
        .state
        .identity
        .get_realm(&rig.realm_id)
        .expect("get_realm")
        .expect("realm")
        .name()
        .to_string();
    let now = i64::try_from(now_secs()).expect("now");
    let h = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&serde_json::json!({ "alg": "EdDSA", "kid": JAR_KID })).expect("header"),
    );
    let c = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&serde_json::json!({
            "iss": cid, "sub": cid,
            "aud": format!("https://hearth.local/realms/{realm_name}"),
            "exp": now + 60, "iat": now, "jti": uuid::Uuid::new_v4().to_string(),
        }))
        .expect("claims"),
    );
    let input = format!("{h}.{c}");
    format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(jar_key().sign(input.as_bytes()).as_ref())
    )
}

/// Exchanges the code in `location` and returns the access token's `aud`.
fn exchanged_audience(rig: &LoginRig, client_id: &str, location: &str) -> Vec<String> {
    let code = query_param(location, "code")
        .unwrap_or_else(|| panic!("no code in the redirect: {location}"));
    let holds_jwks = rig
        .state
        .identity
        .get_client(
            &rig.realm_id,
            &hearth::core::ClientId::new(uuid::Uuid::parse_str(client_id).expect("client uuid")),
        )
        .expect("get_client")
        .is_some_and(|c| c.jwks().is_some());
    let tokens = rig
        .state
        .identity
        .exchange_authorization_code(
            &rig.realm_id,
            &hearth::identity::TokenExchangeRequest {
                client_id: hearth::core::ClientId::new(
                    uuid::Uuid::parse_str(client_id).expect("client uuid"),
                ),
                code,
                redirect_uri: REDIRECT.to_string(),
                code_verifier: Some(PKCE_VERIFIER.to_string()),
                dpop_jkt: None,
                // A JAR client registered a JWKS: it authenticates with an
                // assertion. A public (PAR) client authenticates by PKCE.
                client_assertion_type: holds_jwks
                    .then(|| "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_string()),
                client_assertion: holds_jwks.then(|| jar_client_assertion(rig, client_id)),
            },
        )
        .expect("exchange the code");
    let payload = tokens
        .access_token()
        .split('.')
        .nth(1)
        .expect("JWT payload");
    let claims: serde_json::Value = serde_json::from_slice(
        &data_encoding::BASE64URL_NOPAD
            .decode(payload.as_bytes())
            .expect("base64url payload"),
    )
    .expect("claims json");
    match &claims["aud"] {
        serde_json::Value::String(s) => vec![s.clone()],
        serde_json::Value::Array(a) => a
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        other => panic!("unexpected aud {other}"),
    }
}

/// Happy path of the rewritten JAR branch: no SMS factor and no required
/// action, so the code is issued at once — to the JAR's redirect_uri, with
/// the JAR's state.
#[tokio::test]
async fn jar_authorize_without_gates_issues_a_code_with_the_jar_state() {
    let rig = login_rig_with_mfa(None, |s, _| s);
    let (resp, _) = jar_authorize_with(&rig, &rig.user_id, &serde_json::json!({})).await;
    let loc = location(&resp);
    assert!(
        loc.starts_with(REDIRECT),
        "a JAR authorize with no gate pending must issue the code; got {loc} ({})",
        resp.status()
    );
    assert!(query_param(&loc, "code").is_some(), "no code in {loc}");
    assert_eq!(query_param(&loc, "state").as_deref(), Some("jar-state"));
}

/// The JAR's RFC 8707 `resource` claim must still bind the code: the engine
/// used to take it from the request object, and the token audience with it.
#[tokio::test]
async fn jar_resource_reaches_the_access_token_audience() {
    let rig = login_rig_with_mfa(None, |s, _| s);
    let (resp, client_id) = jar_authorize_with(
        &rig,
        &rig.user_id,
        &serde_json::json!({ "resource": RESOURCE }),
    )
    .await;
    let aud = exchanged_audience(&rig, &client_id, &location(&resp));
    assert!(
        aud.iter().any(|a| a == RESOURCE),
        "the JAR resource must reach the token audience; aud = {aud:?}"
    );
}

/// ... also when the code is issued at the end of the SMS challenge.
#[tokio::test]
async fn jar_resource_survives_the_sms_challenge() {
    let rig = login_rig(|s, sms| s.with_sms(sms as _, Some(KEY.to_vec())));
    let (resp, client_id) = jar_authorize_with(
        &rig,
        &rig.user_id,
        &serde_json::json!({ "resource": RESOURCE }),
    )
    .await;
    assert_eq!(location(&resp), "/ui/sms-challenge");
    let sms_cookie = cookie_pair(&resp, "hearth_ui_sms_mfa").expect("SMS challenge cookie");
    let code = rig.sms.last_code();
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/sms-challenge")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(
                    header::COOKIE,
                    format!("{}; {sms_cookie}", ui_session_cookie(&rig, &rig.user_id)),
                )
                .body(Body::from(format!("code={code}&_csrf={CSRF}")))
                .expect("build sms-challenge POST"),
        )
        .await
        .expect("sms-challenge");
    let aud = exchanged_audience(&rig, &client_id, &location(&resp));
    assert!(
        aud.iter().any(|a| a == RESOURCE),
        "the JAR resource must survive the SMS challenge; aud = {aud:?}"
    );
}

/// ... and when it is issued at the end of the required-action flow.
#[tokio::test]
async fn jar_resource_survives_a_required_action() {
    let rig = login_rig_with_mfa(None, |s, _| s);
    rig.state
        .identity
        .update_user(
            &rig.realm_id,
            &rig.user_id,
            &UpdateUserRequest {
                required_actions: Some(vec![hearth::identity::RequiredAction::UpdatePassword]),
                ..Default::default()
            },
        )
        .expect("require a password update");
    let (resp, client_id) = jar_authorize_with(
        &rig,
        &rig.user_id,
        &serde_json::json!({ "resource": RESOURCE }),
    )
    .await;
    let ra = cookie_pair(&resp, "hearth_ra_session").expect("RA cookie from the intercept");
    let new_password = ["a", "brand", "new", "jar", "passphrase", "7"].join("-");
    let resp = enroll_post(
        &rig,
        &format!("{ra}; hearth_ui_csrf={CSRF}"),
        "/required-action/UPDATE_PASSWORD",
        format!(
            "current_password={}&new_password={new_password}&confirm_password={new_password}\
             &_csrf={CSRF}",
            password()
        ),
    )
    .await;
    let aud = exchanged_audience(&rig, &client_id, &location(&resp));
    assert!(
        aud.iter().any(|a| a == RESOURCE),
        "the JAR resource must survive the required-action flow; aud = {aud:?}"
    );
}

/// The engine refused a request object whose `response_type` is not `code`;
/// the web tier now verifies the JAR itself and must refuse it too, not
/// issue a code for a `token` request.
#[tokio::test]
async fn jar_with_a_non_code_response_type_is_refused() {
    let rig = login_rig_with_mfa(None, |s, _| s);
    let (resp, _) = jar_authorize_with(
        &rig,
        &rig.user_id,
        &serde_json::json!({ "response_type": "token" }),
    )
    .await;
    assert!(
        !location(&resp).starts_with(REDIRECT),
        "a JAR with response_type=token must not get a code; got {}",
        location(&resp)
    );
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// A JAR naming a redirect_uri the client never registered is refused
/// before any intercept runs: no SMS is sent, nothing is redirected there.
#[tokio::test]
async fn jar_with_an_unregistered_redirect_uri_is_refused_before_the_sms_challenge() {
    let rig = login_rig(|s, sms| s.with_sms(sms as _, Some(KEY.to_vec())));
    let (resp, _) = jar_authorize_with(
        &rig,
        &rig.user_id,
        &serde_json::json!({ "redirect_uri": "https://evil.example/cb" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        rig.sms.sent(),
        0,
        "no code may be sent for a refused request"
    );
}

/// The PAR branch dropped the stored `resource` the same way.
#[tokio::test]
async fn par_resource_reaches_the_access_token_audience() {
    let rig = login_rig_with_mfa(None, |s, _| s);
    let client = register_client(&rig);
    let pushed = rig
        .state
        .identity
        .push_authorization_request(
            &rig.realm_id,
            &hearth::identity::PushedAuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: REDIRECT.to_string(),
                scope: "openid".to_string(),
                state: "par-state".to_string(),
                resource: Some(RESOURCE.to_string()),
                response_type: "code".to_string(),
                code_challenge: Some(pkce_challenge()),
                code_challenge_method: Some(hearth::identity::CodeChallengeMethod::S256),
                nonce: None,
                request: None,
                response_mode: None,
                prompt: None,
            },
        )
        .expect("push");
    let uri = format!(
        "/ui/oauth/authorize?client_id={}&request_uri={}",
        client.client_id().as_uuid(),
        form_urlencoded::byte_serialize(pushed.request_uri.as_bytes()).collect::<String>()
    );
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header(header::COOKIE, ui_session_cookie(&rig, &rig.user_id))
                .body(Body::empty())
                .expect("build PAR authorize"),
        )
        .await
        .expect("PAR authorize");
    let aud = exchanged_audience(
        &rig,
        &client.client_id().as_uuid().to_string(),
        &location(&resp),
    );
    assert!(
        aud.iter().any(|a| a == RESOURCE),
        "the PAR resource must reach the token audience; aud = {aud:?}"
    );
}

// ===========================================================================
// Device approval (/ui/device) — the same gates as code issuance
// ===========================================================================

/// Registers a device-grant client and starts a device authorization;
/// returns `(client_id, device_code, user_code)`.
fn start_device_flow(rig: &LoginRig) -> (hearth::core::ClientId, String, String) {
    let client = rig
        .state
        .identity
        .register_client(
            &rig.realm_id,
            &hearth::identity::RegisterClientRequest {
                client_name: "TV app".to_string(),
                redirect_uris: vec![REDIRECT.to_string()],
                require_consent: false,
                grant_types: vec!["urn:ietf:params:oauth:grant-type:device_code".to_string()],
                trust_level: hearth::identity::ClientTrustLevel::FirstParty,
                ..Default::default()
            },
        )
        .expect("register device client");
    let started = rig
        .state
        .identity
        .device_authorize(
            &rig.realm_id,
            &hearth::identity::DeviceAuthorizationRequest {
                client_id: client.client_id().clone(),
                scope: Some("openid".to_string()),
            },
        )
        .expect("device authorize");
    (
        client.client_id().clone(),
        started.device_code,
        started.user_code,
    )
}

async fn post_device(rig: &LoginRig, cookies: &str, user_code: &str) -> Response<Body> {
    rig.app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/device")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, cookies)
                .body(Body::from(format!(
                    "user_code={user_code}&decision=approve&csrf_token={CSRF}"
                )))
                .expect("build device POST"),
        )
        .await
        .expect("device approve")
}

/// Whether the device client can now collect tokens for the device code.
fn device_approved(rig: &LoginRig, client: &hearth::core::ClientId, device_code: &str) -> bool {
    rig.state
        .identity
        .poll_device_token(&rig.realm_id, device_code, client)
        .is_ok()
}

/// A session made without the SMS factor used to approve a device on a realm
/// that requires it — the device client then got tokens for the user.
#[tokio::test]
async fn device_approval_on_an_sms_realm_runs_the_sms_challenge() {
    let rig = login_rig(|s, sms| s.with_sms(sms as _, Some(KEY.to_vec())));
    let (client, device_code, user_code) = start_device_flow(&rig);
    let resp = post_device(&rig, &ui_session_cookie(&rig, &rig.user_id), &user_code).await;
    assert_eq!(
        location(&resp),
        "/ui/sms-challenge",
        "the SMS factor must be challenged before the device is approved"
    );
    assert_eq!(rig.sms.sent(), 1);
    assert!(
        !device_approved(&rig, &client, &device_code),
        "the device must not be approved before the SMS factor is proved"
    );
}

/// ... and proving the factor approves the device.
#[tokio::test]
async fn device_approval_completes_after_the_sms_challenge() {
    let rig = login_rig(|s, sms| s.with_sms(sms as _, Some(KEY.to_vec())));
    let (client, device_code, user_code) = start_device_flow(&rig);
    let session = ui_session_cookie(&rig, &rig.user_id);
    let resp = post_device(&rig, &session, &user_code).await;
    let sms_cookie = cookie_pair(&resp, "hearth_ui_sms_mfa").expect("SMS challenge cookie");
    let code = rig.sms.last_code();
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/sms-challenge")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, format!("{session}; {sms_cookie}"))
                .body(Body::from(format!("code={code}&_csrf={CSRF}")))
                .expect("build sms-challenge POST"),
        )
        .await
        .expect("sms-challenge");
    assert_eq!(location(&resp), "/ui/device?flash=approved");
    assert!(device_approved(&rig, &client, &device_code));
}

/// With no SMS transport the factor cannot be proved, so nothing is approved.
#[tokio::test]
async fn device_approval_without_an_sms_transport_approves_nothing() {
    let rig = login_rig(|s, _| s);
    let (client, device_code, user_code) = start_device_flow(&rig);
    let _ = post_device(&rig, &ui_session_cookie(&rig, &rig.user_id), &user_code).await;
    assert!(
        !device_approved(&rig, &client, &device_code),
        "a device must not be approved without the realm's SMS factor"
    );
}

/// Pending required actions are completed before a device is approved.
#[tokio::test]
async fn device_approval_runs_the_required_action_intercept() {
    let rig = login_rig_with_mfa(None, |s, _| s);
    rig.state
        .identity
        .update_user(
            &rig.realm_id,
            &rig.user_id,
            &UpdateUserRequest {
                required_actions: Some(vec![hearth::identity::RequiredAction::UpdatePassword]),
                ..Default::default()
            },
        )
        .expect("require a password update");
    let (client, device_code, user_code) = start_device_flow(&rig);
    let resp = post_device(&rig, &ui_session_cookie(&rig, &rig.user_id), &user_code).await;
    assert!(
        cookie_pair(&resp, "hearth_ra_session").is_some(),
        "the RA intercept must start; got {} ({})",
        location(&resp),
        resp.status()
    );
    assert!(
        !device_approved(&rig, &client, &device_code),
        "the device must not be approved while required actions are pending"
    );
}

/// Control: with no gate pending the device is approved at once.
#[tokio::test]
async fn device_approval_without_gates_approves_the_device() {
    let rig = login_rig_with_mfa(None, |s, _| s);
    let (client, device_code, user_code) = start_device_flow(&rig);
    let resp = post_device(&rig, &ui_session_cookie(&rig, &rig.user_id), &user_code).await;
    assert_eq!(location(&resp), "/ui/device?flash=approved");
    assert!(device_approved(&rig, &client, &device_code));
}
