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
use hearth::protocol::web::auth::{MFA_PENDING_COOKIE, SESSION_COOKIE};
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
    let e = engines();
    let realm = e
        .identity
        .create_realm(&CreateRealmRequest {
            name: format!("sms-fc-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                mfa_methods: Some(vec!["sms".to_string()]),
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
                    "email={USER_EMAIL}&password={}&_csrf={csrf_field}",
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
