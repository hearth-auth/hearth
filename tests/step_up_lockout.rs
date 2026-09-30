//! Every step-up surface answers a locked account the same way: `429 Too
//! Many Requests` with a `Retry-After` hint (GA sweep 4, owner decision).
//!
//! A wrong step-up password counts as a failed login and a wrong step-up
//! TOTP code spends the account's TOTP guess budget, so once either is spent
//! the account is locked until the window passes, however correct the next
//! proof. Only the admin console's token mint said so (429); the JSON
//! step-up surfaces — passkey enrolment and removal on the account page and
//! on the REST API — answered `403 step_up_required`, which tells the client
//! its proof was wrong and to try another, and the console's TOTP and
//! password pages said "incorrect". Now every one answers 429 with
//! `Retry-After`, and every JSON body carries one error:
//! `{"error": "too_many_attempts", "error_code": "HEARTH_RATE_LIMITED"}`.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, Response, StatusCode};
use hearth::core::{RealmId, UserId};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, IdentityEngine, IdentityError,
    SessionContext, TokenIssuanceContext, UpdateUserRequest, UserStatus,
};
use hearth::protocol::http::{router as http_router, AppState};
use hearth::protocol::web::{self, CookieSecret, WebState};
use tower::ServiceExt as _;

const COOKIE_SECRET: [u8; 32] = [97u8; 32];
const CSRF: &str = "step-up-lockout-csrf";
const PASSWORD: &str = "correct-horse-battery-staple";
/// The default login lockout window (`RateLimitConfig`), and the TOTP one.
const LOCKOUT_SECS: u64 = 300;

struct Rig {
    _harness: common::TestHarness,
    _data_dir: tempfile::TempDir,
    identity: Arc<dyn IdentityEngine>,
    web: axum::Router,
    rest: axum::Router,
    realm_id: RealmId,
    user_id: UserId,
    cookies: String,
    access_token: String,
    totp_secret: Option<String>,
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

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

fn totp_code(secret_base32: &str, unix_secs: u64) -> String {
    let secret = data_encoding::BASE32_NOPAD
        .decode(secret_base32.as_bytes())
        .expect("decode base32");
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &secret);
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

/// The `/ui` router and the REST router over the harness's engines.
fn routers(
    harness: &common::TestHarness,
    data_dir: &std::path::Path,
) -> (axum::Router, axum::Router) {
    let identity = harness.identity_arc();
    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&identity),
        harness.rbac_arc(),
        null_email(),
        data_dir.to_path_buf(),
    ));
    let web_state = WebState::new(
        Arc::clone(&identity),
        harness.rbac_arc(),
        harness.audit_arc(),
        onboarding,
        CookieSecret::from_bytes(COOKIE_SECRET),
        None,
    )
    .with_dev_mode(true);
    let rest_state = Arc::new(AppState::new(
        identity,
        harness.rbac_arc(),
        harness.audit_arc(),
    ));
    (web::router(web_state), http_router(rest_state))
}

/// One active user with a password, a browser session, a first-party access
/// token, and (with `totp`) an enrolled TOTP factor.
async fn rig(totp: bool) -> Rig {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity_arc();
    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: format!("step-up-lockout-{}", uuid::Uuid::new_v4().simple()),
            config: None,
        })
        .expect("realm");
    let user = identity
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("u-{}@lockout.test", uuid::Uuid::new_v4().simple()),
                display_name: "Lockout".to_string(),
                ..Default::default()
            },
        )
        .expect("user");
    identity
        .set_password(
            realm.id(),
            user.id(),
            &CleartextPassword::from_string(PASSWORD.to_string()),
        )
        .expect("password");
    identity
        .update_user(
            realm.id(),
            user.id(),
            &UpdateUserRequest {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .expect("activate");
    let session = identity
        .create_session(realm.id(), user.id(), &SessionContext::default())
        .expect("session");
    let access_token = identity
        .issue_tokens_with_context(
            realm.id(),
            user.id(),
            session.id(),
            &TokenIssuanceContext::default(),
        )
        .expect("tokens")
        .access_token()
        .to_string();
    let totp_secret = totp.then(|| {
        let enrollment = identity
            .enroll_totp(realm.id(), user.id())
            .expect("enroll totp");
        let code = totp_code(&enrollment.secret_base32, now_secs());
        identity
            .verify_totp_enrollment(realm.id(), user.id(), &code)
            .expect("activate totp");
        enrollment.secret_base32
    });
    let issued = web::auth::issue_auth_cookies(
        &CookieSecret::from_bytes(COOKIE_SECRET),
        realm.id(),
        session.id(),
        false,
    );
    let session_pair = issued
        .session_cookie
        .split(';')
        .next()
        .expect("session cookie pair")
        .to_string();

    let data_dir = tempfile::tempdir().expect("tempdir");
    let (web, rest) = routers(&harness, data_dir.path());
    Rig {
        web,
        rest,
        _harness: harness,
        _data_dir: data_dir,
        identity,
        realm_id: realm.id().clone(),
        user_id: user.id().clone(),
        cookies: format!("{session_pair}; hearth_ui_csrf={CSRF}"),
        access_token,
        totp_secret,
    }
}

impl Rig {
    /// Spends the account's login lockout budget with wrong passwords.
    fn lock_password(&self) {
        let wrong = CleartextPassword::from_string("not-the-password-at-all-1".to_string());
        for _ in 0..20 {
            if matches!(
                self.identity
                    .verify_password(&self.realm_id, &self.user_id, &wrong),
                Err(IdentityError::RateLimited)
            ) {
                return;
            }
        }
        panic!("the login lockout never engaged");
    }

    /// Spends the account's TOTP guess budget with wrong codes.
    fn lock_totp(&self) {
        for _ in 0..20 {
            if matches!(
                self.identity
                    .verify_totp(&self.realm_id, &self.user_id, "000000"),
                Err(IdentityError::RateLimited)
            ) {
                return;
            }
        }
        panic!("the TOTP guess budget never ran out");
    }

    fn current_code(&self) -> String {
        let secret = self.totp_secret.as_deref().expect("rig with totp");
        // The next step: the enrolment code of this step is already burned.
        totp_code(secret, now_secs() + 30)
    }

    async fn send(&self, rest: bool, req: Request<Body>) -> Response<Body> {
        let app = if rest { &self.rest } else { &self.web };
        app.clone().oneshot(req).await.expect("request")
    }

    async fn web_json(&self, uri: &str, body: serde_json::Value) -> Response<Body> {
        self.send(
            false,
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::COOKIE, &self.cookies)
                .header("x-csrf-token", CSRF)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .expect("build"),
        )
        .await
    }

    async fn web_form(&self, uri: &str, fields: &[(&str, &str)]) -> Response<Body> {
        let mut form = form_urlencoded::Serializer::new(String::new());
        form.append_pair("_csrf", CSRF);
        for (k, v) in fields {
            form.append_pair(k, v);
        }
        self.send(
            false,
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::COOKIE, &self.cookies)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form.finish()))
                .expect("build"),
        )
        .await
    }

    async fn rest_json(&self, method: &str, uri: &str, body: serde_json::Value) -> Response<Body> {
        self.send(
            true,
            Request::builder()
                .method(method)
                .uri(uri)
                .header("x-realm-id", self.realm_id.as_uuid().to_string())
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", self.access_token),
                )
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .expect("build"),
        )
        .await
    }
}

/// The `Retry-After` of a 429, in seconds; asserts it is a sane hint.
fn assert_locked(resp: &Response<Body>, what: &str) -> u64 {
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "{what}: a locked account must be told to wait, not that its proof was wrong"
    );
    let secs: u64 = resp
        .headers()
        .get(header::RETRY_AFTER)
        .unwrap_or_else(|| panic!("{what}: a 429 must carry Retry-After"))
        .to_str()
        .expect("ascii")
        .parse()
        .expect("delta-seconds");
    assert!(
        (1..=LOCKOUT_SECS).contains(&secs),
        "{what}: Retry-After {secs}s must fall inside the lockout window"
    );
    secs
}

/// Asserts the one JSON body every JSON step-up surface answers.
async fn assert_locked_json(resp: Response<Body>, what: &str) {
    assert_locked(&resp, what);
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.expect("body");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json body");
    assert_eq!(body["error"], "too_many_attempts", "{what}: {body}");
    assert_eq!(body["error_code"], "HEARTH_RATE_LIMITED", "{what}: {body}");
}

// ── JSON surfaces ────────────────────────────────────────────────────────────

#[tokio::test]
async fn account_passkey_enrolment_answers_a_locked_password_with_429() {
    let rig = rig(false).await;
    rig.lock_password();
    let resp = rig
        .web_json(
            "/ui/account/passkeys/register-begin",
            serde_json::json!({ "password": PASSWORD }),
        )
        .await;
    assert_locked_json(resp, "account passkey enrolment").await;
}

#[tokio::test]
async fn account_passkey_removal_answers_a_locked_password_with_429() {
    let rig = rig(false).await;
    rig.lock_password();
    let resp = rig
        .web_form(
            "/ui/account/passkeys/AAAA/delete",
            &[("step_up_secret", PASSWORD)],
        )
        .await;
    assert_locked_json(resp, "account passkey removal").await;
}

#[tokio::test]
async fn account_passkey_enrolment_answers_a_spent_totp_budget_with_429() {
    let rig = rig(true).await;
    rig.lock_totp();
    let code = rig.current_code();
    let resp = rig
        .web_json(
            "/ui/account/passkeys/register-begin",
            serde_json::json!({ "totp_code": code }),
        )
        .await;
    assert_locked_json(resp, "account passkey enrolment by TOTP").await;
}

#[tokio::test]
async fn rest_passkey_enrolment_answers_a_locked_password_with_429() {
    let rig = rig(false).await;
    rig.lock_password();
    let resp = rig
        .rest_json(
            "POST",
            "/webauthn/register/begin",
            serde_json::json!({ "password": PASSWORD }),
        )
        .await;
    assert_locked_json(resp, "REST passkey enrolment").await;
}

#[tokio::test]
async fn rest_passkey_removal_answers_a_spent_totp_budget_with_429() {
    let rig = rig(true).await;
    rig.lock_totp();
    let code = rig.current_code();
    let resp = rig
        .rest_json(
            "DELETE",
            "/webauthn/credentials/AAAA",
            serde_json::json!({ "totp_code": code }),
        )
        .await;
    assert_locked_json(resp, "REST passkey removal").await;
}

/// The control: a wrong proof on an unlocked account is still a 403.
#[tokio::test]
async fn a_wrong_proof_on_an_unlocked_account_is_still_step_up_required() {
    let rig = rig(false).await;
    let resp = rig
        .rest_json(
            "POST",
            "/webauthn/register/begin",
            serde_json::json!({ "password": "not-the-password-at-all-2" }),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.expect("body");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json body");
    assert_eq!(body["error"], "step_up_required", "{body}");
}

// ── Console (HTML) surfaces ──────────────────────────────────────────────────

#[tokio::test]
async fn console_totp_disable_answers_a_spent_totp_budget_with_429() {
    let rig = rig(true).await;
    rig.lock_totp();
    let code = rig.current_code();
    let resp = rig
        .web_form("/ui/account/totp/disable", &[("current_totp_code", &code)])
        .await;
    assert_locked(&resp, "console TOTP disable");
    assert!(
        rig.identity
            .mfa_enabled(&rig.realm_id, &rig.user_id)
            .expect("mfa state"),
        "a locked step-up disables nothing"
    );
}

#[tokio::test]
async fn console_recovery_code_regeneration_answers_a_spent_totp_budget_with_429() {
    let rig = rig(true).await;
    rig.lock_totp();
    let code = rig.current_code();
    let resp = rig
        .web_form(
            "/ui/account/totp/regenerate-codes",
            &[("current_totp_code", &code)],
        )
        .await;
    assert_locked(&resp, "console recovery-code regeneration");
}

#[tokio::test]
async fn console_totp_activation_answers_a_locked_password_with_429() {
    let rig = rig(false).await;
    rig.identity
        .enroll_totp(&rig.realm_id, &rig.user_id)
        .expect("pending enrolment");
    rig.lock_password();
    let resp = rig
        .web_form(
            "/ui/account/totp/activate",
            &[("password", PASSWORD), ("code", "123456")],
        )
        .await;
    assert_locked(&resp, "console TOTP activation");
}

#[tokio::test]
async fn console_password_change_answers_a_locked_password_with_429() {
    let rig = rig(false).await;
    rig.lock_password();
    let fresh = "a-brand-new-passphrase-42";
    let resp = rig
        .web_form(
            "/ui/account/password",
            &[
                ("current_password", PASSWORD),
                ("new_password", fresh),
                ("confirm_password", fresh),
            ],
        )
        .await;
    assert_locked(&resp, "console password change");
}
