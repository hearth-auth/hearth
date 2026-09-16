//! 19.13 (audit 2026-08-28 §4.18#6) — SMS-OTP and email-OTP factors and the
//! direct browser login.
//!
//! `POST /ui/login` chose its MFA branch on `mfa_enabled`, which answers for
//! TOTP alone. A user whose only enrolled factor was an SMS or email OTP was
//! therefore invisible to the gate:
//!
//! * on an `mfa_required` realm they were sent to *forced TOTP enrolment*, as
//!   though they held nothing at all;
//! * on any other realm the login skipped straight past their factor and
//!   issued the session.
//!
//! The login now routes them to `/ui/mfa-otp-challenge`, which delivers a code
//! over the factor they hold and completes the login with `MfaProof::Proved`.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, Response, StatusCode};
use hearth::core::{Clock, RealmId, SystemClock, UserId};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, RealmConfig, UpdateUserRequest,
    UserStatus,
};
use hearth::protocol::web::auth::{MFA_PENDING_COOKIE, SESSION_COOKIE};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::EmbeddedRbacEngine;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use tower::ServiceExt as _;

const COOKIE_SECRET_BYTES: [u8; 32] = [11u8; 32];

fn password() -> String {
    ["correct-horse", "battery", "staple"].join("-")
}

fn email_service() -> Arc<EmailService> {
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

struct Rig {
    app: axum::Router,
    identity: Arc<dyn IdentityEngine>,
    realm_id: RealmId,
    user_id: UserId,
}

/// Builds a router over a realm whose `mfa_methods` offers email OTP, with a
/// user who has it enrolled and no TOTP.
fn build_rig(mfa_required: bool) -> Rig {
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
            name: format!("otp-login-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                mfa_required: Some(mfa_required),
                mfa_methods: Some(vec!["email_otp".to_string()]),
                ..RealmConfig::default()
            }),
        })
        .expect("create realm");
    let user = identity
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: "otp-user@acme.test".to_string(),
                display_name: "Otto".to_string(),
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
                email_otp_enabled: Some(true),
                ..Default::default()
            },
        )
        .expect("enable email OTP");

    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&identity),
        authz.clone() as Arc<dyn hearth::rbac::RbacEngine>,
        email_service(),
        data_dir,
    ));
    let state = WebState::new(
        Arc::clone(&identity),
        authz as Arc<dyn hearth::rbac::RbacEngine>,
        audit as Arc<dyn hearth::audit::AuditEngine>,
        onboarding,
        CookieSecret::from_bytes(COOKIE_SECRET_BYTES),
        Some(email_service()),
    );
    let app = web::router(state);

    Rig {
        app,
        identity,
        realm_id: realm.id().clone(),
        user_id: user.id().clone(),
    }
}

fn header_str<'a>(resp: &'a Response<Body>, name: header::HeaderName) -> Option<&'a str> {
    resp.headers().get(name).and_then(|v| v.to_str().ok())
}

fn has_cookie(resp: &Response<Body>, name: &str) -> bool {
    resp.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.starts_with(&format!("{name}=")))
}

async fn post_login(rig: &Rig) -> Response<Body> {
    rig.app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "email=otp-user@acme.test&password={}",
                    password()
                )))
                .expect("build login request"),
        )
        .await
        .expect("login")
}

/// §4.18#6: an email-OTP-only user on an `mfa_required` realm must be
/// challenged for the factor they hold, not marched through TOTP enrolment as
/// if they had none.
#[tokio::test]
async fn login_challenges_an_email_otp_factor_instead_of_forcing_totp_enrolment() {
    let rig = build_rig(/* mfa_required */ true);
    let resp = post_login(&rig).await;

    assert_eq!(
        header_str(&resp, header::LOCATION),
        Some("/ui/mfa-otp-challenge"),
        "an enrolled email-OTP factor must be challenged, not treated as absent"
    );
    assert!(
        has_cookie(&resp, MFA_PENDING_COOKIE),
        "the challenge needs the pending cookie that proves the password step"
    );
    assert!(
        !has_cookie(&resp, SESSION_COOKIE),
        "no session may be issued before the second factor is proved"
    );
}

/// §4.18#6: the same user on a realm that does *not* mandate MFA. Their own
/// enrolment must still be honoured — TOTP has always been challenged here
/// regardless of realm policy, and an OTP factor is no different.
#[tokio::test]
async fn login_challenges_an_email_otp_factor_even_when_the_realm_does_not_require_mfa() {
    let rig = build_rig(/* mfa_required */ false);
    let resp = post_login(&rig).await;

    assert!(
        !has_cookie(&resp, SESSION_COOKIE),
        "an enrolled OTP factor must not be skipped on the way to a session"
    );
    assert_eq!(
        header_str(&resp, header::LOCATION),
        Some("/ui/mfa-otp-challenge"),
        "the OTP challenge must run before the session is issued"
    );
}

/// Control: a user with no OTP factor lands somewhere *else*, so the two
/// assertions above are not simply observing "every login redirects".
///
/// The realm here offers `email_otp` only, so the enrolment branch is the
/// email-OTP required action rather than forced TOTP — a realm that does not
/// offer TOTP must not be sent to a TOTP enrolment page it would then refuse
/// (§4.18#10).
#[tokio::test]
async fn login_without_any_factor_routes_to_enrolment_not_to_the_otp_challenge() {
    let rig = build_rig(/* mfa_required */ true);
    rig.identity
        .update_user(
            &rig.realm_id,
            &rig.user_id,
            &UpdateUserRequest {
                email_otp_enabled: Some(false),
                ..Default::default()
            },
        )
        .expect("disable email OTP");

    let resp = post_login(&rig).await;
    let location = header_str(&resp, header::LOCATION).unwrap_or_default();
    assert_ne!(
        location, "/ui/mfa-otp-challenge",
        "a user with nothing enrolled must not be challenged for a factor they lack"
    );
    assert!(
        location.contains("ENROLL_EMAIL_OTP") || location == "/ui/mfa-enroll-required",
        "a user holding no factor must be routed to enrolment, got {location:?}"
    );
    assert!(
        !has_cookie(&resp, SESSION_COOKIE),
        "an mfa_required realm must not issue a session to a factorless user"
    );
}

/// The challenge page must render, mint a CSRF token and carry the opaque OTP
/// handle its POST needs — otherwise the redirect above is a dead end.
#[tokio::test]
async fn otp_challenge_page_renders_a_verifiable_form() {
    let rig = build_rig(/* mfa_required */ true);
    let login = post_login(&rig).await;
    let pending = login
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with(&format!("{MFA_PENDING_COOKIE}=")))
        .and_then(|v| v.split(';').next())
        .expect("pending cookie")
        .to_string();

    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/mfa-otp-challenge")
                .header(header::COOKIE, pending)
                .body(Body::empty())
                .expect("build challenge request"),
        )
        .await
        .expect("challenge page");

    assert_eq!(resp.status(), StatusCode::OK, "challenge page must render");
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("body");
    let html = String::from_utf8_lossy(&body).to_string();
    assert!(
        html.contains(r#"name="_csrf""#),
        "the OTP form must carry a CSRF token"
    );
    assert!(
        html.contains(r#"name="otp_nonce""#) && html.contains(r#"value="email_otp""#),
        "the OTP form must carry the pending-OTP handle and the factor it verifies"
    );
}
