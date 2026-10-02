//! Every login path enforces pending required actions and the realm's network
//! policy (GA audit 2026-09-28, findings M11 and M13).
//!
//! The password form ran the required-action gate and the realm's
//! `cidr_policy` ("CIDRs permitted to authenticate"); the passkey login, the
//! magic link (browser and `/token` grant) and the step-up MFA grant ran
//! neither. An operator-forced password change could be walked around by
//! signing in another way, and the network restriction held only for one
//! form.

mod common;

#[path = "common/webauthn_helper.rs"]
mod webauthn_helper;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hearth::core::RealmId;
use hearth::identity::{
    CidrPolicy, CleartextPassword, CreateRealmRequest, CreateUserRequest, RealmConfig,
    RegistrationOptions, RequiredAction, SessionContext, UpdateUserRequest, User, UserStatus,
};
use tower::ServiceExt as _;

const RP_ID: &str = "example.com";
const ORIGIN: &str = "http://example.com";

fn password() -> String {
    ["policy", "paths", "horse", "staple"].join("-")
}

/// Denies the loopback range, which is where every request in these tests
/// comes from (no `ConnectInfo`, so the peer is the loopback fallback).
fn loopback_denied() -> RealmConfig {
    RealmConfig {
        cidr_policy: Some(CidrPolicy {
            allow: Vec::new(),
            deny: vec!["127.0.0.0/8".to_string()],
        }),
        ..RealmConfig::default()
    }
}

fn create_realm(h: &common::TestHarness, config: RealmConfig) -> (RealmId, String) {
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("pol-{}", uuid::Uuid::new_v4().simple()),
            config: Some(config),
        })
        .expect("create realm");
    (realm.id().clone(), realm.name().to_string())
}

fn create_user(h: &common::TestHarness, realm: &RealmId) -> User {
    let user = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("p-{}@example.com", uuid::Uuid::new_v4().simple()),
                display_name: "Policy User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
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
                ..Default::default()
            },
        )
        .expect("activate user");
    h.identity()
        .get_user(realm, user.id())
        .expect("get user")
        .expect("user exists")
}

fn require_password_change(h: &common::TestHarness, realm: &RealmId, user: &User) {
    h.identity()
        .update_user(
            realm,
            user.id(),
            &UpdateUserRequest {
                required_actions: Some(vec![RequiredAction::UpdatePassword]),
                ..Default::default()
            },
        )
        .expect("require a password change");
}

fn compute_totp_code(secret_base32: &str, unix_secs: u64) -> String {
    let secret_bytes = data_encoding::BASE32_NOPAD
        .decode(secret_base32.as_bytes())
        .expect("decode base32");
    let step = unix_secs / 30;
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &secret_bytes);
    let tag = ring::hmac::sign(&key, &step.to_be_bytes());
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

/// Enrols TOTP and returns the secret.
fn enrol_totp(h: &common::TestHarness, realm: &RealmId, user: &User) -> String {
    let enrollment = h
        .identity()
        .enroll_totp(realm, user.id())
        .expect("enroll_totp");
    h.identity()
        .verify_totp_enrollment(
            realm,
            user.id(),
            &compute_totp_code(&enrollment.secret_base32, now_secs()),
        )
        .expect("verify_totp_enrollment");
    enrollment.secret_base32.clone()
}

fn enrol_passkey(
    h: &common::TestHarness,
    realm: &RealmId,
    user: &User,
) -> webauthn_helper::TestAuthenticator {
    let authenticator = webauthn_helper::TestAuthenticator::new(RP_ID);
    let challenge = h
        .identity()
        .start_webauthn_registration(
            realm,
            user.id(),
            &RegistrationOptions {
                rp_id: RP_ID.to_string(),
                discoverable: true,
            },
        )
        .expect("start registration");
    let (cdj, att) = authenticator.build_verified_registration_response(&challenge, ORIGIN);
    h.identity()
        .complete_webauthn_registration(realm, user.id(), &cdj, &att, ORIGIN, true)
        .expect("complete registration");
    authenticator
}

fn build_web_app(h: &common::TestHarness) -> axum::Router {
    use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
    use hearth::identity::onboarding::OnboardingService;
    use hearth::protocol::web::{self, CookieSecret, WebState};

    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);
    let email = Arc::new(
        EmailService::new(
            Arc::new(LoggingEmailSender::new()),
            "Hearth".to_string(),
            None,
            EmailBranding::default(),
            String::new(),
            None,
        )
        .expect("email service"),
    );
    let onboarding = Arc::new(OnboardingService::new(
        h.identity_arc(),
        h.rbac_arc(),
        email,
        data_dir,
    ));
    let state = WebState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
        onboarding,
        CookieSecret::from_bytes([4u8; 32]),
        None,
    )
    .with_dev_mode(true);
    web::router(state)
}

fn rest_app(h: &common::TestHarness) -> axum::Router {
    use hearth::protocol::http::{router, AppState};
    router(Arc::new(AppState::new_dev(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
    )))
}

fn set_cookies(response: &axum::response::Response) -> Vec<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(str::to_string))
        .collect()
}

fn has_session_cookie(cookies: &[String]) -> bool {
    cookies
        .iter()
        .any(|c| c.starts_with("hearth_ui_session=") && !c.contains("Max-Age=0"))
}

async fn body_text(response: axum::response::Response) -> String {
    String::from_utf8_lossy(&to_bytes(response.into_body(), 1 << 20).await.expect("body"))
        .into_owned()
}

async fn redeem_magic_link(
    h: &common::TestHarness,
    realm: &RealmId,
    realm_name: &str,
    user: &User,
) -> axum::response::Response {
    let minted = h
        .identity()
        .request_magic_link(realm, user.email())
        .expect("mint magic link");
    build_web_app(h)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/realms/{realm_name}/magic-link"))
                // GA audit L18: the link's first GET moved the token into
                // this cookie; the confirmation page's POST redeems it.
                .header(
                    axum::http::header::COOKIE,
                    format!("hearth_link_token={}", minted.token()),
                )
                .header(
                    axum::http::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .body(Body::from(format!(
                    "link_binding={}",
                    hearth::protocol::web::link_token::link_binding(
                        &hearth::protocol::web::CookieSecret::from_bytes([4u8; 32]),
                        minted.token()
                    )
                )))
                .expect("build POST"),
        )
        .await
        .expect("oneshot")
}

async fn magic_link_grant(
    h: &common::TestHarness,
    realm: &RealmId,
    user: &User,
) -> (StatusCode, String) {
    let minted = h
        .identity()
        .request_magic_link(realm, user.email())
        .expect("mint magic link");
    let response = rest_app(h)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "grant_type": "urn:hearth:grant-type:magic-link",
                        "token": minted.token(),
                    })
                    .to_string(),
                ))
                .expect("build POST"),
        )
        .await
        .expect("oneshot");
    let status = response.status();
    (status, body_text(response).await)
}

async fn step_up_grant(
    h: &common::TestHarness,
    realm: &RealmId,
    user: &User,
    secret: &str,
) -> (StatusCode, String) {
    let body = format!(
        "grant_type=urn%3Ahearth%3Aparams%3Agrant-type%3Astep-up-mfa&username={}&password={}&mfa_code={}",
        user.email().replace('@', "%40"),
        password(),
        compute_totp_code(secret, now_secs() + 30),
    );
    let response = rest_app(h)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .expect("build POST"),
        )
        .await
        .expect("oneshot");
    let status = response.status();
    (status, body_text(response).await)
}

/// Runs the discoverable passkey login and returns the completion response.
async fn passkey_login(
    h: &common::TestHarness,
    realm_name: &str,
    user: &User,
    authenticator: &webauthn_helper::TestAuthenticator,
) -> axum::response::Response {
    let app = build_web_app(h);
    let begin = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/ui/realms/{realm_name}/login/passkey-begin"))
                .header("host", RP_ID)
                .body(Body::empty())
                .expect("build begin"),
        )
        .await
        .expect("begin");
    assert_eq!(begin.status(), StatusCode::OK);
    let begin_json: serde_json::Value =
        serde_json::from_str(&body_text(begin).await).expect("begin JSON");
    let challenge = URL_SAFE_NO_PAD
        .decode(begin_json["challenge"].as_str().expect("challenge"))
        .expect("base64url");
    let (cdj, auth_data, sig, _) = authenticator.build_verified_authentication_response(
        &challenge,
        ORIGIN,
        1,
        Some(&user.id().as_uuid().to_string()),
    );
    let body = serde_json::json!({
        "credential_id": URL_SAFE_NO_PAD.encode(&authenticator.credential_id),
        "client_data_json": URL_SAFE_NO_PAD.encode(&cdj),
        "authenticator_data": URL_SAFE_NO_PAD.encode(&auth_data),
        "signature": URL_SAFE_NO_PAD.encode(&sig),
        "user_handle": URL_SAFE_NO_PAD.encode(user.id().as_uuid().to_string().as_bytes()),
    });
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri(format!("/ui/realms/{realm_name}/login/passkey-complete"))
            .header("host", RP_ID)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .expect("build complete"),
    )
    .await
    .expect("complete")
}

// ─── M11: pending required actions ──────────────────────────────────────────

/// A passkey login must not walk around a pending password change.
#[tokio::test]
async fn passkey_login_enforces_pending_required_actions() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm, realm_name) = create_realm(&h, RealmConfig::default());
    let user = create_user(&h, &realm);
    let authenticator = enrol_passkey(&h, &realm, &user);
    require_password_change(&h, &realm, &user);

    let response = passkey_login(&h, &realm_name, &user, &authenticator).await;
    let cookies = set_cookies(&response);
    let text = body_text(response).await;
    assert!(!has_session_cookie(&cookies), "no session: {cookies:?}");
    assert!(
        text.contains("/required-action/"),
        "the passkey login must send the user to the pending action: {text}"
    );
}

/// A magic link must not walk around a pending password change.
#[tokio::test]
async fn magic_link_redemption_enforces_pending_required_actions() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm, realm_name) = create_realm(&h, RealmConfig::default());
    let user = create_user(&h, &realm);
    require_password_change(&h, &realm, &user);

    let response = redeem_magic_link(&h, &realm, &realm_name, &user).await;
    let cookies = set_cookies(&response);
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(!has_session_cookie(&cookies), "no session: {cookies:?}");
    assert!(
        location.starts_with("/required-action/"),
        "expected the required-action page, got {location:?}"
    );
}

/// The `/token` magic-link grant refuses a user with pending actions, as the
/// password grant does.
#[tokio::test]
async fn magic_link_grant_enforces_pending_required_actions() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm, _) = create_realm(&h, RealmConfig::default());
    let user = create_user(&h, &realm);
    require_password_change(&h, &realm, &user);

    let (status, text) = magic_link_grant(&h, &realm, &user).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {text}");
    assert!(text.contains("required_actions_pending"), "body: {text}");
    assert!(!text.contains("access_token"), "no tokens: {text}");
}

// ─── M13: the realm's network policy ────────────────────────────────────────

/// The engine refuses a session from a denied network, whatever the path.
#[tokio::test]
async fn a_session_from_a_denied_network_is_refused() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm, _) = create_realm(&h, loopback_denied());
    let user = create_user(&h, &realm);

    h.identity()
        .create_session(
            &realm,
            user.id(),
            &SessionContext {
                ip_address: Some("127.0.0.9".to_string()),
                ..SessionContext::default()
            },
        )
        .expect_err("a denied network must not get a session");
    h.identity()
        .create_session(
            &realm,
            user.id(),
            &SessionContext {
                ip_address: Some("192.0.2.10".to_string()),
                ..SessionContext::default()
            },
        )
        .expect("an allowed network still gets one");
}

/// Deny is evaluated first, then allow: a deny exception carved out of an
/// allowed range refuses its address, while the rest of the range still
/// signs in and everything outside the allow list is refused.
#[tokio::test]
async fn a_deny_exception_inside_an_allowed_range_is_refused() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm, _) = create_realm(
        &h,
        RealmConfig {
            cidr_policy: Some(CidrPolicy {
                allow: vec!["10.0.0.0/8".to_string()],
                deny: vec!["10.1.2.3/32".to_string()],
            }),
            ..RealmConfig::default()
        },
    );
    let user = create_user(&h, &realm);
    let session_from = |ip: &str| {
        h.identity().create_session(
            &realm,
            user.id(),
            &SessionContext {
                ip_address: Some(ip.to_string()),
                ..SessionContext::default()
            },
        )
    };

    session_from("10.1.2.3").expect_err("the denied address inside the allowed range");
    session_from("10.1.2.4").expect("the rest of the allowed range");
    session_from("192.0.2.10").expect_err("outside the allow list");
}

/// The step-up grant from a denied network issues no tokens.
#[tokio::test]
async fn step_up_grant_from_a_denied_network_is_refused() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm, _) = create_realm(&h, loopback_denied());
    let user = create_user(&h, &realm);
    let secret = enrol_totp(&h, &realm, &user);

    let (status, text) = step_up_grant(&h, &realm, &user, &secret).await;
    assert_ne!(status, StatusCode::OK, "body: {text}");
    assert!(!text.contains("access_token"), "no tokens: {text}");
}

/// A magic link redeemed from a denied network signs nobody in.
#[tokio::test]
async fn magic_link_from_a_denied_network_is_refused() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm, realm_name) = create_realm(&h, loopback_denied());
    let user = create_user(&h, &realm);

    let response = redeem_magic_link(&h, &realm, &realm_name, &user).await;
    let cookies = set_cookies(&response);
    assert!(!has_session_cookie(&cookies), "no session: {cookies:?}");

    let (status, text) = magic_link_grant(&h, &realm, &user).await;
    assert_ne!(status, StatusCode::OK, "body: {text}");
    assert!(!text.contains("access_token"), "no tokens: {text}");
}

/// A passkey login from a denied network signs nobody in.
#[tokio::test]
async fn passkey_login_from_a_denied_network_is_refused() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm, realm_name) = create_realm(&h, loopback_denied());
    let user = create_user(&h, &realm);
    let authenticator = enrol_passkey(&h, &realm, &user);

    let response = passkey_login(&h, &realm_name, &user, &authenticator).await;
    let cookies = set_cookies(&response);
    assert!(!has_session_cookie(&cookies), "no session: {cookies:?}");
}
