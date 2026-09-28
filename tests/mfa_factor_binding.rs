//! A second factor the USER holds binds on every login path (GA audit
//! 2026-09-28, findings B4 and B5).
//!
//! `create_session` used to read realm policy only (`mfa_required`,
//! `webauthn_required`), so any path that never challenged the user's own
//! enrolled factor — a magic link, a password login for a passkey-only user, a
//! federated login — opened a full session. And `has_second_factor` ignored
//! passkeys, so an `mfa_required` realm pushed a passkey-only user whose
//! password was stolen into enrolling a TOTP the attacker controls.
//!
//! These tests drive the engine gate, the `/ui` router and the `/token`
//! endpoint.

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
    CleartextPassword, CreateRealmRequest, CreateUserRequest, IdentityError, MfaProof, RealmConfig,
    RegistrationOptions, SessionContext, UpdateUserRequest, User, UserStatus,
};
use tower::ServiceExt as _;

const RP_ID: &str = "example.com";
const ORIGIN: &str = "http://example.com";

fn password() -> String {
    ["factor", "binding", "horse", "staple"].join("-")
}

fn create_realm(h: &common::TestHarness, config: RealmConfig) -> (RealmId, String) {
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("fb-{}", uuid::Uuid::new_v4().simple()),
            config: Some(config),
        })
        .expect("create realm");
    (realm.id().clone(), realm.name().to_string())
}

/// An active user with a password.
fn create_user(h: &common::TestHarness, realm: &RealmId) -> User {
    let user = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("u-{}@example.com", uuid::Uuid::new_v4().simple()),
                display_name: "Factor User".to_string(),
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

fn enrol_totp(h: &common::TestHarness, realm: &RealmId, user: &User) {
    let enrollment = h
        .identity()
        .enroll_totp(realm, user.id())
        .expect("enroll_totp");
    let code = compute_totp_code(&enrollment.secret_base32, now_secs());
    h.identity()
        .verify_totp_enrollment(realm, user.id(), &code)
        .expect("verify_totp_enrollment");
}

/// Registers a passkey for `user` and returns the authenticator holding it.
fn enrol_passkey(
    h: &common::TestHarness,
    realm: &RealmId,
    user: &User,
    user_verified: bool,
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
    let (cdj, att) = if user_verified {
        authenticator.build_verified_registration_response(&challenge, ORIGIN)
    } else {
        authenticator.build_registration_response(&challenge, ORIGIN)
    };
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
        Arc::clone(&email),
        data_dir,
    ));
    let state = WebState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
        onboarding,
        CookieSecret::from_bytes([9u8; 32]),
        Some(email),
    )
    .with_dev_mode(true);
    web::router(state)
}

fn set_cookies(response: &axum::response::Response) -> Vec<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(str::to_string))
        .collect()
}

/// The `name=value` pair of a cookie the response set (not a clearing one).
fn cookie_pair(cookies: &[String], name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    cookies
        .iter()
        .filter(|c| c.starts_with(&prefix) && !c.contains("Max-Age=0"))
        .filter_map(|c| c.split(';').next().map(str::to_string))
        .find(|pair| pair.len() > prefix.len())
}

fn has_session_cookie(cookies: &[String]) -> bool {
    cookie_pair(cookies, "hearth_ui_session").is_some()
}

fn location(response: &axum::response::Response) -> String {
    response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

async fn body_text(response: axum::response::Response) -> String {
    let bytes = to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("read body");
    String::from_utf8_lossy(&bytes).into_owned()
}

async fn get(app: &axum::Router, uri: &str, cookie: Option<&str>) -> axum::response::Response {
    let mut req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("host", RP_ID);
    if let Some(c) = cookie {
        req = req.header(header::COOKIE, c);
    }
    app.clone()
        .oneshot(req.body(Body::empty()).expect("build GET"))
        .await
        .expect("oneshot")
}

async fn post_json(
    app: &axum::Router,
    uri: &str,
    cookie: Option<&str>,
    body: &serde_json::Value,
) -> axum::response::Response {
    let mut req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("host", RP_ID)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(c) = cookie {
        req = req.header(header::COOKIE, c);
    }
    app.clone()
        .oneshot(req.body(Body::from(body.to_string())).expect("build POST"))
        .await
        .expect("oneshot")
}

async fn post_login(app: &axum::Router, realm_name: &str, email: &str) -> axum::response::Response {
    // Test addresses and the password are plain ASCII; only `@` needs escaping.
    let body = format!(
        "email={}&password={}",
        email.replace('@', "%40"),
        password()
    );
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/realms/{realm_name}/login"))
                .header("host", RP_ID)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .expect("build login"),
        )
        .await
        .expect("oneshot")
}

// ─── the engine gate ────────────────────────────────────────────────────────

/// B4 root cause: on a realm that does NOT set `mfa_required`, a user who
/// enrolled TOTP must still not be handed a session by a path that proved no
/// second factor.
#[tokio::test]
async fn an_unproved_session_is_refused_for_a_totp_holder_on_an_optional_mfa_realm() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm, _) = create_realm(&h, RealmConfig::default());
    let user = create_user(&h, &realm);
    enrol_totp(&h, &realm, &user);

    let err = h
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect_err("an enrolled, unproved TOTP must refuse the session");
    assert!(
        matches!(err, IdentityError::MfaRequired),
        "expected MfaRequired, got {err:?}"
    );

    // The control: the same user, having proved the factor, is admitted.
    let session = h
        .identity()
        .create_session(
            &realm,
            user.id(),
            &SessionContext {
                mfa_proof: MfaProof::Proved,
                ..SessionContext::default()
            },
        )
        .expect("a proved factor opens the session");
    assert_eq!(session.user_id(), user.id());
}

/// B5: a passkey is a second factor. A path that proved nothing is refused.
#[tokio::test]
async fn an_unproved_session_is_refused_for_a_passkey_holder() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm, _) = create_realm(&h, RealmConfig::default());
    let user = create_user(&h, &realm);
    enrol_passkey(&h, &realm, &user, true);

    assert!(
        h.identity()
            .has_second_factor(&realm, user.id())
            .expect("has_second_factor"),
        "a registered passkey must count as a second factor"
    );
    assert!(
        h.identity()
            .has_passkey_factor(&realm, user.id())
            .expect("has_passkey_factor"),
        "has_passkey_factor must report the registered passkey"
    );
    let err = h
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect_err("an enrolled, unproved passkey must refuse the session");
    assert!(
        matches!(err, IdentityError::MfaRequired),
        "expected MfaRequired, got {err:?}"
    );
}

/// A UV-less passkey login is possession of the passkey the account holds.
/// It opens a session for a passkey-only user, and is refused for a user who
/// also holds TOTP — that factor is still owed.
#[tokio::test]
async fn passkey_possession_satisfies_only_a_passkey_only_user() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm, _) = create_realm(&h, RealmConfig::default());
    let ctx = SessionContext {
        mfa_proof: MfaProof::PasskeyPossession,
        ..SessionContext::default()
    };

    let passkey_only = create_user(&h, &realm);
    enrol_passkey(&h, &realm, &passkey_only, false);
    h.identity()
        .create_session(&realm, passkey_only.id(), &ctx)
        .expect("the passkey the user holds is the factor this ceremony used");

    let both = create_user(&h, &realm);
    enrol_passkey(&h, &realm, &both, false);
    enrol_totp(&h, &realm, &both);
    let err = h
        .identity()
        .create_session(&realm, both.id(), &ctx)
        .expect_err("the enrolled TOTP is still owed");
    assert!(matches!(err, IdentityError::MfaRequired), "got {err:?}");
}

/// The session records what its authentication proved, and the record
/// survives a reload from storage.
#[tokio::test]
async fn a_session_records_the_proof_its_authentication_made() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm, _) = create_realm(&h, RealmConfig::default());
    let user = create_user(&h, &realm);
    let session = h
        .identity()
        .create_session(
            &realm,
            user.id(),
            &SessionContext {
                mfa_proof: MfaProof::ProvedWebAuthn,
                ..SessionContext::default()
            },
        )
        .expect("create session");
    let loaded = h
        .identity()
        .get_session(&realm, session.id())
        .expect("get session")
        .expect("session exists");
    assert_eq!(loaded.mfa_proof(), MfaProof::ProvedWebAuthn);

    let plain = h
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("a user with no factor needs no proof");
    let loaded = h
        .identity()
        .get_session(&realm, plain.id())
        .expect("get session")
        .expect("session exists");
    assert_eq!(loaded.mfa_proof(), MfaProof::None);
}

// ─── B4: magic link ─────────────────────────────────────────────────────────

/// Browser magic-link redemption for a TOTP holder must send the browser to
/// the TOTP challenge with a pending cookie — never set a session cookie.
#[tokio::test]
async fn magic_link_redemption_challenges_an_enrolled_totp() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm, realm_name) = create_realm(&h, RealmConfig::default());
    let user = create_user(&h, &realm);
    enrol_totp(&h, &realm, &user);
    let minted = h
        .identity()
        .request_magic_link(&realm, user.email())
        .expect("mint magic link");
    let app = build_web_app(&h);

    let response = get(
        &app,
        &format!("/ui/realms/{realm_name}/magic-link"),
        // GA audit L18: the link's first GET moved the token into this cookie.
        Some(&format!("hearth_link_token={}", minted.token())),
    )
    .await;
    let cookies = set_cookies(&response);
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&response), "/ui/mfa-challenge");
    assert!(
        cookie_pair(&cookies, "hearth_ui_mfa_pending").is_some(),
        "the challenge needs the pending cookie: {cookies:?}"
    );
    assert!(
        !has_session_cookie(&cookies),
        "a magic link must not skip the enrolled TOTP: {cookies:?}"
    );
}

/// The same for a passkey-only user: the passkey is challenged.
#[tokio::test]
async fn magic_link_redemption_challenges_an_enrolled_passkey() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm, realm_name) = create_realm(&h, RealmConfig::default());
    let user = create_user(&h, &realm);
    enrol_passkey(&h, &realm, &user, true);
    let minted = h
        .identity()
        .request_magic_link(&realm, user.email())
        .expect("mint magic link");
    let app = build_web_app(&h);

    let response = get(
        &app,
        &format!("/ui/realms/{realm_name}/magic-link"),
        // GA audit L18: the link's first GET moved the token into this cookie.
        Some(&format!("hearth_link_token={}", minted.token())),
    )
    .await;
    let cookies = set_cookies(&response);
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&response), "/ui/mfa-passkey-challenge");
    assert!(!has_session_cookie(&cookies), "cookies: {cookies:?}");
}

/// A user with no second factor still signs in with the link alone.
#[tokio::test]
async fn magic_link_redemption_still_signs_in_a_user_without_a_factor() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm, realm_name) = create_realm(&h, RealmConfig::default());
    let user = create_user(&h, &realm);
    let minted = h
        .identity()
        .request_magic_link(&realm, user.email())
        .expect("mint magic link");
    let app = build_web_app(&h);

    let response = get(
        &app,
        &format!("/ui/realms/{realm_name}/magic-link"),
        // GA audit L18: the link's first GET moved the token into this cookie.
        Some(&format!("hearth_link_token={}", minted.token())),
    )
    .await;
    let cookies = set_cookies(&response);
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(has_session_cookie(&cookies), "cookies: {cookies:?}");
}

async fn magic_link_grant(
    h: &common::TestHarness,
    realm: &RealmId,
    token: &str,
) -> (StatusCode, String) {
    use hearth::protocol::http::{router, AppState};
    let app = router(Arc::new(AppState::new_dev(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
    )));
    let body = serde_json::json!({
        "grant_type": "urn:hearth:grant-type:magic-link",
        "token": token,
    });
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .expect("build POST"),
        )
        .await
        .expect("oneshot");
    let status = response.status();
    (status, body_text(response).await)
}

/// The `/token` magic-link grant has no challenge surface, so it must refuse
/// a user who holds a second factor instead of minting tokens.
#[tokio::test]
async fn magic_link_grant_refuses_a_user_who_holds_a_second_factor() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm, _) = create_realm(&h, RealmConfig::default());
    let user = create_user(&h, &realm);
    enrol_totp(&h, &realm, &user);
    let minted = h
        .identity()
        .request_magic_link(&realm, user.email())
        .expect("mint magic link");

    let (status, text) = magic_link_grant(&h, &realm, minted.token()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body: {text}");
    assert!(
        !text.contains("access_token"),
        "no tokens may be issued: {text}"
    );
    assert!(text.contains("HEARTH_MFA_REQUIRED"), "body: {text}");
}

// ─── B5: password login for a passkey holder ────────────────────────────────

/// On a realm that does not require MFA, a correct password for a user who
/// holds a passkey must lead to a passkey challenge, not a session.
#[tokio::test]
async fn password_login_challenges_an_enrolled_passkey() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm, realm_name) = create_realm(&h, RealmConfig::default());
    let user = create_user(&h, &realm);
    enrol_passkey(&h, &realm, &user, true);
    let app = build_web_app(&h);

    let response = post_login(&app, &realm_name, user.email()).await;
    let cookies = set_cookies(&response);
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&response), "/ui/mfa-passkey-challenge");
    assert!(cookie_pair(&cookies, "hearth_ui_mfa_pending").is_some());
    assert!(!has_session_cookie(&cookies), "cookies: {cookies:?}");
}

/// The B5 account takeover: on an `mfa_required` realm a passkey-only user
/// was sent to forced TOTP enrolment, where the password holder enrolled a
/// TOTP of their own. They must be sent to the passkey challenge instead, and
/// the enrolment page must refuse them outright.
#[tokio::test]
async fn an_mfa_required_realm_never_offers_forced_enrolment_to_a_passkey_holder() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm, realm_name) = create_realm(
        &h,
        RealmConfig {
            mfa_required: Some(true),
            ..RealmConfig::default()
        },
    );
    let user = create_user(&h, &realm);
    enrol_passkey(&h, &realm, &user, true);
    let app = build_web_app(&h);

    let response = post_login(&app, &realm_name, user.email()).await;
    let cookies = set_cookies(&response);
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&response),
        "/ui/mfa-passkey-challenge",
        "a passkey holder must be challenged, not offered TOTP enrolment"
    );
    let pending = cookie_pair(&cookies, "hearth_ui_mfa_pending").expect("pending cookie");

    // Going straight to the enrolment page with the pending cookie must not
    // mint a TOTP secret for the password holder.
    let enrol = get(&app, "/ui/mfa-enroll-required", Some(&pending)).await;
    let status = enrol.status();
    let loc = location(&enrol);
    let text = body_text(enrol).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "body: {text}");
    assert_eq!(loc, "/ui/mfa-passkey-challenge");
    assert!(
        !h.identity()
            .mfa_enabled(&realm, user.id())
            .expect("mfa_enabled"),
        "no TOTP may be enrolled"
    );
}

/// Runs the passkey second-factor ceremony with `authenticator` under the
/// pending cookie and returns the completion response.
async fn complete_passkey_challenge(
    app: &axum::Router,
    pending: &str,
    authenticator: &webauthn_helper::TestAuthenticator,
    user_verified: bool,
) -> axum::response::Response {
    let page = get(app, "/ui/mfa-passkey-challenge", Some(pending)).await;
    assert_eq!(
        page.status(),
        StatusCode::OK,
        "the challenge page must render"
    );

    let begin = post_json(
        app,
        "/ui/mfa-passkey-challenge/begin",
        Some(pending),
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(begin.status(), StatusCode::OK, "begin must succeed");
    let begin_json: serde_json::Value =
        serde_json::from_str(&body_text(begin).await).expect("begin JSON");
    let challenge = URL_SAFE_NO_PAD
        .decode(begin_json["challenge"].as_str().expect("challenge"))
        .expect("challenge is base64url");
    assert!(
        begin_json["allowCredentials"]
            .as_array()
            .is_some_and(|a| !a.is_empty()),
        "the options must name the pending user's credentials: {begin_json}"
    );

    let (cdj, auth_data, sig, _) = if user_verified {
        authenticator.build_verified_authentication_response(&challenge, ORIGIN, 1, None)
    } else {
        authenticator.build_authentication_response(&challenge, ORIGIN, 1, None)
    };
    post_json(
        app,
        "/ui/mfa-passkey-challenge/complete",
        Some(pending),
        &serde_json::json!({
            "credential_id": URL_SAFE_NO_PAD.encode(&authenticator.credential_id),
            "client_data_json": URL_SAFE_NO_PAD.encode(&cdj),
            "authenticator_data": URL_SAFE_NO_PAD.encode(&auth_data),
            "signature": URL_SAFE_NO_PAD.encode(&sig),
        }),
    )
    .await
}

/// The password + passkey login completes, and the session records the
/// WebAuthn proof.
#[tokio::test]
async fn the_passkey_challenge_completes_a_password_login() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm, realm_name) = create_realm(&h, RealmConfig::default());
    let user = create_user(&h, &realm);
    let authenticator = enrol_passkey(&h, &realm, &user, true);
    let app = build_web_app(&h);

    let login = post_login(&app, &realm_name, user.email()).await;
    let pending =
        cookie_pair(&set_cookies(&login), "hearth_ui_mfa_pending").expect("pending cookie");

    let complete = complete_passkey_challenge(&app, &pending, &authenticator, true).await;
    let cookies = set_cookies(&complete);
    let status = complete.status();
    let text = body_text(complete).await;
    assert_eq!(status, StatusCode::OK, "body: {text}");
    assert!(text.contains("redirect"), "body: {text}");
    let session_pair = cookie_pair(&cookies, "hearth_ui_session").expect("session cookie");
    let sid = session_pair
        .trim_start_matches("hearth_ui_session=")
        .split('.')
        .next()
        .expect("session id")
        .to_string();
    let session = h
        .identity()
        .get_session(
            &realm,
            &hearth::core::SessionId::new(uuid::Uuid::parse_str(&sid).expect("uuid")),
        )
        .expect("get session")
        .expect("session exists");
    assert_eq!(session.mfa_proof(), MfaProof::ProvedWebAuthn);
}

/// An assertion from ANOTHER user's passkey must not complete this user's
/// pending login.
#[tokio::test]
async fn the_passkey_challenge_refuses_another_users_passkey() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm, realm_name) = create_realm(&h, RealmConfig::default());
    let victim = create_user(&h, &realm);
    enrol_passkey(&h, &realm, &victim, true);
    let attacker = create_user(&h, &realm);
    let attacker_key = enrol_passkey(&h, &realm, &attacker, true);
    let app = build_web_app(&h);

    let login = post_login(&app, &realm_name, victim.email()).await;
    let pending =
        cookie_pair(&set_cookies(&login), "hearth_ui_mfa_pending").expect("pending cookie");
    let complete = complete_passkey_challenge(&app, &pending, &attacker_key, true).await;
    let cookies = set_cookies(&complete);
    assert_ne!(complete.status(), StatusCode::OK);
    assert!(!has_session_cookie(&cookies), "cookies: {cookies:?}");
}

// ─── B5: client `mfa_required` reads factor USE ─────────────────────────────

const REDIRECT: &str = "https://app.example.com/cb";
const PKCE_VERIFIER: &str = "factor-binding-verifier-verifier-verifier-01";

fn mfa_client(h: &common::TestHarness, realm: &RealmId) -> hearth::identity::OAuthClient {
    h.identity()
        .register_client(
            realm,
            &hearth::identity::RegisterClientRequest {
                client_name: "MFA-required app".to_string(),
                redirect_uris: vec![REDIRECT.to_string()],
                require_consent: false,
                grant_types: vec!["authorization_code".to_string()],
                trust_level: hearth::identity::ClientTrustLevel::FirstParty,
                mfa_required: Some(true),
                ..Default::default()
            },
        )
        .expect("register client")
}

async fn authorize(
    app: &axum::Router,
    realm_name: &str,
    client: &hearth::identity::OAuthClient,
    cookies: &str,
) -> String {
    let challenge = data_encoding::BASE64URL_NOPAD
        .encode(ring::digest::digest(&ring::digest::SHA256, PKCE_VERIFIER.as_bytes()).as_ref());
    let uri = format!(
        "/ui/realms/{realm_name}/oauth/authorize?client_id={}\
         &redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&response_type=code&scope=openid\
         &state=s1&code_challenge={challenge}&code_challenge_method=S256",
        client.client_id().as_uuid()
    );
    let response = get(app, &uri, Some(cookies)).await;
    assert!(
        response.status().is_redirection(),
        "authorize must redirect, got {}",
        response.status()
    );
    location(&response)
}

/// B5, trigger A: a session opened before the user held a factor proved
/// nothing. A client that sets `mfa_required` must not be issued a code on
/// the strength of the passkey the account holds now — the session has to
/// prove it.
#[tokio::test]
async fn an_mfa_required_client_refuses_a_session_that_proved_no_factor() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm, realm_name) = create_realm(&h, RealmConfig::default());
    let user = create_user(&h, &realm);
    let client = mfa_client(&h, &realm);
    let app = build_web_app(&h);

    // Password-only login: the user holds no factor yet, so no proof.
    let login = post_login(&app, &realm_name, user.email()).await;
    let session = cookie_pair(&set_cookies(&login), "hearth_ui_session").expect("session");
    // The account gains a passkey afterwards.
    enrol_passkey(&h, &realm, &user, true);

    let loc = authorize(&app, &realm_name, &client, &session).await;
    assert!(
        loc.starts_with(REDIRECT) && loc.contains("error=login_required"),
        "the client must be told to re-authenticate: {loc}"
    );
    assert!(!loc.contains("code="), "no code may be issued: {loc}");
}

/// The control: a session that proved the passkey is issued the code.
#[tokio::test]
async fn an_mfa_required_client_accepts_a_session_that_proved_a_factor() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm, realm_name) = create_realm(&h, RealmConfig::default());
    let user = create_user(&h, &realm);
    let authenticator = enrol_passkey(&h, &realm, &user, true);
    let client = mfa_client(&h, &realm);
    let app = build_web_app(&h);

    let login = post_login(&app, &realm_name, user.email()).await;
    let pending =
        cookie_pair(&set_cookies(&login), "hearth_ui_mfa_pending").expect("pending cookie");
    let complete = complete_passkey_challenge(&app, &pending, &authenticator, true).await;
    let session = cookie_pair(&set_cookies(&complete), "hearth_ui_session").expect("session");

    let loc = authorize(&app, &realm_name, &client, &session).await;
    assert!(
        loc.starts_with(REDIRECT) && loc.contains("code="),
        "a proved factor must get the code: {loc}"
    );
}
