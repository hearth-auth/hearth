//! The ID token's `amr` claim names the sign-in methods the user proved
//! (OIDC Core §2, values from RFC 8176) (#619).
//!
//! No flow filled `amr` after the SMS removal, so a relying party that needs
//! MFA for a sensitive action could not check it from the token. The values:
//!
//! | Proved | `amr` |
//! |--------|-------|
//! | password | `pwd` |
//! | TOTP or recovery code | `otp` |
//! | passkey | `hwk`, `user` |
//! | a second factor that the MFA policy accepts | `mfa` |
//!
//! An inbox (magic link, email OTP) has no RFC 8176 value and adds nothing.

#[path = "support/browser.rs"]
mod browser;

use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::Response;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use browser::{body_text, hidden_fields, location, Browser};
use hearth::core::{Clock, RealmId, SystemClock, UserId};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CleartextPassword, ClientTrustLevel, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, MfaProof, OAuthClient, RealmConfig,
    RegisterClientRequest, SessionContext, TokenExchangeRequest, UpdateUserRequest, UserStatus,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::EmbeddedRbacEngine;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

const COOKIE_SECRET: [u8; 32] = [61u8; 32];
const CALLBACK: &str = "https://app.example.com/cb";
const VERIFIER: &str = "Zr8mQ2vW5yT1kJ7pX0cN4bF9hL3sD6gA8eU2iO5qR1t";
const EMAIL: &str = "amr-user@acme.test";

fn password() -> String {
    ["Amr", "Claim", "Pa55word!"].concat()
}

struct Rig {
    ui: axum::Router,
    identity: Arc<dyn IdentityEngine>,
    realm_id: RealmId,
    client: OAuthClient,
    user: UserId,
}

/// A realm that offers TOTP and does not require MFA, one active user with a
/// password, and a first-party client.
fn build_rig() -> Rig {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    let _ = temp.keep();
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
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    ));

    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: format!("amr-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                mfa_required: Some(false),
                mfa_methods: Some(vec!["totp".to_string()]),
                ..RealmConfig::default()
            }),
        })
        .expect("create realm");
    let user = identity
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: EMAIL.to_string(),
                display_name: "Amr User".to_string(),
                ..Default::default()
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
                ..Default::default()
            },
        )
        .expect("activate user");
    let client = identity
        .register_client(
            realm.id(),
            &RegisterClientRequest {
                client_name: "Amr App".to_string(),
                redirect_uris: vec![CALLBACK.to_string()],
                require_consent: false,
                grant_types: vec!["authorization_code".to_string()],
                trust_level: ClientTrustLevel::FirstParty,
                ..Default::default()
            },
        )
        .expect("register client");

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
        Arc::clone(&identity),
        Arc::clone(&rbac) as Arc<dyn hearth::rbac::RbacEngine>,
        Arc::clone(&email),
        data_dir,
    ));
    let state = WebState::new(
        Arc::clone(&identity),
        rbac as Arc<dyn hearth::rbac::RbacEngine>,
        audit,
        onboarding,
        CookieSecret::from_bytes(COOKIE_SECRET),
        Some(email),
    );
    Rig {
        ui: web::router(state),
        identity,
        realm_id: realm.id().clone(),
        client,
        user: user.id().clone(),
    }
}

/// Enrols and confirms TOTP for the rig's user. Returns the secret and the
/// time step the confirmation used, which replay protection now refuses.
fn enrol_totp(rig: &Rig) -> (String, u64) {
    let enrollment = rig
        .identity
        .enroll_totp(&rig.realm_id, &rig.user)
        .expect("enroll_totp");
    let step = unix_secs() / 30;
    for candidate in [step, step + 1] {
        let code = totp_code(&enrollment.secret_base32, candidate);
        if rig
            .identity
            .verify_totp_enrollment(&rig.realm_id, &rig.user, &code)
            .is_ok()
        {
            return (enrollment.secret_base32, candidate);
        }
    }
    panic!("TOTP enrolment was not confirmed");
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs()
}

/// RFC 6238 TOTP (SHA-1, 6 digits) for time step `step`.
fn totp_code(secret_base32: &str, step: u64) -> String {
    let secret = data_encoding::BASE32_NOPAD
        .decode(secret_base32.as_bytes())
        .expect("decode base32 secret");
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &secret);
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

/// Posts the real login form with the user's password.
async fn post_password(browser: &mut Browser) -> Response {
    let page = body_text(browser.get("/ui/login").await).await;
    let mut fields = hidden_fields(&page, "/ui/login");
    fields.push(("email".to_string(), EMAIL.to_string()));
    fields.push(("password".to_string(), password()));
    browser.post_form("/ui/login", &fields).await
}

/// Answers the TOTP form on `page` with the code for `step`.
async fn answer_totp(browser: &mut Browser, page: &str, secret: &str, step: u64) {
    let mut fields = hidden_fields(page, "/ui/mfa-challenge");
    fields.push(("code".to_string(), totp_code(secret, step)));
    let resp = browser.post_form("/ui/mfa-challenge", &fields).await;
    let next = location(&resp).expect("the TOTP form redirects");
    assert!(
        !next.contains("mfa-challenge") && !next.contains("/ui/login"),
        "the TOTP code must sign the user in, not ask again: {next}"
    );
}

/// A browser with a session made directly with `proof`, as a sign-in path
/// that proved it would leave.
fn browser_with_session(rig: &Rig, proof: MfaProof) -> Browser {
    let session = rig
        .identity
        .create_session(
            &rig.realm_id,
            &rig.user,
            &SessionContext {
                mfa_proof: proof,
                ..SessionContext::default()
            },
        )
        .expect("browser session");
    let issued = web::auth::issue_auth_cookies(
        &CookieSecret::from_bytes(COOKIE_SECRET),
        &rig.realm_id,
        session.id(),
        false,
    );
    let mut browser = Browser::new(rig.ui.clone());
    browser.accept_set_cookie(&issued.session_cookie, "/ui/login");
    browser.accept_set_cookie(&issued.csrf_cookie, "/ui/login");
    browser
}

/// Runs the browser authorization, exchanges the code, and returns the ID
/// token's `amr`, sorted. Empty when the token has no `amr`.
async fn amr_after_authorize(rig: &Rig, browser: &mut Browser) -> Vec<String> {
    let challenge = URL_SAFE_NO_PAD.encode(ring::digest::digest(
        &ring::digest::SHA256,
        VERIFIER.as_bytes(),
    ));
    let uri = format!(
        "/ui/oauth/authorize?client_id={}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb\
         &response_type=code&scope=openid&state=s&code_challenge={challenge}\
         &code_challenge_method=S256",
        rig.client.client_id().as_uuid(),
    );
    let resp = browser.get(&uri).await;
    let next = location(&resp).expect("authorize redirects");
    assert!(next.starts_with(CALLBACK), "a code is issued: {next}");
    let code = next
        .split("code=")
        .nth(1)
        .and_then(|rest| rest.split('&').next())
        .expect("code parameter")
        .to_string();
    let tokens = rig
        .identity
        .exchange_authorization_code(
            &rig.realm_id,
            &TokenExchangeRequest {
                client_id: rig.client.client_id().clone(),
                code,
                redirect_uri: CALLBACK.to_string(),
                code_verifier: Some(VERIFIER.to_string()),
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
                resource: None,
            },
        )
        .expect("exchange");
    let payload = tokens.id_token().split('.').nth(1).expect("a JWT payload");
    let claims: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("base64url payload"))
            .expect("JSON claims");
    let mut amr: Vec<String> = claims
        .get("amr")
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    amr.sort();
    amr
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| (*v).to_string()).collect()
}

#[tokio::test]
async fn a_password_sign_in_gives_amr_pwd() {
    let rig = build_rig();
    let mut browser = Browser::new(rig.ui.clone());
    let resp = post_password(&mut browser).await;
    let next = location(&resp).expect("the login form redirects");
    assert!(
        !next.contains("/ui/login") && !next.contains("mfa"),
        "a user without a second factor is signed in: {next}"
    );

    assert_eq!(
        amr_after_authorize(&rig, &mut browser).await,
        strings(&["pwd"])
    );
}

#[tokio::test]
async fn a_password_and_totp_sign_in_gives_amr_pwd_otp_mfa() {
    let rig = build_rig();
    let (secret, used_step) = enrol_totp(&rig);
    let mut browser = Browser::new(rig.ui.clone());
    let resp = post_password(&mut browser).await;
    // A user with TOTP gets the login page back with the TOTP form shown.
    assert_eq!(resp.status(), StatusCode::OK, "the TOTP form is shown");
    let page = body_text(resp).await;
    answer_totp(&mut browser, &page, &secret, used_step + 1).await;

    assert_eq!(
        amr_after_authorize(&rig, &mut browser).await,
        strings(&["mfa", "otp", "pwd"])
    );
}

#[tokio::test]
async fn a_session_that_proved_totp_gives_amr_otp_mfa() {
    let rig = build_rig();
    let mut browser = browser_with_session(&rig, MfaProof::Proved);

    assert_eq!(
        amr_after_authorize(&rig, &mut browser).await,
        strings(&["mfa", "otp"])
    );
}

#[tokio::test]
async fn a_user_verified_passkey_gives_amr_hwk_user_mfa() {
    let rig = build_rig();
    let mut browser = browser_with_session(&rig, MfaProof::ProvedWebAuthn);

    assert_eq!(
        amr_after_authorize(&rig, &mut browser).await,
        strings(&["hwk", "mfa", "user"])
    );
}

#[tokio::test]
async fn a_passkey_without_user_verification_is_not_mfa() {
    let rig = build_rig();
    let mut browser = browser_with_session(&rig, MfaProof::PasskeyPossession);

    assert_eq!(
        amr_after_authorize(&rig, &mut browser).await,
        strings(&["hwk", "user"])
    );
}

#[tokio::test]
async fn an_inbox_proof_adds_no_amr_value() {
    let rig = build_rig();
    let mut browser = browser_with_session(&rig, MfaProof::EmailOtp);

    assert_eq!(
        amr_after_authorize(&rig, &mut browser).await,
        Vec::<String>::new()
    );
}
