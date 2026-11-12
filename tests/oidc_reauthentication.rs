//! `max_age`, `prompt=login` and the ID token's `auth_time` (#782).
//!
//! OIDC Core §3.1.2.1: with `prompt=login`, or with `max_age` shorter than
//! the time since the user's last sign-in, the OP MUST make the user sign in
//! again before it issues a code. With `prompt=none`, such a request gets
//! `login_required`. OIDC Core §2: the ID token MUST carry `auth_time` when
//! the request had `max_age`; Hearth always sends it for a browser sign-in.
//!
//! `auth_time` is the time of the session's last completed interactive
//! sign-in, including a required second factor. A forced sign-in is a normal
//! sign-in: it opens a new session and revokes the old one (session-id
//! rotation). The authorize request that resumes after it carries a signed,
//! short-lived, single-use marker, so it does not force a sign-in again.

#[path = "support/browser.rs"]
mod browser;

use std::sync::Arc;

use axum::response::Response;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use browser::{body_text, hidden_fields, location, Browser};
use hearth::core::{Clock, RealmId, SystemClock, UserId};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CleartextPassword, ClientTrustLevel, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, OAuthClient, RealmConfig,
    RegisterClientRequest, TokenExchangeRequest, UpdateUserRequest, UserStatus,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::EmbeddedRbacEngine;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

const COOKIE_SECRET: [u8; 32] = [83u8; 32];
const CALLBACK: &str = "https://app.example.com/cb";
const VERIFIER: &str = "Ra7mQ2vW5yT1kJ7pX0cN4bF9hL3sD6gA8eU2iO5qR1t";
const EMAIL: &str = "reauth-user@acme.test";
const SESSION_COOKIE: &str = "hearth_ui_session";

fn password() -> String {
    ["Re", "Auth", "Pa55word!"].concat()
}

struct Rig {
    ui: axum::Router,
    identity: Arc<dyn IdentityEngine>,
    realm_id: RealmId,
    realm_name: String,
    client: OAuthClient,
}

/// A realm without required MFA, one active user with a password, and a
/// first-party client that needs no consent.
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
    let (realm_id, realm_name, client) = seed_realm(identity.as_ref());

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
        realm_id,
        realm_name,
        client,
    }
}

fn seed_realm(identity: &dyn IdentityEngine) -> (RealmId, String, OAuthClient) {
    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: format!("reauth-{}", uuid::Uuid::new_v4().simple()),
            config: Some(RealmConfig {
                mfa_required: Some(false),
                ..RealmConfig::default()
            }),
        })
        .expect("create realm");
    let user: UserId = identity
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: EMAIL.to_string(),
                display_name: "Reauth User".to_string(),
                ..Default::default()
            },
        )
        .expect("create user")
        .id()
        .clone();
    identity
        .set_password(
            realm.id(),
            &user,
            &CleartextPassword::from_string(password()),
        )
        .expect("set password");
    identity
        .update_user(
            realm.id(),
            &user,
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
                client_name: "Reauth App".to_string(),
                redirect_uris: vec![CALLBACK.to_string()],
                require_consent: false,
                grant_types: vec!["authorization_code".to_string()],
                trust_level: ClientTrustLevel::FirstParty,
                ..Default::default()
            },
        )
        .expect("register client");
    (realm.id().clone(), realm.name().to_string(), client)
}

fn unix_secs() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs(),
    )
    .expect("seconds fit in i64")
}

/// Signs in on the realm's login page `login_url` (which may carry a
/// `return_to`) and returns the login form's response.
async fn sign_in_at(browser: &mut Browser, login_url: &str) -> Response {
    let action = login_url.split('?').next().expect("a path").to_string();
    let page = body_text(browser.get(login_url).await).await;
    let mut fields = hidden_fields(&page, &action);
    fields.push(("email".to_string(), EMAIL.to_string()));
    fields.push(("password".to_string(), password()));
    browser.post_form(&action, &fields).await
}

/// A browser that signed in with the password form.
async fn signed_in_browser(rig: &Rig) -> Browser {
    let mut browser = Browser::new(rig.ui.clone());
    let resp = sign_in_at(
        &mut browser,
        &format!("/ui/realms/{}/login", rig.realm_name),
    )
    .await;
    let next = location(&resp).expect("the login form redirects");
    assert!(!next.contains("/login"), "the user is signed in: {next}");
    browser
}

/// The realm-scoped authorize URI for the rig's client, plus `extra`.
fn authorize_uri(rig: &Rig, extra: &str) -> String {
    let challenge = URL_SAFE_NO_PAD.encode(ring::digest::digest(
        &ring::digest::SHA256,
        VERIFIER.as_bytes(),
    ));
    format!(
        "/ui/realms/{}/oauth/authorize?client_id={}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb\
         &response_type=code&scope=openid&state=s-782&nonce=n-782&code_challenge={challenge}\
         &code_challenge_method=S256{extra}",
        rig.realm_name,
        rig.client.client_id().as_uuid(),
    )
}

/// The value of query parameter `name` in `url`.
fn query_param(url: &str, name: &str) -> Option<String> {
    let query = url.split_once('?')?.1;
    form_urlencoded::parse(query.as_bytes())
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

/// Exchanges the code in the callback `location` and returns the ID token's
/// claims.
fn id_token_claims(rig: &Rig, location: &str) -> serde_json::Value {
    assert!(location.starts_with(CALLBACK), "a callback: {location}");
    let code = query_param(location, "code").expect("a code in the callback");
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
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("base64url payload"))
        .expect("JSON claims")
}

/// `true` when `location` is the realm's sign-in page.
fn is_sign_in_page(rig: &Rig, location: &str) -> bool {
    location.starts_with(&format!("/ui/realms/{}/login", rig.realm_name))
}

/// Runs a forced sign-in to its end: from the sign-in redirect `to_login`,
/// signs in again, follows the login form back to the authorize request, and
/// returns the authorize response's `Location` and the resumed URI.
async fn complete_forced_sign_in(
    rig: &Rig,
    browser: &mut Browser,
    to_login: &str,
) -> (String, String) {
    assert!(is_sign_in_page(rig, to_login), "a sign-in page: {to_login}");
    let resp = sign_in_at(browser, to_login).await;
    let resume = location(&resp).expect("the login form redirects back");
    assert!(
        resume.contains("/oauth/authorize"),
        "the login form returns to the authorize request: {resume}"
    );
    let resp = browser.get(&resume).await;
    (location(&resp).expect("authorize redirects"), resume)
}

#[tokio::test]
async fn the_id_token_carries_the_auth_time_of_the_sign_in() {
    let rig = build_rig();
    let before = unix_secs();
    let mut browser = signed_in_browser(&rig).await;
    let after = unix_secs();

    let resp = browser.get(&authorize_uri(&rig, "")).await;
    let claims = id_token_claims(&rig, &location(&resp).expect("authorize redirects"));
    let auth_time = claims["auth_time"]
        .as_i64()
        .unwrap_or_else(|| panic!("the ID token has auth_time: {claims}"));
    assert!(
        (before..=after).contains(&auth_time),
        "auth_time {auth_time} is the sign-in time ({before}..={after})"
    );
}

#[tokio::test]
async fn a_max_age_the_session_meets_issues_a_code_with_auth_time() {
    let rig = build_rig();
    let mut browser = signed_in_browser(&rig).await;

    let resp = browser.get(&authorize_uri(&rig, "&max_age=3600")).await;
    let next = location(&resp).expect("authorize redirects");
    assert!(next.starts_with(CALLBACK), "no sign-in is needed: {next}");
    let claims = id_token_claims(&rig, &next);
    assert!(claims["auth_time"].is_i64(), "auth_time: {claims}");
}

#[tokio::test]
async fn prompt_login_makes_the_user_sign_in_again() {
    let rig = build_rig();
    let mut browser = signed_in_browser(&rig).await;
    let first_session = browser.cookie(SESSION_COOKIE).expect("a session cookie");

    let resp = browser.get(&authorize_uri(&rig, "&prompt=login")).await;
    let to_login = location(&resp).expect("authorize redirects");
    assert!(
        is_sign_in_page(&rig, &to_login),
        "prompt=login must show the sign-in page, got {to_login}"
    );

    let before = unix_secs();
    let (next, _) = complete_forced_sign_in(&rig, &mut browser, &to_login).await;
    assert!(
        next.starts_with(CALLBACK),
        "a code after the sign-in: {next}"
    );
    assert_eq!(query_param(&next, "state").as_deref(), Some("s-782"));
    let claims = id_token_claims(&rig, &next);
    let auth_time = claims["auth_time"].as_i64().expect("auth_time");
    assert!(
        auth_time >= before,
        "auth_time {auth_time} is the new sign-in (>= {before})"
    );
    assert_ne!(
        browser.cookie(SESSION_COOKIE).as_deref(),
        Some(first_session.as_str()),
        "the forced sign-in opens a new session (session-id rotation)"
    );
}

#[tokio::test]
async fn a_max_age_shorter_than_the_session_age_makes_the_user_sign_in_again() {
    let rig = build_rig();
    let mut browser = signed_in_browser(&rig).await;

    let resp = browser.get(&authorize_uri(&rig, "&max_age=0")).await;
    let to_login = location(&resp).expect("authorize redirects");
    assert!(
        is_sign_in_page(&rig, &to_login),
        "max_age=0 must show the sign-in page, got {to_login}"
    );
    let (next, _) = complete_forced_sign_in(&rig, &mut browser, &to_login).await;
    assert!(
        next.starts_with(CALLBACK),
        "a code after the sign-in: {next}"
    );
    assert!(id_token_claims(&rig, &next)["auth_time"].is_i64());
}

#[tokio::test]
async fn prompt_none_with_an_expired_max_age_gets_login_required() {
    let rig = build_rig();
    let mut browser = signed_in_browser(&rig).await;

    let resp = browser
        .get(&authorize_uri(&rig, "&prompt=none&max_age=0"))
        .await;
    let next = location(&resp).expect("authorize redirects");
    assert!(
        next.starts_with(CALLBACK),
        "the client gets the error: {next}"
    );
    assert_eq!(
        query_param(&next, "error").as_deref(),
        Some("login_required")
    );
    assert_eq!(query_param(&next, "state").as_deref(), Some("s-782"));
    assert!(query_param(&next, "code").is_none(), "no code: {next}");
}

#[tokio::test]
async fn a_replayed_reauthentication_marker_forces_sign_in_again() {
    let rig = build_rig();
    let mut browser = signed_in_browser(&rig).await;

    let resp = browser.get(&authorize_uri(&rig, "&prompt=login")).await;
    let to_login = location(&resp).expect("authorize redirects");
    let (next, resume) = complete_forced_sign_in(&rig, &mut browser, &to_login).await;
    assert!(
        next.starts_with(CALLBACK),
        "control: the first use issues a code: {next}"
    );

    // The same resumed request again, in the same fresh session: the marker
    // is spent, so the user must sign in again.
    let resp = browser.get(&resume).await;
    let again = location(&resp).expect("authorize redirects");
    assert!(
        is_sign_in_page(&rig, &again),
        "a replayed marker must force a sign-in again, got {again}"
    );
}

#[tokio::test]
async fn a_marker_issued_before_the_last_sign_in_does_not_skip_it() {
    let rig = build_rig();
    let mut browser = signed_in_browser(&rig).await;

    // The marker is issued, but the user does not sign in again: the session
    // is older than the marker, so the request still needs a sign-in.
    let resp = browser.get(&authorize_uri(&rig, "&prompt=login")).await;
    let to_login = location(&resp).expect("authorize redirects");
    let resume = query_param(&to_login, "return_to").expect("a return_to");
    assert!(
        resume.contains("hearth_reauth="),
        "control: a marker: {resume}"
    );
    let resp = browser.get(&resume).await;
    let again = location(&resp).expect("authorize redirects");
    assert!(
        is_sign_in_page(&rig, &again),
        "no sign-in after the marker: sign in, got {again}"
    );
}

#[tokio::test]
async fn a_forged_marker_does_not_skip_the_sign_in() {
    let rig = build_rig();
    let mut browser = signed_in_browser(&rig).await;

    let forged = format!(
        "&prompt=login&hearth_reauth={}.{}.AAAA",
        "00".repeat(16),
        unix_secs() - 5
    );
    let resp = browser.get(&authorize_uri(&rig, &forged)).await;
    let next = location(&resp).expect("authorize redirects");
    assert!(
        is_sign_in_page(&rig, &next),
        "a marker without a valid signature must not skip the sign-in, got {next}"
    );
}
