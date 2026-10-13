//! RP-initiated logout ends the Hearth browser session, and it sends the
//! browser somewhere useful (change `logout-ends-sso-session`).
//!
//! The ID token's `sid` names the token session that the code exchange
//! opened, not the browser session that signed the user in. Logout revoked
//! the token session only, so the next `/authorize` signed the user in again
//! without a prompt. The redirect was also dropped unless the request carried
//! `client_id`, which most relying-party libraries do not send, and a browser
//! then ended on `{"message":"logged out"}`.

#[path = "support/browser.rs"]
mod browser;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use browser::{location, Browser};
use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{Clock, RealmId, SessionId, SystemClock, UserId};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    AuthorizationRequest, ClientTrustLevel, CodeChallengeMethod, CreateRealmRequest,
    CreateUserRequest, CredentialConfig, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine,
    MfaProof, OAuthClient, OidcTokenResponse, RealmConfig, RegisterClientRequest, SessionContext,
    TokenExchangeRequest, UpdateClientRequest,
};
use hearth::protocol::http::{self, AppState};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig};
use tower::ServiceExt as _;

const COOKIE_SECRET: [u8; 32] = [73u8; 32];
const CALLBACK: &str = "https://app.example.com/cb";
const SIGNED_OUT: &str = "https://app.example.com/signed-out";
const FCL_URI: &str = "https://app.example.com/fcl";
const VERIFIER: &str = "S4gKJfVNgWiFl2PQ8RxXS7E6Mhr9BqyTvUIe3WoA5Zc";

struct Rig {
    /// The browser UI (`/ui/...`).
    ui: axum::Router,
    /// The JSON and OIDC API (`/end_session`, `/realms/{realm}/end_session`).
    api: axum::Router,
    identity: Arc<dyn IdentityEngine>,
    realm_id: RealmId,
    realm_name: String,
    client: OAuthClient,
    user: UserId,
}

fn build_rig() -> Rig {
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
    let realm_name = format!("sso-logout-{}", uuid::Uuid::new_v4().simple());
    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: realm_name.clone(),
            config: Some(RealmConfig::default()),
        })
        .expect("create realm");
    let client = register_client(identity.as_ref(), realm.id());
    let user = identity
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("u-{}@logout.test", uuid::Uuid::new_v4().simple()),
                display_name: "Logout".to_string(),
                ..Default::default()
            },
        )
        .expect("create user")
        .id()
        .clone();
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
        Arc::clone(&rbac),
        Arc::clone(&email),
        data_dir,
    ));
    let state = WebState::new(
        Arc::clone(&identity),
        Arc::clone(&rbac),
        Arc::clone(&audit),
        onboarding,
        CookieSecret::from_bytes(COOKIE_SECRET),
        Some(email),
    )
    .with_dev_mode(false);
    Rig {
        ui: web::router(state),
        api: http::router(Arc::new(AppState::new(Arc::clone(&identity), rbac, audit))),
        identity,
        realm_id: realm.id().clone(),
        realm_name,
        client,
        user,
    }
}

/// A first-party client with no consent step and [`SIGNED_OUT`] as its
/// registered post-logout redirect URI.
fn register_client(identity: &dyn IdentityEngine, realm: &RealmId) -> OAuthClient {
    let client = identity
        .register_client(
            realm,
            &RegisterClientRequest {
                client_name: "Logout App".to_string(),
                redirect_uris: vec![CALLBACK.to_string()],
                require_consent: false,
                grant_types: vec![
                    "authorization_code".to_string(),
                    "refresh_token".to_string(),
                ],
                trust_level: ClientTrustLevel::FirstParty,
                ..Default::default()
            },
        )
        .expect("register client");
    identity
        .update_client(
            realm,
            client.client_id(),
            &UpdateClientRequest {
                post_logout_redirect_uris: Some(vec![SIGNED_OUT.to_string()]),
                ..Default::default()
            },
        )
        .expect("register the post-logout redirect URI");
    client
}

/// A browser signed in to the UI, and the ID of its session.
fn signed_in(rig: &Rig) -> (Browser, SessionId) {
    let session = rig
        .identity
        .create_session(
            &rig.realm_id,
            &rig.user,
            &SessionContext {
                mfa_proof: MfaProof::None,
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
    (browser, session.id().clone())
}

fn challenge() -> String {
    URL_SAFE_NO_PAD.encode(ring::digest::digest(
        &ring::digest::SHA256,
        VERIFIER.as_bytes(),
    ))
}

fn authorize_uri(rig: &Rig) -> String {
    let challenge = challenge();
    format!(
        "/ui/oauth/authorize?client_id={}&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb\
         &response_type=code&scope=openid&state=s&code_challenge={challenge}\
         &code_challenge_method=S256",
        rig.client.client_id().as_uuid(),
    )
}

fn exchange(rig: &Rig, code: String) -> OidcTokenResponse {
    rig.identity
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
        .expect("exchange")
}

/// Runs the browser authorization, exchanges the code, and returns the ID
/// token.
async fn sign_in_to_the_client(rig: &Rig, browser: &mut Browser) -> String {
    sign_in_for_tokens(rig, browser)
        .await
        .id_token()
        .to_string()
}

/// Runs the browser authorization and exchanges the code.
async fn sign_in_for_tokens(rig: &Rig, browser: &mut Browser) -> OidcTokenResponse {
    let resp = browser.get(&authorize_uri(rig)).await;
    let next = location(&resp).expect("authorize redirects");
    assert!(next.starts_with(CALLBACK), "a code is issued: {next}");
    let code = next
        .split("code=")
        .nth(1)
        .and_then(|rest| rest.split('&').next())
        .expect("code parameter")
        .to_string();
    exchange(rig, code)
}

/// Calls an end-session endpoint with these query parameters.
async fn end_session(
    rig: &Rig,
    realm_path: bool,
    params: &[(&str, &str)],
    accept: Option<&str>,
) -> axum::response::Response {
    let query = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(params)
        .finish();
    let mut req = Request::builder().method("POST");
    if realm_path {
        req = req.uri(format!("/realms/{}/end_session?{query}", rig.realm_name));
    } else {
        req = req
            .uri(format!("/end_session?{query}"))
            .header("x-realm-id", rig.realm_id.as_uuid().to_string());
    }
    if let Some(accept) = accept {
        req = req.header(header::ACCEPT, accept);
    }
    rig.api
        .clone()
        .oneshot(req.body(Body::empty()).expect("request"))
        .await
        .expect("end_session")
}

async fn text(resp: axum::response::Response) -> String {
    String::from_utf8(
        to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("body")
            .to_vec(),
    )
    .expect("utf-8")
}

fn session_is_live(rig: &Rig, id: &SessionId) -> bool {
    rig.identity
        .get_session(&rig.realm_id, id)
        .expect("session lookup")
        .is_some()
}

#[tokio::test]
async fn a_back_end_logout_ends_the_browser_session() {
    let rig = build_rig();
    let (mut browser, browser_session) = signed_in(&rig);
    let id_token = sign_in_to_the_client(&rig, &mut browser).await;

    let resp = end_session(&rig, false, &[("id_token_hint", &id_token)], None).await;
    assert_eq!(resp.status(), StatusCode::OK);

    assert!(
        !session_is_live(&rig, &browser_session),
        "the browser session that signed the user in must end with the logout"
    );
    let resp = browser.get(&authorize_uri(&rig)).await;
    let next = location(&resp).unwrap_or_default();
    assert!(
        next.contains("/login"),
        "the next /authorize must ask the user to sign in, not issue a code: {next}"
    );
}

/// A client can mint a code with its own access token (JSON `/authorize`).
/// The new token session links to the browser session at the top, not to
/// the token session behind the bearer, so logout still ends the browser
/// session.
#[tokio::test]
async fn a_code_minted_with_a_bearer_token_links_to_the_browser_session() {
    let rig = build_rig();
    let (mut browser, browser_session) = signed_in(&rig);
    let first = sign_in_for_tokens(&rig, &mut browser).await;
    let bearer = rig
        .identity
        .validate_token(&rig.realm_id, first.access_token())
        .expect("valid access token");
    let code = rig
        .identity
        .authorize_non_interactive(
            &rig.realm_id,
            &AuthorizationRequest {
                organization: None,
                client_id: rig.client.client_id().clone(),
                redirect_uri: CALLBACK.to_string(),
                scope: "openid".to_string(),
                state: "s2".to_string(),
                resource: None,
                response_type: "code".to_string(),
                user_id: rig.user.clone(),
                code_challenge: Some(challenge()),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: None,
                amr_values: Vec::new(),
                response_mode: None,
                request: None,
            },
            &bearer,
        )
        .expect("a code from the bearer token")
        .code()
        .to_string();
    let second = exchange(&rig, code);

    let resp = end_session(&rig, false, &[("id_token_hint", second.id_token())], None).await;
    assert_eq!(resp.status(), StatusCode::OK);

    assert!(
        !session_is_live(&rig, &browser_session),
        "the link must name the browser session the user signed in with"
    );
}

#[tokio::test]
async fn another_browser_stays_signed_in() {
    let rig = build_rig();
    let (mut first, _) = signed_in(&rig);
    let (_, second_session) = signed_in(&rig);
    let id_token = sign_in_to_the_client(&rig, &mut first).await;

    let resp = end_session(&rig, false, &[("id_token_hint", &id_token)], None).await;
    assert_eq!(resp.status(), StatusCode::OK);

    assert!(
        session_is_live(&rig, &second_session),
        "a logout from one browser must not end the user's other browser sessions"
    );
}

#[tokio::test]
async fn the_hint_names_the_client_for_the_redirect() {
    let rig = build_rig();
    let (mut browser, _) = signed_in(&rig);
    let id_token = sign_in_to_the_client(&rig, &mut browser).await;

    let resp = end_session(
        &rig,
        true,
        &[
            ("id_token_hint", &id_token),
            ("post_logout_redirect_uri", SIGNED_OUT),
            ("state", "xyz"),
        ],
        Some("text/html"),
    )
    .await;
    assert_eq!(
        location(&resp).as_deref(),
        Some("https://app.example.com/signed-out?state=xyz"),
        "without client_id, the verified hint's client validates the redirect"
    );
}

#[tokio::test]
async fn a_logout_repeated_after_the_session_ended_still_redirects() {
    let rig = build_rig();
    let (mut browser, _) = signed_in(&rig);
    let id_token = sign_in_to_the_client(&rig, &mut browser).await;
    let params = [
        ("id_token_hint", id_token.as_str()),
        ("post_logout_redirect_uri", SIGNED_OUT),
    ];

    let first = end_session(&rig, true, &params, Some("text/html")).await;
    assert_eq!(location(&first).as_deref(), Some(SIGNED_OUT));
    let again = end_session(&rig, true, &params, Some("text/html")).await;
    assert_eq!(
        location(&again).as_deref(),
        Some(SIGNED_OUT),
        "logout is idempotent: a second call redirects too"
    );
}

#[tokio::test]
async fn a_uri_the_hints_client_did_not_register_gets_no_redirect() {
    let rig = build_rig();
    let (mut browser, _) = signed_in(&rig);
    let id_token = sign_in_to_the_client(&rig, &mut browser).await;

    let resp = end_session(
        &rig,
        false,
        &[
            ("id_token_hint", &id_token),
            ("post_logout_redirect_uri", "https://evil.example.net/"),
        ],
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(location(&resp), None, "no redirect to an unregistered URI");
    assert_eq!(text(resp).await, r#"{"message":"logged out"}"#);
}

#[tokio::test]
async fn a_browser_with_no_redirect_gets_a_signed_out_page() {
    let rig = build_rig();
    let (mut browser, _) = signed_in(&rig);
    let id_token = sign_in_to_the_client(&rig, &mut browser).await;

    let resp = end_session(
        &rig,
        true,
        &[("id_token_hint", &id_token)],
        Some("text/html,application/xhtml+xml,*/*;q=0.8"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let content_type = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        content_type.starts_with("text/html"),
        "a browser gets a page, not JSON: {content_type}"
    );
    let html = text(resp).await;
    assert!(
        html.contains("You are signed out"),
        "the page tells the user they are signed out: {html}"
    );
}

#[tokio::test]
async fn the_front_channel_page_keeps_state() {
    let rig = build_rig();
    rig.identity
        .update_client(
            &rig.realm_id,
            rig.client.client_id(),
            &UpdateClientRequest {
                frontchannel_logout_uri: Some(Some(FCL_URI.to_string())),
                ..Default::default()
            },
        )
        .expect("front-channel logout URI");
    let (mut browser, _) = signed_in(&rig);
    let id_token = sign_in_to_the_client(&rig, &mut browser).await;

    let resp = end_session(
        &rig,
        true,
        &[
            ("id_token_hint", &id_token),
            ("post_logout_redirect_uri", SIGNED_OUT),
            ("state", "xyz"),
        ],
        Some("text/html"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let html = text(resp).await;
    assert!(html.contains(FCL_URI), "the front-channel iframe: {html}");
    assert!(
        html.contains("2;url=https://app.example.com/signed-out?state=xyz"),
        "the meta refresh carries state, as the plain redirect does: {html}"
    );
}
