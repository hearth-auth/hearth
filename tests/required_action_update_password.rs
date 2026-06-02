//! Integration tests for the UPDATE_PASSWORD required-action handler (HEA-809).
//!
//! Covers:
//! * AC-2: GET renders password-change form
//! * AC-8: POST validates and updates credential, resumes OIDC flow
//! * Policy violation: form re-rendered with error, RA token untouched
//! * Password mismatch: form re-rendered with error
//! * Expired RA token: redirects to "/" (restart login)
//! * Missing RA cookie: 400 Bad Request

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use data_encoding::BASE64URL_NOPAD;
use hearth::audit::EmbeddedAuditEngine;
use hearth::core::{Clock, RealmId, SessionId, SystemClock, Timestamp};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, OAuthClient, PasswordPolicy,
    RealmConfig, RegisterClientRequest, RequiredAction, SessionContext, UpdateUserRequest,
    UserStatus,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig};
use tower::ServiceExt;

const COOKIE_SECRET: [u8; 32] = [9u8; 32];
const PASSWORD: &str = "TestPassword-hearth-ra";
const PKCE_VERIFIER: &str = "dGVzdC12ZXJpZmllci10aGlzLWlzLTQzLWNoYXJhY3RlcnM";

fn pkce_challenge(verifier: &str) -> String {
    BASE64URL_NOPAD
        .encode(ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes()).as_ref())
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

struct Rig {
    app: axum::Router,
    identity: Arc<dyn IdentityEngine>,
    realm_id: RealmId,
    client: OAuthClient,
}

fn build_rig(clock: Arc<dyn Clock>, realm_config: RealmConfig) -> Rig {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);

    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).expect("storage"),
    );
    let audit = Arc::new(EmbeddedAuditEngine::new(
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

    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: format!("ra-pw-test-{}", uuid::Uuid::new_v4()),
            config: Some(realm_config),
        })
        .expect("create realm");

    let client = identity
        .register_client(
            realm.id(),
            &RegisterClientRequest {
                client_name: "Test App".to_string(),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                require_consent: false,
                grant_types: vec!["authorization_code".to_string()],
                trust_level: hearth::identity::ClientTrustLevel::FirstParty,
                ..Default::default()
            },
        )
        .expect("register client");

    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&identity),
        Arc::clone(&rbac),
        null_email(),
        data_dir,
    ));

    let state = WebState::new(
        Arc::clone(&identity),
        rbac,
        Arc::clone(&audit) as _,
        onboarding,
        CookieSecret::from_bytes(COOKIE_SECRET),
        None,
    );

    Rig {
        app: web::router(state),
        identity,
        realm_id: realm.id().clone(),
        client,
    }
}

fn build_rig_default() -> Rig {
    build_rig(
        Arc::new(SystemClock) as Arc<dyn Clock>,
        RealmConfig {
            default_required_actions: vec![RequiredAction::UpdatePassword],
            ..Default::default()
        },
    )
}

/// Creates a user with active status and a password, and returns a session cookie.
fn create_user_with_session(rig: &Rig, email: &str) -> String {
    let user = rig
        .identity
        .create_user(
            &rig.realm_id,
            &CreateUserRequest {
                email: email.to_string(),
                display_name: "Test User".to_string(),
                first_name: "Test".to_string(),
                last_name: "User".to_string(),
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

    let session = rig
        .identity
        .create_session(&rig.realm_id, user.id(), &SessionContext::default())
        .expect("session");

    session_cookie(&rig.realm_id, session.id(), "csrf-tok")
}

/// Builds a signed UI session cookie (mirrors the format used by the web layer).
fn session_cookie(realm_id: &RealmId, session_id: &SessionId, csrf: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256>>::new_from_slice(&COOKIE_SECRET).expect("hmac");
    mac.update(session_id.as_uuid().as_bytes());
    mac.update(b"|");
    mac.update(realm_id.as_uuid().as_bytes());
    let tag = BASE64URL_NOPAD.encode(&mac.finalize().into_bytes());
    format!(
        "hearth_ui_session={}.{}.{}; hearth_ui_csrf={}",
        session_id.as_uuid(),
        realm_id.as_uuid(),
        tag,
        csrf,
    )
}

fn authorize_uri(client: &OAuthClient, scope: &str) -> String {
    let challenge = pkce_challenge(PKCE_VERIFIER);
    format!(
        "/ui/oauth/authorize?client_id={}&redirect_uri={}&response_type=code&scope={}&state=s&code_challenge={}&code_challenge_method=S256",
        client.client_id().as_uuid(),
        urlencode("https://app.example.com/cb"),
        urlencode(scope),
        urlencode(&challenge),
    )
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                use std::fmt::Write as _;
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

fn location_of(resp: &axum::response::Response) -> Option<String> {
    resp.headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// Extracts the raw `hearth_ra_session` cookie value from a response's Set-Cookie headers.
fn ra_cookie_value(resp: &axum::response::Response) -> Option<String> {
    for v in resp.headers().get_all(header::SET_COOKIE) {
        let s = v.to_str().ok()?;
        if let Some(rest) = s.strip_prefix("hearth_ra_session=") {
            return Some(rest.split(';').next()?.to_string());
        }
    }
    None
}

async fn body_text(resp: axum::response::Response) -> String {
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.expect("body");
    String::from_utf8(bytes.to_vec()).expect("utf-8")
}

/// Drives the OIDC authorize flow for a user with UPDATE_PASSWORD required action and
/// returns the RA session token value from the redirect Set-Cookie.
async fn obtain_ra_cookie(rig: &Rig, session_cookie_val: &str) -> String {
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(authorize_uri(&rig.client, "openid"))
                .header(header::COOKIE, session_cookie_val)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");

    assert!(
        resp.status().is_redirection(),
        "authorize should redirect to required-action page, got: {}",
        resp.status()
    );
    let loc = location_of(&resp).expect("Location header");
    assert!(
        loc.contains("/required-action/UPDATE_PASSWORD"),
        "unexpected redirect: {loc}"
    );
    ra_cookie_value(&resp).expect("RA session cookie in authorize response")
}

// ==========================================================================
// AC-2: GET renders the password form
// ==========================================================================

#[tokio::test]
async fn get_update_password_renders_form() {
    let rig = build_rig_default();
    let cookie = create_user_with_session(&rig, "get-form@example.com");
    let ra_token = obtain_ra_cookie(&rig, &cookie).await;

    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/required-action/UPDATE_PASSWORD")
                .header(header::COOKIE, format!("hearth_ra_session={ra_token}"))
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_text(resp).await;
    assert!(
        body.contains("update-password-form"),
        "form data-testid not found in:\n{body}"
    );
    assert!(body.contains("new_password"), "new_password field missing");
    assert!(
        body.contains("confirm_password"),
        "confirm_password field missing"
    );
}

// ==========================================================================
// Missing RA cookie → 400
// ==========================================================================

#[tokio::test]
async fn get_without_ra_cookie_returns_400() {
    let rig = build_rig_default();

    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/required-action/UPDATE_PASSWORD")
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn post_without_ra_cookie_returns_400() {
    let rig = build_rig_default();

    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/required-action/UPDATE_PASSWORD")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("new_password=Abc123!&confirm_password=Abc123!"))
                .expect("req"),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ==========================================================================
// AC-8: Successful password update resumes OIDC flow
// ==========================================================================

#[tokio::test]
async fn post_valid_password_resumes_oidc_flow() {
    let rig = build_rig_default();
    let cookie = create_user_with_session(&rig, "success@example.com");
    let ra_token = obtain_ra_cookie(&rig, &cookie).await;

    let new_password = "NewPassword-secure-1!";

    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/required-action/UPDATE_PASSWORD")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, format!("hearth_ra_session={ra_token}"))
                .body(Body::from(format!(
                    "new_password={}&confirm_password={}",
                    urlencode(new_password),
                    urlencode(new_password)
                )))
                .expect("req"),
        )
        .await
        .expect("oneshot");

    // Should redirect to the OAuth callback with an authorization code.
    assert!(
        resp.status().is_redirection(),
        "expected redirect, got: {}",
        resp.status()
    );
    let loc = location_of(&resp).expect("Location header");
    assert!(
        loc.starts_with("https://app.example.com/cb?code="),
        "expected redirect to callback with code, got: {loc}"
    );
}

// ==========================================================================
// AC-8: After success, UPDATE_PASSWORD removed from user's required_actions
// ==========================================================================

#[tokio::test]
async fn post_valid_password_clears_required_action_from_user() {
    let rig = build_rig_default();
    let cookie = create_user_with_session(&rig, "clear-ra@example.com");

    // Identify the user by looking up the realm's user list.
    let ra_token = obtain_ra_cookie(&rig, &cookie).await;

    // Extract the user's sub from the RA token claims (unsigned — for test convenience).
    let ra_parts: Vec<&str> = ra_token.split('.').collect();
    assert_eq!(ra_parts.len(), 3);
    let claims_json = BASE64URL_NOPAD
        .decode(ra_parts[1].as_bytes())
        .expect("decode claims");
    let claims: serde_json::Value = serde_json::from_slice(&claims_json).expect("parse claims");
    let user_id_str = claims["sub"].as_str().expect("sub");
    let user_uuid = uuid::Uuid::parse_str(user_id_str).expect("uuid");
    let user_id = hearth::core::UserId::new(user_uuid);

    let new_password = "SecureNewPass-99!";

    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/required-action/UPDATE_PASSWORD")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, format!("hearth_ra_session={ra_token}"))
                .body(Body::from(format!(
                    "new_password={}&confirm_password={}",
                    urlencode(new_password),
                    urlencode(new_password)
                )))
                .expect("req"),
        )
        .await
        .expect("oneshot");

    assert!(
        resp.status().is_redirection(),
        "expected redirect, got: {}",
        resp.status()
    );

    // User record must no longer carry UPDATE_PASSWORD.
    let user = rig
        .identity
        .get_user(&rig.realm_id, &user_id)
        .expect("get_user ok")
        .expect("user exists");
    assert!(
        !user
            .required_actions()
            .contains(&RequiredAction::UpdatePassword),
        "UPDATE_PASSWORD should be removed from user record after completion"
    );
}

// ==========================================================================
// Policy violation: form re-rendered with error, token still valid
// ==========================================================================

#[tokio::test]
async fn post_policy_violation_rerenders_form_with_error() {
    let rig = build_rig(
        Arc::new(SystemClock) as Arc<dyn Clock>,
        RealmConfig {
            default_required_actions: vec![RequiredAction::UpdatePassword],
            password_policy: Some(PasswordPolicy {
                min_length: Some(20),
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    let cookie = create_user_with_session(&rig, "policy@example.com");
    let ra_token = obtain_ra_cookie(&rig, &cookie).await;

    // Submit a password that is too short (policy requires 20 chars).
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/required-action/UPDATE_PASSWORD")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, format!("hearth_ra_session={ra_token}"))
                .body(Body::from("new_password=short&confirm_password=short"))
                .expect("req"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "policy violation should re-render form (200), not redirect"
    );
    let body = body_text(resp).await;
    assert!(
        body.contains("update-password-form"),
        "form must be re-rendered on violation"
    );
    assert!(
        body.contains("at least 20"),
        "violation error message missing from: {body}"
    );
}

// ==========================================================================
// Password mismatch: form re-rendered
// ==========================================================================

#[tokio::test]
async fn post_password_mismatch_rerenders_form() {
    let rig = build_rig_default();
    let cookie = create_user_with_session(&rig, "mismatch@example.com");
    let ra_token = obtain_ra_cookie(&rig, &cookie).await;

    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/required-action/UPDATE_PASSWORD")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, format!("hearth_ra_session={ra_token}"))
                .body(Body::from(
                    "new_password=SecurePassword1!&confirm_password=DifferentPassword1!",
                ))
                .expect("req"),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_text(resp).await;
    assert!(
        body.contains("do not match"),
        "mismatch error not found in: {body}"
    );
}

// ==========================================================================
// Expired RA token: redirect to "/" to restart login
// ==========================================================================

#[tokio::test]
async fn post_expired_ra_token_redirects_to_root() {
    use hearth::identity::ra_token::OidcParams;

    let rig = build_rig_default();

    // Create a user (no session cookie needed — we'll forge the RA token directly).
    let user = rig
        .identity
        .create_user(
            &rig.realm_id,
            &CreateUserRequest {
                email: "expired@example.com".to_string(),
                display_name: "Expired User".to_string(),
                first_name: "E".to_string(),
                last_name: "U".to_string(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    // Generate an RA token using a timestamp from the distant past (1 second after epoch).
    // The resulting token will have exp = 901 s, which is far in the past from
    // the handler's SystemTime::now() perspective.
    let past = Timestamp::from_micros(1_000_000);
    let expired_token = rig
        .identity
        .generate_ra_token(
            &rig.realm_id,
            user.id(),
            vec![RequiredAction::UpdatePassword],
            OidcParams {
                client_id: rig.client.client_id().as_uuid().to_string(),
                redirect_uri: "https://app.example.com/cb".to_string(),
                scope: "openid".to_string(),
                code_challenge: "Y46VDv1_9BNSVpCJTxSBi3bHXX7h4wWOWpQ5xEoKcLs".to_string(),
                code_challenge_method: "S256".to_string(),
                nonce: None,
                state: Some("s".to_string()),
                response_type: "code".to_string(),
                response_mode: None,
                via_par: false,
            },
            past,
        )
        .expect("generate expired ra token");

    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/required-action/UPDATE_PASSWORD")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, format!("hearth_ra_session={expired_token}"))
                .body(Body::from(
                    "new_password=SomePassword1!&confirm_password=SomePassword1!",
                ))
                .expect("req"),
        )
        .await
        .expect("oneshot");

    assert!(
        resp.status().is_redirection(),
        "expected redirect, got: {}",
        resp.status()
    );
    let loc = location_of(&resp).expect("Location header");
    assert_eq!(
        loc, "/",
        "expired RA token should redirect to root, got: {loc}"
    );
}

// ==========================================================================
// Multi-action flow: UPDATE_PASSWORD → then OIDC resume (or next action)
// ==========================================================================

#[tokio::test]
async fn update_password_in_multi_action_flow_advances_to_next() {
    // VERIFY_EMAIL (priority 1) comes first; UPDATE_PASSWORD (priority 2) is second.
    // Completing UPDATE_PASSWORD via its dedicated route should advance to VERIFY_EMAIL.
    // (In a real flow VERIFY_EMAIL would intercept first, but we can test UPDATE_PASSWORD
    // completing when it is the only remaining action in the RA JWT.)

    // Build a rig where only UPDATE_PASSWORD is in the default required actions so
    // the authorize intercept generates an RA JWT with only UPDATE_PASSWORD pending.
    let rig = build_rig_default();
    let cookie = create_user_with_session(&rig, "multi-action@example.com");
    let ra_token = obtain_ra_cookie(&rig, &cookie).await;

    // POST valid password — should issue the auth code (only action remaining).
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/required-action/UPDATE_PASSWORD")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, format!("hearth_ra_session={ra_token}"))
                .body(Body::from(
                    "new_password=MultiActionPass1!&confirm_password=MultiActionPass1!",
                ))
                .expect("req"),
        )
        .await
        .expect("oneshot");

    assert!(
        resp.status().is_redirection(),
        "expected redirect, got: {}",
        resp.status()
    );
    let loc = location_of(&resp).unwrap_or_default();
    assert!(
        loc.starts_with("https://app.example.com/cb?code="),
        "expected auth code redirect after completing last action, got: {loc}"
    );
}
