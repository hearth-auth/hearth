//! Integration tests for the Required-Action OIDC interceptor (HEA-806).
//!
//! Covers:
//! * AC-1: authorize route intercepts users with pending required actions
//! * AC-3: sequential multi-action completion
//! * AC-5: users with no required actions proceed normally (no-op path)

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use data_encoding::BASE64URL_NOPAD;
use hearth::audit::EmbeddedAuditEngine;
use hearth::core::{Clock, RealmId, SessionId, SystemClock, UserId};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, OAuthClient, RealmConfig,
    RegisterClientRequest, RequiredAction, SessionContext, UpdateUserRequest, UserStatus,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use tower::ServiceExt;

const COOKIE_SECRET: [u8; 32] = [7u8; 32];
const PASSWORD: &str = "test-password-hearth";
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

fn build_rig_with_realm_actions(default_actions: Vec<RequiredAction>) -> Rig {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);

    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).expect("storage"),
    );
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
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
            name: format!("ra-test-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                default_required_actions: default_actions,
                ..Default::default()
            }),
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
                // FirstParty trust level bypasses consent (engine ignores require_consent field;
                // it derives consent requirement from trust_level == ThirdParty).
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

/// Creates an active user and returns their UserId + a valid session cookie string.
fn create_active_user_with_session(rig: &Rig, email: &str) -> (UserId, String) {
    let user = rig
        .identity
        .create_user(
            &rig.realm_id,
            &CreateUserRequest {
                email: email.to_string(),
                display_name: "Test".to_string(),
                first_name: "T".to_string(),
                last_name: "U".to_string(),
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

    let cookie = session_cookie(&rig.realm_id, session.id(), "csrf-tok");
    (user.id().clone(), cookie)
}

/// Builds a signed UI session cookie.
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
        "/ui/oauth/authorize?client_id={}&redirect_uri={}&response_type=code&scope={}&state=csrf-state&code_challenge={}&code_challenge_method=S256",
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
                out.push(b as char)
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

fn ra_cookie_value(resp: &axum::response::Response) -> Option<String> {
    for v in resp.headers().get_all(header::SET_COOKIE) {
        let s = v.to_str().ok()?;
        if let Some(rest) = s.strip_prefix("hearth_ra_session=") {
            return Some(rest.split(';').next()?.to_string());
        }
    }
    None
}

#[allow(dead_code)]
async fn body_utf8(resp: axum::response::Response) -> String {
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.expect("body");
    String::from_utf8(bytes.to_vec()).expect("utf-8")
}

// ==========================================================================
// AC-5: No required actions → flow proceeds normally
// ==========================================================================

#[tokio::test]
async fn no_required_actions_issues_code_normally() {
    let rig = build_rig_with_realm_actions(vec![]);
    let (_, cookie) = create_active_user_with_session(&rig, "clean@example.com");

    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(authorize_uri(&rig.client, "openid"))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");

    // Trusted client (require_consent=false) → immediate code redirect to redirect_uri.
    assert!(
        resp.status().is_redirection(),
        "expected redirect, got {}",
        resp.status()
    );
    let loc = location_of(&resp).expect("Location header");
    assert!(
        loc.starts_with("https://app.example.com/cb?code="),
        "expected code redirect, got: {loc}"
    );
    // No RA cookie should be set.
    assert!(ra_cookie_value(&resp).is_none(), "unexpected RA cookie set");
}

// ==========================================================================
// AC-1: Single required action → intercepts before code issuance
// ==========================================================================

#[tokio::test]
async fn single_required_action_intercepts_authorize() {
    let rig = build_rig_with_realm_actions(vec![RequiredAction::VerifyEmail]);
    let (_, cookie) = create_active_user_with_session(&rig, "unverified@example.com");

    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(authorize_uri(&rig.client, "openid"))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");

    // Must redirect to the RA action page, not to the client redirect_uri.
    assert!(
        resp.status().is_redirection(),
        "expected redirect, got {}",
        resp.status()
    );
    let loc = location_of(&resp).expect("Location header");
    assert_eq!(
        loc, "/required-action/VERIFY_EMAIL",
        "unexpected redirect location: {loc}"
    );

    // RA session cookie must be set.
    let ra_token = ra_cookie_value(&resp).expect("RA session cookie should be set");
    assert!(!ra_token.is_empty(), "RA token must not be empty");

    // No code should be in the location.
    assert!(
        !loc.contains("code="),
        "auth code must NOT be issued during intercept"
    );
}

#[tokio::test]
async fn single_required_action_completion_resumes_oidc_flow() {
    let rig = build_rig_with_realm_actions(vec![RequiredAction::VerifyEmail]);
    let (_, ui_cookie) = create_active_user_with_session(&rig, "complete@example.com");

    // 1. GET authorize → intercepted, RA cookie set.
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(authorize_uri(&rig.client, "openid"))
                .header(header::COOKIE, &ui_cookie)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        location_of(&resp).as_deref(),
        Some("/required-action/VERIFY_EMAIL")
    );
    let ra_token = ra_cookie_value(&resp).expect("RA token");

    // 2. POST /required-action/VERIFY_EMAIL (action complete) with RA cookie.
    let resp2 = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/required-action/VERIFY_EMAIL")
                .header(header::COOKIE, format!("hearth_ra_session={ra_token}"))
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");

    // All actions complete → must redirect to client redirect_uri with auth code.
    assert!(
        resp2.status().is_redirection(),
        "expected redirect after completion, got {}",
        resp2.status()
    );
    let loc2 = location_of(&resp2).expect("Location after completion");
    assert!(
        loc2.starts_with("https://app.example.com/cb?code="),
        "expected code redirect after RA completion, got: {loc2}",
    );
    assert!(
        loc2.contains("state=csrf-state"),
        "state param must be preserved: {loc2}"
    );

    // RA cookie must be cleared (Max-Age=0).
    let cleared = resp2
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .any(|v| v.to_str().unwrap_or("").contains("hearth_ra_session=;"));
    assert!(
        cleared,
        "RA session cookie must be cleared after completion"
    );
}

// ==========================================================================
// AC-3: Multiple required actions → sequential completion
// ==========================================================================

#[tokio::test]
async fn multiple_required_actions_sequential_completion() {
    // Realm defaults: both actions required. Priority: VerifyEmail(1) first.
    let rig = build_rig_with_realm_actions(vec![
        RequiredAction::UpdatePassword, // stored out-of-priority-order
        RequiredAction::VerifyEmail,
    ]);
    let (_, ui_cookie) = create_active_user_with_session(&rig, "multi@example.com");

    // Step 1: authorize → intercepted, redirected to VERIFY_EMAIL (lower priority = first).
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(authorize_uri(&rig.client, "openid"))
                .header(header::COOKIE, &ui_cookie)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");

    let loc = location_of(&resp).expect("location");
    assert_eq!(
        loc, "/required-action/VERIFY_EMAIL",
        "first action must be VERIFY_EMAIL (priority 1)"
    );
    let ra_token_1 = ra_cookie_value(&resp).expect("RA token after first intercept");

    // Step 2: complete VERIFY_EMAIL → should redirect to UPDATE_PASSWORD (not to client).
    let resp2 = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/required-action/VERIFY_EMAIL")
                .header(header::COOKIE, format!("hearth_ra_session={ra_token_1}"))
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");

    assert!(
        resp2.status().is_redirection(),
        "expected redirect after first completion"
    );
    let loc2 = location_of(&resp2).expect("location after first completion");
    assert_eq!(
        loc2, "/required-action/UPDATE_PASSWORD",
        "second action must be UPDATE_PASSWORD: {loc2}",
    );
    // A fresh RA token must be issued for the second action.
    let ra_token_2 = ra_cookie_value(&resp2).expect("fresh RA token for second action");
    assert_ne!(
        ra_token_1, ra_token_2,
        "each step must issue a fresh RA JWT"
    );

    // Step 3: complete UPDATE_PASSWORD → all done, flow resumes with auth code.
    let resp3 = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/required-action/UPDATE_PASSWORD")
                .header(header::COOKIE, format!("hearth_ra_session={ra_token_2}"))
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");

    assert!(
        resp3.status().is_redirection(),
        "expected code redirect after all actions"
    );
    let loc3 = location_of(&resp3).expect("final location");
    assert!(
        loc3.starts_with("https://app.example.com/cb?code="),
        "expected auth code after completing all actions: {loc3}",
    );
    assert!(
        loc3.contains("state=csrf-state"),
        "state param must be preserved: {loc3}"
    );
}

// ==========================================================================
// Adversarial: missing / tampered RA cookie → 400
// ==========================================================================

#[tokio::test]
async fn action_complete_without_ra_cookie_returns_bad_request() {
    let rig = build_rig_with_realm_actions(vec![]);
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/required-action/VERIFY_EMAIL")
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn action_page_without_ra_cookie_returns_bad_request() {
    let rig = build_rig_with_realm_actions(vec![]);
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/required-action/VERIFY_EMAIL")
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn action_page_unknown_action_returns_not_found() {
    let rig = build_rig_with_realm_actions(vec![]);
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/required-action/UNKNOWN_ACTION")
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
