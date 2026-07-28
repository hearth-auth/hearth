//! Integration tests for the VERIFY_EMAIL required-action handler (HEA-808).
//!
//! Covers:
//! * Normal flow: page renders, email sent, confirm link validates token and resumes OIDC
//! * Expired/invalid token: confirm route renders error page (does not advance RA state)
//! * Auto-clear: user whose email is already verified is advanced without re-verification
//! * Missing RA cookie: 400 on both page and confirm routes

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
use hearth::storage::{EmbeddedStorageEngine, StorageConfig};
use tower::ServiceExt;

const COOKIE_SECRET: [u8; 32] = [9u8; 32];
const PASSWORD: &str = "test-password-hearth-ve";
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

fn build_rig() -> Rig {
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
            name: format!("ve-test-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                default_required_actions: vec![RequiredAction::VerifyEmail],
                ..Default::default()
            }),
        })
        .expect("create realm");

    let client = identity
        .register_client(
            realm.id(),
            &RegisterClientRequest {
                client_name: "VE Test App".to_string(),
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
        Some(null_email()),
    )
    .with_dev_mode(true);

    Rig {
        app: web::router(state),
        identity,
        realm_id: realm.id().clone(),
        client,
    }
}

/// Creates an active user with VERIFY_EMAIL in required_actions.
fn create_user_needing_email_verify(rig: &Rig, email: &str) -> (UserId, String) {
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
    // Activate but keep VerifyEmail in required_actions.
    rig.identity
        .update_user(
            &rig.realm_id,
            user.id(),
            &UpdateUserRequest {
                status: Some(UserStatus::Active),
                required_actions: Some(vec![RequiredAction::VerifyEmail]),
                ..Default::default()
            },
        )
        .expect("activate with verify-email action");

    let session = rig
        .identity
        .create_session(&rig.realm_id, user.id(), &SessionContext::default())
        .expect("session");

    let cookie = session_cookie(&rig.realm_id, session.id(), "csrf-tok");
    (user.id().clone(), cookie)
}

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

fn authorize_uri(client: &OAuthClient) -> String {
    let challenge = pkce_challenge(PKCE_VERIFIER);
    format!(
        "/ui/oauth/authorize?client_id={}&redirect_uri={}&response_type=code&scope=openid&state=csrf-state&code_challenge={}&code_challenge_method=S256",
        client.client_id().as_uuid(),
        urlencode("https://app.example.com/cb"),
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

// ==========================================================================
// Normal flow: VERIFY_EMAIL page renders and confirm completes the action
// ==========================================================================

#[tokio::test]
async fn verify_email_page_renders_and_confirm_resumes_oidc() {
    let rig = build_rig();
    let (user_id, ui_cookie) = create_user_needing_email_verify(&rig, "user@example.com");

    // 1. GET authorize → intercepted at VERIFY_EMAIL.
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(authorize_uri(&rig.client))
                .header(header::COOKIE, &ui_cookie)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        location_of(&resp).as_deref(),
        Some("/required-action/VERIFY_EMAIL"),
        "must be intercepted at VERIFY_EMAIL"
    );
    let ra_token = ra_cookie_value(&resp).expect("RA cookie must be set");

    // 2. GET /required-action/VERIFY_EMAIL → renders "check your email" page.
    let resp2 = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/required-action/VERIFY_EMAIL")
                .header(header::COOKIE, format!("hearth_ra_session={ra_token}"))
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        resp2.status(),
        StatusCode::OK,
        "VERIFY_EMAIL page must return 200"
    );
    let body = body_text(resp2).await;
    // Must render the actual "check your email" page addressed to this user — the
    // prior `|| contains("email")` matched almost any HTML page.
    assert!(
        body.contains("user@example.com"),
        "page must show the user's email address: {body}"
    );
    assert!(
        body.contains("Check your email"),
        "page must be the verify-email prompt: {body}"
    );
    // 3. Get a fresh verification token directly (simulates clicking the email link).
    let token = rig
        .identity
        .issue_email_verification_token(&rig.realm_id, &user_id)
        .expect("issue token");

    // 4. GET /required-action/VERIFY_EMAIL/confirm?token={token} → resumes OIDC.
    let resp3 = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/required-action/VERIFY_EMAIL/confirm?token={}",
                    urlencode(&token)
                ))
                .header(header::COOKIE, format!("hearth_ra_session={ra_token}"))
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");

    assert!(
        resp3.status().is_redirection(),
        "confirm must redirect, got {}",
        resp3.status()
    );
    let loc = location_of(&resp3).expect("Location after confirm");
    assert!(
        loc.starts_with("https://app.example.com/cb?code="),
        "must redirect to OIDC redirect_uri with auth code: {loc}"
    );
    assert!(
        loc.contains("state=csrf-state"),
        "state param must be preserved: {loc}"
    );

    // RA cookie must be cleared (Max-Age=0).
    let cleared = resp3
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .any(|v| v.to_str().unwrap_or("").contains("hearth_ra_session=;"));
    assert!(cleared, "RA cookie must be cleared after completion");

    // The user record must now have email_verified = true.
    let user = rig
        .identity
        .get_user(&rig.realm_id, &user_id)
        .expect("get user")
        .expect("user exists");
    assert!(
        user.email_verified(),
        "email_verified must be true after confirm"
    );
}

// ==========================================================================
// Expired / invalid token → error page rendered, RA state not advanced
// ==========================================================================

#[tokio::test]
async fn confirm_with_invalid_token_renders_error_page() {
    let rig = build_rig();
    let (_user_id, ui_cookie) = create_user_needing_email_verify(&rig, "user2@example.com");

    // Intercept.
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(authorize_uri(&rig.client))
                .header(header::COOKIE, &ui_cookie)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");
    let ra_token = ra_cookie_value(&resp).expect("RA cookie");

    // Confirm with an obviously invalid token.
    let resp2 = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/required-action/VERIFY_EMAIL/confirm?token=invalid-token-abc123")
                .header(header::COOKIE, format!("hearth_ra_session={ra_token}"))
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");

    // Must render an error page (not redirect to OIDC).
    assert_eq!(
        resp2.status(),
        StatusCode::OK,
        "invalid token must render error page, not redirect"
    );
    let body = body_text(resp2).await;
    assert!(
        body.contains("expired") || body.contains("invalid") || body.contains("resend"),
        "error page must indicate link is expired/invalid and offer resend: {body}"
    );
}

// ==========================================================================
// Auto-clear: user email_verified=true in storage → action auto-cleared
// ==========================================================================

#[tokio::test]
async fn verify_email_auto_clears_when_already_verified() {
    let rig = build_rig();
    let (user_id, ui_cookie) = create_user_needing_email_verify(&rig, "user3@example.com");

    // Mark email as verified in storage without removing the required action.
    // We do this by consuming a verification token (which sets email_verified=true).
    let token = rig
        .identity
        .issue_email_verification_token(&rig.realm_id, &user_id)
        .expect("issue token");
    rig.identity
        .verify_email_token(&rig.realm_id, &token)
        .expect("consume token — sets email_verified=true");

    // VERIFY_EMAIL is still in required_actions (user must still be intercepted).
    let user = rig
        .identity
        .get_user(&rig.realm_id, &user_id)
        .expect("get")
        .expect("exists");
    assert!(
        user.email_verified(),
        "email_verified must be true after verify_email_token"
    );
    assert!(
        user.required_actions()
            .contains(&RequiredAction::VerifyEmail),
        "VERIFY_EMAIL must still be in required_actions (not yet auto-cleared)"
    );

    // Intercept at OIDC authorize.
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(authorize_uri(&rig.client))
                .header(header::COOKIE, &ui_cookie)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        location_of(&resp).as_deref(),
        Some("/required-action/VERIFY_EMAIL"),
        "VERIFY_EMAIL still in required_actions → must intercept"
    );
    let ra_token = ra_cookie_value(&resp).expect("RA cookie");

    // GET /required-action/VERIFY_EMAIL → auto-clear fires because email_verified=true.
    let resp2 = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/required-action/VERIFY_EMAIL")
                .header(header::COOKIE, format!("hearth_ra_session={ra_token}"))
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");

    // Must redirect directly to OIDC flow (no verification email needed).
    assert!(
        resp2.status().is_redirection(),
        "auto-clear must redirect, got {}",
        resp2.status()
    );
    let loc = location_of(&resp2).expect("Location after auto-clear");
    assert!(
        loc.starts_with("https://app.example.com/cb?code="),
        "auto-clear must resume OIDC with auth code: {loc}"
    );
}

// ==========================================================================
// Missing RA cookie → HTTP 400
// ==========================================================================

#[tokio::test]
async fn verify_email_page_without_ra_cookie_returns_400() {
    let rig = build_rig();
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
async fn verify_email_confirm_without_ra_cookie_returns_400() {
    let rig = build_rig();
    let resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/required-action/VERIFY_EMAIL/confirm?token=some-token")
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
