//! Supplementary integration tests for Required Actions AC-1 through AC-8.
//!
//! Covers gaps not addressed by the per-feature test files:
//!
//! - AC-3: Skippability — completing the second action first does not bypass the first
//! - AC-4: userId mismatch — tampered RA token sub is rejected via signature verification
//! - AC-6: Admin-assigned action causes intercept on next OIDC login
//! - AC-8: Audit events — RequiredActionCompleted and RequiredActionAutoCleared

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use data_encoding::BASE64URL_NOPAD;
use hearth::audit::{AuditAction, AuditEngine, AuditQuery, EmbeddedAuditEngine};
use hearth::core::{Clock, RealmId, SessionId, SystemClock, UserId};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CleartextPassword, ClientTrustLevel, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, OAuthClient, RealmConfig,
    RegisterClientRequest, RequiredAction, SessionContext, UpdateUserRequest, UserStatus,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig};
use tower::ServiceExt;

const COOKIE_SECRET: [u8; 32] = [11u8; 32];
const PASSWORD: &str = "test-password-hearth-acsuite";
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
    audit: Arc<dyn AuditEngine>,
    realm_id: RealmId,
    client: OAuthClient,
}

fn build_rig(default_actions: Vec<RequiredAction>) -> Rig {
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

    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: format!("ac-suite-{}", uuid::Uuid::new_v4()),
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
                client_name: "AC Suite Test App".to_string(),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                require_consent: false,
                grant_types: vec!["authorization_code".to_string()],
                trust_level: ClientTrustLevel::FirstParty,
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
        Arc::clone(&audit),
        onboarding,
        CookieSecret::from_bytes(COOKIE_SECRET),
        Some(null_email()),
    );

    Rig {
        app: web::router(state),
        identity,
        audit,
        realm_id: realm.id().clone(),
        client,
    }
}

fn create_user_with_required_actions(
    rig: &Rig,
    email: &str,
    actions: Vec<RequiredAction>,
) -> (UserId, String) {
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
                required_actions: Some(actions),
                ..Default::default()
            },
        )
        .expect("update user");

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

// ==========================================================================
// AC-3: Neither action is skippable
// ==========================================================================

/// With VERIFY_EMAIL (priority 1) and UPDATE_PASSWORD (priority 2) both pending,
/// a user who bypasses the redirect and POSTs directly to UPDATE_PASSWORD must
/// still be sent to VERIFY_EMAIL afterward — the first action cannot be skipped.
#[tokio::test]
async fn completing_second_action_first_does_not_skip_first_action() {
    let rig = build_rig(vec![]);
    let (_user_id, ui_cookie) = create_user_with_required_actions(
        &rig,
        "skip-attempt@example.com",
        vec![RequiredAction::VerifyEmail, RequiredAction::UpdatePassword],
    );

    // Authorize → intercepted at VERIFY_EMAIL (lower priority number = first).
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
        Some("/required-action/VERIFY_EMAIL"),
        "must intercept at VERIFY_EMAIL first (priority 1)"
    );
    let ra_token = ra_cookie_value(&resp).expect("RA token from intercept");

    // Attempt to skip VERIFY_EMAIL by posting directly to UPDATE_PASSWORD.
    // The RA token carries both actions; the handler processes UPDATE_PASSWORD
    // but must return the user to VERIFY_EMAIL (not issue the auth code).
    let resp2 = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/required-action/UPDATE_PASSWORD")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, format!("hearth_ra_session={ra_token}"))
                .body(Body::from(
                    "new_password=ValidPass-ac3!&confirm_password=ValidPass-ac3!",
                ))
                .expect("req"),
        )
        .await
        .expect("oneshot");

    assert!(
        resp2.status().is_redirection(),
        "expected redirect after UPDATE_PASSWORD submit, got {}",
        resp2.status()
    );
    let loc2 = location_of(&resp2).expect("Location after UPDATE_PASSWORD");
    assert_eq!(
        loc2, "/required-action/VERIFY_EMAIL",
        "VERIFY_EMAIL must still be required after skipping attempt; got: {loc2}"
    );
    assert!(
        !loc2.contains("code="),
        "auth code must NOT be issued while VERIFY_EMAIL is still pending"
    );
}

// ==========================================================================
// AC-4: userId mismatch — tampered RA token rejected by signature check
// ==========================================================================

/// Changing the `sub` field in the RA JWT payload without re-signing produces
/// an invalid Ed25519 signature.  The handler must reject the tampered token
/// with HTTP 400.  This covers the AC-4 "userId mismatch is rejected" requirement.
#[tokio::test]
async fn tampered_ra_token_sub_is_rejected() {
    let rig = build_rig(vec![]);
    let (_user_id, ui_cookie) = create_user_with_required_actions(
        &rig,
        "tamper@example.com",
        vec![RequiredAction::UpdatePassword],
    );

    // Obtain a valid RA token via the authorize intercept.
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

    let ra_token = ra_cookie_value(&resp).expect("RA token");

    // Decode the payload, swap `sub` to a random UUID (different user), re-encode
    // WITHOUT re-signing — this invalidates the Ed25519 signature over header.payload.
    let parts: Vec<&str> = ra_token.split('.').collect();
    assert_eq!(parts.len(), 3, "RA JWT must have three parts");

    let payload_bytes = BASE64URL_NOPAD
        .decode(parts[1].as_bytes())
        .expect("decode payload");
    let mut claims: serde_json::Value =
        serde_json::from_slice(&payload_bytes).expect("parse payload JSON");
    claims["sub"] = serde_json::Value::String(uuid::Uuid::new_v4().to_string());
    let tampered_payload =
        BASE64URL_NOPAD.encode(serde_json::to_vec(&claims).expect("re-encode").as_slice());

    // Original header + tampered payload + original (now-invalid) signature.
    let tampered_token = format!("{}.{}.{}", parts[0], tampered_payload, parts[2]);

    let resp2 = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/required-action/UPDATE_PASSWORD")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(
                    header::COOKIE,
                    format!("hearth_ra_session={tampered_token}"),
                )
                .body(Body::from(
                    "new_password=ValidPass-ac4!&confirm_password=ValidPass-ac4!",
                ))
                .expect("req"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        resp2.status(),
        StatusCode::BAD_REQUEST,
        "tampered RA token (invalid signature) must return 400; got {}",
        resp2.status()
    );
}

// ==========================================================================
// AC-6: Admin-assigned action causes intercept on next OIDC login
// ==========================================================================

/// A user who had no required actions initially must be intercepted on their
/// next OIDC authorization attempt after an admin assigns VERIFY_EMAIL.
/// This is the end-to-end path for AC-6's "intercepted on next login" criterion.
#[tokio::test]
async fn admin_assigned_action_intercepted_on_next_oidc_authorize() {
    let rig = build_rig(vec![]);

    // Create user with no required actions.
    let (user_id, ui_cookie) =
        create_user_with_required_actions(&rig, "no-action@example.com", vec![]);

    // First authorize: no required actions → auth code issued.
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
    let loc = location_of(&resp).expect("Location");
    assert!(
        loc.starts_with("https://app.example.com/cb?code="),
        "initial authorize (no RAs) must issue code; got: {loc}"
    );

    // Admin assigns VERIFY_EMAIL (mirrors what PATCH /required-actions does).
    rig.identity
        .update_user(
            &rig.realm_id,
            &user_id,
            &UpdateUserRequest {
                required_actions: Some(vec![RequiredAction::VerifyEmail]),
                ..Default::default()
            },
        )
        .expect("assign required action");

    // Create a new session (simulates user's next login).
    let new_session = rig
        .identity
        .create_session(&rig.realm_id, &user_id, &SessionContext::default())
        .expect("new session");
    let new_cookie = session_cookie(&rig.realm_id, new_session.id(), "csrf2");

    // Next authorize must be intercepted.
    let resp2 = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(authorize_uri(&rig.client, "openid"))
                .header(header::COOKIE, &new_cookie)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");

    assert!(
        resp2.status().is_redirection(),
        "expected redirect to required-action page; got {}",
        resp2.status()
    );
    let loc2 = location_of(&resp2).expect("Location after admin-assign");
    assert_eq!(
        loc2, "/required-action/VERIFY_EMAIL",
        "must be intercepted at VERIFY_EMAIL after admin assign; got: {loc2}"
    );
    assert!(
        ra_cookie_value(&resp2).is_some(),
        "RA session cookie must be set"
    );
}

// ==========================================================================
// AC-8: RequiredActionCompleted audit event — UPDATE_PASSWORD
// ==========================================================================

/// Successfully completing UPDATE_PASSWORD must emit a RequiredActionCompleted
/// audit event with `action_type = "UPDATE_PASSWORD"` and the correct user as
/// the resource.
#[tokio::test]
async fn update_password_completion_emits_audit_event() {
    let rig = build_rig(vec![]);
    let (user_id, ui_cookie) = create_user_with_required_actions(
        &rig,
        "audit-up@example.com",
        vec![RequiredAction::UpdatePassword],
    );

    // Intercept.
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
    let ra_token = ra_cookie_value(&resp).expect("RA token");

    // Complete UPDATE_PASSWORD.
    rig.app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/required-action/UPDATE_PASSWORD")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, format!("hearth_ra_session={ra_token}"))
                .body(Body::from(
                    "new_password=AuditTestPass-8!&confirm_password=AuditTestPass-8!",
                ))
                .expect("req"),
        )
        .await
        .expect("oneshot");

    let events = rig
        .audit
        .query(&AuditQuery {
            action: Some(AuditAction::RequiredActionCompleted),
            ..AuditQuery::for_realm(rig.realm_id.clone())
        })
        .expect("audit query");

    let matched = events.iter().any(|e| {
        e.action == AuditAction::RequiredActionCompleted
            && e.resource_id == user_id.as_uuid().to_string()
            && e.metadata
                .as_ref()
                .and_then(|m| m.get("action_type"))
                .and_then(|v| v.as_str())
                == Some("UPDATE_PASSWORD")
    });
    assert!(
        matched,
        "RequiredActionCompleted(UPDATE_PASSWORD) must be in audit log; events: {events:?}"
    );
}

// ==========================================================================
// AC-8: RequiredActionCompleted audit event — VERIFY_EMAIL
// ==========================================================================

/// Clicking the verification link (GET /confirm) must emit RequiredActionCompleted
/// with `action_type = "VERIFY_EMAIL"`.
#[tokio::test]
async fn verify_email_completion_emits_audit_event() {
    let rig = build_rig(vec![]);
    let (user_id, ui_cookie) = create_user_with_required_actions(
        &rig,
        "audit-ve@example.com",
        vec![RequiredAction::VerifyEmail],
    );

    // Intercept.
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
    let ra_token = ra_cookie_value(&resp).expect("RA token");

    // Issue and consume a verification token.
    let ve_token = rig
        .identity
        .issue_email_verification_token(&rig.realm_id, &user_id)
        .expect("issue ve token");

    rig.app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/required-action/VERIFY_EMAIL/confirm?token={}",
                    urlencode(&ve_token)
                ))
                .header(header::COOKIE, format!("hearth_ra_session={ra_token}"))
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");

    let events = rig
        .audit
        .query(&AuditQuery {
            action: Some(AuditAction::RequiredActionCompleted),
            ..AuditQuery::for_realm(rig.realm_id.clone())
        })
        .expect("audit query");

    let matched = events.iter().any(|e| {
        e.action == AuditAction::RequiredActionCompleted
            && e.resource_id == user_id.as_uuid().to_string()
            && e.metadata
                .as_ref()
                .and_then(|m| m.get("action_type"))
                .and_then(|v| v.as_str())
                == Some("VERIFY_EMAIL")
    });
    assert!(
        matched,
        "RequiredActionCompleted(VERIFY_EMAIL) must be in audit log; events: {events:?}"
    );
}

// ==========================================================================
// Security: cross-user VERIFY_EMAIL token substitution (HEA-815)
// ==========================================================================

/// Submitting User A's email-verification token inside User B's RA session must
/// be rejected with HTTP 400, and User B's VERIFY_EMAIL action must remain pending.
///
/// Regression for FINDING-1 from security review HEA-810: the handler previously
/// discarded the `verified_user_id` returned by `verify_email_token`, allowing
/// User B to clear their own VERIFY_EMAIL required-action using a token minted for
/// User A.
#[tokio::test]
async fn cross_user_verify_email_token_is_rejected() {
    let rig = build_rig(vec![]);

    // Create User A and User B, both with VERIFY_EMAIL pending.
    let (user_a_id, cookie_a) = create_user_with_required_actions(
        &rig,
        "user-a@example.com",
        vec![RequiredAction::VerifyEmail],
    );
    let (user_b_id, cookie_b) = create_user_with_required_actions(
        &rig,
        "user-b@example.com",
        vec![RequiredAction::VerifyEmail],
    );

    // Obtain RA session cookies by driving each user through the authorize intercept.
    let resp_a = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(authorize_uri(&rig.client, "openid"))
                .header(header::COOKIE, &cookie_a)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");
    assert_eq!(
        location_of(&resp_a).as_deref(),
        Some("/required-action/VERIFY_EMAIL"),
        "User A must be intercepted"
    );

    let resp_b = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(authorize_uri(&rig.client, "openid"))
                .header(header::COOKIE, &cookie_b)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");
    assert_eq!(
        location_of(&resp_b).as_deref(),
        Some("/required-action/VERIFY_EMAIL"),
        "User B must be intercepted"
    );
    let ra_token_b = ra_cookie_value(&resp_b).expect("User B RA token");

    // Issue a verification token for User A only.
    let token_a = rig
        .identity
        .issue_email_verification_token(&rig.realm_id, &user_a_id)
        .expect("issue ve token for user A");

    // Attack: submit User A's token using User B's RA session.
    let attack_resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/required-action/VERIFY_EMAIL/confirm?token={}",
                    urlencode(&token_a)
                ))
                .header(header::COOKIE, format!("hearth_ra_session={ra_token_b}"))
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        attack_resp.status(),
        StatusCode::BAD_REQUEST,
        "cross-user token submission must return 400; got {}",
        attack_resp.status()
    );

    // User B's VERIFY_EMAIL action must still be present in the DB.
    let user_b = rig
        .identity
        .get_user(&rig.realm_id, &user_b_id)
        .expect("get user B")
        .expect("user B must exist");
    assert!(
        user_b
            .required_actions()
            .contains(&RequiredAction::VerifyEmail),
        "User B's VERIFY_EMAIL must NOT have been cleared by the cross-user attack"
    );

    // User A's VERIFY_EMAIL must also still be pending (token was not consumed successfully).
    let user_a = rig
        .identity
        .get_user(&rig.realm_id, &user_a_id)
        .expect("get user A")
        .expect("user A must exist");
    assert!(
        user_a
            .required_actions()
            .contains(&RequiredAction::VerifyEmail),
        "User A's VERIFY_EMAIL must still be pending — their token was used in attack but rejected"
    );
}

// ==========================================================================
// AC-8: RequiredActionAutoCleared audit event
// ==========================================================================

/// When VERIFY_EMAIL is auto-cleared because the email is already verified in
/// storage, a RequiredActionAutoCleared event must be emitted.
#[tokio::test]
async fn verify_email_auto_clear_emits_audit_event() {
    let rig = build_rig(vec![]);
    let (user_id, ui_cookie) = create_user_with_required_actions(
        &rig,
        "audit-autoclear@example.com",
        vec![RequiredAction::VerifyEmail],
    );

    // Pre-verify the email (simulates migration: email_verified=true but
    // VERIFY_EMAIL still in required_actions).
    let token = rig
        .identity
        .issue_email_verification_token(&rig.realm_id, &user_id)
        .expect("issue token");
    rig.identity
        .verify_email_token(&rig.realm_id, &token)
        .expect("mark verified");

    // Intercept (VERIFY_EMAIL still listed in required_actions).
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
    let ra_token = ra_cookie_value(&resp).expect("RA token");

    // GET /required-action/VERIFY_EMAIL — auto-clear fires (email already verified).
    rig.app
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

    let events = rig
        .audit
        .query(&AuditQuery {
            action: Some(AuditAction::RequiredActionAutoCleared),
            ..AuditQuery::for_realm(rig.realm_id.clone())
        })
        .expect("audit query");

    let matched = events.iter().any(|e| {
        e.action == AuditAction::RequiredActionAutoCleared
            && e.resource_id == user_id.as_uuid().to_string()
            && e.metadata
                .as_ref()
                .and_then(|m| m.get("action_type"))
                .and_then(|v| v.as_str())
                == Some("VERIFY_EMAIL")
    });
    assert!(
        matched,
        "RequiredActionAutoCleared(VERIFY_EMAIL) must be in audit log; events: {events:?}"
    );
}
