//! Console-minted system-realm API tokens (GA audit 3 DOC-2, round 2).
//!
//! `hearth admin token` needs the server stopped and refuses a cluster node, so
//! a running cluster had no source of the system-realm token its runbooks call
//! `/admin/cluster/*` with. An operator signed in to the admin console, with
//! `hearth.admin` in the system realm, now mints one at `/ui/admin/api-tokens`
//! after a fresh step-up (password + second factor), through the normal engine
//! write path — so in cluster mode the session and audit record replicate.

#[path = "common/webauthn_helper.rs"]
mod webauthn_helper;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use base64::Engine as _;
use tower::ServiceExt;

use hearth::audit::{AuditAction, AuditEngine, AuditQuery, EmbeddedAuditEngine};
use hearth::core::{Clock, FakeClock, RealmId, SessionId, SystemClock, UserId};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    verify_step_up, AuthenticationOptions, CleartextPassword, CreateRealmRequest,
    CreateUserRequest, CredentialConfig, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine,
    IdentityError, KdfGateConfig, MfaProof, RegistrationOptions, SessionContext, StepUpError,
    StepUpProof, UpdateUserRequest, UserStatus,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{AssignRoleRequest, EmbeddedRbacEngine, RbacEngine, Scope, Subject};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use webauthn_helper::TestAuthenticator;

const COOKIE_SECRET: [u8; 32] = [41u8; 32];
const CSRF: &str = "csrf-api-token-console";
const PASSWORD: &str = "0per@tor-passw0rd!";
const ORIGIN: &str = "http://localhost";
const RP_ID: &str = "localhost";
const PAGE: &str = "/ui/admin/api-tokens";

fn system_realm() -> RealmId {
    RealmId::new(uuid::Uuid::nil())
}

fn totp_code(secret_base32: &str, unix_secs: u64) -> String {
    let secret = data_encoding::BASE32_NOPAD
        .decode(secret_base32.as_bytes())
        .expect("decode base32");
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &secret);
    let tag = ring::hmac::sign(&key, &(unix_secs / 30).to_be_bytes());
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

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

struct Rig {
    web: axum::Router,
    api: axum::Router,
    identity: Arc<dyn IdentityEngine>,
    rbac: Arc<dyn RbacEngine>,
    audit: Arc<dyn AuditEngine>,
    clock: Arc<FakeClock>,
}

impl Rig {
    fn now_secs(&self) -> u64 {
        u64::try_from(self.clock.now().as_micros() / 1_000_000).expect("positive clock")
    }
}

struct Operator {
    id: UserId,
    session: SessionId,
    totp_secret: Option<String>,
    passkey: Option<TestAuthenticator>,
}

impl Operator {
    fn cookie(&self) -> String {
        cookie(&system_realm(), &self.session)
    }
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

fn build_rig() -> Rig {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);
    let storage: Arc<dyn StorageEngine> = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).expect("storage"),
    );
    let clock = Arc::new(FakeClock::new(SystemClock.now()));
    let clock_dyn = Arc::clone(&clock) as Arc<dyn Clock>;
    let audit: Arc<dyn AuditEngine> = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock_dyn),
    ));
    let rbac: Arc<dyn RbacEngine> = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock_dyn),
    ));
    let identity: Arc<dyn IdentityEngine> = Arc::new(
        EmbeddedIdentityEngine::with_rbac(
            Arc::clone(&storage),
            clock_dyn,
            IdentityConfig {
                credential: CredentialConfig::fast_for_testing(),
                ..IdentityConfig::default()
            },
            Arc::clone(&rbac),
            Arc::clone(&audit),
        )
        .expect("identity"),
    );
    rbac.seed_realm(&system_realm()).expect("seed system realm");

    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&identity),
        Arc::clone(&rbac),
        email_service(),
        data_dir,
    ));
    let web_state = WebState::new(
        Arc::clone(&identity),
        Arc::clone(&rbac),
        Arc::clone(&audit),
        onboarding,
        CookieSecret::from_bytes(COOKIE_SECRET),
        None,
    )
    .with_dev_mode(true);
    let api_state = Arc::new(hearth::protocol::http::AppState::new_dev(
        Arc::clone(&identity),
        Arc::clone(&rbac),
        Arc::clone(&audit),
    ));
    Rig {
        web: web::router(web_state),
        api: hearth::protocol::http::router(api_state),
        identity,
        rbac,
        audit,
        clock,
    }
}

fn create_system_user(rig: &Rig, email: &str, admin: bool) -> UserId {
    let sys = system_realm();
    let user = rig
        .identity
        .create_admin_user(&CreateUserRequest {
            email: email.to_string(),
            display_name: "Operator".to_string(),
            ..Default::default()
        })
        .expect("create system user");
    rig.identity
        .set_password(
            &sys,
            user.id(),
            &CleartextPassword::from_string(PASSWORD.to_string()),
        )
        .expect("password");
    rig.identity
        .update_user(
            &sys,
            user.id(),
            &UpdateUserRequest {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .expect("activate");
    if admin {
        let role = rig
            .rbac
            .get_role_by_name(&sys, "realm.admin")
            .expect("lookup")
            .expect("seeded");
        rig.rbac
            .assign_role(
                &sys,
                &AssignRoleRequest {
                    subject: Subject::User(user.id().clone()),
                    role_id: role.id,
                    scope: Scope::Realm,
                    assigned_by: None,
                },
            )
            .expect("grant realm.admin");
    }
    user.id().clone()
}

/// A console session, as a completed passkey login would open it.
fn console_session(rig: &Rig, user: &UserId) -> SessionId {
    rig.identity
        .create_session(
            &system_realm(),
            user,
            &SessionContext {
                mfa_proof: MfaProof::ProvedWebAuthn,
                ..SessionContext::default()
            },
        )
        .expect("console session")
        .id()
        .clone()
}

/// An operator holding `realm.admin`, a password and a TOTP factor.
fn totp_operator(rig: &Rig, email: &str) -> Operator {
    let id = create_system_user(rig, email, true);
    let sys = system_realm();
    let enrollment = rig.identity.enroll_totp(&sys, &id).expect("enroll totp");
    // One step back, so a step-up can use the current step without tripping
    // replay protection.
    rig.identity
        .verify_totp_enrollment(
            &sys,
            &id,
            &totp_code(&enrollment.secret_base32, rig.now_secs() - 30),
        )
        .expect("activate totp");
    let session = console_session(rig, &id);
    Operator {
        id,
        session,
        totp_secret: Some(enrollment.secret_base32.clone()),
        passkey: None,
    }
}

/// An operator holding `realm.admin`, a password and a passkey.
fn passkey_operator(rig: &Rig) -> Operator {
    let id = create_system_user(rig, "passkey-ops@hearth.example", true);
    let sys = system_realm();
    let authenticator = TestAuthenticator::new(RP_ID);
    let challenge = rig
        .identity
        .start_webauthn_registration(
            &sys,
            &id,
            &RegistrationOptions {
                rp_id: RP_ID.to_string(),
                discoverable: true,
            },
        )
        .expect("start registration");
    let (cdj, att) = authenticator.build_verified_registration_response(&challenge, ORIGIN);
    rig.identity
        .complete_webauthn_registration(&sys, &id, &cdj, &att, ORIGIN, true)
        .expect("register passkey");
    let session = console_session(rig, &id);
    Operator {
        id,
        session,
        totp_secret: None,
        passkey: Some(authenticator),
    }
}

fn cookie(realm: &RealmId, session: &SessionId) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256>>::new_from_slice(&COOKIE_SECRET).expect("key");
    mac.update(session.as_uuid().as_bytes());
    mac.update(b"|");
    mac.update(realm.as_uuid().as_bytes());
    let tag = data_encoding::BASE64URL_NOPAD.encode(&mac.finalize().into_bytes());
    format!(
        "hearth_ui_session={}.{}.{}; hearth_ui_csrf={CSRF}",
        session.as_uuid(),
        realm.as_uuid(),
        tag,
    )
}

struct Page {
    status: StatusCode,
    cache_control: Option<String>,
    location: Option<String>,
    retry_after: Option<String>,
    body: String,
}

async fn send_web(rig: &Rig, req: Request<Body>) -> Page {
    let resp = rig.web.clone().oneshot(req).await.expect("web response");
    let status = resp.status();
    let header_value = |name: header::HeaderName| {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let cache_control = header_value(header::CACHE_CONTROL);
    let location = header_value(header::LOCATION);
    let retry_after = header_value(header::RETRY_AFTER);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    Page {
        status,
        cache_control,
        location,
        retry_after,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

async fn get_page(rig: &Rig, cookie: Option<String>) -> Page {
    let mut req = Request::builder().method("GET").uri(PAGE);
    if let Some(c) = cookie {
        req = req.header(header::COOKIE, c);
    }
    send_web(rig, req.body(Body::empty()).expect("request")).await
}

async fn post_form(rig: &Rig, cookie: Option<String>, fields: &[(&str, &str)]) -> Page {
    let body = serde_urlencoded::to_string(fields).expect("encode form");
    let mut req = Request::builder()
        .method("POST")
        .uri(PAGE)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(c) = cookie {
        req = req.header(header::COOKIE, c);
    }
    send_web(rig, req.body(Body::from(body)).expect("request")).await
}

/// The token shown on the result page (`<code id="api-token" …>TOKEN</code>`).
fn shown_token(page: &Page) -> Option<String> {
    let start = page.body.find("id=\"api-token\"")?;
    let rest = &page.body[start..];
    let open = rest.find('>')? + 1;
    let close = rest[open..].find('<')?;
    let token = rest[open..open + close].trim();
    (token.split('.').count() == 3).then(|| token.to_string())
}

/// Whether anything shaped like a JWT appears in a response body.
fn carries_a_jwt(body: &str) -> bool {
    body.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'))
        .any(|w| w.starts_with("eyJ") && w.split('.').count() == 3)
}

async fn api_status(rig: &Rig, path: &str, token: &str) -> StatusCode {
    let mut req = Request::builder()
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .header("x-realm-id", uuid::Uuid::nil().to_string())
        .body(Body::empty())
        .expect("request");
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            40_001,
        ))));
    rig.api
        .clone()
        .oneshot(req)
        .await
        .expect("api response")
        .status()
}

fn issued_events(rig: &Rig) -> Vec<hearth::audit::AuditEvent> {
    rig.audit
        .query(&AuditQuery {
            action: Some(AuditAction::TokenIssued),
            ..AuditQuery::for_realm(system_realm())
        })
        .expect("audit query")
        .into_iter()
        .filter(|e| {
            e.metadata
                .as_ref()
                .and_then(|m| m.get("issued_via"))
                .and_then(serde_json::Value::as_str)
                == Some("admin console")
        })
        .collect()
}

/// Mints a token with password + the current TOTP code.
async fn mint_with_totp(rig: &Rig, op: &Operator, ttl_minutes: &str) -> Page {
    let code = totp_code(op.totp_secret.as_deref().expect("totp"), rig.now_secs());
    post_form(
        rig,
        Some(op.cookie()),
        &[
            ("_csrf", CSRF),
            ("ttl_minutes", ttl_minutes),
            ("password", PASSWORD),
            ("totp_code", &code),
        ],
    )
    .await
}

// ─── access control ─────────────────────────────────────────────────────────

/// No console session: the page and the form both send the browser to the
/// admin login, and nothing is minted.
#[tokio::test(flavor = "multi_thread")]
async fn without_a_console_session_the_page_redirects_to_login() {
    let rig = build_rig();
    for page in [
        get_page(&rig, None).await,
        post_form(&rig, None, &[("_csrf", CSRF), ("password", PASSWORD)]).await,
    ] {
        assert!(
            page.status.is_redirection(),
            "no session must redirect, got {}",
            page.status
        );
        assert!(
            page.location
                .as_deref()
                .is_some_and(|l| l.contains("login")),
            "to the login page: {:?}",
            page.location
        );
        assert!(!carries_a_jwt(&page.body));
    }
}

/// A tenant-realm session, and a system-realm session without `hearth.admin`,
/// are both forbidden.
#[tokio::test(flavor = "multi_thread")]
async fn a_tenant_or_non_admin_session_is_forbidden() {
    let rig = build_rig();
    let tenant = rig
        .identity
        .create_realm(&CreateRealmRequest {
            name: "tenantco".to_string(),
            config: None,
        })
        .expect("tenant realm");
    rig.rbac.seed_realm(tenant.id()).expect("seed tenant");
    let tenant_user = rig
        .identity
        .create_user(
            tenant.id(),
            &CreateUserRequest {
                email: "admin@tenantco.example".to_string(),
                display_name: "Tenant admin".to_string(),
                ..Default::default()
            },
        )
        .expect("tenant user");
    let tenant_session = rig
        .identity
        .create_session(tenant.id(), tenant_user.id(), &SessionContext::default())
        .expect("tenant session");
    let viewer = create_system_user(&rig, "viewer@hearth.example", false);
    let viewer_session = console_session(&rig, &viewer);

    for jar in [
        cookie(tenant.id(), tenant_session.id()),
        cookie(&system_realm(), &viewer_session),
    ] {
        let page = get_page(&rig, Some(jar.clone())).await;
        assert_eq!(page.status, StatusCode::FORBIDDEN);
        let page = post_form(
            &rig,
            Some(jar),
            &[
                ("_csrf", CSRF),
                ("ttl_minutes", "15"),
                ("password", PASSWORD),
            ],
        )
        .await;
        assert_eq!(page.status, StatusCode::FORBIDDEN);
        assert!(!carries_a_jwt(&page.body));
    }
    assert!(issued_events(&rig).is_empty());
}

// ─── step-up ─────────────────────────────────────────────────────────────────

/// Every incomplete or wrong step-up is refused, as is a missing CSRF token,
/// an out-of-range lifetime, and an operator with no second factor to prove.
#[tokio::test(flavor = "multi_thread")]
async fn a_missing_or_failed_step_up_is_refused() {
    let rig = build_rig();
    let op = totp_operator(&rig, "ops@hearth.example");
    let code = totp_code(op.totp_secret.as_deref().expect("totp"), rig.now_secs());

    let form_page = get_page(&rig, Some(op.cookie())).await;
    assert_eq!(form_page.status, StatusCode::OK, "{}", form_page.body);
    assert!(form_page.body.contains("name=\"ttl_minutes\""));

    let cases: [(&str, Vec<(&str, &str)>); 6] = [
        (
            "no step-up at all",
            vec![("_csrf", CSRF), ("ttl_minutes", "15")],
        ),
        (
            "the password without the second factor",
            vec![
                ("_csrf", CSRF),
                ("ttl_minutes", "15"),
                ("password", PASSWORD),
            ],
        ),
        (
            "the second factor without the password",
            vec![("_csrf", CSRF), ("ttl_minutes", "15"), ("totp_code", &code)],
        ),
        (
            "a wrong password",
            vec![
                ("_csrf", CSRF),
                ("ttl_minutes", "15"),
                ("password", "not-the-password-at-all"),
                ("totp_code", &code),
            ],
        ),
        (
            "a wrong TOTP code",
            vec![
                ("_csrf", CSRF),
                ("ttl_minutes", "15"),
                ("password", PASSWORD),
                ("totp_code", "000000"),
            ],
        ),
        (
            "a missing CSRF token",
            vec![
                ("ttl_minutes", "15"),
                ("password", PASSWORD),
                ("totp_code", &code),
            ],
        ),
    ];
    for (why, fields) in &cases {
        let page = post_form(&rig, Some(op.cookie()), fields).await;
        assert_eq!(page.status, StatusCode::FORBIDDEN, "{why}: {}", page.body);
        assert!(!carries_a_jwt(&page.body), "{why}: no token may be shown");
    }

    for ttl in ["0", "61", "abc"] {
        let page = post_form(
            &rig,
            Some(op.cookie()),
            &[
                ("_csrf", CSRF),
                ("ttl_minutes", ttl),
                ("password", PASSWORD),
            ],
        )
        .await;
        assert_eq!(page.status, StatusCode::BAD_REQUEST, "ttl {ttl}");
        assert!(!carries_a_jwt(&page.body));
    }

    // An operator with only a password has no second factor to prove.
    let bare = create_system_user(&rig, "bare-ops@hearth.example", true);
    let bare_session = rig
        .identity
        .create_session(&system_realm(), &bare, &SessionContext::default())
        .expect("bare session");
    let page = post_form(
        &rig,
        Some(cookie(&system_realm(), bare_session.id())),
        &[
            ("_csrf", CSRF),
            ("ttl_minutes", "15"),
            ("password", PASSWORD),
        ],
    )
    .await;
    assert_eq!(page.status, StatusCode::FORBIDDEN);
    assert!(
        page.body.contains("second factor"),
        "the refusal must say a second factor is needed: {}",
        page.body
    );

    assert!(
        issued_events(&rig).is_empty(),
        "a refusal records no issuance"
    );
}

// ─── the token ───────────────────────────────────────────────────────────────

/// A stepped-up operator gets a token, shown once with `no-store`, that the
/// realm and cluster admin API accept for the system realm; its issuance is
/// audited with actor, TTL and jti — never the token.
#[tokio::test(flavor = "multi_thread")]
async fn a_stepped_up_operator_gets_a_system_admin_token() {
    let rig = build_rig();
    let op = totp_operator(&rig, "ops@hearth.example");

    let page = mint_with_totp(&rig, &op, "5").await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert_eq!(page.cache_control.as_deref(), Some("no-store"));
    assert!(page.location.is_none(), "the token page is not a redirect");
    let token = shown_token(&page).expect("the page shows the token");

    assert_eq!(
        api_status(&rig, "/admin/realms", &token).await,
        StatusCode::OK,
        "the realm admin API accepts the token"
    );
    // Single node: past authentication the cluster endpoint answers 503.
    assert_eq!(
        api_status(&rig, "/admin/cluster/status", &token).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "the cluster admin API authorises the token"
    );

    let claims = rig
        .identity
        .validate_token(&system_realm(), &token)
        .expect("validates in the system realm");
    assert!(claims.permissions.iter().any(|p| p == "hearth.admin"));
    // `POST /admin/backup` needs this too (upgrading guide, step 1).
    assert!(claims.permissions.iter().any(|p| p == "hearth.export"));
    assert_eq!(claims.exp - claims.iat, 300, "the chosen lifetime");
    assert_ne!(
        claims.sid,
        op.session.to_string(),
        "the token is bound to its own session, not the console's"
    );

    let events = issued_events(&rig);
    assert_eq!(events.len(), 1, "{events:?}");
    let event = &events[0];
    assert_eq!(event.actor, op.id.as_uuid().to_string(), "actor = operator");
    let meta = event.metadata.as_ref().expect("metadata");
    assert_eq!(
        meta.get("ttl_secs").and_then(serde_json::Value::as_u64),
        Some(300)
    );
    assert_eq!(
        meta.get("jti").and_then(serde_json::Value::as_str),
        claims.jti.as_deref(),
        "the audit record names the token's jti"
    );
    let record = serde_json::to_string(event).expect("serialise");
    assert!(
        !record.contains(&token),
        "the audit record never holds the token"
    );
}

/// The token stops working when its lifetime ends.
#[tokio::test(flavor = "multi_thread")]
async fn the_token_expires_with_its_lifetime() {
    let rig = build_rig();
    let op = totp_operator(&rig, "ops@hearth.example");
    let token = shown_token(&mint_with_totp(&rig, &op, "2").await).expect("token");
    assert_eq!(
        api_status(&rig, "/admin/realms", &token).await,
        StatusCode::OK
    );

    rig.clock.advance(119 * 1_000_000);
    assert_eq!(
        api_status(&rig, "/admin/realms", &token).await,
        StatusCode::OK,
        "still inside its two minutes"
    );
    rig.clock.advance(2 * 1_000_000);
    assert_eq!(
        api_status(&rig, "/admin/realms", &token).await,
        StatusCode::UNAUTHORIZED,
        "past its lifetime"
    );
}

/// Revoking the token's session kills the token; the console session stays.
#[tokio::test(flavor = "multi_thread")]
async fn revoking_the_tokens_session_kills_it() {
    let rig = build_rig();
    let op = totp_operator(&rig, "ops@hearth.example");
    let token = shown_token(&mint_with_totp(&rig, &op, "15").await).expect("token");
    assert_eq!(
        api_status(&rig, "/admin/realms", &token).await,
        StatusCode::OK
    );

    let sessions = rig
        .identity
        .list_sessions_by_user(
            &system_realm(),
            &op.id,
            &hearth::core::PageRequest::new(0, 50),
        )
        .expect("list sessions")
        .items;
    let token_session = sessions
        .iter()
        .find(|s| s.id() != &op.session)
        .expect("the token's own session")
        .id()
        .clone();
    rig.identity
        .revoke_session(&system_realm(), &token_session)
        .expect("revoke");

    assert_eq!(
        api_status(&rig, "/admin/realms", &token).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        get_page(&rig, Some(op.cookie())).await.status,
        StatusCode::OK,
        "the console session is a different session"
    );
}

/// A passkey assertion counts as the second factor only when it proved user
/// verification (UV): a touch alone is possession, one factor.
#[tokio::test(flavor = "multi_thread")]
async fn a_passkey_counts_only_with_user_verification() {
    let rig = build_rig();
    let op = passkey_operator(&rig);
    let authenticator = op.passkey.as_ref().expect("passkey");

    for (verified, expected) in [(false, StatusCode::FORBIDDEN), (true, StatusCode::OK)] {
        let challenge = rig
            .identity
            .start_webauthn_authentication(
                &system_realm(),
                Some(&op.id),
                &AuthenticationOptions {
                    rp_id: RP_ID.to_string(),
                },
            )
            .expect("challenge");
        let sign_count = if verified { 2 } else { 1 };
        let (cdj, auth_data, sig, _) = if verified {
            authenticator
                .build_verified_authentication_response(&challenge, ORIGIN, sign_count, None)
        } else {
            authenticator.build_authentication_response(&challenge, ORIGIN, sign_count, None)
        };
        let page = post_form(
            &rig,
            Some(op.cookie()),
            &[
                ("_csrf", CSRF),
                ("ttl_minutes", "15"),
                ("password", PASSWORD),
                (
                    "assertion_credential_id",
                    &b64(&authenticator.credential_id),
                ),
                ("assertion_client_data_json", &b64(&cdj)),
                ("assertion_authenticator_data", &b64(&auth_data)),
                ("assertion_signature", &b64(&sig)),
            ],
        )
        .await;
        assert_eq!(page.status, expected, "UV={verified}: {}", page.body);
        assert_eq!(shown_token(&page).is_some(), verified, "UV={verified}");
    }
    assert_eq!(issued_events(&rig).len(), 1, "only the UV assertion minted");
}

// ─── attempt limits (GA audit 3 DOC-2, round 3) ─────────────────────────────

/// The login lockout window of the default `IdentityConfig` (5 failures,
/// 5 minutes) — also the TOTP guess-budget window.
const LOCKOUT_MICROS: i64 = 5 * 60 * 1_000_000;

/// A six-digit code that is none of the codes the account's TOTP secret
/// accepts around `unix_secs` (the validator allows one step of drift).
fn wrong_totp_code(secret_base32: &str, unix_secs: u64) -> String {
    let accepted: Vec<String> = [unix_secs - 30, unix_secs, unix_secs + 30]
        .iter()
        .map(|t| totp_code(secret_base32, *t))
        .collect();
    (0u32..4)
        .map(|n| format!("{n:06}"))
        .find(|c| !accepted.contains(c))
        .expect("a code outside three accepted ones")
}

/// Wrong step-up passwords spend the account's login lockout budget: after
/// five, the right password and a right code are refused (429, no token) —
/// and so is the account's login password check — until the window passes.
#[tokio::test(flavor = "multi_thread")]
async fn wrong_step_up_passwords_lock_the_account_until_the_window_passes() {
    let rig = build_rig();
    let op = totp_operator(&rig, "ops@hearth.example");
    let sys = system_realm();
    let secret = op.totp_secret.clone().expect("totp");

    for attempt in 0..5 {
        let code = totp_code(&secret, rig.now_secs());
        let wrong = format!("wrong-password-number-{attempt}");
        let page = post_form(
            &rig,
            Some(op.cookie()),
            &[
                ("_csrf", CSRF),
                ("ttl_minutes", "15"),
                ("password", &wrong),
                ("totp_code", &code),
            ],
        )
        .await;
        assert_eq!(page.status, StatusCode::FORBIDDEN, "attempt {attempt}");
    }

    let page = mint_with_totp(&rig, &op, "15").await;
    assert_eq!(
        page.status,
        StatusCode::TOO_MANY_REQUESTS,
        "a locked account is refused even with the right password: {}",
        page.body
    );
    assert!(
        page.body.contains("Too many failed attempts"),
        "the page says why: {}",
        page.body
    );
    // The clock stands still: the whole lockout window is still to run.
    assert_eq!(
        page.retry_after.as_deref(),
        Some((LOCKOUT_MICROS / 1_000_000).to_string().as_str()),
        "the 429 says how long the lockout still runs"
    );
    assert!(!carries_a_jwt(&page.body));
    assert!(issued_events(&rig).is_empty());

    // It is the login lockout, not a second counter: login's password check
    // is refused too, and so is the enrolment step-up.
    assert!(matches!(
        rig.identity.verify_password(
            &sys,
            &op.id,
            &CleartextPassword::from_string(PASSWORD.to_string())
        ),
        Err(IdentityError::RateLimited)
    ));
    assert!(matches!(
        verify_step_up(
            &rig.identity,
            &sys,
            &op.id,
            StepUpProof::Password(CleartextPassword::from_string(PASSWORD.to_string())),
        )
        .await,
        Err(StepUpError::Locked { .. })
    ));

    rig.clock.advance(LOCKOUT_MICROS + 1_000_000);
    let page = mint_with_totp(&rig, &op, "15").await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(shown_token(&page).is_some(), "the window has passed");
}

/// Wrong step-up TOTP codes spend the account's TOTP guess budget, the one
/// login's second-factor check draws from: after five, a right code is
/// refused on both surfaces until the window passes.
#[tokio::test(flavor = "multi_thread")]
async fn wrong_step_up_totp_codes_spend_the_totp_guess_budget() {
    let rig = build_rig();
    let op = totp_operator(&rig, "ops@hearth.example");
    let sys = system_realm();
    let secret = op.totp_secret.clone().expect("totp");

    for attempt in 0..5 {
        let wrong = wrong_totp_code(&secret, rig.now_secs());
        let page = post_form(
            &rig,
            Some(op.cookie()),
            &[
                ("_csrf", CSRF),
                ("ttl_minutes", "15"),
                ("password", PASSWORD),
                ("totp_code", &wrong),
            ],
        )
        .await;
        assert_eq!(page.status, StatusCode::FORBIDDEN, "attempt {attempt}");
    }

    let page = mint_with_totp(&rig, &op, "15").await;
    assert_eq!(
        page.status,
        StatusCode::TOO_MANY_REQUESTS,
        "a spent TOTP budget refuses the right code: {}",
        page.body
    );
    let retry_after: i64 = page
        .retry_after
        .as_deref()
        .expect("the 429 carries Retry-After")
        .parse()
        .expect("delta-seconds");
    assert!(
        (1..=LOCKOUT_MICROS / 1_000_000).contains(&retry_after),
        "Retry-After {retry_after}s falls inside the TOTP lockout window"
    );
    assert!(!carries_a_jwt(&page.body));
    assert!(matches!(
        rig.identity
            .verify_totp(&sys, &op.id, &totp_code(&secret, rig.now_secs())),
        Err(IdentityError::RateLimited)
    ));
    assert!(issued_events(&rig).is_empty());

    rig.clock.advance(LOCKOUT_MICROS + 1_000_000);
    let page = mint_with_totp(&rig, &op, "15").await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(shown_token(&page).is_some(), "the window has passed");
}

/// A system-realm step-up draws from the admin-reserved KDF gate, as the
/// admin console login does: a tenant-login flood that fills the shared gate
/// must not shed the operator's step-up.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_operator_step_up_runs_on_the_admin_kdf_gate() {
    // First call wins the process-global OnceLock; nextest runs this test in
    // its own process, so the one-permit bound is deterministic.
    let installed = hearth::identity::init_gate(KdfGateConfig {
        max_in_flight: 1,
        max_queue_wait: std::time::Duration::from_millis(40),
        retry_after: std::time::Duration::from_secs(2),
    });
    assert!(installed, "no earlier gate() call in this process");
    let rig = build_rig();
    let op = totp_operator(&rig, "ops@hearth.example");

    // Hold the shared gate's only permit; the signal fires from inside the
    // gated closure, so once it arrives the gate is provably full.
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let holder = tokio::spawn(async move {
        let _ = hearth::identity::gate()
            .run(move || {
                let _ = tx.send(());
                std::thread::sleep(std::time::Duration::from_millis(1500)); // AUDIT: justified-sleep: holds the shared gate's only KDF permit while the step-up runs
            })
            .await;
    });
    rx.await.expect("holder acquired the only permit");

    let page = mint_with_totp(&rig, &op, "15").await;
    assert_eq!(
        page.status,
        StatusCode::OK,
        "the operator step-up must not queue behind tenant logins: {}",
        page.body
    );
    assert!(shown_token(&page).is_some());
    holder.await.expect("holder");
}
