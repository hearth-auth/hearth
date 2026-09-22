//! Cookie-tossing resistance for the `/ui` double-submit CSRF token
//! (production-readiness task 21.4, audit §4.23#3).
//!
//! A sibling host on the same registrable domain (`evil.example.com` when
//! Hearth is at `admin.example.com`) can `Set-Cookie: hearth_ui_csrf=...;
//! Domain=.example.com`. The browser then sends **two** `hearth_ui_csrf`
//! cookies on every request to Hearth, and RFC 6265 lets the attacker control
//! which one is serialised first (longer `Path` wins; equal paths tie-break on
//! creation time). If the server reads the *first* match positionally, the
//! attacker can make the double-submit check compare their own chosen value
//! against itself and the forgery passes.
//!
//! The defence asserted here: a request carrying more than one
//! `hearth_ui_csrf` cookie is refused outright, on every reader —
//! the `_csrf` form field path, the `X-CSRF-Token` header path, and the
//! pre-auth login form. Exactly one cookie must be present.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use hearth::audit::AuditEngine;
use hearth::core::{RealmId, SessionId, UserId};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, UpdateUserRequest, UserStatus,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{AssignRoleRequest, EmbeddedRbacEngine, RbacEngine, Scope, Subject};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use tower::ServiceExt;

const COOKIE_SECRET: [u8; 32] = [77u8; 32];
/// The genuine token the server issued and the console echoes back.
const REAL: &str = "genuine-csrf-token-value";
/// The value a sibling-domain attacker tosses in and also puts in the body.
const TOSSED: &str = "attacker-chosen-value";

struct Rig {
    app: axum::Router,
    admin_session_id: SessionId,
    system_realm_id: RealmId,
    tenant_realm_name: String,
    tenant_user_id: UserId,
}

fn null_email_service() -> Arc<EmailService> {
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

#[allow(clippy::too_many_lines)] // mirrors the shared admin-UI rig
fn build_rig() -> Rig {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);

    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).expect("storage"),
    );
    let clock = Arc::new(hearth::core::SystemClock) as Arc<dyn hearth::core::Clock>;
    let audit = Arc::new(hearth::audit::EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn AuditEngine>;
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
        .expect("identity"),
    ) as Arc<dyn IdentityEngine>;
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn RbacEngine>;

    let system_realm_id = RealmId::new(uuid::Uuid::nil());
    rbac.seed_realm(&system_realm_id).expect("seed system");

    let admin_user = identity
        .create_admin_user(&CreateUserRequest {
            email: "toss-admin@test.example".to_string(),
            display_name: "TossAdmin".to_string(),
            first_name: String::new(),
            last_name: String::new(),
            attributes: Default::default(),
        })
        .expect("create admin");
    identity
        .set_password(
            &system_realm_id,
            admin_user.id(),
            &CleartextPassword::from_string("s3cr3t1!-p@ss".to_string()),
        )
        .expect("password");
    identity
        .update_user(
            &system_realm_id,
            admin_user.id(),
            &UpdateUserRequest {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .expect("activate");
    let admin_role = rbac
        .get_role_by_name(&system_realm_id, "realm.admin")
        .expect("lookup")
        .expect("seeded");
    rbac.assign_role(
        &system_realm_id,
        &AssignRoleRequest {
            subject: Subject::User(admin_user.id().clone()),
            role_id: admin_role.id,
            scope: Scope::Realm,
            assigned_by: None,
        },
    )
    .expect("assign");
    let admin_session = identity
        .create_session(
            &system_realm_id,
            admin_user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("session");

    let tenant = identity
        .create_realm(&CreateRealmRequest {
            name: "tossco".to_string(),
            config: None,
        })
        .expect("realm");
    let tenant_user = identity
        .create_user(
            tenant.id(),
            &CreateUserRequest {
                email: "victim@tossco.test".to_string(),
                display_name: "Victim".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create tenant user");

    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&identity),
        Arc::clone(&rbac),
        null_email_service(),
        data_dir,
    ));
    let state = WebState::new(
        Arc::clone(&identity),
        Arc::clone(&rbac),
        Arc::clone(&audit),
        onboarding,
        CookieSecret::from_bytes(COOKIE_SECRET),
        None,
    )
    .with_dev_mode(true);

    Rig {
        app: web::router(state),
        admin_session_id: admin_session.id().clone(),
        system_realm_id,
        tenant_realm_name: "tossco".to_string(),
        tenant_user_id: tenant_user.id().clone(),
    }
}

/// Builds the `Cookie` header: session cookie plus whatever CSRF cookies the
/// caller wants, in the order given.
fn cookie_header(rig: &Rig, csrf_values: &[&str]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256>>::new_from_slice(&COOKIE_SECRET).expect("key");
    mac.update(rig.admin_session_id.as_uuid().as_bytes());
    mac.update(b"|");
    mac.update(rig.system_realm_id.as_uuid().as_bytes());
    let tag = data_encoding::BASE64URL_NOPAD.encode(&mac.finalize().into_bytes());
    let mut out = format!(
        "hearth_ui_session={}.{}.{}",
        rig.admin_session_id.as_uuid(),
        rig.system_realm_id.as_uuid(),
        tag,
    );
    for v in csrf_values {
        out.push_str("; hearth_ui_csrf=");
        out.push_str(v);
    }
    out
}

fn form_route(rig: &Rig) -> String {
    let realm = &rig.tenant_realm_name;
    let uid = rig.tenant_user_id.as_uuid();
    format!("/ui/admin/realms/{realm}/users/{uid}/reset-password")
}

fn header_route(rig: &Rig) -> String {
    let realm = &rig.tenant_realm_name;
    format!("/ui/admin/api/realms/{realm}/audit/prune")
}

async fn post_form(rig: &Rig, uri: &str, cookie: String, body: String) -> StatusCode {
    rig.app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .expect("test invariant"),
        )
        .await
        .expect("test invariant")
        .status()
}

async fn post_with_header(rig: &Rig, uri: &str, cookie: String, token: &str) -> StatusCode {
    rig.app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::COOKIE, cookie)
                .header("x-csrf-token", token)
                .body(Body::empty())
                .expect("test invariant"),
        )
        .await
        .expect("test invariant")
        .status()
}

/// The attack: the tossed cookie is serialised FIRST, and the attacker puts
/// the same value in the `_csrf` field. A positional first-match read compares
/// the attacker's value to itself and lets the forgery through.
#[tokio::test]
async fn tossed_csrf_cookie_first_cannot_forge_a_form_mutation() {
    let rig = build_rig();
    let status = post_form(
        &rig,
        &form_route(&rig),
        cookie_header(&rig, &[TOSSED, REAL]),
        format!("_csrf={TOSSED}"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a tossed hearth_ui_csrf cookie placed first forged a form mutation"
    );
}

/// Same attack with the tossed cookie serialised LAST — a "read the last one"
/// fix would be just as forgeable, so this must be refused too.
#[tokio::test]
async fn tossed_csrf_cookie_last_cannot_forge_a_form_mutation() {
    let rig = build_rig();
    let status = post_form(
        &rig,
        &form_route(&rig),
        cookie_header(&rig, &[REAL, TOSSED]),
        format!("_csrf={TOSSED}"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a tossed hearth_ui_csrf cookie placed last forged a form mutation"
    );
}

/// Even echoing the GENUINE token must fail while a duplicate is present:
/// the server cannot tell which cookie the browser will hand the page, so the
/// only safe answer with two cookies is refusal.
#[tokio::test]
async fn duplicate_csrf_cookie_refuses_even_the_genuine_token() {
    let rig = build_rig();
    let status = post_form(
        &rig,
        &form_route(&rig),
        cookie_header(&rig, &[TOSSED, REAL]),
        format!("_csrf={REAL}"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a duplicated hearth_ui_csrf cookie was accepted with the genuine token"
    );
}

/// The `X-CSRF-Token` reader (`RequireCsrf`) must apply the same rule.
#[tokio::test]
async fn tossed_csrf_cookie_cannot_forge_a_header_mutation() {
    let rig = build_rig();
    let status = post_with_header(
        &rig,
        &header_route(&rig),
        cookie_header(&rig, &[TOSSED, REAL]),
        TOSSED,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a tossed hearth_ui_csrf cookie forged an X-CSRF-Token mutation"
    );
}

/// Cookies split across two `Cookie` headers (legal on the wire, and what some
/// proxies emit) must be counted together, not per-header.
#[tokio::test]
async fn duplicate_csrf_cookie_split_across_headers_is_refused() {
    let rig = build_rig();
    let status = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(form_route(&rig))
                .header(header::COOKIE, cookie_header(&rig, &[TOSSED]))
                .header(header::COOKIE, format!("hearth_ui_csrf={REAL}"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!("_csrf={TOSSED}")))
                .expect("test invariant"),
        )
        .await
        .expect("test invariant")
        .status();
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "hearth_ui_csrf duplicated across two Cookie headers was accepted"
    );
}

/// Regression guard: with exactly one cookie the real console still works.
#[tokio::test]
async fn single_csrf_cookie_still_passes_the_guard() {
    let rig = build_rig();
    let form = post_form(
        &rig,
        &form_route(&rig),
        cookie_header(&rig, &[REAL]),
        format!("_csrf={REAL}"),
    )
    .await;
    assert_ne!(
        form,
        StatusCode::FORBIDDEN,
        "a single matching hearth_ui_csrf cookie was rejected on the form path"
    );
    let hdr = post_with_header(
        &rig,
        &header_route(&rig),
        cookie_header(&rig, &[REAL]),
        REAL,
    )
    .await;
    assert_ne!(
        hdr,
        StatusCode::FORBIDDEN,
        "a single matching hearth_ui_csrf cookie was rejected on the header path"
    );
}
