//! CSRF coverage for the `/ui/admin` mutations that previously accepted the
//! session cookie alone (production-readiness task 11.1, audit §4.23#1a).
//!
//! Each route below is reachable by a top-level form POST from a
//! same-registrable-domain sibling host: the browser attaches
//! `hearth_ui_session` and `hearth_ui_csrf` automatically, and the attacker
//! cannot read the CSRF cookie but can force the request. Every one of them
//! MUST therefore verify a `_csrf` form field (or an `X-CSRF-Token` header
//! for the bodyless API routes) against the session's CSRF cookie.
//!
//! Routes covered:
//! - `POST /ui/admin/realms/{realm}/users/{id}/reset-password`
//! - `POST /ui/admin/realms/{realm}/users/{id}/disable-mfa`
//! - `POST /ui/admin/realms/{realm}/users/{id}/reset-mfa-codes`
//! - `POST /ui/admin/realms/{realm}/users/{id}/sessions/{sid}/revoke`
//! - `POST /ui/admin/realms/{realm}/users/{id}/webauthn/{cred}/revoke`
//! - `POST /ui/admin/realms/{realm}/audit/verify`
//! - `POST /ui/admin/api/realms/{realm}/audit/prune`
//! - `POST /ui/admin/api/config/reload`
//! - `POST /ui/admin/settings/editor/preview`

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

const COOKIE_SECRET: [u8; 32] = [23u8; 32];
const CSRF: &str = "csrf-admin-mutation-token";

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
            email: "csrf-admin@test.example".to_string(),
            display_name: "CsrfAdmin".to_string(),
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
            name: "csrfco".to_string(),
            config: None,
        })
        .expect("realm");
    let tenant_user = identity
        .create_user(
            tenant.id(),
            &CreateUserRequest {
                email: "victim@csrfco.test".to_string(),
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
        tenant_realm_name: "csrfco".to_string(),
        tenant_user_id: tenant_user.id().clone(),
    }
}

fn admin_cookie(rig: &Rig) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256>>::new_from_slice(&COOKIE_SECRET).expect("key");
    mac.update(rig.admin_session_id.as_uuid().as_bytes());
    mac.update(b"|");
    mac.update(rig.system_realm_id.as_uuid().as_bytes());
    let tag = data_encoding::BASE64URL_NOPAD.encode(&mac.finalize().into_bytes());
    format!(
        "hearth_ui_session={}.{}.{}; hearth_ui_csrf={CSRF}",
        rig.admin_session_id.as_uuid(),
        rig.system_realm_id.as_uuid(),
        tag,
    )
}

/// Every mutation reachable by a cross-site top-level form POST, with the
/// form body an attacker could supply (no readable CSRF token).
fn form_routes(rig: &Rig) -> Vec<String> {
    let realm = &rig.tenant_realm_name;
    let uid = rig.tenant_user_id.as_uuid();
    vec![
        format!("/ui/admin/realms/{realm}/users/{uid}/reset-password"),
        format!("/ui/admin/realms/{realm}/users/{uid}/disable-mfa"),
        format!("/ui/admin/realms/{realm}/users/{uid}/reset-mfa-codes"),
        format!("/ui/admin/realms/{realm}/users/{uid}/sessions/{uid}/revoke"),
        format!("/ui/admin/realms/{realm}/users/{uid}/webauthn/AAAA/revoke"),
        format!("/ui/admin/realms/{realm}/audit/verify"),
        "/ui/admin/settings/editor/preview".to_string(),
    ]
}

/// Bodyless API mutations on the `/ui` router. A cross-site form POST cannot
/// set `X-CSRF-Token`, so these MUST require that header.
fn header_routes(rig: &Rig) -> Vec<String> {
    let realm = &rig.tenant_realm_name;
    vec![
        format!("/ui/admin/api/realms/{realm}/audit/prune"),
        "/ui/admin/api/config/reload".to_string(),
    ]
}

async fn post_form(rig: &Rig, uri: &str, body: &'static str) -> StatusCode {
    rig.app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::COOKIE, admin_cookie(rig))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .expect("test invariant"),
        )
        .await
        .expect("test invariant")
        .status()
}

async fn post_with_csrf_header(rig: &Rig, uri: &str, token: Option<&str>) -> StatusCode {
    let mut req = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::COOKIE, admin_cookie(rig));
    if let Some(t) = token {
        req = req.header("x-csrf-token", t);
    }
    rig.app
        .clone()
        .oneshot(req.body(Body::empty()).expect("test invariant"))
        .await
        .expect("test invariant")
        .status()
}

/// A cross-site form POST carrying the session and CSRF cookies but no
/// `_csrf` field is refused with 403 on every admin mutation.
#[tokio::test]
async fn form_mutations_without_csrf_field_are_forbidden() {
    let rig = build_rig();
    for uri in form_routes(&rig) {
        let status = post_form(&rig, &uri, "").await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{uri} accepted a form POST with no _csrf field"
        );
    }
}

/// A guessed `_csrf` value is refused too — the token is unguessable, so a
/// wrong one must not pass.
#[tokio::test]
async fn form_mutations_with_wrong_csrf_field_are_forbidden() {
    let rig = build_rig();
    for uri in form_routes(&rig) {
        let status = post_form(&rig, &uri, "_csrf=attacker-guess").await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{uri} accepted a form POST with a wrong _csrf field"
        );
    }
}

/// The same-origin admin console supplies the matching `_csrf` field, so the
/// guard must not break the real UI: the request gets past the CSRF check.
#[tokio::test]
async fn form_mutations_with_matching_csrf_field_pass_the_guard() {
    let rig = build_rig();
    for uri in form_routes(&rig) {
        let body: &'static str = Box::leak(format!("_csrf={CSRF}&yaml=").into_boxed_str());
        let status = post_form(&rig, &uri, body).await;
        assert_ne!(
            status,
            StatusCode::FORBIDDEN,
            "{uri} rejected a form POST carrying the matching _csrf field"
        );
    }
}

/// The bodyless API mutations refuse a request with no `X-CSRF-Token` header,
/// which is exactly the shape a cross-site form POST can produce.
#[tokio::test]
async fn api_mutations_without_csrf_header_are_forbidden() {
    let rig = build_rig();
    for uri in header_routes(&rig) {
        let status = post_with_csrf_header(&rig, &uri, None).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{uri} accepted a POST with no X-CSRF-Token header"
        );
    }
}

/// A wrong `X-CSRF-Token` header is refused.
#[tokio::test]
async fn api_mutations_with_wrong_csrf_header_are_forbidden() {
    let rig = build_rig();
    for uri in header_routes(&rig) {
        let status = post_with_csrf_header(&rig, &uri, Some("attacker-guess")).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{uri} accepted a POST with a wrong X-CSRF-Token header"
        );
    }
}

/// The console's own fetch calls send the matching header and still work.
#[tokio::test]
async fn api_mutations_with_matching_csrf_header_pass_the_guard() {
    let rig = build_rig();
    for uri in header_routes(&rig) {
        let status = post_with_csrf_header(&rig, &uri, Some(CSRF)).await;
        assert_ne!(
            status,
            StatusCode::FORBIDDEN,
            "{uri} rejected a POST carrying the matching X-CSRF-Token header"
        );
    }
}
