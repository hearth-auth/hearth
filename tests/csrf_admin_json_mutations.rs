//! CSRF coverage for the eight remaining `/ui/admin` JSON mutations
//! (production-readiness task 21.2, audit §4.23#1b).
//!
//! Task 11.1 closed the form-driven half. These eight are driven by `fetch()`
//! with a JSON body, so they have no `_csrf` form field — they must require a
//! matching `X-CSRF-Token` header, which a cross-site request cannot set.
//! The admin console already sends the header from `<meta name="csrf">`
//! (`admin.js`, `admin/webhooks-new.js`); the server simply never read it.
//!
//! Routes covered:
//! - `PUT    /ui/admin/api/realms/{realm}/audit/config`
//! - `PATCH  /ui/admin/realms/{realm}/config`
//! - `PATCH  /ui/admin/realms/{realm}/users/{id}/required-actions`
//! - `POST   /ui/admin/realms/{realm}/webhooks/test-ping`
//! - `POST   /ui/admin/settings/editor/visual/validate`
//! - `POST   /ui/admin/settings/editor/visual/preview`
//! - `POST   /ui/admin/settings/editor/visual/export`
//! - `POST   /ui/admin/settings/editor/visual/apply`  ← whole-file hearth.yaml rewrite

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

const COOKIE_SECRET: [u8; 32] = [41u8; 32];
const CSRF: &str = "csrf-json-mutation-token";

struct Rig {
    app: axum::Router,
    admin_session_id: SessionId,
    system_realm_id: RealmId,
    tenant_realm_name: String,
    tenant_user_id: UserId,
}

/// One mutation under test: method, path, and a body that deserialises so a
/// pass through the CSRF gate is measured by the handler, not by a 422 from
/// the `Json` extractor.
struct Route {
    method: &'static str,
    uri: String,
    body: &'static str,
    /// `true` when the handler itself legitimately answers 422, so a 422 on the
    /// happy path does not mean the `Json` extractor rejected the body.
    handler_may_422: bool,
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
            email: "json-csrf-admin@test.example".to_string(),
            display_name: "JsonCsrfAdmin".to_string(),
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
            name: "jsoncsrf".to_string(),
            config: None,
        })
        .expect("realm");
    let tenant_user = identity
        .create_user(
            tenant.id(),
            &CreateUserRequest {
                email: "victim@jsoncsrf.test".to_string(),
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
        tenant_realm_name: "jsoncsrf".to_string(),
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

fn json_routes(rig: &Rig) -> Vec<Route> {
    let realm = &rig.tenant_realm_name;
    let uid = rig.tenant_user_id.as_uuid();
    vec![
        Route {
            method: "PUT",
            uri: format!("/ui/admin/api/realms/{realm}/audit/config"),
            body: r#"{"retention_days":30}"#,
            handler_may_422: false,
        },
        Route {
            method: "PATCH",
            uri: format!("/ui/admin/realms/{realm}/config"),
            body: r#"{"default_required_actions":["VERIFY_EMAIL"]}"#,
            handler_may_422: false,
        },
        Route {
            method: "PATCH",
            uri: format!("/ui/admin/realms/{realm}/users/{uid}/required-actions"),
            body: r#"{"add":["VERIFY_EMAIL"],"remove":[]}"#,
            handler_may_422: false,
        },
        Route {
            method: "POST",
            uri: format!("/ui/admin/realms/{realm}/webhooks/test-ping"),
            body: r#"{"url":"https://example.invalid/hook","secret":null}"#,
            // The SSRF guard answers 422 for a host that does not resolve,
            // which is the handler running, not the extractor refusing.
            handler_may_422: true,
        },
        Route {
            method: "POST",
            uri: "/ui/admin/settings/editor/visual/validate".to_string(),
            body: "{}",
            handler_may_422: false,
        },
        Route {
            method: "POST",
            uri: "/ui/admin/settings/editor/visual/preview".to_string(),
            body: "{}",
            handler_may_422: false,
        },
        Route {
            method: "POST",
            uri: "/ui/admin/settings/editor/visual/export".to_string(),
            body: "{}",
            handler_may_422: false,
        },
        Route {
            method: "POST",
            uri: "/ui/admin/settings/editor/visual/apply".to_string(),
            body: "{}",
            handler_may_422: false,
        },
    ]
}

async fn send(rig: &Rig, route: &Route, csrf_header: Option<&str>) -> StatusCode {
    let mut req = Request::builder()
        .method(route.method)
        .uri(&route.uri)
        .header(header::COOKIE, admin_cookie(rig))
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(t) = csrf_header {
        req = req.header("x-csrf-token", t);
    }
    rig.app
        .clone()
        .oneshot(req.body(Body::from(route.body)).expect("test invariant"))
        .await
        .expect("test invariant")
        .status()
}

/// The attack shape: a cross-site request carries the cookies automatically
/// but cannot set `X-CSRF-Token`. Every one of the eight must refuse.
#[tokio::test]
async fn json_mutations_without_csrf_header_are_forbidden() {
    let rig = build_rig();
    for route in json_routes(&rig) {
        let status = send(&rig, &route, None).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{} {} accepted a request with no X-CSRF-Token header",
            route.method,
            route.uri
        );
    }
}

/// A guessed token must not pass — the cookie value is unguessable.
#[tokio::test]
async fn json_mutations_with_wrong_csrf_header_are_forbidden() {
    let rig = build_rig();
    for route in json_routes(&rig) {
        let status = send(&rig, &route, Some("attacker-guess")).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{} {} accepted a wrong X-CSRF-Token header",
            route.method,
            route.uri
        );
    }
}

/// The real console sends the matching header, so the guard must not break it.
#[tokio::test]
async fn json_mutations_with_matching_csrf_header_pass_the_guard() {
    let rig = build_rig();
    for route in json_routes(&rig) {
        let status = send(&rig, &route, Some(CSRF)).await;
        assert_ne!(
            status,
            StatusCode::FORBIDDEN,
            "{} {} rejected the matching X-CSRF-Token header",
            route.method,
            route.uri
        );
        if !route.handler_may_422 {
            assert_ne!(
                status,
                StatusCode::UNPROCESSABLE_ENTITY,
                "{} {} answered 422 — the Json extractor rejected the body, so this \
                 case never reached the handler and proves nothing",
                route.method,
                route.uri
            );
        }
    }
}
