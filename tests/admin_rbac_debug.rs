//! Integration tests for the RBAC debug / token-preview web-UI endpoints.
//!
//! Covers:
//! - `POST /ui/admin/realms/{realm}/rbac/token-preview` — valid admin + valid UUID
//! - `POST /ui/admin/realms/{realm}/rbac/token-preview` — valid admin + invalid UUID
//! - `POST /ui/admin/realms/{realm}/rbac/token-preview` — unauthenticated → 302

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{RealmId, SessionId};
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, UpdateUserRequest, UserStatus,
};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{AssignRoleRequest, EmbeddedRbacEngine, RbacEngine, Scope, Subject};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use tower::ServiceExt;

const COOKIE_SECRET: [u8; 32] = [42u8; 32];

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

struct Rig {
    app: axum::Router,
    admin_session_id: SessionId,
    system_realm_id: RealmId,
    tenant_realm_name: String,
    tenant_realm_id: RealmId,
    identity: Arc<dyn IdentityEngine>,
}

fn build_rig() -> Rig {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);

    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).expect("storage"),
    );
    let clock = Arc::new(hearth::core::SystemClock) as Arc<dyn hearth::core::Clock>;
    let audit = Arc::new(EmbeddedAuditEngine::new(
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
            email: "dbgadmin@test.example".to_string(),
            display_name: "DbgAdmin".to_string(),
            first_name: String::new(),
            last_name: String::new(),
            attributes: Default::default(),
        })
        .expect("create admin");
    identity
        .set_password(
            &system_realm_id,
            admin_user.id(),
            &CleartextPassword::from_string("s3cr3t".to_string()),
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
            name: "rbac-debug-co".to_string(),
            config: None,
        })
        .expect("realm");
    rbac.seed_realm(tenant.id()).expect("seed tenant");

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
    );
    let app = web::router(state);

    Rig {
        app,
        admin_session_id: admin_session.id().clone(),
        system_realm_id,
        tenant_realm_name: "rbac-debug-co".to_string(),
        tenant_realm_id: tenant.id().clone(),
        identity: Arc::clone(&identity),
    }
}

fn admin_cookie(rig: &Rig, csrf: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256>>::new_from_slice(&COOKIE_SECRET).expect("key");
    mac.update(rig.admin_session_id.as_uuid().as_bytes());
    mac.update(b"|");
    mac.update(rig.system_realm_id.as_uuid().as_bytes());
    let tag = data_encoding::BASE64URL_NOPAD.encode(&mac.finalize().into_bytes());
    format!(
        "hearth_ui_session={}.{}.{}; hearth_ui_csrf={}",
        rig.admin_session_id.as_uuid(),
        rig.system_realm_id.as_uuid(),
        tag,
        csrf,
    )
}

// ---------------------------------------------------------------------------
// Token preview — authenticated
// ---------------------------------------------------------------------------

/// `POST /ui/admin/realms/{realm}/rbac/token-preview` with a valid user UUID
/// returns 200 with JSON containing `sub`, `roles`, `groups`, `permissions`.
#[tokio::test]
async fn token_preview_valid_user_returns_json() {
    let rig = build_rig();
    let csrf = "csrf-tp";
    let cookie = admin_cookie(&rig, csrf);
    let realm = &rig.tenant_realm_name;

    // Create a user in the tenant realm to preview.
    let user = rig
        .identity
        .create_user(
            &rig.tenant_realm_id,
            &CreateUserRequest {
                email: "preview@example.com".to_string(),
                display_name: "Preview".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    let user_uuid = user.id().as_uuid().to_string();

    let body = format!("user_id={user_uuid}&_csrf={csrf}");
    let resp = rig
        .app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/admin/realms/{realm}/rbac/token-preview"))
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("X-CSRF-Token", csrf)
                .body(Body::from(body))
                .expect("test invariant"),
        )
        .await
        .expect("test invariant");

    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ct.contains("application/json"), "should be JSON, got: {ct}");

    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    let obj: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
    assert!(obj.get("sub").is_some(), "response should have 'sub'");
    assert!(obj.get("roles").is_some(), "response should have 'roles'");
    assert!(
        obj.get("permissions").is_some(),
        "response should have 'permissions'"
    );
}

/// `POST /ui/admin/realms/{realm}/rbac/token-preview` with a bad UUID string
/// returns 200 with a JSON error payload (not a 4xx).
#[tokio::test]
async fn token_preview_invalid_uuid_returns_json_error() {
    let rig = build_rig();
    let csrf = "csrf-tp-bad";
    let cookie = admin_cookie(&rig, csrf);
    let realm = &rig.tenant_realm_name;

    let body = format!("user_id=not-a-uuid&_csrf={csrf}");
    let resp = rig
        .app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/admin/realms/{realm}/rbac/token-preview"))
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("X-CSRF-Token", csrf)
                .body(Body::from(body))
                .expect("test invariant"),
        )
        .await
        .expect("test invariant");

    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    let obj: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
    assert!(
        obj.get("error").is_some(),
        "invalid UUID should yield JSON error field"
    );
}

// ---------------------------------------------------------------------------
// Token preview — unauthenticated
// ---------------------------------------------------------------------------

/// Unauthenticated POST to token-preview redirects to login (302 / 303).
#[tokio::test]
async fn token_preview_unauthenticated_redirects() {
    let rig = build_rig();
    let realm = &rig.tenant_realm_name;

    let resp = rig
        .app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/admin/realms/{realm}/rbac/token-preview"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("user_id=00000000-0000-0000-0000-000000000001"))
                .expect("test invariant"),
        )
        .await
        .expect("test invariant");

    let status = resp.status().as_u16();
    assert!(
        (300..400).contains(&status),
        "unauthenticated request should redirect, got {status}"
    );
}
