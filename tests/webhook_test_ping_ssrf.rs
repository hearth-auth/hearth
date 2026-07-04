//! Integration tests for SSRF guard on the `/ui/admin/realms/{realm}/webhooks/test-ping`
//! endpoint (HEA-1673 / HEA-SEC-05).
//!
//! Regression suite: the handler must reject cloud-metadata and private-network
//! URLs with HTTP 422 and must allow properly formed `https://` URLs through.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use hearth::core::{Clock, RealmId, SessionId, SystemClock};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, UpdateUserRequest, UserStatus,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use tower::ServiceExt;

const COOKIE_SECRET_BYTES: [u8; 32] = [17u8; 32];

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

struct TestRig {
    app: axum::Router,
    realm_name: String,
    admin_session_id: SessionId,
}

#[allow(clippy::too_many_lines)]
fn build_rig() -> TestRig {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().to_path_buf();
    std::mem::forget(temp);

    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone())).expect("open storage"),
    );
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let audit = Arc::new(hearth::audit::EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn hearth::audit::AuditEngine>;
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
        .expect("identity engine"),
    ) as Arc<dyn IdentityEngine>;
    let authz = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn RbacEngine>;

    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: "testco".to_string(),
            config: None,
        })
        .expect("create realm");

    let admin_realm_id = RealmId::new(uuid::Uuid::nil());
    let admin_user = identity
        .create_admin_user(&CreateUserRequest {
            email: "admin@testco.example".to_string(),
            display_name: "Admin".to_string(),
            first_name: String::new(),
            last_name: String::new(),
            attributes: Default::default(),
        })
        .expect("create admin user");
    let pw = CleartextPassword::from_string("correct-horse-battery-staple".to_string());
    identity
        .set_password(&admin_realm_id, admin_user.id(), &pw)
        .expect("set admin password");
    identity
        .update_user(
            &admin_realm_id,
            admin_user.id(),
            &UpdateUserRequest {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .expect("activate admin");
    let admin_session = identity
        .create_session(
            &admin_realm_id,
            admin_user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create admin session");

    authz
        .seed_realm(&admin_realm_id)
        .expect("seed system realm");
    authz.seed_realm(realm.id()).expect("seed app realm");
    let admin_role = authz
        .get_role_by_name(&admin_realm_id, "realm.admin")
        .expect("lookup role")
        .expect("seed role present");
    authz
        .assign_role(
            &admin_realm_id,
            &hearth::rbac::AssignRoleRequest {
                subject: hearth::rbac::Subject::User(admin_user.id().clone()),
                role_id: admin_role.id.clone(),
                scope: hearth::rbac::Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign admin role");

    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&identity),
        Arc::clone(&authz),
        null_email_service(),
        data_dir,
    ));
    let state = WebState::new(
        Arc::clone(&identity),
        Arc::clone(&authz),
        audit,
        onboarding,
        CookieSecret::from_bytes(COOKIE_SECRET_BYTES),
        None,
    );
    let app = web::router(state);

    TestRig {
        app,
        realm_name: realm.name().to_string(),
        admin_session_id: admin_session.id().clone(),
    }
}

fn admin_cookie(rig: &TestRig) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let admin_realm = RealmId::new(uuid::Uuid::nil());
    let mut mac = <Hmac<Sha256>>::new_from_slice(&COOKIE_SECRET_BYTES).expect("hmac key");
    mac.update(rig.admin_session_id.as_uuid().as_bytes());
    mac.update(b"|");
    mac.update(admin_realm.as_uuid().as_bytes());
    let tag = data_encoding::BASE64URL_NOPAD.encode(&mac.finalize().into_bytes());
    format!(
        "hearth_ui_session={}.{}.{}",
        rig.admin_session_id.as_uuid(),
        admin_realm.as_uuid(),
        tag,
    )
}

async fn post_test_ping(rig: &TestRig, json_body: &str) -> (StatusCode, serde_json::Value) {
    let cookie = admin_cookie(rig);
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/ui/admin/realms/{}/webhooks/test-ping",
                    rig.realm_name
                ))
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json_body.to_string()))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    let status = response.status();
    let body = to_bytes(response.into_body(), 1 << 20).await.expect("body");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json body");
    (status, json)
}

/// AWS/GCP/Azure instance-metadata IP must be rejected with 422.
#[tokio::test]
async fn test_ping_rejects_cloud_metadata_ip() {
    let rig = build_rig();
    let (status, body) = post_test_ping(
        &rig,
        r#"{"url": "http://169.254.169.254/latest/meta-data/"}"#,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "cloud-metadata URL must be rejected: body={body}"
    );
    assert_eq!(
        body["success"], false,
        "success must be false for SSRF-blocked URL"
    );
}

/// Plain `http://` scheme must be rejected with 422 even for a public hostname.
#[tokio::test]
async fn test_ping_rejects_http_scheme() {
    let rig = build_rig();
    let (status, body) = post_test_ping(&rig, r#"{"url": "http://example.com/webhook"}"#).await;

    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "http:// URL must be rejected: body={body}"
    );
    assert_eq!(
        body["success"], false,
        "success must be false for http:// URL"
    );
}

/// A well-formed `https://` URL with a publicly-routable destination must NOT
/// be rejected by the SSRF guard (HTTP 200). The actual delivery may fail
/// (connection error) but that is a separate concern from the guard.
///
/// Uses an IP literal with a closed port so no DNS is required and the
/// connection fails quickly without hanging the test suite.
#[tokio::test]
async fn test_ping_allows_valid_https_url() {
    let rig = build_rig();
    // 1.1.1.1 is a public Cloudflare IP; port 9999 is almost certainly closed
    // so ureq fails with connection-refused immediately — no long timeout.
    let (status, _body) = post_test_ping(&rig, r#"{"url": "https://1.1.1.1:9999/hook"}"#).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "valid https:// URL must pass the SSRF guard (HTTP 200)"
    );
}
