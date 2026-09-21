#![allow(clippy::unwrap_used)]
//! HTTP-level integration tests for the IdP admin read-only handlers (list + detail).

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use hearth::core::{Clock, IdpId, RealmId, SessionId, SystemClock, Timestamp};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::federation::{FederationSecret, IdpConfig, IdpKind};
use hearth::identity::hibp::{HibpError, HibpTransport};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, RealmConfig, SessionContext,
    UpdateUserRequest, UserStatus,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{
    AssignRoleRequest, EmbeddedRbacEngine, RbacEngine, Scope as RbacScope, Subject,
};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use tower::ServiceExt;

const COOKIE_SECRET: [u8; 32] = [11u8; 32];

/// No-op HIBP transport for integration tests.
///
/// Integration tests compile `hearth` without `#[cfg(test)]`, so the library
/// uses the real `ureq` HTTP transport by default. This stub prevents real
/// network calls to the HIBP API from within the test process.
struct NoOpHibpTransport;
impl HibpTransport for NoOpHibpTransport {
    fn get_range(&self, _prefix: &str, _api_key: Option<&str>) -> Result<String, HibpError> {
        Ok(String::new())
    }
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

struct Rig {
    app: axum::Router,
    realm_name: String,
    idp_id: IdpId,
    admin_session_id: SessionId,
    admin_realm_id: RealmId,
}

#[allow(clippy::too_many_lines)]
fn build_rig() -> Rig {
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
        .expect("identity engine")
        .with_hibp_transport(Arc::new(NoOpHibpTransport)),
    ) as Arc<dyn IdentityEngine>;
    let authz = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn RbacEngine>;

    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: "demo".to_string(),
            config: Some(RealmConfig::default()),
        })
        .expect("create realm");

    // Pre-register a connector (simulates what YAML reconciliation would write).
    let idp_id = IdpId::generate();
    identity
        .register_idp(&IdpConfig {
            id: idp_id.clone(),
            realm_id: realm.id().clone(),
            name: "google".to_string(),
            kind: IdpKind::Oidc,
            display_name: "Sign in with Google".to_string(),
            issuer: "https://accounts.google.com".to_string(),
            authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
            token_endpoint: "https://oauth2.googleapis.com/token".to_string(),
            userinfo_endpoint: Some("https://openidconnect.googleapis.com/v1/userinfo".to_string()),
            jwks_uri: Some("https://www.googleapis.com/oauth2/v3/certs".to_string()),
            scopes: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
            client_id: "demo-client-id".to_string(),
            client_secret: FederationSecret::new("demo-secret".to_string()),
            claim_mappings: BTreeMap::new(),
            leeway_seconds: IdpConfig::default_leeway_seconds(),
            want_assertions_signed: false,
            trust_asserted_email: false,
            apple: None,
            created_at: Timestamp::from_micros(0),
            updated_at: Timestamp::from_micros(0),
        })
        .expect("register idp");

    // Create admin user in the system realm.
    let admin_realm_id = RealmId::new(uuid::Uuid::nil());
    let admin_user = identity
        .create_admin_user(&CreateUserRequest {
            email: "admin@test.local".to_string(),
            display_name: "Admin".to_string(),
            first_name: String::new(),
            last_name: String::new(),
            attributes: Default::default(),
        })
        .expect("create admin user");
    identity
        .set_password(
            &admin_realm_id,
            admin_user.id(),
            &CleartextPassword::from_string("password123!!".to_string()),
        )
        .expect("set password");
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
        .create_session(&admin_realm_id, admin_user.id(), &SessionContext::default())
        .expect("create admin session");

    authz.seed_realm(&admin_realm_id).expect("seed rbac");
    let admin_role = authz
        .get_role_by_name(&admin_realm_id, "realm.admin")
        .expect("lookup role")
        .expect("role exists");
    authz
        .assign_role(
            &admin_realm_id,
            &AssignRoleRequest {
                subject: Subject::User(admin_user.id().clone()),
                role_id: admin_role.id.clone(),
                scope: RbacScope::Realm,
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
        CookieSecret::from_bytes(COOKIE_SECRET),
        None,
    )
    .with_dev_mode(true);
    let app = web::router(state);

    Rig {
        app,
        realm_name: "demo".to_string(),
        idp_id,
        admin_session_id: admin_session.id().clone(),
        admin_realm_id,
    }
}

fn admin_cookie(rig: &Rig, csrf: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256>>::new_from_slice(&COOKIE_SECRET).expect("hmac key");
    mac.update(rig.admin_session_id.as_uuid().as_bytes());
    mac.update(b"|");
    mac.update(rig.admin_realm_id.as_uuid().as_bytes());
    let tag = data_encoding::BASE64URL_NOPAD.encode(&mac.finalize().into_bytes());
    format!(
        "hearth_ui_session={}.{}.{}; hearth_ui_csrf={}",
        rig.admin_session_id.as_uuid(),
        rig.admin_realm_id.as_uuid(),
        tag,
        csrf,
    )
}

// ---------------------------------------------------------------------------
// Test 1 — GET detail (existing) → 200 with provider display name
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_detail_existing_returns_200_with_display_name() {
    let rig = build_rig();
    let csrf = "csrf-detail";
    let cookie = admin_cookie(&rig, csrf);

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/ui/admin/realms/{}/identity-providers/{}",
                    rig.realm_name,
                    rig.idp_id.as_uuid()
                ))
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(
        text.contains("Sign in with Google"),
        "expected display name in body"
    );
}

// ---------------------------------------------------------------------------
// Test 2 — GET detail (unknown UUID) → 404
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_detail_unknown_returns_404() {
    let rig = build_rig();
    let csrf = "csrf-404";
    let cookie = admin_cookie(&rig, csrf);

    let unknown = uuid::Uuid::new_v4();

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/ui/admin/realms/{}/identity-providers/{unknown}",
                    rig.realm_name
                ))
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Test 3 — 22.18: the list emits the prefixed `idp_<uuid>` display form
// ---------------------------------------------------------------------------

/// The link the list page renders must resolve at the detail handler.
///
/// Audit 2026-08-28 §4.22#10: `IdpRow::id` was `IdpId::to_string()`, whose
/// `Display` is the prefixed `idp_<uuid>` form, while `admin_idp_detail`
/// parsed a bare `uuid::Uuid`. Every provider name on the list page 404'd.
#[tokio::test]
async fn list_link_target_resolves_at_the_detail_handler() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-list-link");

    // 1. Render the list and pull the href the template actually emitted.
    let list = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/ui/admin/realms/{}/identity-providers",
                    rig.realm_name
                ))
                .header(header::COOKIE, cookie.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list.status(), StatusCode::OK);
    let body = to_bytes(list.into_body(), usize::MAX).await.unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();

    let marker = format!("/ui/admin/realms/{}/identity-providers/", rig.realm_name);
    let href = text
        .split(&marker)
        .nth(1)
        .map(|rest| {
            let end = rest.find('"').unwrap_or(rest.len());
            rest[..end].to_string()
        })
        .expect("list page must link to a provider detail page");
    assert!(!href.is_empty(), "provider link had an empty id segment");

    // 2. Follow it. This is the assertion that was failing: 404, not 200.
    let detail = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("{marker}{href}"))
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        detail.status(),
        StatusCode::OK,
        "the list's own link ({href}) must reach the detail page"
    );
}

/// The detail handler accepts the prefixed display form as well as the bare
/// UUID, so a link built from either spelling resolves (22.18).
#[tokio::test]
async fn detail_accepts_the_prefixed_idp_id_form() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-prefixed");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/ui/admin/realms/{}/identity-providers/idp_{}",
                    rig.realm_name,
                    rig.idp_id.as_uuid()
                ))
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

/// A prefixed id that is not a UUID is still a 404, not a 500 (22.18).
#[tokio::test]
async fn detail_rejects_a_prefixed_non_uuid() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-junk");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/ui/admin/realms/{}/identity-providers/idp_not-a-uuid",
                    rig.realm_name
                ))
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Test 4 — 22.16: the published callback URL must be the one sent upstream
// ---------------------------------------------------------------------------

/// The detail page publishes the absolute, realm-scoped callback URL that
/// `build_service` transmits as `redirect_uri` (audit §4.22#8).
///
/// The old value was `/realms/{realm}/federation/callback` — relative, and
/// missing the `/ui` prefix, so it matched neither a real Hearth route nor the
/// `redirect_uri` the connector actually sent. An operator pasting it into
/// Google's console got `redirect_uri_mismatch` on every login.
#[tokio::test]
async fn detail_publishes_the_callback_url_that_is_sent_upstream() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-callback");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/ui/admin/realms/{}/identity-providers/{}",
                    rig.realm_name,
                    rig.idp_id.as_uuid()
                ))
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();

    let expected = format!(
        "http://localhost/ui/realms/{}/federation/callback",
        rig.realm_name
    );
    assert!(
        text.contains(&expected),
        "detail page must publish the absolute realm-scoped callback URL ({expected})"
    );
    // The old, unroutable relative form must be gone.
    assert!(
        !text.contains(&format!(">/realms/{}/federation/callback<", rig.realm_name)),
        "the relative `/realms/.../federation/callback` form is not a real route"
    );
}
