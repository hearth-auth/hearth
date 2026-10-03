//! Integration tests for the `/ui/admin/*` management surface.
//!
//! Drives the axum router via `tower::ServiceExt::oneshot`. Covers:
//!
//! * Non-admin user on `/ui/admin/users` → 403.
//! * Admin user list, create, detail, edit, delete.
//! * CSRF rejection on admin mutations.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use hearth::core::Clock;
use hearth::core::SystemClock;
use hearth::core::{PageRequest, RealmId, SessionId};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::onboarding::OnboardingService;
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdTokenSigningAlg, IdentityConfig, IdentityEngine, OAuthClient,
    RegisterClientRequest, UpdateUserRequest, UserStatus,
};
use hearth::protocol::web::{self, CookieSecret, WebState};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use tower::ServiceExt;

/// Builds a no-op email service for tests that don't exercise email delivery.
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

const COOKIE_SECRET_BYTES: [u8; 32] = [42u8; 32];

struct TestRig {
    app: axum::Router,
    identity: Arc<dyn IdentityEngine>,
    #[allow(dead_code)]
    authz: Arc<dyn RbacEngine>,
    realm_id: RealmId,
    #[allow(dead_code)]
    admin_user_id: hearth::core::UserId,
    admin_session_id: SessionId,
    non_admin_user_id: hearth::core::UserId,
    non_admin_session_id: SessionId,
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
            name: "acme".to_string(),
            config: None,
        })
        .expect("create realm");

    // Admin user lives in the system realm (nil UUID) — this matches
    // the invariant enforced by `RequireAdmin`. Tests that exercise
    // admin routes target the application realm ("acme") via the
    // path-based `TargetRealm` extractor (`/ui/admin/realms/acme/...`).
    let admin_realm_id = hearth::core::RealmId::new(uuid::Uuid::nil());
    let admin_user = identity
        .create_admin_user(&CreateUserRequest {
            email: "admin@acme.test".to_string(),
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
                email: None,
                display_name: None,
                status: Some(UserStatus::Active),
                first_name: None,
                last_name: None,
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

    // Grant admin realm role: seed the system realm's defaults and assign
    // the `realm.admin` role (which carries `hearth.admin`) to our admin user.
    authz
        .seed_realm(&admin_realm_id)
        .expect("seed system realm");
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

    // Non-admin user.
    let non_admin_user = identity
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: "bob@acme.test".to_string(),
                display_name: "Bob".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create non-admin user");
    let pw2 = CleartextPassword::from_string("correct-horse-battery-staple".to_string());
    identity
        .set_password(realm.id(), non_admin_user.id(), &pw2)
        .expect("set non-admin password");
    identity
        .update_user(
            realm.id(),
            non_admin_user.id(),
            &UpdateUserRequest {
                email: None,
                display_name: None,
                status: Some(UserStatus::Active),
                first_name: None,
                last_name: None,
                ..Default::default()
            },
        )
        .expect("activate non-admin");
    let non_admin_session = identity
        .create_session(
            realm.id(),
            non_admin_user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create non-admin session");

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
    )
    .with_dev_mode(true);
    let app = web::router(state);

    TestRig {
        app,
        identity,
        authz,
        realm_id: realm.id().clone(),
        admin_user_id: admin_user.id().clone(),
        admin_session_id: admin_session.id().clone(),
        non_admin_user_id: non_admin_user.id().clone(),
        non_admin_session_id: non_admin_session.id().clone(),
    }
}

fn auth_cookie(session_id: &SessionId, realm_id: &RealmId, csrf: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256>>::new_from_slice(&COOKIE_SECRET_BYTES).expect("hmac key");
    mac.update(session_id.as_uuid().as_bytes());
    mac.update(b"|");
    mac.update(realm_id.as_uuid().as_bytes());
    let tag = data_encoding::BASE64URL_NOPAD.encode(&mac.finalize().into_bytes());
    format!(
        "hearth_ui_session={}.{}.{}; hearth_ui_csrf={}",
        session_id.as_uuid(),
        realm_id.as_uuid(),
        tag,
        csrf,
    )
}

fn admin_cookie(rig: &TestRig, csrf: &str) -> String {
    // Admin sessions are bound to the system realm (nil UUID), not the
    // application realm (`rig.realm_id`).
    let admin_realm = hearth::core::RealmId::new(uuid::Uuid::nil());
    auth_cookie(&rig.admin_session_id, &admin_realm, csrf)
}

fn non_admin_cookie(rig: &TestRig, csrf: &str) -> String {
    auth_cookie(&rig.non_admin_session_id, &rig.realm_id, csrf)
}

// ---------------------------------------------------------------------------
// Authorization tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn non_admin_user_gets_403_on_admin_pages() {
    let rig = build_rig();
    let cookie = non_admin_cookie(&rig, "csrf-nonadmin");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/realms/acme/users")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// A **system-realm** session without `hearth.admin` must still be refused.
///
/// `RequireAdmin` has two independent gates: the session must live in the
/// system realm, and the user must resolve `hearth.admin` against the RBAC
/// engine. `non_admin_user_gets_403_on_admin_pages` above only reaches the
/// first — its cookie names a tenant realm, so the request is rejected before
/// the permission lookup happens.
///
/// The mutation spot-check found that (production-readiness task 24.3,
/// `ci/mutations.toml` entry `admin-console-requires-hearth-admin`): with
/// `if is_admin` short-circuited to always-true, the whole admin console opened
/// to any system-realm session and every existing test still passed. This test
/// is the one that notices. Do not fold it into the test above — a single test
/// that trips the realm gate can never exercise the permission gate behind it.
#[tokio::test]
async fn system_realm_user_without_admin_permission_gets_403() {
    let rig = build_rig();

    // A user in the system realm who was never assigned `realm.admin`.
    let system_realm = hearth::core::RealmId::new(uuid::Uuid::nil());
    let plain_user = rig
        .identity
        .create_admin_user(&CreateUserRequest {
            email: "nobody@hearth.test".to_string(),
            display_name: "Nobody".to_string(),
            first_name: String::new(),
            last_name: String::new(),
            attributes: Default::default(),
        })
        .expect("create system-realm user");
    rig.identity
        .update_user(
            &system_realm,
            plain_user.id(),
            &UpdateUserRequest {
                email: None,
                display_name: None,
                status: Some(UserStatus::Active),
                first_name: None,
                last_name: None,
                ..Default::default()
            },
        )
        .expect("activate system-realm user");
    let session = rig
        .identity
        .create_session(
            &system_realm,
            plain_user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create session");

    let cookie = auth_cookie(session.id(), &system_realm, "csrf-plain");
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/realms/acme/users")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a system-realm session without hearth.admin must be refused by the \
         permission gate, not merely by the realm gate"
    );
}

/// A console session cookie for a fresh system-realm user holding only the
/// seeded `role` (a sub-admin), with CSRF token `csrf`.
fn system_sub_admin_cookie(rig: &TestRig, role: &str, csrf: &str) -> String {
    let system_realm = hearth::core::RealmId::new(uuid::Uuid::nil());
    let sub_admin = rig
        .identity
        .create_admin_user(&CreateUserRequest {
            email: format!("{}@hearth.test", role.replace('.', "-")),
            display_name: role.to_string(),
            first_name: String::new(),
            last_name: String::new(),
            attributes: Default::default(),
        })
        .expect("create system-realm user");
    rig.identity
        .update_user(
            &system_realm,
            sub_admin.id(),
            &UpdateUserRequest {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .expect("activate system-realm user");
    let seeded = rig
        .authz
        .get_role_by_name(&system_realm, role)
        .expect("role lookup")
        .unwrap_or_else(|| panic!("{role} seeded in the system realm"));
    rig.authz
        .assign_role(
            &system_realm,
            &hearth::rbac::AssignRoleRequest {
                subject: hearth::rbac::Subject::User(sub_admin.id().clone()),
                role_id: seeded.id,
                scope: hearth::rbac::Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign the sub-admin role");
    let session = rig
        .identity
        .create_session(
            &system_realm,
            sub_admin.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create session");
    auth_cookie(session.id(), &system_realm, csrf)
}

/// The console's user administration is exempt from the per-surface
/// privilege-ceiling calls (`admin_auth::check_user_admin_ceiling`) only
/// because it admits nobody but `hearth.admin`, who clears the ceiling by
/// construction (GA audit round 3). A system-realm *sub*-admin
/// (`hearth.users.admin`) must therefore be refused before any user mutation;
/// if this gate ever widens to sub-admins, the console must call the ceiling.
#[tokio::test]
async fn system_realm_sub_admin_cannot_use_console_user_admin() {
    let rig = build_rig();
    let csrf = "csrf-sub-admin";
    let cookie = system_sub_admin_cookie(&rig, "hearth.users.admin", csrf);

    let uid = rig.non_admin_user_id.as_uuid();
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/admin/realms/acme/users/{uid}/delete"))
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!("_csrf={csrf}")))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        rig.identity
            .get_user(&rig.realm_id, &rig.non_admin_user_id)
            .expect("get_user")
            .is_some(),
        "a refused sub-admin must not delete the user"
    );
}

/// Deleting an organization, removing a member, and deleting a role demote
/// the users affected, so REST, gRPC and SCIM run the admin privilege ceiling
/// on them (GA sweep 4). The console does not, because it admits nobody but
/// `hearth.admin`: a system-realm `hearth.realm.admin` sub-admin must be
/// refused before any of these mutations.
#[tokio::test]
async fn system_realm_sub_admin_cannot_use_console_org_or_role_admin() {
    let rig = build_rig();
    let csrf = "csrf-realm-sub-admin";
    let cookie = system_sub_admin_cookie(&rig, "hearth.realm.admin", csrf);
    let org = rig
        .identity
        .create_organization(
            &rig.realm_id,
            &hearth::identity::CreateOrganizationRequest {
                name: "Acme Ops".into(),
                slug: "acme-ops".into(),
                description: None,
                config: None,
                attributes: Default::default(),
            },
        )
        .expect("create org");
    rig.identity
        .add_member(
            &rig.realm_id,
            org.id(),
            &rig.non_admin_user_id,
            hearth::identity::OrganizationRole::Member,
        )
        .expect("add member");
    let role = rig
        .authz
        .create_role(
            &rig.realm_id,
            &hearth::rbac::CreateRoleRequest {
                name: "ops".into(),
                description: None,
                permissions: vec![],
                parent_roles: vec![],
                scope_kind: Default::default(),
                allow_reserved_permissions: false,
            },
        )
        .expect("create role");
    let org_uri = format!("/ui/admin/realms/acme/organizations/{}", org.id().as_uuid());
    let uid = rig.non_admin_user_id.as_uuid();

    for uri in [
        format!("{org_uri}/delete"),
        format!("{org_uri}/members/{uid}/remove"),
        format!(
            "/ui/admin/realms/acme/rbac/roles/{}/delete",
            role.id.as_uuid()
        ),
    ] {
        let response = rig
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&uri)
                    .header(header::COOKIE, cookie.clone())
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(format!("_csrf={csrf}")))
                    .expect("build request"),
            )
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{uri}");
    }
    assert!(rig
        .identity
        .get_membership(&rig.realm_id, org.id(), &rig.non_admin_user_id)
        .expect("lookup")
        .is_some());
    assert!(rig
        .authz
        .get_role(&rig.realm_id, &role.id)
        .expect("lookup")
        .is_some());
}

#[tokio::test]
async fn unauthenticated_user_redirects_to_login() {
    let rig = build_rig();

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/realms/acme/users")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    // The redirect must actually point at the login page, not just be "some 303".
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("redirect must carry a Location header");
    assert!(
        location.contains("login"),
        "unauthenticated user must be redirected to login, got: {location}"
    );
}

// ---------------------------------------------------------------------------
// User list
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_user_list_renders() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-list");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/realms/acme/users")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body_bytes).expect("utf-8");
    // The acme tenant realm contains only `bob@acme.test`; the admin
    // lives in the system realm so they don't appear here.
    assert!(body.contains("bob@acme.test"), "should list non-admin user");
    assert!(body.contains("Create user"));
}

// ---------------------------------------------------------------------------
// Create user
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_create_user_form_renders() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-new");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/realms/acme/users/new")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body_bytes).expect("utf-8");
    assert!(body.contains("Create user"));
    assert!(body.contains("name=\"email\""));
    assert!(body.contains("name=\"password\""));
}

#[tokio::test]
async fn admin_create_user_succeeds() {
    let rig = build_rig();
    let csrf = "csrf-create";
    let cookie = admin_cookie(&rig, csrf);

    let form = format!(
        "email=charlie%40acme.test&display_name=Charlie&password=super-secret-password-12&_csrf={csrf}"
    );
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/admin/realms/acme/users/new")
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        location.starts_with("/ui/admin/realms/acme/users/"),
        "expected redirect to user detail, got: {location}"
    );
}

#[tokio::test]
async fn admin_create_user_duplicate_email_shows_error() {
    let rig = build_rig();
    let csrf = "csrf-dup";
    let cookie = admin_cookie(&rig, csrf);

    // `bob@acme.test` is the non-admin test user seeded in the Acme
    // realm by `build_rig`. The admin account lives in the system
    // realm and doesn't collide with Acme users by design.
    let form = format!(
        "email=bob%40acme.test&display_name=Clone&password=super-secret-password-12&_csrf={csrf}"
    );
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/admin/realms/acme/users/new")
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body_bytes).expect("utf-8");
    assert!(
        body.contains("already exists"),
        "expected dup error, got: {body}"
    );
}

#[tokio::test]
async fn admin_create_user_without_csrf_returns_403() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-ok");

    let form = "email=x%40acme.test&display_name=X&password=super-secret-password-12&_csrf=wrong";
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/admin/realms/acme/users/new")
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

// ---------------------------------------------------------------------------
// User detail
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_user_detail_renders() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-detail");

    let uri = format!(
        "/ui/admin/realms/acme/users/{}",
        rig.non_admin_user_id.as_uuid()
    );
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(&uri)
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body_bytes).expect("utf-8");
    assert!(body.contains("Bob"));
    assert!(body.contains("bob@acme.test"));
    assert!(body.contains("Delete user"));
}

/// `/ui/admin/realms/acme/sessions` renders the per-realm view (no
/// Realm column, scoped heading). The previous global / cross-realm view
/// was deleted alongside the path-based routing migration — every
/// realm-scoped page now lives under `/ui/admin/realms/{name}/...`.
#[tokio::test]
async fn admin_sessions_realm_scoped_view_omits_realm_column() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-sessions-acme");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/realms/acme/sessions")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body_bytes).expect("utf-8");
    assert!(
        !body.contains("Realm</th>"),
        "scoped view must not show a Realm column"
    );
    assert!(body.contains("bob@acme.test"));
    // Match by session UUID rather than email — the admin's email also
    // appears in the page chrome (topbar, sign-out menu) so a string
    // search would always find it. Counting "session-<uuid>" row IDs is
    // unambiguous: exactly one tenant session, zero system sessions.
    let admin_session_marker = format!("session-{}", rig.admin_session_id.as_uuid());
    let tenant_session_marker = format!("session-{}", rig.non_admin_session_id.as_uuid());
    assert!(
        body.contains(&tenant_session_marker),
        "scoped view must include the tenant session row"
    );
    assert!(
        !body.contains(&admin_session_marker),
        "scoped view must not leak the system admin's session into the Acme realm"
    );
}

/// `/ui/admin/users` renders the search input wired with HTMX live-search
/// attributes (hx-get, hx-trigger, hx-target). Resolves REQ-044.
#[tokio::test]
async fn admin_users_list_renders_htmx_live_search_attrs() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-users-htmx");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/realms/acme/users")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body_bytes).expect("utf-8");

    assert!(
        body.contains(r#"hx-get="/ui/admin/realms/acme/users""#),
        "search form must point hx-get at the list URL"
    );
    assert!(
        body.contains(r#"hx-trigger="input changed delay:200ms"#),
        "search form must debounce input by 200ms"
    );
    // HEA-1615: search now swaps the whole table+pagination region as one unit
    // so sort and pagination never go stale.
    assert!(
        body.contains(r##"hx-target="#users-table-region""##),
        "search form must target the unified table region"
    );
    assert!(
        body.contains(r##"hx-select="#users-table-region""##),
        "search form must hx-select the region out of the full-page response"
    );
    assert!(
        body.contains(r#"<div id="users-table-region">"#),
        "the region wrapper must carry the id the search form targets"
    );
    // The active sort survives a new search keystroke via hx-include.
    assert!(
        body.contains(r##"hx-include="#users-table-region [name='sort']"##),
        "search form must re-send the active sort/dir via hx-include"
    );
}

/// `GET /ui/admin/users` with `HX-Request: true` returns a FULL page whose
/// `#users-table-region` the client extracts via `hx-select` (HEA-1615). The
/// old rows-only partial left the pagination bar stale; a full page keeps the
/// table structural elements nested so DOMParser preserves them (HEA-1643),
/// and swapping the whole region keeps rows, headers, and pagination in sync.
#[tokio::test]
async fn admin_users_list_returns_full_region_for_htmx_request() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-users-htmx-partial");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/realms/acme/users")
                .header(header::COOKIE, cookie)
                .header("HX-Request", "true")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body_bytes).expect("utf-8");

    // The region the client selects must be present in the response.
    assert!(
        body.contains(r#"<div id="users-table-region">"#),
        "HTMX response must contain the table region for hx-select to extract"
    );
    // The region includes the pagination bar so it never goes stale.
    assert!(
        body.contains("Rows per page"),
        "region must include the pagination bar (kept in sync with the rows)"
    );
    // Should still contain at least one user row marker (the seeded bob).
    assert!(
        body.contains("bob@acme.test"),
        "response must include the seeded user rows"
    );
}

/// Sort HTMX request returns a full page so the browser HTML parser sees
/// `<thead>` inside a proper `<table>` context. The client uses
/// `hx-select="#users-table-region"` to extract the whole table+pagination
/// region and swap it as one unit (HEA-1615); `aria-sort` updates without a
/// full page reload. Fixes HEA-1643 (bare `<thead>` outside `<table>` is
/// silently stripped by DOMParser).
#[tokio::test]
async fn admin_users_sort_htmx_returns_full_page_with_aria_sort() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-users-sort-htmx");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/realms/acme/users?sort=email&dir=asc")
                .header(header::COOKIE, cookie)
                .header("HX-Request", "true")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body_bytes).expect("utf-8");

    // Full-page response keeps table elements in proper nesting context.
    assert!(
        body.to_ascii_lowercase().contains("<!doctype html"),
        "sort HTMX response must be a full page so table elements survive DOMParser"
    );
    assert!(
        body.contains("bob@acme.test"),
        "sort HTMX response must include user rows"
    );
    // Active column must have aria-sort="ascending".
    assert!(
        body.contains(r#"aria-sort="ascending""#),
        "active sort column must carry aria-sort=ascending"
    );
    // Inactive columns must remain aria-sort="none".
    assert!(
        body.contains(r#"aria-sort="none""#),
        "inactive sort columns must carry aria-sort=none"
    );
}

/// Sort links extract the whole `#users-table-region` from the full-page
/// response via `hx-select` and swap it as one unit (HEA-1615). A full page
/// keeps `<thead>` nested inside `<table>` so DOMParser preserves it
/// (HEA-1643); wrapping the region means the pagination bar updates with the
/// sort instead of going stale — so no separate OOB thead swap is needed.
#[tokio::test]
async fn admin_users_sort_links_use_hx_select_for_region() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-users-sort-attrs");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/realms/acme/users")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body_bytes).expect("utf-8");

    // Sort links must target + select the unified region.
    assert!(
        body.contains(r##"hx-select="#users-table-region""##),
        "sort links must hx-select the whole table region"
    );
    assert!(
        body.contains(r##"hx-target="#users-table-region""##),
        "sort links must target the whole table region"
    );
    // The stale-prone OOB thead swap is gone — the region carries the thead.
    assert!(
        !body.contains(r##"hx-select-oob="#users-thead""##),
        "sort links must no longer use a separate OOB thead swap"
    );
    // WCAG 2.2 SC 2.4.11 minimum focus ring.
    assert!(
        body.contains("focus-visible:ring-2"),
        "sort link anchor must use focus-visible:ring-2 for WCAG 2.2 SC 2.4.11"
    );
}

/// Sort links carry `hx-include="input[name='q']"` so HTMX dynamically
/// reads the live search input value at click time. This ensures the
/// active search query is preserved even after a partial tbody-only swap
/// has left the thead's static `q` stale (HEA-1646).
#[tokio::test]
async fn admin_users_sort_links_carry_hx_include_for_q() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-users-sort-hx-include");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/realms/acme/users")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body_bytes).expect("utf-8");

    // Sort links must use hx-include to pick up the live search input value
    // (and any active status filter, e.g. on the sessions table — HEA-1615).
    assert!(
        body.contains(r#"hx-include="input[name='q'], input[name='status']""#),
        "sort links must carry hx-include pointing at the search + status inputs"
    );
    // hx-get must NOT bake a static q= into the URL — hx-include owns that.
    // href may still carry it as a no-JS fallback.
    let hx_get_with_q = r#"hx-get="/ui/admin/realms/acme/users?sort=email&dir=asc&q="#;
    assert!(
        !body.contains(hx_get_with_q),
        "sort link hx-get must not contain a static q= param (hx-include provides it)"
    );
}

/// When an HTMX sort request carries an active `?q=` search param, the
/// server must return filtered+sorted rows and render the new thead with
/// `q` in the sort link hrefs so subsequent sort clicks keep the filter.
/// Regression guard for HEA-1646.
#[tokio::test]
async fn admin_users_sort_with_active_search_preserves_filter() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-users-sort-search");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/realms/acme/users?sort=email&dir=asc&q=bob")
                .header(header::COOKIE, cookie)
                .header("HX-Request", "true")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body_bytes).expect("utf-8");

    // Full page so OOB thead swap works.
    assert!(
        body.to_ascii_lowercase().contains("<!doctype html"),
        "sort+search HTMX response must be a full page"
    );
    // The seeded user matching q=bob must appear.
    assert!(
        body.contains("bob@acme.test"),
        "sort+search response must include the matching user row"
    );
    // The sort link href for the active column must carry q=bob so the
    // newly-swapped-in thead has correct static fallback URLs.
    assert!(
        body.contains("&amp;q=bob") || body.contains("&q=bob"),
        "new thead sort links must carry q=bob in href for no-JS fallback"
    );
}

/// Sorting while a search term is active must NOT 400.
///
/// Reproduces the exact request the browser sends (HEA-1615): htmx 1.9's
/// `hx-include` repeats the `q` parameter several times on a sort-header
/// click when the search box is populated, e.g.
/// `?sort=email&dir=asc&q=bob&q=bob&q=bob`. axum's stock `Query` extractor
/// rejects the duplicated scalar key with `400`, so the sort swap silently
/// failed and the table never re-sorted — the board's "sorting still doesn't
/// work when a search term is active". The `DedupQuery` extractor collapses
/// the repeats, so the request now succeeds and returns filtered+sorted rows.
#[tokio::test]
async fn admin_users_sort_with_duplicated_q_param_does_not_400() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-users-dup-q");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                // q repeated 4× — exactly what htmx hx-include emits.
                .uri("/ui/admin/realms/acme/users?sort=email&dir=asc&per_page=25&q=bob&q=bob&q=bob&q=bob")
                .header(header::COOKIE, cookie)
                .header("HX-Request", "true")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    // The whole point: this used to be 400.
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "duplicated q params must not be rejected"
    );
    let body_bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body_bytes).expect("utf-8");

    // Filter still applied (q=bob) and the region is present for hx-select.
    assert!(
        body.contains("bob@acme.test"),
        "dedup must preserve the q=bob filter"
    );
    assert!(
        body.contains(r#"<div id="users-table-region">"#),
        "response must contain the region so the sort swap lands"
    );
}

/// `/ui/admin/sessions` renders the Active/Expired/All filter pills
/// and defaults to the Active view. Resolves REQ-050 in the gap doc.
#[tokio::test]
async fn admin_sessions_list_renders_status_filter_pills() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-sessions-pills");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/realms/acme/sessions")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body_bytes).expect("utf-8");

    // All three pills present, with their query strings.
    assert!(body.contains("?status=active"), "Active pill must be wired");
    assert!(
        body.contains("?status=expired"),
        "Expired pill must be wired"
    );
    assert!(body.contains("?status=all"), "All pill must be wired");

    // Default is Active — only the Active pill carries aria-selected="true".
    let active_marker = r#"href="/ui/admin/realms/acme/sessions?status=active"
     role="tab"
     aria-selected="true""#;
    assert!(
        body.contains(active_marker),
        "Active pill must be the default selected tab"
    );
}

/// `/ui/admin/sessions?status=expired` returns the empty-state row when
/// no sessions are past expiry. Pins the filter wires through end-to-end.
#[tokio::test]
async fn admin_sessions_list_expired_filter_empty_when_all_active() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-sessions-expired");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/realms/acme/sessions?status=expired")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body_bytes).expect("utf-8");

    // Both seeded sessions are fresh — Expired view is empty.
    assert!(
        body.contains("No sessions match the current filter"),
        "expired view should render the empty-state row when all sessions are active"
    );
    // Expired pill is the selected one.
    let expired_marker = r#"href="/ui/admin/realms/acme/sessions?status=expired"
     role="tab"
     aria-selected="true""#;
    assert!(
        body.contains(expired_marker),
        "Expired pill must be the selected tab when ?status=expired"
    );
}

/// Regression: a 404 from inside the admin shell renders **with**
/// chrome (sidebar, user pill, dark theme), not as a stand-alone
/// unstyled white page. The 2026-04-29 audit caught the legacy
/// behaviour leaving an authenticated admin staring at a bare
/// "Not Found" line with no nav to recover.
#[tokio::test]
async fn admin_user_detail_404_renders_inside_admin_shell() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-404-chrome");

    // Hit a UUID that doesn't exist in the acme tenant realm.
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/realms/acme/users/00000000-0000-0000-0000-0000ffff0001")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body_bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body_bytes).expect("utf-8");

    assert!(body.contains("Not Found"));
    // Sidebar nav links — confirm the admin chrome is intact.
    assert!(
        body.contains("/ui/admin/realms"),
        "404 inside admin shell must keep the sidebar (Realms link)"
    );
    assert!(
        body.contains("/ui/logout"),
        "404 inside admin shell must keep the user pill / sign-out"
    );
    assert!(
        body.contains("admin@acme.test"),
        "404 inside admin shell must show the signed-in user's email"
    );
}

/// `GET /ui/admin/users` (no realm) returns 404 — the path-based routing
/// migration deleted the cookie / `?realm=` fallbacks that used to
/// silently resolve a tenant realm. Pins R-5 from `UI_ROUTING.md`.
#[tokio::test]
async fn admin_user_list_without_realm_path_returns_404() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-no-realm");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/users")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn admin_user_detail_returns_404_for_unknown() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-404");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/realms/acme/users/00000000-0000-0000-0000-000000000099")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Edit user
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_edit_user_succeeds() {
    let rig = build_rig();
    let csrf = "csrf-edit";
    let cookie = admin_cookie(&rig, csrf);

    let uid = rig.non_admin_user_id.as_uuid();
    let form =
        format!("email=bob-new%40acme.test&display_name=Robert&status=Disabled&_csrf={csrf}");
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/admin/realms/acme/users/{uid}/edit"))
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    // Verify the changes persisted.
    let updated = rig
        .identity
        .get_user(&rig.realm_id, &rig.non_admin_user_id)
        .expect("get_user")
        .expect("user exists");
    assert_eq!(updated.email(), "bob-new@acme.test");
    assert_eq!(updated.display_name(), "Robert");
    assert_eq!(updated.status(), UserStatus::Disabled);
}

// ---------------------------------------------------------------------------
// Delete user
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_delete_user_succeeds() {
    let rig = build_rig();
    let csrf = "csrf-del";
    let cookie = admin_cookie(&rig, csrf);

    let uid = rig.non_admin_user_id.as_uuid();
    let form = format!("_csrf={csrf}");
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/admin/realms/acme/users/{uid}/delete"))
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/ui/admin/realms/acme/users"),
    );

    // User no longer exists.
    assert!(rig
        .identity
        .get_user(&rig.realm_id, &rig.non_admin_user_id)
        .expect("get_user")
        .is_none());
}

// ===========================================================================
// Realm tests
// ===========================================================================

#[tokio::test]
async fn admin_realm_list_renders() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-tlist");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/realms")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body_bytes).expect("utf-8");
    assert!(body.contains("acme"), "should list the realm");
    assert!(
        body.contains("hearth.yaml"),
        "should show YAML config notice"
    );
}

// NOTE: admin_create_realm_succeeds removed — realms are now managed
// via hearth.yaml; the /admin/realms/new route no longer exists.

#[tokio::test]
async fn admin_realm_detail_renders() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-tdetail");

    let uri = "/ui/admin/realms/acme".to_string();
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body_bytes).expect("utf-8");
    assert!(body.contains("acme"));
    assert!(body.contains("Active"));
}

async fn realm_detail_body(rig: &TestRig, cookie: String) -> String {
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/realms/acme")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    String::from_utf8(body_bytes.to_vec()).expect("utf-8")
}

/// scope-trim-trusted-core, spec `mfa-policy`: a realm whose MFA is off
/// shows a persistent warning naming the setting; a realm that requires MFA
/// shows none.
#[tokio::test]
async fn admin_realm_detail_warns_when_mfa_is_off() {
    let rig = build_rig();
    let body = realm_detail_body(&rig, admin_cookie(&rig, "csrf-mfa-off")).await;
    assert!(
        body.contains("MFA is disabled for this realm"),
        "banner missing"
    );
    assert!(
        body.contains("auth.mfa_required"),
        "the banner names the setting"
    );

    let mut config = rig
        .identity
        .get_realm(&rig.realm_id)
        .expect("get")
        .expect("realm")
        .config()
        .clone();
    config.mfa_required = Some(true);
    rig.identity
        .update_realm(
            &rig.realm_id,
            &hearth::identity::UpdateRealmRequest {
                config: Some(config),
                ..Default::default()
            },
        )
        .expect("require MFA");
    let body = realm_detail_body(&rig, admin_cookie(&rig, "csrf-mfa-on")).await;
    assert!(
        !body.contains("MFA is disabled for this realm"),
        "no banner when required"
    );
}

// NOTE: admin_edit_realm_succeeds removed — realms are now managed
// via hearth.yaml; the /admin/realms/{id}/edit route no longer exists.

#[tokio::test]
async fn admin_delete_realm_requires_archived_status() {
    let rig = build_rig();
    let csrf = "csrf-tdel";
    let cookie = admin_cookie(&rig, csrf);

    // Create a second realm for deletion.
    let extra = rig
        .identity
        .create_realm(&CreateRealmRequest {
            name: "doomed".to_string(),
            config: None,
        })
        .expect("create doomed realm");

    // Deleting an Active realm should be rejected (400).
    let form = format!("_csrf={csrf}");
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/admin/realms/doomed/delete")
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "should reject deletion of non-archived realm"
    );

    // Archive the realm first (simulating what YAML reconciliation does).
    rig.identity
        .update_realm(
            extra.id(),
            &hearth::identity::UpdateRealmRequest {
                status: Some(hearth::identity::RealmStatus::Archived),
                ..Default::default()
            },
        )
        .expect("archive realm");

    // Now deletion should succeed.
    let form2 = format!("_csrf={csrf}");
    let response2 = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/admin/realms/doomed/delete")
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form2))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response2.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response2
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/ui/admin/realms"),
    );

    assert!(rig
        .identity
        .get_realm(extra.id())
        .expect("get_realm")
        .is_none());
}

// ===========================================================================
// Application tests
// ===========================================================================

#[tokio::test]
async fn admin_app_list_renders() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-alist");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/realms/acme/applications")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body_bytes).expect("utf-8");
    // The legacy "Managed via hearth.yaml" badge was replaced by an
    // "Edit in Config Editor" CTA in PR3 — operators have a working
    // path to the editor now, not a dead-end note. See the 2026-04-29
    // UX audit, finding #8.
    assert!(
        body.contains("Edit in Config Editor"),
        "applications list must surface a CTA to the config editor"
    );
    assert!(
        body.contains("/ui/admin/settings/editor?section=oidc"),
        "applications CTA must deep-link to the OIDC section"
    );
}

#[tokio::test]
async fn admin_app_detail_renders() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-adetail");

    // Create a client via the engine.
    let client = rig
        .identity
        .register_client(
            &rig.realm_id,
            &RegisterClientRequest {
                client_name: "DetailApp".to_string(),
                redirect_uris: vec!["https://example.com/cb".to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: true,
                client_logo_url: None,
                ..Default::default()
            },
        )
        .expect("register_client");

    let cid = client.client_id().as_uuid();
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/ui/admin/realms/acme/applications/{cid}"))
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body_bytes).expect("utf-8");
    assert!(body.contains("DetailApp"));
    assert!(body.contains("https://example.com/cb"));
}

// ===========================================================================
// ID-token signing algorithm in the console (task 26.55)
// ===========================================================================
//
// The console offers RS256 next to EdDSA, and an unrelated edit of an RS256
// application saves without touching the algorithm (the edit form always
// posts the radio, while an omitted field means "unchanged" on the REST
// update path).

/// Application form fields shared by the create and edit posts below.
const RP_FORM: &str = "redirect_uris=https%3A%2F%2Frp.example.com%2Fcb\
                       &grant_authorization_code=1&trust_level=third_party";

/// Registers an `acme` client whose ID tokens use `alg`.
fn register_rp(rig: &TestRig, alg: &str) -> OAuthClient {
    rig.identity
        .register_client(
            &rig.realm_id,
            &RegisterClientRequest {
                client_name: "Console RP".to_string(),
                redirect_uris: vec!["https://rp.example.com/cb".to_string()],
                grant_types: vec!["authorization_code".to_string()],
                id_token_signed_response_alg: Some(alg.to_string()),
                ..Default::default()
            },
        )
        .expect("register_client")
}

/// An admin console request: a POST of `form` (the CSRF field is appended),
/// or a GET when `form` is `None`. Returns the status, `Location` and body.
async fn console_request(
    rig: &TestRig,
    uri: &str,
    form: Option<&str>,
) -> (StatusCode, String, String) {
    let csrf = "csrf-id-token-alg";
    let builder = Request::builder()
        .uri(uri)
        .header(header::COOKIE, admin_cookie(rig, csrf));
    let request = match form {
        Some(form) => builder
            .method("POST")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!("{form}&_csrf={csrf}"))),
        None => builder.method("GET").body(Body::empty()),
    }
    .expect("build request");
    let response = rig.app.clone().oneshot(request).await.expect("oneshot");
    let status = response.status();
    let location = location_of(&response);
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = String::from_utf8(body.to_vec()).expect("utf-8");
    (status, location, body)
}

/// The form error a page shows — its `role="alert"` element — if any.
fn form_error(body: &str) -> Option<&str> {
    const OPEN: &str = r#"role="alert">"#;
    let start = body.find(OPEN)? + OPEN.len();
    let len = body[start..].find("</div>")?;
    Some(body[start..start + len].trim())
}

/// The attributes of the ID-token algorithm radio for `alg`, as written in
/// its `<input …>` tag.
fn id_token_alg_radio(body: &str, alg: &str) -> Vec<String> {
    let at = body
        .find(&format!(
            r#"name="id_token_signed_response_alg" value="{alg}""#
        ))
        .unwrap_or_else(|| panic!("the {alg} ID-token radio is rendered"));
    let start = body[..at].rfind("<input").expect("radio tag start");
    let end = at + body[at..].find('>').expect("radio tag end");
    body[start..end]
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

/// Whether a tag's attributes (from [`id_token_alg_radio`]) include the bare
/// boolean attribute `name`.
fn has_flag(attributes: &[String], name: &str) -> bool {
    attributes.iter().any(|attribute| attribute == name)
}

/// Creating a confidential application redirects (post/redirect/get) to its
/// page, which shows the generated secret once — held server-side for this
/// session, never in a URL — with `Cache-Control: no-store`; that secret
/// authenticates, and reloading the page neither shows it again nor creates a
/// second application.
///
/// The form used to redirect with `?secret_shown=1`, which nothing read, so
/// the secret was discarded; the fix after that answered the POST itself with
/// the secret (200), so reloading the page re-submitted the form — the CSRF
/// token is per session — and registered a duplicate application.
#[tokio::test]
async fn console_create_shows_a_confidential_applications_secret_once() {
    const SHOWN: &str = "Client secret (shown once)";
    let rig = build_rig();
    let (status, location, _) = console_request(
        &rig,
        "/ui/admin/realms/acme/applications/new",
        Some(
            "client_name=Billing+Service&client_type=confidential\
             &grant_client_credentials=1&trust_level=first_party",
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "creating an application must redirect, so a reload cannot re-submit the form"
    );
    let client = rig
        .identity
        .list_clients(&rig.realm_id, &PageRequest::default())
        .expect("list_clients")
        .items
        .into_iter()
        .find(|c| c.client_name() == "Billing Service")
        .expect("the application was registered");
    assert_eq!(
        location,
        format!(
            "/ui/admin/realms/acme/applications/{}",
            client.client_id().as_uuid()
        ),
        "the redirect goes to the application's page and carries nothing else"
    );

    let reveal = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(&location)
                .header(header::COOKIE, admin_cookie(&rig, "csrf-id-token-alg"))
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");
    assert_eq!(reveal.status(), StatusCode::OK);
    assert_eq!(
        reveal
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store"),
        "the page that shows a secret must not be cached"
    );
    let body = to_bytes(reveal.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = String::from_utf8(body.to_vec()).expect("utf-8");
    let at = body
        .find(SHOWN)
        .expect("the page after creation shows the new client secret");
    let code = at + body[at..].find("<code").expect("secret element");
    let open = code + body[code..].find('>').expect("secret element end") + 1;
    let close = open + body[open..].find("</code>").expect("secret close");
    let secret = body[open..close].trim().to_string();
    assert!(
        secret.len() >= 43,
        "a 256-bit secret, got {} chars",
        secret.len()
    );
    rig.identity
        .authenticate_client(&rig.realm_id, client.client_id(), Some(&secret))
        .expect("the secret shown on creation must authenticate the new client");

    // Shown once: a reload shows the page without it, and registers nothing.
    let (status, _, detail) = console_request(&rig, &location, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!detail.contains(SHOWN) && !detail.contains(&secret));
    let registered = rig
        .identity
        .list_clients(&rig.realm_id, &PageRequest::default())
        .expect("list_clients")
        .items
        .into_iter()
        .filter(|c| c.client_name() == "Billing Service")
        .count();
    assert_eq!(registered, 1, "exactly one application was created");
}

/// *Regenerate secret* follows the same post/redirect/get: it redirects to the
/// application's page, which shows the new secret once. It used to answer the
/// POST with the secret, so a reload rotated the secret again and the one on
/// screen stopped working.
#[tokio::test]
async fn console_regenerate_shows_the_new_secret_once_after_a_redirect() {
    const SHOWN: &str = "Client secret (shown once)";
    let rig = build_rig();
    let (_, location, _) = console_request(
        &rig,
        "/ui/admin/realms/acme/applications/new",
        Some(
            "client_name=Rotating+Service&client_type=confidential\
             &grant_client_credentials=1&trust_level=first_party",
        ),
    )
    .await;
    // Consume the creation reveal.
    let (_, _, first) = console_request(&rig, &location, None).await;
    assert!(first.contains(SHOWN));

    let (status, regen_location, _) =
        console_request(&rig, &format!("{location}/regenerate-secret"), Some("x=1")).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "regenerate must redirect");
    assert_eq!(regen_location, location);
    let (_, _, shown) = console_request(&rig, &location, None).await;
    assert!(
        shown.contains(SHOWN),
        "the new secret is shown after the redirect"
    );
    let (_, _, again) = console_request(&rig, &location, None).await;
    assert!(!again.contains(SHOWN), "and only once");
}

/// An RS256 application can be edited. The form posts the stored RS256
/// back, which is no change, so an unrelated edit saves, as it does over
/// REST, and the algorithm stays as it was.
#[tokio::test]
async fn console_edit_of_an_rs256_client_saves_unrelated_changes() {
    let rig = build_rig();
    let client = register_rp(&rig, "RS256");
    let cid = client.client_id().as_uuid();

    let (status, location, body) = console_request(
        &rig,
        &format!("/ui/admin/realms/acme/applications/{cid}/edit"),
        Some(&format!(
            "client_name=Renamed+RP&{RP_FORM}&id_token_signed_response_alg=RS256"
        )),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "an unrelated edit must save, got: {:?}",
        form_error(&body)
    );
    assert_eq!(
        location,
        format!("/ui/admin/realms/acme/applications/{cid}")
    );
    let stored = rig
        .identity
        .get_client(&rig.realm_id, client.client_id())
        .expect("get_client")
        .expect("the client exists");
    assert_eq!(stored.client_name(), "Renamed RP", "the edit was saved");
    assert_eq!(
        stored.id_token_signed_response_alg(),
        IdTokenSigningAlg::Rs256,
        "the algorithm the form did not change stays as it was"
    );
}

/// Both forms offer RS256: a new application may pick it, and the edit page
/// of an RS256 application shows it selected and selectable, with no notice
/// that its ID-token grants are refused.
#[tokio::test]
async fn console_forms_offer_rs256() {
    const REFUSED_NOTICE: &str = "until it is switched to EdDSA";
    let rig = build_rig();
    let rs256_client = register_rp(&rig, "RS256");

    let (_, _, body) = console_request(&rig, "/ui/admin/realms/acme/applications/new", None).await;
    let rs256 = id_token_alg_radio(&body, "RS256");
    assert!(!has_flag(&rs256, "disabled"), "got: {rs256:?}");
    let (_, _, body) = console_request(
        &rig,
        &format!(
            "/ui/admin/realms/acme/applications/{}/edit",
            rs256_client.client_id().as_uuid()
        ),
        None,
    )
    .await;
    let rs256 = id_token_alg_radio(&body, "RS256");
    assert!(
        has_flag(&rs256, "checked") && !has_flag(&rs256, "disabled"),
        "got: {rs256:?}"
    );
    assert!(!body.contains(REFUSED_NOTICE));
}

// ===========================================================================
// Application form errors and delete
// ===========================================================================
//
// The FAPI refusal tests used to be the only ones that reached the
// invalid-input branches of the create and edit handlers. Any invalid input
// reaches them, so a redirect URI with a fragment stands in.

/// Application form fields with a redirect URI the engine refuses.
const FRAGMENT_FORM: &str = "redirect_uris=https%3A%2F%2Frp.example.com%2Fcb%23frag\
                             &grant_authorization_code=1&trust_level=third_party";

/// A create the engine refuses re-renders the form with the reason, keeps the
/// typed values, and registers nothing.
#[tokio::test]
async fn console_create_with_invalid_input_rerenders_with_the_reason() {
    let rig = build_rig();
    let (status, location, body) = console_request(
        &rig,
        "/ui/admin/realms/acme/applications/new",
        Some(&format!("client_name=Fragment+RP&{FRAGMENT_FORM}")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "location: {location}");
    let error = form_error(&body).expect("the form shows an error");
    assert!(error.contains("fragment"), "got: {error}");
    assert!(body.contains("Fragment RP"), "the typed name is kept");
    let names: Vec<String> = rig
        .identity
        .list_clients(&rig.realm_id, &PageRequest::default())
        .expect("list_clients")
        .items
        .iter()
        .map(|c| c.client_name().to_string())
        .collect();
    assert!(!names.iter().any(|n| n == "Fragment RP"), "got: {names:?}");
}

/// An edit the engine refuses re-renders the form with the reason and leaves
/// the stored client unchanged.
#[tokio::test]
async fn console_edit_with_invalid_input_rerenders_with_the_reason() {
    let rig = build_rig();
    let client = register_rp(&rig, "EdDSA");
    let cid = client.client_id().as_uuid();
    let (status, location, body) = console_request(
        &rig,
        &format!("/ui/admin/realms/acme/applications/{cid}/edit"),
        Some(&format!("client_name=Renamed+RP&{FRAGMENT_FORM}")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "location: {location}");
    let error = form_error(&body).expect("the form shows an error");
    assert!(error.contains("fragment"), "got: {error}");
    let stored = rig
        .identity
        .get_client(&rig.realm_id, client.client_id())
        .expect("get_client")
        .expect("the client exists");
    assert_eq!(stored.client_name(), "Console RP", "nothing was saved");
    assert_eq!(stored.redirect_uris(), ["https://rp.example.com/cb"]);
}

/// The delete form removes the client and returns to the application list.
#[tokio::test]
async fn console_delete_removes_the_application() {
    let rig = build_rig();
    let client = register_rp(&rig, "EdDSA");
    let cid = client.client_id().as_uuid();
    let (status, location, _) = console_request(
        &rig,
        &format!("/ui/admin/realms/acme/applications/{cid}/delete"),
        Some(""),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location, "/ui/admin/realms/acme/applications");
    let stored = rig
        .identity
        .get_client(&rig.realm_id, client.client_id())
        .expect("get_client");
    assert!(stored.is_none(), "the client is gone");
}

// ===========================================================================
// Session tests
// ===========================================================================

#[tokio::test]
async fn admin_sessions_list_renders() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-slist");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/realms/acme/sessions")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body_bytes).expect("utf-8");
    // The acme realm contains bob's session.
    assert!(
        body.contains("bob@acme.test"),
        "should show non-admin session"
    );
}

#[tokio::test]
async fn admin_revoke_session_succeeds() {
    let rig = build_rig();
    let csrf = "csrf-srevoke";
    let cookie = admin_cookie(&rig, csrf);

    // Create a throwaway session to revoke.
    let extra_session = rig
        .identity
        .create_session(
            &rig.realm_id,
            &rig.non_admin_user_id,
            &hearth::identity::SessionContext::default(),
        )
        .expect("create extra session");

    let sid = extra_session.id().as_uuid();
    let form = format!("_csrf={csrf}");
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/ui/admin/realms/acme/sessions/{sid}/revoke"))
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/ui/admin/realms/acme/sessions"),
    );

    // Session should be gone (revoked → get_session returns None).
    assert!(rig
        .identity
        .get_session(&rig.realm_id, extra_session.id())
        .expect("get_session")
        .is_none());
}

// ===========================================================================
// Audit tests
// ===========================================================================

#[tokio::test]
async fn admin_audit_page_renders() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-audit");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/realms/acme/audit")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body_bytes).expect("utf-8");
    assert!(body.contains("Audit log"));
}

#[tokio::test]
async fn admin_audit_page_shows_events_after_user_create() {
    let rig = build_rig();
    let csrf = "csrf-auditcr";
    let cookie = admin_cookie(&rig, csrf);

    // Create a user via the admin UI to generate an audit event.
    let form = format!(
        "email=auditee%40acme.test&display_name=Auditee&password=super-secret-password-12&_csrf={csrf}"
    );
    let _create_resp = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/admin/realms/acme/users/new")
                .header(header::COOKIE, admin_cookie(&rig, csrf))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    // Now load the audit page filtered by action=user_created.
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/realms/acme/audit?action=user_created")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body_bytes).expect("utf-8");
    assert!(
        body.contains("user_created"),
        "expected user_created event in audit log"
    );
}

// ---------------------------------------------------------------------------
// Realm-aware redirects + admin-users surface
// ---------------------------------------------------------------------------

fn location_of(resp: &axum::http::Response<Body>) -> String {
    resp.headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

fn set_cookie_with(resp: &axum::http::Response<Body>, prefix: &str) -> Option<String> {
    resp.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|c| c.starts_with(prefix))
        .map(str::to_string)
}

#[tokio::test]
async fn unauthenticated_admin_path_redirects_to_admin_login() {
    let rig = build_rig();
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/realms/acme/users")
                .body(Body::empty())
                .expect("build"),
        )
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let loc = location_of(&response);
    assert!(
        loc.starts_with("/ui/admin/login"),
        "admin-path unauthenticated redirect must target /ui/admin/login, got {loc}"
    );
}

#[tokio::test]
async fn unauthenticated_last_realm_cookie_targets_tenant_login() {
    let rig = build_rig();
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/account")
                .header(header::COOKIE, "hearth_ui_last_realm=acme")
                .body(Body::empty())
                .expect("build"),
        )
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let loc = location_of(&response);
    assert!(
        loc.starts_with("/ui/realms/acme/login"),
        "last-realm cookie should drive realm-scoped login redirect, got {loc}"
    );
}

#[tokio::test]
async fn admin_logout_redirects_to_admin_login_and_sets_last_realm() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-logout");
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/logout")
                .header(header::COOKIE, &cookie)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("_csrf=csrf-logout"))
                .expect("build"),
        )
        .await
        .expect("oneshot");
    assert!(
        response.status().is_redirection(),
        "logout should redirect, got {}",
        response.status()
    );
    let loc = location_of(&response);
    assert!(
        loc.starts_with("/ui/admin/login"),
        "admin logout must return to admin login, got {loc}"
    );
    let last_realm = set_cookie_with(&response, "hearth_ui_last_realm=")
        .expect("admin logout must set a hearth_ui_last_realm Set-Cookie header");
    assert!(
        last_realm.contains("hearth_ui_last_realm=__system__"),
        "admin logout must set last-realm sentinel, got {last_realm}"
    );
}

#[tokio::test]
async fn tenant_logout_redirects_to_realm_login() {
    let rig = build_rig();
    let cookie = non_admin_cookie(&rig, "csrf-tenant-logout");
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/ui/logout")
                .header(header::COOKIE, &cookie)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("_csrf=csrf-tenant-logout"))
                .expect("build"),
        )
        .await
        .expect("oneshot");
    assert!(response.status().is_redirection());
    let loc = location_of(&response);
    let realm_name = rig
        .identity
        .get_realm(&rig.realm_id)
        .expect("get realm")
        .expect("realm exists")
        .name()
        .to_string();
    assert_eq!(
        loc,
        format!("/ui/realms/{realm_name}/login"),
        "tenant logout must target the realm's login page"
    );
    let last_realm = set_cookie_with(&response, "hearth_ui_last_realm=")
        .expect("tenant logout must set a hearth_ui_last_realm Set-Cookie header");
    assert!(
        last_realm.contains(&format!("hearth_ui_last_realm={realm_name}")),
        "tenant logout must set last-realm to realm name, got {last_realm}"
    );
}

#[tokio::test]
async fn admin_users_page_lists_only_system_realm_users() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-admin-users");
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/admin-users")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .expect("build"),
        )
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), 1 << 20).await.expect("body");
    let body = String::from_utf8_lossy(&body_bytes);
    assert!(
        body.contains("admin@acme.test"),
        "admin-users page should list system-realm admin"
    );
    assert!(
        !body.contains("bob@acme.test"),
        "admin-users page must not leak tenant-realm users"
    );
    assert!(
        body.contains("Admin Users"),
        "admin-users page header must differ from tenant Users header"
    );
}

#[tokio::test]
async fn tenant_users_list_renders_realm_breadcrumb() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-tenant-users");
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/realms/acme/users")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .expect("build"),
        )
        .await
        .expect("oneshot");
    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), 1 << 20).await.expect("body");
    let body = String::from_utf8_lossy(&body_bytes);
    // Workspace breadcrumb: link to Realms list.
    assert!(
        body.contains("href=\"/ui/admin/realms\""),
        "tenant users list must link back to Realms"
    );
    // Tab bar must mark Users as the active page.
    assert!(
        body.contains("aria-current=\"page\""),
        "tenant users list must mark active tab"
    );
}
