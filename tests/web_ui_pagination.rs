//! Web integration tests for pagination phase 3 (HEA-1618).
//!
//! Verifies:
//! - `per_page` allowlist enforcement: out-of-set values clamp to 25.
//! - Realm list with N > per_page renders prev/next states and correct range.
//! - Page-size dropdown renders with the current size pre-selected.
//! - Search query (`?q=`) is preserved in the page-size form's hidden inputs.

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

const COOKIE_SECRET_BYTES: [u8; 32] = [99u8; 32];

// ---------------------------------------------------------------------------
// Minimal test rig (matches the web_ui_admin.rs pattern exactly)
// ---------------------------------------------------------------------------

struct TestRig {
    app: axum::Router,
    identity: Arc<dyn IdentityEngine>,
    admin_session_id: SessionId,
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

    let admin_realm_id = RealmId::new(uuid::Uuid::nil());

    let admin_user = identity
        .create_admin_user(&CreateUserRequest {
            email: "admin@pag.test".to_string(),
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
                email: None,
                display_name: None,
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
        .expect("admin session");

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
                role_id: admin_role.id,
                scope: hearth::rbac::Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign admin role");

    let onboarding = Arc::new(OnboardingService::new(
        Arc::clone(&identity),
        Arc::clone(&authz),
        null_email_service(),
        data_dir.clone(),
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
        admin_session_id: admin_session.id().clone(),
    }
}

fn admin_cookie(rig: &TestRig, csrf: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let admin_realm = RealmId::new(uuid::Uuid::nil());
    let mut mac = <Hmac<Sha256>>::new_from_slice(&COOKIE_SECRET_BYTES).expect("hmac key");
    mac.update(rig.admin_session_id.as_uuid().as_bytes());
    mac.update(b"|");
    mac.update(admin_realm.as_uuid().as_bytes());
    let tag = data_encoding::BASE64URL_NOPAD.encode(&mac.finalize().into_bytes());
    format!(
        "hearth_ui_session={}.{}.{}; hearth_ui_csrf={}",
        rig.admin_session_id.as_uuid(),
        admin_realm.as_uuid(),
        tag,
        csrf,
    )
}

// ---------------------------------------------------------------------------
// Handler-level per_page allowlist enforcement
// ---------------------------------------------------------------------------

/// Out-of-allowlist `per_page` must be clamped (not rejected) — 200 OK.
/// Verifies there's no unbounded scan or 500 from an extreme value.
#[tokio::test]
async fn per_page_out_of_allowlist_clamped_to_default() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-pp1");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/realms?per_page=100000")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK, "should clamp not reject");
}

/// Every value in the allowlist is accepted.
#[tokio::test]
async fn per_page_in_allowlist_accepted() {
    let rig = build_rig();
    let cookie = admin_cookie(&rig, "csrf-pp2");

    for size in [5u32, 10, 25, 50, 100] {
        let response = rig
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/ui/admin/realms?per_page={size}"))
                    .header(header::COOKIE, cookie.clone())
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("oneshot");
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "per_page={size} should be accepted"
        );
    }
}

// ---------------------------------------------------------------------------
// Pagination bar renders correctly when N > per_page
// ---------------------------------------------------------------------------

/// Seeds 6 realms so that page 1 with per_page=5 shows a next-page link and
/// page 2 shows a prev-page link.
#[tokio::test]
async fn realm_list_pagination_renders_for_multiple_pages() {
    let rig = build_rig();

    for i in 0..6 {
        rig.identity
            .create_realm(&CreateRealmRequest {
                name: format!("realm-pag-{i}"),
                config: None,
            })
            .expect("create realm");
    }

    let cookie = admin_cookie(&rig, "csrf-pag1");

    // Page 1 with per_page=5 — expect "1–5" range and Next link.
    let resp1 = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/realms?page=1&per_page=5")
                .header(header::COOKIE, cookie.clone())
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp1.status(), StatusCode::OK);
    let body1 = to_bytes(resp1.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body1 = std::str::from_utf8(&body1).expect("utf-8");

    assert!(
        body1.contains("1–5"),
        "page 1 of 5-per-page should show '1–5' range summary"
    );
    assert!(
        body1.contains("page=2"),
        "should render a next-page (page=2) link"
    );
    // Prev disabled on page 1 — rendered as <button type="button" disabled> (HEA-1621).
    // aria-disabled on a non-interactive element is invalid; native disabled is correct.
    assert!(
        body1.contains("<button type=\"button\" disabled"),
        "Prev must be a disabled <button> on page 1"
    );

    // Page 2 — Prev enabled, should show range "6–6".
    let resp2 = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/realms?page=2&per_page=5")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp2.status(), StatusCode::OK);
    let body2 = to_bytes(resp2.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body2 = std::str::from_utf8(&body2).expect("utf-8");

    assert!(
        body2.contains("page=1"),
        "page 2 should render a Prev (page=1) link"
    );
    assert!(
        body2.contains("6–6"),
        "page 2 with 6 realms and per_page=5 should show '6–6'"
    );
}

/// The page-size `<select>` renders with the active `per_page` pre-selected
/// and a hidden `page=1` input so size changes reset to the first page.
#[tokio::test]
async fn realm_list_page_size_dropdown_present_and_selected() {
    let rig = build_rig();
    // Need at least one realm so total > 0 (pagination bar is hidden when total == 0).
    rig.identity
        .create_realm(&CreateRealmRequest {
            name: "dropdown-realm".to_string(),
            config: None,
        })
        .expect("create realm");

    let cookie = admin_cookie(&rig, "csrf-psize");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/realms?per_page=10")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body).expect("utf-8");

    assert!(
        body.contains("Rows per page"),
        "page-size label must be present"
    );
    assert!(
        body.contains("<option value=\"10\" selected>"),
        "per_page=10 option must be pre-selected; body snippet:\n{}",
        &body[body.find("per-page-select").unwrap_or(0)..][..500.min(body.len())]
    );
    assert!(
        body.contains("name=\"page\" value=\"1\""),
        "size change must reset to page 1 via hidden input"
    );
}

/// A search query (`?q=`) must appear as a hidden input in the page-size
/// form so it survives page-size changes (resets to page 1, filter preserved).
#[tokio::test]
async fn user_list_search_filter_preserved_in_page_size_form() {
    let rig = build_rig();

    let admin_realm_id = RealmId::new(uuid::Uuid::nil());
    // Seed 6 admin users so the list overflows per_page=5.
    for i in 0..6 {
        let u = rig
            .identity
            .create_admin_user(&CreateUserRequest {
                email: format!("findme-{i}@pag.test"),
                display_name: format!("FindMe {i}"),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            })
            .expect("create user");
        rig.identity
            .update_user(
                &admin_realm_id,
                u.id(),
                &UpdateUserRequest {
                    status: Some(UserStatus::Active),
                    email: None,
                    display_name: None,
                    first_name: None,
                    last_name: None,
                    ..Default::default()
                },
            )
            .expect("activate user");
    }

    let cookie = admin_cookie(&rig, "csrf-qpres");

    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/admin-users?q=findme&per_page=5")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body).expect("utf-8");

    assert!(
        body.contains("name=\"q\" value=\"findme\""),
        "q param must be in a hidden input so page-size change preserves the search filter"
    );
}

/// The per-page `<select>` must NOT carry an `onchange=` inline handler —
/// CSP `script-src 'self'` blocks inline event handlers (HEA-1621).
/// The external listener in admin.js replaces it.
#[tokio::test]
async fn pagination_no_inline_onchange_handler() {
    let rig = build_rig();
    let admin_realm_id = RealmId::new(uuid::Uuid::nil());

    for i in 0..6 {
        let u = rig
            .identity
            .create_admin_user(&CreateUserRequest {
                email: format!("onchange-{i}@csp.test"),
                display_name: format!("Onchange {i}"),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            })
            .expect("create user");
        rig.identity
            .update_user(
                &admin_realm_id,
                u.id(),
                &UpdateUserRequest {
                    status: Some(UserStatus::Active),
                    email: None,
                    display_name: None,
                    first_name: None,
                    last_name: None,
                    ..Default::default()
                },
            )
            .expect("activate user");
    }

    let cookie = admin_cookie(&rig, "csrf-onchange");
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/admin-users?per_page=5")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body).expect("utf-8");

    assert!(
        !body.contains("onchange="),
        "pagination must not use an onchange= inline handler (CSP violation)"
    );
}

/// Disabled prev/next pagination controls must use `<button type=\"button\" disabled>`,
/// not `<span aria-disabled=\"true\">`. `aria-disabled` is invalid on non-interactive
/// elements; the native `disabled` attribute on a button is the correct pattern (HEA-1621).
#[tokio::test]
async fn pagination_disabled_nav_uses_button_not_aria_disabled_span() {
    let rig = build_rig();
    let admin_realm_id = RealmId::new(uuid::Uuid::nil());

    for i in 0..6 {
        let u = rig
            .identity
            .create_admin_user(&CreateUserRequest {
                email: format!("disabled-nav-{i}@a11y.test"),
                display_name: format!("DisabledNav {i}"),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            })
            .expect("create user");
        rig.identity
            .update_user(
                &admin_realm_id,
                u.id(),
                &UpdateUserRequest {
                    status: Some(UserStatus::Active),
                    email: None,
                    display_name: None,
                    first_name: None,
                    last_name: None,
                    ..Default::default()
                },
            )
            .expect("activate user");
    }

    let cookie = admin_cookie(&rig, "csrf-disabnav");
    // Page 1 of 2 — Previous nav control will be in the disabled state.
    let response = rig
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ui/admin/admin-users?per_page=5&page=1")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let body = std::str::from_utf8(&body).expect("utf-8");

    assert!(
        body.contains("<button type=\"button\" disabled"),
        "disabled pagination nav must render as <button type=\"button\" disabled>, not a span"
    );
    assert!(
        !body.contains("aria-disabled=\"true\""),
        "aria-disabled must not appear on non-interactive elements in pagination"
    );
}
