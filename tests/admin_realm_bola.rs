//! Regression tests for HEA-1649: cross-realm BOLA in REST realm admin handlers.
//!
//! ## Failing-first test matrix
//!
//! Tests marked `_is_forbidden` FAIL on pre-fix code (handler returns 2xx/4xx ≠ 403)
//! and PASS after the fix (handler returns 403 Forbidden).
//!
//! | Handler                                        | Negative (BOLA → 403)                             |
//! |------------------------------------------------|---------------------------------------------------|
//! | GET    /admin/realms/{id}                      | `cross_realm_get_realm_is_forbidden`              |
//! | GET    /admin/realms/{id}/branding             | `cross_realm_get_branding_is_forbidden`           |
//! | PATCH  /admin/realms/{id}/branding             | `cross_realm_patch_branding_is_forbidden`         |
//! | GET    /admin/realms/{id}/email-templates      | `cross_realm_list_email_templates_is_forbidden`   |
//! | GET    /admin/realms/{id}/email-templates/{k}  | `cross_realm_get_email_template_is_forbidden`     |
//! | PUT    /admin/realms/{id}/email-templates/{k}  | `cross_realm_put_email_template_is_forbidden`     |
//! | DELETE /admin/realms/{id}/email-templates/{k}  | `cross_realm_delete_email_template_is_forbidden`  |
//! | POST   /admin/realms/{id}/rotate-signing-key   | `cross_realm_rotate_signing_key_is_forbidden`     |
//! | POST   /admin/realms/{id}/sv-bump-all          | `cross_realm_sv_bump_all_is_forbidden`            |
//! | DELETE /admin/realms/{id}                      | `cross_realm_delete_realm_is_forbidden`           |
//!
//! Positive path (system realm superuser):
//! | `system_realm_admin_can_get_any_realm`                                                         |
//! | `own_realm_admin_can_get_own_realm`                                                            |

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hearth::core::RealmId;
use hearth::identity::{CreateUserRequest, SessionContext};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use tower::ServiceExt as _;

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn system_realm_id() -> RealmId {
    RealmId::new(uuid::Uuid::nil())
}

fn build_app(h: &common::TestHarness) -> axum::Router {
    router(Arc::new(AppState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
    )))
}

/// Creates an admin user with `realm.admin` in `realm` and returns an access token.
async fn admin_token(h: &common::TestHarness, realm: &RealmId, suffix: &str) -> String {
    let user = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("bola-{suffix}@test.example"),
                display_name: "BOLA Admin".into(),
                first_name: "BOLA".into(),
                last_name: "Admin".into(),
                attributes: Default::default(),
            },
        )
        .expect("create admin user");

    let role = h
        .rbac()
        .get_role_by_name(realm, "realm.admin")
        .expect("lookup role")
        .expect("realm.admin role exists after seed");
    h.rbac()
        .assign_role(
            realm,
            &AssignRoleRequest {
                subject: Subject::User(user.id().clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign role");

    let session = h
        .identity()
        .create_session(realm, user.id(), &SessionContext::default())
        .expect("create session");
    h.identity()
        .issue_tokens(realm, user.id(), session.id())
        .expect("issue tokens")
        .access_token()
        .to_string()
}

/// Creates a realm, seeds RBAC, creates an admin, returns `(realm_id, token)`.
async fn setup_realm_admin(h: &common::TestHarness, suffix: &str) -> (RealmId, String) {
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed rbac");
    let token = admin_token(h, &realm, suffix).await;
    (realm, token)
}

fn req(method: &str, uri: String, token: &str, auth_realm: &RealmId, body: &str) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Realm-ID", auth_realm.as_uuid().to_string());
    if !body.is_empty() {
        builder = builder.header("Content-Type", "application/json");
    }
    builder
        .body(if body.is_empty() {
            Body::empty()
        } else {
            Body::from(body.to_string())
        })
        .expect("build request")
}

// ─── Negative (BOLA) tests ────────────────────────────────────────────────────
// Each test FAILS on pre-fix code and PASSES after the HEA-1649 fix.

#[tokio::test]
async fn cross_realm_get_realm_is_forbidden() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm_a, token_a) = setup_realm_admin(&h, "gr-a").await;
    let (realm_b, _) = setup_realm_admin(&h, "gr-b").await;

    let resp = build_app(&h)
        .oneshot(req(
            "GET",
            format!("/admin/realms/{}", realm_b.as_uuid()),
            &token_a,
            &realm_a,
            "",
        ))
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "realm-A admin must not read realm-B via GET /admin/realms/{{id}}"
    );
}

#[tokio::test]
async fn cross_realm_get_branding_is_forbidden() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm_a, token_a) = setup_realm_admin(&h, "gb-a").await;
    let (realm_b, _) = setup_realm_admin(&h, "gb-b").await;

    let resp = build_app(&h)
        .oneshot(req(
            "GET",
            format!("/admin/realms/{}/branding", realm_b.as_uuid()),
            &token_a,
            &realm_a,
            "",
        ))
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "realm-A admin must not read realm-B branding"
    );
}

#[tokio::test]
async fn cross_realm_patch_branding_is_forbidden() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm_a, token_a) = setup_realm_admin(&h, "pb-a").await;
    let (realm_b, _) = setup_realm_admin(&h, "pb-b").await;

    let resp = build_app(&h)
        .oneshot(req(
            "PATCH",
            format!("/admin/realms/{}/branding", realm_b.as_uuid()),
            &token_a,
            &realm_a,
            r"{}",
        ))
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "realm-A admin must not patch realm-B branding"
    );
}

#[tokio::test]
async fn cross_realm_list_email_templates_is_forbidden() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm_a, token_a) = setup_realm_admin(&h, "lt-a").await;
    let (realm_b, _) = setup_realm_admin(&h, "lt-b").await;

    let resp = build_app(&h)
        .oneshot(req(
            "GET",
            format!("/admin/realms/{}/email-templates", realm_b.as_uuid()),
            &token_a,
            &realm_a,
            "",
        ))
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "realm-A admin must not list realm-B email templates"
    );
}

#[tokio::test]
async fn cross_realm_get_email_template_is_forbidden() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm_a, token_a) = setup_realm_admin(&h, "gtet-a").await;
    let (realm_b, _) = setup_realm_admin(&h, "gtet-b").await;

    let resp = build_app(&h)
        .oneshot(req(
            "GET",
            format!(
                "/admin/realms/{}/email-templates/verification",
                realm_b.as_uuid()
            ),
            &token_a,
            &realm_a,
            "",
        ))
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "realm-A admin must not read realm-B email template"
    );
}

#[tokio::test]
async fn cross_realm_put_email_template_is_forbidden() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm_a, token_a) = setup_realm_admin(&h, "ptet-a").await;
    let (realm_b, _) = setup_realm_admin(&h, "ptet-b").await;

    // `{}` is valid for LocalizedEmailTemplate — all fields have #[serde(default)].
    // The scope check fires before template validation so the 403 is returned first.
    let resp = build_app(&h)
        .oneshot(req(
            "PUT",
            format!(
                "/admin/realms/{}/email-templates/verification",
                realm_b.as_uuid()
            ),
            &token_a,
            &realm_a,
            r"{}",
        ))
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "realm-A admin must not write realm-B email templates"
    );
}

#[tokio::test]
async fn cross_realm_delete_email_template_is_forbidden() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm_a, token_a) = setup_realm_admin(&h, "dtet-a").await;
    let (realm_b, _) = setup_realm_admin(&h, "dtet-b").await;

    let resp = build_app(&h)
        .oneshot(req(
            "DELETE",
            format!(
                "/admin/realms/{}/email-templates/verification",
                realm_b.as_uuid()
            ),
            &token_a,
            &realm_a,
            "",
        ))
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "realm-A admin must not delete realm-B email templates"
    );
}

#[tokio::test]
async fn cross_realm_rotate_signing_key_is_forbidden() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm_a, token_a) = setup_realm_admin(&h, "rsk-a").await;
    let (realm_b, _) = setup_realm_admin(&h, "rsk-b").await;

    let resp = build_app(&h)
        .oneshot(req(
            "POST",
            format!("/admin/realms/{}/rotate-signing-key", realm_b.as_uuid()),
            &token_a,
            &realm_a,
            "",
        ))
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "realm-A admin must not rotate realm-B signing key (token-DoS vector)"
    );
}

#[tokio::test]
async fn cross_realm_sv_bump_all_is_forbidden() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm_a, token_a) = setup_realm_admin(&h, "sba-a").await;
    let (realm_b, _) = setup_realm_admin(&h, "sba-b").await;

    let resp = build_app(&h)
        .oneshot(req(
            "POST",
            format!("/admin/realms/{}/sv-bump-all", realm_b.as_uuid()),
            &token_a,
            &realm_a,
            "",
        ))
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "realm-A admin must not sv-bump-all in realm-B (session-invalidation DoS)"
    );
}

#[tokio::test]
async fn cross_realm_delete_realm_is_forbidden() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm_a, token_a) = setup_realm_admin(&h, "dr-a").await;
    let (realm_b, _) = setup_realm_admin(&h, "dr-b").await;

    let resp = build_app(&h)
        .oneshot(req(
            "DELETE",
            format!("/admin/realms/{}", realm_b.as_uuid()),
            &token_a,
            &realm_a,
            "",
        ))
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "realm-A admin must not delete realm-B"
    );
}

// ─── Positive tests ───────────────────────────────────────────────────────────

/// System realm admin (nil UUID) must be able to read any tenant realm.
///
/// Uses `create_admin_user` (the only way to create users in the system realm)
/// rather than the regular `create_user` which is blocked by `SystemRealmProtected`.
#[tokio::test]
async fn system_realm_admin_can_get_any_realm() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let sys = system_realm_id();
    h.rbac().seed_realm(&sys).expect("seed system rbac");

    // Create admin in system realm using the system-realm-specific entry point.
    let user = h
        .identity()
        .create_admin_user(&hearth::identity::CreateUserRequest {
            email: "sys-bola-admin@test.example".into(),
            display_name: "SysAdmin".into(),
            first_name: "Sys".into(),
            last_name: "Admin".into(),
            attributes: Default::default(),
        })
        .expect("create system admin");

    let role = h
        .rbac()
        .get_role_by_name(&sys, "realm.admin")
        .expect("lookup role")
        .expect("realm.admin role exists after seed");
    h.rbac()
        .assign_role(
            &sys,
            &hearth::rbac::AssignRoleRequest {
                subject: Subject::User(user.id().clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign role");

    let session = h
        .identity()
        .create_session(
            &sys,
            user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create session");
    let sys_token = h
        .identity()
        .issue_tokens(&sys, user.id(), session.id())
        .expect("issue tokens")
        .access_token()
        .to_string();

    let (realm_b, _) = setup_realm_admin(&h, "sys-target").await;
    let resp = build_app(&h)
        .oneshot(req(
            "GET",
            format!("/admin/realms/{}", realm_b.as_uuid()),
            &sys_token,
            &sys,
            "",
        ))
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "system realm admin must be able to GET any tenant realm"
    );
}

/// A realm admin must be able to read their own realm.
#[tokio::test]
async fn own_realm_admin_can_get_own_realm() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm_a, token_a) = setup_realm_admin(&h, "own-realm").await;

    let resp = build_app(&h)
        .oneshot(req(
            "GET",
            format!("/admin/realms/{}", realm_a.as_uuid()),
            &token_a,
            &realm_a,
            "",
        ))
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "realm admin must be able to GET their own realm"
    );
}

// ─── GET /admin/realms visibility (audit 2026-08-28 §4.1#2) ──────────────────
// The gRPC ListRealms twin filters: system-realm admins see every realm,
// regular realm admins see only their own. The REST handler returned every
// tenant to any realm admin.

/// Creates an admin in the system realm and returns its access token.
fn system_admin_token(h: &common::TestHarness, suffix: &str) -> String {
    let sys = system_realm_id();
    h.rbac().seed_realm(&sys).expect("seed system rbac");
    let user = h
        .identity()
        .create_admin_user(&hearth::identity::CreateUserRequest {
            email: format!("sys-list-{suffix}@test.example"),
            display_name: "SysAdmin".into(),
            first_name: "Sys".into(),
            last_name: "Admin".into(),
            attributes: Default::default(),
        })
        .expect("create system admin");
    let role = h
        .rbac()
        .get_role_by_name(&sys, "realm.admin")
        .expect("lookup role")
        .expect("realm.admin role exists after seed");
    h.rbac()
        .assign_role(
            &sys,
            &hearth::rbac::AssignRoleRequest {
                subject: Subject::User(user.id().clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign role");
    let session = h
        .identity()
        .create_session(
            &sys,
            user.id(),
            &hearth::identity::SessionContext::default(),
        )
        .expect("create session");
    h.identity()
        .issue_tokens(&sys, user.id(), session.id())
        .expect("issue tokens")
        .access_token()
        .to_string()
}

/// Reads the realm IDs out of a `GET /admin/realms` response body.
async fn listed_realm_ids(resp: axum::response::Response) -> Vec<String> {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("parse JSON");
    body["items"]
        .as_array()
        .expect("items array")
        .iter()
        .map(|r| r["id"].as_str().expect("realm id").to_string())
        .collect()
}

/// A tenant realm admin must see only their own realm — not every tenant.
#[tokio::test]
async fn list_realms_returns_only_callers_realm() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm_a, token_a) = setup_realm_admin(&h, "list-a").await;
    let (realm_b, _) = setup_realm_admin(&h, "list-b").await;

    let resp = build_app(&h)
        .oneshot(req("GET", "/admin/realms".into(), &token_a, &realm_a, ""))
        .await
        .expect("request");
    assert_eq!(resp.status(), StatusCode::OK);

    let ids = listed_realm_ids(resp).await;
    assert!(
        ids.contains(&realm_a.as_uuid().to_string()),
        "caller's own realm must be listed"
    );
    assert!(
        !ids.contains(&realm_b.as_uuid().to_string()),
        "a tenant realm admin must not see other tenants (audit §4.1#2); got {ids:?}"
    );
    assert_eq!(
        ids.len(),
        1,
        "a tenant realm admin sees exactly their own realm; got {ids:?}"
    );
}

/// The system-realm operator keeps full visibility.
#[tokio::test]
async fn system_realm_admin_lists_all_realms() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm_a, _) = setup_realm_admin(&h, "syslist-a").await;
    let (realm_b, _) = setup_realm_admin(&h, "syslist-b").await;
    let sys = system_realm_id();
    let sys_token = system_admin_token(&h, "syslist");

    let resp = build_app(&h)
        .oneshot(req("GET", "/admin/realms".into(), &sys_token, &sys, ""))
        .await
        .expect("request");
    assert_eq!(resp.status(), StatusCode::OK);

    let ids = listed_realm_ids(resp).await;
    for realm in [&realm_a, &realm_b] {
        assert!(
            ids.contains(&realm.as_uuid().to_string()),
            "system realm admin must see every tenant; missing {realm:?} in {ids:?}"
        );
    }
}
