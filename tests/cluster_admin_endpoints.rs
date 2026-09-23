//! Integration tests for `/admin/cluster/*` HTTP endpoints.
//!
//! Covers:
//! - AC-4: 401 without auth
//! - AC-5: 403 non-admin (no `hearth.admin` permission)
//! - AC-6: 403 for tenant-realm admin token (HEA-763 — privilege escalation guard)
//! - AC-7: 503 single-node responses with a valid system-realm admin token
//!
//! AC-1/2/3 (multi-node Raft behaviour) are deferred to HEA-738.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hearth::core::RealmId;
use hearth::identity::{CreateUserRequest, SessionContext};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use tower::ServiceExt as _;
use uuid::Uuid;

async fn build_app(harness: &common::TestHarness) -> axum::Router {
    let state = Arc::new(AppState::new(
        harness.identity_arc(),
        harness.rbac_arc(),
        harness.audit_arc(),
    ));
    router(state)
}

async fn issue_token(
    harness: &common::TestHarness,
    realm: &RealmId,
    email: &str,
    with_admin: bool,
) -> String {
    let user = harness
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: email.into(),
                display_name: "T".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    if with_admin {
        let role = harness
            .rbac()
            .get_role_by_name(realm, "realm.admin")
            .expect("lookup")
            .expect("seeded");
        harness
            .rbac()
            .assign_role(
                realm,
                &AssignRoleRequest {
                    subject: Subject::User(user.id().clone()),
                    role_id: role.id,
                    scope: Scope::Realm,
                    assigned_by: None,
                },
            )
            .expect("assign admin");
    }

    let session = harness
        .identity()
        .create_session(realm, user.id(), &SessionContext::default())
        .expect("session");
    harness
        .identity()
        .issue_tokens(realm, user.id(), session.id())
        .expect("issue")
        .access_token()
        .to_string()
}

/// Issue an admin token scoped to the **system realm** (nil UUID).
///
/// Cluster admin endpoints require a system-realm token (HEA-763). This
/// helper creates an admin user in the system realm, assigns `realm.admin`,
/// and returns a bearer token valid for that realm.
async fn issue_system_token(harness: &common::TestHarness, email: &str) -> String {
    let system_realm = RealmId::new(Uuid::nil());
    harness
        .rbac()
        .seed_realm(&system_realm)
        .expect("seed system realm");

    let user = harness
        .identity()
        .create_admin_user(&CreateUserRequest {
            email: email.into(),
            display_name: "SysAdmin".into(),
            first_name: String::new(),
            last_name: String::new(),
            attributes: Default::default(),
        })
        .expect("create admin user");

    let role = harness
        .rbac()
        .get_role_by_name(&system_realm, "realm.admin")
        .expect("lookup")
        .expect("seeded");
    harness
        .rbac()
        .assign_role(
            &system_realm,
            &AssignRoleRequest {
                subject: Subject::User(user.id().clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign admin");

    let session = harness
        .identity()
        .create_session(&system_realm, user.id(), &SessionContext::default())
        .expect("session");
    harness
        .identity()
        .issue_tokens(&system_realm, user.id(), session.id())
        .expect("issue")
        .access_token()
        .to_string()
}

// ── AC-4: 401 without Authorization header ────────────────────────────────────

#[tokio::test]
async fn bootstrap_returns_401_without_auth() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/cluster/bootstrap")
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn status_returns_401_without_auth() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/cluster/status")
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn transfer_leadership_returns_401_without_auth() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/cluster/transfer-leadership")
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ── AC-5: 403 for non-admin token ─────────────────────────────────────────────

#[tokio::test]
async fn bootstrap_returns_403_for_non_admin() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = issue_token(&h, &realm, "user@example.com", false).await;
    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/cluster/bootstrap")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn status_returns_403_for_non_admin() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = issue_token(&h, &realm, "user@example.com", false).await;
    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/cluster/status")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn transfer_leadership_returns_403_for_non_admin() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = issue_token(&h, &realm, "user@example.com", false).await;
    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/cluster/transfer-leadership")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ── AC-6: 403 for tenant-realm admin token (HEA-763) ─────────────────────────
//
// A tenant admin with `hearth.admin` permission MUST NOT be able to invoke
// cluster-level operations. The system-realm guard fires before the cluster
// check, so all three endpoints return 403 regardless of single/multi-node.

#[tokio::test]
async fn bootstrap_returns_403_for_tenant_realm_admin() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = issue_token(&h, &realm, "tenant-admin@example.com", true).await;
    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/cluster/bootstrap")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn status_returns_403_for_tenant_realm_admin() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = issue_token(&h, &realm, "tenant-admin@example.com", true).await;
    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/cluster/status")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn transfer_leadership_returns_403_for_tenant_realm_admin() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = issue_token(&h, &realm, "tenant-admin@example.com", true).await;
    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/cluster/transfer-leadership")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ── AC-7: Single-node 503 for system-realm admin ──────────────────────────────
//
// A valid system-realm admin token passes the realm guard and reaches the
// cluster check, which returns 503 because the test harness has no Raft engine.

#[tokio::test]
async fn bootstrap_returns_503_in_single_node_mode() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let system_realm = RealmId::new(Uuid::nil());
    let token = issue_system_token(&h, "admin@example.com").await;
    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/cluster/bootstrap")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", system_realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn status_returns_503_in_single_node_mode() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let system_realm = RealmId::new(Uuid::nil());
    let token = issue_system_token(&h, "admin@example.com").await;
    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/cluster/status")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", system_realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn transfer_leadership_returns_503_in_single_node_mode() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let system_realm = RealmId::new(Uuid::nil());
    let token = issue_system_token(&h, "admin@example.com").await;
    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/cluster/transfer-leadership")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", system_realm.as_uuid().to_string())
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

// ── Task 26.60: a targeted transfer is refused, not silently ignored ──────────
//
// openraft 0.9.25 cannot hand leadership to a chosen node, so a request that
// names one must be refused before anything happens — never answered with a
// step-down to whichever voter wins. The check is request validation, so it
// fires in single-node mode too, and therefore before any Raft side effect.

async fn post_transfer(app: axum::Router, token: &str, body: &'static str) -> (StatusCode, String) {
    let system_realm = RealmId::new(Uuid::nil());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/cluster/transfer-leadership")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", system_realm.as_uuid().to_string())
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("req"),
        )
        .await
        .expect("resp");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .expect("body");
    (status, String::from_utf8(bytes.to_vec()).expect("utf8"))
}

#[tokio::test]
async fn transfer_leadership_rejects_target_node_id_with_422() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let token = issue_system_token(&h, "admin@example.com").await;
    let app = build_app(&h).await;

    let (status, body) = post_transfer(app, &token, r#"{"target_node_id": 2}"#).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a named target cannot be honoured and must be refused; body: {body}"
    );
    let json: serde_json::Value = serde_json::from_str(&body).expect("json body");
    let error = json["error"].as_str().expect("error string");
    assert!(
        error.contains("targeted leadership transfer is not supported"),
        "error must say why the request was refused; got {error:?}"
    );
}

#[tokio::test]
async fn transfer_leadership_without_target_is_not_refused() {
    // `null`, an absent field and an empty body all mean "no target" and must
    // not be refused — they reach the cluster check (503 here: no Raft engine).
    let h = common::TestHarness::embedded().await.expect("harness");
    let token = issue_system_token(&h, "admin@example.com").await;

    for body in [r#"{"target_node_id": null}"#, "{}", ""] {
        let app = build_app(&h).await;
        let (status, resp_body) = post_transfer(app, &token, body).await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "body {body:?} names no target and must not be refused; got {resp_body}"
        );
    }
}
