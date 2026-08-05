#![allow(clippy::unwrap_used, clippy::assertions_on_constants)]
//! HEA-2032 regression: three SCIM defects confirmed and fixed.
//!
//! ## Defect 1 — Unbounded materialization DoS
//!
//! `list_users` / `list_groups` materialised the entire realm before slicing,
//! so `?count=1` triggered O(realm-size) storage scans and heap allocations.
//! Fix: break the scan loop when `all_items.len() >= SCIM_MAX_SCAN_LIMIT`.
//!
//! Importing `SCIM_MAX_SCAN_LIMIT` from `hearth::abuse` causes a compile error
//! on unpatched trees, so this file itself is the "red" gate for defect 1.
//!
//! ## Defect 2 — Unscoped provisioning token can disable realm admins
//!
//! A SCIM bearer token could PATCH `active=false` or DELETE any user in the
//! realm, including realm admins, enabling realm takeover. Fix: when acting
//! via a SCIM bearer token, refuse mutating operations on principals whose
//! effective permissions include `hearth.admin` or `hearth.users.admin`.
//!
//! ## Defect 3 — Admin-JWT SCIM path unthrottled
//!
//! `check_scim_rate_limit` was called only in the SCIM-token branch; the
//! admin-JWT fallback path bypassed the limiter entirely. Fix: call the same
//! limiter in both branches.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::abuse::SCIM_MAX_SCAN_LIMIT; // compile error on unpatched tree — defect 1 gate
use hearth::core::{RealmId, UserId};
use hearth::identity::{
    CreateRealmRequest, CreateUserRequest, RealmConfig, SessionContext, UpdateRealmRequest,
};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

// ── helpers ───────────────────────────────────────────────────────────────────

fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn build_app(h: &common::TestHarness) -> axum::Router {
    router(Arc::new(AppState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
    )))
}

/// Build an app whose admin rate limiter allows at most 1 SCIM request per
/// realm per minute — tight enough to observe the limiter in a test.
fn build_app_tight_ratelimit(h: &common::TestHarness) -> axum::Router {
    router(Arc::new(
        AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc()).with_rate_limits(
            Some(1),
            None,
            None,
        ),
    ))
}

/// Create a realm, set a SCIM bearer token on it, and return (realm_id, plaintext_token).
fn setup_scim_realm(h: &common::TestHarness, suffix: &str) -> (RealmId, String) {
    let token = format!("hea-2032-scim-token-{suffix}");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("hea-2032-scim-{suffix}"),
            config: None,
        })
        .expect("create realm");
    h.identity()
        .update_realm(
            realm.id(),
            &UpdateRealmRequest {
                config: Some(RealmConfig {
                    scim_bearer_token_hash: Some(sha256_hex(&token)),
                    ..RealmConfig::default()
                }),
                ..UpdateRealmRequest::default()
            },
        )
        .expect("set scim token");
    (realm.id().clone(), token)
}

/// Create a realm with NO scim bearer token (admin-JWT fallback active).
/// Seeds RBAC, creates an admin user, returns (realm_id, access_token).
fn setup_admin_jwt_realm(h: &common::TestHarness, suffix: &str) -> (RealmId, String) {
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("hea-2032-jwt-{suffix}"),
            config: None,
        })
        .expect("create realm");
    let realm_id = realm.id().clone();
    h.rbac().seed_realm(&realm_id).expect("seed realm");
    let (user_id, token) =
        create_admin_user_with_token(h, &realm_id, &format!("admin@{suffix}.test"));
    let _ = user_id;
    (realm_id, token)
}

/// Create a user, assign the `realm.admin` role, and return (user_id, access_token).
/// Caller must have already seeded RBAC for the realm.
fn create_admin_user_with_token(
    h: &common::TestHarness,
    realm_id: &RealmId,
    email: &str,
) -> (UserId, String) {
    let user = h
        .identity()
        .create_user(
            realm_id,
            &CreateUserRequest {
                email: email.to_string(),
                display_name: "Admin".into(),
                first_name: "Admin".into(),
                last_name: "User".into(),
                attributes: Default::default(),
            },
        )
        .expect("create admin user");
    let role = h
        .rbac()
        .get_role_by_name(realm_id, "realm.admin")
        .expect("role lookup")
        .expect("realm.admin seeded role missing");
    h.rbac()
        .assign_role(
            realm_id,
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
        .create_session(realm_id, user.id(), &SessionContext::default())
        .expect("session");
    let token = h
        .identity()
        .issue_tokens(realm_id, user.id(), session.id())
        .expect("tokens")
        .access_token()
        .to_string();
    (user.id().clone(), token)
}

/// Create a plain (non-admin) user in the realm and return its ID.
fn create_plain_user(h: &common::TestHarness, realm_id: &RealmId, email: &str) -> UserId {
    h.identity()
        .create_user(
            realm_id,
            &CreateUserRequest {
                email: email.to_string(),
                display_name: "Plain".into(),
                first_name: "Plain".into(),
                last_name: "User".into(),
                attributes: Default::default(),
            },
        )
        .expect("create plain user")
        .id()
        .clone()
}

async fn scim_list(app: &axum::Router, realm_id: &RealmId, auth: &str, qs: &str) -> StatusCode {
    let uri = if qs.is_empty() {
        "/scim/v2/Users".to_string()
    } else {
        format!("/scim/v2/Users?{qs}")
    };
    let req = Request::builder()
        .method("GET")
        .uri(&uri)
        .header("x-realm-id", realm_id.as_uuid().to_string())
        .header("authorization", auth)
        .body(Body::empty())
        .expect("build list request");
    app.clone().oneshot(req).await.expect("oneshot").status()
}

async fn scim_patch_active(
    app: &axum::Router,
    realm_id: &RealmId,
    auth: &str,
    user_id: &UserId,
    active: bool,
) -> StatusCode {
    let body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "replace",
            "path": "active",
            "value": active
        }]
    });
    let req = Request::builder()
        .method("PATCH")
        .uri(format!("/scim/v2/Users/{}", user_id.as_uuid()))
        .header("content-type", "application/scim+json")
        .header("x-realm-id", realm_id.as_uuid().to_string())
        .header("authorization", auth)
        .body(Body::from(body.to_string()))
        .expect("build patch request");
    app.clone().oneshot(req).await.expect("oneshot").status()
}

async fn scim_delete(
    app: &axum::Router,
    realm_id: &RealmId,
    auth: &str,
    user_id: &UserId,
) -> StatusCode {
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/scim/v2/Users/{}", user_id.as_uuid()))
        .header("x-realm-id", realm_id.as_uuid().to_string())
        .header("authorization", auth)
        .body(Body::empty())
        .expect("build delete request");
    app.clone().oneshot(req).await.expect("oneshot").status()
}

async fn scim_put_user(
    app: &axum::Router,
    realm_id: &RealmId,
    auth: &str,
    user_id: &UserId,
    email: &str,
) -> StatusCode {
    let body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": email,
        "emails": [{"value": email, "primary": true}],
        "active": false,
        "name": {"givenName": "Admin", "familyName": "User"}
    });
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/scim/v2/Users/{}", user_id.as_uuid()))
        .header("content-type", "application/scim+json")
        .header("x-realm-id", realm_id.as_uuid().to_string())
        .header("authorization", auth)
        .body(Body::from(body.to_string()))
        .expect("build put request");
    app.clone().oneshot(req).await.expect("oneshot").status()
}

// ── Defect 1: scan cap constant ───────────────────────────────────────────────

/// The scan-cap constant must exist (compile-time gate) and be ≤ 1 000 so the
/// fix actually bounds memory use.
#[test]
fn scim_max_scan_limit_is_declared_and_bounded() {
    assert!(
        SCIM_MAX_SCAN_LIMIT > 0 && SCIM_MAX_SCAN_LIMIT <= 1_000,
        "SCIM_MAX_SCAN_LIMIT must be in (0, 1000] — got {SCIM_MAX_SCAN_LIMIT}"
    );
}

/// `GET /scim/v2/Users?count=1` must return exactly 1 resource and a correct
/// `totalResults` for a small realm.  This verifies correctness under the cap.
#[tokio::test]
async fn scim_list_users_count_pagination_correct() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm_id, token) = setup_scim_realm(&h, "pagination");
    let app = build_app(&h);
    let auth = format!("Bearer {token}");

    // Create 3 users so pagination is meaningful.
    for i in 0..3u32 {
        h.identity()
            .create_user(
                &realm_id,
                &CreateUserRequest {
                    email: format!("user{i}@pagination.test"),
                    display_name: format!("User {i}"),
                    first_name: format!("User{i}"),
                    last_name: "Test".into(),
                    attributes: Default::default(),
                },
            )
            .expect("create user");
    }

    // count=1 must return exactly 1 resource.
    let req = Request::builder()
        .method("GET")
        .uri("/scim/v2/Users?count=1&startIndex=1")
        .header("x-realm-id", realm_id.as_uuid().to_string())
        .header("authorization", &auth)
        .body(Body::empty())
        .expect("build list request");
    let resp = app.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
    let val: Value = serde_json::from_slice(&bytes).expect("json");
    let resources = val["Resources"].as_array().expect("Resources array");
    assert_eq!(
        resources.len(),
        1,
        "count=1 must return exactly 1 resource, got {} — body: {val}",
        resources.len()
    );
    let total = val["totalResults"].as_u64().expect("totalResults");
    assert_eq!(
        total, 3,
        "totalResults must equal actual user count (3), got {total}"
    );
}

// ── Defect 2: SCIM token cannot act on admin principals ───────────────────────

/// SCIM bearer token must NOT be able to PATCH `active=false` on a realm admin.
/// Before the fix this returned 200; after the fix it returns 403.
#[tokio::test]
async fn scim_token_cannot_disable_realm_admin() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm_id, scim_token) = setup_scim_realm(&h, "disable-admin");
    let app = build_app(&h);

    h.rbac().seed_realm(&realm_id).expect("seed realm");
    let (admin_id, _) = create_admin_user_with_token(&h, &realm_id, "admin@disable-admin.test");

    let status = scim_patch_active(
        &app,
        &realm_id,
        &format!("Bearer {scim_token}"),
        &admin_id,
        false,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "SCIM token must not disable a realm admin — got {status}"
    );

    // Admin user must still be active.
    let user = h
        .identity()
        .get_user(&realm_id, &admin_id)
        .expect("lookup")
        .expect("user exists");
    assert!(
        matches!(user.status(), hearth::identity::UserStatus::Active),
        "admin must remain active after rejected SCIM PATCH"
    );
}

/// SCIM bearer token must NOT be able to DELETE a realm admin.
#[tokio::test]
async fn scim_token_cannot_delete_realm_admin() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm_id, scim_token) = setup_scim_realm(&h, "delete-admin");
    let app = build_app(&h);

    h.rbac().seed_realm(&realm_id).expect("seed realm");
    let (admin_id, _) = create_admin_user_with_token(&h, &realm_id, "admin@delete-admin.test");

    let status = scim_delete(&app, &realm_id, &format!("Bearer {scim_token}"), &admin_id).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "SCIM token must not delete a realm admin — got {status}"
    );

    // Admin must still exist.
    assert!(
        h.identity()
            .get_user(&realm_id, &admin_id)
            .expect("lookup")
            .is_some(),
        "admin must still exist after rejected SCIM DELETE"
    );
}

/// SCIM bearer token must NOT be able to full-replace (PUT) a realm admin.
#[tokio::test]
async fn scim_token_cannot_replace_realm_admin() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm_id, scim_token) = setup_scim_realm(&h, "replace-admin");
    let app = build_app(&h);

    h.rbac().seed_realm(&realm_id).expect("seed realm");
    let (admin_id, _) = create_admin_user_with_token(&h, &realm_id, "admin@replace-admin.test");

    let status = scim_put_user(
        &app,
        &realm_id,
        &format!("Bearer {scim_token}"),
        &admin_id,
        "admin@replace-admin.test",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "SCIM token must not PUT-replace a realm admin — got {status}"
    );
}

/// SCIM bearer token CAN still manage non-admin users (regression guard).
/// The protection must be scoped to admin principals only.
#[tokio::test]
async fn scim_token_can_manage_non_admin_user() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm_id, scim_token) = setup_scim_realm(&h, "nonadmin-ok");
    let app = build_app(&h);

    h.rbac().seed_realm(&realm_id).expect("seed realm");
    let plain_id = create_plain_user(&h, &realm_id, "plain@nonadmin-ok.test");

    // PATCH active=false on a plain user must succeed.
    let status = scim_patch_active(
        &app,
        &realm_id,
        &format!("Bearer {scim_token}"),
        &plain_id,
        false,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "SCIM token must still manage non-admin users — got {status}"
    );
}

// ── Defect 3: admin-JWT path must share the rate limiter ─────────────────────

/// With a rate limit of 1 SCIM request per realm per minute, the second
/// request through the admin-JWT fallback path must return 429.
///
/// Before the fix the second call was allowed (no limiter on the JWT path);
/// after the fix both paths share the same per-realm bucket.
#[tokio::test]
async fn scim_admin_jwt_path_is_rate_limited() {
    let h = common::TestHarness::embedded().await.expect("harness");
    // App with an extremely tight rate limit (1/min per realm).
    let app = build_app_tight_ratelimit(&h);

    let (realm_id, jwt) = setup_admin_jwt_realm(&h, "ratelimit");

    let auth = format!("Bearer {jwt}");

    // First request — must be allowed.
    let s1 = scim_list(&app, &realm_id, &auth, "").await;
    assert_eq!(
        s1,
        StatusCode::OK,
        "first SCIM JWT request must succeed (got {s1})"
    );

    // Second request in the same window — must be rate-limited (429).
    let s2 = scim_list(&app, &realm_id, &auth, "").await;
    assert_eq!(
        s2,
        StatusCode::TOO_MANY_REQUESTS,
        "second SCIM JWT request in same window must hit 429 — got {s2} \
         (before HEA-2032 fix the admin-JWT path bypassed the rate limiter)"
    );
}
