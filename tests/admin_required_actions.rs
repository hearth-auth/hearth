//! Integration tests for the required-actions admin API (HEA-807).
//!
//! Covers AC-6, AC-7, AC-8:
//! - PATCH /admin/realms/{realm}/users/{id}/required-actions — assign/remove
//! - PATCH /admin/realms/{realm}/config — default_required_actions

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hearth::audit::{AuditAction, AuditQuery};
use hearth::core::RealmId;
use hearth::identity::{CreateUserRequest, DcrPolicy, SessionContext};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use tower::ServiceExt as _;

// ===== Helpers =====

fn build_app(h: &common::TestHarness) -> axum::Router {
    router(Arc::new(AppState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
    )))
}

async fn admin_token(h: &common::TestHarness, realm: &RealmId) -> String {
    admin_token_with_email(h, realm, "admin@ra-test.example").await
}

async fn admin_token_with_email(h: &common::TestHarness, realm: &RealmId, email: &str) -> String {
    let user = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: email.into(),
                display_name: "Admin".into(),
                first_name: "Admin".into(),
                last_name: "User".into(),
                attributes: Default::default(),
            },
        )
        .expect("create admin");

    let role = h
        .rbac()
        .get_role_by_name(realm, "realm.admin")
        .expect("lookup")
        .expect("realm.admin seeded");
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
        .expect("assign admin role");

    let session = h
        .identity()
        .create_session(realm, user.id(), &SessionContext::default())
        .expect("session");
    h.identity()
        .issue_tokens(realm, user.id(), session.id())
        .expect("issue")
        .access_token()
        .to_string()
}

async fn non_admin_token(h: &common::TestHarness, realm: &RealmId) -> String {
    let user = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: "nonadmin@ra-test.example".into(),
                display_name: "Non-Admin".into(),
                first_name: "Non".into(),
                last_name: "Admin".into(),
                attributes: Default::default(),
            },
        )
        .expect("create non-admin");

    let session = h
        .identity()
        .create_session(realm, user.id(), &SessionContext::default())
        .expect("session");
    h.identity()
        .issue_tokens(realm, user.id(), session.id())
        .expect("issue")
        .access_token()
        .to_string()
}

async fn create_target_user(h: &common::TestHarness, realm: &RealmId) -> String {
    create_target_user_with_email(h, realm, "target@ra-test.example").await
}

async fn create_target_user_with_email(
    h: &common::TestHarness,
    realm: &RealmId,
    email: &str,
) -> String {
    let user = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: email.into(),
                display_name: "Target User".into(),
                first_name: "Target".into(),
                last_name: "User".into(),
                attributes: Default::default(),
            },
        )
        .expect("create target user");
    user.id().as_uuid().to_string()
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body bytes");
    serde_json::from_slice(&bytes).expect("parse JSON body")
}

// ===== required-actions endpoint tests =====

#[tokio::test]
async fn assign_adds_action_to_user() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;
    let uid = create_target_user(&h, &realm).await;
    let realm_uuid = realm.as_uuid().to_string();

    let app = build_app(&h);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!(
                    "/admin/realms/{realm_uuid}/users/{uid}/required-actions"
                ))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm_uuid.clone())
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"add":["VERIFY_EMAIL"],"remove":[]}"#))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let actions = body["required_actions"]
        .as_array()
        .expect("required_actions array");
    assert!(
        actions.iter().any(|v| v.as_str() == Some("VERIFY_EMAIL")),
        "VERIFY_EMAIL must appear in required_actions; got {actions:?}"
    );
}

#[tokio::test]
async fn remove_removes_action_from_user() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;
    let uid = create_target_user(&h, &realm).await;
    let realm_uuid = realm.as_uuid().to_string();
    let app = build_app(&h);

    // First assign VERIFY_EMAIL.
    app.clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!(
                    "/admin/realms/{realm_uuid}/users/{uid}/required-actions"
                ))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm_uuid.clone())
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"add":["VERIFY_EMAIL"],"remove":[]}"#))
                .expect("build"),
        )
        .await
        .expect("assign");

    // Now remove it.
    let resp = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!(
                    "/admin/realms/{realm_uuid}/users/{uid}/required-actions"
                ))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm_uuid.clone())
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"add":[],"remove":["VERIFY_EMAIL"]}"#))
                .expect("build"),
        )
        .await
        .expect("remove");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    // required_actions omitted when empty (skip_serializing_if) or present as []
    let actions = body["required_actions"].as_array();
    let is_empty = actions.map_or(true, |v| v.is_empty());
    assert!(
        is_empty,
        "required_actions must be empty after remove; got {body:?}"
    );
}

#[tokio::test]
async fn non_admin_gets_403() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = non_admin_token(&h, &realm).await;
    let uid = create_target_user(&h, &realm).await;
    let realm_uuid = realm.as_uuid().to_string();

    let app = build_app(&h);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!(
                    "/admin/realms/{realm_uuid}/users/{uid}/required-actions"
                ))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm_uuid.clone())
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"add":["VERIFY_EMAIL"],"remove":[]}"#))
                .expect("build"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "non-admin must receive 403"
    );
}

#[tokio::test]
async fn unknown_action_type_returns_400() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;
    let uid = create_target_user(&h, &realm).await;
    let realm_uuid = realm.as_uuid().to_string();

    let app = build_app(&h);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!(
                    "/admin/realms/{realm_uuid}/users/{uid}/required-actions"
                ))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm_uuid.clone())
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"add":["UNKNOWN_ACTION"],"remove":[]}"#))
                .expect("build"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "unknown action type must return 400"
    );
    let body = body_json(resp).await;
    assert!(
        body["error"]
            .as_str()
            .map(|s| s.contains("UNKNOWN_ACTION"))
            .unwrap_or(false),
        "error message must mention the bad value; got {body:?}"
    );
}

// ===== Realm config endpoint tests =====

#[tokio::test]
async fn patch_realm_config_sets_default_required_actions() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;
    let realm_uuid = realm.as_uuid().to_string();

    let app = build_app(&h);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/admin/realms/{realm_uuid}/config"))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm_uuid.clone())
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"default_required_actions":["VERIFY_EMAIL","UPDATE_PASSWORD"]}"#,
                ))
                .expect("build"),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::OK);

    // Verify it persisted in the identity engine.
    let updated_realm = h
        .identity()
        .get_realm(&realm)
        .expect("get")
        .expect("exists");
    let defaults = updated_realm.config().default_required_actions.clone();
    assert_eq!(
        defaults.len(),
        2,
        "realm config must have 2 default_required_actions; got {defaults:?}"
    );
}

#[tokio::test]
async fn patch_realm_config_unknown_action_returns_400() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;
    let realm_uuid = realm.as_uuid().to_string();

    let app = build_app(&h);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/admin/realms/{realm_uuid}/config"))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm_uuid.clone())
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"default_required_actions":["BOGUS"]}"#))
                .expect("build"),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ===== AC-8: RequiredActionAssigned audit event =====

/// PATCH /required-actions with `add` must emit a RequiredActionAssigned audit
/// event for each added action with the correct action_type in the metadata.
#[tokio::test]
async fn assign_action_emits_required_action_assigned_audit_event() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;
    let uid = create_target_user(&h, &realm).await;
    let realm_uuid = realm.as_uuid().to_string();

    let app = build_app(&h);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!(
                    "/admin/realms/{realm_uuid}/users/{uid}/required-actions"
                ))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm_uuid.clone())
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"add":["VERIFY_EMAIL"],"remove":[]}"#))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(resp.status(), StatusCode::OK, "PATCH must succeed");

    let events = h
        .audit()
        .query(&AuditQuery {
            action: Some(AuditAction::RequiredActionAssigned),
            ..AuditQuery::for_realm(realm.clone())
        })
        .expect("audit query");

    let matched = events.iter().any(|e| {
        e.action == AuditAction::RequiredActionAssigned
            && e.resource_id == uid
            && e.metadata
                .as_ref()
                .and_then(|m| m.get("action_type"))
                .and_then(|v| v.as_str())
                == Some("VERIFY_EMAIL")
    });
    assert!(
        matched,
        "RequiredActionAssigned(VERIFY_EMAIL) must be in audit log; events: {events:?}"
    );
}

// ===== BOLA regression tests (HEA-816) =====

/// Admin of realm A must receive 403 when targeting a user in realm B.
/// Regression for FINDING-2 from HEA-810: cross-realm BOLA in required-actions handler.
#[tokio::test]
#[allow(clippy::similar_names)]
async fn cross_realm_patch_user_required_actions_is_forbidden() {
    let h = common::TestHarness::embedded().await.expect("harness");

    let realm_a = h.create_realm();
    h.rbac().seed_realm(&realm_a).expect("seed realm_a");

    let realm_b = h.create_realm();
    h.rbac().seed_realm(&realm_b).expect("seed realm_b");

    let admin_a_token = admin_token_with_email(&h, &realm_a, "bola-admin-a@ra-test.example").await;
    let uid_b = create_target_user_with_email(&h, &realm_b, "bola-target-b@ra-test.example").await;

    let realm_a_uuid = realm_a.as_uuid().to_string();
    let realm_b_uuid = realm_b.as_uuid().to_string();

    let app = build_app(&h);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!(
                    "/admin/realms/{realm_b_uuid}/users/{uid_b}/required-actions"
                ))
                .header("Authorization", format!("Bearer {admin_a_token}"))
                .header("X-Realm-ID", realm_a_uuid)
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"add":["VERIFY_EMAIL"],"remove":[]}"#))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "realm-A admin must not modify users in realm-B (cross-realm BOLA)"
    );
}

/// Admin of realm A must receive 403 when patching realm B's config.
/// Regression for FINDING-2 from HEA-810: cross-realm BOLA in realm-config handler.
#[tokio::test]
#[allow(clippy::similar_names)]
async fn cross_realm_patch_realm_config_is_forbidden() {
    let h = common::TestHarness::embedded().await.expect("harness");

    let realm_a = h.create_realm();
    h.rbac().seed_realm(&realm_a).expect("seed realm_a");

    let realm_b = h.create_realm();
    h.rbac().seed_realm(&realm_b).expect("seed realm_b");

    let admin_a_token =
        admin_token_with_email(&h, &realm_a, "bola-cfg-admin-a@ra-test.example").await;

    let realm_a_uuid = realm_a.as_uuid().to_string();
    let realm_b_uuid = realm_b.as_uuid().to_string();

    let app = build_app(&h);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/admin/realms/{realm_b_uuid}/config"))
                .header("Authorization", format!("Bearer {admin_a_token}"))
                .header("X-Realm-ID", realm_a_uuid)
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"default_required_actions":["VERIFY_EMAIL"]}"#,
                ))
                .expect("build request"),
        )
        .await
        .expect("oneshot");

    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "realm-A admin must not modify config of realm-B (cross-realm BOLA)"
    );
}

// ===== HEA-2003: dcr_policy via PATCH /config, and the issuance-plane path =====

/// `PATCH /config` with `dcr_policy` must persist the new policy on the realm.
/// This is the seeder's lever for the issuance plane: it flips the dev-realm to
/// `authenticated` so it can register a confidential `client_credentials` client
/// over `POST /register`, then flips it back to `disabled` (HEA-2003).
#[tokio::test]
async fn patch_realm_config_sets_dcr_policy() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;
    let realm_uuid = realm.as_uuid().to_string();
    let app = build_app(&h);

    // Default realm config leaves dcr_policy unset (treated as Disabled).
    assert!(
        h.identity()
            .get_realm(&realm)
            .expect("get")
            .expect("exists")
            .config()
            .dcr_policy
            .is_none(),
        "precondition: dcr_policy starts unset"
    );

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/admin/realms/{realm_uuid}/config"))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm_uuid.clone())
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"dcr_policy":"authenticated"}"#))
                .expect("build"),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        h.identity()
            .get_realm(&realm)
            .expect("get")
            .expect("exists")
            .config()
            .dcr_policy,
        Some(DcrPolicy::Authenticated),
        "dcr_policy must persist as Authenticated after PATCH"
    );

    // And flipping it back to disabled (the seeder's restore step) must work.
    let resp = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/admin/realms/{realm_uuid}/config"))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm_uuid.clone())
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"dcr_policy":"disabled"}"#))
                .expect("build"),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        h.identity()
            .get_realm(&realm)
            .expect("get")
            .expect("exists")
            .config()
            .dcr_policy,
        Some(DcrPolicy::Disabled),
        "dcr_policy must persist as Disabled after restore"
    );
}

/// An unknown `dcr_policy` value must be rejected with 400, not silently ignored.
#[tokio::test]
async fn patch_realm_config_unknown_dcr_policy_returns_400() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;
    let realm_uuid = realm.as_uuid().to_string();
    let app = build_app(&h);

    let resp = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/admin/realms/{realm_uuid}/config"))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm_uuid.clone())
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"dcr_policy":"wide_open"}"#))
                .expect("build"),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// End-to-end proof of the HEA-2003 issuance path: enable DCR → register a
/// confidential `client_credentials` client via `POST /register` (the only
/// server path that returns a secret) → mint over the **production**
/// `POST /token` grant. This is exactly what the seeder provisions and the
/// saturation harness exercises at run time — with no dev-only endpoint.
#[tokio::test]
async fn dcr_client_credentials_issuance_path_works_end_to_end() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm).await;
    let realm_uuid = realm.as_uuid().to_string();
    let app = build_app(&h);

    // 1. Seeder: flip DCR to authenticated.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/admin/realms/{realm_uuid}/config"))
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm_uuid.clone())
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"dcr_policy":"authenticated"}"#))
                .expect("build"),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::OK);

    // 2. Seeder: register a confidential client_credentials client via DCR.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm_uuid.clone())
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"client_name":"hearth-loadtest-cc","grant_types":["client_credentials"]}"#,
                ))
                .expect("build"),
        )
        .await
        .expect("oneshot");
    assert_eq!(resp.status(), StatusCode::CREATED);
    let reg = body_json(resp).await;
    let cc_client_id = reg["client_id"].as_str().expect("client_id").to_string();
    let cc_secret = reg["client_secret"]
        .as_str()
        .expect("DCR must return a generated client_secret")
        .to_string();
    assert!(!cc_secret.is_empty());

    // 3. Harness (run time): mint over the production POST /token grant. No
    //    /dev/* endpoint involved.
    let token_body = serde_json::json!({
        "grant_type": "client_credentials",
        "client_id": cc_client_id,
        "client_secret": cc_secret,
        // DCR clients are ThirdParty and must request >=1 scope; openid is always legal.
        "scope": "openid",
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("X-Realm-ID", realm_uuid.clone())
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&token_body).expect("serialize")))
                .expect("build"),
        )
        .await
        .expect("oneshot");
    let status = resp.status();
    let tok = body_json(resp).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "client_credentials mint over POST /token must succeed; body={tok}"
    );
    assert!(
        tok["access_token"].as_str().is_some_and(|s| !s.is_empty()),
        "POST /token must return a signed access token: {tok}"
    );
}
