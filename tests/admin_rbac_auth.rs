//! Integration tests for admin HTTP auth (permission-gated via `hearth.admin`
//! and the granular sub-permissions `hearth.users.admin`, `hearth.clients.admin`,
//! `hearth.realm.admin`).

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hearth::core::RealmId;
use hearth::identity::{CreateUserRequest, SessionContext};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, CreateGroupRequest, Scope, Subject};
use tower::ServiceExt as _;

async fn build_app(harness: &common::TestHarness) -> axum::Router {
    let state = Arc::new(AppState::new(
        harness.identity_arc(),
        harness.rbac_arc(),
        harness.audit_arc(),
    ));
    router(state)
}

async fn issue_token_for(
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

fn forge_admin_permission_claim(token: &str) -> String {
    let mut parts = token.split('.').collect::<Vec<_>>();
    assert_eq!(parts.len(), 3, "JWT must have three parts");

    let payload = URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("decode payload segment");
    let mut payload_json: serde_json::Value =
        serde_json::from_slice(&payload).expect("parse payload JSON");

    let claims = payload_json
        .as_object_mut()
        .expect("token payload must be a JSON object");
    claims.insert(
        "permissions".to_string(),
        serde_json::json!(["hearth.admin"]),
    );

    let tampered_payload = serde_json::to_vec(&payload_json).expect("serialize payload JSON");
    let tampered_payload_b64 = URL_SAFE_NO_PAD.encode(tampered_payload);
    parts[1] = tampered_payload_b64.as_str();

    parts.join(".")
}

#[tokio::test]
async fn permission_gated_allows_hearth_admin() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = issue_token_for(&h, &realm, "admin@example.com", true).await;
    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/roles")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn permission_gated_denies_non_admin() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = issue_token_for(&h, &realm, "user@example.com", false).await;
    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/roles")
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
async fn permission_gated_rejects_tampered_unsigned_admin_claim() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let non_admin = issue_token_for(&h, &realm, "user@example.com", false).await;
    let tampered = forge_admin_permission_claim(&non_admin);
    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/roles")
                .header("Authorization", format!("Bearer {tampered}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn unauthenticated_returns_401() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    let app = build_app(&h).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/roles")
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// Issues a token for a user assigned the named seed sub-admin role
/// (e.g. `"hearth.users.admin"`). The realm must already be seeded.
async fn issue_sub_admin_token(
    harness: &common::TestHarness,
    realm: &RealmId,
    email: &str,
    role_name: &str,
) -> String {
    let user = harness
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: email.into(),
                display_name: "SubAdmin".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let role = harness
        .rbac()
        .get_role_by_name(realm, role_name)
        .expect("lookup")
        .unwrap_or_else(|| panic!("seed role '{role_name}' not found — realm was seeded?"));
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
        .expect("assign role");

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

async fn http_get(app: axum::Router, token: &str, realm: &RealmId, uri: &str) -> StatusCode {
    app.oneshot(
        Request::builder()
            .method("GET")
            .uri(uri)
            .header("Authorization", format!("Bearer {token}"))
            .header("X-Realm-ID", realm.as_uuid().to_string())
            .body(Body::empty())
            .expect("req"),
    )
    .await
    .expect("resp")
    .status()
}

// ---------------------------------------------------------------------------
// HEA-1328: Granular sub-admin delegation tests
// ---------------------------------------------------------------------------

/// hearth.users.admin can reach user endpoints.
#[tokio::test]
async fn sub_admin_users_can_access_users_endpoint() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token =
        issue_sub_admin_token(&h, &realm, "usersadmin@example.com", "hearth.users.admin").await;
    let app = build_app(&h).await;

    let status = http_get(app, &token, &realm, "/admin/users").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "hearth.users.admin must be allowed on /admin/users"
    );
}

/// hearth.users.admin is denied on client endpoints.
#[tokio::test]
async fn sub_admin_users_denied_clients_endpoint() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token =
        issue_sub_admin_token(&h, &realm, "usersadmin2@example.com", "hearth.users.admin").await;
    let app = build_app(&h).await;

    let status = http_get(app, &token, &realm, "/admin/applications").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "hearth.users.admin must be denied on /admin/applications"
    );
}

/// hearth.users.admin is denied on realm-management endpoints.
#[tokio::test]
async fn sub_admin_users_denied_realm_endpoint() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token =
        issue_sub_admin_token(&h, &realm, "usersadmin3@example.com", "hearth.users.admin").await;
    let app = build_app(&h).await;

    let status = http_get(app, &token, &realm, "/admin/roles").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "hearth.users.admin must be denied on /admin/roles"
    );
}

/// hearth.clients.admin can reach client endpoints.
#[tokio::test]
async fn sub_admin_clients_can_access_clients_endpoint() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = issue_sub_admin_token(
        &h,
        &realm,
        "clientsadmin@example.com",
        "hearth.clients.admin",
    )
    .await;
    let app = build_app(&h).await;

    let status = http_get(app, &token, &realm, "/admin/applications").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "hearth.clients.admin must be allowed on /admin/applications"
    );
}

/// hearth.clients.admin is denied on user endpoints.
#[tokio::test]
async fn sub_admin_clients_denied_users_endpoint() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = issue_sub_admin_token(
        &h,
        &realm,
        "clientsadmin2@example.com",
        "hearth.clients.admin",
    )
    .await;
    let app = build_app(&h).await;

    let status = http_get(app, &token, &realm, "/admin/users").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "hearth.clients.admin must be denied on /admin/users"
    );
}

/// hearth.realm.admin can reach role-management endpoints.
#[tokio::test]
async fn sub_admin_realm_can_access_roles_endpoint() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token =
        issue_sub_admin_token(&h, &realm, "realmadmin@example.com", "hearth.realm.admin").await;
    let app = build_app(&h).await;

    let status = http_get(app, &token, &realm, "/admin/roles").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "hearth.realm.admin must be allowed on /admin/roles"
    );
}

/// hearth.realm.admin is denied on user endpoints.
#[tokio::test]
async fn sub_admin_realm_denied_users_endpoint() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token =
        issue_sub_admin_token(&h, &realm, "realmadmin2@example.com", "hearth.realm.admin").await;
    let app = build_app(&h).await;

    let status = http_get(app, &token, &realm, "/admin/users").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "hearth.realm.admin must be denied on /admin/users"
    );
}

// ---------------------------------------------------------------------------
// HEA-1679: hearth.agents.admin outer-gate allowlist regression tests
// ---------------------------------------------------------------------------
// Regression guard for HEA-SEC-11: tokens carrying ONLY `hearth.agents.admin`
// must pass the outer gate (extract_admin_auth) but still be denied on
// endpoints that require a different sub-permission.

/// Builds an Axum router identical to [`build_app`] but with agent identity
/// routes enabled so `/v1/agents` is registered.
async fn build_app_with_agent_routes(harness: &common::TestHarness) -> axum::Router {
    use hearth::protocol::http::AppState;
    let state = Arc::new(
        AppState::new(
            harness.identity_arc(),
            harness.rbac_arc(),
            harness.audit_arc(),
        )
        .with_agent_identity(true),
    );
    router(state)
}

/// `hearth.agents.admin` passes the outer gate and reaches `/v1/agents`
/// (response may be 200; must NOT be 403).
#[tokio::test]
async fn agents_admin_passes_outer_gate_to_agent_endpoint() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token =
        issue_sub_admin_token(&h, &realm, "agentsadmin@example.com", "hearth.agents.admin").await;
    let app = build_app_with_agent_routes(&h).await;

    let status = http_get(app, &token, &realm, "/v1/agents").await;
    assert_ne!(
        status,
        StatusCode::FORBIDDEN,
        "hearth.agents.admin must pass the outer gate and not receive 403 on /v1/agents"
    );
}

/// `hearth.agents.admin` is denied on `/admin/users` (wrong sub-permission).
#[tokio::test]
async fn agents_admin_denied_on_users_endpoint() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = issue_sub_admin_token(
        &h,
        &realm,
        "agentsadmin2@example.com",
        "hearth.agents.admin",
    )
    .await;
    let app = build_app(&h).await;

    let status = http_get(app, &token, &realm, "/admin/users").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "hearth.agents.admin must be denied on /admin/users (requires hearth.users.admin)"
    );
}

/// `hearth.agents.admin` is denied on `/admin/roles` (wrong sub-permission).
#[tokio::test]
async fn agents_admin_denied_on_realm_endpoint() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = issue_sub_admin_token(
        &h,
        &realm,
        "agentsadmin3@example.com",
        "hearth.agents.admin",
    )
    .await;
    let app = build_app(&h).await;

    let status = http_get(app, &token, &realm, "/admin/roles").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "hearth.agents.admin must be denied on /admin/roles (requires hearth.realm.admin)"
    );
}

/// hearth.admin (full superuser) still grants access to all domains.
#[tokio::test]
async fn full_admin_accesses_all_domains() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = issue_token_for(&h, &realm, "fulladmin@example.com", true).await;
    let app = build_app(&h).await;

    // The token is shared across oneshot calls via clone.
    for uri in ["/admin/users", "/admin/applications", "/admin/roles"] {
        let status = http_get(app.clone(), &token, &realm, uri).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "hearth.admin must be allowed on {uri}"
        );
    }
}

// ---------------------------------------------------------------------------
// HEA-1680 / HEA-SEC-12: Group membership permission checks
// ---------------------------------------------------------------------------

async fn http_post_json(
    app: axum::Router,
    token: &str,
    realm: &RealmId,
    uri: &str,
    body: &str,
) -> StatusCode {
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("Authorization", format!("Bearer {token}"))
            .header("X-Realm-ID", realm.as_uuid().to_string())
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("req"),
    )
    .await
    .expect("resp")
    .status()
}

async fn http_delete(app: axum::Router, token: &str, realm: &RealmId, uri: &str) -> StatusCode {
    app.oneshot(
        Request::builder()
            .method("DELETE")
            .uri(uri)
            .header("Authorization", format!("Bearer {token}"))
            .header("X-Realm-ID", realm.as_uuid().to_string())
            .body(Body::empty())
            .expect("req"),
    )
    .await
    .expect("resp")
    .status()
}

/// HEA-SEC-12: hearth.users.admin is denied on POST /admin/groups/{id}/members.
/// A sub-admin must not be able to add themselves to a group and inherit roles.
#[tokio::test]
async fn users_admin_denied_add_group_member() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = issue_sub_admin_token(
        &h,
        &realm,
        "usersadmin-grp@example.com",
        "hearth.users.admin",
    )
    .await;
    let app = build_app(&h).await;

    // Group need not exist — permission check fires before DB lookup.
    let group_id = uuid::Uuid::new_v4();
    let user_id = uuid::Uuid::new_v4();
    let body = format!(r#"{{"id":"{user_id}","member_type":"user"}}"#);
    let status = http_post_json(
        app,
        &token,
        &realm,
        &format!("/admin/groups/{group_id}/members"),
        &body,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "hearth.users.admin must be denied on POST /admin/groups/:id/members"
    );
}

/// HEA-SEC-12: hearth.users.admin is denied on DELETE /admin/groups/{id}/members/{member_id}.
#[tokio::test]
async fn users_admin_denied_remove_group_member() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = issue_sub_admin_token(
        &h,
        &realm,
        "usersadmin-grp2@example.com",
        "hearth.users.admin",
    )
    .await;
    let app = build_app(&h).await;

    let group_id = uuid::Uuid::new_v4();
    let member_id = uuid::Uuid::new_v4();
    let status = http_delete(
        app,
        &token,
        &realm,
        &format!("/admin/groups/{group_id}/members/{member_id}?type=user"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "hearth.users.admin must be denied on DELETE /admin/groups/:id/members/:member_id"
    );
}

/// HEA-SEC-12: hearth.users.admin is allowed on GET /admin/groups/{id}.
#[tokio::test]
async fn users_admin_allowed_get_group() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");

    let group = h
        .rbac()
        .create_group(
            &realm,
            &CreateGroupRequest {
                name: "Test Group".into(),
                slug: "test-group-get".into(),
                description: None,
            },
        )
        .expect("create group");

    let token = issue_sub_admin_token(
        &h,
        &realm,
        "usersadmin-grp3@example.com",
        "hearth.users.admin",
    )
    .await;
    let app = build_app(&h).await;

    let status = http_get(
        app,
        &token,
        &realm,
        &format!("/admin/groups/{}", group.id.as_uuid()),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "hearth.users.admin must be allowed on GET /admin/groups/:id"
    );
}

/// HEA-SEC-12: hearth.users.admin is allowed on GET /admin/groups/{id}/members.
#[tokio::test]
async fn users_admin_allowed_list_group_members() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");

    let group = h
        .rbac()
        .create_group(
            &realm,
            &CreateGroupRequest {
                name: "Test Group Members".into(),
                slug: "test-group-members".into(),
                description: None,
            },
        )
        .expect("create group");

    let token = issue_sub_admin_token(
        &h,
        &realm,
        "usersadmin-grp4@example.com",
        "hearth.users.admin",
    )
    .await;
    let app = build_app(&h).await;

    let status = http_get(
        app,
        &token,
        &realm,
        &format!("/admin/groups/{}/members", group.id.as_uuid()),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "hearth.users.admin must be allowed on GET /admin/groups/:id/members"
    );
}

/// HEA-SEC-12: hearth.realm.admin can add a member to a group.
#[tokio::test]
async fn realm_admin_allowed_add_group_member() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");

    let group = h
        .rbac()
        .create_group(
            &realm,
            &CreateGroupRequest {
                name: "Realm Admin Group".into(),
                slug: "realm-admin-group".into(),
                description: None,
            },
        )
        .expect("create group");

    let token = issue_sub_admin_token(
        &h,
        &realm,
        "realmadmin-grp@example.com",
        "hearth.realm.admin",
    )
    .await;

    let target_user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "member-grp@example.com".into(),
                display_name: "Member".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create member user");

    let app = build_app(&h).await;

    let body = format!(
        r#"{{"id":"{}","member_type":"user"}}"#,
        target_user.id().as_uuid()
    );
    let status = http_post_json(
        app,
        &token,
        &realm,
        &format!("/admin/groups/{}/members", group.id.as_uuid()),
        &body,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "hearth.realm.admin must be allowed on POST /admin/groups/:id/members"
    );
}
