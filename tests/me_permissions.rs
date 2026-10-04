//! Integration tests for `GET /v1/me/permissions`.
//!
//! Scenarios: `returns_live_set`, `unauthenticated_401`.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::core::{OrganizationId, RealmId, UserId};
use hearth::identity::{
    CreateOrganizationRequest, CreateUserRequest, OrganizationRole, SessionContext,
    TokenIssuanceContext,
};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{
    AssignRoleRequest, CreateRoleRequest, Permission, RoleScopeKind, Scope, Subject,
};
use tower::ServiceExt as _;

fn build_router(h: &common::TestHarness) -> axum::Router {
    router(Arc::new(AppState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
    )))
}

#[tokio::test]
async fn returns_live_set_reflecting_post_issuance_changes() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");

    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: "u@example.com".into(),
                display_name: "U".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    let session = h
        .identity()
        .create_session(&realm, user.id(), &SessionContext::default())
        .expect("sess");
    let token = h
        .identity()
        .issue_tokens(&realm, user.id(), session.id())
        .expect("issue")
        .access_token()
        .to_string();

    // Assign a role AFTER the token was issued.
    let role = h
        .rbac()
        .create_role(
            &realm,
            &CreateRoleRequest {
                name: "docs.viewer".into(),
                description: None,
                permissions: vec![Permission::new("docs.view").expect("valid")],
                parent_roles: vec![],
                ..Default::default()
            },
        )
        .expect("role");
    h.rbac()
        .assign_role(
            &realm,
            &AssignRoleRequest {
                subject: Subject::User(user.id().clone()),
                role_id: role.id,
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign");

    let app = build_router(&h);
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/me/permissions")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 1_000_000).await.expect("bytes");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    let perms: Vec<&str> = body["permissions"]
        .as_array()
        .expect("permissions array")
        .iter()
        .map(|v| v.as_str().expect("str"))
        .collect();
    assert!(
        perms.contains(&"docs.view"),
        "/v1/me/permissions must resolve freshly after assignment"
    );
}

/// A realm with organization O, a user, and the role `reports.viewer`
/// (permission `reports.view`) assigned to that user scoped to O.
struct OrgFixture {
    h: common::TestHarness,
    realm: RealmId,
    org: OrganizationId,
    user: UserId,
}

impl OrgFixture {
    async fn new(member: bool) -> Self {
        let h = common::TestHarness::in_process().await.expect("harness");
        let realm = h.create_realm();
        h.rbac().seed_realm(&realm).expect("seed");
        let org = h
            .identity()
            .create_organization(
                &realm,
                &CreateOrganizationRequest {
                    name: "Acme".into(),
                    slug: format!("acme-{}", uuid::Uuid::new_v4().simple()),
                    description: None,
                    config: None,
                    attributes: Default::default(),
                },
            )
            .expect("create org")
            .id()
            .clone();
        let user = h
            .identity()
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: "org-user@example.com".into(),
                    display_name: "Org User".into(),
                    ..Default::default()
                },
            )
            .expect("create user")
            .id()
            .clone();
        if member {
            h.identity()
                .add_member(&realm, &org, &user, OrganizationRole::Member)
                .expect("add member");
        }
        let role = h
            .rbac()
            .create_role(
                &realm,
                &CreateRoleRequest {
                    name: "reports.viewer".into(),
                    permissions: vec![Permission::new("reports.view").expect("valid")],
                    scope_kind: RoleScopeKind::Organization,
                    ..Default::default()
                },
            )
            .expect("role");
        h.rbac()
            .assign_role(
                &realm,
                &AssignRoleRequest {
                    subject: Subject::User(user.clone()),
                    role_id: role.id,
                    scope: Scope::Org {
                        org_id: org.clone(),
                    },
                    assigned_by: None,
                },
            )
            .expect("org-scoped assignment");
        Self {
            h,
            realm,
            org,
            user,
        }
    }

    /// An access token for the user, issued with `oid` = `org` when given.
    fn token(&self, org: Option<&OrganizationId>) -> String {
        let session = self
            .h
            .identity()
            .create_session(&self.realm, &self.user, &SessionContext::default())
            .expect("session");
        self.h
            .identity()
            .issue_tokens_with_context(
                &self.realm,
                &self.user,
                session.id(),
                &TokenIssuanceContext {
                    oid: org.map(|o| o.as_uuid().to_string()),
                    ..Default::default()
                },
            )
            .expect("issue")
            .access_token()
            .to_string()
    }

    async fn get(&self, uri: &str, token: &str) -> (StatusCode, serde_json::Value) {
        let resp = build_router(&self.h)
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .header("Authorization", format!("Bearer {token}"))
                    .header("X-Realm-ID", self.realm.as_uuid().to_string())
                    .body(Body::empty())
                    .expect("req"),
            )
            .await
            .expect("resp");
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 1_000_000).await.expect("bytes");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }
}

fn has_permission(body: &serde_json::Value, permission: &str) -> bool {
    body["permissions"]
        .as_array()
        .is_some_and(|p| p.iter().any(|v| v == permission))
}

/// `rbac-admin-api` "The organization comes from the token": a token whose
/// `oid` is O reports the O-scoped role; a token without `oid` does not, and
/// no query parameter is needed for either.
#[tokio::test]
async fn the_organization_comes_from_the_token() {
    let f = OrgFixture::new(true).await;

    let (status, body) = f.get("/v1/me/permissions", &f.token(Some(&f.org))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(has_permission(&body, "reports.view"), "oid = O: {body}");

    let (status, body) = f.get("/v1/me/permissions", &f.token(None)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!has_permission(&body, "reports.view"), "no oid: {body}");

    // A member may still name the organization explicitly.
    let uri = format!("/v1/me/permissions?org_id={}", f.org.as_uuid());
    let (status, body) = f.get(&uri, &f.token(None)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        has_permission(&body, "reports.view"),
        "member, org_id: {body}"
    );
}

/// `rbac-admin-api` "A caller-chosen organization is refused": a user who is
/// not a member of O, but holds a role assignment scoped to O, gets `403` for
/// `?org_id=O` and none of that role's permissions.
#[tokio::test]
async fn a_caller_chosen_organization_is_refused() {
    let f = OrgFixture::new(false).await;
    let token = f.token(None);

    for org_id in [
        f.org.as_uuid().to_string(),
        format!("org_{}", f.org.as_uuid()),
    ] {
        let uri = format!("/v1/me/permissions?org_id={org_id}");
        let (status, body) = f.get(&uri, &token).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{org_id}: {body}");
        assert!(!has_permission(&body, "reports.view"), "{org_id}: {body}");
    }

    // An organization that does not exist is refused the same way.
    let uri = format!("/v1/me/permissions?org_id={}", uuid::Uuid::new_v4());
    let (status, body) = f.get(&uri, &token).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

#[tokio::test]
async fn unauthenticated_returns_401() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = h.create_realm();
    let app = build_router(&h);
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/me/permissions")
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
