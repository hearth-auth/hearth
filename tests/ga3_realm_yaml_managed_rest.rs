//! GA audit round 3 — G-7: realms are declared in `hearth.yaml`, so
//! `POST /admin/realms` and `PATCH /admin/realms/{id}` are refused with `405`
//! and the YAML-managed message, and touch nothing.
//!
//! The removed gRPC `UpdateRealm` once replaced the realm's WHOLE config with
//! the three fields its message carried — a "change the session TTL" call
//! silently dropped the SCIM bearer token, the lockout policy and the rest.
//! These tests pin that the only remaining runtime surface cannot do that.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::core::{PageRequest, RealmId, Timestamp};
use hearth::identity::{
    CreateRealmRequest, CreateUserRequest, RealmConfig, RealmStatus, SessionContext,
};
use hearth::protocol::admin_auth::REALMS_ARE_YAML_MANAGED;
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{
    AssignRoleRequest, CreateRoleRequest, Group, GroupId, Role, RoleScopeKind, RoleSpec, Scope,
    Subject,
};
use serde_json::{json, Value};
use tower::ServiceExt as _;

fn assign_realm_admin(h: &common::TestHarness, realm: &RealmId, user: &hearth::identity::User) {
    let role = h
        .rbac()
        .get_role_by_name(realm, "realm.admin")
        .expect("role lookup")
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
        .expect("assign role");
}

fn mint(h: &common::TestHarness, realm: &RealmId, user: &hearth::identity::User) -> String {
    let session = h
        .identity()
        .create_session(realm, user.id(), &SessionContext::default())
        .expect("session");
    h.identity()
        .issue_tokens(realm, user.id(), session.id())
        .expect("issue tokens")
        .access_token()
        .to_string()
}

/// A tenant realm whose config carries a SCIM bearer token, a lockout policy
/// and a custom session TTL, plus a realm-admin token for it. (Not
/// `mfa_required`: the fixture must still mint a password-only admin token.)
fn tenant_realm_with_config(h: &common::TestHarness) -> (RealmId, String) {
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("ga3-g7-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                session_ttl_micros: Some(1_800_000_000),
                scim_bearer_token_hash: Some("f".repeat(64)),
                max_failed_logins: Some(3),
                ..RealmConfig::default()
            }),
        })
        .expect("create realm");
    let realm_id = realm.id().clone();
    h.rbac().seed_realm(&realm_id).expect("seed realm");
    let user = h
        .identity()
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: format!("admin-{}@ga3.test", uuid::Uuid::new_v4()),
                display_name: "Admin".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create admin");
    assign_realm_admin(h, &realm_id, &user);
    let token = mint(h, &realm_id, &user);
    (realm_id, token)
}

fn system_admin_token(h: &common::TestHarness) -> String {
    let sys = RealmId::new(uuid::Uuid::nil());
    h.rbac().seed_realm(&sys).expect("seed system rbac");
    let user = h
        .identity()
        .create_admin_user(&CreateUserRequest {
            email: format!("sysadmin-{}@ga3.test", uuid::Uuid::new_v4()),
            display_name: "Sys".into(),
            first_name: String::new(),
            last_name: String::new(),
            attributes: Default::default(),
        })
        .expect("create system admin");
    assign_realm_admin(h, &sys, &user);
    mint(h, &sys, &user)
}

async fn rest(
    h: &common::TestHarness,
    method: &str,
    uri: &str,
    realm: &RealmId,
    token: &str,
    body: Option<&Value>,
) -> (StatusCode, Value) {
    let app = router(Arc::new(AppState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
    )));
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-realm-id", realm.as_uuid().to_string())
        .header("authorization", format!("Bearer {token}"))
        .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
        .expect("build request");
    let resp = app.oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn assert_yaml_managed_refusal(status: StatusCode, body: &Value) {
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{body}");
    assert_eq!(body["message"], REALMS_ARE_YAML_MANAGED, "{body}");
}

/// The audit trigger: a realm admin "changes the session TTL". This must be
/// refused and the stored config must keep every field it had.
#[tokio::test]
async fn update_realm_is_refused_and_leaves_config_intact() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let (realm_id, token) = tenant_realm_with_config(&h);
    let uri = format!("/admin/realms/{}", realm_id.as_uuid());

    // Control: the route and realm exist and the token is a working admin.
    let (ok, body) = rest(&h, "GET", &uri, &realm_id, &token, None).await;
    assert_eq!(ok, StatusCode::OK, "control: {body}");

    let (status, body) = rest(
        &h,
        "PATCH",
        &uri,
        &realm_id,
        &token,
        Some(&json!({"config": {"session_ttl_micros": 3_600_000_000_u64}})),
    )
    .await;
    assert_yaml_managed_refusal(status, &body);

    let stored = h
        .identity()
        .get_realm(&realm_id)
        .expect("lookup")
        .expect("realm exists");
    let cfg = stored.config();
    assert_eq!(cfg.session_ttl_micros, Some(1_800_000_000), "TTL unchanged");
    assert_eq!(
        cfg.scim_bearer_token_hash.as_deref(),
        Some("f".repeat(64).as_str())
    );
    assert_eq!(
        cfg.max_failed_logins,
        Some(3),
        "lockout policy must survive"
    );
}

/// The status and rename variants are refused the same way: a realm cannot be
/// suspended or detached from its YAML entry.
#[tokio::test]
async fn update_realm_status_and_name_are_refused() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let (realm_id, token) = tenant_realm_with_config(&h);
    let uri = format!("/admin/realms/{}", realm_id.as_uuid());
    let original_name = h
        .identity()
        .get_realm(&realm_id)
        .expect("lookup")
        .expect("realm exists")
        .name()
        .to_string();

    let (ok, body) = rest(&h, "GET", &uri, &realm_id, &token, None).await;
    assert_eq!(ok, StatusCode::OK, "control: {body}");
    assert_eq!(body["name"], original_name.as_str(), "control: {body}");

    let (status, body) = rest(
        &h,
        "PATCH",
        &uri,
        &realm_id,
        &token,
        Some(&json!({"name": "detached", "status": "suspended"})),
    )
    .await;
    assert_yaml_managed_refusal(status, &body);

    let stored = h
        .identity()
        .get_realm(&realm_id)
        .expect("lookup")
        .expect("realm exists");
    assert_eq!(stored.status(), RealmStatus::Active);
    assert_eq!(stored.name(), original_name);
}

/// A system-realm admin cannot create a realm either.
#[tokio::test]
async fn create_realm_is_refused_for_system_admin() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let token = system_admin_token(&h);
    let sys = RealmId::new(uuid::Uuid::nil());
    let name = format!("ga3-created-{}", uuid::Uuid::new_v4());

    // Control: the same path answers GET for this admin, so the 405 below is
    // the method refusal, not a missing route or a bad token.
    let (ok, body) = rest(&h, "GET", "/admin/realms", &sys, &token, None).await;
    assert_eq!(ok, StatusCode::OK, "control: {body}");

    let (status, body) = rest(
        &h,
        "POST",
        "/admin/realms",
        &sys,
        &token,
        Some(&json!({"name": name})),
    )
    .await;
    assert_yaml_managed_refusal(status, &body);
    assert!(
        h.identity()
            .get_realm_by_name(&name)
            .expect("lookup")
            .is_none(),
        "no realm may be created by a refused call"
    );
}

// ── YAML-managed roles and groups (rbac-admin-api "Declarative RBAC") ───────

/// A realm whose `hearth.yaml` declares the role `support.agent` (held by one
/// user) and the group `ops`, plus a realm-admin token.
fn realm_with_yaml_rbac(h: &common::TestHarness) -> (RealmId, String, Role, Group) {
    let (realm, token) = tenant_realm_with_config(h);
    h.rbac()
        .reconcile_permissions(&realm, &["billing.read".to_string()])
        .expect("reconcile permissions");
    h.rbac()
        .reconcile_roles(
            &realm,
            &[RoleSpec {
                name: "support.agent".into(),
                description: Some("declared".into()),
                permissions: vec!["billing.read".into()],
                parent_names: vec![],
                scope_kind: RoleScopeKind::Realm,
            }],
        )
        .expect("reconcile roles");
    h.rbac()
        .reconcile_groups(
            &realm,
            &[Group {
                id: GroupId::generate(),
                realm_id: realm.clone(),
                name: "Ops".into(),
                slug: "ops".into(),
                description: Some("declared".into()),
                created_at: Timestamp::from_micros(0),
                updated_at: Timestamp::from_micros(0),
                yaml_managed: true,
            }],
        )
        .expect("reconcile groups");
    let role = h
        .rbac()
        .get_role_by_name(&realm, "support.agent")
        .expect("lookup")
        .expect("declared role");
    let holder = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("holder-{}@ga3.test", uuid::Uuid::new_v4()),
                display_name: "Holder".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create holder");
    h.rbac()
        .assign_role(
            &realm,
            &AssignRoleRequest {
                subject: Subject::User(holder.id().clone()),
                role_id: role.id.clone(),
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign declared role");
    let group_id = h
        .rbac()
        .list_groups(&realm, &PageRequest::default())
        .expect("list groups")
        .items
        .into_iter()
        .find(|g| g.slug == "ops")
        .expect("declared group")
        .id;
    let group = h
        .rbac()
        .get_group(&realm, &group_id)
        .expect("get")
        .expect("group");
    (realm, token, role, group)
}

fn assert_points_to_hearth_yaml(status: StatusCode, body: &Value) {
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "yaml_managed", "{body}");
    assert!(
        body["error_description"]
            .as_str()
            .is_some_and(|d| d.contains("hearth.yaml")),
        "the refusal must name hearth.yaml: {body}"
    );
}

/// Scenario "An admin edits a YAML-managed role".
#[tokio::test]
async fn a_yaml_managed_role_cannot_be_edited_at_runtime() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let (realm, token, role, _) = realm_with_yaml_rbac(&h);
    let uri = format!("/admin/roles/{}", role.id.as_uuid());

    let (status, body) = rest(
        &h,
        "PATCH",
        &uri,
        &realm,
        &token,
        Some(&json!({"description": "edited at runtime"})),
    )
    .await;
    assert_points_to_hearth_yaml(status, &body);
    let stored = h
        .rbac()
        .get_role(&realm, &role.id)
        .expect("get")
        .expect("role");
    assert_eq!(stored.description.as_deref(), Some("declared"));
}

/// Scenario "A YAML-managed role cannot be deleted at runtime": refused even
/// with `cascade=true`, and the role and its assignment remain.
#[tokio::test]
async fn a_yaml_managed_role_cannot_be_deleted_at_runtime() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let (realm, token, role, _) = realm_with_yaml_rbac(&h);

    let uri = format!("/admin/roles/{}?cascade=true", role.id.as_uuid());
    let (status, body) = rest(&h, "DELETE", &uri, &realm, &token, None).await;
    assert_points_to_hearth_yaml(status, &body);
    assert!(h.rbac().get_role(&realm, &role.id).expect("get").is_some());
    let members = h
        .rbac()
        .list_role_members(&realm, &role.id, None, 10)
        .expect("members");
    assert_eq!(members.items.len(), 1, "the assignment remains");

    // Control: a role created at runtime is still deletable.
    let runtime = h
        .rbac()
        .create_role(
            &realm,
            &CreateRoleRequest {
                name: "runtime.role".into(),
                ..Default::default()
            },
        )
        .expect("create runtime role");
    let uri = format!("/admin/roles/{}?cascade=true", runtime.id.as_uuid());
    let (status, body) = rest(&h, "DELETE", &uri, &realm, &token, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
}

/// A group declared in `hearth.yaml` is refused the same way: it cannot be
/// edited or deleted at runtime.
#[tokio::test]
async fn a_yaml_managed_group_cannot_be_edited_or_deleted_at_runtime() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let (realm, token, _, group) = realm_with_yaml_rbac(&h);
    assert!(group.yaml_managed, "reconciliation marks a declared group");
    let uri = format!("/admin/groups/{}", group.id.as_uuid());

    let (status, body) = rest(
        &h,
        "PATCH",
        &uri,
        &realm,
        &token,
        Some(&json!({"name": "Renamed"})),
    )
    .await;
    assert_points_to_hearth_yaml(status, &body);

    let (status, body) = rest(&h, "DELETE", &uri, &realm, &token, None).await;
    assert_points_to_hearth_yaml(status, &body);

    let stored = h.rbac().get_group(&realm, &group.id).expect("get");
    assert_eq!(stored.map(|g| g.name).as_deref(), Some("Ops"));
}
