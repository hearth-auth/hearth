//! GA audit round 3 — `GET` / `DELETE /admin/realms/{id}` honour the target
//! realm's cross-realm trust policy.
//!
//! A realm opts into enforcement by storing a policy that names the system
//! realm as its source. REST routes every `/admin/realms/{id}` request through
//! `scoped_realm`, which refuses the crossing when such a policy withholds
//! `hearth.admin`, and permits it when the pair is ungoverned or the policy
//! grants `hearth.admin`. (These assertions were first written against the
//! gRPC twins, removed with the public gRPC API.)

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::core::RealmId;
use hearth::identity::{
    CreateCrossRealmPolicyRequest, CreateRealmRequest, CreateUserRequest, RealmStatus,
    SessionContext, UpdateRealmRequest,
};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use serde_json::Value;
use tower::ServiceExt as _;

fn system_realm() -> RealmId {
    RealmId::new(uuid::Uuid::nil())
}

/// A system-realm `realm.admin` (holds `hearth.admin`) and its token.
fn system_admin_token(h: &common::TestHarness) -> String {
    system_admin(h).1
}

/// A system-realm `realm.admin`: `(user id, token)`.
fn system_admin(h: &common::TestHarness) -> (hearth::core::UserId, String) {
    let sys = system_realm();
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
    let role = h
        .rbac()
        .get_role_by_name(&sys, "realm.admin")
        .expect("role lookup")
        .expect("realm.admin seeded");
    h.rbac()
        .assign_role(
            &sys,
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
        .create_session(&sys, user.id(), &SessionContext::default())
        .expect("session");
    let token = h
        .identity()
        .issue_tokens(&sys, user.id(), session.id())
        .expect("issue tokens")
        .access_token()
        .to_string();
    (user.id().clone(), token)
}

fn tenant_realm(h: &common::TestHarness) -> RealmId {
    h.identity()
        .create_realm(&CreateRealmRequest {
            name: format!("ga3-trust-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone()
}

fn archive(h: &common::TestHarness, realm: &RealmId) {
    h.identity()
        .update_realm(
            realm,
            &UpdateRealmRequest {
                status: Some(RealmStatus::Archived),
                ..UpdateRealmRequest::default()
            },
        )
        .expect("archive realm");
}

/// Stores a policy in `target` naming the system realm as source and granting
/// `capability`.
fn store_policy(h: &common::TestHarness, target: &RealmId, capability: &str) {
    h.identity()
        .create_cross_realm_policy(
            target,
            &CreateCrossRealmPolicyRequest {
                source_realm_id: system_realm(),
                allowed_capabilities: vec![capability.to_string()],
                expires_in_secs: None,
            },
        )
        .expect("store policy");
}

/// Stores a policy in `target` naming the system realm as source but granting
/// only an unrelated capability — i.e. the realm refuses admin crossings.
fn deny_system_crossings(h: &common::TestHarness, target: &RealmId) {
    store_policy(h, target, "search:read");
}

/// Sends `method /admin/realms/{target}` as the system realm.
async fn rest_realm(
    h: &common::TestHarness,
    method: &str,
    token: &str,
    target: &RealmId,
) -> (StatusCode, Value) {
    let app = router(Arc::new(AppState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
    )));
    let req = Request::builder()
        .method(method)
        .uri(format!("/admin/realms/{}", target.as_uuid()))
        .header("x-realm-id", system_realm().as_uuid().to_string())
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .expect("build request");
    let resp = app.oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// A policy that withholds `hearth.admin` from the system realm refuses the
/// read; the same token reads an ungoverned realm (control).
#[tokio::test]
async fn get_realm_refused_when_target_policy_denies_system_realm() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let token = system_admin_token(&h);
    let control = tenant_realm(&h);
    let target = tenant_realm(&h);
    deny_system_crossings(&h, &target);

    let (ok, _) = rest_realm(&h, "GET", &token, &control).await;
    assert_eq!(
        ok,
        StatusCode::OK,
        "control: an ungoverned realm is readable"
    );

    let (refused, body) = rest_realm(&h, "GET", &token, &target).await;
    assert_eq!(refused, StatusCode::FORBIDDEN, "{body}");
    assert!(
        body.get("id").is_none(),
        "a refused read must not leak the realm: {body}"
    );
}

/// The destructive variant: an archived realm whose policy refuses the system
/// realm may not be purged; an archived ungoverned realm may (control).
#[tokio::test]
async fn delete_realm_refused_when_target_policy_denies_system_realm() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let token = system_admin_token(&h);
    let control = tenant_realm(&h);
    let target = tenant_realm(&h);
    // The policy first: a non-active realm refuses new policies.
    deny_system_crossings(&h, &target);
    archive(&h, &target);
    archive(&h, &control);

    let (refused, body) = rest_realm(&h, "DELETE", &token, &target).await;
    assert_eq!(refused, StatusCode::FORBIDDEN, "{body}");
    assert!(
        h.identity().get_realm(&target).expect("lookup").is_some(),
        "the realm must not be deleted"
    );

    let (deleted, body) = rest_realm(&h, "DELETE", &token, &control).await;
    assert_eq!(deleted, StatusCode::NO_CONTENT, "control: {body}");
    assert!(
        h.identity().get_realm(&control).expect("lookup").is_none(),
        "control: the ungoverned archived realm is purged"
    );
}

/// Ungoverned pairs stay permissive-with-audit, and a policy that grants
/// `hearth.admin` allows the crossing — enforcement must not over-refuse.
#[tokio::test]
async fn get_realm_permitted_when_ungoverned_or_granted() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let token = system_admin_token(&h);
    let ungoverned = tenant_realm(&h);
    let granted = tenant_realm(&h);
    store_policy(&h, &granted, "hearth.admin");

    for target in [&ungoverned, &granted] {
        let (status, body) = rest_realm(&h, "GET", &token, target).await;
        assert_eq!(status, StatusCode::OK, "crossing must be permitted: {body}");
        assert_eq!(body["id"], target.as_uuid().to_string(), "{body}");
    }
}

/// `DELETE /admin/realms/{id}` writes `realm_deleted` in the system realm (the
/// deleted realm's own key space must stay empty), attributed to the caller.
#[tokio::test]
async fn delete_realm_is_audited_in_the_system_realm() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (operator_id, token) = system_admin(&h);
    let target = tenant_realm(&h);
    archive(&h, &target);

    let (status, body) = rest_realm(&h, "DELETE", &token, &target).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let events = h
        .audit()
        .query(&hearth::audit::AuditQuery {
            realm_id: system_realm(),
            start_time: None,
            end_time: None,
            actor: Some(operator_id.as_uuid().to_string()),
            action: Some(hearth::audit::AuditAction::RealmDeleted),
            limit: None,
            agent_id: None,
            tool: None,
        })
        .expect("audit query");
    let deleted: Vec<_> = events
        .iter()
        .filter(|e| e.action == hearth::audit::AuditAction::RealmDeleted)
        .collect();
    assert_eq!(deleted.len(), 1, "one realm_deleted event: {events:?}");
    assert_eq!(deleted[0].resource_id, target.as_uuid().to_string());
    assert_eq!(deleted[0].resource_type, "realm");
}
