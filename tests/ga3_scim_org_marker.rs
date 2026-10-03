//! GA audit round 3 — SCIM may manage only the organizations it created.
//!
//! A realm's SCIM provisioning token could replace, patch and delete *every*
//! organization, including ones an operator created through the admin API,
//! the console or `hearth.yaml`. Owner decision: organizations carry a durable
//! "provisioned by SCIM" marker, set only when SCIM creates them. The
//! provisioning token may modify or delete only marked organizations; others
//! are read-only to it (403). Admin-token SCIM callers keep their rights
//! (subject to the `hearth.realm.admin` rule for `/Groups`). No client field —
//! not a SCIM `PUT` or `PATCH` body — can set the marker, and a backup restore
//! carries it.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::core::{OrganizationId, RealmId};
use hearth::identity::{
    CreateOrganizationRequest, CreateRealmRequest, CreateUserRequest, RealmConfig, SessionContext,
    UpdateRealmRequest,
};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use serde_json::json;
use sha2::{Digest, Sha256};
use tower::ServiceExt as _;

fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn app(h: &common::TestHarness) -> axum::Router {
    router(Arc::new(AppState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
    )))
}

fn realm(h: &common::TestHarness) -> RealmId {
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("ga3-org-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();
    h.rbac().seed_realm(&realm).expect("seed realm");
    realm
}

/// Configures a SCIM provisioning token on `realm`; returns the plaintext.
fn enable_scim_token(h: &common::TestHarness, realm: &RealmId) -> String {
    let token = format!("ga3-scim-{}", uuid::Uuid::new_v4());
    h.identity()
        .update_realm(
            realm,
            &UpdateRealmRequest {
                config: Some(RealmConfig {
                    scim_bearer_token_hash: Some(sha256_hex(&token)),
                    ..RealmConfig::default()
                }),
                ..UpdateRealmRequest::default()
            },
        )
        .expect("set scim token");
    token
}

/// An organization created by an operator, not by SCIM.
fn admin_org(h: &common::TestHarness, realm: &RealmId, name: &str) -> OrganizationId {
    h.identity()
        .create_organization(
            realm,
            &CreateOrganizationRequest {
                name: name.into(),
                slug: format!("admin-{}", uuid::Uuid::new_v4().simple()),
                description: None,
                config: None,
                attributes: Default::default(),
            },
        )
        .expect("create org")
        .id()
        .clone()
}

fn realm_admin_token(h: &common::TestHarness, realm: &RealmId) -> String {
    let user = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("admin-{}@ga3.test", uuid::Uuid::new_v4()),
                display_name: "Admin".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    let role = h
        .rbac()
        .get_role_by_name(realm, "realm.admin")
        .expect("lookup")
        .expect("seeded");
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
        .expect("assign");
    let session = h
        .identity()
        .create_session(realm, user.id(), &SessionContext::default())
        .expect("session");
    h.identity()
        .issue_tokens(realm, user.id(), session.id())
        .expect("tokens")
        .access_token()
        .to_string()
}

async fn scim(
    app: &axum::Router,
    method: &str,
    uri: &str,
    realm: &RealmId,
    bearer: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/scim+json")
        .header("x-realm-id", realm.as_uuid().to_string())
        .header("authorization", format!("Bearer {bearer}"))
        .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
        .expect("request");
    let resp = app.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

fn group_uri(org: &OrganizationId) -> String {
    format!("/scim/v2/Groups/{}", org.as_uuid())
}

/// A group body carrying every spelling a client might try for the marker.
fn group_body(name: &str) -> serde_json::Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": name,
        "scimProvisioned": true,
        "scim_provisioned": true,
        "urn:hearth:params:scim:provisioned": true
    })
}

fn rename_patch(name: &str) -> serde_json::Value {
    json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "displayName", "value": name}]
    })
}

/// The provisioning token manages what it created.
#[tokio::test]
async fn scim_token_deletes_a_scim_created_group() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = realm(&h);
    let token = enable_scim_token(&h, &realm);
    let app = app(&h);

    let (created, body) = scim(
        &app,
        "POST",
        "/scim/v2/Groups",
        &realm,
        &token,
        Some(group_body("Engineering")),
    )
    .await;
    assert_eq!(created, StatusCode::CREATED, "{body}");
    let id = body["id"].as_str().expect("group id").to_string();
    let uri = format!("/scim/v2/Groups/{id}");

    let (patched, _) = scim(
        &app,
        "PATCH",
        &uri,
        &realm,
        &token,
        Some(rename_patch("Eng")),
    )
    .await;
    let (deleted, _) = scim(&app, "DELETE", &uri, &realm, &token, None).await;

    assert_eq!(patched, StatusCode::OK, "PATCH own group");
    assert_eq!(deleted, StatusCode::NO_CONTENT, "DELETE own group");
}

/// An operator-created organization is read-only to the provisioning token.
#[tokio::test]
async fn scim_token_cannot_modify_or_delete_an_admin_created_org() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = realm(&h);
    let token = enable_scim_token(&h, &realm);
    let app = app(&h);
    let org = admin_org(&h, &realm, "Finance");
    let uri = group_uri(&org);

    let (read, _) = scim(&app, "GET", &uri, &realm, &token, None).await;
    let (put, _) = scim(&app, "PUT", &uri, &realm, &token, Some(group_body("Pwned"))).await;
    let (patch, _) = scim(
        &app,
        "PATCH",
        &uri,
        &realm,
        &token,
        Some(rename_patch("Pwned")),
    )
    .await;
    let (delete, _) = scim(&app, "DELETE", &uri, &realm, &token, None).await;

    assert_eq!(read, StatusCode::OK, "reads stay allowed");
    assert_eq!(put, StatusCode::FORBIDDEN, "PUT");
    assert_eq!(patch, StatusCode::FORBIDDEN, "PATCH");
    assert_eq!(delete, StatusCode::FORBIDDEN, "DELETE");
    let stored = h
        .identity()
        .get_organization(&realm, &org)
        .expect("lookup")
        .expect("org must still exist");
    assert_eq!(stored.name(), "Finance", "name untouched");
}

/// No client field sets the marker: an admin-token `PUT` carrying every
/// plausible spelling leaves the organization unmarked, so once the realm
/// switches to a provisioning token that token still may not delete it.
/// Admin-token callers themselves keep their rights (the PUT succeeds).
#[tokio::test]
async fn scim_put_cannot_set_the_marker() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = realm(&h);
    let app = app(&h);
    let org = admin_org(&h, &realm, "Legal");
    let admin = realm_admin_token(&h, &realm);

    let (put, body) = scim(
        &app,
        "PUT",
        &group_uri(&org),
        &realm,
        &admin,
        Some(group_body("Legal")),
    )
    .await;
    assert_eq!(put, StatusCode::OK, "admin-token PUT keeps working: {body}");

    let token = enable_scim_token(&h, &realm);
    let (delete, _) = scim(&app, "DELETE", &group_uri(&org), &realm, &token, None).await;

    assert_eq!(
        delete,
        StatusCode::FORBIDDEN,
        "the PUT must not have marked it"
    );
}

/// Admin-token SCIM callers keep today's rights on operator-created orgs.
#[tokio::test]
async fn admin_token_scim_caller_still_deletes_admin_created_org() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm = realm(&h);
    let app = app(&h);
    let org = admin_org(&h, &realm, "Ops");
    let admin = realm_admin_token(&h, &realm);

    let (delete, _) = scim(&app, "DELETE", &group_uri(&org), &realm, &admin, None).await;

    assert_eq!(delete, StatusCode::NO_CONTENT);
}

/// The marker is part of the organization record a backup exports
/// (`list_organizations`) and a restore writes back (`import_organization`):
/// a restored SCIM-created organization stays manageable by the token.
#[tokio::test]
async fn backup_restore_keeps_the_marker() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let source = realm(&h);
    let source_token = enable_scim_token(&h, &source);
    let app = app(&h);
    let (created, body) = scim(
        &app,
        "POST",
        "/scim/v2/Groups",
        &source,
        &source_token,
        Some(group_body("Restored")),
    )
    .await;
    assert_eq!(created, StatusCode::CREATED, "{body}");

    let exported = h
        .identity()
        .list_organizations(&source, &hearth::core::PageRequest::new(0, 100))
        .expect("export")
        .items;
    let target = realm(&h);
    for org in &exported {
        // The backup writes each record as an ndjson line and parses it back
        // on restore: round-trip through the same serde form.
        let line = serde_json::to_string(org).expect("serialize org");
        let restored: hearth::identity::Organization =
            serde_json::from_str(&line).expect("parse org");
        h.identity()
            .import_organization(&target, &restored, false)
            .expect("import");
    }
    let target_token = enable_scim_token(&h, &target);
    let id = body["id"].as_str().expect("group id");

    let (delete, _) = scim(
        &app,
        "DELETE",
        &format!("/scim/v2/Groups/{id}"),
        &target,
        &target_token,
        None,
    )
    .await;

    assert_eq!(
        delete,
        StatusCode::NO_CONTENT,
        "restored marker lets the token manage it"
    );
}
