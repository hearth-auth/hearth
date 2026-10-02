#![allow(clippy::unwrap_used)]
//! `GET /admin/audit` — the realm audit log over REST.
//!
//! Ported from the removed gRPC `AuditService` tests (`grpc_audit_service.rs`,
//! HEA-1834 gap 5 / HEA-1842). The integrity check (`POST /admin/audit/verify`)
//! is covered by `admin_rest_parity.rs`.
//!
//! | Claim | Test |
//! |---|---|
//! | The log returns the realm's appended events | `list_events_returns_realm_events` |
//! | No bearer token ⇒ `401` | `list_events_without_token_unauthenticated` |
//! | Caller with no admin role ⇒ `403` | `list_events_without_admin_permission_denied` |
//! | Granular `hearth.users.admin` without `hearth.realm.admin` ⇒ `403` | `list_events_granular_admin_without_realm_admin_denied` |
//! | A foreign `realm_id` query parameter is ignored | `list_events_ignores_a_foreign_realm_id_parameter` |

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::audit::{AuditAction, CreateAuditEvent};
use hearth::core::RealmId;
use hearth::identity::{CreateUserRequest, SessionContext};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, Scope as RbacScope, Subject};
use serde_json::Value;
use tower::ServiceExt as _;

struct Ctx {
    h: common::TestHarness,
    realm: RealmId,
    app: axum::Router,
}

impl Ctx {
    async fn new() -> Self {
        let h = common::TestHarness::embedded().await.expect("harness");
        let realm = h.create_realm();
        h.rbac().seed_realm(&realm).expect("seed");
        let app = router(Arc::new(AppState::new(
            h.identity_arc(),
            h.rbac_arc(),
            h.audit_arc(),
        )));
        Self { h, realm, app }
    }

    /// A bearer token for a fresh user holding the seeded `role` (or no role).
    fn token(&self, role: Option<&str>) -> String {
        let user = self
            .h
            .identity()
            .create_user(
                &self.realm,
                &CreateUserRequest {
                    email: format!("auditor-{}@example.com", uuid::Uuid::new_v4()),
                    display_name: "Auditor".into(),
                    first_name: String::new(),
                    last_name: String::new(),
                    attributes: Default::default(),
                },
            )
            .expect("user");
        if let Some(role) = role {
            let role = self
                .h
                .rbac()
                .get_role_by_name(&self.realm, role)
                .expect("lookup")
                .expect("seeded role");
            self.h
                .rbac()
                .assign_role(
                    &self.realm,
                    &AssignRoleRequest {
                        subject: Subject::User(user.id().clone()),
                        role_id: role.id,
                        scope: RbacScope::Realm,
                        assigned_by: None,
                    },
                )
                .expect("assign");
        }
        let session = self
            .h
            .identity()
            .create_session(&self.realm, user.id(), &SessionContext::default())
            .expect("session");
        self.h
            .identity()
            .issue_tokens(&self.realm, user.id(), session.id())
            .expect("tokens")
            .access_token()
            .to_string()
    }

    fn seed_events(&self, actions: &[AuditAction]) {
        for (i, action) in actions.iter().enumerate() {
            self.h
                .audit()
                .append(&CreateAuditEvent {
                    realm_id: self.realm.clone(),
                    actor: format!("actor-{i}"),
                    action: action.clone(),
                    resource_type: "test".into(),
                    resource_id: format!("res-{i}"),
                    metadata: None,
                })
                .expect("append audit event");
        }
    }

    async fn list(&self, uri: &str, bearer: Option<&str>) -> (StatusCode, Value) {
        let mut req = Request::builder()
            .method("GET")
            .uri(uri)
            .header("x-realm-id", self.realm.as_uuid().to_string());
        if let Some(b) = bearer {
            req = req.header("authorization", format!("Bearer {b}"));
        }
        let resp = self
            .app
            .clone()
            .oneshot(req.body(Body::empty()).expect("request"))
            .await
            .expect("oneshot");
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.expect("body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }
}

fn actors(body: &Value) -> Vec<String> {
    body["events"]
        .as_array()
        .unwrap_or_else(|| panic!("no events array: {body}"))
        .iter()
        .filter_map(|e| e["actor"].as_str().map(str::to_owned))
        .collect()
}

#[tokio::test]
async fn list_events_returns_realm_events() {
    let ctx = Ctx::new().await;
    ctx.seed_events(&[AuditAction::UserCreated, AuditAction::SessionCreated]);
    let admin = ctx.token(Some("realm.admin"));

    let (status, body) = ctx.list("/admin/audit", Some(&admin)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let actors = actors(&body);
    assert!(
        actors.iter().any(|a| a == "actor-0") && actors.iter().any(|a| a == "actor-1"),
        "the log must contain both seeded events, got {actors:?}"
    );
}

#[tokio::test]
async fn list_events_without_token_unauthenticated() {
    let ctx = Ctx::new().await;
    ctx.seed_events(&[AuditAction::UserCreated]);
    // Control: the same request with an admin bearer is served.
    let admin = ctx.token(Some("realm.admin"));
    let (ok, _) = ctx.list("/admin/audit", Some(&admin)).await;
    assert_eq!(ok, StatusCode::OK);

    let (status, body) = ctx.list("/admin/audit", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(body.get("events").is_none(), "no events leak: {body}");
}

#[tokio::test]
async fn list_events_without_admin_permission_denied() {
    let ctx = Ctx::new().await;
    ctx.seed_events(&[AuditAction::UserCreated]);
    let admin = ctx.token(Some("hearth.realm.admin"));
    let (ok, body) = ctx.list("/admin/audit", Some(&admin)).await;
    assert_eq!(
        ok,
        StatusCode::OK,
        "control: hearth.realm.admin reads the log"
    );
    assert!(actors(&body).iter().any(|a| a == "actor-0"), "{body}");

    let nobody = ctx.token(None);
    let (status, body) = ctx.list("/admin/audit", Some(&nobody)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.get("events").is_none(), "no events leak: {body}");
}

/// `hearth.users.admin` clears the coarse admin gate but the audit log needs
/// `hearth.realm.admin` (HEA-1842 finding 2).
#[tokio::test]
async fn list_events_granular_admin_without_realm_admin_denied() {
    let ctx = Ctx::new().await;
    ctx.seed_events(&[AuditAction::UserCreated]);
    let admin = ctx.token(Some("hearth.realm.admin"));
    let (ok, _) = ctx.list("/admin/audit", Some(&admin)).await;
    assert_eq!(
        ok,
        StatusCode::OK,
        "control: hearth.realm.admin reads the log"
    );

    let users_admin = ctx.token(Some("hearth.users.admin"));
    let (status, body) = ctx.list("/admin/audit", Some(&users_admin)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.get("events").is_none(), "no events leak: {body}");
}

/// The log is read from the `X-Realm-ID` realm; a foreign `realm_id` in the
/// query string changes nothing (HEA-1842 finding 3).
#[tokio::test]
async fn list_events_ignores_a_foreign_realm_id_parameter() {
    let ctx = Ctx::new().await;
    ctx.seed_events(&[AuditAction::UserCreated, AuditAction::SessionCreated]);
    let admin = ctx.token(Some("realm.admin"));
    let foreign = uuid::Uuid::new_v4();
    assert_ne!(&foreign, ctx.realm.as_uuid());

    let (status, body) = ctx
        .list(&format!("/admin/audit?realm_id={foreign}"), Some(&admin))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        actors(&body).iter().any(|a| a == "actor-0"),
        "events must resolve against X-Realm-ID: {body}"
    );
}
