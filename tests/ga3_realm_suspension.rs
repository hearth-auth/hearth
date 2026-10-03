//! GA audit round 3 — realm suspension, the incident-response freeze control.
//!
//! Once gRPC `UpdateRealm` was refused (realms are YAML-managed, G-7) nothing
//! could suspend or reinstate a realm. Owner decision: dedicated operations,
//! `POST /admin/realms/{id}/suspend` / `unsuspend` and the gRPC twins
//! `SuspendRealm` / `UnsuspendRealm`:
//!
//! - only a system-realm admin (`hearth.realm.admin` or `hearth.admin`) may
//!   call them, subject to the same realm scope as other cross-realm realm
//!   operations;
//! - the system realm itself cannot be suspended;
//! - suspension reuses `RealmStatus::Suspended`: tokens issued before it stop
//!   validating, sessions are revoked and no new session starts; unsuspend
//!   restores service;
//! - every transition is audited with the actor and the old and new status;
//! - YAML reconciliation does not undo a runtime suspension.
//!
//! The gRPC twins are driven in `ga3_realm_suspension_grpc.rs`.

mod common;

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::audit::{AuditAction, AuditQuery};
use hearth::config::{Config, RealmYamlConfig};
use hearth::core::{RealmId, UserId};
use hearth::identity::reconcile::reconcile_realms;
use hearth::identity::{
    CreateRealmRequest, CreateUserRequest, IdentityError, RealmStatus, SessionContext,
    UpdateRealmRequest,
};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use tower::ServiceExt as _;

// ── fixture ──────────────────────────────────────────────────────────────────

fn system_realm() -> RealmId {
    RealmId::new(uuid::Uuid::nil())
}

struct Fixture {
    h: common::TestHarness,
    app: axum::Router,
}

impl Fixture {
    async fn new() -> Self {
        let h = common::TestHarness::in_process().await.expect("harness");
        h.rbac()
            .seed_realm(&system_realm())
            .expect("seed system rbac");
        let app = router(Arc::new(AppState::new(
            h.identity_arc(),
            h.rbac_arc(),
            h.audit_arc(),
        )));
        Self { h, app }
    }

    fn tenant(&self) -> RealmId {
        let realm = self
            .h
            .identity()
            .create_realm(&CreateRealmRequest {
                name: format!("ga3-susp-{}", uuid::Uuid::new_v4()),
                config: None,
            })
            .expect("create realm")
            .id()
            .clone();
        self.h.rbac().seed_realm(&realm).expect("seed realm");
        realm
    }

    fn user(&self, realm: &RealmId, roles: &[&str]) -> UserId {
        let req = CreateUserRequest {
            email: format!("u-{}@ga3.test", uuid::Uuid::new_v4()),
            display_name: "U".into(),
            first_name: String::new(),
            last_name: String::new(),
            attributes: Default::default(),
        };
        let user = if realm == &system_realm() {
            self.h.identity().create_admin_user(&req)
        } else {
            self.h.identity().create_user(realm, &req)
        }
        .expect("create user");
        for role in roles {
            let role = self
                .h
                .rbac()
                .get_role_by_name(realm, role)
                .expect("role lookup")
                .unwrap_or_else(|| panic!("seeded role '{role}' missing"));
            self.h
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
        }
        user.id().clone()
    }

    fn token(&self, realm: &RealmId, user: &UserId) -> Result<String, IdentityError> {
        let session = self
            .h
            .identity()
            .create_session(realm, user, &SessionContext::default())?;
        Ok(self
            .h
            .identity()
            .issue_tokens(realm, user, session.id())?
            .access_token()
            .to_string())
    }

    /// A system-realm `realm.admin` (holds `hearth.admin`): `(user, token)`.
    fn operator(&self) -> (UserId, String) {
        let id = self.user(&system_realm(), &["realm.admin"]);
        let token = self.token(&system_realm(), &id).expect("operator token");
        (id, token)
    }

    fn status(&self, realm: &RealmId) -> RealmStatus {
        self.h
            .identity()
            .get_realm(realm)
            .expect("lookup")
            .expect("realm exists")
            .status()
    }

    async fn post(
        &self,
        uri: &str,
        caller_realm: &RealmId,
        token: &str,
    ) -> (StatusCode, serde_json::Value) {
        let req = Request::builder()
            .method("POST")
            .uri(uri)
            .header("x-realm-id", caller_realm.as_uuid().to_string())
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("build request");
        let resp = self.app.clone().oneshot(req).await.expect("oneshot");
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.expect("body");
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    async fn suspend(&self, target: &RealmId, caller: &RealmId, token: &str) -> StatusCode {
        self.post(
            &format!("/admin/realms/{}/suspend", target.as_uuid()),
            caller,
            token,
        )
        .await
        .0
    }

    async fn unsuspend(&self, target: &RealmId, caller: &RealmId, token: &str) -> StatusCode {
        self.post(
            &format!("/admin/realms/{}/unsuspend", target.as_uuid()),
            caller,
            token,
        )
        .await
        .0
    }
}

// ── REST ─────────────────────────────────────────────────────────────────────

/// The freeze: a token issued before suspension is refused after it, no new
/// session starts, and unsuspend restores service.
#[tokio::test]
async fn suspend_refuses_existing_tokens_and_unsuspend_restores() {
    let f = Fixture::new().await;
    let (_, operator) = f.operator();
    let tenant = f.tenant();
    let user = f.user(&tenant, &[]);
    let before = f.token(&tenant, &user).expect("token before suspension");
    f.h.identity()
        .validate_token(&tenant, &before)
        .expect("token validates while the realm is active");

    let (suspend, body) = f
        .post(
            &format!("/admin/realms/{}/suspend", tenant.as_uuid()),
            &system_realm(),
            &operator,
        )
        .await;

    assert_eq!(suspend, StatusCode::OK, "suspend: {body}");
    assert_eq!(f.status(&tenant), RealmStatus::Suspended);
    assert!(
        matches!(
            f.h.identity().validate_token(&tenant, &before),
            Err(IdentityError::RealmSuspended)
        ),
        "a token issued before suspension must be refused after it"
    );
    assert!(
        matches!(f.token(&tenant, &user), Err(IdentityError::RealmSuspended)),
        "no new session may start in a suspended realm"
    );

    let unsuspend = f.unsuspend(&tenant, &system_realm(), &operator).await;

    assert_eq!(unsuspend, StatusCode::OK);
    assert_eq!(f.status(&tenant), RealmStatus::Active);
    let after = f.token(&tenant, &user).expect("login works again");
    f.h.identity()
        .validate_token(&tenant, &after)
        .expect("a fresh token validates after unsuspend");
}

/// Only a system-realm admin may suspend: a tenant's own superuser may not,
/// nor may a system-realm sub-admin without `hearth.realm.admin`.
#[tokio::test]
async fn suspend_requires_a_system_realm_realm_admin() {
    let f = Fixture::new().await;
    let tenant = f.tenant();
    let tenant_admin = f.user(&tenant, &["realm.admin"]);
    let tenant_token = f.token(&tenant, &tenant_admin).expect("tenant token");
    let sys_sub = f.user(&system_realm(), &["hearth.users.admin"]);
    let sys_sub_token = f.token(&system_realm(), &sys_sub).expect("sub token");
    let sys_realm_admin = f.user(&system_realm(), &["hearth.realm.admin"]);
    let sys_realm_admin_token = f
        .token(&system_realm(), &sys_realm_admin)
        .expect("realm-admin token");

    let own = f.suspend(&tenant, &tenant, &tenant_token).await;
    let sub = f.suspend(&tenant, &system_realm(), &sys_sub_token).await;

    assert_eq!(own, StatusCode::FORBIDDEN, "tenant admin on own realm");
    assert_eq!(sub, StatusCode::FORBIDDEN, "system users-admin");
    assert_eq!(f.status(&tenant), RealmStatus::Active);

    let permitted = f
        .suspend(&tenant, &system_realm(), &sys_realm_admin_token)
        .await;
    assert_eq!(permitted, StatusCode::OK, "system hearth.realm.admin");
    assert_eq!(f.status(&tenant), RealmStatus::Suspended);
}

/// The system realm is the operators' own home: it cannot be suspended.
#[tokio::test]
async fn system_realm_cannot_be_suspended() {
    let f = Fixture::new().await;
    let (_, operator) = f.operator();

    let status = f.suspend(&system_realm(), &system_realm(), &operator).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    f.h.identity()
        .validate_token(&system_realm(), &operator)
        .expect("the system realm keeps serving");
}

/// Archived realms belong to YAML reconciliation; suspend/unsuspend must not
/// move them (unsuspend would otherwise revive a realm YAML removed).
#[tokio::test]
async fn archived_realm_cannot_be_suspended_or_unsuspended() {
    let f = Fixture::new().await;
    let (_, operator) = f.operator();
    let tenant = f.tenant();
    f.h.identity()
        .update_realm(
            &tenant,
            &UpdateRealmRequest {
                status: Some(RealmStatus::Archived),
                ..UpdateRealmRequest::default()
            },
        )
        .expect("archive");

    let suspend = f.suspend(&tenant, &system_realm(), &operator).await;
    let unsuspend = f.unsuspend(&tenant, &system_realm(), &operator).await;

    assert_eq!(suspend, StatusCode::CONFLICT, "suspend archived");
    assert_eq!(unsuspend, StatusCode::CONFLICT, "unsuspend archived");
    assert_eq!(f.status(&tenant), RealmStatus::Archived);
}

/// Each transition is audited in the target realm with the actor and the old
/// and new status.
#[tokio::test]
async fn suspension_transitions_are_audited() {
    let f = Fixture::new().await;
    let (operator_id, operator) = f.operator();
    let tenant = f.tenant();

    assert_eq!(
        f.suspend(&tenant, &system_realm(), &operator).await,
        StatusCode::OK
    );
    assert_eq!(
        f.unsuspend(&tenant, &system_realm(), &operator).await,
        StatusCode::OK
    );

    let events =
        f.h.audit()
            .query(&AuditQuery {
                realm_id: tenant.clone(),
                start_time: None,
                end_time: None,
                actor: Some(operator_id.as_uuid().to_string()),
                action: Some(AuditAction::RealmUpdated),
                limit: None,
                agent_id: None,
                tool: None,
            })
            .expect("audit query");
    let transitions: Vec<(String, String)> = events
        .iter()
        .filter_map(|e| {
            let m = e.metadata.as_ref()?;
            Some((
                m["previous_status"].as_str()?.to_string(),
                m["status"].as_str()?.to_string(),
            ))
        })
        .collect();
    assert_eq!(
        transitions,
        vec![
            ("active".to_string(), "suspended".to_string()),
            ("suspended".to_string(), "active".to_string()),
        ],
        "one attributed event per transition, with old and new status"
    );
}

/// A runtime suspension survives YAML reconciliation (startup or reload),
/// even when the realm's YAML block changed and its config is rewritten.
#[tokio::test]
async fn reconcile_does_not_undo_a_runtime_suspension() {
    let f = Fixture::new().await;
    let (_, operator) = f.operator();
    let name = format!("ga3-yaml-{}", uuid::Uuid::new_v4());
    let config = |ttl: &str| Config {
        realms: Some(HashMap::from([(
            name.clone(),
            RealmYamlConfig {
                session_ttl: Some(ttl.to_string()),
                ..RealmYamlConfig::default()
            },
        )])),
        ..Config::default()
    };
    reconcile_realms(f.h.identity(), f.h.rbac(), &config("12h")).expect("first reconcile");
    let realm =
        f.h.identity()
            .get_realm_by_name(&name)
            .expect("lookup")
            .expect("YAML realm created")
            .id()
            .clone();

    assert_eq!(
        f.suspend(&realm, &system_realm(), &operator).await,
        StatusCode::OK
    );
    reconcile_realms(f.h.identity(), f.h.rbac(), &config("6h")).expect("reload with drift");

    let stored =
        f.h.identity()
            .get_realm(&realm)
            .expect("lookup")
            .expect("realm exists");
    assert_eq!(
        stored.status(),
        RealmStatus::Suspended,
        "suspension survives"
    );
    assert_eq!(
        stored.config().session_ttl_micros,
        Some(6 * 3600 * 1_000_000),
        "the reload did apply the YAML change"
    );
}
