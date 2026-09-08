//! Audit 2026-08-28 §4.20#3: a realm wedged in `DeletingInProgress`.
//!
//! `delete_realm` stamps `DeletingInProgress` on a realm before it starts the
//! cascade, so a process death between the `204` and the end of the cascade
//! leaves the realm in that status permanently. Two things then hold it there:
//!
//! - the admin API refuses to delete anything but an `Archived` realm, so the
//!   only route that converges the cascade is closed; and
//! - startup reconciliation calls `update_realm` on a declared realm whose
//!   config drifted, `update_realm` refuses a `DeletingInProgress` realm, and
//!   the error aborts the whole reconciliation — the server does not start.
//!
//! The cascade is idempotent, so a retry is the documented recovery. These
//! tests pin both halves of it.
//!
//! Recovery runs as a **system-realm** admin. Stamping `DeletingInProgress`
//! revokes every session in the realm, and `validate_token` fails closed on a
//! non-active realm, so the wedged realm's own admins hold nothing that still
//! authenticates.

#![allow(clippy::unwrap_used)]

mod common;

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hearth::config::{Config, RealmYamlConfig};
use hearth::core::RealmId;
use hearth::identity::reconcile::reconcile_realms;
use hearth::identity::{CreateUserRequest, RealmStatus, SessionContext, UpdateRealmRequest};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use tower::ServiceExt as _;

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn build_app(h: &common::TestHarness) -> axum::Router {
    router(Arc::new(AppState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
    )))
}

fn system_realm_id() -> RealmId {
    RealmId::new(uuid::Uuid::nil())
}

/// Creates a system-realm admin and returns its access token. The system realm
/// is the only place an operator can hold a token that still authenticates
/// while the target realm is wedged.
async fn system_admin_token(h: &common::TestHarness, suffix: &str) -> String {
    let sys = system_realm_id();
    h.rbac().seed_realm(&sys).expect("seed system rbac");

    let user = h
        .identity()
        .create_admin_user(&CreateUserRequest {
            email: format!("wedge-sys-{suffix}@test.example"),
            display_name: "System Admin".into(),
            first_name: "System".into(),
            last_name: "Admin".into(),
            attributes: Default::default(),
        })
        .expect("create system admin");

    let role = h
        .rbac()
        .get_role_by_name(&sys, "realm.admin")
        .expect("lookup role")
        .expect("realm.admin role exists after seed");
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
        .expect("create session");
    h.identity()
        .issue_tokens(&sys, user.id(), session.id())
        .expect("issue tokens")
        .access_token()
        .to_string()
}

/// Creates a realm and seeds its RBAC. The caller deletes it as a system admin.
fn setup_realm(h: &common::TestHarness) -> RealmId {
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed rbac");
    realm
}

fn delete_request(realm: &RealmId, token: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(format!("/admin/realms/{}", realm.as_uuid()))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Realm-ID", system_realm_id().as_uuid().to_string())
        .body(Body::empty())
        .expect("build request")
}

/// Puts `realm` into `DeletingInProgress`, the state a process death mid-cascade
/// leaves behind.
fn wedge_realm(h: &common::TestHarness, realm: &RealmId) {
    h.identity()
        .update_realm(
            realm,
            &UpdateRealmRequest {
                status: Some(RealmStatus::DeletingInProgress),
                ..Default::default()
            },
        )
        .expect("wedge realm in DeletingInProgress");

    let stored = h
        .identity()
        .get_realm(realm)
        .expect("get realm")
        .expect("realm still exists");
    assert_eq!(
        stored.status(),
        RealmStatus::DeletingInProgress,
        "precondition: the realm is wedged mid-cascade"
    );
}

fn config_with_realms(realms: HashMap<String, RealmYamlConfig>) -> Config {
    Config {
        realms: Some(realms),
        ..Config::default()
    }
}

// ─── The admin API must accept a retry ────────────────────────────────────────

/// A realm wedged in `DeletingInProgress` had its deletion authorised once
/// already. The admin API must let the operator run it again so the idempotent
/// cascade converges, instead of answering `409` for the life of the realm.
#[tokio::test]
async fn a_wedged_realm_can_be_deleted_again_through_the_admin_api() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let token = system_admin_token(&h, "retry").await;
    let realm = setup_realm(&h);
    wedge_realm(&h, &realm);

    let resp = build_app(&h)
        .oneshot(delete_request(&realm, &token))
        .await
        .expect("delete realm");

    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "a realm wedged in DeletingInProgress must be deletable again; \
         refusing it leaves the realm undeletable for the life of the deployment"
    );

    // A realm above `cascade_background_threshold` runs its cascade on a
    // spawned task. That task has no `.await` in it, so yielding lets it
    // finish; a realm below the threshold is already done here.
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    assert!(
        h.identity().get_realm(&realm).expect("get realm").is_none(),
        "the retried cascade must remove the realm record"
    );
}

/// An `Active` realm still may not be permanently deleted — the archival gate
/// stays. This pins that the fix above widened the gate by exactly one status.
#[tokio::test]
async fn an_active_realm_is_still_refused_by_the_admin_api() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let token = system_admin_token(&h, "active").await;
    let realm = setup_realm(&h);

    let resp = build_app(&h)
        .oneshot(delete_request(&realm, &token))
        .await
        .expect("delete realm");

    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "an active realm must still be archived before it can be deleted"
    );
}

// ─── Startup reconciliation must finish ───────────────────────────────────────

/// Reconciliation walks every declared realm. One wedged realm must not stop
/// the server booting, and must not stop the other declared realms being
/// reconciled.
#[tokio::test]
async fn reconciliation_completes_when_a_declared_realm_is_wedged() {
    let h = common::TestHarness::embedded().await.expect("harness");

    // Two declared realms, both created by a first reconcile pass.
    let mut declared: HashMap<String, RealmYamlConfig> = HashMap::new();
    declared.insert("wedged-corp".to_string(), RealmYamlConfig::default());
    declared.insert("healthy-corp".to_string(), RealmYamlConfig::default());
    reconcile_realms(
        h.identity(),
        h.rbac(),
        &config_with_realms(declared.clone()),
    )
    .expect("first reconcile creates both realms");

    let wedged = h
        .identity()
        .get_realm_by_name("wedged-corp")
        .expect("get realm")
        .expect("realm created")
        .id()
        .clone();
    wedge_realm(&h, &wedged);

    // Drift both realms' config so reconciliation calls `update_realm` on each.
    for cfg in declared.values_mut() {
        cfg.session_ttl = Some("13h".to_string());
    }

    reconcile_realms(h.identity(), h.rbac(), &config_with_realms(declared))
        .expect("a realm wedged mid-cascade must not abort startup reconciliation");

    // The healthy realm was still reconciled.
    let healthy = h
        .identity()
        .get_realm_by_name("healthy-corp")
        .expect("get realm")
        .expect("healthy realm still exists");
    assert_eq!(
        healthy.status(),
        RealmStatus::Active,
        "the realm that was not wedged must still be reconciled"
    );
}
