#![allow(clippy::unwrap_used)]
//! Audit §4.9#7 regression: `GET /admin/audit?start_time=…&end_time=…` with
//! `start_time > end_time` built a reversed storage scan window.
//!
//! A reversed window indexed a legacy eager SST body as `entries[lo..hi]` with
//! `lo > hi`. That panics, and under the release profile's `panic=abort` it
//! killed the whole multi-tenant process — SIGABRT in 6 of 6 runs from a
//! single authenticated request.
//!
//! The request is now refused with `400 Bad Request` before it reaches
//! storage, and the storage layer refuses a reversed window on its own.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{Clock, RealmId, SystemClock};
use hearth::identity::{
    CreateRealmRequest, CreateUserRequest, CredentialConfig, EmbeddedIdentityEngine,
    IdentityConfig, IdentityEngine, SessionContext,
};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, EmbeddedRbacEngine, RbacEngine, Scope, Subject};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use serde_json::Value;
use tower::ServiceExt;

struct Rig {
    app: axum::Router,
    realm_id: RealmId,
    token: String,
    _storage: Arc<EmbeddedStorageEngine>,
    _dir: tempfile::TempDir,
}

fn build_rig() -> Rig {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = StorageConfig::dev(dir.path().to_path_buf());
    let engine = Arc::new(EmbeddedStorageEngine::open(config).expect("open"));
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let identity_config = IdentityConfig {
        credential: CredentialConfig::fast_for_testing(),
        ..IdentityConfig::default()
    };
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&engine) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn AuditEngine>;
    let identity = Arc::new(
        EmbeddedIdentityEngine::new(
            Arc::clone(&engine) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
            identity_config,
            Arc::clone(&audit),
        )
        .expect("identity engine"),
    );
    let authz = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&engine) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    ));

    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: "audit-reversed-window".to_string(),
            config: None,
        })
        .expect("create realm");
    let realm_id = realm.id().clone();

    let user = identity
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "admin@audit-reversed-window.test".to_string(),
                display_name: "Admin".to_string(),
                first_name: "Admin".to_string(),
                last_name: "User".to_string(),
                attributes: Default::default(),
            },
        )
        .expect("create admin user");
    authz.seed_realm(&realm_id).expect("seed realm");
    let admin_role = authz
        .get_role_by_name(&realm_id, "realm.admin")
        .expect("lookup")
        .expect("seed role present");
    authz
        .assign_role(
            &realm_id,
            &AssignRoleRequest {
                subject: Subject::User(user.id().clone()),
                role_id: admin_role.id.clone(),
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign role");
    let session = identity
        .create_session(&realm_id, user.id(), &SessionContext::default())
        .expect("session");
    let tokens = identity
        .issue_tokens(&realm_id, user.id(), session.id())
        .expect("tokens");
    let token = tokens.access_token().to_string();

    let state = Arc::new(AppState::new(identity, authz, audit));
    Rig {
        app: router(state),
        realm_id,
        token,
        _storage: engine,
        _dir: dir,
    }
}

async fn get_audit(rig: &Rig, query: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/admin/audit?{query}"))
        .header("authorization", format!("Bearer {}", rig.token))
        .header("x-realm-id", rig.realm_id.as_uuid().to_string())
        .body(Body::empty())
        .expect("build request");
    let resp = rig.app.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
    let val: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, val)
}

#[tokio::test]
async fn reversed_audit_window_is_refused_and_the_server_survives() {
    let rig = build_rig();

    let (status, body) = get_audit(&rig, "start_time=2000000&end_time=1000000").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");

    // The process is still serving: an ordered window over the same route works.
    let (status, _) = get_audit(&rig, "start_time=1000000&end_time=2000000").await;
    assert_eq!(status, StatusCode::OK);
}

/// The bound is on ordering only. Equal bounds select an empty window and are
/// legal; an unbounded query is unaffected.
#[tokio::test]
async fn ordered_and_unbounded_audit_windows_are_unaffected() {
    let rig = build_rig();

    let (status, _) = get_audit(&rig, "start_time=1000000&end_time=1000000").await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = get_audit(&rig, "limit=10").await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = get_audit(&rig, "end_time=2000000").await;
    assert_eq!(status, StatusCode::OK);
}
