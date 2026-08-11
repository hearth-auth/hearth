#![allow(clippy::unwrap_used)]
//! Regression tests for HEA-1750 (A1): OAuth client registration must be a
//! privileged operation on both the REST and gRPC surfaces.
//!
//! Before this fix, `POST /clients` (REST) and `OAuthService::register_client`
//! (gRPC) skipped every authorization gate, letting any unauthenticated caller
//! mint OAuth clients. Both now require an admin token carrying
//! `hearth.clients.admin` (or the `hearth.admin` superuser permission), mirroring
//! the `/admin/clients` and `ApplicationAdminService::create_application` gates.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::core::RealmId;
use hearth::identity::{CreateUserRequest, SessionContext};
use hearth::protocol::admin_auth::AdminRateLimiter;
use hearth::protocol::grpc::oauth::OAuthSvc;
use hearth::protocol::grpc::server::GrpcState;
use hearth::protocol::http::{router, AppState};
use hearth::protocol::proto::identity::v1 as id_pb;
use hearth::protocol::proto::identity::v1::o_auth_service_server::OAuthService;
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use tonic::{Code, Request as TonicRequest};
use tower::ServiceExt as _;

fn register_body() -> serde_json::Value {
    serde_json::json!({
        "client_name": "Attacker App",
        "redirect_uris": ["https://evil.example.com/cb"],
        "grant_types": ["authorization_code"]
    })
}

fn build_app(harness: &common::TestHarness) -> axum::Router {
    let state = Arc::new(AppState::new(
        harness.identity_arc(),
        harness.rbac_arc(),
        harness.audit_arc(),
    ));
    router(state)
}

/// Issues an admin access token carrying the named seed role's permission.
/// The realm must already have its RBAC roles seeded.
fn issue_admin_token(h: &common::TestHarness, realm: &RealmId, role_name: &str) -> String {
    let user = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("{}-admin@hea1750.test", role_name.replace('.', "-")),
                display_name: "Admin".into(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let role = h
        .rbac()
        .get_role_by_name(realm, role_name)
        .expect("lookup role")
        .unwrap_or_else(|| panic!("seed role '{role_name}' not found"));
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

// ===== A1 (REST): unauthenticated POST /clients is rejected =====

#[tokio::test]
async fn rest_post_clients_unauthenticated_rejected() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed rbac");
    let realm_id = realm.as_uuid().to_string();

    let app = build_app(&h);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/clients")
                .header("X-Realm-ID", &realm_id)
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_string(&register_body()).unwrap()))
                .expect("req"),
        )
        .await
        .expect("resp");

    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "unauthenticated POST /clients must be rejected"
    );
}

// ===== A1 (REST): admin-gated POST /clients still succeeds =====

#[tokio::test]
async fn rest_post_clients_admin_succeeds() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed rbac");
    let realm_id = realm.as_uuid().to_string();
    let token = issue_admin_token(&h, &realm, "hearth.clients.admin");

    let app = build_app(&h);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/clients")
                .header("X-Realm-ID", &realm_id)
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_string(&register_body()).unwrap()))
                .expect("req"),
        )
        .await
        .expect("resp");

    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "hearth.clients.admin must be allowed to register a client"
    );

    let body_bytes = to_bytes(resp.into_body(), 1024 * 1024).await.expect("body");
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).expect("json");
    assert!(body["client_id"].as_str().is_some_and(|s| !s.is_empty()));
}

// ===== A1 (gRPC): unauthenticated register_client is rejected =====

fn grpc_state(h: &common::TestHarness) -> GrpcState {
    GrpcState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
        Arc::new(AdminRateLimiter::new()),
    )
}

fn grpc_register_request(
    realm: &RealmId,
    token: Option<&str>,
) -> TonicRequest<id_pb::RegisterClientRequest> {
    let mut r = TonicRequest::new(id_pb::RegisterClientRequest {
        client_name: "gRPC Attacker App".to_string(),
        redirect_uris: vec!["https://evil.example.com/cb".to_string()],
        client_secret: None,
        grant_types: vec!["authorization_code".to_string()],
        access_token_authorization: 0,
        trust_level: None,
    });
    r.metadata_mut().insert(
        "x-realm-id",
        realm.as_uuid().to_string().parse().expect("realm meta"),
    );
    if let Some(t) = token {
        r.metadata_mut().insert(
            "authorization",
            format!("Bearer {t}").parse().expect("meta"),
        );
    }
    r
}

#[tokio::test]
async fn grpc_register_client_unauthenticated_rejected() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed rbac");
    let svc = OAuthSvc::new(grpc_state(&h));

    let err = svc
        .register_client(grpc_register_request(&realm, None))
        .await
        .expect_err("unauthenticated register_client must be denied");

    assert_eq!(
        err.code(),
        Code::Unauthenticated,
        "gRPC register_client without a token must be UNAUTHENTICATED"
    );
}

#[tokio::test]
async fn grpc_register_client_admin_succeeds() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed rbac");
    let token = issue_admin_token(&h, &realm, "hearth.clients.admin");
    let svc = OAuthSvc::new(grpc_state(&h));

    let resp = svc
        .register_client(grpc_register_request(&realm, Some(&token)))
        .await
        .expect("hearth.clients.admin must be allowed to register a client");

    assert!(
        !resp.into_inner().client_id.is_empty(),
        "registered client must have an id"
    );
}
