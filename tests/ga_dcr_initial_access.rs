//! GA audit 2026-09-28 M9 — DCR `authenticated` mode accepted ANY valid realm
//! access token as the RFC 7591 §3.1 initial access token, so any end user
//! (or any `client_credentials` token) could register a client. The initial
//! access token must now carry `hearth.clients.admin` (or `hearth.admin`) —
//! the same authority the admin `/clients` API requires.

#![allow(clippy::unwrap_used)]

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hearth::core::RealmId;
use hearth::identity::{
    CreateRealmRequest, CreateUserRequest, DcrPolicy, RealmConfig, SessionContext,
};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use tower::ServiceExt as _;

struct Env {
    h: common::TestHarness,
    realm: RealmId,
    realm_name: String,
}

async fn env() -> Env {
    let h = common::TestHarness::in_process().await.unwrap();
    let realm_name = format!("dcr-iat-{}", uuid::Uuid::new_v4());
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: realm_name.clone(),
            config: Some(RealmConfig {
                dcr_policy: Some(DcrPolicy::Authenticated),
                ..Default::default()
            }),
        })
        .unwrap()
        .id()
        .clone();
    h.rbac().seed_realm(&realm).unwrap();
    Env {
        h,
        realm,
        realm_name,
    }
}

/// A user access token; with `role` the user first gets that seeded role.
fn token(e: &Env, role: Option<&str>) -> String {
    let user =
        e.h.identity()
            .create_user(
                &e.realm,
                &CreateUserRequest {
                    email: format!("dcr-{}@example.com", uuid::Uuid::new_v4()),
                    display_name: "DCR".into(),
                    ..CreateUserRequest::default()
                },
            )
            .unwrap();
    if let Some(role) = role {
        let role =
            e.h.rbac()
                .get_role_by_name(&e.realm, role)
                .unwrap()
                .unwrap();
        e.h.rbac()
            .assign_role(
                &e.realm,
                &AssignRoleRequest {
                    subject: Subject::User(user.id().clone()),
                    role_id: role.id,
                    scope: Scope::Realm,
                    assigned_by: None,
                },
            )
            .unwrap();
    }
    let session =
        e.h.identity()
            .create_session(&e.realm, user.id(), &SessionContext::default())
            .unwrap();
    e.h.identity()
        .issue_tokens(&e.realm, user.id(), session.id())
        .unwrap()
        .access_token()
        .to_string()
}

async fn register(e: &Env, realm_route: bool, bearer: &str) -> StatusCode {
    let state = Arc::new(AppState::new(
        e.h.identity_arc(),
        e.h.rbac_arc(),
        e.h.audit_arc(),
    ));
    let mut builder = Request::builder()
        .method("POST")
        .header("Authorization", format!("Bearer {bearer}"))
        .header("Content-Type", "application/json");
    builder = if realm_route {
        builder.uri(format!("/realms/{}/register", e.realm_name))
    } else {
        builder
            .uri("/register")
            .header("X-Realm-ID", e.realm.as_uuid().to_string())
    };
    let body = serde_json::json!({
        "client_name": "DCR App",
        "redirect_uris": ["https://dcr.example.com/cb"],
        "grant_types": ["authorization_code"],
    });
    router(state)
        .oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn an_ordinary_user_token_is_not_an_initial_access_token() {
    let e = env().await;
    let user = token(&e, None);
    assert_eq!(register(&e, false, &user).await, StatusCode::FORBIDDEN);
    assert_eq!(register(&e, true, &user).await, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_clients_admin_token_registers_a_client() {
    let e = env().await;
    let admin = token(&e, Some("hearth.clients.admin"));
    assert_eq!(register(&e, false, &admin).await, StatusCode::CREATED);
    assert_eq!(register(&e, true, &admin).await, StatusCode::CREATED);
}

#[tokio::test]
async fn another_sub_admin_permission_is_not_enough() {
    let e = env().await;
    let users_admin = token(&e, Some("hearth.users.admin"));
    assert_eq!(
        register(&e, false, &users_admin).await,
        StatusCode::FORBIDDEN
    );
}
