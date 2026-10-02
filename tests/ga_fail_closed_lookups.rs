//! GA audit 2026-09-28 — two lookups that failed OPEN on an error.
//!
//! - **L12**: the authorization-code exchange (originally gRPC
//!   `TokenExchange`, now pinned on REST `POST /token`) skipped client
//!   authentication entirely when the client lookup returned an error, and
//!   went on to redeem (and burn) the code.
//! - **L13**: SCIM `is_admin_principal` answered "not an admin" on an RBAC
//!   read error, so a SCIM provisioning token could delete or modify an admin
//!   principal whenever the RBAC read failed.
//!
//! Both are driven by a corrupted storage record, which makes the engine's
//! deserialisation fail on every read.

#![allow(clippy::unwrap_used)]

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::core::RealmId;
use hearth::identity::{
    AuthorizationRequest, CodeChallengeMethod, CreateRealmRequest, CreateUserRequest, RealmConfig,
    RegisterClientRequest, UpdateRealmRequest,
};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, CreateRoleRequest, Permission, Scope, Subject};
use tower::ServiceExt as _;

const REDIRECT_URI: &str = "https://app.example.com/cb";
const CLIENT_SECRET: &str = "l12-client-secret-0123456789";
const VERIFIER: &str = "ga-fail-closed-verifier-0123456789abcdefghijk";

fn challenge() -> String {
    use base64::Engine as _;
    let digest = ring::digest::digest(&ring::digest::SHA256, VERIFIER.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.as_ref())
}

// ─── L12 ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn code_exchange_fails_closed_when_the_client_lookup_errors() {
    let h = common::TestHarness::embedded().await.unwrap();
    let realm = h.create_realm();
    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("l12-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "L12".into(),
                ..CreateUserRequest::default()
            },
        )
        .unwrap();
    let client = h
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: format!("l12-{}", uuid::Uuid::new_v4()),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: Some(CLIENT_SECRET.to_string()),
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                ..RegisterClientRequest::default()
            },
        )
        .unwrap();
    let code = h
        .identity()
        .authorize(
            &realm,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: REDIRECT_URI.to_string(),
                scope: "openid".to_string(),
                state: "st".to_string(),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: Some(challenge()),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: None,
                resource: None,
                amr_values: Vec::new(),
                response_mode: None,
                request: None,
                via_par: false,
            },
        )
        .unwrap()
        .code()
        .to_string();

    // Corrupt the client record: every lookup now errors.
    let client_key = format!("oauth:client:{}", client.client_id().as_uuid()).into_bytes();
    let original = h.storage().get(&realm, &client_key).unwrap().unwrap();
    h.storage().put(&realm, &client_key, b"{not json").unwrap();

    let app = router(Arc::new(AppState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
    )));
    let exchange = serde_json::json!({
        "grant_type": "authorization_code",
        "client_id": client.client_id().as_uuid().to_string(),
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": VERIFIER,
        "client_secret": CLIENT_SECRET,
    });

    let (status, body) = post_token(&app, &realm, &exchange).await;
    assert!(
        !status.is_success(),
        "a failed client lookup must refuse the exchange: {status} {body}"
    );
    assert!(body.get("access_token").is_none(), "{body}");

    // Failing closed means the grant was never attempted: with the record
    // restored, the very same request redeems the still-unspent code.
    // (Failing open ran the exchange, which burns the code before it reads
    // the client.)
    h.storage().put(&realm, &client_key, &original).unwrap();
    let (status, body) = post_token(&app, &realm, &exchange).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the refused call must not have consumed the code: {body}"
    );
    assert!(
        body["access_token"].as_str().is_some_and(|t| !t.is_empty()),
        "{body}"
    );
}

async fn post_token(
    app: &axum::Router,
    realm: &RealmId,
    body: &serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("x-realm-id", realm.as_uuid().to_string())
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

// ─── L13 ────────────────────────────────────────────────────────────────────

fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(s.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn scim_realm(h: &common::TestHarness, token: &str) -> RealmId {
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("l13-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .unwrap();
    h.identity()
        .update_realm(
            realm.id(),
            &UpdateRealmRequest {
                config: Some(RealmConfig {
                    scim_bearer_token_hash: Some(sha256_hex(token)),
                    ..RealmConfig::default()
                }),
                ..UpdateRealmRequest::default()
            },
        )
        .unwrap();
    realm.id().clone()
}

#[tokio::test]
async fn scim_delete_fails_closed_when_the_admin_check_cannot_read_rbac() {
    let token = "ga-l13-scim-provisioning-token";
    let h = common::TestHarness::embedded().await.unwrap();
    let realm = scim_realm(&h, token);
    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: format!("l13-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "L13".into(),
                first_name: "L".into(),
                last_name: "Thirteen".into(),
                ..CreateUserRequest::default()
            },
        )
        .unwrap();
    let role = h
        .rbac()
        .create_role(
            &realm,
            &CreateRoleRequest {
                name: "l13-role".into(),
                description: None,
                permissions: vec![Permission::new("docs.read".to_string()).unwrap()],
                parent_roles: Vec::new(),
                scope_kind: hearth::rbac::RoleScopeKind::Realm,
                allow_reserved_permissions: false,
            },
        )
        .unwrap();
    h.rbac()
        .assign_role(
            &realm,
            &AssignRoleRequest {
                subject: Subject::User(user.id().clone()),
                role_id: role.id.clone(),
                scope: Scope::Realm,
                assigned_by: None,
            },
        )
        .unwrap();
    // Corrupt the role: resolving the user's permissions now errors.
    let role_key = format!("rba:role:{}", role.id.as_uuid()).into_bytes();
    h.storage().put(&realm, &role_key, b"{not json").unwrap();
    assert!(
        h.rbac()
            .resolve_permissions(user.id(), &realm, None, None)
            .is_err(),
        "precondition: the RBAC read must fail"
    );

    let app = router(Arc::new(AppState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
    )));
    let status = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/scim/v2/Users/{}", user.id().as_uuid()))
                .header("x-realm-id", realm.as_uuid().to_string())
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status();
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "an unknowable admin status must refuse the delete, not allow it"
    );
    assert!(
        h.identity().get_user(&realm, user.id()).unwrap().is_some(),
        "the user must not have been deleted"
    );
}
