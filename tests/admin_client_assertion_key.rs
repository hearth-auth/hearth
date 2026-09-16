//! §4.22#7 (task 22.15) — an operator surface for `assertion_public_key`.
//!
//! `private_key_jwt` client authentication (RFC 7523 §2.2) and the
//! `urn:ietf:params:oauth:grant-type:jwt-bearer` grant both verify a client's
//! signed assertion against `OAuthClient::assertion_public_key`. The engine has
//! read that field since those features shipped, and `UpdateClientRequest` has
//! carried it all along — but **no protocol surface ever wrote it**. The REST
//! admin handler, the gRPC converter, the admin UI form and the YAML reconciler
//! each hard-coded `assertion_public_key: None`, so the only way a key ever got
//! installed was an in-crate unit test.
//!
//! Discovery meanwhile advertised `private_key_jwt` in
//! `token_endpoint_auth_methods_supported`, and the FAPI 2.0 Advanced profile
//! depends on it. Both were advertised against a key an operator had no way to
//! install.
//!
//! These tests drive `PATCH /admin/applications/{id}` — the surface that was
//! added — rather than the engine, because the engine half already worked.

#![allow(clippy::unwrap_used)]

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use data_encoding::BASE64URL_NOPAD;
use hearth::core::RealmId;
use hearth::identity::{CreateUserRequest, RegisterClientRequest, SessionContext};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::{AssignRoleRequest, Scope, Subject};
use tower::ServiceExt as _;

async fn build_app(harness: &common::TestHarness) -> axum::Router {
    let state = Arc::new(AppState::new(
        harness.identity_arc(),
        harness.rbac_arc(),
        harness.audit_arc(),
    ));
    router(state)
}

/// Issues a realm-admin access token.
async fn admin_token(harness: &common::TestHarness, realm: &RealmId, email: &str) -> String {
    let user = harness
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: email.into(),
                display_name: "Admin".into(),
                ..Default::default()
            },
        )
        .expect("create user");
    let role = harness
        .rbac()
        .get_role_by_name(realm, "realm.admin")
        .expect("lookup")
        .expect("seeded");
    harness
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
        .expect("assign admin");
    let session = harness
        .identity()
        .create_session(realm, user.id(), &SessionContext::default())
        .expect("session");
    harness
        .identity()
        .issue_tokens(realm, user.id(), session.id())
        .expect("issue")
        .access_token()
        .to_string()
}

/// `PATCH /admin/applications/{id}` with `body`, returning the status.
async fn patch_client(
    app: axum::Router,
    token: &str,
    realm: &RealmId,
    client_id: &str,
    body: serde_json::Value,
) -> StatusCode {
    let req = Request::builder()
        .method("PATCH")
        .uri(format!("/admin/applications/{client_id}"))
        .header("authorization", format!("Bearer {token}"))
        .header("x-realm-id", realm.as_uuid().to_string())
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    app.oneshot(req).await.unwrap().status()
}

/// A valid base64url Ed25519 public key (32 bytes).
fn valid_key() -> String {
    BASE64URL_NOPAD.encode(&[7u8; 32])
}

/// The headline gap: there was no way to set the key at all.
#[tokio::test]
async fn patch_installs_the_assertion_public_key() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm, "keyadmin@example.com").await;

    let client = h
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "Assertion Client".to_string(),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("register client");

    assert!(
        client.assertion_public_key().is_none(),
        "a freshly registered client starts with no assertion key"
    );

    let key = valid_key();
    let status = patch_client(
        build_app(&h).await,
        &token,
        &realm,
        &client.client_id().as_uuid().to_string(),
        serde_json::json!({ "assertion_public_key": key }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "PATCH must accept the key");

    let reloaded = h
        .identity()
        .get_client(&realm, client.client_id())
        .expect("get_client")
        .expect("client exists");
    assert_eq!(
        reloaded.assertion_public_key(),
        Some(key.as_str()),
        "the key must be persisted — private_key_jwt and the jwt-bearer grant \
         read exactly this field"
    );
}

/// `null` clears the key; omitting the field leaves it alone.
#[tokio::test]
async fn patch_clears_and_preserves_the_assertion_public_key() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm, "keyadmin2@example.com").await;
    let app = build_app(&h).await;

    let client = h
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "Assertion Client 2".to_string(),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("register client");
    let cid = client.client_id().as_uuid().to_string();
    let key = valid_key();

    assert_eq!(
        patch_client(
            app.clone(),
            &token,
            &realm,
            &cid,
            serde_json::json!({ "assertion_public_key": key })
        )
        .await,
        StatusCode::OK
    );

    // An unrelated PATCH must not disturb it.
    assert_eq!(
        patch_client(
            app.clone(),
            &token,
            &realm,
            &cid,
            serde_json::json!({ "client_name": "Renamed" })
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(
        h.identity()
            .get_client(&realm, client.client_id())
            .unwrap()
            .unwrap()
            .assertion_public_key(),
        Some(key.as_str()),
        "omitting the field must leave the key unchanged"
    );

    // `null` clears it.
    assert_eq!(
        patch_client(
            app,
            &token,
            &realm,
            &cid,
            serde_json::json!({ "assertion_public_key": null })
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(
        h.identity()
            .get_client(&realm, client.client_id())
            .unwrap()
            .unwrap()
            .assertion_public_key(),
        None,
        "null must clear the key"
    );
}

/// The engine's existing validation is reached through the new surface: the
/// value must base64url-decode to exactly 32 bytes.
#[tokio::test]
async fn patch_rejects_a_malformed_assertion_public_key() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();
    h.rbac().seed_realm(&realm).expect("seed");
    let token = admin_token(&h, &realm, "keyadmin3@example.com").await;
    let app = build_app(&h).await;

    let client = h
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "Assertion Client 3".to_string(),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("register client");
    let cid = client.client_id().as_uuid().to_string();

    let too_short = BASE64URL_NOPAD.encode(&[1u8; 16]);
    let too_long = BASE64URL_NOPAD.encode(&[1u8; 64]);
    for bad in [
        "not base64url!!",  // not decodable
        too_short.as_str(), // 16 bytes, not 32
        too_long.as_str(),  // 64 bytes, not 32
    ] {
        let status = patch_client(
            app.clone(),
            &token,
            &realm,
            &cid,
            serde_json::json!({ "assertion_public_key": bad }),
        )
        .await;
        assert_ne!(
            status,
            StatusCode::OK,
            "a malformed assertion key ({bad}) must be refused"
        );
        assert!(
            h.identity()
                .get_client(&realm, client.client_id())
                .unwrap()
                .unwrap()
                .assertion_public_key()
                .is_none(),
            "a refused PATCH must not have written anything"
        );
    }
}
