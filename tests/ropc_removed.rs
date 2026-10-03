//! scope-trim-trusted-core, group 8: the ROPC password grant is not supported.
//!
//! `tests/ropc_grant_type_gate.rs` proves the refusal for public clients on
//! the global token endpoint. This file covers the rest of the requirement:
//! a confidential client authenticating with HTTP Basic, the realm-scoped
//! token endpoint, both discovery documents, and dynamic client registration.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use hearth::identity::{
    CleartextPassword, ClientTrustLevel, CreateRealmRequest, CreateUserRequest, DcrPolicy,
    RealmConfig, RegisterClientRequest,
};
use hearth::protocol::http::{router, AppState};
use tower::ServiceExt as _;

const SECRET: &str = "ropc-removed-client-secret-0123456789";
const PASSWORD: &str = "RopcRemoved123!";

struct Fixture {
    state: Arc<AppState>,
    realm_id: String,
    realm_name: String,
    client_id: String,
    email: String,
}

async fn fixture() -> Fixture {
    let h = common::TestHarness::in_process().await.expect("harness");
    let realm_name = format!("ropc-gone-{}", uuid::Uuid::new_v4());
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: realm_name.clone(),
            config: Some(RealmConfig {
                dcr_policy: Some(DcrPolicy::Open),
                ..Default::default()
            }),
        })
        .expect("realm")
        .id()
        .clone();
    let client = h
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "ROPC confidential".to_string(),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                client_secret: Some(SECRET.to_string()),
                grant_types: vec![
                    "authorization_code".to_string(),
                    "client_credentials".to_string(),
                ],
                trust_level: ClientTrustLevel::FirstParty,
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("client");
    let email = format!("ropc-{}@example.com", uuid::Uuid::new_v4());
    let user = h
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: email.clone(),
                display_name: "ROPC".to_string(),
                ..Default::default()
            },
        )
        .expect("user");
    h.identity()
        .set_password(
            &realm,
            user.id(),
            &CleartextPassword::from_string(PASSWORD.to_string()),
        )
        .expect("password");
    Fixture {
        state: Arc::new(AppState::new(h.identity_arc(), h.rbac_arc(), h.audit_arc())),
        realm_id: realm.as_uuid().to_string(),
        realm_name,
        client_id: client.client_id().as_uuid().to_string(),
        email,
    }
}

async fn send(f: &Fixture, req: Request<Body>) -> (StatusCode, serde_json::Value) {
    let resp = router(Arc::clone(&f.state))
        .oneshot(req)
        .await
        .expect("response");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

/// A form-encoded password grant from a confidential client using HTTP Basic.
fn password_grant(f: &Fixture, path: &str) -> Request<Body> {
    let basic =
        base64::engine::general_purpose::STANDARD.encode(format!("{}:{SECRET}", f.client_id));
    let form = format!(
        "grant_type=password&username={}&password={PASSWORD}",
        f.email.replace('@', "%40")
    );
    Request::builder()
        .method("POST")
        .uri(path)
        .header("X-Realm-ID", &f.realm_id)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Authorization", format!("Basic {basic}"))
        .body(Body::from(form))
        .expect("request")
}

#[tokio::test]
async fn a_confidential_client_is_refused_on_both_token_endpoints() {
    let f = fixture().await;
    for path in [
        "/token".to_string(),
        format!("/realms/{}/token", f.realm_name),
    ] {
        let (status, body) = send(&f, password_grant(&f, &path)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}: {body}");
        assert_eq!(body["error"], "unsupported_grant_type", "{path}: {body}");
        assert!(body.get("access_token").is_none(), "{path}: no token");
    }
}

/// Control: the same client and credentials work for a grant that exists,
/// so the refusal above is about the grant type, not a broken fixture.
#[tokio::test]
async fn control_the_same_client_authenticates_for_client_credentials() {
    let f = fixture().await;
    for path in [
        "/token".to_string(),
        format!("/realms/{}/token", f.realm_name),
    ] {
        let basic =
            base64::engine::general_purpose::STANDARD.encode(format!("{}:{SECRET}", f.client_id));
        let req = Request::builder()
            .method("POST")
            .uri(&path)
            .header("X-Realm-ID", &f.realm_id)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Authorization", format!("Basic {basic}"))
            .body(Body::from("grant_type=client_credentials"))
            .expect("request");
        let (status, body) = send(&f, req).await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
        assert!(body["access_token"].is_string(), "{path}: {body}");
    }
}

#[tokio::test]
async fn discovery_does_not_list_the_password_grant() {
    let f = fixture().await;
    for path in [
        "/.well-known/openid-configuration".to_string(),
        format!("/realms/{}/.well-known/openid-configuration", f.realm_name),
    ] {
        let req = Request::builder()
            .uri(&path)
            .header("X-Realm-ID", &f.realm_id)
            .body(Body::empty())
            .expect("request");
        let (status, body) = send(&f, req).await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
        let grants = body["grant_types_supported"]
            .as_array()
            .unwrap_or_else(|| panic!("{path}: grant_types_supported: {body}"));
        assert!(
            grants.iter().any(|g| g == "authorization_code"),
            "{path}: control"
        );
        assert!(
            !grants.iter().any(|g| g == "password"),
            "{path}: {grants:?}"
        );
    }
}

#[tokio::test]
async fn dynamic_registration_refuses_the_password_grant() {
    let f = fixture().await;
    let register = |grants: serde_json::Value| {
        Request::builder()
            .method("POST")
            .uri("/register")
            .header("X-Realm-ID", &f.realm_id)
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "client_name": "ropc-dcr",
                    "redirect_uris": ["https://app.example.com/cb"],
                    "grant_types": grants,
                })
                .to_string(),
            ))
            .expect("request")
    };
    let (status, body) = send(&f, register(serde_json::json!(["authorization_code"]))).await;
    assert_eq!(status, StatusCode::CREATED, "control: {body}");

    let (status, body) = send(
        &f,
        register(serde_json::json!(["authorization_code", "password"])),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_client_metadata", "{body}");
}

/// The step-up MFA grant is removed too (owner decision 2026-10-02): like
/// ROPC it took the user's password at the token endpoint, and it could not
/// use passkeys. Both endpoints refuse it on the grant type alone.
#[tokio::test]
async fn the_step_up_mfa_grant_is_refused_on_both_token_endpoints() {
    let f = fixture().await;
    let basic =
        base64::engine::general_purpose::STANDARD.encode(format!("{}:{SECRET}", f.client_id));
    for path in [
        "/token".to_string(),
        format!("/realms/{}/token", f.realm_name),
    ] {
        let form = format!(
            "grant_type=urn%3Ahearth%3Aparams%3Agrant-type%3Astep-up-mfa\
             &username={}&password={PASSWORD}&mfa_code=123456",
            f.email.replace('@', "%40")
        );
        let req = Request::builder()
            .method("POST")
            .uri(&path)
            .header("X-Realm-ID", &f.realm_id)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Authorization", format!("Basic {basic}"))
            .body(Body::from(form))
            .expect("request");
        let (status, body) = send(&f, req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}: {body}");
        assert_eq!(body["error"], "unsupported_grant_type", "{path}: {body}");
    }
}
