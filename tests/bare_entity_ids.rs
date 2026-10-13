#![allow(clippy::unwrap_used)]
//! Entity IDs are bare UUIDs (OpenSpec change `bare-entity-ids`).
//!
//! A user had two IDs: the admin API and SCIM showed the bare UUID, and the
//! user's token carried `sub` = `user_<uuid>`. So an application that stored
//! the SCIM `id` could not match it with the token's `sub`.
//!
//! 1. A user's token `sub` is the SCIM `id`, and `sid` and `tid` are bare.
//! 2. A client's own token keeps `sub` = `client_<uuid>`, and the client can
//!    still introspect and revoke it.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use hearth::core::{RealmId, UserId};
use hearth::identity::{
    ClientCredentialsRequest, ClientTrustLevel, CreateRealmRequest, RealmConfig,
    RegisterClientRequest, SessionContext, UpdateRealmRequest,
};
use hearth::protocol::http::{router, AppState};
use serde_json::json;
use sha2::{Digest, Sha256};
use tower::ServiceExt as _;

const SCIM_TOKEN: &str = "bare-ids-scim-token-0123456789";
const CLIENT_SECRET: &str = "bare-ids-client-secret-0123456789!";

fn app(h: &common::TestHarness) -> axum::Router {
    router(Arc::new(AppState::new(
        h.identity_arc(),
        h.rbac_arc(),
        h.audit_arc(),
    )))
}

/// A realm with a SCIM provisioning token. Returns its ID and name.
fn realm(h: &common::TestHarness) -> (RealmId, String) {
    let name = format!(
        "bare-ids-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: name.clone(),
            config: None,
        })
        .expect("create realm");
    let hash: String = Sha256::digest(SCIM_TOKEN.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    h.identity()
        .update_realm(
            realm.id(),
            &UpdateRealmRequest {
                config: Some(RealmConfig {
                    scim_bearer_token_hash: Some(hash),
                    ..RealmConfig::default()
                }),
                ..UpdateRealmRequest::default()
            },
        )
        .expect("set the SCIM token");
    h.rbac().seed_realm(realm.id()).expect("seed realm");
    (realm.id().clone(), name)
}

/// The payload of a JWT, not verified.
fn claims(jwt: &str) -> serde_json::Value {
    let payload = jwt.split('.').nth(1).expect("a JWT payload");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

fn is_bare_uuid(value: &serde_json::Value) -> bool {
    value
        .as_str()
        .and_then(|s| uuid::Uuid::parse_str(s).ok().map(|u| u.to_string() == s))
        .unwrap_or(false)
}

async fn send(app: &axum::Router, req: Request<Body>) -> (StatusCode, serde_json::Value) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

#[tokio::test]
async fn a_users_token_subject_is_their_scim_id() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let (realm, _) = realm(&h);
    let app = app(&h);

    let req = Request::builder()
        .method("POST")
        .uri("/scim/v2/Users")
        .header("content-type", "application/scim+json")
        .header("x-realm-id", realm.as_uuid().to_string())
        .header("authorization", format!("Bearer {SCIM_TOKEN}"))
        .body(Body::from(
            json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": "ada@bare-ids.example",
                "displayName": "Ada",
                "emails": [{"value": "ada@bare-ids.example", "primary": true}],
                "active": true
            })
            .to_string(),
        ))
        .unwrap();
    let (status, user) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED, "{user}");
    let scim_id = user["id"].as_str().expect("SCIM id").to_string();

    let user_id: UserId = scim_id.parse().expect("the SCIM id is a user ID");
    let session = h
        .identity()
        .create_session(&realm, &user_id, &SessionContext::default())
        .expect("session");
    let tokens = h
        .identity()
        .issue_tokens(&realm, &user_id, session.id())
        .expect("issue tokens");

    let access = claims(tokens.access_token());
    assert_eq!(access["sub"], scim_id.as_str(), "{access}");
    assert_eq!(
        access["sid"],
        session.id().as_uuid().to_string(),
        "{access}"
    );
    assert_eq!(access["tid"], realm.as_uuid().to_string(), "{access}");
    assert!(is_bare_uuid(&access["sid"]) && is_bare_uuid(&access["tid"]));

    // The token still works on the routes that read `sub` and `sid`.
    let req = Request::builder()
        .uri("/userinfo")
        .header("x-realm-id", realm.as_uuid().to_string())
        .header("authorization", format!("Bearer {}", tokens.access_token()))
        .body(Body::empty())
        .unwrap();
    let (status, info) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK, "{info}");
    assert_eq!(info["sub"], scim_id.as_str(), "{info}");
}

#[tokio::test]
async fn a_client_token_keeps_its_subject_and_its_owner_can_manage_it() {
    let h = common::TestHarness::in_process().await.expect("harness");
    let (realm, name) = realm(&h);
    let app = app(&h);
    let client = h
        .identity()
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "bare-ids-service".into(),
                redirect_uris: vec!["https://svc.example.com/cb".into()],
                client_secret: Some(CLIENT_SECRET.into()),
                grant_types: vec!["client_credentials".into()],
                trust_level: ClientTrustLevel::FirstParty,
                ..Default::default()
            },
        )
        .expect("register client");
    let client_uuid = client.client_id().as_uuid().to_string();
    let basic = format!(
        "Basic {}",
        STANDARD.encode(format!("{client_uuid}:{CLIENT_SECRET}"))
    );
    let form = |path: &str, body: String| {
        Request::builder()
            .method("POST")
            .uri(format!("/realms/{name}/{path}"))
            .header("authorization", &basic)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap()
    };

    let token = h
        .identity()
        .client_credentials_token(
            &realm,
            &ClientCredentialsRequest {
                client_id: client.client_id().clone(),
                client_secret: Some(CLIENT_SECRET.into()),
                scope: None,
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
                resource: None,
            },
        )
        .expect("client_credentials token")
        .access_token()
        .to_string();
    let access = claims(&token);
    assert_eq!(access["sub"], format!("client_{client_uuid}"), "{access}");
    assert!(is_bare_uuid(&access["tid"]), "{access}");

    // The issuing client introspects its own token…
    let (status, body) = send(&app, form("introspect", format!("token={token}"))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["active"], true, "own token: {body}");
    assert_eq!(body["sub"], format!("client_{client_uuid}"), "{body}");

    // …and revokes it.
    let (status, body) = send(&app, form("revoke", format!("token={token}"))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, body) = send(&app, form("introspect", format!("token={token}"))).await;
    assert_eq!(body["active"], false, "a revoked token: {body}");
}
