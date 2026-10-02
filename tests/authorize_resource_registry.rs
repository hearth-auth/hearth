//! G6 — an RFC 8707 `resource` must name a registered protected resource on
//! every authorization surface, not only at the token-exchange endpoint.
//!
//! The authorization request's `resource` becomes the `aud` of the code's
//! access token. PAR stored any value, and `/authorize` (JSON — which takes a
//! resource only through a pushed `request_uri`) issued a code for it,
//! so a client could mint a Hearth-signed token for a resource server the
//! realm never declared, or for one removed since the request was pushed.
//! Each surface now answers RFC 8707 `invalid_target`.

#![allow(clippy::unwrap_used)]

mod common;

use std::sync::Arc;

use hearth::core::RealmId;
use hearth::identity::{
    CreateRealmRequest, CreateUserRequest, RegisterClientRequest, RegisterProtectedResourceRequest,
    SessionContext,
};
use hearth::protocol::http::{router, AppState};
use tokio::net::TcpListener;

const REDIRECT_URI: &str = "https://app.example.com/callback";
const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const REGISTERED: &str = "https://mcp.example.com/api";
const UNREGISTERED: &str = "https://undeclared.example.com/api";

struct Env {
    harness: Arc<common::TestHarness>,
    base: String,
    realm_id: RealmId,
    client_uuid: String,
    user_token: String,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

fn declared(uri: &str) -> RegisterProtectedResourceRequest {
    RegisterProtectedResourceRequest {
        resource_uri: uri.to_string(),
        display_name: "MCP".to_string(),
        scopes: Vec::new(),
        required_claims: Vec::new(),
        introspection_client_id: None,
    }
}

async fn setup() -> Env {
    let harness = Arc::new(common::TestHarness::embedded().await.expect("harness"));
    let identity = harness.identity();
    let realm_id = identity
        .create_realm(&CreateRealmRequest {
            name: format!("g6-resource-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("realm")
        .id()
        .clone();
    identity
        .register_protected_resource(&realm_id, &declared(REGISTERED))
        .expect("register the protected resource");
    let client = identity
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "G6 resource client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                require_consent: false,
                trust_level: hearth::identity::ClientTrustLevel::FirstParty,
                grant_types: vec!["authorization_code".to_string()],
                ..Default::default()
            },
        )
        .expect("client");
    let user = identity
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: format!("g6-{}@test.invalid", uuid::Uuid::new_v4()),
                display_name: "G6".to_string(),
                ..Default::default()
            },
        )
        .expect("user");
    let session = identity
        .create_session(&realm_id, user.id(), &SessionContext::default())
        .expect("session");
    let user_token = identity
        .issue_tokens(&realm_id, user.id(), session.id())
        .expect("tokens")
        .access_token()
        .to_string();

    let state = Arc::new(AppState::new_dev(
        harness.identity_arc(),
        harness.rbac_arc(),
        harness.audit_arc(),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        axum::serve(
            listener,
            router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async {
            rx.await.ok();
        })
        .await
        .ok();
    });

    Env {
        harness,
        base: format!("http://127.0.0.1:{port}"),
        realm_id,
        client_uuid: client.client_id().as_uuid().to_string(),
        user_token,
        _shutdown: tx,
    }
}

/// `POST /as/par` with `resource`; returns the status and the JSON body.
async fn push(env: &Env, resource: &str) -> (reqwest::StatusCode, serde_json::Value) {
    let resp = reqwest::Client::new()
        .post(format!("{}/as/par", env.base))
        .header("X-Realm-ID", env.realm_id.as_uuid().to_string())
        .json(&serde_json::json!({
            "client_id": env.client_uuid,
            "redirect_uri": REDIRECT_URI,
            "scope": "openid",
            "state": "g6-state",
            "response_type": "code",
            "code_challenge": PKCE_CHALLENGE,
            "code_challenge_method": "S256",
            "resource": resource,
        }))
        .send()
        .await
        .expect("PAR request");
    let status = resp.status();
    (status, resp.json().await.unwrap_or_default())
}

/// A `request_uri` pushed for [`REGISTERED`], whose resource is then removed
/// from the registry (YAML reconcile with it gone) before the code is asked
/// for.
async fn request_uri_for_a_removed_resource(env: &Env) -> String {
    let (status, body) = push(env, REGISTERED).await;
    assert_eq!(
        status, 201,
        "precondition: a registered resource is pushed: {body}"
    );
    env.harness
        .identity()
        .reconcile_protected_resources(&env.realm_id, &[])
        .expect("remove the resource");
    body["request_uri"]
        .as_str()
        .expect("request_uri")
        .to_string()
}

fn assert_invalid_target(status: reqwest::StatusCode, body: &serde_json::Value, what: &str) {
    assert_eq!(
        (status, body["error"].as_str()),
        (reqwest::StatusCode::BAD_REQUEST, Some("invalid_target")),
        "{what} must answer 400 invalid_target, got {status} {body}"
    );
}

#[tokio::test]
async fn par_refuses_an_unregistered_resource() {
    let env = setup().await;
    let (status, body) = push(&env, UNREGISTERED).await;
    assert_invalid_target(status, &body, "PAR naming an undeclared resource");
}

#[tokio::test]
async fn par_accepts_any_spelling_of_a_registered_resource() {
    let env = setup().await;
    let (status, body) = push(&env, "HTTPS://MCP.Example.com:443/api/").await;
    assert_eq!(
        status, 201,
        "a spelling of a registered resource is that resource: {body}"
    );
}

#[tokio::test]
async fn json_authorize_refuses_a_resource_removed_since_the_push() {
    let env = setup().await;
    let request_uri = request_uri_for_a_removed_resource(&env).await;
    let resp = reqwest::Client::new()
        .post(format!("{}/authorize", env.base))
        .header("X-Realm-ID", env.realm_id.as_uuid().to_string())
        .header("Authorization", format!("Bearer {}", env.user_token))
        .json(&serde_json::json!({
            "client_id": env.client_uuid,
            "redirect_uri": "",
            "scope": "",
            "state": "",
            "response_type": "",
            "user_id": "",
            "request_uri": request_uri,
        }))
        .send()
        .await
        .expect("authorize");
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or_default();
    assert_invalid_target(status, &body, "JSON /authorize for a removed resource");
}
