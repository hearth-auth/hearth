//! Regression tests for HEA-1721: unauthenticated POST /authorize must be rejected.
//!
//! Verifies that the machine-API authorization endpoint (`POST /authorize` and
//! `POST /realms/{realm}/authorize`) rejects callers who have not authenticated
//! as the target user, preventing account-takeover via a caller-supplied `user_id`.
//!
//! Coverage:
//! - `unauth_authorize_http_rejected` — no Bearer token → 401
//! - `wrong_user_bearer_is_rejected` — Bearer for user A, user_id=B in body → code issued for A (not B)
//! - `authed_authorize_succeeds` — valid Bearer → 200, code issued
//! - `grpc_unauth_authorize_rejected` — gRPC authorize without Authorization metadata → UNAUTHENTICATED

#![allow(clippy::unwrap_used)]

mod common;

use std::sync::Arc;

use hearth::identity::{
    CreateRealmRequest, CreateUserRequest, RegisterClientRequest, SessionContext,
};
use hearth::protocol::admin_auth::AdminRateLimiter;
use hearth::protocol::grpc::oauth::OAuthSvc;
use hearth::protocol::grpc::GrpcState;
use hearth::protocol::http::{router, AppState};
use hearth::protocol::proto::identity::v1::{self as pb, o_auth_service_server::OAuthService};
use tokio::net::TcpListener;
use tonic::{Code, Request};

const REDIRECT_URI: &str = "https://app.example.com/callback";
const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

struct TestEnv {
    base: String,
    realm_uuid: String,
    client_uuid: String,
    user_uuid: String,
    user_token: String,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

async fn setup() -> TestEnv {
    let harness = common::TestHarness::embedded().await.expect("harness");

    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("hea-1721-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");
    let realm_id = realm.id().clone();

    let client = harness
        .identity()
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "HEA-1721 Test Client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: None,
                require_consent: false,
                grant_types: vec!["authorization_code".to_string()],
                ..Default::default()
            },
        )
        .expect("register client");

    let user = harness
        .identity()
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: format!("hea1721-user-{}@test.invalid", uuid::Uuid::new_v4()),
                display_name: "HEA-1721 Test User".to_string(),
                ..Default::default()
            },
        )
        .expect("create user");

    let session = harness
        .identity()
        .create_session(&realm_id, user.id(), &SessionContext::default())
        .expect("create session");
    let user_token = harness
        .identity()
        .issue_tokens(&realm_id, user.id(), session.id())
        .expect("issue tokens")
        .access_token()
        .to_string();

    let realm_uuid = realm_id.as_uuid().to_string();
    let client_uuid = client.client_id().as_uuid().to_string();
    let user_uuid = user.id().as_uuid().to_string();

    let state = Arc::new(AppState::new_dev(
        harness.identity_arc(),
        harness.rbac_arc(),
        harness.audit_arc(),
    ));

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind random port");
    let port = listener.local_addr().expect("local addr").port();

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let _harness = harness;
        axum::serve(listener, router(state))
            .with_graceful_shutdown(async {
                rx.await.ok();
            })
            .await
            .ok();
    });

    TestEnv {
        base: format!("http://127.0.0.1:{port}"),
        realm_uuid,
        client_uuid,
        user_uuid,
        user_token,
        _shutdown: tx,
    }
}

/// HEA-1721 regression: POST /authorize without a Bearer token must return 401.
///
/// An attacker who knows `client_id`, `redirect_uri`, and `user_id` (all non-secret)
/// but has no valid credential MUST NOT obtain an authorization code.
#[tokio::test]
async fn unauth_authorize_http_rejected() {
    let env = setup().await;
    let http = reqwest::Client::new();

    let resp = http
        .post(format!("{}/authorize", env.base))
        .header("X-Realm-ID", &env.realm_uuid)
        // No Authorization header — the attack vector from HEA-1721.
        .json(&serde_json::json!({
            "client_id": env.client_uuid,
            "redirect_uri": REDIRECT_URI,
            "scope": "openid",
            "state": "attack-state",
            "response_type": "code",
            "user_id": env.user_uuid,
            "code_challenge": PKCE_CHALLENGE,
            "code_challenge_method": "S256"
        }))
        .send()
        .await
        .expect("authorize request");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "POST /authorize without Bearer must return 401, not {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.expect("JSON error body");
    assert_eq!(
        body["error"].as_str(),
        Some("invalid_token"),
        "error field must be 'invalid_token', got: {body}"
    );
}

/// HEA-1721: an authenticated POST /authorize issues a code for the Bearer token's
/// subject, not the `user_id` supplied in the body.
///
/// This confirms that supplying a different `user_id` in the body cannot elevate
/// privileges or impersonate another user.
#[tokio::test]
async fn authed_authorize_issues_code_for_token_subject() {
    let env = setup().await;
    let http = reqwest::Client::new();

    // Provide a different (random) user_id in the body — it must be ignored.
    let decoy_user_id = uuid::Uuid::new_v4().to_string();

    let resp = http
        .post(format!("{}/authorize", env.base))
        .header("X-Realm-ID", &env.realm_uuid)
        .header("Authorization", format!("Bearer {}", env.user_token))
        .json(&serde_json::json!({
            "client_id": env.client_uuid,
            "redirect_uri": REDIRECT_URI,
            "scope": "openid",
            "state": "legit-state",
            "response_type": "code",
            "user_id": decoy_user_id,
            "code_challenge": PKCE_CHALLENGE,
            "code_challenge_method": "S256"
        }))
        .send()
        .await
        .expect("authorize request");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "authenticated POST /authorize must succeed, got {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.expect("JSON body");
    assert!(
        body["code"].as_str().map_or(false, |c| !c.is_empty()),
        "response must contain a non-empty code, got: {body}"
    );

    // Exchange the code to confirm the token is for the authenticated user (env.user_uuid),
    // NOT the decoy user_id supplied in the body.
    let token_resp = http
        .post(format!("{}/token", env.base))
        .header("X-Realm-ID", &env.realm_uuid)
        .json(&serde_json::json!({
            "client_id": env.client_uuid,
            "code": body["code"].as_str().unwrap(),
            "redirect_uri": REDIRECT_URI,
            "code_verifier": PKCE_VERIFIER
        }))
        .send()
        .await
        .expect("token exchange");

    assert_eq!(token_resp.status(), 200, "token exchange must succeed");
    let tokens: serde_json::Value = token_resp.json().await.expect("token JSON");
    let access_token = tokens["access_token"].as_str().expect("access_token");

    // Decode the JWT payload (base64url middle segment) to read sub.
    let payload_b64 = access_token.split('.').nth(1).expect("JWT has 3 parts");
    let padding = (4 - payload_b64.len() % 4) % 4;
    let padded = format!("{}{}", payload_b64, "=".repeat(padding));
    let payload_bytes = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE, &padded)
        .expect("base64 decode JWT payload");
    let claims: serde_json::Value =
        serde_json::from_slice(&payload_bytes).expect("decode JWT claims");

    // Hearth sub claims carry a "user_" prefix: "user_{uuid}".
    let expected_sub = format!("user_{}", env.user_uuid);
    assert_eq!(
        claims["sub"].as_str(),
        Some(expected_sub.as_str()),
        "token sub must match the authenticated user (from Bearer token), not the body's user_id"
    );
}

/// HEA-1721 gRPC parity: gRPC Authorize without an Authorization metadata header
/// must return UNAUTHENTICATED — no code is issued.
#[tokio::test]
async fn grpc_unauth_authorize_rejected() {
    let harness = common::TestHarness::embedded().await.expect("harness");

    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("hea-1721-grpc-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");
    let realm_id = realm.id().clone();

    let client = harness
        .identity()
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "HEA-1721 gRPC Client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: None,
                require_consent: false,
                grant_types: vec!["authorization_code".to_string()],
                ..Default::default()
            },
        )
        .expect("register client");

    let user = harness
        .identity()
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: format!("hea1721-grpc-{}@test.invalid", uuid::Uuid::new_v4()),
                display_name: "HEA-1721 gRPC User".to_string(),
                ..Default::default()
            },
        )
        .expect("create user");

    let svc = OAuthSvc::new(GrpcState::new(
        harness.identity_arc(),
        harness.rbac_arc(),
        harness.audit_arc(),
        Arc::new(AdminRateLimiter::new()),
    ));

    // Build a gRPC request with NO authorization metadata — the attack vector.
    let mut req = Request::new(pb::AuthorizationRequest {
        client_id: client.client_id().as_uuid().to_string(),
        redirect_uri: REDIRECT_URI.to_string(),
        scope: "openid".to_string(),
        state: "grpc-attack-state".to_string(),
        response_type: "code".to_string(),
        user_id: user.id().as_uuid().to_string(),
        code_challenge: Some(PKCE_CHALLENGE.to_string()),
        code_challenge_method: Some("S256".to_string()),
        ..Default::default()
    });
    req.metadata_mut().insert(
        "x-realm-id",
        realm_id
            .as_uuid()
            .to_string()
            .parse()
            .expect("valid header"),
    );
    // Intentionally omit "authorization" metadata.

    let err = svc
        .authorize(req)
        .await
        .expect_err("gRPC authorize without auth must fail");
    assert_eq!(
        err.code(),
        Code::Unauthenticated,
        "must return UNAUTHENTICATED, not a different error code"
    );
}
