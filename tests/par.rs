//! Integration tests for Pushed Authorization Request — RFC 9126.
//!
//! Tests the public `IdentityEngine` surface: `push_authorization_request`
//! and `realm_oidc_discovery`. Replay-protection and TTL-expiry behaviour
//! are covered by unit tests in `src/identity/engine.rs` because those
//! scenarios require calling `consume_par`, which returns a `pub(crate)` type.

mod common;

use std::sync::Arc;

use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{Clock, FakeClock, RealmId, Timestamp};
use hearth::identity::{
    CodeChallengeMethod, CreateRealmRequest, CreateUserRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, IdentityError,
    PushedAuthorizationRequest, RegisterClientRequest, SessionContext,
};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

const EPOCH_MICROS: i64 = 1_700_000_000 * 1_000_000;
const REDIRECT_URI: &str = "https://example.com/callback";
const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

fn pkce_challenge(verifier: &str) -> String {
    use data_encoding::BASE64URL_NOPAD;
    BASE64URL_NOPAD
        .encode(ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes()).as_ref())
}

struct TestEnv {
    engine: EmbeddedIdentityEngine,
    realm: RealmId,
    _dir: tempfile::TempDir,
}

fn setup() -> TestEnv {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf())).expect("storage"),
    );
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(EPOCH_MICROS)));
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock) as Arc<dyn Clock>,
    )) as Arc<dyn AuditEngine>;
    let engine = EmbeddedIdentityEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock) as Arc<dyn Clock>,
        IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        },
        audit,
    )
    .expect("engine");

    let realm = engine
        .create_realm(&CreateRealmRequest {
            name: format!("par-test-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone();

    TestEnv {
        engine,
        realm,
        _dir: dir,
    }
}

fn register_public_client(env: &TestEnv) -> hearth::identity::OAuthClient {
    env.engine
        .register_client(
            &env.realm,
            &RegisterClientRequest {
                client_name: "PAR Test Public".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                client_logo_url: None,
                ..Default::default()
            },
        )
        .expect("register client")
}

fn par_request_with_pkce(client_id: hearth::core::ClientId) -> PushedAuthorizationRequest {
    PushedAuthorizationRequest {
        client_id,
        redirect_uri: REDIRECT_URI.to_string(),
        scope: "openid".to_string(),
        state: "state-abc".to_string(),
        resource: None,
        response_type: "code".to_string(),
        code_challenge: Some(pkce_challenge(PKCE_VERIFIER)),
        code_challenge_method: Some(CodeChallengeMethod::S256),
        nonce: None,
        request: None,
        response_mode: None,
        prompt: None,
    }
}

// ===== P-01: Happy path =====

#[test]
fn happy_path_returns_request_uri_and_expiry() {
    let env = setup();
    let client = register_public_client(&env);

    let resp = env
        .engine
        .push_authorization_request(
            &env.realm,
            &par_request_with_pkce(client.client_id().clone()),
        )
        .expect("PAR push should succeed");

    assert!(
        resp.request_uri
            .starts_with("urn:ietf:params:oauth:request_uri:"),
        "request_uri must use the RFC 9126 URN scheme, got: {}",
        resp.request_uri
    );
    assert_eq!(
        resp.expires_in, 90,
        "TTL must be 90 seconds per RFC 9126 §2.2"
    );
}

// ===== P-02: PKCE enforcement =====

#[test]
fn public_client_without_pkce_rejected() {
    let env = setup();
    let client = register_public_client(&env);

    let req = PushedAuthorizationRequest {
        client_id: client.client_id().clone(),
        redirect_uri: REDIRECT_URI.to_string(),
        scope: "openid".to_string(),
        state: "state-abc".to_string(),
        resource: None,
        response_type: "code".to_string(),
        code_challenge: None,
        code_challenge_method: None,
        nonce: None,
        request: None,
        response_mode: None,
        prompt: None,
    };

    assert!(
        matches!(
            env.engine.push_authorization_request(&env.realm, &req),
            Err(IdentityError::InvalidInput { .. })
        ),
        "public client without PKCE must be rejected with InvalidInput"
    );
}

// ===== P-03: Invalid response_type =====

#[test]
fn non_code_response_type_rejected() {
    let env = setup();
    let client = register_public_client(&env);

    let req = PushedAuthorizationRequest {
        client_id: client.client_id().clone(),
        redirect_uri: REDIRECT_URI.to_string(),
        scope: "openid".to_string(),
        state: "state-abc".to_string(),
        resource: None,
        response_type: "token".to_string(),
        code_challenge: Some(pkce_challenge(PKCE_VERIFIER)),
        code_challenge_method: Some(CodeChallengeMethod::S256),
        nonce: None,
        request: None,
        response_mode: None,
        prompt: None,
    };

    assert!(
        matches!(
            env.engine.push_authorization_request(&env.realm, &req),
            Err(IdentityError::InvalidInput { .. })
        ),
        "response_type other than 'code' must be rejected"
    );
}

// ===== P-04: Discovery document =====

#[test]
fn discovery_advertises_par_endpoint() {
    let env = setup();
    let doc = env
        .engine
        .realm_oidc_discovery(&env.realm)
        .expect("discovery");

    let ep = doc
        .pushed_authorization_request_endpoint
        .expect("pushed_authorization_request_endpoint must be present in discovery document");
    assert!(
        ep.ends_with("/as/par"),
        "PAR endpoint must end with /as/par, got: {ep}"
    );
}

// ===== P-05..P-07: PAR over HTTP =====

const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

const HTTP_CLIENT_SECRET: &str = "test-secret";

/// Start an in-process axum HTTP server backed by a standard realm.
///
/// Returns `(base_url, realm_uuid_string, client_uuid_string, user_uuid_string,
/// shutdown_sender)`.  Drop the sender to stop the server.
async fn start_par_http_server() -> (
    String,
    String,
    String,
    String,
    String,
    tokio::sync::oneshot::Sender<()>,
) {
    use hearth::protocol::http::{router, AppState};
    use tokio::net::TcpListener;

    let harness = common::TestHarness::embedded().await.expect("harness");

    let realm_rec = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("par-http-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");
    let realm_id = realm_rec.id().clone();

    let client = harness
        .identity()
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "PAR HTTP Test Client".to_string(),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                client_secret: Some(HTTP_CLIENT_SECRET.to_string()),
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                trust_level: hearth::identity::ClientTrustLevel::FirstParty,
                ..Default::default()
            },
        )
        .expect("register client");

    let user = harness
        .identity()
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: format!("http-user-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "HTTP PAR User".to_string(),
                ..Default::default()
            },
        )
        .expect("create user");

    let realm_uuid = realm_id.as_uuid().to_string();
    let client_uuid = client.client_id().as_uuid().to_string();
    let user_uuid = user.id().as_uuid().to_string();

    // Issue a Bearer token for the test user so tests can authenticate POST /authorize (HEA-1721).
    let session = harness
        .identity()
        .create_session(&realm_id, user.id(), &SessionContext::default())
        .expect("create session for par test user");
    let user_token = harness
        .identity()
        .issue_tokens(&realm_id, user.id(), session.id())
        .expect("issue tokens for par test user")
        .access_token()
        .to_string();

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
        let _harness = harness; // keeps TempDir alive
        axum::serve(
            listener,
            // Production installs `ConnectInfo` on both accept loops, and the
            // dev-endpoint loopback guard (task 20.1) fails CLOSED without it —
            // a test server that omits it answers 404 on `/admin/bootstrap`.
            router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async {
            rx.await.ok();
        })
        .await
        .ok();
    });

    (
        format!("http://127.0.0.1:{port}"),
        realm_uuid,
        client_uuid,
        user_uuid,
        user_token,
        tx,
    )
}

/// P-05 (regression HEA-1025): HTTP PAR→authorize flow succeeds end-to-end.
///
/// The HTTP `/authorize` handler must consume the pushed `request_uri` and
/// return a real auth code.
#[tokio::test]
async fn par_http_authorize_flow_succeeds() {
    let (base, realm_uuid, client_uuid, user_uuid, user_token, _shutdown) =
        start_par_http_server().await;
    let http = reqwest::Client::new();

    // Step 1: Push authorization parameters to /as/par to get a request_uri.
    let par_resp: serde_json::Value = http
        .post(format!("{base}/as/par"))
        .header("X-Realm-ID", &realm_uuid)
        // The client is confidential: RFC 9126 §2 requires it to authenticate.
        .basic_auth(&client_uuid, Some(HTTP_CLIENT_SECRET))
        .json(&serde_json::json!({
            "client_id": client_uuid,
            "redirect_uri": REDIRECT_URI,
            "scope": "openid",
            "state": "par-b07-state",
            "response_type": "code",
            "code_challenge": PKCE_CHALLENGE,
            "code_challenge_method": "S256",
            "nonce": "par-b07-nonce"
        }))
        .send()
        .await
        .expect("PAR request")
        .json()
        .await
        .expect("PAR response JSON");

    let request_uri = par_resp["request_uri"]
        .as_str()
        .expect("PAR response must include request_uri");
    assert!(
        request_uri.starts_with("urn:ietf:params:oauth:request_uri:"),
        "request_uri must use RFC 9126 URN scheme, got: {request_uri}"
    );

    // Step 2: Authorize using the request_uri — the handler must consume it.
    let auth_resp = http
        .post(format!("{base}/authorize"))
        .header("X-Realm-ID", &realm_uuid)
        .header("Authorization", format!("Bearer {user_token}"))
        .json(&serde_json::json!({
            "user_id": user_uuid,
            "request_uri": request_uri
        }))
        .send()
        .await
        .expect("authorize request");

    assert_eq!(
        auth_resp.status(),
        reqwest::StatusCode::OK,
        "PAR→authorize via HTTP must return 200 OK"
    );
    let auth_body: serde_json::Value = auth_resp.json().await.expect("auth response JSON");
    let code = auth_body["code"]
        .as_str()
        .expect("authorize response must contain 'code'");
    assert!(!code.is_empty(), "auth code must be non-empty");
}

/// P-06 (HEA-1018): replay of a consumed `request_uri` is rejected.
///
/// RFC 9126 §4 requires that a `request_uri` is single-use. `consume_par`
/// marks the entry `used = true` on first consumption. A second `/authorize`
/// call with the same `request_uri` must return 400 `invalid_request`.
#[tokio::test]
async fn par_http_replay_request_uri_rejected() {
    let (base, realm_uuid, client_uuid, user_uuid, user_token, _shutdown) =
        start_par_http_server().await;
    let http = reqwest::Client::new();

    // Push PAR to get a request_uri.
    let par_resp: serde_json::Value = http
        .post(format!("{base}/as/par"))
        .header("X-Realm-ID", &realm_uuid)
        // The client is confidential: RFC 9126 §2 requires it to authenticate.
        .basic_auth(&client_uuid, Some(HTTP_CLIENT_SECRET))
        .json(&serde_json::json!({
            "client_id": client_uuid,
            "redirect_uri": REDIRECT_URI,
            "scope": "openid",
            "state": "par-b09-state",
            "response_type": "code",
            "code_challenge": PKCE_CHALLENGE,
            "code_challenge_method": "S256",
            "nonce": "par-b09-nonce"
        }))
        .send()
        .await
        .expect("PAR request")
        .json()
        .await
        .expect("PAR response JSON");

    let request_uri = par_resp["request_uri"]
        .as_str()
        .expect("PAR response must include request_uri");

    // First use: must succeed.
    let first_resp = http
        .post(format!("{base}/authorize"))
        .header("X-Realm-ID", &realm_uuid)
        .header("Authorization", format!("Bearer {user_token}"))
        .json(&serde_json::json!({
            "user_id": user_uuid,
            "client_id": client_uuid,
            "request_uri": request_uri
        }))
        .send()
        .await
        .expect("first authorize request");
    assert_eq!(
        first_resp.status(),
        reqwest::StatusCode::OK,
        "first PAR->authorize must succeed, got: {}",
        first_resp.status()
    );

    // Second use (replay): must be rejected with invalid_request.
    let replay_resp = http
        .post(format!("{base}/authorize"))
        .header("X-Realm-ID", &realm_uuid)
        .header("Authorization", format!("Bearer {user_token}"))
        .json(&serde_json::json!({
            "user_id": user_uuid,
            "client_id": client_uuid,
            "request_uri": request_uri
        }))
        .send()
        .await
        .expect("replay authorize request");
    assert_eq!(
        replay_resp.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "replayed request_uri must return 400"
    );
    let replay_body: serde_json::Value = replay_resp.json().await.expect("error JSON");
    assert_eq!(
        replay_body["error"].as_str(),
        Some("invalid_request"),
        "replay must produce error=invalid_request, got: {replay_body}"
    );
}

/// P-07 (HEA-1018): `client_id` mismatch between `/authorize` body and
/// stored PAR entry is rejected per RFC 9126 §4.
///
/// Without this check an attacker who obtains a `request_uri` (e.g. via
/// referrer leakage) could submit it using a different `client_id`.
#[tokio::test]
async fn par_http_client_id_mismatch_rejected() {
    let (base, realm_uuid, client_uuid, user_uuid, user_token, _shutdown) =
        start_par_http_server().await;
    let http = reqwest::Client::new();

    // Push PAR using the real client.
    let par_resp: serde_json::Value = http
        .post(format!("{base}/as/par"))
        .header("X-Realm-ID", &realm_uuid)
        // The client is confidential: RFC 9126 §2 requires it to authenticate.
        .basic_auth(&client_uuid, Some(HTTP_CLIENT_SECRET))
        .json(&serde_json::json!({
            "client_id": client_uuid,
            "redirect_uri": REDIRECT_URI,
            "scope": "openid",
            "state": "par-b10-state",
            "response_type": "code",
            "code_challenge": PKCE_CHALLENGE,
            "code_challenge_method": "S256",
            "nonce": "par-b10-nonce"
        }))
        .send()
        .await
        .expect("PAR request")
        .json()
        .await
        .expect("PAR response JSON");

    let request_uri = par_resp["request_uri"]
        .as_str()
        .expect("PAR response must include request_uri");

    // Submit /authorize with a different client_id than the one that pushed the PAR.
    let other_client_id = uuid::Uuid::new_v4().to_string();
    let mismatch_resp = http
        .post(format!("{base}/authorize"))
        .header("X-Realm-ID", &realm_uuid)
        .header("Authorization", format!("Bearer {user_token}"))
        .json(&serde_json::json!({
            "user_id": user_uuid,
            "client_id": other_client_id,
            "request_uri": request_uri
        }))
        .send()
        .await
        .expect("mismatch authorize request");

    assert_eq!(
        mismatch_resp.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "client_id mismatch must return 400"
    );
    let mismatch_body: serde_json::Value = mismatch_resp.json().await.expect("error JSON");
    assert_eq!(
        mismatch_body["error"].as_str(),
        Some("invalid_request"),
        "client_id mismatch must produce error=invalid_request, got: {mismatch_body}"
    );
}
