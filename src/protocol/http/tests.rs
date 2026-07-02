use super::*;
use crate::audit::{AuditEngine, EmbeddedAuditEngine};
use crate::core::SystemClock;
use crate::identity::{CredentialConfig, EmbeddedIdentityEngine, IdentityConfig};
use crate::rbac::{EmbeddedRbacEngine, RbacEngine};
use crate::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use axum::http::StatusCode;
use tower::ServiceExt as _;

/// Creates a test app state with all three engines in a temp directory.
fn test_state(temp_dir: &std::path::Path) -> Arc<AppState> {
    let config = StorageConfig::dev(temp_dir.to_path_buf());
    let engine = Arc::new(EmbeddedStorageEngine::open(config).expect("open storage"));
    let clock = Arc::new(SystemClock) as Arc<dyn crate::core::Clock>;
    let identity_config = IdentityConfig {
        credential: CredentialConfig::fast_for_testing(),
        ..IdentityConfig::default()
    };
    let rbac_engine: Arc<dyn RbacEngine> = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&engine) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    ));
    let audit_engine = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&engine) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    ));
    let identity_engine = EmbeddedIdentityEngine::with_rbac(
        Arc::clone(&engine) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
        identity_config,
        Arc::clone(&rbac_engine),
        Arc::clone(&audit_engine) as Arc<dyn AuditEngine>,
    )
    .expect("identity engine");

    Arc::new(AppState::new(
        Arc::new(identity_engine),
        rbac_engine,
        audit_engine.clone() as Arc<dyn AuditEngine>,
    ))
}

/// Creates a test app state in dev mode.
fn test_state_dev(temp_dir: &std::path::Path) -> Arc<AppState> {
    let config = StorageConfig::dev(temp_dir.to_path_buf());
    let engine = Arc::new(EmbeddedStorageEngine::open(config).expect("open storage"));
    let clock = Arc::new(SystemClock) as Arc<dyn crate::core::Clock>;
    let identity_config = IdentityConfig {
        credential: CredentialConfig::fast_for_testing(),
        ..IdentityConfig::default()
    };
    let rbac_engine: Arc<dyn RbacEngine> = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&engine) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    ));
    let audit_engine = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&engine) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    ));
    let identity_engine = EmbeddedIdentityEngine::with_rbac(
        Arc::clone(&engine) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
        identity_config,
        Arc::clone(&rbac_engine),
        Arc::clone(&audit_engine) as Arc<dyn AuditEngine>,
    )
    .expect("identity engine");

    Arc::new(AppState::new_dev(
        Arc::new(identity_engine),
        rbac_engine,
        audit_engine.clone() as Arc<dyn AuditEngine>,
    ))
}

#[tokio::test]
async fn health_returns_ok() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let state = test_state(temp_dir.path());
    let app = router(state);

    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/health")
                .body(axum::body::Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn bootstrap_returns_404_in_production_mode() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let state = test_state(temp_dir.path());
    let app = router(state);

    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/admin/bootstrap")
                .body(axum::body::Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn bootstrap_returns_admin_credentials_in_dev_mode() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let state = test_state_dev(temp_dir.path());
    let app = router(state);

    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/admin/bootstrap")
                .body(axum::body::Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 10_000)
        .await
        .expect("body");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");

    // Verify all expected fields are present
    assert!(json.get("realm_id").is_some(), "missing realm_id");
    assert!(json.get("user_id").is_some(), "missing user_id");
    assert!(json.get("access_token").is_some(), "missing access_token");
    assert!(json.get("refresh_token").is_some(), "missing refresh_token");

    // Verify realm_id and user_id are valid UUIDs
    let realm_str = json["realm_id"].as_str().expect("realm_id string");
    let _: uuid::Uuid = realm_str.parse().expect("valid realm UUID");
    let user_str = json["user_id"].as_str().expect("user_id string");
    let _: uuid::Uuid = user_str.parse().expect("valid user UUID");

    // Verify access_token is non-empty
    let token = json["access_token"].as_str().expect("access_token string");
    assert!(!token.is_empty(), "access_token should not be empty");
}

/// Regression test for HEA-1644: re-bootstrapping a dev server that already has
/// `admin@hearth.test` must reset the password to `HearthTest123!` so login
/// always works after a restart with persistent data.
#[tokio::test]
async fn bootstrap_resets_dev_admin_password_on_second_call() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let state = test_state_dev(temp_dir.path());
    let sys = crate::identity::keys::system_realm_id();

    // First bootstrap — creates admin@hearth.test with HearthTest123!
    let resp = router(Arc::clone(&state))
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/admin/bootstrap")
                .body(axum::body::Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK, "first bootstrap");

    // Simulate a password change (e.g. admin changes their own password).
    let admin = state
        .identity
        .get_user_by_email(&sys, "admin@hearth.test")
        .expect("lookup")
        .expect("user exists");
    let changed = crate::identity::CleartextPassword::from_string("SomeOtherPassword!".to_string());
    state
        .identity
        .set_password(&sys, admin.id(), &changed)
        .expect("set changed password");

    // Confirm HearthTest123! no longer works.
    let dev_pwd = crate::identity::CleartextPassword::from_string("HearthTest123!".to_string());
    assert!(
        !state
            .identity
            .verify_password(&sys, admin.id(), &dev_pwd)
            .expect("verify"),
        "password should differ before re-bootstrap"
    );

    // Second bootstrap — must reset password back to HearthTest123!
    let resp = router(Arc::clone(&state))
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/admin/bootstrap")
                .body(axum::body::Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK, "second bootstrap");

    // HearthTest123! must work again.
    assert!(
        state
            .identity
            .verify_password(&sys, admin.id(), &dev_pwd)
            .expect("verify after re-bootstrap"),
        "re-bootstrap must restore HearthTest123! password"
    );
}

/// PAR with a signed JAR JWT in the request body is accepted under FAPI Advanced.
///
/// Regression for HEA-1019: `HttpParRequest` was missing the `request` field,
/// so the JAR was silently dropped and Advanced realms always rejected with
/// `FapiViolation`.  This test exercises the full HTTP deserialisation path and
/// MUST return 201 with the fix applied.
#[tokio::test]
#[allow(clippy::too_many_lines)] // TODO: HEA-1354 split this function
async fn par_jar_accepted_under_fapi_advanced() {
    use crate::identity::{
        CreateRealmRequest, FapiProfile, RegisterClientRequest, UpdateRealmRequest,
    };
    use base64::Engine as _;

    let temp_dir = tempfile::tempdir().expect("tempdir");
    let state = test_state(temp_dir.path());

    // Create an Advanced FAPI realm.
    let realm_rec = state
        .identity
        .create_realm(&CreateRealmRequest {
            name: format!("fapi-adv-jar-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");
    let mut config = realm_rec.config().clone();
    config.fapi_profile = Some(FapiProfile::Advanced);
    state
        .identity
        .update_realm(
            realm_rec.id(),
            &UpdateRealmRequest {
                config: Some(config),
                ..Default::default()
            },
        )
        .expect("set FAPI Advanced");

    // Generate Ed25519 key pair and register a JARM-capable JWKS client.
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).expect("keygen");
    let pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("from_pkcs8");
    let pub_bytes = ring::signature::KeyPair::public_key(&pair)
        .as_ref()
        .to_vec();
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let x = b64.encode(&pub_bytes);
    let jwks = format!(
        r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","kid":"hea1019","x":"{x}"}}]}}"#
    );

    let client = state
        .identity
        .register_client(
            realm_rec.id(),
            &RegisterClientRequest {
                client_name: "FAPI-A JAR HTTP Client".to_string(),
                redirect_uris: vec!["https://app.example.com/callback".to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                jwks: Some(jwks),
                authorization_signed_response_alg: Some("EdDSA".to_string()),
                ..Default::default()
            },
        )
        .expect("register client");

    // Sign a minimal JAR JWT.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs() as i64;
    let issuer = format!("https://hearth.local/realms/{}", realm_rec.name());
    // HTTP body expects the raw UUID; JAR claims compare against the prefixed form.
    let cid_http = client.client_id().as_uuid().to_string();
    let cid_jar = client.client_id().to_string();
    const REDIRECT: &str = "https://app.example.com/callback";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    let header_b64 = b64.encode(
        serde_json::to_vec(&serde_json::json!({"alg": "EdDSA", "kid": "hea1019"}))
            .expect("header json"),
    );
    let claims_b64 = b64.encode(
        serde_json::to_vec(&serde_json::json!({
            "iss": cid_jar, "aud": issuer,
            "exp": now + 300, "iat": now,
            "jti": uuid::Uuid::new_v4().to_string(),
            "client_id": cid_jar,
            "response_type": "code",
            "redirect_uri": REDIRECT,
            "scope": "openid",
            "state": "jar-state",
            "code_challenge": CHALLENGE,
            "code_challenge_method": "S256",
            "nonce": "hea1019-nonce"
        }))
        .expect("claims json"),
    );
    let signing_input = format!("{header_b64}.{claims_b64}");
    let sig = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .expect("pair")
        .sign(signing_input.as_bytes());
    let jar_jwt = format!("{signing_input}.{}", b64.encode(sig.as_ref()));

    let body = serde_json::to_vec(&serde_json::json!({
        "client_id": cid_http,
        "redirect_uri": REDIRECT,
        "scope": "openid",
        "state": "par-state",
        "response_type": "code",
        "code_challenge": CHALLENGE,
        "code_challenge_method": "S256",
        "nonce": "hea1019-nonce",
        "request": jar_jwt
    }))
    .expect("body json");

    let app = router(state);
    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/realms/{}/as/par", realm_rec.name()))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "JAR in HTTP PAR body must be accepted under FAPI Advanced (HEA-1019 regression)"
    );
    let resp_body = axum::body::to_bytes(resp.into_body(), 4_096)
        .await
        .expect("body bytes");
    let json: serde_json::Value = serde_json::from_slice(&resp_body).expect("json");
    assert!(
        json.get("request_uri").is_some(),
        "response must include request_uri"
    );
}

/// PAR without a JAR JWT is rejected under FAPI Advanced.
///
/// Counterpart to `par_jar_accepted_under_fapi_advanced`: confirms the
/// negative case still returns 400 / `invalid_request` when the `request`
/// field is absent.
#[tokio::test]
async fn par_without_jar_rejected_under_fapi_advanced() {
    use crate::identity::{
        CreateRealmRequest, FapiProfile, RegisterClientRequest, UpdateRealmRequest,
    };

    let temp_dir = tempfile::tempdir().expect("tempdir");
    let state = test_state(temp_dir.path());

    let realm_rec = state
        .identity
        .create_realm(&CreateRealmRequest {
            name: format!("fapi-adv-nojar-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");
    let mut config = realm_rec.config().clone();
    config.fapi_profile = Some(FapiProfile::Advanced);
    state
        .identity
        .update_realm(
            realm_rec.id(),
            &UpdateRealmRequest {
                config: Some(config),
                ..Default::default()
            },
        )
        .expect("set FAPI Advanced");

    let client = state
        .identity
        .register_client(
            realm_rec.id(),
            &RegisterClientRequest {
                client_name: "FAPI-A No-JAR Client".to_string(),
                redirect_uris: vec!["https://app.example.com/callback".to_string()],
                client_secret: Some("secret".to_string()),
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("register client");

    let body = serde_json::to_vec(&serde_json::json!({
        "client_id": client.client_id().as_uuid().to_string(),
        "redirect_uri": "https://app.example.com/callback",
        "scope": "openid",
        "state": "par-state",
        "response_type": "code",
        "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        "code_challenge_method": "S256",
        "nonce": "test-nonce"
    }))
    .expect("body json");

    let app = router(state);
    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/realms/{}/as/par", realm_rec.name()))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "PAR without JAR must be rejected (FapiViolation) under FAPI Advanced"
    );
    let resp_body = axum::body::to_bytes(resp.into_body(), 4_096)
        .await
        .expect("body bytes");
    let json: serde_json::Value = serde_json::from_slice(&resp_body).expect("json");
    assert_eq!(
        json["error"], "invalid_request",
        "error must be invalid_request for FAPI violation"
    );
}
