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

/// HEA-2087: Bootstrap must also return a **system-realm** admin token capable
/// of cross-realm management. The dev-realm-scoped `access_token` 403s on another
/// realm's `rotate-signing-key` (the `scoped_realm` BOLA guard only lets a
/// nil-UUID system token operate cross-realm); the new `system_access_token`
/// (issued for the seeded `admin@hearth.test` system admin) must succeed.
#[tokio::test]
async fn bootstrap_system_token_can_rotate_other_realm_signing_key() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let state = test_state_dev(temp_dir.path());

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
    let body = axum::body::to_bytes(resp.into_body(), 10_000)
        .await
        .expect("body");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");

    // The dev-realm credential (existing behavior).
    let dev_token = json["access_token"]
        .as_str()
        .expect("access_token")
        .to_string();
    let dev_realm_id = json["realm_id"].as_str().expect("realm_id").to_string();

    // The new cross-realm system credential.
    let system_token = json["system_access_token"]
        .as_str()
        .expect("system_access_token present")
        .to_string();
    assert!(
        !system_token.is_empty(),
        "system_access_token must be non-empty on first bootstrap"
    );
    let system_realm_id = json["system_realm_id"]
        .as_str()
        .expect("system_realm_id present")
        .to_string();
    assert_eq!(
        system_realm_id,
        uuid::Uuid::nil().to_string(),
        "system_realm_id must be the nil UUID (the reserved system realm)"
    );

    // A separate realm to exercise cross-realm management against.
    let other = state
        .identity
        .create_realm(&crate::identity::CreateRealmRequest {
            name: "other-realm".to_string(),
            config: None,
        })
        .expect("create other realm");
    let other_id = other.id().as_uuid().to_string();
    let rotate_uri = format!("/admin/realms/{other_id}/rotate-signing-key");

    // The dev-realm token cannot cross-realm manage — documents the root cause.
    let resp = router(Arc::clone(&state))
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(&rotate_uri)
                .header("Authorization", format!("Bearer {dev_token}"))
                .header("X-Realm-ID", &dev_realm_id)
                .body(axum::body::Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "dev-realm-scoped token must NOT be able to rotate another realm's key"
    );

    // The system-realm token must cross-realm manage successfully.
    let resp = router(Arc::clone(&state))
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(&rotate_uri)
                .header("Authorization", format!("Bearer {system_token}"))
                .header("X-Realm-ID", &system_realm_id)
                .body(axum::body::Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "system-realm token must be able to rotate another realm's signing key cross-realm"
    );
}

/// HEA-2087: Re-bootstrap (dev-realm already exists) must still return a working
/// cross-realm `system_access_token`, so an integration harness that re-bootstraps
/// after a restart can keep managing realms.
#[tokio::test]
async fn rebootstrap_returns_working_system_token() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let state = test_state_dev(temp_dir.path());

    // First bootstrap to obtain a Bearer token for the authenticated re-bootstrap.
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
    let body = axum::body::to_bytes(resp.into_body(), 10_000)
        .await
        .expect("body");
    let first: serde_json::Value = serde_json::from_slice(&body).expect("json");
    let dev_token = first["access_token"]
        .as_str()
        .expect("access_token")
        .to_string();

    // Re-bootstrap with the Bearer token.
    let resp = router(Arc::clone(&state))
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/admin/bootstrap")
                .header("Authorization", format!("Bearer {dev_token}"))
                .body(axum::body::Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK, "re-bootstrap");
    let body = axum::body::to_bytes(resp.into_body(), 10_000)
        .await
        .expect("body");
    let second: serde_json::Value = serde_json::from_slice(&body).expect("json");

    let system_token = second["system_access_token"]
        .as_str()
        .expect("system_access_token present on re-bootstrap")
        .to_string();
    assert!(
        !system_token.is_empty(),
        "system_access_token must be non-empty on re-bootstrap"
    );
    let system_realm_id = second["system_realm_id"]
        .as_str()
        .expect("system_realm_id present");
    assert_eq!(system_realm_id, uuid::Uuid::nil().to_string());

    // Prove the re-bootstrap system token works cross-realm.
    let other = state
        .identity
        .create_realm(&crate::identity::CreateRealmRequest {
            name: "other-realm".to_string(),
            config: None,
        })
        .expect("create other realm");
    let other_id = other.id().as_uuid().to_string();
    let resp = router(Arc::clone(&state))
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/admin/realms/{other_id}/rotate-signing-key"))
                .header("Authorization", format!("Bearer {system_token}"))
                .header("X-Realm-ID", uuid::Uuid::nil().to_string())
                .body(axum::body::Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "re-bootstrap system token must manage realms cross-realm"
    );
}

/// HEA-1670: First bootstrap must return `admin_password`; the password must
/// authenticate the `admin@hearth.test` user.
#[tokio::test]
async fn bootstrap_returns_admin_password_on_first_call() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let state = test_state_dev(temp_dir.path());
    let sys = crate::identity::keys::system_realm_id();

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
    let body = axum::body::to_bytes(resp.into_body(), 10_000)
        .await
        .expect("body");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");

    let pwd_str = json["admin_password"]
        .as_str()
        .expect("admin_password field present");
    assert!(
        !pwd_str.is_empty(),
        "admin_password must be non-empty on first bootstrap"
    );
    assert_eq!(
        pwd_str,
        super::admin::DEV_SYSTEM_ADMIN_PASSWORD,
        "admin_password must match the well-known dev constant"
    );

    let admin = state
        .identity
        .get_user_by_email(&sys, "admin@hearth.test")
        .expect("lookup")
        .expect("user exists");
    let cleartext = crate::identity::CleartextPassword::from_string(pwd_str.to_string());
    assert!(
        state
            .identity
            .verify_password(&sys, admin.id(), &cleartext)
            .expect("verify"),
        "returned admin_password must authenticate the system admin user"
    );
}

/// HEA-1670: Re-bootstrap must NOT reset the existing password.
#[tokio::test]
async fn bootstrap_does_not_reset_password_on_second_call() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let state = test_state_dev(temp_dir.path());
    let sys = crate::identity::keys::system_realm_id();

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
    let body = axum::body::to_bytes(resp.into_body(), 10_000)
        .await
        .expect("body");
    let first: serde_json::Value = serde_json::from_slice(&body).expect("json");
    let access_token = first["access_token"]
        .as_str()
        .expect("access_token")
        .to_string();

    let admin = state
        .identity
        .get_user_by_email(&sys, "admin@hearth.test")
        .expect("lookup")
        .expect("user exists");
    let new_pwd = crate::identity::CleartextPassword::from_string("ChangedPassword!99".to_string());
    state
        .identity
        .set_password(&sys, admin.id(), &new_pwd)
        .expect("set changed password");

    let resp = router(Arc::clone(&state))
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/admin/bootstrap")
                .header("Authorization", format!("Bearer {access_token}"))
                .body(axum::body::Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK, "re-bootstrap must succeed");
    let body = axum::body::to_bytes(resp.into_body(), 10_000)
        .await
        .expect("body");
    let second: serde_json::Value = serde_json::from_slice(&body).expect("json");

    let pwd_on_reboot = second
        .get("admin_password")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert!(
        pwd_on_reboot.is_empty(),
        "admin_password must NOT be returned on re-bootstrap"
    );
    assert!(
        state
            .identity
            .verify_password(&sys, admin.id(), &new_pwd)
            .expect("verify"),
        "re-bootstrap must NOT reset the admin password"
    );
}

/// HEA-1998: `POST /dev/seed-password` sets a credential the login path can
/// verify, so the load-test login / KDF saturation plane has authenticatable
/// users.
#[tokio::test]
async fn dev_seed_password_sets_verifiable_credential() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let state = test_state_dev(temp_dir.path());

    let realm = state
        .identity
        .create_realm(&crate::identity::CreateRealmRequest {
            name: "seedpw-realm".to_string(),
            config: None,
        })
        .expect("create realm");
    let user = state
        .identity
        .create_user(
            realm.id(),
            &crate::identity::CreateUserRequest {
                email: "loaduser@loadtest.test".to_string(),
                display_name: "Load User".to_string(),
                ..Default::default()
            },
        )
        .expect("create user");

    let pw = "L0adT3st!KnownPassword";
    let body = serde_json::json!({
        "user_id": user.id().as_uuid().to_string(),
        "password": pw,
    });
    let resp = router(Arc::clone(&state))
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/dev/seed-password")
                .header("X-Realm-ID", realm.id().as_uuid().to_string())
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "seed-password must succeed in dev mode"
    );

    let cleartext = crate::identity::CleartextPassword::from_string(pw.to_string());
    assert!(
        state
            .identity
            .verify_password(realm.id(), user.id(), &cleartext)
            .expect("verify"),
        "seeded password must authenticate the user (login / KDF plane)"
    );
}

/// HEA-1998: an invalid `user_id` is a 400, not a 500 or a panic.
#[tokio::test]
async fn dev_seed_password_rejects_invalid_user_id() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let state = test_state_dev(temp_dir.path());
    let realm = crate::core::RealmId::generate();

    let body = serde_json::json!({"user_id": "not-a-uuid", "password": "x"});
    let resp = router(state)
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/dev/seed-password")
                .header("X-Realm-ID", realm.as_uuid().to_string())
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// HEA-1998: the dev seeding route MUST be absent in production mode (404),
/// matching the fingerprint-resistance rule for the other `/dev/*` endpoints.
#[tokio::test]
async fn dev_seed_password_absent_in_production_mode() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let state = test_state(temp_dir.path());

    let body = serde_json::json!({"user_id": uuid::Uuid::nil().to_string(), "password": "x"});
    let resp = router(state)
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/dev/seed-password")
                .header("X-Realm-ID", uuid::Uuid::nil().to_string())
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// HEA-1670: Unauthenticated re-bootstrap must return 401 after first bootstrap.
#[tokio::test]
async fn bootstrap_requires_auth_on_second_call() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let state = test_state_dev(temp_dir.path());

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
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "unauthenticated re-bootstrap must return 401"
    );
}

/// HEA-1716: Fresh bootstraps always return the fixed dev password constant.
///
/// The system admin now uses a stable password (DEV_SYSTEM_ADMIN_PASSWORD) so
/// the Playwright UI test suite can log in without reading the bootstrap response.
#[tokio::test]
async fn bootstrap_returns_fixed_dev_password_on_first_call() {
    async fn first_password(dir: &std::path::Path) -> String {
        let state = test_state_dev(dir);
        let resp = router(state)
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
        json["admin_password"]
            .as_str()
            .expect("admin_password")
            .to_string()
    }

    let dir_a = tempfile::tempdir().expect("tempdir a");
    let dir_b = tempfile::tempdir().expect("tempdir b");
    let pwd_a = first_password(dir_a.path()).await;
    let pwd_b = first_password(dir_b.path()).await;

    assert_eq!(
        pwd_a,
        super::admin::DEV_SYSTEM_ADMIN_PASSWORD,
        "first bootstrap must return the well-known dev constant"
    );
    assert_eq!(
        pwd_b,
        super::admin::DEV_SYSTEM_ADMIN_PASSWORD,
        "second fresh install must also return the well-known dev constant"
    );
}

// ── A-40: Host header allowlist tests ────────────────────────────────────────

/// Builds a test state with the given `allowed_hosts` list.
fn test_state_with_allowed_hosts(temp_dir: &std::path::Path, hosts: Vec<String>) -> Arc<AppState> {
    let config = StorageConfig::dev(temp_dir.to_path_buf());
    let engine = Arc::new(EmbeddedStorageEngine::open(config).expect("open storage"));
    let clock = Arc::new(crate::core::SystemClock) as Arc<dyn crate::core::Clock>;
    let identity_config = crate::identity::IdentityConfig {
        credential: crate::identity::CredentialConfig::fast_for_testing(),
        ..crate::identity::IdentityConfig::default()
    };
    let rbac_engine: Arc<dyn crate::rbac::RbacEngine> =
        Arc::new(crate::rbac::EmbeddedRbacEngine::new(
            Arc::clone(&engine) as Arc<dyn crate::storage::StorageEngine>,
            Arc::clone(&clock),
        ));
    let audit_engine = Arc::new(crate::audit::EmbeddedAuditEngine::new(
        Arc::clone(&engine) as Arc<dyn crate::storage::StorageEngine>,
        Arc::clone(&clock),
    ));
    let identity_engine = crate::identity::EmbeddedIdentityEngine::with_rbac(
        Arc::clone(&engine) as Arc<dyn crate::storage::StorageEngine>,
        Arc::clone(&clock),
        identity_config,
        Arc::clone(&rbac_engine),
        Arc::clone(&audit_engine) as Arc<dyn crate::audit::AuditEngine>,
    )
    .expect("identity engine");
    Arc::new(
        AppState::new(
            Arc::new(identity_engine),
            rbac_engine,
            audit_engine as Arc<dyn crate::audit::AuditEngine>,
        )
        .with_allowed_hosts(hosts),
    )
}

/// A-40: A non-allowlisted Host header must be rejected with 400.
#[tokio::test]
async fn host_allowlist_blocks_unlisted_host() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let state =
        test_state_with_allowed_hosts(temp_dir.path(), vec!["allowed.example.com".to_string()]);
    let app = router(state);

    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/health")
                .header("host", "evil.attacker.com")
                .body(axum::body::Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "unlisted Host must return 400"
    );
}

/// A-40: A request with an allowlisted Host header must be forwarded normally.
#[tokio::test]
async fn host_allowlist_allows_listed_host() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let state =
        test_state_with_allowed_hosts(temp_dir.path(), vec!["allowed.example.com".to_string()]);
    let app = router(state);

    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/health")
                .header("host", "allowed.example.com")
                .body(axum::body::Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "allowlisted Host must pass through"
    );
}

/// A-40: When allowed_hosts is empty the middleware is fail-open (any Host passes).
#[tokio::test]
async fn host_allowlist_empty_allows_any_host() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    // Default state has allowed_hosts = vec![]
    let state = test_state(temp_dir.path());
    let app = router(state);

    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/health")
                .header("host", "whatever.arbitrary.host")
                .body(axum::body::Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "empty allowed_hosts must accept any Host value"
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

/// HEA-2117: POST /authorize must accept a request that omits `user_id` from the
/// JSON body when the caller supplies a valid Bearer token.  Before the fix,
/// `proto_authorize_to_domain` tried to parse an empty string as a UUID and
/// returned 400 "invalid user_id UUID" even though the handler always overwrites
/// the body-supplied user_id with the authenticated principal anyway (HEA-1721).
#[tokio::test]
async fn authorize_succeeds_without_user_id_in_body_when_bearer_present() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let state = test_state_dev(temp_dir.path());

    // Bootstrap to get a realm, admin user, and access token.
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
    assert_eq!(resp.status(), StatusCode::OK, "bootstrap");
    let body = axum::body::to_bytes(resp.into_body(), 32_000)
        .await
        .expect("body");
    let boot: serde_json::Value = serde_json::from_slice(&body).expect("json");
    let realm_id = boot["realm_id"].as_str().expect("realm_id").to_string();
    let access_token = boot["access_token"]
        .as_str()
        .expect("access_token")
        .to_string();

    // Register a confidential client.
    let resp = router(Arc::clone(&state))
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/clients")
                .header("X-Realm-ID", &realm_id)
                .header("Authorization", format!("Bearer {access_token}"))
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"client_name":"test-app","redirect_uris":["https://example.com/cb"]}"#,
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::CREATED, "register client");
    let body = axum::body::to_bytes(resp.into_body(), 8_000)
        .await
        .expect("body");
    let client: serde_json::Value = serde_json::from_slice(&body).expect("json");
    let client_id = client["client_id"].as_str().expect("client_id").to_string();

    // Generate a minimal PKCE challenge.
    let verifier = "dGhpcyBpcyBhIHRlc3QgdmVyaWZpZXIgdGhpcyBpcyBhIHRlc3Q";
    let challenge = {
        use data_encoding::BASE64URL_NOPAD;
        use ring::digest;
        let hash = digest::digest(&digest::SHA256, verifier.as_bytes());
        BASE64URL_NOPAD.encode(hash.as_ref())
    };

    // POST /authorize WITHOUT a user_id field in the body but WITH Bearer token.
    let body = serde_json::json!({
        "client_id":             client_id,
        "redirect_uri":          "https://example.com/cb",
        "response_type":         "code",
        "scope":                 "openid",
        "state":                 "test-state",
        "code_challenge":        challenge,
        "code_challenge_method": "S256"
        // intentionally no "user_id" key
    });
    let resp = router(Arc::clone(&state))
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/authorize")
                .header("X-Realm-ID", &realm_id)
                .header("Authorization", format!("Bearer {access_token}"))
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_string(&body).expect("json"),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "authorize without user_id must succeed when Bearer token is present (HEA-2117)"
    );
    let resp_body = axum::body::to_bytes(resp.into_body(), 4_096)
        .await
        .expect("body");
    let json: serde_json::Value = serde_json::from_slice(&resp_body).expect("json");
    assert!(
        json.get("code")
            .and_then(|v| v.as_str())
            .map(|s| !s.is_empty())
            .unwrap_or(false),
        "response must contain a non-empty authorization code; got: {json}"
    );
}

// ==================== HEA-2111: trust_level via API ====================

/// Helper: bootstrap a dev realm and return (realm_id, access_token).
async fn bootstrap_dev(state: &Arc<AppState>) -> (String, String) {
    let resp = router(Arc::clone(state))
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/admin/bootstrap")
                .body(axum::body::Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK, "bootstrap");
    let b = axum::body::to_bytes(resp.into_body(), 32_000)
        .await
        .expect("body");
    let boot: serde_json::Value = serde_json::from_slice(&b).expect("json");
    (
        boot["realm_id"].as_str().expect("realm_id").to_string(),
        boot["access_token"]
            .as_str()
            .expect("access_token")
            .to_string(),
    )
}

/// HEA-2111: Admin POST /admin/applications with trust_level=first_party must
/// persist FirstParty trust on the stored client.  A subsequent PATCH that does
/// not include trust_level must leave it unchanged (the ..Default::default()
/// landmine must not silently swallow the field).
#[tokio::test]
async fn admin_create_first_party_client_via_api() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let state = test_state_dev(temp_dir.path());
    let (realm_id, token) = bootstrap_dev(&state).await;

    // Create a first-party client via the admin API.
    let resp = router(Arc::clone(&state))
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/admin/applications")
                .header("X-Realm-ID", &realm_id)
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(
                    // trust_level: 2 = CLIENT_TRUST_LEVEL_FIRST_PARTY (pbjson integer form)
                    r#"{"client_name":"fp-app","redirect_uris":["https://example.com/cb"],"trust_level":2}"#,
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "admin create first-party client"
    );
    let b = axum::body::to_bytes(resp.into_body(), 8_000)
        .await
        .expect("body");
    let client: serde_json::Value = serde_json::from_slice(&b).expect("json");
    let client_id = client["client_id"].as_str().expect("client_id").to_string();

    // Verify the trust level is persisted by patching with an unrelated field
    // and confirming that trust_level is not reset to ThirdParty by
    // ..Default::default() in the handler.
    let resp = router(Arc::clone(&state))
        .oneshot(
            axum::http::Request::builder()
                .method("PATCH")
                .uri(format!("/admin/applications/{client_id}"))
                .header("X-Realm-ID", &realm_id)
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"client_name":"fp-app-renamed"}"#,
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK, "patch unrelated field");

    // Fetch the client and confirm trust_level is still first_party.
    let resp = router(Arc::clone(&state))
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri(format!("/admin/applications/{client_id}"))
                .header("X-Realm-ID", &realm_id)
                .header("Authorization", format!("Bearer {token}"))
                .body(axum::body::Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::OK, "get client");
    // The stored client must still be first_party after the patch.
    // We verify by reading the stored client directly from the identity engine
    // to avoid depending on the API serialisation of trust_level.
    use crate::core::ClientId;
    use crate::identity::oidc::ClientTrustLevel;
    let realm_uuid: uuid::Uuid = realm_id.parse().expect("realm uuid");
    let realm_id_t = crate::core::RealmId::new(realm_uuid);
    let client_uuid: uuid::Uuid = client_id.parse().expect("client uuid");
    let stored = state
        .identity
        .get_client(&realm_id_t, &ClientId::new(client_uuid))
        .expect("get_client ok")
        .expect("client exists");
    assert_eq!(
        stored.trust_level(),
        ClientTrustLevel::FirstParty,
        "trust_level must survive a PATCH that omits the field (..Default::default() landmine)"
    );
}

/// HEA-2111: DCR path (POST /register) must always produce ThirdParty trust
/// even when the caller sends trust_level=FIRST_PARTY in the body.
#[tokio::test]
async fn dcr_cannot_self_grant_first_party_trust() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let state = test_state_dev(temp_dir.path());
    let (realm_id, _token) = bootstrap_dev(&state).await;

    let resp = router(Arc::clone(&state))
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/register")
                .header("X-Realm-ID", &realm_id)
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(
                    // trust_level: 2 = CLIENT_TRUST_LEVEL_FIRST_PARTY (pbjson integer form)
                    r#"{"client_name":"dcr-attacker","redirect_uris":["https://evil.example.com/cb"],"trust_level":2}"#,
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    // DCR may be disabled (default in dev) — either 403 or 201 is acceptable,
    // but if the client is created its trust must be ThirdParty.
    if resp.status() == StatusCode::CREATED {
        let b = axum::body::to_bytes(resp.into_body(), 8_000)
            .await
            .expect("body");
        let client: serde_json::Value = serde_json::from_slice(&b).expect("json");
        let client_id = client["client_id"].as_str().expect("client_id").to_string();
        use crate::core::ClientId;
        use crate::identity::oidc::ClientTrustLevel;
        let realm_uuid: uuid::Uuid = realm_id.parse().expect("realm uuid");
        let realm_id_t = crate::core::RealmId::new(realm_uuid);
        let client_uuid: uuid::Uuid = client_id.parse().expect("client uuid");
        let stored = state
            .identity
            .get_client(&realm_id_t, &ClientId::new(client_uuid))
            .expect("get_client ok")
            .expect("client exists");
        assert_eq!(
            stored.trust_level(),
            ClientTrustLevel::ThirdParty,
            "DCR must not allow self-granted first-party trust"
        );
    }
}

/// HEA-2111: PATCH /admin/applications/{id} with trust_level=first_party must
/// upgrade the client's trust level; trust_level=third_party must downgrade it.
#[tokio::test]
async fn patch_client_trust_level_roundtrip() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let state = test_state_dev(temp_dir.path());
    let (realm_id, token) = bootstrap_dev(&state).await;

    // Create a third-party client (default).
    let resp = router(Arc::clone(&state))
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/admin/applications")
                .header("X-Realm-ID", &realm_id)
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"client_name":"tp-app","redirect_uris":["https://example.com/cb"]}"#,
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::CREATED, "create client");
    let b = axum::body::to_bytes(resp.into_body(), 8_000)
        .await
        .expect("body");
    let client: serde_json::Value = serde_json::from_slice(&b).expect("json");
    let client_id = client["client_id"].as_str().expect("client_id").to_string();

    use crate::core::ClientId;
    use crate::identity::oidc::ClientTrustLevel;
    let realm_uuid: uuid::Uuid = realm_id.parse().expect("realm uuid");
    let realm_id_t = crate::core::RealmId::new(realm_uuid);
    let client_uuid: uuid::Uuid = client_id.parse().expect("client uuid");

    // Upgrade to first_party via PATCH.
    let resp = router(Arc::clone(&state))
        .oneshot(
            axum::http::Request::builder()
                .method("PATCH")
                .uri(format!("/admin/applications/{client_id}"))
                .header("X-Realm-ID", &realm_id)
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(r#"{"trust_level":"first_party"}"#))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "patch upgrade to first_party"
    );
    let stored = state
        .identity
        .get_client(&realm_id_t, &ClientId::new(client_uuid))
        .expect("get_client ok")
        .expect("client exists");
    assert_eq!(
        stored.trust_level(),
        ClientTrustLevel::FirstParty,
        "trust_level must be FirstParty after PATCH with trust_level=first_party"
    );

    // Downgrade back to third_party via PATCH.
    let resp = router(Arc::clone(&state))
        .oneshot(
            axum::http::Request::builder()
                .method("PATCH")
                .uri(format!("/admin/applications/{client_id}"))
                .header("X-Realm-ID", &realm_id)
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(r#"{"trust_level":"third_party"}"#))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "patch downgrade to third_party"
    );
    let stored = state
        .identity
        .get_client(&realm_id_t, &ClientId::new(client_uuid))
        .expect("get_client ok")
        .expect("client exists");
    assert_eq!(
        stored.trust_level(),
        ClientTrustLevel::ThirdParty,
        "trust_level must be ThirdParty after PATCH with trust_level=third_party"
    );
}
