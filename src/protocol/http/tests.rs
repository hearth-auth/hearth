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

/// HEA-2143: `GET /dev/probe-user` resolves an email to its user id.
///
/// The migration example scripts need a user id to mint a token with
/// `POST /dev/seed-token`, but a migrated realm has no admin credentials of
/// its own and admin bearer tokens only validate under the realm named in
/// `X-Realm-ID` — so there is no way to look a migrated user up. This probe
/// already performed the `get_user_by_email` lookup and discarded the result;
/// returning the id makes it usable without weakening anything (the route is
/// dev-only, unauthenticated, and loopback-bound, and `POST /dev/seed-token`
/// on the same server is already strictly more powerful).
#[tokio::test]
async fn dev_probe_user_returns_user_id_for_known_email() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let state = test_state_dev(temp_dir.path());

    let realm = state
        .identity
        .create_realm(&crate::identity::CreateRealmRequest {
            name: "probe-realm".to_string(),
            config: None,
        })
        .expect("create realm");
    let user = state
        .identity
        .create_user(
            realm.id(),
            &crate::identity::CreateUserRequest {
                email: "probe@probe.test".to_string(),
                display_name: "Probe User".to_string(),
                ..Default::default()
            },
        )
        .expect("create user");

    let resp = router(Arc::clone(&state))
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri(
                    "/dev/probe-user?realm_id=<RID>&email=probe%40probe.test"
                        .replace("<RID>", &realm.id().as_uuid().to_string()),
                )
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
    assert_eq!(
        json.get("user_id").and_then(serde_json::Value::as_str),
        Some(user.id().as_uuid().to_string().as_str()),
        "probe must resolve a known email to its user id"
    );
}

/// HEA-2143: an unknown email still returns 200 (the C8 latency sweep depends
/// on found/not-found being indistinguishable in status), with a null id.
#[tokio::test]
async fn dev_probe_user_unknown_email_is_200_with_null_id() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let state = test_state_dev(temp_dir.path());
    let realm = crate::core::RealmId::generate();

    let resp = router(state)
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri(
                    "/dev/probe-user?realm_id=<RID>&email=nobody%40probe.test"
                        .replace("<RID>", &realm.as_uuid().to_string()),
                )
                .body(axum::body::Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "an absent user must stay a 200 — the sweep measures latency, not existence"
    );
    let body = axum::body::to_bytes(resp.into_body(), 10_000)
        .await
        .expect("body");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert!(
        json.get("user_id").is_some_and(serde_json::Value::is_null),
        "unknown email must report user_id: null, got {json}"
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

/// The cross-realm fixture for the §4.1#6 BOLA-guard tests: a bootstrapped
/// deployment plus one peer realm holding a single user.
struct CrossRealmFixture {
    state: Arc<AppState>,
    dev_token: String,
    dev_realm_id: String,
    system_token: String,
    system_realm_id: String,
    peer_realm_id: String,
    peer_user_id: String,
    _dir: tempfile::TempDir,
}

/// Bootstraps a deployment and creates a peer realm with one user in it.
async fn cross_realm_fixture(peer_name: &str) -> CrossRealmFixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = test_state_dev(dir.path());

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

    let peer = state
        .identity
        .create_realm(&crate::identity::CreateRealmRequest {
            name: peer_name.to_string(),
            config: None,
        })
        .expect("create peer realm");
    let peer_user = state
        .identity
        .create_user(
            peer.id(),
            &crate::identity::CreateUserRequest {
                email: format!("{peer_name}@example.com"),
                display_name: "Peer User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: std::collections::BTreeMap::new(),
            },
        )
        .expect("create peer user");

    CrossRealmFixture {
        dev_token: json["access_token"].as_str().expect("access_token").into(),
        dev_realm_id: json["realm_id"].as_str().expect("realm_id").into(),
        system_token: json["system_access_token"]
            .as_str()
            .expect("system_access_token")
            .into(),
        system_realm_id: json["system_realm_id"]
            .as_str()
            .expect("system_realm_id")
            .into(),
        peer_realm_id: peer.id().as_uuid().to_string(),
        peer_user_id: peer_user.id().as_uuid().to_string(),
        state,
        _dir: dir,
    }
}

/// Sends one authenticated admin `PATCH` and returns only its status code.
async fn admin_patch_status(
    state: &Arc<AppState>,
    uri: &str,
    token: &str,
    realm_header: &str,
    body: &'static str,
) -> StatusCode {
    router(Arc::clone(state))
        .oneshot(
            axum::http::Request::builder()
                .method("PATCH")
                .uri(uri)
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm_header)
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(body))
                .expect("request"),
        )
        .await
        .expect("response")
        .status()
}

/// Audit 2026-08-28 §4.1#6 — `admin_patch_realm_config` hand-rolled
/// `auth.realm_id != realm_id` instead of calling `scoped_realm`. The
/// hand-rolled copy drops the nil-UUID system-realm branch, so the system
/// operator was locked out of an operation every other `/admin/realms/{id}/*`
/// handler grants them. A peer realm's admin must still be refused.
#[tokio::test]
async fn system_token_patches_another_realms_config() {
    const BODY: &str = r#"{"default_required_actions":["VERIFY_EMAIL"]}"#;

    let f = cross_realm_fixture("bola-peer-config").await;
    let uri = format!("/admin/realms/{}/config", f.peer_realm_id);

    let status =
        admin_patch_status(&f.state, &uri, &f.system_token, &f.system_realm_id, BODY).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "system token must be able to patch another realm's config"
    );

    let status = admin_patch_status(&f.state, &uri, &f.dev_token, &f.dev_realm_id, BODY).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a realm-scoped token must NOT patch another realm's config"
    );
}

/// Audit 2026-08-28 §4.1#6 — the same defect and the same fix in
/// `admin_patch_user_required_actions`.
#[tokio::test]
async fn system_token_patches_another_realms_user_required_actions() {
    const BODY: &str = r#"{"add":["VERIFY_EMAIL"],"remove":[]}"#;

    let f = cross_realm_fixture("bola-peer-actions").await;
    let uri = format!(
        "/admin/realms/{}/users/{}/required-actions",
        f.peer_realm_id, f.peer_user_id
    );

    let status =
        admin_patch_status(&f.state, &uri, &f.system_token, &f.system_realm_id, BODY).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "system token must be able to patch another realm's user required-actions"
    );

    let status = admin_patch_status(&f.state, &uri, &f.dev_token, &f.dev_realm_id, BODY).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a realm-scoped token must NOT patch another realm's user required-actions"
    );
}

/// Every `/admin/realms/{id}/*` route, as `(method, path suffix, body)`.
/// The suffix is appended to `/admin/realms/{realm_id}`; `{user}` is replaced
/// with the peer realm's user id.
const REALM_SCOPED_ADMIN_ROUTES: &[(&str, &str, &str)] = &[
    ("GET", "", ""),
    ("DELETE", "", ""),
    ("POST", "/rotate-signing-key", ""),
    ("GET", "/branding", ""),
    ("PATCH", "/branding", "{}"),
    ("GET", "/email-templates", ""),
    ("GET", "/email-templates/verify_email", ""),
    (
        "PUT",
        "/email-templates/verify_email",
        r#"{"subject":"s","body":"b"}"#,
    ),
    ("DELETE", "/email-templates/verify_email", ""),
    ("PATCH", "/config", r#"{"default_required_actions":[]}"#),
    (
        "PATCH",
        "/users/{user}/required-actions",
        r#"{"add":[],"remove":[]}"#,
    ),
    ("POST", "/sv-bump-all", ""),
];

/// Audit 2026-08-28 §4.1#6 — the BOLA regression guard for the whole
/// realm-scoped admin surface.
///
/// A handler that reads `{realm_id}` from the path and acts on it without
/// `scoped_realm` is a permissive BOLA bypass: a tenant admin reaches a peer
/// realm's object. Rather than trusting a reading of each handler, this walks
/// every such route with a realm-scoped token aimed at a peer realm and
/// requires `403` from all of them.
#[tokio::test]
async fn every_realm_scoped_admin_route_refuses_a_peer_realms_admin() {
    let f = cross_realm_fixture("bola-parity-peer").await;

    for (method, suffix, body) in REALM_SCOPED_ADMIN_ROUTES {
        let uri = format!(
            "/admin/realms/{}{}",
            f.peer_realm_id,
            suffix.replace("{user}", &f.peer_user_id)
        );
        let resp = router(Arc::clone(&f.state))
            .oneshot(
                axum::http::Request::builder()
                    .method(*method)
                    .uri(&uri)
                    .header("Authorization", format!("Bearer {}", f.dev_token))
                    .header("X-Realm-ID", &f.dev_realm_id)
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(*body))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "{method} {uri} must refuse a realm-scoped token aimed at a peer realm"
        );
    }
}

/// Every RBAC write on the public admin API, as `(method, path, body)`.
/// Paths carry placeholder object ids: the system-realm gate must fire before
/// the handler ever looks the object up, so a non-existent id still yields 403.
const RBAC_WRITE_ROUTES: &[(&str, &str, &str)] = &[
    ("POST", "/admin/roles", r#"{"name":"r","description":"","permissions":[],"parent_roles":[]}"#),
    ("PATCH", "/admin/roles/role_00000000-0000-0000-0000-000000000001", r#"{"description":"x"}"#),
    ("DELETE", "/admin/roles/role_00000000-0000-0000-0000-000000000001", ""),
    ("POST", "/admin/groups", r#"{"name":"g","slug":"g"}"#),
    ("PATCH", "/admin/groups/group_00000000-0000-0000-0000-000000000001", r#"{"description":"x"}"#),
    ("DELETE", "/admin/groups/group_00000000-0000-0000-0000-000000000001", ""),
    ("POST", "/admin/groups/group_00000000-0000-0000-0000-000000000001/members", r#"{"type":"user","id":"00000000-0000-0000-0000-000000000002"}"#),
    ("DELETE", "/admin/groups/group_00000000-0000-0000-0000-000000000001/members/user_00000000-0000-0000-0000-000000000002", ""),
    ("POST", "/admin/users/user_00000000-0000-0000-0000-000000000002/roles", r#"{"role_id":"role_00000000-0000-0000-0000-000000000001"}"#),
    ("DELETE", "/admin/assignments/assign_00000000-0000-0000-0000-000000000003", ""),
];

/// Audit 2026-08-28 §4.1#7 — the README states the reserved system realm is
/// read-only through public APIs, and names `create_realm`, `delete_realm`,
/// `register_user`, `register_client` and `create_organization` as rejecting it.
/// Role and group writes carried no such gate, so a `system_access_token`
/// mutated the operators' own realm through `/admin/*`.
///
/// The gate sits at the protocol edge, not in the RBAC engine: the operator
/// console at `/ui/admin/admin-users` legitimately writes system-realm roles
/// and calls the engine directly.
#[tokio::test]
async fn public_rbac_writes_reject_the_system_realm() {
    let f = cross_realm_fixture("system-rbac-gate").await;

    for (method, uri, body) in RBAC_WRITE_ROUTES {
        let resp = router(Arc::clone(&f.state))
            .oneshot(
                axum::http::Request::builder()
                    .method(*method)
                    .uri(*uri)
                    .header("Authorization", format!("Bearer {}", f.system_token))
                    .header("X-Realm-ID", &f.system_realm_id)
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(*body))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "{method} {uri} must refuse a write aimed at the reserved system realm"
        );
    }
}

/// The same routes must stay open to a tenant realm's admin — the gate must
/// refuse the system realm only, not RBAC writes in general.
#[tokio::test]
async fn public_rbac_writes_still_serve_a_tenant_realm() {
    let f = cross_realm_fixture("tenant-rbac-open").await;

    let resp = router(Arc::clone(&f.state))
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/admin/roles")
                .header("Authorization", format!("Bearer {}", f.dev_token))
                .header("X-Realm-ID", &f.dev_realm_id)
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"name":"tenant-role","description":"","permissions":[],"parent_roles":[]}"#,
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_ne!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a tenant realm admin must still be able to create a role"
    );
}

// ── Audit 2026-08-28 §4.1#8 — cross-realm trust policy enforcement ──────────

/// Stores a cross-realm trust policy in `target_realm` naming `source_realm`.
fn store_cross_realm_policy(
    state: &Arc<AppState>,
    target_realm: &str,
    source_realm: &str,
    capabilities: &[&str],
) {
    let target_uuid: uuid::Uuid = target_realm.parse().expect("target uuid");
    let source_uuid: uuid::Uuid = source_realm.parse().expect("source uuid");
    let target = crate::core::RealmId::new(target_uuid);
    let source = crate::core::RealmId::new(source_uuid);
    state
        .identity
        .create_cross_realm_policy(
            &target,
            &crate::identity::CreateCrossRealmPolicyRequest {
                source_realm_id: source,
                allowed_capabilities: capabilities.iter().map(|c| (*c).to_string()).collect(),
                expires_in_secs: None,
            },
        )
        .expect("create cross-realm policy");
}

/// Audit 2026-08-28 §4.1#8 — `check_cross_realm_policy` had no production
/// caller: a realm could store a trust policy, see it audited, and the server
/// would never consult it. The `scoped_realm` guard is the one production path
/// where a realm boundary is actually crossed (a nil-realm system operator
/// reaching into a tenant realm), so the policy is enforced there.
///
/// A policy that governs the (target, source) pair but withholds the admin
/// capability must now refuse the crossing.
#[tokio::test]
async fn denying_cross_realm_policy_refuses_the_system_operator() {
    const BODY: &str = r#"{"default_required_actions":["VERIFY_EMAIL"]}"#;

    let f = cross_realm_fixture("xrealm-policy-deny").await;
    store_cross_realm_policy(
        &f.state,
        &f.peer_realm_id,
        &f.system_realm_id,
        &["agents:read"],
    );

    let uri = format!("/admin/realms/{}/config", f.peer_realm_id);
    let status =
        admin_patch_status(&f.state, &uri, &f.system_token, &f.system_realm_id, BODY).await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a stored cross-realm policy that withholds the admin capability must \
         refuse the crossing"
    );
}

/// The permitting half of the same property: a policy that grants the admin
/// capability leaves the crossing open.
#[tokio::test]
async fn permitting_cross_realm_policy_allows_the_system_operator() {
    const BODY: &str = r#"{"default_required_actions":["VERIFY_EMAIL"]}"#;

    let f = cross_realm_fixture("xrealm-policy-allow").await;
    store_cross_realm_policy(
        &f.state,
        &f.peer_realm_id,
        &f.system_realm_id,
        &["hearth.admin"],
    );

    let uri = format!("/admin/realms/{}/config", f.peer_realm_id);
    let status =
        admin_patch_status(&f.state, &uri, &f.system_token, &f.system_realm_id, BODY).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "a stored cross-realm policy granting hearth.admin must permit the crossing"
    );
}

/// A wildcard capability permits every cross-realm admin operation.
#[tokio::test]
async fn wildcard_cross_realm_policy_allows_the_system_operator() {
    const BODY: &str = r#"{"default_required_actions":["VERIFY_EMAIL"]}"#;

    let f = cross_realm_fixture("xrealm-policy-wildcard").await;
    store_cross_realm_policy(&f.state, &f.peer_realm_id, &f.system_realm_id, &["*"]);

    let uri = format!("/admin/realms/{}/config", f.peer_realm_id);
    let status =
        admin_patch_status(&f.state, &uri, &f.system_token, &f.system_realm_id, BODY).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "a wildcard cross-realm policy must permit the crossing"
    );
}

/// A policy naming a *different* source realm does not govern this crossing,
/// so the permissive-with-audit default still applies. This is the guard that
/// keeps an unrelated tenant's policy from locking the operator out.
#[tokio::test]
async fn unrelated_cross_realm_policy_leaves_the_default_permissive() {
    const BODY: &str = r#"{"default_required_actions":["VERIFY_EMAIL"]}"#;

    let f = cross_realm_fixture("xrealm-policy-unrelated").await;
    store_cross_realm_policy(
        &f.state,
        &f.peer_realm_id,
        &f.dev_realm_id,
        &["agents:read"],
    );

    let uri = format!("/admin/realms/{}/config", f.peer_realm_id);
    let status =
        admin_patch_status(&f.state, &uri, &f.system_token, &f.system_realm_id, BODY).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "a policy naming another source realm must not govern the system \
         operator's crossing"
    );
}

// ── Audit 2026-08-28 §4.1#9 and §4.1#10 ─────────────────────────────────────
//
// #9: `extract_admin_auth` admits any of the five `hearth.*.admin` permissions,
//     and its own comment says "sub-admins pass this outer gate but are still
//     checked per-handler via require_admin_permission()". Eight authenticated
//     admin handlers never made that per-handler call, so a token holding only
//     `hearth.clients.admin` reached role definitions, webhook delivery logs,
//     AAT validation, transaction-token consumption, SPIFFE mappings,
//     cross-realm trust policies and agent cards.
//
// #10: five admin sub-resource handlers scope their query to the caller's realm
//     but never check that the *parent* object exists there, so a parent absent
//     from the realm produced `200` with an empty collection instead of `404`.

/// A dev-mode `AppState` with every optional admin surface wired: the Phase-A
/// agent routes, the Phase-D advanced routes, and a storage-backed webhook
/// engine.
///
/// Without these the routes under test are either unregistered (404 from the
/// router) or answer `501 Not Implemented` before reaching the handler, and a
/// status assertion on them would be vacuous.
fn test_state_dev_full(temp_dir: &std::path::Path) -> Arc<AppState> {
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
    let webhook = Arc::new(crate::webhook::EmbeddedWebhookEngine::new(
        Arc::clone(&engine) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    )) as Arc<dyn crate::webhook::WebhookEngine>;

    Arc::new(
        AppState::new_dev(
            Arc::new(identity_engine),
            rbac_engine,
            audit_engine as Arc<dyn AuditEngine>,
        )
        .with_agent_identity(true)
        .with_agent_advanced(true)
        .with_webhook(webhook),
    )
}

/// The fixture for the §4.1#9 / §4.1#10 admin-surface tests.
struct AdminSurfaceFixture {
    state: Arc<AppState>,
    realm_id: String,
    /// A full `hearth.admin` superuser token.
    admin_token: String,
    /// A token whose *only* permission is `hearth.clients.admin`. It passes the
    /// outer `extract_admin_auth` gate and must be refused by every handler
    /// outside the OAuth-client domain.
    narrow_token: String,
    /// A user that really exists in `realm_id`.
    user_id: String,
    /// A group that really exists in `realm_id`.
    group_id: String,
    /// A webhook subscription that really exists in `realm_id`.
    webhook_id: String,
    /// The reserved system realm (nil UUID), as a string.
    system_realm_id: String,
    /// A **system-realm** token carrying `hearth.admin`.
    system_admin_token: String,
    /// A **system-realm** token whose only permission is `hearth.users.admin`.
    /// It clears `extract_cluster_admin_auth`'s nil-realm assertion, so it is
    /// the only token that can tell a cluster permission gate apart from the
    /// realm gate.
    system_narrow_token: String,
    _dir: tempfile::TempDir,
}

/// Bootstraps a dev deployment, mints a single-permission sub-admin token, and
/// creates one real user, group and webhook so both directions of the property
/// can be asserted.
#[allow(clippy::too_many_lines)]
async fn admin_surface_fixture() -> AdminSurfaceFixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = test_state_dev_full(dir.path());

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
    let body = axum::body::to_bytes(resp.into_body(), 10_000)
        .await
        .expect("body");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    let realm_id_str: String = json["realm_id"].as_str().expect("realm_id").into();
    let realm_id = crate::core::RealmId::new(realm_id_str.parse().expect("realm uuid"));

    // A sub-admin holding the shipped `hearth.clients.admin` delegation role,
    // whose only permission is `hearth.clients.admin`. This is exactly the
    // shape `src/rbac/seed.rs` tells operators to assign for Keycloak-style
    // delegation, so the test measures the real deployment story.
    let narrow_role = state
        .rbac
        .get_role_by_name(&realm_id, "hearth.clients.admin")
        .expect("lookup seed role")
        .expect("seed role hearth.clients.admin is present after bootstrap");
    let narrow_user = state
        .identity
        .create_user(
            &realm_id,
            &crate::identity::CreateUserRequest {
                email: "clients-only@example.com".to_string(),
                display_name: "Clients Only".to_string(),
                ..Default::default()
            },
        )
        .expect("create narrow user");
    let narrow_uid = narrow_user.id().clone();
    state
        .identity
        .update_user(
            &realm_id,
            &narrow_uid,
            &crate::identity::UpdateUserRequest {
                status: Some(crate::identity::UserStatus::Active),
                ..Default::default()
            },
        )
        .expect("activate narrow user");
    state
        .rbac
        .assign_role(
            &realm_id,
            &crate::rbac::AssignRoleRequest {
                subject: crate::rbac::Subject::User(narrow_uid.clone()),
                role_id: narrow_role.id.clone(),
                scope: crate::rbac::Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign narrow role");
    let narrow_session = state
        .identity
        .create_session(
            &realm_id,
            &narrow_uid,
            &crate::identity::SessionContext::default(),
        )
        .expect("narrow session");
    let narrow_tokens = state
        .identity
        .issue_tokens(&realm_id, &narrow_uid, narrow_session.id())
        .expect("narrow tokens");

    // Real objects, so the 404 assertions cannot pass by blanket-404ing.
    let real_user = state
        .identity
        .create_user(
            &realm_id,
            &crate::identity::CreateUserRequest {
                email: "present@example.com".to_string(),
                display_name: "Present User".to_string(),
                ..Default::default()
            },
        )
        .expect("create real user");
    let real_group = state
        .rbac
        .create_group(
            &realm_id,
            &crate::rbac::CreateGroupRequest {
                name: "Present Group".to_string(),
                slug: "present-group".to_string(),
                description: None,
            },
        )
        .expect("create real group");
    let real_webhook = state
        .webhook
        .as_ref()
        .expect("webhook engine")
        .create(&crate::webhook::CreateWebhookRequest {
            realm_id: realm_id.clone(),
            url: "https://example.com/hook".to_string(),
            secret: "0123456789abcdef0123456789abcdef".to_string(),
            enabled: true,
            event_filters: Vec::new(),
        })
        .expect("create real webhook");

    // A sub-admin **inside the system realm**. `extract_cluster_admin_auth`
    // asserts the caller's realm is the nil-UUID system realm and stops there,
    // so only a system-realm token can distinguish a missing permission gate
    // from the realm assertion that is already present. Bootstrap has already
    // RBAC-seeded the system realm, so the delegation role exists.
    let system_realm = crate::identity::keys::system_realm_id();
    let sys_role = state
        .rbac
        .get_role_by_name(&system_realm, "hearth.users.admin")
        .expect("lookup system seed role")
        .expect("seed role hearth.users.admin is present in the system realm");
    let sys_user = state
        .identity
        .create_admin_user(&crate::identity::CreateUserRequest {
            email: "cluster-subadmin@hearth.test".to_string(),
            display_name: "Cluster Sub-Admin".to_string(),
            ..Default::default()
        })
        .expect("create system-realm sub-admin");
    let sys_uid = sys_user.id().clone();
    state
        .identity
        .update_user(
            &system_realm,
            &sys_uid,
            &crate::identity::UpdateUserRequest {
                status: Some(crate::identity::UserStatus::Active),
                ..Default::default()
            },
        )
        .expect("activate system-realm sub-admin");
    state
        .rbac
        .assign_role(
            &system_realm,
            &crate::rbac::AssignRoleRequest {
                subject: crate::rbac::Subject::User(sys_uid.clone()),
                role_id: sys_role.id.clone(),
                scope: crate::rbac::Scope::Realm,
                assigned_by: None,
            },
        )
        .expect("assign system-realm sub-admin role");
    let sys_session = state
        .identity
        .create_session(
            &system_realm,
            &sys_uid,
            &crate::identity::SessionContext::default(),
        )
        .expect("system-realm sub-admin session");
    let sys_tokens = state
        .identity
        .issue_tokens(&system_realm, &sys_uid, sys_session.id())
        .expect("system-realm sub-admin tokens");

    AdminSurfaceFixture {
        admin_token: json["access_token"].as_str().expect("access_token").into(),
        narrow_token: narrow_tokens.access_token().to_string(),
        system_realm_id: json["system_realm_id"]
            .as_str()
            .expect("system_realm_id")
            .into(),
        system_admin_token: json["system_access_token"]
            .as_str()
            .expect("system_access_token")
            .into(),
        system_narrow_token: sys_tokens.access_token().to_string(),
        realm_id: realm_id_str,
        user_id: real_user.id().as_uuid().to_string(),
        group_id: real_group.id.as_uuid().to_string(),
        webhook_id: real_webhook.id.as_uuid().to_string(),
        state,
        _dir: dir,
    }
}

/// Sends one authenticated admin request and returns only its status code.
async fn admin_request_status(
    state: &Arc<AppState>,
    method: &str,
    uri: &str,
    token: &str,
    realm_header: &str,
    body: &str,
) -> StatusCode {
    router(Arc::clone(state))
        .oneshot(
            axum::http::Request::builder()
                .method(method)
                .uri(uri)
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm_header)
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("response")
        .status()
}

/// Every authenticated admin route that carried no per-handler permission gate,
/// as `(method, uri, body)`.
///
/// The bodies must deserialize into the handler's `Json` extractor or the
/// request dies at `422` inside the extractor and the assertion measures the
/// extractor rather than the gate.
const UNGATED_ADMIN_ROUTES: &[(&str, &str, &str)] = &[
    // `hearth.realm.admin` domain — the siblings in each family already gate.
    (
        "GET",
        "/admin/roles/00000000-0000-0000-0000-0000000000a1",
        "",
    ),
    (
        "GET",
        "/admin/webhooks/00000000-0000-0000-0000-0000000000a2/deliveries",
        "",
    ),
    // `hearth.agents.admin` domain — Phase-D advanced + Phase-A agent card.
    ("POST", "/v1/aats/validate", r#"{"aat":"not-a-real-aat"}"#),
    (
        "POST",
        "/v1/transaction-tokens/consume",
        r#"{"token":"not-a-real-token"}"#,
    ),
    (
        "GET",
        "/v1/spiffe-mappings/agt_00000000-0000-0000-0000-0000000000a3",
        "",
    ),
    ("GET", "/v1/cross-realm-policies", ""),
    ("GET", "/v1/cross-realm-policies/no-such-policy", ""),
    (
        "GET",
        "/.well-known/agent.json?agent_id=agt_00000000-0000-0000-0000-0000000000a4",
        "",
    ),
];

/// Audit 2026-08-28 §4.1#9 — every authenticated admin handler carries a
/// per-handler permission gate.
///
/// `extract_admin_auth` admits any of the five `hearth.*.admin` permissions on
/// purpose: it is the outer gate, and each handler is expected to name the
/// sub-admin domain it belongs to. The eight routes listed above named none, so
/// a token holding only `hearth.clients.admin` reached role definitions,
/// webhook delivery logs and the whole agent-authorization surface.
///
/// Both directions are asserted: the narrow token must be refused, and the
/// `hearth.admin` superuser must still get through — a gate that refuses
/// everyone would otherwise pass the first half vacuously.
#[tokio::test]
async fn every_authenticated_admin_handler_gates_on_a_sub_admin_permission() {
    let f = admin_surface_fixture().await;

    for (method, uri, body) in UNGATED_ADMIN_ROUTES {
        let status =
            admin_request_status(&f.state, method, uri, &f.narrow_token, &f.realm_id, body).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{method} {uri} must refuse a token holding only hearth.clients.admin"
        );
    }

    for (method, uri, body) in UNGATED_ADMIN_ROUTES {
        let status =
            admin_request_status(&f.state, method, uri, &f.admin_token, &f.realm_id, body).await;
        assert_ne!(
            status,
            StatusCode::FORBIDDEN,
            "{method} {uri} must still admit a hearth.admin superuser; the gate must \
             name a domain, not refuse everyone"
        );
    }
}

/// Audit 2026-08-28 §4.1#10 — an admin sub-resource route answers `404` when
/// its parent object is absent from the caller's realm.
///
/// Each of these handlers scopes its own query to `auth.realm_id`, so no other
/// realm's rows are ever served; the defect is the status code. A caller asking
/// for the sessions of a user that does not exist in their realm was answered
/// `200 {"items": []}` — indistinguishable from a user that exists and has no
/// sessions.
///
/// The `{present}` form of each route is walked too: a handler that answered
/// `404` unconditionally would pass the first half and fail here.
#[tokio::test]
async fn admin_subresource_routes_answer_404_for_a_parent_absent_from_the_realm() {
    let f = admin_surface_fixture().await;
    const MISSING: &str = "00000000-0000-0000-0000-0000000000ff";

    let absent = [
        format!("/admin/users/{MISSING}/consents"),
        format!("/admin/users/{MISSING}/roles"),
        format!("/admin/users/{MISSING}/sessions"),
        format!("/admin/groups/{MISSING}/members"),
        format!("/admin/webhooks/{MISSING}/deliveries"),
    ];
    for uri in &absent {
        let status =
            admin_request_status(&f.state, "GET", uri, &f.admin_token, &f.realm_id, "").await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "GET {uri} must answer 404 for a parent absent from the caller's realm"
        );
    }

    let present = [
        format!("/admin/users/{}/consents", f.user_id),
        format!("/admin/users/{}/roles", f.user_id),
        format!("/admin/users/{}/sessions", f.user_id),
        format!("/admin/groups/{}/members", f.group_id),
        format!("/admin/webhooks/{}/deliveries", f.webhook_id),
    ];
    for uri in &present {
        let status =
            admin_request_status(&f.state, "GET", uri, &f.admin_token, &f.realm_id, "").await;
        assert_eq!(
            status,
            StatusCode::OK,
            "GET {uri} must still answer 200 for a parent that exists in the realm"
        );
    }
}

// ── Audit 2026-08-28 §4.1#8 follow-up — who may author a system-source policy ─

/// Fixture for the cross-realm-policy *write* tests: a bootstrapped dev
/// deployment with the Phase-D advanced routes registered (without
/// `with_agent_advanced(true)` every `/v1/cross-realm-policies` assertion would
/// be vacuous — the router answers `404` before reaching the handler), plus one
/// peer tenant realm to act as a benign non-system source.
struct XRealmWriteFixture {
    state: Arc<AppState>,
    dev_token: String,
    dev_realm_id: String,
    system_token: String,
    system_realm_id: String,
    peer_realm_id: String,
    _dir: tempfile::TempDir,
}

async fn xrealm_write_fixture(peer_name: &str) -> XRealmWriteFixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = test_state_dev_full(dir.path());

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
    let body = axum::body::to_bytes(resp.into_body(), 10_000)
        .await
        .expect("body");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");

    let peer = state
        .identity
        .create_realm(&crate::identity::CreateRealmRequest {
            name: peer_name.to_string(),
            config: None,
        })
        .expect("create peer realm");

    XRealmWriteFixture {
        dev_token: json["access_token"].as_str().expect("access_token").into(),
        dev_realm_id: json["realm_id"].as_str().expect("realm_id").into(),
        system_token: json["system_access_token"]
            .as_str()
            .expect("system_access_token")
            .into(),
        system_realm_id: json["system_realm_id"]
            .as_str()
            .expect("system_realm_id")
            .into(),
        peer_realm_id: peer.id().as_uuid().to_string(),
        state,
        _dir: dir,
    }
}

/// `POST /v1/cross-realm-policies` as `token` in `realm_header`, naming
/// `source_realm` as the policy's source. Returns only the status code.
async fn post_cross_realm_policy(
    state: &Arc<AppState>,
    token: &str,
    realm_header: &str,
    source_realm: &str,
) -> StatusCode {
    let body = format!(
        r#"{{"source_realm_id":"{source_realm}","allowed_capabilities":["agents:read"],"expires_in_secs":null}}"#
    );
    router(Arc::clone(state))
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/v1/cross-realm-policies")
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Realm-ID", realm_header)
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(body))
                .expect("request"),
        )
        .await
        .expect("response")
        .status()
}

/// Audit 2026-08-28 §4.1#8 follow-up — the enforcement wired into `scoped_realm`
/// reads cross-realm trust policies out of the *target* realm, and every
/// `/v1/cross-realm-policies` write stores the policy in the **actor's own**
/// realm. A tenant admin could therefore author a policy naming the reserved
/// system realm as source, withhold `hearth.admin`, and revoke the platform
/// operator's `/admin/realms/{id}/*` access to their realm — a tenant denying
/// service to the operator.
///
/// A policy whose source is the system realm may now only be authored by a
/// system-realm actor.
#[tokio::test]
async fn tenant_realm_cannot_author_a_system_source_cross_realm_policy() {
    let f = xrealm_write_fixture("xrealm-write-deny").await;

    let status =
        post_cross_realm_policy(&f.state, &f.dev_token, &f.dev_realm_id, &f.system_realm_id).await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a tenant-realm admin must not author a cross-realm policy naming the \
         reserved system realm as its source"
    );
}

/// The permitting half: a system-realm actor authoring the same policy succeeds.
#[tokio::test]
async fn system_realm_actor_may_author_a_system_source_cross_realm_policy() {
    let f = xrealm_write_fixture("xrealm-write-allow").await;

    let status = post_cross_realm_policy(
        &f.state,
        &f.system_token,
        &f.system_realm_id,
        &f.system_realm_id,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::CREATED,
        "a system-realm actor must still be able to author a system-source policy"
    );
}

/// Policies between two tenant realms are unaffected by the new rule.
#[tokio::test]
async fn tenant_to_tenant_cross_realm_policy_is_unaffected() {
    let f = xrealm_write_fixture("xrealm-write-tenant").await;

    let status =
        post_cross_realm_policy(&f.state, &f.dev_token, &f.dev_realm_id, &f.peer_realm_id).await;

    assert_eq!(
        status,
        StatusCode::CREATED,
        "a policy naming another tenant realm as source must still be accepted"
    );
}

/// The recovery valve must stay open. A policy stored before this rule existed
/// (written here through the engine, as the API no longer permits it) is the
/// residue case: the tenant admin must be able to `DELETE` it, because deleting
/// a system-source policy can only ever *relax* the operator's access — the
/// ungoverned default is permissive. Refusing the delete would make a legacy
/// lockout unrecoverable from either side.
#[tokio::test]
async fn tenant_realm_may_delete_a_legacy_system_source_policy() {
    let f = xrealm_write_fixture("xrealm-write-residue").await;

    let dev_uuid: uuid::Uuid = f.dev_realm_id.parse().expect("dev uuid");
    let sys_uuid: uuid::Uuid = f.system_realm_id.parse().expect("system uuid");
    let policy = f
        .state
        .identity
        .create_cross_realm_policy(
            &crate::core::RealmId::new(dev_uuid),
            &crate::identity::CreateCrossRealmPolicyRequest {
                source_realm_id: crate::core::RealmId::new(sys_uuid),
                allowed_capabilities: vec!["agents:read".to_string()],
                expires_in_secs: None,
            },
        )
        .expect("legacy policy");

    let resp = router(Arc::clone(&f.state))
        .oneshot(
            axum::http::Request::builder()
                .method("DELETE")
                .uri(format!("/v1/cross-realm-policies/{}", policy.policy_id))
                .header("Authorization", format!("Bearer {}", f.dev_token))
                .header("X-Realm-ID", &f.dev_realm_id)
                .body(axum::body::Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "a tenant admin must be able to delete a legacy system-source policy"
    );
}

// ── Audit follow-up: `/admin/cluster/*` permission gate ──────────────────────
//
// The same defect class as §4.1#9, one layer up. `extract_cluster_admin_auth`
// proves the caller holds a valid admin token *and* that their realm is the
// nil-UUID system realm — then stops. It reads no permission, so a system-realm
// operator delegated only `hearth.users.admin` could bootstrap Raft membership
// or transfer leadership: the two most destructive operations in the product.

/// Every `/admin/cluster/*` route, as `(method, uri, body)`.
///
/// All three handlers read the body as `axum::body::Bytes`, not `Json<T>`, and
/// treat an empty body as the default request — so no extractor can answer
/// before the handler runs and mask the gate under test.
const CLUSTER_ADMIN_ROUTES: &[(&str, &str, &str)] = &[
    ("POST", "/admin/cluster/bootstrap", ""),
    ("GET", "/admin/cluster/status", ""),
    ("POST", "/admin/cluster/transfer-leadership", ""),
];

/// Audit follow-up to 2026-08-28 §4.1#9 — the cluster plane requires
/// `hearth.admin`, not merely a system-realm identity.
///
/// Three assertions, and all three are needed:
///
/// 1. A **system-realm** token holding only `hearth.users.admin` is refused.
///    It must be system-realm: a tenant-realm token is already refused by the
///    nil-UUID assertion, so testing with one would pass vacuously against the
///    gate that was already there.
/// 2. A `hearth.admin` system token is **not** refused. The fixture runs
///    single-node, so it gets `503 not in cluster mode` — which also proves the
///    permission gate is ordered *before* the cluster-availability check: the
///    sub-admin in (1) never learns whether this deployment runs a cluster.
/// 3. A tenant-realm token is still refused, so the pre-existing realm boundary
///    has not regressed.
#[tokio::test]
async fn cluster_admin_routes_require_hearth_admin_not_just_a_system_realm_identity() {
    let f = admin_surface_fixture().await;

    for (method, uri, body) in CLUSTER_ADMIN_ROUTES {
        let status = admin_request_status(
            &f.state,
            method,
            uri,
            &f.system_narrow_token,
            &f.system_realm_id,
            body,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{method} {uri} must refuse a system-realm token holding only \
             hearth.users.admin"
        );
    }

    for (method, uri, body) in CLUSTER_ADMIN_ROUTES {
        let status = admin_request_status(
            &f.state,
            method,
            uri,
            &f.system_admin_token,
            &f.system_realm_id,
            body,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{method} {uri} must admit a hearth.admin system operator and fail \
             only on cluster availability; a 403 here would mean the gate \
             refuses everyone, and anything else would mean the gate is not \
             ordered before the availability check"
        );
    }

    for (method, uri, body) in CLUSTER_ADMIN_ROUTES {
        let status =
            admin_request_status(&f.state, method, uri, &f.admin_token, &f.realm_id, body).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{method} {uri} must still refuse a tenant-realm admin (HEA-763 \
             realm boundary, unchanged)"
        );
    }
}

// ── 25.14 — the operator's authoring path into a tenant realm's policies ─────

/// Sends an authenticated admin request with no body and returns status + body.
async fn admin_request(
    state: &Arc<AppState>,
    method: &str,
    uri: &str,
    token: &str,
    realm_header: &str,
    body: Option<String>,
) -> (StatusCode, serde_json::Value) {
    let builder = axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Realm-ID", realm_header)
        .header("Content-Type", "application/json");
    let req = match body {
        Some(b) => builder.body(axum::body::Body::from(b)).expect("request"),
        None => builder.body(axum::body::Body::empty()).expect("request"),
    };
    let resp = router(Arc::clone(state))
        .oneshot(req)
        .await
        .expect("response");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 200_000)
        .await
        .expect("body");
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// 25.14 — the recovery valve, end to end. A policy stored in a tenant realm
/// that withholds `hearth.admin` locks the platform operator out of that
/// realm's `/admin/realms/{id}/*` routes (the 17.5 enforcement). Before this
/// route existed the operator had no way to reach that policy: every
/// `/v1/cross-realm-policies` handler is keyed on the caller's own realm.
///
/// The new route is deliberately **exempt** from the cross-realm policy consult
/// — a valve gated on the thing it exists to undo is not a valve — so the
/// operator can delete the policy and recover.
#[tokio::test]
async fn operator_recovers_from_a_locking_policy_through_the_admin_route() {
    const BODY: &str = r#"{"default_required_actions":["VERIFY_EMAIL"]}"#;

    let f = cross_realm_fixture("xrealm-valve").await;
    store_cross_realm_policy(
        &f.state,
        &f.peer_realm_id,
        &f.system_realm_id,
        &["agents:read"],
    );

    let config_uri = format!("/admin/realms/{}/config", f.peer_realm_id);
    let locked = admin_patch_status(
        &f.state,
        &config_uri,
        &f.system_token,
        &f.system_realm_id,
        BODY,
    )
    .await;
    assert_eq!(
        locked,
        StatusCode::FORBIDDEN,
        "precondition: the policy must actually lock the operator out"
    );

    // The operator can still SEE what governs the realm...
    let list_uri = format!("/admin/realms/{}/cross-realm-policies", f.peer_realm_id);
    let (status, listed) = admin_request(
        &f.state,
        "GET",
        &list_uri,
        &f.system_token,
        &f.system_realm_id,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "operator must be able to list");
    let policy_id = listed["items"][0]["policy_id"]
        .as_str()
        .expect("policy_id in listing")
        .to_string();

    // ...and remove it.
    let (status, _) = admin_request(
        &f.state,
        "DELETE",
        &format!("{list_uri}/{policy_id}"),
        &f.system_token,
        &f.system_realm_id,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "the valve must be exempt from the policy it exists to undo"
    );

    let recovered = admin_patch_status(
        &f.state,
        &config_uri,
        &f.system_token,
        &f.system_realm_id,
        BODY,
    )
    .await;
    assert_eq!(
        recovered,
        StatusCode::OK,
        "operator access must be restored once the policy is gone"
    );
}

/// 25.14 — the operator can author a policy into a tenant realm, which is what
/// makes the 17.5 deny branch reachable on a clean deployment: before this
/// route, no principal could put a system-source policy into a tenant realm at
/// all (25.11 refuses the tenant, and `/v1/*` is keyed on the caller's realm).
#[tokio::test]
async fn operator_authors_a_cross_realm_policy_into_a_tenant_realm() {
    const BODY: &str = r#"{"default_required_actions":["VERIFY_EMAIL"]}"#;

    let f = cross_realm_fixture("xrealm-author").await;
    let list_uri = format!("/admin/realms/{}/cross-realm-policies", f.peer_realm_id);

    let (status, created) = admin_request(
        &f.state,
        "POST",
        &list_uri,
        &f.system_token,
        &f.system_realm_id,
        Some(format!(
            r#"{{"source_realm_id":"{}","allowed_capabilities":["agents:read"],"expires_in_secs":null}}"#,
            f.system_realm_id
        )),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "operator may author the policy"
    );
    assert_eq!(
        created["target_realm_id"].as_str(),
        Some(f.peer_realm_id.as_str()),
        "the policy must be stored in the tenant realm named in the path"
    );

    // The policy withholds hearth.admin, so the 17.5 deny branch now fires on a
    // deployment where nothing else could have produced it.
    let config_uri = format!("/admin/realms/{}/config", f.peer_realm_id);
    let status = admin_patch_status(
        &f.state,
        &config_uri,
        &f.system_token,
        &f.system_realm_id,
        BODY,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an operator-authored policy that withholds hearth.admin must bind the operator"
    );
}

/// 25.14 — the exemption is narrow: it removes the policy consult, not the BOLA
/// guard. A tenant admin still cannot reach a peer realm's policies.
#[tokio::test]
async fn tenant_admin_cannot_reach_a_peer_realms_cross_realm_policies() {
    let f = cross_realm_fixture("xrealm-bola").await;
    let list_uri = format!("/admin/realms/{}/cross-realm-policies", f.peer_realm_id);

    for (method, body) in [
        ("GET", None),
        (
            "POST",
            Some(
                r#"{"source_realm_id":"00000000-0000-0000-0000-000000000000","allowed_capabilities":[],"expires_in_secs":null}"#
                    .to_string(),
            ),
        ),
    ] {
        let (status, _) =
            admin_request(&f.state, method, &list_uri, &f.dev_token, &f.dev_realm_id, body).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{method} {list_uri} must refuse a peer realm's admin"
        );
    }
}

/// 25.14 — the 25.11 write rule still applies on this route. A tenant admin
/// operating on their *own* realm (path realm == token realm, so the BOLA guard
/// passes) must still not author a policy naming the system realm as source.
#[tokio::test]
async fn tenant_admin_cannot_author_a_system_source_policy_on_the_admin_route() {
    let f = cross_realm_fixture("xrealm-own-realm").await;
    let list_uri = format!("/admin/realms/{}/cross-realm-policies", f.dev_realm_id);

    let (status, _) = admin_request(
        &f.state,
        "POST",
        &list_uri,
        &f.dev_token,
        &f.dev_realm_id,
        Some(format!(
            r#"{{"source_realm_id":"{}","allowed_capabilities":["*"],"expires_in_secs":null}}"#,
            f.system_realm_id
        )),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the 25.11 system-source rule must hold on the admin route too"
    );
}
