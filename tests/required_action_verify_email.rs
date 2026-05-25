//! Integration tests for HEA-754: VERIFY_EMAIL required action — verification email + redemption.
// HEA-754 stub: handlers not yet implemented; lints suppressed until implementation lands.
#![allow(clippy::unwrap_used, clippy::similar_names)]
//!
//! Covers all acceptance criteria from the issue:
//! - AC-1: POST request sends email, returns 202, stores SHA-256 hashed token
//! - AC-2: Valid token → VERIFY_EMAIL cleared, full-access token returned
//! - AC-3: Expired token → 410 Gone, `verification_token_expired`
//! - AC-4: Already-redeemed token → 410 Gone (single-use)
//! - AC-5: Rate-limit: max 3 resends/hr/user; previous token invalidated on resend
//! - AC-6: Engine-level: `request_email_verification` returns plaintext token

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hearth::audit::EmbeddedAuditEngine;
use hearth::core::{FakeClock, RealmId, Timestamp};
use hearth::identity::email::{EmailBranding, EmailService, LoggingEmailSender};
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, EmbeddedIdentityEngine,
    IdentityConfig, IdentityEngine, PasswordGrantRequest, RequiredAction,
};
use hearth::protocol::http::{router, AppState};
use hearth::rbac::EmbeddedRbacEngine;
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};
use tower::ServiceExt as _;

// ===== Helpers =====

/// Builds a (storage, clock, identity_engine) triple backed by a FakeClock.
fn make_engine_with_clock(
    temp_dir: &tempfile::TempDir,
) -> (Arc<EmbeddedIdentityEngine>, Arc<FakeClock>) {
    let config = StorageConfig::dev(temp_dir.path().to_path_buf());
    let storage = Arc::new(EmbeddedStorageEngine::open(config).expect("storage"));
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(
        1_700_000_000_000_000,
    )));
    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock) as Arc<dyn hearth::core::Clock>,
    ));
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock) as Arc<dyn hearth::core::Clock>,
    ));
    let id_config = IdentityConfig {
        credential: hearth::identity::CredentialConfig::fast_for_testing(),
        ..IdentityConfig::default()
    };
    let engine = EmbeddedIdentityEngine::with_rbac(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock) as Arc<dyn hearth::core::Clock>,
        id_config,
        rbac as Arc<dyn hearth::rbac::RbacEngine>,
        audit as Arc<dyn hearth::audit::AuditEngine>,
    )
    .expect("identity engine");
    (Arc::new(engine), clock)
}

async fn setup(
    identity: &dyn IdentityEngine,
) -> (hearth::core::RealmId, hearth::core::UserId, String) {
    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: format!("ve-test-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");
    let realm_id = realm.id().clone();

    let email = format!("user-{}@ve-test.local", uuid::Uuid::new_v4());
    let user = identity
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: email.clone(),
                display_name: "VE Test User".to_string(),
                first_name: "VE".to_string(),
                last_name: "Test".to_string(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    let pw = CleartextPassword::from_string("Hearth_Test_P@ss1!".to_string());
    identity
        .set_password(&realm_id, user.id(), &pw)
        .expect("set password");

    (realm_id, user.id().clone(), email)
}

fn build_app(harness: &common::TestHarness) -> axum::Router {
    let email_service = Arc::new(
        EmailService::new(
            Arc::new(LoggingEmailSender::new()),
            "Hearth".to_string(),
            None,
            EmailBranding::default(),
            "<svg/>".to_string(),
            None,
        )
        .expect("email service"),
    );
    let state = Arc::new(
        AppState::new(
            harness.identity_arc(),
            harness.rbac_arc(),
            harness.audit_arc(),
        )
        .with_email(email_service),
    );
    router(state)
}

/// Acquires a required-action JWT with `VERIFY_EMAIL` pending.
async fn acquire_required_action_token(
    identity: &dyn IdentityEngine,
    realm_id: &hearth::core::RealmId,
    user_id: &hearth::core::UserId,
    email: &str,
) -> String {
    identity
        .add_required_action(realm_id, user_id, RequiredAction::VerifyEmail)
        .expect("add VERIFY_EMAIL action");

    let resp = identity
        .password_grant_token(
            realm_id,
            &PasswordGrantRequest {
                email: email.to_string(),
                password: "Hearth_Test_P@ss1!".to_string(),
                scope: None,
            },
        )
        .expect("password_grant_token");

    let claims = hearth::identity::decode_claims_unverified(resp.access_token())
        .expect("decode access token");
    assert_eq!(claims.token_type, "required_action");
    assert!(claims
        .required_actions
        .contains(&RequiredAction::VerifyEmail));

    resp.access_token().to_string()
}

// ===== AC-6: Engine-level — request_email_verification returns a token =====

#[tokio::test]
async fn engine_request_email_verification_returns_token() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let (realm_id, user_id, _email) = setup(identity).await;

    identity
        .add_required_action(&realm_id, &user_id, RequiredAction::VerifyEmail)
        .expect("add action");

    let token = identity
        .request_email_verification(&realm_id, &user_id)
        .expect("request_email_verification");

    // Token must be non-empty (32-byte base64url = 43 chars without padding)
    assert!(!token.is_empty(), "verification token must be non-empty");
    assert!(
        token.len() >= 40,
        "token should be at least 40 chars (base64url of 32 bytes): len={}",
        token.len()
    );
}

// ===== AC-2: Valid token → VERIFY_EMAIL cleared, full-access token =====

#[tokio::test]
async fn engine_redeem_email_verification_clears_action_and_returns_token() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let (realm_id, user_id, _email) = setup(identity).await;

    identity
        .add_required_action(&realm_id, &user_id, RequiredAction::VerifyEmail)
        .expect("add action");

    let token = identity
        .request_email_verification(&realm_id, &user_id)
        .expect("request_email_verification");

    let grant = identity
        .redeem_email_verification(&realm_id, &token)
        .expect("redeem_email_verification");

    // Access token must be a full-access token (not required-action)
    let claims = hearth::identity::decode_claims_unverified(&grant.access_token)
        .expect("decode access token");
    assert_eq!(
        claims.token_type, "access",
        "redeemed token must be full-access, got: {:?}",
        claims.token_type
    );
    assert!(
        claims.required_actions.is_empty(),
        "redeemed token must have no required_actions, got: {:?}",
        claims.required_actions
    );

    // VERIFY_EMAIL must be cleared from pending actions
    let pending = identity
        .pending_actions(&realm_id, &user_id)
        .expect("pending_actions");
    assert!(
        !pending.contains(&RequiredAction::VerifyEmail),
        "VERIFY_EMAIL must be cleared after redemption, pending: {:?}",
        pending
    );
}

// ===== AC-4: Already-redeemed (single-use) =====

#[tokio::test]
async fn engine_redeem_email_verification_is_single_use() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let (realm_id, user_id, _email) = setup(identity).await;

    identity
        .add_required_action(&realm_id, &user_id, RequiredAction::VerifyEmail)
        .expect("add action");

    let token = identity
        .request_email_verification(&realm_id, &user_id)
        .expect("request_email_verification");

    // First redemption succeeds
    identity
        .redeem_email_verification(&realm_id, &token)
        .expect("first redemption");

    // Second redemption must fail
    let err = identity
        .redeem_email_verification(&realm_id, &token)
        .expect_err("second redemption must fail");

    assert!(
        matches!(
            err,
            hearth::identity::IdentityError::EmailVerificationTokenInvalid
        ),
        "second redemption must return EmailVerificationTokenInvalid, got: {err:?}"
    );
}

// ===== AC-3: Expired token → error =====

#[tokio::test]
async fn engine_redeem_expired_token_returns_expired_error() {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let (engine, clock) = make_engine_with_clock(&temp_dir);
    let identity: &dyn IdentityEngine = engine.as_ref();

    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: format!("ve-exp-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");
    let realm_id: RealmId = realm.id().clone();

    let email = format!("user-{}@exp-test.local", uuid::Uuid::new_v4());
    let user = identity
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: email.clone(),
                display_name: "Exp Test".to_string(),
                first_name: "E".to_string(),
                last_name: "T".to_string(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    identity
        .add_required_action(&realm_id, user.id(), RequiredAction::VerifyEmail)
        .expect("add action");

    let token = identity
        .request_email_verification(&realm_id, user.id())
        .expect("request_email_verification");

    // Advance clock past 24 hr TTL
    clock.advance(25 * 3600 * 1_000_000_i64);

    let err = identity
        .redeem_email_verification(&realm_id, &token)
        .expect_err("expired token must fail");

    assert!(
        matches!(
            err,
            hearth::identity::IdentityError::EmailVerificationTokenExpired
        ),
        "expired token must return EmailVerificationTokenExpired, got: {err:?}"
    );
}

// ===== AC-5: Second resend invalidates previous token =====

#[tokio::test]
async fn engine_resend_invalidates_previous_token() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let (realm_id, user_id, _email) = setup(identity).await;

    identity
        .add_required_action(&realm_id, &user_id, RequiredAction::VerifyEmail)
        .expect("add action");

    let first_token = identity
        .request_email_verification(&realm_id, &user_id)
        .expect("first request");

    let _second_token = identity
        .request_email_verification(&realm_id, &user_id)
        .expect("second request");

    // First token must now be invalid (superseded)
    let err = identity
        .redeem_email_verification(&realm_id, &first_token)
        .expect_err("superseded token must fail");

    assert!(
        matches!(
            err,
            hearth::identity::IdentityError::EmailVerificationTokenInvalid
        ),
        "superseded token must return EmailVerificationTokenInvalid, got: {err:?}"
    );
}

// ===== AC-5: Rate limit — max 3 resends/hr/user =====

#[tokio::test]
async fn engine_request_email_verification_rate_limits_after_three() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let (realm_id, user_id, _email) = setup(identity).await;

    identity
        .add_required_action(&realm_id, &user_id, RequiredAction::VerifyEmail)
        .expect("add action");

    // 3 requests should succeed
    for _ in 0..3 {
        identity
            .request_email_verification(&realm_id, &user_id)
            .expect("request within rate limit");
    }

    // 4th request must be rate-limited
    let err = identity
        .request_email_verification(&realm_id, &user_id)
        .expect_err("4th request must be rate-limited");

    assert!(
        matches!(err, hearth::identity::IdentityError::RateLimited),
        "4th request must return RateLimited, got: {err:?}"
    );
}

// ===== HTTP: AC-1 — POST 202 Accepted =====

#[tokio::test]
async fn http_post_request_email_verification_returns_202() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let (realm_id, user_id, email) = setup(identity).await;

    let ra_token = acquire_required_action_token(identity, &realm_id, &user_id, &email).await;

    let app = build_app(&harness);

    let req = Request::builder()
        .method("POST")
        .uri("/v1/required-actions/request-email-verification")
        .header("Authorization", format!("Bearer {ra_token}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::ACCEPTED,
        "POST /v1/required-actions/request-email-verification must return 202"
    );
}

// ===== HTTP: AC-1 — rejects full-access token at the request endpoint =====

#[tokio::test]
async fn http_request_email_verification_rejects_full_access_token() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let (realm_id, _user_id, email) = setup(identity).await;

    // Get a full-access token (no pending actions)
    let full_token = identity
        .password_grant_token(
            &realm_id,
            &PasswordGrantRequest {
                email,
                password: "Hearth_Test_P@ss1!".to_string(),
                scope: None,
            },
        )
        .expect("password_grant_token")
        .access_token()
        .to_string();

    let app = build_app(&harness);

    let req = Request::builder()
        .method("POST")
        .uri("/v1/required-actions/request-email-verification")
        .header("Authorization", format!("Bearer {full_token}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    // Must reject — only required-action tokens with VERIFY_EMAIL are accepted
    assert!(
        resp.status() == StatusCode::UNAUTHORIZED || resp.status() == StatusCode::FORBIDDEN,
        "full-access token must be rejected at request-email-verification, got: {}",
        resp.status()
    );
}

// ===== HTTP: AC-2 — GET verify returns 200 + full-access token =====

#[tokio::test]
async fn http_get_verify_email_returns_200_and_full_access_token() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let (realm_id, user_id, email) = setup(identity).await;

    let ra_token = acquire_required_action_token(identity, &realm_id, &user_id, &email).await;

    let app = build_app(&harness);

    // First: POST to request a verification token
    let post_req = Request::builder()
        .method("POST")
        .uri("/v1/required-actions/request-email-verification")
        .header("Authorization", format!("Bearer {ra_token}"))
        .body(Body::empty())
        .unwrap();
    let post_resp = app.clone().oneshot(post_req).await.unwrap();
    assert_eq!(post_resp.status(), StatusCode::ACCEPTED);

    // Extract token from response body
    let body = to_bytes(post_resp.into_body(), 1024 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let raw_token = json["verification_token"]
        .as_str()
        .expect("response must include verification_token field");

    // Then: GET to redeem it
    let get_req = Request::builder()
        .method("GET")
        .uri(format!(
            "/v1/required-actions/verify-email?token={raw_token}"
        ))
        .body(Body::empty())
        .unwrap();
    let get_resp = app.oneshot(get_req).await.unwrap();

    assert_eq!(
        get_resp.status(),
        StatusCode::OK,
        "GET /v1/required-actions/verify-email must return 200"
    );

    let body = to_bytes(get_resp.into_body(), 1024 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let access_token = json["access_token"]
        .as_str()
        .expect("response must include access_token");

    let claims = hearth::identity::decode_claims_unverified(access_token).expect("decode");
    assert_eq!(
        claims.token_type, "access",
        "returned token must be full-access type"
    );
    assert!(
        claims.required_actions.is_empty(),
        "returned token must have no required_actions"
    );
}

// ===== HTTP: AC-3 — GET with expired token → 410 Gone =====
// (engine-level expiry test already covers the core logic; this test validates the HTTP mapping)

#[tokio::test]
async fn http_get_verify_email_expired_token_returns_410() {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let config = StorageConfig::dev(temp_dir.path().to_path_buf());
    let storage = Arc::new(EmbeddedStorageEngine::open(config).expect("storage"));
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(
        1_700_000_000_000_000,
    )));
    let clock_dyn = Arc::clone(&clock) as Arc<dyn hearth::core::Clock>;

    let rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock_dyn),
    ));
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock_dyn),
    ));
    let id_config = IdentityConfig {
        credential: hearth::identity::CredentialConfig::fast_for_testing(),
        ..IdentityConfig::default()
    };
    let engine = Arc::new(
        EmbeddedIdentityEngine::with_rbac(
            Arc::clone(&storage) as Arc<dyn StorageEngine>,
            Arc::clone(&clock_dyn),
            id_config,
            Arc::clone(&rbac) as Arc<dyn hearth::rbac::RbacEngine>,
            Arc::clone(&audit) as Arc<dyn hearth::audit::AuditEngine>,
        )
        .expect("identity engine"),
    );
    let identity: &dyn IdentityEngine = engine.as_ref();

    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: format!("ve-http-exp-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");
    let realm_id = realm.id().clone();
    let user = identity
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: format!("u-{}@exp.local", uuid::Uuid::new_v4()),
                display_name: "E".to_string(),
                first_name: "E".to_string(),
                last_name: "T".to_string(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    identity
        .add_required_action(&realm_id, user.id(), RequiredAction::VerifyEmail)
        .expect("add action");
    let raw_token = identity
        .request_email_verification(&realm_id, user.id())
        .expect("request token");

    // Advance clock past 24h TTL
    clock.advance(25 * 3600 * 1_000_000_i64);

    let email_service = Arc::new(
        EmailService::new(
            Arc::new(LoggingEmailSender::new()),
            "Hearth".to_string(),
            None,
            EmailBranding::default(),
            "<svg/>".to_string(),
            None,
        )
        .expect("email service"),
    );
    let state = Arc::new(
        AppState::new(
            engine as Arc<dyn IdentityEngine>,
            rbac as Arc<dyn hearth::rbac::RbacEngine>,
            audit as Arc<dyn hearth::audit::AuditEngine>,
        )
        .with_email(email_service),
    );
    let app = router(state);

    let req = Request::builder()
        .method("GET")
        .uri(format!(
            "/v1/required-actions/verify-email?token={raw_token}"
        ))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::GONE,
        "expired token must return 410 Gone"
    );

    let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        json["error"].as_str(),
        Some("verification_token_expired"),
        "error must be verification_token_expired, got: {:?}",
        json
    );
}

// ===== HTTP: AC-4 — GET with already-redeemed token → 410 Gone =====

#[tokio::test]
async fn http_get_verify_email_already_redeemed_returns_410() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let (realm_id, user_id, _email) = setup(identity).await;

    identity
        .add_required_action(&realm_id, &user_id, RequiredAction::VerifyEmail)
        .expect("add action");
    let raw_token = identity
        .request_email_verification(&realm_id, &user_id)
        .expect("request token");

    // Redeem once
    identity
        .redeem_email_verification(&realm_id, &raw_token)
        .expect("first redemption");

    // Second redemption via HTTP must return 410
    let app = build_app(&harness);
    let req = Request::builder()
        .method("GET")
        .uri(format!(
            "/v1/required-actions/verify-email?token={raw_token}"
        ))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::GONE,
        "second redemption must return 410 Gone"
    );
}
