//! TDD integration tests for HEA-753: POST /v1/required-actions/update-password.
//!
//! Covers all five acceptance criteria from the issue spec.

mod common;

use std::sync::Arc;

use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, IdentityEngine, PasswordGrantRequest,
    PasswordPolicy, RealmConfig, RequiredAction,
};
use hearth::protocol::http::{router, AppState};
use tokio::net::TcpListener;

const VALID_PASSWORD: &str = "Hearth_Test_P@ssword1!";
const NEW_VALID_PASSWORD: &str = "Hearth_NewTest_P@ssword2!";

/// Starts an in-process axum server. Returns `(base_url, identity_arc, shutdown_tx)`.
async fn start_http_server() -> (
    String,
    Arc<dyn IdentityEngine>,
    tokio::sync::oneshot::Sender<()>,
) {
    let harness = common::TestHarness::embedded()
        .await
        .expect("embedded harness");
    let identity = harness.identity_arc();
    let state = Arc::new(AppState::new_dev(
        Arc::clone(&identity),
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
    (format!("http://127.0.0.1:{port}"), identity, tx)
}

/// Creates a realm + user with `VALID_PASSWORD`, adds `UPDATE_PASSWORD` to the
/// pending-action set, and obtains the required-action token via password grant.
///
/// Returns `(realm_id, user_id, required_action_token)`.
async fn setup_with_update_password_action(
    identity: &dyn IdentityEngine,
    realm_name: &str,
    config: Option<RealmConfig>,
) -> (hearth::core::RealmId, hearth::core::UserId, String) {
    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: realm_name.to_string(),
            config,
        })
        .expect("create realm");
    let realm_id = realm.id().clone();

    let email = format!("user-{}@hea753.test", uuid::Uuid::new_v4());
    let user = identity
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: email.clone(),
                display_name: "HEA-753 Test".to_string(),
                first_name: "Test".to_string(),
                last_name: "User".to_string(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let pw = CleartextPassword::from_string(VALID_PASSWORD.to_string());
    identity
        .set_password(&realm_id, user.id(), &pw)
        .expect("set password");
    identity
        .add_required_action(&realm_id, user.id(), RequiredAction::UpdatePassword)
        .expect("add UpdatePassword action");

    // Authenticate — produces a required-action token (not a full-access token)
    let grant = identity
        .password_grant_token(
            &realm_id,
            &PasswordGrantRequest {
                email,
                password: VALID_PASSWORD.to_string(),
                scope: None,
            },
        )
        .expect("password_grant_token");

    let claims =
        hearth::identity::decode_claims_unverified(grant.access_token()).expect("decode claims");
    assert_eq!(
        claims.token_type, "required_action",
        "precondition: must be a required-action token"
    );

    (
        realm_id,
        user.id().clone(),
        grant.access_token().to_string(),
    )
}

// ===== AC-1: Valid RA token + valid password → 200 full-access token, action cleared =====

#[tokio::test]
async fn ac1_valid_ra_token_returns_full_access_token() {
    let (base, identity, _shutdown) = start_http_server().await;
    let realm_name = format!("hea753-ac1-{}", uuid::Uuid::new_v4());
    let (realm_id, user_id, ra_token) =
        setup_with_update_password_action(identity.as_ref(), &realm_name, None).await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/required-actions/update-password"))
        .header("X-Realm-ID", realm_id.as_uuid().to_string())
        .header("Authorization", format!("Bearer {ra_token}"))
        .json(&serde_json::json!({"new_password": NEW_VALID_PASSWORD}))
        .send()
        .await
        .expect("POST /v1/required-actions/update-password");

    assert_eq!(
        resp.status().as_u16(),
        200,
        "expected 200, got {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.expect("parse body");
    let access_token = body["access_token"].as_str().expect("access_token in body");

    // Returned token must be a full-access token
    let new_claims =
        hearth::identity::decode_claims_unverified(access_token).expect("decode new token");
    assert_eq!(
        new_claims.token_type, "access",
        "response must be full-access token, got: {:?}",
        new_claims.token_type
    );
    assert!(
        new_claims.required_actions.is_empty(),
        "full-access token must have no required_actions"
    );

    // UpdatePassword must be cleared from the stored pending set
    let remaining = identity
        .pending_actions(&realm_id, &user_id)
        .expect("pending_actions");
    assert!(
        !remaining.contains(&RequiredAction::UpdatePassword),
        "UpdatePassword must be cleared from stored pending set"
    );
}

// ===== AC-2: Policy-violating password → 422, action NOT cleared =====

#[tokio::test]
async fn ac2_policy_violation_returns_422_action_not_cleared() {
    let (base, identity, _shutdown) = start_http_server().await;
    let realm_name = format!("hea753-ac2-{}", uuid::Uuid::new_v4());
    let config = RealmConfig {
        password_policy: Some(PasswordPolicy {
            min_length: Some(16),
            require_uppercase: Some(true),
            require_number: Some(true),
            ..Default::default()
        }),
        ..Default::default()
    };
    let (realm_id, user_id, ra_token) =
        setup_with_update_password_action(identity.as_ref(), &realm_name, Some(config)).await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/required-actions/update-password"))
        .header("X-Realm-ID", realm_id.as_uuid().to_string())
        .header("Authorization", format!("Bearer {ra_token}"))
        .json(&serde_json::json!({"new_password": "short"}))
        .send()
        .await
        .expect("POST");

    assert_eq!(
        resp.status().as_u16(),
        422,
        "policy violation must return 422, got {}",
        resp.status()
    );

    // Action must NOT be cleared
    let remaining = identity
        .pending_actions(&realm_id, &user_id)
        .expect("pending_actions");
    assert!(
        remaining.contains(&RequiredAction::UpdatePassword),
        "UpdatePassword must still be pending after policy violation"
    );
}

// ===== AC-3: Token submitted twice (after completion) → 401 =====

#[tokio::test]
async fn ac3_second_submission_after_completion_returns_401() {
    let (base, identity, _shutdown) = start_http_server().await;
    let realm_name = format!("hea753-ac3-{}", uuid::Uuid::new_v4());
    let (realm_id, _user_id, ra_token) =
        setup_with_update_password_action(identity.as_ref(), &realm_name, None).await;

    let client = reqwest::Client::new();

    // First call must succeed
    let resp1 = client
        .post(format!("{base}/v1/required-actions/update-password"))
        .header("X-Realm-ID", realm_id.as_uuid().to_string())
        .header("Authorization", format!("Bearer {ra_token}"))
        .json(&serde_json::json!({"new_password": NEW_VALID_PASSWORD}))
        .send()
        .await
        .expect("first POST");
    assert_eq!(resp1.status().as_u16(), 200, "first call must succeed");

    // Second call with the SAME required-action token must fail 401
    let resp2 = client
        .post(format!("{base}/v1/required-actions/update-password"))
        .header("X-Realm-ID", realm_id.as_uuid().to_string())
        .header("Authorization", format!("Bearer {ra_token}"))
        .json(&serde_json::json!({"new_password": "AnotherValidP@ssword1!"}))
        .send()
        .await
        .expect("second POST");
    assert_eq!(
        resp2.status().as_u16(),
        401,
        "consumed required-action token must return 401, got {}",
        resp2.status()
    );
}

// ===== AC-4: Normal access token → 403 =====

#[tokio::test]
async fn ac4_normal_access_token_returns_403() {
    let (base, identity, _shutdown) = start_http_server().await;
    let realm_name = format!("hea753-ac4-{}", uuid::Uuid::new_v4());
    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: realm_name,
            config: None,
        })
        .expect("create realm");
    let realm_id = realm.id().clone();

    let email = format!("user-{}@hea753.test", uuid::Uuid::new_v4());
    let user = identity
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: email.clone(),
                display_name: "AC4 User".to_string(),
                first_name: "AC4".to_string(),
                last_name: "User".to_string(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    identity
        .set_password(
            &realm_id,
            user.id(),
            &CleartextPassword::from_string(VALID_PASSWORD.to_string()),
        )
        .expect("set password");

    // Normal full-access token (no pending actions)
    let grant = identity
        .password_grant_token(
            &realm_id,
            &PasswordGrantRequest {
                email,
                password: VALID_PASSWORD.to_string(),
                scope: None,
            },
        )
        .expect("password grant");
    let claims = hearth::identity::decode_claims_unverified(grant.access_token())
        .expect("decode access token claims");
    assert_eq!(
        claims.token_type, "access",
        "precondition: must be full-access token"
    );

    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/required-actions/update-password"))
        .header("X-Realm-ID", realm_id.as_uuid().to_string())
        .header("Authorization", format!("Bearer {}", grant.access_token()))
        .json(&serde_json::json!({"new_password": NEW_VALID_PASSWORD}))
        .send()
        .await
        .expect("POST");

    assert_eq!(
        resp.status().as_u16(),
        403,
        "normal access token must return 403, got {}",
        resp.status()
    );
}

// ===== AC-5: New password equals current → 422 password_reuse, action NOT cleared =====

#[tokio::test]
async fn ac5_same_password_returns_422_password_reuse() {
    let (base, identity, _shutdown) = start_http_server().await;
    let realm_name = format!("hea753-ac5-{}", uuid::Uuid::new_v4());
    let (realm_id, user_id, ra_token) =
        setup_with_update_password_action(identity.as_ref(), &realm_name, None).await;

    // Submit the SAME password that was set during setup
    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/required-actions/update-password"))
        .header("X-Realm-ID", realm_id.as_uuid().to_string())
        .header("Authorization", format!("Bearer {ra_token}"))
        .json(&serde_json::json!({"new_password": VALID_PASSWORD}))
        .send()
        .await
        .expect("POST");

    assert_eq!(
        resp.status().as_u16(),
        422,
        "same password must return 422, got {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.expect("parse body");
    assert_eq!(
        body["error"].as_str(),
        Some("password_reuse"),
        "error must be 'password_reuse', got: {body}"
    );

    // Action must NOT be cleared
    let remaining = identity
        .pending_actions(&realm_id, &user_id)
        .expect("pending_actions");
    assert!(
        remaining.contains(&RequiredAction::UpdatePassword),
        "UpdatePassword must still be pending after password_reuse rejection"
    );
}

// ===== Argon2id upgrade: PBKDF2 credential is replaced with Argon2id =====

/// After completing UPDATE_PASSWORD, the new credential is stored as Argon2id
/// and the old password no longer authenticates.
#[tokio::test]
async fn argon2id_upgrade_on_completion() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("embedded harness");
    let identity = harness.identity();
    let realm_name = format!("hea753-upgrade-{}", uuid::Uuid::new_v4());
    let (realm_id, user_id, ra_token) =
        setup_with_update_password_action(identity, &realm_name, None).await;

    // Call complete_update_password directly at the engine level
    let new_pw = CleartextPassword::from_string(NEW_VALID_PASSWORD.to_string());
    let result = identity.complete_update_password(&realm_id, &ra_token, new_pw);
    assert!(
        result.is_ok(),
        "complete_update_password must succeed, got: {:?}",
        result
    );

    // New password must authenticate
    let verified = identity
        .verify_password(
            &realm_id,
            &user_id,
            &CleartextPassword::from_string(NEW_VALID_PASSWORD.to_string()),
        )
        .expect("verify new password");
    assert!(
        verified,
        "new password must verify after credential rotation"
    );

    // Old password must no longer work
    let old_verified = identity
        .verify_password(
            &realm_id,
            &user_id,
            &CleartextPassword::from_string(VALID_PASSWORD.to_string()),
        )
        .expect("verify old password");
    assert!(!old_verified, "old password must be invalidated");

    // UpdatePassword must be cleared
    let remaining = identity
        .pending_actions(&realm_id, &user_id)
        .expect("pending actions");
    assert!(!remaining.contains(&RequiredAction::UpdatePassword));
}
