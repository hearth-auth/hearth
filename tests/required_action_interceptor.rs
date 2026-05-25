//! TDD integration tests for HEA-752: Login-flow interceptor — required-action JWT gating.
//!
//! Covers all acceptance criteria from the issue:
//! - AC-1: Pending action → required-action JWT (not full access token)
//! - AC-2: No pending actions → normal full-access token (no regression)
//! - AC-3: Multiple pending actions → all listed in token
//! - AC-4: Required-action token at protected endpoint → 403 RequiredActionsPending
//! - AC-5: Expiry — token has ≤ 15 min TTL; structure ensures TokenExpired (401) on expiry

mod common;

use std::collections::BTreeSet;
use std::sync::Arc;

use hearth::identity::{
    AuthorizationRequest, CleartextPassword, CodeChallengeMethod, CreateRealmRequest,
    CreateUserRequest, IdentityEngine, PasswordGrantRequest, RegisterClientRequest, RequiredAction,
    TokenExchangeRequest, TokenIntrospectionRequest,
};
use hearth::protocol::http::{router, AppState};
use tokio::net::TcpListener;

const TEST_PKCE_VERIFIER: &str = "S4gKJfVNgWiFl2PQ8RxXS7E6Mhr9BqyTvUIe3WoA5Zc";

fn pkce_challenge(verifier: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes()).as_ref())
}

/// Helper: creates a realm and a user with password, returning `(realm_id, user_id, email, password)`.
async fn setup_realm_user_password(
    identity: &dyn IdentityEngine,
) -> (
    hearth::core::RealmId,
    hearth::core::UserId,
    String, // email
    String, // password
) {
    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: format!("ra-test-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");
    let realm_id = realm.id().clone();

    let email = format!("user-{}@ra-test.local", uuid::Uuid::new_v4());
    let password = "Hearth_RA_Test_P@ssword1!".to_string();

    let user = identity
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: email.clone(),
                display_name: "RA Test User".to_string(),
                first_name: "RA".to_string(),
                last_name: "Test".to_string(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let pw = CleartextPassword::from_string(password.clone());
    identity
        .set_password(&realm_id, user.id(), &pw)
        .expect("set password");

    (realm_id, user.id().clone(), email, password)
}

// ===== AC-1: User with UPDATE_PASSWORD pending → required-action token =====

#[tokio::test]
async fn password_grant_with_pending_action_returns_required_action_token() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let (realm_id, user_id, email, password) = setup_realm_user_password(identity).await;

    // Add a pending action
    identity
        .add_required_action(&realm_id, &user_id, RequiredAction::UpdatePassword)
        .expect("add action");

    // Authenticate via ROPC password grant
    let response = identity
        .password_grant_token(
            &realm_id,
            &PasswordGrantRequest {
                email,
                password,
                scope: None,
            },
        )
        .expect("password_grant_token should succeed (credentials are valid)");

    // Decode the access token — must be a required-action token
    let claims = hearth::identity::decode_claims_unverified(response.access_token())
        .expect("decode access token");

    assert_eq!(
        claims.token_type, "required_action",
        "token_type must be 'required_action' when actions are pending, got: {:?}",
        claims.token_type
    );
    assert!(
        claims
            .required_actions
            .contains(&RequiredAction::UpdatePassword),
        "required_actions must contain UpdatePassword, got: {:?}",
        claims.required_actions
    );
    // Empty scopes/roles/permissions
    assert!(
        claims.scope.is_none() || claims.scope.as_deref() == Some(""),
        "required-action token must have no scope, got: {:?}",
        claims.scope
    );
    assert!(
        claims.permissions.is_empty(),
        "required-action token must have no permissions, got: {:?}",
        claims.permissions
    );
    // TTL ≤ 15 min (900 seconds)
    assert!(
        claims.exp - claims.iat <= 900,
        "required-action token TTL must be ≤ 900 s, got: {}",
        claims.exp - claims.iat
    );
}

// ===== AC-2: No pending actions → normal full-access token (regression guard) =====

#[tokio::test]
async fn password_grant_without_pending_actions_returns_normal_token() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let (realm_id, _user_id, email, password) = setup_realm_user_password(identity).await;

    let response = identity
        .password_grant_token(
            &realm_id,
            &PasswordGrantRequest {
                email,
                password,
                scope: None,
            },
        )
        .expect("password_grant_token");

    let claims = hearth::identity::decode_claims_unverified(response.access_token())
        .expect("decode access token");

    assert_eq!(
        claims.token_type, "access",
        "token_type must be 'access' when no actions are pending, got: {:?}",
        claims.token_type
    );
    assert!(
        claims.required_actions.is_empty(),
        "required_actions must be empty for a normal token, got: {:?}",
        claims.required_actions
    );
    // Normal token must have a refresh token
    assert!(
        !response.refresh_token().is_empty(),
        "normal token response must include a refresh token"
    );
}

// ===== AC-3: Multiple pending actions → all listed =====

#[tokio::test]
async fn multiple_pending_actions_all_listed_in_token() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let (realm_id, user_id, email, password) = setup_realm_user_password(identity).await;

    identity
        .add_required_action(&realm_id, &user_id, RequiredAction::UpdatePassword)
        .expect("add UpdatePassword");
    identity
        .add_required_action(&realm_id, &user_id, RequiredAction::VerifyEmail)
        .expect("add VerifyEmail");

    let response = identity
        .password_grant_token(
            &realm_id,
            &PasswordGrantRequest {
                email,
                password,
                scope: None,
            },
        )
        .expect("password_grant_token");

    let claims = hearth::identity::decode_claims_unverified(response.access_token())
        .expect("decode access token");

    assert_eq!(claims.token_type, "required_action");
    let pending: BTreeSet<RequiredAction> = claims.required_actions.iter().cloned().collect();
    assert!(
        pending.contains(&RequiredAction::UpdatePassword),
        "must list UpdatePassword"
    );
    assert!(
        pending.contains(&RequiredAction::VerifyEmail),
        "must list VerifyEmail"
    );
    assert_eq!(pending.len(), 2, "must list exactly 2 actions");
}

// ===== AC-4: Required-action token at protected endpoint → RequiredActionsPending =====

#[tokio::test]
async fn required_action_token_rejected_at_validate_token() {
    use hearth::identity::IdentityError;

    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let (realm_id, user_id, email, password) = setup_realm_user_password(identity).await;

    identity
        .add_required_action(&realm_id, &user_id, RequiredAction::UpdatePassword)
        .expect("add action");

    let response = identity
        .password_grant_token(
            &realm_id,
            &PasswordGrantRequest {
                email,
                password,
                scope: None,
            },
        )
        .expect("password_grant_token");

    // validate_token must reject required-action tokens with RequiredActionsPending
    let result = identity.validate_token(&realm_id, response.access_token());
    assert!(
        matches!(result, Err(IdentityError::RequiredActionsPending)),
        "validate_token must return RequiredActionsPending for required-action token, got: {result:?}"
    );
}

// ===== AC-5: Required-action token TTL ≤ 900 s; expiry before type gate → 401 =====

#[tokio::test]
async fn required_action_token_has_short_ttl() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let (realm_id, user_id, email, password) = setup_realm_user_password(identity).await;

    identity
        .add_required_action(&realm_id, &user_id, RequiredAction::UpdatePassword)
        .expect("add action");

    let response = identity
        .password_grant_token(
            &realm_id,
            &PasswordGrantRequest {
                email,
                password,
                scope: None,
            },
        )
        .expect("password_grant_token");

    let claims =
        hearth::identity::decode_claims_unverified(response.access_token()).expect("decode");
    assert!(
        claims.exp - claims.iat <= 900,
        "required-action token TTL must be ≤ 15 min (900 s), actual: {}",
        claims.exp - claims.iat
    );
    // The expires_in field in the response must also reflect the short TTL
    assert!(
        response.expires_in() <= 900,
        "PasswordGrantResponse.expires_in must be ≤ 900 for required-action path, got: {}",
        response.expires_in()
    );
}

// ===== Cleanup path: removing action restores normal token =====

#[tokio::test]
async fn removing_pending_action_restores_normal_token() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let (realm_id, user_id, email, password) = setup_realm_user_password(identity).await;

    identity
        .add_required_action(&realm_id, &user_id, RequiredAction::UpdatePassword)
        .expect("add");
    identity
        .remove_required_action(&realm_id, &user_id, RequiredAction::UpdatePassword)
        .expect("remove");

    let response = identity
        .password_grant_token(
            &realm_id,
            &PasswordGrantRequest {
                email,
                password,
                scope: None,
            },
        )
        .expect("password_grant_token");

    let claims =
        hearth::identity::decode_claims_unverified(response.access_token()).expect("decode");
    assert_eq!(
        claims.token_type, "access",
        "after removing action, must get normal access token"
    );
    assert!(claims.required_actions.is_empty());

    // And validate_token must accept it
    identity
        .validate_token(&realm_id, response.access_token())
        .expect("normal token must pass validate_token");
}

// ===== Auth-code exchange: pending actions gate applies to PKCE flow too =====

#[tokio::test]
async fn auth_code_exchange_with_pending_action_returns_required_action_token() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();

    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: format!("ra-oidc-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("realm");
    let realm_id = realm.id().clone();

    let user = identity
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: format!("user-{}@ra-oidc.test", uuid::Uuid::new_v4()),
                display_name: "OIDC RA User".to_string(),
                first_name: "OIDC".to_string(),
                last_name: "RA".to_string(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    // Register a first-party OAuth client (no consent required)
    let client = identity
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "ra-test-client".to_string(),
                redirect_uris: vec!["https://app.test/callback".to_string()],
                client_secret: None,
                grant_types: vec![
                    "authorization_code".to_string(),
                    "refresh_token".to_string(),
                ],
                require_consent: false,
                ..Default::default()
            },
        )
        .expect("register client");

    // Authorize (creates a stored auth code bound to this user)
    let auth_response = identity
        .authorize(
            &realm_id,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.test/callback".to_string(),
                scope: "openid".to_string(),
                state: "test-state".to_string(),
                response_type: "code".to_string(),
                code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: None,
                user_id: user.id().clone(),
                resource: None,
            },
        )
        .expect("authorize");

    // Add pending action BEFORE code exchange
    identity
        .add_required_action(&realm_id, user.id(), RequiredAction::UpdatePassword)
        .expect("add action");

    // Exchange auth code — must return required-action token
    let token_response = identity
        .exchange_authorization_code(
            &realm_id,
            &TokenExchangeRequest {
                client_id: client.client_id().clone(),
                code: auth_response.code().to_string(),
                redirect_uri: "https://app.test/callback".to_string(),
                code_verifier: Some(TEST_PKCE_VERIFIER.to_string()),
            },
        )
        .expect("exchange_authorization_code");

    let claims = hearth::identity::decode_claims_unverified(token_response.access_token())
        .expect("decode access token");

    assert_eq!(
        claims.token_type, "required_action",
        "auth code exchange with pending action must return required-action token"
    );
    assert!(
        claims
            .required_actions
            .contains(&RequiredAction::UpdatePassword),
        "required_actions must list UpdatePassword"
    );
    assert!(claims.permissions.is_empty());
    assert!(claims.exp - claims.iat <= 900);
}

// ===== HEA-759: introspect_token must return active:false for required-action tokens =====

#[tokio::test]
async fn introspect_required_action_token_is_inactive() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let (realm_id, user_id, email, password) = setup_realm_user_password(identity).await;

    identity
        .add_required_action(&realm_id, &user_id, RequiredAction::UpdatePassword)
        .expect("add action");

    let response = identity
        .password_grant_token(
            &realm_id,
            &PasswordGrantRequest {
                email,
                password,
                scope: None,
            },
        )
        .expect("password_grant_token");

    // Confirm the token is actually a required-action token before introspecting
    let claims =
        hearth::identity::decode_claims_unverified(response.access_token()).expect("decode");
    assert_eq!(claims.token_type, "required_action");

    // RFC 7662 §2.2: introspection must return active:false — required-action tokens
    // are not authorized for resource access and must not be treated as bearer credentials.
    let introspect = identity
        .introspect_token(
            &realm_id,
            &TokenIntrospectionRequest {
                token: response.access_token().to_string(),
                token_type_hint: None,
            },
        )
        .expect("introspect_token should not error");

    assert!(
        !introspect.active,
        "introspect_token must return active:false for a required-action token (HEA-759)"
    );
}

// ===== HEA-760: HTTP auth helpers return 403 (not 401) for required-action tokens =====

/// Starts an in-process axum server, returns `(base_url, identity_arc, shutdown_tx)`.
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

/// `GET /v1/me/permissions` with a required-action token must return 403
/// with `error_code: HEARTH_REQUIRED_ACTIONS_PENDING` (not 401 invalid_token).
///
/// Covers the `me_permissions` handler path in `extract_user_auth` (HEA-760).
#[tokio::test]
async fn required_action_token_at_me_permissions_returns_403() {
    let (base, identity, _shutdown) = start_http_server().await;

    // Bootstrap: create realm + user with password via the identity engine directly.
    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: format!("hea760-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");
    let realm_id = realm.id().clone();

    let email = format!("user-{}@hea760.test", uuid::Uuid::new_v4());
    let user = identity
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: email.clone(),
                display_name: "HEA-760 Test".to_string(),
                first_name: "Test".to_string(),
                last_name: "User".to_string(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let pw = CleartextPassword::from_string("Hearth_760_P@ssword!".to_string());
    identity
        .set_password(&realm_id, user.id(), &pw)
        .expect("set password");

    identity
        .add_required_action(&realm_id, user.id(), RequiredAction::UpdatePassword)
        .expect("add required action");

    // Obtain a required-action token via the password grant.
    let grant_resp = identity
        .password_grant_token(
            &realm_id,
            &PasswordGrantRequest {
                email,
                password: "Hearth_760_P@ssword!".to_string(),
                scope: None,
            },
        )
        .expect("password_grant_token");

    let claims =
        hearth::identity::decode_claims_unverified(grant_resp.access_token()).expect("decode");
    assert_eq!(
        claims.token_type, "required_action",
        "precondition: must be a required-action token"
    );

    // Hit a helper-protected endpoint with the required-action token.
    let resp = reqwest::Client::new()
        .get(format!("{base}/v1/me/permissions"))
        .header("X-Realm-ID", realm_id.as_uuid().to_string())
        .header(
            "Authorization",
            format!("Bearer {}", grant_resp.access_token()),
        )
        .send()
        .await
        .expect("GET /v1/me/permissions");

    assert_eq!(
        resp.status().as_u16(),
        403,
        "required-action token must yield 403 Forbidden, not {}",
        resp.status()
    );

    let body: serde_json::Value = resp.json().await.expect("parse response body");
    assert_eq!(
        body["error_code"].as_str(),
        Some("HEARTH_REQUIRED_ACTIONS_PENDING"),
        "error_code must be HEARTH_REQUIRED_ACTIONS_PENDING, got: {body}"
    );
    assert_eq!(
        body["error"].as_str(),
        Some("required_actions_pending"),
        "error field must be required_actions_pending, got: {body}"
    );
}
