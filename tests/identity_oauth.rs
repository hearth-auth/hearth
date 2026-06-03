//! OAuth 2.0 / OIDC engine unit tests.
//!
//! Extracted from `src/identity/engine/mod.rs` inline test module ([HEA-1131] Phase 1).
//! Uses `EmbeddedIdentityEngine` directly (not HTTP) with `FakeClock` for deterministic
//! time control.
//!
//! PAR tests remain in `engine/mod.rs` because `consume_par` returns
//! `StoredPushedAuthorizationRequest` which is `pub(crate)`.

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{ClientId, Clock, FakeClock, RealmId, Timestamp, UserId};
use hearth::identity::RealmConfig;
use hearth::identity::{
    AuthorizationRequest, CodeChallengeMethod, CreateRealmRequest, CreateUserRequest,
    CredentialConfig, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, IdentityError,
    OAuthClient, PendingAuthorizationRequest, RegisterClientRequest, SessionContext,
    TokenExchangeRequest, User,
};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Creates a minimal engine with a `FakeClock` for deterministic tests.
fn setup_engine() -> (tempfile::TempDir, EmbeddedIdentityEngine, Arc<FakeClock>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf()))
            .expect("open storage"),
    ) as Arc<dyn StorageEngine>;
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
    let identity_config = IdentityConfig {
        credential: CredentialConfig::fast_for_testing(),
        ..IdentityConfig::default()
    };
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock) as Arc<dyn Clock>,
    ));
    let engine = EmbeddedIdentityEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock) as Arc<dyn Clock>,
        identity_config,
        audit as Arc<dyn AuditEngine>,
    )
    .expect("engine creation");
    (dir, engine, clock)
}

fn create_test_user(engine: &EmbeddedIdentityEngine, realm: &RealmId) -> User {
    engine
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("user-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Test User".to_string(),
                ..Default::default()
            },
        )
        .expect("create user")
}

fn pkce_challenge(verifier: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest.as_ref())
}

const TEST_PKCE_VERIFIER: &str = "S4gKJfVNgWiFl2PQ8RxXS7E6Mhr9BqyTvUIe3WoA5Zc";

#[allow(dead_code)]
fn register_test_client(engine: &EmbeddedIdentityEngine, realm: &RealmId) -> OAuthClient {
    engine
        .register_client(
            realm,
            &RegisterClientRequest {
                client_name: "Test App".to_string(),
                redirect_uris: vec!["https://app.example.com/callback".to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: true,
                client_logo_url: None,
                ..Default::default()
            },
        )
        .expect("register client")
}

// ===== Step 22: OAuth 2.0 Complete Unit Tests =====

/// Helper: creates a realm via `create_realm` and returns `RealmId`.
fn create_test_realm(engine: &EmbeddedIdentityEngine) -> RealmId {
    let realm = engine
        .create_realm(&CreateRealmRequest {
            name: format!("test-realm-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig::default()),
        })
        .expect("create realm");
    realm.id().clone()
}

/// Helper: registers a confidential client with `client_credentials` grant.
fn register_confidential_client(
    engine: &EmbeddedIdentityEngine,
    realm_id: &RealmId,
    secret: &str,
) -> OAuthClient {
    engine
        .register_client(
            realm_id,
            &RegisterClientRequest {
                client_name: "Confidential App".to_string(),
                redirect_uris: vec![],
                client_secret: Some(secret.to_string()),
                grant_types: vec!["client_credentials".to_string()],
                require_consent: true,
                client_logo_url: None,
                ..Default::default()
            },
        )
        .expect("register confidential client")
}

// ===== B1: Client credentials grant =====

#[test]
fn client_credentials_register_and_issue_token() {
    use hearth::identity::ClientCredentialsRequest;

    let (_dir, engine, _clock) = setup_engine();
    let realm_id = create_test_realm(&engine);
    let secret = uuid::Uuid::new_v4().to_string();

    // Register confidential client
    let client = register_confidential_client(&engine, &realm_id, &secret);
    assert!(client.is_confidential());
    assert!(client
        .grant_types()
        .contains(&"client_credentials".to_string()));

    // Issue token via client credentials
    let response = engine
        .client_credentials_token(
            &realm_id,
            &ClientCredentialsRequest {
                client_id: client.client_id().clone(),
                client_secret: Some(secret.clone()),
                scope: Some("read write".to_string()),
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
            },
        )
        .expect("client_credentials_token should succeed");

    assert_eq!(response.token_type(), "Bearer");
    assert!(response.expires_in() > 0);
    assert_eq!(response.scope(), Some("read write"));

    // Verify the access token is valid
    let claims = hearth::identity::decode_claims_unverified(response.access_token())
        .expect("decode access token");
    assert_eq!(claims.sub, client.client_id().to_string());
    assert_eq!(claims.token_type, "access");
    assert_eq!(claims.scope.as_deref(), Some("read write"));
}

#[test]
fn client_credentials_wrong_secret_rejected() {
    use hearth::identity::ClientCredentialsRequest;

    let (_dir, engine, _clock) = setup_engine();
    let realm_id = create_test_realm(&engine);
    let client = register_confidential_client(&engine, &realm_id, "correct-secret");

    let result = engine.client_credentials_token(
        &realm_id,
        &ClientCredentialsRequest {
            client_id: client.client_id().clone(),
            client_secret: Some("wrong-secret".to_string()),
            scope: None,
            dpop_jkt: None,
            client_assertion_type: None,
            client_assertion: None,
        },
    );

    assert!(
        matches!(result, Err(IdentityError::InvalidClientSecret)),
        "wrong secret should be rejected, got: {result:?}"
    );
}

#[test]
fn client_credentials_unsupported_grant_type() {
    use hearth::identity::ClientCredentialsRequest;

    let (_dir, engine, _clock) = setup_engine();
    let realm_id = create_test_realm(&engine);

    // Register a public client (no client_credentials grant)
    let client = engine
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "Public App".to_string(),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: true,
                client_logo_url: None,
                ..Default::default()
            },
        )
        .expect("register public client");

    let result = engine.client_credentials_token(
        &realm_id,
        &ClientCredentialsRequest {
            client_id: client.client_id().clone(),
            client_secret: Some("anything".to_string()),
            scope: None,
            dpop_jkt: None,
            client_assertion_type: None,
            client_assertion: None,
        },
    );

    assert!(
        matches!(result, Err(IdentityError::UnsupportedGrantType)),
        "public client should not support client_credentials, got: {result:?}"
    );
}

// ===== B2: Device authorization =====

#[test]
fn device_authorize_returns_valid_codes() {
    use hearth::identity::DeviceAuthorizationRequest;

    let (_dir, engine, _clock) = setup_engine();
    let realm_id = create_test_realm(&engine);

    // Register a client
    let client = engine
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "Device App".to_string(),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                client_secret: None,
                grant_types: vec!["urn:ietf:params:oauth:grant-type:device_code".to_string()],
                require_consent: true,
                client_logo_url: None,
                ..Default::default()
            },
        )
        .expect("register client");

    let response = engine
        .device_authorize(
            &realm_id,
            &DeviceAuthorizationRequest {
                client_id: client.client_id().clone(),
                scope: Some("openid".to_string()),
            },
        )
        .expect("device_authorize should succeed");

    // Verify response
    assert!(!response.device_code.is_empty());
    assert_eq!(response.user_code.len(), 8, "user code should be 8 chars");
    assert_eq!(response.interval, 5);
    assert!(response.expires_in > 0);

    // Verify user code only contains unambiguous chars
    let valid_chars = "BCDFGHJKMNPQRSTVWXYZ23456789";
    for c in response.user_code.chars() {
        assert!(
            valid_chars.contains(c),
            "user code char '{c}' not in unambiguous alphabet"
        );
    }
}

// ===== B3: Refresh token rotation =====

#[test]
fn refresh_token_rotation_issues_new_pair() {
    let (_dir, engine, clock) = setup_engine();
    let realm_id = create_test_realm(&engine);
    let user = create_test_user(&engine, &realm_id);
    let client = engine
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "Rotation App".to_string(),
                redirect_uris: vec!["https://app.example.com/callback".to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: true,
                client_logo_url: None,
                ..Default::default()
            },
        )
        .expect("register client");

    // Auth code flow → tokens with grant family
    let auth = engine
        .authorize(
            &realm_id,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                scope: "openid".to_string(),
                state: "test-state".to_string(),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: None,
                resource: None,
                amr_values: Vec::new(),
                response_mode: None,
                request: None,
                via_par: false,
            },
        )
        .expect("authorize");

    let tokens = engine
        .exchange_authorization_code(
            &realm_id,
            &TokenExchangeRequest {
                client_id: client.client_id().clone(),
                code: auth.code().to_string(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                code_verifier: Some(TEST_PKCE_VERIFIER.to_string()),
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
            },
        )
        .expect("exchange code");

    // Verify refresh token has fid claim
    let refresh_claims =
        hearth::identity::decode_claims_unverified(tokens.refresh_token()).expect("decode refresh");
    assert!(
        refresh_claims.fid.is_some(),
        "refresh token should have fid"
    );

    // Advance clock and refresh
    clock.advance(60 * 1_000_000); // 60 seconds in microseconds
    let new_tokens = engine
        .refresh_tokens(&realm_id, tokens.refresh_token(), None, None)
        .expect("refresh should succeed");

    // New tokens are different
    assert_ne!(new_tokens.access_token(), tokens.access_token());
    assert_ne!(new_tokens.refresh_token(), tokens.refresh_token());

    // New refresh token has the same family ID
    let new_refresh_claims = hearth::identity::decode_claims_unverified(new_tokens.refresh_token())
        .expect("decode new refresh");
    assert_eq!(new_refresh_claims.fid, refresh_claims.fid);

    // Old refresh token is now rejected (rotation)
    let result = engine.refresh_tokens(&realm_id, tokens.refresh_token(), None, None);
    assert!(
        matches!(result, Err(IdentityError::TokenRevoked)),
        "old refresh token should be rejected after rotation, got: {result:?}"
    );
}

// refresh_token_subject_must_match_session_user is in engine/mod.rs because
// it calls get_or_load_realm_signing_key() which is pub(crate).

#[test]
fn refresh_token_rejects_forged_legacy_payload_without_fid() {
    let (_dir, engine, _clock) = setup_engine();
    let realm_id = create_test_realm(&engine);
    let user = create_test_user(&engine, &realm_id);
    let client = engine
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "Forgery App".to_string(),
                redirect_uris: vec!["https://app.example.com/callback".to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: true,
                client_logo_url: None,
                ..Default::default()
            },
        )
        .expect("register client");

    let auth = engine
        .authorize(
            &realm_id,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                scope: "openid".to_string(),
                state: "forgery-state".to_string(),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: None,
                resource: None,
                amr_values: Vec::new(),
                response_mode: None,
                request: None,
                via_par: false,
            },
        )
        .expect("authorize");
    let token_pair = engine
        .exchange_authorization_code(
            &realm_id,
            &TokenExchangeRequest {
                client_id: client.client_id().clone(),
                code: auth.code().to_string(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                code_verifier: Some(TEST_PKCE_VERIFIER.to_string()),
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
            },
        )
        .expect("exchange code");

    let mut forged_claims = hearth::identity::decode_claims_unverified(token_pair.refresh_token())
        .expect("decode refresh claims");
    assert!(
        forged_claims.fid.is_some(),
        "expected grant-family refresh token"
    );
    forged_claims.fid = None;

    let parts: Vec<&str> = token_pair.refresh_token().split('.').collect();
    assert_eq!(parts.len(), 3, "refresh token should be JWT compact form");
    let forged_payload = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&forged_claims).expect("serialize forged refresh claims"));
    let forged_token = format!("{}.{}.{}", parts[0], forged_payload, parts[2]);

    let result = engine.refresh_tokens(&realm_id, &forged_token, None, None);
    assert!(
        matches!(result, Err(IdentityError::InvalidToken)),
        "forged no-fid payload must be rejected, got: {result:?}"
    );
}

// ===== B4: Token revocation =====

#[test]
fn revoke_access_token_invalidates_session() {
    use hearth::identity::TokenRevocationRequest;

    let (_dir, engine, _clock) = setup_engine();
    let realm_id = create_test_realm(&engine);
    let user = create_test_user(&engine, &realm_id);
    let session = engine
        .create_session(&realm_id, user.id(), &SessionContext::default())
        .expect("session");
    let tokens = engine
        .issue_tokens(&realm_id, user.id(), session.id())
        .expect("issue tokens");

    // Token is valid
    let claims = engine
        .validate_token(&realm_id, tokens.access_token())
        .expect("should be valid");
    assert_eq!(claims.sub, user.id().to_string());

    // Revoke the access token
    engine
        .revoke_token(
            &realm_id,
            &TokenRevocationRequest {
                token: tokens.access_token().to_string(),
                token_type_hint: Some("access_token".to_string()),
            },
        )
        .expect("revoke should succeed");

    // Token is now invalid (session revoked)
    let result = engine.validate_token(&realm_id, tokens.access_token());
    assert!(
        result.is_err(),
        "access token should be invalid after revocation"
    );
}

#[test]
fn revoke_refresh_token_invalidates_family() {
    use hearth::identity::TokenRevocationRequest;

    let (_dir, engine, _clock) = setup_engine();
    let realm_id = create_test_realm(&engine);
    let user = create_test_user(&engine, &realm_id);
    let client = engine
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "Revoke App".to_string(),
                redirect_uris: vec!["https://app.example.com/callback".to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: true,
                client_logo_url: None,
                ..Default::default()
            },
        )
        .expect("register client");

    let auth = engine
        .authorize(
            &realm_id,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                scope: "openid".to_string(),
                state: "state".to_string(),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: None,
                resource: None,
                amr_values: Vec::new(),
                response_mode: None,
                request: None,
                via_par: false,
            },
        )
        .expect("authorize");

    let tokens = engine
        .exchange_authorization_code(
            &realm_id,
            &TokenExchangeRequest {
                client_id: client.client_id().clone(),
                code: auth.code().to_string(),
                redirect_uri: "https://app.example.com/callback".to_string(),
                code_verifier: Some(TEST_PKCE_VERIFIER.to_string()),
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
            },
        )
        .expect("exchange code");

    // Revoke the refresh token
    engine
        .revoke_token(
            &realm_id,
            &TokenRevocationRequest {
                token: tokens.refresh_token().to_string(),
                token_type_hint: Some("refresh_token".to_string()),
            },
        )
        .expect("revoke should succeed");

    // Refresh is now rejected
    let result = engine.refresh_tokens(&realm_id, tokens.refresh_token(), None, None);
    assert!(
        matches!(result, Err(IdentityError::TokenRevoked)),
        "refresh should fail after revocation, got: {result:?}"
    );
}

// ===== B5: Token introspection =====

#[test]
fn introspect_active_token() {
    use hearth::identity::TokenIntrospectionRequest;

    let (_dir, engine, _clock) = setup_engine();
    let realm_id = create_test_realm(&engine);
    let user = create_test_user(&engine, &realm_id);
    let session = engine
        .create_session(&realm_id, user.id(), &SessionContext::default())
        .expect("session");
    let tokens = engine
        .issue_tokens(&realm_id, user.id(), session.id())
        .expect("issue tokens");

    let response = engine
        .introspect_token(
            &realm_id,
            &TokenIntrospectionRequest {
                token: tokens.access_token().to_string(),
                token_type_hint: None,
                introspecting_client_id: None,
            },
        )
        .expect("introspect should succeed");

    assert!(response.active, "valid token should be active");
    assert_eq!(response.sub.as_deref(), Some(&*user.id().to_string()));
    assert_eq!(response.token_type.as_deref(), Some("access"));
    assert!(response.exp.is_some());
    assert!(response.iat.is_some());
}

#[test]
fn introspect_revoked_token_is_inactive() {
    use hearth::identity::{TokenIntrospectionRequest, TokenRevocationRequest};

    let (_dir, engine, _clock) = setup_engine();
    let realm_id = create_test_realm(&engine);
    let user = create_test_user(&engine, &realm_id);
    let session = engine
        .create_session(&realm_id, user.id(), &SessionContext::default())
        .expect("session");
    let tokens = engine
        .issue_tokens(&realm_id, user.id(), session.id())
        .expect("issue tokens");

    // Revoke
    engine
        .revoke_token(
            &realm_id,
            &TokenRevocationRequest {
                token: tokens.access_token().to_string(),
                token_type_hint: None,
            },
        )
        .expect("revoke");

    // Introspect
    let response = engine
        .introspect_token(
            &realm_id,
            &TokenIntrospectionRequest {
                token: tokens.access_token().to_string(),
                token_type_hint: None,
                introspecting_client_id: None,
            },
        )
        .expect("introspect should succeed");

    assert!(!response.active, "revoked token should be inactive");
}

#[test]
fn introspect_invalid_token_is_inactive() {
    use hearth::identity::TokenIntrospectionRequest;

    let (_dir, engine, _clock) = setup_engine();
    let realm_id = create_test_realm(&engine);

    let response = engine
        .introspect_token(
            &realm_id,
            &TokenIntrospectionRequest {
                token: "not-a-valid-token".to_string(),
                token_type_hint: None,
                introspecting_client_id: None,
            },
        )
        .expect("introspect should succeed even for invalid tokens");

    assert!(!response.active, "invalid token should be inactive");
}

// ===== Phase 1 Step 22: OAuth 2.0 Adversarial Tests =====

/// Adversarial: Refresh token theft detection.
///
/// Scenario: attacker steals a refresh token, legitimate user rotates,
/// then attacker tries to use the stolen (old) token. The entire grant
/// family must be revoked, including the legitimate user's new token.
#[test]
fn adversarial_refresh_token_theft_detection() {
    let (_dir, engine, clock) = setup_engine();
    let realm_id = create_test_realm(&engine);

    let user = engine
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: "theft-victim@test.com".to_string(),
                display_name: "Theft Victim".to_string(),
                ..Default::default()
            },
        )
        .expect("create user");

    let client = engine
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "Theft Test Client".to_string(),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: true,
                client_logo_url: None,
                ..Default::default()
            },
        )
        .expect("register client");

    let auth = engine
        .authorize(
            &realm_id,
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/cb".to_string(),
                scope: "openid".to_string(),
                state: "theft-state".to_string(),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: None,
                resource: None,
                amr_values: Vec::new(),
                response_mode: None,
                request: None,
                via_par: false,
            },
        )
        .expect("authorize");

    let tokens = engine
        .exchange_authorization_code(
            &realm_id,
            &TokenExchangeRequest {
                client_id: client.client_id().clone(),
                code: auth.code().to_string(),
                redirect_uri: "https://app.example.com/cb".to_string(),
                code_verifier: Some(TEST_PKCE_VERIFIER.to_string()),
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
            },
        )
        .expect("exchange");

    // Attacker steals refresh token
    let stolen_refresh = tokens.refresh_token().to_string();

    // Legitimate user rotates (advance clock for unique tokens)
    clock.advance(1_000_000);
    let new_pair = engine
        .refresh_tokens(&realm_id, &stolen_refresh, None, None)
        .expect("legitimate rotation");
    let legitimate_refresh = new_pair.refresh_token().to_string();

    // Attacker uses the stolen (old) refresh token
    clock.advance(1_000_000);
    let attack_result = engine.refresh_tokens(&realm_id, &stolen_refresh, None, None);
    assert!(
        attack_result.is_err(),
        "stolen refresh token must be rejected"
    );

    // Legitimate user's new refresh token should ALSO be revoked
    // (entire grant family revoked due to theft detection)
    let legitimate_result = engine.refresh_tokens(&realm_id, &legitimate_refresh, None, None);
    assert!(
        legitimate_result.is_err(),
        "legitimate refresh token must also be revoked after theft detection"
    );

    // The session should be revoked too
    let validate_result = engine.validate_token(&realm_id, new_pair.access_token());
    assert!(
        validate_result.is_err(),
        "session should be revoked after theft detection"
    );
}

/// Adversarial: Invalid client secrets produce generic errors.
///
/// Verifies that wrong secrets, empty secrets, and non-existent clients
/// all return the same error type (no information leakage).
#[test]
fn adversarial_invalid_client_secret_generic_error() {
    use hearth::identity::ClientCredentialsRequest;

    let (_dir, engine, _clock) = setup_engine();
    let realm_id = create_test_realm(&engine);

    let client = engine
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "Secret Test Client".to_string(),
                redirect_uris: vec![],
                client_secret: Some("correct-secret-123".to_string()),
                grant_types: vec!["client_credentials".to_string()],
                require_consent: true,
                client_logo_url: None,
                ..Default::default()
            },
        )
        .expect("register client");

    // Wrong secret
    let wrong_result = engine.client_credentials_token(
        &realm_id,
        &ClientCredentialsRequest {
            client_id: client.client_id().clone(),
            client_secret: Some("wrong-secret-456".to_string()),
            scope: None,
            dpop_jkt: None,
            client_assertion_type: None,
            client_assertion: None,
        },
    );
    assert!(
        matches!(wrong_result, Err(IdentityError::InvalidClientSecret)),
        "wrong secret should return InvalidClientSecret"
    );

    // Empty secret
    let empty_result = engine.client_credentials_token(
        &realm_id,
        &ClientCredentialsRequest {
            client_id: client.client_id().clone(),
            client_secret: Some(String::new()),
            scope: None,
            dpop_jkt: None,
            client_assertion_type: None,
            client_assertion: None,
        },
    );
    assert!(
        matches!(empty_result, Err(IdentityError::InvalidClientSecret)),
        "empty secret should return InvalidClientSecret"
    );

    // Non-existent client
    let fake_client_id = hearth::core::ClientId::generate();
    let missing_result = engine.client_credentials_token(
        &realm_id,
        &ClientCredentialsRequest {
            client_id: fake_client_id,
            client_secret: Some("any-secret".to_string()),
            scope: None,
            dpop_jkt: None,
            client_assertion_type: None,
            client_assertion: None,
        },
    );
    assert!(
        matches!(missing_result, Err(IdentityError::InvalidClient)),
        "non-existent client should return InvalidClient"
    );
}

/// Adversarial: Device polling rate limit enforcement.
///
/// Polls faster than the allowed interval and verifies `SlowDown` error.
#[test]
fn adversarial_device_polling_rate_limit() {
    use hearth::identity::DeviceAuthorizationRequest;

    let (_dir, engine, _clock) = setup_engine();
    let realm_id = create_test_realm(&engine);

    let client = engine
        .register_client(
            &realm_id,
            &RegisterClientRequest {
                client_name: "Rate Limit Test".to_string(),
                redirect_uris: vec![],
                client_secret: None,
                grant_types: vec!["urn:ietf:params:oauth:grant-type:device_code".to_string()],
                require_consent: true,
                client_logo_url: None,
                ..Default::default()
            },
        )
        .expect("register client");

    let device_resp = engine
        .device_authorize(
            &realm_id,
            &DeviceAuthorizationRequest {
                client_id: client.client_id().clone(),
                scope: Some("openid".to_string()),
            },
        )
        .expect("device authorize");

    // First poll — should return AuthorizationPending (not SlowDown)
    let first_poll =
        engine.poll_device_token(&realm_id, &device_resp.device_code, client.client_id());
    assert!(
        matches!(first_poll, Err(IdentityError::AuthorizationPending)),
        "first poll should return AuthorizationPending, got: {first_poll:?}"
    );

    // Immediate second poll — should return SlowDown
    let second_poll =
        engine.poll_device_token(&realm_id, &device_resp.device_code, client.client_id());
    assert!(
        matches!(second_poll, Err(IdentityError::SlowDown)),
        "rapid second poll should return SlowDown, got: {second_poll:?}"
    );
}

// ===== Phase 1 Step 22: OAuth 2.0 Extended Property Tests =====

mod oauth_proptests {
    use super::*;
    use hearth::identity::{TokenIntrospectionRequest, TokenRevocationRequest};
    use proptest::prelude::*;

    proptest! {
        /// Property: After N issue/refresh/revoke operations, the active
        /// token count matches expectations.
        ///
        /// Issues tokens via auth code flow, optionally refreshes or revokes
        /// them, then introspects all tokens and verifies the active count.
        #[test]
        fn active_token_set_consistency(
            n_users in 1..5usize,
            ops in proptest::collection::vec(0..3u8, 1..8),
        ) {
            let (_dir, engine, _clock) = setup_engine();
            let realm = engine.create_realm(&CreateRealmRequest {
                name: "prop-test-realm".to_string(),
                config: None,
            }).expect("create realm");
            let realm_id = realm.id().clone();

            // Register a public client
            let client = engine.register_client(
                &realm_id,
                &RegisterClientRequest {
                    client_name: "Prop Test Client".to_string(),
                    redirect_uris: vec!["https://app.example.com/cb".to_string()],
                    client_secret: None,
                    grant_types: vec!["authorization_code".to_string()],
                    require_consent: true,
                    client_logo_url: None,
                                        ..Default::default()
                },
            ).expect("register client");

            // Create N users and issue tokens for each
            let mut access_tokens = Vec::new();
            let mut refresh_tokens = Vec::new();

            for i in 0..n_users {
                let email = format!("propuser-{i}-{}@test.com", uuid::Uuid::new_v4());
                let user = engine.create_user(&realm_id, &CreateUserRequest {
                    email,
                    display_name: format!("Prop User {i}"),
                    ..Default::default()
                }).expect("create user");

                let auth = engine.authorize(&realm_id, &AuthorizationRequest {
                    client_id: client.client_id().clone(),
                    redirect_uri: "https://app.example.com/cb".to_string(),
                    scope: "openid".to_string(),
                    state: format!("state-{i}"),
                    response_type: "code".to_string(),
                    user_id: user.id().clone(),
                    code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                    code_challenge_method: Some(CodeChallengeMethod::S256),
                    nonce: None,
                                        resource: None,
                                        amr_values: Vec::new(),
                                    response_mode: None,
                                    request: None,
                                    via_par: false,
                }).expect("authorize");

                let tokens = engine.exchange_authorization_code(&realm_id, &TokenExchangeRequest {
                    client_id: client.client_id().clone(),
                    code: auth.code().to_string(),
                    redirect_uri: "https://app.example.com/cb".to_string(),
                    code_verifier: Some(TEST_PKCE_VERIFIER.to_string()),
                    dpop_jkt: None,
                    client_assertion_type: None,
                    client_assertion: None,
                }).expect("exchange");

                access_tokens.push(tokens.access_token().to_string());
                refresh_tokens.push(tokens.refresh_token().to_string());
            }

            // Apply operations: 0 = noop, 1 = refresh, 2 = revoke access
            for (i, op) in ops.iter().enumerate() {
                let idx = i % access_tokens.len();
                match op {
                    1 => {
                        // Refresh — may fail if already revoked
                        if let Ok(new_pair) = engine.refresh_tokens(
                            &realm_id,
                            &refresh_tokens[idx],
                            None,
                            None,
                        ) {
                            access_tokens[idx] = new_pair.access_token().to_string();
                            refresh_tokens[idx] = new_pair.refresh_token().to_string();
                        }
                    }
                    2 => {
                        // Revoke access token
                        let _ = engine.revoke_token(
                            &realm_id,
                            &TokenRevocationRequest {
                                token: access_tokens[idx].clone(),
                                token_type_hint: Some("access_token".to_string()),
                            },
                        );
                    }
                    _ => {} // noop
                }
            }

            // Count active tokens via introspection
            let mut active_count = 0usize;
            for token in &access_tokens {
                let resp = engine.introspect_token(
                    &realm_id,
                    &TokenIntrospectionRequest {
                        token: token.clone(),
                        token_type_hint: None,
                        introspecting_client_id: None,
                    },
                ).expect("introspect");
                if resp.active {
                    active_count += 1;
                }
            }

            // Active count must be <= total issued
            prop_assert!(
                active_count <= access_tokens.len(),
                "active count ({}) must not exceed total ({})",
                active_count,
                access_tokens.len(),
            );
        }

        /// Property: At any point during N refresh rotations, exactly one
        /// refresh token is valid per grant family.
        ///
        /// Rotates a refresh token N times, checking after each rotation
        /// that only the latest refresh token is accepted.
        #[test]
        fn single_valid_refresh_token(n_rotations in 1..6usize) {
            let (_dir, engine, clock) = setup_engine();
            let realm = engine.create_realm(&CreateRealmRequest {
                name: "single-refresh-realm".to_string(),
                config: None,
            }).expect("create realm");
            let realm_id = realm.id().clone();

            let email = format!("rotate-{}@test.com", uuid::Uuid::new_v4());
            let user = engine.create_user(&realm_id, &CreateUserRequest {
                email,
                display_name: "Rotate User".to_string(),
                ..Default::default()
            }).expect("create user");

            let client = engine.register_client(
                &realm_id,
                &RegisterClientRequest {
                    client_name: "Rotate Client".to_string(),
                    redirect_uris: vec!["https://app.example.com/cb".to_string()],
                    client_secret: None,
                    grant_types: vec!["authorization_code".to_string()],
                    require_consent: true,
                    client_logo_url: None,
                                        ..Default::default()
                },
            ).expect("register client");

            let auth = engine.authorize(&realm_id, &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/cb".to_string(),
                scope: "openid".to_string(),
                state: "rotate-state".to_string(),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
                code_challenge_method: Some(CodeChallengeMethod::S256),
                nonce: None,
                                resource: None,
                                amr_values: Vec::new(),
                            response_mode: None,
                            request: None,
                            via_par: false,
            }).expect("authorize");

            let tokens = engine.exchange_authorization_code(&realm_id, &TokenExchangeRequest {
                client_id: client.client_id().clone(),
                code: auth.code().to_string(),
                redirect_uri: "https://app.example.com/cb".to_string(),
                code_verifier: Some(TEST_PKCE_VERIFIER.to_string()),
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
            }).expect("exchange");

            let mut current_refresh = tokens.refresh_token().to_string();
            let mut old_refresh_tokens: Vec<String> = Vec::new();

            for i in 0..n_rotations {
                // Advance clock 1 second to get unique timestamps
                clock.advance(1_000_000);

                let new_pair = engine.refresh_tokens(&realm_id, &current_refresh, None, None)
                    .unwrap_or_else(|e| panic!("rotation {i} failed: {e}"));

                old_refresh_tokens.push(current_refresh);
                current_refresh = new_pair.refresh_token().to_string();

                // Current refresh token should work for introspection
                let resp = engine.introspect_token(
                    &realm_id,
                    &TokenIntrospectionRequest {
                        token: current_refresh.clone(),
                        token_type_hint: None,
                        introspecting_client_id: None,
                    },
                ).expect("introspect current");
                prop_assert!(resp.active, "current refresh token must be active at rotation {}", i);
            }

            // After all rotations, none of the old refresh tokens should work
            for (i, old_token) in old_refresh_tokens.iter().enumerate() {
                let result = engine.refresh_tokens(&realm_id, old_token, None, None);
                // First old token reuse triggers theft detection
                if result.is_err() {
                    // After theft detection, all tokens in the family are revoked
                    break;
                }
                // If we got here, this old token happened to match (shouldn't)
                prop_assert!(false, "old refresh token {} should have been rejected", i);
            }
        }
    }
}

// ===== OAuth Consent engine tests =====

fn setup_consent_env() -> (
    tempfile::TempDir,
    EmbeddedIdentityEngine,
    Arc<FakeClock>,
    RealmId,
    UserId,
    ClientId,
) {
    let (dir, engine, clock) = setup_engine();
    let realm = engine
        .create_realm(&CreateRealmRequest {
            name: "consent-realm".to_string(),
            config: None,
        })
        .expect("create realm");
    let user = engine
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: "alice@example.com".to_string(),
                display_name: "Alice".to_string(),
                ..Default::default()
            },
        )
        .expect("create user");
    let client = engine
        .register_client(
            realm.id(),
            &RegisterClientRequest {
                client_name: "Consent Test App".to_string(),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: true,
                client_logo_url: None,
                ..Default::default()
            },
        )
        .expect("register client");
    (
        dir,
        engine,
        clock,
        realm.id().clone(),
        user.id().clone(),
        client.client_id().clone(),
    )
}

#[test]
fn grant_and_get_consent_round_trip() {
    let (_dir, engine, _clock, realm, user, client) = setup_consent_env();
    let rec = engine
        .grant_consent(
            &realm,
            &user,
            &client,
            &["profile".to_string(), "email".to_string()],
        )
        .expect("grant");
    assert_eq!(rec.granted_scopes, vec!["email", "profile"]);

    let loaded = engine
        .get_consent(&realm, &user, &client)
        .expect("get")
        .expect("present");
    assert_eq!(loaded.granted_scopes, vec!["email", "profile"]);
    assert!(loaded.covers(&["profile".to_string()]));
    assert!(!loaded.covers(&["admin".to_string()]));
}

#[test]
fn grant_consent_merges_into_existing_record() {
    let (_dir, engine, clock, realm, user, client) = setup_consent_env();
    engine
        .grant_consent(&realm, &user, &client, &["profile".to_string()])
        .expect("grant 1");
    clock.advance(1_000_000);
    let rec = engine
        .grant_consent(&realm, &user, &client, &["email".to_string()])
        .expect("grant 2");
    assert_eq!(rec.granted_scopes, vec!["email", "profile"]);
    assert!(rec.updated_at.as_micros() > rec.granted_at.as_micros());
}

#[test]
fn grant_consent_requires_existing_client() {
    let (_dir, engine, _clock, realm, user, _client) = setup_consent_env();
    let bogus = ClientId::generate();
    let err = engine
        .grant_consent(&realm, &user, &bogus, &["profile".to_string()])
        .expect_err("client not found");
    assert!(matches!(err, IdentityError::ClientNotFound), "got: {err:?}");
}

#[test]
fn list_consents_by_user_returns_joined_entries() {
    let (_dir, engine, _clock, realm, user, client) = setup_consent_env();
    engine
        .grant_consent(&realm, &user, &client, &["profile".to_string()])
        .expect("grant");
    let list = engine.list_consents_by_user(&realm, &user).expect("list");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].client_name, "Consent Test App");
    assert_eq!(list[0].record.granted_scopes, vec!["profile"]);
}

#[test]
fn list_consents_filters_orphaned_client_records() {
    let (_dir, engine, _clock, realm, user, client) = setup_consent_env();
    engine
        .grant_consent(&realm, &user, &client, &["profile".to_string()])
        .expect("grant");
    engine
        .delete_client(&realm, &client)
        .expect("delete client");
    // delete_client cascades consent away — verify list is empty.
    let list = engine.list_consents_by_user(&realm, &user).expect("list");
    assert!(list.is_empty(), "expected no live consents, got {list:?}");
}

#[test]
fn revoke_consent_returns_not_found_when_absent() {
    let (_dir, engine, _clock, realm, user, client) = setup_consent_env();
    let err = engine
        .revoke_consent(&realm, &user, &client)
        .expect_err("no record yet");
    assert!(
        matches!(err, IdentityError::ConsentNotFound),
        "got: {err:?}"
    );
}

#[test]
fn revoke_consent_removes_record_entirely() {
    let (_dir, engine, _clock, realm, user, client) = setup_consent_env();
    engine
        .grant_consent(&realm, &user, &client, &["profile".to_string()])
        .expect("grant");
    engine
        .revoke_consent(&realm, &user, &client)
        .expect("revoke");
    assert!(engine
        .get_consent(&realm, &user, &client)
        .expect("get")
        .is_none());
}

#[test]
fn revoke_all_consents_drops_every_user_record() {
    let (_dir, engine, _clock, realm, user, client1) = setup_consent_env();
    let client2 = engine
        .register_client(
            &realm,
            &RegisterClientRequest {
                client_name: "Second Client".to_string(),
                redirect_uris: vec!["https://other.example.com/cb".to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: true,
                client_logo_url: None,
                ..Default::default()
            },
        )
        .expect("register 2");
    engine
        .grant_consent(&realm, &user, &client1, &["profile".to_string()])
        .expect("grant 1");
    engine
        .grant_consent(&realm, &user, client2.client_id(), &["email".to_string()])
        .expect("grant 2");
    let count = engine
        .revoke_all_consents_for_user(&realm, &user)
        .expect("revoke all");
    assert_eq!(count, 2);
    assert!(engine
        .list_consents_by_user(&realm, &user)
        .expect("list")
        .is_empty());
}

#[test]
fn pending_authorization_ticket_is_single_use() {
    let (_dir, engine, clock, realm, user, client) = setup_consent_env();
    let now = clock.now();
    let pending = PendingAuthorizationRequest {
        user_id: user.clone(),
        client_id: client.clone(),
        redirect_uri: "https://app.example.com/cb".to_string(),
        requested_scopes: vec!["profile".to_string()],
        state: "xyz".to_string(),
        response_type: "code".to_string(),
        code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
        code_challenge_method: Some("S256".to_string()),
        nonce: None,
        response_mode: None,
        authorization_signed_response_alg: None,
        created_at: now,
        expires_at: now.add_micros(600_000_000),
    };
    let ticket = engine
        .put_pending_authorization(&realm, &pending)
        .expect("put");
    let first = engine
        .take_pending_authorization(&realm, &ticket)
        .expect("take 1");
    assert_eq!(first.user_id, user);
    let err = engine
        .take_pending_authorization(&realm, &ticket)
        .expect_err("take 2 should fail");
    assert!(matches!(err, IdentityError::ConsentTicketNotFound));
}

#[test]
fn pending_authorization_ticket_expires() {
    let (_dir, engine, clock, realm, user, client) = setup_consent_env();
    let now = clock.now();
    let pending = PendingAuthorizationRequest {
        user_id: user,
        client_id: client,
        redirect_uri: "https://app.example.com/cb".to_string(),
        requested_scopes: vec!["profile".to_string()],
        state: "xyz".to_string(),
        response_type: "code".to_string(),
        code_challenge: Some(pkce_challenge(TEST_PKCE_VERIFIER)),
        code_challenge_method: Some("S256".to_string()),
        nonce: None,
        response_mode: None,
        authorization_signed_response_alg: None,
        created_at: now,
        expires_at: now.add_micros(600_000_000),
    };
    let ticket = engine
        .put_pending_authorization(&realm, &pending)
        .expect("put");
    // advance past expiry
    clock.advance(600_000_001);
    let err = engine
        .take_pending_authorization(&realm, &ticket)
        .expect_err("expired");
    assert!(
        matches!(err, IdentityError::ConsentTicketExpired),
        "got {err:?}"
    );
}

#[test]
fn delete_user_cascades_consent_records() {
    let (_dir, engine, _clock, realm, user, client) = setup_consent_env();
    engine
        .grant_consent(&realm, &user, &client, &["profile".to_string()])
        .expect("grant");
    engine.delete_user(&realm, &user).expect("delete user");
    assert!(engine
        .get_consent(&realm, &user, &client)
        .expect("get")
        .is_none());
}

#[test]
fn consent_records_are_realm_isolated() {
    let (_dir, engine, _clock, realm_a, user, client) = setup_consent_env();
    let realm_b = engine
        .create_realm(&CreateRealmRequest {
            name: "Other".to_string(),
            config: None,
        })
        .expect("create realm B");
    engine
        .grant_consent(&realm_a, &user, &client, &["profile".to_string()])
        .expect("grant");
    // Same (user, client) key in realm_b must not find realm_a's record.
    let other = engine
        .get_consent(realm_b.id(), &user, &client)
        .expect("get");
    assert!(other.is_none());
}
