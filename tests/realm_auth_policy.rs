//! Integration tests for per-realm auth policy enforcement (HEA-477).
//!
//! Confirms that `allowed_auth_methods`, token TTL overrides, `mfa_required`,
//! and `password_complexity` are enforced at runtime rather than accepted
//! silently. Each test exercises the identity engine directly so enforcement
//! cannot be bypassed by omitting web-layer checks.

mod common;

use hearth::core::RealmId;
use hearth::identity::{
    AuthorizationRequest, CleartextPassword, CodeChallengeMethod, CreateRealmRequest,
    CreateUserRequest, IdentityError, MagicLinkResponse, PasswordPolicy, RealmConfig,
    RegisterClientRequest, SessionContext, TokenExchangeRequest, UpdateRealmRequest,
};

// ===== TOTP helper (mirrors tests/mfa.rs) =====

/// Computes a TOTP code from a base32 secret at the given Unix timestamp.
fn compute_totp_code(secret_base32: &str, unix_secs: u64) -> String {
    let secret_bytes = data_encoding::BASE32_NOPAD
        .decode(secret_base32.as_bytes())
        .expect("decode base32");
    let step = unix_secs / 30;
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &secret_bytes);
    let tag = ring::hmac::sign(&key, &step.to_be_bytes());
    let hash = tag.as_ref();
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let binary = u32::from_be_bytes([
        hash[offset] & 0x7f,
        hash[offset + 1],
        hash[offset + 2],
        hash[offset + 3],
    ]);
    format!("{:06}", binary % 1_000_000)
}

/// Enrolls TOTP for a user and returns after MFA is fully activated.
fn enroll_mfa(harness: &common::TestHarness, realm: &RealmId, user_id: &hearth::core::UserId) {
    let enrollment = harness
        .identity()
        .enroll_totp(realm, user_id)
        .expect("enroll_totp");
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs();
    let code = compute_totp_code(&enrollment.secret_base32, now_secs);
    harness
        .identity()
        .verify_totp_enrollment(realm, user_id, &code)
        .expect("verify_totp_enrollment");
}

// ===== helpers =====

fn create_realm_with_config(
    harness: &common::TestHarness,
    config: RealmConfig,
) -> hearth::identity::Realm {
    harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("policy-test-{}", uuid::Uuid::new_v4()),
            config: Some(config),
        })
        .expect("create realm")
}

fn create_user(harness: &common::TestHarness, realm: &RealmId) -> hearth::identity::User {
    harness
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: format!("user-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Test User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user")
}

// ===== allowed_auth_methods enforcement =====

#[tokio::test]
async fn magic_link_blocked_when_not_in_allowed_methods() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm_with_config(
        &harness,
        RealmConfig {
            allowed_auth_methods: Some(vec!["password".to_string()]),
            ..RealmConfig::default()
        },
    );
    let user = create_user(&harness, realm.id());

    let err = harness
        .identity()
        .request_magic_link(realm.id(), user.email())
        .expect_err("magic_link should be blocked");

    assert!(
        matches!(err, IdentityError::AuthMethodNotAllowed { method } if method == "magic_link"),
        "expected AuthMethodNotAllowed(magic_link), got: {err}"
    );
}

#[tokio::test]
async fn magic_link_allowed_when_in_allowed_methods() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm_with_config(
        &harness,
        RealmConfig {
            allowed_auth_methods: Some(vec!["password".to_string(), "magic_link".to_string()]),
            ..RealmConfig::default()
        },
    );
    let user = create_user(&harness, realm.id());

    let resp: MagicLinkResponse = harness
        .identity()
        .request_magic_link(realm.id(), user.email())
        .expect("magic_link should succeed when allowed");
    assert!(
        !resp.token().is_empty(),
        "magic link token must be non-empty"
    );
}

#[tokio::test]
async fn magic_link_allowed_when_no_restriction() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm_with_config(&harness, RealmConfig::default());
    let user = create_user(&harness, realm.id());

    let resp: MagicLinkResponse = harness
        .identity()
        .request_magic_link(realm.id(), user.email())
        .expect("magic_link should succeed when allowed_auth_methods is unconfigured");
    assert!(
        !resp.token().is_empty(),
        "magic link token must be non-empty"
    );
}

// ===== per-realm token TTL enforcement =====

/// Per-realm access/refresh TTL overrides are applied at **token issuance**,
/// not just stored in config.
///
/// The previous version of this test only asserted that the TTL values
/// round-tripped through `get_realm` — it never issued a token, so it could
/// not detect a regression where TTL overrides are persisted but ignored during
/// issuance. This version drives the full auth-code flow and decodes the real
/// access token's `exp` claim, proving the per-realm TTL reaches the signed JWT.
#[tokio::test]
async fn token_ttl_overrides_applied_at_issuance() {
    use base64::Engine as _;

    let harness = common::TestHarness::embedded().await.expect("harness");

    // 5-minute access TTL (tight, easily distinguishable from the default 60-min).
    let access_ttl_secs: i64 = 5 * 60; // 300 s
    let access_ttl_micros: i64 = access_ttl_secs * 1_000_000;
    let refresh_ttl_micros: i64 = 24 * 60 * 60 * 1_000_000;

    let realm = create_realm_with_config(
        &harness,
        RealmConfig {
            access_token_ttl_micros: Some(access_ttl_micros),
            refresh_token_ttl_micros: Some(refresh_ttl_micros),
            ..RealmConfig::default()
        },
    );

    // Config round-trip — the TTL must survive storage.
    let loaded = harness
        .identity()
        .get_realm(realm.id())
        .expect("get_realm")
        .expect("realm exists");
    assert_eq!(
        loaded.config().access_token_ttl_micros,
        Some(access_ttl_micros),
        "access_token_ttl_micros must survive storage round-trip"
    );

    // === Issuance gate — the real assertion ===
    // Register a minimal public client and run the full authorization_code
    // flow so we get a real signed access token from this realm.
    let user = create_user(&harness, realm.id());
    let client = harness
        .identity()
        .register_client(
            realm.id(),
            &RegisterClientRequest {
                client_name: "TTL-test app".to_string(),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                client_logo_url: None,
                ..Default::default()
            },
        )
        .expect("register client");

    // PKCE verifier / challenge (S256).
    let pkce_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let digest = ring::digest::digest(&ring::digest::SHA256, pkce_verifier.as_bytes());
    let pkce_challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.as_ref());

    let auth = harness
        .identity()
        .authorize(
            realm.id(),
            &AuthorizationRequest {
                client_id: client.client_id().clone(),
                redirect_uri: "https://app.example.com/cb".to_string(),
                scope: "openid".to_string(),
                state: "ttl-test-state".to_string(),
                response_type: "code".to_string(),
                user_id: user.id().clone(),
                code_challenge: Some(pkce_challenge),
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

    let tokens = harness
        .identity()
        .exchange_authorization_code(
            realm.id(),
            &TokenExchangeRequest {
                client_id: client.client_id().clone(),
                code: auth.code().to_string(),
                redirect_uri: "https://app.example.com/cb".to_string(),
                code_verifier: Some(pkce_verifier.to_string()),
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
            },
        )
        .expect("exchange code");

    // Decode the real signed access token and extract `exp`.
    let claims =
        hearth::identity::tokens::decode_claims_unverified(tokens.access_token()).expect("decode");

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_secs() as i64;

    let lifetime_secs = claims.exp - claims.iat;

    // The per-realm 5-minute TTL must reach the signed JWT.
    // Allow a ±10 s tolerance for CPU scheduling jitter.
    assert!(
        (lifetime_secs - access_ttl_secs).abs() <= 10,
        "access token lifetime must equal the per-realm 5-minute override \
         (expected ~{access_ttl_secs}s, got {lifetime_secs}s = exp {} - iat {})",
        claims.exp,
        claims.iat,
    );

    // The token must be valid right now.
    assert!(
        claims.exp > now_secs,
        "freshly issued access token must not already be expired: exp={}, now={}",
        claims.exp,
        now_secs
    );
}

// ===== password complexity enforcement (existing, validated here for completeness) =====

#[tokio::test]
async fn password_complexity_enforced_on_set_password() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm_with_config(
        &harness,
        RealmConfig {
            password_policy: Some(hearth::identity::PasswordPolicy {
                min_length: Some(12),
                require_uppercase: Some(true),
                require_number: Some(true),
                require_special: Some(false),
                not_username: None,
                not_email: None,
                history_depth: None,
                max_age_days: None,
            }),
            ..RealmConfig::default()
        },
    );
    let user = create_user(&harness, realm.id());

    // Too short — should fail with a policy violation.
    let err = harness
        .identity()
        .set_password(
            realm.id(),
            user.id(),
            &CleartextPassword::from_string("short1A".to_string()),
        )
        .expect_err("short password should fail");
    assert!(
        matches!(err, IdentityError::InvalidInput { .. }),
        "expected InvalidInput for short password, got: {err}"
    );

    // Meets policy — should succeed.
    harness
        .identity()
        .set_password(
            realm.id(),
            user.id(),
            &CleartextPassword::from_string("ValidLongPassword1".to_string()),
        )
        .expect("password meeting policy should succeed");
}

// ===== mfa_required enforcement (existing, validated here for completeness) =====

#[tokio::test]
async fn mfa_required_realm_config_persists_and_is_readable() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm_with_config(
        &harness,
        RealmConfig {
            mfa_required: Some(true),
            ..RealmConfig::default()
        },
    );

    let loaded = harness
        .identity()
        .get_realm(realm.id())
        .expect("get_realm")
        .expect("realm exists");

    assert_eq!(
        loaded.config().mfa_required,
        Some(true),
        "mfa_required should be persisted"
    );
}

// ===== allowed_auth_methods update via UpdateRealmRequest =====

#[tokio::test]
async fn allowed_auth_methods_can_be_updated() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm_with_config(&harness, RealmConfig::default());
    let user = create_user(&harness, realm.id());

    // Initially unrestricted — magic_link works.
    harness
        .identity()
        .request_magic_link(realm.id(), user.email())
        .expect("magic_link should succeed before restriction");

    // Restrict to password only.
    harness
        .identity()
        .update_realm(
            realm.id(),
            &UpdateRealmRequest {
                config: Some(RealmConfig {
                    allowed_auth_methods: Some(vec!["password".to_string()]),
                    ..RealmConfig::default()
                }),
                ..UpdateRealmRequest::default()
            },
        )
        .expect("update realm");

    // Now magic_link should be blocked.
    let err = harness
        .identity()
        .request_magic_link(realm.id(), user.email())
        .expect_err("magic_link should now be blocked");

    assert!(
        matches!(err, IdentityError::AuthMethodNotAllowed { method } if method == "magic_link"),
        "expected AuthMethodNotAllowed after update, got: {err}"
    );
}

// ===== mfa_required enforcement =====

#[tokio::test]
async fn mfa_required_blocks_session_when_user_has_no_mfa() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm_with_config(
        &harness,
        RealmConfig {
            mfa_required: Some(true),
            ..RealmConfig::default()
        },
    );
    let user = create_user(&harness, realm.id());

    let err = harness
        .identity()
        .create_session(realm.id(), user.id(), &SessionContext::default())
        .expect_err("create_session should fail: realm requires MFA but user has none enrolled");

    assert!(
        matches!(err, IdentityError::MfaRequired),
        "expected MfaRequired, got: {err}"
    );
}

#[tokio::test]
async fn mfa_required_allows_session_when_user_has_mfa() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm_with_config(
        &harness,
        RealmConfig {
            mfa_required: Some(true),
            ..RealmConfig::default()
        },
    );
    let user = create_user(&harness, realm.id());
    enroll_mfa(&harness, realm.id(), user.id());

    let session = harness
        .identity()
        .create_session(realm.id(), user.id(), &SessionContext::default())
        .expect("create_session should succeed: user has MFA enrolled");
    assert_eq!(
        session.user_id(),
        user.id(),
        "session must be bound to the correct user"
    );
}

#[tokio::test]
async fn mfa_required_passkey_satisfies_policy() {
    // Passkeys are inherently multi-factor (possession + biometric/PIN).
    // A session created via passkey authentication must bypass the TOTP
    // enrollment gate even when the realm sets mfa_required = true.
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm_with_config(
        &harness,
        RealmConfig {
            mfa_required: Some(true),
            ..RealmConfig::default()
        },
    );
    let user = create_user(&harness, realm.id());

    let ctx = SessionContext {
        satisfies_mfa_via_passkey: true,
        ..SessionContext::default()
    };
    let session = harness
        .identity()
        .create_session(realm.id(), user.id(), &ctx)
        .expect("passkey session should bypass mfa_required TOTP gate");
    assert_eq!(
        session.user_id(),
        user.id(),
        "session must be bound to the correct user"
    );
}

// ===== allowed_auth_methods enforcement for password =====

#[tokio::test]
async fn password_blocked_when_not_in_allowed_methods() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm_with_config(
        &harness,
        RealmConfig {
            allowed_auth_methods: Some(vec!["magic_link".to_string()]),
            ..RealmConfig::default()
        },
    );
    let user = create_user(&harness, realm.id());

    // Set a password first so the lookup would otherwise succeed.
    harness
        .identity()
        .set_password(
            realm.id(),
            user.id(),
            &CleartextPassword::from_string("AnyPassword1!".to_string()),
        )
        .expect("set_password");

    let err = harness
        .identity()
        .verify_password(
            realm.id(),
            user.id(),
            &CleartextPassword::from_string("AnyPassword1!".to_string()),
        )
        .expect_err("verify_password should be blocked");

    assert!(
        matches!(err, IdentityError::AuthMethodNotAllowed { method } if method == "password"),
        "expected AuthMethodNotAllowed(password), got: {err}"
    );
}

#[tokio::test]
async fn password_allowed_when_in_allowed_methods() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm_with_config(
        &harness,
        RealmConfig {
            allowed_auth_methods: Some(vec!["password".to_string(), "magic_link".to_string()]),
            ..RealmConfig::default()
        },
    );
    let user = create_user(&harness, realm.id());
    harness
        .identity()
        .set_password(
            realm.id(),
            user.id(),
            &CleartextPassword::from_string("AnyPassword1!".to_string()),
        )
        .expect("set_password");

    let ok = harness
        .identity()
        .verify_password(
            realm.id(),
            user.id(),
            &CleartextPassword::from_string("AnyPassword1!".to_string()),
        )
        .expect("verify_password should succeed");
    assert!(ok, "correct password should verify as true");
}

// ===== password complexity: additional coverage =====

#[tokio::test]
async fn password_complexity_require_special_enforced() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm_with_config(
        &harness,
        RealmConfig {
            password_policy: Some(PasswordPolicy {
                min_length: Some(8),
                require_special: Some(true),
                ..PasswordPolicy::default()
            }),
            ..RealmConfig::default()
        },
    );
    let user = create_user(&harness, realm.id());

    // No special character — should fail.
    let err = harness
        .identity()
        .set_password(
            realm.id(),
            user.id(),
            &CleartextPassword::from_string("NoSpecial1".to_string()),
        )
        .expect_err("missing special character should fail");
    assert!(
        matches!(err, IdentityError::InvalidInput { .. }),
        "expected InvalidInput for missing special char, got: {err}"
    );

    // Includes special character — should succeed.
    harness
        .identity()
        .set_password(
            realm.id(),
            user.id(),
            &CleartextPassword::from_string("HasSpecial1!".to_string()),
        )
        .expect("password with special char should pass policy");
}

#[tokio::test]
async fn password_complexity_not_email_enforced() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm_with_config(
        &harness,
        RealmConfig {
            password_policy: Some(PasswordPolicy {
                min_length: Some(8),
                not_email: Some(true),
                ..PasswordPolicy::default()
            }),
            ..RealmConfig::default()
        },
    );
    let user = create_user(&harness, realm.id());

    // Use the user's email as the password — should fail.
    let err = harness
        .identity()
        .set_password(
            realm.id(),
            user.id(),
            &CleartextPassword::from_string(user.email().to_string()),
        )
        .expect_err("email-as-password should fail");
    assert!(
        matches!(err, IdentityError::InvalidInput { .. }),
        "expected InvalidInput for email-as-password, got: {err}"
    );

    // Different password — should succeed.
    harness
        .identity()
        .set_password(
            realm.id(),
            user.id(),
            &CleartextPassword::from_string("not-the-email-password1A".to_string()),
        )
        .expect("non-email password should pass policy");
}
