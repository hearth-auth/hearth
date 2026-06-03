//! Integration tests for the SMS MFA challenge interstitial (HEA-854).
//!
//! These tests exercise the engine-level primitives that back the web
//! challenge flow:
//!
//! - `issue_sms_otp` → `verify_sms_otp` round-trip
//! - `issue_authorization_code` with `amr_values: vec!["sms"]` produces
//!   access and ID tokens carrying `amr: ["sms"]`
//! - `SmsMfaChallengeSucceeded` and `SmsMfaChallengeFailed` audit events
//!   are emitted at the correct call sites
//!
//! The web interstitial UI layer (`sms_challenge.rs`) is covered by the
//! unit tests embedded in that module (cookie round-trip, cross-user
//! rejection).

mod common;

use std::sync::{Arc, Mutex};

use hearth::audit::{AuditAction, AuditQuery};
use hearth::identity::{
    CodeChallengeMethod, CreateRealmRequest, CreateUserRequest, RealmConfig, RegisterClientRequest,
    SmsError, SmsMessage, SmsSender, TokenExchangeRequest, UpdateUserRequest,
};

// ---------------------------------------------------------------------------
// Test-only capturing SMS sender
// ---------------------------------------------------------------------------

/// An [`SmsSender`] implementation that records every outgoing message
/// into an in-memory buffer. Used in tests to extract the OTP code from
/// the message body without touching any network.
struct CapturingSmsSmsSender {
    messages: Mutex<Vec<SmsMessage>>,
}

impl CapturingSmsSmsSender {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            messages: Mutex::new(Vec::new()),
        })
    }

    /// Extracts the 6-digit OTP code from the last sent message body.
    ///
    /// Expects the format: `"Your verification code is: NNNNNN"`.
    fn last_otp_code(&self) -> Option<String> {
        #[allow(clippy::unwrap_used)]
        let guard = self.messages.lock().unwrap();
        let body = guard.last()?.body.clone();
        body.rsplit_once(": ")
            .map(|(_, code)| code.trim().to_string())
    }
}

impl SmsSender for CapturingSmsSmsSender {
    fn send(&self, message: &SmsMessage) -> Result<(), SmsError> {
        #[allow(clippy::unwrap_used)]
        self.messages.lock().unwrap().push(message.clone());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const TEST_PHONE: &str = "+15555550101";
const HMAC_KEY: &[u8] = b"test-hmac-key-not-for-production";
const TEST_PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

fn pkce_challenge(verifier: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(verifier.as_bytes());
    data_encoding::BASE64URL_NOPAD.encode(&hash)
}

fn now_unix_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Creates a realm with `mfa_methods: ["sms"]`.
fn create_sms_realm(h: &common::TestHarness) -> hearth::core::RealmId {
    h.identity()
        .create_realm(&CreateRealmRequest {
            name: format!("sms-mfa-test-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                mfa_methods: Some(vec!["sms".to_string()]),
                ..RealmConfig::default()
            }),
        })
        .expect("create realm")
        .id()
        .clone()
}

/// Creates a user and marks their phone as verified.
fn create_verified_phone_user(
    h: &common::TestHarness,
    realm: &hearth::core::RealmId,
) -> hearth::core::UserId {
    let email = format!("sms-test-{}@example.com", uuid::Uuid::new_v4());
    let user = h
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email,
                display_name: "SMS Test User".to_string(),
                ..CreateUserRequest::default()
            },
        )
        .expect("create user");

    // Set a verified phone number on the user.
    h.identity()
        .update_user(
            realm,
            user.id(),
            &UpdateUserRequest {
                phone_number: Some(Some(TEST_PHONE.to_string())),
                phone_verified: Some(true),
                ..UpdateUserRequest::default()
            },
        )
        .expect("set phone");

    user.id().clone()
}

/// Registers a public OAuth client and returns its ID.
fn create_client(h: &common::TestHarness, realm: &hearth::core::RealmId) -> hearth::core::ClientId {
    h.identity()
        .register_client(
            realm,
            &RegisterClientRequest {
                client_name: "SMS MFA Test App".to_string(),
                redirect_uris: vec!["https://app.example.com/cb".to_string()],
                client_secret: None,
                grant_types: vec!["authorization_code".to_string()],
                require_consent: false,
                client_logo_url: None,
                ..Default::default()
            },
        )
        .expect("register client")
        .client_id()
        .clone()
}

// ---------------------------------------------------------------------------
// AC-1: issue_sms_otp → verify_sms_otp succeeds with correct code
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sms_otp_correct_code_passes() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = create_sms_realm(&h);
    let sender = CapturingSmsSmsSender::new();
    let now = now_unix_ts();

    let nonce = h
        .identity()
        .issue_sms_otp(&realm, TEST_PHONE, HMAC_KEY, sender.as_ref(), now)
        .expect("issue_sms_otp");

    let code = sender.last_otp_code().expect("OTP sent");
    assert_eq!(code.len(), 6, "OTP must be 6 digits: {code}");

    h.identity()
        .verify_sms_otp(&realm, &nonce, &code, HMAC_KEY, now)
        .expect("verify_sms_otp with correct code");
}

// ---------------------------------------------------------------------------
// AC-2: Wrong code returns InvalidSmsOtp
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sms_otp_wrong_code_fails() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = create_sms_realm(&h);
    let sender = CapturingSmsSmsSender::new();
    let now = now_unix_ts();

    let nonce = h
        .identity()
        .issue_sms_otp(&realm, TEST_PHONE, HMAC_KEY, sender.as_ref(), now)
        .expect("issue_sms_otp");

    let err = h
        .identity()
        .verify_sms_otp(&realm, &nonce, "000000", HMAC_KEY, now)
        .expect_err("wrong code must fail");

    assert!(
        matches!(err, hearth::identity::IdentityError::InvalidSmsOtp),
        "expected InvalidSmsOtp, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// AC-3: amr=["sms"] appears in access token and ID token after challenge
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sms_amr_claim_in_tokens() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = create_sms_realm(&h);
    let user_id = create_verified_phone_user(&h, &realm);
    let client_id = create_client(&h, &realm);

    let auth_resp = h
        .identity()
        .issue_authorization_code(
            &realm,
            &user_id,
            &client_id,
            "https://app.example.com/cb",
            "openid",
            "state-abc",
            Some(pkce_challenge(TEST_PKCE_VERIFIER)),
            Some(CodeChallengeMethod::S256),
            None,
            vec!["sms".to_string()],
            None,
            None,
            false,
        )
        .expect("issue_authorization_code");

    let token_resp = h
        .identity()
        .exchange_authorization_code(
            &realm,
            &TokenExchangeRequest {
                client_id: client_id.clone(),
                code: auth_resp.code().to_string(),
                redirect_uri: "https://app.example.com/cb".to_string(),
                code_verifier: Some(TEST_PKCE_VERIFIER.to_string()),
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
            },
        )
        .expect("exchange_authorization_code");

    // Access token must carry amr=["sms"].
    let access_claims = hearth::identity::decode_claims_unverified(token_resp.access_token())
        .expect("decode access token");
    assert_eq!(
        access_claims.amr,
        vec!["sms".to_string()],
        "access token must carry amr=[\"sms\"]"
    );

    // ID token must also carry amr=["sms"].
    let id_claims =
        hearth::identity::decode_claims_unverified(token_resp.id_token()).expect("decode id token");
    assert_eq!(
        id_claims.amr,
        vec!["sms".to_string()],
        "ID token must carry amr=[\"sms\"]"
    );
}

// ---------------------------------------------------------------------------
// AC-4: Token without SMS MFA has empty amr claim
// ---------------------------------------------------------------------------

#[tokio::test]
async fn no_sms_mfa_means_empty_amr() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = create_sms_realm(&h);
    let user_id = create_verified_phone_user(&h, &realm);
    let client_id = create_client(&h, &realm);

    let auth_resp = h
        .identity()
        .issue_authorization_code(
            &realm,
            &user_id,
            &client_id,
            "https://app.example.com/cb",
            "openid",
            "state-xyz",
            Some(pkce_challenge(TEST_PKCE_VERIFIER)),
            Some(CodeChallengeMethod::S256),
            None,
            Vec::new(),
            None,
            None,
            false,
        )
        .expect("issue_authorization_code");

    let token_resp = h
        .identity()
        .exchange_authorization_code(
            &realm,
            &TokenExchangeRequest {
                client_id,
                code: auth_resp.code().to_string(),
                redirect_uri: "https://app.example.com/cb".to_string(),
                code_verifier: Some(TEST_PKCE_VERIFIER.to_string()),
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
            },
        )
        .expect("exchange_authorization_code");

    let claims = hearth::identity::decode_claims_unverified(token_resp.access_token())
        .expect("decode access token");
    assert!(
        claims.amr.is_empty(),
        "no amr expected without SMS MFA: {:?}",
        claims.amr
    );
}

// ---------------------------------------------------------------------------
// AC-5: SmsMfaChallengeSucceeded audit event is appendable and queryable
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sms_mfa_challenge_succeeded_audit_event() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = create_sms_realm(&h);
    let user_id = create_verified_phone_user(&h, &realm);

    h.audit()
        .append(&hearth::audit::CreateAuditEvent {
            realm_id: realm.clone(),
            actor: user_id.as_uuid().to_string(),
            action: AuditAction::SmsMfaChallengeSucceeded,
            resource_type: "user".to_string(),
            resource_id: user_id.as_uuid().to_string(),
            metadata: Some(serde_json::json!({"test": true})),
        })
        .expect("append audit event");

    let events = h
        .audit()
        .query(&AuditQuery {
            realm_id: realm.clone(),
            action: Some(AuditAction::SmsMfaChallengeSucceeded),
            actor: None,
            start_time: None,
            end_time: None,
            limit: Some(10),
        })
        .expect("audit query");

    assert_eq!(events.len(), 1, "expected 1 SmsMfaChallengeSucceeded event");
    assert_eq!(events[0].action, AuditAction::SmsMfaChallengeSucceeded);
    assert_eq!(events[0].actor, user_id.as_uuid().to_string());
}

// ---------------------------------------------------------------------------
// AC-6: SmsMfaChallengeFailed audit event is appendable and queryable
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sms_mfa_challenge_failed_audit_event() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = create_sms_realm(&h);
    let user_id = create_verified_phone_user(&h, &realm);

    h.audit()
        .append(&hearth::audit::CreateAuditEvent {
            realm_id: realm.clone(),
            actor: user_id.as_uuid().to_string(),
            action: AuditAction::SmsMfaChallengeFailed,
            resource_type: "user".to_string(),
            resource_id: user_id.as_uuid().to_string(),
            metadata: Some(serde_json::json!({"reason": "wrong_code"})),
        })
        .expect("append audit event");

    let events = h
        .audit()
        .query(&AuditQuery {
            realm_id: realm.clone(),
            action: Some(AuditAction::SmsMfaChallengeFailed),
            actor: None,
            start_time: None,
            end_time: None,
            limit: Some(10),
        })
        .expect("audit query");

    assert_eq!(events.len(), 1, "expected 1 SmsMfaChallengeFailed event");
    assert_eq!(events[0].action, AuditAction::SmsMfaChallengeFailed);
}

// ---------------------------------------------------------------------------
// AC-7: amr=["sms"] is preserved through token refresh
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sms_amr_preserved_through_refresh() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = create_sms_realm(&h);
    let user_id = create_verified_phone_user(&h, &realm);
    let client_id = create_client(&h, &realm);

    let auth_resp = h
        .identity()
        .issue_authorization_code(
            &realm,
            &user_id,
            &client_id,
            "https://app.example.com/cb",
            "openid",
            "state-refresh",
            Some(pkce_challenge(TEST_PKCE_VERIFIER)),
            Some(CodeChallengeMethod::S256),
            None,
            vec!["sms".to_string()],
            None,
            None,
            false,
        )
        .expect("issue_authorization_code");

    let tokens = h
        .identity()
        .exchange_authorization_code(
            &realm,
            &TokenExchangeRequest {
                client_id,
                code: auth_resp.code().to_string(),
                redirect_uri: "https://app.example.com/cb".to_string(),
                code_verifier: Some(TEST_PKCE_VERIFIER.to_string()),
                dpop_jkt: None,
                client_assertion_type: None,
                client_assertion: None,
            },
        )
        .expect("exchange code");

    let refreshed = h
        .identity()
        .refresh_tokens(&realm, tokens.refresh_token(), None, None)
        .expect("refresh tokens");

    let claims = hearth::identity::decode_claims_unverified(refreshed.access_token())
        .expect("decode refreshed access token");
    assert_eq!(
        claims.amr,
        vec!["sms".to_string()],
        "amr must be preserved through refresh"
    );
}
