//! Integration tests for the step-up MFA grant that completes a password
//! (ROPC) grant for a user holding a second factor (HEA-836).
//!
//! A password grant proves the password and nothing else, so a user who holds
//! a second factor is answered `StepUpChallengeRequired`; the step-up grant
//! then re-verifies the password plus the MFA code and issues tokens.
//!
//! Adaptive MFA (device fingerprinting) was removed in Hearth 3.0.0; the
//! tests of the fingerprint gate that used to live here went with it. The
//! step-up grant itself is kept and is exercised here with an enrolled TOTP.

mod common;

use std::time::{SystemTime, UNIX_EPOCH};

use hearth::audit::{AuditAction, AuditQuery};
use hearth::core::RealmId;
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, IdentityError, PasswordGrantRequest,
    StepUpMfaGrantRequest, User,
};

// ──────────────────────────────────────────────────────────────
// Shared helpers
// ──────────────────────────────────────────────────────────────

const PASSWORD: &str = "S3cur3P@ss!1";

fn ropc(email: &str) -> PasswordGrantRequest {
    PasswordGrantRequest {
        email: email.to_string(),
        password: PASSWORD.to_string(),
        scope: None,
        client_ip: Some("10.20.30.40".to_string()),
        user_agent: Some("Chrome/125.0".to_string()),
    }
}

fn step_up(email: &str, mfa_code: String) -> StepUpMfaGrantRequest {
    StepUpMfaGrantRequest {
        email: email.to_string(),
        password: PASSWORD.to_string(),
        mfa_code,
        scope: None,
        client_ip: Some("10.20.30.40".to_string()),
        user_agent: Some("Chrome/125.0".to_string()),
        dpop_jkt: None,
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_secs()
}

/// Computes a TOTP code using RFC 6238 HOTP (SHA-1).
fn compute_totp_code(secret_base32: &str, unix_secs: u64) -> String {
    let secret_bytes = data_encoding::BASE32_NOPAD
        .decode(secret_base32.as_bytes())
        .expect("decode base32");
    let step = unix_secs / 30;
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &secret_bytes);
    let msg = step.to_be_bytes();
    let tag = ring::hmac::sign(&key, &msg);
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

/// Creates a realm and a password user in it.
fn realm_and_user(h: &common::TestHarness, prefix: &str) -> (RealmId, User) {
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("{prefix}-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");
    let user = h
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("{prefix}-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Step-up User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    h.identity()
        .set_password(
            realm.id(),
            user.id(),
            &CleartextPassword::from_string(PASSWORD.to_string()),
        )
        .expect("set password");
    (realm.id().clone(), user)
}

/// Enrols and verifies TOTP for `user`; returns the base32 secret.
fn enrol_totp(h: &common::TestHarness, realm: &RealmId, user: &User) -> String {
    let enrollment = h
        .identity()
        .enroll_totp(realm, user.id())
        .expect("enroll totp");
    let code = compute_totp_code(&enrollment.secret_base32, now_secs());
    h.identity()
        .verify_totp_enrollment(realm, user.id(), &code)
        .expect("verify enrollment");
    enrollment.secret_base32
}

/// A code for the next TOTP step, so it is not rejected as a replay of the
/// enrolment-verification code, which consumed the current step.
fn next_step_code(secret_base32: &str) -> String {
    compute_totp_code(secret_base32, now_secs() + 30)
}

// ──────────────────────────────────────────────────────────────
// Control: no second factor → the password grant issues tokens
// ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn password_grant_without_a_second_factor_issues_tokens() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm, user) = realm_and_user(&h, "stepup-nofactor");

    let response = h
        .identity()
        .password_grant_token(&realm, &ropc(user.email()))
        .expect("a user with no second factor and no mfa_required gets tokens");
    assert!(
        !response.access_token.is_empty(),
        "access token must be non-empty"
    );
}

// ──────────────────────────────────────────────────────────────
// BLK-1: Step-up completion grant issues tokens
// ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn step_up_completion_issues_token() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm, user) = realm_and_user(&h, "stepup-complete");
    let secret = enrol_totp(&h, &realm, &user);

    // A password grant for a user holding TOTP is sent to step-up.
    let err = h
        .identity()
        .password_grant_token(&realm, &ropc(user.email()))
        .expect_err("a user holding TOTP must be sent to step-up");
    assert!(
        matches!(err, IdentityError::StepUpChallengeRequired),
        "expected StepUpChallengeRequired, got: {err:?}"
    );

    // Complete the step-up with the correct MFA code.
    let response = h
        .identity()
        .step_up_mfa_grant_token(&realm, &step_up(user.email(), next_step_code(&secret)))
        .expect("step-up completion must succeed with correct MFA code");
    assert!(
        !response.access_token().is_empty(),
        "access token must be non-empty"
    );

    // Completing a step-up once does not waive the factor (GA audit B4/B5):
    // the next password-only grant is sent back to step-up.
    let second_login = h
        .identity()
        .password_grant_token(&realm, &ropc(user.email()))
        .expect_err("a user holding TOTP must prove it on every password grant");
    assert!(
        matches!(second_login, IdentityError::StepUpChallengeRequired),
        "expected StepUpChallengeRequired, got: {second_login:?}"
    );
}

#[tokio::test]
async fn step_up_completion_rejects_wrong_mfa_code() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm, user) = realm_and_user(&h, "stepup-reject");
    enrol_totp(&h, &realm, &user);

    let err = h
        .identity()
        .step_up_mfa_grant_token(&realm, &step_up(user.email(), "000000".to_string()))
        .expect_err("wrong MFA code must be rejected");
    assert!(
        matches!(err, IdentityError::InvalidMfaCode),
        "expected InvalidMfaCode, got: {err:?}"
    );
}

// ──────────────────────────────────────────────────────────────
// INFO-1: step_up_mfa_grant_token emits StepUpMfaCompleted audit event
// ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn step_up_completion_emits_audit_event() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let (realm, user) = realm_and_user(&h, "stepup-completeaudit");
    let secret = enrol_totp(&h, &realm, &user);

    h.identity()
        .step_up_mfa_grant_token(&realm, &step_up(user.email(), next_step_code(&secret)))
        .expect("step-up completion must succeed");

    let mut query = AuditQuery::for_realm(realm.clone());
    query.action = Some(AuditAction::StepUpMfaCompleted);
    let events = h.audit().query(&query).expect("query audit");
    assert!(
        !events.is_empty(),
        "StepUpMfaCompleted audit event must be emitted on successful step-up completion"
    );
}
