//! Integration tests for `mfa_required` gating **factor use**, not factor
//! enrolment (production-readiness audit 2026-08-28 §4.18#3, task 9.6).
//!
//! Before this change the engine gate asked "does this user have a factor
//! enrolled?". Any login path that never ran a challenge — federation, ROPC,
//! the device grant — therefore issued a session to an MFA-required user on the
//! strength of the enrolment alone. The gate now asks "was a second factor
//! proved in this authentication?", carried by [`SessionContext::mfa_proof`].

mod common;

use std::time::{SystemTime, UNIX_EPOCH};

use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, IdentityError, MfaProof,
    PasswordGrantRequest, RealmConfig, SessionContext, StepUpMfaGrantRequest,
};

const PASSWORD: &str = "S3cur3P@ss!1";

/// Computes an RFC 6238 TOTP code (SHA-1, 30-second step).
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

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_secs()
}

/// A realm with `mfa_required: true`, plus a user who holds a password.
async fn mfa_realm_and_user(
    label: &str,
) -> (
    common::TestHarness,
    hearth::identity::Realm,
    hearth::identity::User,
) {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("{label}-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                mfa_required: Some(true),
                ..RealmConfig::default()
            }),
        })
        .expect("create realm");
    let user = h
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("u-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "MFA User".to_string(),
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
    (h, realm, user)
}

/// Fully enrols TOTP (pending → active) and returns the base32 secret.
fn enrol_totp(
    h: &common::TestHarness,
    realm: &hearth::identity::Realm,
    user_id: &hearth::core::UserId,
) -> String {
    let enrollment = h
        .identity()
        .enroll_totp(realm.id(), user_id)
        .expect("enroll_totp");
    let code = compute_totp_code(&enrollment.secret_base32, now_secs());
    h.identity()
        .verify_totp_enrollment(realm.id(), user_id, &code)
        .expect("verify_totp_enrollment");
    enrollment.secret_base32.clone()
}

// ─── the engine gate ────────────────────────────────────────────────────────

/// An enrolled factor that was never used must not open a session. This is the
/// federation and device-grant bypass: both call `create_session` with a
/// default context after proving only the first factor.
#[tokio::test]
async fn create_session_refuses_an_enrolled_but_unused_factor() {
    let (h, realm, user) = mfa_realm_and_user("mfa-use-gate").await;
    enrol_totp(&h, &realm, user.id());

    let err = h
        .identity()
        .create_session(realm.id(), user.id(), &SessionContext::default())
        .expect_err("an unused factor must not satisfy mfa_required");
    assert!(
        matches!(err, IdentityError::MfaRequired),
        "expected MfaRequired, got: {err:?}"
    );
}

/// A context that proves a factor was used opens the session.
#[tokio::test]
async fn create_session_accepts_a_proved_factor() {
    let (h, realm, user) = mfa_realm_and_user("mfa-use-proved").await;
    enrol_totp(&h, &realm, user.id());

    let ctx = SessionContext {
        mfa_proof: MfaProof::Proved,
        ..SessionContext::default()
    };
    h.identity()
        .create_session(realm.id(), user.id(), &ctx)
        .expect("a proved second factor must open the session");
}

/// A session derived from an earlier authentication that already passed the
/// gate — an authorization code, a device code, a completed required action —
/// opens without re-proving the factor.
#[tokio::test]
async fn create_session_accepts_an_inherited_proof() {
    let (h, realm, user) = mfa_realm_and_user("mfa-use-inherited").await;
    enrol_totp(&h, &realm, user.id());

    let ctx = SessionContext {
        mfa_proof: MfaProof::Inherited,
        ..SessionContext::default()
    };
    h.identity()
        .create_session(realm.id(), user.id(), &ctx)
        .expect("an inherited proof must open the session");
}

/// A realm that does not require MFA is untouched by the gate.
#[tokio::test]
async fn create_session_is_unchanged_when_the_realm_does_not_require_mfa() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("mfa-off-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");
    let user = h
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("u-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Plain User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    h.identity()
        .create_session(realm.id(), user.id(), &SessionContext::default())
        .expect("no MFA policy means no gate");
}

// ─── ROPC ───────────────────────────────────────────────────────────────────

/// ROPC never runs a challenge. With an enrolled factor it must ask the client
/// to come back through the step-up MFA grant.
#[tokio::test]
async fn ropc_demands_the_second_factor_when_the_realm_requires_mfa() {
    let (h, realm, user) = mfa_realm_and_user("mfa-use-ropc").await;
    enrol_totp(&h, &realm, user.id());

    let err = h
        .identity()
        .password_grant_token(
            realm.id(),
            &PasswordGrantRequest {
                email: user.email().to_string(),
                password: PASSWORD.to_string(),
                scope: None,
                client_ip: Some("10.1.2.3".to_string()),
                user_agent: Some("UA/1".to_string()),
            },
        )
        .expect_err("ROPC must not issue tokens without the second factor");
    assert!(
        matches!(err, IdentityError::StepUpChallengeRequired),
        "expected StepUpChallengeRequired, got: {err:?}"
    );
}

/// ROPC for an MFA-required user who has no factor at all must send them to
/// enrolment, not issue tokens.
#[tokio::test]
async fn ropc_demands_enrolment_when_the_user_has_no_factor() {
    let (h, realm, user) = mfa_realm_and_user("mfa-use-ropc-nofactor").await;

    let err = h
        .identity()
        .password_grant_token(
            realm.id(),
            &PasswordGrantRequest {
                email: user.email().to_string(),
                password: PASSWORD.to_string(),
                scope: None,
                client_ip: Some("10.1.2.4".to_string()),
                user_agent: Some("UA/1".to_string()),
            },
        )
        .expect_err("ROPC must not issue tokens to an MFA-required user with no factor");
    assert!(
        matches!(err, IdentityError::EnrollMfaRequired),
        "expected EnrollMfaRequired, got: {err:?}"
    );
}

/// The step-up MFA grant verifies a TOTP code, so it still issues tokens on an
/// MFA-required realm. This guards the fix against over-blocking.
#[tokio::test]
async fn step_up_mfa_grant_still_issues_tokens_when_the_realm_requires_mfa() {
    let (h, realm, user) = mfa_realm_and_user("mfa-use-stepup").await;
    let secret = enrol_totp(&h, &realm, user.id());

    // A fresh time step avoids the replay guard tripping on the enrolment code.
    let code = compute_totp_code(&secret, now_secs() + 30);
    h.identity()
        .step_up_mfa_grant_token(
            realm.id(),
            &StepUpMfaGrantRequest {
                email: user.email().to_string(),
                password: PASSWORD.to_string(),
                mfa_code: code,
                scope: None,
                client_ip: Some("10.1.2.5".to_string()),
                user_agent: Some("UA/1".to_string()),
            },
        )
        .expect("a verified TOTP code must issue tokens");
}
