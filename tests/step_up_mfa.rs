//! Integration tests for adaptive step-up MFA via the ROPC / password-grant
//! flow (HEA-836).
//!
//! These tests exercise the `password_grant_token` path end-to-end, verifying
//! that the step-up gate fires at the right points, injects the right errors,
//! and emits the expected audit events.
//!
//! For unit-level fingerprint-store tests see `tests/device_fingerprint.rs`.

mod common;

use std::time::{SystemTime, UNIX_EPOCH};

use hearth::audit::{AuditAction, AuditQuery};
use hearth::identity::{
    AdaptiveMfaConfig, CleartextPassword, CreateRealmRequest, CreateUserRequest, IdentityError,
    PasswordGrantRequest, RealmConfig, RequiredAction, StepUpMfaGrantRequest,
};

// ──────────────────────────────────────────────────────────────
// Shared helpers
// ──────────────────────────────────────────────────────────────

const PASSWORD: &str = "S3cur3P@ss!";

fn realm_cfg_with_adaptive(enabled: bool, secret: &str, window_days: u32) -> RealmConfig {
    RealmConfig {
        adaptive_mfa: AdaptiveMfaConfig {
            enabled,
            recognition_window_days: window_days,
            fingerprint_hmac_secret: secret.to_string(),
        },
        ..RealmConfig::default()
    }
}

fn ropc(email: &str, ip: &str, ua: &str) -> PasswordGrantRequest {
    PasswordGrantRequest {
        email: email.to_string(),
        password: PASSWORD.to_string(),
        scope: None,
        client_ip: Some(ip.to_string()),
        user_agent: Some(ua.to_string()),
    }
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

// ──────────────────────────────────────────────────────────────
// AC-6: Disabled adaptive MFA → tokens issued without step-up
// ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn adaptive_mfa_disabled_issues_token_normally() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("stepup-disabled-{}", uuid::Uuid::new_v4()),
            config: Some(realm_cfg_with_adaptive(false, "irrelevant-secret", 30)),
        })
        .expect("create realm");
    let user = h
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("disabled-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Disabled MFA User".to_string(),
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

    let result = h
        .identity()
        .password_grant_token(realm.id(), &ropc(user.email(), "10.0.0.1", "UA/1"));
    assert!(
        result.is_ok(),
        "disabled adaptive MFA must not block login; got: {result:?}"
    );
}

// ──────────────────────────────────────────────────────────────
// AC-7: Empty HMAC secret → treated as disabled (fail-safe)
// ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn empty_hmac_secret_is_a_hard_config_error() {
    // BLK-2: enabled=true with empty secret must be a hard error (fail-secure),
    // not silently skip the check (fail-open).
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("stepup-emptysecret-{}", uuid::Uuid::new_v4()),
            config: Some(realm_cfg_with_adaptive(true, "", 30)),
        })
        .expect("create realm");
    let user = h
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("emptysecret-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Empty Secret User".to_string(),
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

    let err = h
        .identity()
        .password_grant_token(
            realm.id(),
            &ropc(user.email(), "192.168.1.55", "Mozilla/5.0"),
        )
        .expect_err("enabled=true with empty secret must return an error");
    assert!(
        matches!(err, IdentityError::Internal { .. }),
        "expected Internal config error, got: {err:?}"
    );
}

// ──────────────────────────────────────────────────────────────
// AC-8: Recognised device → token issued without challenge
// ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn recognised_device_issues_token_without_challenge() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let secret = "recognised-device-secret-32bytes!";
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("stepup-recognised-{}", uuid::Uuid::new_v4()),
            config: Some(realm_cfg_with_adaptive(true, secret, 30)),
        })
        .expect("create realm");
    let user = h
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("recognised-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Recognised User".to_string(),
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

    let ip = "10.1.2.50";
    let ua = "Mozilla/5.0 Chrome/125.0.0.0";

    // Pre-seed: mark the device as trusted by recording its fingerprint.
    h.identity()
        .record_device_fingerprint(realm.id(), user.id(), ip, ua)
        .expect("pre-seed device fingerprint");

    let result = h
        .identity()
        .password_grant_token(realm.id(), &ropc(user.email(), ip, ua));
    assert!(
        result.is_ok(),
        "pre-seeded device must bypass step-up; got: {result:?}"
    );
}

// ──────────────────────────────────────────────────────────────
// AC-9: Unrecognised device + enrolled TOTP → StepUpChallengeRequired
// ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn unrecognised_device_with_enrolled_totp_returns_step_up_challenge() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let secret = "totp-stepup-secret-32-bytes-exact";
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("stepup-totp-{}", uuid::Uuid::new_v4()),
            config: Some(realm_cfg_with_adaptive(true, secret, 30)),
        })
        .expect("create realm");
    let user = h
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("totp-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "TOTP User".to_string(),
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

    // Fully enroll TOTP (pending → active).
    let enrollment = h
        .identity()
        .enroll_totp(realm.id(), user.id())
        .expect("enroll totp");
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_secs();
    let code = compute_totp_code(&enrollment.secret_base32, now_secs);
    h.identity()
        .verify_totp_enrollment(realm.id(), user.id(), &code)
        .expect("verify enrollment");

    let err = h
        .identity()
        .password_grant_token(realm.id(), &ropc(user.email(), "172.16.0.1", "Mozilla/5.0"))
        .expect_err("unrecognised device + TOTP must require step-up");
    assert!(
        matches!(err, IdentityError::StepUpChallengeRequired),
        "expected StepUpChallengeRequired, got: {err:?}"
    );
}

// ──────────────────────────────────────────────────────────────
// AC-10: Unrecognised device + no enrolled factor → EnrollMfaRequired
// ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn unrecognised_device_no_factor_returns_enroll_mfa_required() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let secret = "enroll-required-secret-32-bytes-0";
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("stepup-nofactor-{}", uuid::Uuid::new_v4()),
            config: Some(realm_cfg_with_adaptive(true, secret, 30)),
        })
        .expect("create realm");
    let user = h
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("nofactor-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "No Factor User".to_string(),
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

    let err = h
        .identity()
        .password_grant_token(realm.id(), &ropc(user.email(), "192.0.2.1", "Mozilla/5.0"))
        .expect_err("unrecognised device without MFA must require enrollment");
    assert!(
        matches!(err, IdentityError::EnrollMfaRequired),
        "expected EnrollMfaRequired, got: {err:?}"
    );
}

// ──────────────────────────────────────────────────────────────
// AC-11: Unrecognised device injects EnrollMfa required action on user record
// ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn unrecognised_device_injects_enroll_mfa_required_action() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let secret = "enroll-inject-secret-32-bytes-01!";
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("stepup-inject-{}", uuid::Uuid::new_v4()),
            config: Some(realm_cfg_with_adaptive(true, secret, 30)),
        })
        .expect("create realm");
    let user = h
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("inject-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Inject Action User".to_string(),
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

    // Trigger EnrollMfaRequired — ignore the error.
    let _ = h
        .identity()
        .password_grant_token(realm.id(), &ropc(user.email(), "192.0.2.5", "Mozilla/5.0"));

    let updated = h
        .identity()
        .get_user(realm.id(), user.id())
        .expect("get_user ok")
        .expect("user exists");
    assert!(
        updated
            .required_actions()
            .contains(&RequiredAction::EnrollMfa),
        "EnrollMfa must be injected into required_actions; got: {:?}",
        updated.required_actions()
    );
}

// ──────────────────────────────────────────────────────────────
// Adversarial: different /24 subnet → new fingerprint, step-up triggered
// ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn different_subnet_produces_different_fingerprint_and_triggers_step_up() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let secret = "adversarial-subnet-secret-32bytes";
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("stepup-subnet-{}", uuid::Uuid::new_v4()),
            config: Some(realm_cfg_with_adaptive(true, secret, 30)),
        })
        .expect("create realm");
    let user = h
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("subnet-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Subnet Adversary".to_string(),
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

    // Pre-seed fingerprint for subnet A (10.0.1.x).
    h.identity()
        .record_device_fingerprint(realm.id(), user.id(), "10.0.1.50", "Mozilla/5.0 Chrome/125")
        .expect("pre-seed subnet A");

    // Login from subnet B (10.0.2.x) — unrecognised, should trigger step-up.
    let err = h
        .identity()
        .password_grant_token(
            realm.id(),
            &ropc(user.email(), "10.0.2.50", "Mozilla/5.0 Chrome/125"),
        )
        .expect_err("subnet B must not be recognised from subnet A seed");
    assert!(
        matches!(
            err,
            IdentityError::StepUpChallengeRequired | IdentityError::EnrollMfaRequired
        ),
        "expected step-up from unrecognised subnet B; got: {err:?}"
    );
}

// ──────────────────────────────────────────────────────────────
// StepUpMfaTriggered audit event emitted on unrecognised device
// ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn step_up_emits_audit_event() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let secret = "audit-event-secret-32-bytes-exact";
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("stepup-audit-{}", uuid::Uuid::new_v4()),
            config: Some(realm_cfg_with_adaptive(true, secret, 30)),
        })
        .expect("create realm");
    let user = h
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("audit-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Audit User".to_string(),
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

    // Trigger step-up (unrecognised device, no factor).
    let _ = h.identity().password_grant_token(
        realm.id(),
        &ropc(user.email(), "10.10.10.10", "Mozilla/5.0"),
    );

    let mut query = AuditQuery::for_realm(realm.id().clone());
    query.action = Some(AuditAction::StepUpMfaTriggered);
    let events = h.audit().query(&query).expect("query audit");
    assert!(
        !events.is_empty(),
        "StepUpMfaTriggered audit event must be emitted on unrecognised device"
    );
}

// ──────────────────────────────────────────────────────────────
// BLK-1: Step-up completion grant issues tokens and records device
// ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn step_up_completion_issues_token_and_records_device() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let secret = "step-up-complete-secret-32bytes!";
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("stepup-complete-{}", uuid::Uuid::new_v4()),
            config: Some(realm_cfg_with_adaptive(true, secret, 30)),
        })
        .expect("create realm");
    let user = h
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("complete-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Completion User".to_string(),
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

    // Enroll TOTP.
    let enrollment = h
        .identity()
        .enroll_totp(realm.id(), user.id())
        .expect("enroll totp");
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_secs();
    let code = compute_totp_code(&enrollment.secret_base32, now_secs);
    h.identity()
        .verify_totp_enrollment(realm.id(), user.id(), &code)
        .expect("verify enrollment");

    // Confirm initial login from unrecognised device triggers step-up.
    let err = h
        .identity()
        .password_grant_token(
            realm.id(),
            &ropc(user.email(), "10.20.30.40", "Chrome/125.0"),
        )
        .expect_err("unrecognised device must trigger step-up");
    assert!(
        matches!(err, IdentityError::StepUpChallengeRequired),
        "expected StepUpChallengeRequired, got: {err:?}"
    );

    // Complete the step-up with correct MFA code.
    // Use now_secs + 30 (next TOTP step) so the code isn't rejected as a replay
    // of the enrollment-verification step which also consumed the current step.
    let now_secs2 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_secs();
    let mfa_code = compute_totp_code(&enrollment.secret_base32, now_secs2 + 30);
    let response = h
        .identity()
        .step_up_mfa_grant_token(
            realm.id(),
            &StepUpMfaGrantRequest {
                email: user.email().to_string(),
                password: PASSWORD.to_string(),
                mfa_code,
                scope: None,
                client_ip: Some("10.20.30.40".to_string()),
                user_agent: Some("Chrome/125.0".to_string()),
            },
        )
        .expect("step-up completion must succeed with correct MFA code");

    assert!(
        !response.access_token().is_empty(),
        "access token must be non-empty"
    );

    // Subsequent login from the same device must be recognised without step-up.
    let second_login = h.identity().password_grant_token(
        realm.id(),
        &ropc(user.email(), "10.20.30.40", "Chrome/125.0"),
    );
    assert!(
        second_login.is_ok(),
        "device must be recognised after step-up completion; got: {second_login:?}"
    );
}

#[tokio::test]
async fn step_up_completion_rejects_wrong_mfa_code() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let secret = "step-up-reject-secret-32-bytes-0";
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("stepup-reject-{}", uuid::Uuid::new_v4()),
            config: Some(realm_cfg_with_adaptive(true, secret, 30)),
        })
        .expect("create realm");
    let user = h
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("reject-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Reject User".to_string(),
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

    // Enroll TOTP.
    let enrollment = h
        .identity()
        .enroll_totp(realm.id(), user.id())
        .expect("enroll totp");
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_secs();
    let code = compute_totp_code(&enrollment.secret_base32, now_secs);
    h.identity()
        .verify_totp_enrollment(realm.id(), user.id(), &code)
        .expect("verify enrollment");

    let err = h
        .identity()
        .step_up_mfa_grant_token(
            realm.id(),
            &StepUpMfaGrantRequest {
                email: user.email().to_string(),
                password: PASSWORD.to_string(),
                mfa_code: "000000".to_string(), // wrong code
                scope: None,
                client_ip: Some("10.20.30.40".to_string()),
                user_agent: Some("Firefox/109.0".to_string()),
            },
        )
        .expect_err("wrong MFA code must be rejected");
    assert!(
        matches!(err, IdentityError::InvalidMfaCode),
        "expected InvalidMfaCode, got: {err:?}"
    );
}

// ──────────────────────────────────────────────────────────────
// HIGH-2: UA normalisation — minor update must NOT retrigger step-up
// ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn minor_ua_update_does_not_retrigger_step_up() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let secret = "ua-minor-update-secret-32-bytes-!";
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("stepup-uaminor-{}", uuid::Uuid::new_v4()),
            config: Some(realm_cfg_with_adaptive(true, secret, 30)),
        })
        .expect("create realm");
    let user = h
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("uaminor-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "UA Minor User".to_string(),
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

    // Enroll TOTP so step-up returns StepUpChallengeRequired (not EnrollMfaRequired).
    let enrollment = h
        .identity()
        .enroll_totp(realm.id(), user.id())
        .expect("enroll totp");
    let enroll_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_secs();
    let enroll_code = compute_totp_code(&enrollment.secret_base32, enroll_secs);
    h.identity()
        .verify_totp_enrollment(realm.id(), user.id(), &enroll_code)
        .expect("verify enrollment");

    // Use step_up_mfa_grant_token to establish the fingerprint for Chrome/125.
    // Use next TOTP step (+30s) to avoid replay of the enrollment-verification step.
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_secs();
    let mfa_code = compute_totp_code(&enrollment.secret_base32, now_secs + 30);
    h.identity()
        .step_up_mfa_grant_token(
            realm.id(),
            &StepUpMfaGrantRequest {
                email: user.email().to_string(),
                password: PASSWORD.to_string(),
                mfa_code,
                scope: None,
                client_ip: Some("10.0.0.1".to_string()),
                user_agent: Some("Mozilla/5.0 Chrome/125.0.6422.112".to_string()),
            },
        )
        .expect("step-up completion must record Chrome/125 fingerprint");

    // Second login with a minor version bump — same major, should still be recognised.
    let second = h.identity().password_grant_token(
        realm.id(),
        &ropc(user.email(), "10.0.0.1", "Mozilla/5.0 Chrome/125.0.9999.0"),
    );
    assert!(
        second.is_ok(),
        "minor UA update must NOT trigger step-up (same major version); got: {second:?}"
    );
}

#[tokio::test]
async fn major_ua_update_triggers_step_up() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let secret = "ua-major-update-secret-32-bytes-!";
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("stepup-uamajor-{}", uuid::Uuid::new_v4()),
            config: Some(realm_cfg_with_adaptive(true, secret, 30)),
        })
        .expect("create realm");
    let user = h
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("uamajor-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "UA Major User".to_string(),
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

    // Enroll TOTP so step-up returns StepUpChallengeRequired (not EnrollMfaRequired).
    let enrollment = h
        .identity()
        .enroll_totp(realm.id(), user.id())
        .expect("enroll totp");
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_secs();
    let code = compute_totp_code(&enrollment.secret_base32, now_secs);
    h.identity()
        .verify_totp_enrollment(realm.id(), user.id(), &code)
        .expect("verify enrollment");

    // First login — establishes fingerprint for Chrome/125.
    // This device is NOT recognised yet, so expect StepUpChallengeRequired.
    // We use step_up_mfa_grant_token to complete it and record the fingerprint.
    // Use now + 30 to get the next TOTP step so it isn't rejected as a replay
    // of the enrollment-verification step that already consumed the current step.
    let now_secs2 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_secs();
    let mfa_code = compute_totp_code(&enrollment.secret_base32, now_secs2 + 30);
    h.identity()
        .step_up_mfa_grant_token(
            realm.id(),
            &StepUpMfaGrantRequest {
                email: user.email().to_string(),
                password: PASSWORD.to_string(),
                mfa_code,
                scope: None,
                client_ip: Some("10.0.0.5".to_string()),
                user_agent: Some("Mozilla/5.0 Chrome/125.0.0.0".to_string()),
            },
        )
        .expect("step-up completion with Chrome/125 must succeed");

    // Confirm same major is recognised.
    let same_major = h.identity().password_grant_token(
        realm.id(),
        &ropc(user.email(), "10.0.0.5", "Mozilla/5.0 Chrome/125.0.9999.0"),
    );
    assert!(
        same_major.is_ok(),
        "same major version must be recognised; got: {same_major:?}"
    );

    // Login with Chrome/126 (major bump) — must trigger step-up again.
    let major_bump = h
        .identity()
        .password_grant_token(
            realm.id(),
            &ropc(user.email(), "10.0.0.5", "Mozilla/5.0 Chrome/126.0.0.0"),
        )
        .expect_err("major UA update must trigger step-up");
    assert!(
        matches!(major_bump, IdentityError::StepUpChallengeRequired),
        "expected StepUpChallengeRequired on major UA bump, got: {major_bump:?}"
    );
}

// ──────────────────────────────────────────────────────────────
// INFO-1: step_up_mfa_grant_token emits StepUpMfaCompleted audit event
// ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn step_up_completion_emits_audit_event() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let secret = "step-up-completed-audit-32bytes!!";
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("stepup-completeaudit-{}", uuid::Uuid::new_v4()),
            config: Some(realm_cfg_with_adaptive(true, secret, 30)),
        })
        .expect("create realm");
    let user = h
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("completeaudit-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Completion Audit User".to_string(),
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

    // Enroll TOTP so step-up can be completed.
    let enrollment = h
        .identity()
        .enroll_totp(realm.id(), user.id())
        .expect("enroll totp");
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_secs();
    let code = compute_totp_code(&enrollment.secret_base32, now_secs);
    h.identity()
        .verify_totp_enrollment(realm.id(), user.id(), &code)
        .expect("verify enrollment");

    // Complete the step-up MFA challenge.
    let now_secs2 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_secs();
    let mfa_code = compute_totp_code(&enrollment.secret_base32, now_secs2 + 30);
    h.identity()
        .step_up_mfa_grant_token(
            realm.id(),
            &StepUpMfaGrantRequest {
                email: user.email().to_string(),
                password: PASSWORD.to_string(),
                mfa_code,
                scope: None,
                client_ip: Some("10.30.40.50".to_string()),
                user_agent: Some("Firefox/127.0".to_string()),
            },
        )
        .expect("step-up completion must succeed");

    // StepUpMfaCompleted must be emitted.
    let mut query = AuditQuery::for_realm(realm.id().clone());
    query.action = Some(AuditAction::StepUpMfaCompleted);
    let events = h.audit().query(&query).expect("query audit");
    assert!(
        !events.is_empty(),
        "StepUpMfaCompleted audit event must be emitted on successful step-up completion"
    );
}

// ──────────────────────────────────────────────────────────────
// LOW-1: HMAC secret shorter than 32 bytes is a hard config error
// ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn short_hmac_secret_is_a_hard_config_error() {
    // NIST SP 800-107: HMAC keys must be ≥ hash output length (32 bytes for SHA-256).
    // A secret shorter than 32 bytes must be rejected fail-secure (not silently skipped).
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("stepup-shortkey-{}", uuid::Uuid::new_v4()),
            config: Some(realm_cfg_with_adaptive(true, "tooshort", 30)),
        })
        .expect("create realm");
    let user = h
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("shortkey-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Short Key User".to_string(),
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

    let err = h
        .identity()
        .password_grant_token(
            realm.id(),
            &ropc(user.email(), "192.168.1.1", "Mozilla/5.0"),
        )
        .expect_err("enabled=true with short secret must return an error");
    assert!(
        matches!(err, IdentityError::Internal { .. }),
        "expected Internal config error for short HMAC secret, got: {err:?}"
    );
}
