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
    PasswordGrantRequest, RealmConfig, RequiredAction,
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
async fn empty_hmac_secret_treated_as_disabled() {
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

    let result = h.identity().password_grant_token(
        realm.id(),
        &ropc(user.email(), "192.168.1.55", "Mozilla/5.0"),
    );
    assert!(
        result.is_ok(),
        "empty HMAC secret must behave like disabled; got: {result:?}"
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
