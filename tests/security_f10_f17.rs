//! Adversarial and behavioral tests for HEA-1371 security hardening.
//!
//! Covers findings F10–F17 (Low severity) from the HEA-1363 audit.

mod common;

use std::sync::Arc;

use hearth::core::RealmId;
use hearth::identity::{CleartextPassword, CreateRealmRequest, CreateUserRequest};

fn create_realm(harness: &common::TestHarness) -> RealmId {
    harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("sec-test-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm")
        .id()
        .clone()
}

// ===== F10: Magic-link single-use TOCTOU =====
//
// Two concurrent `validate_magic_link` calls for the same token must not both
// succeed. The per-token lock ensures exactly one redemption.

#[tokio::test]
async fn f10_magic_link_single_use_concurrent() {
    let harness = Arc::new(
        common::TestHarness::embedded()
            .await
            .expect("harness setup"),
    );
    let realm = create_realm(&harness);
    let email = format!("ml-concurrent-{}@example.com", uuid::Uuid::new_v4());
    harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: email.clone(),
                display_name: "User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let response = harness
        .identity()
        .request_magic_link(&realm, &email)
        .expect("request_magic_link");
    let token = response.token().to_string();

    let h1 = Arc::clone(&harness);
    let h2 = Arc::clone(&harness);
    let r1 = realm.clone();
    let r2 = realm.clone();
    let t1 = token.clone();
    let t2 = token.clone();

    let (res1, res2) = tokio::join!(
        tokio::task::spawn_blocking(move || h1.identity().validate_magic_link(&r1, &t1)),
        tokio::task::spawn_blocking(move || h2.identity().validate_magic_link(&r2, &t2)),
    );

    let ok1 = res1.expect("join1").is_ok();
    let ok2 = res2.expect("join2").is_ok();

    // Exactly one should succeed; both succeeding would be a TOCTOU bug.
    assert_ne!(ok1, ok2, "exactly one concurrent redemption must succeed");
}

// ===== F10: Password-reset token single-use under sequential calls =====
//
// A password-reset token used once should be rejected on a second attempt.

#[tokio::test]
async fn f10_password_reset_token_single_use() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = create_realm(&harness);
    let email = format!("reset-single-{}@example.com", uuid::Uuid::new_v4());
    let user = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: email.clone(),
                display_name: "Reset User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");
    harness
        .identity()
        .set_password(
            &realm,
            user.id(),
            &CleartextPassword::from_string("OldPassword123!".to_string()),
        )
        .expect("set password");

    let Some(token) = harness
        .identity()
        .request_password_reset(&realm, &email)
        .expect("request_password_reset")
    else {
        panic!("should return a token for a known email");
    };

    let new_pw = CleartextPassword::from_string("NewPassword456!".to_string());
    let new_pw2 = CleartextPassword::from_string("AnotherPw789!".to_string());

    // First use: should succeed
    harness
        .identity()
        .reset_password_with_token(&realm, &token, &new_pw)
        .expect("first reset should succeed");

    // Second use: same token must be rejected
    let err = harness
        .identity()
        .reset_password_with_token(&realm, &token, &new_pw2)
        .expect_err("second reset must fail");
    assert!(
        matches!(
            err,
            hearth::identity::IdentityError::PasswordResetTokenInvalid
        ),
        "expected PasswordResetTokenInvalid, got: {err:?}"
    );
}

// ===== F11: TOTP constant-time comparison =====
//
// Verifies that wrong TOTP codes are rejected. The ct_eq change is structural;
// we confirm the correct behavioral outcome: bad codes are rejected.
// (Side-channel timing cannot be proven in unit tests.)

#[tokio::test]
async fn f11_totp_wrong_code_rejected() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");
    let realm = create_realm(&harness);
    let email = format!("totp-ct-{}@example.com", uuid::Uuid::new_v4());
    let user = harness
        .identity()
        .create_user(
            &realm,
            &CreateUserRequest {
                email: email.clone(),
                display_name: "TOTP User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let _enrollment = harness
        .identity()
        .enroll_totp(&realm, user.id())
        .expect("enroll_totp");

    // An all-zeros code that is almost certainly not the current TOTP must be rejected.
    let bad_code = "000000";
    let result = harness
        .identity()
        .verify_totp_enrollment(&realm, user.id(), bad_code);
    assert!(
        result.is_err(),
        "all-zeros code must not pass enrollment verification"
    );
}

// ===== F15: Browser-login timing parity via dummy_verify_password =====
//
// `dummy_verify_password` must be callable without error. The behavioral
// guarantee is that the nonexistent-user path runs the same Argon2 work as
// the wrong-password path.

#[tokio::test]
async fn f15_dummy_verify_password_runs_without_error() {
    let harness = common::TestHarness::embedded()
        .await
        .expect("harness setup");

    let password = CleartextPassword::from_string("anything".to_string());
    // Must not panic; result is intentionally discarded.
    harness.identity().dummy_verify_password(&password);
}
