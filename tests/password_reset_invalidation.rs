//! A password-reset token must die when something supersedes it
//! (audit 2026-08-28 §4.24#1).
//!
//! The stored reset record only carried `used` and `created_at_micros`, so a
//! link stayed live after the account's email changed, after the password was
//! changed out of band, and after a newer reset link was issued. All three
//! leave a stale link that still takes over the account.
//!
//! The last test guards the opposite direction: a reset the password policy
//! rejects must NOT burn the token, or one typo strands the user.

mod common;

use hearth::core::{RealmId, UserId};
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, IdentityError, PasswordPolicy,
    RealmConfig, UpdateUserRequest,
};

const GOOD_PASSWORD: &str = "correct-horse-battery-staple-42";
const OTHER_PASSWORD: &str = "another-correct-horse-battery-77";

fn create_realm(harness: &common::TestHarness, policy: Option<PasswordPolicy>) -> RealmId {
    harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("reset-inval-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                password_policy: policy,
                ..RealmConfig::default()
            }),
        })
        .expect("create realm")
        .id()
        .clone()
}

fn create_user(harness: &common::TestHarness, realm: &RealmId, email: &str) -> UserId {
    let user = harness
        .identity()
        .create_user(
            realm,
            &CreateUserRequest {
                email: email.to_string(),
                display_name: "Reset Test User".to_string(),
                ..CreateUserRequest::default()
            },
        )
        .expect("create user");
    harness
        .identity()
        .set_password(
            realm,
            user.id(),
            &CleartextPassword::from_string(GOOD_PASSWORD.to_string()),
        )
        .expect("set initial password");
    user.id().clone()
}

fn assert_token_invalid(err: &IdentityError, what: &str) {
    assert!(
        matches!(err, IdentityError::PasswordResetTokenInvalid),
        "{what} must return PasswordResetTokenInvalid, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// The account email changes after the reset is requested
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reset_token_dies_when_the_account_email_changes() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm(&harness, None);
    let email = format!("before-{}@example.com", uuid::Uuid::new_v4());
    let user = create_user(&harness, &realm, &email);

    let token = harness
        .identity()
        .request_password_reset(&realm, &email)
        .expect("request reset")
        .expect("token issued");

    harness
        .identity()
        .update_user(
            &realm,
            &user,
            &UpdateUserRequest {
                email: Some(format!("after-{}@example.com", uuid::Uuid::new_v4())),
                ..UpdateUserRequest::default()
            },
        )
        .expect("change email");

    let err = harness
        .identity()
        .reset_password_with_token(
            &realm,
            &token,
            &CleartextPassword::from_string(OTHER_PASSWORD.to_string()),
        )
        .expect_err("a reset issued for the old email must not work");
    assert_token_invalid(&err, "a reset token whose account email changed");
}

// ---------------------------------------------------------------------------
// The password changes out of band after the reset is requested
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reset_token_dies_when_the_password_changes_out_of_band() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm(&harness, None);
    let email = format!("oob-{}@example.com", uuid::Uuid::new_v4());
    let user = create_user(&harness, &realm, &email);

    let token = harness
        .identity()
        .request_password_reset(&realm, &email)
        .expect("request reset")
        .expect("token issued");

    // Admin sets a new password directly — the reset link is now stale.
    harness
        .identity()
        .set_password(
            &realm,
            &user,
            &CleartextPassword::from_string(OTHER_PASSWORD.to_string()),
        )
        .expect("out-of-band password change");

    let err = harness
        .identity()
        .reset_password_with_token(
            &realm,
            &token,
            &CleartextPassword::from_string(GOOD_PASSWORD.to_string()),
        )
        .expect_err("a reset issued before the password changed must not work");
    assert_token_invalid(&err, "a reset token superseded by a password change");
}

// ---------------------------------------------------------------------------
// A newer reset token supersedes the older one
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_newer_reset_token_supersedes_the_older_one() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm(&harness, None);
    let email = format!("supersede-{}@example.com", uuid::Uuid::new_v4());
    create_user(&harness, &realm, &email);

    let first = harness
        .identity()
        .request_password_reset(&realm, &email)
        .expect("request first reset")
        .expect("first token issued");
    let second = harness
        .identity()
        .request_password_reset(&realm, &email)
        .expect("request second reset")
        .expect("second token issued");

    let err = harness
        .identity()
        .reset_password_with_token(
            &realm,
            &first,
            &CleartextPassword::from_string(OTHER_PASSWORD.to_string()),
        )
        .expect_err("the superseded token must not work");
    assert_token_invalid(&err, "a reset token superseded by a newer one");

    // The newest link is the one that works.
    harness
        .identity()
        .reset_password_with_token(
            &realm,
            &second,
            &CleartextPassword::from_string(OTHER_PASSWORD.to_string()),
        )
        .expect("the newest reset token must still work");
}

// ---------------------------------------------------------------------------
// A rejected password must not burn the token
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_rejected_password_does_not_consume_the_reset_token() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = create_realm(
        &harness,
        Some(PasswordPolicy {
            min_length: Some(24),
            ..PasswordPolicy::default()
        }),
    );
    let email = format!("policy-{}@example.com", uuid::Uuid::new_v4());
    create_user(&harness, &realm, &email);

    let token = harness
        .identity()
        .request_password_reset(&realm, &email)
        .expect("request reset")
        .expect("token issued");

    // Too short for the realm policy — the submission fails.
    let err = harness
        .identity()
        .reset_password_with_token(
            &realm,
            &token,
            &CleartextPassword::from_string("short-pass-1".to_string()),
        )
        .expect_err("a password below the policy floor must be refused");
    assert!(
        !matches!(err, IdentityError::PasswordResetTokenInvalid),
        "the failure must be about the password, not the token, got: {err:?}"
    );

    // The same link must still work with a compliant password.
    harness
        .identity()
        .reset_password_with_token(
            &realm,
            &token,
            &CleartextPassword::from_string(OTHER_PASSWORD.to_string()),
        )
        .expect("the link must survive a rejected password");
}
