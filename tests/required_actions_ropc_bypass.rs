//! Regression tests for HEA-905: required-actions bypass via ROPC password grant.
//!
//! Verifies that `password_grant_token` blocks token issuance when the
//! authenticated user has pending required actions, closing the gap where
//! the UI-layer interstitial was enforced but the protocol layer was not.

mod common;

use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, IdentityError, PasswordGrantRequest,
    RequiredAction, UpdateUserRequest,
};

const PASSWORD: &str = "HearthR0pcBypass!Test";

fn ropc(email: &str) -> PasswordGrantRequest {
    PasswordGrantRequest {
        email: email.to_string(),
        password: PASSWORD.to_string(),
        scope: None,
        client_ip: None,
        user_agent: None,
    }
}

// ──────────────────────────────────────────────────────────────
// AC-1 (HEA-905): pending required actions block token issuance
// ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn password_grant_blocked_when_update_password_pending() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("ra-bypass-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");

    let user = h
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("ra-bypass-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "RA Test User".to_string(),
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

    // Assign UPDATE_PASSWORD required action.
    h.identity()
        .update_user(
            realm.id(),
            user.id(),
            &UpdateUserRequest {
                required_actions: Some(vec![RequiredAction::UpdatePassword]),
                ..Default::default()
            },
        )
        .expect("assign required action");

    let err = h
        .identity()
        .password_grant_token(realm.id(), &ropc(user.email()))
        .expect_err("ROPC must be blocked when UPDATE_PASSWORD is pending");

    match err {
        IdentityError::RequiredActionsBlocking { actions } => {
            assert!(
                actions.contains(&RequiredAction::UpdatePassword),
                "RequiredActionsBlocking must include the pending action; got {actions:?}"
            );
        }
        other => panic!("expected RequiredActionsBlocking, got: {other:?}"),
    }
}

#[tokio::test]
async fn password_grant_blocked_when_verify_email_pending() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("ra-bypass-email-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");

    let user = h
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("ra-bypass-email-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "RA Email User".to_string(),
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

    h.identity()
        .update_user(
            realm.id(),
            user.id(),
            &UpdateUserRequest {
                required_actions: Some(vec![RequiredAction::VerifyEmail]),
                ..Default::default()
            },
        )
        .expect("assign required action");

    let err = h
        .identity()
        .password_grant_token(realm.id(), &ropc(user.email()))
        .expect_err("ROPC must be blocked when VERIFY_EMAIL is pending");

    assert!(
        matches!(err, IdentityError::RequiredActionsBlocking { .. }),
        "expected RequiredActionsBlocking, got: {err:?}"
    );
}

#[tokio::test]
async fn password_grant_blocked_returns_all_pending_actions() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("ra-bypass-multi-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");

    let user = h
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("ra-bypass-multi-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "RA Multi User".to_string(),
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

    let pending = vec![RequiredAction::VerifyEmail, RequiredAction::UpdatePassword];
    h.identity()
        .update_user(
            realm.id(),
            user.id(),
            &UpdateUserRequest {
                required_actions: Some(pending.clone()),
                ..Default::default()
            },
        )
        .expect("assign required actions");

    let err = h
        .identity()
        .password_grant_token(realm.id(), &ropc(user.email()))
        .expect_err("ROPC must be blocked when multiple actions are pending");

    match err {
        IdentityError::RequiredActionsBlocking { actions } => {
            assert_eq!(
                actions, pending,
                "all pending actions must be reported; got {actions:?}"
            );
        }
        other => panic!("expected RequiredActionsBlocking, got: {other:?}"),
    }
}

// ──────────────────────────────────────────────────────────────
// AC (HEA-905 step 6): ENROLL_PHONE_OTP also blocks ROPC
// ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn password_grant_blocked_when_enroll_phone_otp_pending() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("ra-bypass-otp-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");

    let user = h
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("ra-bypass-otp-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "RA OTP User".to_string(),
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

    h.identity()
        .update_user(
            realm.id(),
            user.id(),
            &UpdateUserRequest {
                required_actions: Some(vec![RequiredAction::EnrollPhoneOtp]),
                ..Default::default()
            },
        )
        .expect("assign required action");

    let err = h
        .identity()
        .password_grant_token(realm.id(), &ropc(user.email()))
        .expect_err("ROPC must be blocked when ENROLL_PHONE_OTP is pending");

    match err {
        IdentityError::RequiredActionsBlocking { actions } => {
            assert!(
                actions.contains(&RequiredAction::EnrollPhoneOtp),
                "RequiredActionsBlocking must include EnrollPhoneOtp; got {actions:?}"
            );
        }
        other => panic!("expected RequiredActionsBlocking, got: {other:?}"),
    }
}

// ──────────────────────────────────────────────────────────────
// AC (HEA-905 step 5): clearing required actions re-enables ROPC
// ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn password_grant_unblocked_after_clearing_required_actions() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("ra-bypass-clear-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");

    let user = h
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("ra-bypass-clear-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "RA Clear User".to_string(),
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

    // Assign pending action — ROPC must be blocked.
    h.identity()
        .update_user(
            realm.id(),
            user.id(),
            &UpdateUserRequest {
                required_actions: Some(vec![RequiredAction::UpdatePassword]),
                ..Default::default()
            },
        )
        .expect("assign required action");

    let blocked = h
        .identity()
        .password_grant_token(realm.id(), &ropc(user.email()))
        .expect_err("ROPC must be blocked before actions are cleared");
    assert!(
        matches!(blocked, IdentityError::RequiredActionsBlocking { .. }),
        "expected RequiredActionsBlocking before clear; got: {blocked:?}"
    );

    // Clear required actions — ROPC must succeed.
    h.identity()
        .update_user(
            realm.id(),
            user.id(),
            &UpdateUserRequest {
                required_actions: Some(vec![]),
                ..Default::default()
            },
        )
        .expect("clear required actions");

    let result = h
        .identity()
        .password_grant_token(realm.id(), &ropc(user.email()));
    assert!(
        result.is_ok(),
        "ROPC must succeed after required actions are cleared; got: {result:?}"
    );
    let resp = result.expect("token response");
    assert!(
        !resp.access_token().is_empty(),
        "access token must be non-empty after clear"
    );
}

// ──────────────────────────────────────────────────────────────
// Regression: no required actions → token issued normally
// ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn password_grant_succeeds_when_no_required_actions() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("ra-bypass-clean-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");

    let user = h
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("ra-bypass-clean-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Clean User".to_string(),
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
        .password_grant_token(realm.id(), &ropc(user.email()));

    assert!(
        result.is_ok(),
        "user with no pending required actions must get a token; got: {result:?}"
    );
    let resp = result.expect("token response");
    assert!(
        !resp.access_token().is_empty(),
        "access token must be non-empty"
    );
}
