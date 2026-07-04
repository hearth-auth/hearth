//! Integration tests for HSEC-003 (password policy floor) and HSEC-004
//! (system realm MFA default).
//!
//! Assertions:
//! - Empty and short passwords are rejected at `set_password` and self-registration
//!   even when no `PasswordPolicy` is configured on the realm.
//! - A policy `min_length` lower than 8 does not lower the floor below 8.
//! - A policy `min_length` higher than 8 is respected as the effective minimum.
//! - Creating a session in the system realm without MFA enrolled is rejected
//!   even when `mfa_required` is not explicitly set in the realm config.

mod common;

use hearth::core::RealmId;
use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, IdentityError, PasswordPolicy,
    RealmConfig, RegisterUserRequest, RegistrationPolicy, SessionContext,
};

// ─── helpers ─────────────────────────────────────────────────────────────────

fn plain_session_context() -> SessionContext {
    SessionContext {
        ip_address: None,
        user_agent_raw: None,
        device_label: None,
        satisfies_mfa_via_passkey: false,
    }
}

// ─── HSEC-003: password floor on set_password ─────────────────────────────

#[tokio::test]
async fn empty_password_rejected_without_policy() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("floor-test-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");

    let user = harness
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("u-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Test User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    let err = harness
        .identity()
        .set_password(
            realm.id(),
            user.id(),
            &CleartextPassword::from_string(String::new()),
        )
        .expect_err("empty password must be rejected");

    assert!(
        matches!(err, IdentityError::InvalidInput { .. }),
        "expected InvalidInput for empty password, got: {err}"
    );
}

#[tokio::test]
async fn short_password_rejected_without_policy() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("floor-test-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");

    let user = harness
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("u-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Test User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    // 7 characters — one below the 8-char floor.
    let err = harness
        .identity()
        .set_password(
            realm.id(),
            user.id(),
            &CleartextPassword::from_string("short7x".to_string()),
        )
        .expect_err("7-char password must be rejected by floor");

    assert!(
        matches!(err, IdentityError::InvalidInput { .. }),
        "expected InvalidInput for short password, got: {err}"
    );
}

#[tokio::test]
async fn eight_char_password_accepted_without_policy() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("floor-test-{}", uuid::Uuid::new_v4()),
            config: None,
        })
        .expect("create realm");

    let user = harness
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("u-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Test User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    harness
        .identity()
        .set_password(
            realm.id(),
            user.id(),
            &CleartextPassword::from_string("exactly8".to_string()),
        )
        .expect("8-char password must be accepted at the floor");
}

// ─── HSEC-003: floor wins when policy min_length < 8 ─────────────────────

#[tokio::test]
async fn policy_min_length_below_floor_still_enforces_floor() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("floor-test-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                password_policy: Some(PasswordPolicy {
                    // Operator sets 4, but the hard floor is 8.
                    min_length: Some(4),
                    ..PasswordPolicy::default()
                }),
                ..RealmConfig::default()
            }),
        })
        .expect("create realm");

    let user = harness
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("u-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Test User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    // 5 chars satisfies the operator policy (min_length=4) but not the floor (8).
    let err = harness
        .identity()
        .set_password(
            realm.id(),
            user.id(),
            &CleartextPassword::from_string("five5".to_string()),
        )
        .expect_err("5-char password must be rejected even with min_length=4 policy");

    assert!(
        matches!(err, IdentityError::InvalidInput { .. }),
        "expected InvalidInput, got: {err}"
    );

    // 8 chars meets the floor and satisfies the policy.
    harness
        .identity()
        .set_password(
            realm.id(),
            user.id(),
            &CleartextPassword::from_string("exactly8".to_string()),
        )
        .expect("8-char password must be accepted when policy min_length < 8");
}

#[tokio::test]
async fn policy_min_length_above_floor_is_respected() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("floor-test-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                password_policy: Some(PasswordPolicy {
                    min_length: Some(12),
                    ..PasswordPolicy::default()
                }),
                ..RealmConfig::default()
            }),
        })
        .expect("create realm");

    let user = harness
        .identity()
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: format!("u-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "Test User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    // 8 chars meets the floor but not the policy (min=12).
    let err = harness
        .identity()
        .set_password(
            realm.id(),
            user.id(),
            &CleartextPassword::from_string("exactly8".to_string()),
        )
        .expect_err("8-char password must fail when policy requires 12");

    assert!(
        matches!(err, IdentityError::InvalidInput { .. }),
        "expected InvalidInput, got: {err}"
    );

    // 12 chars satisfies the policy.
    harness
        .identity()
        .set_password(
            realm.id(),
            user.id(),
            &CleartextPassword::from_string("longenough12".to_string()),
        )
        .expect("12-char password must be accepted when policy min_length=12");
}

// ─── HSEC-003: floor on self-registration ─────────────────────────────────

#[tokio::test]
async fn self_registration_short_password_rejected_without_policy() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("floor-test-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                registration_policy: Some(RegistrationPolicy::Open),
                ..RealmConfig::default()
            }),
        })
        .expect("create realm");

    let err = harness
        .identity()
        .register_user(
            realm.id(),
            &RegisterUserRequest {
                email: format!("new-{}@example.com", uuid::Uuid::new_v4()),
                display_name: "New User".to_string(),
                password: CleartextPassword::from_string("short".to_string()),
                first_name: String::new(),
                last_name: String::new(),
                invitation_token: None,
                client_ip: None,
            },
        )
        .expect_err("5-char registration password must be rejected by floor");

    assert!(
        matches!(err, IdentityError::InvalidInput { .. }),
        "expected InvalidInput, got: {err}"
    );
}

// ─── HSEC-004: system realm defaults to MFA required ─────────────────────

#[tokio::test]
async fn system_realm_session_requires_mfa_by_default() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let sys_realm = RealmId::new(uuid::Uuid::nil());

    // create_admin_user is the system-realm-specific entry point; create_user
    // is blocked by SystemRealmProtected on the nil-UUID realm.
    let user = harness
        .identity()
        .create_admin_user(&CreateUserRequest {
            email: format!("admin-{}@hearth.test", uuid::Uuid::new_v4()),
            display_name: "Admin".to_string(),
            first_name: String::new(),
            last_name: String::new(),
            attributes: Default::default(),
        })
        .expect("create admin user in system realm");

    harness
        .identity()
        .set_password(
            &sys_realm,
            user.id(),
            &CleartextPassword::from_string("Adm1nP@ssw0rd!".to_string()),
        )
        .expect("set password");

    // Session creation must be rejected because the system realm defaults
    // mfa_required to true and the user has no MFA enrolled (HSEC-004).
    let err = harness
        .identity()
        .create_session(&sys_realm, user.id(), &plain_session_context())
        .expect_err("session without MFA must be rejected in system realm");

    assert!(
        matches!(err, IdentityError::MfaRequired),
        "expected MfaRequired, got: {err}"
    );
}
