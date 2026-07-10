//! Integration tests for HSEC-003 (password policy floor) and HSEC-004
//! (system realm MFA default).
//!
//! Assertions:
//! - Empty and short passwords are rejected at `set_password` and self-registration
//!   even when no `PasswordPolicy` is configured on the realm.
//! - A policy `min_length` lower than 12 does not lower the floor below 12.
//! - A policy `min_length` higher than 12 is respected as the effective minimum.
//! - Creating a session in the system realm without MFA enrolled SUCCEEDS when
//!   `mfa_required` is not explicitly set (opt-in default).
//! - Creating a session in the system realm fails with `MfaRequired` when
//!   `mfa_required: true` is explicitly configured and no MFA is enrolled.

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

    // 11 characters — one below the 12-char floor.
    let err = harness
        .identity()
        .set_password(
            realm.id(),
            user.id(),
            &CleartextPassword::from_string("short11char".to_string()),
        )
        .expect_err("11-char password must be rejected by floor");

    assert!(
        matches!(err, IdentityError::InvalidInput { .. }),
        "expected InvalidInput for short password, got: {err}"
    );
}

#[tokio::test]
async fn twelve_char_password_accepted_without_policy() {
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
            &CleartextPassword::from_string("exactly12pwd".to_string()),
        )
        .expect("12-char password must be accepted at the floor");
}

// ─── HSEC-003: floor wins when policy min_length < 12 ────────────────────

#[tokio::test]
async fn policy_min_length_below_floor_still_enforces_floor() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let realm = harness
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("floor-test-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                password_policy: Some(PasswordPolicy {
                    // Operator sets 4, but the hard floor is 12.
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

    // 5 chars satisfies the operator policy (min_length=4) but not the floor (12).
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

    // 12 chars meets the floor and satisfies the policy.
    harness
        .identity()
        .set_password(
            realm.id(),
            user.id(),
            &CleartextPassword::from_string("exactly12pwd".to_string()),
        )
        .expect("12-char password must be accepted when policy min_length < 12");
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
                    min_length: Some(15),
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

    // 12 chars meets the floor but not the policy (min=15).
    let err = harness
        .identity()
        .set_password(
            realm.id(),
            user.id(),
            &CleartextPassword::from_string("exactly12pwd".to_string()),
        )
        .expect_err("12-char password must fail when policy requires 15");

    assert!(
        matches!(err, IdentityError::InvalidInput { .. }),
        "expected InvalidInput, got: {err}"
    );

    // 15 chars satisfies the policy.
    harness
        .identity()
        .set_password(
            realm.id(),
            user.id(),
            &CleartextPassword::from_string("longenoughpwd15".to_string()),
        )
        .expect("15-char password must be accepted when policy min_length=15");
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

// ─── HSEC-004: system realm MFA is opt-in, not default ───────────────────

/// HSEC-004 (revised): When `mfa_required` is not configured on the system
/// realm, session creation must SUCCEED. The admin control plane must be
/// bootable on a fresh install — there is no way to pre-enroll MFA before
/// the first admin session. Operators enable MFA enforcement explicitly after
/// enrollment via `mfa_required: true` in hearth.yaml.
#[tokio::test]
async fn system_realm_session_succeeds_without_mfa_when_not_configured() {
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

    // With mfa_required not configured (None), session creation must succeed.
    harness
        .identity()
        .create_session(&sys_realm, user.id(), &plain_session_context())
        .expect("session without MFA must succeed when mfa_required is not configured");
}

/// HSEC-004: When `mfa_required: true` is explicitly set on a realm, session
/// creation for a user without MFA enrolled must be rejected. Tests the same
/// code path as the system realm check (update_realm rejects system-realm edits,
/// so we use a user realm which exercises the identical enforcement block).
#[tokio::test]
async fn realm_session_requires_mfa_when_explicitly_configured() {
    let harness = common::TestHarness::embedded().await.expect("harness");

    let realm = harness
        .identity()
        .create_realm(&hearth::identity::CreateRealmRequest {
            name: format!("mfa-test-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                mfa_required: Some(true),
                ..Default::default()
            }),
        })
        .expect("create realm with mfa_required");
    let realm_id = realm.id().clone();

    let user = harness
        .identity()
        .create_user(
            &realm_id,
            &CreateUserRequest {
                email: format!("user-{}@hearth.test", uuid::Uuid::new_v4()),
                display_name: "User".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    harness
        .identity()
        .set_password(
            &realm_id,
            user.id(),
            &CleartextPassword::from_string("Adm1nP@ssw0rd!".to_string()),
        )
        .expect("set password");

    let err = harness
        .identity()
        .create_session(&realm_id, user.id(), &plain_session_context())
        .expect_err("session without MFA must be rejected when mfa_required=true");

    assert!(
        matches!(err, IdentityError::MfaRequired),
        "expected MfaRequired, got: {err}"
    );
}
