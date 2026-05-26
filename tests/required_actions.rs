//! Integration tests for `required_actions` on users and realm default config.
//!
//! Covers AC-5 (no required actions = unaffected), AC-6 (field visible on GET),
//! and AC-7 (realm defaults applied to new users).

mod common;

use hearth::identity::{
    CleartextPassword, CreateRealmRequest, CreateUserRequest, RealmConfig, RegisterUserRequest,
    RegistrationPolicy, RequiredAction, UpdateUserRequest,
};

fn make_user_request(prefix: &str) -> CreateUserRequest {
    CreateUserRequest {
        email: format!("{}-{}@example.com", prefix, uuid::Uuid::new_v4()),
        display_name: "Test User".to_string(),
        first_name: "Test".to_string(),
        last_name: "User".to_string(),
        attributes: Default::default(),
    }
}

// ---------------------------------------------------------------------------
// AC-5: users with no required actions are unaffected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn new_user_in_realm_with_no_defaults_has_empty_required_actions() {
    let h = common::TestHarness::embedded().await.expect("harness");
    let realm = h.create_realm();

    let user = h
        .identity()
        .create_user(&realm, &make_user_request("ac5"))
        .expect("create user");

    assert!(
        user.required_actions().is_empty(),
        "expected empty required_actions, got {:?}",
        user.required_actions()
    );
}

// ---------------------------------------------------------------------------
// AC-7: realm defaults applied to new users
// ---------------------------------------------------------------------------

#[tokio::test]
async fn new_user_inherits_realm_default_required_actions() {
    let h = common::TestHarness::embedded().await.expect("harness");

    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("realm-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                default_required_actions: vec![
                    RequiredAction::VerifyEmail,
                    RequiredAction::UpdatePassword,
                ],
                ..Default::default()
            }),
        })
        .expect("create realm")
        .id()
        .clone();

    let user = h
        .identity()
        .create_user(&realm, &make_user_request("ac7"))
        .expect("create user");

    assert_eq!(
        user.required_actions(),
        &[RequiredAction::VerifyEmail, RequiredAction::UpdatePassword],
        "expected realm defaults to be copied onto new user"
    );
}

// ---------------------------------------------------------------------------
// AC-6: required_actions visible on GET user
// ---------------------------------------------------------------------------

#[tokio::test]
async fn required_actions_visible_on_get_user() {
    let h = common::TestHarness::embedded().await.expect("harness");

    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("realm-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                default_required_actions: vec![RequiredAction::VerifyEmail],
                ..Default::default()
            }),
        })
        .expect("create realm")
        .id()
        .clone();

    let created = h
        .identity()
        .create_user(&realm, &make_user_request("ac6"))
        .expect("create user");

    let fetched = h
        .identity()
        .get_user(&realm, created.id())
        .expect("get user")
        .expect("user should exist");

    assert_eq!(
        fetched.required_actions(),
        &[RequiredAction::VerifyEmail],
        "required_actions must survive a round-trip through storage"
    );
}

// ---------------------------------------------------------------------------
// Update: required_actions can be cleared via UpdateUserRequest
// ---------------------------------------------------------------------------

#[tokio::test]
async fn update_user_can_clear_required_actions() {
    let h = common::TestHarness::embedded().await.expect("harness");

    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("realm-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                default_required_actions: vec![RequiredAction::VerifyEmail],
                ..Default::default()
            }),
        })
        .expect("create realm")
        .id()
        .clone();

    let user = h
        .identity()
        .create_user(&realm, &make_user_request("clear"))
        .expect("create user");

    assert!(!user.required_actions().is_empty());

    let updated = h
        .identity()
        .update_user(
            &realm,
            user.id(),
            &UpdateUserRequest {
                required_actions: Some(vec![]),
                ..Default::default()
            },
        )
        .expect("update user");

    assert!(
        updated.required_actions().is_empty(),
        "required_actions should be empty after clearing"
    );
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// AC-7: realm defaults applied on self-service registration (register_user)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn register_user_inherits_realm_default_required_actions() {
    let h = common::TestHarness::embedded().await.expect("harness");

    let realm = h
        .identity()
        .create_realm(&CreateRealmRequest {
            name: format!("realm-reg-ac7-{}", uuid::Uuid::new_v4()),
            config: Some(RealmConfig {
                default_required_actions: vec![
                    RequiredAction::VerifyEmail,
                    RequiredAction::UpdatePassword,
                ],
                registration_policy: Some(RegistrationPolicy::Open),
                ..Default::default()
            }),
        })
        .expect("create realm")
        .id()
        .clone();

    let email = format!("registrant-{}@example.com", uuid::Uuid::new_v4());
    let resp = h
        .identity()
        .register_user(
            &realm,
            &RegisterUserRequest {
                email: email.clone(),
                display_name: "Reg User".to_string(),
                first_name: "Reg".to_string(),
                last_name: "User".to_string(),
                password: CleartextPassword::from_string(
                    "correct-horse-battery-staple1!".to_string(),
                ),
                client_ip: None,
                invitation_token: None,
            },
        )
        .expect("register_user");

    let user = h
        .identity()
        .get_user(&realm, &resp.user_id)
        .expect("get user ok")
        .expect("user must exist after registration");

    assert_eq!(
        user.required_actions(),
        &[RequiredAction::VerifyEmail, RequiredAction::UpdatePassword],
        "register_user must copy realm default_required_actions onto new user"
    );
}

// ---------------------------------------------------------------------------
// Deserialization migration: missing field → empty vec (serde default)
// ---------------------------------------------------------------------------

#[test]
fn user_without_required_actions_field_deserializes_as_empty() {
    // Simulates a stored user record from before this field existed.
    let json = r#"{
        "id": "01900000-0000-0000-0000-000000000001",
        "email": "old@example.com",
        "display_name": "Old User",
        "first_name": "Old",
        "last_name": "User",
        "status": "Active",
        "created_at": 0,
        "updated_at": 0
    }"#;

    let user: hearth::identity::User = serde_json::from_str(json).expect("deserialize legacy user");

    assert!(
        user.required_actions().is_empty(),
        "missing required_actions field must deserialize as empty vec (migration invariant)"
    );
}
