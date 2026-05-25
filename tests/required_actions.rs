//! Integration tests for HEA-751: RequiredAction domain model + realm-scoped storage.
//!
//! Tests the `add_required_action`, `remove_required_action`, and `pending_actions`
//! methods of `IdentityEngine`. All TDD red-phase — these tests must fail before
//! the implementation exists.

mod common;

use hearth::identity::{CreateRealmRequest, CreateUserRequest, IdentityEngine, RequiredAction};

/// Builds a test realm + user pair, returning `(realm_id, user_id)`.
async fn setup_realm_and_user(
    identity: &dyn IdentityEngine,
) -> (hearth::core::RealmId, hearth::core::UserId) {
    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: "action-test-realm".to_string(),
            config: None,
        })
        .expect("create realm");

    let user = identity
        .create_user(
            realm.id(),
            &CreateUserRequest {
                email: "alice@actions.test".to_string(),
                display_name: "Alice".to_string(),
                first_name: "Alice".to_string(),
                last_name: "Actions".to_string(),
                attributes: Default::default(),
            },
        )
        .expect("create user");

    (realm.id().clone(), user.id().clone())
}

// ===== AC-3: empty pending set for a fresh user =====

#[tokio::test]
async fn pending_actions_empty_for_new_user() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let (realm_id, user_id) = setup_realm_and_user(identity).await;

    let actions = identity
        .pending_actions(&realm_id, &user_id)
        .expect("pending_actions");

    assert!(
        actions.is_empty(),
        "new user should have no pending actions, got: {actions:?}"
    );
}

// ===== AC-1: add persists an action =====

#[tokio::test]
async fn add_required_action_update_password_persists() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let (realm_id, user_id) = setup_realm_and_user(identity).await;

    identity
        .add_required_action(&realm_id, &user_id, RequiredAction::UpdatePassword)
        .expect("add action");

    let actions = identity
        .pending_actions(&realm_id, &user_id)
        .expect("pending_actions");

    assert!(
        actions.contains(&RequiredAction::UpdatePassword),
        "UpdatePassword must be in pending set after add, got: {actions:?}"
    );
}

#[tokio::test]
async fn add_required_action_verify_email_persists() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let (realm_id, user_id) = setup_realm_and_user(identity).await;

    identity
        .add_required_action(&realm_id, &user_id, RequiredAction::VerifyEmail)
        .expect("add VerifyEmail");

    let actions = identity
        .pending_actions(&realm_id, &user_id)
        .expect("pending_actions");

    assert!(
        actions.contains(&RequiredAction::VerifyEmail),
        "VerifyEmail must be in pending set, got: {actions:?}"
    );
}

// ===== AC-1: multiple actions accumulate in the same set =====

#[tokio::test]
async fn add_multiple_actions_accumulate() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let (realm_id, user_id) = setup_realm_and_user(identity).await;

    identity
        .add_required_action(&realm_id, &user_id, RequiredAction::UpdatePassword)
        .expect("add UpdatePassword");
    identity
        .add_required_action(&realm_id, &user_id, RequiredAction::VerifyEmail)
        .expect("add VerifyEmail");

    let actions = identity
        .pending_actions(&realm_id, &user_id)
        .expect("pending_actions");

    assert_eq!(
        actions.len(),
        2,
        "both actions must be present, got: {actions:?}"
    );
    assert!(actions.contains(&RequiredAction::UpdatePassword));
    assert!(actions.contains(&RequiredAction::VerifyEmail));
}

// ===== AC-1: add is idempotent =====

#[tokio::test]
async fn add_required_action_idempotent() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let (realm_id, user_id) = setup_realm_and_user(identity).await;

    identity
        .add_required_action(&realm_id, &user_id, RequiredAction::UpdatePassword)
        .expect("first add");
    identity
        .add_required_action(&realm_id, &user_id, RequiredAction::UpdatePassword)
        .expect("second add (idempotent)");

    let actions = identity
        .pending_actions(&realm_id, &user_id)
        .expect("pending_actions");

    assert_eq!(
        actions.len(),
        1,
        "duplicate add must not create two entries, got: {actions:?}"
    );
}

// ===== AC-2: remove atomically removes an action =====

#[tokio::test]
async fn remove_required_action_removes_entry() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let (realm_id, user_id) = setup_realm_and_user(identity).await;

    identity
        .add_required_action(&realm_id, &user_id, RequiredAction::UpdatePassword)
        .expect("add");
    identity
        .add_required_action(&realm_id, &user_id, RequiredAction::VerifyEmail)
        .expect("add second");

    identity
        .remove_required_action(&realm_id, &user_id, RequiredAction::UpdatePassword)
        .expect("remove");

    let actions = identity
        .pending_actions(&realm_id, &user_id)
        .expect("pending_actions");

    assert!(
        !actions.contains(&RequiredAction::UpdatePassword),
        "UpdatePassword must be removed, got: {actions:?}"
    );
    assert!(
        actions.contains(&RequiredAction::VerifyEmail),
        "VerifyEmail must remain, got: {actions:?}"
    );
}

// ===== AC-2: remove on absent action is a no-op (idempotent) =====

#[tokio::test]
async fn remove_absent_action_is_noop() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let (realm_id, user_id) = setup_realm_and_user(identity).await;

    identity
        .remove_required_action(&realm_id, &user_id, RequiredAction::UpdatePassword)
        .expect("remove absent action is a no-op");

    let actions = identity
        .pending_actions(&realm_id, &user_id)
        .expect("pending_actions");

    assert!(
        actions.is_empty(),
        "set must remain empty, got: {actions:?}"
    );
}

// ===== Realm isolation: actions are scoped per realm =====

#[tokio::test]
async fn required_actions_are_realm_scoped() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();

    let realm_a = identity
        .create_realm(&CreateRealmRequest {
            name: "realm-a".to_string(),
            config: None,
        })
        .expect("create realm A");

    let realm_b = identity
        .create_realm(&CreateRealmRequest {
            name: "realm-b".to_string(),
            config: None,
        })
        .expect("create realm B");

    let user_a = identity
        .create_user(
            realm_a.id(),
            &CreateUserRequest {
                email: "bob@realm-a.test".to_string(),
                display_name: "Bob A".to_string(),
                first_name: "Bob".to_string(),
                last_name: "A".to_string(),
                attributes: Default::default(),
            },
        )
        .expect("create user A");

    let user_b = identity
        .create_user(
            realm_b.id(),
            &CreateUserRequest {
                email: "bob@realm-b.test".to_string(),
                display_name: "Bob B".to_string(),
                first_name: "Bob".to_string(),
                last_name: "B".to_string(),
                attributes: Default::default(),
            },
        )
        .expect("create user B");

    identity
        .add_required_action(realm_a.id(), user_a.id(), RequiredAction::UpdatePassword)
        .expect("add to realm A");

    let actions_b = identity
        .pending_actions(realm_b.id(), user_b.id())
        .expect("pending in realm B");

    assert!(
        actions_b.is_empty(),
        "realm B user must not see realm A action, got: {actions_b:?}"
    );
}

// ===== AC-5: concurrent adds of different actions both persist =====

#[tokio::test]
async fn concurrent_adds_both_persist() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let (realm_id, user_id) = setup_realm_and_user(identity).await;

    let identity_arc = harness.identity_arc();
    let realm_id2 = realm_id.clone();
    let user_id2 = user_id.clone();

    let handle = std::thread::spawn(move || {
        identity_arc
            .add_required_action(&realm_id2, &user_id2, RequiredAction::VerifyEmail)
            .expect("add VerifyEmail from thread");
    });

    identity
        .add_required_action(&realm_id, &user_id, RequiredAction::UpdatePassword)
        .expect("add UpdatePassword from main thread");

    handle.join().expect("thread panicked");

    let actions = identity
        .pending_actions(&realm_id, &user_id)
        .expect("pending_actions");

    assert!(
        actions.contains(&RequiredAction::UpdatePassword),
        "UpdatePassword must be present, got: {actions:?}"
    );
    assert!(
        actions.contains(&RequiredAction::VerifyEmail),
        "VerifyEmail must be present, got: {actions:?}"
    );
}

// ===== AC-3: pending_actions returns unknown user as empty (not error) =====

#[tokio::test]
async fn pending_actions_unknown_user_returns_empty() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();

    let realm = identity
        .create_realm(&CreateRealmRequest {
            name: "lookup-realm".to_string(),
            config: None,
        })
        .expect("create realm");

    let ghost_user = hearth::core::UserId::generate();
    let actions = identity
        .pending_actions(realm.id(), &ghost_user)
        .expect("pending_actions for non-existent user returns empty");

    assert!(
        actions.is_empty(),
        "non-existent user must return empty set, got: {actions:?}"
    );
}
