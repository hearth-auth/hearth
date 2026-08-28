#![allow(clippy::unwrap_used)]
//! Integration tests for reconcile_seed_users.
//!
//! Exercises the `seed_users:` block inside a realm declaration through the
//! public `reconcile_realms()` entry point (the private `reconcile_seed_users`
//! helper is not separately callable).  Three scenarios:
//!
//! 1. Seed users are created with Active status and declared role assignments.
//! 2. A second reconcile run is idempotent (no duplicate-user error).
//! 3. An invalid role name logs a warning but does not abort reconciliation.

mod common;

use std::collections::HashMap;

use hearth::config::{Config, RealmYamlConfig, SeedUserYamlConfig};
use hearth::identity::reconcile::reconcile_realms;
use hearth::identity::UserStatus;

/// Builds a minimal `Config` with one realm that declares the given seed users.
fn config_with_seed_users(realm_name: &str, seed_users: Vec<SeedUserYamlConfig>) -> Config {
    let mut config = Config::dev();
    let realm_cfg = RealmYamlConfig {
        seed_users: Some(seed_users),
        ..Default::default()
    };
    let mut realms = HashMap::new();
    realms.insert(realm_name.to_string(), realm_cfg);
    config.realms = Some(realms);
    config
}

// ===== Scenario 1: seed users created with Active status and role assignments =====
//
// When a RealmYamlConfig includes seed_users with a valid role, reconcile_realms
// must create the user, activate it, and assign the declared realm role.

#[tokio::test]
async fn seed_users_created_with_active_status_and_roles() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let rbac = harness.rbac();

    let seed_users = vec![SeedUserYamlConfig {
        email: "alice@seed.test".to_string(),
        display_name: "Alice Seed".to_string(),
        password: "S33dP@ssword!".to_string(),
        // realm.admin is always present after seed_realm runs on a new realm
        roles: vec!["realm.admin".to_string()],
        email_verified: true,
    }];

    let config = config_with_seed_users("acme", seed_users);
    reconcile_realms(identity, rbac, &config).expect("reconcile must succeed");

    let realm = identity
        .get_realm_by_name("acme")
        .expect("get_realm_by_name")
        .expect("realm must exist after reconcile");

    // User must exist with correct display name
    let user = identity
        .get_user_by_email(realm.id(), "alice@seed.test")
        .expect("get_user_by_email")
        .expect("seed user must be created");

    assert_eq!(user.display_name(), "Alice Seed");
    assert_eq!(
        user.status(),
        UserStatus::Active,
        "seed user must be activated by reconcile"
    );

    // The declared role must be assigned
    let admin_role = rbac
        .get_role_by_name(realm.id(), "realm.admin")
        .expect("get_role_by_name")
        .expect("realm.admin seed role must exist after reconcile");

    let assignments = rbac
        .list_user_assignments(realm.id(), user.id())
        .expect("list_user_assignments");

    let has_admin = assignments.iter().any(|a| a.role_id == admin_role.id);
    assert!(has_admin, "realm.admin must be assigned to the seed user");
}

// ===== Scenario 2: second reconcile run is idempotent =====
//
// Calling reconcile_realms twice with the same config must not error or
// produce duplicate user records.

#[tokio::test]
async fn reconcile_seed_users_is_idempotent() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let rbac = harness.rbac();

    let seed_users = vec![SeedUserYamlConfig {
        email: "bob@seed.test".to_string(),
        display_name: "Bob Seed".to_string(),
        password: "S33dP@ssword!".to_string(),
        // AUDIT: justified-empty-fixture: seed user intentionally has no roles — this is an idempotency test, not an RBAC preservation test (HEA-2158)
        roles: vec![],
        email_verified: true,
    }];

    let config = config_with_seed_users("idempotent", seed_users);

    // First run — creates the realm and user
    reconcile_realms(identity, rbac, &config).expect("first reconcile must succeed");

    // Second run — must skip the existing user without returning an error
    reconcile_realms(identity, rbac, &config).expect("second reconcile must succeed");

    let realm = identity
        .get_realm_by_name("idempotent")
        .expect("get_realm_by_name")
        .expect("realm must exist");

    let page = identity
        .list_users(realm.id(), &hearth::core::PageRequest::new(0, 100))
        .expect("list_users");

    assert_eq!(
        page.items.len(),
        1,
        "second reconcile must not duplicate the seed user"
    );
}

// ===== Scenario 3: invalid role name logs warning but does not abort =====
//
// When a seed user declares a role that does not exist in the realm, reconcile
// must log a warning and continue — it must NOT return an Err or skip creating
// the user entirely.

#[tokio::test]
async fn invalid_role_name_does_not_abort_reconcile() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let rbac = harness.rbac();

    let seed_users = vec![SeedUserYamlConfig {
        email: "carol@seed.test".to_string(),
        display_name: "Carol Seed".to_string(),
        password: "S33dP@ssword!".to_string(),
        // This role name does not exist; reconcile must warn and continue.
        roles: vec!["nonexistent.role.xyz".to_string()],
        email_verified: true,
    }];

    let config = config_with_seed_users("warn-realm", seed_users);

    let result = reconcile_realms(identity, rbac, &config);
    assert!(
        result.is_ok(),
        "reconcile must not abort on unknown role name; got: {result:?}"
    );

    let realm = identity
        .get_realm_by_name("warn-realm")
        .expect("get_realm_by_name")
        .expect("realm must still be created");

    // The user must exist even though the role assignment was skipped
    let user = identity
        .get_user_by_email(realm.id(), "carol@seed.test")
        .expect("get_user_by_email")
        .expect("seed user must be created even when role name is invalid");

    assert_eq!(
        user.status(),
        UserStatus::Active,
        "user must be Active despite the missing role"
    );

    // No role assignments should exist (the nonexistent role was skipped)
    let assignments = rbac
        .list_user_assignments(realm.id(), user.id())
        .expect("list_user_assignments");
    assert!(
        assignments.is_empty(),
        "no assignment should exist for a nonexistent role"
    );
}
