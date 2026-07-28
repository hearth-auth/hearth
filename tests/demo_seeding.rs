#![allow(clippy::unwrap_used)]
//! Integration tests for the large-scale demo seeder.
//!
//! Exercises the top-level `demo:` block + per-realm `seeding:` block through
//! the public `reconcile_realms()` entry point. Scenarios:
//!
//! 1. With `demo.enabled = true`, a realm's `seeding.users` count produces that
//!    many synthetic users — all Active, all sharing the demo password.
//! 2. With `demo.enabled = false`, the `seeding:` block is ignored entirely (the
//!    realm is still created, but no bulk users are seeded). This is the
//!    production guard.
//! 3. Re-running is idempotent via the per-realm sentinel: a second reconcile at
//!    the same count is a no-op; raising the count seeds only the delta.
//! 4. The shipped example config (`examples/large-scale-demo/hearth.yaml`)
//!    parses successfully.

mod common;

use std::collections::HashMap;

use hearth::config::{Config, DemoConfig, RealmYamlConfig, SeedingYamlConfig};
use hearth::identity::reconcile::{reconcile_realms, seed_demo_realms};
use hearth::identity::{CleartextPassword, IdentityEngine, UserStatus};
use hearth::rbac::RbacEngine;

const SHARED_PASSWORD: &str = "DemoPassw0rd!";

/// Mirrors the production startup order: reconcile realms/RBAC/clients
/// (synchronous), then run the demo seeder (which production runs in a
/// background task after the listener binds). `reconcile_realms` no longer
/// seeds, so tests must call `seed_demo_realms` explicitly.
fn reconcile_and_seed(identity: &dyn IdentityEngine, rbac: &dyn RbacEngine, config: &Config) {
    reconcile_realms(identity, rbac, config).expect("reconcile must succeed");
    seed_demo_realms(identity, config);
}

/// Builds a `Config` with one realm that declares a `seeding:` block, and a
/// top-level `demo:` block gated by `enabled`.
fn config_with_seeding(
    realm_name: &str,
    users: u64,
    email_domain: &str,
    demo_enabled: bool,
) -> Config {
    let mut config = Config::dev();
    config.demo = DemoConfig {
        enabled: demo_enabled,
        password: Some(SHARED_PASSWORD.to_string()),
    };
    let realm_cfg = RealmYamlConfig {
        seeding: Some(SeedingYamlConfig {
            users,
            email_domain: Some(email_domain.to_string()),
            display_name_prefix: None,
            email_verified: None,
        }),
        ..Default::default()
    };
    let mut realms = HashMap::new();
    realms.insert(realm_name.to_string(), realm_cfg);
    config.realms = Some(realms);
    config
}

// ===== Scenario 1: seeds N users sharing the demo password =====

#[tokio::test]
async fn seeding_creates_users_sharing_demo_password() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let rbac = harness.rbac();

    let config = config_with_seeding("acme", 50, "acme.demo", true);
    reconcile_and_seed(identity, rbac, &config);

    let realm = identity
        .get_realm_by_name("acme")
        .expect("get_realm_by_name")
        .expect("realm must exist after reconcile");

    // Exactly 50 users seeded.
    let page = identity
        .list_users(realm.id(), &hearth::core::PageRequest::new(0, 100))
        .expect("list_users");
    assert_eq!(page.items.len(), 50, "seeding.users must create 50 users");

    // First and last generated accounts exist, are Active and email-verified.
    for email in ["user0000001@acme.demo", "user0000050@acme.demo"] {
        let user = identity
            .get_user_by_email(realm.id(), email)
            .expect("get_user_by_email")
            .unwrap_or_else(|| panic!("seed user {email} must exist"));
        assert_eq!(user.status(), UserStatus::Active, "{email} must be Active");
        assert!(user.email_verified(), "{email} must be email-verified");

        // The shared password authenticates every seeded user.
        let ok = identity
            .verify_password(
                realm.id(),
                user.id(),
                &CleartextPassword::from_string(SHARED_PASSWORD.to_string()),
            )
            .expect("verify_password");
        assert!(ok, "shared demo password must authenticate {email}");
    }

    // A wrong password must NOT authenticate.
    let first = identity
        .get_user_by_email(realm.id(), "user0000001@acme.demo")
        .expect("get_user_by_email")
        .expect("first user exists");
    let bad = identity
        .verify_password(
            realm.id(),
            first.id(),
            &CleartextPassword::from_string("not-the-password".to_string()),
        )
        .expect("verify_password");
    assert!(!bad, "wrong password must not authenticate a seeded user");
}

// ===== Scenario 2: demo.enabled = false is the production guard =====

#[tokio::test]
async fn seeding_skipped_when_demo_disabled() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let rbac = harness.rbac();

    // Same seeding block, but demo mode is OFF.
    let config = config_with_seeding("prod-like", 25, "prod.demo", false);
    reconcile_and_seed(identity, rbac, &config);

    // The realm is still declaratively created...
    let realm = identity
        .get_realm_by_name("prod-like")
        .expect("get_realm_by_name")
        .expect("declared realm must still be created");

    // ...but NO bulk users are seeded when demo.enabled is false.
    let page = identity
        .list_users(realm.id(), &hearth::core::PageRequest::new(0, 100))
        .expect("list_users");
    assert!(
        page.items.is_empty(),
        "no users may be seeded when demo.enabled is false"
    );
}

// ===== Scenario 3: idempotent + resumable via the sentinel =====

#[tokio::test]
async fn seeding_is_idempotent_and_resumable() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let rbac = harness.rbac();

    // First run: 20 users.
    let config20 = config_with_seeding("grow", 20, "grow.demo", true);
    reconcile_and_seed(identity, rbac, &config20);

    let realm = identity
        .get_realm_by_name("grow")
        .expect("get_realm_by_name")
        .expect("realm exists");

    let count = |id: &hearth::core::RealmId| {
        identity
            .list_users(
                id,
                &hearth::core::PageRequest::new(0, hearth::core::MAX_PAGE_LIMIT),
            )
            .expect("list_users")
            .total as usize
    };
    assert_eq!(count(realm.id()), 20, "first run seeds 20");

    // Second run at the same count: no-op (sentinel matches).
    reconcile_and_seed(identity, rbac, &config20);
    assert_eq!(
        count(realm.id()),
        20,
        "re-run at same count must not duplicate"
    );

    // Raise the count to 50: only the 30-user delta is seeded.
    let config50 = config_with_seeding("grow", 50, "grow.demo", true);
    reconcile_and_seed(identity, rbac, &config50);
    assert_eq!(
        count(realm.id()),
        50,
        "raising the count seeds only the delta"
    );
}

// ===== Scenario 4: large count crosses a memtable flush boundary =====
//
// 20k users × 3 keys comfortably exceeds the memtable flush threshold, so the
// earliest users are flushed to SSTs and must be read back from disk. This
// exercises the batched memtable write + flush + SST read path at non-trivial
// size — the 50-user scenarios above never cross a flush boundary, which is how
// the O(N²) per-entry-clone bug went unnoticed. With the batched `put_batch`
// this completes in well under a second.

#[tokio::test]
async fn seeding_large_count_crosses_flush_boundary() {
    let harness = common::TestHarness::embedded().await.expect("harness");
    let identity = harness.identity();
    let rbac = harness.rbac();

    let config = config_with_seeding("bigco", 20_000, "bigco.demo", true);
    reconcile_and_seed(identity, rbac, &config);

    let realm = identity
        .get_realm_by_name("bigco")
        .expect("get_realm_by_name")
        .expect("realm must exist");

    // Boundary users across the whole range exist, are Active, and authenticate
    // with the shared password. user0000001 was almost certainly flushed to an
    // SST by the time the 20,000th user was written, so this reads back from disk.
    for idx in [1u32, 9_999, 20_000] {
        let email = format!("user{idx:07}@bigco.demo");
        let user = identity
            .get_user_by_email(realm.id(), &email)
            .expect("get_user_by_email")
            .unwrap_or_else(|| panic!("seed user {email} must exist"));
        assert_eq!(user.status(), UserStatus::Active, "{email} must be Active");
        let ok = identity
            .verify_password(
                realm.id(),
                user.id(),
                &CleartextPassword::from_string(SHARED_PASSWORD.to_string()),
            )
            .expect("verify_password");
        assert!(ok, "shared password must authenticate {email}");
    }

    // Exactly target_count users — one past the end must not exist.
    assert!(
        identity
            .get_user_by_email(realm.id(), "user0020001@bigco.demo")
            .expect("get_user_by_email")
            .is_none(),
        "must not seed beyond target_count"
    );
}

// ===== Scenario 5: the shipped example config parses =====

#[test]
fn example_large_scale_demo_config_parses() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/examples/large-scale-demo/hearth.yaml"
    );
    // The example is a dev/demo config (loaded via `serve --dev --config`), so
    // validate it under the same relaxed dev-mode rules.
    let config = Config::from_file_as_dev(std::path::Path::new(path))
        .expect("examples/large-scale-demo/hearth.yaml must parse and validate");

    assert!(config.demo.enabled, "example must enable demo mode");
    let realms = config.realms.expect("example must declare realms");
    let total: u64 = realms
        .values()
        .filter_map(|r| r.seeding.as_ref())
        .map(|s| s.users)
        .sum();
    assert!(
        total >= 1_000_000,
        "example must seed at least 1M users across realms (got {total})"
    );
}

// ===== Scenario 6: the loadtest corpus config is a large corpus by default =====

/// `make loadtest` boots this config so the harness runs against a
/// multi-hundred-thousand-user corpus by default (HEA-1787). Guards the three
/// invariants the pipeline relies on: demo seeding is enabled, the rate
/// limiters are disabled (loopback-only), and the *default* (no env overrides)
/// corpus is genuinely large — not the old 200-user REST seed.
#[test]
fn loadtest_corpus_config_is_large_by_default() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/loadtest/loadtest-corpus.yaml");
    // Loaded via `serve --dev --config` by run-loadtest.sh, so validate under
    // the same relaxed dev-mode rules. Env placeholders carry `:-` defaults, so
    // this parses with no env set — the default corpus.
    let config = Config::from_file_as_dev(std::path::Path::new(path))
        .expect("loadtest/loadtest-corpus.yaml must parse and validate");

    assert!(config.demo.enabled, "loadtest corpus must enable demo mode");
    assert_eq!(
        config.security.load_test_unthrottled,
        Some(true),
        "loadtest corpus must disable rate limiters (loopback-only)"
    );

    let realms = config.realms.expect("loadtest corpus must declare realms");
    let total: u64 = realms
        .values()
        .filter_map(|r| r.seeding.as_ref())
        .map(|s| s.users)
        .sum();
    assert!(
        total >= 500_000,
        "default loadtest corpus must seed a large dataset (got {total})"
    );
}
