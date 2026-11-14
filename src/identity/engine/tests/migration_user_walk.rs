//! A cross-realm migration lists the source users with one walk, not with
//! offset pages that each walk the realm up to their offset (#644).

use super::*;

use std::sync::atomic::Ordering;
use std::sync::Arc;

use super::user_list_reads::counting_engine;
use crate::config::MigrateConflictPolicy;
use crate::identity::migration::cross_realm::{
    execute_cross_realm_migration, CrossRealmMigrateOptions,
};

/// The user-record reads of one copy migration of `users` users.
fn migration_user_reads(users: u64) -> usize {
    let (_dir, counting, engine) = counting_engine();
    let src = create_test_realm(&engine);
    let dst = create_test_realm(&engine);
    for i in 0..users {
        engine
            .create_user(
                &src,
                &CreateUserRequest {
                    email: format!("u{i:05}@example.com"),
                    display_name: format!("User {i}"),
                    ..Default::default()
                },
            )
            .expect("create user");
    }
    let storage = Arc::clone(&counting) as Arc<dyn StorageEngine>;
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000_000)));
    let rbac = crate::rbac::EmbeddedRbacEngine::new(Arc::clone(&storage), clock);
    let opts = CrossRealmMigrateOptions {
        move_semantics: false,
        users: true,
        orgs: false,
        on_conflict: MigrateConflictPolicy::Skip,
    };

    counting.user_reads.store(0, Ordering::SeqCst);
    let report = execute_cross_realm_migration(
        &engine,
        &rbac,
        storage.as_ref(),
        &src,
        &dst,
        "walk-src",
        &opts,
    )
    .expect("migration");
    assert_eq!(report.migrated, users);
    counting.user_reads.load(Ordering::SeqCst)
}

#[test]
fn a_migration_reads_each_source_user_a_fixed_number_of_times() {
    // Before the fix: 6,004 and 17,009 reads (each offset page walked the
    // user keys up to its offset).
    let small = migration_user_reads(1_000);
    let large = migration_user_reads(2_000);
    assert!(large <= small * 2 + 100, "small {small}, large {large}");
    // After the fix: 3,000 and 6,000 reads (3 per user).
    assert!(large <= 4 * 2_000, "large {large}");
}
