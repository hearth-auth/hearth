//! A user-list page reads about one page of user records, not the realm
//! (#644). The exact total comes from the count that the storage engine
//! keeps.

use super::*;

use std::ops::ControlFlow;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::storage::{EntryVisitor, ScanEntry, StorageError};

/// Counts the user records (`usr:id:` keys) that reads walk or return. Every
/// call goes through to the real engine, `count_prefix` included.
struct UserReadCountingStorage {
    inner: Arc<dyn StorageEngine>,
    user_reads: AtomicUsize,
}

impl UserReadCountingStorage {
    fn count(&self, key: &[u8]) {
        if key.starts_with(crate::core::USER_RECORD_KEY_PREFIX) {
            self.user_reads.fetch_add(1, Ordering::SeqCst);
        }
    }
}

impl StorageEngine for UserReadCountingStorage {
    fn get(&self, realm_id: &RealmId, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.count(key);
        self.inner.get(realm_id, key)
    }

    fn put(&self, realm_id: &RealmId, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        self.inner.put(realm_id, key, value)
    }

    fn delete(&self, realm_id: &RealmId, key: &[u8]) -> Result<(), StorageError> {
        self.inner.delete(realm_id, key)
    }

    fn scan(
        &self,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
    ) -> Result<Vec<ScanEntry>, StorageError> {
        let entries = self.inner.scan(realm_id, start, end)?;
        for entry in &entries {
            self.count(&entry.key);
        }
        Ok(entries)
    }

    fn scan_keys(
        &self,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
    ) -> Result<Vec<Vec<u8>>, StorageError> {
        let keys = self.inner.scan_keys(realm_id, start, end)?;
        for key in &keys {
            self.count(key);
        }
        Ok(keys)
    }

    fn visit_keys(
        &self,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
        visit: &mut dyn FnMut(&[u8]) -> ControlFlow<()>,
    ) -> Result<(), StorageError> {
        self.inner.visit_keys(realm_id, start, end, &mut |key| {
            self.count(key);
            visit(key)
        })
    }

    fn visit_entries(
        &self,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
        visit: &mut EntryVisitor<'_>,
    ) -> Result<(), StorageError> {
        self.inner
            .visit_entries(realm_id, start, end, &mut |key, value| {
                self.count(key);
                visit(key, value)
            })
    }

    fn count_prefix(
        &self,
        realm_id: &RealmId,
        prefix: &[u8],
        cap: u64,
    ) -> Result<u64, StorageError> {
        self.inner.count_prefix(realm_id, prefix, cap)
    }

    fn put_batch(
        &self,
        realm_id: &RealmId,
        entries: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<(), StorageError> {
        self.inner.put_batch(realm_id, entries)
    }

    fn write_batch(
        &self,
        realm_id: &RealmId,
        puts: &[(Vec<u8>, Vec<u8>)],
        deletes: &[Vec<u8>],
    ) -> Result<(), StorageError> {
        self.inner.write_batch(realm_id, puts, deletes)
    }

    fn list_realms(&self) -> Result<Vec<RealmId>, StorageError> {
        self.inner.list_realms()
    }

    fn begin_snapshot_restore(&self, snapshot_id: &str) -> Result<(), StorageError> {
        self.inner.begin_snapshot_restore(snapshot_id)
    }

    fn complete_snapshot_restore(&self) -> Result<(), StorageError> {
        self.inner.complete_snapshot_restore()
    }
}

/// An engine on a real store, with every user record read counted.
fn counting_engine() -> (
    tempfile::TempDir,
    Arc<UserReadCountingStorage>,
    EmbeddedIdentityEngine,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let inner = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf())).expect("open"),
    ) as Arc<dyn StorageEngine>;
    let counting = Arc::new(UserReadCountingStorage {
        inner,
        user_reads: AtomicUsize::new(0),
    });
    let storage = Arc::clone(&counting) as Arc<dyn StorageEngine>;
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000_000)));
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock) as Arc<dyn Clock>,
    ));
    let engine = EmbeddedIdentityEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock) as Arc<dyn Clock>,
        IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        },
        audit as Arc<dyn AuditEngine>,
    )
    .expect("engine")
    .with_hibp_transport(Arc::new(NeverPwnedStub));
    (dir, counting, engine)
}

#[test]
fn a_first_user_page_reads_one_page_of_records_and_reports_the_exact_total() {
    const USERS: usize = 300;
    const PAGE: u32 = 20;

    let (_dir, counting, engine) = counting_engine();
    let realm = create_test_realm(&engine);
    for i in 0..USERS {
        let request = CreateUserRequest {
            email: format!("user{i:04}@example.com"),
            display_name: format!("User {i:04}"),
            ..Default::default()
        };
        engine.create_user(&realm, &request).expect("create user");
    }

    counting.user_reads.store(0, Ordering::SeqCst);
    let page = engine
        .list_users(&realm, &crate::core::PageRequest::new(0, PAGE))
        .expect("list users");
    let reads = counting.user_reads.load(Ordering::SeqCst);

    assert_eq!(page.items.len(), PAGE as usize);
    assert_eq!(page.total, USERS as u64);
    // One page of keys for the window plus one page of records for the
    // values. A walk of the realm reads every user key at least once.
    assert!(
        reads <= 2 * PAGE as usize + 2,
        "a first page of {PAGE} read {reads} user keys or records"
    );
}

/// Every sort index holds exactly one entry per user record, at the key of
/// that record's current value (#644).
fn assert_sort_indexes_match_records(storage: &dyn StorageEngine, realm: &RealmId) {
    use crate::identity::user_index;

    let prefix = keys::user_id_scan_prefix();
    let users: Vec<User> = storage
        .scan(realm, &prefix, &keys::prefix_end(&prefix))
        .expect("scan users")
        .iter()
        .map(|entry| EmbeddedIdentityEngine::deserialize_user(&entry.value).expect("user"))
        .collect();
    for field in [
        UserSortField::Email,
        UserSortField::Name,
        UserSortField::Status,
        UserSortField::Created,
    ] {
        for dir in [SortDir::Asc, SortDir::Desc] {
            let index = user_index::index_prefix(field, dir);
            let mut found: Vec<Vec<u8>> = storage
                .scan_keys(realm, &index, &keys::prefix_end(&index))
                .expect("scan index");
            let mut expected: Vec<Vec<u8>> = users
                .iter()
                .map(|u| user_index::index_key(u, field, dir))
                .collect();
            found.sort();
            expected.sort();
            assert_eq!(found, expected, "the {field:?} {dir:?} index");
        }
    }
}

#[test]
fn every_user_write_path_keeps_the_sort_indexes() {
    let (_dir, engine, _clock) = setup_engine();
    let realm = create_test_realm(&engine);
    let storage = engine.storage.as_ref();

    let create = |email: &str, name: &str| {
        engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: email.to_string(),
                    display_name: name.to_string(),
                    ..Default::default()
                },
            )
            .expect("create user")
    };
    let alice = create("alice@example.com", "Alice");
    let bob = create("bob@example.com", "Bob");
    let carol = create("carol@example.com", "Carol");
    assert_sort_indexes_match_records(storage, &realm);

    engine
        .update_user(
            &realm,
            alice.id(),
            &UpdateUserRequest {
                display_name: Some("Zoe".to_string()),
                status: Some(UserStatus::Disabled),
                email: Some("zoe@example.com".to_string()),
                ..Default::default()
            },
        )
        .expect("update user");
    assert_sort_indexes_match_records(storage, &realm);

    let token = engine
        .initiate_email_change(&realm, bob.id(), "robert@example.com")
        .expect("initiate email change");
    engine
        .confirm_email_change(&realm, &token)
        .expect("confirm email change");
    assert_sort_indexes_match_records(storage, &realm);

    let pending = engine
        .import_user(
            &realm,
            &ImportUserRequest {
                id: None,
                email: "dave@example.com".to_string(),
                display_name: "Dave".to_string(),
                first_name: String::new(),
                last_name: String::new(),
                status: UserStatus::PendingVerification,
                credential: None,
                attributes: BTreeMap::new(),
                restored: None,
            },
        )
        .expect("import user");
    assert_sort_indexes_match_records(storage, &realm);
    let token = engine
        .issue_email_verification_token(&realm, pending.id())
        .expect("verification token");
    engine
        .verify_email_token(&realm, &token)
        .expect("verify email");
    assert_sort_indexes_match_records(storage, &realm);

    engine
        .seed_demo_users(
            &realm,
            &CleartextPassword::from_string("Seed-password-123!".to_string()),
            &DemoSeedSpec {
                target_count: 5,
                email_domain: "seed.example.com".to_string(),
                display_name_prefix: "Seed".to_string(),
                email_verified: true,
            },
        )
        .expect("seed users");
    assert_sort_indexes_match_records(storage, &realm);

    engine.delete_user(&realm, carol.id()).expect("delete user");
    assert_sort_indexes_match_records(storage, &realm);
}

/// The order that a sorted user list promises: the column (a name without
/// case), then the user id.
fn promised_order(users: &[User], field: UserSortField, dir: SortDir) -> Vec<UserId> {
    fn rank(status: UserStatus) -> u8 {
        match status {
            UserStatus::Active => 0,
            UserStatus::PendingVerification => 1,
            UserStatus::Disabled => 2,
        }
    }
    let mut sorted: Vec<&User> = users.iter().collect();
    sorted.sort_by(|a, b| {
        let column = match field {
            UserSortField::Email => a.email().cmp(b.email()),
            UserSortField::Name => a
                .display_name()
                .to_lowercase()
                .cmp(&b.display_name().to_lowercase()),
            UserSortField::Status => rank(a.status()).cmp(&rank(b.status())),
            UserSortField::Created => a.created_at().cmp(&b.created_at()),
        };
        column.then_with(|| a.id().as_uuid().as_bytes().cmp(b.id().as_uuid().as_bytes()))
    });
    if dir == SortDir::Desc {
        sorted.reverse();
    }
    sorted.into_iter().map(|u| u.id().clone()).collect()
}

use crate::identity::search::{SortDir, UserSortField};

const SORT_FIELDS: [UserSortField; 4] = [
    UserSortField::Email,
    UserSortField::Name,
    UserSortField::Status,
    UserSortField::Created,
];

#[test]
fn a_sorted_page_without_search_text_reads_one_page_of_records() {
    const USERS: usize = 300;
    const PAGE: u32 = 20;

    let (_dir, counting, engine) = counting_engine();
    let realm = create_test_realm(&engine);
    let mut users = Vec::with_capacity(USERS);
    for i in 0..USERS {
        // Names in mixed case, and a status mix with many equal values.
        let name = if i % 2 == 0 {
            format!("user {:03}", (i * 7) % USERS)
        } else {
            format!("User {:03}", (i * 7) % USERS)
        };
        let user = engine
            .create_user(
                &realm,
                &CreateUserRequest {
                    email: format!("u{:03}@example.com", (i * 11) % USERS),
                    display_name: name,
                    ..Default::default()
                },
            )
            .expect("create user");
        let user = if i % 3 == 0 {
            engine
                .update_user(
                    &realm,
                    user.id(),
                    &UpdateUserRequest {
                        status: Some(UserStatus::Disabled),
                        ..Default::default()
                    },
                )
                .expect("disable user")
        } else {
            user
        };
        users.push(user);
    }

    for field in SORT_FIELDS {
        for dir in [SortDir::Asc, SortDir::Desc] {
            let promised = promised_order(&users, field, dir);
            for offset in [0_u64, 40, 290] {
                counting.user_reads.store(0, Ordering::SeqCst);
                let page = engine
                    .search_users(
                        &realm,
                        "",
                        &crate::core::PageRequest::new(offset, PAGE),
                        Some(field),
                        dir,
                    )
                    .expect("sorted page");
                let reads = counting.user_reads.load(Ordering::SeqCst);

                let got: Vec<UserId> = page.items.iter().map(|u| u.id().clone()).collect();
                let start = usize::try_from(offset).expect("offset");
                let end = (start + PAGE as usize).min(USERS);
                assert_eq!(got, promised[start..end], "{field:?} {dir:?} at {offset}");
                assert_eq!(page.total, USERS as u64, "{field:?} {dir:?} total");
                assert!(
                    reads <= PAGE as usize + 2,
                    "{field:?} {dir:?} at {offset}: a page of {PAGE} read {reads} user records"
                );
            }
        }
    }
}

#[test]
fn a_sorted_page_skips_a_stale_index_entry_and_stays_full() {
    let (_dir, _counting, engine) = counting_engine();
    let realm = create_test_realm(&engine);
    let users: Vec<User> = (0..30)
        .map(|i| {
            engine
                .create_user(
                    &realm,
                    &CreateUserRequest {
                        email: format!("s{i:02}@example.com"),
                        display_name: format!("Name {i:02}"),
                        ..Default::default()
                    },
                )
                .expect("create user")
        })
        .collect();

    // A race of two writes can leave an entry for a value that the record
    // no longer holds. This one sorts first.
    let mut stale = users[5].clone();
    stale.set_display_name("Aaa".to_string());
    let stale_key =
        crate::identity::user_index::index_key(&stale, UserSortField::Name, SortDir::Asc);
    engine
        .storage
        .put(&realm, &stale_key, &[])
        .expect("put stale entry");

    let page = engine
        .search_users(
            &realm,
            "",
            &crate::core::PageRequest::new(0, 10),
            Some(UserSortField::Name),
            SortDir::Asc,
        )
        .expect("sorted page");
    let got: Vec<UserId> = page.items.iter().map(|u| u.id().clone()).collect();
    let promised = promised_order(&users, UserSortField::Name, SortDir::Asc);
    assert_eq!(got, promised[..10]);
    assert_eq!(page.total, 30);
}

/// A `PageRequest` built as a struct literal skips the clamp of
/// `PageRequest::new`. A sorted page still holds at most `MAX_PAGE_LIMIT`
/// users, so a caller cannot size the page (#644).
#[test]
fn a_sorted_page_holds_at_most_the_page_limit_for_an_unclamped_request() {
    use crate::core::MAX_PAGE_LIMIT;

    let users = MAX_PAGE_LIMIT as usize + 10;
    let (_dir, _counting, engine) = counting_engine();
    let realm = create_test_realm(&engine);
    for i in 0..users {
        let request = CreateUserRequest {
            email: format!("user{i:04}@example.com"),
            display_name: format!("User {i:04}"),
            ..Default::default()
        };
        engine.create_user(&realm, &request).expect("create user");
    }

    let unclamped = crate::core::PageRequest {
        offset: 0,
        limit: 1_000_000,
    };
    let page = engine
        .search_users(
            &realm,
            "",
            &unclamped,
            Some(UserSortField::Email),
            SortDir::Asc,
        )
        .expect("sorted page");

    assert_eq!(page.items.len(), MAX_PAGE_LIMIT as usize);
    assert_eq!(page.items[0].email(), "user0000@example.com");
    assert_eq!(page.total, users as u64);
}
