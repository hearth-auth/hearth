//! A user search reads the trigram search index, not every user record of
//! the realm (#644). Its matches and its total stay exact: a search also
//! reads the users whose writes the merger has not applied yet.

use super::*;

use std::sync::atomic::Ordering;

use super::user_list_reads::counting_engine;
use crate::identity::search::{SortDir, UserSortField};

fn create(engine: &EmbeddedIdentityEngine, realm: &RealmId, email: &str, name: &str) -> User {
    engine
        .create_user(
            realm,
            &CreateUserRequest {
                email: email.to_string(),
                display_name: name.to_string(),
                ..Default::default()
            },
        )
        .expect("create user")
}

fn merge_all(engine: &EmbeddedIdentityEngine, realm: &RealmId) {
    while engine.merge_search_outbox(realm, 1_024).expect("merge") > 0 {}
}

fn search(
    engine: &EmbeddedIdentityEngine,
    realm: &RealmId,
    query: &str,
) -> crate::core::PagedResult<User> {
    engine
        .search_users(
            realm,
            query,
            &crate::core::PageRequest::new(0, 50),
            None,
            SortDir::Asc,
        )
        .expect("search")
}

fn emails(page: &crate::core::PagedResult<User>) -> Vec<&str> {
    page.items.iter().map(User::email).collect()
}

#[test]
fn a_search_reads_only_the_records_of_its_candidates() {
    let (_dir, counting, engine) = counting_engine();
    let realm = create_test_realm(&engine);
    for i in 0..300 {
        let name = if i % 60 == 0 {
            format!("Zebra {i}")
        } else {
            format!("User {i}")
        };
        create(&engine, &realm, &format!("u{i:03}@example.com"), &name);
    }
    merge_all(&engine, &realm);

    counting.user_reads.store(0, Ordering::SeqCst);
    let page = search(&engine, &realm, "zebra");
    let reads = counting.user_reads.load(Ordering::SeqCst);

    assert_eq!(page.total, 5);
    assert_eq!(
        emails(&page),
        [
            "u000@example.com",
            "u060@example.com",
            "u120@example.com",
            "u180@example.com",
            "u240@example.com"
        ]
    );
    assert!(
        reads <= 10,
        "a search of 5 matches in 300 users read {reads} user records"
    );
}

#[test]
fn a_search_sees_the_writes_that_the_merger_has_not_applied() {
    let (_dir, _counting, engine) = counting_engine();
    let realm = create_test_realm(&engine);
    let kept = create(&engine, &realm, "kept@example.com", "Walrus One");
    let renamed = create(&engine, &realm, "renamed@example.com", "Walrus Two");
    let gone = create(&engine, &realm, "gone@example.com", "Walrus Three");
    merge_all(&engine, &realm);

    // None of these writes is merged.
    engine
        .update_user(
            &realm,
            renamed.id(),
            &UpdateUserRequest {
                display_name: Some("Otter".to_string()),
                ..UpdateUserRequest::default()
            },
        )
        .expect("rename");
    engine.delete_user(&realm, gone.id()).expect("delete");
    create(&engine, &realm, "new@example.com", "Walrus Four");
    engine
        .update_user(
            &realm,
            kept.id(),
            &UpdateUserRequest {
                status: Some(UserStatus::Disabled),
                ..UpdateUserRequest::default()
            },
        )
        .expect("disable");

    let page = search(&engine, &realm, "walrus");
    assert_eq!(emails(&page), ["kept@example.com", "new@example.com"]);
    assert_eq!(page.total, 2);
    assert_eq!(
        emails(&search(&engine, &realm, "otter")),
        ["renamed@example.com"]
    );
}

#[test]
fn a_search_of_one_or_two_characters_matches_the_start_of_the_email() {
    let (_dir, _counting, engine) = counting_engine();
    let realm = create_test_realm(&engine);
    create(&engine, &realm, "ab@example.com", "Zed");
    create(&engine, &realm, "xab@example.com", "Abby");
    create(&engine, &realm, "bob@example.com", "Bob");
    merge_all(&engine, &realm);

    assert_eq!(emails(&search(&engine, &realm, "ab")), ["ab@example.com"]);
    assert_eq!(emails(&search(&engine, &realm, "AB")), ["ab@example.com"]);
    assert_eq!(emails(&search(&engine, &realm, "b")), ["bob@example.com"]);
    assert_eq!(search(&engine, &realm, "b").total, 1);
}

#[test]
fn an_unsorted_search_is_in_email_order() {
    let (_dir, _counting, engine) = counting_engine();
    let realm = create_test_realm(&engine);
    for email in ["carol@example.com", "alice@example.com", "bob@example.com"] {
        create(&engine, &realm, email, "Same Name");
    }
    merge_all(&engine, &realm);
    assert_eq!(
        emails(&search(&engine, &realm, "same")),
        ["alice@example.com", "bob@example.com", "carol@example.com"]
    );
}

#[test]
fn a_glob_with_no_usable_text_is_refused_as_too_broad() {
    let (_dir, _counting, engine) = counting_engine();
    let realm = create_test_realm(&engine);
    create(&engine, &realm, "ab@example.com", "Zed");
    for query in ["*a*", "?b*", "*@?"] {
        let result = engine.search_users(
            &realm,
            query,
            &crate::core::PageRequest::new(0, 10),
            Some(UserSortField::Email),
            SortDir::Asc,
        );
        assert!(
            matches!(result, Err(IdentityError::InvalidInput { .. })),
            "{query}: {result:?}"
        );
    }
    // A glob with three characters in a row, or a start, is not too broad.
    assert_eq!(
        emails(&search(&engine, &realm, "*exa*")),
        ["ab@example.com"]
    );
    assert_eq!(emails(&search(&engine, &realm, "ab*")), ["ab@example.com"]);
    assert_eq!(emails(&search(&engine, &realm, "z?d")), ["ab@example.com"]);
}

/// What a search promises, from a scan of every user record: the users that
/// match, in the order of the sort index, and their number. `None` when the
/// query is too broad.
fn promised(
    users: &[User],
    query: &str,
    field: UserSortField,
    dir: SortDir,
) -> Option<Vec<UserId>> {
    use crate::identity::search::{GlobSegment, SearchQuery};
    let q = query.trim();
    let chars = q.chars().count();
    let quoted = chars >= 2 && q.starts_with('"') && q.ends_with('"');
    let matcher = SearchQuery::compile(query);
    if let SearchQuery::Glob(segments) = &matcher {
        let has_run = segments
            .iter()
            .any(|s| matches!(s, GlobSegment::Literal(t) if t.chars().count() >= 3));
        let starts = matches!(segments.first(), Some(GlobSegment::Literal(_)));
        let only_stars = segments.iter().all(|s| *s == GlobSegment::Star);
        if !has_run && !starts && !only_stars {
            return None;
        }
    }
    let lower = q.to_lowercase();
    let mut found: Vec<&User> = users
        .iter()
        .filter(|u| {
            if (1..=2).contains(&chars) && !quoted && !q.contains(['*', '?']) {
                u.email().starts_with(&lower)
            } else {
                matcher.matches_any(&[u.email(), u.display_name()])
            }
        })
        .collect();
    found.sort_by_cached_key(|u| crate::identity::user_index::index_key(u, field, dir));
    Some(found.into_iter().map(|u| u.id().clone()).collect())
}

/// All user records of `realm`.
fn all_users(engine: &EmbeddedIdentityEngine, realm: &RealmId) -> Vec<User> {
    let prefix = keys::user_id_scan_prefix();
    engine
        .storage
        .scan(realm, &prefix, &keys::prefix_end(&prefix))
        .expect("scan")
        .iter()
        .map(|e| EmbeddedIdentityEngine::deserialize_user(&e.value).expect("user"))
        .collect()
}

const PIECES: &[&str] = &["ann", "bob", "an", "Zoë", "éa", "Ab", "nn", "x"];

fn text_strategy() -> impl proptest::strategy::Strategy<Value = String> {
    use proptest::prelude::*;
    proptest::collection::vec(proptest::sample::select(PIECES), 1..4).prop_map(|p| p.concat())
}

fn query_strategy() -> impl proptest::strategy::Strategy<Value = String> {
    use proptest::prelude::*;
    let piece = proptest::sample::select(PIECES).prop_map(str::to_string);
    prop_oneof![
        text_strategy(),
        piece.clone(),
        text_strategy().prop_map(|t| t.to_uppercase()),
        text_strategy().prop_map(|t| format!("*{t}*")),
        piece.clone().prop_map(|t| format!("{t}*")),
        piece.clone().prop_map(|t| format!("?{t}*")),
        text_strategy().prop_map(|t| format!("\"{t}\"")),
        piece.prop_map(|t| format!("  {t}@ ")),
        Just("*".to_string()),
        Just("**".to_string()),
        Just("*?*".to_string()),
        Just(String::new()),
    ]
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(32))]

    /// A search gives the users, order and total of a scan of every record,
    /// with writes that the merger has and has not applied, for an in-memory
    /// sort and for a walk of the sort index.
    #[test]
    fn a_search_equals_a_scan_of_every_record(
        names in proptest::collection::vec((text_strategy(), text_strategy()), 1..25),
        renames in proptest::collection::vec((0..25usize, text_strategy()), 0..6),
        deletes in proptest::collection::vec(0..25usize, 0..3),
        queries in proptest::collection::vec(query_strategy(), 1..6),
        offset in 0..6u64,
    ) {
        let (_dir, _counting, engine) = counting_engine();
        let realm = create_test_realm(&engine);
        let mut users: Vec<User> = names
            .iter()
            .enumerate()
            .map(|(i, (local, name))| {
                create(&engine, &realm, &format!("{}{i}@example.com", local.to_lowercase()), name)
            })
            .collect();
        merge_all(&engine, &realm);
        // These writes stay in the outbox.
        for (u, name) in &renames {
            let user = &users[u % users.len()];
            engine
                .update_user(
                    &realm,
                    user.id(),
                    &UpdateUserRequest {
                        display_name: Some(name.clone()),
                        ..UpdateUserRequest::default()
                    },
                )
                .expect("rename");
        }
        for u in &deletes {
            if users.len() > 1 {
                let user = users.remove(u % users.len());
                engine.delete_user(&realm, user.id()).expect("delete");
            }
        }
        create(&engine, &realm, "late@example.com", "Ann Late");
        let records = all_users(&engine, &realm);

        for query in &queries {
            for (field, dir) in [
                (UserSortField::Email, SortDir::Asc),
                (UserSortField::Name, SortDir::Desc),
                (UserSortField::Created, SortDir::Asc),
            ] {
                for sort_max in [3, 10_000] {
                    let page = crate::core::PageRequest::new(offset, 4);
                    let got = engine
                        .search_users_indexed(&realm, query, &page, field, dir, sort_max)
                        .map(|found| found.map(|p| {
                            (p.total, p.items.iter().map(|u| u.id().clone()).collect::<Vec<_>>())
                        }));
                    let Some(all) = promised(&records, query, field, dir) else {
                        proptest::prop_assert!(
                            matches!(got, Err(IdentityError::InvalidInput { .. })),
                            "{query:?} is too broad: {got:?}"
                        );
                        continue;
                    };
                    let Some((total, items)) = got.expect("search") else {
                        // The query matches every user.
                        proptest::prop_assert_eq!(all.len(), records.len(), "{:?}", query);
                        continue;
                    };
                    let start = usize::try_from(offset).expect("offset").min(all.len());
                    let end = (start + 4).min(all.len());
                    proptest::prop_assert_eq!(total, all.len() as u64, "{:?} {:?} {:?}", query, field, sort_max);
                    proptest::prop_assert_eq!(&items, &all[start..end].to_vec(), "{:?} {:?} {:?}", query, field, sort_max);
                }
            }
        }
    }
}
