//! The trigram search index (#644): each user write puts an outbox entry in
//! its batch, and the merger turns the outbox into posting blocks that equal
//! a rebuild from the user records.

use super::*;

use std::collections::{BTreeMap, BTreeSet};
use std::ops::ControlFlow;

use crate::identity::search_index::{self as si, PostingBlock, Trigram};

/// All keys and values under `prefix` in `realm`.
fn entries_under(
    engine: &EmbeddedIdentityEngine,
    realm: &RealmId,
    prefix: &[u8],
) -> Vec<(Vec<u8>, Vec<u8>)> {
    let end = keys::prefix_end(prefix);
    let mut out = Vec::new();
    engine
        .storage
        .visit_entries(realm, prefix, &end, &mut |k, v| {
            out.push((k.to_vec(), v.to_vec()));
            ControlFlow::Continue(())
        })
        .expect("visit");
    out
}

fn outbox_users(engine: &EmbeddedIdentityEngine, realm: &RealmId) -> Vec<UserId> {
    entries_under(engine, realm, si::OUTBOX_PREFIX)
        .iter()
        .map(|(k, _)| si::outbox_user(k).expect("outbox key"))
        .collect()
}

/// Runs the merger until the outbox is empty.
fn merge_all(engine: &EmbeddedIdentityEngine, realm: &RealmId, step: usize) {
    for _ in 0..10_000 {
        if engine.merge_search_outbox(realm, step).expect("merge") == 0 {
            return;
        }
    }
    panic!("the merge does not end");
}

/// Asserts that the search index of `realm` is exactly the index that a
/// rebuild from its user records gives (docids aside).
fn assert_index_matches_records(engine: &EmbeddedIdentityEngine, realm: &RealmId) {
    let users: Vec<User> = entries_under(engine, realm, &keys::user_id_scan_prefix())
        .iter()
        .map(|(_, v)| EmbeddedIdentityEngine::deserialize_user(v).expect("user"))
        .collect();
    let forward: BTreeMap<Vec<u8>, (u64, BTreeSet<Trigram>)> =
        entries_under(engine, realm, si::FORWARD_PREFIX)
            .into_iter()
            .map(|(k, v)| (k, si::decode_forward(&v).expect("forward value")))
            .collect();
    let docs: BTreeMap<u64, Vec<u8>> = entries_under(engine, realm, si::DOC_PREFIX)
        .into_iter()
        .map(|(k, v)| {
            let raw: [u8; 8] = k[si::DOC_PREFIX.len()..].try_into().expect("docid");
            (u64::from_be_bytes(raw), v)
        })
        .collect();
    let mut postings: BTreeSet<(Trigram, u64)> = BTreeSet::new();
    for (k, v) in entries_under(engine, realm, si::POSTING_PREFIX) {
        let tri_bytes = &k[si::POSTING_PREFIX.len()..si::POSTING_PREFIX.len() + si::TRIGRAM_LEN];
        let t = si::decode_trigram(tri_bytes).expect("trigram");
        let bucket = si::posting_bucket(&si::posting_prefix(&t), &k).expect("bucket");
        let block = PostingBlock::decode(&v).expect("block");
        assert!(!block.is_empty(), "an empty block is deleted");
        for d in block.docids(bucket) {
            postings.insert((t, d));
        }
    }

    let mut expected_postings = BTreeSet::new();
    let mut seen_docids = BTreeSet::new();
    for user in &users {
        let (docid, trigrams) = forward
            .get(&si::forward_key(user.id()))
            .unwrap_or_else(|| panic!("user {} has a forward entry", user.email()))
            .clone();
        assert_eq!(trigrams, si::user_trigrams(user), "{}", user.email());
        assert_eq!(
            docs.get(&docid).map(Vec::as_slice),
            Some(user.id().as_uuid().as_bytes().as_slice()),
            "the docid of {} maps to it",
            user.email()
        );
        assert!(seen_docids.insert(docid), "docid {docid} is used once");
        for t in trigrams {
            expected_postings.insert((t, docid));
        }
    }
    assert_eq!(forward.len(), users.len(), "one forward entry per user");
    assert_eq!(docs.len(), users.len(), "one docid per user");
    assert_eq!(postings, expected_postings, "postings equal a rebuild");
}

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

fn rename(engine: &EmbeddedIdentityEngine, realm: &RealmId, user: &User, name: &str) {
    engine
        .update_user(
            realm,
            user.id(),
            &UpdateUserRequest {
                display_name: Some(name.to_string()),
                ..UpdateUserRequest::default()
            },
        )
        .expect("rename");
}

#[test]
fn a_change_of_the_indexed_text_puts_an_outbox_entry() {
    let (_dir, engine, _clock) = setup_engine();
    let realm = create_test_realm(&engine);

    let ann = create(&engine, &realm, "ann@example.com", "Ann");
    assert_eq!(
        outbox_users(&engine, &realm),
        vec![ann.id().clone()],
        "create"
    );

    rename(&engine, &realm, &ann, "Anna");
    assert_eq!(outbox_users(&engine, &realm).len(), 2, "rename");

    engine
        .update_user(
            &realm,
            ann.id(),
            &UpdateUserRequest {
                status: Some(UserStatus::Disabled),
                ..UpdateUserRequest::default()
            },
        )
        .expect("disable");
    assert_eq!(
        outbox_users(&engine, &realm).len(),
        2,
        "a status change keeps the text"
    );

    engine.delete_user(&realm, ann.id()).expect("delete");
    assert_eq!(outbox_users(&engine, &realm).len(), 3, "delete");
}

#[test]
fn the_merge_builds_the_index_of_the_records_and_empties_the_outbox() {
    let (_dir, engine, _clock) = setup_engine();
    let realm = create_test_realm(&engine);

    let mut users = Vec::new();
    for i in 0..60 {
        users.push(create(
            &engine,
            &realm,
            &format!("user{i}@example.com"),
            &format!("User {i}"),
        ));
    }
    merge_all(&engine, &realm, 1_000);
    assert_eq!(outbox_users(&engine, &realm), Vec::<UserId>::new());
    assert_index_matches_records(&engine, &realm);

    // Renames add and remove trigrams; deletes remove a user's postings.
    for user in users.iter().take(20) {
        rename(&engine, &realm, user, "Zed Quux");
    }
    for user in users.iter().skip(40) {
        engine.delete_user(&realm, user.id()).expect("delete");
    }
    merge_all(&engine, &realm, 1_000);
    assert_index_matches_records(&engine, &realm);
}

#[test]
fn a_merge_in_small_steps_gives_the_same_index() {
    let (_dir, engine, _clock) = setup_engine();
    let realm = create_test_realm(&engine);

    let users: Vec<User> = (0..25)
        .map(|i| {
            create(
                &engine,
                &realm,
                &format!("step{i}@example.org"),
                &format!("Step {i}"),
            )
        })
        .collect();
    for user in users.iter().step_by(3) {
        rename(&engine, &realm, user, "Renamed Once");
        rename(&engine, &realm, user, "Renamed Twice");
    }
    // Steps of 1 and 2 split the outbox entries of one user over merges.
    merge_all(&engine, &realm, 1);
    assert_index_matches_records(&engine, &realm);

    for user in users.iter().step_by(2) {
        rename(&engine, &realm, user, "Again");
    }
    merge_all(&engine, &realm, 2);
    assert_eq!(outbox_users(&engine, &realm), Vec::<UserId>::new());
    assert_index_matches_records(&engine, &realm);
}

#[test]
fn a_deleted_user_leaves_no_index_entry() {
    let (_dir, engine, _clock) = setup_engine();
    let realm = create_test_realm(&engine);

    let gone = create(&engine, &realm, "gone@example.com", "Gone Person");
    merge_all(&engine, &realm, 100);
    engine.delete_user(&realm, gone.id()).expect("delete");
    merge_all(&engine, &realm, 100);

    assert_eq!(
        entries_under(&engine, &realm, si::POSTING_PREFIX),
        Vec::new()
    );
    assert_eq!(
        entries_under(&engine, &realm, si::FORWARD_PREFIX),
        Vec::new()
    );
    assert_eq!(entries_under(&engine, &realm, si::DOC_PREFIX), Vec::new());
}

/// One step of the property test below.
#[derive(Debug, Clone)]
enum Op {
    Create(usize),
    Rename(usize, usize),
    ChangeEmail(usize),
    Delete(usize),
    Merge(usize),
}

/// Display names with case, accents, non-Latin text and short words.
const NAMES: &[&str] = &[
    "Ann",
    "ANN LEE",
    "Zoë Ünal",
    "日本語の名前",
    "Bo",
    "x",
    "Ann Anna Annie",
];

fn op_strategy() -> impl proptest::strategy::Strategy<Value = Op> {
    use proptest::prelude::*;
    prop_oneof![
        3 => (0..NAMES.len()).prop_map(Op::Create),
        2 => (0..32usize, 0..NAMES.len()).prop_map(|(u, n)| Op::Rename(u, n)),
        1 => (0..32usize).prop_map(Op::ChangeEmail),
        1 => (0..32usize).prop_map(Op::Delete),
        1 => (1..8usize).prop_map(Op::Merge),
    ]
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(24))]

    /// Any order of user writes and partial merges ends in the index that a
    /// rebuild from the user records gives.
    #[test]
    fn any_writes_and_partial_merges_give_the_rebuilt_index(
        ops in proptest::collection::vec(op_strategy(), 1..60)
    ) {
        let (_dir, engine, _clock) = setup_engine();
        let realm = create_test_realm(&engine);
        let mut live: Vec<User> = Vec::new();
        let mut serial = 0usize;
        for op in ops {
            serial += 1;
            match op {
                Op::Create(n) => {
                    live.push(create(&engine, &realm, &format!("p{serial}@example.com"), NAMES[n]));
                }
                Op::Rename(u, n) if !live.is_empty() => {
                    let user = live[u % live.len()].clone();
                    rename(&engine, &realm, &user, NAMES[n]);
                }
                Op::ChangeEmail(u) if !live.is_empty() => {
                    let user = live[u % live.len()].clone();
                    engine
                        .update_user(
                            &realm,
                            user.id(),
                            &UpdateUserRequest {
                                email: Some(format!("moved{serial}@example.org")),
                                ..UpdateUserRequest::default()
                            },
                        )
                        .expect("change email");
                }
                Op::Delete(u) if !live.is_empty() => {
                    let user = live.remove(u % live.len());
                    engine.delete_user(&realm, user.id()).expect("delete");
                }
                Op::Merge(step) => {
                    engine.merge_search_outbox(&realm, step).expect("merge");
                }
                _ => {}
            }
        }
        merge_all(&engine, &realm, 5);
        proptest::prop_assert!(outbox_users(&engine, &realm).is_empty());
        assert_index_matches_records(&engine, &realm);
    }
}
