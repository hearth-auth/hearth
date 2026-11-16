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

/// One outbox read of the merger: the start key of the range, and the keys
/// that the read visited.
type OutboxRead = (Vec<u8>, Vec<Vec<u8>>);

/// Records each outbox read of the merger. Every call goes through to the
/// real engine.
struct OutboxReadRecorder {
    inner: Arc<dyn StorageEngine>,
    reads: std::sync::Mutex<Vec<OutboxRead>>,
}

impl OutboxReadRecorder {
    fn reads(&self) -> Vec<OutboxRead> {
        self.reads.lock().expect("reads").clone()
    }
}

impl StorageEngine for OutboxReadRecorder {
    fn get(
        &self,
        realm_id: &RealmId,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, crate::storage::StorageError> {
        self.inner.get(realm_id, key)
    }

    fn put(
        &self,
        realm_id: &RealmId,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), crate::storage::StorageError> {
        self.inner.put(realm_id, key, value)
    }

    fn delete(&self, realm_id: &RealmId, key: &[u8]) -> Result<(), crate::storage::StorageError> {
        self.inner.delete(realm_id, key)
    }

    fn scan(
        &self,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
    ) -> Result<Vec<crate::storage::ScanEntry>, crate::storage::StorageError> {
        self.inner.scan(realm_id, start, end)
    }

    fn scan_keys(
        &self,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
    ) -> Result<Vec<Vec<u8>>, crate::storage::StorageError> {
        self.inner.scan_keys(realm_id, start, end)
    }

    fn visit_keys(
        &self,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
        visit: &mut dyn FnMut(&[u8]) -> ControlFlow<()>,
    ) -> Result<(), crate::storage::StorageError> {
        if !start.starts_with(si::OUTBOX_PREFIX) {
            return self.inner.visit_keys(realm_id, start, end, visit);
        }
        let mut seen = Vec::new();
        let result = self.inner.visit_keys(realm_id, start, end, &mut |key| {
            seen.push(key.to_vec());
            visit(key)
        });
        self.reads
            .lock()
            .expect("reads")
            .push((start.to_vec(), seen));
        result
    }

    fn visit_entries(
        &self,
        realm_id: &RealmId,
        start: &[u8],
        end: &[u8],
        visit: &mut crate::storage::EntryVisitor<'_>,
    ) -> Result<(), crate::storage::StorageError> {
        self.inner.visit_entries(realm_id, start, end, visit)
    }

    fn count_prefix(
        &self,
        realm_id: &RealmId,
        prefix: &[u8],
        cap: u64,
    ) -> Result<u64, crate::storage::StorageError> {
        self.inner.count_prefix(realm_id, prefix, cap)
    }

    fn put_batch(
        &self,
        realm_id: &RealmId,
        entries: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<(), crate::storage::StorageError> {
        self.inner.put_batch(realm_id, entries)
    }

    fn write_batch(
        &self,
        realm_id: &RealmId,
        puts: &[(Vec<u8>, Vec<u8>)],
        deletes: &[Vec<u8>],
    ) -> Result<(), crate::storage::StorageError> {
        self.inner.write_batch(realm_id, puts, deletes)
    }

    fn list_realms(&self) -> Result<Vec<RealmId>, crate::storage::StorageError> {
        self.inner.list_realms()
    }

    fn begin_snapshot_restore(
        &self,
        snapshot_id: &str,
    ) -> Result<(), crate::storage::StorageError> {
        self.inner.begin_snapshot_restore(snapshot_id)
    }

    fn complete_snapshot_restore(&self) -> Result<(), crate::storage::StorageError> {
        self.inner.complete_snapshot_restore()
    }
}

/// An engine on a real store, with each outbox read of the merger recorded.
fn recording_engine() -> (
    tempfile::TempDir,
    Arc<OutboxReadRecorder>,
    EmbeddedIdentityEngine,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let inner = Arc::new(
        EmbeddedStorageEngine::open(StorageConfig::dev(dir.path().to_path_buf())).expect("open"),
    ) as Arc<dyn StorageEngine>;
    let recorder = Arc::new(OutboxReadRecorder {
        inner,
        reads: std::sync::Mutex::new(Vec::new()),
    });
    let storage = Arc::clone(&recorder) as Arc<dyn StorageEngine>;
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
    (dir, recorder, engine)
}

/// The outbox keys that the merger read, in read order, from read `from` on.
fn keys_read(recorder: &OutboxReadRecorder, from: usize) -> Vec<Vec<u8>> {
    recorder.reads()[from..]
        .iter()
        .flat_map(|(_, keys)| keys.clone())
        .collect()
}

#[test]
fn a_merge_reads_the_outbox_from_where_the_previous_merge_stopped() {
    // A read from the prefix start passes the tombstones of every key that
    // the earlier merges deleted, so each batch was slower than the one
    // before it (#870).
    let (_dir, recorder, engine) = recording_engine();
    let realm = create_test_realm(&engine);
    for i in 0..50 {
        create(
            &engine,
            &realm,
            &format!("user{i}@example.com"),
            &format!("User {i}"),
        );
    }

    let before = recorder.reads().len();
    assert_eq!(engine.merge_search_outbox(&realm, 10).expect("merge"), 10);
    let first = keys_read(&recorder, before);
    let last_of_first = first.last().expect("the first merge read keys").clone();

    let before = recorder.reads().len();
    assert_eq!(engine.merge_search_outbox(&realm, 10).expect("merge"), 10);
    let reads = recorder.reads();
    let (start, _) = &reads[before];
    assert!(
        start.as_slice() >= last_of_first.as_slice(),
        "the second merge read the outbox from {start:?}, before the last key of the \
         first merge {last_of_first:?}"
    );

    merge_all(&engine, &realm, 10);
    assert_eq!(outbox_users(&engine, &realm), Vec::<UserId>::new());
    assert_index_matches_records(&engine, &realm);
}

#[test]
fn an_outbox_key_before_the_cursor_is_merged_after_the_read_wraps() {
    let (_dir, recorder, engine) = recording_engine();
    let realm = create_test_realm(&engine);
    for i in 0..50 {
        create(
            &engine,
            &realm,
            &format!("user{i}@example.com"),
            &format!("User {i}"),
        );
    }
    let before = recorder.reads().len();
    engine.merge_search_outbox(&realm, 25).expect("merge");
    let cursor = keys_read(&recorder, before)
        .last()
        .expect("the merge read keys")
        .clone();

    // New users until one outbox key sorts before the cursor. A user id is
    // random, so about half of the new keys do.
    let mut early = None;
    for i in 0..200 {
        let user = create(
            &engine,
            &realm,
            &format!("late{i}@example.com"),
            "Late User",
        );
        let below = entries_under(&engine, &realm, si::OUTBOX_PREFIX)
            .iter()
            .any(|(k, _)| {
                k.as_slice() < cursor.as_slice() && si::outbox_user(k).as_ref() == Some(user.id())
            });
        if below {
            early = Some(user);
            break;
        }
    }
    let early = early.expect("a new outbox key sorts before the cursor");

    merge_all(&engine, &realm, 25);
    assert_eq!(outbox_users(&engine, &realm), Vec::<UserId>::new());
    assert_index_matches_records(&engine, &realm);
    let forward = entries_under(&engine, &realm, &si::forward_key(early.id()));
    assert_eq!(
        forward.len(),
        1,
        "the user whose key sorted before the cursor is indexed"
    );
}
