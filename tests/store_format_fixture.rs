//! #646: this build must read the store that the committed fixture holds.
//!
//! `tests/fixtures/store-format/` is a data directory that the generator
//! (`scripts/regen-store-format-fixture.sh`) wrote with the current store
//! format. A change to how records, the WAL, SSTs or the key file are laid
//! out on disk breaks these tests. Then bump
//! `hearth::storage::format::STORE_FORMAT_VERSION`, regenerate the fixture and
//! say what an operator must do in `docs/guides/upgrading.md`.

#[path = "store_format/fixture.rs"]
mod fixture;

use std::path::{Path, PathBuf};

use hearth::audit::AuditEngine as _;
use hearth::identity::{CleartextPassword, IdentityEngine as _};
use hearth::storage::format::{FORMAT_FILE, STORE_FORMAT_VERSION};

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(fixture::FIXTURE_DIR)
}

fn manifest() -> fixture::Manifest {
    let text = std::fs::read_to_string(fixture_dir().join(fixture::MANIFEST_FILE))
        .expect("read the fixture manifest");
    serde_json::from_str(&text).expect("parse the fixture manifest")
}

/// Copies the fixture into a fresh directory: opening a store writes to it.
fn copy_of_fixture() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("data");
    std::fs::create_dir(&dir).expect("create data dir");
    for entry in std::fs::read_dir(fixture_dir()).expect("read fixture dir") {
        let entry = entry.expect("entry");
        if entry.file_name() != fixture::MANIFEST_FILE {
            std::fs::copy(entry.path(), dir.join(entry.file_name())).expect("copy");
        }
    }
    (tmp, dir)
}

/// The fixture must be the format of this build. If this fails, a change
/// bumped `STORE_FORMAT_VERSION` without a new fixture.
#[test]
fn the_fixture_has_this_builds_store_format() {
    let format = std::fs::read_to_string(fixture_dir().join(FORMAT_FILE)).expect("read FORMAT");
    assert_eq!(
        format,
        format!("hearth-store-format {STORE_FORMAT_VERSION}\n"),
        "STORE_FORMAT_VERSION is {STORE_FORMAT_VERSION}, but the fixture has another \
         format: run scripts/regen-store-format-fixture.sh"
    );
    assert_eq!(manifest().store_format, STORE_FORMAT_VERSION);
}

/// The data that the fixture holds reads back with this build: users and
/// passwords, a session (in the WAL), role permissions, signing keys and the
/// audit chain.
#[test]
fn this_build_reads_the_fixture_store() {
    let m = manifest();
    let (realm, users, session) = fixture::ids(&m);
    let (_tmp, dir) = copy_of_fixture();
    let e = fixture::open(&dir, fixture::T0_MICROS + 60_000_000).unwrap_or_else(|err| {
        panic!(
            "this build cannot open the fixture store: {err}. If the on-disk format changed, \
             bump STORE_FORMAT_VERSION and run scripts/regen-store-format-fixture.sh"
        )
    });

    assert!(
        e.identity.get_realm(&realm).expect("get realm").is_some(),
        "the fixture realm is missing"
    );
    for (email, id) in &users {
        let user = e
            .identity
            .get_user_by_email(&realm, email)
            .expect("get user")
            .unwrap_or_else(|| panic!("user {email} is missing"));
        assert_eq!(user.id(), id, "user {email} has another id");
        assert!(
            e.identity
                .verify_password(
                    &realm,
                    id,
                    &CleartextPassword::from_string(fixture::PASSWORD.to_string())
                )
                .expect("verify password"),
            "the password of {email} does not verify"
        );
    }
    // The storage engine keeps the user count (#644, store format 2), so the
    // list total is the number of users without a walk.
    let listed = e
        .identity
        .list_users(&realm, &hearth::core::PageRequest::new(0, 1))
        .expect("list users");
    assert_eq!(
        listed.total,
        users.len() as u64,
        "the kept user count is wrong"
    );
    // A sorted list walks a sort index (#644, store format 3), so the store
    // must hold an entry of each user.
    let sorted = e
        .identity
        .search_users(
            &realm,
            "",
            &hearth::core::PageRequest::new(0, 100),
            Some(hearth::identity::search::UserSortField::Name),
            hearth::identity::search::SortDir::Desc,
        )
        .expect("sorted list");
    assert_eq!(
        sorted.items.len(),
        users.len(),
        "a sorted list misses users of the store"
    );
    let s = e
        .identity
        .get_session(&realm, &session)
        .expect("get session")
        .expect("the session (written to the WAL) is missing");
    assert_eq!(s.user_id(), &users[1].1);
    // The realm session list walks the live-session index (#644, store
    // format 4), so the store must hold an entry of the session.
    let live = e
        .identity
        .list_sessions_by_realm(&realm, &hearth::core::PageRequest::new(0, 10))
        .expect("list sessions");
    assert_eq!(live.total, 1, "the kept live-session count is wrong");
    assert_eq!(
        live.items
            .iter()
            .map(|s| s.id().clone())
            .collect::<Vec<_>>(),
        vec![session.clone()],
        "the realm session list misses the session of the store"
    );

    assert_eq!(
        fixture::permissions(e.rbac.as_ref(), &realm, &users[0].1).expect("permissions"),
        m.admin_permissions,
        "the admin's permissions changed"
    );
    assert_eq!(
        fixture::kids(e.identity.as_ref(), &realm).expect("kids"),
        m.kids,
        "the realm signing keys changed"
    );
    assert_eq!(
        e.audit.count_events(&realm).expect("count"),
        m.audit_events,
        "the audit event count changed"
    );
    assert!(
        e.audit
            .verify_integrity(&realm, None, None)
            .expect("verify the audit chain"),
        "the audit chain of the fixture does not verify"
    );
}

/// A store with another format version is refused before any record is read.
#[test]
fn a_store_with_another_format_is_refused() {
    let (_tmp, dir) = copy_of_fixture();
    let other = STORE_FORMAT_VERSION + 1;
    std::fs::write(
        dir.join(FORMAT_FILE),
        format!("hearth-store-format {other}\n"),
    )
    .expect("write FORMAT");
    let Err(err) = fixture::open(&dir, fixture::T0_MICROS) else {
        panic!("a store of format {other} must be refused");
    };
    assert!(
        err.contains(&format!("store format {STORE_FORMAT_VERSION}")),
        "the error must name the supported format: {err}"
    );
}
