//! Sort indexes of user records (#644).
//!
//! A sorted user list walks one index in key order and reads one page of user
//! records, instead of a load and sort of every user. There is one index per
//! sort column and direction. Email ascending uses the email index
//! (`usr:email:{email}` → user id), so this module adds seven:
//!
//! | Index | Key |
//! |-------|-----|
//! | email, descending | `usr:sort:email:d:` + `!email` + `0xFF` + `!uuid` |
//! | name, ascending | `usr:sort:name:a:` + `lower(name)` + `0x00` + `uuid` |
//! | name, descending | `usr:sort:name:d:` + `!lower(name)` + `0xFF` + `!uuid` |
//! | status, ascending | `usr:sort:status:a:` + `rank` + `uuid` |
//! | status, descending | `usr:sort:status:d:` + `!rank` + `!uuid` |
//! | created, ascending | `usr:sort:created:a:` + `be(created)` + `uuid` |
//! | created, descending | `usr:sort:created:d:` + `!be(created)` + `!uuid` |
//!
//! `!` is the bitwise complement of each byte, so a descending index walks in
//! exactly the reverse order of the ascending one. The terminator after a
//! string (`0x00` ascending, `0xFF` descending) keeps a shorter string in its
//! place: UTF-8 text never holds either byte. The last 16 bytes of every key
//! give the user id. Values are empty.
//!
//! Each write of a user record writes all seven entries of the new value in
//! the same batch, and deletes only the old entries that differ. A race of
//! two writes can then leave a stale entry but never drop a needed one, and a
//! reader skips an entry whose record no longer matches it.

use crate::core::UserId;
use crate::identity::keys;
use crate::identity::search::{SortDir, UserSortField};
use crate::identity::types::{User, UserStatus};

/// One put of a write batch.
pub(crate) type IndexPut = (Vec<u8>, Vec<u8>);

/// The first bytes of every sort index key except email ascending.
const SORT_PREFIX: &str = "usr:sort:";

/// The length of the raw user id at the end of every sort index key.
const ID_LEN: usize = 16;

/// The sort indexes this module keeps: every pair but email ascending.
const KEPT: [(UserSortField, SortDir); 7] = [
    (UserSortField::Email, SortDir::Desc),
    (UserSortField::Name, SortDir::Asc),
    (UserSortField::Name, SortDir::Desc),
    (UserSortField::Status, SortDir::Asc),
    (UserSortField::Status, SortDir::Desc),
    (UserSortField::Created, SortDir::Asc),
    (UserSortField::Created, SortDir::Desc),
];

fn column_name(field: UserSortField) -> &'static str {
    match field {
        UserSortField::Email => "email",
        UserSortField::Name => "name",
        UserSortField::Status => "status",
        UserSortField::Created => "created",
    }
}

/// The status rank of the sort order: Active, then PendingVerification,
/// then Disabled.
fn status_rank(status: UserStatus) -> u8 {
    match status {
        UserStatus::Active => 0,
        UserStatus::PendingVerification => 1,
        UserStatus::Disabled => 2,
    }
}

/// The scan prefix of the index for `field` and `dir`.
pub(crate) fn index_prefix(field: UserSortField, dir: SortDir) -> Vec<u8> {
    if (field, dir) == (UserSortField::Email, SortDir::Asc) {
        return keys::user_email_scan_prefix();
    }
    let dir = match dir {
        SortDir::Asc => "a",
        SortDir::Desc => "d",
    };
    format!("{SORT_PREFIX}{}:{dir}:", column_name(field)).into_bytes()
}

/// The key of `user` in the index for `field` and `dir`.
pub(crate) fn index_key(user: &User, field: UserSortField, dir: SortDir) -> Vec<u8> {
    if (field, dir) == (UserSortField::Email, SortDir::Asc) {
        return keys::encode_user_email(user.email());
    }
    let mut column: Vec<u8> = match field {
        UserSortField::Email => user.email().as_bytes().to_vec(),
        UserSortField::Name => user.display_name().to_lowercase().into_bytes(),
        UserSortField::Status => vec![status_rank(user.status())],
        // The sign bit flipped: a signed time sorts as unsigned bytes.
        #[allow(clippy::cast_sign_loss)]
        UserSortField::Created => ((user.created_at().as_micros() as u64) ^ (1 << 63))
            .to_be_bytes()
            .to_vec(),
    };
    let text = matches!(field, UserSortField::Email | UserSortField::Name);
    let mut id = user.id().as_uuid().as_bytes().to_vec();
    if dir == SortDir::Desc {
        for byte in column.iter_mut().chain(id.iter_mut()) {
            *byte = !*byte;
        }
    }
    let mut key = index_prefix(field, dir);
    key.reserve(column.len() + 1 + ID_LEN);
    key.extend_from_slice(&column);
    if text {
        key.push(if dir == SortDir::Desc { 0xFF } else { 0x00 });
    }
    key.extend_from_slice(&id);
    key
}

/// The scan prefix of the users with `status` in the status ascending
/// index. In it, the users of one status are in user-id order.
pub(crate) fn status_walk_prefix(status: UserStatus) -> Vec<u8> {
    let mut prefix = index_prefix(UserSortField::Status, SortDir::Asc);
    prefix.push(status_rank(status));
    prefix
}

/// The key of `user_id` in the status ascending index, for a user with
/// `status`.
pub(crate) fn status_walk_key(status: UserStatus, user_id: &UserId) -> Vec<u8> {
    let mut key = status_walk_prefix(status);
    key.extend_from_slice(user_id.as_uuid().as_bytes());
    key
}

/// The user id that an index entry points at.
pub(crate) fn entry_user_id(
    field: UserSortField,
    dir: SortDir,
    key: &[u8],
    value: &[u8],
) -> Option<UserId> {
    if (field, dir) == (UserSortField::Email, SortDir::Asc) {
        return keys::decode_user_id_value(value);
    }
    let start = key.len().checked_sub(ID_LEN)?;
    let mut id = [0_u8; ID_LEN];
    id.copy_from_slice(&key[start..]);
    if dir == SortDir::Desc {
        for byte in &mut id {
            *byte = !*byte;
        }
    }
    Some(UserId::new(uuid::Uuid::from_bytes(id)))
}

/// The index writes for a change of a user record from `old` to `new`
/// (`None`: the record does not exist): `(puts, deletes)`. The email
/// ascending index is the email index, which its own writers keep.
pub(crate) fn index_writes(
    old: Option<&User>,
    new: Option<&User>,
) -> (Vec<IndexPut>, Vec<Vec<u8>>) {
    let new_keys: Vec<Vec<u8>> = new
        .map(|user| KEPT.iter().map(|&(f, d)| index_key(user, f, d)).collect())
        .unwrap_or_default();
    let deletes = old
        .map(|user| {
            KEPT.iter()
                .map(|&(f, d)| index_key(user, f, d))
                .filter(|key| !new_keys.contains(key))
                .collect()
        })
        .unwrap_or_default();
    let puts = new_keys.into_iter().map(|key| (key, Vec::new())).collect();
    (puts, deletes)
}

/// Decodes a stored user record, for a writer that copies raw records and
/// must still write their index entries (the cross-realm move).
pub(crate) fn decode_record(bytes: &[u8]) -> Option<User> {
    crate::codec::decode::<crate::identity::types::user::UserStorageRecord>(bytes)
        .ok()
        .map(User::from_storage_record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::Timestamp;

    const FIELDS: [UserSortField; 4] = [
        UserSortField::Email,
        UserSortField::Name,
        UserSortField::Status,
        UserSortField::Created,
    ];

    fn user(email: &str, name: &str, status: UserStatus, created: i64) -> User {
        User::new(
            UserId::generate(),
            email.to_string(),
            name.to_string(),
            String::new(),
            String::new(),
            status,
            Vec::new(),
            Timestamp::from_micros(created),
            Timestamp::from_micros(created),
        )
    }

    fn rank(status: UserStatus) -> u8 {
        match status {
            UserStatus::Active => 0,
            UserStatus::PendingVerification => 1,
            UserStatus::Disabled => 2,
        }
    }

    /// The order a sorted list promises: the column, then the user id.
    fn expected_order(users: &[User], field: UserSortField, dir: SortDir) -> Vec<UserId> {
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

    fn sample() -> Vec<User> {
        vec![
            user("ab@x.io", "Bob", UserStatus::Active, 30),
            user("abc@x.io", "bob", UserStatus::Disabled, -5),
            user("a@x.io", "Alice", UserStatus::PendingVerification, 30),
            user("zed@x.io", "Al", UserStatus::Active, 1_000_000),
            user("m@x.io", "Ünal", UserStatus::Disabled, 0),
            user("b@x.io", "Bo", UserStatus::Active, 30),
        ]
    }

    #[test]
    fn every_index_walks_in_the_order_the_list_promises() {
        let users = sample();
        for field in FIELDS {
            for dir in [SortDir::Asc, SortDir::Desc] {
                let prefix = index_prefix(field, dir);
                let mut entries: Vec<(Vec<u8>, Vec<u8>)> = users
                    .iter()
                    .map(|u| {
                        let key = index_key(u, field, dir);
                        assert!(
                            key.starts_with(&prefix),
                            "{field:?} {dir:?}: key outside prefix"
                        );
                        let value = if (field, dir) == (UserSortField::Email, SortDir::Asc) {
                            keys::encode_user_id_value(u.id())
                        } else {
                            Vec::new()
                        };
                        (key, value)
                    })
                    .collect();
                entries.sort();
                let walked: Vec<UserId> = entries
                    .iter()
                    .map(|(k, v)| entry_user_id(field, dir, k, v).expect("user id of entry"))
                    .collect();
                assert_eq!(
                    walked,
                    expected_order(&users, field, dir),
                    "{field:?} {dir:?}"
                );
            }
        }
    }

    #[test]
    fn email_ascending_is_the_email_index() {
        let u = user("a@x.io", "A", UserStatus::Active, 1);
        assert_eq!(
            index_key(&u, UserSortField::Email, SortDir::Asc),
            keys::encode_user_email(u.email())
        );
        assert_eq!(
            index_prefix(UserSortField::Email, SortDir::Asc),
            keys::user_email_scan_prefix()
        );
    }

    #[test]
    fn a_new_record_puts_seven_entries_and_a_removed_one_deletes_them() {
        let u = user("a@x.io", "A", UserStatus::Active, 1);
        let (puts, deletes) = index_writes(None, Some(&u));
        assert_eq!((puts.len(), deletes.len()), (7, 0));
        assert!(puts.iter().all(|(_, v)| v.is_empty()));
        let (puts, deletes) = index_writes(Some(&u), None);
        assert_eq!((puts.len(), deletes.len()), (0, 7));
    }

    #[test]
    fn a_change_puts_every_entry_and_deletes_only_the_ones_that_differ() {
        let old = user("a@x.io", "A", UserStatus::Active, 1);
        let mut new = old.clone();
        new.set_display_name("B".to_string());
        let (puts, deletes) = index_writes(Some(&old), Some(&new));
        assert_eq!(puts.len(), 7);
        let mut expected = vec![
            index_key(&old, UserSortField::Name, SortDir::Asc),
            index_key(&old, UserSortField::Name, SortDir::Desc),
        ];
        expected.sort();
        let mut deletes = deletes;
        deletes.sort();
        assert_eq!(deletes, expected);
    }
}
