//! Key-cursor walks of the users of a realm (#644).
//!
//! An offset cursor walks every key before the offset, and a user deleted
//! before the offset moves the next user onto a page the client already
//! holds. A walk instead starts after the key of the last user it returned,
//! so each step reads only its own entries.

use std::ops::ControlFlow;

use crate::core::{RealmId, UserId, MAX_PAGE_LIMIT};
use crate::identity::error::IdentityError;
use crate::identity::search::{
    SortDir, UserCursorPage, UserPageCursor, UserSortField, UserWalk, UserWalkPage,
};
use crate::identity::{keys, user_index, User};

use super::EmbeddedIdentityEngine;

/// The first key after `key`: `key` plus a zero byte.
fn after_key(mut key: Vec<u8>) -> Vec<u8> {
    key.push(0);
    key
}

impl EmbeddedIdentityEngine {
    pub(super) fn walk_users_inner(
        &self,
        realm_id: &RealmId,
        walk: UserWalk,
        after: Option<&UserId>,
        limit: u32,
    ) -> Result<UserWalkPage, IdentityError> {
        let limit = limit.clamp(1, MAX_PAGE_LIMIT) as usize;
        match walk {
            UserWalk::All => self.walk_all_users(realm_id, after, limit),
            UserWalk::Status(status) => self.walk_users_with_status(realm_id, status, after, limit),
        }
    }

    /// Walks the user records themselves: one read for each user.
    fn walk_all_users(
        &self,
        realm_id: &RealmId,
        after: Option<&UserId>,
        limit: usize,
    ) -> Result<UserWalkPage, IdentityError> {
        let prefix = keys::user_id_scan_prefix();
        let end = keys::prefix_end(&prefix);
        let start = after.map_or_else(|| prefix.clone(), |id| after_key(keys::encode_user_id(id)));
        let mut entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        self.storage
            .visit_entries(realm_id, &start, &end, &mut |key, value| {
                entries.push((key.to_vec(), value.to_vec()));
                if entries.len() >= limit {
                    ControlFlow::Break(())
                } else {
                    ControlFlow::Continue(())
                }
            })
            .map_err(Self::storage_err)?;
        let more = entries.len() >= limit;
        let last = entries
            .last()
            .and_then(|(key, _)| keys::decode_user_record_key(key));
        let mut users = Vec::new();
        for (_, value) in &entries {
            users.push(Self::deserialize_user(value)?);
        }
        Ok(UserWalkPage { users, last, more })
    }

    /// Walks the status sort index for `status`, then reads the record of
    /// each entry. An entry whose record is gone or has another status is a
    /// stale entry of a racing write: the walk skips it.
    fn walk_users_with_status(
        &self,
        realm_id: &RealmId,
        status: crate::identity::UserStatus,
        after: Option<&UserId>,
        limit: usize,
    ) -> Result<UserWalkPage, IdentityError> {
        let prefix = user_index::status_walk_prefix(status);
        let end = keys::prefix_end(&prefix);
        let start = after.map_or_else(
            || prefix.clone(),
            |id| after_key(user_index::status_walk_key(status, id)),
        );
        let mut ids: Vec<UserId> = Vec::new();
        self.storage
            .visit_keys(realm_id, &start, &end, &mut |key| {
                if let Some(id) = key
                    .strip_prefix(prefix.as_slice())
                    .and_then(|raw| uuid::Uuid::from_slice(raw).ok())
                {
                    ids.push(UserId::new(id));
                }
                if ids.len() >= limit {
                    ControlFlow::Break(())
                } else {
                    ControlFlow::Continue(())
                }
            })
            .map_err(Self::storage_err)?;
        let more = ids.len() >= limit;
        let last = ids.last().cloned();
        let mut users: Vec<User> = Vec::new();
        for id in &ids {
            let Some(bytes) = self
                .storage
                .get(realm_id, &keys::encode_user_id(id))
                .map_err(Self::storage_err)?
            else {
                continue;
            };
            let user = Self::deserialize_user(&bytes)?;
            if user.status() == status {
                users.push(user);
            }
        }
        Ok(UserWalkPage { users, last, more })
    }

    pub(super) fn user_page_by_cursor_inner(
        &self,
        realm_id: &RealmId,
        field: UserSortField,
        dir: SortDir,
        cursor: &UserPageCursor,
        limit: u32,
    ) -> Result<UserCursorPage, IdentityError> {
        let limit = limit.clamp(1, MAX_PAGE_LIMIT) as usize;
        let total = self
            .storage
            .count_prefix(realm_id, &keys::user_id_scan_prefix(), 0)
            .map_err(Self::storage_err)?;
        let cursor_user = match cursor {
            UserPageCursor::First => None,
            UserPageCursor::After(id) | UserPageCursor::Before(id) => self
                .storage
                .get(realm_id, &keys::encode_user_id(id))
                .map_err(Self::storage_err)?
                .map(|bytes| Self::deserialize_user(&bytes))
                .transpose()?,
        };
        let first_page = |engine: &Self| -> Result<UserCursorPage, IdentityError> {
            let mut users = engine.walk_sort_index(realm_id, field, dir, None, limit + 1)?;
            let has_next = users.len() > limit;
            users.truncate(limit);
            Ok(UserCursorPage {
                users,
                has_prev: false,
                has_next,
                total,
            })
        };
        let Some(from) = cursor_user else {
            return first_page(self);
        };
        if matches!(cursor, UserPageCursor::After(_)) {
            let start = user_index::index_key(&from, field, dir);
            let mut users = self.walk_sort_index(realm_id, field, dir, Some(start), limit + 1)?;
            let has_next = users.len() > limit;
            users.truncate(limit);
            return Ok(UserCursorPage {
                users,
                has_prev: true,
                has_next,
                total,
            });
        }
        // The page before `from` is the page after it in the other direction,
        // read back to front.
        let back = match dir {
            SortDir::Asc => SortDir::Desc,
            SortDir::Desc => SortDir::Asc,
        };
        let start = user_index::index_key(&from, field, back);
        let mut users = self.walk_sort_index(realm_id, field, back, Some(start), limit + 1)?;
        if users.len() <= limit {
            // At most a page comes before `from`: that is the first page.
            return first_page(self);
        }
        users.truncate(limit);
        users.reverse();
        Ok(UserCursorPage {
            users,
            has_prev: true,
            has_next: true,
            total,
        })
    }

    /// Up to `want` users from the sort index of `field` and `dir`, after the
    /// index key `after` (exclusive) or from the start. An entry whose record
    /// is gone or no longer has that key is a stale entry of a racing write:
    /// the walk skips it and reads on.
    fn walk_sort_index(
        &self,
        realm_id: &RealmId,
        field: UserSortField,
        dir: SortDir,
        after: Option<Vec<u8>>,
        want: usize,
    ) -> Result<Vec<User>, IdentityError> {
        let prefix = user_index::index_prefix(field, dir);
        let end = keys::prefix_end(&prefix);
        let mut start = after.map_or_else(|| prefix.clone(), after_key);
        let mut users: Vec<User> = Vec::new();
        while users.len() < want {
            let ask = want - users.len();
            let mut entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
            self.storage
                .visit_entries(realm_id, &start, &end, &mut |key, value| {
                    entries.push((key.to_vec(), value.to_vec()));
                    if entries.len() >= ask {
                        ControlFlow::Break(())
                    } else {
                        ControlFlow::Continue(())
                    }
                })
                .map_err(Self::storage_err)?;
            for (key, value) in &entries {
                let Some(id) = user_index::entry_user_id(field, dir, key, value) else {
                    continue;
                };
                let Some(bytes) = self
                    .storage
                    .get(realm_id, &keys::encode_user_id(&id))
                    .map_err(Self::storage_err)?
                else {
                    continue;
                };
                let user = Self::deserialize_user(&bytes)?;
                if user_index::index_key(&user, field, dir) == *key {
                    users.push(user);
                }
            }
            let Some((last, _)) = entries.last() else {
                break;
            };
            if entries.len() < ask {
                break;
            }
            start = after_key(last.clone());
        }
        Ok(users)
    }
}
