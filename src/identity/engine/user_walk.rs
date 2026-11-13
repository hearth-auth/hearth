//! Key-cursor walks of the users of a realm (#644).
//!
//! An offset cursor walks every key before the offset, and a user deleted
//! before the offset moves the next user onto a page the client already
//! holds. A walk instead starts after the key of the last user it returned,
//! so each step reads only its own entries.

use std::ops::ControlFlow;

use crate::core::{RealmId, UserId, MAX_PAGE_LIMIT};
use crate::identity::error::IdentityError;
use crate::identity::search::{UserWalk, UserWalkPage};
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
}
