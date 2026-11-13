//! SCIM `startIndex` paging of users (#644).
//!
//! SCIM pages by position (`startIndex`), not by cursor. A position walks the
//! user keys up to it, so a client that reads a realm of `n` users in pages of
//! `p` would walk about `n² / 2p` keys. A memo keeps, for each realm and each
//! position where a page ended, the key of the last user of that page. The
//! next page in sequence starts after that key and reads only its own users.
//! A user deleted from an earlier page then does not move a user past the
//! client either.
//!
//! The memo is per node and is not persisted. A miss costs only the walk.

use std::collections::HashMap;
use std::ops::ControlFlow;
use std::sync::{Mutex, PoisonError};

use crate::core::{PagedResult, RealmId, MAX_PAGE_LIMIT};
use crate::identity::error::IdentityError;
use crate::identity::keys;
use crate::identity::User;
use crate::storage::ScanEntry;

use super::EmbeddedIdentityEngine;

/// Upper bound on remembered positions, over all realms. When the memo is
/// full, it is emptied: memory stays bounded however many clients page, and
/// a miss costs one walk.
const MEMO_MAX_POSITIONS: usize = 4_096;

/// Per-node memo: `(realm, position where a page ended)` → key of the last
/// user of that page.
pub(super) struct PositionMemo {
    // INVARIANT: guard released before each method returns; no .await in scope.
    last_keys: Mutex<HashMap<(RealmId, u64), Vec<u8>>>,
}

impl PositionMemo {
    pub(super) fn new() -> Self {
        Self {
            last_keys: Mutex::new(HashMap::new()),
        }
    }

    /// The key of the last user before `position`, when a page ended there.
    fn get(&self, realm_id: &RealmId, position: u64) -> Option<Vec<u8>> {
        self.last_keys
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&(realm_id.clone(), position))
            .cloned()
    }

    /// Records that a page ended at `position` with the user key `last_key`.
    fn remember(&self, realm_id: &RealmId, position: u64, last_key: Vec<u8>) {
        let mut last_keys = self
            .last_keys
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let key = (realm_id.clone(), position);
        if last_keys.len() >= MEMO_MAX_POSITIONS && !last_keys.contains_key(&key) {
            last_keys.clear();
        }
        last_keys.insert(key, last_key);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.last_keys
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

impl EmbeddedIdentityEngine {
    /// See [`crate::identity::IdentityEngine::list_users_at_position`].
    pub(super) fn list_users_at_position_inner(
        &self,
        realm_id: &RealmId,
        position: u64,
        limit: u32,
    ) -> Result<PagedResult<User>, IdentityError> {
        let prefix = keys::user_id_scan_prefix();
        let total = self
            .storage
            .count_prefix(realm_id, &prefix, 0)
            .map_err(Self::storage_err)?;
        let limit = limit.min(MAX_PAGE_LIMIT);
        if limit == 0 {
            return Ok(PagedResult::new(Vec::new(), total, position, 0));
        }

        let entries = if let Some(last_key) = self.scim_page_memo.get(realm_id, position) {
            self.user_entries_after(realm_id, &prefix, &last_key, limit)?
        } else {
            let walk_cap = position.saturating_add(u64::from(limit));
            self.storage
                .scan_prefix_paged(realm_id, &prefix, position, limit, walk_cap)
                .map_err(Self::storage_err)?
                .0
        };
        if let Some(last) = entries.last() {
            let end = position.saturating_add(entries.len() as u64);
            self.scim_page_memo
                .remember(realm_id, end, last.key.clone());
        }

        let items = entries
            .iter()
            .map(|entry| Self::deserialize_user(&entry.value))
            .collect::<Result<Vec<User>, IdentityError>>()?;
        Ok(PagedResult::new(items, total, position, limit))
    }

    /// Up to `limit` user records whose keys come after `after`, in key order.
    fn user_entries_after(
        &self,
        realm_id: &RealmId,
        prefix: &[u8],
        after: &[u8],
        limit: u32,
    ) -> Result<Vec<ScanEntry>, IdentityError> {
        let end = keys::prefix_end(prefix);
        // The smallest key above `after`.
        let mut start = after.to_vec();
        start.push(0);

        let mut first: Option<Vec<u8>> = None;
        let mut window_end: Option<Vec<u8>> = None;
        let mut seen: u32 = 0;
        self.storage
            .visit_keys(realm_id, &start, &end, &mut |key| {
                if seen == limit {
                    window_end = Some(key.to_vec());
                    return ControlFlow::Break(());
                }
                if seen == 0 {
                    first = Some(key.to_vec());
                }
                seen += 1;
                ControlFlow::Continue(())
            })
            .map_err(Self::storage_err)?;

        let Some(first) = first else {
            return Ok(Vec::new());
        };
        let window_end = window_end.unwrap_or(end);
        let mut window = self
            .storage
            .scan(realm_id, &first, &window_end)
            .map_err(Self::storage_err)?;
        // Keys written inside the window after the walk would lengthen it.
        window.truncate(limit as usize);
        Ok(window)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_memo_is_emptied_before_a_new_position() {
        let memo = PositionMemo::new();
        let realm = RealmId::new(uuid::Uuid::new_v4());
        for position in 0..MEMO_MAX_POSITIONS as u64 {
            memo.remember(&realm, position, vec![1]);
        }
        assert_eq!(memo.len(), MEMO_MAX_POSITIONS);

        memo.remember(&realm, 0, vec![2]);
        assert_eq!(memo.len(), MEMO_MAX_POSITIONS, "an update keeps the memo");
        assert_eq!(memo.get(&realm, 0), Some(vec![2]));

        memo.remember(&realm, MEMO_MAX_POSITIONS as u64, vec![3]);
        assert_eq!(memo.len(), 1, "a new position in a full memo empties it");
        assert_eq!(memo.get(&realm, MEMO_MAX_POSITIONS as u64), Some(vec![3]));
        assert_eq!(memo.get(&realm, 0), None);
    }

    #[test]
    fn the_memo_keeps_realms_apart() {
        let memo = PositionMemo::new();
        let a = RealmId::new(uuid::Uuid::new_v4());
        let b = RealmId::new(uuid::Uuid::new_v4());
        memo.remember(&a, 5, vec![1]);
        assert_eq!(memo.get(&a, 5), Some(vec![1]));
        assert_eq!(memo.get(&b, 5), None);
    }
}
