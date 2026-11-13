//! User search on the trigram search index (#644). See
//! `identity/search_index.rs` for the index and `search_merge.rs` for the
//! merger that keeps it.
//!
//! A search first finds its candidates in an index, then reads the record of
//! each candidate and keeps the users that match. The candidates are:
//!
//! | Query | Candidates |
//! |-------|------------|
//! | 1 or 2 characters | the users whose email starts with it (email index) |
//! | text of 3 or more characters | the users whose index entry holds every trigram of the text, and every user with a write that the merger has not applied |
//! | `"exact"` of fewer than 3 characters | the email index entry and the name index entries of that text |
//! | glob with no 3 literal characters in a row | the email and name index entries that start with its first literal |
//!
//! A glob that has no 3 literal characters in a row and does not start with
//! a literal has no candidates in an index, and the search refuses it.
//!
//! The total is the exact number of matches. Up to [`IN_MEMORY_SORT_MAX`]
//! matches are sorted in memory; with more, the search walks the sort index
//! of the column and keeps the matches until the page is full.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::ops::ControlFlow;

use crate::core::{PageRequest, PagedResult, RealmId, UserId, MAX_PAGE_LIMIT};
use crate::identity::error::IdentityError;
use crate::identity::search::{GlobSegment, SearchQuery, SortDir, UserSortField};
use crate::identity::search_index::{self as si, PostingBlock, Trigram};
use crate::identity::{keys, user_index, User};

use super::EmbeddedIdentityEngine;

/// The largest number of matches that a search sorts in memory.
pub(super) const IN_MEMORY_SORT_MAX: usize = 10_000;

/// The largest number of query trigrams that a search reads. More trigrams
/// give fewer candidates, but each one is a read of its posting blocks.
const MAX_QUERY_TRIGRAMS: usize = 16;

/// The number of index entries that one step of an index walk reads.
const WALK_STEP: usize = 256;

/// How a search finds its candidates.
enum Plan {
    /// The users whose email starts with this text. The email index is
    /// written with the record, so each entry is a match.
    EmailPrefix(String),
    /// The users whose index entry holds all of these trigrams, and the
    /// users with a pending write.
    Trigrams(BTreeSet<Trigram>),
    /// The users whose email or lowercase name starts with this text.
    FieldPrefix(String),
    /// The users whose email or lowercase name is this text.
    FieldExact(String),
}

/// The plan of `query`, or `None` for a query that matches every user.
fn plan_of(query: &str, matcher: &SearchQuery) -> Result<Option<Plan>, IdentityError> {
    let q = query.trim();
    let chars = q.chars().count();
    let quoted = chars >= 2 && q.starts_with('"') && q.ends_with('"');
    if (1..=2).contains(&chars) && !quoted && !q.contains(['*', '?']) {
        return Ok(Some(Plan::EmailPrefix(q.to_lowercase())));
    }
    Ok(Some(match matcher {
        SearchQuery::MatchAll => return Ok(None),
        SearchQuery::Substring(text) => Plan::Trigrams(si::trigrams_of(text)),
        SearchQuery::Exact(text) if text.chars().count() >= 3 => {
            Plan::Trigrams(si::trigrams_of(text))
        }
        SearchQuery::Exact(text) => Plan::FieldExact(text.clone()),
        // A glob of stars only matches every user.
        SearchQuery::Glob(segments) if segments.iter().all(|s| *s == GlobSegment::Star) => {
            return Ok(None);
        }
        SearchQuery::Glob(segments) => {
            let mut trigrams = BTreeSet::new();
            for segment in segments {
                if let GlobSegment::Literal(text) = segment {
                    trigrams.extend(si::trigrams_of(text));
                }
            }
            if !trigrams.is_empty() {
                Plan::Trigrams(trigrams)
            } else if let Some(GlobSegment::Literal(start)) = segments.first() {
                Plan::FieldPrefix(start.clone())
            } else {
                return Err(IdentityError::InvalidInput {
                    reason: "the search pattern is too broad: give at least 3 characters in \
                             a row, or start the pattern with a character that is not a wildcard"
                        .to_string(),
                });
            }
        }
    }))
}

/// A user and its key in the sort index of the page.
type Keyed = (Vec<u8>, User);

impl EmbeddedIdentityEngine {
    /// One page of the users of `realm_id` that match `query`, in the order
    /// of `field` and `dir`, with the exact total. With `None`, the query
    /// matches every user and the caller lists the realm instead.
    pub(super) fn search_users_indexed(
        &self,
        realm_id: &RealmId,
        query: &str,
        page: &PageRequest,
        field: UserSortField,
        dir: SortDir,
        sort_max: usize,
    ) -> Result<Option<PagedResult<User>>, IdentityError> {
        let matcher = SearchQuery::compile(query);
        let Some(plan) = plan_of(query, &matcher)? else {
            return Ok(None);
        };
        let limit = page.limit.clamp(1, MAX_PAGE_LIMIT);
        let offset = usize::try_from(page.offset).unwrap_or(usize::MAX);
        let take = limit as usize;

        if let Plan::EmailPrefix(prefix) = &plan {
            let items_total =
                self.email_prefix_page(realm_id, prefix, offset, take, field, dir, sort_max)?;
            return Ok(Some(PagedResult::new(
                items_total.0,
                items_total.1,
                page.offset,
                limit,
            )));
        }

        let candidates = self.candidates(realm_id, &plan)?;
        let is_match = |user: &User| matcher.matches_any(&[user.email(), user.display_name()]);
        let mut total = 0_u64;
        let mut kept: Vec<Keyed> = Vec::new();
        let mut overflow = false;
        for id in candidates {
            let Some(user) = self.read_user(realm_id, &id)? else {
                continue;
            };
            if !is_match(&user) {
                continue;
            }
            total += 1;
            if !overflow {
                kept.push((user_index::index_key(&user, field, dir), user));
                if kept.len() > sort_max {
                    overflow = true;
                    kept = Vec::new();
                }
            }
        }
        let items = if overflow {
            self.walk_sort_index_matching(realm_id, field, dir, offset, take, &is_match)?
        } else {
            page_of_sorted(kept, offset, take)
        };
        Ok(Some(PagedResult::new(items, total, page.offset, limit)))
    }

    /// A page and the total of the users whose email starts with `prefix`.
    #[allow(clippy::too_many_arguments)]
    fn email_prefix_page(
        &self,
        realm_id: &RealmId,
        prefix: &str,
        offset: usize,
        take: usize,
        field: UserSortField,
        dir: SortDir,
        sort_max: usize,
    ) -> Result<(Vec<User>, u64), IdentityError> {
        // The email index is in email order, so its entries are the matches
        // in the order of an email-ascending page.
        let ids = self.email_prefix_ids(realm_id, prefix)?;
        let total = ids.len() as u64;
        if (field, dir) == (UserSortField::Email, SortDir::Asc) {
            let mut items = Vec::new();
            for id in ids.iter().skip(offset).take(take) {
                if let Some(user) = self.read_user(realm_id, id)? {
                    items.push(user);
                }
            }
            return Ok((items, total));
        }
        let is_match = |user: &User| user.email().starts_with(prefix);
        if ids.len() > sort_max {
            let items =
                self.walk_sort_index_matching(realm_id, field, dir, offset, take, &is_match)?;
            return Ok((items, total));
        }
        let mut kept: Vec<Keyed> = Vec::new();
        for id in &ids {
            if let Some(user) = self.read_user(realm_id, id)? {
                if is_match(&user) {
                    kept.push((user_index::index_key(&user, field, dir), user));
                }
            }
        }
        Ok((page_of_sorted(kept, offset, take), total))
    }

    /// The candidate users of `plan`, each once.
    fn candidates(&self, realm_id: &RealmId, plan: &Plan) -> Result<Vec<UserId>, IdentityError> {
        match plan {
            Plan::EmailPrefix(prefix) => self.email_prefix_ids(realm_id, prefix),
            Plan::Trigrams(trigrams) => self.trigram_candidates(realm_id, trigrams),
            Plan::FieldPrefix(prefix) => {
                let mut ids = self.email_prefix_ids(realm_id, prefix)?;
                let mut name = user_index::index_prefix(UserSortField::Name, SortDir::Asc);
                name.extend_from_slice(prefix.as_bytes());
                ids.extend(self.name_index_ids(realm_id, &name)?);
                Ok(unique(ids))
            }
            Plan::FieldExact(text) => {
                let mut ids: Vec<UserId> = self
                    .storage
                    .get(realm_id, &keys::encode_user_email(text))
                    .map_err(Self::storage_err)?
                    .and_then(|value| keys::decode_user_id_value(&value))
                    .into_iter()
                    .collect();
                let mut name = user_index::index_prefix(UserSortField::Name, SortDir::Asc);
                name.extend_from_slice(text.as_bytes());
                name.push(0x00);
                ids.extend(self.name_index_ids(realm_id, &name)?);
                Ok(unique(ids))
            }
        }
    }

    /// The users whose index entry holds every trigram of `trigrams` (at
    /// most [`MAX_QUERY_TRIGRAMS`] of them), then the users with a pending
    /// write. A pending user comes only from the outbox, so an index entry
    /// that its write makes stale is not a candidate.
    fn trigram_candidates(
        &self,
        realm_id: &RealmId,
        trigrams: &BTreeSet<Trigram>,
    ) -> Result<Vec<UserId>, IdentityError> {
        let pending: BTreeSet<UserId> = self.pending_search_users(realm_id)?;

        // Read the posting blocks of each trigram, and intersect them from
        // the trigram with the fewest documents.
        let mut lists: Vec<BTreeMap<u64, PostingBlock>> = Vec::new();
        for trigram in spread(trigrams, MAX_QUERY_TRIGRAMS) {
            let list = self.posting_list(realm_id, &trigram)?;
            if list.is_empty() {
                lists.clear();
                break;
            }
            lists.push(list);
        }
        lists.sort_by_key(|list| list.values().map(PostingBlock::len).sum::<usize>());
        let mut lists = lists.into_iter();
        let mut matched = lists.next().unwrap_or_default();
        for list in lists {
            matched.retain(|bucket, block| {
                list.get(bucket).is_some_and(|other| {
                    block.retain_common(other);
                    !block.is_empty()
                })
            });
            if matched.is_empty() {
                break;
            }
        }

        let mut ids = Vec::new();
        for (bucket, block) in &matched {
            for docid in block.docids(*bucket) {
                let Some(value) = self
                    .storage
                    .get(realm_id, &si::doc_key(docid))
                    .map_err(Self::storage_err)?
                else {
                    continue;
                };
                let Ok(raw) = <[u8; 16]>::try_from(value.as_slice()) else {
                    continue;
                };
                let id = UserId::new(uuid::Uuid::from_bytes(raw));
                if !pending.contains(&id) {
                    ids.push(id);
                }
            }
        }
        ids.extend(pending);
        Ok(ids)
    }

    /// The users named by the outbox of `realm_id`.
    fn pending_search_users(&self, realm_id: &RealmId) -> Result<BTreeSet<UserId>, IdentityError> {
        let end = keys::prefix_end(si::OUTBOX_PREFIX);
        let mut users = BTreeSet::new();
        self.storage
            .visit_keys(realm_id, si::OUTBOX_PREFIX, &end, &mut |key| {
                if let Some(id) = si::outbox_user(key) {
                    users.insert(id);
                }
                ControlFlow::Continue(())
            })
            .map_err(Self::storage_err)?;
        Ok(users)
    }

    /// The posting blocks of `trigram`, by bucket.
    fn posting_list(
        &self,
        realm_id: &RealmId,
        trigram: &Trigram,
    ) -> Result<BTreeMap<u64, PostingBlock>, IdentityError> {
        let prefix = si::posting_prefix(trigram);
        let end = keys::prefix_end(&prefix);
        let mut list = BTreeMap::new();
        self.storage
            .visit_entries(realm_id, &prefix, &end, &mut |key, value| {
                if let (Some(bucket), Some(block)) = (
                    si::posting_bucket(&prefix, key),
                    PostingBlock::decode(value),
                ) {
                    list.insert(bucket, block);
                }
                ControlFlow::Continue(())
            })
            .map_err(Self::storage_err)?;
        Ok(list)
    }

    /// The users of the email index entries that start with `prefix`, in
    /// email order.
    fn email_prefix_ids(
        &self,
        realm_id: &RealmId,
        prefix: &str,
    ) -> Result<Vec<UserId>, IdentityError> {
        let start = keys::encode_user_email(prefix);
        let end = keys::prefix_end(&start);
        let mut ids = Vec::new();
        self.storage
            .visit_entries(realm_id, &start, &end, &mut |_, value| {
                if let Some(id) = keys::decode_user_id_value(value) {
                    ids.push(id);
                }
                ControlFlow::Continue(())
            })
            .map_err(Self::storage_err)?;
        Ok(ids)
    }

    /// The users of the name-ascending index entries under `start`.
    fn name_index_ids(
        &self,
        realm_id: &RealmId,
        start: &[u8],
    ) -> Result<Vec<UserId>, IdentityError> {
        let end = keys::prefix_end(start);
        let mut ids = Vec::new();
        self.storage
            .visit_entries(realm_id, start, &end, &mut |key, value| {
                if let Some(id) =
                    user_index::entry_user_id(UserSortField::Name, SortDir::Asc, key, value)
                {
                    ids.push(id);
                }
                ControlFlow::Continue(())
            })
            .map_err(Self::storage_err)?;
        Ok(ids)
    }

    /// The record of `user_id`, or `None` when it is gone.
    fn read_user(
        &self,
        realm_id: &RealmId,
        user_id: &UserId,
    ) -> Result<Option<User>, IdentityError> {
        self.storage
            .get(realm_id, &keys::encode_user_id(user_id))
            .map_err(Self::storage_err)?
            .map(|bytes| Self::deserialize_user(&bytes))
            .transpose()
    }

    /// Walks the sort index of `field` and `dir` from its start, skips the
    /// first `skip` users that `is_match` keeps, and returns the next `take`
    /// of them. A stale entry (its record is gone or has another key) is
    /// skipped.
    fn walk_sort_index_matching(
        &self,
        realm_id: &RealmId,
        field: UserSortField,
        dir: SortDir,
        skip: usize,
        take: usize,
        is_match: &dyn Fn(&User) -> bool,
    ) -> Result<Vec<User>, IdentityError> {
        let prefix = user_index::index_prefix(field, dir);
        let end = keys::prefix_end(&prefix);
        let mut start = prefix;
        let mut skipped = 0_usize;
        let mut users = Vec::new();
        loop {
            let mut entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
            self.storage
                .visit_entries(realm_id, &start, &end, &mut |key, value| {
                    entries.push((key.to_vec(), value.to_vec()));
                    if entries.len() >= WALK_STEP {
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
                let Some(user) = self.read_user(realm_id, &id)? else {
                    continue;
                };
                if user_index::index_key(&user, field, dir) != *key || !is_match(&user) {
                    continue;
                }
                if skipped < skip {
                    skipped += 1;
                    continue;
                }
                users.push(user);
                if users.len() >= take {
                    return Ok(users);
                }
            }
            match entries.last() {
                Some((last, _)) if entries.len() >= WALK_STEP => {
                    start = last.clone();
                    start.push(0);
                }
                _ => return Ok(users),
            }
        }
    }
}

/// Sorts `kept` by key and returns the users at `offset`, at most `take`.
fn page_of_sorted(mut kept: Vec<Keyed>, offset: usize, take: usize) -> Vec<User> {
    kept.sort_by(|a, b| a.0.cmp(&b.0));
    kept.into_iter()
        .skip(offset)
        .take(take)
        .map(|(_, user)| user)
        .collect()
}

/// `ids` without repeats, in first-seen order.
fn unique(ids: Vec<UserId>) -> Vec<UserId> {
    let mut seen = HashSet::new();
    ids.into_iter()
        .filter(|id| seen.insert(id.clone()))
        .collect()
}

/// At most `max` trigrams of `trigrams`, spread over the whole set.
fn spread(trigrams: &BTreeSet<Trigram>, max: usize) -> Vec<Trigram> {
    let all: Vec<Trigram> = trigrams.iter().copied().collect();
    if all.len() <= max {
        return all;
    }
    (0..max).map(|i| all[i * all.len() / max]).collect()
}
