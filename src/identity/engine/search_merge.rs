//! The merger of the trigram search index (#644): it applies the outbox
//! entries of a realm to the posting blocks. See `identity/search_index.rs`.
//!
//! One merge reads up to `max_entries` outbox keys, reads the current record
//! and forward entry of each user that they name, and writes the changed
//! posting blocks, forward entries, docid map entries and the next docid in
//! one batch, with a delete of each outbox key that it read. A write that
//! lands after the merge read a record also put a new outbox key, so a later
//! merge indexes that user again. Only one merge runs at a time.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::ControlFlow;

use crate::core::{RealmId, UserId};
use crate::identity::error::IdentityError;
use crate::identity::keys;
use crate::identity::search_index::{self as si, PostingBlock, Trigram};

use super::EmbeddedIdentityEngine;

/// One change of a posting block: add or remove the docid with this offset.
type BlockChange = (u16, bool);

impl EmbeddedIdentityEngine {
    /// Applies up to `max_entries` outbox entries of `realm_id` to the search
    /// index, and returns the number of entries it applied.
    pub(crate) fn merge_search_outbox(
        &self,
        realm_id: &RealmId,
        max_entries: usize,
    ) -> Result<usize, IdentityError> {
        // The lock guards no data: a panic in a merge leaves nothing
        // half-written, so a poisoned lock is safe to take.
        let _merge = self
            .search_merge_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let outbox = self.read_outbox(realm_id, max_entries.max(1))?;
        if outbox.is_empty() {
            return Ok(0);
        }
        let users: BTreeSet<UserId> = outbox.iter().filter_map(|k| si::outbox_user(k)).collect();

        let mut next_docid = self.read_next_docid(realm_id)?;
        let start_docid = next_docid;
        let mut puts: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        let mut deletes: Vec<Vec<u8>> = outbox.clone();
        let mut blocks: BTreeMap<(Trigram, u64), Vec<BlockChange>> = BTreeMap::new();

        for user_id in &users {
            let record = self
                .storage
                .get(realm_id, &keys::encode_user_id(user_id))
                .map_err(Self::storage_err)?
                .map(|bytes| Self::deserialize_user(&bytes))
                .transpose()?;
            let forward_key = si::forward_key(user_id);
            let forward = self
                .storage
                .get(realm_id, &forward_key)
                .map_err(Self::storage_err)?
                .and_then(|bytes| si::decode_forward(&bytes));
            let new_trigrams = record.as_ref().map(si::user_trigrams).unwrap_or_default();

            let (docid, old_trigrams) = match (forward, record.is_some()) {
                (Some(entry), _) => entry,
                (None, true) => {
                    let docid = next_docid;
                    next_docid += 1;
                    puts.push((si::doc_key(docid), user_id.as_uuid().as_bytes().to_vec()));
                    (docid, BTreeSet::new())
                }
                (None, false) => continue,
            };
            let offset = si::offset_of(docid);
            let bucket = si::bucket_of(docid);
            for t in new_trigrams.difference(&old_trigrams) {
                blocks.entry((*t, bucket)).or_default().push((offset, true));
            }
            for t in old_trigrams.difference(&new_trigrams) {
                blocks
                    .entry((*t, bucket))
                    .or_default()
                    .push((offset, false));
            }
            if record.is_some() {
                puts.push((forward_key, si::encode_forward(docid, &new_trigrams)));
            } else {
                deletes.push(forward_key);
                deletes.push(si::doc_key(docid));
            }
        }

        for ((trigram, bucket), changes) in blocks {
            let key = si::posting_key(&trigram, si::first_docid_of(bucket));
            let mut block = self
                .storage
                .get(realm_id, &key)
                .map_err(Self::storage_err)?
                .map_or_else(PostingBlock::default, |bytes| {
                    PostingBlock::decode(&bytes).unwrap_or_else(|| {
                        tracing::warn!("search index: an unreadable posting block is rebuilt");
                        PostingBlock::default()
                    })
                });
            for (offset, add) in changes {
                if add {
                    block.insert(offset);
                } else {
                    block.remove(offset);
                }
            }
            if block.is_empty() {
                deletes.push(key);
            } else {
                puts.push((key, block.encode()));
            }
        }
        if next_docid != start_docid {
            puts.push((si::SEQ_KEY.to_vec(), next_docid.to_be_bytes().to_vec()));
        }

        self.storage
            .write_batch(realm_id, &puts, &deletes)
            .map_err(Self::storage_err)?;
        Ok(outbox.len())
    }

    /// Up to `max` outbox keys of `realm_id`, in key order.
    fn read_outbox(&self, realm_id: &RealmId, max: usize) -> Result<Vec<Vec<u8>>, IdentityError> {
        let end = keys::prefix_end(si::OUTBOX_PREFIX);
        let mut out = Vec::new();
        self.storage
            .visit_keys(realm_id, si::OUTBOX_PREFIX, &end, &mut |key| {
                out.push(key.to_vec());
                if out.len() >= max {
                    ControlFlow::Break(())
                } else {
                    ControlFlow::Continue(())
                }
            })
            .map_err(Self::storage_err)?;
        Ok(out)
    }

    /// The next free docid of `realm_id`.
    fn read_next_docid(&self, realm_id: &RealmId) -> Result<u64, IdentityError> {
        let bytes = self
            .storage
            .get(realm_id, si::SEQ_KEY)
            .map_err(Self::storage_err)?;
        Ok(bytes
            .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
            .map_or(0, u64::from_be_bytes))
    }
}
