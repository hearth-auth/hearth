//! The trigram search index of user records (#644).
//!
//! A search reads the users whose email or display name holds the query,
//! instead of every user record of the realm. The index has these keys
//! (values in brackets):
//!
//! | Key | Value |
//! |-----|-------|
//! | `usr:srch:ob:` + `uuid` + `nonce` | empty: an outbox entry, one for each write that changes the indexed text |
//! | `usr:srch:fwd:` + `uuid` | the user's docid and the trigrams last indexed for it |
//! | `usr:srch:doc:` + `be(docid)` | the user id of the docid |
//! | `usr:srch:seq` | the next docid |
//! | `usr:srch:p:` + `trigram` + `be48(docid >> 16)` | a posting block: the docids of the bucket that hold the trigram |
//!
//! A **docid** is a small per-realm number for a user, so a posting costs one
//! or two bytes instead of a 16-byte user id. A **trigram** is three
//! consecutive characters of the lowercased email or display name, as three
//! big-endian `u32` code points. A **posting block** holds the docids of one
//! bucket of 65,536 docids that hold one trigram, so the block of a docid is
//! known without a search.
//!
//! Index writes are delayed. A user write puts only its outbox entry, in the
//! same batch as the record. The merger (`engine/search_merge.rs`) reads the
//! outbox, reads the current records, changes the posting blocks, and deletes
//! the outbox entries that it read, all in one batch. Each outbox entry has its
//! own random nonce, so a write after the merger's read leaves a new entry and
//! the merger indexes that user again. A search treats each user with an
//! outbox entry as not indexed and checks its record itself, so its result is
//! exact at any time.

use std::collections::BTreeSet;

use crate::core::UserId;
use crate::identity::types::User;

/// One put of a write batch.
pub(crate) type IndexPut = (Vec<u8>, Vec<u8>);

/// The prefix of the outbox entries.
pub(crate) const OUTBOX_PREFIX: &[u8] = b"usr:srch:ob:";
/// The prefix of the forward entries (user id → docid and trigrams).
pub(crate) const FORWARD_PREFIX: &[u8] = b"usr:srch:fwd:";
/// The prefix of the docid map (docid → user id).
pub(crate) const DOC_PREFIX: &[u8] = b"usr:srch:doc:";
/// The key of the next docid.
pub(crate) const SEQ_KEY: &[u8] = b"usr:srch:seq";
/// The prefix of the posting blocks.
pub(crate) const POSTING_PREFIX: &[u8] = b"usr:srch:p:";

/// The length of an encoded trigram: three big-endian `u32` code points.
pub(crate) const TRIGRAM_LEN: usize = 12;
/// The number of low docid bits that a posting block holds.
const BUCKET_BITS: u32 = 16;
/// The length of the bucket number in a posting block key.
const BUCKET_LEN: usize = 6;
/// The length of the random nonce of an outbox entry.
const NONCE_LEN: usize = 8;
/// The length of a raw user id.
const ID_LEN: usize = 16;

/// The tag of a posting block stored as a sorted list of `u16`.
const LIST_TAG: u8 = 0;
/// The tag of a posting block stored as a bitmap.
const BITMAP_TAG: u8 = 1;
/// The length of a posting block bitmap: one bit for each docid of a bucket.
const BITMAP_LEN: usize = 1 << (BUCKET_BITS - 3);

/// A trigram: three consecutive lowercased characters.
pub(crate) type Trigram = [char; 3];

/// The trigrams of `text`, lowercased.
pub(crate) fn trigrams_of(text: &str) -> BTreeSet<Trigram> {
    let chars: Vec<char> = text.to_lowercase().chars().collect();
    chars.windows(3).map(|w| [w[0], w[1], w[2]]).collect()
}

/// The trigrams that a search finds `user` by: those of the email and those
/// of the display name. A trigram across the two fields is not one of them.
pub(crate) fn user_trigrams(user: &User) -> BTreeSet<Trigram> {
    let mut set = trigrams_of(user.email());
    set.extend(trigrams_of(user.display_name()));
    set
}

/// The 12-byte key form of `trigram`.
pub(crate) fn encode_trigram(trigram: &Trigram) -> [u8; TRIGRAM_LEN] {
    let mut out = [0; TRIGRAM_LEN];
    let (slots, _) = out.as_chunks_mut::<4>();
    for (slot, c) in slots.iter_mut().zip(trigram) {
        *slot = u32::from(*c).to_be_bytes();
    }
    out
}

/// The trigram of a 12-byte key form, or `None` when a code point is not a
/// character.
pub(crate) fn decode_trigram(bytes: &[u8]) -> Option<Trigram> {
    if bytes.len() != TRIGRAM_LEN {
        return None;
    }
    let mut out = ['\0'; 3];
    let (chunks, _) = bytes.as_chunks::<4>();
    for (c, chunk) in out.iter_mut().zip(chunks) {
        *c = char::from_u32(u32::from_be_bytes(*chunk))?;
    }
    Some(out)
}

/// The key of the posting block of `trigram` that holds `docid`.
pub(crate) fn posting_key(trigram: &Trigram, docid: u64) -> Vec<u8> {
    let mut key = posting_prefix(trigram);
    key.extend_from_slice(&bucket_of(docid).to_be_bytes()[8 - BUCKET_LEN..]);
    key
}

/// The first key of the posting blocks of `trigram`.
pub(crate) fn posting_prefix(trigram: &Trigram) -> Vec<u8> {
    let mut key = Vec::with_capacity(POSTING_PREFIX.len() + TRIGRAM_LEN + BUCKET_LEN);
    key.extend_from_slice(POSTING_PREFIX);
    key.extend_from_slice(&encode_trigram(trigram));
    key
}

/// The bucket number of a posting block key of `trigram`.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "the search query reads it (#644 part 2b)")
)]
pub(crate) fn posting_bucket(trigram_prefix: &[u8], key: &[u8]) -> Option<u64> {
    let raw = key.strip_prefix(trigram_prefix)?;
    if raw.len() != BUCKET_LEN {
        return None;
    }
    let mut be = [0u8; 8];
    be[8 - BUCKET_LEN..].copy_from_slice(raw);
    Some(u64::from_be_bytes(be))
}

/// The key of the forward entry of `user_id`.
pub(crate) fn forward_key(user_id: &UserId) -> Vec<u8> {
    let mut key = FORWARD_PREFIX.to_vec();
    key.extend_from_slice(user_id.as_uuid().as_bytes());
    key
}

/// The key of the docid map entry of `docid`.
pub(crate) fn doc_key(docid: u64) -> Vec<u8> {
    let mut key = DOC_PREFIX.to_vec();
    key.extend_from_slice(&docid.to_be_bytes());
    key
}

/// A new outbox key of `user_id`, with a random nonce.
pub(crate) fn new_outbox_key(user_id: &UserId) -> Vec<u8> {
    let mut key = OUTBOX_PREFIX.to_vec();
    key.extend_from_slice(user_id.as_uuid().as_bytes());
    // A v4 UUID is 122 random bits; its first 8 bytes are random.
    key.extend_from_slice(&uuid::Uuid::new_v4().as_bytes()[..NONCE_LEN]);
    key
}

/// The user id of an outbox key.
pub(crate) fn outbox_user(key: &[u8]) -> Option<UserId> {
    let raw = key.strip_prefix(OUTBOX_PREFIX)?;
    if raw.len() != ID_LEN + NONCE_LEN {
        return None;
    }
    let id = uuid::Uuid::from_slice(&raw[..ID_LEN]).ok()?;
    Some(UserId::new(id))
}

/// The outbox put for a change of a user record from `old` to `new`
/// (`None`: the record does not exist), or `None` when the change keeps the
/// indexed text (the email and the display name, lowercased).
pub(crate) fn outbox_write(old: Option<&User>, new: Option<&User>) -> Option<IndexPut> {
    let text = |u: &User| (u.email().to_lowercase(), u.display_name().to_lowercase());
    let id = match (old, new) {
        (None, None) => return None,
        (Some(a), Some(b)) if text(a) == text(b) => return None,
        (_, Some(user)) | (Some(user), None) => user.id(),
    };
    Some((new_outbox_key(id), Vec::new()))
}

/// The value of a forward entry: the docid and the trigrams last indexed.
pub(crate) fn encode_forward(docid: u64, trigrams: &BTreeSet<Trigram>) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + trigrams.len() * TRIGRAM_LEN);
    out.extend_from_slice(&docid.to_be_bytes());
    for t in trigrams {
        out.extend_from_slice(&encode_trigram(t));
    }
    out
}

/// Decodes a forward entry value.
pub(crate) fn decode_forward(bytes: &[u8]) -> Option<(u64, BTreeSet<Trigram>)> {
    if bytes.len() < 8 || !(bytes.len() - 8).is_multiple_of(TRIGRAM_LEN) {
        return None;
    }
    let (head, rest) = bytes.split_at(8);
    let mut be = [0u8; 8];
    be.copy_from_slice(head);
    let (chunks, _) = rest.as_chunks::<TRIGRAM_LEN>();
    let trigrams = chunks
        .iter()
        .map(|chunk| decode_trigram(chunk))
        .collect::<Option<BTreeSet<_>>>()?;
    Some((u64::from_be_bytes(be), trigrams))
}

/// The docids of one posting block, as offsets in its bucket.
///
/// Encoded as a sorted list of big-endian `u16` (tag `0`) while that is
/// smaller than a bitmap, else as an 8 KiB bitmap (tag `1`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PostingBlock {
    offsets: BTreeSet<u16>,
}

impl PostingBlock {
    /// Decodes a stored block, or `None` when the bytes are not a block.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let (&tag, body) = bytes.split_first()?;
        let mut offsets = BTreeSet::new();
        match tag {
            LIST_TAG => {
                let (pairs, odd) = body.as_chunks::<2>();
                if !odd.is_empty() {
                    return None;
                }
                for pair in pairs {
                    offsets.insert(u16::from_be_bytes(*pair));
                }
            }
            BITMAP_TAG => {
                if body.len() != BITMAP_LEN {
                    return None;
                }
                for (i, byte) in body.iter().enumerate() {
                    for bit in 0..8 {
                        if byte & (1 << bit) != 0 {
                            // INVARIANT: i < 8,192, so i * 8 + bit < 65,536.
                            #[allow(clippy::cast_possible_truncation)]
                            offsets.insert((i * 8 + bit) as u16);
                        }
                    }
                }
            }
            _ => return None,
        }
        Some(Self { offsets })
    }

    /// The stored form, the smaller of the two encodings.
    pub(crate) fn encode(&self) -> Vec<u8> {
        if self.offsets.len() * 2 < BITMAP_LEN {
            let mut out = Vec::with_capacity(1 + self.offsets.len() * 2);
            out.push(LIST_TAG);
            for o in &self.offsets {
                out.extend_from_slice(&o.to_be_bytes());
            }
            out
        } else {
            let mut out = vec![0u8; 1 + BITMAP_LEN];
            out[0] = BITMAP_TAG;
            for &o in &self.offsets {
                out[1 + usize::from(o / 8)] |= 1 << (o % 8);
            }
            out
        }
    }

    /// Adds the docid with `offset` in the bucket.
    pub(crate) fn insert(&mut self, offset: u16) {
        self.offsets.insert(offset);
    }

    /// Removes the docid with `offset` in the bucket.
    pub(crate) fn remove(&mut self, offset: u16) {
        self.offsets.remove(&offset);
    }

    /// `true` when the block holds no docid.
    pub(crate) fn is_empty(&self) -> bool {
        self.offsets.is_empty()
    }

    /// The number of docids in the block.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the search query reads it (#644 part 2b)")
    )]
    pub(crate) fn len(&self) -> usize {
        self.offsets.len()
    }

    /// `true` when the block holds the docid with `offset`.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the search query reads it (#644 part 2b)")
    )]
    pub(crate) fn contains(&self, offset: u16) -> bool {
        self.offsets.contains(&offset)
    }

    /// The docids of the block in `bucket`, in ascending order.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the search query reads it (#644 part 2b)")
    )]
    pub(crate) fn docids(&self, bucket: u64) -> impl Iterator<Item = u64> + '_ {
        let base = bucket << BUCKET_BITS;
        self.offsets.iter().map(move |&o| base + u64::from(o))
    }
}

/// The bucket of `docid`.
pub(crate) fn bucket_of(docid: u64) -> u64 {
    docid >> BUCKET_BITS
}

/// The first docid of `bucket`.
pub(crate) fn first_docid_of(bucket: u64) -> u64 {
    bucket << BUCKET_BITS
}

/// The offset of `docid` in its bucket.
pub(crate) fn offset_of(docid: u64) -> u16 {
    // INVARIANT: the mask keeps 16 bits.
    #[allow(clippy::cast_possible_truncation)]
    let offset = (docid & 0xFFFF) as u16;
    offset
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::Timestamp;
    use crate::identity::types::UserStatus;
    use proptest::prelude::*;

    fn user(email: &str, name: &str) -> User {
        User::new(
            UserId::generate(),
            email.to_string(),
            name.to_string(),
            String::new(),
            String::new(),
            UserStatus::Active,
            Vec::new(),
            Timestamp::from_micros(1),
            Timestamp::from_micros(1),
        )
    }

    fn tri(s: &str) -> Trigram {
        let c: Vec<char> = s.chars().collect();
        [c[0], c[1], c[2]]
    }

    #[test]
    fn trigrams_are_the_lowercased_windows_of_three_characters() {
        let got: Vec<Trigram> = trigrams_of("AbcD").into_iter().collect();
        assert_eq!(got, vec![tri("abc"), tri("bcd")]);
        assert!(trigrams_of("ab").is_empty());
        assert_eq!(
            trigrams_of("ÉtÉ").into_iter().collect::<Vec<_>>(),
            vec![tri("été")]
        );
    }

    #[test]
    fn user_trigrams_do_not_cross_the_two_fields() {
        let got = user_trigrams(&user("ab@x.io", "Cd"));
        assert!(got.contains(&tri("ab@")));
        assert!(got.contains(&tri(".io")));
        assert!(!got.contains(&tri("ioc")) && !got.contains(&tri("ocd")));
        assert_eq!(got.len(), trigrams_of("ab@x.io").len());
    }

    #[test]
    fn a_trigram_key_round_trips_and_has_a_fixed_length() {
        let t = tri("a€z");
        let bytes = encode_trigram(&t);
        assert_eq!(bytes.len(), TRIGRAM_LEN);
        assert_eq!(decode_trigram(&bytes), Some(t));
        assert_eq!(decode_trigram(&[0xFF; TRIGRAM_LEN]), None);
    }

    #[test]
    fn posting_keys_sort_by_trigram_then_bucket() {
        let t = tri("abc");
        let a = posting_key(&t, 5);
        let b = posting_key(&t, 70_000);
        assert!(a.starts_with(&posting_prefix(&t)));
        assert!(a.starts_with(POSTING_PREFIX));
        assert!(a < b);
        assert_eq!(posting_bucket(&posting_prefix(&t), &a), Some(0));
        assert_eq!(posting_bucket(&posting_prefix(&t), &b), Some(1));
        assert_eq!(a, posting_key(&t, 65_535));
        assert!(posting_key(&tri("abd"), 0) > b);
    }

    #[test]
    fn outbox_keys_are_unique_and_name_the_user() {
        let id = UserId::generate();
        let a = new_outbox_key(&id);
        let b = new_outbox_key(&id);
        assert_ne!(a, b);
        assert!(a.starts_with(OUTBOX_PREFIX));
        assert_eq!(outbox_user(&a), Some(id));
        assert_eq!(outbox_user(b"usr:srch:ob:short"), None);
    }

    #[test]
    fn only_a_change_of_the_indexed_text_writes_the_outbox() {
        let a = user("a@x.io", "Ann");
        assert!(outbox_write(None, Some(&a)).is_some(), "create");
        assert!(outbox_write(Some(&a), None).is_some(), "delete");
        assert!(outbox_write(Some(&a), Some(&a)).is_none(), "no change");
        let mut renamed = a.clone();
        renamed.set_display_name("Anna".to_string());
        assert!(outbox_write(Some(&a), Some(&renamed)).is_some(), "rename");
        let mut recased = a.clone();
        recased.set_display_name("ANN".to_string());
        assert!(
            outbox_write(Some(&a), Some(&recased)).is_none(),
            "the index is lowercased"
        );
        let put = outbox_write(None, Some(&a)).unwrap_or_default();
        assert_eq!(outbox_user(&put.0).as_ref(), Some(a.id()));
        assert_eq!(put.1, Vec::<u8>::new());
    }

    #[test]
    fn a_forward_entry_round_trips() {
        let t = trigrams_of("hello@x.io");
        let bytes = encode_forward(77, &t);
        assert_eq!(decode_forward(&bytes), Some((77, t)));
        assert_eq!(decode_forward(&[1, 2]), None);
    }

    #[test]
    fn docids_split_into_bucket_and_offset() {
        assert_eq!((bucket_of(0), offset_of(0)), (0, 0));
        assert_eq!((bucket_of(65_535), offset_of(65_535)), (0, 65_535));
        assert_eq!((bucket_of(65_536), offset_of(65_536)), (1, 0));
        assert!(doc_key(1) < doc_key(256));
    }

    #[test]
    fn a_small_block_is_a_list_and_a_large_block_is_a_bitmap() {
        let mut block = PostingBlock::default();
        assert!(block.is_empty());
        block.insert(3);
        block.insert(1);
        block.insert(3);
        assert_eq!(block.len(), 2);
        assert_eq!(block.encode(), vec![0, 0, 1, 0, 3]);
        let mut big = PostingBlock::default();
        for i in 0..5_000u16 {
            big.insert(i * 13);
        }
        let bytes = big.encode();
        assert_eq!(bytes.len(), 1 + 8_192);
        assert_eq!(bytes[0], 1);
        assert_eq!(PostingBlock::decode(&bytes), Some(big));
        assert_eq!(PostingBlock::decode(&[9]), None);
        assert_eq!(PostingBlock::decode(&[0, 1]), None);
    }

    #[test]
    fn block_docids_add_the_bucket_base() {
        let mut block = PostingBlock::default();
        block.insert(2);
        block.insert(7);
        assert_eq!(
            block.docids(3).collect::<Vec<_>>(),
            vec![3 * 65_536 + 2, 3 * 65_536 + 7]
        );
        block.remove(2);
        assert!(!block.contains(2));
        assert!(block.contains(7));
    }

    proptest! {
        #[test]
        fn a_block_round_trips(offsets in proptest::collection::btree_set(any::<u16>(), 0..6_000)) {
            let mut block = PostingBlock::default();
            for o in &offsets {
                block.insert(*o);
            }
            let bytes = block.encode();
            prop_assert!(bytes.len() <= 1 + 8_192);
            prop_assert_eq!(PostingBlock::decode(&bytes), Some(block.clone()));
            prop_assert_eq!(block.len(), offsets.len());
        }

        #[test]
        fn a_substring_holds_every_trigram_of_the_query(text in "[a-zé@. ]{0,24}", start in 0usize..24, len in 3usize..10) {
            let chars: Vec<char> = text.chars().collect();
            prop_assume!(start + len <= chars.len());
            let query: String = chars[start..start + len].iter().collect();
            let field = trigrams_of(&text);
            for t in trigrams_of(&query) {
                prop_assert!(field.contains(&t));
            }
        }
    }
}
