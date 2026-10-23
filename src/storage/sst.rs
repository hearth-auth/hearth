//! Sorted String Table (SST) persistence for memtable flushes.
//!
//! All SST files are encrypted at rest using AES-256-GCM envelope encryption.
//!
//! ## File formats
//!
//! ### V1 — original format (magic `b"HSST"`)
//!
//! ```text
//! BASE HEADER (12 bytes):
//!   [4B] magic    = b"HSST"
//!   [4B] entry_count (u32 LE)
//!   [4B] CRC32 of the plaintext data section
//!
//! ENCRYPTION HEADER (76 bytes): ...
//! ENCRYPTED DATA SECTION: serialized (CompositeKey, MemtableValue) entries
//! ```
//!
//! ### V2 — with per-file Bloom filter (magic `b"HSS2"`)
//!
//! ```text
//! BASE HEADER (12 bytes):
//!   [4B] magic    = b"HSS2"
//!   [4B] entry_count (u32 LE)
//!   [4B] CRC32 of the V2 plaintext data section (covers filter + entries)
//!
//! ENCRYPTION HEADER (76 bytes):
//!   [16B] KEK identifier (realm UUID bytes)
//!   [12B] Nonce used for DEK wrapping
//!   [32B] DEK ciphertext (AES-256-GCM output)
//!   [16B] GCM authentication tag for DEK wrapping
//!
//! ENCRYPTED DATA SECTION (variable):
//!   Plaintext inside the AES-256-GCM envelope:
//!     [4B] bloom_byte_count (u32 LE) — 0 for empty SSTs (no filter data)
//!     [1B] bloom_k — hash function count (only if bloom_byte_count > 0)
//!     [N B] bloom bits (only if bloom_byte_count > 0)
//!     [M B] serialized (CompositeKey, MemtableValue) entries (same as V1)
//! ```
//!
//! V1 SSTs are still readable (they load without a bloom filter;
//! `might_contain` returns `true` for every query).
//!
//! ### V3 — block-structured (magic `b"HSS3"`, HEA-1914)
//!
//! Data blocks of ~4 KiB, each sealed on its own, then one encrypted footer
//! that holds the whole block index and the whole Bloom filter. A reader keeps
//! that footer on the heap while the file is open. Still readable; no longer
//! written.
//!
//! ### V4 — partitioned index and filter (magic `b"HSS4"`, #445)
//!
//! ```text
//! BASE HEADER (12 bytes): magic, entry_count (u32 LE), CRC32 of the footer ciphertext
//! ENCRYPTION HEADER (76 bytes): as V2
//! BLOCKS, for each partition in key order:
//!   its data blocks          serialized entries, ~4 KiB of plaintext each
//!   its filter block         [1B k][Bloom bits] for the keys of its data blocks
//!   its index block          per data block: first key + block handle
//! FOOTER (encrypted):
//!   [8B]  entry_count (u64 LE), authenticated
//!   [4B]  partition count, then per partition:
//!         first key, index block handle, [1B has_filter], filter block handle
//!   [1B]  has_range, then the min and max keys
//! TRAILER (12 bytes): footer_offset (u64 LE) + footer_ciphertext_len (u32 LE)
//! ```
//!
//! A block handle is `[8B file_offset][4B ciphertext_len][4B plaintext_len]
//! [4B ordinal]`. Every block is sealed with `block_nonce(sst_number, ordinal)`
//! as nonce and AAD, where the ordinal is the block's position in write order,
//! so a block cannot be moved to another position or file. A reader keeps only
//! the footer's partition list on the heap. Filter and index blocks load
//! through the block cache like data blocks, so the heap of an open file does
//! not grow with the rows it holds.
//!
//! Per-file DEKs are randomly generated. The V1/V2 data nonce is derived from
//! the SST file number via `counter_nonce()`.

use std::path::Path;
use std::sync::Arc;

use uuid::Uuid;

use crate::core::RealmId;
use crate::storage::block_cache::{BlockCache, BlockId, CachedBlock};
use crate::storage::encryption::{
    self, block_nonce, counter_nonce, DataEncryptionKey, EncryptionHeader, KekId,
    SST_FOOTER_BLOCK_INDEX,
};
use crate::storage::error::StorageError;
use crate::storage::fs::{FileBacking, Fs, FsFile, RealFs};
use crate::storage::key_merge::KeyCursor;
use crate::storage::memtable::{CompositeKey, MemtableValue};

/// SST format V1 magic bytes — original format, no bloom filter.
const SST_MAGIC: &[u8; 4] = b"HSST";

/// SST format V2 magic bytes — includes per-file Bloom filter in the plaintext section.
const SST_MAGIC_V2: &[u8; 4] = b"HSS2";

/// SST format V3 magic bytes — block-structured, per-block AEAD, encrypted
/// footer index (HEA-1914). Still readable; no longer written.
const SST_MAGIC_V3: &[u8; 4] = b"HSS3";

/// SST format V4 magic bytes — V3's blocks, with the block index and the Bloom
/// filter split into partitions that load through the block cache (#445). New
/// SSTs are written v4.
const SST_MAGIC_V4: &[u8; 4] = b"HSS4";

/// Size of the base header: magic(4) + entry_count(4) + crc32(4).
const BASE_HEADER_SIZE: usize = 12;

/// Total header size: base(12) + encryption(76).
pub(crate) const TOTAL_HEADER_SIZE: usize = BASE_HEADER_SIZE + encryption::ENCRYPTION_HEADER_SIZE;

/// Target plaintext size of a data block, in bytes. Blocks never split an
/// entry, so an oversized single entry produces a larger block. ~4 KiB keeps a
/// decrypted block's heap footprint small while amortising per-block AEAD cost.
const BLOCK_TARGET_BYTES: usize = 4096;

/// Target plaintext size of a v4 index block. One index entry is about 60
/// bytes for Hearth's keys, so a partition covers about 270 data blocks, about
/// 1 MiB of data. The footer keeps one entry per partition on the heap: about
/// 0.01 % of the data, against about 2.4 % for v3's whole index and filter.
const INDEX_PARTITION_TARGET_BYTES: usize = 16 * 1024;

/// Fixed trailer written at the very end of a v3 or v4 file:
/// `[8B footer_offset (u64 LE)] [4B footer_ciphertext_len (u32 LE)]`.
const TRAILER_SIZE: usize = 12;

/// Sealed-block bytes a [`V4BodyWriter`] collects before one write to the
/// file. Bounds what the writer holds while it keeps write calls few: one call
/// per ~64 blocks instead of one per block.
const WRITE_CHUNK_BYTES: usize = 256 * 1024;

/// Bytes a [`V4BodyWriter`] writes to the file between two syncs of its data
/// (#445). A compaction rewrites the whole store: up to ~1 GB in the
/// steady-state memory test. With one sync at the end, the kernel sent all of
/// it to the disk at once, and the WAL's syncs waited behind it, so writes
/// stalled for up to seconds. Each stalled write kept a blocking-pool thread,
/// and the pool never shrank. With a sync every 4 MiB, a WAL sync waits behind
/// about 4 MiB at most.
const SYNC_EVERY_BYTES: usize = 4 * 1024 * 1024;

/// Minimum byte length of a serialized entry: type(1) + realm(16) + key_len(4)
/// + val_len(4), with an empty key and an empty/tombstone value.
///
/// The base header's `entry_count` is *unauthenticated* — it sits outside both
/// the AEAD and the CRC on every format version — so it MUST NOT size an
/// allocation directly. Every pre-allocation derived from it is clamped by this
/// constant against a length that *is* authenticated (a decrypted section's
/// plaintext length, or the sealed footer's per-block plaintext lengths), which
/// bounds the reservation to something the real file could actually contain
/// (HEA-1917).
const SST_MIN_ENTRY_BYTES: usize = 1 + 16 + 4 + 4;

/// One entry of the v3 footer's block index. Loaded eagerly at open (size is
/// `O(#blocks)`, not `O(#entries)`); the block payloads stay on disk / mmap.
#[derive(Debug, Clone)]
struct BlockIndexEntry {
    /// First `CompositeKey` in the block — the search key for locating the block
    /// that may contain a lookup key.
    first_key: CompositeKey,
    /// Byte offset of the block's ciphertext from the start of the file.
    file_offset: u64,
    /// Length of the block's ciphertext (including the 16-byte GCM tag).
    ciphertext_len: u32,
    /// Length of the block's decrypted plaintext (cache-weight accounting).
    plaintext_len: u32,
}

// ── Bloom filter ─────────────────────────────────────────────────────────────

/// Probabilistic Bloom filter for fast membership tests on SST entries.
///
/// Keys are realm-scoped: the `(realm_id, key)` pair is hashed together, so a
/// filter built for realm A never yields false positives for realm B's keys.
///
/// Uses `k = 7` independent bit positions derived from two CRC32-based hashes
/// via double hashing: `H(i) = H1 + i · H2 (mod m)`. This scheme produces
/// statistically independent bit positions from just two fast hash evaluations.
///
/// **Invariant**: a present key is NEVER reported absent (no false negatives).
/// A false positive causes one unnecessary SST binary search — a performance
/// cost, never a correctness error.
#[derive(Debug)]
pub(crate) struct BloomFilter {
    /// Bit array — each position maps to one double-hash probe position.
    bits: Vec<u8>,
    /// Number of hash functions (probe positions) per key insertion / test.
    k: u8,
}

impl BloomFilter {
    /// Builds a filter sized for `entries` at approximately 1% FPR with k = 7.
    ///
    /// Allocates ≈ 10 bits per entry, which is slightly above the theoretical
    /// optimum of 9.6 bits for FPR = 1%, k = 7, for a round number.
    /// An empty entry slice returns an empty (always-passing) filter.
    fn build(entries: &[(CompositeKey, MemtableValue)]) -> Self {
        let mut filter = Self::empty_for(entries.len());
        for (key, _) in entries {
            filter.insert(key.realm_id(), key.key());
        }
        filter
    }

    /// Allocates an empty filter sized for `n` entries at ≈ 1% FPR with k = 7,
    /// ready to have each key `insert`ed. Sizing is decoupled from insertion so
    /// the SST writer can size the filter from a known entry count and then fill
    /// it in the same single pass it uses to serialize entries — no fully
    /// materialised entry slice required (HEA-1908).
    ///
    /// `n == 0` returns an empty (always-passing) filter.
    fn empty_for(n: usize) -> Self {
        if n == 0 {
            return Self {
                bits: Vec::new(),
                k: 0,
            };
        }
        let bit_count = n.saturating_mul(10).max(64);
        let byte_count = bit_count.div_ceil(8);
        Self {
            bits: vec![0u8; byte_count],
            k: 7,
        }
    }

    /// A filter sized for exactly the keys whose [`bloom_hashes`] are
    /// `hashes`, with every one of them inserted. A v4 writer keeps the hashes
    /// of one partition and builds its filter when the partition is sealed, so
    /// the filter is sized from the real row count (#445).
    fn from_hashes(hashes: &[(u64, u64)]) -> Self {
        let mut filter = Self::empty_for(hashes.len());
        for &(h1, h2) in hashes {
            filter.insert_hashes(h1, h2);
        }
        filter
    }

    /// A small filter, for tests of the block cache.
    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        Self::empty_for(8)
    }

    /// The plaintext of a v4 filter block: `[1B k][bits]`.
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.bits.len());
        out.push(self.k);
        out.extend_from_slice(&self.bits);
        out
    }

    /// Reads a v4 filter block's plaintext.
    fn decode(plaintext: &[u8]) -> Result<Self, StorageError> {
        let (&k, bits) = plaintext
            .split_first()
            .ok_or_else(|| StorageError::InvalidSstFormat {
                reason: "v4 filter block is empty".to_string(),
            })?;
        Ok(Self {
            bits: bits.to_vec(),
            k,
        })
    }

    /// The heap the filter's bits hold.
    fn heap_bytes(&self) -> usize {
        self.bits.capacity()
    }

    /// Sets k bit positions for the given `(realm_id, key)` pair.
    fn insert(&mut self, realm_id: &RealmId, key: &[u8]) {
        let (h1, h2) = bloom_hashes(realm_id, key);
        self.insert_hashes(h1, h2);
    }

    /// Sets the k bit positions of a key whose [`bloom_hashes`] are `(h1, h2)`.
    fn insert_hashes(&mut self, h1: u64, h2: u64) {
        if self.bits.is_empty() {
            return;
        }
        let m = (self.bits.len() * 8) as u64;
        for i in 0..u64::from(self.k) {
            let bit = h1.wrapping_add(i.wrapping_mul(h2)) % m;
            self.bits[(bit / 8) as usize] |= 1u8 << (bit % 8);
        }
    }

    /// Returns `true` if the key *might* be present; `false` means definitely absent.
    ///
    /// An empty filter (zero bits) always returns `true` so absent-filter SSTs
    /// are never skipped.
    fn might_contain(&self, realm_id: &RealmId, key: &[u8]) -> bool {
        if self.bits.is_empty() {
            return true;
        }
        let (h1, h2) = bloom_hashes(realm_id, key);
        let m = (self.bits.len() * 8) as u64;
        for i in 0..u64::from(self.k) {
            let bit = h1.wrapping_add(i.wrapping_mul(h2)) % m;
            if self.bits[(bit / 8) as usize] & (1u8 << (bit % 8)) == 0 {
                return false;
            }
        }
        true
    }
}

/// Returns two independent CRC32-based hashes for `(realm_id, key)`.
///
/// Different salts and input ordering make H1 and H2 statistically
/// uncorrelated. H2 is always odd so the double-hashing probe sequence
/// is a full permutation of all `m` bit positions.
fn bloom_hashes(realm_id: &RealmId, key: &[u8]) -> (u64, u64) {
    let realm_bytes = realm_id.as_uuid().as_bytes();
    let h1 = {
        // Salt: first four bytes of the golden-ratio constant (0x9e3779b1)
        let mut h = crc32fast::Hasher::new();
        h.update(b"\x9e\x37\x79\xb1");
        h.update(realm_bytes);
        h.update(key);
        u64::from(h.finalize())
    };
    let h2 = {
        // Salt: Murmur3 mix constant (0x514e28b7); note: key before realm
        let mut h = crc32fast::Hasher::new();
        h.update(b"\x51\x4e\x28\xb7");
        h.update(key);
        h.update(realm_bytes);
        u64::from(h.finalize()) | 1 // must be odd: coprime with any 2^k bit-array size
    };
    (h1, h2)
}

/// Parsed entries and optional bloom filter returned from [`SstReader::parse_v2_plaintext`].
type ParsedV2 = (Vec<(CompositeKey, MemtableValue)>, Option<BloomFilter>);

/// Serialises a `CompositeKey` into a v3 footer: `realm(16) + len(4) + bytes`.
/// Staging name for an SST being written: the target name with `.staging`
/// appended (`000123.sst` → `000123.sst.staging`).
///
/// `.staging` rather than `.tmp` so a staged memtable flush is
/// distinguishable from a compaction merge output, whose temporary target
/// already uses the `.tmp` suffix. Files with either extension are invisible
/// to the startup SST scan, and engine open sweeps any left behind by a crash
/// or write fault (audit 2026-08-28 §4.11#4).
fn staging_path_for(path: &Path) -> std::path::PathBuf {
    let mut name = path
        .file_name()
        .map(std::ffi::OsStr::to_os_string)
        .unwrap_or_default();
    name.push(".staging");
    path.with_file_name(name)
}

fn write_footer_key(buf: &mut Vec<u8>, key: &CompositeKey) {
    buf.extend_from_slice(key.realm_id().as_uuid().as_bytes());
    #[allow(clippy::cast_possible_truncation)]
    let len = key.key().len() as u32;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(key.key());
}

/// Reads a footer-serialised `CompositeKey` from `data` starting at `pos`,
/// returning the key and the position just past it.
fn read_footer_key(data: &[u8], pos: usize) -> Result<(CompositeKey, usize), StorageError> {
    let err = || StorageError::InvalidSstFormat {
        reason: "v3 footer: truncated key".to_string(),
    };
    if pos + 20 > data.len() {
        return Err(err());
    }
    let uuid_bytes: [u8; 16] = data[pos..pos + 16].try_into().map_err(|_| err())?;
    let key_len =
        u32::from_le_bytes(data[pos + 16..pos + 20].try_into().map_err(|_| err())?) as usize;
    let start = pos + 20;
    if start + key_len > data.len() {
        return Err(err());
    }
    let key = data[start..start + key_len].to_vec();
    Ok((
        CompositeKey::new(RealmId::new(Uuid::from_bytes(uuid_bytes)), key),
        start + key_len,
    ))
}

// ── Entries and data blocks ───────────────────────────────────────────────────

/// One serialized entry, borrowed from the plaintext it was read from.
#[derive(Clone, Copy)]
pub(crate) struct EntryRef<'a> {
    realm: &'a [u8; 16],
    key: &'a [u8],
    /// The value, or `None` for a tombstone.
    value: Option<&'a [u8]>,
}

impl<'a> EntryRef<'a> {
    /// The entry's key, without its realm.
    pub(crate) fn key(&self) -> &'a [u8] {
        self.key
    }

    /// The entry's value, or `None` for a tombstone.
    pub(crate) fn value(&self) -> Option<&'a [u8]> {
        self.value
    }

    /// Orders this entry against `(realm, key)` as [`CompositeKey`] orders:
    /// realm UUID bytes first, then key bytes.
    fn cmp_to(&self, realm: &RealmId, key: &[u8]) -> std::cmp::Ordering {
        self.realm
            .cmp(realm.as_uuid().as_bytes())
            .then_with(|| self.key.cmp(key))
    }

    /// Orders this entry against `key`, as [`CompositeKey`] orders.
    fn cmp_composite(&self, key: &CompositeKey) -> std::cmp::Ordering {
        self.cmp_to(key.realm_id(), key.key())
    }

    /// The entry's value as an owned [`MemtableValue`].
    fn memtable_value(&self) -> MemtableValue {
        self.value.map_or(MemtableValue::Tombstone, |v| {
            MemtableValue::Data(v.to_vec())
        })
    }

    /// The entry as an owned key and value.
    fn into_owned(self) -> (CompositeKey, MemtableValue) {
        (
            CompositeKey::new(
                RealmId::new(Uuid::from_bytes(*self.realm)),
                self.key.to_vec(),
            ),
            self.memtable_value(),
        )
    }
}

/// A borrowed view of an owned value: `None` for a tombstone.
fn value_view(value: &MemtableValue) -> Option<&[u8]> {
    match value {
        MemtableValue::Data(data) => Some(data),
        MemtableValue::Tombstone => None,
    }
}

/// Reads the serialized entry at `pos` in `data` and returns it with the
/// position of the next entry. This is the one parser of the entry format
/// that [`SstWriter::serialize_entry`] writes.
fn read_entry(data: &[u8], pos: usize) -> Result<(EntryRef<'_>, usize), StorageError> {
    let invalid = |reason: &str| StorageError::InvalidSstFormat {
        reason: reason.to_string(),
    };
    let len_at = |at: usize| {
        data.get(at..at.checked_add(4)?)
            .and_then(|b| b.try_into().ok())
            .map(|b| u32::from_le_bytes(b) as usize)
    };

    let entry_type = *data
        .get(pos)
        .ok_or_else(|| invalid("truncated entry: missing type byte"))?;
    let mut p = pos + 1;

    let realm: &[u8; 16] = data
        .get(p..p + 16)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| invalid("truncated entry: missing realm UUID"))?;
    p += 16;

    let key_len = len_at(p).ok_or_else(|| invalid("truncated entry: missing key length"))?;
    p += 4;
    let key = p
        .checked_add(key_len)
        .and_then(|end| data.get(p..end))
        .ok_or_else(|| invalid("truncated entry: missing key data"))?;
    p += key_len;

    let val_len = len_at(p).ok_or_else(|| invalid("truncated entry: missing value length"))?;
    p += 4;
    let value = p
        .checked_add(val_len)
        .and_then(|end| data.get(p..end))
        .ok_or_else(|| invalid("truncated entry: missing value data"))?;
    p += val_len;

    let value = match entry_type {
        0x00 => Some(value),
        0x01 => None,
        other => {
            return Err(StorageError::InvalidSstFormat {
                reason: format!("unknown entry type: {other:#x}"),
            })
        }
    };
    Ok((EntryRef { realm, key, value }, p))
}

/// A decrypted v3 data block: its plaintext and the offset of each entry in it.
///
/// The block keeps the plaintext as it came out of the AEAD, so it costs two
/// heap buffers whatever its entry count, and the block cache charges exactly
/// those buffers. Decoding every entry into its own key and value buffers took
/// about 1.7 times the plaintext for small rows, while the cache charged only
/// the plaintext (#445).
pub(crate) struct DataBlock {
    plaintext: Vec<u8>,
    /// The start of each entry in `plaintext`, ascending.
    offsets: Vec<u32>,
}

impl DataBlock {
    /// Validates every entry of a decrypted block and records where each one
    /// starts.
    fn decode(plaintext: Vec<u8>) -> Result<Self, StorageError> {
        let mut offsets = Vec::new();
        let mut pos = 0;
        while pos < plaintext.len() {
            offsets.push(
                u32::try_from(pos).map_err(|_| StorageError::InvalidSstFormat {
                    reason: "v3 block larger than 4 GiB".to_string(),
                })?,
            );
            pos = read_entry(&plaintext, pos)?.1;
        }
        Ok(Self { plaintext, offsets })
    }

    /// A block holding `entries`, which MUST be sorted.
    #[cfg(test)]
    pub(crate) fn from_entries(entries: &[(CompositeKey, MemtableValue)]) -> Self {
        let mut plaintext = Vec::new();
        for (key, value) in entries {
            SstWriter::serialize_entry(&mut plaintext, key, value);
        }
        Self::decode(plaintext).expect("serialized entries decode")
    }

    /// The number of entries.
    pub(crate) fn len(&self) -> usize {
        self.offsets.len()
    }

    /// The entry at `index`, or `None` past the last entry.
    pub(crate) fn entry(&self, index: usize) -> Option<EntryRef<'_>> {
        let pos = *self.offsets.get(index)? as usize;
        read_entry(&self.plaintext, pos)
            .ok()
            .map(|(entry, _)| entry)
    }

    /// The entries in key order.
    fn iter(&self) -> impl Iterator<Item = EntryRef<'_>> {
        (0..self.len()).filter_map(|index| self.entry(index))
    }

    /// The index of the first entry at or after `(realm, key)`.
    fn lower_bound(&self, realm: &RealmId, key: &[u8]) -> usize {
        let (mut lo, mut hi) = (0, self.len());
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            match self.entry(mid) {
                Some(entry) if entry.cmp_to(realm, key).is_lt() => lo = mid + 1,
                _ => hi = mid,
            }
        }
        lo
    }

    /// The entry stored under exactly `(realm, key)`.
    fn find(&self, realm: &RealmId, key: &[u8]) -> Option<EntryRef<'_>> {
        self.entry(self.lower_bound(realm, key))
            .filter(|entry| entry.cmp_to(realm, key).is_eq())
    }

    /// The heap the block's two buffers hold.
    pub(crate) fn heap_bytes(&self) -> usize {
        self.plaintext.capacity() + self.offsets.capacity() * std::mem::size_of::<u32>()
    }
}

// ── Block handles, index blocks and cached blocks (v4) ────────────────────────

/// Where a sealed block sits in its file, and the ordinal it was sealed under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BlockHandle {
    /// Byte offset of the block's ciphertext from the start of the file.
    file_offset: u64,
    /// Length of the block's ciphertext, the 16-byte GCM tag included.
    ciphertext_len: u32,
    /// Length of the block's plaintext.
    plaintext_len: u32,
    /// The block's position in write order. Its AEAD nonce and AAD are
    /// `block_nonce(sst_number, ordinal)`, and it keys the block in the cache.
    /// A v3 file's data blocks have their block index as ordinal.
    ordinal: u32,
}

/// Serialized length of a [`BlockHandle`].
const HANDLE_BYTES: usize = 8 + 4 + 4 + 4;

impl BlockHandle {
    fn write(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.file_offset.to_le_bytes());
        buf.extend_from_slice(&self.ciphertext_len.to_le_bytes());
        buf.extend_from_slice(&self.plaintext_len.to_le_bytes());
        buf.extend_from_slice(&self.ordinal.to_le_bytes());
    }

    /// Reads a handle at `pos`, or `None` if `data` is too short.
    fn read(data: &[u8], pos: usize) -> Option<Self> {
        let bytes = data.get(pos..pos.checked_add(HANDLE_BYTES)?)?;
        let u32_at = |at: usize| bytes[at..at + 4].try_into().ok().map(u32::from_le_bytes);
        Some(Self {
            file_offset: u64::from_le_bytes(bytes[0..8].try_into().ok()?),
            ciphertext_len: u32_at(8)?,
            plaintext_len: u32_at(12)?,
            ordinal: u32_at(16)?,
        })
    }
}

/// One entry of an [`IndexBlock`]: the first key of a data block, borrowed
/// from the index block's plaintext, and the data block's handle.
#[derive(Clone, Copy)]
struct IndexEntryRef<'a> {
    realm: &'a [u8; 16],
    key: &'a [u8],
    handle: BlockHandle,
}

impl IndexEntryRef<'_> {
    /// Orders this entry's first key against `(realm, key)` as
    /// [`CompositeKey`] orders.
    fn cmp_to(&self, realm: &RealmId, key: &[u8]) -> std::cmp::Ordering {
        self.realm
            .cmp(realm.as_uuid().as_bytes())
            .then_with(|| self.key.cmp(key))
    }

    /// Orders this entry's first key against `key`.
    fn cmp_composite(&self, key: &CompositeKey) -> std::cmp::Ordering {
        self.cmp_to(key.realm_id(), key.key())
    }
}

/// Reads the index entry at `pos`: a footer-encoded key, then a handle.
fn read_index_entry(data: &[u8], pos: usize) -> Result<(IndexEntryRef<'_>, usize), StorageError> {
    let truncated = || StorageError::InvalidSstFormat {
        reason: "v4 index block: truncated entry".to_string(),
    };
    let realm: &[u8; 16] = data
        .get(pos..pos + 16)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(truncated)?;
    let key_len = data
        .get(pos + 16..pos + 20)
        .and_then(|b| b.try_into().ok())
        .map(|b| u32::from_le_bytes(b) as usize)
        .ok_or_else(truncated)?;
    let key_start = pos + 20;
    let key_end = key_start.checked_add(key_len).ok_or_else(truncated)?;
    let key = data.get(key_start..key_end).ok_or_else(truncated)?;
    let handle = BlockHandle::read(data, key_end).ok_or_else(truncated)?;
    Ok((IndexEntryRef { realm, key, handle }, key_end + HANDLE_BYTES))
}

/// A decrypted index block: for each data block of one partition, its first
/// key and its handle. Like a [`DataBlock`], it keeps its plaintext and one
/// offset per entry.
pub(crate) struct IndexBlock {
    plaintext: Vec<u8>,
    offsets: Vec<u32>,
}

impl IndexBlock {
    /// Validates every entry and records where each one starts.
    fn decode(plaintext: Vec<u8>) -> Result<Self, StorageError> {
        let mut offsets = Vec::new();
        let mut pos = 0;
        while pos < plaintext.len() {
            offsets.push(
                u32::try_from(pos).map_err(|_| StorageError::InvalidSstFormat {
                    reason: "v4 index block larger than 4 GiB".to_string(),
                })?,
            );
            pos = read_index_entry(&plaintext, pos)?.1;
        }
        Ok(Self { plaintext, offsets })
    }

    fn len(&self) -> usize {
        self.offsets.len()
    }

    fn entry(&self, index: usize) -> Option<IndexEntryRef<'_>> {
        let pos = *self.offsets.get(index)? as usize;
        read_index_entry(&self.plaintext, pos)
            .ok()
            .map(|(entry, _)| entry)
    }

    /// The position of the data block that may hold `(realm, key)`: the last
    /// one whose first key is at or before it. `None` if the key sorts before
    /// every data block of this index.
    fn position_for(&self, realm: &RealmId, key: &[u8]) -> Option<usize> {
        let (mut lo, mut hi) = (0, self.len());
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            match self.entry(mid) {
                Some(entry) if entry.cmp_to(realm, key).is_le() => lo = mid + 1,
                _ => hi = mid,
            }
        }
        lo.checked_sub(1)
    }

    fn heap_bytes(&self) -> usize {
        self.plaintext.capacity() + self.offsets.capacity() * std::mem::size_of::<u32>()
    }
}

/// The kind of a block in a v4 file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockKind {
    Data,
    Index,
    Filter,
}

/// A decrypted block of an SST file, as the block cache holds it.
pub(crate) enum Block {
    /// Rows.
    Data(DataBlock),
    /// One partition's block index.
    Index(IndexBlock),
    /// One partition's Bloom filter.
    Filter(BloomFilter),
}

impl Block {
    /// Decodes a decrypted block of the given kind.
    fn decode(kind: BlockKind, plaintext: Vec<u8>) -> Result<Self, StorageError> {
        Ok(match kind {
            BlockKind::Data => Self::Data(DataBlock::decode(plaintext)?),
            BlockKind::Index => Self::Index(IndexBlock::decode(plaintext)?),
            BlockKind::Filter => Self::Filter(BloomFilter::decode(&plaintext)?),
        })
    }

    fn kind(&self) -> BlockKind {
        match self {
            Self::Data(_) => BlockKind::Data,
            Self::Index(_) => BlockKind::Index,
            Self::Filter(_) => BlockKind::Filter,
        }
    }

    /// The heap the block holds.
    pub(crate) fn heap_bytes(&self) -> usize {
        match self {
            Self::Data(block) => block.heap_bytes(),
            Self::Index(block) => block.heap_bytes(),
            Self::Filter(filter) => filter.heap_bytes(),
        }
    }

    /// Whether the block is part of an index or a filter: every lookup in its
    /// range reads it, so the cache gives it more chances than a data block.
    pub(crate) fn is_metadata(&self) -> bool {
        !matches!(self, Self::Data(_))
    }

    fn wrong_kind() -> StorageError {
        StorageError::InvalidSstFormat {
            reason: "SST block of the wrong kind".to_string(),
        }
    }

    pub(crate) fn data(&self) -> Result<&DataBlock, StorageError> {
        match self {
            Self::Data(block) => Ok(block),
            _ => Err(Self::wrong_kind()),
        }
    }

    fn index(&self) -> Result<&IndexBlock, StorageError> {
        match self {
            Self::Index(block) => Ok(block),
            _ => Err(Self::wrong_kind()),
        }
    }

    fn filter(&self) -> Result<&BloomFilter, StorageError> {
        match self {
            Self::Filter(filter) => Ok(filter),
            _ => Err(Self::wrong_kind()),
        }
    }
}

// ── SST metadata ──────────────────────────────────────────────────────────────

/// Metadata about a written SST file.
#[derive(Debug, Clone)]
pub(crate) struct SstMetadata {
    /// Number of entries written.
    pub entry_count: u32,
    /// Total file size in bytes.
    pub file_size: u64,
}

/// Writes sorted entries to an SST file on disk.
pub(crate) struct SstWriter;

impl SstWriter {
    /// Writes a sorted slice of entries to an SST file at the given path.
    ///
    /// Entries MUST be pre-sorted by `CompositeKey`. The writer does not
    /// re-sort — it trusts the caller (memtable iteration is already sorted).
    pub(crate) fn write_sst(
        path: &Path,
        entries: &[(CompositeKey, MemtableValue)],
        sst_number: u64,
        dek: &DataEncryptionKey,
        enc_header: &EncryptionHeader,
    ) -> Result<SstMetadata, StorageError> {
        Self::write_sst_with_fs(
            path,
            |sink| {
                for (k, v) in entries {
                    sink(k, v)?;
                }
                Ok(())
            },
            &RealFs,
            sst_number,
            dek,
            enc_header,
        )
    }

    /// Writes an SST file by **pulling entries through a caller-driven `feed`**,
    /// using a custom filesystem implementation.
    ///
    /// `feed` is invoked once with a `sink` and MUST call `sink(key, value)` for
    /// every entry in ascending `CompositeKey` order. The Bloom filters and the
    /// serialized payload are produced in a **single pass** as entries arrive.
    ///
    /// Inverting control (a `sink` the caller pushes into, rather than an iterator
    /// the writer pulls) is what lets a memtable flush stream directly off its
    /// lock-free `SkipMap` with **no copy at all** (HEA-1908): each
    /// `crossbeam_skiplist::Entry` guard's `key()`/`value()` references are only
    /// valid while the guard is alive, which an `Iterator<Item = (&K, &V)>` cannot
    /// express, but a per-entry `sink` call can — the guard stays live across its
    /// own `sink` call and nothing accumulates. Previously both flush callsites
    /// materialised the entire parked map into an owned `Vec` first, duplicating
    /// every key and value for the whole encrypt+`fsync`. The writer side holds
    /// no copy either: [`V4BodyWriter`] writes each sealed block to the staging
    /// file as it goes (#445).
    pub(crate) fn write_sst_with_fs<Feed>(
        path: &Path,
        feed: Feed,
        fs: &dyn Fs,
        sst_number: u64,
        dek: &DataEncryptionKey,
        enc_header: &EncryptionHeader,
    ) -> Result<SstMetadata, StorageError>
    where
        Feed: FnOnce(
            &mut dyn FnMut(&CompositeKey, &MemtableValue) -> Result<(), StorageError>,
        ) -> Result<(), StorageError>,
    {
        // Stage the body at a `.staging` sibling and rename into place at the
        // end, so an interrupted body write can never leave a torn file at
        // the live `NNNNNN.sst` name — a short live SST made the next
        // startup refuse to open the whole data directory (audit 2026-08-28
        // §4.11#4). A crash or write fault strands only the `.staging` file,
        // which the startup scan ignores and engine open sweeps.
        let staging_path = staging_path_for(path);
        let mut file = fs.create(&staging_path)?;

        let mut body = V4BodyWriter::start(&mut *file, enc_header, sst_number, dek)?;
        feed(&mut |key, value| body.push(key, value))?;
        let metadata = body.finish()?;
        file.sync_all()?;
        drop(file);
        // Publish: the fully-written, fsync'd body atomically takes the live
        // name. Then fsync the parent directory so both the rename and the
        // file's directory entry are durable — a newly created file can
        // otherwise vanish entirely if power is lost before the dir update
        // commits (HEA-1855). Callers that finalize via a second rename
        // (compaction) additionally fsync the dir after that rename.
        fs.rename(&staging_path, path)?;
        if let Some(parent) = path.parent() {
            fs.sync_dir(parent)?;
        }

        Ok(metadata)
    }

    /// Serializes a single entry into the buffer.
    fn serialize_entry(buf: &mut Vec<u8>, key: &CompositeKey, value: &MemtableValue) {
        match value {
            MemtableValue::Data(_) => buf.push(0x00),
            MemtableValue::Tombstone => buf.push(0x01),
        }

        // Realm UUID (16 bytes)
        buf.extend_from_slice(key.realm_id().as_uuid().as_bytes());

        // Key: length-prefixed
        #[allow(clippy::cast_possible_truncation)]
        let key_len = key.key().len() as u32;
        buf.extend_from_slice(&key_len.to_le_bytes());
        buf.extend_from_slice(key.key());

        // Value: length-prefixed (0 for tombstone)
        match value {
            MemtableValue::Data(v) => {
                #[allow(clippy::cast_possible_truncation)]
                let val_len = v.len() as u32;
                buf.extend_from_slice(&val_len.to_le_bytes());
                buf.extend_from_slice(v);
            }
            MemtableValue::Tombstone => {
                buf.extend_from_slice(&0u32.to_le_bytes());
            }
        }
    }

    /// Writes a v4 SST from an **ordered, streaming** iterator, writing sealed
    /// blocks to the file as it goes instead of buffering the whole output in
    /// memory (HEA-1922). Peak heap during the write is bounded by
    /// [`V4BodyWriter`]: one partition, not `O(corpus)`. This is what lets
    /// compaction merge an arbitrarily large corpus past a bounded working set.
    ///
    /// `entries` MUST yield items in ascending `CompositeKey` order. Tombstones
    /// are dropped when `drop_tombstones` is set. The header's `entry_count` is
    /// the *actual* number written, matching the eager writer.
    fn write_sst_streaming_with_fs<I>(
        path: &Path,
        entries: I,
        drop_tombstones: bool,
        fs: &dyn Fs,
        sst_number: u64,
        dek: &DataEncryptionKey,
        enc_header: &EncryptionHeader,
    ) -> Result<SstMetadata, StorageError>
    where
        I: IntoIterator<Item = Result<(CompositeKey, MemtableValue), StorageError>>,
    {
        let mut file = fs.create(path)?;
        let mut body = V4BodyWriter::start(&mut *file, enc_header, sst_number, dek)?;
        for item in entries {
            let (key, value) = item?;
            if drop_tombstones && matches!(value, MemtableValue::Tombstone) {
                continue;
            }
            body.push(&key, &value)?;
        }
        let metadata = body.finish()?;
        file.sync_all()?;
        // Fsync the parent directory so the freshly created SST's directory entry
        // is durable (HEA-1855). Compaction additionally fsyncs the dir after the
        // finalizing rename.
        if let Some(parent) = path.parent() {
            fs.sync_dir(parent)?;
        }

        Ok(metadata)
    }
}

/// Writes the body of a v4 SST in one pass. The memtable flush
/// ([`SstWriter::write_sst_with_fs`]) and compaction
/// ([`SstWriter::write_sst_streaming_with_fs`]) both use it, so both produce
/// byte-identical files. The module docs give the layout.
///
/// Sealed blocks go to the file in chunks of at most [`WRITE_CHUNK_BYTES`], and
/// the writer syncs the file's data every [`SYNC_EVERY_BYTES`].
/// The writer holds one data block's plaintext, one chunk, one partition's
/// index entries and key hashes, and the footer's partition list: never the
/// file, and never the whole block index or Bloom filter (HEA-1922, #445). A
/// partition's filter is built from the hashes of its own keys when the
/// partition is sealed, so each filter is sized from the real row count. The
/// base header is only known at the end, so [`Self::finish`] backfills it with
/// a seek to offset 0.
struct V4BodyWriter<'a> {
    file: &'a mut dyn FsFile,
    sst_number: u64,
    dek: &'a DataEncryptionKey,
    /// File offset of the next sealed block, `pending` included.
    file_offset: u64,
    /// Sealed ciphertext not yet written to `file`.
    pending: Vec<u8>,
    /// Bytes written to `file` since its data was last synced.
    unsynced: usize,
    /// The ordinal the next sealed block gets.
    next_ordinal: u32,
    /// Plaintext of the data block being filled.
    block: Vec<u8>,
    block_first_key: Option<CompositeKey>,
    /// Index entries of the partition being filled.
    partition_index: Vec<u8>,
    partition_first_key: Option<CompositeKey>,
    /// Bloom hashes of the keys of the partition being filled.
    partition_hashes: Vec<(u64, u64)>,
    /// The footer's partition entries, serialized.
    partitions: Vec<u8>,
    partition_count: u32,
    min_key: Option<CompositeKey>,
    max_key: Option<CompositeKey>,
    written: u64,
}

impl<'a> V4BodyWriter<'a> {
    /// Reserves the base header and writes the encryption header.
    fn start(
        file: &'a mut dyn FsFile,
        enc_header: &EncryptionHeader,
        sst_number: u64,
        dek: &'a DataEncryptionKey,
    ) -> Result<Self, StorageError> {
        file.write_all(&[0u8; BASE_HEADER_SIZE])?;
        file.write_all(&enc_header.to_bytes())?;
        Ok(Self {
            file,
            sst_number,
            dek,
            file_offset: TOTAL_HEADER_SIZE as u64,
            pending: Vec::with_capacity(WRITE_CHUNK_BYTES),
            unsynced: 0,
            next_ordinal: 0,
            block: Vec::new(),
            block_first_key: None,
            partition_index: Vec::new(),
            partition_first_key: None,
            partition_hashes: Vec::new(),
            partitions: Vec::new(),
            partition_count: 0,
            min_key: None,
            max_key: None,
            written: 0,
        })
    }

    /// Adds one entry. Entries MUST arrive in ascending `CompositeKey` order;
    /// the writer does not re-sort.
    fn push(&mut self, key: &CompositeKey, value: &MemtableValue) -> Result<(), StorageError> {
        self.partition_hashes
            .push(bloom_hashes(key.realm_id(), key.key()));
        if self.block_first_key.is_none() {
            self.block_first_key = Some(key.clone());
        }
        if self.partition_first_key.is_none() {
            self.partition_first_key = Some(key.clone());
        }
        if self.min_key.is_none() {
            self.min_key = Some(key.clone());
        }
        self.max_key = Some(key.clone());
        SstWriter::serialize_entry(&mut self.block, key, value);
        self.written = self.written.saturating_add(1);
        if self.block.len() >= BLOCK_TARGET_BYTES {
            self.seal_data_block()?;
        }
        Ok(())
    }

    /// Encrypts `plaintext` as the next block, queues its ciphertext for the
    /// file and returns its handle.
    fn seal(&mut self, plaintext: &[u8]) -> Result<BlockHandle, StorageError> {
        let ordinal = self.next_ordinal;
        if ordinal == SST_FOOTER_BLOCK_INDEX {
            return Err(StorageError::InvalidSstFormat {
                reason: "v4 writer: too many blocks for one file".to_string(),
            });
        }
        let too_large = || StorageError::InvalidSstFormat {
            reason: "v4 writer: block larger than 4 GiB".to_string(),
        };
        let nonce = block_nonce(self.sst_number, ordinal);
        let ct = encryption::encrypt_section(plaintext, self.dek, &nonce, &nonce)?;
        let handle = BlockHandle {
            file_offset: self.file_offset,
            ciphertext_len: u32::try_from(ct.len()).map_err(|_| too_large())?,
            plaintext_len: u32::try_from(plaintext.len()).map_err(|_| too_large())?,
            ordinal,
        };
        self.next_ordinal += 1;
        self.file_offset = self.file_offset.saturating_add(ct.len() as u64);
        if !self.pending.is_empty() && self.pending.len() + ct.len() > WRITE_CHUNK_BYTES {
            self.file.write_all(&self.pending)?;
            self.unsynced += self.pending.len();
            self.pending.clear();
            if self.unsynced >= SYNC_EVERY_BYTES {
                self.file.sync_data()?;
                self.unsynced = 0;
            }
        }
        self.pending.extend_from_slice(&ct);
        Ok(handle)
    }

    /// Seals the data block being filled and adds it to the partition's
    /// index; seals the partition once its index reaches its target size. A
    /// no-op on an empty block.
    fn seal_data_block(&mut self) -> Result<(), StorageError> {
        if self.block.is_empty() {
            return Ok(());
        }
        let first_key =
            self.block_first_key
                .take()
                .ok_or_else(|| StorageError::InvalidSstFormat {
                    reason: "v4 writer: non-empty block without a first key".to_string(),
                })?;
        let block = std::mem::take(&mut self.block);
        let handle = self.seal(&block);
        self.block = block;
        self.block.clear();
        write_footer_key(&mut self.partition_index, &first_key);
        handle?.write(&mut self.partition_index);
        if self.partition_index.len() >= INDEX_PARTITION_TARGET_BYTES {
            self.seal_partition()?;
        }
        Ok(())
    }

    /// Seals the partition being filled: its filter block, then its index
    /// block, then its entry in the footer. A no-op on an empty partition.
    fn seal_partition(&mut self) -> Result<(), StorageError> {
        if self.partition_index.is_empty() {
            return Ok(());
        }
        let first_key =
            self.partition_first_key
                .take()
                .ok_or_else(|| StorageError::InvalidSstFormat {
                    reason: "v4 writer: non-empty partition without a first key".to_string(),
                })?;
        let filter = BloomFilter::from_hashes(&self.partition_hashes).encode();
        self.partition_hashes.clear();
        let filter_handle = self.seal(&filter)?;
        let index = std::mem::take(&mut self.partition_index);
        let index_handle = self.seal(&index);
        self.partition_index = index;
        self.partition_index.clear();
        write_footer_key(&mut self.partitions, &first_key);
        index_handle?.write(&mut self.partitions);
        self.partitions.push(1);
        filter_handle.write(&mut self.partitions);
        self.partition_count =
            self.partition_count
                .checked_add(1)
                .ok_or_else(|| StorageError::InvalidSstFormat {
                    reason: "v4 writer: too many partitions for one file".to_string(),
                })?;
        Ok(())
    }

    /// Seals the last block and partition, writes the queued blocks, the
    /// encrypted footer and the trailer, and backfills the base header. Does
    /// not sync the file: the caller syncs it before it publishes the file.
    fn finish(mut self) -> Result<SstMetadata, StorageError> {
        self.seal_data_block()?;
        self.seal_partition()?;
        self.file.write_all(&self.pending)?;
        self.pending = Vec::new();

        let mut footer = Vec::with_capacity(8 + 4 + self.partitions.len() + 1);
        footer.extend_from_slice(&self.written.to_le_bytes());
        footer.extend_from_slice(&self.partition_count.to_le_bytes());
        footer.extend_from_slice(&self.partitions);
        match (&self.min_key, &self.max_key) {
            (Some(mn), Some(mx)) => {
                footer.push(1);
                write_footer_key(&mut footer, mn);
                write_footer_key(&mut footer, mx);
            }
            _ => footer.push(0),
        }

        let footer_nonce = block_nonce(self.sst_number, SST_FOOTER_BLOCK_INDEX);
        let footer_ct =
            encryption::encrypt_section(&footer, self.dek, &footer_nonce, &footer_nonce)?;
        let footer_offset = self.file_offset;
        let footer_crc = crc32fast::hash(&footer_ct);
        self.file.write_all(&footer_ct)?;

        // Trailer: footer_offset (u64 LE) + footer_ct_len (u32 LE).
        self.file.write_all(&footer_offset.to_le_bytes())?;
        let footer_len =
            u32::try_from(footer_ct.len()).map_err(|_| StorageError::InvalidSstFormat {
                reason: "v4 writer: footer larger than 4 GiB".to_string(),
            })?;
        self.file.write_all(&footer_len.to_le_bytes())?;
        let file_size = footer_offset
            .saturating_add(footer_ct.len() as u64)
            .saturating_add(TRAILER_SIZE as u64);

        // Backfill the base header now that entry_count and footer_crc are known.
        // The encryption header written at offset BASE_HEADER_SIZE is untouched.
        let entry_count = u32::try_from(self.written).unwrap_or(u32::MAX);
        self.file.seek(std::io::SeekFrom::Start(0))?;
        let mut base_header = [0u8; BASE_HEADER_SIZE];
        base_header[0..4].copy_from_slice(SST_MAGIC_V4);
        base_header[4..8].copy_from_slice(&entry_count.to_le_bytes());
        base_header[8..12].copy_from_slice(&footer_crc.to_le_bytes());
        self.file.write_all(&base_header)?;

        Ok(SstMetadata {
            entry_count,
            file_size,
        })
    }
}

/// Writes the body of a v3 SST in one pass. Hearth writes v4 files now; tests
/// use this writer to make the v3 files that a reader must still open.
///
/// Layout written to the file (HEA-1914):
///   [BASE HEADER 12B]  magic HSS3, entry_count, crc32(footer ciphertext)
///   [ENC HEADER  76B]  wrapped per-file DEK
///   [block_0 ct][block_1 ct]...[block_{n-1} ct]   each independently AEAD'd
///   [footer ciphertext]                            encrypted block index
///   [TRAILER 12B]  footer_offset (u64 LE) + footer_ct_len (u32 LE)
///
/// Each block is sealed with `block_nonce(sst_number, block_index)` used as
/// both nonce and AAD, so a block cannot be replayed at a different position
/// or in a different file. Blocks target ~4 KiB of plaintext and never split
/// an entry. The Bloom filter is sized up front and filled in the same pass.
///
/// Sealed blocks go to the file in chunks of at most
/// [`WRITE_CHUNK_BYTES`], so the writer holds one block's plaintext, one
/// chunk, the block index and the Bloom filter — `O(#blocks + entries/8)`,
/// never the file (HEA-1922). The memtable flush once kept every sealed block
/// and then a copy of the whole file: about 3.4 times the flushed bytes (#445).
/// The base header is only known at the end, so [`Self::finish`] backfills it
/// with a seek to offset 0.
#[cfg(test)]
struct V3BodyWriter<'a> {
    file: &'a mut dyn FsFile,
    sst_number: u64,
    dek: &'a DataEncryptionKey,
    /// File offset of the next sealed block, `pending` included.
    file_offset: u64,
    /// Sealed ciphertext not yet written to `file`.
    pending: Vec<u8>,
    filter: BloomFilter,
    index: Vec<BlockIndexEntry>,
    /// Plaintext of the block being filled.
    block: Vec<u8>,
    block_first_key: Option<CompositeKey>,
    min_key: Option<CompositeKey>,
    max_key: Option<CompositeKey>,
    written: u32,
}

#[cfg(test)]
impl<'a> V3BodyWriter<'a> {
    /// Reserves the base header and writes the encryption header.
    /// `entry_count_hint` sizes the Bloom filter; it MAY exceed the number of
    /// entries pushed — an over-estimate only lowers the false-positive rate.
    fn start(
        file: &'a mut dyn FsFile,
        enc_header: &EncryptionHeader,
        entry_count_hint: usize,
        sst_number: u64,
        dek: &'a DataEncryptionKey,
    ) -> Result<Self, StorageError> {
        file.write_all(&[0u8; BASE_HEADER_SIZE])?;
        file.write_all(&enc_header.to_bytes())?;
        Ok(Self {
            file,
            sst_number,
            dek,
            file_offset: TOTAL_HEADER_SIZE as u64,
            pending: Vec::with_capacity(WRITE_CHUNK_BYTES),
            filter: BloomFilter::empty_for(entry_count_hint),
            index: Vec::new(),
            block: Vec::new(),
            block_first_key: None,
            min_key: None,
            max_key: None,
            written: 0,
        })
    }

    /// Adds one entry. Entries MUST arrive in ascending `CompositeKey` order;
    /// the writer does not re-sort.
    fn push(&mut self, key: &CompositeKey, value: &MemtableValue) -> Result<(), StorageError> {
        self.filter.insert(key.realm_id(), key.key());
        if self.block_first_key.is_none() {
            self.block_first_key = Some(key.clone());
        }
        if self.min_key.is_none() {
            self.min_key = Some(key.clone());
        }
        self.max_key = Some(key.clone());
        SstWriter::serialize_entry(&mut self.block, key, value);
        self.written = self.written.saturating_add(1);
        if self.block.len() >= BLOCK_TARGET_BYTES {
            self.seal_block()?;
        }
        Ok(())
    }

    /// Encrypts the block being filled, queues its ciphertext for the file and
    /// records its index entry. A no-op on an empty block.
    fn seal_block(&mut self) -> Result<(), StorageError> {
        if self.block.is_empty() {
            return Ok(());
        }
        let first_key =
            self.block_first_key
                .take()
                .ok_or_else(|| StorageError::InvalidSstFormat {
                    reason: "v3 writer: non-empty block without a first key".to_string(),
                })?;
        #[allow(clippy::cast_possible_truncation)]
        let block_index = self.index.len() as u32;
        let nonce = block_nonce(self.sst_number, block_index);
        let ct = encryption::encrypt_section(&self.block, self.dek, &nonce, &nonce)?;
        #[allow(clippy::cast_possible_truncation)]
        self.index.push(BlockIndexEntry {
            first_key,
            file_offset: self.file_offset,
            ciphertext_len: ct.len() as u32,
            plaintext_len: self.block.len() as u32,
        });
        self.file_offset = self.file_offset.saturating_add(ct.len() as u64);
        if !self.pending.is_empty() && self.pending.len() + ct.len() > WRITE_CHUNK_BYTES {
            self.file.write_all(&self.pending)?;
            self.pending.clear();
        }
        self.pending.extend_from_slice(&ct);
        self.block.clear();
        Ok(())
    }

    /// Seals the last block, writes the queued blocks, the encrypted footer
    /// index and the trailer, and backfills the base header. Does not sync the
    /// file: the caller syncs it before it publishes the file.
    fn finish(mut self) -> Result<SstMetadata, StorageError> {
        self.seal_block()?;
        self.file.write_all(&self.pending)?;
        self.pending = Vec::new();

        let mut footer = Vec::new();
        #[allow(clippy::cast_possible_truncation)]
        footer.extend_from_slice(&(self.index.len() as u32).to_le_bytes());
        for e in &self.index {
            footer.extend_from_slice(&e.file_offset.to_le_bytes());
            footer.extend_from_slice(&e.ciphertext_len.to_le_bytes());
            footer.extend_from_slice(&e.plaintext_len.to_le_bytes());
            write_footer_key(&mut footer, &e.first_key);
        }
        match (&self.min_key, &self.max_key) {
            (Some(mn), Some(mx)) => {
                footer.push(1);
                write_footer_key(&mut footer, mn);
                write_footer_key(&mut footer, mx);
            }
            _ => footer.push(0),
        }
        #[allow(clippy::cast_possible_truncation)]
        let bloom_byte_count = self.filter.bits.len() as u32;
        footer.extend_from_slice(&bloom_byte_count.to_le_bytes());
        if bloom_byte_count > 0 {
            footer.push(self.filter.k);
            footer.extend_from_slice(&self.filter.bits);
        }

        let footer_nonce = block_nonce(self.sst_number, SST_FOOTER_BLOCK_INDEX);
        let footer_ct =
            encryption::encrypt_section(&footer, self.dek, &footer_nonce, &footer_nonce)?;
        let footer_offset = self.file_offset;
        let footer_crc = crc32fast::hash(&footer_ct);
        self.file.write_all(&footer_ct)?;

        // Trailer: footer_offset (u64 LE) + footer_ct_len (u32 LE).
        self.file.write_all(&footer_offset.to_le_bytes())?;
        #[allow(clippy::cast_possible_truncation)]
        self.file
            .write_all(&(footer_ct.len() as u32).to_le_bytes())?;
        let file_size = footer_offset
            .saturating_add(footer_ct.len() as u64)
            .saturating_add(TRAILER_SIZE as u64);

        // Backfill the base header now that entry_count and footer_crc are known.
        // The encryption header written at offset BASE_HEADER_SIZE is untouched.
        self.file.seek(std::io::SeekFrom::Start(0))?;
        let mut base_header = [0u8; BASE_HEADER_SIZE];
        base_header[0..4].copy_from_slice(SST_MAGIC_V3);
        base_header[4..8].copy_from_slice(&self.written.to_le_bytes());
        base_header[8..12].copy_from_slice(&footer_crc.to_le_bytes());
        self.file.write_all(&base_header)?;

        Ok(SstMetadata {
            entry_count: self.written,
            file_size,
        })
    }
}

/// A position in one SST's keys within a realm's window; see
/// [`SstReader::key_cursor`].
pub(crate) enum SstKeyCursor<'a> {
    /// The window is exhausted, or the SST never overlapped it.
    Done,
    /// A V1/V2 SST: the window's resident entries not yet visited.
    Eager {
        /// Remaining entries, all inside the window.
        entries: &'a [(CompositeKey, MemtableValue)],
    },
    /// A V3/V4 SST, read one block at a time.
    Blocked(BlockedKeyCursor<'a>),
}

/// The V3/V4 state of an [`SstKeyCursor`].
pub(crate) struct BlockedKeyCursor<'a> {
    /// The data blocks still to visit.
    walk: BlockWalk<'a>,
    /// The window's exclusive upper bound.
    end: CompositeKey,
    /// The current data block, or `None` once the window is exhausted.
    block: Option<Arc<CachedBlock>>,
    /// The current entry's position in `block`.
    pos: usize,
}

impl BlockedKeyCursor<'_> {
    /// Fetches the next data block, or ends the walk when no block is left
    /// that starts before the window's end.
    fn load_block(&mut self) -> Result<(), StorageError> {
        self.block = self.walk.next_block(Some(&self.end))?;
        self.pos = 0;
        Ok(())
    }

    /// Moves past the end of an exhausted block into the next one, and ends
    /// the walk at the window's end.
    fn settle(&mut self) -> Result<(), StorageError> {
        loop {
            let Some(block) = &self.block else {
                return Ok(());
            };
            match block.block.data()?.entry(self.pos) {
                Some(entry) => {
                    if entry.cmp_composite(&self.end).is_ge() {
                        self.block = None;
                    }
                    return Ok(());
                }
                None => self.load_block()?,
            }
        }
    }
}

impl SstKeyCursor<'_> {
    /// The key and value (`None` for a tombstone) at this position, or `None`
    /// once the window is exhausted.
    fn entry(&self) -> Option<(&[u8], Option<&[u8]>)> {
        match self {
            Self::Done => None,
            Self::Eager { entries } => entries.first().map(|(k, v)| (k.key(), value_view(v))),
            Self::Blocked(blocked) => blocked
                .block
                .as_ref()?
                .block
                .data()
                .ok()?
                .entry(blocked.pos)
                .map(|entry| (entry.key(), entry.value())),
        }
    }
}

impl KeyCursor for SstKeyCursor<'_> {
    fn current(&self) -> Option<(&[u8], bool)> {
        let (key, value) = self.entry()?;
        Some((key, value.is_some()))
    }

    fn value(&self) -> Option<&[u8]> {
        self.entry()?.1
    }

    fn advance(&mut self) -> Result<(), StorageError> {
        match self {
            Self::Done => Ok(()),
            Self::Eager { entries } => {
                *entries = entries.get(1..).unwrap_or_default();
                Ok(())
            }
            Self::Blocked(blocked) => {
                blocked.pos += 1;
                blocked.settle()
            }
        }
    }
}

/// Backing representation of an SST reader's entries.
enum SstBody {
    /// V1/V2 legacy formats: all entries eagerly decrypted and resident.
    Eager(Vec<(CompositeKey, MemtableValue)>),
    /// V3/V4: block-structured. Data blocks are memory-mapped and decrypted on
    /// demand through the shared block cache (HEA-1914). A v4 file's index and
    /// filter blocks load the same way, so only its partition list is resident
    /// (#445).
    Blocked(BlockedBody),
}

/// Heap an open reader holds besides its file mapping: the entries of a v1/v2
/// SST, or the partition list of a v3/v4 SST with a v3 file's whole block
/// index and Bloom filter; plus its Bloom filter and key range. Key bytes count
/// at their length. `hearth_storage_sst_reader_bytes` reports the sum over the
/// live readers (#445).
fn count_resident_bytes(
    body: &SstBody,
    bloom_filter: Option<&BloomFilter>,
    key_range: Option<&(CompositeKey, CompositeKey)>,
) -> usize {
    let body_bytes = match body {
        SstBody::Eager(entries) => {
            entries.capacity() * std::mem::size_of::<(CompositeKey, MemtableValue)>()
                + entries
                    .iter()
                    .map(|(key, value)| {
                        key.key().len()
                            + match value {
                                MemtableValue::Data(v) => v.len(),
                                MemtableValue::Tombstone => 0,
                            }
                    })
                    .sum::<usize>()
        }
        SstBody::Blocked(blocked) => {
            blocked.partitions.capacity() * std::mem::size_of::<Partition>()
                + blocked
                    .partitions
                    .iter()
                    .map(|partition| {
                        partition.first_key.key().len()
                            + partition.index.pinned_bytes()
                            + partition.filter.as_ref().map_or(0, Piece::pinned_bytes)
                    })
                    .sum::<usize>()
        }
    };
    let bloom_bytes = bloom_filter.map_or(0, |filter| filter.bits.capacity());
    let range_bytes = key_range.map_or(0, |(min, max)| min.key().len() + max.key().len());
    body_bytes + bloom_bytes + range_bytes
}

/// Process-wide source of unique `reader_id`s. Each physical `SstReader::open`
/// gets a fresh value so block-cache keys never collide across a compaction
/// that reuses an SST file number (see [`BlockId`]).
static NEXT_READER_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// An index or filter block of a partition.
enum Piece {
    /// Held on the heap for the life of the reader: a v3 file's footer holds
    /// the whole block index and Bloom filter.
    Pinned(Arc<CachedBlock>),
    /// Stored in the file and read through the block cache (v4).
    Stored(BlockHandle),
}

impl Piece {
    /// The heap this piece holds for the life of the reader.
    fn pinned_bytes(&self) -> usize {
        match self {
            Self::Pinned(block) => block.block.heap_bytes(),
            Self::Stored(_) => 0,
        }
    }
}

/// One entry of a blocked file's top-level index: a run of data blocks in key
/// order, with their index block and their Bloom filter.
struct Partition {
    /// The first key of the partition's first data block.
    first_key: CompositeKey,
    index: Piece,
    /// `None` for a v3 file without a filter.
    filter: Option<Piece>,
}

/// Lazily-decrypted body of a v3 or v4 SST.
struct BlockedBody {
    /// Whole-file backing (mmap in production, heap in simulation).
    backing: FileBacking,
    /// The end of the blocks: every block lies in `[TOTAL_HEADER_SIZE,
    /// blocks_end)`, before the footer.
    blocks_end: usize,
    /// The top-level index, sorted by first key. A v3 file has one partition
    /// whose pieces are pinned.
    partitions: Vec<Partition>,
    /// Per-file DEK retained for on-demand block decryption.
    dek: DataEncryptionKey,
    /// Shared, bounded cache of decrypted blocks.
    cache: Arc<BlockCache>,
    /// Unique per-open id used to key this reader's blocks in the shared cache.
    reader_id: u64,
    /// An authenticated upper bound on the entries in the file (see
    /// [`SstReader::authenticated_max_entries`]).
    max_entries: usize,
}

impl BlockedBody {
    /// The partition that may contain `(realm, key)`: the last one whose first
    /// key is at or before it. `None` if the key sorts before every partition.
    fn partition_for_key(&self, realm: &RealmId, key: &[u8]) -> Option<usize> {
        let pp = self.partitions.partition_point(|p| {
            p.first_key
                .realm_id()
                .cmp(realm)
                .then_with(|| p.first_key.key().cmp(key))
                .is_le()
        });
        pp.checked_sub(1)
    }

    /// Reads one block of `kind`: through the shared cache when `cached`, or
    /// decrypted privately. A one-shot walk (compaction, the cleanup sweep)
    /// reads uncached, so it does not evict the query path's working set
    /// (HEA-1922). Surfaces AEAD/format errors rather than a wrong or absent
    /// value.
    fn load(
        &self,
        handle: BlockHandle,
        kind: BlockKind,
        sst_number: u64,
        cached: bool,
    ) -> Result<Arc<CachedBlock>, StorageError> {
        let id = BlockId {
            reader_id: self.reader_id,
            block_index: handle.ordinal,
        };
        if cached {
            if let Some(block) = self.cache.get(id) {
                if block.block.kind() != kind {
                    return Err(Block::wrong_kind());
                }
                return Ok(block);
            }
        }
        let start = usize::try_from(handle.file_offset).unwrap_or(usize::MAX);
        let end = start
            .checked_add(handle.ciphertext_len as usize)
            .filter(|end| start >= TOTAL_HEADER_SIZE && *end <= self.blocks_end)
            .ok_or_else(|| StorageError::InvalidSstFormat {
                reason: "SST block lies outside the data section".to_string(),
            })?;
        let nonce = block_nonce(sst_number, handle.ordinal);
        let plaintext =
            encryption::decrypt_section(&self.backing[start..end], &self.dek, &nonce, &nonce)?;
        let block = Arc::new(CachedBlock::new(Block::decode(kind, plaintext)?));
        if cached {
            self.cache.insert(id, Arc::clone(&block));
        }
        Ok(block)
    }

    /// Reads an index or filter piece of a partition.
    fn piece(
        &self,
        piece: &Piece,
        kind: BlockKind,
        sst_number: u64,
        cached: bool,
    ) -> Result<Arc<CachedBlock>, StorageError> {
        match piece {
            Piece::Pinned(block) => Ok(Arc::clone(block)),
            Piece::Stored(handle) => self.load(*handle, kind, sst_number, cached),
        }
    }

    /// Point lookup: the partition, then its filter, then its index, then the
    /// one data block that may hold the key.
    fn get(
        &self,
        realm_id: &RealmId,
        key: &[u8],
        sst_number: u64,
        cached: bool,
    ) -> Result<Option<MemtableValue>, StorageError> {
        let Some(partition) = self
            .partition_for_key(realm_id, key)
            .and_then(|p| self.partitions.get(p))
        else {
            return Ok(None);
        };
        if let Some(filter) = &partition.filter {
            let filter = self.piece(filter, BlockKind::Filter, sst_number, cached)?;
            if !filter.block.filter()?.might_contain(realm_id, key) {
                return Ok(None);
            }
        }
        let index = self.piece(&partition.index, BlockKind::Index, sst_number, cached)?;
        let index = index.block.index()?;
        let Some(entry) = index
            .position_for(realm_id, key)
            .and_then(|i| index.entry(i))
        else {
            return Ok(None);
        };
        let block = self.load(entry.handle, BlockKind::Data, sst_number, cached)?;
        Ok(block
            .block
            .data()?
            .find(realm_id, key)
            .map(|entry| entry.memtable_value()))
    }
}

/// A walk over a blocked file's data blocks in key order, across partitions.
/// It holds one index block at a time.
struct BlockWalk<'a> {
    body: &'a BlockedBody,
    sst_number: u64,
    /// Whether blocks go through the shared block cache.
    cached: bool,
    /// The partition being walked.
    partition: usize,
    /// That partition's index block, once loaded.
    index: Option<Arc<CachedBlock>>,
    /// The next entry of `index` to visit.
    next: usize,
}

impl<'a> BlockWalk<'a> {
    /// A walk from the file's first data block.
    fn from_start(body: &'a BlockedBody, sst_number: u64, cached: bool) -> Self {
        Self {
            body,
            sst_number,
            cached,
            partition: 0,
            index: None,
            next: 0,
        }
    }

    /// A walk from the data block that may hold `(realm, key)`, or from the
    /// first data block when the key sorts before all of them.
    fn seek(
        body: &'a BlockedBody,
        sst_number: u64,
        cached: bool,
        realm: &RealmId,
        key: &[u8],
    ) -> Result<Self, StorageError> {
        let mut walk = Self::from_start(body, sst_number, cached);
        if let Some(p) = body.partition_for_key(realm, key) {
            walk.partition = p;
            let index = walk.load_index()?;
            walk.next = index.block.index()?.position_for(realm, key).unwrap_or(0);
            walk.index = Some(index);
        }
        Ok(walk)
    }

    /// The index block of the partition being walked.
    fn load_index(&self) -> Result<Arc<CachedBlock>, StorageError> {
        let partition = self.body.partitions.get(self.partition).ok_or_else(|| {
            StorageError::InvalidSstFormat {
                reason: "SST partition out of range".to_string(),
            }
        })?;
        self.body.piece(
            &partition.index,
            BlockKind::Index,
            self.sst_number,
            self.cached,
        )
    }

    /// The next data block, or `None` when none is left, or when the next one
    /// starts at or after `end`.
    fn next_block(
        &mut self,
        end: Option<&CompositeKey>,
    ) -> Result<Option<Arc<CachedBlock>>, StorageError> {
        loop {
            let Some(partition) = self.body.partitions.get(self.partition) else {
                return Ok(None);
            };
            if self.index.is_none() {
                if end.is_some_and(|end| partition.first_key >= *end) {
                    return Ok(None);
                }
                self.index = Some(self.load_index()?);
            }
            let next = match &self.index {
                Some(index) => index.block.index()?.entry(self.next).map(|entry| {
                    let past_end = end.is_some_and(|end| entry.cmp_composite(end).is_ge());
                    (past_end, entry.handle)
                }),
                None => None,
            };
            match next {
                Some((true, _)) => return Ok(None),
                Some((false, handle)) => {
                    self.next += 1;
                    return self
                        .body
                        .load(handle, BlockKind::Data, self.sst_number, self.cached)
                        .map(Some);
                }
                None => {
                    self.partition += 1;
                    self.index = None;
                    self.next = 0;
                }
            }
        }
    }
}

/// Reads entries from an SST file on disk.
pub(crate) struct SstReader {
    /// Backing store: eager entries (V1/V2) or lazy blocks (V3/V4).
    body: SstBody,
    /// Number of entries as declared in the header.
    entry_count: u32,
    /// Monotonically increasing SST file number for path derivation.
    sst_number: u64,
    /// Per-SST Bloom filter for fast key rejection (V2 SSTs). A V3/V4 SST
    /// keeps its filters in its partitions.
    ///
    /// A `None` filter is treated as "might contain everything" — V1 SSTs
    /// written before HEA-1626 are still read correctly; they just don't get
    /// the fast-reject optimisation.
    bloom_filter: Option<BloomFilter>,
    /// Inclusive `(min, max)` `CompositeKey` bounds of the entries in this SST,
    /// or `None` for an empty SST.
    ///
    /// They enable O(1) range pruning (HEA-1773): a point or range lookup
    /// whose realm-first `CompositeKey` falls entirely outside `[min, max]` can
    /// skip this SST without touching the Bloom filter or block index. This
    /// bounds cold-read fan-out `S` when SSTs cover disjoint key ranges (e.g.
    /// realm-partitioned data), independent of compaction cadence.
    key_range: Option<(CompositeKey, CompositeKey)>,
    /// Heap this reader holds while it is open, counted once at open (see
    /// [`count_resident_bytes`]); a reader never changes after open.
    resident_bytes: usize,
}

impl std::fmt::Debug for SstReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self.body {
            SstBody::Eager(_) => "eager",
            SstBody::Blocked(_) => "blocked",
        };
        f.debug_struct("SstReader")
            .field("kind", &kind)
            .field("entry_count", &self.entry_count)
            .field("sst_number", &self.sst_number)
            .finish_non_exhaustive()
    }
}

impl SstReader {
    /// Opens and validates an SST file with a fresh private block cache.
    ///
    /// Test/tooling convenience. Production callers pass a shared cache via
    /// [`Self::open_with_fs`] so decrypted-block residency is bounded across all
    /// readers, not per-reader.
    pub(crate) fn open(
        path: &Path,
        sst_number: u64,
        dek: &DataEncryptionKey,
    ) -> Result<Self, StorageError> {
        Self::open_with_fs(
            path,
            &RealFs,
            sst_number,
            dek,
            Arc::new(BlockCache::new(64 * 1024 * 1024)),
        )
    }

    /// Opens an SST file using a custom filesystem implementation and a shared
    /// block cache.
    pub(crate) fn open_with_fs(
        path: &Path,
        fs: &dyn Fs,
        sst_number: u64,
        dek: &DataEncryptionKey,
        cache: Arc<BlockCache>,
    ) -> Result<Self, StorageError> {
        // Map (or read) the whole file. For V3 the mapping is retained so blocks
        // stay OS-page-cache-backed; for V1/V2 the eager path reads through it
        // once and drops it.
        let backing = fs.map_readonly(path)?;

        // Minimum file size: base header + encryption header
        if backing.len() < TOTAL_HEADER_SIZE {
            return Err(StorageError::InvalidSstFormat {
                reason: format!("file too small: {} bytes", backing.len()),
            });
        }

        let entry_count = u32::from_le_bytes(backing[4..8].try_into().map_err(|_| {
            StorageError::InvalidSstFormat {
                reason: "invalid entry count bytes".to_string(),
            }
        })?);
        let stored_crc = u32::from_le_bytes(backing[8..12].try_into().map_err(|_| {
            StorageError::InvalidSstFormat {
                reason: "invalid CRC bytes".to_string(),
            }
        })?);

        // --- Parse encryption header (validate it parseable) ---
        let enc_bytes: &[u8; encryption::ENCRYPTION_HEADER_SIZE] = backing
            [BASE_HEADER_SIZE..TOTAL_HEADER_SIZE]
            .try_into()
            .map_err(|_| StorageError::InvalidSstFormat {
                reason: "truncated encryption header".to_string(),
            })?;
        let _enc_header = EncryptionHeader::from_bytes(enc_bytes);

        // --- V3/V4: block-structured, lazy ---
        if &backing[0..4] == SST_MAGIC_V4 {
            return Self::open_v4(backing, entry_count, stored_crc, sst_number, dek, cache);
        }
        if &backing[0..4] == SST_MAGIC_V3 {
            return Self::open_v3(backing, entry_count, stored_crc, sst_number, dek, cache);
        }

        // --- V1/V2: eager whole-file decrypt ---
        let is_v2 = match &backing[0..4] {
            m if m == SST_MAGIC => false,
            m if m == SST_MAGIC_V2 => true,
            _ => {
                return Err(StorageError::InvalidSstFormat {
                    reason: "invalid magic bytes".to_string(),
                })
            }
        };
        let ciphertext = &backing[TOTAL_HEADER_SIZE..];
        let data_nonce = counter_nonce(sst_number);
        let aad = sst_number.to_le_bytes();
        let plaintext = encryption::decrypt_section(ciphertext, dek, &data_nonce, &aad)?;

        let computed_crc = crc32fast::hash(&plaintext);
        if stored_crc != computed_crc {
            return Err(StorageError::ChecksumMismatch {
                offset: TOTAL_HEADER_SIZE as u64,
            });
        }

        let (entries, bloom_filter) = if is_v2 {
            Self::parse_v2_plaintext(&plaintext, entry_count)?
        } else {
            (Self::deserialize_entries(&plaintext, entry_count)?, None)
        };

        let key_range = match (entries.first(), entries.last()) {
            (Some((min, _)), Some((max, _))) => Some((min.clone(), max.clone())),
            _ => None,
        };

        let body = SstBody::Eager(entries);
        let resident_bytes = count_resident_bytes(&body, bloom_filter.as_ref(), key_range.as_ref());
        Ok(Self {
            body,
            entry_count,
            sst_number,
            bloom_filter,
            key_range,
            resident_bytes,
        })
    }

    /// Reads the trailer of a v3 or v4 file, checks the footer's CRC and
    /// decrypts it. Returns the footer's offset, where the blocks end, and its
    /// plaintext.
    fn read_footer(
        backing: &FileBacking,
        stored_crc: u32,
        sst_number: u64,
        dek: &DataEncryptionKey,
    ) -> Result<(usize, Vec<u8>), StorageError> {
        let len = backing.len();
        if len < TOTAL_HEADER_SIZE + TRAILER_SIZE {
            return Err(StorageError::InvalidSstFormat {
                reason: "SST file too small for its trailer".to_string(),
            });
        }
        let trailer = &backing[len - TRAILER_SIZE..];
        #[allow(clippy::cast_possible_truncation)]
        let footer_offset = u64::from_le_bytes(trailer[0..8].try_into().map_err(|_| {
            StorageError::InvalidSstFormat {
                reason: "SST trailer: invalid footer offset".to_string(),
            }
        })?) as usize;
        let footer_len = u32::from_le_bytes(trailer[8..12].try_into().map_err(|_| {
            StorageError::InvalidSstFormat {
                reason: "SST trailer: invalid footer length".to_string(),
            }
        })?) as usize;

        // Footer must lie between the header and the trailer. A truncated file
        // fails this bound instead of reading arbitrary bytes.
        let footer_end = footer_offset
            .checked_add(footer_len)
            .filter(|end| footer_offset >= TOTAL_HEADER_SIZE && *end <= len - TRAILER_SIZE)
            .ok_or_else(|| StorageError::InvalidSstFormat {
                reason: "SST footer offset/length out of range (truncated?)".to_string(),
            })?;

        let footer_ct = &backing[footer_offset..footer_end];
        if crc32fast::hash(footer_ct) != stored_crc {
            return Err(StorageError::ChecksumMismatch {
                offset: footer_offset as u64,
            });
        }
        let footer_nonce = block_nonce(sst_number, SST_FOOTER_BLOCK_INDEX);
        let footer_plain =
            encryption::decrypt_section(footer_ct, dek, &footer_nonce, &footer_nonce)?;
        Ok((footer_offset, footer_plain))
    }

    /// Checks that a block lies between the header and the footer, so a
    /// truncated data section is rejected at open, not mid-read.
    fn check_block_range(handle: &BlockHandle, blocks_end: usize) -> Result<(), StorageError> {
        let start = usize::try_from(handle.file_offset).unwrap_or(usize::MAX);
        let end = start
            .checked_add(handle.ciphertext_len as usize)
            .ok_or_else(|| StorageError::InvalidSstFormat {
                reason: "SST block length overflow".to_string(),
            })?;
        if start < TOTAL_HEADER_SIZE || end > blocks_end || handle.ordinal == SST_FOOTER_BLOCK_INDEX
        {
            return Err(StorageError::InvalidSstFormat {
                reason: "SST block range out of bounds (truncated?)".to_string(),
            });
        }
        Ok(())
    }

    /// Opens a v3 or v4 body over `partitions`.
    #[allow(clippy::too_many_arguments)]
    fn open_blocked(
        backing: FileBacking,
        blocks_end: usize,
        partitions: Vec<Partition>,
        max_entries: usize,
        key_range: Option<(CompositeKey, CompositeKey)>,
        entry_count: u32,
        sst_number: u64,
        dek: &DataEncryptionKey,
        cache: Arc<BlockCache>,
    ) -> Self {
        let reader_id = NEXT_READER_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let body = SstBody::Blocked(BlockedBody {
            backing,
            blocks_end,
            partitions,
            dek: dek.clone_key(),
            cache,
            reader_id,
            max_entries,
        });
        let resident_bytes = count_resident_bytes(&body, None, key_range.as_ref());
        Self {
            body,
            entry_count,
            sst_number,
            bloom_filter: None,
            key_range,
            resident_bytes,
        }
    }

    /// Parses a V3 SST: read the trailer, verify+decrypt the footer, load the
    /// block index, and validate every block offset lies within the data
    /// section (eager truncation detection). Block payloads stay on disk.
    ///
    /// The whole index and Bloom filter become the pinned pieces of one
    /// partition, so v3 and v4 files share every read path.
    fn open_v3(
        backing: FileBacking,
        entry_count: u32,
        stored_crc: u32,
        sst_number: u64,
        dek: &DataEncryptionKey,
        cache: Arc<BlockCache>,
    ) -> Result<Self, StorageError> {
        let (footer_offset, footer_plain) =
            Self::read_footer(&backing, stored_crc, sst_number, dek)?;
        let (index, key_range, bloom_filter) = Self::parse_v3_footer(&footer_plain)?;

        // A v3 data block's nonce is its position in the index: its ordinal.
        let mut index_plaintext = Vec::new();
        for (ordinal, e) in index.iter().enumerate() {
            let handle = BlockHandle {
                file_offset: e.file_offset,
                ciphertext_len: e.ciphertext_len,
                plaintext_len: e.plaintext_len,
                ordinal: u32::try_from(ordinal).map_err(|_| StorageError::InvalidSstFormat {
                    reason: "v3: too many blocks".to_string(),
                })?,
            };
            Self::check_block_range(&handle, footer_offset)?;
            write_footer_key(&mut index_plaintext, &e.first_key);
            handle.write(&mut index_plaintext);
        }
        let max_entries = index
            .iter()
            .map(|e| e.plaintext_len as usize / SST_MIN_ENTRY_BYTES)
            .fold(0usize, usize::saturating_add);
        let partitions = match index.first() {
            None => Vec::new(),
            Some(first) => vec![Partition {
                first_key: first.first_key.clone(),
                index: Piece::Pinned(Arc::new(CachedBlock::new(Block::Index(
                    IndexBlock::decode(index_plaintext)?,
                )))),
                filter: bloom_filter
                    .map(|filter| Piece::Pinned(Arc::new(CachedBlock::new(Block::Filter(filter))))),
            }],
        };
        Ok(Self::open_blocked(
            backing,
            footer_offset,
            partitions,
            max_entries,
            key_range,
            entry_count,
            sst_number,
            dek,
            cache,
        ))
    }

    /// Parses a V4 SST: read the trailer, verify+decrypt the footer and load
    /// its partition list. Index, filter and data blocks stay on disk.
    fn open_v4(
        backing: FileBacking,
        entry_count: u32,
        stored_crc: u32,
        sst_number: u64,
        dek: &DataEncryptionKey,
        cache: Arc<BlockCache>,
    ) -> Result<Self, StorageError> {
        let (footer_offset, footer_plain) =
            Self::read_footer(&backing, stored_crc, sst_number, dek)?;
        let (max_entries, partitions, key_range) = Self::parse_v4_footer(&footer_plain)?;
        for partition in &partitions {
            for piece in std::iter::once(&partition.index).chain(&partition.filter) {
                if let Piece::Stored(handle) = piece {
                    Self::check_block_range(handle, footer_offset)?;
                }
            }
        }
        Ok(Self::open_blocked(
            backing,
            footer_offset,
            partitions,
            max_entries,
            key_range,
            entry_count,
            sst_number,
            dek,
            cache,
        ))
    }

    /// Parses a decrypted V4 footer into `(entry count, partitions, key range)`.
    #[allow(clippy::type_complexity)]
    fn parse_v4_footer(
        data: &[u8],
    ) -> Result<(usize, Vec<Partition>, Option<(CompositeKey, CompositeKey)>), StorageError> {
        let trunc = || StorageError::InvalidSstFormat {
            reason: "v4: truncated footer".to_string(),
        };
        let entry_count = data
            .get(0..8)
            .and_then(|b| b.try_into().ok())
            .map(u64::from_le_bytes)
            .ok_or_else(trunc)?;
        let partition_count = data
            .get(8..12)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_le_bytes)
            .ok_or_else(trunc)? as usize;
        // Each partition entry takes at least a key header, two handles and a
        // flag, so the footer's length bounds the reservation.
        let min_entry = 20 + 2 * HANDLE_BYTES + 1;
        let mut partitions = Vec::with_capacity(partition_count.min(data.len() / min_entry));
        let mut pos = 12;
        for _ in 0..partition_count {
            let (first_key, next) = read_footer_key(data, pos)?;
            let index = BlockHandle::read(data, next).ok_or_else(trunc)?;
            let has_filter = *data.get(next + HANDLE_BYTES).ok_or_else(trunc)?;
            let filter_pos = next + HANDLE_BYTES + 1;
            let filter = BlockHandle::read(data, filter_pos).ok_or_else(trunc)?;
            pos = filter_pos + HANDLE_BYTES;
            partitions.push(Partition {
                first_key,
                index: Piece::Stored(index),
                filter: (has_filter == 1).then_some(Piece::Stored(filter)),
            });
        }

        let has_range = *data.get(pos).ok_or_else(trunc)?;
        pos += 1;
        let key_range = if has_range == 1 {
            let (min, p1) = read_footer_key(data, pos)?;
            let (max, _) = read_footer_key(data, p1)?;
            Some((min, max))
        } else {
            None
        };
        Ok((
            usize::try_from(entry_count).unwrap_or(usize::MAX),
            partitions,
            key_range,
        ))
    }

    /// Parses a decrypted V3 footer into `(block index, key range, bloom)`.
    #[allow(clippy::type_complexity)]
    fn parse_v3_footer(
        data: &[u8],
    ) -> Result<
        (
            Vec<BlockIndexEntry>,
            Option<(CompositeKey, CompositeKey)>,
            Option<BloomFilter>,
        ),
        StorageError,
    > {
        let trunc = || StorageError::InvalidSstFormat {
            reason: "v3: truncated footer".to_string(),
        };
        let read_u32 = |data: &[u8], pos: usize| -> Result<u32, StorageError> {
            data.get(pos..pos + 4)
                .and_then(|b| b.try_into().ok())
                .map(u32::from_le_bytes)
                .ok_or_else(trunc)
        };
        let read_u64 = |data: &[u8], pos: usize| -> Result<u64, StorageError> {
            data.get(pos..pos + 8)
                .and_then(|b| b.try_into().ok())
                .map(u64::from_le_bytes)
                .ok_or_else(trunc)
        };

        let block_count = read_u32(data, 0)? as usize;
        let mut pos = 4;
        let mut index = Vec::with_capacity(block_count);
        for _ in 0..block_count {
            let file_offset = read_u64(data, pos)?;
            let ciphertext_len = read_u32(data, pos + 8)?;
            let plaintext_len = read_u32(data, pos + 12)?;
            let (first_key, next) = read_footer_key(data, pos + 16)?;
            pos = next;
            index.push(BlockIndexEntry {
                first_key,
                file_offset,
                ciphertext_len,
                plaintext_len,
            });
        }

        let has_range = *data.get(pos).ok_or_else(trunc)?;
        pos += 1;
        let key_range = if has_range == 1 {
            let (min, p1) = read_footer_key(data, pos)?;
            let (max, p2) = read_footer_key(data, p1)?;
            pos = p2;
            Some((min, max))
        } else {
            None
        };

        let bloom_byte_count = read_u32(data, pos)? as usize;
        pos += 4;
        let bloom_filter = if bloom_byte_count > 0 {
            let k = *data.get(pos).ok_or_else(trunc)?;
            pos += 1;
            let bits = data
                .get(pos..pos + bloom_byte_count)
                .ok_or_else(trunc)?
                .to_vec();
            Some(BloomFilter { bits, k })
        } else {
            None
        };

        Ok((index, key_range, bloom_filter))
    }

    /// Returns `true` if the point key `(realm_id, key)` could fall within this
    /// SST's stored key range.
    ///
    /// This is an O(1) range check against the precomputed `[min, max]` bounds.
    /// An empty SST covers nothing and always returns `false`. A `true` result
    /// does not guarantee the key is present — it only means the key is not
    /// provably outside the range, so callers still consult the Bloom filter
    /// and binary search.
    pub(crate) fn may_contain(&self, realm_id: &RealmId, key: &[u8]) -> bool {
        let Some((min, max)) = &self.key_range else {
            return false;
        };
        // Compare the (realm, key) tuple against min/max without allocating a
        // CompositeKey: order by realm UUID first, then key bytes.
        let cmp = |ck: &CompositeKey| ck.realm_id().cmp(realm_id).then_with(|| ck.key().cmp(key));
        cmp(min).is_le() && cmp(max).is_ge()
    }

    /// Returns `true` if this SST's key range overlaps the half-open range
    /// `[start_key, end_key)` within `realm_id`.
    ///
    /// O(1) prune used before a range scan to skip non-overlapping SSTs. An
    /// empty SST never overlaps.
    pub(crate) fn overlaps_range(
        &self,
        realm_id: &RealmId,
        start_key: &[u8],
        end_key: &[u8],
    ) -> bool {
        let Some((min, max)) = &self.key_range else {
            return false;
        };
        let cmp = |ck: &CompositeKey, key: &[u8]| {
            ck.realm_id().cmp(realm_id).then_with(|| ck.key().cmp(key))
        };
        // Overlap iff min < end (half-open upper bound) and max >= start.
        cmp(min, end_key).is_lt() && cmp(max, start_key).is_ge()
    }

    /// Returns all entries in sorted order.
    ///
    /// For a V3 SST this decrypts every block in turn (off the hot path — used
    /// by compaction and tests), so it returns `Result` to surface a corrupt
    /// block rather than silently dropping it.
    pub(crate) fn iter_all(&self) -> Result<Vec<(CompositeKey, MemtableValue)>, StorageError> {
        match &self.body {
            SstBody::Eager(entries) => Ok(entries.clone()),
            SstBody::Blocked(body) => {
                // The header `entry_count` is unauthenticated (outside the footer
                // AEAD and its CRC) and, for v3, never checked against reality, so
                // it must not size an allocation directly — a tampered or corrupted
                // value would drive a multi-gigabyte `Vec::with_capacity` and abort
                // the process on the compaction path (HEA-1917). Clamp it to an
                // upper bound derived from the authenticated footer: no block can
                // hold more than `plaintext_len / SST_MIN_ENTRY_BYTES` entries.
                let cap_bound = self.authenticated_max_entries();
                let mut out = Vec::with_capacity((self.entry_count as usize).min(cap_bound));
                let mut walk = BlockWalk::from_start(body, self.sst_number, true);
                while let Some(block) = walk.next_block(None)? {
                    out.extend(block.block.data()?.iter().map(EntryRef::into_owned));
                }
                Ok(out)
            }
        }
    }

    /// Returns all entries for a specific realm, with raw keys (no realm prefix).
    pub(crate) fn iter_realm(
        &self,
        realm_id: &RealmId,
    ) -> Result<Vec<(Vec<u8>, MemtableValue)>, StorageError> {
        Ok(self
            .iter_all()?
            .into_iter()
            .filter(|(k, _)| k.realm_id() == realm_id)
            .map(|(k, v)| (k.key().to_vec(), v))
            .collect())
    }

    /// Point lookup for a specific realm and key.
    ///
    /// Prunes via the O(1) key range and the Bloom filter first, then binary
    /// searches. For V3 the search first locates the single candidate block via
    /// the footer index, fetches it (cache hit or mmap-slice + decrypt), then
    /// binary searches within the block. Returns `Err` if a matching block
    /// fails AEAD/format validation — never a wrong or silently-absent value.
    pub(crate) fn get(
        &self,
        realm_id: &RealmId,
        key: &[u8],
    ) -> Result<Option<MemtableValue>, StorageError> {
        self.get_with(realm_id, key, true)
    }

    /// A point lookup like [`get`](Self::get) that neither consults nor fills
    /// the shared block cache: the probed block is decoded privately (#445).
    pub(crate) fn get_uncached(
        &self,
        realm_id: &RealmId,
        key: &[u8],
    ) -> Result<Option<MemtableValue>, StorageError> {
        self.get_with(realm_id, key, false)
    }

    fn get_with(
        &self,
        realm_id: &RealmId,
        key: &[u8],
        cached: bool,
    ) -> Result<Option<MemtableValue>, StorageError> {
        // O(1) range prune: skip SSTs whose key range cannot contain the key
        // (HEA-1773). Cheaper than the Bloom filter's k hashes and also rejects
        // V1 SSTs that carry no filter.
        if !self.may_contain(realm_id, key) {
            return Ok(None);
        }
        // Fast reject: if the bloom filter says "no", the key is definitely absent.
        if let Some(ref filter) = self.bloom_filter {
            if !filter.might_contain(realm_id, key) {
                return Ok(None);
            }
        }
        match &self.body {
            SstBody::Eager(entries) => Ok(entries
                .binary_search_by(|(k, _)| {
                    k.realm_id().cmp(realm_id).then_with(|| k.key().cmp(key))
                })
                .ok()
                .map(|idx| entries[idx].1.clone())),
            SstBody::Blocked(body) => body.get(realm_id, key, self.sst_number, cached),
        }
    }

    /// Range scan within a single realm's key space.
    ///
    /// Returns entries where `start_key <= key < end_key` (half-open interval).
    pub(crate) fn range_scan(
        &self,
        realm_id: &RealmId,
        start_key: &[u8],
        end_key: &[u8],
    ) -> Result<Vec<(Vec<u8>, MemtableValue)>, StorageError> {
        self.range_scan_inner(realm_id, start_key, end_key, |v| {
            v.map_or(MemtableValue::Tombstone, |data| {
                MemtableValue::Data(data.to_vec())
            })
        })
    }

    /// Key-only range scan — like [`range_scan`] but returns `(key, is_alive)`
    /// pairs without cloning value bytes.
    pub(crate) fn range_scan_keys(
        &self,
        realm_id: &RealmId,
        start_key: &[u8],
        end_key: &[u8],
    ) -> Result<Vec<(Vec<u8>, bool)>, StorageError> {
        self.range_scan_inner(realm_id, start_key, end_key, |v| v.is_some())
    }

    /// Shared body of [`range_scan`]/[`range_scan_keys`]: prune, locate the
    /// `[start, end)` window, and project each in-range value (`None` for a
    /// tombstone) with `project`.
    fn range_scan_inner<T>(
        &self,
        realm_id: &RealmId,
        start_key: &[u8],
        end_key: &[u8],
        project: impl Fn(Option<&[u8]>) -> T,
    ) -> Result<Vec<(Vec<u8>, T)>, StorageError> {
        // A reversed window would index the eager body as `entries[lo..hi]`
        // with `lo > hi`, which panics and — under `panic=abort` — takes the
        // whole multi-tenant process down (audit §4.9#7). Refuse it here as
        // well as at the engine boundary: this is the layer that would crash.
        if start_key > end_key {
            return Err(StorageError::InvalidRange);
        }
        // O(1) range prune: skip SSTs disjoint from the scan window (HEA-1773).
        if !self.overlaps_range(realm_id, start_key, end_key) {
            return Ok(Vec::new());
        }
        let start = CompositeKey::new(realm_id.clone(), start_key.to_vec());
        let end = CompositeKey::new(realm_id.clone(), end_key.to_vec());

        match &self.body {
            SstBody::Eager(entries) => {
                let lo = entries.partition_point(|(k, _)| k < &start);
                let hi = entries.partition_point(|(k, _)| k < &end);
                Ok(entries[lo..hi]
                    .iter()
                    .map(|(k, v)| (k.key().to_vec(), project(value_view(v))))
                    .collect())
            }
            SstBody::Blocked(body) => {
                let mut out = Vec::new();
                // Start at the block that may hold `start`; the walk ends at the
                // first block that starts at or after `end`.
                let mut walk = BlockWalk::seek(body, self.sst_number, true, realm_id, start_key)?;
                while let Some(block) = walk.next_block(Some(&end))? {
                    for entry in block.block.data()?.iter() {
                        if entry.cmp_composite(&start).is_ge() && entry.cmp_composite(&end).is_lt()
                        {
                            out.push((entry.key().to_vec(), project(entry.value())));
                        }
                    }
                }
                Ok(out)
            }
        }
    }

    /// A cursor over this SST's keys in a realm's `[start_key, end_key)`
    /// window, for a streaming key walk: it holds one decrypted block at a
    /// time and copies no key (#447).
    ///
    /// # Errors
    ///
    /// [`StorageError::InvalidRange`] for a reversed window, or the error
    /// fetching the window's first block.
    pub(crate) fn key_cursor(
        &self,
        realm_id: &RealmId,
        start_key: &[u8],
        end_key: &[u8],
    ) -> Result<SstKeyCursor<'_>, StorageError> {
        self.cursor(realm_id, start_key, end_key, true)
    }

    /// A cursor like [`key_cursor`](Self::key_cursor) that neither consults
    /// nor fills the shared block cache.
    ///
    /// For a walk that reads each block once and is done with it, such as the
    /// cleanup sweep over a realm's expiring rows (#445): cached, those blocks
    /// would fill the cache with rows nobody reads again and evict the query
    /// path's working set. Compaction streams its inputs the same way
    /// (HEA-1922).
    pub(crate) fn uncached_cursor(
        &self,
        realm_id: &RealmId,
        start_key: &[u8],
        end_key: &[u8],
    ) -> Result<SstKeyCursor<'_>, StorageError> {
        self.cursor(realm_id, start_key, end_key, false)
    }

    fn cursor(
        &self,
        realm_id: &RealmId,
        start_key: &[u8],
        end_key: &[u8],
        cached: bool,
    ) -> Result<SstKeyCursor<'_>, StorageError> {
        // The same reversed-window guard as `range_scan_inner` (audit §4.9#7).
        if start_key > end_key {
            return Err(StorageError::InvalidRange);
        }
        if !self.overlaps_range(realm_id, start_key, end_key) {
            return Ok(SstKeyCursor::Done);
        }
        let start = CompositeKey::new(realm_id.clone(), start_key.to_vec());
        let end = CompositeKey::new(realm_id.clone(), end_key.to_vec());
        match &self.body {
            SstBody::Eager(entries) => {
                let lo = entries.partition_point(|(k, _)| k < &start);
                let hi = entries.partition_point(|(k, _)| k < &end);
                Ok(SstKeyCursor::Eager {
                    entries: &entries[lo..hi],
                })
            }
            SstBody::Blocked(body) => {
                // The block that may hold `start`, or the first block when
                // `start` precedes every block.
                let walk = BlockWalk::seek(body, self.sst_number, cached, realm_id, start_key)?;
                let mut blocked = BlockedKeyCursor {
                    walk,
                    end,
                    block: None,
                    pos: 0,
                };
                blocked.load_block()?;
                if let Some(block) = &blocked.block {
                    blocked.pos = block
                        .block
                        .data()?
                        .lower_bound(start.realm_id(), start.key());
                }
                blocked.settle()?;
                Ok(SstKeyCursor::Blocked(blocked))
            }
        }
    }

    /// Heap bytes this reader holds while it is open: its partition list (v4),
    /// its block index and Bloom filter (v3), or its entries and Bloom filter
    /// (v1/v2), and its key range. The file mapping and the blocks in the
    /// block cache are not counted.
    pub(crate) fn resident_bytes(&self) -> usize {
        self.resident_bytes
    }

    /// Returns the entry count as declared in the SST header.
    pub(crate) fn entry_count(&self) -> u32 {
        self.entry_count
    }

    /// Returns an authenticated upper bound on the number of entries this SST
    /// can hold, derived only from integrity-protected data.
    ///
    /// The header `entry_count` (bytes 4..8) is *unauthenticated* — covered by
    /// neither the footer AEAD nor the footer CRC — so it MUST NOT size an
    /// allocation directly: a tampered or bit-rotted value (e.g. `u32::MAX`)
    /// would drive a multi-gigabyte reservation and abort the process via an
    /// uncatchable `handle_alloc_error` (HEA-1917). This bound is safe to size
    /// Bloom filters or `Vec` capacities against:
    /// - **v4:** the entry count in the AEAD-authenticated footer.
    /// - **v3:** the footer block index is AEAD-authenticated, and no block can
    ///   hold more than `plaintext_len / SST_MIN_ENTRY_BYTES` entries; summed
    ///   (saturating) over every block.
    /// - **Eager (v1/v2):** the entries are already resident and decrypted, so
    ///   their true count is known.
    pub(crate) fn authenticated_max_entries(&self) -> usize {
        match &self.body {
            SstBody::Eager(entries) => entries.len(),
            SstBody::Blocked(body) => body.max_entries,
        }
    }

    /// Returns the SST file number used for path derivation.
    pub(crate) fn sst_number(&self) -> u64 {
        self.sst_number
    }

    /// The id that keys this reader's blocks in the block cache; every open of
    /// a file gets a new one. `None` for a v1/v2 reader, which has no blocks.
    #[cfg(test)]
    pub(crate) fn reader_id(&self) -> Option<u64> {
        match &self.body {
            SstBody::Eager(_) => None,
            SstBody::Blocked(body) => Some(body.reader_id),
        }
    }

    /// Parses a V2 plaintext section: bloom filter preamble followed by entries.
    ///
    /// V2 layout:
    /// ```text
    /// [4B] bloom_byte_count (u32 LE) — 0 = empty SST, no filter data follows
    /// [1B] bloom_k                   — only if bloom_byte_count > 0
    /// [N B] bloom bits               — only if bloom_byte_count > 0
    /// [entry bytes]                  — same serialisation as V1
    /// ```
    fn parse_v2_plaintext(data: &[u8], expected_count: u32) -> Result<ParsedV2, StorageError> {
        if data.len() < 4 {
            return Err(StorageError::InvalidSstFormat {
                reason: "V2: truncated bloom header".to_string(),
            });
        }
        let bloom_byte_count = u32::from_le_bytes(data[0..4].try_into().map_err(|_| {
            StorageError::InvalidSstFormat {
                reason: "V2: invalid bloom byte count bytes".to_string(),
            }
        })?) as usize;
        let mut pos = 4;

        let bloom_filter = if bloom_byte_count > 0 {
            if pos >= data.len() {
                return Err(StorageError::InvalidSstFormat {
                    reason: "V2: missing bloom k byte".to_string(),
                });
            }
            let bloom_k = data[pos];
            pos += 1;
            if pos + bloom_byte_count > data.len() {
                return Err(StorageError::InvalidSstFormat {
                    reason: "V2: truncated bloom bits".to_string(),
                });
            }
            let bits = data[pos..pos + bloom_byte_count].to_vec();
            pos += bloom_byte_count;
            Some(BloomFilter { bits, k: bloom_k })
        } else {
            None
        };

        let entries = Self::deserialize_entries(&data[pos..], expected_count)?;
        Ok((entries, bloom_filter))
    }

    /// Deserializes a whole data section into entries, asserting the count.
    fn deserialize_entries(
        data: &[u8],
        expected_count: u32,
    ) -> Result<Vec<(CompositeKey, MemtableValue)>, StorageError> {
        Self::parse_entries(data, Some(expected_count))
    }

    /// Parses a run of serialized entries until `data` is exhausted.
    ///
    /// When `expected_count` is `Some(n)` the decoded entry count must equal `n`
    /// (whole-section decode for V1/V2). When `None` the run is decoded without
    /// a count assertion (a single V3 block, whose entry count is not stored).
    fn parse_entries(
        data: &[u8],
        expected_count: Option<u32>,
    ) -> Result<Vec<(CompositeKey, MemtableValue)>, StorageError> {
        // `expected_count` originates from the unauthenticated base header, and
        // the count-mismatch check below only runs *after* the decode loop — so
        // an oversized reservation here aborts the process (uncatchable) long
        // before that error can be returned. Clamp against `data.len()`, which
        // IS authenticated at this point (V1/V2: the AEAD-decrypted section;
        // V3: an AEAD-decrypted block), so a tampered or bit-rotted count can
        // only ever under-reserve, never over-reserve (HEA-1917).
        let cap = (expected_count.unwrap_or(0) as usize).min(data.len() / SST_MIN_ENTRY_BYTES);
        let mut entries = Vec::with_capacity(cap);
        let mut pos = 0;
        while pos < data.len() {
            let (entry, next) = read_entry(data, pos)?;
            entries.push(entry.into_owned());
            pos = next;
        }

        if let Some(expected_count) = expected_count {
            #[allow(clippy::cast_possible_truncation)]
            let actual_count = entries.len() as u32;
            if actual_count != expected_count {
                return Err(StorageError::InvalidSstFormat {
                    reason: format!(
                        "entry count mismatch: header says {expected_count}, found {actual_count}"
                    ),
                });
            }
        }

        Ok(entries)
    }
}

/// Streaming cursor over one input SST during compaction.
///
/// Holds at most one decoded block (V3) resident at a time, refilling from the
/// next block on demand, so a k-way merge across `N` inputs needs only
/// `O(N × block)` heap rather than materialising every entry (HEA-1922). A V1/V2
/// eager reader already keeps its whole entry vector resident, so the cursor
/// simply clones through it once.
struct SstCursor<'a> {
    reader: &'a SstReader,
    buf: std::collections::VecDeque<(CompositeKey, MemtableValue)>,
    /// The blocks of a V3/V4 input not yet decoded, read past the cache.
    walk: Option<BlockWalk<'a>>,
    exhausted: bool,
}

impl<'a> SstCursor<'a> {
    fn new(reader: &'a SstReader) -> Self {
        let walk = match &reader.body {
            SstBody::Blocked(body) => Some(BlockWalk::from_start(body, reader.sst_number, false)),
            SstBody::Eager(_) => None,
        };
        Self {
            reader,
            buf: std::collections::VecDeque::new(),
            walk,
            exhausted: false,
        }
    }

    /// Ensures `buf` holds at least one entry while the input is not exhausted,
    /// decoding the next block (V3) or loading the eager vector (V1/V2) as needed.
    fn fill(&mut self) -> Result<(), StorageError> {
        while self.buf.is_empty() && !self.exhausted {
            match (&self.reader.body, &mut self.walk) {
                (SstBody::Blocked(_), Some(walk)) => match walk.next_block(None)? {
                    Some(block) => self
                        .buf
                        .extend(block.block.data()?.iter().map(EntryRef::into_owned)),
                    None => self.exhausted = true,
                },
                (SstBody::Eager(entries), _) => {
                    self.buf.extend(entries.iter().cloned());
                    self.exhausted = true;
                }
                (SstBody::Blocked(_), None) => self.exhausted = true,
            }
        }
        Ok(())
    }

    /// Returns the next entry's key without consuming it.
    fn peek_key(&mut self) -> Result<Option<&CompositeKey>, StorageError> {
        self.fill()?;
        Ok(self.buf.front().map(|(k, _)| k))
    }

    /// Removes and returns the next entry.
    fn pop(&mut self) -> Result<Option<(CompositeKey, MemtableValue)>, StorageError> {
        self.fill()?;
        Ok(self.buf.pop_front())
    }
}

/// Heap element: the current head key of input `idx`. `Ord` is inverted so a
/// `BinaryHeap` (a max-heap) yields the *smallest* key — and, among equal keys,
/// the *lowest* input index — first.
struct MergeHead {
    key: CompositeKey,
    idx: usize,
}

impl PartialEq for MergeHead {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key && self.idx == other.idx
    }
}
impl Eq for MergeHead {}
impl Ord for MergeHead {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other
            .key
            .cmp(&self.key)
            .then_with(|| other.idx.cmp(&self.idx))
    }
}
impl PartialOrd for MergeHead {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// K-way merge over compaction inputs, yielding entries in ascending
/// `CompositeKey` order with newest-input-wins on duplicate keys (HEA-1922).
///
/// Inputs are ordered oldest-to-newest (index 0 oldest). Only one entry per
/// input lives in the heap at a time, and each input's payload is streamed one
/// block at a time through its [`SstCursor`], so peak resident state is
/// `O(#inputs × block)` regardless of corpus size. A decode/AEAD failure on any
/// input is surfaced as an `Err` item so the caller aborts the compaction.
struct KMergeIter<'a> {
    cursors: Vec<SstCursor<'a>>,
    heap: std::collections::BinaryHeap<MergeHead>,
    seeded: bool,
}

impl<'a> KMergeIter<'a> {
    fn new(inputs: &[&'a SstReader]) -> Self {
        Self {
            cursors: inputs.iter().map(|r| SstCursor::new(r)).collect(),
            heap: std::collections::BinaryHeap::new(),
            seeded: false,
        }
    }

    /// Loads each input's first key into the heap.
    fn seed(&mut self) -> Result<(), StorageError> {
        for idx in 0..self.cursors.len() {
            if let Some(key) = self.cursors[idx].peek_key()? {
                let key = key.clone();
                self.heap.push(MergeHead { key, idx });
            }
        }
        self.seeded = true;
        Ok(())
    }

    /// Re-seeds the heap with input `idx`'s new head, if any.
    fn repush(&mut self, idx: usize) -> Result<(), StorageError> {
        if let Some(key) = self.cursors[idx].peek_key()? {
            let key = key.clone();
            self.heap.push(MergeHead { key, idx });
        }
        Ok(())
    }

    /// Produces the next merged entry, or `None` when every input is drained.
    fn advance(&mut self) -> Result<Option<(CompositeKey, MemtableValue)>, StorageError> {
        if !self.seeded {
            self.seed()?;
        }
        let Some(MergeHead { key: min_key, idx }) = self.heap.pop() else {
            return Ok(None);
        };
        // Gather every input whose head equals `min_key`. Each input has at most
        // one head in the heap, and keys within an input are strictly increasing,
        // so no input appears twice.
        let mut equal = vec![idx];
        while self.heap.peek().is_some_and(|top| top.key == min_key) {
            if let Some(head) = self.heap.pop() {
                equal.push(head.idx);
            }
        }
        // Highest index = newest input = surviving value; the rest are shadowed
        // but still advanced.
        let newest = equal.iter().copied().max().unwrap_or(idx);
        let mut winner: Option<MemtableValue> = None;
        for ci in equal {
            if let Some((_, value)) = self.cursors[ci].pop()? {
                if ci == newest {
                    winner = Some(value);
                }
            }
            self.repush(ci)?;
        }
        let value = winner.ok_or_else(|| StorageError::InvalidSstFormat {
            reason: "compaction merge: winning entry vanished".to_string(),
        })?;
        Ok(Some((min_key, value)))
    }
}

impl Iterator for KMergeIter<'_> {
    type Item = Result<(CompositeKey, MemtableValue), StorageError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.advance().transpose()
    }
}

/// Compacts multiple SST files into a single output SST.
///
/// Input SSTs are ordered oldest-to-newest. For duplicate keys, the newest
/// value wins. Tombstones are removed entirely during compaction (they have
/// served their purpose of shadowing older values).
pub(crate) fn compact(
    input_ssts: &[&SstReader],
    output_path: &Path,
    output_sst_number: u64,
    dek: &DataEncryptionKey,
    enc_header: &EncryptionHeader,
) -> Result<SstMetadata, StorageError> {
    compact_with_fs(
        input_ssts,
        output_path,
        &RealFs,
        output_sst_number,
        dek,
        enc_header,
    )
}

/// Compacts SST files using a custom filesystem implementation.
///
/// Drops tombstones — use only for a **full** merge where no older SST survives
/// (see [`compact_with_fs_opts`] for the partial-merge variant that preserves
/// them).
pub(crate) fn compact_with_fs(
    input_ssts: &[&SstReader],
    output_path: &Path,
    fs: &dyn Fs,
    output_sst_number: u64,
    dek: &DataEncryptionKey,
    enc_header: &EncryptionHeader,
) -> Result<SstMetadata, StorageError> {
    compact_with_fs_opts(
        input_ssts,
        output_path,
        fs,
        output_sst_number,
        dek,
        enc_header,
        true,
    )
}

/// Compacts SST files, optionally preserving tombstones.
///
/// Input SSTs are ordered oldest-to-newest; for duplicate keys the newest value
/// wins. When `drop_tombstones` is `true` the merged output omits tombstones
/// entirely — correct only when the inputs include the oldest SST, so no older
/// file can hold a shadowed value. A **partial** compaction that leaves older
/// SSTs live MUST pass `false`, otherwise a delete could be resurrected from an
/// un-merged older file (HEA-1885).
pub(crate) fn compact_with_fs_opts(
    input_ssts: &[&SstReader],
    output_path: &Path,
    fs: &dyn Fs,
    output_sst_number: u64,
    dek: &DataEncryptionKey,
    enc_header: &EncryptionHeader,
    drop_tombstones: bool,
) -> Result<SstMetadata, StorageError> {
    // Stream a k-way merge of the inputs straight into the block-filling writer:
    // no `BTreeMap`/`Vec` of the whole corpus is ever materialised, so peak heap
    // is `O(#inputs × block)` rather than `O(corpus)` — the flat-RAM criterion
    // the query path already met, now extended to the compaction path (HEA-1922).
    // The writer sizes each partition's Bloom filter from the keys it really
    // wrote. A v3 output sized one filter for the whole merge from the inputs'
    // worst case of 25-byte rows, about six times too large for Hearth's rows
    // (#445).
    let merged = KMergeIter::new(input_ssts);

    SstWriter::write_sst_streaming_with_fs(
        output_path,
        merged,
        drop_tombstones,
        fs,
        output_sst_number,
        dek,
        enc_header,
    )
}

/// Reads the encryption header from an SST file without decrypting the data.
///
/// Returns the `(KekId, EncryptionHeader)` so callers can look up the
/// appropriate KEK before fully opening the file.
pub(crate) fn read_encryption_header(
    path: &Path,
    fs: &dyn Fs,
) -> Result<(KekId, EncryptionHeader), StorageError> {
    // Bounded read: `reload_sst_readers` calls this once per live SST on every
    // memtable flush, so reading the whole file here made one flush re-read
    // every byte of every live SST (audit 2026-08-28 §4.21#5).
    let data = fs.read_prefix(path, TOTAL_HEADER_SIZE)?;
    if data.len() < TOTAL_HEADER_SIZE {
        return Err(StorageError::InvalidSstFormat {
            reason: format!("file too small for header: {} bytes", data.len()),
        });
    }

    if ![SST_MAGIC, SST_MAGIC_V2, SST_MAGIC_V3, SST_MAGIC_V4]
        .iter()
        .any(|magic| data[0..4] == magic[..])
    {
        return Err(StorageError::InvalidSstFormat {
            reason: "invalid magic bytes".to_string(),
        });
    }

    let enc_bytes: &[u8; encryption::ENCRYPTION_HEADER_SIZE] = data
        [BASE_HEADER_SIZE..TOTAL_HEADER_SIZE]
        .try_into()
        .map_err(|_| StorageError::InvalidSstFormat {
            reason: "truncated encryption header".to_string(),
        })?;

    let enc_header = EncryptionHeader::from_bytes(enc_bytes);
    let kek_id = enc_header.kek_id;

    Ok((kek_id, enc_header))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::RealmId;
    use crate::storage::encryption;
    use crate::storage::memtable::{Memtable, MemtableConfig};

    /// Helper to create encryption context for tests.
    fn test_encryption_context() -> (DataEncryptionKey, EncryptionHeader) {
        let dek = encryption::generate_dek().expect("dek");
        let kek = encryption::generate_kek().expect("kek");
        let kek_id = [0x42u8; encryption::KEK_ID_SIZE];
        let enc_header = encryption::wrap_dek(&dek, &kek, kek_id).expect("wrap");
        (dek, enc_header)
    }

    /// The data blocks of a v3/v4 reader in key order, decoded past the cache.
    fn data_blocks(reader: &SstReader) -> Vec<Arc<CachedBlock>> {
        let SstBody::Blocked(body) = &reader.body else {
            panic!("expected a block-structured SST");
        };
        let mut walk = BlockWalk::from_start(body, reader.sst_number, false);
        let mut blocks = Vec::new();
        while let Some(block) = walk.next_block(None).expect("walk") {
            blocks.push(block);
        }
        blocks
    }

    /// The partitions of a v3/v4 reader.
    fn partitions(reader: &SstReader) -> &[Partition] {
        let SstBody::Blocked(body) = &reader.body else {
            panic!("expected a block-structured SST");
        };
        &body.partitions
    }

    /// Writes `entries` as a v3 file, which Hearth no longer writes but must
    /// still read.
    fn write_v3_for_test(
        path: &Path,
        entries: &[(CompositeKey, MemtableValue)],
        sst_number: u64,
        dek: &DataEncryptionKey,
        enc_header: &EncryptionHeader,
    ) {
        let mut file = RealFs.create(path).expect("create");
        let mut body = V3BodyWriter::start(&mut *file, enc_header, entries.len(), sst_number, dek)
            .expect("start");
        for (key, value) in entries {
            body.push(key, value).expect("push");
        }
        body.finish().expect("finish");
        file.sync_all().expect("sync");
    }

    /// A data block searches its plaintext in place, so its entries MUST sort
    /// exactly as `CompositeKey` sorts: realm first, then key bytes. Realms
    /// that differ in their first or last byte, and keys that are prefixes of
    /// each other, are the cases a wrong comparison gets wrong.
    #[test]
    fn data_block_entries_sort_and_search_as_composite_keys() {
        let realms = [
            RealmId::new(Uuid::from_bytes([0x00; 16])),
            RealmId::new(Uuid::from_bytes([
                0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff,
            ])),
            RealmId::new(Uuid::from_bytes([0x80; 16])),
            RealmId::new(Uuid::from_bytes([0xff; 16])),
        ];
        let keys: [&[u8]; 5] = [b"", b"a", b"a\x00", b"ab", b"b"];
        let mut entries: Vec<(CompositeKey, MemtableValue)> = realms
            .iter()
            .flat_map(|realm| {
                keys.iter().enumerate().map(move |(i, key)| {
                    let value = if i % 2 == 0 {
                        MemtableValue::Data(key.to_vec())
                    } else {
                        MemtableValue::Tombstone
                    };
                    (CompositeKey::new(realm.clone(), key.to_vec()), value)
                })
            })
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let block = DataBlock::from_entries(&entries);

        assert_eq!(block.len(), entries.len());
        for (i, (key, value)) in entries.iter().enumerate() {
            let entry = block.entry(i).expect("entry");
            assert_eq!(
                entry.into_owned(),
                (key.clone(), value.clone()),
                "entry {i}"
            );
            for (other, _) in &entries {
                assert_eq!(
                    entry.cmp_composite(other),
                    key.cmp(other),
                    "{key:?} against {other:?}"
                );
            }
            assert_eq!(block.lower_bound(key.realm_id(), key.key()), i);
            assert_eq!(
                block
                    .find(key.realm_id(), key.key())
                    .map(|e| e.memtable_value()),
                Some(value.clone())
            );
        }
        let absent = RealmId::new(Uuid::from_bytes([0x40; 16]));
        assert!(block.find(&absent, b"a").is_none());
        assert_eq!(block.lower_bound(&absent, b"a"), 2 * keys.len());
    }

    #[test]
    fn flush_memtable_to_sst_produces_valid_format() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("test.sst");

        let mt = Memtable::new(MemtableConfig::default());
        let realm = RealmId::generate();

        mt.put(&realm, b"key1", b"value1").expect("put");
        mt.put(&realm, b"key2", b"value2").expect("put");
        mt.put(&realm, b"key3", b"value3").expect("put");

        let entries = mt.iter_all();
        let (dek, enc_header) = test_encryption_context();
        let metadata =
            SstWriter::write_sst(&sst_path, &entries, 1, &dek, &enc_header).expect("write_sst");

        assert_eq!(metadata.entry_count, 3);
        assert!(metadata.file_size > 0);

        // Verify raw file structure — new SSTs use the V4 magic
        let raw = std::fs::read(&sst_path).expect("read file");
        assert!(raw.len() >= TOTAL_HEADER_SIZE);
        assert_eq!(&raw[0..4], b"HSS4", "new SSTs must use V4 magic");
        assert_eq!(u32::from_le_bytes(raw[4..8].try_into().expect("bytes")), 3);
    }

    #[test]
    fn read_sst_matches_original_memtable_contents() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("test.sst");

        let mt = Memtable::new(MemtableConfig::default());
        let realm = RealmId::generate();

        mt.put(&realm, b"alpha", b"val-a").expect("put");
        mt.put(&realm, b"bravo", b"val-b").expect("put");
        mt.delete(&realm, b"charlie").expect("delete");
        mt.put(&realm, b"delta", b"val-d").expect("put");

        let original_entries = mt.iter_all();
        let (dek, enc_header) = test_encryption_context();
        SstWriter::write_sst(&sst_path, &original_entries, 1, &dek, &enc_header)
            .expect("write_sst");

        let reader = SstReader::open(&sst_path, 1, &dek).expect("open");
        let read_entries = reader.iter_all().expect("iter_all");

        assert_eq!(read_entries.len(), original_entries.len());
        for (orig, read) in original_entries.iter().zip(read_entries.iter()) {
            assert_eq!(orig, read);
        }
    }

    /// A v4 reader holds only its partition list on the heap: its block index
    /// and Bloom filter stay in the file and load through the block cache. A
    /// v3 reader holds both whole, so its heap grows with every row in the
    /// file, and it reports that heap (#445).
    #[test]
    fn a_v4_reader_holds_only_its_partition_list_on_the_heap() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (dek, enc_header) = test_encryption_context();
        let realm = RealmId::generate();
        let entries: Vec<(CompositeKey, MemtableValue)> = (0..20_000)
            .map(|i| {
                (
                    CompositeKey::new(realm.clone(), format!("key-{i:08}").into_bytes()),
                    MemtableValue::Data(vec![b'v'; 200]),
                )
            })
            .collect();
        let v4_path = dir.path().join("v4.sst");
        let v3_path = dir.path().join("v3.sst");
        SstWriter::write_sst(&v4_path, &entries, 1, &dek, &enc_header).expect("write v4");
        write_v3_for_test(&v3_path, &entries, 2, &dek, &enc_header);
        let v4 = SstReader::open(&v4_path, 1, &dek).expect("open v4");
        let v3 = SstReader::open(&v3_path, 2, &dek).expect("open v3");

        assert!(
            partitions(&v4).len() >= 2,
            "precondition: 4.7 MB of rows span several partitions"
        );
        assert!(
            v4.resident_bytes() < 4096,
            "a v4 reader of 20,000 rows holds {} bytes of heap",
            v4.resident_bytes()
        );
        let bloom_bytes = 20_000 * 10 / 8;
        assert!(
            v3.resident_bytes() > bloom_bytes,
            "a v3 reader reports {} bytes; its Bloom filter alone is {bloom_bytes}",
            v3.resident_bytes()
        );
        for (key, value) in entries.iter().step_by(997) {
            assert_eq!(
                v4.get(&realm, key.key()).expect("get v4").as_ref(),
                Some(value)
            );
            assert_eq!(
                v3.get(&realm, key.key()).expect("get v3").as_ref(),
                Some(value)
            );
        }
    }

    /// Each v4 filter is sized from the rows of its own partition. Compaction
    /// sized a v3 file's one filter from its inputs' worst case of 25-byte
    /// rows: about six times too large for Hearth's rows (#445).
    #[test]
    fn compaction_sizes_each_filter_from_its_real_row_count() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();
        let rows = |range: std::ops::Range<usize>| -> Vec<(CompositeKey, MemtableValue)> {
            range
                .map(|i| {
                    (
                        CompositeKey::new(realm.clone(), format!("key-{i:08}").into_bytes()),
                        MemtableValue::Data(vec![b'v'; 120]),
                    )
                })
                .collect()
        };
        let (dek, enc) = test_encryption_context();
        let (a_path, b_path) = (dir.path().join("a.sst"), dir.path().join("b.sst"));
        SstWriter::write_sst(&a_path, &rows(0..10_000), 1, &dek, &enc).expect("write a");
        SstWriter::write_sst(&b_path, &rows(5_000..15_000), 2, &dek, &enc).expect("write b");
        let a = SstReader::open(&a_path, 1, &dek).expect("open a");
        let b = SstReader::open(&b_path, 2, &dek).expect("open b");
        let out_path = dir.path().join("out.sst");
        let meta = compact(&[&a, &b], &out_path, 3, &dek, &enc).expect("compact");
        assert_eq!(meta.entry_count, 15_000, "the inputs overlap by 5,000 rows");

        let out = SstReader::open(&out_path, 3, &dek).expect("open output");
        let SstBody::Blocked(body) = &out.body else {
            panic!("compaction writes a blocked SST");
        };
        let filter_bytes: usize = body
            .partitions
            .iter()
            .map(|p| {
                let filter = p.filter.as_ref().expect("a v4 partition has a filter");
                let block = body
                    .piece(filter, BlockKind::Filter, 3, false)
                    .expect("load filter");
                block.block.filter().expect("filter block").bits.len()
            })
            .sum();
        let exact = 15_000 * 10 / 8;
        assert!(
            filter_bytes >= exact && filter_bytes <= exact + 8 * body.partitions.len(),
            "15,000 rows took {filter_bytes} bytes of filter; 10 bits a row is {exact}"
        );
        for i in (0..15_000).step_by(499) {
            assert!(
                out.get(&realm, format!("key-{i:08}").as_bytes())
                    .expect("get")
                    .is_some(),
                "row {i}"
            );
        }
    }

    #[test]
    fn compaction_merges_deduplicates_and_removes_tombstones() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();

        // SST 1 (older): key1=v1, key2=v2, key3=v3
        let sst1_path = dir.path().join("sst1.sst");
        let entries1 = vec![
            (
                CompositeKey::new(realm.clone(), b"key1".to_vec()),
                MemtableValue::Data(b"v1-old".to_vec()),
            ),
            (
                CompositeKey::new(realm.clone(), b"key2".to_vec()),
                MemtableValue::Data(b"v2".to_vec()),
            ),
            (
                CompositeKey::new(realm.clone(), b"key3".to_vec()),
                MemtableValue::Data(b"v3".to_vec()),
            ),
        ];
        let (dek1, enc1) = test_encryption_context();
        SstWriter::write_sst(&sst1_path, &entries1, 1, &dek1, &enc1).expect("write sst1");

        // SST 2 (newer): key1=v1-new (overwrite), key3=tombstone (delete)
        let sst2_path = dir.path().join("sst2.sst");
        let entries2 = vec![
            (
                CompositeKey::new(realm.clone(), b"key1".to_vec()),
                MemtableValue::Data(b"v1-new".to_vec()),
            ),
            (
                CompositeKey::new(realm.clone(), b"key3".to_vec()),
                MemtableValue::Tombstone,
            ),
        ];
        let (dek2, enc2) = test_encryption_context();
        SstWriter::write_sst(&sst2_path, &entries2, 2, &dek2, &enc2).expect("write sst2");

        // Compact (oldest first, newest last)
        let reader1 = SstReader::open(&sst1_path, 1, &dek1).expect("open sst1");
        let reader2 = SstReader::open(&sst2_path, 2, &dek2).expect("open sst2");
        let output_path = dir.path().join("compacted.sst");
        let (dek_out, enc_out) = test_encryption_context();
        let metadata =
            compact(&[&reader1, &reader2], &output_path, 3, &dek_out, &enc_out).expect("compact");

        assert_eq!(metadata.entry_count, 2);

        let compacted = SstReader::open(&output_path, 3, &dek_out).expect("open compacted");
        let all = compacted.iter_all().expect("iter_all");

        assert_eq!(all.len(), 2);
        assert_eq!(all[0].0.key(), b"key1");
        assert_eq!(all[0].1, MemtableValue::Data(b"v1-new".to_vec()));
        assert_eq!(all[1].0.key(), b"key2");
        assert_eq!(all[1].1, MemtableValue::Data(b"v2".to_vec()));
    }

    /// Streaming compaction (HEA-1922) must produce identical results to the old
    /// materialise-everything path across **many blocks** — the merge, dedup, and
    /// tombstone drop all have to work across V3 block boundaries, not just within
    /// a single block as the small fixtures above test. Uses a corpus far larger
    /// than `BLOCK_TARGET_BYTES` so both inputs and the output span dozens of
    /// blocks, then verifies newest-wins, deletion, ordering, and point lookups.
    #[test]
    fn streaming_compaction_merges_correctly_across_many_blocks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();
        // Zero-padded keys so lexicographic order matches numeric order.
        let key = |i: usize| CompositeKey::new(realm.clone(), format!("key{i:06}").into_bytes());
        const N: usize = 2000;

        // Older SST: every key present with an "old" value.
        let mut old_entries: Vec<(CompositeKey, MemtableValue)> = (0..N)
            .map(|i| (key(i), MemtableValue::Data(format!("old-{i}").into_bytes())))
            .collect();
        old_entries.sort_by(|a, b| a.0.cmp(&b.0));
        let (dek_old, enc_old) = test_encryption_context();
        let old_path = dir.path().join("old.sst");
        SstWriter::write_sst(&old_path, &old_entries, 1, &dek_old, &enc_old).expect("write old");

        // Newer SST: multiples of 10 deleted; other evens overwritten; odds absent.
        let mut new_entries: Vec<(CompositeKey, MemtableValue)> = (0..N)
            .filter_map(|i| {
                if i % 10 == 0 {
                    Some((key(i), MemtableValue::Tombstone))
                } else if i % 2 == 0 {
                    Some((key(i), MemtableValue::Data(format!("new-{i}").into_bytes())))
                } else {
                    None
                }
            })
            .collect();
        new_entries.sort_by(|a, b| a.0.cmp(&b.0));
        let (dek_new, enc_new) = test_encryption_context();
        let new_path = dir.path().join("new.sst");
        SstWriter::write_sst(&new_path, &new_entries, 2, &dek_new, &enc_new).expect("write new");

        // Sanity: the inputs really do span multiple blocks (else this test would
        // silently degrade to the single-block case the small fixtures cover).
        let old_reader = SstReader::open(&old_path, 1, &dek_old).expect("open old");
        let new_reader = SstReader::open(&new_path, 2, &dek_new).expect("open new");
        assert!(
            data_blocks(&old_reader).len() > 1,
            "corpus must span multiple blocks"
        );

        // Full compaction (oldest first) — tombstones dropped.
        let (dek_out, enc_out) = test_encryption_context();
        let out_path = dir.path().join("compacted.sst");
        let meta = compact(
            &[&old_reader, &new_reader],
            &out_path,
            3,
            &dek_out,
            &enc_out,
        )
        .expect("compact");

        // Expected surviving set: drop multiples of 10, evens→new, odds→old.
        let expected: Vec<(String, String)> = (0..N)
            .filter_map(|i| {
                if i % 10 == 0 {
                    None
                } else if i % 2 == 0 {
                    Some((format!("key{i:06}"), format!("new-{i}")))
                } else {
                    Some((format!("key{i:06}"), format!("old-{i}")))
                }
            })
            .collect();
        assert_eq!(meta.entry_count as usize, expected.len());

        let compacted = SstReader::open(&out_path, 3, &dek_out).expect("open compacted");
        let all = compacted.iter_all().expect("iter_all");
        assert_eq!(all.len(), expected.len());
        for (i, (got, (exp_key, exp_val))) in all.iter().zip(expected.iter()).enumerate() {
            assert_eq!(got.0.key(), exp_key.as_bytes(), "key order mismatch at {i}");
            assert_eq!(
                got.1,
                MemtableValue::Data(exp_val.clone().into_bytes()),
                "value mismatch at {i}"
            );
        }
        // Ordering must be strictly ascending across the whole (multi-block) file.
        for w in all.windows(2) {
            assert!(w[0].0 < w[1].0, "entries not strictly sorted");
        }

        // Point lookups exercise the footer block index + per-block decrypt.
        assert!(
            compacted.get(&realm, b"key000010").expect("get").is_none(),
            "deleted key must be absent"
        );
        assert_eq!(
            compacted.get(&realm, b"key000002").expect("get"),
            Some(MemtableValue::Data(b"new-2".to_vec())),
            "even key overwritten by newer SST"
        );
        assert_eq!(
            compacted.get(&realm, b"key001997").expect("get"),
            Some(MemtableValue::Data(b"old-1997".to_vec())),
            "odd key retained from older SST"
        );
    }

    /// A **partial** streaming compaction (`drop_tombstones = false`) must retain
    /// tombstones across block boundaries so a deleted key is not resurrected from
    /// an older, un-merged SST (HEA-1885, exercised through the HEA-1922 streaming
    /// writer).
    #[test]
    fn streaming_partial_compaction_preserves_tombstones_across_blocks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();
        let key = |i: usize| CompositeKey::new(realm.clone(), format!("key{i:06}").into_bytes());
        const N: usize = 1500;

        let mut a: Vec<(CompositeKey, MemtableValue)> = (0..N)
            .map(|i| (key(i), MemtableValue::Data(format!("a-{i}").into_bytes())))
            .collect();
        a.sort_by(|x, y| x.0.cmp(&y.0));
        let (dek_a, enc_a) = test_encryption_context();
        let a_path = dir.path().join("a.sst");
        SstWriter::write_sst(&a_path, &a, 5, &dek_a, &enc_a).expect("write a");

        // Newer member deletes every 7th key.
        let mut b: Vec<(CompositeKey, MemtableValue)> = (0..N)
            .filter(|i| i % 7 == 0)
            .map(|i| (key(i), MemtableValue::Tombstone))
            .collect();
        b.sort_by(|x, y| x.0.cmp(&y.0));
        let (dek_b, enc_b) = test_encryption_context();
        let b_path = dir.path().join("b.sst");
        SstWriter::write_sst(&b_path, &b, 6, &dek_b, &enc_b).expect("write b");

        let reader_a = SstReader::open(&a_path, 5, &dek_a).expect("open a");
        let reader_b = SstReader::open(&b_path, 6, &dek_b).expect("open b");
        let (dek_out, enc_out) = test_encryption_context();
        let out_path = dir.path().join("partial.sst");
        compact_with_fs_opts(
            &[&reader_a, &reader_b],
            &out_path,
            &RealFs,
            6,
            &dek_out,
            &enc_out,
            false, // partial merge: tombstones MUST survive
        )
        .expect("partial compact");

        let compacted = SstReader::open(&out_path, 6, &dek_out).expect("open partial");
        // Deleted keys survive as tombstones (shadow the older, un-merged SST).
        assert_eq!(
            compacted.get(&realm, b"key000007").expect("get"),
            Some(MemtableValue::Tombstone),
            "tombstone must be preserved in a partial merge"
        );
        assert_eq!(
            compacted.get(&realm, b"key001400").expect("get"),
            Some(MemtableValue::Tombstone),
            "tombstone in a late block must be preserved too"
        );
        // A non-deleted key keeps its data value.
        assert_eq!(
            compacted.get(&realm, b"key000008").expect("get"),
            Some(MemtableValue::Data(b"a-8".to_vec())),
        );
    }

    /// Pins the *streaming* nature of compaction (HEA-1922), not just its output.
    ///
    /// The two behavioural compaction tests above pass byte-for-byte identically
    /// whether the k-way merge streams block-by-block or eagerly materialises the
    /// whole corpus in a `BTreeMap`/`Vec` first — so neither guards the memory
    /// property HEA-1922 actually changed (606 → 35.5 MiB transient peak; pinned
    /// otherwise only by `examples/sst_v3_c0_memory`, which is not a `nextest`
    /// gate). This test drives the merge one entry at a time and asserts that the
    /// entries held resident across all input cursors never exceed a bound that is
    /// `O(#inputs × block)` — a constant *independent of corpus size*. An eager
    /// whole-corpus merge would hold `Θ(N)` entries and blow the bound; a revert
    /// that removes [`KMergeIter`] fails to compile. Proven RED under HEA-1939 by
    /// making `SstCursor::fill` decode every block at once.
    #[test]
    fn streaming_compaction_holds_bounded_entries_regardless_of_corpus() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();
        let key = |i: usize| CompositeKey::new(realm.clone(), format!("key{i:06}").into_bytes());
        const N: usize = 4000;

        // Two disjoint, interleaved inputs (evens vs odds) so the merge must keep
        // alternating between cursors — both stay live across the whole merge.
        let mut a_entries: Vec<(CompositeKey, MemtableValue)> = (0..N)
            .step_by(2)
            .map(|i| (key(i), MemtableValue::Data(format!("a-{i}").into_bytes())))
            .collect();
        a_entries.sort_by(|x, y| x.0.cmp(&y.0));
        let (dek_a, enc_a) = test_encryption_context();
        let a_path = dir.path().join("a.sst");
        SstWriter::write_sst(&a_path, &a_entries, 1, &dek_a, &enc_a).expect("write a");

        let mut b_entries: Vec<(CompositeKey, MemtableValue)> = (1..N)
            .step_by(2)
            .map(|i| (key(i), MemtableValue::Data(format!("b-{i}").into_bytes())))
            .collect();
        b_entries.sort_by(|x, y| x.0.cmp(&y.0));
        let (dek_b, enc_b) = test_encryption_context();
        let b_path = dir.path().join("b.sst");
        SstWriter::write_sst(&b_path, &b_entries, 2, &dek_b, &enc_b).expect("write b");

        let reader_a = SstReader::open(&a_path, 1, &dek_a).expect("open a");
        let reader_b = SstReader::open(&b_path, 2, &dek_b).expect("open b");

        // Largest single block, and a sanity check that the corpus really spans
        // many blocks — else "one block per cursor" would vacuously be the whole
        // corpus and the bound below would prove nothing.
        let max_block_entries = |reader: &SstReader| -> usize {
            let blocks = data_blocks(reader);
            assert!(
                blocks.len() >= 8,
                "corpus must span many blocks (got {})",
                blocks.len()
            );
            blocks
                .iter()
                .map(|b| b.block.data().expect("data block").len())
                .max()
                .unwrap_or(0)
        };
        let block_cap = max_block_entries(&reader_a).max(max_block_entries(&reader_b));

        // Each cursor holds at most one decoded block at a time; the bound gives
        // one extra block of headroom over the `#inputs × block` worst case.
        let inputs = [&reader_a, &reader_b];
        let bound = block_cap * (inputs.len() + 1);

        let mut merge = KMergeIter::new(&inputs);
        let mut produced = 0usize;
        let mut peak = 0usize;
        while let Some(item) = merge.next() {
            item.expect("merge item");
            produced += 1;
            let resident: usize = merge.cursors.iter().map(|c| c.buf.len()).sum();
            peak = peak.max(resident);
            assert!(
                resident <= bound,
                "streaming merge held {resident} entries (> bound {bound} = \
                 {block_cap} block × {} inputs + 1); compaction is materialising \
                 more than O(#inputs × block) — the HEA-1922 streaming property \
                 is broken",
                inputs.len()
            );
        }

        assert_eq!(produced, N, "merge must yield every key exactly once");
        // The bound is a real constraint only if it sits far below the corpus:
        // an eager merge (peak ≈ N) must clearly violate it.
        assert!(
            peak < N / 4,
            "peak residency {peak} is not meaningfully below corpus {N}; the \
             bound would not distinguish streaming from an eager merge"
        );
    }

    #[test]
    fn may_contain_prunes_keys_outside_range() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("range.sst");
        let realm = RealmId::generate();

        // Entries span [key1, key3].
        let entries = vec![
            (
                CompositeKey::new(realm.clone(), b"key1".to_vec()),
                MemtableValue::Data(b"v1".to_vec()),
            ),
            (
                CompositeKey::new(realm.clone(), b"key3".to_vec()),
                MemtableValue::Data(b"v3".to_vec()),
            ),
        ];
        let (dek, enc) = test_encryption_context();
        SstWriter::write_sst(&sst_path, &entries, 1, &dek, &enc).expect("write");
        let reader = SstReader::open(&sst_path, 1, &dek).expect("open");

        // Below min and above max are pruned; in-range keys are not.
        assert!(!reader.may_contain(&realm, b"key0"), "below min pruned");
        assert!(!reader.may_contain(&realm, b"key9"), "above max pruned");
        assert!(reader.may_contain(&realm, b"key1"), "min boundary kept");
        assert!(reader.may_contain(&realm, b"key3"), "max boundary kept");
        assert!(reader.may_contain(&realm, b"key2"), "interior kept");

        // A different realm is entirely out of this SST's range.
        let other = RealmId::generate();
        assert!(!reader.may_contain(&other, b"key2"));

        // get() honours the prune: an out-of-range key returns None.
        assert!(reader.get(&realm, b"key9").expect("get").is_none());
    }

    #[test]
    fn empty_sst_never_contains_or_overlaps() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("empty_range.sst");
        let entries: Vec<(CompositeKey, MemtableValue)> = vec![];
        let (dek, enc) = test_encryption_context();
        SstWriter::write_sst(&sst_path, &entries, 1, &dek, &enc).expect("write");
        let reader = SstReader::open(&sst_path, 1, &dek).expect("open");

        let realm = RealmId::generate();
        assert!(!reader.may_contain(&realm, b"anything"));
        assert!(!reader.overlaps_range(&realm, b"a", b"z"));
    }

    #[test]
    fn overlaps_range_prunes_disjoint_scan_windows() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("scan_range.sst");
        let realm = RealmId::generate();

        // Entries span [key3, key6].
        let entries = vec![
            (
                CompositeKey::new(realm.clone(), b"key3".to_vec()),
                MemtableValue::Data(b"v3".to_vec()),
            ),
            (
                CompositeKey::new(realm.clone(), b"key6".to_vec()),
                MemtableValue::Data(b"v6".to_vec()),
            ),
        ];
        let (dek, enc) = test_encryption_context();
        SstWriter::write_sst(&sst_path, &entries, 1, &dek, &enc).expect("write");
        let reader = SstReader::open(&sst_path, 1, &dek).expect("open");

        // Window entirely below the range (end_key is exclusive at key3).
        assert!(!reader.overlaps_range(&realm, b"key0", b"key3"));
        // Window entirely above the range.
        assert!(!reader.overlaps_range(&realm, b"key7", b"key9"));
        // Overlapping windows.
        assert!(reader.overlaps_range(&realm, b"key0", b"key4"));
        assert!(reader.overlaps_range(&realm, b"key5", b"key9"));

        // Disjoint scan returns no rows; overlapping scan returns them.
        assert_eq!(
            reader
                .range_scan(&realm, b"key7", b"key9")
                .expect("range_scan"),
            [] as [(std::vec::Vec<u8>, crate::storage::memtable::MemtableValue); 0]
        );
        assert_eq!(
            reader
                .range_scan(&realm, b"key0", b"zzz")
                .expect("range_scan")
                .len(),
            2
        );
    }

    #[test]
    fn empty_memtable_flush_produces_valid_sst() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("empty.sst");

        let entries: Vec<(CompositeKey, MemtableValue)> = vec![];
        let (dek, enc_header) = test_encryption_context();
        let metadata =
            SstWriter::write_sst(&sst_path, &entries, 1, &dek, &enc_header).expect("write_sst");

        assert_eq!(metadata.entry_count, 0);

        let reader = SstReader::open(&sst_path, 1, &dek).expect("open");
        assert_eq!(reader.entry_count(), 0);
        assert_eq!(
            reader.iter_all().expect("iter_all"),
            [] as [(
                crate::storage::memtable::CompositeKey,
                crate::storage::memtable::MemtableValue
            ); 0]
        );
    }

    #[test]
    fn wrong_dek_fails_decryption() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("wrong_dek.sst");

        let realm = RealmId::generate();
        let entries = vec![(
            CompositeKey::new(realm, b"key1".to_vec()),
            MemtableValue::Data(b"val1".to_vec()),
        )];
        let (dek, enc_header) = test_encryption_context();
        SstWriter::write_sst(&sst_path, &entries, 1, &dek, &enc_header).expect("write_sst");

        // Try to open with a different DEK
        let wrong_dek = encryption::generate_dek().expect("wrong dek");
        let result = SstReader::open(&sst_path, 1, &wrong_dek);

        assert!(result.is_err());
    }

    #[test]
    fn wrong_sst_number_fails_decryption() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("wrong_num.sst");

        let realm = RealmId::generate();
        let entries = vec![(
            CompositeKey::new(realm, b"key1".to_vec()),
            MemtableValue::Data(b"val1".to_vec()),
        )];
        let (dek, enc_header) = test_encryption_context();
        SstWriter::write_sst(&sst_path, &entries, 42, &dek, &enc_header).expect("write_sst");

        // Try to open with wrong SST number (changes nonce + AAD)
        let result = SstReader::open(&sst_path, 99, &dek);

        assert!(result.is_err());
    }

    #[test]
    fn corruption_in_ciphertext_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("corrupt.sst");

        let realm = RealmId::generate();
        let entries = vec![(
            CompositeKey::new(realm.clone(), b"key1".to_vec()),
            MemtableValue::Data(b"val1".to_vec()),
        )];
        let (dek, enc_header) = test_encryption_context();
        SstWriter::write_sst(&sst_path, &entries, 1, &dek, &enc_header).expect("write_sst");

        // Corrupt a byte in the first data block (at TOTAL_HEADER_SIZE + 1).
        // V3 SSTs decrypt blocks lazily, so open() succeeds — the error surfaces
        // when the key is actually read via get().
        let mut raw = std::fs::read(&sst_path).expect("read");
        raw[TOTAL_HEADER_SIZE + 1] ^= 0xFF;
        std::fs::write(&sst_path, &raw).expect("write corrupt");

        // open() may or may not fail depending on version; get() must fail.
        let result = SstReader::open(&sst_path, 1, &dek);
        let is_err = result.is_err() || result.expect("open").get(&realm, b"key1").is_err();
        assert!(is_err, "corrupt block must surface an error on read");
    }

    #[test]
    fn invalid_magic_detected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("bad_magic.sst");

        let realm = RealmId::generate();
        let entries = vec![(
            CompositeKey::new(realm, b"k".to_vec()),
            MemtableValue::Data(b"v".to_vec()),
        )];
        let (dek, enc_header) = test_encryption_context();
        SstWriter::write_sst(&sst_path, &entries, 1, &dek, &enc_header).expect("write_sst");

        let mut raw = std::fs::read(&sst_path).expect("read");
        raw[0..4].copy_from_slice(b"BAAD");
        std::fs::write(&sst_path, &raw).expect("write");

        let result = SstReader::open(&sst_path, 1, &dek);
        assert!(matches!(result, Err(StorageError::InvalidSstFormat { .. })));
    }

    #[test]
    fn realm_isolation_in_reader() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("multi_realm.sst");

        let realm_a = RealmId::generate();
        let realm_b = RealmId::generate();

        let mt = Memtable::new(MemtableConfig::default());
        mt.put(&realm_a, b"a-key1", b"a-val1").expect("put");
        mt.put(&realm_a, b"a-key2", b"a-val2").expect("put");
        mt.put(&realm_b, b"b-key1", b"b-val1").expect("put");

        let entries = mt.iter_all();
        let (dek, enc_header) = test_encryption_context();
        SstWriter::write_sst(&sst_path, &entries, 1, &dek, &enc_header).expect("write_sst");

        let reader = SstReader::open(&sst_path, 1, &dek).expect("open");

        let a_entries = reader.iter_realm(&realm_a).expect("iter_realm");
        assert_eq!(a_entries.len(), 2);
        for (k, _) in &a_entries {
            assert!(k.starts_with(b"a-key"), "unexpected key: {k:?}");
        }

        let b_entries = reader.iter_realm(&realm_b).expect("iter_realm");
        assert_eq!(b_entries.len(), 1);
        assert_eq!(b_entries[0].0, b"b-key1".to_vec());

        let ghost = RealmId::generate();
        assert_eq!(
            reader.iter_realm(&ghost).expect("iter_realm"),
            [] as [(std::vec::Vec<u8>, crate::storage::memtable::MemtableValue); 0]
        );
    }

    #[test]
    fn compaction_all_tombstones_produces_empty_sst() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();

        let sst_path = dir.path().join("tombstones.sst");
        let entries = vec![
            (
                CompositeKey::new(realm.clone(), b"k1".to_vec()),
                MemtableValue::Tombstone,
            ),
            (
                CompositeKey::new(realm, b"k2".to_vec()),
                MemtableValue::Tombstone,
            ),
        ];
        let (dek, enc_header) = test_encryption_context();
        SstWriter::write_sst(&sst_path, &entries, 1, &dek, &enc_header).expect("write");

        let reader = SstReader::open(&sst_path, 1, &dek).expect("open");
        let output_path = dir.path().join("compacted.sst");
        let (dek_out, enc_out) = test_encryption_context();
        let metadata = compact(&[&reader], &output_path, 2, &dek_out, &enc_out).expect("compact");

        assert_eq!(metadata.entry_count, 0);
        let compacted = SstReader::open(&output_path, 2, &dek_out).expect("open compacted");
        assert_eq!(
            compacted.iter_all().expect("iter_all"),
            [] as [(
                crate::storage::memtable::CompositeKey,
                crate::storage::memtable::MemtableValue
            ); 0]
        );
    }

    // === Bloom filter tests (TDD for HEA-1626 Phase 2) ===

    /// Unit: Bloom filter unit — building and querying without SST I/O.
    #[test]
    fn bloom_filter_unit_insert_and_query() {
        let realm = RealmId::generate();
        let entries: Vec<(CompositeKey, MemtableValue)> = (0u32..50)
            .map(|i| {
                let key = format!("k{i:04}").into_bytes();
                (
                    CompositeKey::new(realm.clone(), key),
                    MemtableValue::Data(vec![i as u8]),
                )
            })
            .collect();

        let filter = BloomFilter::build(&entries);
        assert!(
            !filter.bits.is_empty(),
            "non-empty entry set must produce a filter"
        );

        // Critical: every inserted key must be found (no false negatives).
        for (key, _) in &entries {
            assert!(
                filter.might_contain(key.realm_id(), key.key()),
                "false negative for key {:?} — silent data loss",
                key.key()
            );
        }
    }

    /// Unit: realm identity is folded into the Bloom hash, so identical key
    /// bytes in two different realms probe different bit positions.
    ///
    /// The filter is probabilistic (a false positive on realm B's key is
    /// permitted), so the realm-isolation contract cannot be asserted through
    /// `might_contain` without flakiness. Instead this pins the *deterministic*
    /// seam it rests on: `bloom_hashes(realm, key)` must differ between realms
    /// for the same key. If realm were dropped from the hash both pairs would be
    /// byte-identical and this assertion would fail — the property is therefore
    /// load-bearing, not decorative. (Deterministic reject coverage through the
    /// real reader path lives in `sst_get_bloom_rejects_wrong_realm_without_false_negative`.)
    #[test]
    fn bloom_filter_rejects_different_realm_same_key_bytes() {
        let realm_a = RealmId::generate();
        let realm_b = RealmId::generate();

        let hashes_a = bloom_hashes(&realm_a, b"shared-key");
        let hashes_b = bloom_hashes(&realm_b, b"shared-key");
        assert_ne!(
            hashes_a, hashes_b,
            "realm must participate in the bloom hash — identical key bytes in \
             different realms must not hash to the same probe positions"
        );

        // Sanity: the realm the filter was built for is still present.
        let filter = BloomFilter::build(&[(
            CompositeKey::new(realm_a.clone(), b"shared-key".to_vec()),
            MemtableValue::Data(b"v".to_vec()),
        )]);
        assert!(
            filter.might_contain(&realm_a, b"shared-key"),
            "the inserted realm/key must never be a false negative"
        );
    }

    /// Unit: Bloom filter built from an empty entry set is empty and always passes.
    #[test]
    fn bloom_filter_empty_entries_is_empty_and_permissive() {
        let filter = BloomFilter::build(&[]);
        assert_eq!(filter.bits, [] as [u8; 0]);
        let realm = RealmId::generate();
        // Empty filter must never cause false negatives if entries were somehow
        // absent — it returns true for everything (permissive guard).
        assert!(filter.might_contain(&realm, b"any-key"));
    }

    /// Unit: V2 SST file carries the bloom filter through write → read roundtrip.
    /// This is the crash-safety test: the SST file is fsynced before registration,
    /// so a kill-9 either leaves the complete file (with bloom filter) or an
    /// incomplete file that is not registered and thus ignored on restart.
    #[test]
    fn bloom_filter_survives_sst_write_and_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("bloom_reopen.sst");
        let realm = RealmId::generate();

        let entries: Vec<(CompositeKey, MemtableValue)> = (0u32..200)
            .map(|i| {
                let key = format!("user:{i:08}").into_bytes();
                (
                    CompositeKey::new(realm.clone(), key),
                    MemtableValue::Data(vec![42u8; 16]),
                )
            })
            .collect();

        let (dek, enc_header) = test_encryption_context();
        SstWriter::write_sst(&sst_path, &entries, 1, &dek, &enc_header).expect("write");

        // Simulate process restart: drop reader, reopen from disk.
        let reader = SstReader::open(&sst_path, 1, &dek).expect("reopen");

        assert!(
            !partitions(&reader).is_empty()
                && partitions(&reader).iter().all(|p| p.filter.is_some()),
            "every partition of a new SST must have its Bloom filter after reopen"
        );

        // Critical property: no false negatives after reopen.
        for (key, _) in &entries {
            assert!(
                reader
                    .get(key.realm_id(), key.key())
                    .expect("get")
                    .is_some(),
                "bloom filter false negative after reopen for key {:?}",
                key.key()
            );
        }
        // Absent key must return None.
        assert!(reader
            .get(&realm, b"totally-absent")
            .expect("get")
            .is_none());
    }

    /// Unit: SST get() returns None via bloom fast-reject before binary search
    /// when a clearly absent key in a different realm is queried.
    #[test]
    fn sst_get_bloom_rejects_wrong_realm_without_false_negative() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("reject.sst");
        let realm_a = RealmId::generate();
        let realm_b = RealmId::generate();

        let entries = vec![(
            CompositeKey::new(realm_a.clone(), b"key1".to_vec()),
            MemtableValue::Data(b"value".to_vec()),
        )];
        let (dek, enc_header) = test_encryption_context();
        SstWriter::write_sst(&sst_path, &entries, 1, &dek, &enc_header).expect("write");

        let reader = SstReader::open(&sst_path, 1, &dek).expect("open");

        // realm_a's key is present
        assert!(reader.get(&realm_a, b"key1").expect("get").is_some());
        // realm_b does not own realm_a's keys — must return None
        assert!(reader.get(&realm_b, b"key1").expect("get").is_none());
    }

    use proptest::prelude::*;

    proptest! {
        /// Property: for every `(realm_id, key)` pair inserted into a Bloom filter,
        /// `might_contain` must return `true`. A false negative is structurally
        /// impossible (we only set bits), but this property test guards against
        /// implementation bugs (off-by-one in bit indexing, wrong hash, etc.).
        ///
        /// This is the primary regression guard for HEA-1626 Phase 2 — a false
        /// negative from the SST bloom filter would cause silent data loss.
        #[test]
        fn proptest_bloom_no_false_negatives(
            keys in prop::collection::vec(
                prop::collection::vec(any::<u8>(), 1..64usize),
                1..200usize,
            )
        ) {
            let realm = RealmId::generate();
            let entries: Vec<(CompositeKey, MemtableValue)> = keys
                .into_iter()
                .map(|key| (CompositeKey::new(realm.clone(), key), MemtableValue::Data(vec![0u8])))
                .collect();

            let filter = BloomFilter::build(&entries);
            for (ck, _) in &entries {
                prop_assert!(
                    filter.might_contain(ck.realm_id(), ck.key()),
                    "false negative for key {:?}",
                    ck.key()
                );
            }
        }
    }

    #[test]
    fn compaction_single_sst_input_preserves_live_entries() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();

        let sst_path = dir.path().join("single.sst");
        let entries = vec![
            (
                CompositeKey::new(realm.clone(), b"k1".to_vec()),
                MemtableValue::Data(b"v1".to_vec()),
            ),
            (
                CompositeKey::new(realm.clone(), b"k2".to_vec()),
                MemtableValue::Tombstone,
            ),
            (
                CompositeKey::new(realm, b"k3".to_vec()),
                MemtableValue::Data(b"v3".to_vec()),
            ),
        ];
        let (dek, enc_header) = test_encryption_context();
        SstWriter::write_sst(&sst_path, &entries, 1, &dek, &enc_header).expect("write");

        let reader = SstReader::open(&sst_path, 1, &dek).expect("open");
        let output_path = dir.path().join("compacted.sst");
        let (dek_out, enc_out) = test_encryption_context();
        let metadata = compact(&[&reader], &output_path, 2, &dek_out, &enc_out).expect("compact");

        assert_eq!(metadata.entry_count, 2);
        let compacted = SstReader::open(&output_path, 2, &dek_out).expect("open compacted");
        let all = compacted.iter_all().expect("iter_all");
        assert_eq!(all[0].0.key(), b"k1");
        assert_eq!(all[1].0.key(), b"k3");
    }

    #[test]
    fn point_lookup_and_range_scan_over_sst() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("lookup.sst");
        let realm = RealmId::generate();

        let mt = Memtable::new(MemtableConfig::default());
        mt.put(&realm, b"apple", b"v-apple").expect("put");
        mt.put(&realm, b"banana", b"v-banana").expect("put");
        mt.put(&realm, b"cherry", b"v-cherry").expect("put");
        mt.put(&realm, b"date", b"v-date").expect("put");
        mt.put(&realm, b"elderberry", b"v-elder").expect("put");
        mt.delete(&realm, b"fig").expect("delete");

        let entries = mt.iter_all();
        let (dek, enc_header) = test_encryption_context();
        SstWriter::write_sst(&sst_path, &entries, 1, &dek, &enc_header).expect("write");

        let reader = SstReader::open(&sst_path, 1, &dek).expect("open");

        assert_eq!(
            reader.get(&realm, b"banana").expect("get"),
            Some(MemtableValue::Data(b"v-banana".to_vec()))
        );
        assert_eq!(reader.get(&realm, b"grape").expect("get"), None);
        assert_eq!(
            reader.get(&realm, b"fig").expect("get"),
            Some(MemtableValue::Tombstone)
        );

        let range = reader
            .range_scan(&realm, b"banana", b"date")
            .expect("range");
        assert_eq!(range.len(), 2);
        assert_eq!(range[0].0, b"banana".to_vec());
        assert_eq!(range[1].0, b"cherry".to_vec());

        let ghost = RealmId::generate();
        assert_eq!(
            reader.range_scan(&ghost, b"a", b"z").expect("range"),
            [] as [(std::vec::Vec<u8>, crate::storage::memtable::MemtableValue); 0]
        );
        assert_eq!(reader.get(&ghost, b"apple").expect("get"), None);

        let realm_entries = reader.iter_realm(&realm).expect("iter_realm");
        assert_eq!(realm_entries.len(), 6);
    }

    /// Counts every byte handed back by the filesystem, per call site.
    struct ByteCountingFs {
        inner: crate::storage::fs::RealFs,
        whole_file_bytes: std::sync::atomic::AtomicUsize,
        prefix_bytes: std::sync::atomic::AtomicUsize,
    }

    impl ByteCountingFs {
        fn new() -> Self {
            Self {
                inner: crate::storage::fs::RealFs,
                whole_file_bytes: std::sync::atomic::AtomicUsize::new(0),
                prefix_bytes: std::sync::atomic::AtomicUsize::new(0),
            }
        }
    }

    impl Fs for ByteCountingFs {
        fn open_append(&self, path: &Path) -> std::io::Result<Box<dyn crate::storage::fs::FsFile>> {
            self.inner.open_append(path)
        }
        fn create(&self, path: &Path) -> std::io::Result<Box<dyn crate::storage::fs::FsFile>> {
            self.inner.create(path)
        }
        fn open_read(&self, path: &Path) -> std::io::Result<Box<dyn crate::storage::fs::FsFile>> {
            self.inner.open_read(path)
        }
        fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
            let data = self.inner.read(path)?;
            self.whole_file_bytes
                .fetch_add(data.len(), std::sync::atomic::Ordering::Relaxed);
            Ok(data)
        }
        fn read_prefix(&self, path: &Path, len: usize) -> std::io::Result<Vec<u8>> {
            let data = self.inner.read_prefix(path, len)?;
            self.prefix_bytes
                .fetch_add(data.len(), std::sync::atomic::Ordering::Relaxed);
            Ok(data)
        }
        fn write(&self, path: &Path, data: &[u8]) -> std::io::Result<()> {
            self.inner.write(path, data)
        }
        fn create_dir_all(&self, path: &Path) -> std::io::Result<()> {
            self.inner.create_dir_all(path)
        }
        fn read_dir(&self, path: &Path) -> std::io::Result<Vec<std::path::PathBuf>> {
            self.inner.read_dir(path)
        }
        fn remove_file(&self, path: &Path) -> std::io::Result<()> {
            self.inner.remove_file(path)
        }
        fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
            self.inner.rename(from, to)
        }
        fn sync_dir(&self, dir: &Path) -> std::io::Result<()> {
            self.inner.sync_dir(dir)
        }
    }

    #[test]
    fn read_encryption_header_reads_only_the_header() {
        // §4.21#5: `reload_sst_readers` calls this once per live SST on EVERY
        // memtable flush.  It read the whole file to take 60 bytes off the
        // front, so one flush re-read every byte of every live SST.
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("big.sst");

        let realm = RealmId::generate();
        let value = vec![b'v'; 4096];
        let entries: Vec<_> = (0..256)
            .map(|i| {
                (
                    CompositeKey::new(realm.clone(), format!("key{i:04}").into_bytes()),
                    MemtableValue::Data(value.clone()),
                )
            })
            .collect();
        let (dek, enc_header) = test_encryption_context();
        SstWriter::write_sst(&sst_path, &entries, 1, &dek, &enc_header).expect("write_sst");

        let file_len = std::fs::metadata(&sst_path).expect("metadata").len() as usize;
        assert!(
            file_len > 512 * 1024,
            "the fixture must be large enough for the difference to matter, got {file_len} bytes"
        );

        let fs = ByteCountingFs::new();
        let (_kek_id, _hdr) = read_encryption_header(&sst_path, &fs).expect("read header");

        let whole = fs
            .whole_file_bytes
            .load(std::sync::atomic::Ordering::Relaxed);
        let prefix = fs.prefix_bytes.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            whole, 0,
            "reading a {TOTAL_HEADER_SIZE}-byte header must not read the whole file"
        );
        assert!(
            prefix <= 4096,
            "header read took {prefix} bytes; it needs {TOTAL_HEADER_SIZE}"
        );
    }

    #[test]
    fn read_encryption_header_extracts_kek_id() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("enc_header.sst");

        let realm = RealmId::generate();
        let entries = vec![(
            CompositeKey::new(realm, b"key1".to_vec()),
            MemtableValue::Data(b"val1".to_vec()),
        )];
        let (dek, enc_header) = test_encryption_context();
        SstWriter::write_sst(&sst_path, &entries, 1, &dek, &enc_header).expect("write_sst");

        let (kek_id, _) = read_encryption_header(&sst_path, &RealFs).expect("read header");
        assert_eq!(kek_id, enc_header.kek_id);
    }

    // === V3 block-format tests (HEA-1914) ===

    /// Builds `n` fixed-size entries (keys `k000000..`, values 80 bytes) so the
    /// v3 writer packs several equal-length blocks — the shape needed to test
    /// block-swap position binding cleanly.
    fn fixed_entries(realm: &RealmId, n: u32) -> Vec<(CompositeKey, MemtableValue)> {
        (0..n)
            .map(|i| {
                (
                    CompositeKey::new(realm.clone(), format!("k{i:06}").into_bytes()),
                    MemtableValue::Data(vec![(i % 251) as u8; 80]),
                )
            })
            .collect()
    }

    /// Decrypts and parses a v3 file's footer index from its raw bytes.
    fn read_v3_index(raw: &[u8], sst_number: u64, dek: &DataEncryptionKey) -> Vec<BlockIndexEntry> {
        let len = raw.len();
        let trailer = &raw[len - TRAILER_SIZE..];
        let footer_offset = u64::from_le_bytes(trailer[0..8].try_into().expect("off")) as usize;
        let footer_len = u32::from_le_bytes(trailer[8..12].try_into().expect("len")) as usize;
        let footer_ct = &raw[footer_offset..footer_offset + footer_len];
        let nonce = block_nonce(sst_number, SST_FOOTER_BLOCK_INDEX);
        let footer_plain =
            encryption::decrypt_section(footer_ct, dek, &nonce, &nonce).expect("decrypt footer");
        let (index, _, _) = SstReader::parse_v3_footer(&footer_plain).expect("parse footer");
        index
    }

    #[test]
    fn v3_multi_block_round_trip_all_keys_and_tombstones() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("multi.sst");
        let realm = RealmId::generate();

        let mut entries = fixed_entries(&realm, 400);
        // Sprinkle in a tombstone and keep the vec sorted by key.
        entries.push((
            CompositeKey::new(realm.clone(), b"k999999".to_vec()),
            MemtableValue::Tombstone,
        ));
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        let (dek, enc) = test_encryption_context();
        write_v3_for_test(&sst_path, &entries, 1, &dek, &enc);

        // Multiple blocks were produced.
        let raw = std::fs::read(&sst_path).expect("read");
        assert_eq!(&raw[0..4], b"HSS3");
        let index = read_v3_index(&raw, 1, &dek);
        assert!(
            index.len() >= 3,
            "expected several blocks, got {}",
            index.len()
        );

        let reader = SstReader::open(&sst_path, 1, &dek).expect("open");
        for (k, v) in &entries {
            assert_eq!(
                reader.get(k.realm_id(), k.key()).expect("get").as_ref(),
                Some(v),
                "key {:?} not read back correctly",
                k.key()
            );
        }
        // Tombstone survives as a tombstone (shadowing), not dropped.
        assert_eq!(
            reader.get(&realm, b"k999999").expect("get"),
            Some(MemtableValue::Tombstone)
        );
        // iter_all across all blocks returns every entry.
        assert_eq!(reader.iter_all().expect("iter_all").len(), entries.len());
    }

    #[test]
    fn v3_block_tamper_fails_aead_no_panic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("tamper.sst");
        let realm = RealmId::generate();
        let entries = fixed_entries(&realm, 200);
        let (dek, enc) = test_encryption_context();
        write_v3_for_test(&sst_path, &entries, 1, &dek, &enc);

        let mut raw = std::fs::read(&sst_path).expect("read");
        let index = read_v3_index(&raw, 1, &dek);
        // Flip a byte inside block 0's ciphertext.
        let off0 = index[0].file_offset as usize;
        raw[off0 + 3] ^= 0xFF;
        std::fs::write(&sst_path, &raw).expect("rewrite");

        // Open still succeeds (footer intact); the corrupt block surfaces as an
        // error on read, never a panic or a wrong/absent value.
        let reader = SstReader::open(&sst_path, 1, &dek).expect("open");
        let first_key = entries[0].0.key().to_vec();
        let result = reader.get(&realm, &first_key);
        assert!(
            matches!(result, Err(StorageError::Crypto { .. })),
            "tampered block must surface a crypto error, got {result:?}"
        );
    }

    #[test]
    fn v3_block_swap_forgery_fails_position_binding() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("swap.sst");
        let realm = RealmId::generate();
        let entries = fixed_entries(&realm, 400);
        let (dek, enc) = test_encryption_context();
        write_v3_for_test(&sst_path, &entries, 1, &dek, &enc);

        let mut raw = std::fs::read(&sst_path).expect("read");
        let index = read_v3_index(&raw, 1, &dek);
        assert!(index.len() >= 3);
        // Blocks 0 and 1 are full and equal length (fixed-size entries).
        assert_eq!(
            index[0].ciphertext_len, index[1].ciphertext_len,
            "test needs equal-length blocks for a clean splice"
        );
        let (off0, len0) = (
            index[0].file_offset as usize,
            index[0].ciphertext_len as usize,
        );
        let off1 = index[1].file_offset as usize;
        // Splice a valid ciphertext (block 0) over block 1's slot.
        let block0 = raw[off0..off0 + len0].to_vec();
        raw[off1..off1 + len0].copy_from_slice(&block0);
        std::fs::write(&sst_path, &raw).expect("rewrite");

        let reader = SstReader::open(&sst_path, 1, &dek).expect("open");
        // A key that lives in block 1 must fail: the spliced ciphertext was
        // sealed under block 0's nonce/AAD, so decrypting at position 1 fails.
        let block1_key = index[1].first_key.key().to_vec();
        let result = reader.get(&realm, &block1_key);
        assert!(
            matches!(result, Err(StorageError::Crypto { .. })),
            "block-swap must fail position binding, got {result:?}"
        );
    }

    /// Writes `entries` with the v3 writer or the v4 writer.
    fn write_either(
        v3: bool,
        path: &Path,
        entries: &[(CompositeKey, MemtableValue)],
        sst_number: u64,
        dek: &DataEncryptionKey,
        enc: &EncryptionHeader,
    ) {
        if v3 {
            write_v3_for_test(path, entries, sst_number, dek, enc);
        } else {
            SstWriter::write_sst(path, entries, sst_number, dek, enc).expect("write v4");
        }
    }

    /// The stored handle of a v4 piece.
    fn stored(piece: &Piece) -> BlockHandle {
        match piece {
            Piece::Stored(handle) => *handle,
            Piece::Pinned(_) => panic!("expected a v4 piece stored in the file"),
        }
    }

    /// Enough fixed-size rows for three partitions or more.
    const PARTITIONED_ROWS: u32 = 40_000;

    #[test]
    fn v4_round_trip_across_partitions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("partitioned.sst");
        let realm = RealmId::generate();
        let mut entries = fixed_entries(&realm, PARTITIONED_ROWS);
        for (i, (_, value)) in entries.iter_mut().enumerate() {
            if i % 11 == 0 {
                *value = MemtableValue::Tombstone;
            }
        }
        let (dek, enc) = test_encryption_context();
        SstWriter::write_sst(&sst_path, &entries, 1, &dek, &enc).expect("write");
        let reader = SstReader::open(&sst_path, 1, &dek).expect("open");
        let parts = partitions(&reader);
        assert!(parts.len() >= 3, "precondition: {} partitions", parts.len());

        // Every partition boundary, and the rows on both sides of it.
        let boundaries: Vec<usize> = parts
            .iter()
            .map(|p| {
                entries
                    .iter()
                    .position(|(k, _)| k == &p.first_key)
                    .expect("a partition starts at a stored key")
            })
            .collect();
        assert_eq!(boundaries[0], 0);
        for &b in &boundaries[1..] {
            for (k, v) in &entries[b - 1..=b] {
                assert_eq!(reader.get(&realm, k.key()).expect("get").as_ref(), Some(v));
            }
        }
        for (k, v) in entries.iter().step_by(7) {
            assert_eq!(reader.get(&realm, k.key()).expect("get").as_ref(), Some(v));
        }
        // Absent keys: before the first row, between two rows, after the last.
        for absent in [&b"a"[..], b"k000100x", b"z"] {
            assert_eq!(reader.get(&realm, absent).expect("get"), None, "{absent:?}");
        }
        assert_eq!(reader.iter_all().expect("iter_all"), entries);

        // A scan and a key walk across the second partition boundary.
        let b = boundaries[1];
        let (start, end) = (entries[b - 50].0.key(), entries[b + 50].0.key());
        let scanned = reader.range_scan(&realm, start, end).expect("scan");
        let expected: Vec<(Vec<u8>, MemtableValue)> = entries[b - 50..b + 50]
            .iter()
            .map(|(k, v)| (k.key().to_vec(), v.clone()))
            .collect();
        assert_eq!(scanned, expected);
        let mut cursor = reader.key_cursor(&realm, start, end).expect("cursor");
        let mut walked = Vec::new();
        while let Some((key, alive)) = cursor.current() {
            walked.push((key.to_vec(), alive));
            cursor.advance().expect("advance");
        }
        assert_eq!(
            walked,
            reader
                .range_scan_keys(&realm, start, end)
                .expect("scan keys")
        );
    }

    #[test]
    fn v4_index_and_filter_block_tamper_fails_aead_no_panic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("tamper_v4.sst");
        let realm = RealmId::generate();
        let entries = fixed_entries(&realm, PARTITIONED_ROWS);
        let (dek, enc) = test_encryption_context();
        SstWriter::write_sst(&sst_path, &entries, 1, &dek, &enc).expect("write");
        let (index0, filter1, key0, key1) = {
            let reader = SstReader::open(&sst_path, 1, &dek).expect("open");
            let parts = partitions(&reader);
            (
                stored(&parts[0].index),
                stored(parts[1].filter.as_ref().expect("filter")),
                parts[0].first_key.key().to_vec(),
                parts[1].first_key.key().to_vec(),
            )
        };

        let mut raw = std::fs::read(&sst_path).expect("read");
        raw[index0.file_offset as usize + 3] ^= 0xFF;
        raw[filter1.file_offset as usize + 3] ^= 0xFF;
        std::fs::write(&sst_path, &raw).expect("rewrite");

        // The footer is intact, so the file opens; each tampered piece
        // surfaces as an error when a lookup reads it.
        let reader = SstReader::open(&sst_path, 1, &dek).expect("open");
        for key in [key0, key1] {
            let result = reader.get(&realm, &key);
            assert!(
                matches!(result, Err(StorageError::Crypto { .. })),
                "a tampered piece must surface a crypto error, got {result:?}"
            );
        }
    }

    #[test]
    fn v4_filter_block_swap_forgery_fails_position_binding() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("swap_v4.sst");
        let realm = RealmId::generate();
        let entries = fixed_entries(&realm, PARTITIONED_ROWS);
        let (dek, enc) = test_encryption_context();
        SstWriter::write_sst(&sst_path, &entries, 1, &dek, &enc).expect("write");
        let (filter0, filter1, key1) = {
            let reader = SstReader::open(&sst_path, 1, &dek).expect("open");
            let parts = partitions(&reader);
            (
                stored(parts[0].filter.as_ref().expect("filter")),
                stored(parts[1].filter.as_ref().expect("filter")),
                parts[1].first_key.key().to_vec(),
            )
        };
        assert_eq!(
            filter0.ciphertext_len, filter1.ciphertext_len,
            "test needs equal-length filter blocks for a clean splice"
        );

        // Splice partition 0's valid filter ciphertext over partition 1's.
        let mut raw = std::fs::read(&sst_path).expect("read");
        let (off0, off1) = (filter0.file_offset as usize, filter1.file_offset as usize);
        let len = filter0.ciphertext_len as usize;
        let block0 = raw[off0..off0 + len].to_vec();
        raw[off1..off1 + len].copy_from_slice(&block0);
        std::fs::write(&sst_path, &raw).expect("rewrite");

        let reader = SstReader::open(&sst_path, 1, &dek).expect("open");
        let result = reader.get(&realm, &key1);
        assert!(
            matches!(result, Err(StorageError::Crypto { .. })),
            "a filter block moved to another partition must fail, got {result:?}"
        );
    }

    #[test]
    fn truncated_v3_and_v4_files_are_clean_errors() {
        let realm = RealmId::generate();
        let entries = fixed_entries(&realm, 200);
        for v3 in [true, false] {
            let dir = tempfile::tempdir().expect("tempdir");
            let (dek, enc) = test_encryption_context();
            // The trailer and part of the footer gone; and a cut inside the
            // blocks, where the trailer reads garbage.
            for cut in [TRAILER_SIZE + 8, 0] {
                let sst_path = dir.path().join(format!("trunc_{v3}_{cut}.sst"));
                write_either(v3, &sst_path, &entries, 1, &dek, &enc);
                let mut raw = std::fs::read(&sst_path).expect("read");
                let keep = if cut == 0 {
                    TOTAL_HEADER_SIZE + 100
                } else {
                    raw.len() - cut
                };
                raw.truncate(keep);
                std::fs::write(&sst_path, &raw).expect("rewrite");
                let result = SstReader::open(&sst_path, 1, &dek);
                assert!(
                    matches!(
                        result,
                        Err(StorageError::InvalidSstFormat { .. }
                            | StorageError::ChecksumMismatch { .. })
                    ),
                    "v3={v3}, cut={cut}: a truncated file must be a clean error, got {result:?}"
                );
            }
        }
    }

    /// Hearth must read the SST format of the previous minor version
    /// (ARCHITECTURE §6.4). A v3 file stays readable, and a compaction
    /// rewrites it as v4.
    #[test]
    fn v3_files_still_read_and_compact_into_v4() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();
        let mut entries = fixed_entries(&realm, 2_000);
        entries[10].1 = MemtableValue::Tombstone;
        let (dek, enc) = test_encryption_context();
        let v3_path = dir.path().join("old.sst");
        write_v3_for_test(&v3_path, &entries, 1, &dek, &enc);
        assert_eq!(&std::fs::read(&v3_path).expect("read")[0..4], b"HSS3");
        let v3 = SstReader::open(&v3_path, 1, &dek).expect("open v3");
        for (k, v) in &entries {
            assert_eq!(v3.get(&realm, k.key()).expect("get").as_ref(), Some(v));
        }

        let out_path = dir.path().join("new.sst");
        compact(&[&v3], &out_path, 2, &dek, &enc).expect("compact");
        assert_eq!(&std::fs::read(&out_path).expect("read")[0..4], b"HSS4");
        let v4 = SstReader::open(&out_path, 2, &dek).expect("open v4");
        let live: Vec<_> = entries
            .iter()
            .filter(|(_, v)| matches!(v, MemtableValue::Data(_)))
            .cloned()
            .collect();
        assert_eq!(
            v4.iter_all().expect("iter_all"),
            live,
            "a full merge drops tombstones"
        );
    }

    /// Manually writes a legacy V1 (`HSST`, no bloom) file to prove the eager
    /// back-compat path still reads pre-block SSTs.
    fn write_v1_manual(
        path: &Path,
        entries: &[(CompositeKey, MemtableValue)],
        sst_number: u64,
        dek: &DataEncryptionKey,
        enc_header: &EncryptionHeader,
    ) {
        let mut plaintext = Vec::new();
        for (k, v) in entries {
            SstWriter::serialize_entry(&mut plaintext, k, v);
        }
        let crc = crc32fast::hash(&plaintext);
        let nonce = counter_nonce(sst_number);
        let aad = sst_number.to_le_bytes();
        let ct = encryption::encrypt_section(&plaintext, dek, &nonce, &aad).expect("encrypt");
        let mut out = Vec::new();
        out.extend_from_slice(SST_MAGIC);
        #[allow(clippy::cast_possible_truncation)]
        out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&enc_header.to_bytes());
        out.extend_from_slice(&ct);
        std::fs::write(path, &out).expect("write v1");
    }

    /// Manually writes a legacy V2 (`HSS2`, empty bloom) file.
    fn write_v2_manual(
        path: &Path,
        entries: &[(CompositeKey, MemtableValue)],
        sst_number: u64,
        dek: &DataEncryptionKey,
        enc_header: &EncryptionHeader,
    ) {
        let mut payload = Vec::new();
        for (k, v) in entries {
            SstWriter::serialize_entry(&mut payload, k, v);
        }
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&0u32.to_le_bytes()); // bloom_byte_count = 0
        plaintext.extend_from_slice(&payload);
        let crc = crc32fast::hash(&plaintext);
        let nonce = counter_nonce(sst_number);
        let aad = sst_number.to_le_bytes();
        let ct = encryption::encrypt_section(&plaintext, dek, &nonce, &aad).expect("encrypt");
        let mut out = Vec::new();
        out.extend_from_slice(SST_MAGIC_V2);
        #[allow(clippy::cast_possible_truncation)]
        out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&enc_header.to_bytes());
        out.extend_from_slice(&ct);
        std::fs::write(path, &out).expect("write v2");
    }

    /// Security regression (HEA-1917, CTO review): the same unauthenticated
    /// `entry_count` that drove the oversized `Vec::with_capacity` on the V3
    /// path also reaches the **legacy V1/V2** read path via `parse_entries`,
    /// where the count-mismatch check only fires *after* the decode loop — i.e.
    /// after the reservation. Tampering the header count on an otherwise-valid
    /// V2 file must surface as a clean `InvalidSstFormat`, not a process abort.
    ///
    /// Under nextest (one process per test) the pre-fix code fails this test by
    /// aborting on `handle_alloc_error`; post-fix it returns `Err`.
    #[test]
    fn v2_tampered_entry_count_does_not_oversize_allocation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("bad_count_v2.sst");
        let realm = RealmId::generate();
        let entries = fixed_entries(&realm, 200);
        let (dek, enc) = test_encryption_context();
        write_v2_manual(&sst_path, &entries, 7, &dek, &enc);

        // Bytes 4..8 are covered by neither the section AEAD (whose AAD is only
        // `sst_number`) nor the CRC (which is over the decrypted plaintext), so
        // the body still authenticates and the corruption is invisible.
        let mut raw = std::fs::read(&sst_path).expect("read");
        raw[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        std::fs::write(&sst_path, &raw).expect("rewrite");

        let err = SstReader::open(&sst_path, 7, &dek).expect_err("tampered count must be rejected");
        assert!(
            matches!(err, StorageError::InvalidSstFormat { ref reason }
                if reason.contains("entry count mismatch")),
            "expected a clean count-mismatch error, got: {err:?}"
        );
    }

    /// Audit §4.9#7: a reversed scan window (`start > end`) indexed a legacy
    /// eager body as `entries[lo..hi]` with `lo > hi`, panicking inside
    /// `range_scan_inner`. Under the release profile's `panic=abort` that
    /// killed the whole multi-tenant process; one `GET /admin/audit` did it in
    /// 6 of 6 runs. Both projections must refuse it cleanly instead.
    ///
    /// Under nextest (one process per test) the pre-fix code fails this test
    /// by panicking; post-fix it returns `Err`.
    #[test]
    fn reversed_scan_window_on_a_legacy_eager_sst_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("reversed_v2.sst");
        let realm = RealmId::generate();
        let entries = fixed_entries(&realm, 200);
        let (dek, enc) = test_encryption_context();
        write_v2_manual(&sst_path, &entries, 7, &dek, &enc);
        let reader = SstReader::open(&sst_path, 7, &dek).expect("open");

        // Both bounds sit inside the SST's key range, so the O(1) range prune
        // does not filter this window out.
        let err = reader
            .range_scan(&realm, b"k000150", b"k000050")
            .expect_err("reversed window must be refused");
        assert!(
            matches!(err, StorageError::InvalidRange),
            "expected InvalidRange, got: {err:?}"
        );
        let err = reader
            .range_scan_keys(&realm, b"k000150", b"k000050")
            .expect_err("reversed window must be refused");
        assert!(
            matches!(err, StorageError::InvalidRange),
            "expected InvalidRange, got: {err:?}"
        );

        // An empty-but-ordered window is not reversed, and stays legal.
        assert_eq!(
            reader
                .range_scan(&realm, b"k000050", b"k000050")
                .expect("equal bounds are legal"),
            [] as [(std::vec::Vec<u8>, crate::storage::memtable::MemtableValue); 0]
        );
    }

    #[test]
    fn v1_and_v2_legacy_files_still_read() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();
        let entries = vec![
            (
                CompositeKey::new(realm.clone(), b"alpha".to_vec()),
                MemtableValue::Data(b"a".to_vec()),
            ),
            (
                CompositeKey::new(realm.clone(), b"bravo".to_vec()),
                MemtableValue::Tombstone,
            ),
            (
                CompositeKey::new(realm.clone(), b"charlie".to_vec()),
                MemtableValue::Data(b"c".to_vec()),
            ),
        ];

        for (name, sst_num, write) in [
            (
                "legacy_v1.sst",
                1u64,
                write_v1_manual
                    as fn(
                        &Path,
                        &[(CompositeKey, MemtableValue)],
                        u64,
                        &DataEncryptionKey,
                        &EncryptionHeader,
                    ),
            ),
            ("legacy_v2.sst", 2u64, write_v2_manual),
        ] {
            let path = dir.path().join(name);
            let (dek, enc) = test_encryption_context();
            write(&path, &entries, sst_num, &dek, &enc);
            let reader = SstReader::open(&path, sst_num, &dek).expect("open legacy");
            assert_eq!(
                reader.get(&realm, b"alpha").expect("get"),
                Some(MemtableValue::Data(b"a".to_vec())),
                "{name}: alpha"
            );
            assert_eq!(
                reader.get(&realm, b"bravo").expect("get"),
                Some(MemtableValue::Tombstone),
                "{name}: bravo tombstone"
            );
            assert_eq!(
                reader.get(&realm, b"charlie").expect("get"),
                Some(MemtableValue::Data(b"c".to_vec())),
                "{name}: charlie"
            );
            assert_eq!(
                reader.get(&realm, b"absent").expect("get"),
                None,
                "{name}: absent"
            );
            assert_eq!(
                reader.iter_all().expect("iter_all").len(),
                3,
                "{name}: iter_all"
            );
        }
    }

    /// Security regression (HEA-1917): the header `entry_count` is unauthenticated
    /// (outside the footer AEAD and CRC) and is never validated for v3. A tampered
    /// value must NOT drive an oversized allocation in `iter_all` — before the fix,
    /// `Vec::with_capacity(entry_count)` would attempt a multi-gigabyte reservation
    /// and abort the process on the compaction path. After the fix the capacity is
    /// clamped to an authenticated bound and `iter_all` returns the true entries.
    #[test]
    fn v3_tampered_entry_count_does_not_oversize_allocation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("bad_count.sst");
        let realm = RealmId::generate();
        let entries = fixed_entries(&realm, 200);
        let (dek, enc) = test_encryption_context();
        SstWriter::write_sst(&sst_path, &entries, 1, &dek, &enc).expect("write");

        // Tamper the unauthenticated header entry_count to u32::MAX. This byte
        // range is covered by neither the footer AEAD nor the footer CRC, so the
        // file still opens: the corruption is invisible to integrity checks.
        let mut raw = std::fs::read(&sst_path).expect("read");
        raw[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        std::fs::write(&sst_path, &raw).expect("rewrite");

        let reader = SstReader::open(&sst_path, 1, &dek).expect("open");
        assert_eq!(reader.entry_count(), u32::MAX, "tampered count is loaded");

        // Must complete without a giant allocation (would abort pre-fix), and must
        // return exactly the real entries — the block AEAD still authenticates them.
        let all = reader.iter_all().expect("iter_all");
        assert_eq!(all.len(), entries.len(), "real entries recovered");
        for (orig, got) in entries.iter().zip(all.iter()) {
            assert_eq!(orig, got);
        }
    }

    /// Security regression (HEA-1933): the streaming compaction rewrite
    /// (919b66a4) sized the merged Bloom filter from a pre-read
    /// `entry_count_hint` summed over each input reader's *unauthenticated*
    /// header `entry_count` (bytes 4..8). A tampered/bit-rotted `u32::MAX` count
    /// on an input SST would drive `BloomFilter::empty_for` at ~10 GiB and abort
    /// the process via an uncatchable `handle_alloc_error` — the same class
    /// HEA-1917 fixed at `iter_all`/`parse_entries` but left live on this new
    /// sizing site. After the fix the hint is clamped to the authenticated
    /// footer bound, so compaction completes and returns the real entries.
    #[test]
    fn compaction_tampered_input_entry_count_does_not_oversize_allocation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();
        let src_path = dir.path().join("tampered_input.sst");
        let entries = fixed_entries(&realm, 200);
        let (dek, enc) = test_encryption_context();
        SstWriter::write_sst(&src_path, &entries, 1, &dek, &enc).expect("write");

        // Tamper the unauthenticated header entry_count to u32::MAX. Bytes 4..8
        // are covered by neither the footer AEAD nor CRC, so the file opens
        // cleanly — the corruption is invisible to integrity checks.
        let mut raw = std::fs::read(&src_path).expect("read");
        raw[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        std::fs::write(&src_path, &raw).expect("rewrite");

        let tampered = SstReader::open(&src_path, 1, &dek).expect("open");
        assert_eq!(tampered.entry_count(), u32::MAX, "tampered count is loaded");

        // Compact through the streaming entry point. Pre-fix this sums the
        // header count into `entry_count_hint` and attempts a ~10 GiB Bloom
        // allocation; post-fix the hint is bounded by the authenticated footer.
        let (dek_out, enc_out) = test_encryption_context();
        let out_path = dir.path().join("compacted.sst");
        let meta = compact_with_fs_opts(
            &[&tampered],
            &out_path,
            &RealFs,
            2,
            &dek_out,
            &enc_out,
            true,
        )
        .expect("compaction must not abort on a tampered input count");

        // The output header carries the *real* merged count, and every entry
        // round-trips — the block AEAD still authenticates the data.
        assert_eq!(
            meta.entry_count as usize,
            entries.len(),
            "real count written"
        );
        let compacted = SstReader::open(&out_path, 2, &dek_out).expect("open compacted");
        let all = compacted.iter_all().expect("iter_all");
        assert_eq!(all.len(), entries.len(), "real entries recovered");
        for (orig, got) in entries.iter().zip(all.iter()) {
            assert_eq!(orig, got);
        }
    }

    #[test]
    fn v3_bounded_cache_reads_correctly_under_eviction() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("evict.sst");
        let realm = RealmId::generate();
        let entries = fixed_entries(&realm, 800);
        let (dek, enc) = test_encryption_context();
        SstWriter::write_sst(&sst_path, &entries, 1, &dek, &enc).expect("write");

        // A cache far smaller than the corpus: most reads miss and evict.
        let cache = Arc::new(BlockCache::new(16 * 1024));
        let reader =
            SstReader::open_with_fs(&sst_path, &RealFs, 1, &dek, Arc::clone(&cache)).expect("open");

        // Read every key twice in a shuffled-ish order; all must be correct
        // despite continual eviction, and cache residency stays bounded.
        for step in [1usize, 7, 13] {
            let mut i = 0usize;
            while i < entries.len() {
                let (k, v) = &entries[i];
                assert_eq!(
                    reader.get(k.realm_id(), k.key()).expect("get").as_ref(),
                    Some(v),
                    "wrong value for {:?} under eviction",
                    k.key()
                );
                i += step;
            }
        }
        assert!(
            cache.resident_bytes() <= 16 * 1024 + 16 * 4096,
            "cache residency {} exceeds cap + slack",
            cache.resident_bytes()
        );
    }

    /// Every key and live flag a cursor walks over `[start, end)`.
    fn walk_cursor(
        reader: &SstReader,
        realm: &RealmId,
        start: &[u8],
        end: &[u8],
    ) -> Vec<(Vec<u8>, bool)> {
        let mut cursor = reader.key_cursor(realm, start, end).expect("key_cursor");
        let mut out = Vec::new();
        while let Some((key, alive)) = cursor.current() {
            out.push((key.to_vec(), alive));
            cursor.advance().expect("advance");
        }
        out
    }

    /// The streaming key cursor (#447) walks exactly what `range_scan_keys`
    /// collects — tombstones flagged, windows starting and ending inside and
    /// between blocks — on a V3 blocked SST and on a legacy eager one.
    #[test]
    fn key_cursor_walks_what_range_scan_keys_collects() {
        let dir = tempfile::tempdir().expect("tempdir");
        let realm = RealmId::generate();
        let other_realm = RealmId::generate();
        let mut entries = fixed_entries(&realm, 400);
        for (i, (_, value)) in entries.iter_mut().enumerate() {
            if i % 7 == 0 {
                *value = MemtableValue::Tombstone;
            }
        }
        let (dek, enc) = test_encryption_context();
        let blocked_path = dir.path().join("cursor_v3.sst");
        SstWriter::write_sst(&blocked_path, &entries, 1, &dek, &enc).expect("write v3");
        let eager_path = dir.path().join("cursor_v2.sst");
        write_v2_manual(&eager_path, &entries, 2, &dek, &enc);
        let blocked = SstReader::open(&blocked_path, 1, &dek).expect("open v3");
        let eager = SstReader::open(&eager_path, 2, &dek).expect("open v2");
        assert!(
            data_blocks(&blocked).len() > 3,
            "precondition: a blocked SST of several blocks"
        );
        assert!(
            matches!(eager.body, SstBody::Eager(_)),
            "precondition: eager"
        );

        let windows: [(&[u8], &[u8]); 6] = [
            (b"k", b"l"),
            (b"k000123", b"k000321"),
            (b"k000050", b"k000051"),
            (b"k000050", b"k000050"),
            (b"a", b"b"),
            (b"k000399", b"z"),
        ];
        for (kind, reader) in [("blocked", &blocked), ("eager", &eager)] {
            for (start, end) in windows {
                assert_eq!(
                    walk_cursor(reader, &realm, start, end),
                    reader
                        .range_scan_keys(&realm, start, end)
                        .expect("range_scan_keys"),
                    "window {:?}..{:?} on the {kind} SST",
                    String::from_utf8_lossy(start),
                    String::from_utf8_lossy(end),
                );
            }
            assert_eq!(walk_cursor(reader, &other_realm, b"k", b"l"), Vec::new());
            assert!(matches!(
                reader.key_cursor(&realm, b"k000150", b"k000050"),
                Err(StorageError::InvalidRange)
            ));
        }
    }

    /// Records the most bytes written to any file it creates between two syncs.
    struct SyncGapFs {
        inner: RealFs,
        max_gap: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl SyncGapFs {
        fn new() -> Self {
            Self {
                inner: RealFs,
                max_gap: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            }
        }

        fn max_gap(&self) -> usize {
            self.max_gap.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    /// A file that [`SyncGapFs`] created.
    struct SyncGapFile {
        inner: Box<dyn FsFile>,
        unsynced: std::sync::atomic::AtomicUsize,
        max_gap: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl FsFile for SyncGapFile {
        fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
            self.inner.write_all(buf)?;
            let unsynced = self.unsynced.get_mut();
            *unsynced += buf.len();
            self.max_gap
                .fetch_max(*unsynced, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        }
        fn read_to_end(&mut self, buf: &mut Vec<u8>) -> std::io::Result<usize> {
            self.inner.read_to_end(buf)
        }
        fn sync_all(&self) -> std::io::Result<()> {
            self.inner.sync_all()?;
            self.unsynced.store(0, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        }
        fn sync_data(&self) -> std::io::Result<()> {
            self.inner.sync_data()?;
            self.unsynced.store(0, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        }
        fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
            self.inner.seek(pos)
        }
        fn set_len(&self, size: u64) -> std::io::Result<()> {
            self.inner.set_len(size)
        }
    }

    impl Fs for SyncGapFs {
        fn open_append(&self, path: &Path) -> std::io::Result<Box<dyn FsFile>> {
            self.inner.open_append(path)
        }
        fn create(&self, path: &Path) -> std::io::Result<Box<dyn FsFile>> {
            Ok(Box::new(SyncGapFile {
                inner: self.inner.create(path)?,
                unsynced: std::sync::atomic::AtomicUsize::new(0),
                max_gap: Arc::clone(&self.max_gap),
            }))
        }
        fn open_read(&self, path: &Path) -> std::io::Result<Box<dyn FsFile>> {
            self.inner.open_read(path)
        }
        fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
            self.inner.read(path)
        }
        fn read_prefix(&self, path: &Path, len: usize) -> std::io::Result<Vec<u8>> {
            self.inner.read_prefix(path, len)
        }
        fn write(&self, path: &Path, data: &[u8]) -> std::io::Result<()> {
            self.inner.write(path, data)
        }
        fn create_dir_all(&self, path: &Path) -> std::io::Result<()> {
            self.inner.create_dir_all(path)
        }
        fn read_dir(&self, path: &Path) -> std::io::Result<Vec<std::path::PathBuf>> {
            self.inner.read_dir(path)
        }
        fn remove_file(&self, path: &Path) -> std::io::Result<()> {
            self.inner.remove_file(path)
        }
        fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
            self.inner.rename(from, to)
        }
        fn sync_dir(&self, dir: &Path) -> std::io::Result<()> {
            self.inner.sync_dir(dir)
        }
    }

    /// Entries in key order that make an SST four times [`SYNC_EVERY_BYTES`].
    fn four_sync_intervals_of_entries() -> Vec<(CompositeKey, MemtableValue)> {
        let realm = RealmId::generate();
        let value = vec![b'v'; 4096];
        (0..4 * SYNC_EVERY_BYTES / value.len())
            .map(|i| {
                (
                    CompositeKey::new(realm.clone(), format!("key{i:06}").into_bytes()),
                    MemtableValue::Data(value.clone()),
                )
            })
            .collect()
    }

    /// Asserts that the SST at `path` is large enough for the test, and that at
    /// most one sync interval plus two write chunks went to it between two
    /// syncs: the last chunk of the body, and the footer and headers that
    /// `finish` writes before the caller's final sync.
    fn assert_synced_as_written(path: &Path, fs: &SyncGapFs) {
        let len = std::fs::metadata(path).expect("metadata").len();
        assert!(
            len >= 4 * SYNC_EVERY_BYTES as u64,
            "the fixture must span several sync intervals, got {len} bytes"
        );
        let gap = fs.max_gap();
        assert!(
            gap <= SYNC_EVERY_BYTES + 2 * WRITE_CHUNK_BYTES,
            "{gap} bytes went to the file between two syncs"
        );
    }

    /// #445 — a compaction syncs its output as it writes it. With one sync at
    /// the end, the kernel sent the whole output, up to ~1 GB in the
    /// steady-state memory test, to the disk at once, and the WAL's syncs waited
    /// behind it: writes stalled for up to seconds at the end of each compaction.
    #[test]
    fn the_compaction_writer_syncs_as_it_writes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("000001.sst");
        let fs = SyncGapFs::new();
        let (dek, enc_header) = test_encryption_context();
        let entries = four_sync_intervals_of_entries();

        SstWriter::write_sst_streaming_with_fs(
            &path,
            entries.into_iter().map(Ok),
            false,
            &fs,
            1,
            &dek,
            &enc_header,
        )
        .expect("write");

        assert_synced_as_written(&path, &fs);
    }

    /// #445 — a memtable flush syncs its SST as it writes it, like a compaction.
    #[test]
    fn the_flush_writer_syncs_as_it_writes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("000001.sst");
        let fs = SyncGapFs::new();
        let (dek, enc_header) = test_encryption_context();
        let entries = four_sync_intervals_of_entries();

        SstWriter::write_sst_with_fs(
            &path,
            |push| {
                for (key, value) in &entries {
                    push(key, value)?;
                }
                Ok(())
            },
            &fs,
            1,
            &dek,
            &enc_header,
        )
        .expect("write");

        assert_synced_as_written(&path, &fs);
    }
}
