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
//! New SST writes always produce V2. V1 SSTs are still readable (they load
//! without a bloom filter; `might_contain` returns `true` for every query).
//!
//! Per-file DEKs are randomly generated. The data nonce is derived from
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
use crate::storage::fs::{FileBacking, Fs, RealFs};
use crate::storage::memtable::{CompositeKey, MemtableValue};

/// SST format V1 magic bytes — original format, no bloom filter.
const SST_MAGIC: &[u8; 4] = b"HSST";

/// SST format V2 magic bytes — includes per-file Bloom filter in the plaintext section.
const SST_MAGIC_V2: &[u8; 4] = b"HSS2";

/// SST format V3 magic bytes — block-structured, per-block AEAD, encrypted
/// footer index (HEA-1914). New SSTs are written v3; V1/V2 stay readable.
const SST_MAGIC_V3: &[u8; 4] = b"HSS3";

/// Size of the base header: magic(4) + entry_count(4) + crc32(4).
const BASE_HEADER_SIZE: usize = 12;

/// Total header size: base(12) + encryption(76).
pub(crate) const TOTAL_HEADER_SIZE: usize = BASE_HEADER_SIZE + encryption::ENCRYPTION_HEADER_SIZE;

/// Target plaintext size of a v3 data block, in bytes. Blocks never split an
/// entry, so an oversized single entry produces a larger block. ~4 KiB keeps a
/// decrypted block's heap footprint small while amortising per-block AEAD cost.
const V3_BLOCK_TARGET_BYTES: usize = 4096;

/// Fixed v3 trailer written at the very end of the file:
/// `[8B footer_offset (u64 LE)] [4B footer_ciphertext_len (u32 LE)]`.
const V3_TRAILER_SIZE: usize = 12;

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
struct BloomFilter {
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

    /// Sets k bit positions for the given `(realm_id, key)` pair.
    fn insert(&mut self, realm_id: &RealmId, key: &[u8]) {
        let (h1, h2) = bloom_hashes(realm_id, key);
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
            entries.iter().map(|(k, v)| (k, v)),
            entries.len(),
            &RealFs,
            sst_number,
            dek,
            enc_header,
        )
    }

    /// Writes an SST file from an **ordered iterator** of entries using a custom
    /// filesystem implementation.
    ///
    /// `entries` MUST yield `(CompositeKey, MemtableValue)` references in sorted
    /// `CompositeKey` order, and `entry_count` MUST be its length. Taking an
    /// iterator rather than a slice lets a memtable flush stream directly off its
    /// lock-free `SkipMap` without first materialising a full `Vec` copy of every
    /// key and value (HEA-1908) — the bloom filter and the serialized payload are
    /// both produced in a **single pass** over the iterator, with the filter sized
    /// up front from `entry_count`.
    pub(crate) fn write_sst_with_fs<'a, I>(
        path: &Path,
        entries: I,
        entry_count: usize,
        fs: &dyn Fs,
        sst_number: u64,
        dek: &DataEncryptionKey,
        enc_header: &EncryptionHeader,
    ) -> Result<SstMetadata, StorageError>
    where
        I: IntoIterator<Item = (&'a CompositeKey, &'a MemtableValue)>,
    {
        let mut file = fs.create(path)?;

        // --- Build V3 block-structured body (HEA-1914) ---
        //
        // Layout written to the file:
        //   [BASE HEADER 12B]  magic HSS3, entry_count, crc32(footer ciphertext)
        //   [ENC HEADER  76B]  wrapped per-file DEK
        //   [block_0 ct][block_1 ct]...[block_{n-1} ct]   each independently AEAD'd
        //   [footer ciphertext]                            encrypted block index
        //   [TRAILER 12B]  footer_offset (u64 LE) + footer_ct_len (u32 LE)
        //
        // Each block is sealed with `block_nonce(sst_number, block_index)` used
        // as both nonce and AAD, so a block cannot be replayed at a different
        // position or in a different file. Blocks target ~4 KiB of plaintext and
        // never split an entry. The bloom filter is sized up front and filled in
        // the same single pass. No full slice of the entries is materialised.
        let mut filter = BloomFilter::empty_for(entry_count);
        let mut blocks_buf: Vec<u8> = Vec::new();
        let mut index: Vec<BlockIndexEntry> = Vec::new();
        let mut cur_block: Vec<u8> = Vec::new();
        let mut cur_first_key: Option<CompositeKey> = None;
        let mut min_key: Option<CompositeKey> = None;
        let mut max_key: Option<CompositeKey> = None;
        let mut written: u32 = 0;

        for (key, value) in entries {
            filter.insert(key.realm_id(), key.key());
            if cur_first_key.is_none() {
                cur_first_key = Some(key.clone());
            }
            if min_key.is_none() {
                min_key = Some(key.clone());
            }
            max_key = Some(key.clone());
            Self::serialize_entry(&mut cur_block, key, value);
            written = written.saturating_add(1);
            if cur_block.len() >= V3_BLOCK_TARGET_BYTES {
                Self::seal_block(
                    &mut blocks_buf,
                    &mut index,
                    &mut cur_block,
                    &mut cur_first_key,
                    sst_number,
                    dek,
                )?;
            }
        }
        // Flush the final partial block.
        Self::seal_block(
            &mut blocks_buf,
            &mut index,
            &mut cur_block,
            &mut cur_first_key,
            sst_number,
            dek,
        )?;

        // --- Build and encrypt the footer index ---
        let mut footer = Vec::new();
        #[allow(clippy::cast_possible_truncation)]
        footer.extend_from_slice(&(index.len() as u32).to_le_bytes());
        for e in &index {
            footer.extend_from_slice(&e.file_offset.to_le_bytes());
            footer.extend_from_slice(&e.ciphertext_len.to_le_bytes());
            footer.extend_from_slice(&e.plaintext_len.to_le_bytes());
            write_footer_key(&mut footer, &e.first_key);
        }
        match (&min_key, &max_key) {
            (Some(mn), Some(mx)) => {
                footer.push(1);
                write_footer_key(&mut footer, mn);
                write_footer_key(&mut footer, mx);
            }
            _ => footer.push(0),
        }
        #[allow(clippy::cast_possible_truncation)]
        let bloom_byte_count = filter.bits.len() as u32;
        footer.extend_from_slice(&bloom_byte_count.to_le_bytes());
        if bloom_byte_count > 0 {
            footer.push(filter.k);
            footer.extend_from_slice(&filter.bits);
        }

        let footer_nonce = block_nonce(sst_number, SST_FOOTER_BLOCK_INDEX);
        let footer_ct = encryption::encrypt_section(&footer, dek, &footer_nonce, &footer_nonce)?;
        let footer_offset = TOTAL_HEADER_SIZE as u64 + blocks_buf.len() as u64;
        let footer_crc = crc32fast::hash(&footer_ct);

        // --- Assemble the whole file and write it in one pass ---
        let entry_count = written;
        let mut out = Vec::with_capacity(
            TOTAL_HEADER_SIZE + blocks_buf.len() + footer_ct.len() + V3_TRAILER_SIZE,
        );
        out.extend_from_slice(SST_MAGIC_V3);
        out.extend_from_slice(&entry_count.to_le_bytes());
        out.extend_from_slice(&footer_crc.to_le_bytes());
        out.extend_from_slice(&enc_header.to_bytes());
        out.extend_from_slice(&blocks_buf);
        out.extend_from_slice(&footer_ct);
        out.extend_from_slice(&footer_offset.to_le_bytes());
        #[allow(clippy::cast_possible_truncation)]
        out.extend_from_slice(&(footer_ct.len() as u32).to_le_bytes());

        file.write_all(&out)?;
        file.sync_all()?;
        // Fsync the parent directory so the freshly created SST's directory
        // entry is durable. A newly created file can otherwise vanish entirely
        // if power is lost before the dir update commits (HEA-1855). Callers
        // that finalize via rename (compaction) additionally fsync the dir after
        // the rename.
        if let Some(parent) = path.parent() {
            fs.sync_dir(parent)?;
        }

        let file_size = out.len() as u64;

        Ok(SstMetadata {
            entry_count,
            file_size,
        })
    }

    /// Encrypts one accumulated block plaintext, appends the ciphertext to
    /// `blocks_buf`, and records its index entry. Clears `plaintext` and takes
    /// `first_key` so the caller can begin the next block. A no-op on an empty
    /// block.
    fn seal_block(
        blocks_buf: &mut Vec<u8>,
        index: &mut Vec<BlockIndexEntry>,
        plaintext: &mut Vec<u8>,
        first_key: &mut Option<CompositeKey>,
        sst_number: u64,
        dek: &DataEncryptionKey,
    ) -> Result<(), StorageError> {
        if plaintext.is_empty() {
            return Ok(());
        }
        let first_key = first_key
            .take()
            .ok_or_else(|| StorageError::InvalidSstFormat {
                reason: "v3 writer: non-empty block without a first key".to_string(),
            })?;
        #[allow(clippy::cast_possible_truncation)]
        let block_index = index.len() as u32;
        let nonce = block_nonce(sst_number, block_index);
        let ct = encryption::encrypt_section(plaintext, dek, &nonce, &nonce)?;
        let file_offset = TOTAL_HEADER_SIZE as u64 + blocks_buf.len() as u64;
        #[allow(clippy::cast_possible_truncation)]
        index.push(BlockIndexEntry {
            first_key,
            file_offset,
            ciphertext_len: ct.len() as u32,
            plaintext_len: plaintext.len() as u32,
        });
        blocks_buf.extend_from_slice(&ct);
        plaintext.clear();
        Ok(())
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
}

/// Backing representation of an SST reader's entries.
enum SstBody {
    /// V1/V2 legacy formats: all entries eagerly decrypted and resident.
    Eager(Vec<(CompositeKey, MemtableValue)>),
    /// V3: block-structured. Only the footer index is resident; data blocks are
    /// memory-mapped and decrypted on demand through the shared block cache
    /// (HEA-1914). Resident RAM is `O(#blocks + cache_cap)`, not `O(corpus)`.
    Blocked(BlockedBody),
}

/// Process-wide source of unique `reader_id`s. Each physical `SstReader::open`
/// gets a fresh value so block-cache keys never collide across a compaction
/// that reuses an SST file number (see [`BlockId`]).
static NEXT_READER_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Lazily-decrypted body of a v3 SST.
struct BlockedBody {
    /// Whole-file backing (mmap in production, heap in simulation).
    backing: FileBacking,
    /// Footer block index, sorted by `first_key`.
    index: Vec<BlockIndexEntry>,
    /// Per-file DEK retained for on-demand block decryption.
    dek: DataEncryptionKey,
    /// Shared, bounded cache of decrypted blocks.
    cache: Arc<BlockCache>,
    /// Unique per-open id used to key this reader's blocks in the shared cache.
    reader_id: u64,
}

impl BlockedBody {
    /// Index of the block that may contain `(realm, key)`, or `None` if the key
    /// sorts before the first block's `first_key`. Binary search over the
    /// footer index: the candidate is the last block whose `first_key <= target`.
    fn block_for_key(&self, realm: &RealmId, key: &[u8]) -> Option<usize> {
        let le = |e: &BlockIndexEntry| {
            e.first_key
                .realm_id()
                .cmp(realm)
                .then_with(|| e.first_key.key().cmp(key))
                .is_le()
        };
        let pp = self.index.partition_point(|e| le(e));
        pp.checked_sub(1)
    }

    /// Fetches a decrypted block, from the shared cache on a hit or by slicing
    /// the backing and decrypting on a miss. Surfaces AEAD/format errors rather
    /// than returning a wrong or absent value.
    fn fetch_block(
        &self,
        block_index: usize,
        sst_number: u64,
    ) -> Result<Arc<CachedBlock>, StorageError> {
        #[allow(clippy::cast_possible_truncation)]
        let id = BlockId {
            reader_id: self.reader_id,
            block_index: block_index as u32,
        };
        if let Some(block) = self.cache.get(id) {
            return Ok(block);
        }
        let entry = self
            .index
            .get(block_index)
            .ok_or_else(|| StorageError::InvalidSstFormat {
                reason: "v3 block index out of range".to_string(),
            })?;
        let start = entry.file_offset as usize;
        let end = start
            .checked_add(entry.ciphertext_len as usize)
            .filter(|end| *end <= self.backing.len())
            .ok_or_else(|| StorageError::InvalidSstFormat {
                reason: "v3 block extends past end of file".to_string(),
            })?;
        #[allow(clippy::cast_possible_truncation)]
        let nonce = block_nonce(sst_number, block_index as u32);
        let plaintext =
            encryption::decrypt_section(&self.backing[start..end], &self.dek, &nonce, &nonce)?;
        let entries = SstReader::parse_entries(&plaintext, None)?;
        let block = Arc::new(CachedBlock::new(entries, plaintext.len()));
        self.cache.insert(id, Arc::clone(&block));
        Ok(block)
    }
}

/// Reads entries from an SST file on disk.
pub(crate) struct SstReader {
    /// Backing store: eager entries (V1/V2) or lazy blocks (V3).
    body: SstBody,
    /// Number of entries as declared in the header.
    entry_count: u32,
    /// Monotonically increasing SST file number for path derivation.
    sst_number: u64,
    /// Per-SST Bloom filter for fast key rejection (V2/V3 SSTs).
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

        // --- V3: block-structured, lazy ---
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

        Ok(Self {
            body: SstBody::Eager(entries),
            entry_count,
            sst_number,
            bloom_filter,
            key_range,
        })
    }

    /// Parses a V3 SST: read the trailer, verify+decrypt the footer, load the
    /// block index, and validate every block offset lies within the data
    /// section (eager truncation detection). Block payloads stay on disk.
    fn open_v3(
        backing: FileBacking,
        entry_count: u32,
        stored_crc: u32,
        sst_number: u64,
        dek: &DataEncryptionKey,
        cache: Arc<BlockCache>,
    ) -> Result<Self, StorageError> {
        let len = backing.len();
        if len < TOTAL_HEADER_SIZE + V3_TRAILER_SIZE {
            return Err(StorageError::InvalidSstFormat {
                reason: "v3: file too small for trailer".to_string(),
            });
        }
        let trailer = &backing[len - V3_TRAILER_SIZE..];
        #[allow(clippy::cast_possible_truncation)]
        let footer_offset = u64::from_le_bytes(trailer[0..8].try_into().map_err(|_| {
            StorageError::InvalidSstFormat {
                reason: "v3: invalid trailer footer offset".to_string(),
            }
        })?) as usize;
        let footer_len = u32::from_le_bytes(trailer[8..12].try_into().map_err(|_| {
            StorageError::InvalidSstFormat {
                reason: "v3: invalid trailer footer length".to_string(),
            }
        })?) as usize;

        // Footer must lie between the header and the trailer. A truncated file
        // fails this bound instead of reading arbitrary bytes.
        let footer_end = footer_offset
            .checked_add(footer_len)
            .filter(|end| footer_offset >= TOTAL_HEADER_SIZE && *end <= len - V3_TRAILER_SIZE)
            .ok_or_else(|| StorageError::InvalidSstFormat {
                reason: "v3: footer offset/length out of range (truncated?)".to_string(),
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

        let (index, key_range, bloom_filter) = Self::parse_v3_footer(&footer_plain)?;

        // Validate every block's byte range lies within [header, footer_offset)
        // so a truncated data section is rejected at open, not mid-read.
        for e in &index {
            let start = e.file_offset as usize;
            let end = start
                .checked_add(e.ciphertext_len as usize)
                .ok_or_else(|| StorageError::InvalidSstFormat {
                    reason: "v3: block length overflow".to_string(),
                })?;
            if start < TOTAL_HEADER_SIZE || end > footer_offset {
                return Err(StorageError::InvalidSstFormat {
                    reason: "v3: block range out of bounds (truncated?)".to_string(),
                });
            }
        }

        let reader_id = NEXT_READER_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(Self {
            body: SstBody::Blocked(BlockedBody {
                backing,
                index,
                dek: dek.clone_key(),
                cache,
                reader_id,
            }),
            entry_count,
            sst_number,
            bloom_filter,
            key_range,
        })
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
                let mut out = Vec::with_capacity(self.entry_count as usize);
                for bi in 0..body.index.len() {
                    let block = body.fetch_block(bi, self.sst_number)?;
                    out.extend(block.entries.iter().cloned());
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
        let cmp = |(k, _): &(CompositeKey, MemtableValue)| {
            k.realm_id().cmp(realm_id).then_with(|| k.key().cmp(key))
        };
        match &self.body {
            SstBody::Eager(entries) => Ok(entries
                .binary_search_by(cmp)
                .ok()
                .map(|idx| entries[idx].1.clone())),
            SstBody::Blocked(body) => {
                let Some(bi) = body.block_for_key(realm_id, key) else {
                    return Ok(None);
                };
                let block = body.fetch_block(bi, self.sst_number)?;
                Ok(block
                    .entries
                    .binary_search_by(cmp)
                    .ok()
                    .map(|idx| block.entries[idx].1.clone()))
            }
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
        self.range_scan_inner(realm_id, start_key, end_key, |v| v.clone())
    }

    /// Key-only range scan — like [`range_scan`] but returns `(key, is_alive)`
    /// pairs without cloning value bytes.
    pub(crate) fn range_scan_keys(
        &self,
        realm_id: &RealmId,
        start_key: &[u8],
        end_key: &[u8],
    ) -> Result<Vec<(Vec<u8>, bool)>, StorageError> {
        self.range_scan_inner(realm_id, start_key, end_key, |v| {
            matches!(v, MemtableValue::Data(_))
        })
    }

    /// Shared body of [`range_scan`]/[`range_scan_keys`]: prune, locate the
    /// `[start, end)` window, and project each in-range value with `project`.
    fn range_scan_inner<T>(
        &self,
        realm_id: &RealmId,
        start_key: &[u8],
        end_key: &[u8],
        project: impl Fn(&MemtableValue) -> T,
    ) -> Result<Vec<(Vec<u8>, T)>, StorageError> {
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
                    .map(|(k, v)| (k.key().to_vec(), project(v)))
                    .collect())
            }
            SstBody::Blocked(body) => {
                let mut out = Vec::new();
                // Start at the block that may hold `start`; if `start` precedes
                // the first block, begin at block 0.
                let mut bi = body.block_for_key(realm_id, start_key).unwrap_or(0);
                while bi < body.index.len() {
                    // Blocks are sorted; once a block starts at/after `end`,
                    // no later block can contribute.
                    if body.index[bi].first_key >= end {
                        break;
                    }
                    let block = body.fetch_block(bi, self.sst_number)?;
                    for (k, v) in &block.entries {
                        if k >= &start && k < &end {
                            out.push((k.key().to_vec(), project(v)));
                        }
                    }
                    bi += 1;
                }
                Ok(out)
            }
        }
    }

    /// Returns the entry count as declared in the SST header.
    pub(crate) fn entry_count(&self) -> u32 {
        self.entry_count
    }

    /// Returns the SST file number used for path derivation.
    pub(crate) fn sst_number(&self) -> u64 {
        self.sst_number
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
        let mut entries = Vec::with_capacity(expected_count.unwrap_or(0) as usize);
        let mut pos = 0;

        while pos < data.len() {
            if pos >= data.len() {
                return Err(StorageError::InvalidSstFormat {
                    reason: "truncated entry: missing type byte".to_string(),
                });
            }
            let entry_type = data[pos];
            pos += 1;

            // Realm UUID (16 bytes)
            if pos + 16 > data.len() {
                return Err(StorageError::InvalidSstFormat {
                    reason: "truncated entry: missing realm UUID".to_string(),
                });
            }
            let uuid_bytes: [u8; 16] =
                data[pos..pos + 16]
                    .try_into()
                    .map_err(|_| StorageError::InvalidSstFormat {
                        reason: "invalid UUID bytes".to_string(),
                    })?;
            let realm_id = RealmId::new(Uuid::from_bytes(uuid_bytes));
            pos += 16;

            // Key length + key data
            if pos + 4 > data.len() {
                return Err(StorageError::InvalidSstFormat {
                    reason: "truncated entry: missing key length".to_string(),
                });
            }
            let key_len = u32::from_le_bytes(data[pos..pos + 4].try_into().map_err(|_| {
                StorageError::InvalidSstFormat {
                    reason: "invalid key length bytes".to_string(),
                }
            })?) as usize;
            pos += 4;

            if pos + key_len > data.len() {
                return Err(StorageError::InvalidSstFormat {
                    reason: "truncated entry: missing key data".to_string(),
                });
            }
            let key = data[pos..pos + key_len].to_vec();
            pos += key_len;

            // Value length + value data
            if pos + 4 > data.len() {
                return Err(StorageError::InvalidSstFormat {
                    reason: "truncated entry: missing value length".to_string(),
                });
            }
            let val_len = u32::from_le_bytes(data[pos..pos + 4].try_into().map_err(|_| {
                StorageError::InvalidSstFormat {
                    reason: "invalid value length bytes".to_string(),
                }
            })?) as usize;
            pos += 4;

            if pos + val_len > data.len() {
                return Err(StorageError::InvalidSstFormat {
                    reason: "truncated entry: missing value data".to_string(),
                });
            }
            let value_data = data[pos..pos + val_len].to_vec();
            pos += val_len;

            let composite_key = CompositeKey::new(realm_id, key);
            let value = match entry_type {
                0x00 => MemtableValue::Data(value_data),
                0x01 => MemtableValue::Tombstone,
                other => {
                    return Err(StorageError::InvalidSstFormat {
                        reason: format!("unknown entry type: {other:#x}"),
                    })
                }
            };

            entries.push((composite_key, value));
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
    let mut merged = std::collections::BTreeMap::new();
    for sst in input_ssts {
        for (key, value) in sst.iter_all()? {
            merged.insert(key, value);
        }
    }

    let live_entries: Vec<(CompositeKey, MemtableValue)> = merged
        .into_iter()
        .filter(|(_, v)| !(drop_tombstones && matches!(v, MemtableValue::Tombstone)))
        .collect();

    SstWriter::write_sst_with_fs(
        output_path,
        live_entries.iter().map(|(k, v)| (k, v)),
        live_entries.len(),
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
    let data = fs.read(path)?;
    if data.len() < TOTAL_HEADER_SIZE {
        return Err(StorageError::InvalidSstFormat {
            reason: format!("file too small for header: {} bytes", data.len()),
        });
    }

    if &data[0..4] != SST_MAGIC && &data[0..4] != SST_MAGIC_V2 && &data[0..4] != SST_MAGIC_V3 {
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

        // Verify raw file structure — new SSTs use V2 magic with bloom filter
        let raw = std::fs::read(&sst_path).expect("read file");
        assert!(raw.len() >= TOTAL_HEADER_SIZE);
        assert_eq!(&raw[0..4], b"HSS3", "new SSTs must use V3 magic");
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
        assert!(reader
            .range_scan(&realm, b"key7", b"key9")
            .expect("range_scan")
            .is_empty());
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
        assert!(reader.iter_all().expect("iter_all").is_empty());
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
        assert!(reader.iter_realm(&ghost).expect("iter_realm").is_empty());
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
        assert!(compacted.iter_all().expect("iter_all").is_empty());
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
        assert!(filter.bits.is_empty());
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
            reader.bloom_filter.is_some(),
            "bloom filter must be present in V2 SST after reopen"
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
        assert!(reader
            .range_scan(&ghost, b"a", b"z")
            .expect("range")
            .is_empty());
        assert_eq!(reader.get(&ghost, b"apple").expect("get"), None);

        let realm_entries = reader.iter_realm(&realm).expect("iter_realm");
        assert_eq!(realm_entries.len(), 6);
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
        let trailer = &raw[len - V3_TRAILER_SIZE..];
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
        SstWriter::write_sst(&sst_path, &entries, 1, &dek, &enc).expect("write");

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
        SstWriter::write_sst(&sst_path, &entries, 1, &dek, &enc).expect("write");

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
        SstWriter::write_sst(&sst_path, &entries, 1, &dek, &enc).expect("write");

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

    #[test]
    fn v3_truncated_footer_is_clean_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("trunc_footer.sst");
        let realm = RealmId::generate();
        let entries = fixed_entries(&realm, 200);
        let (dek, enc) = test_encryption_context();
        SstWriter::write_sst(&sst_path, &entries, 1, &dek, &enc).expect("write");

        let mut raw = std::fs::read(&sst_path).expect("read");
        // Drop the trailer and most of the footer.
        raw.truncate(raw.len() - (V3_TRAILER_SIZE + 8));
        std::fs::write(&sst_path, &raw).expect("rewrite");

        let result = SstReader::open(&sst_path, 1, &dek);
        assert!(
            matches!(
                result,
                Err(StorageError::InvalidSstFormat { .. } | StorageError::ChecksumMismatch { .. })
            ),
            "truncated footer must be a clean format error, got {result:?}"
        );
    }

    #[test]
    fn v3_truncated_final_block_is_clean_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sst_path = dir.path().join("trunc_block.sst");
        let realm = RealmId::generate();
        let entries = fixed_entries(&realm, 200);
        let (dek, enc) = test_encryption_context();
        SstWriter::write_sst(&sst_path, &entries, 1, &dek, &enc).expect("write");

        let mut raw = std::fs::read(&sst_path).expect("read");
        // Cut the file inside the data section (drops footer + last blocks). The
        // trailer now reads garbage, so open must reject it — no panic.
        raw.truncate(TOTAL_HEADER_SIZE + 100);
        std::fs::write(&sst_path, &raw).expect("rewrite");

        let result = SstReader::open(&sst_path, 1, &dek);
        assert!(
            matches!(
                result,
                Err(StorageError::InvalidSstFormat { .. } | StorageError::ChecksumMismatch { .. })
            ),
            "truncated data section must be a clean format error, got {result:?}"
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
}
