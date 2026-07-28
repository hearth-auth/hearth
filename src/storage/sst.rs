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

use uuid::Uuid;

use crate::core::RealmId;
use crate::storage::encryption::{self, counter_nonce, DataEncryptionKey, EncryptionHeader, KekId};
use crate::storage::error::StorageError;
use crate::storage::fs::{Fs, RealFs};
use crate::storage::memtable::{CompositeKey, MemtableValue};

/// SST format V1 magic bytes — original format, no bloom filter.
const SST_MAGIC: &[u8; 4] = b"HSST";

/// SST format V2 magic bytes — includes per-file Bloom filter in the plaintext section.
const SST_MAGIC_V2: &[u8; 4] = b"HSS2";

/// Size of the base header: magic(4) + entry_count(4) + crc32(4).
const BASE_HEADER_SIZE: usize = 12;

/// Total header size: base(12) + encryption(76).
pub(crate) const TOTAL_HEADER_SIZE: usize = BASE_HEADER_SIZE + encryption::ENCRYPTION_HEADER_SIZE;

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
        let n = entries.len();
        if n == 0 {
            return Self {
                bits: Vec::new(),
                k: 0,
            };
        }
        let bit_count = n.saturating_mul(10).max(64);
        let byte_count = bit_count.div_ceil(8);
        let mut filter = Self {
            bits: vec![0u8; byte_count],
            k: 7,
        };
        for (key, _) in entries {
            filter.insert(key.realm_id(), key.key());
        }
        filter
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
        Self::write_sst_with_fs(path, entries, &RealFs, sst_number, dek, enc_header)
    }

    /// Writes an SST file using a custom filesystem implementation.
    pub(crate) fn write_sst_with_fs(
        path: &Path,
        entries: &[(CompositeKey, MemtableValue)],
        fs: &dyn Fs,
        sst_number: u64,
        dek: &DataEncryptionKey,
        enc_header: &EncryptionHeader,
    ) -> Result<SstMetadata, StorageError> {
        let mut file = fs.create(path)?;

        // --- Build Bloom filter and V2 plaintext section ---
        //
        // V2 plaintext layout:
        //   [4B] bloom_byte_count (u32 LE) — 0 means no filter (empty SST)
        //   [1B] bloom_k           — only present if bloom_byte_count > 0
        //   [N B] bloom bits       — only present if bloom_byte_count > 0
        //   [entry bytes]          — same serialisation as V1
        let filter = BloomFilter::build(entries);
        let entry_payload = Self::serialize_entries(entries);

        #[allow(clippy::cast_possible_truncation)]
        let bloom_byte_count = filter.bits.len() as u32;
        let filter_overhead = if bloom_byte_count > 0 {
            1 + filter.bits.len() // 1 byte for k
        } else {
            0
        };
        let mut plaintext = Vec::with_capacity(4 + filter_overhead + entry_payload.len());
        plaintext.extend_from_slice(&bloom_byte_count.to_le_bytes());
        if bloom_byte_count > 0 {
            plaintext.push(filter.k);
            plaintext.extend_from_slice(&filter.bits);
        }
        plaintext.extend_from_slice(&entry_payload);

        let crc = crc32fast::hash(&plaintext);

        // --- Write base header (V2 magic) ---
        #[allow(clippy::cast_possible_truncation)]
        let entry_count = entries.len() as u32;
        file.write_all(SST_MAGIC_V2)?;
        file.write_all(&entry_count.to_le_bytes())?;
        file.write_all(&crc.to_le_bytes())?;

        // --- Write encryption header ---
        file.write_all(&enc_header.to_bytes())?;

        // --- Encrypt and write data section ---
        let data_nonce = counter_nonce(sst_number);
        let aad = sst_number.to_le_bytes();
        let ciphertext = encryption::encrypt_section(&plaintext, dek, &data_nonce, &aad)?;
        file.write_all(&ciphertext)?;

        file.sync_all()?;

        let file_size = TOTAL_HEADER_SIZE as u64 + ciphertext.len() as u64;

        Ok(SstMetadata {
            entry_count,
            file_size,
        })
    }

    /// Serializes entries into the data section binary format.
    fn serialize_entries(entries: &[(CompositeKey, MemtableValue)]) -> Vec<u8> {
        let mut buf = Vec::new();
        for (key, value) in entries {
            Self::serialize_entry(&mut buf, key, value);
        }
        buf
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

/// Reads entries from an SST file on disk.
#[derive(Debug)]
pub(crate) struct SstReader {
    /// All entries loaded from the SST, sorted by `CompositeKey`.
    entries: Vec<(CompositeKey, MemtableValue)>,
    /// Number of entries as declared in the header.
    entry_count: u32,
    /// Monotonically increasing SST file number for path derivation.
    sst_number: u64,
    /// Per-SST Bloom filter for fast key rejection (present in V2 SSTs only).
    ///
    /// A `None` filter is treated as "might contain everything" — V1 SSTs
    /// written before HEA-1626 are still read correctly; they just don't get
    /// the fast-reject optimisation.
    bloom_filter: Option<BloomFilter>,
    /// Inclusive `(min, max)` `CompositeKey` bounds of the entries in this SST,
    /// or `None` for an empty SST.
    ///
    /// Because entries are stored sorted, these are simply the first and last
    /// keys. They enable O(1) range pruning (HEA-1773): a point or range lookup
    /// whose realm-first `CompositeKey` falls entirely outside `[min, max]` can
    /// skip this SST without touching the Bloom filter or binary search. This
    /// bounds cold-read fan-out `S` when SSTs cover disjoint key ranges (e.g.
    /// realm-partitioned data), independent of compaction cadence.
    key_range: Option<(CompositeKey, CompositeKey)>,
}

impl SstReader {
    /// Opens and validates an SST file, decrypting and loading all entries.
    pub(crate) fn open(
        path: &Path,
        sst_number: u64,
        dek: &DataEncryptionKey,
    ) -> Result<Self, StorageError> {
        Self::open_with_fs(path, &RealFs, sst_number, dek)
    }

    /// Opens an SST file using a custom filesystem implementation.
    pub(crate) fn open_with_fs(
        path: &Path,
        fs: &dyn Fs,
        sst_number: u64,
        dek: &DataEncryptionKey,
    ) -> Result<Self, StorageError> {
        let data = fs.read(path)?;

        // Minimum file size: base header + encryption header
        if data.len() < TOTAL_HEADER_SIZE {
            return Err(StorageError::InvalidSstFormat {
                reason: format!("file too small: {} bytes", data.len()),
            });
        }

        // --- Parse base header ---
        // Accept both V1 (b"HSST", no bloom filter) and V2 (b"HSS2", with bloom filter).
        let is_v2 = match &data[0..4] {
            m if m == SST_MAGIC => false,
            m if m == SST_MAGIC_V2 => true,
            _ => {
                return Err(StorageError::InvalidSstFormat {
                    reason: "invalid magic bytes".to_string(),
                })
            }
        };
        let entry_count = u32::from_le_bytes(data[4..8].try_into().map_err(|_| {
            StorageError::InvalidSstFormat {
                reason: "invalid entry count bytes".to_string(),
            }
        })?);
        let stored_crc = u32::from_le_bytes(data[8..12].try_into().map_err(|_| {
            StorageError::InvalidSstFormat {
                reason: "invalid CRC bytes".to_string(),
            }
        })?);

        // --- Parse encryption header (validate it parseable) ---
        let enc_bytes: &[u8; encryption::ENCRYPTION_HEADER_SIZE] = data
            [BASE_HEADER_SIZE..TOTAL_HEADER_SIZE]
            .try_into()
            .map_err(|_| StorageError::InvalidSstFormat {
                reason: "truncated encryption header".to_string(),
            })?;
        let _enc_header = EncryptionHeader::from_bytes(enc_bytes);

        // --- Decrypt data section ---
        let ciphertext = &data[TOTAL_HEADER_SIZE..];
        let data_nonce = counter_nonce(sst_number);
        let aad = sst_number.to_le_bytes();
        let plaintext = encryption::decrypt_section(ciphertext, dek, &data_nonce, &aad)?;

        // --- Verify CRC ---
        let computed_crc = crc32fast::hash(&plaintext);
        if stored_crc != computed_crc {
            return Err(StorageError::ChecksumMismatch {
                offset: TOTAL_HEADER_SIZE as u64,
            });
        }

        // --- Parse bloom filter (V2 only) + entries ---
        let (entries, bloom_filter) = if is_v2 {
            Self::parse_v2_plaintext(&plaintext, entry_count)?
        } else {
            (Self::deserialize_entries(&plaintext, entry_count)?, None)
        };

        // Precompute inclusive key-range bounds for O(1) pruning. Entries are
        // sorted, so the first and last keys are the min and max.
        let key_range = match (entries.first(), entries.last()) {
            (Some((min, _)), Some((max, _))) => Some((min.clone(), max.clone())),
            _ => None,
        };

        Ok(Self {
            entries,
            entry_count,
            sst_number,
            bloom_filter,
            key_range,
        })
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
    pub(crate) fn iter_all(&self) -> &[(CompositeKey, MemtableValue)] {
        &self.entries
    }

    /// Returns all entries for a specific realm, with raw keys (no realm prefix).
    pub(crate) fn iter_realm(&self, realm_id: &RealmId) -> Vec<(Vec<u8>, MemtableValue)> {
        self.entries
            .iter()
            .filter(|(k, _)| k.realm_id() == realm_id)
            .map(|(k, v)| (k.key().to_vec(), v.clone()))
            .collect()
    }

    /// Point lookup for a specific realm and key.
    ///
    /// Checks the Bloom filter first (O(k) hash operations) to quickly reject
    /// SSTs that cannot contain the key — avoiding an O(log n) binary search
    /// for absent keys in the common case. The binary search itself is
    /// allocation-free: `(realm_id, key)` bytes are compared directly against
    /// `CompositeKey` fields without constructing a new `CompositeKey`.
    pub(crate) fn get(&self, realm_id: &RealmId, key: &[u8]) -> Option<MemtableValue> {
        // O(1) range prune: skip SSTs whose key range cannot contain the key
        // (HEA-1773). Cheaper than the Bloom filter's k hashes and also rejects
        // V1 SSTs that carry no filter.
        if !self.may_contain(realm_id, key) {
            return None;
        }
        // Fast reject: if the bloom filter says "no", the key is definitely absent.
        if let Some(ref filter) = self.bloom_filter {
            if !filter.might_contain(realm_id, key) {
                return None;
            }
        }
        // Alloc-free binary search: compare realm UUID bytes then key bytes
        // directly, without allocating a CompositeKey wrapper.
        self.entries
            .binary_search_by(|(k, _)| k.realm_id().cmp(realm_id).then_with(|| k.key().cmp(key)))
            .ok()
            .map(|idx| self.entries[idx].1.clone())
    }

    /// Range scan within a single realm's key space.
    ///
    /// Returns entries where `start_key <= key < end_key` (half-open interval).
    /// Uses `partition_point` binary search for O(log n) boundary location
    /// instead of the previous O(n) linear filter.
    pub(crate) fn range_scan(
        &self,
        realm_id: &RealmId,
        start_key: &[u8],
        end_key: &[u8],
    ) -> Vec<(Vec<u8>, MemtableValue)> {
        // O(1) range prune: skip SSTs disjoint from the scan window (HEA-1773).
        if !self.overlaps_range(realm_id, start_key, end_key) {
            return Vec::new();
        }
        let start = CompositeKey::new(realm_id.clone(), start_key.to_vec());
        let end = CompositeKey::new(realm_id.clone(), end_key.to_vec());

        // Binary search for the half-open range [start, end) in O(log n).
        let lo = self.entries.partition_point(|(k, _)| k < &start);
        let hi = self.entries.partition_point(|(k, _)| k < &end);

        self.entries[lo..hi]
            .iter()
            .map(|(k, v)| (k.key().to_vec(), v.clone()))
            .collect()
    }

    /// Key-only range scan — like [`range_scan`] but returns `(key, is_alive)`
    /// pairs without cloning value bytes. Used by the key-only scan path to
    /// avoid allocating value bytes when only the count or key list is needed.
    ///
    /// Uses `partition_point` binary search for O(log n) boundary location.
    pub(crate) fn range_scan_keys(
        &self,
        realm_id: &RealmId,
        start_key: &[u8],
        end_key: &[u8],
    ) -> Vec<(Vec<u8>, bool)> {
        // O(1) range prune: skip SSTs disjoint from the scan window (HEA-1773).
        if !self.overlaps_range(realm_id, start_key, end_key) {
            return Vec::new();
        }
        let start = CompositeKey::new(realm_id.clone(), start_key.to_vec());
        let end = CompositeKey::new(realm_id.clone(), end_key.to_vec());

        let lo = self.entries.partition_point(|(k, _)| k < &start);
        let hi = self.entries.partition_point(|(k, _)| k < &end);

        self.entries[lo..hi]
            .iter()
            .map(|(k, v)| (k.key().to_vec(), matches!(v, MemtableValue::Data(_))))
            .collect()
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

    /// Deserializes the data section into entries.
    fn deserialize_entries(
        data: &[u8],
        expected_count: u32,
    ) -> Result<Vec<(CompositeKey, MemtableValue)>, StorageError> {
        let mut entries = Vec::with_capacity(expected_count as usize);
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

        #[allow(clippy::cast_possible_truncation)]
        let actual_count = entries.len() as u32;
        if actual_count != expected_count {
            return Err(StorageError::InvalidSstFormat {
                reason: format!(
                    "entry count mismatch: header says {expected_count}, found {actual_count}"
                ),
            });
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
pub(crate) fn compact_with_fs(
    input_ssts: &[&SstReader],
    output_path: &Path,
    fs: &dyn Fs,
    output_sst_number: u64,
    dek: &DataEncryptionKey,
    enc_header: &EncryptionHeader,
) -> Result<SstMetadata, StorageError> {
    let mut merged = std::collections::BTreeMap::new();
    for sst in input_ssts {
        for (key, value) in sst.iter_all() {
            merged.insert(key.clone(), value.clone());
        }
    }

    let live_entries: Vec<(CompositeKey, MemtableValue)> = merged
        .into_iter()
        .filter(|(_, v)| !matches!(v, MemtableValue::Tombstone))
        .collect();

    SstWriter::write_sst_with_fs(
        output_path,
        &live_entries,
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

    if &data[0..4] != SST_MAGIC && &data[0..4] != SST_MAGIC_V2 {
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
        assert_eq!(&raw[0..4], b"HSS2", "new SSTs must use V2 magic");
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
        let read_entries = reader.iter_all();

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
        let all = compacted.iter_all();

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
        assert!(reader.get(&realm, b"key9").is_none());
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
        assert!(reader.range_scan(&realm, b"key7", b"key9").is_empty());
        assert_eq!(reader.range_scan(&realm, b"key0", b"zzz").len(), 2);
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
        assert!(reader.iter_all().is_empty());
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
            CompositeKey::new(realm, b"key1".to_vec()),
            MemtableValue::Data(b"val1".to_vec()),
        )];
        let (dek, enc_header) = test_encryption_context();
        SstWriter::write_sst(&sst_path, &entries, 1, &dek, &enc_header).expect("write_sst");

        // Corrupt a byte in the ciphertext
        let mut raw = std::fs::read(&sst_path).expect("read");
        raw[TOTAL_HEADER_SIZE + 1] ^= 0xFF;
        std::fs::write(&sst_path, &raw).expect("write corrupt");

        let result = SstReader::open(&sst_path, 1, &dek);
        assert!(result.is_err());
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

        let a_entries = reader.iter_realm(&realm_a);
        assert_eq!(a_entries.len(), 2);
        for (k, _) in &a_entries {
            assert!(k.starts_with(b"a-key"), "unexpected key: {k:?}");
        }

        let b_entries = reader.iter_realm(&realm_b);
        assert_eq!(b_entries.len(), 1);
        assert_eq!(b_entries[0].0, b"b-key1".to_vec());

        let ghost = RealmId::generate();
        assert!(reader.iter_realm(&ghost).is_empty());
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
        assert!(compacted.iter_all().is_empty());
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
                reader.get(key.realm_id(), key.key()).is_some(),
                "bloom filter false negative after reopen for key {:?}",
                key.key()
            );
        }
        // Absent key must return None.
        assert!(reader.get(&realm, b"totally-absent").is_none());
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
        assert!(reader.get(&realm_a, b"key1").is_some());
        // realm_b does not own realm_a's keys — must return None
        assert!(reader.get(&realm_b, b"key1").is_none());
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
        let all = compacted.iter_all();
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
            reader.get(&realm, b"banana"),
            Some(MemtableValue::Data(b"v-banana".to_vec()))
        );
        assert_eq!(reader.get(&realm, b"grape"), None);
        assert_eq!(reader.get(&realm, b"fig"), Some(MemtableValue::Tombstone));

        let range = reader.range_scan(&realm, b"banana", b"date");
        assert_eq!(range.len(), 2);
        assert_eq!(range[0].0, b"banana".to_vec());
        assert_eq!(range[1].0, b"cherry".to_vec());

        let ghost = RealmId::generate();
        assert!(reader.range_scan(&ghost, b"a", b"z").is_empty());
        assert_eq!(reader.get(&ghost, b"apple"), None);

        let realm_entries = reader.iter_realm(&realm);
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
}
