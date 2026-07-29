//! Write-ahead log for durable storage of mutations.
//!
//! All WAL records are encrypted at rest using AES-256-GCM envelope encryption.
//! New WAL files start with a 6-byte version header followed by the 76-byte
//! encryption header. Legacy files (v0) that lack the version header are
//! migrated in-place on first open.
//!
//! On-disk layout (v1, default for new files):
//! ```text
//! VERSION HEADER (6 bytes):
//!   [4B] Magic: b"HWAL"
//!   [2B] Version: 0x0001 (u16 LE)
//!
//! ENCRYPTION HEADER (76 bytes):
//!   [16B] KEK identifier
//!   [12B] Nonce for DEK wrapping
//!   [32B] DEK ciphertext
//!   [16B] GCM auth tag
//!
//! RECORDS (starting at byte 82):
//!   Per record:
//!     [4B] encrypted payload length (u32 LE, includes GCM tag)
//!     [NB] encrypted payload (AES-256-GCM ciphertext + 16B tag)
//!     [4B] CRC32 of encrypted payload bytes
//! ```
//!
//! Payload (plaintext, before encryption):
//! ```text
//! [8 bytes: timestamp i64 LE]
//! [16 bytes: realm UUID]
//! [1 byte: operation (0=Put, 1=Delete, 2=Batch)]
//! [4 bytes: key length u32 LE]
//! [N bytes: key]
//! [4 bytes: value length u32 LE]
//! [M bytes: value]
//! ```

use crate::core::{RealmId, Timestamp};
use crate::storage::encryption::{
    self, counter_nonce, DataEncryptionKey, EncryptionHeader, KekId, ENCRYPTION_HEADER_SIZE,
};
use crate::storage::error::StorageError;
use crate::storage::fs::{Fs, FsFile};
use crate::storage::migrations::{self, WAL_MAGIC, WAL_VERSION_CURRENT, WAL_VERSION_HEADER_SIZE};
use std::collections::VecDeque;
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use uuid::Uuid;

/// The type of mutation in a WAL entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalOperation {
    /// Insert or update a key-value pair.
    Put,
    /// Remove a key.
    Delete,
    /// Atomic multi-entry write. The outer `WalEntry`'s `value` field encodes
    /// the nested list of `(sub_op, key, value)` tuples; its `key` field is
    /// unused (empty). Readers that do not recognise this opcode must treat
    /// the record as corrupt and stop replay — preserving the all-or-nothing
    /// guarantee on downgrade.
    Batch,
}

/// A single entry in the write-ahead log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalEntry {
    /// When this mutation occurred.
    pub timestamp: Timestamp,
    /// Which realm owns this data.
    pub realm_id: RealmId,
    /// The type of mutation.
    pub operation: WalOperation,
    /// The key being mutated.
    pub key: Vec<u8>,
    /// The value (empty for Delete operations).
    pub value: Vec<u8>,
}

impl WalEntry {
    /// Serializes this entry into its binary payload representation.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + 16 + 1 + 4 + self.key.len() + 4 + self.value.len());

        // Timestamp: i64 LE
        buf.extend_from_slice(&self.timestamp.as_micros().to_le_bytes());

        // Realm UUID: 16 bytes
        buf.extend_from_slice(self.realm_id.as_uuid().as_bytes());

        // Operation: 1 byte
        let op_byte: u8 = match self.operation {
            WalOperation::Put => 0,
            WalOperation::Delete => 1,
            WalOperation::Batch => 2,
        };
        buf.push(op_byte);

        // Key: length-prefixed
        #[allow(clippy::cast_possible_truncation)]
        let key_len = self.key.len() as u32;
        buf.extend_from_slice(&key_len.to_le_bytes());
        buf.extend_from_slice(&self.key);

        // Value: length-prefixed
        #[allow(clippy::cast_possible_truncation)]
        let val_len = self.value.len() as u32;
        buf.extend_from_slice(&val_len.to_le_bytes());
        buf.extend_from_slice(&self.value);

        buf
    }

    /// Deserializes a binary payload into a `WalEntry`.
    ///
    /// Returns `Err` for any malformed or truncated input. This function
    /// is guaranteed not to panic on arbitrary input.
    pub fn deserialize(data: &[u8]) -> Result<Self, StorageError> {
        // Minimum size: 8 (ts) + 16 (uuid) + 1 (op) + 4 (key_len) + 4 (val_len) = 33
        if data.len() < 33 {
            return Err(StorageError::DeserializationFailed {
                reason: format!("payload too short: {} bytes", data.len()),
            });
        }

        let mut pos = 0;

        // Timestamp
        let ts_bytes: [u8; 8] =
            data[pos..pos + 8]
                .try_into()
                .map_err(|_| StorageError::DeserializationFailed {
                    reason: "invalid timestamp bytes".to_string(),
                })?;
        let timestamp = Timestamp::from_micros(i64::from_le_bytes(ts_bytes));
        pos += 8;

        // Realm UUID
        let uuid_bytes: [u8; 16] =
            data[pos..pos + 16]
                .try_into()
                .map_err(|_| StorageError::DeserializationFailed {
                    reason: "invalid UUID bytes".to_string(),
                })?;
        let realm_id = RealmId::new(Uuid::from_bytes(uuid_bytes));
        pos += 16;

        // Operation
        let operation = match data[pos] {
            0 => WalOperation::Put,
            1 => WalOperation::Delete,
            2 => WalOperation::Batch,
            other => {
                return Err(StorageError::DeserializationFailed {
                    reason: format!("unknown operation byte: {other}"),
                })
            }
        };
        pos += 1;

        // Key
        if data.len() < pos + 4 {
            return Err(StorageError::DeserializationFailed {
                reason: "truncated key length".to_string(),
            });
        }
        let key_len_bytes: [u8; 4] =
            data[pos..pos + 4]
                .try_into()
                .map_err(|_| StorageError::DeserializationFailed {
                    reason: "invalid key length bytes".to_string(),
                })?;
        let key_len = u32::from_le_bytes(key_len_bytes) as usize;
        pos += 4;

        if data.len() < pos + key_len {
            return Err(StorageError::DeserializationFailed {
                reason: "truncated key data".to_string(),
            });
        }
        let key = data[pos..pos + key_len].to_vec();
        pos += key_len;

        // Value
        if data.len() < pos + 4 {
            return Err(StorageError::DeserializationFailed {
                reason: "truncated value length".to_string(),
            });
        }
        let val_len_bytes: [u8; 4] =
            data[pos..pos + 4]
                .try_into()
                .map_err(|_| StorageError::DeserializationFailed {
                    reason: "invalid value length bytes".to_string(),
                })?;
        let val_len = u32::from_le_bytes(val_len_bytes) as usize;
        pos += 4;

        if data.len() < pos + val_len {
            return Err(StorageError::DeserializationFailed {
                reason: "truncated value data".to_string(),
            });
        }
        let value = data[pos..pos + val_len].to_vec();

        Ok(WalEntry {
            timestamp,
            realm_id,
            operation,
            key,
            value,
        })
    }
}

/// A single sub-operation inside a `WalOperation::Batch` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchEntry {
    /// Put or Delete. Batch is disallowed — batches cannot nest.
    pub operation: WalOperation,
    /// Target key within the batch's realm.
    pub key: Vec<u8>,
    /// Value (empty for Delete).
    pub value: Vec<u8>,
}

/// Encodes a sequence of batch entries into the `value` field of a batch
/// `WalEntry`. The outer record's timestamp + realm apply to every sub-entry.
///
/// Layout:
/// ```text
/// [4 bytes: count (u32 LE)]
/// for each entry:
///   [1 byte: sub-op (0=Put, 1=Delete)]
///   [4 bytes: key length (u32 LE)]
///   [N bytes: key]
///   [4 bytes: value length (u32 LE)]
///   [M bytes: value]
/// ```
pub fn encode_batch_payload(entries: &[BatchEntry]) -> Result<Vec<u8>, StorageError> {
    let mut buf = Vec::with_capacity(4 + entries.len() * 16);
    #[allow(clippy::cast_possible_truncation)]
    let count = entries.len() as u32;
    buf.extend_from_slice(&count.to_le_bytes());
    for entry in entries {
        let sub_op: u8 = match entry.operation {
            WalOperation::Put => 0,
            WalOperation::Delete => 1,
            WalOperation::Batch => {
                return Err(StorageError::DeserializationFailed {
                    reason: "batches cannot nest".to_string(),
                })
            }
        };
        buf.push(sub_op);
        #[allow(clippy::cast_possible_truncation)]
        let k_len = entry.key.len() as u32;
        buf.extend_from_slice(&k_len.to_le_bytes());
        buf.extend_from_slice(&entry.key);
        #[allow(clippy::cast_possible_truncation)]
        let v_len = entry.value.len() as u32;
        buf.extend_from_slice(&v_len.to_le_bytes());
        buf.extend_from_slice(&entry.value);
    }
    Ok(buf)
}

/// Inverse of [`encode_batch_payload`]. Returns `Err` for any truncation or
/// malformed sub-op so the WAL reader falls back to its "stop at corruption"
/// policy — preserving all-or-nothing semantics.
pub fn decode_batch_payload(data: &[u8]) -> Result<Vec<BatchEntry>, StorageError> {
    if data.len() < 4 {
        return Err(StorageError::DeserializationFailed {
            reason: "batch payload missing count".to_string(),
        });
    }
    let count_bytes: [u8; 4] =
        data[0..4]
            .try_into()
            .map_err(|_| StorageError::DeserializationFailed {
                reason: "invalid batch count".to_string(),
            })?;
    let count = u32::from_le_bytes(count_bytes) as usize;
    let mut pos = 4usize;
    // Cap to prevent OOM from a corrupted/malicious count field.
    // Minimum sub-entry: 1 (op) + 4 (key_len) + 4 (val_len) = 9 bytes.
    const MIN_BATCH_ENTRY_SIZE: usize = 9;
    let count = count.min(data.len().saturating_sub(4) / MIN_BATCH_ENTRY_SIZE);
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        if pos + 1 > data.len() {
            return Err(StorageError::DeserializationFailed {
                reason: "truncated batch sub-op".to_string(),
            });
        }
        let operation = match data[pos] {
            0 => WalOperation::Put,
            1 => WalOperation::Delete,
            other => {
                return Err(StorageError::DeserializationFailed {
                    reason: format!("invalid batch sub-op byte: {other}"),
                })
            }
        };
        pos += 1;

        if pos + 4 > data.len() {
            return Err(StorageError::DeserializationFailed {
                reason: "truncated batch key length".to_string(),
            });
        }
        let k_len_bytes: [u8; 4] =
            data[pos..pos + 4]
                .try_into()
                .map_err(|_| StorageError::DeserializationFailed {
                    reason: "invalid batch key length".to_string(),
                })?;
        let k_len = u32::from_le_bytes(k_len_bytes) as usize;
        pos += 4;
        if pos + k_len > data.len() {
            return Err(StorageError::DeserializationFailed {
                reason: "truncated batch key".to_string(),
            });
        }
        let key = data[pos..pos + k_len].to_vec();
        pos += k_len;

        if pos + 4 > data.len() {
            return Err(StorageError::DeserializationFailed {
                reason: "truncated batch value length".to_string(),
            });
        }
        let v_len_bytes: [u8; 4] =
            data[pos..pos + 4]
                .try_into()
                .map_err(|_| StorageError::DeserializationFailed {
                    reason: "invalid batch value length".to_string(),
                })?;
        let v_len = u32::from_le_bytes(v_len_bytes) as usize;
        pos += 4;
        if pos + v_len > data.len() {
            return Err(StorageError::DeserializationFailed {
                reason: "truncated batch value".to_string(),
            });
        }
        let value = data[pos..pos + v_len].to_vec();
        pos += v_len;

        entries.push(BatchEntry {
            operation,
            key,
            value,
        });
    }
    Ok(entries)
}

/// Byte offset of the first WAL record in a v1 (or migrated) file.
/// = `WAL_VERSION_HEADER_SIZE` (6) + `ENCRYPTION_HEADER_SIZE` (76) = 82.
const V1_RECORD_OFFSET: u64 = (WAL_VERSION_HEADER_SIZE + ENCRYPTION_HEADER_SIZE) as u64;

/// Controls when the WAL fsyncs to disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncMode {
    /// Fsync after every write (production default).
    EveryWrite,
    /// No fsync — faster but unsafe. For development/testing only.
    None,
}

/// Configuration for the write-ahead log.
#[derive(Debug, Clone)]
pub struct WalConfig {
    /// Maximum WAL file size in bytes before rotation.
    pub max_size: u64,
    /// Fsync policy.
    pub sync_mode: SyncMode,
}

impl Default for WalConfig {
    fn default() -> Self {
        Self {
            max_size: 64 * 1024 * 1024, // 64 MiB
            sync_mode: SyncMode::EveryWrite,
        }
    }
}

/// Rotation state: per-segment DEK, encryption header, and nonce counter.
///
/// All three fields are protected by a single `Mutex` so the DEK swap and
/// counter reset in `rotate_locked` are one atomic critical section, closing
/// the (old-DEK, nonce-0) reuse window described in HEA-SEC-08.
struct RotationState {
    dek: DataEncryptionKey,
    enc_header: EncryptionHeader,
    /// Monotonic record counter used as the AES-GCM nonce input.
    /// Reset to zero atomically with the DEK swap during rotation.
    record_counter: u64,
}

// ─── Group-commit types ──────────────────────────────────────────────────────

/// A single writer's entry waiting to be committed by the group leader.
struct GroupSlot {
    /// Pre-serialised WAL entry payload (plaintext before encryption).
    plaintext: Vec<u8>,
    /// Outcome written by the leader once the entry is written + synced.
    state: Mutex<GroupSlotState>,
    /// Notifies the owning writer when `state.done` flips to `true`.
    cv: Condvar,
}

/// Outcome state inside a `GroupSlot`.
struct GroupSlotState {
    /// `true` once the leader has written and synced (or errored) this slot.
    done: bool,
    /// `None` = success; `Some(msg)` = the error message from the commit.
    error: Option<String>,
}

/// Shared group-commit queue and leader flag.
struct GroupState {
    /// Writers waiting for the current leader to commit their entries.
    pending: VecDeque<Arc<GroupSlot>>,
    /// `true` while a leader is active (holding `file` mutex, writing+syncing).
    leader_active: bool,
}

// ─────────────────────────────────────────────────────────────────────────────

/// Write-ahead log providing durable, ordered storage of mutations.
///
/// Thread-safe via `std::sync::Mutex`. WAL writes are blocking I/O and
/// should be called from `tokio::task::spawn_blocking`.
pub struct Wal {
    file: Mutex<Box<dyn FsFile>>,
    path: PathBuf,
    config: WalConfig,
    /// Rotation state (DEK, enc header, and nonce counter), locked together.
    ///
    /// The counter lives in `RotationState` rather than as a separate
    /// `AtomicU64` so the DEK swap and counter reset in `rotate_locked` are
    /// a single atomic critical section (HEA-SEC-08).
    rotation: Mutex<RotationState>,
    /// Key encryption key (unused currently, reserved for key rotation).
    #[allow(dead_code)]
    kek: encryption::KeyEncryptionKey,
    /// KEK identifier.
    #[allow(dead_code)]
    kek_id: KekId,
    /// Retained for potential re-open after rotation in future phases.
    #[allow(dead_code)]
    fs: Arc<dyn Fs>,
    /// Byte offset of the first WAL record in the file.
    /// Always `V1_RECORD_OFFSET` (82) for files created or migrated by this binary.
    record_start: u64,
    /// Called inside `rotate_locked` before the WAL is truncated.
    ///
    /// The storage engine injects a memtable-to-SST flush callback here so
    /// that all in-memory data is durable before the WAL segment is reused.
    /// Without this, a `kill -9` between truncation and the next regular
    /// memtable flush would lose every write since the last SST flush.
    pre_rotate_fn: Option<Arc<dyn Fn() -> Result<(), StorageError> + Send + Sync>>,
    /// Group-commit queue and leader flag.
    ///
    /// Writers push a `GroupSlot` here before competing for the file mutex.
    /// The leader drains the queue, writes and syncs all entries under the
    /// file mutex, then signals each slot.  `SyncMode::None` bypasses this
    /// path entirely.
    group: Mutex<GroupState>,
    /// Cumulative count of successful `sync_all` calls on this WAL.
    ///
    /// Incremented after each `commit_batch` sync completes.  Used by the
    /// saturation-throughput benchmark to measure fsyncs/write under group
    /// commit.  Off the hot path (relaxed ordering is sufficient).
    sync_count: Arc<AtomicU64>,
}

/// Outcome of scanning the record region of a WAL segment.
struct RecordScan {
    /// Entries that replayed cleanly, in file order.
    entries: Vec<WalEntry>,
    /// Number of entries recovered — the next record's nonce counter value.
    count: u64,
    /// Byte length of the valid record prefix, relative to the region start.
    /// Anything beyond this is a torn or corrupt tail.
    valid_len: usize,
}

/// Scans the record region of a WAL segment, stopping at the first record that
/// is torn, CRC-invalid, or undecodable.
///
/// Both replay ([`Wal::read_all`]) and recovery ([`Wal::open_with_fs`]) go
/// through this function so the "last valid record" boundary they compute can
/// never diverge. A divergence is exactly what let post-recovery appends land
/// beyond a corrupt tail and then vanish on the next restart (HEA-1853).
fn scan_records(region: &[u8], dek: &DataEncryptionKey) -> Result<RecordScan, StorageError> {
    let mut entries = Vec::new();
    let mut pos: usize = 0;
    let mut valid_len: usize = 0;
    let mut record_num: u64 = 0;

    while pos + 4 <= region.len() {
        let record_start = pos;

        // Read payload length
        let len_bytes: [u8; 4] = match region[pos..pos + 4].try_into() {
            Ok(b) => b,
            Err(_) => break,
        };
        let payload_len = u32::from_le_bytes(len_bytes) as usize;
        pos += 4;

        // Check we have enough data for payload + CRC.
        // Torn writes (incomplete record with partial ciphertext
        // or missing CRC) are intentionally silent truncation:
        // the process crashed mid-write, and we return the valid
        // prefix from before the crash.
        if pos + payload_len + 4 > region.len() {
            break;
        }

        let ciphertext = &region[pos..pos + payload_len];
        pos += payload_len;

        // Read and verify CRC (over ciphertext)
        let crc_bytes: [u8; 4] = match region[pos..pos + 4].try_into() {
            Ok(b) => b,
            Err(_) => break,
        };
        let stored_crc = u32::from_le_bytes(crc_bytes);
        let computed_crc = crc32fast::hash(ciphertext);
        pos += 4;

        if stored_crc != computed_crc {
            // CRC mismatch at any position means the record was not
            // durably written. Stop replay here and discard everything
            // that follows — entries after a corrupt record cannot be
            // applied safely since they may depend on state that the
            // corrupt entry would have established.
            //
            // This covers both the tail-truncation case (process crashed
            // mid-write, no records follow) and the concurrent write-fault
            // case (another thread appended records after the crash, so
            // bytes follow the corrupt entry). Both require the same
            // response: truncate to the last fully-verified record.
            if pos < region.len() {
                tracing::warn!(
                    offset = record_start,
                    "WAL replay: CRC mismatch with trailing data — \
                     truncating to last good record (possible concurrent \
                     write fault or unclean shutdown)"
                );
            }
            break;
        }

        // Decrypt payload — AEAD tag failure surfaces as error
        // unconditionally. GCM authentication failure means the
        // ciphertext was tampered with (or the wrong key/nonce/
        // AAD was used). None of those happen during clean
        // truncation.
        let nonce = counter_nonce(record_num);
        let aad = record_num.to_le_bytes();
        let plaintext = encryption::decrypt_section(ciphertext, dek, &nonce, &aad)?;

        match WalEntry::deserialize(&plaintext) {
            Ok(entry) => entries.push(entry),
            Err(_) => break, // Deserialization failure — stop
        }

        record_num += 1;
        valid_len = pos;
    }

    Ok(RecordScan {
        entries,
        count: record_num,
        valid_len,
    })
}

/// Rewrites a WAL segment so it contains only `entries`, discarding a corrupt
/// or torn tail, and returns the segment's new DEK and encryption header.
///
/// Without this, recovery would park the append cursor at physical EOF — behind
/// the garbage — so the next replay would stop before reaching anything written
/// after recovery, silently losing it under a corruption-then-crash double
/// fault (HEA-1853).
///
/// The rebuild re-keys (fresh DEK, nonce counter restarting at zero) for the
/// same reason `Wal::rotate_locked` does (HEA-SEC-08): discarding records while
/// keeping the old DEK would encrypt a new record under the (DEK, nonce) pair
/// the discarded corrupt record already consumed.
///
/// The new segment is staged and renamed into place, so a crash partway through
/// leaves the original file intact and recovery stays retryable.
fn rebuild_truncated_segment(
    path: &Path,
    fs: &dyn Fs,
    kek: &encryption::KeyEncryptionKey,
    kek_id: KekId,
    entries: &[WalEntry],
    size_hint: usize,
) -> Result<(DataEncryptionKey, EncryptionHeader), StorageError> {
    let new_dek = encryption::generate_dek()?;
    let new_header = encryption::wrap_dek(&new_dek, kek, kek_id)?;

    let mut rebuilt = Vec::with_capacity(size_hint);
    rebuilt.extend_from_slice(&WAL_MAGIC);
    rebuilt.extend_from_slice(&WAL_VERSION_CURRENT.to_le_bytes());
    rebuilt.extend_from_slice(&new_header.to_bytes());

    for (i, entry) in entries.iter().enumerate() {
        let record_num = u64::try_from(i).map_err(|_| StorageError::Crypto {
            reason: "WAL record count exceeds u64".to_string(),
        })?;
        let plaintext = entry.serialize();
        let nonce = counter_nonce(record_num);
        let aad = record_num.to_le_bytes();
        let ciphertext = encryption::encrypt_section(&plaintext, &new_dek, &nonce, &aad)?;
        #[allow(clippy::cast_possible_truncation)]
        let payload_len = ciphertext.len() as u32;
        rebuilt.extend_from_slice(&payload_len.to_le_bytes());
        rebuilt.extend_from_slice(&ciphertext);
        rebuilt.extend_from_slice(&crc32fast::hash(&ciphertext).to_le_bytes());
    }

    let staging = path.with_extension("wal-recovering");
    {
        let mut staged = fs.create(&staging)?;
        staged.write_all(&rebuilt)?;
        staged.sync_all()?;
    }
    fs.rename(&staging, path)?;
    // Fsync the parent directory so the rename (new inode) is durable. Without
    // this, a power loss after post-recovery appends are fsync'd but before the
    // directory entry commits would resolve the OLD inode on restart, replaying
    // the corrupt tail and losing those appends — the HEA-1853 loss class
    // through a narrower window (HEA-1855).
    if let Some(parent) = path.parent() {
        fs.sync_dir(parent)?;
    }

    Ok((new_dek, new_header))
}

impl Wal {
    /// Opens or creates a WAL file at the given path using a custom filesystem.
    ///
    /// Used by the simulation crate to inject faults via a `FaultFs`.
    pub fn open_with_fs(
        path: &Path,
        config: WalConfig,
        fs: Arc<dyn Fs>,
        kek: &encryption::KeyEncryptionKey,
        kek_id: KekId,
    ) -> Result<Self, StorageError> {
        let mut file = fs.open_append(path)?;
        let file_size = file.seek(SeekFrom::End(0))?;

        let (dek, enc_header, record_count) = if file_size == 0 {
            // New file: write version header then encryption header.
            let dek = encryption::generate_dek()?;
            let enc_header = encryption::wrap_dek(&dek, kek, kek_id)?;
            file.write_all(&WAL_MAGIC)?;
            file.write_all(&WAL_VERSION_CURRENT.to_le_bytes())?;
            file.write_all(&enc_header.to_bytes())?;
            file.sync_all()?;
            // Fsync the parent directory so the freshly created segment's
            // directory entry is durable; otherwise a power loss before the dir
            // update commits can make the whole file vanish on restart
            // (HEA-1855).
            if let Some(parent) = path.parent() {
                fs.sync_dir(parent)?;
            }
            (dek, enc_header, 0u64)
        } else {
            // Existing file: read all bytes, detect format version, migrate if needed.
            let mut all_data = Vec::new();
            file.seek(SeekFrom::Start(0))?;
            file.read_to_end(&mut all_data)?;

            // Detect v0 (no magic) vs v1+ (starts with HWAL).
            let all_data = if all_data.starts_with(&WAL_MAGIC) {
                // Versioned file — validate version.
                if all_data.len() < WAL_VERSION_HEADER_SIZE {
                    return Err(StorageError::Crypto {
                        reason: "WAL version header is truncated".to_string(),
                    });
                }
                let version = u16::from_le_bytes([all_data[4], all_data[5]]);
                if version > WAL_VERSION_CURRENT {
                    return Err(StorageError::UnsupportedWalVersion { found: version });
                }
                all_data
            } else {
                // Legacy v0 file — migrate to current version in-place.
                let migrated = migrations::apply_migrations(&all_data, 0, WAL_VERSION_CURRENT)?;
                file.set_len(0)?;
                file.write_all(&migrated)?;
                file.sync_all()?;
                migrated
            };

            // After detection/migration, layout is: [6B ver][76B enc][records...].
            let enc_start = WAL_VERSION_HEADER_SIZE;
            let enc_end = enc_start + ENCRYPTION_HEADER_SIZE;

            if all_data.len() < enc_end {
                return Err(StorageError::Crypto {
                    reason: format!("WAL file too small for headers: {} bytes", all_data.len()),
                });
            }

            let header_arr: [u8; ENCRYPTION_HEADER_SIZE] = all_data[enc_start..enc_end]
                .try_into()
                .map_err(|_| StorageError::Crypto {
                    reason: "failed to read WAL encryption header".to_string(),
                })?;

            let enc_header = EncryptionHeader::from_bytes(&header_arr);
            let dek = encryption::unwrap_dek(&enc_header, kek)?;

            // Replay the record region with exactly the validation `read_all`
            // uses, so the append cursor lands on the same boundary replay
            // stops at.
            let record_data = &all_data[enc_end..];
            let scan = scan_records(record_data, &dek)?;

            if scan.valid_len == record_data.len() {
                file.seek(SeekFrom::End(0))?;
                (dek, enc_header, scan.count)
            } else {
                // Corrupt or torn tail (HEA-1853) — rebuild the segment from
                // the surviving prefix. See `rebuild_truncated_segment`.
                tracing::warn!(
                    discarded_bytes = record_data.len() - scan.valid_len,
                    recovered_records = scan.count,
                    "WAL recovery: truncating corrupt tail and re-keying segment"
                );

                let (new_dek, new_header) = rebuild_truncated_segment(
                    path,
                    fs.as_ref(),
                    kek,
                    kek_id,
                    &scan.entries,
                    enc_end + scan.valid_len,
                )?;

                file = fs.open_append(path)?;
                file.seek(SeekFrom::End(0))?;
                (new_dek, new_header, scan.count)
            }
        };

        Ok(Self {
            file: Mutex::new(file),
            path: path.to_path_buf(),
            config,
            rotation: Mutex::new(RotationState {
                dek,
                enc_header,
                record_counter: record_count,
            }),
            pre_rotate_fn: None,
            kek: kek.clone_key(),
            kek_id,
            fs,
            record_start: V1_RECORD_OFFSET,
            group: Mutex::new(GroupState {
                pending: VecDeque::new(),
                leader_active: false,
            }),
            sync_count: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Returns a copy of the encryption header for this WAL segment.
    #[allow(dead_code)]
    pub(crate) fn enc_header(&self) -> EncryptionHeader {
        self.rotation
            .lock()
            .expect("rotation mutex poisoned")
            .enc_header
            .clone()
    }

    /// Appends an entry to the WAL.
    ///
    /// Convenience wrapper around [`Wal::append_with_pre_rotate`] with a no-op
    /// pre-rotate callback. Use when there is no pre-rotation work needed
    /// (e.g., WAL-only tests that don't care about the memtable).
    pub fn append(&self, entry: &WalEntry) -> Result<(), StorageError> {
        self.append_with_pre_rotate(entry, || Ok(()))
    }

    /// Appends an entry to the WAL, calling `pre_rotate` before rotating if
    /// rotation is needed.
    ///
    /// When `SyncMode::EveryWrite` is configured (the production default) this
    /// uses **leader/follower group commit**: multiple concurrent callers share
    /// a single `fsync` call rather than each paying a private one.  The leader
    /// — whichever thread first finds the queue empty — writes every pending
    /// entry under the file mutex and calls `sync_all` once.  Followers wait on
    /// a per-slot condvar and return as soon as their bytes are covered.
    ///
    /// Durability guarantee: no writer returns `Ok` until a `sync_all` that
    /// covered its bytes has completed.
    ///
    /// `pre_rotate` fires while the WAL file mutex is held (exactly as before);
    /// with group commit the leader calls the per-batch `pre_rotate` on the
    /// first batch that triggers rotation.
    pub fn append_with_pre_rotate<F>(
        &self,
        entry: &WalEntry,
        pre_rotate: F,
    ) -> Result<(), StorageError>
    where
        F: FnOnce() -> Result<(), StorageError>,
    {
        let plaintext = entry.serialize();

        // ── Fast path: SyncMode::None (dev / test only) ───────────────────
        if self.config.sync_mode != SyncMode::EveryWrite {
            return self.write_entry_no_sync(plaintext, pre_rotate);
        }

        // ── Group-commit path (SyncMode::EveryWrite) ──────────────────────
        //
        // Push a slot to the shared queue.  The first writer to find the queue
        // empty becomes the leader and runs the commit loop; all others wait on
        // their slot's condvar until the leader marks them done.
        let slot = Arc::new(GroupSlot {
            plaintext,
            state: Mutex::new(GroupSlotState {
                done: false,
                error: None,
            }),
            cv: Condvar::new(),
        });

        let am_leader = {
            let mut gs = self
                .group
                .lock()
                .map_err(|_| StorageError::Io(std::io::Error::other("WAL group mutex poisoned")))?;
            gs.pending.push_back(Arc::clone(&slot));
            if gs.leader_active {
                false
            } else {
                gs.leader_active = true;
                true
            }
        };

        if am_leader {
            // Propagate only hard (unrecoverable) failures from the leader
            // loop.  Per-entry I/O errors travel through slot.state.error.
            self.lead_group_commit(pre_rotate)?;
        }

        // Wait for our slot — either set by us as leader, or by another leader.
        let mut state = slot
            .state
            .lock()
            .map_err(|_| StorageError::Io(std::io::Error::other("WAL slot mutex poisoned")))?;
        while !state.done {
            state = slot.cv.wait(state).map_err(|_| {
                StorageError::Io(std::io::Error::other("WAL slot condvar poisoned"))
            })?;
        }
        match state.error.take() {
            None => Ok(()),
            Some(msg) => Err(StorageError::Io(std::io::Error::other(msg))),
        }
    }

    // ── Group-commit internals ────────────────────────────────────────────────

    /// Writes one entry directly to the file without fsync (`SyncMode::None`).
    ///
    /// The file mutex is held for the whole operation to preserve nonce ordering.
    fn write_entry_no_sync<F>(&self, plaintext: Vec<u8>, pre_rotate: F) -> Result<(), StorageError>
    where
        F: FnOnce() -> Result<(), StorageError>,
    {
        let mut file = self
            .file
            .lock()
            .map_err(|_| StorageError::Io(std::io::Error::other("WAL mutex poisoned")))?;

        let file_size = file.seek(SeekFrom::End(0))?;
        #[allow(clippy::cast_possible_truncation)]
        let approx_record_size = 4 + plaintext.len() as u64 + encryption::TAG_SIZE as u64 + 4;
        if self.config.max_size > 0 && file_size + approx_record_size > self.config.max_size {
            pre_rotate()?;
            self.rotate_locked(&mut **file)?;
        }

        let (nonce, aad, dek) = {
            let mut rot = self
                .rotation
                .lock()
                .map_err(|_| StorageError::Io(std::io::Error::other("rotation mutex poisoned")))?;
            let record_num = rot.record_counter;
            rot.record_counter += 1;
            let nonce = counter_nonce(record_num);
            let aad = record_num.to_le_bytes();
            let mut dek_bytes = [0u8; 32];
            dek_bytes.copy_from_slice(rot.dek.as_bytes());
            (nonce, aad, DataEncryptionKey::from_bytes(dek_bytes))
        };

        let ciphertext = encryption::encrypt_section(&plaintext, &dek, &nonce, &aad)?;
        let crc = crc32fast::hash(&ciphertext);

        #[allow(clippy::cast_possible_truncation)]
        let payload_len = ciphertext.len() as u32;
        file.write_all(&payload_len.to_le_bytes())?;
        file.write_all(&ciphertext)?;
        file.write_all(&crc.to_le_bytes())?;

        // Intentionally no fsync — this path is SyncMode::None (dev/test only).
        Ok(())
    }

    /// Leader commit loop: drain the pending queue and commit each batch under
    /// the file mutex with a single `sync_all`.  Loops until the queue is empty,
    /// then releases the leader role atomically with the empty check.
    ///
    /// `pre_rotate` is forwarded to the first batch only (it is `FnOnce`);
    /// subsequent batches rely on `rotate_locked` calling `pre_rotate_fn`.
    fn lead_group_commit<F>(&self, pre_rotate: F) -> Result<(), StorageError>
    where
        F: FnOnce() -> Result<(), StorageError>,
    {
        let mut pre_rotate = Some(pre_rotate);

        loop {
            // Drain atomically.  If the queue is empty, release leadership and
            // exit — the release is inside the lock so no writer can push and
            // miss the leader before we exit.
            let batch: Vec<Arc<GroupSlot>> = {
                let mut gs = self.group.lock().map_err(|_| {
                    StorageError::Io(std::io::Error::other("WAL group mutex poisoned"))
                })?;
                let b: Vec<_> = gs.pending.drain(..).collect();
                if b.is_empty() {
                    gs.leader_active = false;
                    return Ok(());
                }
                b
            };

            // Write every slot in the batch + ONE fsync.
            self.commit_batch(&batch, pre_rotate.take())?;

            // Loop: drain any writers that arrived while we were committing.
        }
    }

    /// Writes every slot in `batch` to the WAL file and calls `sync_all` once.
    ///
    /// All I/O runs under the file mutex so writes are in record-number order
    /// and rotation is atomic with respect to concurrent appenders.  Each slot
    /// is marked done (success or error string) before this function returns;
    /// per-slot errors never propagate out of here so the leader loop can
    /// continue with subsequent batches.
    fn commit_batch<F>(
        &self,
        batch: &[Arc<GroupSlot>],
        pre_rotate: Option<F>,
    ) -> Result<(), StorageError>
    where
        F: FnOnce() -> Result<(), StorageError>,
    {
        // All writes + the single fsync happen under the file mutex.
        let commit_result: Result<(), StorageError> = (|| {
            let mut file = self
                .file
                .lock()
                .map_err(|_| StorageError::Io(std::io::Error::other("WAL file mutex poisoned")))?;

            // Estimate total on-disk size to decide whether to rotate before
            // assigning any record numbers (rotation resets the counter to 0).
            let file_size = file.seek(SeekFrom::End(0))?;
            #[allow(clippy::cast_possible_truncation)]
            let approx_total: u64 = batch
                .iter()
                .map(|s| 4 + s.plaintext.len() as u64 + encryption::TAG_SIZE as u64 + 4)
                .sum();

            if self.config.max_size > 0 && file_size + approx_total > self.config.max_size {
                if let Some(f) = pre_rotate {
                    f()?;
                }
                self.rotate_locked(&mut **file)?;
            }

            // Assign record numbers and write entries in queue order so that
            // nonce ordering on disk matches the record-number sequence.  The
            // rotation mutex is locked once per entry inside the file-mutex
            // critical section to uphold HEA-SEC-08.
            for slot in batch {
                let (nonce, aad, dek) = {
                    let mut rot = self.rotation.lock().map_err(|_| {
                        StorageError::Io(std::io::Error::other("rotation mutex poisoned"))
                    })?;
                    let record_num = rot.record_counter;
                    rot.record_counter += 1;
                    let nonce = counter_nonce(record_num);
                    let aad = record_num.to_le_bytes();
                    let mut dek_bytes = [0u8; 32];
                    dek_bytes.copy_from_slice(rot.dek.as_bytes());
                    (nonce, aad, DataEncryptionKey::from_bytes(dek_bytes))
                };

                let ciphertext = encryption::encrypt_section(&slot.plaintext, &dek, &nonce, &aad)?;
                let crc = crc32fast::hash(&ciphertext);

                #[allow(clippy::cast_possible_truncation)]
                let payload_len = ciphertext.len() as u32;
                file.write_all(&payload_len.to_le_bytes())?;
                file.write_all(&ciphertext)?;
                file.write_all(&crc.to_le_bytes())?;
            }

            // ONE fsync for the entire group — the group-commit throughput win.
            file.sync_all()?;
            self.sync_count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })();

        // Propagate the outcome to every slot; errors travel as strings so
        // callers receive a typed `StorageError::Io` with a message.
        let err_msg = commit_result.as_ref().err().map(|e| e.to_string());
        for slot in batch {
            if let Ok(mut state) = slot.state.lock() {
                state.done = true;
                state.error = err_msg.clone();
                slot.cv.notify_one();
            }
        }

        // Per-entry errors are communicated through the slot; only return Err
        // for hard failures that prevent signalling (mutex poisoning).
        Ok(())
    }

    /// Reads all valid entries from the WAL.
    ///
    /// Stops at the first corrupted or incomplete record, returning only
    /// the valid prefix. This is the expected recovery behavior.
    pub fn read_all(&self) -> Result<Vec<WalEntry>, StorageError> {
        let mut file = self
            .file
            .lock()
            .map_err(|_| StorageError::Io(std::io::Error::other("WAL mutex poisoned")))?;

        // Snapshot the DEK for this read pass
        let dek = {
            let rot = self
                .rotation
                .lock()
                .map_err(|_| StorageError::Io(std::io::Error::other("rotation mutex poisoned")))?;
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(rot.dek.as_bytes());
            DataEncryptionKey::from_bytes(bytes)
        };

        // Skip version + encryption headers; seek directly to the first record.
        let file_size = file.seek(SeekFrom::End(0))?;
        if file_size <= self.record_start {
            return Ok(Vec::new());
        }

        let mut all_data = Vec::new();
        file.seek(SeekFrom::Start(self.record_start))?;
        file.read_to_end(&mut all_data)?;

        Ok(scan_records(&all_data, &dek)?.entries)
    }

    /// Forces an fsync of the WAL file.
    pub fn sync(&self) -> Result<(), StorageError> {
        let file = self
            .file
            .lock()
            .map_err(|_| StorageError::Io(std::io::Error::other("WAL mutex poisoned")))?;
        file.sync_all()?;
        Ok(())
    }

    /// Returns the cumulative number of successful `sync_all` calls on this WAL.
    ///
    /// Useful for benchmarking group-commit efficiency: dividing this by the
    /// number of committed writes gives the fsyncs-per-write ratio.
    pub fn sync_count(&self) -> u64 {
        self.sync_count.load(Ordering::Relaxed)
    }

    /// Registers a callback that is invoked inside `rotate_locked` before the
    /// WAL segment is truncated.
    ///
    /// The callback MUST flush all in-memory data to a durable layer (e.g.,
    /// memtable → SST) so that a crash between truncation and the next
    /// regular flush does not lose data. The callback is called while the WAL
    /// file mutex is held; it must not call any WAL methods or a deadlock
    /// will occur.
    pub(crate) fn set_pre_rotate_fn(
        &mut self,
        f: impl Fn() -> Result<(), StorageError> + Send + Sync + 'static,
    ) {
        self.pre_rotate_fn = Some(Arc::new(f));
    }

    /// Rotates the WAL file by truncating and writing a fresh version + encryption header.
    ///
    /// Calls `pre_rotate_fn` (if set) before truncating, ensuring in-memory
    /// data is flushed to a durable store first. A `kill -9` after truncation
    /// but before the next regular flush would otherwise lose all writes since
    /// the last SST flush.
    fn rotate_locked(&self, file: &mut dyn FsFile) -> Result<(), StorageError> {
        // Generate new per-segment DEK and encrypt with the KEK
        let new_dek = encryption::generate_dek()?;
        let mut kek_bytes = [0u8; 32];
        kek_bytes.copy_from_slice(self.kek.as_bytes());
        let kek = encryption::KeyEncryptionKey::from_bytes(kek_bytes);
        let new_enc_header = encryption::wrap_dek(&new_dek, &kek, self.kek_id)?;

        // Flush memtable → SST before truncating so the WAL contents are
        // durable on disk. If this errors, abort — do NOT truncate.
        if let Some(ref flush) = self.pre_rotate_fn {
            flush()?;
        }

        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&WAL_MAGIC)?;
        file.write_all(&WAL_VERSION_CURRENT.to_le_bytes())?;
        file.write_all(&new_enc_header.to_bytes())?;

        if self.config.sync_mode == SyncMode::EveryWrite {
            file.sync_all()?;
        }

        // Swap DEK, enc header, and nonce counter atomically under one mutex
        // lock (HEA-SEC-08).  Separating the counter reset from the DEK swap
        // would reopen the (old-DEK, nonce-0) reuse window.
        {
            let mut rot = self
                .rotation
                .lock()
                .map_err(|_| StorageError::Io(std::io::Error::other("rotation mutex poisoned")))?;
            rot.dek = new_dek;
            rot.enc_header = new_enc_header;
            rot.record_counter = 0;
        }

        Ok(())
    }
}

impl std::fmt::Debug for Wal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let record_counter = self
            .rotation
            .try_lock()
            .map(|r| r.record_counter)
            .unwrap_or(0);
        f.debug_struct("Wal")
            .field("path", &self.path)
            .field("config", &self.config)
            .field("record_counter", &record_counter)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::RealmId;
    use crate::storage::encryption::KEK_ID_SIZE;
    use crate::storage::fs::RealFs;
    use proptest::prelude::*;
    use std::io::Write;

    /// Helper to generate a test KEK for WAL tests.
    /// Uses a fixed deterministic key so that WAL re-open tests work correctly.
    fn test_kek() -> (encryption::KeyEncryptionKey, KekId) {
        let mut kek_bytes = [0u8; 32];
        for i in 0..32 {
            kek_bytes[i] = (i * 13 + 7) as u8;
        }
        let kek = encryption::KeyEncryptionKey::from_bytes(kek_bytes);
        let kek_id = [0x42u8; KEK_ID_SIZE];
        (kek, kek_id)
    }

    /// Helper to open a WAL for testing.
    fn open_test_wal(path: &Path, config: WalConfig) -> Wal {
        let (kek, kek_id) = test_kek();
        Wal::open_with_fs(path, config, Arc::new(RealFs), &kek, kek_id).expect("open wal")
    }

    /// Helper to create a test WAL entry.
    fn make_entry(key: &[u8], value: &[u8], op: WalOperation) -> WalEntry {
        WalEntry {
            timestamp: Timestamp::from_micros(1_700_000_000_000_000),
            realm_id: RealmId::new(Uuid::new_v4()),
            operation: op,
            key: key.to_vec(),
            value: value.to_vec(),
        }
    }

    // --- Version header tests ---

    #[test]
    fn new_wal_file_has_hwal_version_header() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wal_path = dir.path().join("test.wal");
        let wal = open_test_wal(
            &wal_path,
            WalConfig {
                max_size: 0,
                sync_mode: SyncMode::None,
            },
        );
        drop(wal);

        let data = std::fs::read(&wal_path).expect("read wal file");
        assert!(
            data.starts_with(b"HWAL"),
            "new WAL should start with HWAL magic, got: {:?}",
            &data[..4.min(data.len())]
        );
        assert_eq!(
            u16::from_le_bytes([data[4], data[5]]),
            1,
            "expected format version 1"
        );
        assert_eq!(
            data.len(),
            V1_RECORD_OFFSET as usize,
            "new empty WAL should be exactly {} bytes",
            V1_RECORD_OFFSET
        );
    }

    #[test]
    fn legacy_v0_wal_migrated_to_v1_on_open() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wal_path = dir.path().join("legacy.wal");
        let (kek, kek_id) = test_kek();

        // Manually write a v0 WAL file: just the 76-byte encryption header, no HWAL magic.
        {
            let dek = encryption::generate_dek().expect("generate dek");
            let enc_header = encryption::wrap_dek(&dek, &kek, kek_id).expect("wrap dek");
            std::fs::write(&wal_path, enc_header.to_bytes()).expect("write v0 wal");
        }

        // Open: should detect v0, run migration, rewrite with HWAL prefix.
        let wal = Wal::open_with_fs(
            &wal_path,
            WalConfig::default(),
            Arc::new(RealFs),
            &kek,
            kek_id,
        )
        .expect("open migrated wal");
        let entries = wal.read_all().expect("read migrated wal");
        assert!(
            entries.is_empty(),
            "migrated empty WAL should have no records"
        );
        drop(wal);

        let data = std::fs::read(&wal_path).expect("read migrated file");
        assert!(
            data.starts_with(b"HWAL"),
            "v0 file should have been migrated to v1 on open"
        );
        assert_eq!(
            u16::from_le_bytes([data[4], data[5]]),
            1,
            "migrated file should be at version 1"
        );
    }

    #[test]
    fn v1_wal_entries_survive_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wal_path = dir.path().join("test.wal");
        let entry = make_entry(b"persist-key", b"persist-val", WalOperation::Put);

        {
            let wal = open_test_wal(&wal_path, WalConfig::default());
            wal.append(&entry).expect("append");
        }
        {
            let wal = open_test_wal(&wal_path, WalConfig::default());
            let entries = wal.read_all().expect("read all");
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].key, b"persist-key");
            assert_eq!(entries[0].value, b"persist-val");
        }
    }

    // --- Serialization tests ---

    #[test]
    fn wal_entry_put_serde_round_trip() {
        let entry = make_entry(b"users/alice", b"data-here", WalOperation::Put);
        let bytes = entry.serialize();
        let decoded = WalEntry::deserialize(&bytes).expect("deserialize");
        assert_eq!(entry, decoded);
    }

    #[test]
    fn wal_entry_delete_serde_round_trip() {
        let entry = make_entry(b"users/bob", b"", WalOperation::Delete);
        let bytes = entry.serialize();
        let decoded = WalEntry::deserialize(&bytes).expect("deserialize");
        assert_eq!(entry, decoded);
    }

    // --- P0 fast unit tests ---

    #[test]
    fn empty_wal_returns_no_entries() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wal_path = dir.path().join("test.wal");
        let wal = open_test_wal(&wal_path, WalConfig::default());
        let entries = wal.read_all().expect("read");
        assert!(entries.is_empty());
    }

    #[test]
    fn append_single_entry_and_read_back() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wal_path = dir.path().join("test.wal");
        let wal = open_test_wal(&wal_path, WalConfig::default());

        let entry = make_entry(b"key1", b"value1", WalOperation::Put);
        wal.append(&entry).expect("append");

        let entries = wal.read_all().expect("read");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], entry);
    }

    #[test]
    fn append_multiple_preserves_order() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wal_path = dir.path().join("test.wal");
        let wal = open_test_wal(&wal_path, WalConfig::default());

        let mut expected = Vec::new();
        for i in 0..10 {
            let entry = make_entry(
                format!("key{i}").as_bytes(),
                format!("val{i}").as_bytes(),
                WalOperation::Put,
            );
            wal.append(&entry).expect("append");
            expected.push(entry);
        }

        let entries = wal.read_all().expect("read");
        assert_eq!(entries.len(), 10);
        assert_eq!(entries, expected);
    }

    /// Verifies a WAL written with [`SyncMode::EveryWrite`] is fully readable
    /// after the writer is dropped and the file re-opened.
    ///
    /// NOTE: this is a *persistence-across-reopen* check, not a proof of
    /// fsync-before-ack. Both writer and reader live in the same process, so the
    /// bytes would be served from the OS page cache even if `fsync` were never
    /// called. The fsync-before-ack durability invariant (surviving a real
    /// `kill -9` where the page cache is lost) is exercised by the
    /// `hearth-simulation` crate's `wal_crash` real-thread/tempfile crash loop.
    #[test]
    fn wal_data_persists_across_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wal_path = dir.path().join("test.wal");

        let entry = make_entry(b"durable-key", b"durable-val", WalOperation::Put);

        // Write and drop (closes the file handle; does NOT drop the page cache)
        {
            let wal = open_test_wal(
                &wal_path,
                WalConfig {
                    sync_mode: SyncMode::EveryWrite,
                    ..WalConfig::default()
                },
            );
            wal.append(&entry).expect("append");
        }

        // Re-open and verify data persisted
        {
            let wal = open_test_wal(&wal_path, WalConfig::default());
            let entries = wal.read_all().expect("read");
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0], entry);
        }
    }

    #[test]
    fn wal_recovery_stops_at_corruption() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wal_path = dir.path().join("test.wal");

        let entry1 = make_entry(b"good1", b"val1", WalOperation::Put);
        let entry2 = make_entry(b"good2", b"val2", WalOperation::Put);

        // Write two valid entries
        {
            let wal = open_test_wal(&wal_path, WalConfig::default());
            wal.append(&entry1).expect("append 1");
            wal.append(&entry2).expect("append 2");
        }

        // Append garbage bytes to simulate corruption
        {
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&wal_path)
                .expect("open for corruption");
            file.write_all(b"GARBAGE_CORRUPT_DATA_HERE")
                .expect("write garbage");
            file.sync_all().expect("sync");
        }

        // Re-open: should get both valid entries, garbage ignored
        {
            let wal = open_test_wal(&wal_path, WalConfig::default());
            let entries = wal.read_all().expect("read");
            assert_eq!(entries.len(), 2);
            assert_eq!(entries[0], entry1);
            assert_eq!(entries[1], entry2);
        }
    }

    /// HEA-1853: recovering from a corrupt tail MUST truncate that tail, so a
    /// record appended to the recovered WAL is still replayable after the next
    /// restart.
    ///
    /// Before the fix the append cursor was placed at physical EOF — *after* the
    /// garbage — so the following replay halted at the still-present corruption
    /// and silently dropped every post-recovery write (corruption-then-crash
    /// double fault).
    #[test]
    fn corrupt_tail_truncated_so_post_recovery_appends_survive_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wal_path = dir.path().join("test.wal");

        let entry1 = make_entry(b"good1", b"val1", WalOperation::Put);
        let entry2 = make_entry(b"good2", b"val2", WalOperation::Put);
        let post = make_entry(b"post-recovery", b"must-survive", WalOperation::Put);

        {
            let wal = open_test_wal(&wal_path, WalConfig::default());
            wal.append(&entry1).expect("append 1");
            wal.append(&entry2).expect("append 2");
        }

        let original = std::fs::read(&wal_path).expect("read wal file");
        let original_header: Vec<u8> = original
            [WAL_VERSION_HEADER_SIZE..WAL_VERSION_HEADER_SIZE + ENCRYPTION_HEADER_SIZE]
            .to_vec();

        const GARBAGE: &[u8] = b"POWER_LOSS_GARBAGE_PARTIAL_RECORD";
        {
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&wal_path)
                .expect("open for corruption");
            file.write_all(GARBAGE).expect("write garbage");
            file.sync_all().expect("sync");
        }

        let corrupt_size = std::fs::metadata(&wal_path).expect("stat").len();

        // Recovery pass: the valid prefix replays, and the garbage tail is
        // physically removed from the file rather than merely skipped.
        {
            let wal = open_test_wal(&wal_path, WalConfig::default());
            let entries = wal.read_all().expect("read after recovery");
            assert_eq!(entries, vec![entry1.clone(), entry2.clone()]);
        }

        let recovered = std::fs::read(&wal_path).expect("read wal file");
        assert!(
            (recovered.len() as u64) < corrupt_size,
            "corrupt tail must be truncated on recovery: {corrupt_size} -> {} bytes",
            recovered.len()
        );
        assert!(
            !recovered.windows(GARBAGE.len()).any(|w| w == GARBAGE),
            "the corrupt tail bytes must not remain in the recovered segment"
        );
        // Truncation re-keys the segment: the surviving prefix is re-encrypted
        // under a fresh DEK so no (DEK, nonce) pair is reused for the record
        // slot the discarded corrupt record occupied.
        assert_ne!(
            &recovered[WAL_VERSION_HEADER_SIZE..WAL_VERSION_HEADER_SIZE + ENCRYPTION_HEADER_SIZE],
            &original_header[..],
            "recovery must install a fresh wrapped DEK"
        );

        // A write made against the recovered segment.
        {
            let wal = open_test_wal(&wal_path, WalConfig::default());
            wal.append(&post).expect("append after recovery");
        }

        // The double fault: reopen again. The post-recovery record must replay.
        {
            let wal = open_test_wal(&wal_path, WalConfig::default());
            let entries = wal.read_all().expect("read after second open");
            assert_eq!(
                entries,
                vec![entry1, entry2, post],
                "post-recovery append must survive the next restart"
            );
        }
    }

    // --- P1 fast ---

    #[test]
    fn wal_rotation_at_size_threshold() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wal_path = dir.path().join("test.wal");

        // Very small max_size to trigger rotation quickly
        let config = WalConfig {
            max_size: 500,
            sync_mode: SyncMode::None,
        };
        let wal = open_test_wal(&wal_path, config);

        // Write entries until rotation occurs
        for i in 0..20 {
            let entry = make_entry(
                format!("key-{i}").as_bytes(),
                format!("value-{i}").as_bytes(),
                WalOperation::Put,
            );
            wal.append(&entry).expect("append");
        }

        // After rotation, the WAL should contain fewer entries than written
        // because rotation truncates the file
        let entries = wal.read_all().expect("read");
        assert!(
            entries.len() < 20,
            "expected rotation to truncate, got {} entries",
            entries.len()
        );
    }

    #[test]
    fn wal_reads_across_rotation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wal_path = dir.path().join("test.wal");

        let config = WalConfig {
            max_size: 500,
            sync_mode: SyncMode::None,
        };
        let wal = open_test_wal(&wal_path, config);

        // Fill up and trigger rotation
        for i in 0..30 {
            let entry = make_entry(
                format!("burst-{i}").as_bytes(),
                format!("val-{i}").as_bytes(),
                WalOperation::Put,
            );
            wal.append(&entry).expect("append");
        }

        // After rotation, write more entries that should survive
        let post_entry = make_entry(b"post-rotate", b"survives", WalOperation::Put);
        wal.append(&post_entry).expect("append post");

        let entries = wal.read_all().expect("read");
        assert!(
            entries.iter().any(|e| e.key == b"post-rotate"),
            "post-rotation entry should be readable"
        );
    }

    // --- HEA-SEC-08: nonce counter atomicity ---

    /// After a WAL rotation the record counter must reset to zero atomically
    /// with the DEK swap.  If they are split (counter reset outside the mutex)
    /// a writer encrypts with the new DEK but a nonce derived from the old
    /// counter; `read_all` then tries counter_nonce(0..N) — GCM tag mismatch
    /// → records silently dropped.
    ///
    /// Size arithmetic (key≈6 B, value≈6 B → ~69 B/record):
    ///   Header = 82 B.  82 + 8×69 = 634 > 600 → rotation fires on fill-7.
    ///   After rotation: 82 B. 4 fills + 3 post ≈ 7×69 = 483 B.
    ///   82 + 483 = 565 < 600 → no second rotation.
    #[test]
    fn rotation_counter_resets_atomically_with_dek() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wal_path = dir.path().join("rot_atomic.wal");

        let config = WalConfig {
            max_size: 600,
            sync_mode: SyncMode::EveryWrite,
        };

        let post1 = make_entry(b"post-rotate-1", b"val-1", WalOperation::Put);
        let post2 = make_entry(b"post-rotate-2", b"val-2", WalOperation::Put);
        let post3 = make_entry(b"post-rotate-3", b"val-3", WalOperation::Put);

        {
            let wal = open_test_wal(&wal_path, config.clone());
            for i in 0..10u8 {
                wal.append(&make_entry(
                    format!("fill-{i}").as_bytes(),
                    b"filler",
                    WalOperation::Put,
                ))
                .expect("fill");
            }
            wal.append(&post1).expect("post1");
            wal.append(&post2).expect("post2");
            wal.append(&post3).expect("post3");

            let entries = wal.read_all().expect("read live");
            assert!(
                entries.iter().any(|e| e.key == b"post-rotate-1"),
                "post1 must be readable after rotation"
            );
            assert!(
                entries.iter().any(|e| e.key == b"post-rotate-2"),
                "post2 must be readable after rotation"
            );
            assert!(
                entries.iter().any(|e| e.key == b"post-rotate-3"),
                "post3 must be readable after rotation"
            );
        }

        {
            let wal = open_test_wal(&wal_path, config);
            assert!(
                wal.read_all()
                    .expect("read after reopen")
                    .iter()
                    .any(|e| e.key == b"post-rotate-1"),
                "post1 must survive WAL reopen"
            );
            wal.append(&make_entry(b"after-reopen", b"ok", WalOperation::Put))
                .expect("append after reopen");
            assert!(
                wal.read_all()
                    .expect("read after extra append")
                    .iter()
                    .any(|e| e.key == b"after-reopen"),
                "entry written after reopen must be readable"
            );
        }
    }

    /// Counter reconstructed from on-disk state on reopen; writing another
    /// entry must not produce a nonce collision with existing records.
    #[test]
    fn counter_reconstructed_from_disk_on_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wal_path = dir.path().join("counter_reopen.wal");
        const N: usize = 5;

        {
            let wal = open_test_wal(&wal_path, WalConfig::default());
            for i in 0..N {
                wal.append(&make_entry(
                    format!("k{i}").as_bytes(),
                    format!("v{i}").as_bytes(),
                    WalOperation::Put,
                ))
                .expect("write");
            }
        }

        {
            let wal = open_test_wal(&wal_path, WalConfig::default());
            assert_eq!(
                wal.read_all().expect("read before extra").len(),
                N,
                "expected {N} entries before extra write"
            );
            wal.append(&make_entry(b"extra", b"e", WalOperation::Put))
                .expect("extra write");
            let after = wal.read_all().expect("read after extra");
            assert_eq!(after.len(), N + 1, "expected {} entries", N + 1);
            assert_eq!(after.last().expect("last").key, b"extra");
        }
    }

    #[test]
    fn wal_tampered_gcm_ciphertext_detected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let wal_path = dir.path().join("test.wal");

        let entry1 = make_entry(b"good1", b"val1", WalOperation::Put);
        let entry2 = make_entry(b"good2", b"val2", WalOperation::Put);

        // Write two valid entries
        {
            let wal = open_test_wal(&wal_path, WalConfig::default());
            wal.append(&entry1).expect("append 1");
            wal.append(&entry2).expect("append 2");
        }

        // Tamper with the GCM tag of entry2 (last 16 bytes of ciphertext)
        {
            // Read the raw WAL file
            let mut data = std::fs::read(&wal_path).expect("read wal");
            // Skip version header (6 bytes) + encryption header (76 bytes) = 82 bytes.
            // Record 0: [4B len][ciphertext][4B CRC]
            // Record 1: [4B len][ciphertext][4B CRC]
            // Find the second record's ciphertext and flip a byte near the end
            let mut pos = V1_RECORD_OFFSET as usize;

            // Skip record 0
            if pos + 4 <= data.len() {
                let len0 = u32::from_le_bytes(data[pos..pos + 4].try_into().expect("4-byte slice"))
                    as usize;
                pos += 4 + len0 + 4;
            }
            // Now at record 1: flip byte in the GCM tag region (last 16 bytes of ciphertext)
            if pos + 4 <= data.len() {
                let len1 = u32::from_le_bytes(data[pos..pos + 4].try_into().expect("4-byte slice"))
                    as usize;
                // CRC is at pos + 4 + len1..pos + 4 + len1 + 4
                // GCM tag is the last 16 bytes of the ciphertext (at pos+4+len1-16..pos+4+len1)
                let tag_pos = pos + 4 + len1 - 1; // last byte of tag
                data[tag_pos] ^= 0xFF; // tamper
            }

            std::fs::write(&wal_path, &data).expect("write tampered wal");
        }

        // Re-open: should only get entry1 (entry2 fails GCM auth)
        {
            let wal = open_test_wal(&wal_path, WalConfig::default());
            let entries = wal.read_all().expect("read");
            assert_eq!(
                entries.len(),
                1,
                "only first record should survive tampering"
            );
            assert_eq!(entries[0], entry1);
        }
    }

    // --- Property tests ---

    /// Strategy for generating arbitrary `WalEntry` values.
    fn arb_wal_entry() -> impl Strategy<Value = WalEntry> {
        (
            any::<i64>(),
            any::<[u8; 16]>(),
            prop_oneof![Just(0u8), Just(1u8)],
            prop::collection::vec(any::<u8>(), 0..256),
            prop::collection::vec(any::<u8>(), 0..256),
        )
            .prop_map(|(ts, uuid_bytes, op_byte, key, value)| {
                let operation = if op_byte == 0 {
                    WalOperation::Put
                } else {
                    WalOperation::Delete
                };
                WalEntry {
                    timestamp: Timestamp::from_micros(ts),
                    realm_id: RealmId::new(Uuid::from_bytes(uuid_bytes)),
                    operation,
                    key,
                    value,
                }
            })
    }

    #[test]
    fn decode_batch_payload_oversized_count_does_not_over_allocate() {
        // Four bytes: only the count field, no sub-entry data at all.
        // count = u32::MAX would allocate ~4 GiB without the cap.
        // With the cap: 0 remaining bytes → 0 / 9 = 0 entries possible.
        // The function must complete (Ok([])) rather than attempting the
        // enormous allocation.
        let mut data = vec![0u8; 4];
        data[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
        let result = decode_batch_payload(&data).expect("capped count → empty Ok, not OOM");
        assert!(result.is_empty(), "no sub-entry bytes → no entries decoded");
    }

    proptest! {
        #[test]
        fn proptest_entry_serde_round_trip(entry in arb_wal_entry()) {
            let bytes = entry.serialize();
            let decoded = WalEntry::deserialize(&bytes).expect("deserialize");
            prop_assert_eq!(entry, decoded);
        }

        #[test]
        fn proptest_random_writes_maintain_order(
            entries in prop::collection::vec(arb_wal_entry(), 1..50)
        ) {
            let dir = tempfile::tempdir().expect("tempdir");
            let wal_path = dir.path().join("test.wal");
            let config = WalConfig {
                max_size: u64::MAX,
                sync_mode: SyncMode::None,
            };
            let wal = open_test_wal(&wal_path, config);

            for entry in &entries {
                wal.append(entry).expect("append");
            }

            let read_back = wal.read_all().expect("read");
            prop_assert_eq!(entries, read_back);
        }

        #[test]
        fn proptest_wal_replay_prefix_consistency(
            entries in prop::collection::vec(arb_wal_entry(), 1..30)
        ) {
            let dir = tempfile::tempdir().expect("tempdir");
            let wal_path = dir.path().join("test.wal");
            let config = WalConfig {
                max_size: u64::MAX,
                sync_mode: SyncMode::None,
            };

            // Write all entries
            {
                let wal = open_test_wal(&wal_path, config.clone());
                for entry in &entries {
                    wal.append(entry).expect("append");
                }
            }

            // Re-open and verify all entries survive
            {
                let wal = open_test_wal(&wal_path, config);
                let read_back = wal.read_all().expect("read");
                prop_assert_eq!(entries, read_back);
            }
        }
    }
}
