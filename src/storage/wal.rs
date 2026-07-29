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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Instant;
use uuid::Uuid;

/// Nanoseconds elapsed since `start`, saturating at `u64::MAX`.
///
/// Used only by the group-commit phase profiler; sampled once per batch.
fn elapsed_ns(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

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
pub(crate) struct GroupSlot {
    /// Pre-serialised WAL entry payload (plaintext before encryption).
    plaintext: Vec<u8>,
    /// Monotonic position in the commit stream, assigned at enqueue.
    ///
    /// This is the writer's entire claim on the commit: it waits until the
    /// shared [`CommitSignal`] reports a completed ticket at least this high.
    ticket: u64,
}

/// Opaque handle returned by [`Wal::enqueue_entry`].
///
/// Must be passed to [`Wal::await_entry_durable`] to block until the WAL entry
/// is guaranteed durable (covered by an `fsync`/`sync_data`).
pub(crate) enum WalDurabilityHandle {
    /// Entry was written synchronously (`SyncMode::None`). Already durable.
    Immediate,
    /// Entry is pending in the group-commit queue.
    Pending { am_leader: bool, ticket: u64 },
}

/// Shared group-commit queue and leader flag.
struct GroupState {
    /// Writers waiting for the current leader to commit their entries.
    pending: VecDeque<GroupSlot>,
    /// `true` while a leader is active (holding `file` mutex, writing+syncing).
    leader_active: bool,
    /// Ticket to hand to the next enqueuing writer.
    ///
    /// Tickets are issued under this mutex in queue order, and batches drain a
    /// FIFO prefix under a single active leader, so a batch's tickets are
    /// always contiguous and strictly above every previously committed one.
    /// That is what makes a single "highest completed ticket" watermark a
    /// sufficient signal for every waiter.
    next_ticket: u64,
}

/// Commit watermark broadcast to every waiting writer (HEA-1959).
///
/// The original design gave each writer its own `Mutex` + `Condvar` and had the
/// leader `notify_one` each slot in turn. At batch = 110 that is 110 futex
/// wakes serialized on the leader's critical path — measured at ~2.6 us/entry,
/// the largest remaining serial cost once the write syscalls were coalesced.
///
/// Replacing it with one watermark plus one `notify_all` makes the leader's
/// signalling cost O(1) per batch instead of O(batch).
struct CommitSignal {
    /// Highest ticket whose commit has finished, successfully or not.
    ///
    /// Monotonically non-decreasing. A writer holding ticket `t` is durable
    /// once `completed >= t` and no failure covers `t`.
    completed: u64,
    /// First failed ticket and its error, if a commit has ever failed.
    ///
    /// A write fault fences the WAL permanently, so failure is monotone: once
    /// set, every ticket at or above `.0` failed. Writers below it committed
    /// before the fault and keep their successful acknowledgement.
    failed_from: Option<(u64, String)>,
}

// ─────────────────────────────────────────────────────────────────────────────

/// RAII guard held by the group-commit leader for the duration of its commit
/// loop.
///
/// If `commit_batch` panics (e.g. the memtable-flush closure inside
/// `pre_rotate` raises), the unwind would otherwise leave `leader_active ==
/// true` permanently, silently hanging every subsequent writer on a condvar
/// that nobody will ever notify.  Wrapping leadership in this guard converts
/// that silent hang into the same fail-fast behaviour the pre-group-commit code
/// exhibited (mutex-poison → immediate `Err`).
///
/// Call `guard.disarmed = true` just before the normal empty-queue return so
/// that `Drop` is a no-op on the happy path.
struct LeaderGuard<'a> {
    group: &'a Mutex<GroupState>,
    signal: &'a (Mutex<CommitSignal>, Condvar),
    /// Lowest ticket in the in-flight commit batch, if one is in progress.
    ///
    /// `lead_group_commit` sets this immediately after the drain and before
    /// calling `commit_batch`, so that a panic inside `commit_batch` (e.g. the
    /// `pre_rotate` memtable-flush closure) causes `Drop` to fail these writers
    /// rather than leaving them blocked forever.
    in_flight_from: Option<u64>,
    /// `true` once the leader finishes normally — suppresses the panic-path
    /// drain in `Drop`.
    disarmed: bool,
}

impl Drop for LeaderGuard<'_> {
    fn drop(&mut self) {
        if self.disarmed {
            return;
        }
        // Panic / hard-error path: restore a clean state so that any blocked
        // writer fails fast rather than waiting forever.
        // R2: use `unwrap_or_else` (matching how the signal mutex is handled)
        // so a poisoned group mutex does not silently skip the entire body —
        // that would strand writers indefinitely.
        let (highest_issued, first_queued) = {
            let mut gs = self.group.lock().unwrap_or_else(|e| e.into_inner());
            gs.leader_active = false;
            // Discard queued entries: the WAL is in an indeterminate state, so
            // nothing after the fault may be written and acked.
            let first_queued = gs.pending.front().map(|slot| slot.ticket);
            gs.pending.clear();
            (gs.next_ticket.saturating_sub(1), first_queued)
        };

        // The failure covers every ticket that was NOT committed: the in-flight
        // batch if there was one, otherwise the queue we just discarded.
        //
        // It must NOT default to ticket 0 when neither exists. Doing so would
        // retroactively fail every writer this leader already acked — the same
        // ghost-write class as the R1 bug, in a new form (caught by
        // `leader_guard_drop_does_not_fail_committed_writer`).
        let failed_from = self.in_flight_from.or(first_queued);

        let (lock, cv) = self.signal;
        {
            let mut sig = lock.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(from) = failed_from {
                if sig.failed_from.is_none() {
                    sig.failed_from = Some((
                        from,
                        "WAL leader exited unexpectedly; write failed".to_string(),
                    ));
                }
            }
            // Release every waiter regardless, so no writer blocks forever.
            sig.completed = sig.completed.max(highest_issued);
        }
        cv.notify_all();
    }
}

/// Cumulative per-phase timing of `commit_batch`, in nanoseconds.
///
/// Every field is sampled once per batch.  Together with `batches` and
/// `entries` this decomposes the group-commit cycle into the device-bound part
/// (`fsync_ns`) and the serial CPU/syscall part that scales with batch size
/// (`encrypt_ns` + `write_ns` + `signal_ns`) — the distinction HEA-1959 needs.
#[derive(Default)]
pub(crate) struct CommitProfile {
    /// Batches committed.
    batches: AtomicU64,
    /// Entries committed across all batches.
    entries: AtomicU64,
    /// Time assigning record numbers and encrypting (per-entry serial work).
    encrypt_ns: AtomicU64,
    /// Time in `write_all` calls (per-entry serial syscalls).
    write_ns: AtomicU64,
    /// Time in `sync_all` (device-bound, amortised over the whole batch).
    fsync_ns: AtomicU64,
    /// Time marking slots done and notifying condvars (per-entry futex wakes).
    signal_ns: AtomicU64,
}

/// Snapshot of [`CommitProfile`] returned by [`Wal::commit_profile`].
#[derive(Debug, Clone, Copy)]
pub struct CommitProfileSnapshot {
    /// Batches committed.
    pub batches: u64,
    /// Entries committed across all batches.
    pub entries: u64,
    /// Nanoseconds spent assigning record numbers and encrypting.
    pub encrypt_ns: u64,
    /// Nanoseconds spent in `write_all`.
    pub write_ns: u64,
    /// Nanoseconds spent in `sync_all`.
    pub fsync_ns: u64,
    /// Nanoseconds spent signalling committed slots.
    pub signal_ns: u64,
}

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
    /// Commit watermark every pending writer waits on.
    ///
    /// One `notify_all` per batch replaces one `notify_one` per entry, taking
    /// the leader's signalling cost off the per-entry serial path (HEA-1959).
    commit_signal: (Mutex<CommitSignal>, Condvar),
    /// Cumulative count of successful `sync_all` calls on this WAL.
    ///
    /// Incremented after each `commit_batch` sync completes.  Used by the
    /// saturation-throughput benchmark to measure fsyncs/write under group
    /// commit.  Off the hot path (relaxed ordering is sufficient).
    sync_count: AtomicU64,
    /// Per-phase timing of the group-commit critical path (HEA-1959).
    ///
    /// Sampled once per batch (not per entry), so the four `Instant::now()`
    /// calls amortise to well under 100 ns/entry at the batch sizes where this
    /// matters (30–110 entries).  Read by `examples/saturation_throughput.rs`
    /// to attribute the T=64→256 coalescing decay to a phase.
    commit_profile: CommitProfile,
    /// Set to `true` after any write error inside `commit_batch`.
    ///
    /// A mid-batch write fault leaves a torn record in the file; any bytes
    /// written after it are dropped by `scan_records` on recovery.  Fencing
    /// prevents subsequent appends from returning `Ok` for data that will be
    /// silently discarded at replay time.
    fenced: AtomicBool,
    /// Test hook: barrier released by every writer (leader and followers)
    /// after pushing its slot and computing `am_leader`, but before the
    /// leader begins draining the queue.
    ///
    /// When `Some`, all N concurrent callers of `append_with_pre_rotate`
    /// rendezvous here, guaranteeing the leader sees every slot in `pending`
    /// when it drains — making batch membership deterministic in tests.
    #[cfg(feature = "test-hooks")]
    pub commit_barrier: Option<Arc<std::sync::Barrier>>,
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
            commit_signal: (
                Mutex::new(CommitSignal {
                    completed: 0,
                    failed_from: None,
                }),
                Condvar::new(),
            ),
            group: Mutex::new(GroupState {
                pending: VecDeque::new(),
                leader_active: false,
                next_ticket: 1,
            }),
            sync_count: AtomicU64::new(0),
            commit_profile: CommitProfile::default(),
            fenced: AtomicBool::new(false),
            #[cfg(feature = "test-hooks")]
            commit_barrier: None,
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

    // ── Split-commit API (HEA-1948) ──────────────────────────────────────────
    //
    // `enqueue_entry` + `await_entry_durable` split what `append_with_pre_rotate`
    // does in a single blocking call into two phases:
    //
    //   Phase 1 (enqueue_entry)  — push entry to the group-commit queue.
    //                              Must be called while holding any serialising
    //                              lock (e.g. audit chain lock) so that WAL record
    //                              ordering matches logical ordering.
    //
    //   Phase 2 (await_entry_durable) — wait for the fsync that covers the entry.
    //                              MUST be called outside the serialising lock so
    //                              concurrent writers can enqueue and coalesce into
    //                              the same group-commit batch.

    /// Enqueue a WAL entry for group commit without blocking for the fsync.
    ///
    /// For `SyncMode::None` (dev/test): writes the entry synchronously via
    /// `write_entry_no_sync` and returns [`WalDurabilityHandle::Immediate`].
    /// `pre_rotate` is consumed and forwarded to `write_entry_no_sync`.
    ///
    /// For `SyncMode::EveryWrite`: serialises the entry, pushes it to the
    /// group-commit queue, and returns [`WalDurabilityHandle::Pending`].
    /// `pre_rotate` is **dropped without being called** here — pass a fresh
    /// instance to [`Self::await_entry_durable`] where it may be needed by
    /// the group-commit leader.
    pub(crate) fn enqueue_entry<F>(
        &self,
        entry: &WalEntry,
        pre_rotate: F,
    ) -> Result<WalDurabilityHandle, StorageError>
    where
        F: FnOnce() -> Result<(), StorageError>,
    {
        if self.fenced.load(Ordering::Acquire) {
            return Err(StorageError::Io(std::io::Error::other(
                "WAL fenced after write fault — all subsequent writes rejected",
            )));
        }

        let plaintext = entry.serialize();

        if self.config.sync_mode != SyncMode::EveryWrite {
            return self
                .write_entry_no_sync(plaintext, pre_rotate)
                .map(|()| WalDurabilityHandle::Immediate);
        }

        // EveryWrite path: drop pre_rotate here. The leader will reconstruct
        // it independently inside await_entry_durable (the storage engine passes
        // `|| self.trigger_flush()` to both enqueue_entry and await_entry_durable).
        drop(pre_rotate);

        let (am_leader, ticket) = {
            let mut gs = self
                .group
                .lock()
                .map_err(|_| StorageError::Io(std::io::Error::other("WAL group mutex poisoned")))?;
            let ticket = gs.next_ticket;
            gs.next_ticket += 1;
            gs.pending.push_back(GroupSlot { plaintext, ticket });
            let am_leader = !gs.leader_active;
            gs.leader_active = true;
            (am_leader, ticket)
        };

        Ok(WalDurabilityHandle::Pending { am_leader, ticket })
    }

    /// Block until the WAL entry represented by `handle` is durable.
    ///
    /// For [`WalDurabilityHandle::Immediate`]: returns `Ok(())` immediately.
    ///
    /// For [`WalDurabilityHandle::Pending`]: if this thread won leadership of
    /// the group-commit queue, runs the commit loop (writing all queued slots +
    /// one `sync_all`) before returning. Otherwise, waits on the slot condvar
    /// until a leader marks it done.
    ///
    /// `pre_rotate` is forwarded to `lead_group_commit` when this thread acts
    /// as leader; it is dropped without being called for follower threads.
    pub(crate) fn await_entry_durable<F>(
        &self,
        handle: WalDurabilityHandle,
        pre_rotate: F,
    ) -> Result<(), StorageError>
    where
        F: FnOnce() -> Result<(), StorageError>,
    {
        let (am_leader, ticket) = match handle {
            WalDurabilityHandle::Immediate => return Ok(()),
            WalDurabilityHandle::Pending { am_leader, ticket } => (am_leader, ticket),
        };

        // Test hook: rendezvous all concurrent writers here — after callers
        // have released any serialising lock (e.g. the audit chain lock) but
        // before the leader drains the queue.  This makes batch membership
        // deterministic in tests that need a guaranteed group size.
        #[cfg(feature = "test-hooks")]
        if let Some(ref b) = self.commit_barrier {
            b.wait();
        }

        if am_leader {
            self.lead_group_commit(pre_rotate)?;
        }
        // Follower: the looping leader handles this slot; pre_rotate is dropped.

        // Wait for the commit watermark to reach this writer's ticket.
        self.await_ticket(ticket)
    }

    // ── Original combined-phase append (unchanged) ────────────────────────────

    /// Appends an entry to the WAL, calling `pre_rotate` before rotating if
    /// rotation is needed.
    ///
    /// When `SyncMode::EveryWrite` is configured (the production default) this
    /// uses **looping-leader group commit** (HEA-1955): multiple concurrent
    /// callers share a single `fsync` per batch.  The leader — whichever thread
    /// first finds the queue empty — drains the queue, writes all entries, and
    /// calls `sync_all` once.  It then loops immediately: if new entries arrived
    /// during the fsync they are committed in the next iteration without any
    /// thread handoff.  The leader exits only when it finds the queue empty.
    ///
    /// Durability guarantee: no writer returns `Ok` until a `sync_all` that
    /// covered its bytes has completed.
    ///
    /// `pre_rotate` usage: the leader invokes it on the first batch that
    /// triggers rotation; subsequent batches pass `None`.  Follower threads'
    /// `pre_rotate` closures are dropped without being called.  All call sites
    /// in `engine.rs` supply the identical `|| self.trigger_flush()` closure,
    /// so the dropped instances have no observable effect.
    pub fn append_with_pre_rotate<F>(
        &self,
        entry: &WalEntry,
        pre_rotate: F,
    ) -> Result<(), StorageError>
    where
        F: FnOnce() -> Result<(), StorageError>,
    {
        // A write fault inside commit_batch fences the WAL: bytes written after
        // a torn record are dropped by scan_records on recovery, so subsequent
        // appends must not be acked as durable.
        if self.fenced.load(Ordering::Acquire) {
            return Err(StorageError::Io(std::io::Error::other(
                "WAL fenced after write fault — all subsequent writes rejected",
            )));
        }

        let plaintext = entry.serialize();

        // ── Fast path: SyncMode::None (dev / test only) ───────────────────
        if self.config.sync_mode != SyncMode::EveryWrite {
            return self.write_entry_no_sync(plaintext, pre_rotate);
        }

        // ── Group-commit path (SyncMode::EveryWrite) ──────────────────────
        //
        // Push a slot to the shared queue.  The first writer to find the queue
        // empty becomes the leader and runs the commit loop; all others wait on
        // the shared commit watermark until it covers their ticket.
        let (am_leader, ticket) = {
            let mut gs = self
                .group
                .lock()
                .map_err(|_| StorageError::Io(std::io::Error::other("WAL group mutex poisoned")))?;
            let ticket = gs.next_ticket;
            gs.next_ticket += 1;
            gs.pending.push_back(GroupSlot { plaintext, ticket });
            let am_leader = !gs.leader_active;
            gs.leader_active = true;
            (am_leader, ticket)
        };

        // Test hook: rendezvous all concurrent writers before the leader
        // drains the queue.  This makes batch membership deterministic
        // (every writer that reaches the barrier is guaranteed to appear in
        // the leader's first drain) without relying on fsync latency.
        #[cfg(feature = "test-hooks")]
        if let Some(ref b) = self.commit_barrier {
            b.wait();
        }

        if am_leader {
            // Leader: run the commit loop.  The looping leader drains every
            // pending batch itself rather than handing off to a follower
            // (HEA-1955).  Per-entry I/O errors travel through slot.state.error.
            self.lead_group_commit(pre_rotate)?;
        }
        // Follower: the looping leader handles this slot; pre_rotate is dropped.

        // Wait for the commit watermark to reach this writer's ticket.  The
        // looping leader publishes the watermark for every batch it commits
        // before returning, so this is typically a no-op for the leader thread
        // (its own ticket was in the first batch).
        self.await_ticket(ticket)
    }

    /// Blocks until the commit watermark covers `ticket`, then reports its
    /// outcome.
    ///
    /// Waking is edge-free: `completed` is a monotone watermark rather than a
    /// per-writer flag, so a wakeup can never be "missed" — a writer that
    /// checks late simply observes an already-satisfied condition and returns
    /// without waiting at all.
    fn await_ticket(&self, ticket: u64) -> Result<(), StorageError> {
        let (lock, cv) = &self.commit_signal;
        let mut sig = lock
            .lock()
            .map_err(|_| StorageError::Io(std::io::Error::other("WAL commit mutex poisoned")))?;
        while sig.completed < ticket {
            sig = cv.wait(sig).map_err(|_| {
                StorageError::Io(std::io::Error::other("WAL commit condvar poisoned"))
            })?;
        }
        match &sig.failed_from {
            Some((from, msg)) if ticket >= *from => {
                Err(StorageError::Io(std::io::Error::other(msg.clone())))
            }
            _ => Ok(()),
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

    /// Commits all pending WAL writes in a loop until the queue is empty.
    ///
    /// HEA-1955: the previous single-batch design promoted a follower after
    /// each fsync, paying ~1–3 ms of OS thread-wakeup latency per inter-fsync
    /// gap.  At T=256 this cut coalescing efficiency from ~92% to 23%.
    ///
    /// The looping leader eliminates handoff: after committing one batch it
    /// immediately drains the queue again — no thread parking, no condvar
    /// round-trip.  `leader_active` stays `true` throughout so late-arriving
    /// writers never race to elect a parallel leader.
    ///
    /// Panic safety: the RAII `LeaderGuard` holds `in_flight` throughout each
    /// batch.  If `commit_batch` panics, `Drop` signals every in-flight slot
    /// with an error and clears `leader_active`, so no writer hangs forever.
    fn lead_group_commit<F>(&self, pre_rotate: F) -> Result<(), StorageError>
    where
        F: FnOnce() -> Result<(), StorageError>,
    {
        // RAII guard: converts any panic inside commit_batch into a clean
        // fail-fast for every waiting writer rather than a silent hang.
        // Disarmed on the normal empty-queue exit.
        let mut guard = LeaderGuard {
            group: &self.group,
            signal: &self.commit_signal,
            in_flight_from: None,
            disarmed: false,
        };

        // Wrap in Option so the FnOnce can be consumed on the first rotation-
        // triggering batch and passed as None to subsequent batches.
        let mut pre_rotate_opt = Some(pre_rotate);
        let mut batch: Vec<GroupSlot>;

        loop {
            // Drain atomically.  Exit when the queue is empty.
            {
                let mut gs = self.group.lock().map_err(|_| {
                    StorageError::Io(std::io::Error::other("WAL group mutex poisoned"))
                })?;
                batch = gs.pending.drain(..).collect();
                if batch.is_empty() {
                    gs.leader_active = false;
                    guard.disarmed = true;
                    return Ok(());
                }
                // Record the batch's first ticket in the guard before
                // commit_batch so Drop can fail these writers on a panic
                // (HEA-1924 / HEA-1925).
                guard.in_flight_from = Some(batch[0].ticket);
            }

            // Write every slot + ONE fsync for this batch.
            self.commit_batch(&batch, pre_rotate_opt.take())?;
            // Clear so Drop does not re-fail committed writers on a later
            // error in this same call (R1 ghost-write fix).
            guard.in_flight_from = None;

            // Loop immediately: drain the next batch without waking a
            // follower.  This is the HEA-1955 efficiency improvement.
        }
    }

    /// Writes every slot in `batch` to the WAL file and calls `sync_all` once.
    ///
    /// All I/O runs under the file mutex so writes are in record-number order
    /// and rotation is atomic with respect to concurrent appenders.  Each slot
    /// is marked done (success or error string) before this function returns;
    /// per-slot errors travel through `slot.state.error` and do not propagate
    /// to the caller.
    fn commit_batch<F>(
        &self,
        batch: &[GroupSlot],
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
            // NOTE: if a batch's total size exceeds max_size, all entries still
            // land in a single segment (overshooting the cap); the next batch
            // will immediately trigger a rotation, so the overshoot is
            // self-correcting within one segment.
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

            // Reserve every record number for this batch in ONE rotation-mutex
            // critical section and snapshot the DEK once.  Rotation, if it was
            // needed, already happened above while this same file mutex was
            // held, so the counter cannot be reset underneath us mid-batch —
            // the reservation is as atomic as the per-entry locking it replaces
            // and upholds HEA-SEC-08 identically (each record still gets its
            // own counter-derived nonce and AAD).
            let t_encrypt = Instant::now();
            let (first_record_num, dek) = {
                let mut rot = self.rotation.lock().map_err(|_| {
                    StorageError::Io(std::io::Error::other("rotation mutex poisoned"))
                })?;
                let first = rot.record_counter;
                rot.record_counter += batch.len() as u64;
                let mut dek_bytes = [0u8; 32];
                dek_bytes.copy_from_slice(rot.dek.as_bytes());
                (first, DataEncryptionKey::from_bytes(dek_bytes))
            };

            // One AES key schedule for the whole batch instead of one per entry.
            let cipher = encryption::SectionCipher::new(&dek)?;

            // Serialise the entire batch into one buffer, then issue a single
            // `write_all`.  The previous three-syscalls-per-entry pattern cost
            // ~5.1 µs/entry of serial time on the commit critical path, which
            // at batch=110 was a third of the whole cycle (HEA-1959).
            let mut buf: Vec<u8> = Vec::with_capacity(approx_total as usize);
            for (i, slot) in batch.iter().enumerate() {
                let record_num = first_record_num + i as u64;
                let nonce = counter_nonce(record_num);
                let aad = record_num.to_le_bytes();

                // Length prefix is known ahead of the seal: plaintext + GCM tag.
                #[allow(clippy::cast_possible_truncation)]
                let payload_len = (slot.plaintext.len() + encryption::TAG_SIZE) as u32;
                buf.extend_from_slice(&payload_len.to_le_bytes());

                let ct_start = buf.len();
                let ct_len = cipher.seal_into(&mut buf, &slot.plaintext, &nonce, &aad)?;
                let crc = crc32fast::hash(&buf[ct_start..ct_start + ct_len]);
                buf.extend_from_slice(&crc.to_le_bytes());
            }
            let encrypt_ns = elapsed_ns(t_encrypt);

            let t_write = Instant::now();
            file.write_all(&buf)?;
            self.commit_profile
                .write_ns
                .fetch_add(elapsed_ns(t_write), Ordering::Relaxed);

            // ONE fsync for the entire group — the group-commit throughput win.
            //
            // `sync_data` (fdatasync) rather than `sync_all` (fsync): the WAL
            // segment is created and parent-dir-fsynced at open (HEA-1855) and
            // thereafter only appended to, so the only metadata replay needs is
            // the file length — which fdatasync persists. Skipping the mtime
            // journal commit halves the device round-trips per batch
            // (HEA-1959). Durability is unchanged: no writer is acked before a
            // sync covering its bytes returns.
            let t_fsync = Instant::now();
            file.sync_data()?;
            let fsync_ns = elapsed_ns(t_fsync);
            self.sync_count.fetch_add(1, Ordering::Relaxed);

            let p = &self.commit_profile;
            p.encrypt_ns.fetch_add(encrypt_ns, Ordering::Relaxed);
            p.fsync_ns.fetch_add(fsync_ns, Ordering::Relaxed);
            p.batches.fetch_add(1, Ordering::Relaxed);
            p.entries.fetch_add(batch.len() as u64, Ordering::Relaxed);
            Ok(())
        })();

        // A mid-batch write fault leaves a torn record in the file; bytes
        // written after it are dropped by scan_records on recovery.  Fence the
        // WAL so subsequent appends are rejected rather than silently acking
        // data that replay will discard.
        if commit_result.is_err() {
            self.fenced.store(true, Ordering::Release);
        }

        // Propagate the outcome to every slot; errors travel as strings so
        // callers receive a typed `StorageError::Io` with a message.
        // Use unwrap_or_else so a poisoned slot mutex does not silently skip
        // the signal and strand a writer waiting on the condvar forever.
        let err_msg = commit_result.as_ref().err().map(|e| e.to_string());
        let t_signal = Instant::now();

        // Publish the watermark ONCE for the whole batch, then a single
        // `notify_all`.  The previous design took one slot mutex and one
        // `notify_one` futex wake per entry — ~2.6 µs/entry serialized on the
        // leader's critical path, which at batch=110 was ~0.29 ms of the
        // commit cycle (HEA-1959).  This is O(1) per batch instead.
        //
        // INVARIANT: `batch` is a FIFO prefix of the queue committed by the
        // single active leader, so its tickets are contiguous and strictly
        // above every previously completed one.  Publishing the last ticket
        // therefore releases exactly the writers this batch made durable.
        //
        // INVARIANT: the mutex is released before `notify_all` so woken
        // writers do not immediately re-block on it.  The watermark is already
        // visible at that point, so no wakeup can be lost.
        if let Some(last) = batch.last() {
            let (lock, cv) = &self.commit_signal;
            {
                let mut sig = lock.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(msg) = err_msg {
                    if sig.failed_from.is_none() {
                        sig.failed_from = Some((batch[0].ticket, msg));
                    }
                }
                sig.completed = sig.completed.max(last.ticket);
            }
            cv.notify_all();
        }
        self.commit_profile
            .signal_ns
            .fetch_add(elapsed_ns(t_signal), Ordering::Relaxed);

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

    /// Returns a snapshot of the cumulative group-commit phase timings.
    ///
    /// Used by `examples/saturation_throughput.rs` to attribute the coalescing
    /// decay at high queue depth to a specific phase of the commit cycle
    /// (HEA-1959).  Counters are cumulative since WAL open; take a difference
    /// around a measurement window.
    pub fn commit_profile(&self) -> CommitProfileSnapshot {
        let p = &self.commit_profile;
        CommitProfileSnapshot {
            batches: p.batches.load(Ordering::Relaxed),
            entries: p.entries.load(Ordering::Relaxed),
            encrypt_ns: p.encrypt_ns.load(Ordering::Relaxed),
            write_ns: p.write_ns.load(Ordering::Relaxed),
            fsync_ns: p.fsync_ns.load(Ordering::Relaxed),
            signal_ns: p.signal_ns.load(Ordering::Relaxed),
        }
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

    // ── HEA-1935: LeaderGuard hardening ──────────────────────────────────────

    /// Builds a fresh signal pair for the LeaderGuard tests.
    fn test_signal() -> (Mutex<CommitSignal>, Condvar) {
        (
            Mutex::new(CommitSignal {
                completed: 0,
                failed_from: None,
            }),
            Condvar::new(),
        )
    }

    /// R1 regression: `Drop` must not retroactively fail an already-committed
    /// writer.
    ///
    /// Before the fix, `lead_group_commit` did not clear its in-flight marker
    /// after a successful `commit_batch`.  If the subsequent group-mutex lock
    /// failed, `Drop` fired with `disarmed=false` and failed writers that had
    /// already been acked — a ghost write.
    ///
    /// Post-HEA-1959 the marker is `in_flight_from`, cleared immediately after
    /// `commit_batch` returns `Ok`.  A drop with no in-flight batch must leave
    /// the already-published watermark reporting success.
    #[test]
    fn leader_guard_drop_does_not_fail_committed_writer() {
        let signal = test_signal();
        // Simulate: tickets 1..=3 committed successfully and published.
        signal
            .0
            .lock()
            .expect("fresh mutex")
            .completed = 3;

        let group = Mutex::new(GroupState {
            pending: VecDeque::new(),
            leader_active: true,
            next_ticket: 4,
        });

        // commit_batch succeeded, so in_flight_from was cleared. An armed drop
        // must not invent a failure for the committed tickets.
        let guard = LeaderGuard {
            group: &group,
            signal: &signal,
            in_flight_from: None,
            disarmed: false,
        };
        drop(guard);

        let sig = signal.0.lock().expect("signal mutex must not be poisoned");
        assert_eq!(
            sig.completed, 3,
            "watermark must not regress on an armed drop"
        );
        // in_flight_from was None, so failure starts at ticket 0 only if the
        // guard invented one. Committed tickets 1..=3 must still read as OK.
        match &sig.failed_from {
            None => {}
            Some((from, msg)) => panic!(
                "committed writers must not be retroactively failed; \
                 got failed_from=({from}, {msg})"
            ),
        }
    }

    /// R2 regression: `Drop` must release in-flight writers even when the group
    /// mutex is poisoned.
    ///
    /// Pre-fix, `Drop` used `if let Ok(mut gs) = self.group.lock()`, which
    /// silently no-ops on a poisoned mutex — leaving every in-flight writer
    /// stranded forever (the HEA-1924 failure mode).  The fix uses
    /// `unwrap_or_else(|e| e.into_inner())`.
    #[test]
    fn leader_guard_drop_on_poisoned_group_mutex_releases_in_flight() {
        let signal = test_signal();
        let group = Arc::new(Mutex::new(GroupState {
            pending: VecDeque::new(),
            leader_active: true,
            next_ticket: 3, // tickets 1 and 2 issued
        }));

        // Poison the group mutex via a thread that panics while holding it.
        {
            let g = Arc::clone(&group);
            std::thread::spawn(move || {
                let _lock = g.lock().expect("fresh mutex should not be poisoned");
                panic!("poison the group mutex for R2 test");
            })
            .join()
            .expect_err("spawned thread must have panicked");
        }
        assert!(
            group.lock().is_err(),
            "group mutex must be poisoned after thread panic"
        );

        // Armed guard with ticket 1 in flight.  Pre-fix Drop no-ops on a
        // poisoned mutex, stranding the writer.  Post-fix Drop recovers via
        // unwrap_or_else, advances the watermark past every issued ticket, and
        // records the failure.
        let guard = LeaderGuard {
            group: &group,
            signal: &signal,
            in_flight_from: Some(1),
            disarmed: false,
        };
        drop(guard);

        let sig = signal.0.lock().expect("signal mutex must not be poisoned");
        assert_eq!(
            sig.completed, 2,
            "watermark must cover every issued ticket so no writer waits forever"
        );
        let (from, msg) = sig
            .failed_from
            .as_ref()
            .expect("in-flight writer must receive an error on the drop path");
        assert_eq!(*from, 1, "failure must start at the in-flight batch");
        assert!(!msg.is_empty(), "error message must be populated");
    }

    /// A writer whose ticket the watermark already covers must not block, and
    /// must not be failed by a *later* batch's failure.
    ///
    /// This is the property that replaces per-slot `done` flags: correctness now
    /// rests on `failed_from` being a lower bound, so an early success cannot be
    /// retroactively invalidated by a subsequent write fault.
    #[test]
    fn earlier_tickets_keep_their_ack_when_a_later_batch_fails() {
        let signal = test_signal();
        {
            let mut sig = signal.0.lock().expect("fresh mutex");
            sig.completed = 10;
            sig.failed_from = Some((6, "write fault".to_string()));
        }
        let sig = signal.0.lock().expect("mutex");
        for t in 1..=5u64 {
            let failed = matches!(&sig.failed_from, Some((from, _)) if t >= *from);
            assert!(!failed, "ticket {t} committed before the fault must stay OK");
        }
        for t in 6..=10u64 {
            let failed = matches!(&sig.failed_from, Some((from, _)) if t >= *from);
            assert!(failed, "ticket {t} at or after the fault must report failure");
        }
    }
}
