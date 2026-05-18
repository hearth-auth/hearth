use std::collections::{BTreeMap, HashMap};
use std::io::Cursor;
use std::ops::RangeBounds;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

use openraft::{
    storage::{LogFlushed, RaftLogStorage, RaftSnapshotBuilder, RaftStateMachine},
    BasicNode, Entry, EntryPayload, LogId, LogState, Snapshot, SnapshotMeta, StorageError,
    StoredMembership, Vote,
};

use crate::cluster::types::{KVResponse, NodeId, TypeConfig};
use crate::storage::EmbeddedStorageEngine;

// ── Log storage ───────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct LogData {
    last_purged: Option<LogId<NodeId>>,
    committed: Option<LogId<NodeId>>,
    vote: Option<Vote<NodeId>>,
    entries: BTreeMap<u64, Entry<TypeConfig>>,
}

/// Thread-safe in-memory Raft log.
#[derive(Debug, Clone, Default)]
pub struct MemLogStore(Arc<Mutex<LogData>>);

impl MemLogStore {
    pub fn new() -> Self {
        Self::default()
    }
}

// `LogReader` shares the same Arc<Mutex<...>> as the store.
pub struct LogReader(Arc<Mutex<LogData>>);

fn read_range<RB>(data: &LogData, range: RB) -> Vec<Entry<TypeConfig>>
where
    RB: RangeBounds<u64>,
{
    data.entries.range(range).map(|(_, e)| e.clone()).collect()
}

// openraft 0.9.24 uses native async fn in traits (rustc ≥ 1.75).
// Do NOT add #[async_trait] — it produces lifetime mismatches.
impl openraft::storage::RaftLogReader<TypeConfig> for LogReader {
    async fn try_get_log_entries<RB>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<TypeConfig>>, StorageError<NodeId>>
    where
        RB: RangeBounds<u64> + Clone + std::fmt::Debug + Send,
    {
        let data = self.0.lock().unwrap();
        Ok(read_range(&data, range))
    }
}

// RaftLogStorage requires the store itself to also implement RaftLogReader.
impl openraft::storage::RaftLogReader<TypeConfig> for MemLogStore {
    async fn try_get_log_entries<RB>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<TypeConfig>>, StorageError<NodeId>>
    where
        RB: RangeBounds<u64> + Clone + std::fmt::Debug + Send,
    {
        let data = self.0.lock().unwrap();
        Ok(read_range(&data, range))
    }
}

impl RaftLogStorage<TypeConfig> for MemLogStore {
    type LogReader = LogReader;

    async fn get_log_state(&mut self) -> Result<LogState<TypeConfig>, StorageError<NodeId>> {
        let data = self.0.lock().unwrap();
        let last = data.entries.values().next_back().map(|e| e.log_id);
        Ok(LogState {
            last_purged_log_id: data.last_purged,
            last_log_id: last.or(data.last_purged),
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        LogReader(self.0.clone())
    }

    async fn save_committed(
        &mut self,
        committed: Option<LogId<NodeId>>,
    ) -> Result<(), StorageError<NodeId>> {
        self.0.lock().unwrap().committed = committed;
        Ok(())
    }

    async fn read_committed(
        &mut self,
    ) -> Result<Option<LogId<NodeId>>, StorageError<NodeId>> {
        Ok(self.0.lock().unwrap().committed)
    }

    async fn save_vote(&mut self, vote: &Vote<NodeId>) -> Result<(), StorageError<NodeId>> {
        self.0.lock().unwrap().vote = Some(*vote);
        Ok(())
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<NodeId>>, StorageError<NodeId>> {
        Ok(self.0.lock().unwrap().vote)
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<TypeConfig>,
    ) -> Result<(), StorageError<NodeId>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + Send,
        I::IntoIter: Send,
    {
        let mut data = self.0.lock().unwrap();
        for entry in entries {
            data.entries.insert(entry.log_id.index, entry);
        }
        // In-memory: no actual I/O, so signal immediate flush.
        callback.log_io_completed(Ok(()));
        Ok(())
    }

    async fn truncate(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        let mut data = self.0.lock().unwrap();
        data.entries.retain(|&index, _| index <= log_id.index);
        Ok(())
    }

    async fn purge(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        let mut data = self.0.lock().unwrap();
        data.entries.retain(|&index, _| index > log_id.index);
        data.last_purged = Some(log_id);
        Ok(())
    }
}

// ── State machine ─────────────────────────────────────────────────────────────

/// Shared snapshot store.  Held by both `MemStateMachine` and every
/// `MemSnapshotBuilder` it creates.  When `build_snapshot` finishes it writes
/// the payload here so that `get_current_snapshot` can serve it to followers.
pub type SnapshotStore =
    Arc<Mutex<Option<(SnapshotMeta<NodeId, BasicNode>, Vec<u8>)>>>;

struct SmInner {
    last_applied: Option<LogId<NodeId>>,
    last_membership: StoredMembership<NodeId, BasicNode>,
    kv: EmbeddedStorageEngine,
}

pub struct MemStateMachine {
    inner: SmInner,
    /// Shared with every `MemSnapshotBuilder` this SM spawns so that a built
    /// snapshot is immediately visible via `get_current_snapshot`.
    snapshot_data: SnapshotStore,
    /// Per-entry delay injected inside apply() to simulate a slow follower.
    pub apply_delay_ms: Arc<AtomicU64>,
}

impl MemStateMachine {
    /// Create a new state machine sharing `kv` with the caller.
    pub fn new(kv: EmbeddedStorageEngine) -> Self {
        Self {
            inner: SmInner {
                last_applied: None,
                last_membership: StoredMembership::default(),
                kv,
            },
            snapshot_data: Arc::new(Mutex::new(None)),
            apply_delay_ms: Arc::new(AtomicU64::new(0)),
        }
    }
}

// ── Snapshot builder ─────────────────────────────────────────────────────────

pub struct MemSnapshotBuilder {
    pub last_applied: Option<LogId<NodeId>>,
    pub last_membership: StoredMembership<NodeId, BasicNode>,
    pub data: HashMap<String, String>,
    /// Shared store: written here so the owning SM's `get_current_snapshot`
    /// picks up the newly-built snapshot without extra coordination.
    pub snapshot_store: SnapshotStore,
}

/// Magic prefix written at the start of every compressed snapshot.
/// Lets `install_snapshot` detect whether data is zstd-compressed.
const SNAP_MAGIC: &[u8; 4] = b"ZST1";

impl RaftSnapshotBuilder<TypeConfig> for MemSnapshotBuilder {
    async fn build_snapshot(
        &mut self,
    ) -> Result<Snapshot<TypeConfig>, StorageError<NodeId>> {
        let json_bytes = serde_json::to_vec(&self.data).map_err(|e| {
            StorageError::from_io_error(
                openraft::ErrorSubject::StateMachine,
                openraft::ErrorVerb::Write,
                std::io::Error::new(std::io::ErrorKind::Other, e),
            )
        })?;

        // Compress at level 3 (fast preset; good ratio for KV data).
        let compressed = zstd::encode_all(json_bytes.as_slice(), 3).map_err(|e| {
            StorageError::from_io_error(
                openraft::ErrorSubject::StateMachine,
                openraft::ErrorVerb::Write,
                e,
            )
        })?;

        // Prepend magic so install_snapshot knows to decompress.
        let mut payload = Vec::with_capacity(SNAP_MAGIC.len() + compressed.len());
        payload.extend_from_slice(SNAP_MAGIC);
        payload.extend_from_slice(&compressed);

        let meta = SnapshotMeta {
            snapshot_id: format!(
                "snap-{}",
                self.last_applied.map(|l| l.index).unwrap_or(0)
            ),
            last_log_id: self.last_applied,
            last_membership: self.last_membership.clone(),
        };

        // Persist in the shared store so get_current_snapshot() returns this
        // snapshot for followers that need to catch up.
        *self.snapshot_store.lock().unwrap() = Some((meta.clone(), payload.clone()));

        Ok(Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(payload)),
        })
    }
}

// ── RaftStateMachine impl ─────────────────────────────────────────────────────

impl RaftStateMachine<TypeConfig> for MemStateMachine {
    type SnapshotBuilder = MemSnapshotBuilder;

    async fn applied_state(
        &mut self,
    ) -> Result<
        (Option<LogId<NodeId>>, StoredMembership<NodeId, BasicNode>),
        StorageError<NodeId>,
    > {
        Ok((
            self.inner.last_applied,
            self.inner.last_membership.clone(),
        ))
    }

    async fn apply<I>(
        &mut self,
        entries: I,
    ) -> Result<Vec<KVResponse>, StorageError<NodeId>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + Send,
        I::IntoIter: Send,
    {
        let delay_ms = self.apply_delay_ms.load(Ordering::Relaxed);
        if delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }
        let mut responses = Vec::new();
        for entry in entries {
            self.inner.last_applied = Some(entry.log_id);
            match entry.payload {
                EntryPayload::Blank => {}
                EntryPayload::Normal(cmd) => {
                    self.inner.kv.set(cmd.key, cmd.value);
                }
                EntryPayload::Membership(m) => {
                    self.inner.last_membership =
                        StoredMembership::new(Some(entry.log_id), m);
                }
            }
            responses.push(KVResponse {
                applied_log_index: entry.log_id.index,
            });
        }
        Ok(responses)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        MemSnapshotBuilder {
            last_applied: self.inner.last_applied,
            last_membership: self.inner.last_membership.clone(),
            data: self.inner.kv.snapshot(),
            snapshot_store: self.snapshot_data.clone(),
        }
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<Cursor<Vec<u8>>>, StorageError<NodeId>> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<NodeId, BasicNode>,
        snapshot: Box<Cursor<Vec<u8>>>,
    ) -> Result<(), StorageError<NodeId>> {
        let raw = snapshot.into_inner();

        // Decompress if the payload starts with our magic prefix.
        let json_bytes: Vec<u8> = if raw.starts_with(SNAP_MAGIC) {
            zstd::decode_all(&raw[SNAP_MAGIC.len()..]).map_err(|e| {
                StorageError::from_io_error(
                    openraft::ErrorSubject::StateMachine,
                    openraft::ErrorVerb::Read,
                    e,
                )
            })?
        } else {
            raw.clone()
        };

        let data: HashMap<String, String> =
            serde_json::from_slice(&json_bytes).map_err(|e| {
                StorageError::from_io_error(
                    openraft::ErrorSubject::StateMachine,
                    openraft::ErrorVerb::Read,
                    std::io::Error::new(std::io::ErrorKind::Other, e),
                )
            })?;
        self.inner.kv.restore(data);
        self.inner.last_applied = meta.last_log_id;
        self.inner.last_membership = meta.last_membership.clone();
        *self.snapshot_data.lock().unwrap() = Some((meta.clone(), raw));
        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<TypeConfig>>, StorageError<NodeId>> {
        Ok(
            self.snapshot_data
                .lock()
                .unwrap()
                .as_ref()
                .map(|(meta, bytes)| Snapshot {
                    meta: meta.clone(),
                    snapshot: Box::new(Cursor::new(bytes.clone())),
                }),
        )
    }
}
