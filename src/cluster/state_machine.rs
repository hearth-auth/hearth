//! Raft state machine: applies committed log entries to `EmbeddedStorageEngine`.
//!
//! [`HearthStateMachine`] implements [`RaftStateMachine`] from openraft 0.9.
//!
//! ## spawn_blocking contract
//! `StorageEngine` is synchronous (`fn`, not `async fn`).  Every call to the
//! engine from an async context MUST use `tokio::task::spawn_blocking` to
//! avoid blocking the Tokio executor thread pool under load.
//!
//! ## Snapshot format
//! Snapshots are serialised with `ciborium` (CBOR) and then compressed with
//! `flate2` (gzip).  CBOR is chosen because it encodes `Vec<u8>` as compact
//! byte strings, not arrays of integers, keeping snapshot sizes small.

use std::collections::BTreeSet;
use std::io::{Cursor, Read as _, Write as _};
use std::sync::Arc;
use std::time::Instant;

use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use openraft::storage::RaftSnapshotBuilder;
use openraft::storage::RaftStateMachine;
use openraft::{
    EntryPayload, LogId, Snapshot, SnapshotMeta, StorageError, StorageIOError, StoredMembership,
};
use serde::{Deserialize, Serialize};
use tokio::task::spawn_blocking;
use tracing::{debug, info, instrument};

use crate::cluster::types::{HearthLogResponse, HearthNode, HearthRaftConfig, RaftCommand};
use crate::core::RealmId;
use crate::storage::StorageEngine;

// ── Error helpers ─────────────────────────────────────────────────────────────

fn io_write_err(e: impl std::error::Error + Send + Sync + 'static) -> StorageError<u64> {
    StorageError::IO {
        source: StorageIOError::write(&e),
    }
}

fn io_read_err(e: impl std::error::Error + Send + Sync + 'static) -> StorageError<u64> {
    StorageError::IO {
        source: StorageIOError::read(&e),
    }
}

fn to_write_err<E: std::error::Error + Send + Sync + 'static>(e: E) -> StorageError<u64> {
    io_write_err(e)
}

fn to_read_err<E: std::error::Error + Send + Sync + 'static>(e: E) -> StorageError<u64> {
    io_read_err(e)
}

// ── Snapshot wire format ──────────────────────────────────────────────────────

/// A single realm's full key-space at snapshot time.
#[derive(Serialize, Deserialize)]
struct RealmData {
    realm_id: RealmId,
    /// All (key, value) pairs for this realm, sorted by key.
    entries: Vec<(Vec<u8>, Vec<u8>)>,
}

/// The full snapshot payload serialised via CBOR then gzip-compressed.
#[derive(Serialize, Deserialize)]
struct SnapshotPayload {
    realms: Vec<RealmData>,
}

// ── Stored snapshot ───────────────────────────────────────────────────────────

struct StoredSnapshot {
    meta: SnapshotMeta<u64, HearthNode>,
    /// Compressed (gzip) CBOR-encoded `SnapshotPayload`.
    data: Vec<u8>,
}

// ── HearthSnapshotBuilder ─────────────────────────────────────────────────────

/// Builds a snapshot by scanning the full key-space of each known realm.
///
/// Returned by [`HearthStateMachine::get_snapshot_builder`].  The builder
/// holds its own `Arc` to the engine so snapshot creation doesn't block
/// the state machine from continuing to apply entries concurrently.
pub struct HearthSnapshotBuilder {
    engine: Arc<dyn StorageEngine>,
    known_realms: BTreeSet<RealmId>,
    last_applied: Option<LogId<u64>>,
    last_membership: StoredMembership<u64, HearthNode>,
}

impl RaftSnapshotBuilder<HearthRaftConfig> for HearthSnapshotBuilder {
    #[instrument(skip(self), name = "snapshot_build")]
    async fn build_snapshot(&mut self) -> Result<Snapshot<HearthRaftConfig>, StorageError<u64>> {
        let engine = Arc::clone(&self.engine);
        let realms = self.known_realms.iter().cloned().collect::<Vec<_>>();
        let last_applied = self.last_applied;
        let last_membership = self.last_membership.clone();

        let snapshot_id = format!(
            "snap-{}-{}",
            last_applied.as_ref().map(|id| id.index).unwrap_or(0),
            uuid::Uuid::new_v4()
        );

        // Scan the full key-space of every known realm inside spawn_blocking —
        // StorageEngine::scan is a synchronous call.
        let payload: SnapshotPayload = spawn_blocking(move || {
            let mut realm_data_vec = Vec::with_capacity(realms.len());
            for realm_id in &realms {
                let entries = engine
                    .scan(realm_id, &[], &[0xFF; 256])
                    .map_err(|e| io_read_err(e))?
                    .into_iter()
                    .map(|e| (e.key, e.value))
                    .collect();
                realm_data_vec.push(RealmData {
                    realm_id: realm_id.clone(),
                    entries,
                });
            }
            Ok::<SnapshotPayload, StorageError<u64>>(SnapshotPayload {
                realms: realm_data_vec,
            })
        })
        .await
        .map_err(|e| io_read_err(std::io::Error::other(e.to_string())))??;

        // Serialise to CBOR then gzip-compress.
        let compressed = compress_payload(&payload)?;

        let meta = SnapshotMeta {
            last_log_id: last_applied,
            last_membership,
            snapshot_id: snapshot_id.clone(),
        };

        info!(
            snapshot_id = %snapshot_id,
            realms = payload.realms.len(),
            compressed_bytes = compressed.len(),
            "snapshot built"
        );

        Ok(Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(compressed)),
        })
    }
}

// ── HearthStateMachine ────────────────────────────────────────────────────────

/// Applies committed Raft entries to [`EmbeddedStorageEngine`].
///
/// Tracks which realms have received writes so snapshot creation can scan
/// every live realm without a separate realm-registry call.
pub struct HearthStateMachine {
    /// The underlying storage engine.  Shared with the server — never swapped.
    ///
    /// `build_clustered` passes `Arc::clone(&inner)` here; snapshot install
    /// applies data in-place so the server's `inner` handle always reads
    /// current state without any `Arc` swap (HEA-2126).
    engine: Arc<dyn StorageEngine>,
    /// Set of realms that have had at least one write applied.
    known_realms: BTreeSet<RealmId>,
    /// Last applied log id (updated after every `apply` call).
    last_applied: Option<LogId<u64>>,
    /// Last applied membership config.
    last_membership: StoredMembership<u64, HearthNode>,
    /// Most recently built or installed snapshot (kept for `get_current_snapshot`).
    current_snapshot: Option<StoredSnapshot>,
}

impl HearthStateMachine {
    /// Create a state machine wrapping an existing storage engine.
    pub fn new(engine: Arc<dyn StorageEngine>) -> Self {
        Self {
            engine,
            known_realms: BTreeSet::new(),
            last_applied: None,
            last_membership: StoredMembership::default(),
            current_snapshot: None,
        }
    }
}

impl RaftStateMachine<HearthRaftConfig> for HearthStateMachine {
    type SnapshotBuilder = HearthSnapshotBuilder;

    async fn applied_state(
        &mut self,
    ) -> Result<(Option<LogId<u64>>, StoredMembership<u64, HearthNode>), StorageError<u64>> {
        Ok((self.last_applied, self.last_membership.clone()))
    }

    #[instrument(skip(self, entries), name = "sm_apply")]
    #[allow(clippy::cast_precision_loss)]
    async fn apply<I>(&mut self, entries: I) -> Result<Vec<HearthLogResponse>, StorageError<u64>>
    where
        I: IntoIterator<Item = openraft::Entry<HearthRaftConfig>> + Send,
        I::IntoIter: Send,
    {
        let entries: Vec<_> = entries.into_iter().collect();
        let mut responses = Vec::with_capacity(entries.len());
        let start = Instant::now();
        let count = entries.len();

        for entry in entries {
            self.last_applied = Some(entry.log_id);

            let response = match &entry.payload {
                EntryPayload::Blank => HearthLogResponse::default(),

                EntryPayload::Normal(cmd) => self.apply_command(cmd.clone()).await?,

                EntryPayload::Membership(membership) => {
                    self.last_membership =
                        StoredMembership::new(Some(entry.log_id), membership.clone());
                    debug!(log_id = ?entry.log_id, "membership change applied");
                    HearthLogResponse::default()
                }
            };

            responses.push(response);
        }

        let elapsed = start.elapsed();
        if count > 0 {
            let throughput = count as f64 / elapsed.as_secs_f64();
            info!(
                entries = count,
                elapsed_ms = elapsed.as_millis(),
                entries_per_sec = throughput as u64,
                "state machine apply complete"
            );
        }

        Ok(responses)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        HearthSnapshotBuilder {
            engine: Arc::clone(&self.engine),
            known_realms: self.known_realms.clone(),
            last_applied: self.last_applied,
            last_membership: self.last_membership.clone(),
        }
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<Cursor<Vec<u8>>>, StorageError<u64>> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    #[instrument(skip(self, snapshot), name = "sm_install_snapshot")]
    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<u64, HearthNode>,
        snapshot: Box<Cursor<Vec<u8>>>,
    ) -> Result<(), StorageError<u64>> {
        let compressed = snapshot.into_inner();

        // Decompress and deserialise the payload.
        let payload = decompress_payload(&compressed)?;

        // Extract realm IDs before moving payload into spawn_blocking.
        let realm_ids: BTreeSet<RealmId> =
            payload.realms.iter().map(|r| r.realm_id.clone()).collect();

        let engine = Arc::clone(&self.engine);

        // Apply the snapshot in-place through the live engine — no directory swap,
        // no new EmbeddedStorageEngine open (HEA-2126).
        spawn_blocking(move || restore_snapshot_in_place(&engine, &payload))
            .await
            .map_err(|e| io_write_err(std::io::Error::other(e.to_string())))??;

        // Rebuild known_realms from the snapshot.
        self.known_realms = realm_ids;

        self.last_applied = meta.last_log_id;
        self.last_membership = meta.last_membership.clone();

        self.current_snapshot = Some(StoredSnapshot {
            meta: meta.clone(),
            data: compressed,
        });

        info!(
            snapshot_id = %meta.snapshot_id,
            realms = self.known_realms.len(),
            "snapshot installed"
        );

        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<HearthRaftConfig>>, StorageError<u64>> {
        match &self.current_snapshot {
            None => Ok(None),
            Some(snap) => Ok(Some(Snapshot {
                meta: snap.meta.clone(),
                snapshot: Box::new(Cursor::new(snap.data.clone())),
            })),
        }
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

impl HearthStateMachine {
    /// Apply a single [`RaftCommand`] to the storage engine via `spawn_blocking`.
    ///
    /// Returns the [`HearthLogResponse`] to propagate back to `client_write` callers.
    /// Unconditional commands always return `success: true`; `PutIfAbsent` returns
    /// `success: false` when the key was already present.
    async fn apply_command(
        &mut self,
        cmd: RaftCommand,
    ) -> Result<HearthLogResponse, StorageError<u64>> {
        let engine = Arc::clone(&self.engine);

        match cmd {
            RaftCommand::Put {
                leader_timestamp: _,
                realm,
                key,
                value,
            } => {
                self.known_realms.insert(realm.clone());
                spawn_blocking(move || engine.put(&realm, &key, &value).map_err(to_write_err))
                    .await
                    .map_err(|e| io_write_err(std::io::Error::other(e.to_string())))??;
            }

            RaftCommand::Delete {
                leader_timestamp: _,
                realm,
                key,
            } => {
                self.known_realms.insert(realm.clone());
                spawn_blocking(move || engine.delete(&realm, &key).map_err(to_write_err))
                    .await
                    .map_err(|e| io_write_err(std::io::Error::other(e.to_string())))??;
            }

            RaftCommand::Batch {
                leader_timestamp: _,
                realm,
                entries,
            } => {
                self.known_realms.insert(realm.clone());
                spawn_blocking(move || engine.put_batch(&realm, &entries).map_err(to_write_err))
                    .await
                    .map_err(|e| io_write_err(std::io::Error::other(e.to_string())))??;
            }

            RaftCommand::PutIfAbsent {
                leader_timestamp: _,
                realm,
                key,
                value,
            } => {
                self.known_realms.insert(realm.clone());
                // State machine entries are applied sequentially — no concurrent
                // apply can interleave between the get and the put here, so the
                // check-and-write is atomically serialised by Raft ordering.
                let success = spawn_blocking(move || {
                    engine
                        .put_if_absent(&realm, &key, &value)
                        .map_err(to_write_err)
                })
                .await
                .map_err(|e| io_write_err(std::io::Error::other(e.to_string())))??;
                return Ok(HearthLogResponse {
                    success,
                    payload: Vec::new(),
                });
            }
        }

        Ok(HearthLogResponse::default())
    }
}

/// Compress a [`SnapshotPayload`] to CBOR + gzip bytes.
fn compress_payload(payload: &SnapshotPayload) -> Result<Vec<u8>, StorageError<u64>> {
    let mut cbor_buf = Vec::new();
    ciborium::into_writer(payload, &mut cbor_buf)
        .map_err(|e| io_write_err(std::io::Error::other(e.to_string())))?;

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&cbor_buf).map_err(to_write_err)?;
    encoder.finish().map_err(to_write_err)
}

/// Decompress gzip + CBOR bytes back to a [`SnapshotPayload`].
fn decompress_payload(data: &[u8]) -> Result<SnapshotPayload, StorageError<u64>> {
    let mut decoder = GzDecoder::new(data);
    let mut cbor_buf = Vec::new();
    decoder.read_to_end(&mut cbor_buf).map_err(to_read_err)?;
    ciborium::from_reader(&cbor_buf[..])
        .map_err(|e| io_read_err(std::io::Error::other(e.to_string())))
}

/// Blocking: apply a Raft snapshot in-place through the live engine.
///
/// Clears every live key for every realm currently present on disk (memtable
/// and SST files), then replays all entries from the snapshot via `put_batch`.
/// Because this operates on the same `Arc<dyn StorageEngine>` that the server
/// reads through (the `inner` handle from `build_clustered`), all reads via
/// the server's original `Arc` immediately observe the post-snapshot state —
/// no pointer swap required.
///
/// Phase 1 uses [`StorageEngine::list_realms`] to discover on-disk realms
/// rather than the state machine's in-memory `known_realms` set.  This fixes
/// the HEA-2131 regression: a restarted follower's `known_realms` is always
/// empty (the set is never persisted), so the previous approach left stale
/// keys from realms the leader deleted during the follower's downtime.
///
/// The process-local `OPEN_DIRS` guard and the OS-level advisory `LOCK` file
/// remain continuous across the install, so the exclusive lock is never
/// released (HEA-2126 bugs 1–3).
///
/// # Crash safety
///
/// An in-place restore is not atomic across a crash mid-restore: a process
/// killed between the delete phase and the replay phase leaves the engine in a
/// partially-cleared state.  On restart the WAL replays whatever was durably
/// written, which may be a mix of cleared and un-cleared realm data.  Operators
/// using Raft snapshot catch-up should either recover from a quorum peer or
/// wipe the data directory before restarting a node that died mid-restore.
///
/// Note: the directory-swap this replaces was also not crash-atomic — the OS
/// advisory lock file was moved with `data_dir` and immediately unlinked,
/// leaving the directory unprotected after any install (HEA-2126 bug 3).
fn restore_snapshot_in_place(
    engine: &Arc<dyn StorageEngine>,
    payload: &SnapshotPayload,
) -> Result<(), StorageError<u64>> {
    // Phase 1: delete all live keys for every realm currently on disk.
    //
    // `list_realms` enumerates from the live engine (memtable + SST files),
    // not from the state machine's in-memory `known_realms` set, so it
    // correctly clears stale data on a restarted follower whose `known_realms`
    // is empty (HEA-2131).
    let on_disk_realms = engine.list_realms().map_err(to_write_err)?;
    for realm_id in &on_disk_realms {
        let keys = engine
            .scan(realm_id, &[], &[0xFF; 256])
            .map_err(to_write_err)?
            .into_iter()
            .map(|e| e.key)
            .collect::<Vec<_>>();
        if !keys.is_empty() {
            engine
                .write_batch(realm_id, &[], &keys)
                .map_err(to_write_err)?;
        }
    }

    // Phase 2: replay the snapshot data.
    for realm_data in &payload.realms {
        engine
            .put_batch(&realm_data.realm_id, &realm_data.entries)
            .map_err(to_write_err)?;
    }

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    use openraft::{CommittedLeaderId, Entry, EntryPayload, LogId};
    use tempfile::tempdir;
    use uuid::Uuid;

    use crate::cluster::types::RaftCommand;
    use crate::storage::{EmbeddedStorageEngine, StorageConfig, StorageError};

    fn make_realm() -> RealmId {
        RealmId::new(Uuid::new_v4())
    }

    fn make_log_id(index: u64) -> LogId<u64> {
        LogId::new(CommittedLeaderId::new(1, 0), index)
    }

    fn make_put_entry(
        index: u64,
        realm: RealmId,
        key: Vec<u8>,
        value: Vec<u8>,
    ) -> Entry<HearthRaftConfig> {
        Entry {
            log_id: make_log_id(index),
            payload: EntryPayload::Normal(RaftCommand::Put {
                leader_timestamp: 0,
                realm,
                key,
                value,
            }),
        }
    }

    fn make_delete_entry(index: u64, realm: RealmId, key: Vec<u8>) -> Entry<HearthRaftConfig> {
        Entry {
            log_id: make_log_id(index),
            payload: EntryPayload::Normal(RaftCommand::Delete {
                leader_timestamp: 0,
                realm,
                key,
            }),
        }
    }

    fn make_batch_entry(
        index: u64,
        realm: RealmId,
        entries: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Entry<HearthRaftConfig> {
        Entry {
            log_id: make_log_id(index),
            payload: EntryPayload::Normal(RaftCommand::Batch {
                leader_timestamp: 0,
                realm,
                entries,
            }),
        }
    }

    fn open_sm(dir: &std::path::Path) -> HearthStateMachine {
        let config = StorageConfig::dev(dir.to_path_buf());
        let engine = EmbeddedStorageEngine::open(config).expect("open engine");
        HearthStateMachine::new(Arc::new(engine))
    }

    // ── Put / Delete / Batch ──────────────────────────────────────────────────

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn put_command_stores_value() {
        let dir = tempdir().unwrap();
        let mut sm = open_sm(dir.path().join("data").as_path());
        let realm = make_realm();

        sm.apply([make_put_entry(
            1,
            realm.clone(),
            b"k".to_vec(),
            b"v".to_vec(),
        )])
        .await
        .unwrap();

        let got = sm.engine.get(&realm, b"k").unwrap();
        assert_eq!(got, Some(b"v".to_vec()));
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn delete_command_removes_value() {
        let dir = tempdir().unwrap();
        let mut sm = open_sm(dir.path().join("data").as_path());
        let realm = make_realm();

        sm.apply([
            make_put_entry(1, realm.clone(), b"k".to_vec(), b"v".to_vec()),
            make_delete_entry(2, realm.clone(), b"k".to_vec()),
        ])
        .await
        .unwrap();

        let got = sm.engine.get(&realm, b"k").unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn batch_command_writes_all_pairs() {
        let dir = tempdir().unwrap();
        let mut sm = open_sm(dir.path().join("data").as_path());
        let realm = make_realm();
        let pairs = vec![
            (b"a".to_vec(), b"1".to_vec()),
            (b"b".to_vec(), b"2".to_vec()),
            (b"c".to_vec(), b"3".to_vec()),
        ];

        sm.apply([make_batch_entry(1, realm.clone(), pairs.clone())])
            .await
            .unwrap();

        for (k, v) in &pairs {
            let got = sm.engine.get(&realm, k).unwrap();
            assert_eq!(got.as_deref(), Some(v.as_slice()));
        }
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn last_applied_tracks_log_index() {
        let dir = tempdir().unwrap();
        let mut sm = open_sm(dir.path().join("data").as_path());
        let realm = make_realm();

        assert!(sm.applied_state().await.unwrap().0.is_none());

        sm.apply([
            make_put_entry(1, realm.clone(), b"x".to_vec(), b"y".to_vec()),
            make_put_entry(5, realm.clone(), b"a".to_vec(), b"b".to_vec()),
        ])
        .await
        .unwrap();

        let (last, _) = sm.applied_state().await.unwrap();
        assert_eq!(last.unwrap().index, 5);
    }

    // ── Snapshot round-trip ───────────────────────────────────────────────────

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn snapshot_roundtrip_identical_keyspace() {
        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();

        let data_dir_a = dir_a.path().join("data");
        let data_dir_b = dir_b.path().join("data");

        // Node A: build data and take a snapshot.
        let snapshot = {
            let mut sm_a = open_sm(&data_dir_a);
            let realm = make_realm();

            sm_a.apply([
                make_put_entry(1, realm.clone(), b"foo".to_vec(), b"bar".to_vec()),
                make_put_entry(2, realm.clone(), b"hello".to_vec(), b"world".to_vec()),
                make_batch_entry(
                    3,
                    realm.clone(),
                    vec![
                        (b"a".to_vec(), b"1".to_vec()),
                        (b"b".to_vec(), b"2".to_vec()),
                    ],
                ),
            ])
            .await
            .unwrap();

            let mut builder = sm_a.get_snapshot_builder().await;
            builder.build_snapshot().await.unwrap()
        };

        // Node B: install the snapshot then verify key-space matches.
        let mut sm_b = open_sm(&data_dir_b);
        sm_b.install_snapshot(&snapshot.meta, snapshot.snapshot)
            .await
            .unwrap();

        // Snapshot correctness: same known realms and same entries for each realm.
        assert_eq!(sm_b.known_realms.len(), 1);
        let realm_id = sm_b.known_realms.iter().next().unwrap().clone();

        let check_pairs: &[(&[u8], &[u8])] = &[
            (b"foo", b"bar"),
            (b"hello", b"world"),
            (b"a", b"1"),
            (b"b", b"2"),
        ];
        for (k, v) in check_pairs {
            let got = sm_b.engine.get(&realm_id, k).unwrap();
            assert_eq!(
                got.as_deref(),
                Some(*v),
                "key {:?} mismatch after snapshot install",
                k
            );
        }
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn snapshot_compress_decompress_roundtrip() {
        let payload = SnapshotPayload {
            realms: vec![RealmData {
                realm_id: make_realm(),
                entries: vec![
                    (b"key1".to_vec(), b"value1".to_vec()),
                    (b"key2".to_vec(), b"value2".to_vec()),
                ],
            }],
        };

        let compressed = compress_payload(&payload).unwrap();
        assert!(!compressed.is_empty());

        let decoded = decompress_payload(&compressed).unwrap();
        assert_eq!(decoded.realms.len(), 1);
        assert_eq!(decoded.realms[0].entries.len(), 2);
        assert_eq!(decoded.realms[0].entries[0].0, b"key1");
        assert_eq!(decoded.realms[0].entries[1].1, b"value2");
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn get_current_snapshot_none_initially() {
        let dir = tempdir().unwrap();
        let mut sm = open_sm(dir.path().join("data").as_path());
        assert!(sm.get_current_snapshot().await.unwrap().is_none());
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn get_current_snapshot_returns_after_build_and_install() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().join("data");
        let mut sm = open_sm(&data_dir);
        let realm = make_realm();

        sm.apply([make_put_entry(
            1,
            realm.clone(),
            b"k".to_vec(),
            b"v".to_vec(),
        )])
        .await
        .unwrap();

        let mut builder = sm.get_snapshot_builder().await;
        let snap = builder.build_snapshot().await.unwrap();
        let meta = snap.meta.clone();
        let data = snap.snapshot.clone();

        sm.install_snapshot(&meta, data).await.unwrap();
        assert!(sm.get_current_snapshot().await.unwrap().is_some());
    }

    // ── HEA-2131 regression pins ──────────────────────────────────────────────

    /// Regression pin for HEA-2131 (restart path): a follower that restarts and
    /// then receives a snapshot must clear on-disk data for realms absent from the
    /// snapshot, even though `known_realms` is empty on fresh construction.
    ///
    /// Before the fix, Phase 1 of `restore_snapshot_in_place` iterated
    /// `known_realms` (empty after restart), skipped the delete loop entirely,
    /// and left stale keys permanently on disk.
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn snapshot_install_clears_ondisk_realms_absent_from_known_realms() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().join("data");
        let realm = make_realm();

        // Leader's snapshot: realm contains ONLY `keep`.
        let snap = {
            let dir_a = tempdir().unwrap();
            let mut sm_a = open_sm(dir_a.path().join("data").as_path());
            sm_a.apply([make_put_entry(
                1,
                realm.clone(),
                b"keep".to_vec(),
                b"keep_val".to_vec(),
            )])
            .await
            .unwrap();
            let mut builder = sm_a.get_snapshot_builder().await;
            builder.build_snapshot().await.unwrap()
        };

        // Restarted follower: data already on disk, freshly constructed state
        // machine, so known_realms is empty.
        let config = StorageConfig::dev(data_dir.clone());
        let inner: Arc<EmbeddedStorageEngine> =
            Arc::new(EmbeddedStorageEngine::open(config).expect("open engine"));
        inner.put(&realm, b"stale", b"stale_val").unwrap();

        let mut sm = HearthStateMachine::new(Arc::clone(&inner) as Arc<dyn StorageEngine>);
        assert!(
            sm.known_realms.is_empty(),
            "precondition: fresh state machine has no known realms"
        );

        sm.install_snapshot(&snap.meta, snap.snapshot)
            .await
            .unwrap();

        assert_eq!(
            inner.get(&realm, b"keep").unwrap(),
            Some(b"keep_val".to_vec()),
            "snapshot data must be present after install"
        );
        assert_eq!(
            inner.get(&realm, b"stale").unwrap(),
            None,
            "a key absent from the installed snapshot must not survive the install; \
             the follower has diverged from the leader"
        );
    }

    /// Regression pin for HEA-2131 (no-restart path): a realm written directly to
    /// the engine (bypassing `apply`, so never in `known_realms`) must be cleared
    /// when a snapshot that omits that realm is installed.
    ///
    /// This covers the same root cause as the restart pin above but without a
    /// process restart: `known_realms` is empty because `apply` was never called
    /// for the stale realm, not because the state machine was freshly constructed.
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn snapshot_install_clears_realm_never_applied_by_this_node() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().join("data");
        let realm_stale = make_realm();
        let realm_snap = make_realm();

        // Snapshot includes only realm_snap.
        let snap = {
            let dir_a = tempdir().unwrap();
            let mut sm_a = open_sm(dir_a.path().join("data").as_path());
            sm_a.apply([make_put_entry(
                1,
                realm_snap.clone(),
                b"snap_key".to_vec(),
                b"snap_val".to_vec(),
            )])
            .await
            .unwrap();
            let mut builder = sm_a.get_snapshot_builder().await;
            builder.build_snapshot().await.unwrap()
        };

        // Fresh state machine whose engine already has data for realm_stale written
        // directly (not via apply), so known_realms is empty and the stale realm is
        // not tracked.
        let config = StorageConfig::dev(data_dir.clone());
        let inner: Arc<EmbeddedStorageEngine> =
            Arc::new(EmbeddedStorageEngine::open(config).expect("open engine"));
        inner.put(&realm_stale, b"stale_key", b"stale_val").unwrap();

        let mut sm = HearthStateMachine::new(Arc::clone(&inner) as Arc<dyn StorageEngine>);
        assert!(
            sm.known_realms.is_empty(),
            "precondition: no prior applies, known_realms is empty"
        );

        sm.install_snapshot(&snap.meta, snap.snapshot)
            .await
            .unwrap();

        assert_eq!(
            inner.get(&realm_stale, b"stale_key").unwrap(),
            None,
            "a realm never applied by this node must not survive snapshot install when \
             it is absent from the incoming snapshot"
        );
        assert_eq!(
            inner.get(&realm_snap, b"snap_key").unwrap(),
            Some(b"snap_val".to_vec()),
            "snapshot data must be present after install"
        );
    }

    // ── HEA-2126 regression pins ──────────────────────────────────────────────

    /// Bug 2 pin: reads through the **original** `Arc<EmbeddedStorageEngine>`
    /// (the `inner` handle held by the server, mirroring `build_clustered`)
    /// must observe the snapshot data after install.
    ///
    /// Before the fix, `install_snapshot` replaced `self.engine` with a new
    /// Arc pointing at a freshly-opened (now separate) engine, while the
    /// server's original Arc still pointed at the pre-snapshot directory.
    /// Any read routed through `ClusterEngine::inner` would silently return
    /// stale data (or worse, data from a deleted directory).
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn snapshot_install_visible_through_original_arc() {
        // Simulate the production topology: the server holds Arc<EmbeddedStorageEngine>
        // (inner) and the state machine holds Arc::clone(&inner) cast to dyn StorageEngine.
        let dir = tempdir().unwrap();
        let data_dir = dir.path().join("data");
        let config = StorageConfig::dev(data_dir.clone());
        let inner: Arc<EmbeddedStorageEngine> =
            Arc::new(EmbeddedStorageEngine::open(config).expect("open engine"));

        // State machine wraps the same object — mirrors build_clustered.
        let sm_engine: Arc<dyn StorageEngine> = Arc::clone(&inner) as Arc<dyn StorageEngine>;
        let mut sm = HearthStateMachine::new(sm_engine);
        let realm = make_realm();

        // Build a snapshot from a separate node (different data).
        let snap = {
            let dir_a = tempdir().unwrap();
            let mut sm_a = open_sm(dir_a.path().join("data").as_path());
            sm_a.apply([make_put_entry(
                1,
                realm.clone(),
                b"snap_key".to_vec(),
                b"snap_val".to_vec(),
            )])
            .await
            .unwrap();
            let mut builder = sm_a.get_snapshot_builder().await;
            builder.build_snapshot().await.unwrap()
        };

        sm.install_snapshot(&snap.meta, snap.snapshot)
            .await
            .unwrap();

        // Reads through the ORIGINAL Arc must see the snapshot data.
        let via_inner = inner.get(&realm, b"snap_key").unwrap();
        assert_eq!(
            via_inner,
            Some(b"snap_val".to_vec()),
            "reads through the original engine Arc must observe post-install snapshot data"
        );
    }

    /// Bug 3 pin: the `data_dir` exclusive lock must remain held after a
    /// snapshot install.
    ///
    /// Before the fix, the rename sequence moved the locked `LOCK` inode to a
    /// backup directory and unlinked it, silently releasing the exclusive lock.
    /// A second process (or a second in-process open) could then acquire the
    /// lock and open the same directory concurrently.
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn data_dir_lock_held_after_snapshot_install() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().join("data");
        let mut sm = open_sm(&data_dir);
        let realm = make_realm();

        sm.apply([make_put_entry(
            1,
            realm.clone(),
            b"k".to_vec(),
            b"v".to_vec(),
        )])
        .await
        .unwrap();

        let mut builder = sm.get_snapshot_builder().await;
        let snap = builder.build_snapshot().await.unwrap();
        let meta = snap.meta.clone();

        sm.install_snapshot(&meta, snap.snapshot).await.unwrap();

        // The exclusive lock on data_dir must still be held — a second open
        // on the same directory must return AlreadyLocked.
        let result = EmbeddedStorageEngine::open(StorageConfig::dev(data_dir.clone()));
        assert!(
            matches!(result, Err(StorageError::AlreadyLocked { .. })),
            "data_dir must remain exclusively locked after snapshot install; got: {result:?}"
        );
    }

    // ── Concurrent reads during snapshot ─────────────────────────────────────

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn concurrent_reads_during_snapshot_build() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().join("data");
        let mut sm = open_sm(&data_dir);
        let realm = make_realm();
        let pairs: Vec<_> = (0u8..20).map(|i| (vec![i], vec![i * 2])).collect();

        sm.apply([make_batch_entry(1, realm.clone(), pairs.clone())])
            .await
            .unwrap();

        // Clone the engine so a "concurrent reader" can access it.
        let engine_for_reader = Arc::clone(&sm.engine);
        let realm_for_reader = realm.clone();

        // The reader runs concurrently with the snapshot build and must observe
        // every already-committed pair with its exact value — a snapshot build
        // must not block, corrupt, or transiently hide committed reads. Collect
        // and return the observed values so the guarantee is actually asserted
        // (the previous `let _ = ...` discarded them, so the read was a no-op).
        let read_handle = tokio::spawn(async move {
            pairs
                .iter()
                .map(|(k, _)| engine_for_reader.get(&realm_for_reader, k).unwrap())
                .collect::<Vec<_>>()
        });

        let mut builder = sm.get_snapshot_builder().await;
        let snap = builder.build_snapshot().await.unwrap();

        let observed = read_handle.await.unwrap();
        for (i, got) in observed.iter().enumerate() {
            #[allow(clippy::cast_possible_truncation)]
            let expected = (i as u8) * 2;
            assert_eq!(
                got.as_deref(),
                Some([expected].as_slice()),
                "concurrent read of key {i} during snapshot build must return its committed value",
            );
        }

        // Snapshot must include all pairs.
        let payload = decompress_payload(&snap.snapshot.into_inner()).unwrap();
        assert_eq!(payload.realms[0].entries.len(), 20);
    }
}
